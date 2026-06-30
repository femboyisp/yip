# Data-plane throughput pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise yipd single-core data-plane throughput (the clean-link weak spot) without changing the wire format, by profiling the pipeline then removing the dominant per-packet costs.

**Architecture:** Three ordered phases. Phase 1 profiles the egress/ingress pipeline so we attack measured bottlenecks. Phase 2 removes the dominant cost (RaptorQ encode ~25 µs/packet) by bypassing the encoder when zero repair symbols are requested. Phase 3 batches I/O (GSO/sendmmsg/recvmmsg), removes per-symbol allocations, and finally wires yipd onto yip-io (it currently uses a raw `std::net::UdpSocket`).

**Tech Stack:** Rust, `raptorq` 2.0, `libc` (sendmmsg/recvmmsg/UDP_SEGMENT/UDP_GRO), Criterion, network namespaces + `tc netem` for end-to-end measurement.

## Global Constraints

- **No wire-format change.** Existing peers must interoperate; no new packet types, header fields, or constant offsets (anti-DPI posture preserved). The committed `tunnel_netns` ping test must stay green.
- **Release builds for all end-to-end measurement** (debug RaptorQ is ~75× slower — yipd is built `--release` everywhere).
- **Mullvad lint set, `-D warnings`.** No `as` numeric casts (use `From`/`TryFrom`). `#![forbid(unsafe_code)]` on every crate **except `yip-io`** (the only crate allowed `unsafe`, and only there).
- **≥90 % line coverage** on logic crates (`yip-transport`); keep `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo-shear`, `cargo test` green (pre-commit hooks enforce these).
- **Every optimization is measured independently** against `run-iperf-compare.sh` / `run-scp-compare.sh` and kept only if it helps; revert if it does not.
- Pinned dependency versions; `CHANGELOG.md` updated per Keep a Changelog.

---

### Task 1: Per-stage pipeline profile (Phase 1 — the gate)

Establishes where the per-packet CPU actually goes, on this hardware, before any optimization. The result governs Task 2's target.

**Files:**
- Create: `crates/yip-bench/examples/pipeline_profile.rs`
- Reference: `crates/yip-transport/src/lib.rs` (`Transport::encode`/`decode`), `crates/yip-crypto` (`Session::seal`/`open`), `crates/yip-wire` (`WireCodec::frame`/`deframe`)
- Reference for fixtures: `crates/yip-bench/src/lib.rs` (`established_pair()`, `sample_inner()`)

**Interfaces:**
- Consumes: `yip_bench::established_pair()` → an established `Session` pair; `yip_bench::sample_inner()` → a representative inner packet. (If these helpers are not public/suitable, build a `Session` pair inline via `yip_crypto` and a `Transport::new(vec![])`.)
- Produces: a runnable `cargo run --release -p yip-bench --example pipeline_profile` that prints a per-stage µs/op table. No code consumed by later tasks.

- [ ] **Step 1: Write the profile example**

```rust
//! Per-stage egress/ingress profile. Run:
//!   cargo run --release -p yip-bench --example pipeline_profile
use std::time::Instant;
use yip_transport::{FlowClass, Transport};

fn main() {
    let iters = 5000u32;
    let inner = vec![0xABu8; 1184]; // inner MTU the bench uses
    // Stand in for the sealed ciphertext (inner + 16-byte AEAD tag).
    let ciphertext = vec![0xCDu8; inner.len() + 16];

    // Egress: FEC encode (the suspected dominant cost).
    let mut tx = Transport::new(vec![]);
    let t = Instant::now();
    let mut nsym = 0usize;
    for _ in 0..iters {
        let (_c, syms) = tx.encode(&ciphertext, &inner, false, 0);
        nsym += syms.len();
    }
    let enc_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    // Ingress: FEC decode.
    let mut rx = Transport::new(vec![]);
    let t = Instant::now();
    let mut decoded = 0u32;
    for _ in 0..iters {
        let (cls, syms) = tx.encode(&ciphertext, &inner, false, 0);
        for s in &syms {
            if rx.decode(s, cls).is_some() {
                decoded += 1;
                break;
            }
        }
    }
    let encdec_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    println!("symbols/packet : {:.2}", nsym as f64 / f64::from(iters));
    println!("encode         : {enc_us:.1} us/packet");
    println!("decode (approx): {:.1} us/packet", encdec_us - enc_us);
    println!("decoded ok     : {decoded}/{iters}");
}
```

- [ ] **Step 2: Run it (release) and capture the table**

Run: `cargo run --release -p yip-bench --example pipeline_profile`
Expected: prints `symbols/packet`, `encode` (expect ~20–30 µs), `decode` (expect small), `decoded ok = iters/iters`. If `encode` is NOT the dominant term, STOP and re-scope Task 2 against whatever dominates (note it in the plan).

- [ ] **Step 3: Record the result**

Append the measured table to `crates/yip-bench/README.md` under a new `## Per-stage pipeline profile` heading (one short paragraph + the numbers). This is the evidence that justifies Task 2.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/examples/pipeline_profile.rs crates/yip-bench/README.md
git commit -m "Profile the egress/ingress pipeline per stage"
```

---

### Task 2: Bypass RaptorQ encode when repair = 0 (Phase 2a — headline lever)

When the controller requests zero repair symbols, emit the object's source symbols directly instead of constructing a full `Encoder` (which solves for intermediate symbols even when none are needed). Must be **byte-identical** to the current `encode(..., repair=0)` so peers and DPI observers cannot tell the difference.

**Files:**
- Modify: `crates/yip-transport/src/fec.rs` (`FecEncoder::encode`, ~lines 43-62)
- Test: `crates/yip-transport/src/fec.rs` (`#[cfg(test)]` module)
- Reference: current `FecEncoder::encode` builds `ObjectTransmissionInformation::with_defaults(object_size, symbol_size)`, `Encoder::new(ciphertext, oti)`, `.get_encoded_packets(repair)`, then `split_packet(object_id, object_size, &p)` per packet.

**Interfaces:**
- Consumes: `FlowParams { symbol_size: u16, .. }`, the `Symbol { object_id, object_size, payload_id: [u8;4], data: Vec<u8> }` type, and `split_packet(object_id: u16, object_size: u32, &EncodingPacket) -> Symbol`.
- Produces: `FecEncoder::encode(&mut self, ciphertext: &[u8], params: FlowParams, repair: u32) -> Vec<Symbol>` — unchanged signature; behaviour identical, faster on the `repair == 0` path.

- [ ] **Step 1: Write the byte-identical + round-trip test**

```rust
#[test]
fn zero_repair_bypass_is_byte_identical_to_encoder() {
    use crate::{FlowClass};
    let params = FlowClass::Default.params();
    let ciphertext = vec![0x5Au8; 1200]; // > one symbol to exercise multi-symbol objects

    // Reference path: force the real Encoder with repair = 0.
    let mut ref_enc = FecEncoder::new();
    let reference = encode_via_real_encoder(&mut ref_enc, &ciphertext, params); // helper below

    // Production path: FecEncoder::encode with repair = 0 (should bypass).
    let mut enc = FecEncoder::new();
    let produced = enc.encode(&ciphertext, params, 0);

    assert_eq!(produced.len(), reference.len(), "symbol count differs");
    for (p, r) in produced.iter().zip(reference.iter()) {
        assert_eq!(p.payload_id, r.payload_id, "payload_id differs");
        assert_eq!(p.object_size, r.object_size, "object_size differs");
        assert_eq!(p.data, r.data, "symbol data differs");
    }
}

#[test]
fn zero_repair_symbols_still_decode() {
    let params = crate::FlowClass::Default.params();
    let ciphertext = vec![0x5Au8; 1200];
    let mut enc = FecEncoder::new();
    let syms = enc.encode(&ciphertext, params, 0);
    let mut re = FecReassembler::new(params.symbol_size, 256);
    let mut out = None;
    for s in &syms {
        if let Some(o) = re.push(s) { out = Some(o); break; }
    }
    assert_eq!(out.as_deref(), Some(ciphertext.as_slice()));
}
```

Add this test-only helper in the test module (constructs symbols through the real `Encoder` with 0 repair, the exact current code path):

```rust
#[cfg(test)]
fn encode_via_real_encoder(_e: &mut FecEncoder, ciphertext: &[u8], params: crate::FlowParams) -> Vec<Symbol> {
    use raptorq::{Encoder, ObjectTransmissionInformation};
    let object_size = u32::try_from(ciphertext.len()).unwrap();
    let oti = ObjectTransmissionInformation::with_defaults(u64::from(object_size), params.symbol_size);
    let encoder = Encoder::new(ciphertext, oti);
    encoder.get_encoded_packets(0).iter().map(|p| split_packet(0, object_size, p)).collect()
}
```

- [ ] **Step 2: Run the test to verify it fails or passes as-is**

Run: `cargo test -p yip-transport zero_repair -- --nocapture`
Expected: `zero_repair_symbols_still_decode` PASSES already (current code handles repair=0); `zero_repair_bypass_is_byte_identical_to_encoder` PASSES trivially today (both go through the encoder). This test is the **safety net** for the refactor in Step 3 — it must stay green after the bypass is added.

- [ ] **Step 3: Implement the bypass**

In `FecEncoder::encode`, when `repair == 0`, construct the source `EncodingPacket`s directly without `Encoder::new`'s intermediate-symbol solve. Verify the exact raptorq 2.0 constructor (`raptorq::EncodingPacket::new(PayloadId, Vec<u8>)` and `raptorq::PayloadId::new(sbn, esi)`); the produced packets MUST serialize byte-identically to `Encoder::get_encoded_packets(0)` (the Step-1 test enforces this). Sketch:

```rust
pub fn encode(&mut self, ciphertext: &[u8], params: crate::FlowParams, repair: u32) -> Vec<Symbol> {
    let object_id = self.next_object_id;
    self.next_object_id = self.next_object_id.wrapping_add(1);
    let object_size = u32::try_from(ciphertext.len()).expect("frame fits u32");

    if repair == 0 {
        // Fast path: systematic source symbols are the data itself — emit them
        // directly, skipping the ~25 µs intermediate-symbol solve in Encoder::new.
        return source_symbols(object_id, object_size, ciphertext, params.symbol_size);
    }

    let oti = ObjectTransmissionInformation::with_defaults(u64::from(object_size), params.symbol_size);
    let encoder = Encoder::new(ciphertext, oti);
    encoder.get_encoded_packets(repair).into_iter()
        .map(|p| split_packet(object_id, object_size, &p)).collect()
}
```

Implement `source_symbols(object_id, object_size, ciphertext, symbol_size) -> Vec<Symbol>` to chunk `ciphertext` into `symbol_size` pieces (zero-padding the final symbol to `symbol_size`, matching raptorq), assigning `PayloadId`/ESI `0..K` in source-block 0, producing `Symbol`s via the same `split_packet` serialization. If a byte-identical construction proves infeasible against the raptorq API, KEEP the encoder path and instead pursue only the Task-3 wins (note this in the plan and drop Task 2 — do not ship a divergent wire format).

- [ ] **Step 4: Run tests + the profile**

Run: `cargo test -p yip-transport -- --nocapture` (all pass, incl. the two new tests)
Run: `cargo run --release -p yip-bench --example pipeline_profile` — but with `repair=0`: temporarily encode via a 0-repair class to confirm encode µs drops sharply (expect <5 µs vs ~25 µs).
Expected: byte-identical + decode tests green; encode time on the repair=0 path drops ~5–10×.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/fec.rs
git commit -m "Bypass RaptorQ encode when zero repair symbols are requested"
```

---

### Task 3: Batched DataPlaneIo (GSO/sendmmsg + recvmmsg) in yip-io (Phase 3a)

Add batched send/recv to the `DataPlaneIo` trait and implement it in `PlainIo` via `libc`. The `unsafe` stays contained in yip-io (the only crate permitted it). `IoUringIo` keeps its per-op path (batched ring submit is deferred).

**Files:**
- Modify: `crates/yip-io/src/lib.rs` (the `DataPlaneIo` trait + `PlainIo`)
- Test: `crates/yip-io/src/lib.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: a connected `std::net::UdpSocket` (PlainIo wraps it).
- Produces, on `DataPlaneIo`:
  - `fn send_batch(&mut self, datagrams: &[&[u8]]) -> io::Result<usize>` — send up to N datagrams in one syscall (sendmmsg); returns count sent. Default impl loops `send`.
  - `fn recv_batch(&mut self, bufs: &mut [[u8; MAX_WIRE_DATAGRAM]], lens: &mut [usize]) -> io::Result<usize>` — recvmmsg up to `bufs.len()` datagrams; writes per-datagram lengths into `lens`, returns count. Default impl does a single `recv`.
  - `const MAX_DATAGRAM_BATCH: usize = 64;` and `const MAX_WIRE_DATAGRAM: usize = 2048;` (module consts). Wire datagrams are ≤ MTU, so 2048 is ample; the caller owns the batch buffer on the **heap** (`vec![[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]`), never a 64×65535 stack array.
  Provide default trait methods so `IoUringIo` compiles unchanged.

- [ ] **Step 1: Write loopback batch tests**

```rust
#[test]
fn plainio_send_and_recv_batch_roundtrip() {
    use std::net::UdpSocket;
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.connect(rx.local_addr().unwrap()).unwrap();
    rx.connect(tx.local_addr().unwrap()).unwrap();
    let mut tx_io = PlainIo::new(tx);
    let mut rx_io = PlainIo::new(rx);

    let a = b"first-datagram".as_slice();
    let b = b"second".as_slice();
    let sent = tx_io.send_batch(&[a, b]).unwrap();
    assert_eq!(sent, 2);

    let mut bufs = vec![[0u8; MAX_WIRE_DATAGRAM]; 8];
    let mut lens = [0usize; 8];
    // recvmmsg may return fewer than sent per call; loop until we have 2.
    let mut got: Vec<Vec<u8>> = Vec::new();
    while got.len() < 2 {
        let n = rx_io.recv_batch(&mut bufs, &mut lens).unwrap();
        for i in 0..n { got.push(bufs[i][..lens[i]].to_vec()); }
    }
    assert!(got.contains(&a.to_vec()));
    assert!(got.contains(&b.to_vec()));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yip-io plainio_send_and_recv_batch -v`
Expected: FAIL — `send_batch`/`recv_batch` not defined.

- [ ] **Step 3: Implement batched trait methods + PlainIo libc impl**

Add `send_batch`/`recv_batch` to the trait with default impls (loop `send`/single `recv`) so `IoUringIo` is unaffected. In `PlainIo`, override them with `libc::sendmmsg`/`libc::recvmmsg` over `mmsghdr`/`iovec` arrays (`unsafe`, contained here; mirror the existing `submit_and_reap` unsafe-comment discipline). Add a GSO helper later only if Task 6 needs it; sendmmsg is the baseline batched path. Keep `MAX_DATAGRAM_BATCH = 64`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p yip-io -- --nocapture`
Expected: the new test passes; existing io_uring tests still pass/skip.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/lib.rs
git commit -m "Add batched send/recv (sendmmsg/recvmmsg) to DataPlaneIo"
```

---

### Task 4: Egress buffer reuse + batched send in yipd (Phase 3b)

Remove the per-symbol `Vec` allocation and the per-symbol `send()` syscall in the egress loop: frame all of a packet's symbols into reused buffers and send them in one `send_batch`.

**Files:**
- Modify: `bin/yipd/src/tunnel.rs` (egress thread, ~lines 107-146)
- Reference: current egress does, per symbol: `wire_glue::symbol_to_frame` → `codec_tx.frame` → `Vec::with_capacity(1 + dg.len())` → `out.push(PacketType::Data)` → `out.extend(dg)` → `udp_tx.send(&out)`.

**Interfaces:**
- Consumes: `yip_io::PlainIo`/`DataPlaneIo::send_batch` (Task 3); the existing `wire_glue::symbol_to_frame`, `Codec::frame`, `PacketType::Data`.
- Produces: no new public interface; egress emits one `send_batch` per TUN packet with zero per-symbol heap allocation (buffers owned by the thread, reused each iteration).

- [ ] **Step 1: Write/extend the netns egress test expectation**

No new unit test (the loop is integration-tested by `tunnel_netns`). Instead, before changing code, confirm the baseline: run the existing tunnel test green.

Run: `sudo -E cargo test -p yipd --test tunnel_netns ping_across_yipd_tunnel -- --nocapture --test-threads=1`
Expected: PASS (3/3 ping). This is the regression gate for the refactor.

- [ ] **Step 2: Implement reuse + batched send**

Replace the per-symbol allocate-and-send with: a thread-owned `Vec<Vec<u8>>` scratch (or a single arena + offset slices) reused each packet; frame each symbol into the scratch; collect `&[u8]` slices; call `io.send_batch(&slices)`. Keep the `PacketType::Data` prefix per datagram (no wire change). On partial send (`sent < n`), log and continue (matches today's drop-on-ENOBUFS tolerance).

- [ ] **Step 3: Run the netns tunnel test**

Run: `sudo -E cargo test -p yipd --test tunnel_netns ping_across_yipd_tunnel -- --nocapture --test-threads=1`
Expected: PASS — wire format unchanged, ping still 3/3.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/tunnel.rs
git commit -m "Egress: reuse buffers and batch-send a packet's symbols"
```

---

### Task 5: Wire yipd onto yip-io + ingress recvmmsg + socket buffers (Phase 3c)

Replace the daemon's raw `UdpSocket` send/recv with yip-io's `DataPlaneIo`, batch ingress with `recv_batch`, and size socket buffers.

**Files:**
- Modify: `bin/yipd/src/tunnel.rs` (socket setup ~line 49/95-96, ingress loop ~lines 152-214)
- Reference: ingress currently does `udp_rx.recv(&mut buf)` per datagram → prefix check → `deframe` → `frame_to_symbol` → `transport.decode` → `session.open` → `tun_writer.write_frame`.

**Interfaces:**
- Consumes: `yip_io::{select_backend, DataPlaneIo, PlainIo}`, `DataPlaneIo::recv_batch` (Task 3).
- Produces: no new public interface; egress/ingress run over `DataPlaneIo`; `SO_SNDBUF`/`SO_RCVBUF` raised.

- [ ] **Step 1: Baseline gate**

Run: `sudo -E cargo test -p yipd --test tunnel_netns ping_across_yipd_tunnel -- --nocapture --test-threads=1`
Expected: PASS.

- [ ] **Step 2: Implement**

After `connect`, set `SO_SNDBUF`/`SO_RCVBUF` (e.g. 4 MiB) on the socket (via `libc::setsockopt` in a small helper, or `socket2` if already a dep — check `Cargo.lock`; prefer no new dep, so libc). Wrap the send half in `PlainIo`/`select_backend`; the ingress loop reads a batch via `recv_batch` and processes each datagram through the existing deframe→decode→open→write path. Keep the two-thread split and `Arc<Mutex>`.

- [ ] **Step 3: Run the netns tunnel test**

Run: `sudo -E cargo test -p yipd --test tunnel_netns ping_across_yipd_tunnel -- --nocapture --test-threads=1`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/tunnel.rs
git commit -m "Wire yipd onto yip-io batched I/O; size socket buffers"
```

---

### Task 6: End-to-end measurement + docs (the verdict)

Measure the cumulative effect and record it honestly; revert any task that did not help.

**Files:**
- Modify: `crates/yip-bench/README.md` (before/after throughput), `CHANGELOG.md`
- Run: `crates/yip-bench/tests/run-iperf-compare.sh`, `run-scp-compare.sh`

- [ ] **Step 1: Build release + run the throughput harnesses**

```bash
cargo build --release -p yipd
sudo -E bash crates/yip-bench/tests/run-iperf-compare.sh target/release/yipd
sudo -E bash crates/yip-bench/tests/run-scp-compare.sh target/release/yipd
```
Expected: yip clean-link single-stream throughput meets or exceeds the pre-pass baseline (yip ~157 Mbit/s @ 10 ms RTT; scp 0% ~14 MB/s). Loss-rate columns unchanged within variance.

- [ ] **Step 2: Record before/after + update CHANGELOG**

Add a short "Throughput pass" subsection to `crates/yip-bench/README.md` with before/after numbers and which levers moved the needle. Add a `CHANGELOG.md` entry. If a lever showed no gain, note it and revert that commit.

- [ ] **Step 3: Full gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/README.md CHANGELOG.md
git commit -m "Measure and record the data-plane throughput pass"
```

---

## Stretch (deferred unless Phase 1 + Task 6 justify it)

- **Task 2b — Bulk-class object amortization.** Coalesce more bytes per `Encoder` construction for `FlowClass::Bulk` only. NOTE: coalescing multiple TUN packets into one FEC object needs a way to split them back on receive, which risks a wire change — only pursue if it can be done within the existing framing, and only if Task 6 shows encode is still the bulk ceiling. Otherwise leave deferred.
- **GSO (`UDP_SEGMENT`) egress** as a faster alternative to sendmmsg, if Task 6 shows syscall cost still matters after batching.

## Self-review notes

- **Spec coverage:** Phase 1 → Task 1; Phase 2a → Task 2; Phase 3 (batched API) → Task 3; (buffer reuse) → Task 4; (yip-io adoption + socket buffers + recvmmsg) → Task 5; measurement → Task 6. Phase 2b is the explicit stretch. Out-of-scope items (single-ring rewrite, Arc<Mutex> removal, multicore, AF_XDP) are not tasked, as intended.
- **Wire-compat gate:** Task 2 is guarded by a byte-identical test and a written escape hatch (drop the lever rather than diverge). Tasks 4–5 are guarded by the `tunnel_netns` ping test.
- **unsafe containment:** only Task 3/5 touch `unsafe`, only in `yip-io` (Task 5's setsockopt helper lives in yip-io or uses libc within the daemon — prefer adding a `set_buffers` helper to yip-io to keep unsafe out of yipd).
