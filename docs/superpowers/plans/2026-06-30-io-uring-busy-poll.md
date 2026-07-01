# Unified io_uring busy-poll data loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace yipd's two-thread `Arc<Mutex>` `PlainIo` data plane with a single-threaded event loop over both the UDP and TUN fds — lower latency, no locks, GSO — preferring an io_uring busy-poll driver with an epoll fallback.

**Architecture:** Extract all packet logic into a mutex-free, I/O-free `DataPlane` (unit-tested end to end). Drive it from a thin single-threaded driver: `PollDriver` (epoll, the fallback and Phase-A checkpoint) or `UringDriver` (io_uring busy-poll over one ring, the only new `unsafe`, in yip-io). No wire change.

**Tech Stack:** Rust, `io-uring` 0.7.13, `libc` (epoll, UDP_SEGMENT/GSO), the existing `yip-crypto`/`yip-transport`/`yip-wire`/`yip-device` crates.

## Global Constraints

- **No wire-format change.** Byte-identical framing (seal → FEC → `symbol_to_frame` → `Data` prefix; same `Control` packet). The netns `tunnel_netns` suite (ping / ping-under-loss / arq-integrity) is the gate, run against **both** drivers.
- **`unsafe` only in `yip-io`.** yipd stays `#![forbid(unsafe_code)]`; all io_uring buffer/SQE/CQE `unsafe` lives in `UringDriver` with a `// SAFETY:` comment per block. yip-device's raw-fd accessor may need one contained `unsafe`/libc call — keep it in yip-device (already `unsafe`-using for ioctl).
- **No `Arc<Mutex>` in the data path.** A single thread owns `DataPlane`.
- **Buffer ring < 1 MiB** (RLIMIT_MEMLOCK = 1 MiB on the dev box): the provided-buffer ring is ≤ 256 × `MAX_WIRE_DATAGRAM` (2048) = 512 KiB.
- **`YIP_FORCE_POLL=1`** (env) forces the fallback driver so CI/tests exercise both.
- Mullvad lints, `-D warnings`; no `as` numeric casts except the sanctioned `PacketType::* as u8` idiom; exact dependency pins; ≥90 % coverage on logic crates; `CHANGELOG.md` per Keep a Changelog.

---

## Phase A — `DataPlane` extraction + single-thread `PollDriver` (mergeable checkpoint)

Phase A alone is a shippable win: it removes every data-path mutex and the two-thread model, replacing them with one epoll thread driving a unit-tested `DataPlane`. It introduces NO io_uring and NO new unsafe.

### Task 1: [Phase A]  `DataPlane` struct + egress path (`on_tun_packet`)

**Files:**
- Create: `bin/yipd/src/dataplane.rs`
- Modify: `bin/yipd/src/main.rs` (add `mod dataplane;`)
- Reference: `bin/yipd/src/tunnel.rs:205-301` (the egress closure — the logic to move), `:67-99` (`SentLog`), `:109` (`conn_tag_from_cb`).

**Interfaces:**
- Produces: `pub struct DataPlane` owning `Session`, `Transport`, `SentLog`, `RetxBuffer`, `WireCodec` (built from `established.auth_key`/`hp_key`), `conn_tag: u64`, reused framing scratch, and monotonic timers. `SentLog` moves from tunnel.rs into dataplane.rs (or a shared module).
  - `pub fn new(established: yip_crypto::Established, conn_tag: u64) -> DataPlane`
  - `pub fn on_tun_packet(&mut self, inner: &[u8], now_ms: u64) -> &[Vec<u8>]` — seal → `transport.encode` → for each symbol `symbol_to_frame` + `codec.frame` + `[PacketType::Data]` prefix into a reused `Vec<Vec<u8>>`; record `sent_log.insert(counter,class)` and `retx.put(counter, sealed.ciphertext, class, object_id, now_ms)`. Returns the framed egress datagrams (borrow of the reused buffer).

- [ ] **Step 1: Write the egress unit test**

```rust
#[test]
fn on_tun_packet_produces_decodable_egress() {
    // Build an established session pair (mirror how tests in yip-crypto do it,
    // or reuse a helper). Two DataPlanes sharing the derived keys / conn_tag.
    let (mut a, mut b) = dataplane_pair();     // helper in this test module
    let inner = vec![0x11u8; 200];
    let dgrams: Vec<Vec<u8>> = a.on_tun_packet(&inner, 0).to_vec();
    assert!(!dgrams.is_empty());
    // Feed them to peer B's ingress; expect the original inner back out.
    let mut got = None;
    for dg in &dgrams {
        if let Outcome::TunWrite(w) = b.on_udp_datagram(dg, 0) { got = Some(w.to_vec()); }
    }
    assert_eq!(got.as_deref(), Some(inner.as_slice()));
}
```
(This test also exercises A2's `on_udp_datagram`; if writing A1 first, assert only `!dgrams.is_empty()` and that each begins with the `Data` prefix, then extend in A2.)

- [ ] **Step 2: Run → fail** (`DataPlane` undefined). `cargo test -p yipd --lib on_tun_packet`.

- [ ] **Step 3: Implement `DataPlane::new` + `on_tun_packet`** by moving the egress closure body (tunnel.rs:205-301) into the method, replacing the `Arc<Mutex>` `.lock()` calls with direct `&mut self` field access. Keep the reused-arena framing.

- [ ] **Step 4: Run the test → pass** (with the A1-scoped assertions).

- [ ] **Step 5: Commit** — `git commit -m "Extract DataPlane egress path (on_tun_packet)"`

### Task 2: [Phase A]  ingress + control + tick (`on_udp_datagram`, `tick`)

**Files:**
- Modify: `bin/yipd/src/dataplane.rs`
- Reference: `bin/yipd/src/tunnel.rs:312-651` (ingress closure: data path, control handler, feedback emit, ratio log).

**Interfaces:**
- Consumes: `DataPlane` (A1), `LossDetector`, `LossReport`, `Transport::{decode,observe_loss,repair_object}`, `Session::open`, `wire_glue::frame_to_symbol`.
- Produces:
  - `pub enum Outcome<'a> { None, TunWrite(&'a [u8]), Send(&'a [Vec<u8>]), TunWriteThenSend(&'a [u8], &'a [Vec<u8>]) }` (a data packet may yield a TUN write; a control packet may yield ARQ retransmit sends).
  - `pub fn on_udp_datagram(&mut self, dg: &[u8], now_ms: u64) -> Outcome<'_>` — branch on `dg[0]`. `Data`: `codec.deframe` → `frame_to_symbol` → `detector.on_seen` → `transport.decode` → on `Some`: `detector.on_delivered` + `session.open` → `Outcome::TunWrite(inner)`. `Control`: `session.open(counter, ct)` (auth) → `detector.on_seen`+`on_delivered` → `LossReport::decode` → per-class `observe_loss` → build ARQ retransmit datagrams for eligible `arq` NACKs into a reused buffer → `Outcome::Send`. Must own the `LossDetector` field now (moved into `DataPlane`).
  - `pub fn tick(&mut self, now_ms: u64) -> Option<&[u8]>` — if `now_ms - last_feedback >= FEEDBACK_INTERVAL_MS`, build+seal a `LossReport` `Control` packet (reused buffer) and return it; also drive the periodic bulk-ratio + ARQ-retransmit-count diagnostic logs.

- [ ] **Step 1: Write ingress/control/tick unit tests**

```rust
#[test]
fn control_packet_drives_observe_loss_and_arq() {
    let (mut a, mut b) = dataplane_pair();
    // A sends 3 objects; drop the middle datagram so B sees a gap.
    let d0 = a.on_tun_packet(&[0u8;100], 0).to_vec();
    let _d1 = a.on_tun_packet(&[1u8;100], 0).to_vec(); // dropped
    let d2 = a.on_tun_packet(&[2u8;100], 1).to_vec();
    for dg in d0.iter().chain(d2.iter()) { let _ = b.on_udp_datagram(dg, 2); }
    // After grace, B's tick emits a Control feedback with the missing counter.
    let fb = b.tick(20).expect("feedback emitted").to_vec();
    // A ingests the control packet → attributes loss + (for Bulk) retransmits.
    match a.on_udp_datagram(&fb, 21) { Outcome::Send(s) => assert!(!s.is_empty()), _ => {} }
    // (Exact retransmit depends on class; at minimum assert the control packet
    //  parses and does not panic, and observe_loss was called — see below.)
}

#[test]
fn forged_control_packet_is_rejected() {
    let (mut a, _b) = dataplane_pair();
    let mut forged = vec![2u8 /*Control*/]; forged.extend_from_slice(&7u64.to_be_bytes());
    forged.extend_from_slice(&[0xAB; 32]); // garbage ciphertext
    // Must not panic; auth fails so no observe_loss / retransmit.
    let _ = a.on_udp_datagram(&forged, 0);
}
```

- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** by moving the ingress data path, control handler, feedback emitter, and ratio-log logic (tunnel.rs:312-651) into `on_udp_datagram`/`tick`, replacing `.lock()` with `&mut self`. The ARQ retransmit path (`retx.get` → `repair_object` → frame) moves in verbatim (now lock-free).
- [ ] **Step 4: Run tests → pass** (plus round-trip test from A1 now fully green).
- [ ] **Step 5: Commit** — `git commit -m "Extract DataPlane ingress/control/tick paths"`

### Task 3: [Phase A]  single-thread `PollDriver`; retire the two-thread model

**Files:**
- Create: `crates/yip-io/src/poll.rs` (or a `PollDriver` in lib.rs) — the epoll loop.
- Modify: `bin/yipd/src/tunnel.rs` (`run()` — replace the two threads with one driver call), `crates/yip-device/src/lib.rs` (expose raw fds + a non-blocking setter).
- Reference: current `run()` setup (tunnel.rs:120-198) stays (bind, handshake, buffers, TUN); the two `.spawn` closures (205-656) are replaced.

**Interfaces:**
- Consumes: `DataPlane` (A1/A2). Needs a driver-agnostic callback trait so yip-io doesn't depend on yipd:
  ```rust
  // in yip-io
  pub trait Dispatch {
      fn on_udp(&mut self, dg: &[u8], now_ms: u64) -> DispatchOut<'_>;
      fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[Vec<u8>];
      fn tick(&mut self, now_ms: u64) -> Option<&[u8]>;
  }
  pub enum DispatchOut<'a> { None, Tun(&'a [u8]), Udp(&'a [Vec<u8>]), Both(&'a [u8], &'a [Vec<u8>]) }
  ```
  yipd's `DataPlane` implements `Dispatch` (adapting its `Outcome` to `DispatchOut`).
- Produces: `pub fn run_poll<D: Dispatch>(udp: RawFd, tun: RawFd, d: &mut D) -> io::Result<()>` — set both fds non-blocking; `epoll` for readability; on UDP readable → `recvmmsg` batch → `d.on_udp` each → send outputs (`sendmmsg`) / write TUN; on TUN readable → read frames → `d.on_tun` → `sendmmsg`; each loop iteration call `d.tick(now_ms)` and send its output; use a short epoll timeout so `tick` fires on cadence even when idle.

- [ ] **Step 1: `PollDriver` loopback unit test** (yip-io): two UDP sockets + a stub `Dispatch` that echoes; assert a datagram round-trips through `run_poll` driven for a few iterations (or factor the readable-handling into a testable helper). At minimum a unit test that `run_poll` sets fds non-blocking and one iteration moves a datagram.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement `run_poll`** + `yip-device` raw-fd/non-blocking accessors (`TunReader::as_raw_fd`, `TunWriter::as_raw_fd`, or a `TunTap::into_raw_fds`). Rewrite `tunnel.rs::run()` to build `DataPlane`, drop all `Arc`/`Mutex`, and call `run_poll(udp_fd, tun_fd, &mut dataplane)`.
- [ ] **Step 4: netns gate.** Build the test binary + run all three netns tests under sudo (build the binary, run under `sudo -E`; `sudo cargo` does not work). All must PASS — same wire, same behavior, now single-threaded.
- [ ] **Step 5: Commit** — `git commit -m "Single-thread PollDriver over DataPlane; retire two-thread Arc<Mutex> model"`

### Task 4: [Phase A]  Phase-A verification + docs

- [ ] Run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, coverage on the touched crates; the three netns tests under sudo. Record a latency/throughput before-after (poll driver vs the old two-thread) in the bench README. Update `CHANGELOG.md`. Commit. **This is the mergeable Phase-A checkpoint** — the lock-free single-thread win with no io_uring yet.

---

## Phase B — `UringDriver` (the io_uring busy-poll driver; the only new `unsafe`)

### Task 5: [Phase B]  `UringDriver` — one ring over UDP+TUN, provided-buffer recvs

**Files:**
- Create: `crates/yip-io/src/uring.rs`
- Test: `crates/yip-io/src/uring.rs` `#[cfg(test)]`
- Reference: existing `IoUringIo` (`crates/yip-io/src/lib.rs:73-131`) for the io-uring 0.7 API idioms + the RLIMIT_MEMLOCK skip discipline.

**Interfaces:**
- Consumes: the `Dispatch` trait (Task A3).
- Produces: `pub struct UringDriver` + `pub fn run_uring<D: Dispatch>(udp: RawFd, tun: RawFd, d: &mut D) -> io::Result<()>`. Builds one `io_uring`; registers a provided-buffer group of `RING_BUFS = 256` × `MAX_WIRE_DATAGRAM` (512 KiB); arms multishot `Recv` on `udp` and pooled `Read` on `tun`; `user_data` encodes the source (const tags `UDP_RECV`/`TUN_RECV` + buffer id, and a send-slot id). Loop: `submit_and_wait(1)` → drain CQ → per recv, borrow the buffer, call `d.on_udp`/`d.on_tun`, submit `Send`/`Write` for outputs, re-provide the buffer → re-arm recvs → `d.tick`. Every `unsafe` block carries a `// SAFETY:` comment.
- `pub fn uring_available() -> bool` — probe (build a ring + register a tiny buffer group within memlock); used by the daemon to choose.

- [ ] **Step 1: Loopback unit test** (skip-on-Err if the ring/registration fails under memlock — mirror the existing io_uring test): two connected UDP sockets, a stub `Dispatch` that turns each received datagram into one to send back; drive `run_uring` for a bounded number of iterations (or a testable `poll_once`); assert a datagram round-trips and that recv buffers are recycled (send N, receive N without exhausting the ring).
- [ ] **Step 2: Run → fail / skip.**
- [ ] **Step 3: Implement** the ring, buffer group, recv arming, CQ drain, and buffer recycle. Keep `RING_BUFS × MAX_WIRE_DATAGRAM < 1 MiB`. TUN via pooled single `Read` re-submits if multishot READ is unreliable (driver-internal, note in a comment).
- [ ] **Step 4: Run test → pass (or skip-on-Err).** `cargo test -p yip-io uring`.
- [ ] **Step 5: Commit** — `git commit -m "UringDriver: single ring over UDP+TUN with provided-buffer recvs"`

### Task 6: [Phase B]  GSO egress + bounded in-flight send table

**Files:** Modify `crates/yip-io/src/uring.rs`; test in the same module.

**Interfaces:** internal to `UringDriver`. Send buffers must outlive their `Send` CQE — hold them in a bounded `in_flight: Vec<Option<Vec<u8>>>` slot table keyed by `user_data` send-slot id, freed on the send completion. GSO: when `on_tun`/`on_udp` returns multiple same-size datagrams to one peer, copy them contiguously into one send buffer and submit one `Send` with the `UDP_SEGMENT` cmsg (segment size = one framed datagram); on GSO `EIO`/unsupported, fall back to per-datagram sends.

- [ ] **Step 1: Test** that a multi-datagram output is delivered intact via the GSO path over loopback (receiver reassembles the same bytes), and that the in-flight table frees slots on completion (send more than `in_flight` capacity across iterations without leaking). Skip-on-Err under memlock.
- [ ] **Step 2-4:** implement, run, verify (GSO path + sendmmsg fallback both deliver identical bytes).
- [ ] **Step 5: Commit** — `git commit -m "UringDriver: GSO egress + bounded in-flight send table"`

### Task 7: [Phase B]  wire `UringDriver` into yipd; run netns suite on both drivers

**Files:** Modify `bin/yipd/src/tunnel.rs` (driver selection).

- [ ] **Step 1: baseline** — the three netns tests pass on `PollDriver` (Phase A).
- [ ] **Step 2: Implement selection** in `run()`: if `std::env::var("YIP_FORCE_POLL").is_ok()` → `run_poll`; else if `yip_io::uring_available()` → `run_uring`; else `run_poll`. Both receive `&mut dataplane`.
- [ ] **Step 3: netns gate on BOTH drivers** — run all three netns tests (a) default (UringDriver active on this box) and (b) with `YIP_FORCE_POLL=1`. All six runs PASS (byte-identical wire; behavior parity).
- [ ] **Step 4: Commit** — `git commit -m "Select UringDriver at startup with PollDriver fallback (YIP_FORCE_POLL forces fallback)"`

### Task 8: [Phase B]  bench + CI + docs

**Files:** Modify `crates/yip-bench/README.md`, `.github/workflows/integration.yml`, `CHANGELOG.md`.

- [ ] **Step 1: Measure** ping RTT across the tunnel + clean-link throughput with each driver (`YIP_FORCE_POLL=1` vs default). Expect io_uring RTT ≤ poll RTT ≤ the old two-thread RTT; throughput holds/improves (GSO + no locks).
- [ ] **Step 2: CI** — run the netns suite with `YIP_FORCE_POLL=1` in addition to the default in the `netns-tunnel-test` job (so both drivers are guarded), honesty guards intact.
- [ ] **Step 3: Record** the latency/throughput deltas in the bench README + a `CHANGELOG.md` entry (single-threaded io_uring loop, lock removal, GSO). Full gate green.
- [ ] **Step 4: Commit** — `git commit -m "Measure + CI-guard the io_uring vs poll drivers"`

---

## Self-review notes

- **Spec coverage:** `DataPlane` (no I/O/locks) → A1/A2; retire two-thread + single-thread driver → A3; Phase-A checkpoint → A4; `UringDriver` one-ring-two-fds + buffer ring < 1 MiB → B1; GSO + send lifetimes → B2; startup selection + `YIP_FORCE_POLL` + both-driver netns gate → B3; bench + CI + docs → B4. Fallback parity is enforced by A3 (poll) + B3 (both). No-wire-change gated by netns throughout.
- **Phase boundary:** A1–A4 ship a working, mergeable, lock-free single-thread daemon with ZERO io_uring/unsafe — the checkpoint before the risky driver.
- **Type consistency:** `Dispatch`/`DispatchOut` (yip-io) ↔ `DataPlane`/`Outcome` (yipd) adapter; `run_poll`/`run_uring`/`uring_available` signatures; `RING_BUFS`, `MAX_WIRE_DATAGRAM` used consistently.
- **`unsafe` containment:** only B1/B2 (uring.rs in yip-io) add `unsafe`; yipd + the `DataPlane` stay `#![forbid(unsafe_code)]`. yip-device's raw-fd accessor uses the crate's existing libc/unsafe allowance.
- **Known risk flagged in-plan:** if the B-phase buffer discipline proves too error-prone, A-phase (PollDriver) is already shipped and the daemon works on it — B can iterate without blocking the lock-removal win.
