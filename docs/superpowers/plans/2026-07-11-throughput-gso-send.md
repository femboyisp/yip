# Send-side UDP GSO on the poll path (lever 4a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the per-datagram kernel UDP send-stack traversal on the poll hot path by coalescing same-destination, same-length, distinct-`fate` datagrams into one `UDP_SEGMENT` (GSO) send, preserving FEC per-symbol loss-independence.

**Architecture:** A new `crates/yip-io/src/gso.rs` holds the one FEC-safety rule both backends share (`can_coalesce`, `max_gso_run_len`, `partition_fate_safe`). The io_uring backend is refactored to call it (behavior-preserving). The poll backend's `flush_tx` partitions its egress batch into fate-safe runs and sends each run of ≥2 as one `sendmsg`+`UDP_SEGMENT` cmsg, falling back to the existing per-datagram `send_mmsg` for singletons and — after latching a "GSO unavailable" flag — whenever a GSO send reports the feature unsupported.

**Tech Stack:** Rust, `libc` (`sendmsg`, `CMSG_*`, `SOL_UDP`, `UDP_SEGMENT`), Linux ≥ 4.18 (target boxes run 6.12). No new crate dependencies.

## Global Constraints

- **`#![forbid(unsafe_code)]` holds outside `yip-io`/`yip-device`.** All new `unsafe` (the cmsg construction, the `sendmsg`) lives in `yip-io`; every block carries a `// SAFETY:` comment.
- **No `as` numeric casts** except discriminants/libc-ABI; use `u16::try_from(...)` / `usize::try_from(...)` with `.expect(...)`/`.ok()?`.
- **No bare `#[allow]`** — use `#[expect(reason = "...")]`.
- **FEC-safety invariant (load-bearing):** a GSO skb carries **at most one datagram per distinct `fate`** and all datagrams in it share one `dst` — so no coalesced skb ever holds two symbols of one FEC object or mixes peers.
- **Wire-identical:** GSO changes only how datagrams reach the socket, never their bytes/size/count/destination on the wire.
- **Latency-neutral:** only coalesce datagrams already queued in one `flush_tx` burst; never wait to fill a batch.
- **Scope:** poll send path only. `uring.rs` is refactored to the shared helper but otherwise unchanged; the recv path and the QUIC `run_quic` loop are untouched.
- **`refrences/` is read-only.**

---

### Task 0: De-risking spike — does `UDP_SEGMENT` help on virtio? (throwaway)

**Purpose:** Before writing production code, prove on the real target boxes that `UDP_SEGMENT` meaningfully beats plain `sendmmsg`. **Hard decision gate: if GSO gives < ~1.3× throughput-per-CPU on these virtio boxes, STOP and report — do not build Tasks 1–5.** This is throwaway measurement code, not committed to the crate.

**Files:**
- Create (throwaway, in the scratchpad — NOT under `crates/`): `/tmp/claude-*/scratchpad/gso_spike.rs` (a standalone `rustc`-compiled binary) or an inline Rust file built with `rustc -O`.

- [ ] **Step 1: Write a standalone UDP blaster with a `--gso` flag**

A single-file program that, for a fixed wall-clock duration, sends 1200-byte UDP payloads to a destination as fast as a non-blocking socket allows, two modes:
- **plain:** one `sendmmsg` of 32 separate 1200-byte datagrams per batch.
- **gso:** one `sendmsg` of a 32×1200-byte buffer with a `UDP_SEGMENT` cmsg (segment size 1200).
It prints datagrams/sec sent. Pair it with reading `/proc/self/stat` utime+stime to report **datagrams per CPU-second** (the metric the gate compares). Reference the cmsg construction in `crates/yip-io/src/uring.rs:146-185` (`prepare_gso`).

```rust
// gso_spike.rs — build: rustc -O gso_spike.rs -o gso_spike ; run: ./gso_spike <dst_ip> <port> plain|gso
// (uses only std + raw libc via extern "C"; or add `--extern libc` if convenient)
// Sends for 5s, prints: mode, datagrams_sent, cpu_seconds, datagrams_per_cpu_sec
```

- [ ] **Step 2: Run both modes box→box on the real target boxes**

On the two EPYC boxes (`45.61.149.155` "Y1", `144.172.98.216` "Y2"): run a UDP sink on Y2 (a tiny recv loop or `iperf3 -s -u`), then run the spike from Y1 in `plain` then `gso` mode, over their public path (or the existing yip underlay eth0 — raw UDP, no tunnel). Record datagrams-per-CPU-second for each.

```bash
# scp the compiled gso_spike to Y1 and Y2; sink on Y2, blast from Y1 both modes.
```

- [ ] **Step 3: Record the decision**

Write the two numbers and the ratio into `crates/yip-bench/RESULTS.md` under a new "4a GSO spike" heading (this file IS committed — the spike binary is not). State the verdict explicitly:
- **ratio ≥ ~1.3×** → proceed to Task 1.
- **ratio < ~1.3×** → STOP; GSO does not pay off on virtio here; report to the human and do not implement Tasks 1–5.

- [ ] **Step 4: Commit the recorded result**

```bash
git add crates/yip-bench/RESULTS.md
git commit -m "spike(throughput-4a): UDP_SEGMENT vs plain sendmmsg on virtio — decision gate"
```

---

### Task 1: Shared fate-safe GSO grouping module (`gso.rs`)

**Files:**
- Create: `crates/yip-io/src/gso.rs`
- Modify: `crates/yip-io/src/lib.rs` (add `pub(crate) mod gso;` near the other `mod` declarations at lines 5-8)
- Modify: `crates/yip-io/src/uring.rs:583-613` (`can_coalesce_gso_tagged`) and `:693-700` (`max_gso_datagrams_for_segment`) to delegate to the shared helper — behavior-preserving.

**Interfaces:**
- Consumes: `crate::poll::EgressDatagram` (fields `fate: u16`, `dst: SocketAddr`, `bytes: Vec<u8>`).
- Produces:
  - `pub(crate) fn can_coalesce(run: &[EgressDatagram]) -> Option<u16>`
  - `pub(crate) fn max_gso_run_len(segment_size: u16, hard_cap: usize) -> usize`
  - `pub(crate) struct GsoRun { pub segment_size: u16, pub members: Vec<usize> }`
  - `pub(crate) fn partition_fate_safe(dgs: &[EgressDatagram], hard_cap: usize, out: &mut Vec<GsoRun>)`
  - `pub(crate) const MAX_UDP_PAYLOAD: usize = 65_507;`
  - `pub(crate) const MAX_GSO_SEGMENTS_PER_SEND: usize = 32;`

- [ ] **Step 1: Write the failing tests for `can_coalesce` and `max_gso_run_len`**

Create `crates/yip-io/src/gso.rs` with only a `#[cfg(test)] mod tests` (no impl yet):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::poll::EgressDatagram;
    use std::net::SocketAddr;

    fn dg(fate: u16, dst: &str, len: usize) -> EgressDatagram {
        EgressDatagram { fate, dst: dst.parse().unwrap(), bytes: vec![0u8; len] }
    }
    const A: &str = "10.0.0.1:9"; const B: &str = "10.0.0.2:9";

    #[test]
    fn coalesce_ok_same_dst_len_distinct_fate() {
        let run = [dg(1, A, 1200), dg(2, A, 1200), dg(3, A, 1200)];
        assert_eq!(can_coalesce(&run), Some(1200));
    }
    #[test]
    fn coalesce_none_single() { assert_eq!(can_coalesce(&[dg(1, A, 1200)]), None); }
    #[test]
    fn coalesce_none_mixed_dst() {
        assert_eq!(can_coalesce(&[dg(1, A, 1200), dg(2, B, 1200)]), None);
    }
    #[test]
    fn coalesce_none_mixed_len() {
        assert_eq!(can_coalesce(&[dg(1, A, 1200), dg(2, A, 1100)]), None);
    }
    #[test]
    fn coalesce_none_repeat_fate() {
        assert_eq!(can_coalesce(&[dg(1, A, 1200), dg(1, A, 1200)]), None);
    }
    #[test]
    fn coalesce_none_zero_len() {
        assert_eq!(can_coalesce(&[dg(1, A, 0), dg(2, A, 0)]), None);
    }
    #[test]
    fn max_run_len_caps_by_udp_ceiling_and_segment_cap() {
        // 1200-byte segments: 65507/1200 = 54, clamped to MAX_GSO_SEGMENTS_PER_SEND (32) ∧ hard_cap.
        assert_eq!(max_gso_run_len(1200, 64), 32);
        assert_eq!(max_gso_run_len(1200, 8), 8);
        assert_eq!(max_gso_run_len(0, 64), 1);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `cargo test -p yip-io --lib gso::`
Expected: FAIL — `can_coalesce` / `max_gso_run_len` not found.

- [ ] **Step 3: Implement `can_coalesce`, `max_gso_run_len`, and the constants**

Prepend to `crates/yip-io/src/gso.rs` (above the test module):

```rust
//! Shared fate-safe UDP GSO grouping rule, used by both the poll and io_uring
//! backends so the FEC(+addressing)-safety invariant lives in exactly one place:
//! a coalesced `UDP_SEGMENT` skb must never carry two datagrams of one FEC
//! object (same `fate`) and must never mix destinations.
use crate::poll::EgressDatagram;

/// Largest UDP payload the kernel accepts in one datagram.
pub(crate) const MAX_UDP_PAYLOAD: usize = 65_507;
/// Cap on segments coalesced into one `UDP_SEGMENT` send.
pub(crate) const MAX_GSO_SEGMENTS_PER_SEND: usize = 32;

/// If every datagram in `run` (len ≥ 2) shares one destination, one non-zero
/// byte length, and a pairwise-distinct `fate`, return that common length as the
/// GSO segment size; otherwise `None`. The single FEC(+addressing)-safety choke
/// point.
pub(crate) fn can_coalesce(run: &[EgressDatagram]) -> Option<u16> {
    if run.len() < 2 {
        return None;
    }
    let first = run.first()?;
    let first_len = first.bytes.len();
    if first_len == 0 {
        return None;
    }
    let segment_size = u16::try_from(first_len).ok()?;
    let first_dst = first.dst;
    for (i, d) in run.iter().enumerate() {
        if d.bytes.len() != first_len || d.dst != first_dst {
            return None;
        }
        if run[..i].iter().any(|prior| prior.fate == d.fate) {
            return None;
        }
    }
    Some(segment_size)
}

/// Max datagrams to coalesce for a given segment size — bounded by the 64 KB UDP
/// payload ceiling, `MAX_GSO_SEGMENTS_PER_SEND`, and the caller's `hard_cap`.
pub(crate) fn max_gso_run_len(segment_size: u16, hard_cap: usize) -> usize {
    let seg = usize::from(segment_size);
    if seg == 0 {
        return 1;
    }
    (MAX_UDP_PAYLOAD / seg).clamp(1, MAX_GSO_SEGMENTS_PER_SEND.min(hard_cap))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p yip-io --lib gso::`
Expected: PASS (7 tests).

- [ ] **Step 5: Write the failing test for `partition_fate_safe`**

Add to the `tests` module in `gso.rs`:

```rust
    fn runs(dgs: &[EgressDatagram], cap: usize) -> Vec<(u16, Vec<usize>)> {
        let mut out = Vec::new();
        partition_fate_safe(dgs, cap, &mut out);
        out.into_iter().map(|r| (r.segment_size, r.members)).collect()
    }

    #[test]
    fn partition_one_run_all_distinct_fate() {
        let d = [dg(1, A, 1200), dg(2, A, 1200), dg(3, A, 1200)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0, 1, 2])]);
    }
    #[test]
    fn partition_splits_repeat_fate_to_next_pass() {
        let d = [dg(1, A, 1200), dg(2, A, 1200), dg(1, A, 1200)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0, 1]), (1200, vec![2])]);
    }
    #[test]
    fn partition_splits_mixed_dst() {
        let d = [dg(1, A, 1200), dg(2, B, 1200)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0]), (1200, vec![1])]);
    }
    #[test]
    fn partition_splits_mixed_len() {
        let d = [dg(1, A, 1200), dg(2, A, 1100)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0]), (1100, vec![1])]);
    }
    #[test]
    fn partition_respects_hard_cap() {
        let d = [dg(1, A, 1200), dg(2, A, 1200), dg(3, A, 1200)];
        // cap 2 → first run takes 2, third defers to its own run.
        assert_eq!(runs(&d, 2), vec![(1200, vec![0, 1]), (1200, vec![2])]);
    }
    #[test]
    fn partition_singleton() {
        assert_eq!(runs(&[dg(7, A, 1200)], 64), vec![(1200, vec![0])]);
    }
    #[test]
    fn partition_zero_len_is_singleton_seg0() {
        assert_eq!(runs(&[dg(1, A, 0)], 64), vec![(0, vec![0])]);
    }
```

- [ ] **Step 6: Run to verify failure**

Run: `cargo test -p yip-io --lib gso::partition`
Expected: FAIL — `partition_fate_safe` / `GsoRun` not found.

- [ ] **Step 7: Implement `GsoRun` and `partition_fate_safe`**

Add to `gso.rs` (above the tests):

```rust
/// One fate-safe run: indices into the partitioned slice, plus the common
/// segment size (the shared byte length, or 0 for a non-coalescable singleton).
/// A run with `members.len() >= 2` is GSO-coalescable; length 1 sends plain.
pub(crate) struct GsoRun {
    pub segment_size: u16,
    pub members: Vec<usize>,
}

/// Greedily partition `dgs` into fate-safe runs (arrival order, multi-pass).
/// Each pass starts a run at the first remaining datagram and admits every later
/// remaining datagram that shares its `dst` and byte length, has a `fate` not yet
/// in the run, and fits under `max_gso_run_len(seg, hard_cap)`; the rest defer to
/// the next pass. A zero-length or > `u16` datagram forms its own `segment_size 0`
/// singleton. Reuses `out` (cleared first). Exactly one run is emitted per pass,
/// so the loop always makes progress and terminates.
pub(crate) fn partition_fate_safe(dgs: &[EgressDatagram], hard_cap: usize, out: &mut Vec<GsoRun>) {
    out.clear();
    let mut remaining: Vec<usize> = (0..dgs.len()).collect();
    while !remaining.is_empty() {
        let head_idx = remaining[0];
        let head = &dgs[head_idx];
        match u16::try_from(head.bytes.len()).ok().filter(|&l| l > 0) {
            None => {
                // Cannot be a GSO segment (empty or > u16): emit as a singleton.
                out.push(GsoRun { segment_size: 0, members: vec![head_idx] });
                remaining.remove(0);
            }
            Some(seg) => {
                let cap = max_gso_run_len(seg, hard_cap);
                let mut members = vec![head_idx];
                let mut deferred: Vec<usize> = Vec::new();
                for &i in &remaining[1..] {
                    let d = &dgs[i];
                    let admit = d.dst == head.dst
                        && d.bytes.len() == head.bytes.len()
                        && members.iter().all(|&k| dgs[k].fate != d.fate)
                        && members.len() < cap;
                    if admit {
                        members.push(i);
                    } else {
                        deferred.push(i);
                    }
                }
                out.push(GsoRun { segment_size: seg, members });
                remaining = deferred;
            }
        }
    }
}
```

- [ ] **Step 8: Run partition tests**

Run: `cargo test -p yip-io --lib gso::partition`
Expected: PASS (7 tests).

- [ ] **Step 9: Refactor `uring.rs` to delegate to the shared helper (behavior-preserving)**

In `crates/yip-io/src/uring.rs`, replace the body of `can_coalesce_gso_tagged` (lines ~590-613) with a call to the shared rule, and `max_gso_datagrams_for_segment` (lines ~693-700) likewise:

```rust
    fn can_coalesce_gso_tagged(datagrams: &[EgressDatagram]) -> Option<u16> {
        crate::gso::can_coalesce(datagrams)
    }

    fn max_gso_datagrams_for_segment(segment_size: u16) -> usize {
        crate::gso::max_gso_run_len(segment_size, MAX_GSO_DATAGRAMS)
    }
```

Delete the now-unused local `const MAX_UDP_PAYLOAD` (uring.rs:45) if nothing else references it; if the test at uring.rs:1883 references the literal only in a comment, leave that comment. Keep `MAX_GSO_SEGMENTS_PER_SEND`/`MAX_GSO_DATAGRAMS` as-is (they still gate `queue_udp_gso`).

- [ ] **Step 10: Run the uring GSO tests to confirm no behavior change**

Run: `cargo test -p yip-io --lib uring::`
Expected: PASS — all existing uring GSO tests still green (the refactor is behavior-preserving).

- [ ] **Step 11: Commit**

```bash
git add crates/yip-io/src/gso.rs crates/yip-io/src/lib.rs crates/yip-io/src/uring.rs
git commit -m "feat(yip-io): shared fate-safe GSO grouping (gso.rs); uring delegates to it"
```

---

### Task 2: `send_gso` primitive on the poll path

**Files:**
- Modify: `crates/yip-io/src/poll.rs` (add two `const`s near the top-of-file imports, and the `send_gso` fn beside `send_mmsg` at ~line 216; add a loopback test in the existing `mod tests` at line 493).

**Interfaces:**
- Consumes: `crate::std_to_sockaddr` (already imported, poll.rs:15), `EgressDatagram`.
- Produces: `fn send_gso(udp_fd: RawFd, run: &[EgressDatagram], segment_size: u16, dst: SocketAddr, payload: &mut Vec<u8>) -> io::Result<bool>` — `Ok(true)` = kernel accepted (or transient full buffer dropped it, same acceptable loss as `send_mmsg`); `Ok(false)` = GSO unsupported (`EIO`/`EINVAL`) — caller must latch GSO off and plain-send the run.

- [ ] **Step 1: Add the GSO cmsg constants**

Near the top of `crates/yip-io/src/poll.rs` (after the `use` block, before `pub trait Dispatch`):

```rust
/// `UDP_SEGMENT` cmsg payload is a single `u16` (the segment size).
const GSO_CONTROL_PAYLOAD_LEN: u32 = 2;
/// Control-message scratch space for one `UDP_SEGMENT` cmsg.
const GSO_CONTROL_SPACE: usize = 64;
```

- [ ] **Step 2: Write the failing loopback test for `send_gso`**

Add to `mod tests` in `poll.rs`. It is GSO-support-gated: if the kernel rejects GSO (`Ok(false)`), it skips rather than fails, so it is robust across CI kernels.

```rust
    #[test]
    fn send_gso_delivers_each_segment_when_supported() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();

        let run = vec![
            EgressDatagram { fate: 1, dst: rx_addr, bytes: vec![0xAA; 1000] },
            EgressDatagram { fate: 2, dst: rx_addr, bytes: vec![0xBB; 1000] },
            EgressDatagram { fate: 3, dst: rx_addr, bytes: vec![0xCC; 1000] },
        ];
        let mut payload = Vec::new();
        let accepted =
            send_gso(tx.as_raw_fd(), &run, 1000, rx_addr, &mut payload).expect("send_gso");
        if !accepted {
            return; // kernel lacks UDP_SEGMENT here — nothing to assert.
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut got = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok((n, _)) = rx.recv_from(&mut buf) {
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got.len(), 3, "GSO must segment into 3 separate datagrams");
        assert!(got.iter().all(|d| d.len() == 1000));
    }
```

*(add `use std::os::fd::AsRawFd;` in the test module if not present.)*

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p yip-io --lib send_gso_delivers`
Expected: FAIL — `send_gso` not found.

- [ ] **Step 4: Implement `send_gso_payload` (the cmsg body) and the `send_gso` wrapper**

Beside `send_mmsg` in `poll.rs`. `send_gso_payload` holds the single copy of the `UDP_SEGMENT` cmsg `unsafe` (modelled on `uring.rs::prepare_gso`, uring.rs:146-185); `send_gso` is a thin wrapper that concatenates a `&[EgressDatagram]` run into `payload` and calls it. Task 3 adds a second wrapper (`send_gso_indexed`) over the same body — so the `unsafe` lives in exactly one place.

```rust
/// Send an already-assembled `payload` (N × `segment_size` bytes) as ONE
/// `sendmsg` with a `UDP_SEGMENT` cmsg to `dst`. `Ok(true)`: accepted, or a
/// transient full send buffer dropped it (acceptable single-burst loss, as in
/// `send_mmsg`). `Ok(false)`: GSO unsupported (`EIO`/`EINVAL`) — caller latches
/// GSO off and plain-sends the run.
fn send_gso_payload(
    udp_fd: RawFd,
    payload: &[u8],
    segment_size: u16,
    dst: SocketAddr,
) -> io::Result<bool> {
    let (mut storage, addr_len) = std_to_sockaddr(dst);
    let mut iov = libc::iovec {
        // SAFETY: cast a shared slice to *mut for the iovec ABI; sendmsg only
        // reads through iov_base. `payload` outlives the syscall.
        iov_base: payload.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut control = [0u8; GSO_CONTROL_SPACE];
    // SAFETY: msghdr is plain-old-data; zeroed is a valid initial state we fully
    // populate below before the syscall.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::from_mut(&mut storage).cast::<libc::c_void>();
    msg.msg_namelen = addr_len;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: `CMSG_SPACE` is a pure size computation; no pointer deref.
    let cmsg_space = usize::try_from(unsafe { libc::CMSG_SPACE(GSO_CONTROL_PAYLOAD_LEN) })
        .expect("cmsg space fits usize");
    debug_assert!(cmsg_space <= control.len());
    msg.msg_controllen = cmsg_space;

    // SAFETY: `msg` points to valid in-frame iovec/control storage; we write
    // exactly one SOL_UDP/UDP_SEGMENT cmsg (a u16 segment size) into `control`.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            return Err(io::Error::other("missing first cmsg header"));
        }
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = usize::try_from(libc::CMSG_LEN(GSO_CONTROL_PAYLOAD_LEN))
            .expect("cmsg len fits usize");
        let seg_ptr = libc::CMSG_DATA(cmsg).cast::<u16>();
        *seg_ptr = segment_size;
    }

    // SAFETY: `msg` is fully initialised; its iov/name/control point into this
    // frame's storage, valid until sendmsg returns. MSG_NOSIGNAL suppresses SIGPIPE.
    let ret = unsafe { libc::sendmsg(udp_fd, &raw const msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        let e = io::Error::last_os_error();
        let raw = e.raw_os_error().unwrap_or(0);
        if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
            return Ok(true); // transient full buffer: drop this run (acceptable)
        }
        if raw == libc::EIO || raw == libc::EINVAL {
            return Ok(false); // GSO unsupported → caller latches off + plain-sends
        }
        return Err(e);
    }
    Ok(true)
}

/// Assemble `run`'s payloads into `payload` (reused) and GSO-send them.
fn send_gso(
    udp_fd: RawFd,
    run: &[EgressDatagram],
    segment_size: u16,
    dst: SocketAddr,
    payload: &mut Vec<u8>,
) -> io::Result<bool> {
    payload.clear();
    for dg in run {
        payload.extend_from_slice(&dg.bytes);
    }
    send_gso_payload(udp_fd, payload, segment_size, dst)
}
```

- [ ] **Step 5: Run the loopback test**

Run: `cargo test -p yip-io --lib send_gso_delivers`
Expected: PASS (delivers 3 datagrams, or skips if the CI kernel lacks `UDP_SEGMENT`).

- [ ] **Step 6: Commit**

```bash
git add crates/yip-io/src/poll.rs
git commit -m "feat(yip-io): send_gso — one sendmsg + UDP_SEGMENT cmsg on the poll path"
```

---

### Task 3: Wire fate-safe GSO into `flush_tx`

**Files:**
- Modify: `crates/yip-io/src/poll.rs` — add `struct GsoScratch`, rewrite `flush_tx` (lines 183-194) to partition+GSO+fallback, add `send_run_plain`, thread `&mut GsoScratch` through `drain_udp` (107-140), `drain_tun` (144-178), and `run_poll` (buffers at ~421-424 and the call sites at ~455-472).

**Interfaces:**
- Consumes: `crate::gso::{partition_fate_safe, GsoRun}`, `send_gso` (Task 2), `send_mmsg` (existing).
- Produces: `struct GsoScratch { enabled: bool, runs: Vec<crate::gso::GsoRun>, payload: Vec<u8> }`; new `flush_tx(udp_fd, tx, gso)` and `drain_udp(.., gso)` / `drain_tun(.., gso)` signatures.

- [ ] **Step 1: Write the failing end-to-end loopback test for `flush_tx`**

This test is **robust regardless of kernel GSO support**: whether GSO sends the run or the fallback plain-sends it, all datagrams must arrive. Add to `mod tests` in `poll.rs`:

```rust
    #[test]
    fn flush_tx_delivers_all_datagrams_gso_or_fallback() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();

        // fates [1,2,3,1]: one 3-run (0,1,2) + a deferred singleton (3).
        let mut tx: Vec<EgressDatagram> = [1u16, 2, 3, 1]
            .iter()
            .map(|&f| EgressDatagram { fate: f, dst: rx_addr, bytes: vec![f as u8; 1000] })
            .collect();
        let mut gso = GsoScratch::new();
        flush_tx(tx_sock.as_raw_fd(), &mut tx, &mut gso).expect("flush_tx");
        assert!(tx.is_empty(), "flush_tx must drain tx");

        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut count = 0;
        let mut buf = [0u8; 2048];
        while let Ok((n, _)) = rx.recv_from(&mut buf) {
            assert_eq!(n, 1000);
            count += 1;
        }
        assert_eq!(count, 4, "all four datagrams must arrive (GSO or plain fallback)");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-io --lib flush_tx_delivers`
Expected: FAIL — `GsoScratch` / new `flush_tx` signature not found.

- [ ] **Step 3: Add `GsoScratch` and `send_run_plain`, rewrite `flush_tx`**

In `poll.rs`, replace the current `flush_tx` (183-194) with:

```rust
/// Reusable scratch + latched capability for GSO sends on the poll path.
struct GsoScratch {
    /// Latched to `false` the first time a GSO send reports the feature
    /// unsupported (`EIO`/`EINVAL`); thereafter `flush_tx` uses plain sends only.
    enabled: bool,
    runs: Vec<crate::gso::GsoRun>,
    payload: Vec<u8>,
}

impl GsoScratch {
    fn new() -> Self {
        Self {
            enabled: true,
            runs: Vec::with_capacity(MAX_DATAGRAM_BATCH),
            payload: Vec::with_capacity(MAX_WIRE_DATAGRAM * crate::gso::MAX_GSO_SEGMENTS_PER_SEND),
        }
    }
}

/// Plain-send `run` via `send_mmsg` (looping partial sends). A momentarily-full
/// send buffer drops the remainder of the run (same acceptable single-burst loss
/// as the old per-datagram send).
fn send_run_plain(udp_fd: RawFd, run: &[EgressDatagram]) -> io::Result<()> {
    let mut sent = 0;
    while sent < run.len() {
        let n = send_mmsg(udp_fd, &run[sent..])?;
        if n == 0 {
            break;
        }
        sent += n;
    }
    Ok(())
}

/// Send everything queued in `tx`, then clear it. With GSO enabled, partitions
/// `tx` into fate-safe runs and sends each run of ≥2 as one `UDP_SEGMENT` send
/// (falling back to plain sends for singletons and, after latching GSO off, on
/// any "unsupported" result). Wire-identical to plain `send_mmsg`; the datagram
/// bytes, sizes, count, and destinations on the wire are unchanged.
fn flush_tx(udp_fd: RawFd, tx: &mut Vec<EgressDatagram>, gso: &mut GsoScratch) -> io::Result<()> {
    if !gso.enabled {
        let r = send_run_plain(udp_fd, tx);
        tx.clear();
        return r;
    }
    crate::gso::partition_fate_safe(tx, MAX_DATAGRAM_BATCH, &mut gso.runs);
    // Detach the runs scratch so we can borrow `gso.payload`/`gso.enabled` mutably
    // while iterating (the runs hold only indices into `tx`); restore it after.
    let runs = std::mem::take(&mut gso.runs);
    let mut outcome = Ok(());
    for run in &runs {
        if run.members.len() >= 2 && run.segment_size > 0 {
            let dst = tx[run.members[0]].dst;
            match send_gso_indexed(udp_fd, tx, &run.members, run.segment_size, dst, &mut gso.payload)
            {
                Ok(true) => {}
                Ok(false) => {
                    gso.enabled = false; // latch: GSO unsupported here
                    for &i in &run.members {
                        if let Err(e) = send_run_plain(udp_fd, std::slice::from_ref(&tx[i])) {
                            outcome = Err(e);
                            break;
                        }
                    }
                }
                Err(e) => outcome = Err(e),
            }
        } else {
            for &i in &run.members {
                if let Err(e) = send_run_plain(udp_fd, std::slice::from_ref(&tx[i])) {
                    outcome = Err(e);
                    break;
                }
            }
        }
        if outcome.is_err() {
            break;
        }
    }
    gso.runs = runs; // restore the reusable scratch allocation
    tx.clear();
    outcome
}
```

Add a thin index-based wrapper next to `send_gso` (Task 2) so `flush_tx` need not copy the run out of `tx`. It calls the same `send_gso_payload` body from Task 2 — the `unsafe` cmsg code stays in one place:

```rust
/// Like `send_gso`, but reads the run's datagrams from `tx` by `indices`
/// (avoids copying the run out of the egress batch).
fn send_gso_indexed(
    udp_fd: RawFd,
    tx: &[EgressDatagram],
    indices: &[usize],
    segment_size: u16,
    dst: SocketAddr,
    payload: &mut Vec<u8>,
) -> io::Result<bool> {
    payload.clear();
    for &i in indices {
        payload.extend_from_slice(&tx[i].bytes);
    }
    send_gso_payload(udp_fd, payload, segment_size, dst)
}
```

- [ ] **Step 4: Thread `&mut GsoScratch` through `drain_udp`, `drain_tun`, `run_poll`**

- `drain_udp` (107): add param `gso: &mut GsoScratch` (last), and change its two `flush_tx(udp_fd, tx)?` calls (134) to `flush_tx(udp_fd, tx, gso)?`. Its `#[expect(clippy::too_many_arguments, ...)]` already covers the extra arg — update the reason string to mention `gso`.
- `drain_tun` (144): add param `gso: &mut GsoScratch` (last); change `flush_tx(udp_fd, tx)?` (173, 176) to pass `gso`.
- `run_poll`: after `let mut tx_batch ...` (424) add `let mut gso = GsoScratch::new();`. Update the `drain_udp(...)` call (~455) and `drain_tun(...)` call (~472) to pass `&mut gso` as the final argument.

- [ ] **Step 5: Run the flush_tx test + the existing poll drain tests**

Run: `cargo test -p yip-io --lib poll::`
Expected: PASS — `flush_tx_delivers_all_datagrams_gso_or_fallback`, `send_gso_delivers...`, and all pre-existing `drain_udp_*` / TUN-egress tests green (the drain tests exercise the new `flush_tx` signature through `drain_*`).

- [ ] **Step 6: Clippy + fmt**

Run: `cargo clippy -p yip-io --all-targets -- -D warnings && cargo fmt -p yip-io`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/yip-io/src/poll.rs
git commit -m "feat(yip-io): fate-safe GSO in poll flush_tx with plain fallback + latch"
```

---

### Task 4: No-regression — workspace, netns loss recovery, uring path

**Files:**
- No source changes expected; this task is the correctness gate. If a regression appears, fix it in the offending file and re-run.

**Interfaces:** none (verification task).

- [ ] **Step 1: Full workspace test**

Run: `cargo test --workspace`
Expected: 0 failures.

- [ ] **Step 2: Build the release binary for the netns scripts**

Run: `cargo build --release -p yipd`
Expected: builds; `target/release/yipd` present.

- [ ] **Step 3: netns baseline tunnel**

Run: `sudo ./crates/yip-bench/tests/run-netns-tunnel.sh "$PWD/target/release/yipd"`
Expected: PASS (tunnel comes up, traffic passes).

- [ ] **Step 4: netns loss recovery (the critical FEC-safety gate)**

Run: `sudo ./crates/yip-bench/tests/run-netns-tunnel-loss.sh "$PWD/target/release/yipd"`
Expected: PASS — FEC still recovers under 10% netem loss **with GSO sends engaged**. This is the end-to-end proof that GSO did not break per-symbol loss-independence.

- [ ] **Step 5: ARQ integrity**

Run: `sudo ./crates/yip-bench/tests/run-arq-integrity.sh "$PWD/target/release/yipd"`
Expected: PASS.

- [ ] **Step 6: io_uring path still works**

Run: `YIP_USE_URING=1 sudo -E ./crates/yip-bench/tests/run-netns-tunnel.sh "$PWD/target/release/yipd"`
Expected: PASS — the uring backend (refactored in Task 1) still brings up a tunnel and passes traffic.

- [ ] **Step 7: Commit (only if a regression fix was needed; otherwise skip)**

```bash
git add -A && git commit -m "fix(yip-io): <regression fixed during 4a no-regression gate>"
```

---

### Task 5: Benchmark gate — measure the delta on the real EPYC boxes

**Files:**
- Modify: `crates/yip-bench/RESULTS.md` (append a "4a send-side GSO" section with before/after).

**Interfaces:** none (measurement task). Reuse the scratchpad probe scripts from the batched-I/O measurement (`solo-udp.sh`, the 4-box NAT chain) — these are throwaway, not committed.

- [ ] **Step 1: Deploy the 4a `yipd` to the two EPYC gateways**

Build `target/release/yipd` on this branch and `scp` it to `root@45.61.149.155:/root/yipd-4a` and `root@144.172.98.216:/root/yipd-4a`. **Do not overwrite `/root/yip.conf`** — write configs to `/root/yip-4a.conf` and start with an explicit config path and a non-conflicting listen port (e.g. 51830) so the user's existing tunnel is untouched.

- [ ] **Step 2: Re-run the isolated 4-box test**

Stand up the NAT chain `ny → Y1 ═yip═ Y2 → lv` exactly as in the batched-I/O measurement (DNAT/MASQUERADE on Y1/Y2, iperf server on lv, client on ny). Run UDP at rising rates (200M/500M/1G target, `-l 1000`) and sample the ingress gateway `yipd` CPU with a `/proc/<pid>/stat` delta sampler. Record delivered Mbit/s at saturation and the ingress CPU%.

- [ ] **Step 3: Re-run the direct box-to-box test**

iperf over the tunnel between Y1 and Y2 directly (TCP single, TCP -P8, UDP rising rate), sampling both `yipd` CPUs, as in the prior direct test.

- [ ] **Step 4: Record before/after in RESULTS.md**

Append a "4a send-side GSO (poll path)" section to `crates/yip-bench/RESULTS.md` with a table: metric | #54 baseline (batched I/O) | 4a (GSO) | delta. Use the prior run's recorded #54 numbers as the baseline column (isolated ~200 Mbit/s at 98% CPU; direct ~266 Mbit/s UDP). State honestly whether GSO moved the ceiling, and note the MASQUERADE-conntrack caveat for the isolated test.

- [ ] **Step 5: Tear down and restore the boxes**

Flush the NAT rules, remove any added addresses, restore `yip0` MTU, stop the 4a `yipd` and iperf servers, and confirm the user's original tunnel (self-cert v6, Y1↔Y2) still pings. Remove `/root/yipd-4a` and `/root/yip-4a.conf`.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-bench/RESULTS.md
git commit -m "bench(throughput-4a): real-hardware before/after for send-side GSO"
```

---

## Notes for the executor

- **Task 0 is a hard gate.** If the spike ratio is < ~1.3×, stop after Task 0 and report — do not implement Tasks 1–5.
- The FEC-safety choke point is `crate::gso::can_coalesce` / `partition_fate_safe`. Any change that could let two same-`fate` datagrams share a skb is a correctness regression; Task 4 Step 4 is its end-to-end guard.
- `unsafe` is confined to `yip-io`. Do not introduce `unsafe`, `as` numeric casts (except libc-ABI/discriminants), or bare `#[allow]` anywhere.
- Keep `send_gso_payload` the single home of the cmsg `unsafe`; `send_gso` and `send_gso_indexed` are thin wrappers over it.
