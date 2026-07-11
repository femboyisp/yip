# Throughput — Batched UDP I/O (sendmmsg/recvmmsg) — Design Spec

**Status:** draft (under review)
**Sub-project:** #4 (Throughput & Scalability). Lever 3 of the single-core-10-Gbit set
(cheap FEC ✓ → fast AEAD ✓ → **batched I/O**). On main after fast AEAD (0ca20e1).

---

## 1. Goal

Cut the per-packet UDP **syscall** cost on the default poll hot path by batching sends and
receives with `sendmmsg(2)`/`recvmmsg(2)`, so I/O drops from ~1–3 µs/packet to ~0.1–0.3 µs.
With levers 1 (FEC ~0.32 µs) and 2 (AEAD ~0.63 µs) merged, per-packet I/O is now the
dominant single-core cost; batching it is the remaining big lever toward the ~7 Gbit/s
single-core projection on the target VPS.

## 2. Why

`yip_io::poll::run_poll` (the default data-plane loop; also used under QUIC-less operation)
drives the UDP + TUN fds from one epoll thread. Today:
- `drain_udp` (poll.rs:102) does one `recvfrom` **per datagram** in a loop.
- `drain_tun` (poll.rs:183) calls `d.on_tun` per TUN packet and sends each resulting
  `EgressDatagram` via one `sendto` (poll.rs:244) — and each TUN packet produces **multiple**
  FEC symbols, so the tx path issues ~2–3 `sendto`s **per packet**.

`yip-io` already contains working `sendmmsg`/`recvmmsg` mechanics (`PlainIo::send_batch`/
`recv_batch`), but they are **unwired** on the `run_poll` hot path AND insufficient for yipd's
multi-peer data plane: `send_batch(&[&[u8]])` targets a *connected* socket (no per-datagram
destination), and `recv_batch` returns byte counts but **drops the source address** that
`Dispatch::on_udp` needs. So this milestone adds **addressed** batch syscalls and wires them in.

## 3. Architecture

**Opportunistic batching — batch what is already ready, never wait.** When epoll reports a fd
readable there is usually a *burst* of queued packets; we drain the whole burst and issue one
syscall for it. Under light load (one packet ready) it is still one syscall. **This is
latency-neutral: no artificial "wait to fill a batch."** The only added delay is draining a
burst that already exists (a few µs, under load only).

### 3.1 Addressed batch syscalls (`yip-io`)
Add two free functions in `yip-io` (raw-fd based, so `run_poll` uses them without holding a
`UdpSocket`), reusing the existing `sendmmsg`/`recvmmsg` `unsafe` mechanics but carrying
per-datagram addresses via each `mmsghdr`'s `msg_name`:
- `send_mmsg(udp_fd, datagrams: &[EgressDatagram]) -> io::Result<usize>` — one `sendmmsg`,
  each datagram to its own `dst` (`msg_name`). Returns the count accepted; the caller loops to
  send any remainder (partial `sendmmsg`).
- `recv_mmsg(udp_fd, bufs: &mut [[u8; MAX_WIRE_DATAGRAM]], lens: &mut [usize], srcs: &mut [SocketAddr]) -> io::Result<usize>`
  — one `recvmmsg`, capturing each datagram's `src` from `msg_name`. Returns the count.
Both cap at `MAX_DATAGRAM_BATCH` (existing const, 64). The existing connected `send_batch`/
`recv_batch` remain for their current callers; the addressed variants are the hot-path ones.

### 3.2 RX drain (`drain_udp`)
Replace the per-datagram `recvfrom` loop with: `recv_mmsg` to drain up to 64 queued datagrams
in one syscall; for each `(src, bytes)`, `d.on_udp(src, bytes, now_ms)` and forward its
outcome (TUN write and/or a UDP reply, the latter accumulated into the tx batch — §3.3). Loop
`recv_mmsg` until it returns fewer than the batch size (socket drained).

### 3.3 TX drain (`drain_tun`) — where the win concentrates
Restructure to accumulate then batch-send:
1. Read the burst of TUN packets (TUN stays per-packet — a char device yields one packet per
   read); for each, `d.on_tun(inner, now_ms)` → its `EgressDatagram`s.
2. **Accumulate all egress across the burst** into one reusable batch `Vec<EgressDatagram>`
   (owned by `run_poll`, cleared per drain — no per-burst allocation).
3. One `send_mmsg(udp_fd, &batch)` for the whole burst (looping on partial sends).
`tick` feedback and `on_udp`-produced UDP replies are appended to the same batch mechanism.
So N TUN packets × M symbols collapse from N·M `sendto`s to one (or few) `sendmmsg`.

### 3.4 Buffers
`run_poll` owns reusable arrays: an `[[u8; MAX_WIRE_DATAGRAM]; 64]` recv buffer + `[usize; 64]`
lens + `[SocketAddr; 64]` srcs, and a `Vec<EgressDatagram>` tx batch. Allocated once before the
loop, reused every iteration.

## 4. Invariants

1. **Latency-neutral:** no code path waits to accumulate a batch; batching only amortizes a
   burst that is already queued. A single ready packet still traverses recv→process→send with
   one recv syscall and one send syscall.
2. **FEC loss-independence preserved:** `sendmmsg` puts each datagram on the wire as its **own
   independent UDP packet** (no coalescing) — so two symbols of one FEC object are never lost
   as a unit. (This milestone does **NOT** use GSO/`UDP_SEGMENT`, so the `EgressDatagram.fate`
   field is irrelevant here; GSO is a later optional add-on.)
3. **Correctness unchanged:** the same datagrams, to the same destinations, in the same order
   within a batch, reach the wire as before — only the syscall count changes. End-to-end loss
   recovery and ARQ must still pass.
4. **`unsafe` contained in `yip-io`:** the new `sendmmsg`/`recvmmsg` code lives in `yip-io`
   (already exempt from `forbid(unsafe_code)`); `yipd` and other crates stay unsafe-free. Every
   `unsafe` block carries a `// SAFETY:` comment (existing convention).
5. **Partial syscalls handled:** `sendmmsg` may accept fewer than requested → loop the
   remainder; `recvmmsg` may return fewer than the batch → treated as "burst drained."
6. **Scope:** the `poll` path only. `io_uring` (`uring.rs`, opt-in `YIP_USE_URING`) already has
   its own GSO batching — untouched. **QUIC mode uses its own `run_quic` loop — out of scope.**

## 5. Testing

- **Unit (`yip-io`):** `send_mmsg` delivers each datagram to its correct `dst` (two peers,
  distinct destinations, both receive their own datagram); `recv_mmsg` returns the correct
  `src` per datagram; partial-send loop covers all datagrams; empty-batch is a no-op.
- **Existing poll tests preserved:** `drain_udp_delivers_datagram`,
  `drain_udp_drains_multiple_datagrams`, `drain_udp_forwards_dispatch_out_udp_to_peer`, and the
  TUN-egress tests must pass against the batched drains (adjust to the new call shape if
  needed, without weakening what they assert).
- **Netns no-regression + throughput:** `run-netns-tunnel.sh`, `run-netns-tunnel-loss.sh`
  (loss recovery still works with batched sends), `run-arq-integrity.sh` green; and the
  **headline metric** — `run-iperf-compare.sh` (or the netem/iperf harness) single-core TCP
  throughput **before vs after**, recorded in `crates/yip-bench/RESULTS.md`. Expect a clear
  jump (I/O syscalls were the dominant remaining cost).
- Both drivers still start (poll default; `YIP_USE_URING=1` unaffected).

## 6. Scope & files

- **Modify:** `crates/yip-io/src/lib.rs` (add `send_mmsg`/`recv_mmsg` addressed free functions,
  reusing the existing `sendmmsg`/`recvmmsg` mechanics + `MAX_DATAGRAM_BATCH`),
  `crates/yip-io/src/poll.rs` (`drain_udp` → `recv_mmsg`; `drain_tun` → accumulate + `send_mmsg`;
  reusable buffers in `run_poll`; keep `send_to_udp`/`send_to_tun` for TUN writes + fallback),
  `crates/yip-bench/RESULTS.md`.
- **Untouched:** `uring.rs`, the QUIC path (`bin/yipd/src/quic.rs`), `Dispatch` trait +
  `EgressDatagram` type (unchanged — the batch reads `dst`/`bytes` off existing fields), the
  crypto/FEC pipeline, `yip-wire`.

**Out of scope (later, if measurements justify):** GSO/`UDP_SEGMENT` coalescing (using the
`fate` field), AF_XDP zero-copy, TUN-side batching (`IFF_VNET_HDR`/GSO), QUIC-path batching.
