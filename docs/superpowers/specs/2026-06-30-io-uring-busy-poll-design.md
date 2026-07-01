# Unified io_uring busy-poll data loop — design

**Status:** approved (brainstorming, 2026-06-30)
**Scope:** sub-project #1 (core data plane), the latency/efficiency lever
**Predecessors:** M1–M6 + M5.5, bench harness (PR #1), throughput pass (PR #2),
feedback loop + ARQ (PR #3), follow-ups (PR #4), CI guards (PR #5).

## Goal

Replace yipd's two-thread, `Arc<Mutex>`-shared, `sendmmsg`/`recvmmsg` data plane
with a **single-threaded event loop** over both the UDP and TUN fds. Primary
wins: lower per-packet latency (no thread handoff, no lock waits, no blocking
syscalls — yip's north star), **elimination of every `Arc<Mutex>`** in the data
path, and **UDP GSO** on egress. An `io_uring` busy-poll driver is preferred; an
`epoll` driver is the fallback where io_uring is unavailable.

This is explicitly a **single-core** design. Scaling raw throughput across cores
(multi-queue flow sharding) is a separate, later milestone and is out of scope.

## Success criteria

- yipd runs a single-threaded data loop with **no `Arc<Mutex>`** in the data path
  (session, transport, loss detector, sent-log, retx buffer all single-owner).
- The `io_uring` driver services **both** the UDP socket and the TUN device from
  **one ring**, with a provided-buffer ring bounded < 1 MiB (fits `RLIMIT_MEMLOCK
  = 1 MiB` on the dev box) and GSO on egress.
- A working **fallback** (`epoll`) when io_uring is unavailable; both drivers pass
  the identical netns suite.
- **No wire-format change** — existing peers interoperate; the netns tests (ping,
  ping-under-loss, arq-integrity) pass with the io_uring driver **forced on**.
- Measured: per-packet/RTT latency no worse than (target: better than) the
  two-thread baseline; clean-link throughput holds or improves (GSO + no locks).
- `unsafe` confined to `yip-io`; yipd stays `#![forbid(unsafe_code)]`.

## Background — current state

- `bin/yipd/src/tunnel.rs`: two threads (`egress`, `ingress`), each wrapping the
  connected `UdpSocket` in `yip_io::PlainIo` (`send_batch`/`recv_batch` =
  `sendmmsg`/`recvmmsg` with `MSG_WAITFORONE`). Shared state — `Session`,
  `Transport`, `SentLog`, `LossDetector`, `RetxBuffer` — behind `Arc<Mutex>`. The
  ingress thread also runs the loss detector, feedback emitter, control-packet
  handler, and ARQ retransmit.
- `yip_io::IoUringIo` (io-uring 0.7.13) is a **per-op** `submit_and_wait`
  placeholder (one syscall per packet) — no batching, UDP-only, unused by yipd.
- `RLIMIT_MEMLOCK = 1 MiB` on the dev box; kernel 6.18 does **not** charge the
  basic ring against memlock (the basic ring test passes here), but **registered
  buffers** do count — so any provided-buffer ring must stay well under 1 MiB.
- TUN fd: `yip_device::TunTap` (currently `split()` into blocking reader/writer).
  The io_uring driver needs the raw fd(s) for `RECV`/`WRITE`/`READ` submissions.

## Design

### 1. `DataPlane` — the mutex-free, I/O-free correctness core

Extract **all** per-packet logic out of the thread closures into a single struct
that owns the concrete state and performs no I/O and holds no locks:

```
pub struct DataPlane {
    session: Session,
    transport: Transport,
    detector: LossDetector,
    sent_log: SentLog,
    retx: RetxBuffer,
    codec: WireCodec,
    conn_tag: u64,
    // reused scratch buffers for framing; counters; feedback/log timers
}
```

Methods are pure transforms over borrowed input → borrowed/owned output; a driver
supplies the bytes and performs the actual reads/writes:

- `on_tun_packet(&mut self, inner: &[u8], now_ms: u64) -> &[Datagram]` — seal →
  FEC-encode → frame each symbol (into reused buffers) → record in sent-log + retx
  buffer; returns the framed egress datagrams (with the `Data` prefix) to send.
- `on_udp_datagram(&mut self, dg: &[u8], now_ms: u64) -> Outcome` — branch on the
  packet-type prefix. `Data`: deframe → `frame_to_symbol` → detector.on_seen →
  transport.decode → (on decode) detector.on_delivered + session.open → yields an
  **inner packet to write to TUN**. `Control`: session.open (auth) →
  detector.on_seen/on_delivered → LossReport::decode → per-class `observe_loss` →
  yields **ARQ retransmit datagrams** for eligible NACKs. Returns an `Outcome`
  enum describing what the driver must emit (a TUN write and/or UDP sends), all
  referencing reused buffers.
- `tick(&mut self, now_ms: u64) -> Option<&[u8]>` — if the feedback interval has
  elapsed, build+seal a `LossReport` `Control` packet and return it to send; also
  drives the periodic diagnostic logs (bulk ratio, ARQ retransmit count).

`DataPlane` has **no threads, no locks, no sockets** — it is unit-tested end to
end (feed it TUN packets and UDP datagrams, assert the emitted datagrams / TUN
writes / observe_loss effects). This is where data-plane correctness is proven,
independent of either driver. Lives in a new `bin/yipd/src/dataplane.rs`.

### 2. `UringDriver` — the io_uring busy-poll driver (the only new `unsafe`)

Lives in `yip-io` (the sole `unsafe`-permitted crate) as a reusable component the
daemon drives; the daemon passes it the two raw fds and a `&mut DataPlane`-shaped
callback interface (a small trait so yip-io does not depend on yipd types).

- **One ring** servicing the UDP socket fd and the TUN fd.
- **Receives:** a **provided-buffer ring** (io_uring buffer group), `N` buffers of
  `MAX_WIRE_DATAGRAM` (2048) — bounded < 1 MiB (e.g. `N = 256` → 512 KiB).
  Multishot `RECV` armed on the UDP fd; `READ` (pooled or multishot where
  supported) on the TUN fd. `user_data` encodes the source (udp-recv / tun-recv /
  a send-completion slot).
- **Loop:** `submit_and_wait`/busy-poll → drain the completion queue → for each
  recv completion, hand the borrowed buffer to the callback (`on_udp_datagram` or
  `on_tun_packet`), collect the emitted datagrams/TUN-writes, submit them as
  `SEND`/`WRITE` SQEs, then **return the recv buffer to the ring** (re-provide) →
  re-arm any exhausted recvs → call `tick` on a cadence.
- **GSO egress:** a packet's FEC symbols are same-size framed datagrams to one
  peer → coalesce them into one buffer and submit a single `SEND` with the
  `UDP_SEGMENT` cmsg (segment size = one framed datagram). Fallback to individual
  `SEND`s if GSO is rejected.
- **Buffer-lifetime discipline (the SAFETY core):** recv buffers are owned by the
  ring; a completion "borrows" one by buffer-id until the callback returns and we
  re-provide it. Send buffers must outlive their `SEND` completion: they live in a
  **bounded in-flight table** keyed by `user_data`, freed only when the send CQE
  arrives. Every `unsafe` block carries a `// SAFETY:` comment stating the
  invariant. No buffer is ever aliased between a live SQE and the callback.

### 3. `PollDriver` — the fallback

Where io_uring is unavailable (old kernel, or memlock too tight for even the small
buffer ring), a single thread runs an `epoll` loop over the UDP + TUN fds set
**non-blocking**, driving the **same** `DataPlane` callback via `PlainIo`-style
batched `recvmmsg`/`sendmmsg`. Same single-threaded, lock-free structure as the
uring driver — only the I/O mechanism differs. Reuses the existing
`set_socket_buffers` + batched-send/recv code.

### 4. Startup selection

At daemon start, after the handshake and TUN creation, probe io_uring (attempt to
build the ring + register the buffer group within memlock); on success use
`UringDriver`, else `PollDriver`. A `YIP_FORCE_POLL=1` env (test-only) forces the
fallback so both paths are exercised in CI. The netns tests run once with each
driver.

## Components touched

- `bin/yipd/src/dataplane.rs` (new): `DataPlane` + `Outcome`/`Datagram` types +
  its unit tests.
- `bin/yipd/src/tunnel.rs`: drop the two-thread + `Arc<Mutex>` model; build a
  `DataPlane`, probe, and run the chosen driver. Egress/ingress closures removed.
- `crates/yip-io/`: `UringDriver` (io_uring busy-poll over two fds, buffer ring,
  GSO, in-flight table) + a small driver trait/callback interface; `PollDriver`
  (epoll fallback) or a shared poll helper; keep `PlainIo`/`set_socket_buffers`.
  The old per-op `IoUringIo` may be retired or folded into `UringDriver`.
- `crates/yip-device`: expose the raw TUN fd(s) for submission (a `as_raw_fd` /
  non-blocking accessor) without breaking the existing `split()` API used by tests.
- `crates/yip-bench`: latency + throughput comparison (io_uring vs poll driver).

## Wire compatibility

No wire-format change. The `DataPlane` produces byte-identical framing to the
current daemon (same seal → FEC → `symbol_to_frame` → `Data` prefix; same
`Control` packet). Interop and anti-DPI posture are unchanged; the netns
`tunnel_netns` suite is the gate, run against **both** drivers.

## Testing

- **`DataPlane` unit tests** (no I/O, the bulk of correctness): a TUN packet
  produces the expected egress datagrams; a looped-back egress datagram decodes to
  the original inner; a `Control` packet drives `observe_loss` and emits ARQ
  retransmits for eligible NACKs; `tick` emits feedback on cadence. Mirror the
  scenarios currently only covered end-to-end.
- **`UringDriver` loopback unit tests** in yip-io: UDP↔UDP over loopback with the
  small buffer ring (< 1 MiB so they run under the dev-box memlock); assert
  datagrams round-trip and buffers are correctly recycled; skip-on-Err if the ring
  can't be built (mirrors the existing io_uring test discipline).
- **End-to-end (the real gate):** the netns tests (`ping_across_yipd_tunnel`,
  `ping_across_yipd_tunnel_under_loss`, `arq_recovers_bulk_loss`) must pass with
  **`UringDriver` active** AND with `YIP_FORCE_POLL=1`. Wire both into CI.
- **Bench:** re-run the latency (ping RTT across the tunnel) and throughput
  harness with each driver; record the latency delta (target: io_uring ≤ poll ≤
  the old two-thread RTT) and that clean-link throughput holds/improves with GSO.

## Out of scope (deferred)

- Multi-queue / multi-core throughput sharding (the throughput-scaling milestone).
- AF_XDP backend.
- L2/TAP path; rekey; wire-auth `object_id` binding (separate milestones).
- Zero-copy TX (registered send buffers) beyond what GSO provides.

## Risks

- **`unsafe` buffer lifetimes** (the top risk). Mitigated by: confining all
  io_uring code to `UringDriver` in yip-io; the bounded in-flight send table; the
  provide/borrow/re-provide recv discipline; SAFETY comments on every block; and
  the loopback unit tests + netns gate. If the buffer discipline proves too
  error-prone, the `DataPlane` split means we can ship `PollDriver` alone and keep
  iterating on the uring driver without blocking the lock-removal win.
- **memlock (< 1 MiB) too tight for the buffer ring** on some hosts. Mitigated by
  sizing the ring small (256 × 2 KiB) and falling back to `PollDriver` on ring/
  registration failure.
- **Single-core throughput regression** vs two parallel threads for bulk. Accepted
  per the approved scope (latency-first); measured in the bench, and multi-queue
  is the named future lever if bulk regresses meaningfully.
- **Fallback parity.** Both drivers drive the identical `DataPlane`, and the netns
  suite runs against both, so behavior cannot silently diverge.
- **TUN in the ring.** If multishot `READ` on the TUN fd is unreliable on the
  target kernel, fall back to pooled single `READ` re-submits (still one ring, one
  thread) — a driver-internal detail, no architecture change.
