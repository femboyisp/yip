# Data-plane throughput pass — design

**Status:** approved (brainstorming, 2026-06-30)
**Scope:** sub-project #1 (core data plane), incremental optimization milestone
**Predecessors:** M1–M6 + M5.5 (data plane) and the benchmark harness (merged `d190a8b`).

## Goal

Raise yipd's single-core data-plane throughput — especially the clean-link case
the benchmark exposed as weak (yip ~157 Mbit/s single-stream vs in-kernel
WireGuard ~1 Gbit/s at a 10 ms RTT) — **without changing the wire format**, while
keeping latency and loss-recovery (the proven thesis) intact.

This is an **incremental, measurement-driven pass**, not the unified io_uring
busy-poll rewrite (that remains deferred — see Out of Scope).

## Success criteria

- A repeatable per-stage profile of the egress and ingress pipelines on the dev
  box, attributing per-packet CPU to each stage.
- A measured throughput improvement on `run-iperf-compare.sh` /
  `run-scp-compare.sh` (clean-link bulk), with each optimization validated
  individually against the bench (kept or reverted on its own merits).
- No wire-format change: existing peers interoperate; the anti-DPI posture is
  unchanged; all netns ping/tunnel tests stay green.
- Loss-recovery behaviour unchanged at every nonzero loss rate (FEC still works
  exactly as before whenever repair > 0).

## Background — current state

- **yipd bypasses yip-io.** `bin/yipd/src/tunnel.rs` uses a raw
  `std::net::UdpSocket` with two blocking threads (egress: TUN→UDP, ingress:
  UDP→TUN) and `Arc<Mutex>` around `Session` and `Transport`. yip-io's
  `DataPlaneIo` is not used by the daemon at all.
- **Per-symbol syscalls + allocations.** Egress calls `udp_tx.send()` once **per
  FEC symbol**, each preceded by a `Vec::with_capacity` for the framed datagram.
  Ingress calls `recv()` once per datagram.
- **FEC encode dominates per-packet CPU.** Hot-path benches (release): AEAD seal
  ≈ 2 µs, **RaptorQ encode ≈ 25 µs**, wire frame ≈ 0.5 µs; a `send()` syscall is
  ≈ 1 µs. So a ~3-symbol packet spends ~25 µs in FEC vs ~3 µs in syscalls — FEC is
  ~80 % of egress CPU, capping a single core near ~380 Mbit/s **independent of
  syscall batching**. `Encoder::new` runs a full intermediate-symbol solve per
  object, every packet, even when no repair symbols are requested.
- **yip-io's `IoUringIo` is a placeholder:** one `submit_and_wait` per single
  packet, UDP-only, no batching — no faster than a plain syscall today.

## Design

The work proceeds in three ordered phases. Phase 1 is a gate: it tells us the
real cost ranking before we optimize, so we attack measured bottlenecks rather
than assumed ones. Phases 2–3 are independent and each validated on its own.

### Phase 1 — Profile first (the gate)

Add a focused, reproducible per-stage profile of both pipelines:

- **Egress:** seal → FEC encode → frame → send, timed per stage.
- **Ingress:** recv → deframe → FEC decode → open → TUN write, timed per stage.

Implementation options (pick the lightest that gives attributable numbers): a
dev-only timing harness in `yip-bench` that drives the real `Session`/`Transport`
over representative packets (extends the existing `examples/`-style approach), or
opt-in stage timers behind a cfg/env flag in the daemon loop. The deliverable is
a committed table attributing per-packet µs per stage. Expected outcome: FEC
encode dominates egress; decode + open dominate ingress. The rest of the plan is
written against that expectation but **the profile result governs** — if it
surprises us, Phase 2 re-targets.

### Phase 2 — Attack the dominant cost (FEC encode)

Two levers, in priority order:

**2a. Bypass RaptorQ when repair = 0 (headline lever).**
The adaptive controller (`yip-transport::control`) already drives the repair
ratio toward zero on clean/realtime flows. When the controller requests **zero
repair symbols** for an object, the encoder currently still constructs a full
`Encoder` and solves for intermediate symbols. Instead, emit the object's source
symbol(s) directly as framed datagrams with **no encode step** — the receiver
already reconstructs single-/full-source objects without repair, so this is
wire-compatible and uses the existing class/flags + payload-id scheme (no new
wire fields, no new packet type, no anti-DPI signature). This removes ~25 µs/
packet on exactly the clean-link case. Must be exactly equivalent on the wire to
"encode with 0 repair" so a peer cannot tell the difference; verified by a
round-trip test asserting byte-identical symbols.

**2b. Amortize encode over larger objects for the Bulk class.**
For `FlowClass::Bulk`, coalesce more bytes per `Encoder` construction so the
fixed setup cost spreads across more payload, accepting a small, **bounded**
latency increase that applies only to Bulk (realtime/default unaffected). The
exact coalescing bound is set from the Phase-1 numbers; gated so it never delays
a realtime/latency-sensitive flow. Kept only if the bench shows a real bulk gain.

### Phase 3 — I/O batching + finally use yip-io

Real, cheap wins, and the milestone where yipd stops bypassing yip-io:

- **Batched `DataPlaneIo`.** Extend the trait with batched send/recv:
  - egress: send many framed datagrams in one syscall via **UDP GSO**
    (`UDP_SEGMENT`), with a **sendmmsg** fallback when GSO is unsupported;
  - ingress: **recvmmsg** to read a batch per syscall (and enable `UDP_GRO`).
  Implement in `PlainIo` via `libc` (the unsafe stays contained in yip-io).
  `IoUringIo` keeps its per-op path for now — batched ring submit is the deferred
  rewrite, but it will implement the same batched trait later.
- **Remove per-symbol allocation.** Frame a packet's symbols into reused buffers
  rather than a fresh `Vec` per symbol.
- **Size socket buffers** (`SO_SNDBUF`/`SO_RCVBUF`) to absorb bursts.
- **Wire yipd onto yip-io.** Replace the daemon's raw `UdpSocket` send/recv with
  yip-io's (batched) `DataPlaneIo`, selecting the backend via `select_backend`.

Note on batching vs latency: per-packet GSO only coalesces the few symbols of one
TUN packet (modest). Cross-packet batching would add queuing latency, so it is
**not** done for realtime traffic; any opportunistic cross-packet coalescing is
limited to the Bulk class and bounded as in 2b.

## Components touched

- `crates/yip-transport` — `FecEncoder::encode` gains the repair==0 bypass (2a);
  Bulk coalescing (2b). Decode path unchanged.
- `crates/yip-io` — batched `DataPlaneIo` methods + `PlainIo` GSO/sendmmsg/
  recvmmsg implementation (3).
- `bin/yipd/src/tunnel.rs` — egress/ingress loops use the batched API + reused
  buffers; daemon adopts yip-io instead of raw `UdpSocket` (3).
- `crates/yip-bench` — Phase-1 profile harness; before/after measurement runs.

## Wire compatibility & anti-DPI

No wire-format change. The FEC-bypass path (2a) must produce byte-identical
output to "encode with zero repair," so it is invisible to a peer and to a DPI
observer. No new packet types, header fields, or constant offsets are introduced.
Existing peers (and the committed netns tunnel test) interoperate unchanged.

## Testing & measurement

- Phase 1 profile committed as a reproducible harness + a results table.
- `yip-transport`: round-trip test asserting the repair==0 bypass yields symbols
  byte-identical to the encoded-with-0-repair path, and that decode recovers the
  object; keep ≥90 % coverage.
- `yip-io`: loopback unit tests for batched send/recv (GSO + sendmmsg fallback +
  recvmmsg), skipping gracefully where a sockopt is unsupported.
- End-to-end: `run-iperf-compare.sh` / `run-scp-compare.sh` before/after tables;
  existing netns ping + `tunnel_netns` tests stay green (no wire change).
- Each optimization is measured independently and kept only if it helps.

## Out of scope (explicitly deferred)

- The unified single io_uring ring busy-poll loop servicing both UDP + TUN fds
  with multishot recv + batched submit (the spec's grand vision).
- Removing the `Arc<Mutex>` / splitting tx/rx session state (not the bottleneck).
- Multi-core flow sharding / multi-queue.
- AF_XDP backend.
- Rekey, ARQ, deadline FEC eviction, L2/TAP — tracked separately.

## Risks

- **Profile says something other than FEC dominates.** Mitigated by the Phase-1
  gate: we re-target Phase 2 to whatever actually dominates.
- **GSO/GRO unsupported on a target kernel.** Mitigated by sendmmsg fallback and
  graceful sockopt probing (mirrors yip-io's existing backend-probe pattern).
- **2a wire divergence.** Mitigated by the byte-identical round-trip test gate;
  if it cannot be made identical, 2a is dropped rather than risking interop.
