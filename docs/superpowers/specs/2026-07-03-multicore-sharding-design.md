# Multi-core throughput sharding — per-peer engine model

**Status:** design (not implemented; issue #10). Depends on the multi-peer data
plane (sub-project #2 control plane) — see Dependency below. For the current
single-peer tunnel this design is a **no-op** (1 peer → 1 engine → 1 core); it is
specified now so the seams exist before multi-peer lands.
**Scope:** issue #10, sub-project #1 (data plane) forward-looking. Recommends a
model, names the syscalls/files, defers the harder single-flow variant.
**Predecessors:** issue #6 (single-thread `DataPlane` + epoll `PollDriver`, lock
removal — Phase A), issue #7 (`UringDriver` + busy-poll,
`docs/superpowers/specs/2026-06-30-io-uring-busy-poll-design.md`), issue #17
(GSO fate tags, `docs/superpowers/specs/2026-07-02-uring-gso-fate-tags-design.md`).
The io_uring-vs-poll investigation (Phase B bench, `crates/yip-bench/README.md`)
proved the bottleneck is **CPU per packet, not I/O**.

## Goal

Let yip's aggregate throughput scale with core count on a **multi-peer mesh** by
running N independent single-thread data-plane **engines**, one pinned per core,
with peers assigned to engines by hash — **no shared state, no locks**, preserving
the Phase A per-flow single-thread latency win. Design it so it is a no-op for
today's single peer and drops in cleanly when the multi-peer peer table exists.

Explicitly **not** the goal: parallelizing one point-to-point flow across cores.
That is regime (B) below — described, and deferred.

## Background (verified in code)

- **Throughput is CPU-bound on one thread, not I/O-bound.** RaptorQ FEC encode
  (~24µs/packet) plus AEAD seal dominate `DataPlane::on_tun_packet`
  (`bin/yipd/src/dataplane.rs:180`): seal → `Transport::encode` → frame each
  symbol. All of it runs on the single epoll/uring thread. The Phase B bench
  (`crates/yip-bench/README.md`) showed io_uring vs poll is a wash on throughput —
  confirming the limiter is per-packet compute, so the only lever left is more
  cores.
- **yipd today is a single-peer, connected-UDP, point-to-point tunnel.**
  `tunnel.rs::run` (`bin/yipd/src/tunnel.rs:45`) binds one `UdpSocket`, runs one
  handshake, then `sock.connect(peer_addr)` (line 64) so every `recv`/`send` is
  tied to exactly one 4-tuple. It builds **one** `DataPlane`
  (`DataPlane::new`, line 93) and hands its fd pair to a single driver loop —
  `run_uring` or `run_poll` (lines 104-108). There is no peer table; the data
  plane hardwires `SINGLE_REMOTE_PEER_ID = 1`
  (`bin/yipd/src/dataplane.rs:35`).
- **Consequence for `SO_REUSEPORT`:** kernel `SO_REUSEPORT` load-balances
  **incoming datagrams across sockets by 4-tuple hash**. With one connected flow
  there is exactly one 4-tuple, so every datagram hashes to the same socket —
  `SO_REUSEPORT` sharding buys **nothing** for a single point-to-point link. It
  only helps when there are **many** peers (many 4-tuples) to spread. This is the
  central constraint the design must confront: the useful parallelism is
  **across peers**, and today there is only one.
- **Each `DataPlane` is already a self-contained, lock-free, I/O-free state
  machine** (`bin/yipd/src/dataplane.rs:112`): it owns its `yip_crypto::Session`,
  `Transport` (FEC encoder/decoder + adaptive repair controller), `Codec`,
  `SentLog`, `RetxBuffer`, `LossDetector`, `MacTable`, feedback/rekey timers, and
  reused scratch buffers. Nothing in it is `Arc`/`Mutex`/`static`-mutable. **This
  is the enabling property**: N independent `DataPlane`s can run on N threads with
  zero coordination as long as each owns its own fds. The single-thread ownership
  is load-bearing for correctness (per-flow ordering, monotone AEAD counter,
  `Transport` reassembly) — the design must not break it.
- **The driver already abstracts the fd pair.** `run_poll(udp_fd, tun_fd, d)`
  (`crates/yip-io/src/poll.rs:237`) and `run_uring(udp_fd, tun_fd, d)`
  (`crates/yip-io/src/uring.rs:1062`) each take a `(udp_fd, tun_fd)` and a
  `&mut impl Dispatch`. Neither assumes it is the *only* driver in the process —
  they just loop on the two fds they were given. So "one engine = one driver loop
  over its own (udp_fd, tun_fd) on its own thread" needs **no change to the
  driver loops themselves**.
- **Driver selection is env-gated, not multi-instance today.**
  `tunnel.rs` (line 104) picks uring vs poll via `YIP_USE_URING` +
  `uring_available()`; busy-poll via `YIP_URING_BUSYPOLL`
  (`crates/yip-io/src/uring.rs:217`). These are per-process env reads; N engines
  would each honor the same env, so this composes without change.
- **The TUN device is created once, single-queue.**
  `TunTap::create` (`crates/yip-device/src/lib.rs:114`) issues `TUNSETIFF`
  (`0x4004_54ca`, line 13) with `IFF_TUN|IFF_NO_PI` or `IFF_TAP|IFF_NO_PI`
  (lines 129-134). There is **no** `IFF_MULTI_QUEUE` today — the device exposes
  exactly one queue fd, which caps kernel↔userspace TUN throughput at one core's
  worth of copies regardless of how many engines exist. Multi-queue TUN is a
  required piece of this design (below).
- **Config is static two-peer key=value** (`bin/yipd/src/config.rs`): no engine
  count, no multi-peer list. Adding an `engines=N` key is a small, forward-compat
  addition (unknown keys are already silently ignored, line 136).

## Non-goals

- **No single-flow parallelism in this milestone.** Splitting one peer's crypto+FEC
  across cores (regime B) is described in Alternatives and deferred — it
  reintroduces the cross-thread coordination Phase A deleted.
- **No control-plane / peer-table implementation here.** This spec assumes a
  peer table arrives from sub-project #2 and defines only the sharding seam it
  plugs into. It does not design discovery, NAT traversal, or the peer table's
  storage.
- **No wire-format change.** Sharding is a host-local scheduling decision; the
  bytes on the wire are identical. Peer→engine assignment is derived locally from
  the peer identity, never signaled.
- **No change to `DataPlane`'s internals or the `Dispatch` trait.** An engine *is*
  a `DataPlane` + a driver loop; the parallelism lives one level up, in a new
  supervisor in `yipd`.
- **No NUMA-aware memory placement in v1** (pinning only; see Risks).
- **No dynamic per-packet work-stealing between engines** — that would share state.
  Rebalancing is coarse-grained (peer reassignment), not per-packet.

## Success criteria

- On a multi-peer workload (M peers, M ≥ N), **aggregate** encrypt+FEC throughput
  scales ~linearly with engine count N up to core count, measured by a new
  multi-peer bench (see Testing).
- **Per-flow latency and ordering are unchanged** vs. the single-engine baseline:
  a given peer's traffic is handled start-to-finish on **one** engine (session
  affinity), so there is no cross-core reordering, no added queue hop, no lock.
  Single-peer RTT must match today's `PollDriver`/`UringDriver` numbers exactly
  (it *is* the same code path with N=1).
- **Single peer / `engines=1` is byte-for-byte the current behavior** — one
  `DataPlane`, one socket, one TUN queue, one thread. The netns gate
  (`ping_across_yipd_tunnel*`, `l2_tap_ping_or_arp_across_tunnel`) passes
  unchanged.
- Composes with the existing `YIP_USE_URING` / `YIP_URING_BUSYPOLL` opt-ins: each
  engine independently runs poll or uring(+busy-poll) per the same env.

## Architecture

### 0. The two regimes, stated plainly

| | (A) Per-peer engine sharding | (B) Single-flow crypto worker-pool |
|---|---|---|
| Scales | aggregate throughput across **many peers** | one **fat point-to-point** link |
| Mechanism | N independent `DataPlane` engines, peer→engine by hash | one `DataPlane`'s crypto+FEC fanned to a worker pool |
| Shared state | **none** (each engine fully independent) | queues + per-flow ordering + shared send path |
| Latency | unchanged (single-thread per flow) | added queue hop; reorder risk |
| Fits yip's mesh vision | **yes** | only the degenerate single-link case |
| Recommendation | **PRIMARY** | **DEFERRED** (Alternatives §B) |

**Recommendation: build (A).** It matches the P2P-mesh product (throughput is an
aggregate-over-peers quantity there), preserves the Phase A single-thread win with
zero locks, and reuses the existing driver loops verbatim. (B) only helps the
single-link fat-pipe case and pays for it by re-adding the coordination Phase A
removed; defer until that case is a measured need.

### 1. The engine and the supervisor

Define an **Engine** = one OS thread that owns:

- one `DataPlane` (its own session/FEC/feedback/rekey/MAC state),
- one UDP socket fd bound to the shared `listen` addr with `SO_REUSEPORT`,
- one TUN/TAP **queue** fd from a single shared multi-queue device,
- one driver loop (`run_poll` or `run_uring`, chosen by the existing env),
- optional CPU affinity pinning to core `i`.

A new **supervisor** in `bin/yipd/` (proposed `bin/yipd/src/supervisor.rs`)
replaces the single-driver tail of `tunnel.rs::run`:

1. Resolve `engine_count` = `engines=N` from config, or `available_parallelism()`
   when `engines=auto`/absent (clamped to `[1, num_cpus]`).
2. Create the TUN/TAP device **once** with `IFF_MULTI_QUEUE` and open
   `engine_count` queue fds against it (see §3).
3. Open `engine_count` UDP sockets with `SO_REUSEPORT` on the same `listen` addr
   (see §2).
4. For each engine `i`: build its `DataPlane`, spawn a thread, optionally
   `sched_setaffinity` to core `i`, then call the existing `run_poll`/`run_uring`
   with that engine's `(udp_fd, tun_fd)`.
5. Join / propagate the first fatal driver error (each driver loop only returns on
   fatal I/O error, matching today).

For `engine_count == 1` the supervisor collapses to exactly today's code path
(one socket, single-queue TUN, no `SO_REUSEPORT`/`IFF_MULTI_QUEUE` needed, no
extra thread) — the no-op guarantee.

### 2. Symmetric UDP: `SO_REUSEPORT`, and why it needs multi-peer

Each engine's UDP socket sets `SO_REUSEPORT` before `bind(listen)`
(`setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, 1)`). The kernel then hashes each
**inbound** datagram's 4-tuple to one socket in the reuseport group, so a given
peer's packets always land on the **same** engine's socket — the kernel does the
ingress steering for free, and it is **consistent with** our egress-side
peer→engine assignment as long as both derive from the same flow identity (see
§5, session affinity).

**Critical caveat (the single-peer no-op):** with one connected flow there is one
4-tuple, so the kernel sends *all* ingress to one socket — the other engines'
sockets go idle. `SO_REUSEPORT` sharding therefore delivers scaling **only** with
many peers. For `engines=1` we skip `SO_REUSEPORT` entirely and keep the current
`connect(peer_addr)` connected-socket fast path. For `engines>1` the sockets are
**unconnected** (they must receive from many peers), so the data plane moves from
`recv`/`send` to `recvfrom`/`sendto` with an explicit peer address — a change the
multi-peer data plane needs regardless of sharding (it is a peer-table
prerequisite, not sharding-specific).

Egress symmetry: an engine sends a given peer's datagrams out of *its own*
socket. Because the peer was assigned to this engine by the same hash the kernel
uses for ingress, ingress and egress for that peer share one socket and one core —
no cross-engine hand-off.

### 3. Symmetric TUN: one device, N queues via `IFF_MULTI_QUEUE`

The TUN/TAP device is created **once** and shared; parallelism comes from
**multiple queue fds** on that one device, not multiple devices (multiple devices
would mean multiple IPs/routes — wrong model). Extend `yip-device`:

- Add `IFF_MULTI_QUEUE` (`0x0100`) to the `TUNSETIFF` flags when engine_count > 1
  (`crates/yip-device/src/lib.rs`, alongside the existing `IFF_TUN`/`IFF_TAP`/
  `IFF_NO_PI` at lines 9-11).
- Add an API to open **additional queue fds** on the already-created device: each
  extra queue is a fresh `open("/dev/net/tun")` + `TUNSETIFF` with the **same
  device name** and the `IFF_MULTI_QUEUE` flag. The kernel attaches each such fd
  as another queue of the same interface.
- The kernel then **flow-steers** egress (kernel→userspace) frames across the
  queue fds by inner-flow hash (its `tun_select_queue` / RSS-like logic), so
  different inner flows are read by different engines in parallel — the TUN-side
  analogue of `SO_REUSEPORT`.
- Each engine passes its own queue fd as `tun_fd` to its driver loop. No driver
  change: `run_poll`/`run_uring` already take an opaque `tun_fd`.

Optionally set `TUNSETSTEERINGEBPF` later for explicit, deterministic steering
that matches our peer→engine hash; v1 relies on the kernel's default queue
selection (see Risks — steering correctness).

For `engine_count == 1`, `IFF_MULTI_QUEUE` is omitted and the device is the exact
single-queue device created today.

### 4. Each engine runs its own poll or uring(+busy-poll) loop

No new loop is written. Each engine thread calls the **existing**
`yip_io::poll::run_poll` or `yip_io::uring::run_uring` on its `(udp_fd, tun_fd)`,
selected by the same `YIP_USE_URING` / `uring_available()` / `YIP_URING_BUSYPOLL`
logic that lives in `tunnel.rs` today (hoisted into the supervisor so every engine
makes the same choice). Consequences:

- **Busy-poll interaction:** `YIP_URING_BUSYPOLL` spins the CQ, burning a core
  while active. With one busy-poll engine per core that is the intended trade
  (dedicate the core to the flow). With `engines=auto` = num_cpus **and**
  busy-poll on, every core spins — acceptable for a throughput benchmark, wasteful
  at idle; document that busy-poll + auto-engines is a max-throughput setting, not
  a default. Consider capping busy-poll engines below num_cpus (Risks).
- GSO fate-tagging (issue #17) is per-engine and unaffected: each engine's
  `DataPlane` still emits `EgressDatagram{fate,bytes}` and its `UringDriver`
  coalesces within that engine only. No cross-engine GSO batching (would need
  shared state) — out of scope by construction.

### 5. Peer → engine assignment, session affinity, and rebalancing

- **Assignment:** `engine_index = hash(peer_id) % engine_count`, where `peer_id`
  is the peer's self-certifying identity (public-key-derived; the same value the
  future peer table keys on). This is a pure function of stable peer identity, so
  it is **deterministic and stateless** — any part of the system computes the same
  engine for a peer without coordination.
- **Session affinity (the ordering guarantee):** all of a peer's work —
  ingress decode, egress encode, that peer's `LossDetector`/`RetxBuffer`/rekey
  timers, its monotone AEAD counter — lives in exactly **one** engine's
  `DataPlane` for the life of the session. A single peer's ordered flow therefore
  never crosses cores, so there is no reordering and no shared counter. This is
  what preserves the Phase A per-flow latency property. (Handshake/rekey for a
  peer also runs on its owning engine, so epoch state stays local.)
- **Ingress/egress consistency:** the kernel's `SO_REUSEPORT` 4-tuple hash and our
  `hash(peer_id)` must land the same peer on the same engine. Since a connected
  peer has a fixed 4-tuple ↔ peer_id mapping, we make the two agree by *binding
  peers to engines at handshake-completion time* on whichever engine's socket the
  kernel delivered the handshake to — i.e. the engine that receives a peer's first
  packet **owns** it, and records the mapping. This sidesteps any mismatch between
  the kernel's hash and ours (we adopt the kernel's placement rather than fighting
  it). The `hash(peer_id) % N` form above is the fallback for engine selection on
  the **egress-initiated** (we-initiate) side, where we choose the socket.
- **Rebalancing:** peer count and engine count are both slow-changing. v1 uses
  **static** assignment (a peer keeps its engine for the session's life);
  reassignment happens only on session teardown/re-handshake. No live migration of
  session state between engines in v1 (that would need a stop-the-world handoff of
  `DataPlane` state — deferred, see follow-ups). Uneven load from a hot peer is a
  known limitation of static hashing (Risks).

### 6. Config / CLI surface

Add one key to `bin/yipd/src/config.rs` (`Config` struct + parser match arm):

```
engines = auto        # default: available_parallelism(), clamped to num_cpus
engines = 1           # explicit single-engine = today's behavior (no-op path)
engines = 4           # N pinned engines
```

- Absent ⇒ treat as `auto`. Unknown/other keys already ignored (forward-compat).
- `engines=1` selects the connected-socket, single-queue, no-thread fast path
  (no `SO_REUSEPORT`, no `IFF_MULTI_QUEUE`, no pinning).
- Env opt-ins are unchanged and **orthogonal**: `YIP_USE_URING`,
  `YIP_URING_BUSYPOLL` apply per-engine. Optionally add `YIP_ENGINE_PIN=0` to
  disable affinity pinning for debugging.

## Alternatives

### (A-alt) One shared socket + one shared TUN queue, N worker threads

Instead of `SO_REUSEPORT` + `IFF_MULTI_QUEUE`, keep one socket and one TUN fd and
have N threads all `recvfrom`/`read` them, dispatching by peer hash to per-peer
state behind a lock or concurrent map. **Rejected:** reintroduces shared mutable
state and lock contention on the hot path — the exact thing Phase A (#6) deleted —
and the single shared fd's syscall path becomes the new bottleneck. The
kernel-steered symmetric model (chosen) keeps each engine's fds private and
lock-free.

### (B) Single-flow crypto worker-pool — DEFERRED

For a **single** fat point-to-point link (one peer, multi-Gbit) where regime (A)
gives no speedup (one peer ⇒ one engine ⇒ one core), parallelize the *stage* that
is expensive, like WireGuard's per-CPU encryption queues:

- One reader thread pulls inner packets off the (single) TUN queue.
- Distribute inner packets to a pool of crypto+FEC workers **by inner-5-tuple
  hash** (so each inner flow stays on one worker → preserves per-inner-flow
  ordering).
- Workers seal + FEC-encode in parallel (the ~24µs/packet cost, now on N cores).
- A send stage emits to the shared UDP socket, **re-serializing per FEC object**
  so a single RaptorQ object's symbols keep their invariants and the peer's
  monotone AEAD counter stays consistent.

**Why deferred:**

- It reintroduces exactly what Phase A removed: cross-thread queues, per-flow
  ordering bookkeeping, and a shared/contended send path (the AEAD counter and
  `Transport` object numbering are single-writer today; parallel workers need a
  coordination point). Bigger change, breaks the single-thread simplicity that
  makes the current data plane easy to reason about.
- It only helps the **single-link fat-pipe** case. yip's product is a P2P mesh;
  the common throughput question is aggregate-over-peers, which (A) solves without
  any of this cost.
- The two are **composable later**: (A) shards peers across engines; (B) could,
  much later, parallelize a *single hot peer* within its engine. Do (A) first;
  reach for (B) only if a single-peer multi-Gbit link is a measured requirement.

Recommend filing (B) as its own future issue, gated on a demonstrated single-link
bottleneck.

### (C) Do nothing until proven

The orchestration spec (`2026-07-01-issues-7-11-orchestration-design.md`, Wave 3
item 4) already says #10 is "deferred until throughput bottleneck proven." This
spec is the **design on the shelf** for when that proof arrives (or when
multi-peer lands and aggregate scaling is wanted). It is a no-op until then, so
writing it now costs nothing and de-risks the multi-peer milestone.

## Component / file changes

- `bin/yipd/src/supervisor.rs` **(new)** — engine-count resolution, device+socket
  fan-out, thread spawn + optional affinity, driver-loop selection hoisted from
  `tunnel.rs`, join/error propagation. `engine_count==1` collapses to today's
  path.
- `bin/yipd/src/tunnel.rs` — `run()` delegates its post-handshake tail to the
  supervisor. The single-peer handshake stays here for now; multi-peer handshake
  handling is a sub-project #2 concern (supervisor gains a per-engine
  accept/handshake role then).
- `bin/yipd/src/config.rs` — add `engines: EngineCount` (`Auto | N`) field + parse
  arm; default `Auto`. Unit tests mirror the existing per-key tests
  (`engines=auto|1|4`, invalid value error).
- `crates/yip-device/src/lib.rs` — add `IFF_MULTI_QUEUE` const; a
  `create_multiqueue(name, kind, count) -> Vec<TunTap>` (or
  `attach_queue(name, kind)`) that opens N queue fds with the flag on one device;
  keep single-queue `create` as the `count==1` path. `#![...]`/`unsafe` stays
  confined here (already the only `unsafe` outside `yip-io`).
- `crates/yip-io/` — **add a `SO_REUSEPORT` socket-builder helper** (small; next to
  `set_socket_buffers`) and an **affinity helper** (`sched_setaffinity` wrapper).
  **No change to `run_poll`/`run_uring` loops** — they already take opaque fds.
- `crates/yip-bench/` — new multi-peer aggregate-throughput scenario + README
  section (see Testing). Existing single-peer RTT bench is the N=1 regression
  baseline.
- No change to `bin/yipd/src/dataplane.rs` internals, the `Dispatch` trait, or the
  wire format.

## Data flow (multi-engine, egress and ingress for one peer P assigned to engine i)

1. Kernel delivers P's inner packets to **engine i's TUN queue fd** (kernel
   flow-steering across the `IFF_MULTI_QUEUE` queues).
2. Engine i's driver loop reads it → `DataPlane_i::on_tun_packet` → seal + FEC +
   frame (all on core i) → `EgressDatagram`s.
3. Engine i sends them out **its own `SO_REUSEPORT` UDP socket** to P.
4. P's replies arrive; the kernel's reuseport 4-tuple hash delivers them to
   **engine i's UDP socket** (same engine that owns P).
5. Engine i's driver loop → `DataPlane_i::on_udp_datagram` → decode + open →
   writes the inner packet to **engine i's TUN queue** → kernel injects to the
   stack.
6. No step ever touches another engine's state; a different peer Q on engine j
   runs the identical flow fully in parallel on core j. On the wire: identical
   bytes to single-engine.

## Testing / validation plan

**Correctness (must hold at every engine count):**
- `engines=1` netns suite (`ping_across_yipd_tunnel`,
  `ping_across_yipd_tunnel_under_loss`, `l2_tap_ping_or_arp_across_tunnel`) under
  both `poll` and `uring` — byte-identical to today (no-op guarantee).
- New netns multi-peer test: 3+ peers to one hub with `engines>1`; assert every
  peer's ping/ARP succeeds and (via logs) each peer is pinned to a single engine
  for its session (session-affinity / ordering check).
- Per-inner-flow ordering: a single peer's ordered stream (e.g. TCP throughput
  test or sequenced UDP) shows **no reordering** vs. `engines=1` — proves session
  affinity keeps a flow on one core.

**Throughput scaling (the point of the issue):**
- New `yip-bench` multi-peer scenario: M synthetic peers driving bulk traffic
  through a hub; measure aggregate encrypt+FEC throughput at `engines ∈ {1,2,4,8}`.
  Success = ~linear scaling up to core count on the many-peer workload.
- Single-peer throughput at `engines=8` must **equal** `engines=1` (one peer can
  only use one engine) — this both proves the no-regression property and
  demonstrates *why* regime (B) would be needed for the single-link case.

**Latency (must not regress):**
- Single-peer RTT at `engines=auto` vs. `engines=1` vs. today's baseline — within
  noise. Confirms the supervisor/threading adds no per-flow latency.

**Composition:**
- Run the multi-peer throughput scenario under each of `poll`, `uring`,
  `uring+busy-poll` to confirm each engine honors the env opt-ins independently.

## Risks / open questions

| Risk / question | Notes |
|---|---|
| **Hard dependency on the multi-peer data plane (sub-project #2).** | (A) needs a peer table and unconnected `recvfrom`/`sendto` egress with explicit peer addresses. Until that lands, this design is a **no-op** (1 peer → 1 engine). Ship the seams (`engines=` config, multi-queue device API, `SO_REUSEPORT` helper, supervisor) so multi-peer drops in; keep `engines=1` as the only exercised path meanwhile. |
| **Single-peer no-op is intentional but must be loud.** | Docs/CLI must state that `engines>1` does nothing for one peer, and that a single fat link needs regime (B), not (A). Avoid users expecting single-flow speedup. |
| **TUN `IFF_MULTI_QUEUE` flow-steering correctness.** | The kernel's default queue selection may not match our peer→engine hash, so a peer's egress-inject and its ingress-decode could land on different engines (state is per-engine → wrong-engine writes). Mitigation: adopt "first-packet engine owns the peer" (§5) so we follow the kernel's placement; optionally pin steering with `TUNSETSTEERINGEBPF` in a follow-up for determinism. Needs empirical verification on the target kernel. |
| **`SO_REUSEPORT` rebalancing on socket add/remove.** | The reuseport group's hash buckets shift when sockets are added/removed, potentially moving an established peer to a different socket/engine mid-session. Because engine count is fixed at startup in v1 (no live add/remove), this is avoided; flagged for when dynamic engine scaling is wanted. |
| **Per-engine rekey / feedback / loss state is isolated — correct, but no cross-engine aggregation.** | Each engine's `LossDetector`/controller sees only its own peers. That is correct (state is per-peer), but any *global* rate/loss view (e.g. a future congestion-fairness policy across peers) would need explicit aggregation. Out of scope; note for control plane. |
| **Static hashing → hot-peer imbalance.** | One very heavy peer saturates its engine while others idle; no work-stealing (would share state). Acceptable for v1 aggregate-scaling; live session migration between engines is a deferred follow-up. |
| **NUMA / pinning.** | v1 pins engine i→core i via `sched_setaffinity` but does no NUMA-aware memory placement; on multi-socket boxes a socket buffer may be remote to its engine's core. Deferred; expose `YIP_ENGINE_PIN=0` to disable pinning for debugging/comparison. |
| **Busy-poll × auto-engines burns every core.** | `YIP_URING_BUSYPOLL` + `engines=auto`(=num_cpus) spins all cores. Document as a max-throughput bench setting; consider capping busy-poll engine count below num_cpus, or leaving one core unpinned for the OS. |
| **Regime (B) not addressed.** | Single-link fat-pipe scaling is explicitly out of scope; file as its own issue gated on a measured single-peer bottleneck. |
| **Human sign-off requested on:** the "first-packet engine owns the peer" affinity rule vs. an explicit `TUNSETSTEERINGEBPF` + matching `SO_REUSEPORT` eBPF (`SO_ATTACH_REUSEPORT_EBPF`) for fully deterministic symmetric steering; the `engines=auto` default (vs. defaulting to 1 and opting in); and whether v1 should ship any of the multi-queue plumbing before sub-project #2, or hold the entire spec until the peer table exists. | — |
