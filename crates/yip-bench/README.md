# yip-bench — benchmark harness

Hot-path micro-benchmarks (via Criterion) and a `tc netem` latency/loss harness
comparing yip against kernel WireGuard.

## Quick run

```sh
# Micro-benchmarks (no privileges needed)
cargo bench -p yip-bench

# Full netem comparison (root required — creates netns, TUN, tc rules)
cargo test -p yip-bench --test netem_bench -- --nocapture --test-threads=1
# or the standalone script:
sudo bash crates/yip-bench/tests/run-compare.sh
```

---

## Hot-path micro-benchmark results

Environment: Linux 6.18 · AMD Ryzen 5 7640U · `cargo bench -p yip-bench`

| Benchmark | Median ns/op | Notes |
|---|---|---|
| `aead_seal_1300` | ~1 957 ns | ChaCha20-Poly1305 seal, 1300-byte payload |
| `aead_open_1300` | ~3 930 ns | **seal + open** (counter must advance to avoid replay rejection); open alone ≈ 2 µs |
| `wire_frame_1300` | ~512 ns | Header serialise + SipHash auth tag + keyed header-protection XOR |
| `wire_deframe_1300` | ~553 ns | Inverse of frame |
| `transport_encode_1300` | ~24 028 ns | RaptorQ FEC encode (classify → object-encode, includes repair-symbol generation) |

### Honesty note on `aead_open_1300`

The 3 930 ns figure measures **seal then open** in a single Criterion iteration.
The benchmark does this because the AEAD session maintains a sliding anti-replay
window keyed on the sender's nonce counter: replaying the same ciphertext without
advancing the counter would be rejected as a replay attack.  The true cost of
`open` alone is approximately **2 µs** (the 3 930 ns minus the ~1 957 ns seal).
The benchmark comment in `benches/hotpath.rs` explains this in detail.

---

## yip vs kernel WireGuard — netem loss comparison

The headline result:

> **yip's RaptorQ FEC recovers nearly all injected packet loss — for a ~0.2 ms
> latency premium over WireGuard — while WireGuard, which has no FEC, passes the
> loss straight through.**

At 10 % injected loss, yip showed ~1 % effective loss (FEC recovered ~90 % of
dropped packets); WireGuard showed ~17 %.  The latency cost is negligible: yip's
RTT tracks WireGuard's to within ~0.2 ms (both dominated by the 10 ms netem
delay), so the FEC encode/decode pipeline is effectively free on the wire.

> **Build note (important):** these figures require a **release** `yipd`.  yipd's
> RaptorQ data path is ~75× slower compiled without optimizations (the GF(256)
> matrix math dominates), which throttles throughput to a few Mbit/s and adds
> ~2 ms of per-packet latency — entirely a build-mode artifact, not FEC cost.  The
> harness and CI now build `--release`, so the comparison against in-kernel
> WireGuard is apples-to-apples.

The effective-loss law (expected values; a single 100-ping sample scatters around
these): with independent per-direction loss *p* and proactive repair symbols, yip
effective loss ≈ *p*² (only the residual that escapes FEC recovery survives);
WireGuard, which has no FEC, passes loss through at roughly *p* up to the
bidirectional bound 1 − (1 − *p*)² (a round-trip ping must deliver on both hops).
At *p* = 10 % that band is ≈ 10–19 %; the committed table below shows WireGuard at
17 % and yip at 1 % — read the **gap** between the columns, not the exact per-cell
value.

### Latest sweep

The table below comes from the most recent run of `tests/run-compare.sh` with a
**release** `yipd`.  The harness overwrites `RESULTS.md` each time it runs; the
figures here are from the committed baseline run (2026-06-30, kernel 6.18,
AMD Ryzen 5 7640U):

| injected % | yip effective loss | WG effective loss | yip RTT (ms) | WG RTT (ms) |
|---|---|---|---|---|
| 0 % | 0 % | 0 % | 10.54 | 10.32 |
| 1 % | 0 % | 2 % | 10.57 | 10.33 |
| 3 % | 0 % | 4 % | 10.54 | 10.36 |
| 5 % | 0 % | 8 % | 10.55 | 10.39 |
| 10 % | 1 % | 17 % | 10.54 | 10.34 |

Measurement: `ping -c 100 -i 0.05 -W 1`; netem: `loss X% delay 5ms` applied
symmetrically to both veth ends.  100 pings per data point — stochastic, so
run-to-run variance of ±1–3 % at low loss rates is expected.

See `RESULTS.md` for the raw output from the most recent automated run.

---

## scp throughput under loss

`tests/run-scp-compare.sh` (driven by the `scp_throughput_comparison` test) copies
a **20 MB** file with `scp` across each tunnel under `tc netem` loss of 0/5/10 %,
times the transfer, and reports MB/s.  Each transfer is wrapped in `timeout 120`;
a timeout or failure records 0 MB/s rather than failing the harness.  `scp` layers
its own SSH AEAD on top of *both* tunnels equally, so the SSH crypto cost cancels
out of the comparison — what differs is how each tunnel carries TCP under loss.

The thesis: yip's RaptorQ FEC masks loss from TCP (so throughput holds), while
WireGuard's TCP sees real retransmits + congestion backoff (so it collapses).

### Measured table (release `yipd`)

The harness builds `yipd --release` (see the build note above):

| loss% | yip_MBps | wg_MBps |
|-------|----------|---------|
| 0     | 13.83    | 35.17   |
| 5     | 2.44     | 0.37    |
| 10    | 1.02     | 0.16    |

(kernel 6.18, AMD Ryzen 5 7640U; 20 MB payload; netem `loss X% delay 5ms`
symmetric on both veth ends; sshd on port 2222.  Single-stream scp over a 10 ms
RTT path — high run-to-run variance, so read the **crossover**, not the cells.)

### Honest interpretation

The two tunnels trade places as loss rises — this crossover *is* the result:

1. **On a clean link, yip is slower.** At 0 % loss WireGuard moves ~35 MB/s vs
   yip's ~14 MB/s.  WireGuard is in-kernel and has no FEC; yip is single-threaded
   userspace, seals + FEC-encodes every packet, and runs a smaller inner MTU
   (1184, see below).  This is the price of the FEC pipeline on a link that does
   not need it.  (Raw single-stream throughput on a *zero-delay* link is higher
   still — iperf3 over the tunnel reaches ~270 Mbit/s; the 10 ms netem delay here
   caps a single TCP stream well below that.)

2. **Under loss, yip dominates.** yip degrades gracefully (13.8 → 2.4 → 1.0 MB/s)
   because FEC repair symbols hide the drops from TCP, so TCP rarely backs off.
   WireGuard collapses (35 → 0.37 → 0.16 MB/s) — classic TCP-over-lossy-link
   congestion backoff.  By 5 % loss yip is already ~6× WireGuard, and ~6× again at
   10 %.  yip *resists* loss; WireGuard *succumbs* to it.

That crossover is the whole thesis: yip spends a little clean-link throughput to
buy large loss resilience — the right trade for the lossy/contended links yip
targets, and irrelevant on a clean fast path where both are fast enough.

A secondary inefficiency was also fixed while investigating: the harness now sets
the `yip0` TUN **MTU to 1184**.  yip seals each inner packet (+16-byte AEAD tag)
and FEC-encodes it into fixed 1200-byte symbols; a full 1500-byte inner segment
seals to 1516 bytes and splits into *two* source symbols (plus repair), fanning
every TCP segment into 2+ UDP datagrams.  Capping the inner MTU so the sealed
packet fits one symbol (`inner + 16 ≤ 1200 ⇒ inner ≤ 1184`) keeps each segment to
one source symbol — yip's analogue of WireGuard auto-setting `wg0` to MTU 1420.

---

## UDP loss recovery: yip vs UDPspeeder

`tests/run-fec-compare.sh` (driven by the `udp_loss_recovery_comparison` test) is
the **FEC-vs-FEC headline**. UDPspeeder is yip's closest competitor — both add
rateless/blockwise FEC over UDP to recover packet loss. This harness measures
raw UDP **delivered-loss** with a pure-UDP sequenced blaster (`udp_tx.py` /
`udp_rx.py`: send *N* seq-numbered datagrams, count unique sequence numbers at
the receiver) across three transports under the same netem loss:

- **bare-link** — straight veth, no FEC (the loss floor)
- **UDPspeeder** — Reed-Solomon FEC forwarder, `f20:10` (20 source : 10 repair)
- **yip** — RaptorQ-FEC tunnel (release `yipd`)

A pure-UDP blaster is required because iperf3 needs a TCP control channel even in
`-u` mode, so it cannot traverse a UDP-only forwarder like UDPspeeder.

### Measured table (release `yipd`)

N = 20000 packets at 4000 pps; netem `loss X% delay 5ms` symmetric on both veth
ends (kernel 6.18, AMD Ryzen 5 7640U):

| loss% | bare_recv% | udpspeeder_recv% | yip_recv% |
|-------|------------|------------------|-----------|
| 0     | 100.0      | 100.0            | 100.0     |
| 5     | 95.2       | 100.0            | 99.8      |
| 10    | 90.0       | 100.0            | 99.0      |

### Honest interpretation

The bare-link column is the control: it delivers ~`100 − loss`% exactly, proving
the netem impairment is real. Both FEC transports then recover almost all of it.
UDPspeeder's fixed-block `f20:10` Reed-Solomon recovered **100%** at both 5% and
10% loss here; yip's RaptorQ recovered **99.8%** and **99.0%** — within a hair of
perfect. The takeaway is that yip is in the same league as the purpose-built
FEC forwarder on raw loss recovery, while *also* being a full encrypted L2/L3 VPN
(UDPspeeder is only a loss-hiding UDP relay with no tunneling or crypto of its
own). Read the **gap from the bare column**, not the last decimal between the two
FEC columns — both effectively erase the loss.

---

## Throughput matrix: yip vs WireGuard vs OpenVPN vs n2n

`tests/run-iperf-compare.sh` (driven by the `iperf_throughput_comparison` test)
sets up each full-IP tunnel in its own netns pair and, at each loss rate, runs
`ping -c 50 -i 0.1` (effective loss + RTT) and `iperf3 -c <tun> -t 8` (TCP
Mbit/s). The contenders:

- **yip** — RaptorQ-FEC tunnel (release `yipd`), inner MTU 1184
- **WireGuard** — in-kernel, no FEC
- **OpenVPN** — TLS p2p TUN, **AES-256-GCM** (AEAD) via peer-fingerprint mode
  (self-signed EC certs, no PKI) — its real deployed data channel, not legacy CBC
- **n2n** — v3 supernode + 2 edges, TAP overlay. One TAP data plane serves both
  L2 and L3, so it is measured **once** (not split into two fabricated columns).

### Measured tables (release `yipd`)

netem `loss X% delay 5ms` symmetric (kernel 6.18, AMD Ryzen 5 7640U):

**loss = 0%**

| contender | eff_loss% | rtt_ms | tcp_Mbit/s |
|-----------|-----------|--------|------------|
| yip       | 0         | 10.61  | 157        |
| wireguard | 0         | 10.36  | 1000       |
| openvpn   | 0         | 10.30  | 107        |
| n2n       | 0         | 10.29  | 199        |

**loss = 5%**

| contender | eff_loss% | rtt_ms | tcp_Mbit/s |
|-----------|-----------|--------|------------|
| yip       | 2         | 10.56  | 21.9       |
| wireguard | 4         | 10.47  | 3.27       |
| openvpn   | 6         | 10.27  | 3.27       |
| n2n       | 22        | 10.28  | 3.27       |

**loss = 10%**

| contender | eff_loss% | rtt_ms | tcp_Mbit/s |
|-----------|-----------|--------|------------|
| yip       | 2         | 10.60  | 8.90       |
| wireguard | 6         | 10.47  | 1.05       |
| openvpn   | 32        | 10.30  | 1.18       |
| n2n       | 16        | 10.29  | 1.44       |

(Single-stream TCP over a 10 ms RTT path is stochastic — read the trend, not the
cell. The under-loss collapse of every no-FEC tunnel to ~1 Mbit/s is the point.)

### Honest interpretation

Two stories, the same one yip is built to tell:

1. **On a clean link, the kernel wins on raw speed.** At 0% loss WireGuard moves
   ~1 Gbit/s — it is in-kernel with no FEC. The userspace tunnels cluster well
   below that, single-stream-over-10 ms-RTT-limited (yip 157, n2n 199, OpenVPN
   107 Mbit/s — single-stream numbers are noisy; on a zero-delay link OpenVPN's
   DCO+GCM channel reaches >1 Gbit/s). yip pays for sealing + FEC-encoding every
   packet single-threaded. On a link that does not need FEC, FEC is pure cost.

2. **Under loss, yip pulls ahead of everyone — including WireGuard.** At 5% loss
   yip holds 21.9 Mbit/s while every no-FEC tunnel collapses to ~3.3 Mbit/s
   (yip ~7×). At 10% the gap widens: yip 8.9 Mbit/s vs WireGuard 1.05, n2n 1.44,
   OpenVPN 1.18. The ping column tells the same story — yip's effective loss stays
   at ~2% while the no-FEC tunnels swing to 6–32% because RaptorQ repair symbols
   reconstruct the drops before TCP ever sees them. yip *resists* loss; the
   FEC-less tunnels *succumb* to it. RTT is within ~0.3 ms across all four (the
   10 ms netem delay dominates), so FEC adds no meaningful latency.

This is yip's thesis as a matrix: trade a little clean-link throughput for large
loss resilience — the right call on the lossy/contended links yip targets, and
cheap on a clean fast path where every tunnel is fast enough.

---

## Caveats and deferred items

- **Run-to-run variance:** each data point is 100 pings at 50 ms inter-packet
  interval (~5 s of traffic).  The effective-loss figures at low injected rates
  can vary by ±1–3 % between runs.  More pings (e.g. 1000) would tighten this.
- **Build mode:** all end-to-end (netns) figures require a **release** `yipd`; the
  harness and CI build `--release`.  A debug binary is ~75× slower on the RaptorQ
  path and produces meaningless throughput/latency numbers (see the build note
  above).  The Criterion hot-path micro-benchmarks are always release.
- **iperf3 throughput:** a committed iperf3 TCP sweep (`run-iperf-compare.sh`,
  see the throughput matrix above) is now wired into the harness across yip,
  WireGuard, OpenVPN, and n2n.
- **Additional contenders:** OpenVPN (L3, TLS+AES-256-GCM) and n2n (L2/L3 TAP
  overlay) are committed comparison contenders alongside yip and WireGuard in the
  iperf matrix; UDPspeeder (RS-FEC) is the committed contender in the UDP loss
  matrix. Each SKIPs cleanly with a logged reason when its tool/module is absent.
  ZeroTier and AmneziaWG remain deferred (not installed in this environment).
- **TCP-under-loss latency-spike comparison:** deferred (the iperf3 sweep reports
  steady-state throughput + RTT, not per-segment latency spikes).
- **WireGuard column:** if the runner does not have the `wireguard` kernel module
  or the `wg` CLI tool the WireGuard column is skipped with a logged reason, and
  the yip-only columns are still reported.

---

## Per-stage pipeline profile

This section establishes where per-packet CPU actually goes through the egress/ingress
pipeline, before optimization. The profile spans the FEC encode (suspected dominant),
FEC decode, and related stages. Run with `cargo run --release -p yip-bench --example pipeline_profile`.

Environment: Linux 6.18 · AMD Ryzen 5 7640U · release build

| Metric | Value | Notes |
|--------|-------|-------|
| symbols/packet | 2.00 | RaptorQ output (1200-byte symbols per 1200-byte sealed packet) |
| encode | 24.2 µs/packet | **Dominant cost** — FEC encode (object-encode + repair generation) |
| decode (approx) | 0.8 µs/packet | Per-symbol decode cost; recovers with first successful symbol |
| decoded ok | 5000/5000 | 100% recovery on clean path (as expected) |

The headline: **encode is the confirmed dominant term** at ~24.2 µs/packet, validating Task 2's focus on FEC
encode throughput optimization. Decode is negligible (~0.8 µs), confirming asymmetric pipeline cost. The example uses
a 1184-byte inner MTU (the bench standard) sealed to 1200 bytes with 16-byte AEAD tag.

Note the **symbols/packet = 2.00**: a single-symbol (1200-byte) object is sent as 1 source + 1 repair, because
the repair-ratio controller floors at `max(1)`. Every packet therefore carries ≥100 % redundancy *and* runs the
encoder — see the throughput-pass finding below.

---

## Throughput pass (egress/ingress optimization)

A measurement-driven pass on the data-plane hot path. What landed, and the honest verdict:

**Shipped (correct, no wire change, all netns ping/byte-identical tests green):**
- **Batched I/O via yip-io.** Egress sends all of a packet's symbols in one `sendmmsg`; ingress reads
  bursts with `recvmmsg` (`MSG_WAITFORONE`). yipd now uses yip-io's `PlainIo` instead of a raw `UdpSocket`.
- **No per-symbol allocation** — egress frames into a reused thread-owned arena.
- **4 MiB `SO_SNDBUF`/`SO_RCVBUF`** (set via a yip-io `set_socket_buffers` helper; yipd stays
  `#![forbid(unsafe_code)]`).
- **FEC-encode bypass when `repair == 0`** (`yip-transport`) — skips the ~24 µs `Encoder::new` solve,
  emitting source symbols byte-identically to the encoder. Implemented and tested.

**Measured (release, kernel 6.18, Ryzen 5 7640U):** clean-link single-stream TCP ≈ 220–285 Mbit/s — **no
regression** vs the pre-pass baseline (single-stream-over-RTT is noisy; the larger socket buffers likely help the
windowed case). UDP 100 Mbit still delivers at 0 % loss.

**The honest finding — the headline win is gated.** The FEC-encode bypass is **dormant**: the controller's
`repair_count` floors at `max(1)`, so it never requests zero repair, so the bypass never fires and every packet
still runs the encoder *and* carries a redundant repair symbol (the 2.00 symbols/packet above). That floor is
currently **load-bearing**: the daemon does not yet feed observed loss back to the controller (deferred
ARQ/feedback), so the repair ratio is effectively static — dropping it to zero would disable FEC entirely and
forfeit yip's loss-recovery thesis. **The clean-link throughput win (skip the encode *and* halve the per-packet
datagram count) is therefore unlocked by the adaptive loss-feedback loop, not by this pass alone.** This pass
delivered the plumbing (batched I/O, buffers, a ready-and-tested bypass fast-path); activating the win is the
next milestone.

---

## Feedback loop — Phase A (the clean-link throughput unlock)

The throughput pass shipped a *dormant* zero-repair FEC bypass. The adaptive
loss-feedback loop (this milestone) activates it: the receiver reports post-FEC
residual loss in an authenticated `Control` packet, the sender feeds it to the
per-class controller, and an ARQ-eligible (`Bulk`) flow on a clean link decays
its repair ratio to **zero** — firing the bypass (skip the ~24 µs encode) and
halving the per-packet datagram count (1 source symbol, no repair).

Measured (release, kernel 6.18, Ryzen 5 7640U; clean-link single-stream TCP over
the netns tunnel):

| build | bulk repair ratio | clean-link TCP |
|-------|-------------------|----------------|
| throughput pass (bypass dormant) | 0.05 floor (≥1 repair, encode always runs) | ~273–285 Mbit/s |
| feedback loop (Phase A) | **0.0000** (converged; bypass fires) | **~457 Mbit/s** |

The bulk controller's repair ratio was confirmed at `0.0000` throughout a 40 s
run via yipd's diagnostic log — direct proof the loop converged, not merely
inferred from the throughput rise. The ~60 % jump is consistent with removing the
FEC encode (which the per-stage profile showed is ~80 % of egress CPU) and sending
one datagram per packet instead of two. Under loss the controller snaps repair
back up immediately (Phase B's ARQ then backstops the residual).

### Phase B — reactive ARQ + loss-recovery under the feedback loop

With the feedback loop active, loss recovery is unchanged — the controller
re-arms FEC the instant loss is reported. Measured UDP delivery under `tc netem`
(`run-fec-compare.sh`), feedback loop live:

| loss% | bare_recv% | yip_recv% |
|-------|------------|-----------|
| 0     | 100.0      | 100.0     |
| 5     | 94.7       | 99.7      |
| 10    | 89.9       | 99.0      |

Reactive ARQ retransmits `Bulk` objects the receiver NACKs, using fresh RaptorQ
repair symbols that carry the original object id (so the receiver tops up its
existing decoder). The retransmit codec is unit-proven (`repair_object` completes
an object delivered only one symbol short), the daemon wiring was reviewed for
object-id preservation and lock discipline, and the tunnel stays alive under 10 %
netem loss (netns ping 10/10). A dedicated end-to-end harness that forces
FEC-insufficiency and asserts ARQ-specific `Bulk` recovery (establishing the
tunnel *before* applying loss, with a retransmit buffer sized to the flow rate)
is a tracked follow-up.

---

## Single-thread data loop — Phase A (lock removal, epoll `PollDriver`)

The two-thread `Arc<Mutex>` data plane was replaced by a single-threaded event
loop: all packet logic lives in a mutex-free `DataPlane`, driven by an `epoll`
`PollDriver` (io_uring driver is Phase B). `bin/yipd/src/tunnel.rs` went from
~637 to ~93 lines; no threads, no locks, no `.join()`.

Measured (release, kernel 6.18, Ryzen 5 7640U, netns tunnel, no netem):

| metric | two-thread `Arc<Mutex>` | single-thread `PollDriver` |
|--------|-------------------------|----------------------------|
| tunnel RTT (added over veth) | ~0.51 ms | **~0.36 ms** |
| clean-link single-stream TCP | ~457 Mbit/s | ~419 Mbit/s (within single-stream variance) |

Removing per-packet lock/handoff overhead **lowered latency** (the north-star
metric) with throughput holding inside single-stream noise. The small single-core
ceiling is the accepted trade — multi-queue throughput sharding is the deferred
scaling lever. All three netns tests (ping, ping-under-loss, arq-integrity) pass
unchanged on the single-threaded daemon (same wire format).

---

## io_uring driver A/B — RTT (default `PollDriver` vs opt-in io_uring)

> **The io_uring driver was demoted from the default when its *blocking* wait
> regressed RTT, then re-tuned: with adaptive busy-poll it now *beats* the epoll
> `PollDriver`.** It remains opt-in pending clean-hardware numbers to justify
> re-defaulting (see "What's needed to re-default" below).

- **RTT command:** `crates/yip-bench/tests/run-driver-ab-rtt.sh` (ping
  `-c 100 -i 0.02` across the tunnel, `target/release/yipd`) — measures all three
  modes: `poll`, `uring` (blocking), `uring-busypoll` (`YIP_URING_BUSYPOLL=1`).

| mode | env | tunnel RTT avg (ms) — **lower is better** |
|------|-----|-------------------------------------------|
| poll (default) | — | ~0.37 |
| uring (blocking) | `YIP_USE_URING=1` | ~0.41 |
| **uring + adaptive busy-poll** | `YIP_USE_URING=1 YIP_URING_BUSYPOLL=1` | **~0.30** |

Measured 2026-07-02 (kernel 6.18, AMD Ryzen 5 7640U, release `yipd`) under
`chrt -f 50` (SCHED_FIFO) — see the measurement note below.

**What the regression was, and the fix.** The single-flow ping-pong has nothing
to batch, so io_uring's blocking `submit_and_wait` pays the **thread wakeup /
scheduling latency** on every event — that, not allocation or batching, was the
whole ~0.1 ms regression. Two changes closed it:

- **Alloc-free hot path** (recv scratch reuse, send-buffer pool, reused CQE vec) —
  matches poll.rs; RTT-neutral but removes malloc churn / cuts throughput-path CPU.
- **Adaptive busy-poll** (`YIP_URING_BUSYPOLL=1`): spin the completion queue to
  catch the imminent reply completion instead of blocking. Adaptive = spin only
  while an exchange is active; an idle tunnel backs off to a blocking wait and
  burns no CPU. This is the "burn CPU for latency" knob (yip's north star).

The blocking wait is also bounded by a 10 ms timeout (io_uring `EXT_ARG`) so
`tick` fires on cadence on an idle tunnel — parity with poll.rs's `epoll_wait`.

**Measurement note.** This dev box runs background load that preempts the yipd
thread on CFS and adds run-to-run noise (busy-poll competes for the core). Running
the harness under `sudo chrt -f 50 bash …/run-driver-ab-rtt.sh <yipd>` gives
SCHED_FIFO priority and a clean, consistent read. On a genuinely quiet box the
`chrt` wrapper is unnecessary.

**What's needed to re-default io_uring** (all on a quiet box):

1. RTT **p50 + p99** over many samples, uring+busypoll vs poll (the tail is the
   "insane low latency" claim).
2. **Idle yipd CPU ≈ 0%** with adaptive busy-poll and no traffic (confirm the backoff).
3. **Active-traffic CPU** of busy-poll (it spins ~1 core per busy tunnel) — make
   the tradeoff explicit before it is default.
4. **Throughput uring ≥ poll** (iperf3 + scp-under-loss) — re-defaulting must not
   regress bulk. (Earlier: iperf3 clean-link was a wash, ~305–356 Mbit/s both.)
5. A **spin-budget sweep** for the minimum `CQ_SPIN_BUDGET` that still wins
   (`2_000_000` is over-provisioned for the loaded box; the knee is lower on quiet
   hardware, which cuts the active-CPU cost).

CI gates **both** drivers in `netns-tunnel-test` so the opt-in path stays correct.
Throughput-side GSO batching is a separate track (issue #17).
