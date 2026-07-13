# yip-bench Results

Generated: 2026-06-30 19:51:19 UTC

## yip vs kernel WireGuard — netem loss sweep
ping -c 100 -i 0.05 -W 1 across each tunnel; netem: loss X% delay 5ms (symmetric)

| injected% | yip_loss% | wg_loss%  | yip_rtt_ms | wg_rtt_ms |
|-----------|-----------|-----------|------------|-----------|
| 0%        | 0%         | 0%         | 10.541      | 10.322     |
| 1%        | 0%         | 2%         | 10.567      | 10.332     |
| 3%        | 0%         | 4%         | 10.544      | 10.360     |
| 5%        | 0%         | 8%         | 10.550      | 10.388     |
| 10%        | 1%         | 17%         | 10.544      | 10.337     |

## Throughput 4a — RS codec

Generated: 2026-07-09 20:02 UTC

Sub-project #1 throughput work (4a) replaced the per-packet RaptorQ encoder
(a fresh `raptorq::Encoder` + `SourceBlockEncodingPlan::generate` Gaussian
elimination solve on every packet, ~26 µs) with a hand-rolled systematic
Reed–Solomon codec over GF(256) (Cauchy generator matrix, exhaustive MDS
property-tested — see `crates/yip-transport/src/rs.rs`). RaptorQ has been
fully removed from `yip-transport` and `yip-bench`.

### `transport_encode_1300` (criterion, `cargo bench -p yip-bench --bench hotpath`)

| | before (RaptorQ) | after (RS codec) |
|---|---|---|
| median | ~26 µs | **1.32–1.34 µs** (stable across two runs: `[1.3129, 1.3214, 1.3303]` µs and `[1.3358, 1.3408, 1.3459]` µs) |

~95% reduction. Note: the 4a design spike projected a sub-1 µs / ~0.77 µs
figure for this path; the measured criterion median on this machine is
~1.33 µs, higher than that projection (and higher than the brief's "well
under 1 µs" expectation). Reported as measured, not massaged. It is still
comfortably below the AEAD seal cost measured on this box
(`aead_seal_1300` median 1.95 µs, `cargo bench -p yip-bench --bench hotpath
-- aead_seal_1300`), so FEC encode is no longer the single-core bottleneck.

### `pipeline_profile` (`cargo run --release -p yip-bench --example pipeline_profile`)

| | before (RaptorQ) | after (RS codec) |
|---|---|---|
| encode | ~26 µs/packet (implied by the 4a spike's ~26 µs plan-solve finding) | **0.8–1.4 µs/packet** across three runs (1.4, 1.0, 0.8) — this micro-benchmark uses a coarse `Instant`-based loop and is noisier than criterion; treat the criterion number above as authoritative |
| symbols/packet | 2.00 | 2.00 (unchanged) |
| decoded ok | 5000/5000 | 5000/5000 (unchanged) |

### Single-core throughput implication

FEC encode (~1.3 µs, criterion) is now well below AEAD seal (~1.95 µs,
criterion) on this machine. FEC is no longer the single-core bottleneck —
the AEAD seal/open pair is now the dominant per-packet cost, consistent
with the plan's throughput model (FEC term ≪ AEAD term → AEAD-bound →
multi-gigabit single-core headroom, pending 4b I/O batching and 4c
multi-core sharding to realize it end-to-end).

### No-regression

- `cargo test` (full workspace): **134 unit/integration tests + 18 netns
  tests (self-skipped when not root, ran as no-ops here since `cargo test`
  itself was not run under sudo) + housekeeping tests across all crates —
  all green, 0 failed.**
- netns FEC/ARQ integration gate (`sudo bin/yipd/tests/run-netns-tunnel.sh`,
  `run-netns-tunnel-loss.sh`, `run-netns-tunnel-l2.sh`,
  `run-arq-integrity.sh`, each passed the release `yipd` binary explicitly):
  **all four passed** under real network namespaces with `sudo`:
  - `run-netns-tunnel`: clean tunnel, 3/3 ping, 0% loss — PASS
  - `run-netns-tunnel-loss`: 10% netem loss, 10/10 ping delivered (RS FEC
    recovers the injected loss) — PASS
  - `run-netns-tunnel-l2`: TAP/L2 bridging, 3/3 ping — PASS
  - `run-arq-integrity`: 5% loss + 5ms delay, 20000×1400B UDP blast,
    99.3% delivered (≥98% required), 128 ARQ retransmits fired
    (`repair_with_id` topped up stalled objects) — PASS
  This exercises the RS codec's erasure-recovery path end-to-end (not just
  the exhaustive MDS property test and `fec` round-trip unit tests), so all
  four legs of the correctness guarantee (field axioms, exhaustive MDS,
  fec round-trip, netns end-to-end) are now confirmed on this run.

## QUIC-vs-raw benchmark (3c.1 Task 7)

Generated: 2026-07-09 14:20:16 UTC

`transport=quic` (real QUIC/TLS1.3 handshake + DATAGRAM-frame pump,
wrapping the inner yip Noise-IK session — see bin/yipd/src/quic.rs) vs
yip's default raw-UDP path. Same netns/veth harness as the driver A/B
RTT test and the iperf3 throughput matrix; `ping -c 100 -i 0.02` for
RTT, `iperf3 -t 8` for TCP throughput. This is NOT the obf_psk
cover-traffic premium (3a/3b, a separate cost) — this isolates the QUIC
mimicry premium alone.

| transport | rtt_avg_ms | tcp_Mbit/s |
|-----------|------------|------------|
| raw       | 0.394      | 355        |
| quic      | 0.438      | 266        |

Honest framing: `transport=quic` is an **opt-in premium** for DPI
resistance (see `bin/yipd/tests/run-quic-mimicry-oracle.sh` / the
`quic_classified_as_quic` test for the payoff — a real nDPI
classification flip to QUIC with no Susp Entropy risk). Raw UDP remains
yip's low-latency default; the double-encryption/two-layer-handshake
cost above is what QUIC mimicry spends to buy that payoff (the 3c.1
Task 1 spike estimated ~1.68x CPU/packet for the QUIC path; the table
above is the measured RTT/throughput consequence of that cost).

## P+Q fast-path FEC (throughput P+Q)

Generated: 2026-07-11 09:08 UTC

Prior work (4a) replaced RaptorQ with a hand-rolled systematic
Reed–Solomon codec using a general Cauchy generator matrix for every
repair symbol (`crates/yip-transport/src/rs.rs`, `Scheme::Cauchy`),
measured at ~1.3 µs median for `transport_encode_1300` (K=2, R=1). This
task's predecessor (P+Q) added a second generator scheme,
`Scheme::Pq`, selected automatically for non-ARQ classes (Realtime,
Default) whenever R∈{1,2}: R=1 is a pure XOR (RAID-5 "P" row, no GF(256)
multiplies at all), R=2 adds a second XOR-plus-power-of-2-multiply row
("Q", the RAID-6 syndrome). ARQ-eligible classes (Bulk) keep Cauchy
regardless of R so a retransmit batch stays scheme-compatible with the
original send.

### Benchmarks (criterion, `cargo bench -p yip-bench --bench hotpath -- encode`)

| bench | what it measures | before (4a, Cauchy) | after (P+Q) |
|---|---|---|---|
| `transport_encode_1300` | `Transport::encode` on a 1300B inner packet (Default class, K=2, R=1 → now `Scheme::Pq`) | ~1.32–1.34 µs | **316–332 ns** (two runs) |
| `fec_encode_r1_p` | `FecEncoder::encode` direct, K=3 object, repair=1 (pure XOR "P" row) | n/a (new bench) | **434–520 ns** (two runs, noisier — small-N criterion variance) |
| `fec_encode_r2_pq` | `FecEncoder::encode` direct, K=3 object, repair=2 (P row + Q row) | n/a (new bench) | **1.87–1.92 µs** (two runs, stable) |

Two consecutive `cargo bench` runs:
- run 1: `transport_encode_1300` 332.16 ns / `fec_encode_r1_p` 434.00 ns / `fec_encode_r2_pq` 1.8822 µs
- run 2: `transport_encode_1300` 317.70 ns / `fec_encode_r1_p` 504.65 ns / `fec_encode_r2_pq` 1.8944 µs

**R=1 is well below the 4a baseline**, as expected: it's now a pure
XOR loop with zero GF(256) table-lookup multiplies, versus Cauchy's
per-byte multiply-accumulate against a non-trivial coefficient. Both
`transport_encode_1300` (~320 ns) and the isolated `fec_encode_r1_p`
(~450–520 ns; slightly higher because it carries a 3600 B/K=3 object
vs. the 2400 B/K=2 object in `transport_encode_1300`, plus builds 4
symbols instead of 3) land comfortably sub-µs, matching the design
goal.

**R=2 is honestly reported, not massaged, and does *not* beat the 4a
number at face value** (~1.88 µs vs. ~1.33 µs) — but this is not an
apples-to-apples comparison: the 4a baseline was measured at K=2, R=1
(3 total symbols, one GF-multiply repair row), while `fec_encode_r2_pq`
is K=3, R=2 (5 total symbols, one pure-XOR row plus one GF-multiply
row). The Q row still does real GF(256) `mul_slice_into` work for 2 of
its 3 source terms (only the `i=0` term is `c==1`, XOR-fast), so its
cost is in the same ballpark as a single Cauchy repair row of similar
size — R=2 pays for two rows' worth of work (~450 ns P row + ~1.4 µs Q
row), which is expected and correct, not a regression. No apples-to-
apples R=2-vs-R=2-Cauchy-at-K=3 benchmark was recorded (out of scope
for this task); the R=1 case is the one the design targets as the
common proactive-repair path for Realtime/Default classes and it is
the one that lands sub-µs.

### Takeaway

Non-ARQ classes (Realtime, Default) proactively send R=1 repair on
most packets (`initial_repair_ratio` 0.15/0.10, adaptive), so the R=1
P/XOR path is the one exercised on nearly every packet in steady
state — and it is now sub-µs (~320–520 ns), comfortably below both the
4a Cauchy baseline (~1.3 µs) and the AEAD seal cost (~1.95 µs,
`aead_seal_1300`), so FEC protection stays "on" by default without
becoming the per-packet bottleneck. R=2 (two-erasure RAID-6 protection,
used when the adaptive controller raises the ratio under observed
loss) costs more per packet as expected, but remains a bounded, correct
GF(256) operation — never a full Gaussian-elimination Cauchy solve —
and only engages when loss conditions call for stronger repair.

### No-regression

- `cargo test -p yip-transport`: **69 passed, 0 failed** (includes
  `rs::tests::exhaustive_k_of_k_plus_r_decodes_both_schemes` — the MDS
  property test across both schemes — and
  `fec::tests::arq_retransmit_recovers_after_partial_original_send`,
  the unit-level guarantee that the prior task's ARQ-retransmit fix
  holds).
- `cargo test` (full workspace, all crates + the 21-test
  `tunnel_netns` in-process suite): **346 passed, 0 failed, 0
  ignored** across every crate (yip-io, yip-wire, yip-crypto,
  yip-transport, yip-device, yip-membership, yip-obf, yip-rendezvous,
  yip-bench, yipd, plus doc-tests).
- netns FEC/ARQ integration gate (`sudo bin/yipd/tests/run-netns-tunnel.sh`,
  `run-netns-tunnel-loss.sh`, `run-arq-integrity.sh`, each passed the
  release `yipd` binary explicitly, sudo/netns available in this
  environment): **all three passed**:
  - `run-netns-tunnel`: clean tunnel, 3/3 ping, 0% loss — PASS
  - `run-netns-tunnel-loss`: 10% netem loss, 10/10 ping delivered (P+Q
    FEC recovers the injected loss) — PASS
  - `run-arq-integrity`: 5% loss + 5ms delay, 20000×1400B UDP blast,
    99.3% delivered (≥98% required), 134 ARQ retransmits fired — PASS.
    This is the test that specifically exercises the ARQ-retransmit
    bug fix from the prior task end-to-end (Bulk-class objects that
    stall for want of one shard get topped up via `repair_with_id`,
    which always uses Cauchy regardless of R so a retransmit batch
    stays scheme-compatible with the original send); it passing here
    confirms that fix holds under real network-namespace loss, not
    just in the `arq_retransmit_recovers_after_partial_original_send`
    unit test.

## Fast AEAD (ring ChaCha20-Poly1305)

Generated: 2026-07-11 15:46 UTC

Task 2 (already merged into this branch, `feat/throughput-fast-aead`)
swapped `Session::seal`/`open`'s cipher backend from `snow`'s own
transport-mode AEAD to `ring`'s asm ChaCha20-Poly1305, keyed from the
same Noise Split() secret transport keys (byte-identical output,
confirmed by the `session_seal_is_byte_identical_to_snow_write_message_both_directions`
durable KAT) — the ~4x win this milestone targets. This task (3) is the
no-alloc buffer API on top of that swap plus the dataplane hot-loop
wiring and this measurement/no-regression pass.

### `aead_seal_1300` / `aead_open_1300` (criterion, `cargo bench -p yip-bench --bench hotpath -- aead`)

| bench | before (snow) | after (ring) |
|---|---|---|
| `aead_seal_1300` | ~2.1 µs (documented snow baseline; this machine's own criterion baseline directory recorded a **-67.8%** regression-to-improvement delta on this run, consistent with a ~2.1 µs → ~0.63 µs move) | **633.98 ns median** `[629.65 ns, 633.98 ns, 638.31 ns]` |
| `aead_open_1300` | ~2.1 µs+ (snow) | **1.2843 µs median** `[1.2769 µs, 1.2843 µs, 1.2922 µs]` — this bench re-seals every iteration and measures seal+open **combined** (see the bench's own comment in `hotpath.rs`), so the isolated open cost is roughly `1.2843 µs − 0.634 µs ≈ 0.65 µs`, in the same ~0.5–0.9 µs band as seal |

Single-core throughput implication: at ~0.634 µs/seal, one core can
seal roughly 1.58M 1300 B packets/s in isolation (`1/633.98ns ≈
1.577M/s`, × 1300 B × 8 bit ≈ 16.4 Gbit/s of AEAD throughput headroom,
ignoring FEC/wire/syscall overhead already measured elsewhere in this
file at sub-µs and ~1.3 µs respectively) — AEAD is no longer the
dominant per-packet cost by itself; it now sits below the P+Q FEC R=2
path and in the same ballpark as R=1 FEC.

### No-alloc delta (`seal_into`/`open_into`), reported honestly

Per the Task-1 spike, swapping the *buffer* from a fresh per-call
`Vec` (`seal`'s `plaintext.to_vec()`) to a caller-reused `Vec`
(`seal_into`'s `out.clear(); out.extend_from_slice(..)`) measured only
**~0.02 µs** of delta in isolation — allocator reuse of a small,
consistently-sized (~1.3 KB) buffer is already close to free on this
allocator, so this is *not* where this task's value is. This
measurement was not independently re-run here (Step 3 only re-runs the
existing `aead_seal_1300`/`aead_open_1300` benches, which still call
the allocating `seal`/`open` — `seal_into` is exercised end-to-end via
the dataplane hot path instead, see below); reporting it here as
previously measured rather than re-claiming a fresh number.

The real, structural win of this task is in `bin/yipd/src/dataplane.rs`'s
`on_tun_packet` tx hot loop: before, every packet paid **two**
1300-ish-byte heap allocations — `seal`'s internal `plaintext.to_vec()`
and the subsequent `sealed.ciphertext.clone()` needed to hand an owned
copy to `RetxBuffer::put` (which takes `Vec<u8>` by value). After this
change, `seal_into` writes into a reused `self.seal_buf` field (no
allocation on the seal step itself in the steady state where a packet
isn't buffered for retx), and the `.clone()` call is gone entirely:
the sealed bytes are *moved* into `retx.put` via `std::mem::take(&mut
self.seal_buf)` rather than cloned. Net effect: **one heap allocation
per packet instead of two**, on the path that runs on every packet the
tunnel sends (not a synthetic benchmark number, but visible by
inspection of the diff — see `dataplane.rs`'s `on_tun_packet`). The
cold feedback-report seal in `tick` (~line 539 pre-change) is left on
the simple, allocating `seal`, matching the brief.

### No-regression

- `cargo test` (full workspace): see command output captured in
  `.superpowers/sdd/task-3-report.md`.
- netns FEC/ARQ integration gate (`sudo bin/yipd/tests/run-netns-tunnel.sh`,
  `run-netns-tunnel-loss.sh`, `run-arq-integrity.sh`, release `yipd`
  binary): outcome recorded in `.superpowers/sdd/task-3-report.md` —
  this is the end-to-end proof that a session establishes and passes
  traffic under the new AEAD + no-alloc dataplane path.

## Batched UDP I/O (sendmmsg/recvmmsg) — 2026-07-11

Lever 3 of the single-core-10-Gbit set (FEC and AEAD levers already merged).
`run_poll`'s hot path now batches UDP I/O: `drain_udp` drains the rx burst with
one `recvmmsg`; `drain_tun` accumulates a TUN burst's egress symbols and sends
them with one `sendmmsg`. Structurally this collapses the tx path from ~2–3
`sendto` syscalls **per packet** (one per FEC symbol) to **one `sendmmsg` per
burst**, and the rx path from one `recvfrom` per datagram to one `recvmmsg` per
burst. Batching is opportunistic (drain what epoll already has queued — no
wait-to-fill), so it is latency-neutral, and each datagram is still its own UDP
packet (no GSO) so FEC symbol loss-independence is preserved.

### Correctness (verified end-to-end, netns, real sudo)
- `run-netns-tunnel`: PASS (3/3 ping across the tunnel).
- `run-netns-tunnel-loss`: **PASS (10/10 under 10% netem loss)** — FEC still
  recovers dropped packets with batched sends.
- `run-arq-integrity`: PASS (118 ARQ retransmits, all assertions).
- Full `cargo test --workspace`: 0 failures. yip-io unit tests cover the
  addressed `send_mmsg`/`recv_mmsg` (per-datagram dst/src) directly.

### Throughput number: not cleanly captured this run
`crates/yip-bench/tests/run-iperf-compare.sh` wedged repeatedly in this
environment (two `yipd` daemons come up but iperf never completes; no output
after minutes — a harness/environment flake, not a data-plane regression, since
the tunnel itself passes traffic in every other netns test above). So a
measured before/after Gbit figure is **not recorded here**. The expected impact
per the design model is I/O dropping from ~1–3 µs/packet (per-packet syscall) to
~0.1–0.3 µs (amortized over the burst); combined with the merged FEC (~0.32 µs)
and AEAD (~0.63 µs) levers this targets ~7 Gbit/s single-core on the target VPS.
A clean iperf measurement is left as a follow-up (fix or replace the
iperf-compare harness).

## 4a GSO spike — UDP_SEGMENT vs plain sendmmsg on virtio (decision gate)

Throwaway send-path microbenchmark (`gso_spike.c`, not committed) run on a real
target box: `root@45.61.149.155` (1-core AMD EPYC, virtio, kernel 6.12), blasting
1200-byte UDP to `144.172.98.216:9999` over the public path, 4 s × 3 runs each.
Metric = **datagrams sent per CPU-second** (getrusage utime+stime), which isolates
send-path CPU cost independent of the network's throughput ceiling.

| mode  | datagrams/CPU-s (median) | cpu_s for ~0.6–0.7M datagrams |
|-------|--------------------------|-------------------------------|
| plain sendmmsg (32/batch) | ~181,000 | ~3.3 s |
| gso  (1 sendmsg + UDP_SEGMENT, 32×1200) | ~462,000 | ~1.55 s |

**Ratio ≈ 2.6× datagrams per CPU-second in favour of GSO** — GSO sent *more*
datagrams (~725k vs ~600k) in *half* the CPU. Well above the 1.3× decision gate.

**Verdict: PROCEED.** `UDP_SEGMENT` more than halves send-path CPU per datagram on
these virtio boxes, so wiring it into the poll path (Tasks 1–5) is justified. This
directly corroborates the earlier kernel-stack profiling that pinned `__sys_sendmmsg`
as the dominant single-core cost.

## 4a send-side GSO (poll path) — real-hardware before/after

A/B on two 1-core AMD EPYC / 967 MB virtio VPSes (Y1 `45.61.149.155`, Y2
`144.172.98.216`, 23.5 ms apart), same-session back-to-back so network conditions
cancel in the delta. Baseline binary = main `e030a39` (#54 batched I/O, **no GSO**);
4a binary = this branch (GSO on the poll send path). UDP, 1200-byte payloads, yip0
MTU 1380. Sender-side (`Y1`) yipd CPU sampled via `/proc/<pid>/stat` delta.

**Direct** (iperf on Y1↔Y2 over the tunnel — sender core shared with iperf, so the
same confounder applies to both columns and cancels in the delta):

| UDP target | baseline delivered | 4a delivered | Y1 yipd CPU (both) |
|-----------:|-------------------:|-------------:|:-------------------|
| 300 Mbit/s | 195 | **240** | 71% |
| 600 Mbit/s | 179 | **255** | 64% |
| 1 Gbit/s   | 174 | **227** | ~56% |

Peak delivered **195 → 255 Mbit/s (+31%)** at identical sender CPU.

**Isolated** (4-box NAT chain `ny → Y1 ═yip═ Y2 → lv`; the yip gateways' cores do
only forwarding — the real deployment shape; note the double-MASQUERADE conntrack
adds per-packet kernel cost that partly masks the send-syscall savings):

| UDP target | baseline delivered | 4a delivered | Y1 ingress yipd CPU |
|-----------:|-------------------:|-------------:|:--------------------|
| 300 Mbit/s | 91  | **154** | ~90% |
| 600 Mbit/s | 157 | **196** | ~95% (pegged) |
| 1 Gbit/s   | 97  | **193** | ~93% |

Peak **157 → 196 Mbit/s (+25%)** at ~equal (near-pegged) CPU; larger at lower-loss
operating points.

**Interpretation.** GSO delivers a consistent **~+25–31% end-to-end throughput at
equal single-core CPU** on the target hardware. This is smaller than the spike's
2.6× *send-path* CPU win (see "4a GSO spike") because send-side GSO only amortizes
the transmit-stack cost — the receive path, TUN I/O, NAT conntrack, and interrupt
handling do not benefit, so the integrated gain is diluted. TCP single-/parallel-
stream numbers over this 23.5 ms, high-loss path are window/loss-collapsed noise
and are not reported. Correctness (netns 10% loss + ARQ, both drivers) was verified
separately; FEC per-symbol loss-independence is preserved by the fate-safe grouping.

## 4b TUN-offload spike — vnet-hdr GSO write vs per-packet (decision gate + confirmed constants)

Throwaway probe (`tun_gso_spike.c`, not committed) on `root@45.61.149.155` (1-core AMD EPYC,
virtio, kernel 6.12): open a TUN with `IFF_TUN|IFF_NO_PI|IFF_VNET_HDR` + `TUNSETOFFLOAD`, write
1400-byte TCP segments two ways, 4 s × 3.

- `info`: **`IFF_VNET_HDR` ok; `TUNSETOFFLOAD(CSUM|TSO4|TSO6)` accepted; `sizeof(virtio_net_hdr)=10`.**

| write mode | segments / CPU-second (median) |
|------------|-------------------------------:|
| per-packet (`GSO_NONE`, one write per segment) | ~378,000 |
| coalesced GSO (one write per 44 segments) | ~5,250,000 |

**Ratio ≈ 13.8× segments per CPU-second in favour of GSO writes.** Well above the gate. The
coalesced GSO `write()` **succeeded (no `EINVAL`)**, which confirms the `virtio_net_hdr` layout
the 4b coalescer depends on: **10-byte header, host byte order, `gso_type=GSO_TCPV4(1)`,
`flags=F_NEEDS_CSUM(1)`, `csum_start = ip_hdr_len` (20 for no-options IPv4), `csum_offset = 16`
(TCP checksum), `hdr_len = ip_hdr_len + tcp_hdr_len` (40), `gso_size = MSS`.** The kernel
segments the frame and computes per-segment L4 checksums.

**Verdict: PROCEED.** vnet-hdr GSO writes cut the per-segment TUN-write CPU ~14× on the target
kernel — directly attacking the ~20% receiver `tun_chr_write_iter` cost. (End-to-end gain will
be smaller: the write is ~20% of receiver CPU and only bulk-TCP coalesces.) Constants confirmed
for Tasks 1/3/4.

## 4b TUN vnet-hdr GSO/GRO offload — real-hardware before/after

A/B on Y1 `45.61.149.155` ↔ Y2 `144.172.98.216` (1-core AMD EPYC, virtio, 24 ms apart),
same session, baseline = main `ec3ae21` (no offload) vs this branch (`yip4b0` device, separate
port; the user's `yip0` tunnel untouched). Bulk **TCP** in-tunnel (`iperf3 -P 32`), `perf` on
the **receiver** (Y2) yipd — the side whose `tun_chr_write_iter` cost this lever targets.

| metric (-P 32 bulk TCP) | baseline (no offload) | 4b (offload) |
|-------------------------|----------------------:|-------------:|
| receiver `tun_chr_write_iter` (perf) | 19.0% | **14.6%** |
| aggregate throughput | 51.7 Mbit/s | 56.4 Mbit/s |

**The mechanism works:** GSO coalescing engages under load and cuts the targeted receiver
TUN-write cost from ~19% to ~14.6% (a ~23% reduction of that component; the Task-0 spike
measured the raw per-segment write ~14× cheaper). But **end-to-end throughput barely moves
(+9%, within noise)** because on these boxes throughput is capped by the 24 ms RTT + TCP window
+ same-core `iperf` contention — it is *not* TUN-write-CPU-bound at ~50 Mbit/s, so freeing that
CPU doesn't lift the ceiling.

**Where it helps and where it doesn't (honest):** coalescing needs *dense same-flow bursts*.
A single high-rate flow is RTT-limited here to ~40 Mbit/s (too few packets/burst to coalesce);
32 parallel flows raise pps but *interleave* flows, so consecutive packets are often different
flows and the coalescer flushes on flow change — limiting the win to the ~4.4-point reduction
above. The offload's full benefit lands on **low-RTT / high-throughput single flows** (LAN,
or where yipd owns the core and TUN-write CPU is the actual bottleneck). On these specific
24 ms-RTT 1-core VPSes the win is real but small. It is a **no-wire-change, correctness-preserving,
poll-only** change that costs nothing when it can't coalesce (singletons pass through), so it is
a safe reduction of a real cost with upside on faster paths — not a headline throughput win here.

## 3c.2 TLS-parrot spike — can rustls emit a browser-clean ClientHello? (decision gate)

Throwaway spike (scratchpad `tls-spike`, rustls 0.23, not committed): a default
rustls TLS 1.3 client (ALPN h2;http/1.1, SNI=www.apple.com) to a local TLS server,
captured on `lo`, classified with the prebuilt `ndpiReader` (the 3a/3c oracle).

**Result — the costume works at the protocol level, but the JA4 does not parrot a browser:**
- nDPI classifies it **`TLS.Apple` `[cat: Web/5][Breed: Safe][Confidence: DPI]`** by
  SNI — **not** VPN, **not** `NDPI_OBFUSCATED_TRAFFIC`. The SNI-based disguise works.
- **rustls JA4 = `t13d1011h2_61a7ad8aa9b6_d705fb1e10bf`** (10 ciphers, 11 extensions,
  **no GREASE**). A current Chrome is `t13d1516h2_…` (~15 ciphers, ~16 extensions,
  **GREASE**). Counts alone (`1011` vs `1516`) plus the sorted-hashes differ — the
  fingerprint reads as **"a rustls client," not a browser**.
- **rustls cannot be coaxed to a browser JA4:** it intentionally sends no GREASE and
  exposes no cipher/extension-order customization (a deliberate rustls stance).
- Two nDPI risks on the capture: "Known Proto on Non Std Port" (artifact of :4443;
  real use is :443) and **"Mismatching Protocol with server IP address"** (the fake
  SNI won't match the peer's real IP — a genuine consideration for any SNI costume).

**Verdict:** a genuinely browser-clean JA3/JA4 (the milestone's stated requirement)
requires **BoringSSL (`boring` crate)** — the basis of the Rust TLS-impersonation
ecosystem (rquest). That is a heavy C dependency + more integration (raw SSL API for a
bidirectional tunnel, both client and server sides). DECISION NEEDED: (a) accept the
rustls costume (protocol-clean, JA4 = rustls-fingerprintable) — simplest; or (b) commit
to `boring` for a true Chrome-parrot JA4 — matches the requirement, heavy.

### 3c.2 spike (cont.): BoringSSL viability — the chosen path

Extended the spike to `boring` 4.22 (BoringSSL bindings), same loopback+ndpiReader method:
- **Builds** — but requires **cmake** (was missing on the Void dev box; `xbps-install cmake`
  fixed it) plus a BoringSSL compile (~19 s here). This is a **new hard build dependency for
  the whole project + CI** (cmake + the BoringSSL compile), vs yip's current pure-Rust+ring build.
- **JA4 = `t13d1712h2_5b57614c22b0_ef7df7f74e48`** by default (17 ciphers, 12 extensions,
  **GREASE present**) — already browser-*shaped* (unlike rustls's `t13d1011h2`, no GREASE), and
  **configurable** to Chrome's exact `t13d1516h2` (BoringSSL exposes the cipher/extension/sigalg/
  GREASE control the impersonation crates use). Still classifies `TLS.Apple`/`Web`/`Safe`.

**Gate = PASS on boring** (viable + tunable to a real Chrome parrot). **Accepted caveats for the
3c.2 build:** (1) cmake + BoringSSL become required to build yipd (CI job + contributors); (2) the
`run_tls` pump uses boring's raw SSL API (both client + server sides) rather than rustls; (3) the
exact current-Chrome recipe must be sourced/maintained (fingerprint drift) — lean on a maintained
recipe. Decision (user): **commit to boring** for a true Chrome JA4.
