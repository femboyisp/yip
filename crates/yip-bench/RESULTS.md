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
