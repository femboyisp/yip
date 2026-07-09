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
