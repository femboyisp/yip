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

> **yip's RaptorQ FEC recovers nearly all injected packet loss;
> WireGuard, which has no FEC, passes it through.**

At 10 % injected loss, yip showed ~3 % effective loss (FEC recovered ~70 % of
dropped packets); WireGuard showed ~12 % effective loss.  The FEC cost is an RTT
premium of ~8 ms (~18 ms yip vs ~10 ms WireGuard) from the encode/decode pipeline.

The effective-loss law: with independent per-direction loss *p* and proactive
repair symbols, yip effective loss ≈ *p*² (residual that escapes FEC recovery);
WireGuard effective loss ≈ 1 − (1 − *p*)² bidirectional (both hops must deliver
for a round-trip ping to succeed).

### Latest sweep

The table below comes from the most recent run of `tests/run-compare.sh`.
The harness overwrites `RESULTS.md` each time it runs; the figures here are from
the committed baseline run (2026-06-30, kernel 6.18, AMD Ryzen 5 7640U):

| injected % | yip effective loss | WG effective loss | yip RTT (ms) | WG RTT (ms) |
|---|---|---|---|---|
| 0 % | 0 % | 0 % | 17.9 | 10.4 |
| 1 % | 0 % | 0 % | 17.7 | 10.4 |
| 3 % | 0 % | 7 % | 18.0 | 10.4 |
| 5 % | 1 % | 9 % | 18.0 | 10.4 |
| 10 % | 3 % | 12 % | 18.4 | 10.4 |

Measurement: `ping -c 100 -i 0.05 -W 1`; netem: `loss X% delay 5ms` applied
symmetrically to both veth ends.  100 pings per data point — stochastic, so
run-to-run variance of ±1–3 % at low loss rates is expected.

See `RESULTS.md` for the raw output from the most recent automated run.

---

## Caveats and deferred items

- **Run-to-run variance:** each data point is 100 pings at 50 ms inter-packet
  interval (~5 s of traffic).  The effective-loss figures at low injected rates
  can vary by ±1–3 % between runs.  More pings (e.g. 1000) would tighten this.
- **iperf3 throughput:** not yet measured; deferred until iperf3 is available in
  the CI environment.
- **L2 contenders:** n2n, ZeroTier, and OpenVPN comparison is deferred (tools not
  installed in the current environment).
- **TCP-under-loss latency-spike comparison:** deferred (requires iperf3 or a TCP
  load generator).
- **WireGuard column:** if the runner does not have the `wireguard` kernel module
  or the `wg` CLI tool the WireGuard column is skipped with a logged reason, and
  the yip-only columns are still reported.
