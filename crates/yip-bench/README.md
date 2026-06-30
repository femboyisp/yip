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

## Caveats and deferred items

- **Run-to-run variance:** each data point is 100 pings at 50 ms inter-packet
  interval (~5 s of traffic).  The effective-loss figures at low injected rates
  can vary by ±1–3 % between runs.  More pings (e.g. 1000) would tighten this.
- **Build mode:** all end-to-end (netns) figures require a **release** `yipd`; the
  harness and CI build `--release`.  A debug binary is ~75× slower on the RaptorQ
  path and produces meaningless throughput/latency numbers (see the build note
  above).  The Criterion hot-path micro-benchmarks are always release.
- **iperf3 throughput:** the ~270 Mbit/s clean-link single-stream figure quoted
  above was measured with iperf3 over the tunnel; a committed iperf3 sweep
  (TCP + UDP-under-loss) wired into the harness is the next addition.
- **Additional contenders:** OpenVPN (L3) and n2n (L2/L3) are installed and
  queued as comparison contenders alongside yip and WireGuard.
- **TCP-under-loss latency-spike comparison:** deferred (requires the iperf3 sweep
  above or a dedicated TCP load generator).
- **WireGuard column:** if the runner does not have the `wireguard` kernel module
  or the `wg` CLI tool the WireGuard column is skipped with a logged reason, and
  the yip-only columns are still reported.
