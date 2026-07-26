# CPU-bound-regime spike (#4 throughput campaign go/no-go)

Script: `crates/yip-bench/tests/run-cpu-regime.sh`
Run:    `sudo bash crates/yip-bench/tests/run-cpu-regime.sh target/release/yipd`

**Question:** can the yip receiver ever become CPU-bound (its packet-processing
core pegged), or is throughput always RTT/window-bound? This is the go/no-go for
the #4 CPU-optimization work (codec/MAC swaps): if the receiver never saturates
a core, those wins can never move end-to-end throughput.

**Method:** two netns + veth, yip tunnel between them. The receiving yipd is
`taskset`-pinned to ONE core (models the 1-core EPYC target); sender yipd + iperf
get other cores. Push data B->A (UDP blast, then TCP -P 8) while sweeping netem
RTT; record tunnel throughput + the pinned RX core's utilization (1.0 = one core
saturated). Dev box: Ryzen 5 7640U, 12 core.

## Result

| RTT  | flow | Gbps  | rx_cores | udp_loss |
|------|------|------:|---------:|---------:|
| 0ms  | udp  | 1.196 | 0.96     | 80.1%    |
| 0ms  | tcp  | 0.969 | 0.86     | -        |
| 1ms  | udp  | 1.250 | 0.98     | 79.5%    |
| 1ms  | tcp  | 0.798 | 0.76     | -        |
| 5ms  | udp  | 1.222 | 0.97     | 79.8%    |
| 5ms  | tcp  | 0.627 | 0.43     | -        |
| 12ms | udp  | 1.243 | 0.97     | 79.6%    |
| 12ms | tcp  | 0.504 | 0.48     | -        |
| 24ms | udp  | 1.049 | 0.96     | 82.9%    |
| 24ms | tcp  | 0.424 | 0.38     | -        |

## Verdict: a CPU-bound regime EXISTS

- **UDP blast pins the RX core at ~0.97 and caps at ~1.2 Gbps with ~80% loss at
  every RTT.** The single core is a hard ~1.2 Gbps processing ceiling; offered
  load above it is dropped. Unambiguous CPU bound.
- **TCP is CPU-bound at low RTT, window-bound at high RTT.** 0ms: 0.97 Gbps @
  core 0.86 (near-ceiling). 24ms: 0.42 Gbps @ core 0.38 (core idle, window caps).
- The earlier "CPU wins don't move throughput" verdict (4b, #58) was
  **regime-specific to the 24ms single-flow WAN path** — window-bound, core idle.

## Implication for #4

CPU optimizations DO translate to throughput in the CPU-bound regime:
short-RTT / regional paths and aggregate / many-parallel-flow traffic, where the
1-core receiver ceiling (~1.2 Gbps here) is the binding constraint. In that
regime a 4% MAC saving ~= +50 Mbps, and larger codec-path wins scale directly.
They do NOT help the high-RTT single-flow case (window-bound).

**Caveat:** veth has no real NIC, so absolute Gbps is optimistic — a real NIC
adds its own ceiling. But the per-core processing ceiling is real and still
binds a fast-NIC / high-parallelism box. The finding (a CPU regime exists) is a
strong positive despite the optimistic absolute number.

## Where the RX core actually goes (next step if pursuing #4)

The ~1.2 Gbps ceiling is the sum of the receive path: TUN-write (~20% in the 4b
profile) + AEAD decrypt + FEC decode + SipHash. To raise the ceiling, attack the
biggest components first (TUN-write, then AEAD), not just the ~9% SipHash.
