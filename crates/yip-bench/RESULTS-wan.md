# yip WAN benchmark results

> **Reproducible:** `crates/yip-bench/wan/` — `provision.sh` then `run-wan-bench.sh` against any two root-SSH Linux hosts (see `wan.env.example`).

## Conditions

- **Hosts:** `EC2 us-east-1 (t3.small)` ↔ `EC2 us-west-2 (t3.small)` (two 1-vCPU / ~1 GB Debian 13 VPSes, kernel 6.1.0-54-cloud-amd64)
- **Baseline path:** ~60.628 ms RTT, single Gbit links
- **Date / commit:** 2026-10-18T18:03:54Z / `3b46250`
- **Host tuning (applied equally, all tunnels):** `net.core.rmem_max=net.core.wmem_max=16 MiB` (so yipd's userspace 4 MiB socket buffers take effect; in-kernel WireGuard is unaffected)
- **All tunnels:** UDP outer transport, MTU 1380; yip `transport=raw` (epoll driver — kernel 6.12 has no io_uring multishot recv, #25); WireGuard kernel module; OpenVPN static-key AES-256-GCM

> Single-vCPU is intentional: it is the honest small-VPS case. yip is a single-threaded userspace data plane, so on one core it shares CPU with the workload — unlike in-kernel WireGuard. Raw clean-path throughput is therefore not yip's strong suit here; **loss resilience is** (below).

## Clean-path throughput & latency

| tunnel | TCP 1-stream | TCP 4-stream | UDP goodput | UDP loss | idle RTT | RTT under load | CPU (A, 1 vCPU) |
|---|--:|--:|--:|--:|--:|--:|--:|
| baseline (no tunnel) | 411.0 Mbit/s | 1016.1 Mbit/s | 200.0 Mbit/s | 0.00% | 60.647 ms | 60.645 ms | 3.5% |
| yip | 163.2 Mbit/s | 175.2 Mbit/s | 200.0 Mbit/s | 0.00% | 61.503 ms | 61.538 ms | 20.4% |
| WireGuard | 422.0 Mbit/s | 823.6 Mbit/s | 200.0 Mbit/s | 0.01% | 54.989 ms | 55.206 ms | 18.8% |
| OpenVPN | 20.6 Mbit/s | 28.8 Mbit/s | 200.0 Mbit/s | 0.16% | 60.574 ms | 60.750 ms | 3.4% |

## Loss resilience (netem injected on the A→B outer path)

Effective end-to-end loss (ping) — lower is better; yip's FEC recovers what the others pass through:

| injected loss | baseline (no tunnel) | yip | WireGuard | OpenVPN |
|---|--:|--:|--:|--:|
| 0% | 0% | 0% | 0% | 0% |
| 1% | 0% | 0% | 0% | 0% |
| 3% | 5% | 1% | 3% | 3% |
| 5% | 7% | 1% | 4% | 5% |
| 10% | 12% | 0% | 11% | 6% |

TCP goodput under the same injected loss (Mbit/s):

| injected loss | baseline (no tunnel) | yip | WireGuard | OpenVPN |
|---|--:|--:|--:|--:|
| 0% | 420.5 | 156.8 | 420.8 | 18.0 |
| 1% | 3.0 | 11.3 | 3.2 | 2.7 |
| 3% | 1.7 | 117.6 | 1.2 | 1.6 |
| 5% | 1.6 | 81.5 | 1.0 | 0.9 |
| 10% | 0.6 | 16.6 | 0.5 | 0.5 |

## Reproduce
```sh
cd crates/yip-bench/wan
cp wan.env.example wan.env   # edit HOST_A/HOST_B/SSH_KEY
./provision.sh              # install tooling, ship yipd, bring up 3 tunnels
./run-wan-bench.sh          # run the matrix -> results/<ts>/wan.csv
./collect.sh                # regenerate this file
./teardown.sh               # remove tunnels + netem
```
