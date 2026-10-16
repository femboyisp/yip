# yip WAN benchmark results

> **Reproducible:** `crates/yip-bench/wan/` — `provision.sh` then `run-wan-bench.sh` against any two root-SSH Linux hosts (see `wan.env.example`).

## Conditions

- **Hosts:** `VPS-A (Las Vegas)` ↔ `VPS-B (Utah)` (two 1-vCPU / ~1 GB Debian 13 VPSes, kernel 6.12.63+deb13-cloud-amd64)
- **Baseline path:** ~23.245 ms RTT, single Gbit links
- **Date / commit:** 2026-07-15T06:14:31Z / `8cdc7f6`
- **Host tuning (applied equally, all tunnels):** `net.core.rmem_max=net.core.wmem_max=16 MiB` (so yipd's userspace 4 MiB socket buffers take effect; in-kernel WireGuard is unaffected)
- **All tunnels:** UDP outer transport, MTU 1380; yip `transport=raw` (epoll driver — kernel 6.12 has no io_uring multishot recv, #25); WireGuard kernel module; OpenVPN static-key AES-256-GCM

> Single-vCPU is intentional: it is the honest small-VPS case. yip is a single-threaded userspace data plane, so on one core it shares CPU with the workload — unlike in-kernel WireGuard. Raw clean-path throughput is therefore not yip's strong suit here; **loss resilience is** (below).

## Clean-path throughput & latency

| tunnel | TCP 1-stream | TCP 4-stream | UDP goodput | UDP loss | idle RTT | RTT under load | CPU (A, 1 vCPU) |
|---|--:|--:|--:|--:|--:|--:|--:|
| baseline (no tunnel) | 1161.6 Mbit/s | 4110.7 Mbit/s | 200.0 Mbit/s | 1.25% | 23.245 ms | 24.958 ms | 13.4% |
| yip | 116.8 Mbit/s | 138.4 Mbit/s | 200.0 Mbit/s | 2.06% | 24.768 ms | 50.877 ms | 41.2% |
| WireGuard | 438.1 Mbit/s | 447.4 Mbit/s | 200.0 Mbit/s | 4.24% | 23.282 ms | 23.760 ms | 46.2% |
| OpenVPN | 38.5 Mbit/s | 60.5 Mbit/s | 200.0 Mbit/s | 5.61% | 26.114 ms | 23.822 ms | 48.5% |

## Loss resilience (netem injected on the A→B outer path)

Effective end-to-end loss (ping) — lower is better; yip's FEC recovers what the others pass through:

| injected loss | baseline (no tunnel) | yip | WireGuard | OpenVPN |
|---|--:|--:|--:|--:|
| 0% | 0% | 0% | 0% | 0% |
| 1% | 2% | 0% | 1% | 1% |
| 3% | 5% | 0% | 2% | 4% |
| 5% | 9% | 0% | 1% | 5% |
| 10% | 7% | 1% | 9% | 11% |

TCP goodput under the same injected loss (Mbit/s):

| injected loss | baseline (no tunnel) | yip | WireGuard | OpenVPN |
|---|--:|--:|--:|--:|
| 0% | 1155.6 | 53.2 | 442.4 | 42.1 |
| 1% | 6.7 | 93.7 | 5.1 | 6.6 |
| 3% | 37.6 | 35.6 | 2.5 | 2.4 |
| 5% | 2.9 | 24.8 | 1.7 | 1.8 |
| 10% | 1.2 | 13.0 | 1.0 | 0.9 |

## Reproduce
```sh
cd crates/yip-bench/wan
cp wan.env.example wan.env   # edit HOST_A/HOST_B/SSH_KEY
./provision.sh              # install tooling, ship yipd, bring up 3 tunnels
./run-wan-bench.sh          # run the matrix -> results/<ts>/wan.csv
./collect.sh                # regenerate this file
./teardown.sh               # remove tunnels + netem
```
