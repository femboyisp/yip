# yip WAN benchmark results

> **Reproducible:** `crates/yip-bench/wan/` — `provision.sh` then `run-wan-bench.sh` against any two root-SSH Linux hosts (see `wan.env.example`).

## Conditions

- **Hosts:** `EC2 us-east-1 (t3.small)` ↔ `EC2 us-west-2 (t3.small)` (two 1-vCPU / ~1 GB Debian 13 VPSes, kernel 6.1.0-54-cloud-amd64)
- **Baseline path:** ~54.513 ms RTT, single Gbit links
- **Date / commit:** 2026-10-18T18:22:48Z / `ad9d573`
- **Host tuning (applied equally, all tunnels):** `net.core.rmem_max=net.core.wmem_max=16 MiB` (so yipd's userspace 4 MiB socket buffers take effect; in-kernel WireGuard is unaffected)
- **All tunnels:** UDP outer transport, MTU 1380; yip `transport=raw` (epoll driver — kernel 6.12 has no io_uring multishot recv, #25); WireGuard kernel module; OpenVPN static-key AES-256-GCM

> Single-vCPU is intentional: it is the honest small-VPS case. yip is a single-threaded userspace data plane, so on one core it shares CPU with the workload — unlike in-kernel WireGuard. Raw clean-path throughput is therefore not yip's strong suit here; **loss resilience is** (below).

## Clean-path throughput & latency

| tunnel | TCP 1-stream | TCP 4-stream | UDP goodput | UDP loss | idle RTT | RTT under load | CPU (A, 1 vCPU) |
|---|--:|--:|--:|--:|--:|--:|--:|
| baseline (no tunnel) | 388.2 Mbit/s | 1376.4 Mbit/s | 200.0 Mbit/s | 0.00% | 54.497 ms | 54.507 ms | 2.8% |
| yip | 231.2 Mbit/s | 213.9 Mbit/s | 200.0 Mbit/s | 1.75% | 54.916 ms | 59.944 ms | 15.3% |
| WireGuard | 426.4 Mbit/s | 1434.0 Mbit/s | 200.0 Mbit/s | 0.51% | 54.705 ms | 54.746 ms | 12.5% |
| OpenVPN | 21.6 Mbit/s | 30.7 Mbit/s | 200.0 Mbit/s | 0.00% | 57.935 ms | 57.295 ms | 4.3% |

## Loss resilience (netem injected on the A→B outer path)

Effective end-to-end loss (ping) — lower is better; yip's FEC recovers what the others pass through:

| injected loss | baseline (no tunnel) | yip | WireGuard | OpenVPN |
|---|--:|--:|--:|--:|
| 0% | 0% | 0% | 0% | 0% |
| 1% | 0% | 0% | 1% | 0% |
| 3% | 0% | 0% | 2% | 5% |
| 5% | 6% | 0% | 6% | 4% |
| 10% | 13% | 1% | 14% | 10% |

TCP goodput under the same injected loss (Mbit/s):

| injected loss | baseline (no tunnel) | yip | WireGuard | OpenVPN |
|---|--:|--:|--:|--:|
| 0% | 426.2 | 108.3 | 426.4 | 27.6 |
| 1% | 4.6 | 38.4 | 2.4 | 2.4 |
| 3% | 1.1 | 167.2 | 1.2 | 1.4 |
| 5% | 1.1 | 14.2 | 0.8 | 0.7 |
| 10% | 0.7 | 35.6 | 0.5 | 0.4 |

## Reproduce
```sh
cd crates/yip-bench/wan
cp wan.env.example wan.env   # edit HOST_A/HOST_B/SSH_KEY
./provision.sh              # install tooling, ship yipd, bring up 3 tunnels
./run-wan-bench.sh          # run the matrix -> results/<ts>/wan.csv
./collect.sh                # regenerate this file
./teardown.sh               # remove tunnels + netem
```
