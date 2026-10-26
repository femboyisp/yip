<div align="center">

<img src="assets/banner.svg" alt="yip logo" width="400" />

# 🦊 yip

**Low-latency P2P mesh VPN in Rust.**<br/>
*Reed-Solomon FEC loss immunity • 40 Gbps AF_XDP multi-core scaling • NAT traversal • Self-certifying routing • Anti-DPI TLS mimicry*

<p align="center">
  <a href="https://github.com/femboyisp/yip/actions/workflows/ci.yml"><img src="https://github.com/femboyisp/yip/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0" /></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.85%2B-orange.svg" alt="Rust 1.85+" /></a>
  <a href="docs/01-getting-started.md"><img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Platform: Linux" /></a>
  <a href="bin/yipd/tests/run-multi-dpi-oracle.sh"><img src="https://img.shields.io/badge/dpi%20oracle-4%20engines%20clean-brightgreen.svg" alt="DPI Oracle" /></a>
</p>

</div>

---

## What is yip?

Ever wonder why standard VPNs choke the moment a packet drops? WireGuard is fantastic on a pristine gigabit fiber link, but on lossy Wi-Fi, cellular, or crowded trans-oceanic routes, TCP panics, triggers exponential backoff, and collapses.

**yip fixes this.** It is a fast, clever peer-to-peer mesh VPN in Rust that bakes Reed-Solomon forward error correction straight into the wire. Missing packets get reconstructed in-flight before the application even realizes a drop happened.

Under the hood, yip pairs proactive loss recovery with 40 Gbps AF_XDP zero-copy line-rate scaling, automatic NAT hole-punching, post-quantum ML-KEM handshakes, and authentic Chrome TLS mimicry to sneak past strict DPI firewalls unnoticed. It runs circles around packet loss and keeps your connections alive where ordinary tunnels stall out.

> [!NOTE]
> yip builds an encrypted peer-to-peer overlay, not an anonymizing mix-net like Tor. Connected peers authenticate each other directly and see each other's physical IP addresses.

---

## When to Use yip

| Use yip for | Stick with WireGuard or others for |
| :--- | :--- |
| **Contended, lossy, or wireless links** (cellular, satellite, trans-oceanic transit) where packet drops stall standard tunnels | **Clean zero-loss gigabit LANs** where in-kernel WireGuard already saturates the wire with lower CPU overhead |
| **High-packet-rate 40G/100G edge infrastructure** scaling across multiple CPU cores via zero-copy AF_XDP | **Anonymity or mix-net routing** without trusted multi-hop relay chaining (peers authenticate directly) |
| **Hostile network environments** monitored by aggressive Deep Packet Inspection (DPI) firewalls | **Desktop platforms other than Linux** (macOS and Windows desktop clients are not currently supported) |
| **Future-proof quantum resistance** via NIST FIPS 203 ML-KEM-512 hybrid handshakes | Environments where legacy unencrypted protocols or centralized proprietary controllers are required |

---

## 5-Minute Quickstart

Set up an encrypted, forward-error-corrected tunnel between two Linux nodes in four steps:

```bash
# 1. Install pre-compiled static binary (or: cargo binstall yipd)
curl -fsSL https://raw.githubusercontent.com/femboyisp/yip/main/install.sh | sh

# 2. Generate identity keypair and print self-certifying overlay IPv6 address
yipd --genkey > /etc/yip/node.key && yipd --addr $(grep '^public=' /etc/yip/node.key | cut -d= -f2)

# 3. Start the daemon (systemd service or direct configuration file invocation)
sudo systemctl start yipd
# Or run manually: sudo yipd /etc/yip/yipd.conf

# 4. Verify telemetry and ping remote overlay peer
yipctl status
ping6 <peer-overlay-ip>
```

---

## Minimal Working Configurations

### Scenario A: Direct Point-to-Point (VPS-to-VPS)

Direct UDP tunnel between two publicly addressable nodes with Cauchy RS-FEC:

```toml
# /etc/yip/yipd.conf (Host A: 198.51.100.1)
local_private = e81d76326087b220d3f237ef39aa4d91361ff55b7661005a7657d23d8c117d4a
local_public  = 7df4d68205f03a2cae7e1713444fcda80ff43a29de7e9b0b4b2c159286d9a11a
listen        = 0.0.0.0:443
device        = yip0

# Remote peer: Host B (203.0.113.2)
[peer]
public_key    = 9b49ffeb4566b53a0f78cae08920bc9e30a6e0c60f252cfdf4740e74f8c92b21
endpoint      = 203.0.113.2:443
```

### Scenario B: NAT Rendezvous (Behind CGNAT)

Node behind NAT discovering and coordinating through an intermediate rendezvous relay:

```toml
# /etc/yip/yipd.conf (Node A behind CGNAT)
local_private = 1111111111111111111111111111111111111111111111111111111111111111
local_public  = 2222222222222222222222222222222222222222222222222222222222222222
listen        = 0.0.0.0:443
device        = yip0
rendezvous    = 198.51.100.5:51821

# Remote peer: Node B (endpoint resolved dynamically via rendezvous)
[peer]
public_key    = 3333333333333333333333333333333333333333333333333333333333333333
```

---

## Performance & Benchmark Highlights

Deterministic benchmarks measured across multi-region cloud WANs (AWS `us-east-1` to `us-west-2`, ~58ms RTT) and multi-core edge hardware:

<p align="center">
  <img src="assets/bench-throughput-loss.svg" width="49%" alt="Throughput Under Packet Loss" />
  <img src="assets/bench-multicore-scaling.svg" width="49%" alt="Multi-Core Scaling" />
</p>

- **138× throughput advantage at 10% packet loss**: Sustains **14.0 Mbit/s** goodput where WireGuard collapses to **0.1 Mbit/s**.
- **23× throughput advantage at 3% loss**: Delivers **221.3 Mbit/s** compared to WireGuard's **9.6 Mbit/s**.
- **40.27 Gbps line-rate scaling**: Scales across 8 CPU cores (3.93 Mpps) using zero-copy AF_XDP and lock-free SPSC queues.
- **Flat ~62ms P99 latency**: In-flight symbol reconstruction eliminates TCP head-of-line blocking and retransmission spikes across 0% to 10% packet loss.

<details>
<summary><b>Click to expand raw automated WAN benchmark data table</b></summary>

<!-- BENCHMARK-TABLE-START -->

<!-- generated by crates/yip-bench/wan/collect.sh -->
*Two 1-vCPU Debian 13 VPSes, ~54.902 ms apart, 2026-10-26. yip trades raw clean-path throughput for loss resilience (see the FEC row).*

| | TCP 1-stream | UDP loss (200M) | effective loss @10% injected |
|---|--:|--:|--:|
| **yip** | 290.6 Mbit/s | 0.05% | 1% |
| **WireGuard** | 408.1 Mbit/s | 10.72% | 9% |
| **OpenVPN** | 21.4 Mbit/s | 0.35% | 10% |

<!-- BENCHMARK-TABLE-END -->

</details>

Full methodology and reproducible test harnesses are documented in [`crates/yip-bench/RESULTS.md`](crates/yip-bench/RESULTS.md) and [`05. Benchmarks & Performance`](docs/05-benchmarking-and-performance.md).

---

## Documentation Curriculum

| Document | Purpose |
| :--- | :--- |
| [`01. Getting Started`](docs/01-getting-started.md) | Platform requirements, installation options, systemd/init services, and first-tunnel setup |
| [`02. Configuration Reference`](docs/02-configuration.md) | Comprehensive parameter reference, production deployment scenarios, and `yipctl` command guide |
| [`03. Architecture & Internals`](docs/03-architecture.md) | Control and data plane separation, kernel-bypass AF_XDP queues, Cauchy RS-FEC, and memory hierarchy |
| [`04. Security & Threat Model`](docs/04-security-and-threat-model.md) | Post-quantum hybrid handshake, zero-fixed-signature wire format, and anti-DPI test oracle defenses |
| [`05. Benchmarks & Performance`](docs/05-benchmarking-and-performance.md) | Real-world WAN test data, multi-core scaling charts, loss-recovery mathematical proofs, and kernel tuning |
| [`06. Troubleshooting Runbook`](docs/06-troubleshooting.md) | Step-by-step diagnostic workflows, MTU discovery issues, NAT traversal debugging, and telemetry inspection |

---

## License

Copyright © 2026 FEMBOY CYBER NETWORKS LLC.

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
