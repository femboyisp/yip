<p align="center">
  <img src="assets/yip.gif" alt="yip logo" width="320">
</p>

# yip

**Post-quantum, loss-resilient encrypted overlay mesh with kernel-bypass datapaths and active anti-DPI defense.**

<p align="center">
  <a href="https://github.com/femboyisp/yip/actions/workflows/ci.yml"><img src="https://github.com/femboyisp/yip/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-orange.svg" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Platform: Linux">
  <img src="https://img.shields.io/badge/DPI%20Evasion-4--Engine%20Oracle-brightgreen" alt="DPI Evasion: 4-Engine Oracle">
</p>

---

## What is `yip`?

`yip` is a high-performance encrypted overlay tunnel engineered with proactive Cauchy Reed–Solomon Forward Error Correction (RS-FEC over GF(256)) and hybrid post-quantum cryptography (`Noise_IKpsk2` + ML-KEM-512). Traditional VPNs (such as WireGuard) suffer catastrophic TCP throughput collapse under packet loss—even a 1% to 10% packet drop rate triggers congestion backoff that reduces TCP transmission speeds by 90% to 99%. `yip` reconstructs lost symbols in-flight before kernel TCP stacks register a drop, sustaining high goodput without backoff. It is purpose-built for systems engineers, network operators, and infrastructure teams connecting lossy, contested, or censorship-heavy links. `yip` is **not** an anonymity network or Tor alternative: endpoints authenticate directly, and peer IP addresses are visible to peers in the mesh.

---

## When to Use `yip`

Evaluate whether `yip` is the right fit for your network topology and operational requirements:

| Use `yip` for | Do NOT use `yip` for |
| :--- | :--- |
| **Contended, lossy, or wireless WAN links** (cellular, satellite, trans-oceanic) where drop rates stall standard VPNs | **Anonymity / mix-net routing** without trusted multi-hop relay chaining (peer endpoints authenticate directly) |
| **High-packet-rate multi-core 40G/100G edge infrastructure** scaling linearly via AF_XDP zero-copy kernel bypass | **Clean zero-loss gigabit LANs** where kernel WireGuard already saturates line rate with lower CPU overhead |
| **Environments requiring quantum resistance** through NIST FIPS 203 ML-KEM-512 hybrid handshakes | **General-purpose non-Linux hosts** (macOS and Windows desktop clients are not currently supported) |
| **Networks monitored by hostile Deep Packet Inspection firewalls** via uTLS fingerprinting and Xray-REALITY TLS 1.3 | Environments where legacy unencrypted protocols or centralized proprietary controllers are mandated |

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

The following minimal working configurations illustrate point-to-point and NAT-traversed topologies:

### Scenario A: Direct Point-to-Point (VPS-to-VPS)

Direct UDP tunnel between two publicly addressable nodes with Cauchy RS-FEC:

```toml
# /etc/yip/yipd.conf (Host A - 198.51.100.1)
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

Deterministic benchmarks measured across multi-region cloud WANs (AWS `us-east-1` ↔ `us-west-2`, ~58ms RTT) and multi-core edge hardware:

<p align="center">
  <img src="assets/bench-throughput-loss.svg" width="49%" alt="Throughput Under Packet Loss" />
  <img src="assets/bench-multicore-scaling.svg" width="49%" alt="Multi-Core Scaling" />
</p>

- **138× throughput advantage at 10% packet loss**: Sustains **14.0 Mbit/s** goodput where WireGuard collapses to **0.1 Mbit/s**.
- **23× throughput advantage at 3% loss**: Delivers **221.3 Mbit/s** compared to WireGuard's **9.6 Mbit/s**.
- **40.27 Gbps line-rate scaling**: Scales across 8 CPU cores (3.93 Mpps) using zero-copy AF_XDP and lock-free SPSC queues.
- **Flat ~62ms P99 latency**: In-flight symbol reconstruction eliminates TCP head-of-line blocking and retransmission spikes across 0% to 10% packet loss.

Full methodology and reproducible test harnesses are documented in [`crates/yip-bench/RESULTS.md`](crates/yip-bench/RESULTS.md) and [`05. Benchmarks & Performance`](docs/05-benchmarking-and-performance.md).

---

## Documentation Curriculum

The `yip` engineering documentation is organized into six comprehensive guides:

| Document | Purpose |
| :--- | :--- |
| [`01. Getting Started`](docs/01-getting-started.md) | Platform requirements, installation options, systemd/init services, and first-tunnel setup |
| [`02. Configuration Reference`](docs/02-configuration.md) | Comprehensive parameter reference, production deployment scenarios, and `yipctl` command guide |
| [`03. Architecture & Internals`](docs/03-architecture.md) | Control/data plane separation, kernel-bypass AF_XDP queues, Cauchy RS-FEC, and memory hierarchy |
| [`04. Security & Threat Model`](docs/04-security-and-threat-model.md) | Post-quantum hybrid handshake, zero-fixed-signature wire format, and anti-DPI test oracle defenses |
| [`05. Benchmarks & Performance`](docs/05-benchmarking-and-performance.md) | Real-world WAN test data, multi-core scaling charts, loss-recovery mathematical proofs, and kernel tuning |
| [`06. Troubleshooting Runbook`](docs/06-troubleshooting.md) | Step-by-step diagnostic workflows, MTU discovery issues, NAT traversal debugging, and telemetry inspection |

---

## License

Copyright © 2026 FEMBOY CYBER NETWORKS LLC.

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
