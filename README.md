<div align="center">

<img src="assets/yip.gif" alt="yip logo" width="340" />

# 🦊 yip

**Low-latency P2P mesh VPN in Rust.**<br/>
*Reed-Solomon FEC loss immunity • 40 Gbps AF_XDP multi-core scaling • NAT traversal • Zero-trust CA mesh • Anti-DPI TLS mimicry*

<p align="center">
  <a href="https://github.com/femboyisp/yip/actions/workflows/ci.yml"><img src="https://github.com/femboyisp/yip/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0" /></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.85%2B-orange.svg" alt="Rust 1.85+" /></a>
  <a href="docs/01-getting-started.md"><img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Platform: Linux" /></a>
  <a href="bin/yipd/tests/run-multi-dpi-oracle.sh"><img src="https://img.shields.io/badge/dpi%20oracle-4%20engines%20clean-brightgreen.svg" alt="DPI Oracle" /></a>
</p>

<p align="center">
  <img src="assets/terminal-telemetry.gif" width="100%" alt="yipctl top: live multi-transport mesh telemetry dashboard" />
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

<a id="why-yip"></a>
## Why yip Exists: The Problem with Traditional VPNs

Every modern tunnel protocol (WireGuard, OpenVPN, IPsec) operates on a fatal assumption: the underlying transport network delivers packets reliably. On clean local fiber or controlled datacenter cross-connects, that assumption holds. WireGuard achieves stellar throughput with minimal CPU overhead.

The open internet is not a clean datacenter cross-connect. When you transmit across long-haul continental WANs, congested public Wi-Fi, cellular networks, or international boundaries, packet loss is an inescapable reality.

When an underlying network drops packets, standard VPNs pass that loss straight up the protocol stack. For TCP connections, this triggers catastrophic congestion control backoff. Mathis' formula models this throughput limit:

$$T \le \frac{MSS}{RTT} \times \frac{C}{\sqrt{p}}$$

Because throughput is inversely proportional to the square root of packet loss probability ($p$), even a modest 1% to 3% packet loss rate forces TCP into severe window throttling, slashing effective throughput by 90% to 99%. On a 100 Mbit/s link with 60ms round-trip time, injecting just 3% packet loss can plummet transfer speeds from 95 Mbit/s down to under 10 Mbit/s. At 10% packet loss, connections stall completely.

**yip's answer is proactive in-flight repair.** Instead of waiting for timeout expirations and reactive retransmissions, yip computes Cauchy Reed-Solomon erasure coding over Galois Field $GF(2^8)$ directly in the datapath. For every block of data packets, yip generates dynamic mathematical parity packets in-flight. When transit networks drop intermediate packets, yip reconstructs the missing symbols on the fly before kernel TCP stacks or user applications ever detect a gap. The result is sustained throughput and predictable latency across lossy links.

---

## Comprehensive 6-Pillar Feature Showcase

### 1. Galois Field Proactive FEC
- **Systematic Cauchy RS + RLNC Streaming**: In-flight erasure coding over $GF(2^8)$ pairs Cauchy Reed-Solomon block codes with Random Linear Network Coding (RLNC) streaming fountain codes.
- **Poly-Vector SIMD Acceleration**: Hardware-accelerated matrix multiplication across AVX-512BW, Intel GFNI, AVX2, SSSE3, ARM NEON, and WebAssembly SIMD128.
- **Adaptive Repair Scaling**: Real-time sliding window telemetry dynamically adjusts repair symbol overhead based on observed channel loss, eliminating goodput waste on clean links.
- **Zero-Allocation Hot-Path Reassembly**: Pre-allocated contiguous object buffers and in-place Cauchy RS repair (`reconstruct_missing_sources`) deliver clean packets in **117 ns** with zero heap allocations.

### 2. Zero-Trust PKI & Decentralized Mesh Membership
- **Dual Cryptographic CA Architecture**: Supports both an air-gapped, offline master key root CA (`yip-ca sign-cert`) and an online, decentralized **$t$-of-$n$ Threshold CA** (`yip-ca serve --role coordinator|signer`).
- **RFC 9591 FROST Ed25519 Quorum**: Threshold signers collaborate using the FROST(Ed25519, SHA-512) ciphersuite. Because Schnorr threshold signatures aggregate linearly into a standard 64-byte Ed25519 signature, threshold credentials are 100% byte-for-byte indistinguishable from single-signer certificates, requiring zero changes to existing node verifiers.
- **Single-Round (1-RTT) Online Enrollment**: Pre-generated nonce pools (`frost_ed25519::round1::preprocess`) pre-cached at the coordinator collapse online certificate enrollment from two network round-trips to a single RPC round-trip.
- **Asynchronous Robustness (ROAST)**: Coordinator signing loop is wrapped in a ROAST state machine, guaranteeing progress and unforgeable issuance even if up to $n - t$ signers are unresponsive, delayed, or Byzantine.
- **Rollback-Immune Nonce Vault**: Memory-locked (`mlock`), zeroized-on-drop ephemeral nonce pools bound to 128-bit CSPRNG boot-epoch IDs eliminate nonce-reuse private key extraction under VM snapshots.
- **Automated Lifecycle & Background Renewal**: Proactive zero-knowledge polynomial share refreshing (CVE-2025-58359 hardened), lost-share repair, and automated zero-touch renewal inside `bin/yipd` at $\ge 70\%$ of certificate TTL.
- **Signed RootSets & Epidemic Gossip**: Node identity, authorized endpoints, and routing capabilities propagate across nodes using anti-entropy gossip protocol records (`Record`) with cryptographic signature validation.
- **TAI64N Anti-Replay Freshness Gating**: Sub-nanosecond monotonic timestamps enforce strict certificate freshness and reject stale or replayed topology announcements.

```mermaid
flowchart TD
    subgraph ThresholdCA ["Decentralized Threshold CA Quorum (t-of-n FROST)"]
        Coord["Coordinator Gateway<br/>(yip-ca serve --role coordinator)<br/>ROAST State Machine"]
        S1["Signer 1<br/>KeyShare 1<br/>Nonce Vault"]
        S2["Signer 2<br/>KeyShare 2<br/>Nonce Vault"]
        Sn["Signer n<br/>KeyShare n<br/>Nonce Vault"]

        S1 -.->|1. Preprocessed Nonce Commitments| Coord
        S2 -.->|1. Preprocessed Nonce Commitments| Coord
        Sn -.->|1. Preprocessed Nonce Commitments| Coord
    end

    Node["Mesh Member Node (yipd)<br/>Automatic 70% TTL Rotation"]

    Node -->|2. Enroll Request (CSR + PoP)| Coord
    Coord -->|3. SigningPackage (Single RTT)| S1 & S2
    S1 & S2 -->|4. Signature Shares| Coord
    Coord -->|5. Linear Aggregation (RFC 9591)| Coord
    Coord -->|6. Standard 64-byte Ed25519 Cert| Node
```

### 3. Kernel-Bypass Performance
- **Zero-Copy AF_XDP (XSK)**: Direct UMEM memory ring driver with per-core slab partitioning and lock-free ring recycling bypasses the Linux network stack, sustaining 40.27 Gbps and 3.93 Mpps across 8 CPU cores.
- **Asynchronous `io_uring`**: High-performance multishot ring polling drives high packet rates without thread contention or syscall overhead.
- **Multi-Queue TUN Sharding**: `IFF_MULTI_QUEUE` worker isolation maps packet flows to dedicated CPU cores via lock-free SPSC ring buffers.
- **Vectorized Socket I/O**: Batched `recvmmsg` and `sendmmsg` (tunable 32/64/128-packet bursts) with `UDP_SEGMENT` Generic Segmentation Offload (GSO) optimize standard POSIX network paths.
- **Flat Open-Addressing Tables**: Replaces dynamic pointer maps with bounded flat slot tables using SplitMix64 fast hashing and backward-shift deletion with zero tombstones.

### 4. Post-Quantum Cryptography & Identity
- **Single-RTT Hybrid Handshake**: Blends Noise_IKpsk2 (Curve25519) with NIST FIPS 203 ML-KEM-512 (Kyber) within compact datagrams strictly under the 1200-byte internet MTU floor.
- **120-Second Epoch Ratcheting**: Automated forward-secrecy key rotation with a 20-second dual-receive grace window prevents dropped packets during rekey transitions.
- **Rigorous Memory Hygiene**: Cryptographic secrets implement explicit `Zeroize` traits to purge private key material from memory buffers immediately upon drop.
- **Self-Certifying IPv6 Addressing**: Cryptographic BLAKE2s-120 hashing derives immutable, anti-spoofing overlay addresses in the `fd00::/8` ULA space directly from node public keys.

### 5. 4-Mode Anti-DPI Armor
- **`raw-obf`**: SipHash-CTR keystream masking with a 64-bit SipHash-1-3 coverage authentication tag strips all fixed wire headers, leaving uniform high-entropy payload noise.
- **`quic` Masquerade**: Encapsulates tunnel traffic inside standard RFC 9221 HTTP/3 datagrams indistinguishable from ordinary web media traffic.
- **`tls` Emulation**: Authentic TLS 1.3 framing paired with uTLS Google Chrome ClientHello fingerprints evades SNI inspection and protocol whitelisting.
- **`relay` (REALITY)**: Advanced certificate borrowing and transparent TCP splicing forward unauthorized probes to authentic upstream target servers.
- **DAITA Cover Defense**: Discrete packet-length bucketing and randomized decoy traffic defeat statistical packet-size analysis and website fingerprinting.
- **4-Engine DPI Oracle Verified**: Continuously tested and verified clean against nDPI, Zeek, Suricata, and Wireshark inspection rules.

### 6. NAT Traversal & Blind Relays
- **STUN UDP Hole-Punching**: Embedded STUN resolver discovers public reflexive mappings and classifies symmetric, full-cone, and port-restricted NAT topologies.
- **Zero-Knowledge Blind Relays**: Untrusted rendezvous nodes (`yip-rendezvous`) relay encrypted envelopes without possessing decryption keys or inspecting packet contents.
- **Seamless Roaming**: Cryptographic session binding automatically maintains connection state when roaming between Wi-Fi, Ethernet, and cellular interfaces.
- **Headless Daemon Control**: Full management and real-time observability over a protected UNIX domain control socket using the `yipctl` command-line utility.

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
local_private = dd152fc311a115549005da852d101a7d3a14594c728f71ff87aa0872da6c0fa9
local_public  = bf923deeaddb66dde39e99987abdfd789c54eb882a570c340cd338071727ceeb
listen        = 0.0.0.0:443
device        = yip0

# Remote peer: Host B (203.0.113.2)
[peer]
public_key    = 1f5b6b76d9723a79221777a7450522c32faa7300efd59b0a5efa42665cac0a0a
endpoint      = 203.0.113.2:443
```

### Scenario B: NAT Rendezvous (Behind CGNAT)

Node behind NAT discovering and coordinating through an intermediate rendezvous relay:

```toml
# /etc/yip/yipd.conf (Node A behind CGNAT)
local_private = 2f2b5880cc15f29f826e876f5396c6f418e2366b73b415c5441f152b23c0334d
local_public  = 4cbc48cf095389d829abf3c7d78747ca35c96483375bd73860b2ebba94c99d50
listen        = 0.0.0.0:443
device        = yip0
rendezvous    = 198.51.100.5:443

# Remote peer: Node B (endpoint resolved dynamically via rendezvous)
[peer]
public_key    = 6ed3f82ba6450cd14ec52509deb42a87c6a8d2fa91a5a145f2ddcfdb0d675d12
```

### Scenario C: Zero-Trust CA Mesh (Dynamic Discovery)

Nodes discover and peer with authorized members automatically via signed gossip and rendezvous, requiring zero manual `[peer]` entries:

```toml
# /etc/yip/yipd.conf (Mesh Member Node)
local_private       = 2f2b5880cc15f29f826e876f5396c6f418e2366b73b415c5441f152b23c0334d
local_public        = 4cbc48cf095389d829abf3c7d78747ca35c96483375bd73860b2ebba94c99d50
listen              = 0.0.0.0:443
device              = yip0
rendezvous          = 198.51.100.5:443

# Zero-trust CA mesh enrollment (issued via yip-ca offline or online threshold CA)
ca_public           = 8a03a4cf43c2907041efb394c0effabad5bdb4cbbc35d17c924c0b6cbfa8ba75
cert                = /etc/yip/node.cert
roots               = /etc/yip/network.roots
member_sign_private = c22239d00522843313aa03a662e8f0cb6abb7889f8f103510ebb5dee0e924857
network_id          = f11a8e0df8fa6352eeb62192de7ece47

# Optional: Online threshold CA coordinator for zero-touch background renewal at >= 70% TTL
threshold_ca_server = 198.51.100.10:4443
```

Check certificate validity or trigger immediate renewal via the daemon control socket:
```bash
sudo yipd cert status
sudo yipd cert renew
```

---

## Performance & Benchmark Highlights

Deterministic benchmarks measured across multi-region cloud WANs (AWS `us-east-1` to `us-west-2`, ~58ms RTT) and multi-core edge hardware:

<p align="center">
  <img src="assets/bench-throughput-loss.svg" width="49%" alt="Throughput Under Packet Loss" />
  <img src="assets/bench-multicore-scaling.svg" width="49%" alt="Multi-Core Scaling" />
</p>

- **173× throughput advantage at 10% packet loss**: Sustains **86.6 Mbit/s** goodput where WireGuard collapses to **0.5 Mbit/s**.
- **193× throughput advantage at 3% loss**: Delivers **251.3 Mbit/s** compared to WireGuard's **1.3 Mbit/s**.
- **40.27 Gbps line-rate scaling**: Scales across 8 CPU cores (3.93 Mpps) using zero-copy AF_XDP and lock-free SPSC queues.
- **Flat ~60ms P99 latency**: In-flight symbol reconstruction eliminates TCP head-of-line blocking and retransmission spikes across 0% to 10% packet loss.

<details>
<summary><b>Click to expand raw automated WAN benchmark data table</b></summary>

<!-- BENCHMARK-TABLE-START -->

<!-- generated by crates/yip-bench/wan/collect.sh -->
*Two 1-vCPU Debian 13 VPSes, ~54.365 ms apart, 2026-10-27. yip trades raw clean-path throughput for loss resilience (see the FEC row).*

| | TCP 1-stream | UDP loss (200M) | effective loss @10% injected |
|---|--:|--:|--:|
| **yip** | 253.7 Mbit/s | 0.00% | 0% |
| **WireGuard** | 453.1 Mbit/s | 0.00% | 7% |
| **OpenVPN** | 32.6 Mbit/s | 0.04% | 8% |

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
| [`Motivation & Philosophy`](docs/motivation.md) | Design philosophy, anti-censorship regulatory context, and the problem with traditional VPNs |

---

## License

Copyright © 2026 FEMBOY CYBER NETWORKS LLC.

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
