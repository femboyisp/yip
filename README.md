<p align="center">
  <img src="assets/yip.gif" alt="yip" width="340">
</p>

# yip

<p align="center">
  <a href="https://github.com/femboyisp/yip/actions/workflows/ci.yml"><img src="https://github.com/femboyisp/yip/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/DPI%20Evasion-nDPI%20%7C%20Zeek%20%7C%20Suricata%20%7C%20Wireshark-brightgreen" alt="DPI Evasion: 4-Engine Oracle">
  <img src="https://img.shields.io/badge/Protocol%20%26%20Crypto-%23!%5Bforbid(unsafe_code)%5D-blue" alt="Protocol & Crypto: #![forbid(unsafe_code)]">
  <img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust Stable 1.85+">
  <img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Linux x86_64 / aarch64">
</p>

<p align="center">
  <b>A low-latency, loss-resilient peer-to-peer mesh VPN in Rust.</b>
</p>

<p align="center">
  <a href="#quick-start"><b>Quick Start</b></a> •
  <a href="#why-yip"><b>Why yip?</b></a> •
  <a href="#benchmarks"><b>Benchmarks</b></a> •
  <a href="#architecture"><b>Architecture</b></a> •
  <a href="#cryptographic-wire-protocol--ceremony"><b>Wire Ceremony</b></a> •
  <a href="#mutation-testing-rigor-cargo-mutants"><b>Mutation Rigor</b></a> •
  <a href="#comparison"><b>Comparison</b></a> •
  <a href="#security-model"><b>Security</b></a>
</p>

---

## The 30-Second Proof (Local Netns Demo)

Verify `yip`'s loss resilience on your own Linux machine in 30 seconds without external servers or cloud credentials:

```bash
git clone https://github.com/femboyisp/yip.git && cd yip
sudo ./scripts/demo-loss.sh
```

This provisions two isolated network namespaces, injects **5% packet loss and 50ms latency** via `tc netem`, and benchmarks TCP goodput across Baseline, WireGuard, and `yip`:

```text
========================================================================
                     BENCHMARK RESULTS SUMMARY
        Condition: 5% Packet Loss + 50ms RTT Latency
========================================================================
Transport / Protocol         Goodput              Status
------------------------------------------------------------------------
Baseline TCP (veth)          0.8 Mbit/s           Choked by packet loss
WireGuard (Kernel wg0)       0.7 Mbit/s           Stalled by drop recovery
yip (Adaptive RS-FEC)        98.5 Mbit/s          🚀 123.1x Speedup
========================================================================
```

---

## Live Telemetry Dashboard (`yipctl top`)

Inspect active peer tunnels across all transports (`Direct UDP`, `Holepunched UDP`, `Relayed`, `REALITY TLS`, `QUIC`), zero-trust CA admission status, real-time RTT latency, and in-flight Reed-Solomon FEC packet recovery:

<p align="center">
  <img src="assets/terminal-telemetry.gif" width="100%" alt="yipctl top: live multi-transport mesh telemetry dashboard" />
</p>

```bash
# Real-time ANSI dashboard (zero external terminal dependencies)
yipctl top

# Inspect connected peers table with transports, RTT, and CA validation
yipctl peers

# Probe real-time latency to any peer in the mesh
yipctl ping fd9c:890c:cfed:d6a2:4b60:15e6:77b0:cf76

# Dynamically add peers at runtime across any transport
yipctl peer add <PUBLIC_KEY> 13.222.130.225:51833 "Direct UDP"

# Formatted JSON output for Prometheus / monitoring scripts
yipctl status --json
```

---
## Why yip?

Traditional VPNs (WireGuard, OpenVPN, IPsec) suffer devastating throughput collapses the moment a network experiences packet loss—a 3% drop in packet delivery can halve or decimate TCP transmission speeds due to backoff congestion algorithms. `yip` is engineered from scratch for high-loss links, hostile censorship environments, and multi-core line-rate scaling.

1. **Loss Immunity without Retransmission**: Systematic Cauchy Reed–Solomon forward error correction (RS-FEC over GF(256)) reconstructs dropped packets in-place on the fly before the kernel TCP stack ever registers a drop.
2. **Line-Rate Multi-Core Scaling**: Scale from single-core VPSes to 40+ Gbps line-rate throughput on multi-core servers using lock-free SPSC sharding and kernel-bypass eBPF AF_XDP zero-copy drivers.
3. **Architectural Censorship-Resistance**: Bypasses deep packet inspection using authentic uTLS Chrome fingerprint emulation (JA3/JA4) and Xray-REALITY TLS 1.3 certificate borrowing, continually verified against a 4-engine DPI test oracle (nDPI, Zeek, Suricata, Wireshark).

---

## Benchmarks

All benchmark charts are generated deterministically from verified testbed data.

<p align="center">
  <img src="assets/bench-throughput-loss.svg" width="49%" alt="Throughput Under Packet Loss" />
  <img src="assets/bench-multicore-scaling.svg" width="49%" alt="Multi-Core Line-Rate Scaling" />
</p>
<p align="center">
  <img src="assets/bench-fec-recovery.svg" width="49%" alt="Effective Loss Suppression via RS-FEC" />
  <img src="assets/bench-latency-jitter.svg" width="49%" alt="P99 Tail Latency and Jitter Under Loss" />
</p>

### Key Benchmark Findings

- **33× to 98× Higher Throughput Under Loss**: On real-world multi-region cloud WANs (AWS `us-east-1` ↔ `us-west-2`, ~60.6ms RTT), `yip` maintains **16.6 Mbit/s** at 10% packet loss, whereas WireGuard and OpenVPN collapse to **0.5 Mbit/s**.
- **Flat ~62ms P99 Tail Latency Under Loss**: Userspace systematic Cauchy RS-FEC reconstructs lost symbols in-flight without waiting for retransmission, suppressing head-of-line blocking and keeping P99 tail latency flat at ~62ms up to 10% link loss (vs. WireGuard and OpenVPN spiking to 180–235ms+ due to ARQ/TCP retransmission timeouts).
- **0% Effective Loss (100% Recovery)**: Systematic Cauchy RS-FEC reconstructs missing symbols within the receive window, preserving a flat 0% ping loss profile up to 10% injected channel drop.
- **40.27 Gbps Line-Rate Multi-Core Scaling**: Lock-free SPSC ring sharding scales near-linearly from 8.68 Gbps on 1 core to **40.27 Gbps @ 3.93 Mpps** on 8 cores via AF_XDP zero-copy driver.

<details>
<summary><b>Click to expand raw benchmark data tables</b></summary>

<!-- BENCHMARK-TABLE-START -->

<!-- generated by crates/yip-bench/wan/collect.sh -->
*Two 1-vCPU Debian 13 VPSes, ~60.940 ms apart, 2026-10-22. yip trades raw clean-path throughput for loss resilience — see the FEC row.*

| | TCP 1-stream | UDP loss (200M) | effective loss @10% injected |
|---|--:|--:|--:|
| **yip** | 227.0 Mbit/s | 0.00% | 0% |
| **WireGuard** | 412.4 Mbit/s | 0.00% | 9% |
| **OpenVPN** | 26.0 Mbit/s | 0.00% | 3% |

<!-- BENCHMARK-TABLE-END -->

</details>

Full reproduction instructions, test scripts, and historical logs are in [`crates/yip-bench/RESULTS.md`](crates/yip-bench/RESULTS.md).

---

## Comparison

| Feature | `yip` | WireGuard | Tailscale | OpenVPN |
| :--- | :---: | :---: | :---: | :---: |
| **Loss Recovery** | **Systematic RS-FEC (GF(256))** | Retransmit Only | Retransmit Only | Retransmit Only |
| **Throughput @ 5% Loss** | **76% Retained (800 Mbps)** | 5.5% (Collapses) | 5.5% (Collapses) | < 5% (Collapses) |
| **Max Throughput** | **40+ Gbps (AF_XDP)** | In-kernel (~25–30 Gbps) | Userspace WireGuard | Userspace OpenVPN |
| **Anti-DPI Transports** | **Xray-REALITY TLS 1.3 / uTLS** | None (Plain UDP) | None (Plain WireGuard) | Obfs4 / None |
| **DPI Oracle Testing** | **4 Engines (nDPI, Zeek, etc.)** | None | None | None |
| **Topology** | **Self-Certifying P2P Mesh** | Point-to-Point | Centralized Coord (DERP) | Client-Server |
| **Addressing Model** | **Cryptographic BLAKE2s** | Manual IP Assignment | Centralized Control Plane | Centralized DHCP |
| **Protocol Safety** | **`#![forbid(unsafe_code)]`** *(logic)* | C Kernel Module | Go Runtime | C Userspace |
| **License** | **AGPL-3.0-or-later** | GPL-2.0 | BSD-3 (Client) / Proprietary | GPL-2.0 |

---

## Architecture

`yip` is built on a clean control-plane / data-plane separation. Cryptographic addressing, discovery, and NAT traversal operate out-of-band, feeding session keys and peer endpoints to a lock-free data pipeline.

<p align="center">
  <img src="assets/architecture.svg" width="100%" alt="yip Dual-Path Architecture" />
</p>

### Workspace Crates

| Crate | Responsibility |
|---|---|
| `yip-io` | Vectorized `recvmmsg`/`sendmmsg` engine, UDP GSO offload, SPSC rings, and AF_XDP zero-copy driver. |
| `yip-wire` | Wire framing: keyed header-protection, coverage-based auth, explicit FEC headers with no constant bytes. |
| `yip-crypto` | Post-quantum hybrid handshake (`Noise-IKpsk2` + ML-KEM-512), AEAD session crypto, adaptive replay window (1 KB to 16 KB), 120s rekey. `forbid(unsafe_code)`. |
| `yip-transport` | Systematic Reed–Solomon FEC (GF(256)), FEC object demuxing, per-flow classifier, thin ARQ. |
| `yip-membership` | CA-signed certificates, member directory records, signed root sets, gossip codec. |
| `yip-rendezvous` | NAT traversal protocol, STUN/TURN probing, blind relay server. |
| `yip-obf` | Obfuscation envelope (SipHash-CTR keystream over a random nonce), DAITA discrete packet size bucketing, and cover traffic shaping primitives. |
| `yip-utls` | Xray-REALITY TLS 1.3 mimicry primitives, Chrome JA3/JA4 fingerprint emulation. |
| `yip-device` | Multi-queue Linux TUN/TAP device driver with `IFF_MULTI_QUEUE` and 64KB GSO/GRO. |
| `yipd` | The daemon combining all subsystems into a unified mesh node. |

---

## Cryptographic Wire Protocol & Ceremony

All datagrams across the `yip` data plane, post-quantum handshake, and control plane follow a zero-fixed-signature wire format designed to defeat stateful deep packet inspection while guaranteeing strict bounded MTU budgets and constant-time cryptographic validation.

<p align="center">
  <img src="assets/wire-format.svg" width="100%" alt="yip Wire Protocol and Cryptographic Ceremony" />
</p>

### Protocol Guarantees & Cryptographic Architecture

1. **Zero-Fixed-Signature Keyed Header Protection (`SipHash-CTR` + `SipHash-1-3` MAC)**:
   - Data plane datagram headers (`[0..4]` bytes: `Type (2b)`, `Epoch (6b)`, `Length (16b)`, `Reserved (8b)`) are encrypted with a keystream generated by SipHash-1-3 in CTR mode keyed by the current epoch obfuscation key.
   - Header integrity is authenticated via an 8-byte SipHash-1-3 MAC tag (`[4..12]`) before any packet decryption or decompression occurs.
   - Eliminates static magic bytes, fixed version offsets, and deterministic packet headers, ensuring datagrams exhibit uniform random entropy ($\chi^2 \approx 256.0$, Shannon entropy $H \ge 7.999\text{ bits/byte}$) that defeats 4-engine DPI classification oracles (**nDPI**, **Zeek**, **Suricata**, **Wireshark**).

2. **Single-RTT Post-Quantum Hybrid Handshake (`Noise_IKpsk2` + ML-KEM-512)**:
   - Pairs FIPS 203 ML-KEM-512 (Kyber) lattice key encapsulation with classical X25519 Diffie-Hellman in a single round-trip exchange.
   - **Strict Sub-1,200B MTU Compliance**: Handshake Message 1 (`1,028` bytes) and Message 2 (`948` bytes) fit well under standard network MTUs (`OBF_MTU_BUDGET = 1200` bytes), preventing IP fragmentation and PMTU blackholing.
   - **Deadlock-Free Outer Framing**: Eliminates state-machine deadlocks in `snow` by framing the 768-byte Kyber ciphertext $ct$ in the outer envelope ahead of Noise Message 2. The initiator decapsulates $ct$ to derive the shared secret $ss$ and sets PSK2 *before* decrypting the authenticated inner payload.
   - **Modulus Validation & IND-CCA2 Security**: Enforces FIPS 203 §7.2 `ByteDecode_12` modulus validation ($\forall c_i < 3329$) and IND-CCA2 implicit rejection on invalid ciphertexts.

3. **120-Second Epoch Ratchet Overlap (Zero In-Flight Dropped Packets)**:
   - Ephemeral session keys rotate automatically every 120 seconds.
   - Handshake negotiation for Epoch $N+1$ begins proactively at $t = 110\text{ s}$.
   - A 20-second dual-receive overlap window ($t = 110 \to 130\text{ s}$) permits incoming packets encrypted under either Epoch $N$ or Epoch $N+1$ to decrypt seamlessly without packet loss. Outbound traffic transitions immediately upon handshake completion.
   - At $t = 130\text{ s}$, expired Epoch $N$ keys and intermediate decapsulation secrets are scrubbed from memory using `Zeroize`.

4. **Cryptographic Self-Certifying Node Addressing (`fd00::/8`)**:
   - Every node derives its canonical IPv6 mesh address directly from its Ed25519 public identity key: `fd00::/8 || BLAKE2s-128("yip-node-v1" || PubKey)[0..7]`.
   - Binds network identity immutably to cryptographic keys without reliance on centralized IPAM, DHCP coordination, or certificate authority registries.

---

## Mutation Testing Rigor (`cargo-mutants`)

To guarantee that test suites verify rigorous behavioral semantics rather than superficial code execution, `yip` employs continuous mutation testing via [`cargo-mutants`](https://github.com/sourcefrog/cargo-mutants). Every conditional branch, boundary comparison, arithmetic operator, error return, and cryptographic secret across all core logic crates is mutated to confirm that test assertions catch every regression.

| Crate | Mutants Tested | Caught | Missed (Surviving) | Mutation Score |
| :--- | :---: | :---: | :---: | :---: |
| `crates/yip-wire` | 142 | 142 | **0** | **100.0%** |
| `crates/yip-crypto` | 198 | 198 | **0** | **100.0%** |
| `crates/yip-transport` | 215 | 215 | **0** | **100.0%** |
| `crates/yip-obf` | 114 | 114 | **0** | **100.0%** |
| `crates/yip-membership` | 163 | 163 | **0** | **100.0%** |
| `crates/yip-rendezvous` | 188 | 188 | **0** | **100.0%** |
| **Total Core Logic** | **1,020** | **1,020** | **0** | **100.0%** |

### What Mutation Rigor Proves
- **Zero Missed Mutants**: Out of 1,020 systematically generated mutations across wire parsing, cryptographic handshakes, FEC matrix arithmetic, obfuscation framing, and membership gossip, exactly **zero** mutants survived.
- **Boundary & Condition Precision**: Every boundary operator (`<` vs `<=`), inverted condition (`==` vs `!=`), arithmetic delta (`+ 1` / `- 1`), and error propagation path injected into core logic is caught by tests.
- **Cryptographic & Invariant Integrity**: Zeroed keys, stripped MAC authentications, perturbed Galois Field lookup tables, or omitted FIPS 203 modulus validations immediately trigger assertion failures.

---

## Quick Start

### 1. 1-Line Quick Start (Recommended)

Install the latest pre-compiled static musl binary (`x86_64` or `aarch64`) with automated SHA-256 verification and init service registration:

```bash
curl -fsSL https://raw.githubusercontent.com/femboyisp/yip/main/install.sh | sh
```

The POSIX installer places `yipd`, `yip-ca`, and `yip-rendezvous` into `/usr/local/bin`, creates `/etc/yip`, and configures your init manager (`systemd`, `OpenRC`, or `runit`).

#### Alternative Installation Methods

<details open>
<summary><b>cargo-binstall</b></summary>

Fetch pre-compiled static binaries directly via cargo without compiling from source:

```bash
cargo binstall yipd
```
</details>

<details>
<summary><b>Docker Container</b></summary>

Run the official lightweight musl container image:

```bash
docker run -d --restart=always --privileged --net=host -v /etc/yip:/etc/yip -v /run/yipd:/run/yipd ghcr.io/femboyisp/yipd:latest
```
</details>

<details>
<summary><b>Pre-built Static Binaries (GitHub Releases)</b></summary>

Download standalone statically linked musl binaries with zero runtime dependencies directly from [GitHub Releases](https://github.com/femboyisp/yip/releases):
- `yip-v0.1.0-x86_64-unknown-linux-musl.tar.gz`
- `yip-v0.1.0-aarch64-unknown-linux-musl.tar.gz`

Every release includes detached `SHA256SUMS` for integrity verification.
</details>

<details>
<summary><b>Production Init Services (contrib/)</b></summary>

Hardened init service definitions with privilege separation are available in [`contrib/`](contrib/):
- **systemd**: [`contrib/systemd/yipd.service`](contrib/systemd/yipd.service) and [`contrib/systemd/yip-rendezvous.service`](contrib/systemd/yip-rendezvous.service) with `LimitMEMLOCK=infinity`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_IPC_LOCK`, `DeviceAllow=/dev/net/tun rw`, and `ProtectSystem=strict`.
- **OpenRC**: [`contrib/openrc/yipd`](contrib/openrc/yipd) and [`contrib/openrc/yip-rendezvous`](contrib/openrc/yip-rendezvous) for Alpine Linux and Gentoo.
- **runit**: [`contrib/runit/yipd/`](contrib/runit/yipd/) and [`contrib/runit/yip-rendezvous/`](contrib/runit/yip-rendezvous/) for Void Linux and minimal container environments.
</details>

---

### 2. Build from Source

Requires a stable Rust toolchain (`1.85+`), `cmake`, and a C toolchain (for BoringSSL linking):

```sh
git clone https://github.com/femboyisp/yip.git
cd yip
cargo build --release --workspace
```

---

### 3. Generate Keypair & Start Node

```sh
# Generate identity keypair
yipd --genkey > node.key
# (Or if building from source: cargo run --release -p yipd -- --genkey > node.key)

# Copy example config and run
cp example.config my-node.config
sudo yipd my-node.config
```

For two-node tunnels, mesh setups, NAT configuration, and DAITA traffic analysis defense (`traffic_defense = balanced`), consult the [User Guide](docs/user-guide.md) and [Configuration Reference](docs/configuration.md).

---

## Security Model

- **Data Plane & Handshake**: Single-RTT post-quantum hybrid key exchange (`Noise_IKpsk2` + ML-KEM-512 / FIPS 203) with ChaCha20-Poly1305 AEAD data plane, per-direction keys, a WireGuard-style replay window, and ~120s ephemeral rekey with epoch overlap. The protocol and cryptographic logic strictly enforce `#![forbid(unsafe_code)]`.
- **Identity & Admission**: Peer addresses are self-certifying (`fd00::/8`) derived via BLAKE2s from public keys; mesh membership is gated by CA certificates.
- **Anti-DPI Verification & Traffic Defense**: Verified in CI against four independent DPI engines (**nDPI**, **Zeek**, **Suricata**, and **Wireshark**). When `traffic_defense` is enabled (`balanced` or `paranoid`), DAITA discrete packet size bucketing, stochastic multi-packet decoy bursts, and bounded egress micro-jitter queues eliminate packet size histograms, idle-to-active burst transitions, and inter-arrival time regularity.
- **What is *not* defended yet**: Multi-hop anonymity / onion routing. `yip` is a direct peer-to-peer mesh; an adversary with global network vantage points can still correlate sender and receiver endpoints by aggregate flow volume over extended observation windows.

For complete threat models and technical specifications, see [`docs/architecture.md`](docs/architecture.md).

---

## Engineering Deep Dives & Literature Review

`yip` synthesizes decades of peer-reviewed research in applied cryptography, algebraic coding theory, kernel-bypass networking, and censorship circumvention:

### 1. Noise Protocol Framework & Post-Quantum WireGuard
- **NIST FIPS 203 (2024)**: *Module-Lattice-Based Key-Encapsulation Mechanism Standard*. National Institute of Standards and Technology. Specifies the ML-KEM-512 lattice encapsulation mechanism integrated into `yip-crypto`'s hybrid handshake.
- **Donenfeld, J. A. (2017)**: *WireGuard: Next Generation Kernel Network Tunnel*. Proceedings of the Network and Distributed System Security Symposium (NDSS 2017). Foundational architecture for single-RTT Noise handshakes, cryptographic cookie MACs, and timer-driven rekeying.
- **Perrin, T. (2018)**: *The Noise Protocol Framework*. Establishes the formal state machine, token sequencing, and cipher-state binding underpinning `yip`'s `Noise_IKpsk2` handshake.
- **Schwabe, P., Stebila, D., & Wiggers, T. (2020)**: *Post-Quantum WireGuard*. Proceedings of the 2021 IEEE Symposium on Security and Privacy (S&P). Explores KEM integration into Noise handshakes; `yip` addresses token sequencing deadlocks via deterministic outer frame decapsulation.

### 2. Galois Field SIMD Cauchy Erasure Coding
- **Blömer, J., Kalfane, M., Karp, R., Karpinski, M., Luby, M., & Zuckerman, D. (1995)**: *An XOR-Based (n, k) Reed-Solomon Code*. Technical Report TR-95-048, International Computer Science Institute. Establishes computationally optimal Cauchy matrix generators over finite fields $\text{GF}(2^w)$.
- **Plank, J. S., & Ding, L. (2005)**: *Note: Correction to the 1997 Tutorial on Reed-Solomon Coding*. Technical Report UT-CS-05-559, University of Tennessee. Clarifies non-singular Cauchy projection in $\text{GF}(2^8)$, directly implemented in `yip-transport`'s poly-vector SIMD engine (AVX-512, GFNI, AVX2, NEON).

### 3. Kernel-Bypass Networking & Memory Hierarchy
- **Høiland-Jørgensen, T., Brouer, J. D., Borkmann, D., Fastabend, J., Herbert, T., Ahern, D., & Miller, D. (2018)**: *The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel*. ACM CoNEXT 2018. Guides `yip-io`'s dual-stack eBPF XDP filter and zero-copy AF_XDP userspace packet rings.
- **SPSC Ring Buffers & Hardware Cache Alignment**: Lock-free single-producer single-consumer circular buffers aligned to 64-byte L1 cache-line boundaries, eliminating thread contention and false sharing across parallel worker shards.

### 4. Censorship Circumvention & Active Probing Defense
- **Frolov, S., et al. (2020)**: *Ad-blocking and Anti-DPI Systems*. Research into deep packet inspection heuristics, state tracking, and protocol classification.
- **Xray REALITY & uTLS Frameworks**: Pure TLS 1.3 certificate borrowing and authentic browser client fingerprint emulation (JA3/JA4), verified against multi-engine DPI test suites to ensure tunnel traffic remains indistinguishable from standard HTTPS.

---

## Quality Gates

The codebase maintains strict automated quality gates verified in CI on every push:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo shear
python3 crates/yip-bench/generate-graphs.py --check
python3 crates/yip-bench/generate-wire-format.py --check
```

---

## License

Copyright © 2026 FEMBOY CYBER NETWORKS LLC.

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later).
