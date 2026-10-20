# Design Document: Visual Benchmarks, Architecture Diagrams & README Overhaul

- **Author**: Antigravity Pair Programmer & Maintainer
- **Date**: 2026-10-20
- **Status**: Approved
- **Target Release**: Pre-1.0 Showcase & Discovery

---

## 1. Executive Summary

`yip` is a high-performance, censorship-resistant peer-to-peer mesh VPN in Rust featuring systematic Reed–Solomon forward error correction over GF(256), line-rate multi-core sharding (scaling to 40+ Gbps via AF_XDP), self-certifying routing, and anti-DPI transports (including uTLS Chrome fingerprinting and Xray-REALITY TLS 1.3 mimicry).

While the underlying engine is technically peerless and verified through extensive real-world multi-region AWS and netns benchmarks, its presentation has relied primarily on dense ASCII markdown tables and text. This design elevates `yip`'s public presentation to top-tier open-source quality by introducing:
1. Automated, standalone vector SVG benchmark charts for throughput-under-loss, FEC recovery, and multi-core scaling with explicit testbed context.
2. A dual-path vector SVG system architecture and packet-flow diagram.
3. A streamlined root `README.md` with responsive visual grids, a 3-pillar highlight, automated benchmark table synchronization, and a head-to-head comparison matrix.
4. Curated GitHub/Forgejo discovery metadata (description, high-value SEO tags, rasterized + vector social preview cards).
5. Continuous, deterministic asset regeneration and validation hooked into the benchmark harness and CI.

---

## 2. Visual Graphs & Generation Pipeline

### 2.1 Generated Vector Assets
All charts are rendered as clean, standalone vector SVGs (`assets/*.svg`) using a consistent GitHub Dark theme (`#0d1117` background, subtle outer card border `stroke="#30363d" stroke-width="1.5"` with `rx="12"` rounded corners for clean rendering on both Light and Dark themes, slate grid lines `#21262d`, high-contrast crisp curves, and a zero-dependency system font stack `ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif` / `ui-monospace, SFMono-Regular, Menlo, monospace`).

1. **`assets/bench-throughput-loss.svg` (The Headline)**:
   - **Subtitle**: `AWS Multi-Region WAN: us-east-1 ↔ us-west-2 (~60.6ms RTT, 1 vCPU, 10% FEC Parity)`
   - **X-axis**: Channel Packet Loss (0%, 1%, 3%, 5%, 10%).
   - **Y-axis**: TCP Goodput (Mbit/s, symlog / logarithmic scale or linear with 1%–10% inset zoom so the `16.6 Mbit/s vs 0.5 Mbit/s` gap at 10% loss is clearly visible rather than squashed against the bottom axis).
   - **Curves**:
     - `yip` (Fox Orange `#f97316`): Sustains high throughput across all loss levels (163.2 Mbit/s clean, 117.6 Mbit/s @ 3%, 81.5 Mbit/s @ 5%, 16.6 Mbit/s @ 10%).
     - `WireGuard` (Cyan `#38bdf8`): 422 Mbit/s clean, collapsing to 1.2 Mbit/s @ 3% and 0.5 Mbit/s @ 10%.
     - `OpenVPN` (Purple `#a855f7`): 20.6 Mbit/s clean, collapsing to 1.6 Mbit/s @ 3% and 0.5 Mbit/s @ 10%.
     - `Baseline unencapsulated` (Dashed Slate `#64748b`): Drops from 420 Mbit/s to 0.6 Mbit/s.
   - **Annotations**: Badge highlighting *"33× to 98× higher throughput under loss"*, plus note explaining systematic FEC parity trade-off on clean links vs. survival under loss.

2. **`assets/bench-fec-recovery.svg` (Effective Loss Suppression)**:
   - **Subtitle**: `AWS Multi-Region WAN: us-east-1 ↔ us-west-2 (~60.6ms RTT, Systematic Cauchy RS GF(256))`
   - **X-axis**: Injected Packet Loss (0% to 10%).
   - **Y-axis**: Effective Ping Packet Loss % (0% to 15%).
   - **Curves**:
     - `yip` (Fox Orange `#f97316`): Flatline at 0%–1% effective loss due to Reed–Solomon FEC reconstruction.
     - `WireGuard` / `OpenVPN` / `Baseline`: Linear ascent tracking packet drops (6% to 12%).
   - **Annotations**: Badge highlighting *"Zero TCP backoff penalty via systematic Reed–Solomon FEC"*.

3. **`assets/bench-multicore-scaling.svg` (Multi-Core Line-Rate Scaling)**:
   - **Subtitle**: `Dedicated Multi-Core Testbed: 64 Parallel TCP Streams, Lock-Free SPSC Sharding (AMD Ryzen / EPYC)`
   - **X-axis**: Worker Cores (1, 2, 4, 8).
   - **Y-axis**: Multi-Stream TCP Throughput (Gbps, linear scale).
   - **Curves**:
     - `AF_XDP Zero-Copy` (Bright Ember `#fb923c`): 8.68 Gbps → 11.26 Gbps → 21.22 Gbps → 40.27 Gbps.
     - `Vectorized epoll / recvmmsg` (Cyan `#38bdf8`): 4.58 Gbps → 6.04 Gbps → 11.43 Gbps → 21.56 Gbps.
   - **Annotations**: Badge highlighting *"40+ Gbps Line-Rate Multi-Core Scaling"*.

### 2.2 Generator Script (`crates/yip-bench/generate-graphs.py`)
- Implemented as a standalone, dependency-free Python 3 script.
- Generates valid XML/SVG output directly without requiring external `matplotlib` or `cairo` dependencies, ensuring it runs reliably on any minimal Linux environment or CI runner.
- **Structured Data Sources**:
  - Reads WAN loss metrics from `crates/yip-bench/wan/results/history.csv`.
  - Reads multi-core scaling metrics from `crates/yip-bench/results/sharding-scale.csv`.
- **Deterministic Output (Zero Git-Diff Noise)**:
  - Enforces strict float formatting (`f"{val:.2f}"`), sorted keys, and omits dynamic generation timestamps so regenerating unchanged metrics produces byte-identical SVGs.
- **Validation Mode (`--check`)**:
  - Supports `python3 crates/yip-bench/generate-graphs.py --check` for CI and pre-commit hooks to verify that `assets/*.svg` parse as valid XML and are up-to-date with the latest CSV inputs without modifying files on disk.
- Invoked automatically by `crates/yip-bench/wan/collect.sh` during benchmark reduction and in GitHub Actions / Forgejo CI workflows.

---

## 3. Visual System Architecture Diagram (`assets/architecture.svg`)

A dedicated vector graphic illustrating the separation between the control plane, the parallelized data plane, and the bifurcated transport paths:

### 3.1 Diagram Components
1. **Control Plane Layer & Auxiliary Services (Top)**:
   - **Identity & Self-Certifying Addressing**: BLAKE2s derivation (`fd00::/8` mesh IPv6 addresses derived directly from node Ed25519/X25519 public keys).
   - **Offline Authority (`yip-ca`) & Mesh Discovery**: CA-gated gossip membership discovery, certificate admission, and revocation propagation.
   - **Coordination & NAT Traversal (`yip-rendezvous`)**: Deterministic STUN hole-punching with authenticated blind relay fallback and TLS fronting.
   - **Transport Negotiation**: Dynamic selection and roaming across Direct UDP, Obfuscated UDP, QUIC, or Xray-REALITY TLS 1.3 transports.

2. **Data Plane Pipeline (Middle — Parallelized Per-Flow Shards)**:
   - **Ingress/Egress**: Linux TUN/TAP device (`/dev/net/tun`) utilizing `IFF_VNET_HDR` 64 KB GSO/GRO super-packets.
   - **Lock-Free Worker Sharding (`Shard 0 .. Shard N`)**: Multi-queue flow-affinity partitioning (`shards = N`) over lock-free SPSC circular ring descriptors (`yip-io::spsc`) eliminating cross-core lock contention and preserving packet ordering.
   - **Encryption & Epoch Rekeying**: ChaCha20-Poly1305 AEAD in a Noise-IK session with ~120s zero-downtime epoch rekeying and adaptive time-based anti-replay windows.
   - **FEC Layer**: Systematic Cauchy Reed–Solomon encoding over GF(256) (P+Q fast path, AVX2/GFNI SIMD) and rateless RLNC fountain codes.

3. **Bifurcated Transport & I/O Engine (Bottom)**:
   - **Fast Path (Line-Rate Kernel Bypass & Batch I/O)**:
     - Dual-stack eBPF `AF_XDP` zero-copy socket redirect driver (`XSKMAP` / `UMEM` rings).
     - Vectorized `epoll` / `io_uring` with `sendmmsg`/`recvmmsg` GSO/GRO coalescing.
   - **Stealth / Anti-DPI Path (Censorship Evasion)**:
     - `yip-utls` Chrome TLS 1.3 fingerprint mimicry (JA3/JA4 parity), `Xray-REALITY` active-probe-resistant TLS fronting, and QUIC datagram framing.
     - Verified continuously by the **4-Engine DPI Oracle** (`nDPI`, `Zeek`, `Suricata`, `Wireshark`).

---

## 4. README & Presentation Overhaul

### 4.1 Structural Sections of `README.md`
1. **Hero Header**:
   - Centered logo/mascot animation (`assets/yip.gif`).
   - One-sentence tagline: *"A low-latency, loss-resilient peer-to-peer mesh VPN in Rust."*
   - **Badges**:
     - CI Status & Mutants Gate
     - Stable Rust & Linux Platform
     - Honest Safety Boundary: `Protocol & Crypto: #![forbid(unsafe_code)]` (explicitly noting kernel FFI is isolated to `yip-io` and `yip-device`)
     - 4-Engine DPI Oracle: `DPI Evasion: nDPI | Zeek | Suricata | Wireshark (Passed)`
   - Quick navigation pills: `[Quick Start]` `[Benchmarks]` `[Architecture]` `[Comparison]` `[Why yip?]`.

2. **The "Why yip?" 3-Pillar Highlight**:
   - Concise highlight cards explaining **Loss Immunity** (Reed–Solomon + RLNC FEC), **Multi-Core Line-Rate Scaling** (40+ Gbps AF_XDP & SPSC sharding), and **Active/Passive Censorship Evasion** (uTLS + REALITY TLS 1.3 + QUIC).

3. **Visual Benchmarks Section**:
   - Responsive side-by-side 2-column layout using GFM-compatible inline HTML:
     ```html
     <p align="center">
       <img src="assets/bench-throughput-loss.svg" width="49%" alt="Throughput Under Loss" />
       <img src="assets/bench-multicore-scaling.svg" width="49%" alt="Multi-Core Scaling" />
     </p>
     ```
   - Full-width `assets/bench-fec-recovery.svg`.
   - Collapsible `<details>` element containing the raw tabular data wrapped in automated sync markers (`<!-- BENCHMARK-TABLE-START -->` ... `<!-- BENCHMARK-TABLE-END -->`), updated automatically by `crates/yip-bench/wan/collect.sh`.

4. **Visual Architecture Section**:
   - Embedded `assets/architecture.svg` accompanied by concise architectural highlights of the control/data plane split and safety boundaries.

5. **Head-to-Head Comparison Matrix**:
   - Feature table comparing `yip` against **WireGuard**, **Tailscale**, and **OpenVPN** across:
     - Forward Error Correction (Systematic RS + RLNC vs. None)
     - Throughput at 3%–10% WAN Loss (Sustained vs. TCP Collapse)
     - Multi-Core Data Plane Scaling (40+ Gbps AF_XDP / Sharded Workers)
     - Active & Passive DPI Resistance (REALITY TLS 1.3 / uTLS / QUIC vs. Fingerprinted)
     - Coordination & Trust Model (Self-hosted `yip-ca` & `yip-rendezvous`, self-certifying `fd00::/8` IPs)

6. **Quick Start**:
   - 3-step setup guide (`example.config`, `yipd --genkey`, run command).

7. **Security & Roadmap Links**:
   - Direct references to `docs/architecture.md`, `SECURITY.md`, `ROADMAP.md`, and `CHANGELOG.md`.

---

## 5. GitHub Discovery & Repository Metadata

### 5.1 Repository Description
Updated via `gh repo edit`:
> `🦊 Low-latency P2P mesh VPN in Rust. Reed–Solomon FEC loss immunity, 40 Gbps AF_XDP multi-core scaling, NAT traversal, self-certifying routing, and anti-DPI TLS mimicry.`

### 5.2 Curated Repository Topics (20 max)
- `rust`, `vpn`, `mesh-vpn`, `wireguard-alternative`, `networking`, `p2p`, `privacy`, `forward-error-correction`, `fec`, `reed-solomon`, `af-xdp`, `ebpf`, `zero-copy`, `io-uring`, `low-latency`, `censorship-resistance`, `dpi-evasion`, `noise-protocol`, `nat-traversal`, `tunnel`

### 5.3 Social Media Preview Card (`assets/social-card.png` & `assets/social-card.svg`)
- `assets/social-card.svg` generated with the logo, core value proposition, and visual benchmark curve.
- Rasterized to a `1280×640` PNG (`assets/social-card.png`, `< 1 MB`) for upload to GitHub Repository Social Preview and compatibility with OpenGraph scrapers (Twitter/X, Discord, Slack, Mastodon) that do not render SVG previews.

---

## 6. Verification & Quality Gates

1. **Deterministic SVG Validation**:
   - Run `python3 crates/yip-bench/generate-graphs.py --check` to ensure all generated SVG files parse cleanly as valid XML and match current CSV data without git-diff noise.
   - Verify proper visual rendering and border contrast (`stroke="#30363d"`) in both dark and light viewer contexts across GitHub and Forgejo/Gitea.
2. **Pipeline & README Sync Integration**:
   - Execute `crates/yip-bench/wan/collect.sh` and confirm all 3 benchmark SVGs and the `<!-- BENCHMARK-TABLE-START -->` block in `README.md` update cleanly from `history.csv` and `sharding-scale.csv`.
   - Verify workflows `.github/workflows/wan-benchmark.yml`, `.github/workflows/ci.yml`, and `.forgejo/workflows/ci.yml` preserve and check SVG generation.
3. **Markdown Integrity**:
   - Verify markdown rendering and confirm all relative asset paths (`assets/*.svg`, `assets/yip.gif`, `assets/social-card.png`) resolve accurately on both GitHub and Forgejo.
4. **Workspace Quality Gates**:
   - Ensure standard checks pass: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`, `cargo deny check`.
