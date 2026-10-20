# Design Document: Visual Benchmarks, Architecture Diagrams & README Overhaul

- **Author**: Antigravity Pair Programmer & Maintainer
- **Date**: 2026-10-20
- **Status**: Approved
- **Target Release**: Pre-1.0 Showcase & Discovery

---

## 1. Executive Summary

`yip` is a high-performance, censorship-resistant peer-to-peer mesh VPN in Rust featuring systematic Reed–Solomon forward error correction over GF(256), line-rate multi-core sharding (scaling to 40+ Gbps via AF_XDP), self-certifying routing, and anti-DPI transports (including Xray-REALITY TLS 1.3 mimicry).

While the underlying engine is technically peerless and verified through extensive real-world multi-region AWS and netns benchmarks, its presentation has relied primarily on dense ASCII markdown tables and text. This design elevates `yip`'s public presentation to top-tier open-source quality by introducing:
1. Automated, standalone vector SVG benchmark charts for throughput-under-loss, FEC recovery, and multi-core scaling.
2. An elegant vector SVG system architecture and packet-flow diagram.
3. A streamlined root `README.md` with visual grids, a 3-pillar highlight, and a head-to-head comparison matrix.
4. Curated GitHub discovery metadata (description, high-value SEO tags, social preview card).
5. Continuous automated asset regeneration hooked into the benchmark harness and CI.

---

## 2. Visual Graphs & Generation Pipeline

### 2.1 Generated Vector Assets
All charts are rendered as clean, standalone vector SVGs (`assets/*.svg`) using a consistent GitHub Dark theme (`#0d1117` background, slate grid lines, high-contrast crisp curves, embedded system fonts, and rounded borders).

1. **`assets/bench-throughput-loss.svg` (The Headline)**:
   - **X-axis**: Channel Packet Loss (0%, 1%, 3%, 5%, 10%).
   - **Y-axis**: TCP Goodput (Mbit/s, logarithmic or adaptive linear scale).
   - **Curves**:
     - `yip` (Fox Orange `#f97316`): Sustains high throughput across all loss levels (163.2 Mbit/s clean, 117.6 Mbit/s @ 3%, 81.5 Mbit/s @ 5%, 16.6 Mbit/s @ 10%).
     - `WireGuard` (Cyan `#38bdf8`): 422 Mbit/s clean, collapsing to 1.2 Mbit/s @ 3% and 0.5 Mbit/s @ 10%.
     - `OpenVPN` (Purple `#a855f7`): 20.6 Mbit/s clean, collapsing to 1.6 Mbit/s @ 3% and 0.5 Mbit/s @ 10%.
     - `Baseline unencapsulated` (Dashed Slate `#64748b`): Drops from 420 Mbit/s to 0.6 Mbit/s.
   - **Annotations**: Badge highlighting *"33× to 98× higher throughput under loss"*.

2. **`assets/bench-fec-recovery.svg` (Effective Loss Suppression)**:
   - **X-axis**: Injected Packet Loss (0% to 10%).
   - **Y-axis**: Effective Ping Packet Loss % (0% to 15%).
   - **Curves**:
     - `yip`: Flatline at 0%–1% effective loss due to Reed–Solomon FEC reconstruction.
     - `WireGuard` / `OpenVPN` / `Baseline`: Linear ascent tracking packet drops (6% to 12%).
   - **Annotations**: Badge highlighting *"Zero TCP backoff penalty via systematic Reed–Solomon FEC"*.

3. **`assets/bench-multicore-scaling.svg` (Multi-Core Line-Rate Scaling)**:
   - **X-axis**: Worker Cores (1, 2, 4, 8).
   - **Y-axis**: Multi-Stream TCP Throughput (Gbps).
   - **Curves**:
     - `AF_XDP Zero-Copy` (Bright Ember `#fb923c`): 8.68 Gbps $\to$ 11.26 Gbps $\to$ 21.22 Gbps $\to$ 40.27 Gbps.
     - `Vectorized epoll / recvmmsg` (Cyan `#38bdf8`): 4.58 Gbps $\to$ 6.04 Gbps $\to$ 11.43 Gbps $\to$ 21.56 Gbps.
   - **Annotations**: Badge highlighting *"40+ Gbps Line-Rate Multi-Core Scaling"*.

### 2.2 Generator Script (`crates/yip-bench/generate-graphs.py`)
- Implemented as a standalone, dependency-free Python 3 script.
- Generates valid XML/SVG output directly without requiring external matplotlib or Cairo dependencies, ensuring it runs reliably on any minimal Linux environment or CI runner.
- Reads source data from `crates/yip-bench/wan/results/history.csv` and multi-core scaling metrics.
- Invoked automatically by `crates/yip-bench/wan/collect.sh` during benchmark reduction and in GitHub Actions CI workflows.

---

## 3. Visual System Architecture Diagram (`assets/architecture.svg`)

A dedicated vector graphic illustrating the separation between the control plane and data plane:

### 3.1 Diagram Components
1. **Control Plane Layer (Top)**:
   - **Identity & Addressing**: BLAKE2s derivation (`fd00::/8` addresses derived directly from node public keys).
   - **Mesh Discovery**: CA-gated gossip discovery and certificate admission.
   - **NAT Traversal**: Deterministic STUN hole-punching with blind relay fallback.
   - **Transport Negotiation**: Negotiation of direct, obfuscated, QUIC, or Xray-REALITY TLS 1.3 transports.
2. **Data Plane Pipeline (Bottom)**:
   - **Ingress/Egress**: Linux TUN/TAP device (`/dev/net/tun`) utilizing `IFF_VNET_HDR` 64 KB GSO/GRO super-packets.
   - **Worker Sharding**: Multi-queue lock-free worker partitioning (`shards = N`) with circular ring descriptors.
   - **Encryption**: ChaCha20-Poly1305 AEAD in a Noise-IK session with ~120s epoch rekeying and anti-replay windows.
   - **FEC Layer**: Systematic Cauchy Reed–Solomon encoding over GF(256) (P+Q fast path, AVX2/GFNI SIMD) and rateless RLNC fountain codes.
   - **I/O Engine**: Vectorized epoll `sendmmsg`/`recvmmsg` GSO coalescing and dual-stack eBPF AF_XDP zero-copy socket redirect driver (`XSKMAP`).

---

## 4. README & Presentation Overhaul

### 4.1 Structural Sections of `README.md`
1. **Hero Header**:
   - Centered logo/mascot animation (`assets/yip.gif`).
   - One-sentence tagline: *"A low-latency, loss-resilient peer-to-peer mesh VPN in Rust."*
   - Badges: CI Status, Mutants Gate, Stable Rust, Linux Platform, Code Safety (`#![forbid(unsafe_code)]`), nDPI Status (`Passed / Unknown`).
   - Quick navigation pills: `[Quick Start]` `[Benchmarks]` `[Architecture]` `[Comparison]` `[Why yip?]`.
2. **The "Why yip?" 3-Pillar Highlight**:
   - Concise cards explaining Loss Immunity, Multi-Core Scaling, and Censorship Evasion.
3. **Visual Benchmarks Section**:
   - 2-Column responsive layout pairing `bench-throughput-loss.svg` and `bench-multicore-scaling.svg`.
   - Full-width `bench-fec-recovery.svg`.
   - Collapsible `<details>` element containing the raw tabular data for transparency.
4. **Visual Architecture Section**:
   - Embedded `assets/architecture.svg` accompanied by concise architectural highlights.
5. **Head-to-Head Comparison Matrix**:
   - Feature table comparing `yip` against WireGuard, Tailscale, and OpenVPN.
6. **Quick Start**:
   - 3-step setup guide (`example.config`, `yipd --genkey`, run command).
7. **Security & Roadmap Links**:
   - Direct references to `docs/architecture.md`, `ROADMAP.md`, and `CHANGELOG.md`.

---

## 5. GitHub Discovery & Repository Metadata

### 5.1 Repository Description
Updated via `gh repo edit`:
> `🦊 Low-latency P2P mesh VPN in Rust. Reed–Solomon FEC loss immunity, 40 Gbps AF_XDP multi-core scaling, NAT traversal, self-certifying routing, and anti-DPI TLS mimicry.`

### 5.2 Curated Repository Topics (20 max)
- `rust`
- `vpn`
- `mesh-vpn`
- `wireguard-alternative`
- `networking`
- `p2p`
- `privacy`
- `forward-error-correction`
- `fec`
- `reed-solomon`
- `af-xdp`
- `ebpf`
- `zero-copy`
- `io-uring`
- `low-latency`
- `censorship-resistance`
- `dpi-evasion`
- `noise-protocol`
- `nat-traversal`
- `tunnel`

### 5.3 Social Media Preview Card (`assets/social-card.png` / `assets/social-card.svg`)
- 1280×640 OpenGraph preview asset combining the logo, core value proposition, and visual benchmark curve for sharing on social channels.

---

## 6. Verification & Quality Gates

1. **SVG Validation**:
   - Ensure all generated SVG files parse cleanly as valid XML.
   - Verify proper rendering in both dark and light viewer contexts.
2. **Pipeline Integration**:
   - Execute `crates/yip-bench/wan/collect.sh` and confirm all 3 benchmark SVGs update from `history.csv`.
   - Verify workflow `.github/workflows/wan-benchmark.yml` preserves SVG generation on benchmark runs.
3. **Markdown Integrity**:
   - Verify markdown rendering with `python3 -c "import markdown; ..."` or linting tools.
   - Confirm all relative image links (`assets/*.svg`) resolve accurately.
4. **Workspace Quality Gates**:
   - Ensure standard checks pass: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`, `cargo deny check`.
