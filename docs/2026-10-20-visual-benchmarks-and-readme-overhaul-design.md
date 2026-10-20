# Design Document: Visual Benchmarks, Architecture Diagrams & README Overhaul

- **Author**: Antigravity Pair Programmer & Maintainer
- **Date**: 2026-10-20
- **Status**: Approved (Incorporating Community & Architectural Review)
- **Target Release**: Pre-1.0 Showcase & Discovery

---

## 1. Executive Summary

`yip` is a high-performance, censorship-resistant peer-to-peer mesh VPN in Rust featuring systematic Reed–Solomon forward error correction over GF(256), line-rate multi-core sharding (scaling to 40+ Gbps via AF_XDP), self-certifying routing, and anti-DPI transports (including Xray-REALITY TLS 1.3 mimicry).

While the underlying engine is technically peerless and verified through extensive real-world multi-region AWS and netns benchmarks, its presentation has relied primarily on dense ASCII markdown tables and text. This design elevates `yip`'s public presentation to top-tier open-source quality by introducing:
1. Automated, standalone vector SVG benchmark charts for throughput-under-loss (with log scaling / inset zoom), FEC recovery, and multi-core scaling.
2. A dual-path vector SVG system architecture and packet-flow diagram illustrating the Fast Path (AF_XDP/epoll) vs. Stealth Path (Xray-REALITY/QUIC) verified against the 4-engine DPI oracle (nDPI, Zeek, Suricata, Wireshark).
3. A streamlined, mobile-responsive root `README.md` featuring side-by-side SVG cards (`width="49%"`), a 3-pillar highlight, accurate safety boundaries (`Protocol & Crypto: #![forbid(unsafe_code)]`), and an expanded comparison matrix.
4. Curated GitHub discovery metadata (punchy description, high-value SEO tags, and a 1280×640 PNG social preview card).
5. Continuous automated asset regeneration and `--check` validation hooked into `crates/yip-bench/wan/collect.sh`, `.github/workflows/`, and `.forgejo/workflows/`.

---

## 2. Visual Graphs & Generation Pipeline

### 2.1 Generated Vector Assets
All charts are rendered as clean, standalone vector SVGs (`assets/*.svg`) using a consistent GitHub Dark theme (`#0d1117` background, subtle `#30363d` outer card border with rounded corners `rx="12"`, slate grid lines `#21262d`, high-contrast curves, and a clean system font stack):
`font-family="ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"` (and system monospace for numerals and badges).

1. **`assets/bench-throughput-loss.svg` (The Headline)**:
   - **Context Subtitle**: `AWS Multi-Region WAN: us-east-1 ↔ us-west-2, ~60.6ms RTT, 1 vCPU, 10% Parity Overhead`.
   - **X-axis**: Channel Packet Loss (0%, 1%, 3%, 5%, 10%).
   - **Y-axis Scaling**: Symlog / hybrid logarithmic scaling with readable tick marks (1, 5, 20, 100, 450 Mbit/s) or an inset zoom panel for the 1%–10% loss region so the `16.6 Mbit/s vs 0.5 Mbit/s` gap at 10% loss is visually unmistakable rather than squashed against the bottom axis.
   - **Curves**:
     - `yip` (Fox Orange `#f97316`): Sustains high throughput across all loss levels (163.2 Mbit/s clean, 117.6 Mbit/s @ 3%, 81.5 Mbit/s @ 5%, 16.6 Mbit/s @ 10%).
     - `WireGuard` (Cyan `#38bdf8`): 422 Mbit/s clean, collapsing to 1.2 Mbit/s @ 3% and 0.5 Mbit/s @ 10%.
     - `OpenVPN` (Purple `#a855f7`): 20.6 Mbit/s clean, collapsing to 1.6 Mbit/s @ 3% and 0.5 Mbit/s @ 10%.
     - `Baseline unencapsulated` (Dashed Slate `#64748b`): Drops from 420 Mbit/s to 0.6 Mbit/s.
   - **Callout Annotations**:
     - Badge: *"33× to 98× higher throughput under loss"*.
     - Callout text: *"Clean-path difference reflects 10% fixed FEC parity + single-core userspace scheduling; loss resilience prevents TCP window collapse."*

2. **`assets/bench-fec-recovery.svg` (Effective Loss Suppression)**:
   - **Context Subtitle**: `End-to-End Effective Ping Loss vs. Injected Network Drops`.
   - **X-axis**: Injected Packet Loss (0% to 10%).
   - **Y-axis**: Effective Ping Packet Loss % (0% to 15%).
   - **Curves**:
     - `yip`: Flatline at 0%–1% effective loss due to Reed–Solomon FEC reconstruction.
     - `WireGuard` / `OpenVPN` / `Baseline`: Linear ascent tracking packet drops (6% to 12%).
   - **Callout Badge**: *"Zero TCP backoff penalty via systematic Reed–Solomon FEC"*.

3. **`assets/bench-multicore-scaling.svg` (Multi-Core Line-Rate Scaling)**:
   - **Context Subtitle**: `Dedicated Multi-Core Scaling Testbed: 64 Concurrent TCP Streams, AMD Ryzen / EPYC`.
   - **X-axis**: Worker Cores (1, 2, 4, 8).
   - **Y-axis**: Multi-Stream TCP Throughput (Gbps, 0 to 45 Gbps).
   - **Curves**:
     - `AF_XDP Zero-Copy` (Bright Ember `#fb923c`): 8.68 Gbps $\to$ 11.26 Gbps $\to$ 21.22 Gbps $\to$ 40.27 Gbps.
     - `Vectorized epoll / recvmmsg` (Cyan `#38bdf8`): 4.58 Gbps $\to$ 6.04 Gbps $\to$ 11.43 Gbps $\to$ 21.56 Gbps.
     - `io_uring single-flow baseline` (Emerald `#10b981`): Opt-in low-latency busy-polling tier.
   - **Callout Badge**: *"40+ Gbps Line-Rate Multi-Core Scaling (Zero Drops, Zero Out-of-Order)"*.

### 2.2 Structured Benchmark Data Sources
To prevent fragile markdown parsing or hardcoded Python arrays:
- **WAN Benchmarks**: Parsed directly from `crates/yip-bench/wan/results/history.csv`.
- **Multi-Core Scaling**: Parsed from a structured data file `crates/yip-bench/results/sharding-scale.csv` populated by the Criterion / sharding benchmark harnesses.

### 2.3 Deterministic SVG Generator (`crates/yip-bench/generate-graphs.py`)
- Zero external dependencies: pure Python 3 using `xml.etree.ElementTree` or structured SVG formatting.
- **Strict Determinism**: Formats floating-point numbers deterministically (`f"{val:.2f}"`), sorts all dictionary keys, and omits dynamic generation timestamps from comments to guarantee zero git-diff churn when re-running on identical data.
- **Validation Mode (`--check`)**: Supports a fast `--check` flag that parses `assets/*.svg`, verifies valid XML structure, and confirms plotted points match `history.csv` without re-running any benchmarks.

---

## 3. Visual System Architecture Diagram (`assets/architecture.svg`)

A comprehensive, dark-themed SVG vector diagram illustrating `yip`'s control plane and data plane split, specifically highlighting its core technical innovations:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     CONTROL PLANE (Low-Frequency)                                      │
│                                                                                                        │
│   [ BLAKE2s Key-Derivation ] ──────> [ CA-Gated Mesh Discovery ] ──────> [ NAT Hole-Punching & Relay ] │
│      (Address = Public Key)           (yip-ca Signed Certificates)          (yip-rendezvous Blind STUN)│
└───────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                    │ Session Setup & Rekey (~120s)
┌───────────────────────────────────────────────────▼────────────────────────────────────────────────────┐
│                                     DATA PLANE (High-Throughput)                                       │
│                                                                                                        │
│   [ Linux TUN / TAP Device ] ─── (64 KB GSO/GRO super-packets with IFF_VNET_HDR)                       │
│              │                                                                                         │
│              ▼                                                                                         │
│   [ Lock-Free SPSC Shards ] ──── [ Shard 0 ] │ [ Shard 1 ] │ [ ... ] │ [ Shard N ]                   │
│                                  (Core-pinned worker threads, chunked nonces, circular rings)          │
│              │                                                                                         │
│              ▼                                                                                         │
│   [ ChaCha20-Poly1305 AEAD ] ── (Noise-IK 1-RTT encrypted frames with replay protection)               │
│              │                                                                                         │
│              ▼                                                                                         │
│   [ Systematic Cauchy RS-FEC ] ─ (GF(256) AVX2/GFNI SIMD + rateless RLNC fountain codes)               │
│              │                                                                                         │
│              ├─────────────────────────────────────────┐                                               │
│              ▼ (Fast Path)                             ▼ (Stealth / Anti-DPI Path)                     │
│   [ Direct UDP / obf_psk ]                  [ uTLS TLS 1.3 / QUIC Mimicry ]                            │
│   - eBPF AF_XDP Zero-Copy (XSKMAP)          - Chrome 150 JA3/JA4 Parity                                │
│   - Vectorized epoll sendmmsg (GSO)         - Xray-REALITY TCP / QUIC Datagrams                        │
│   ──> 40+ Gbps line-rate throughput         ──> 4-Engine Oracle: nDPI | Zeek | Suricata | Wireshark    │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Key Architectural Highlights in the Diagram
- **Dual Data Paths**:
  - **Fast Path**: Kernel-bypass eBPF AF_XDP zero-copy rings and vectorized `sendmmsg` GSO coalescing delivering line-rate multi-core performance.
  - **Stealth / Anti-DPI Path**: High-fidelity uTLS Chrome JA3/JA4 fingerprinting, Xray-REALITY TLS 1.3 byte streams, and throwaway QUIC Datagrams, verified against the 4-engine DPI oracle (`nDPI`, `Zeek`, `Suricata`, `Wireshark`).
- **Parallel Worker Lanes**: Explicitly renders parallel `Shard 0 .. Shard N` lanes to visualize the lock-free SPSC queue design that enables linear multi-core scaling without lock contention or packet reordering.
- **Auxiliary Binaries**: Depicts the offline CA tool `yip-ca` and the headless relay/discovery coordinator `yip-rendezvous`.

---

## 4. README & Presentation Overhaul

### 4.1 Structural Sections of `README.md`

#### 1. Hero Header & Accurate Badges
- Centered fox mascot animation (`assets/yip.gif`).
- High-impact tagline: *"A low-latency, loss-resilient peer-to-peer mesh VPN in Rust."*
- Curated badge bar:
  - `CI Build` (`main`)
  - `4-Engine DPI Oracle` (`nDPI | Zeek | Suricata | Wireshark: Passed`)
  - `Protocol & Crypto` (`#![forbid(unsafe_code)]`)
  - `Rust` (`1.85+ stable`)
  - `Platform` (`Linux x86_64 / arm64`)
  - `License` (`AGPL-3.0`)
- Quick navigation links: `[Quick Start]` `[Benchmarks]` `[Architecture]` `[Comparison]` `[Why yip?]`.

#### 2. The "Why yip?" 3-Pillar Highlight
1. **Loss Immunity without Retransmission**: Systematic Reed–Solomon FEC (GF(256)) prevents TCP congestion window halving. Tail latency stays flat on lossy cellular, satellite, and long-haul WAN links.
2. **Line-Rate Multi-Core Scaling**: 21.5 Gbps with vectorized sockets; 40+ Gbps with kernel-bypass AF_XDP zero-copy.
3. **Architectural Censorship-Resistance**: Zero fixed wire signatures, verified against 4 major DPI engines, and authentic Xray-REALITY browser TLS 1.3 mimicry.

#### 3. Responsive 2-Column Visual Benchmark Grid
To avoid fragile CSS or horizontal scrollbars, the charts will be laid out using centered markdown image pairs with responsive percentages:

```html
<p align="center">
  <img src="assets/bench-throughput-loss.svg" alt="Throughput vs Packet Loss" width="49%" />
  <img src="assets/bench-multicore-scaling.svg" alt="Multi-Core Scaling" width="49%" />
</p>
<p align="center">
  <img src="assets/bench-fec-recovery.svg" alt="Effective Loss Recovery" width="98.5%" />
</p>
```

#### 4. Automated Raw Data Synchronization
Below the visual charts, the exact numbers are embedded in a collapsible `<details>` block:
```html
<details>
<summary><b>Click to expand raw benchmark data tables</b></summary>

<!-- BENCHMARK-TABLE-START -->
<!-- generated by crates/yip-bench/wan/collect.sh -->
...
<!-- BENCHMARK-TABLE-END -->

</details>
```
`crates/yip-bench/wan/collect.sh` is updated to replace the content between `<!-- BENCHMARK-TABLE-START -->` and `<!-- BENCHMARK-TABLE-END -->` automatically, ensuring the raw table never drifts out of sync with the generated SVGs.

#### 5. Head-to-Head Comparison Matrix
An expanded, honest comparison table:

| Capability | `yip` | WireGuard | Tailscale | OpenVPN |
|:---|:---:|:---:|:---:|:---:|
| **FEC Packet Loss Recovery** | **Systematic RS GF(256) + RLNC** | None (TCP collapses) | None (TCP collapses) | None |
| **Max Throughput (Multi-Core)** | **40.2 Gbps (AF_XDP)** | In-kernel (~15–20 Gbps) | Userspace (~1–2 Gbps) | ~1–2 Gbps |
| **Active/Passive DPI Evasion** | **4-Engine Verified (REALITY/QUIC)**| None (trivially blocked) | None | Optional plugin |
| **TCP-over-TCP Meltdown** | **Immune (UDP / Datagram)** | Immune (UDP) | Immune (UDP) | Suffers under TCP mode |
| **Self-Certifying Identity** | **Yes (`fd00::/8` from PubKey)**| Yes (PublicKey) | Centralized Coordination| CA / PKI |
| **NAT Hole-Punching + Relay** | **Built-in (STUN + Blind Relay)**| External | Built-in (DERP) | External |
| **Kernel Requirement** | **Userspace + Opt-in eBPF** | Kernel module required | Userspace TUN | Kernel TUN |

---

## 5. GitHub Discovery & Forgejo Dual-Homing

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

### 5.3 Social Media Preview Card (`assets/social-card.png`)
- Since GitHub's social preview uploader and OpenGraph scrapers (Twitter/X, Discord, Slack, Telegram) do not accept SVG files, a high-resolution `1280×640` PNG card (`assets/social-card.png`) will be generated alongside `assets/social-card.svg`.
- The card features the `yip` fox emblem, the hero tagline, and the headline throughput benchmark curve.

### 5.4 Forgejo / Gitea Compatibility
- All image links in `README.md` use relative paths (`assets/*.svg`, `assets/*.png`) so they render natively in both GitHub and Forgejo without external CDN dependencies or broken image anchors.
- All workflow checks are mirrored across `.github/workflows/` and `.forgejo/workflows/`.

---

## 6. Verification & Quality Gates

1. **Deterministic SVG Output**:
   - `python3 crates/yip-bench/generate-graphs.py --check` must pass cleanly in CI.
   - Re-running `generate-graphs.py` without data changes must result in zero `git diff`.
2. **XML & Asset Integrity**:
   - Every generated SVG must parse without errors via `python3 -c "import xml.etree.ElementTree as ET; ET.parse('assets/bench-throughput-loss.svg')"`.
3. **Automated Reduction & Marker Sync**:
   - Running `crates/yip-bench/wan/collect.sh` must regenerate all 3 SVGs and update the `<!-- BENCHMARK-TABLE-START -->` block in `README.md` cleanly.
4. **Workspace Quality Gates**:
   - `cargo fmt --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test --all`
   - `cargo deny check`
