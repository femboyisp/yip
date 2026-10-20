# Visual Benchmarks, Architecture Diagrams & README Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform `yip`'s repository presentation into a top-tier open-source showcase with automated vector benchmark graphs (with symlog/inset scaling), a dual-path architecture SVG, a streamlined responsive README, synced raw data markers, and curated GitHub discovery metadata.

**Architecture:** A lightweight, dependency-free Python generator script (`crates/yip-bench/generate-graphs.py`) parses structured CSV data (`history.csv` and `sharding-scale.csv`) and deterministically produces standalone GitHub-Dark SVGs (`assets/*.svg`) with system fonts and card borders. `crates/yip-bench/wan/collect.sh` and CI workflows (`.github` and `.forgejo`) hook into this generator and update markdown markers in `README.md` automatically.

**Tech Stack:** Python 3 (standard library `xml.etree.ElementTree`), SVG 1.1 vector graphics, Bash, GitHub Actions / Forgejo CI, `gh` CLI.

## Global Constraints

- Standalone zero-dependency Python: `generate-graphs.py` must run with standard library Python 3 without requiring `matplotlib`, `cairo`, or `numpy`.
- Strict determinism: all floats formatted with fixed precision (e.g. `f"{val:.2f}"`), sorted keys, and no dynamic generation timestamps in SVG XML to prevent git-diff churn.
- Theme compatibility: all cards styled with `#0d1117` background, rounded corners `rx="12"`, and a subtle outer border `stroke="#30363d" stroke-width="1.5"` for crisp contrast on both GitHub Dark and Light modes.
- System font stack only: `ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif` and `ui-monospace, SFMono-Regular, Menlo, monospace` (no external `@import`).
- GFM mobile responsiveness: 2-column benchmark pairing must use inline HTML `<p align="center"><img width="49%" .../></p>`.
- Dual-homed: asset paths and workflow checks must be strictly relative and compatible with both GitHub and Forgejo/Gitea.

---

### Task 1: Structured Multi-Core Scaling Data & Deterministic SVG Generator

**Files:**
- Create: `crates/yip-bench/results/sharding-scale.csv`
- Create: `crates/yip-bench/generate-graphs.py`
- Create: `crates/yip-bench/tests/test-generate-graphs.sh`
- Test: `bash crates/yip-bench/tests/test-generate-graphs.sh`

**Interfaces:**
- Consumes: `crates/yip-bench/wan/results/history.csv` (WAN loss sweep data)
- Produces:
  - `assets/bench-throughput-loss.svg`
  - `assets/bench-fec-recovery.svg`
  - `assets/bench-multicore-scaling.svg`
- Command Interface:
  - `python3 crates/yip-bench/generate-graphs.py` (generates/updates assets)
  - `python3 crates/yip-bench/generate-graphs.py --check` (exits 0 if up to date, 1 if drift detected or invalid XML)

- [ ] **Step 1: Create structured multi-core scaling data file**
Create `crates/yip-bench/results/sharding-scale.csv` with verified scaling metrics across 1, 2, 4, and 8 worker cores:
```csv
cores,recvmmsg_gbps,recvmmsg_mpps,af_xdp_gbps,af_xdp_mpps,io_uring_gbps
1,4.58,0.45,8.68,0.85,5.12
2,6.04,0.59,11.26,1.10,6.80
4,11.43,1.12,21.22,2.07,12.50
8,21.56,2.10,40.27,3.93,22.10
```

- [ ] **Step 2: Write failing test script for graph generator**
Create `crates/yip-bench/tests/test-generate-graphs.sh`:
- Verifies `python3 crates/yip-bench/generate-graphs.py` creates all three SVGs.
- Verifies all SVGs parse as valid XML (`xml.etree.ElementTree`).
- Verifies determinism: running twice produces identical file hashes (`sha256sum`).
- Verifies `--check` flag returns exit 0 on clean state and exit 1 when an asset is missing or altered.
- Verifies SVG card styling: checks for `stroke="#30363d"` and `rx="12"`.
- Run `bash crates/yip-bench/tests/test-generate-graphs.sh` and ensure it fails.

- [ ] **Step 3: Implement `generate-graphs.py`**
Implement the standalone Python SVG generator:
- Build reusable SVG canvas class: `#0d1117` background, `#30363d` border, system font stack, grid lines `#21262d`, axis labels, and legend badges.
- `generate_throughput_loss_chart()`:
  - Parses latest run from `crates/yip-bench/wan/results/history.csv`.
  - Subtitle: `AWS Multi-Region WAN: us-east-1 ↔ us-west-2 (~60.6ms RTT, 1 vCPU, 10% FEC Parity)`.
  - Y-axis uses symlog or linear with 1%–10% inset zoom showing the dramatic gap (yip 16.6 Mbit/s vs WireGuard 0.5 Mbit/s at 10% loss).
  - Annotations: *"33× to 98× higher throughput under loss"*.
- `generate_fec_recovery_chart()`:
  - Subtitle: `AWS Multi-Region WAN: us-east-1 ↔ us-west-2 (~60.6ms RTT, Systematic Cauchy RS GF(256))`.
  - Y-axis: 0% to 15% ping loss.
  - Curves: yip (0% flatline) vs WireGuard / OpenVPN / Baseline (6%–12%).
  - Annotations: *"Zero TCP backoff penalty via systematic Reed–Solomon FEC"*.
- `generate_multicore_scaling_chart()`:
  - Subtitle: `Dedicated Multi-Core Testbed: 64 Parallel TCP Streams, Lock-Free SPSC Sharding (AMD Ryzen / EPYC)`.
  - Parses `crates/yip-bench/results/sharding-scale.csv`.
  - Curves: AF_XDP Zero-Copy (8.68 $\to$ 40.27 Gbps), Vectorized epoll (4.58 $\to$ 21.56 Gbps), io_uring.
  - Annotations: *"40+ Gbps Line-Rate Multi-Core Scaling"*.
- Implement `--check` mode: compares existing on-disk SVGs with newly generated strings; exits 1 if differences are found.

- [ ] **Step 4: Run test script and verify pass**
Run `bash crates/yip-bench/tests/test-generate-graphs.sh` to confirm all assertions pass.

- [ ] **Step 5: Commit Task 1**
```bash
git add crates/yip-bench/results/sharding-scale.csv crates/yip-bench/generate-graphs.py crates/yip-bench/tests/test-generate-graphs.sh assets/bench-*.svg
git commit -m "feat(bench): add deterministic vector SVG benchmark graph generator (#109)"
```

---

### Task 2: Visual Dual-Path System Architecture SVG Diagram

**Files:**
- Create: `crates/yip-bench/generate-architecture.py`
- Create: `assets/architecture.svg`
- Test: `python3 -c "import xml.etree.ElementTree as ET; ET.parse('assets/architecture.svg')"`

**Interfaces:**
- Produces: `assets/architecture.svg`
- Visual Features:
  - Control Plane (top): `BLAKE2s Key-Derivation`, `CA-Gated Mesh Discovery (yip-ca)`, `NAT Hole-Punching & Relay (yip-rendezvous)`
  - Data Plane (middle): `Linux TUN/TAP Device (64KB GSO/GRO)`, `Lock-Free SPSC Shards (Shard 0 .. Shard N)`, `ChaCha20-Poly1305 AEAD (Noise-IK, 120s rekey)`, `Systematic Cauchy RS-FEC (GF(256) SIMD + RLNC)`
  - Dual-Path Bottom:
    - **Fast Path**: `eBPF AF_XDP Zero-Copy (XSKMAP)` + `Vectorized epoll sendmmsg` $\to$ 40+ Gbps
    - **Stealth / Anti-DPI Path**: `uTLS Chrome JA3/JA4 Parity` + `Xray-REALITY TLS 1.3 / QUIC` $\to$ 4-Engine Oracle (`nDPI`, `Zeek`, `Suricata`, `Wireshark`)
  - Border: `stroke="#30363d" stroke-width="1.5" rx="12"` on `#0d1117` canvas.

- [ ] **Step 1: Write `crates/yip-bench/generate-architecture.py`**
Script that deterministically generates `assets/architecture.svg`:
- Defines visual containers, glowing flow arrows, box outlines, and text labels.
- Color codes: Control Plane (`#6366f1`), Data Plane pipeline (`#06b6d4`), RS-FEC / Anti-DPI hero elements (`#f97316`), Fast Path (`#10b981`).
- Embeds clean typography using the zero-dependency system font stack.

- [ ] **Step 2: Generate `assets/architecture.svg`**
Run `python3 crates/yip-bench/generate-architecture.py` to create `assets/architecture.svg`.

- [ ] **Step 3: Validate XML integrity and visual contrast**
Validate XML with `python3 -c "import xml.etree.ElementTree as ET; ET.parse('assets/architecture.svg')"`.
Check visually or via text inspection that all box coordinates, text labels, and arrow paths align cleanly.

- [ ] **Step 4: Commit Task 2**
```bash
git add crates/yip-bench/generate-architecture.py assets/architecture.svg
git commit -m "docs(arch): add dual-path vector system architecture SVG diagram"
```

---

### Task 3: Pipeline Integration, Marker Sync & Social Preview Card

**Files:**
- Modify: `crates/yip-bench/wan/collect.sh`
- Create: `crates/yip-bench/generate-social-card.py`
- Create: `assets/social-card.svg`
- Create: `assets/social-card.png`
- Modify: `.github/workflows/ci.yml`
- Modify: `.forgejo/workflows/ci.yml`
- Modify: `.github/workflows/wan-benchmark.yml`
- Test: `bash crates/yip-bench/wan/tests/test-collect-sync.sh`

**Interfaces:**
- Consumes: `crates/yip-bench/wan/results/history.csv`
- Produces: Synchronized `README.md` benchmark table between `<!-- BENCHMARK-TABLE-START -->` and `<!-- BENCHMARK-TABLE-END -->`, regenerated SVGs, and `assets/social-card.png`.

- [ ] **Step 1: Update `crates/yip-bench/wan/collect.sh`**
- After updating `RESULTS-wan.md` and `readme-snippet.md`, call `python3 "$REPO_ROOT/crates/yip-bench/generate-graphs.py"` to ensure SVGs stay synced with the newest run data.
- Add marker replacement logic to `collect.sh`:
  Replace the content in `README.md` between `<!-- BENCHMARK-TABLE-START -->` and `<!-- BENCHMARK-TABLE-END -->` with the newest snippet.

- [ ] **Step 2: Write test verifying marker synchronization**
Create `crates/yip-bench/tests/test-collect-sync.sh` to test that `collect.sh` correctly updates the target markdown markers without modifying text outside the block.

- [ ] **Step 3: Implement social preview card generator**
Create `crates/yip-bench/generate-social-card.py`:
- Generates `assets/social-card.svg` (1280×640) with `#0d1117` background, fox mascot emblem, hero title, one-liner tagline, and the headline throughput curve.
- Automatically rasterizes `assets/social-card.png` via Python (`resvg-js`, `rsvg-convert`, `cairosvg`, or PIL/headless fallback) to produce a `< 1 MB` PNG ready for GitHub repository settings and OpenGraph social previews.

- [ ] **Step 4: Add graph check to CI workflows**
Update `.github/workflows/ci.yml` and `.forgejo/workflows/ci.yml` to include:
```yaml
      - name: verify benchmark graphs are up-to-date
        run: python3 crates/yip-bench/generate-graphs.py --check
```
Update `.github/workflows/wan-benchmark.yml` to run graph generation before committing results.

- [ ] **Step 5: Run tests and verify CI syntax**
Run `bash crates/yip-bench/tests/test-collect-sync.sh`.
Run `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); yaml.safe_load(open('.github/workflows/wan-benchmark.yml'))"`.

- [ ] **Step 6: Commit Task 3**
```bash
git add crates/yip-bench/wan/collect.sh crates/yip-bench/generate-social-card.py assets/social-card.* .github/workflows/ .forgejo/workflows/ crates/yip-bench/tests/test-collect-sync.sh
git commit -m "ci(bench): integrate automated graph generation and README marker synchronization"
```

---

### Task 4: Root README.md Overhaul & Comparison Matrix

**Files:**
- Modify: `README.md`
- Test: Verify relative links, image embeds, markdown parsing, and marker sync

**Interfaces:**
- Consumes: `assets/*.svg`, `assets/*.png`, `crates/yip-bench/wan/results/readme-snippet.md`
- Produces: Complete high-polish root `README.md`

- [ ] **Step 1: Overhaul Hero Header & Badges**
- Top logo: `assets/yip.gif` (centered).
- Tagline: *"A low-latency, loss-resilient peer-to-peer mesh VPN in Rust."*
- Badges:
  - CI Build (`main`)
  - 4-Engine DPI Oracle: `DPI Evasion: nDPI | Zeek | Suricata | Wireshark`
  - Honest Safety Boundary: `Protocol & Crypto: #![forbid(unsafe_code)]`
  - Stable Rust `1.85+` & Platform `Linux x86_64 / arm64`
  - License `AGPL-3.0`
- Pill navigation links: `[Quick Start]` `[Benchmarks]` `[Architecture]` `[Comparison]` `[Why yip?]`

- [ ] **Step 2: Add "Why yip?" 3-Pillar Highlight**
Add visual card section explaining:
1. **Loss Immunity without Retransmission**: Reed–Solomon FEC (GF(256)) prevents TCP congestion collapse.
2. **Line-Rate Multi-Core Scaling**: 21.5 Gbps with vectorized sockets; 40+ Gbps with AF_XDP.
3. **Architectural Censorship-Resistance**: Verified against 4 major DPI engines; authentic Xray-REALITY browser TLS 1.3 mimicry.

- [ ] **Step 3: Embed Responsive Benchmark Grid & Sync Markers**
- Embed 2-column image pair:
```html
<p align="center">
  <img src="assets/bench-throughput-loss.svg" width="49%" alt="Throughput Under Loss" />
  <img src="assets/bench-multicore-scaling.svg" width="49%" alt="Multi-Core Scaling" />
</p>
<p align="center">
  <img src="assets/bench-fec-recovery.svg" width="98.5%" alt="Effective Loss Recovery" />
</p>
```
- Embed collapsible raw data table wrapped in:
```html
<details>
<summary><b>Click to expand raw benchmark data tables</b></summary>

<!-- BENCHMARK-TABLE-START -->
<!-- generated by crates/yip-bench/wan/collect.sh -->
<!-- BENCHMARK-TABLE-END -->

</details>
```

- [ ] **Step 4: Embed Visual Architecture & Comparison Matrix**
- Embed `assets/architecture.svg`.
- Insert the head-to-head comparison matrix table comparing `yip` against WireGuard, Tailscale, and OpenVPN.
- Streamline Quick Start and Developer guide sections.

- [ ] **Step 5: Verify Markdown Rendering & Link Integrity**
Run:
```bash
python3 -c "
import re
with open('README.md') as f:
    content = f.read()
assert '<!-- BENCHMARK-TABLE-START -->' in content
assert '<!-- BENCHMARK-TABLE-END -->' in content
for img in re.findall(r'src=\"([^\"]+)\"', content):
    import os
    assert os.path.exists(img), f'Missing image: {img}'
print('README verification passed!')
"
```

- [ ] **Step 6: Commit Task 4**
```bash
git add README.md
git commit -m "docs: overhaul README with visual benchmark grid, architecture diagram, and comparison matrix"
```

---

### Task 5: GitHub Discovery Metadata Update

**Files:**
- Modify: GitHub repository description and topics via `gh repo edit`
- Test: Verify metadata with `gh repo view --json description,repositoryTopics`

**Interfaces:**
- Updates GitHub remote metadata

- [ ] **Step 1: Update repository description**
```bash
gh repo edit --description "🦊 Low-latency P2P mesh VPN in Rust. Reed–Solomon FEC loss immunity, 40 Gbps AF_XDP multi-core scaling, NAT traversal, self-certifying routing, and anti-DPI TLS mimicry."
```

- [ ] **Step 2: Update curated repository topics**
```bash
gh repo edit --add-topic "rust,vpn,mesh-vpn,wireguard-alternative,networking,p2p,privacy,forward-error-correction,fec,reed-solomon,af-xdp,ebpf,zero-copy,io-uring,low-latency,censorship-resistance,dpi-evasion,noise-protocol,nat-traversal,tunnel"
```

- [ ] **Step 3: Verify metadata**
Run `gh repo view --json description,repositoryTopics` and confirm all 20 topics and the description match the specification.

- [ ] **Step 4: Run full workspace test suite and quality gates**
Run:
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo deny check
python3 crates/yip-bench/generate-graphs.py --check
```

- [ ] **Step 5: Commit any final sync adjustments**
```bash
git status
# If any clean changes remain:
# git commit -m "chore: finalize visual showcase and repository metadata (#109)"
```
