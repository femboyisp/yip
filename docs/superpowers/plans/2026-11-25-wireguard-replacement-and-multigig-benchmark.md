# WireGuard Replacement Positioning & 2 Gbps Multi-Gigabit Benchmark Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reposition `yip` as a direct, modern successor to WireGuard on Linux and Android infrastructure, replace outdated disclaimers, feature the 2 Gbps 10-contender line-rate loss sweep as the hero benchmark table, correct the clean UDP loss metric to 0.00%, and author the WireGuard migration guide (`docs/migrating-from-wireguard.md`).

**Architecture:** Update documentation, benchmarking datasets, and README landing page across the repository to reflect empirical multi-gigabit performance (sustaining 1,880 Mbit/s at 5% loss and 1,050 Mbit/s at 10% loss on 2G links), present all 10 contenders uniformly, eliminate misleading 0.15% clean UDP artifacts, and provide a comprehensive directive mapping guide from `wg0.conf` to `yipd.conf`.

**Tech Stack:** Markdown, Rust (cargo test/clippy/doc), Python (generate-graphs.py), Bash.

## Global Constraints

- Strictly ZERO EMOJIS in all code, tests, documentation, commit messages, PR descriptions, and assistant responses.
- Maintain `#![forbid(unsafe_code)]` / `#![deny(unsafe_code)]` outside `crates/yip-device` and `crates/yip-io`.
- All XML and SVG assets must pass determinism checks via `python3 crates/yip-bench/generate-graphs.py --check`.
- Zero compiler or rustdoc warnings (`cargo doc --workspace --no-deps` must exit 0).
- DO NOT tag or release until explicit user confirmation.

---

### Task 1: Benchmark Table Overhaul & 10-Contender Sweep Synchronization

**Files:**
- Modify: `README.md:290-340`
- Modify: `docs/05-benchmarking-and-performance.md:100-220`
- Modify: `crates/yip-bench/RESULTS.md:850-890`

**Interfaces:**
- Consumes: Verified 2 Gbps loss curve empirical dataset from spec (`docs/superpowers/specs/2026-11-25-wireguard-replacement-and-multigig-benchmark-design.md`).
- Produces: Uniform 10-contender comparative tables across all benchmark documentation.

- [ ] **Step 1: Update README.md benchmark table to feature the 2 Gbps 10-contender hero matrix**
  - Replace the 3-contender table (`yip`, `WireGuard`, `OpenVPN`) with the full 10-contender 2 Gbps dedicated link loss sweep (0%, 1%, 3%, 5%, 10% loss).
  - Correct the clean UDP loss entry for `yip` to `0.00%`.
  - Highlight `yip`'s sustained 1,880 Mbit/s at 5% loss and 1,050 Mbit/s at 10% loss.

- [ ] **Step 2: Update docs/05-benchmarking-and-performance.md summary tables**
  - Synchronize Section 1 and Section 2 tables with all 10 contenders (`yip`, `wireguard`, `wireguard-go`, `amneziawg`, `openvpn`, `n2n`, `zerotier`, `tailscale`, `netbird`, `nebula`).
  - Correct clean UDP loss across all testbeds to `0.00%`.
  - Add explicit note explaining socket buffer sizing for line rate without drops.

- [ ] **Step 3: Update crates/yip-bench/RESULTS.md summary table**
  - Synchronize the summary table to eliminate the 0.15% artifact and display all 10 contenders.

- [ ] **Step 4: Verify SVG assets and graph script validity**
  - Run `python3 crates/yip-bench/generate-graphs.py --check` to ensure all vector assets match.

---

### Task 2: Reposition `yip` as a Modern WireGuard Successor in Documentation

**Files:**
- Modify: `README.md:70-85`
- Modify: `docs/motivation.md:340-370`
- Modify: `docs/03-architecture.md:300-360`

**Interfaces:**
- Consumes: Architecture decisions and driver capabilities established in `bin/yipd`.
- Produces: Updated positioning narrative removing obsolete "stick with WireGuard" disclaimers.

- [ ] **Step 1: Replace "When to Choose yip" in README.md**
  - Remove "Stick with WireGuard for clean zero-loss gigabit LANs" and "Stick with WireGuard for simple point-to-point home VPNs".
  - Replace with "Why Choose yip Over WireGuard" comparative table highlighting point-to-point Mode 1 simplicity, clean-line rate parity, FEC loss resilience, post-quantum ML-KEM-768 encryption, native NAT traversal, and anti-DPI obfuscation.
  - Retain the transparent disclosure regarding macOS and Windows desktop GUI client development status.

- [ ] **Step 2: Update docs/motivation.md Section 5**
  - Update Section 5 ("Engineering for Real-World Networks") to reflect modern line-rate throughput on clean links via GSO/GRO and crypto worker pool, eliminating obsolete statements claiming a 14% clean throughput deficit.
  - Contrast `yip`'s in-flight FEC loss resilience against WireGuard's collapse under 1%–10% packet drop.

- [ ] **Step 3: Update docs/03-architecture.md driver overview**
  - Emphasize that Tier 1 standard unprivileged sockets deliver full multi-gigabit line-rate on Linux, making `yip` a drop-in in-kernel WireGuard replacement without kernel modules.

---

### Task 3: Author WireGuard Migration Guide (`docs/migrating-from-wireguard.md`)

**Files:**
- Create: `docs/migrating-from-wireguard.md`
- Modify: `README.md:86-90`
- Modify: `docs/01-getting-started.md:1-30`

**Interfaces:**
- Consumes: `yipd.conf` configuration syntax from `bin/yipd/src/config.rs`.
- Produces: Authoritative, comprehensive operator migration guide.

- [ ] **Step 1: Create docs/migrating-from-wireguard.md**
  - Document side-by-side directive translation (`[Interface]` to `yipd.conf`, `PrivateKey`/`PublicKey`, `ListenPort`, `Address`, `[Peer]`, `AllowedIPs` to `route_mode`/CIDRs).
  - Document key format conversion from WireGuard base64 to `yip` 64-character hex.
  - Provide complete working configuration examples for Point-to-Point VPS, NAT Rendezvous, and Full Internet Gateway / Exit Node.
  - Document `systemctl` service migration (`wg-quick@wg0` to `yipd`).

- [ ] **Step 2: Link the migration guide in README.md and documentation indices**
  - Add link to `docs/migrating-from-wireguard.md` in the README table of contents and documentation curriculum.

---

### Task 4: Validation, Verification & Changelog Update

**Files:**
- Modify: `CHANGELOG.md:24-40`

**Interfaces:**
- Consumes: All edits from Tasks 1-3.
- Produces: Clean git commit and PR push passing all quality gates.

- [ ] **Step 1: Update CHANGELOG.md under `[Unreleased]`**
  - Document the WireGuard replacement positioning, 2 Gbps 10-contender hero benchmark matrix, 0.00% clean loss correction, and new migration guide.

- [ ] **Step 2: Execute validation suite**
  - Run `python3 crates/yip-bench/generate-graphs.py --check`.
  - Run `cargo clippy --workspace --all-targets -- -D warnings`.
  - Run `cargo doc --workspace --no-deps`.
  - Run `cargo test --workspace`.
  - Verify zero emojis with unicode checker script.

- [ ] **Step 3: Commit and push**
  - Commit changes with message `docs(bench, guide): position yip as wireguard successor, add 2G 10-contender hero matrix and migration guide (#263)`.
  - Push to `origin feat/bench-docs-aws-wan-sync-263`.
  - Monitor CI checks until green.
