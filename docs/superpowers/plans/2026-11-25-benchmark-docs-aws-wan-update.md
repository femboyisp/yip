# Benchmark Suite Update, AWS Inter-Region WAN Sweeps, and Documentation Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the `yip` benchmarking suite and multi-region AWS WAN dataset, regenerate deterministic SVG charts, synchronize architectural specifications and performance guides with the newly merged parallel crypto worker pool, and eliminate rustdoc warnings.

**Architecture:** Automated ephemeral EC2 provisioning across `us-east-1` and `us-west-2` via `aws-up.sh` executes the 0%–10% netem loss matrix with guaranteed `aws-down.sh` teardown. Metrics are ingested by `collect.sh` into `history.csv`, driving `generate-graphs.py` deterministic SVG regeneration and synchronizing `docs/05-benchmarking-and-performance.md`, `README.md`, `docs/03-architecture.md`, and crate rustdocs.

**Tech Stack:** Rust (cargo, rustdoc), Python 3 (SVG generation, XML validation), Bash (AWS CLI, SSH, iperf3, tc-netem, iproute2).

## Global Constraints

- Strictly ZERO EMOJIS across all code, tests, documentation, commit messages, PR descriptions, and replies.
- Maintain `#![forbid(unsafe_code)]` / `#![deny(unsafe_code)]` across all safe crates outside `crates/yip-device` and `crates/yip-io`.
- All ephemeral cloud resources (instances, security groups, keypairs) must be verified 100% destroyed upon completion or failure.
- DO NOT tag or release until explicit user authorization.

---

### Task 1: Crate API Documentation & Intra-Doc Link Fixes

**Files:**
- Modify: `bin/yipd/src/dataplane.rs:220-230`
- Modify: `crates/yip-crypto/src/session.rs:1-80`
- Modify: `crates/yip-transport/src/lib.rs:210-250`
- Modify: `bin/yipd/src/crypto_pool/mod.rs:1-50`

**Interfaces:**
- Consumes: `bin/yipd::codec::WireCodec`, `yip_crypto::Session::reserve_counters`, `yip_transport::Transport::classify`.
- Produces: Clean rustdoc output with zero warnings across `--workspace --no-deps`.

- [ ] **Step 1: Fix unresolved intra-doc link in `bin/yipd/src/dataplane.rs`**
  Update the doc comment on `DataplaneReactor` or line 224 to reference `crate::codec::WireCodec` or escape brackets `\[`WireCodec`\]`.

- [ ] **Step 2: Add doc comments and examples to `yip-crypto`**
  Document `Session::reserve_counters` and `Session::commit_replay` with doctests or code examples in `crates/yip-crypto/src/session.rs`.

- [ ] **Step 3: Add doc comments and examples to `yip-transport`**
  Document `Transport::classify` and `Transport::encode_scratch_with_class` in `crates/yip-transport/src/lib.rs`.

- [ ] **Step 4: Add module-level doc comments to `bin/yipd/src/crypto_pool`**
  Document the architecture of `OutboundCryptoPool` and `InboundCryptoPool` in `bin/yipd/src/crypto_pool/mod.rs`.

- [ ] **Step 5: Verify with `cargo doc`**
  Run `cargo doc --workspace --no-deps` and verify 0 warnings.

- [ ] **Step 6: Commit changes**
  Commit with message `docs(api): fix rustdoc intra-doc links and document crypto pool interfaces (#263)`.

---

### Task 2: Ephemeral AWS EC2 Provisioning, Benchmark Execution, and Teardown

**Files:**
- Execute: `crates/yip-bench/wan/aws-up.sh`
- Execute: `crates/yip-bench/wan/provision.sh`
- Execute: `crates/yip-bench/wan/run-wan-bench.sh`
- Execute: `crates/yip-bench/wan/collect.sh`
- Execute: `crates/yip-bench/wan/aws-down.sh`
- Output: `crates/yip-bench/wan/results/history.csv`
- Output: `crates/yip-bench/wan/results/best_of_3/wan.csv`
- Output: `crates/yip-bench/RESULTS.md`

**Interfaces:**
- Consumes: AWS CLI credentials (`yip-wan-benchmarker`), `target/release/yipd`.
- Produces: Fresh sweep rows in `history.csv` for current git commit and timestamp.

- [ ] **Step 1: Build release binary `yipd`**
  Run `cargo build --release --bin yipd`.

- [ ] **Step 2: Launch ephemeral EC2 testbed via `aws-up.sh`**
  Execute `bash crates/yip-bench/wan/aws-up.sh --region-a us-east-1 --region-b us-west-2 --instance-type t3.small`. Verify `wan.env` and `results/.aws-session.json` are created.

- [ ] **Step 3: Provision nodes via `provision.sh`**
  Execute `bash crates/yip-bench/wan/provision.sh`. Verify `yipd`, `wireguard`, and `openvpn` are installed and reachable.

- [ ] **Step 4: Execute WAN benchmark sweep via `run-wan-bench.sh`**
  Execute `bash crates/yip-bench/wan/run-wan-bench.sh`. Verify full 0% to 10% packet loss matrix completes.

- [ ] **Step 5: Reduce results via `collect.sh`**
  Execute `bash crates/yip-bench/wan/collect.sh`. Confirm `history.csv` and `RESULTS.md` are updated.

- [ ] **Step 6: Teardown cloud resources via `aws-down.sh`**
  Execute `bash crates/yip-bench/wan/aws-down.sh`. Verify `aws ec2 describe-instances` returns 0 running/pending instances in `us-east-1` and `us-west-2`.

- [ ] **Step 7: Commit updated dataset**
  Commit with message `bench(wan): record AWS inter-region transit benchmark sweep (#263)`.

---

### Task 3: Deterministic SVG Benchmark Asset Regeneration

**Files:**
- Execute: `crates/yip-bench/generate-graphs.py`
- Modify: `assets/bench-throughput-loss.svg`
- Modify: `assets/bench-fec-recovery.svg`
- Modify: `assets/bench-multicore-scaling.svg`
- Modify: `assets/bench-latency-jitter.svg`
- Modify: `assets/*.png`

**Interfaces:**
- Consumes: Updated `history.csv`, `sharding-scale.csv`, `latency-jitter.csv`.
- Produces: Deterministic SVG and raster PNG files in `assets/`.

- [ ] **Step 1: Execute `generate-graphs.py`**
  Run `python3 crates/yip-bench/generate-graphs.py`.

- [ ] **Step 2: Validate XML determinism**
  Run `python3 crates/yip-bench/generate-graphs.py --check`. Verify code exits 0.

- [ ] **Step 3: Commit regenerated assets**
  Commit with message `assets(bench): regenerate deterministic SVG benchmark graphs (#263)`.

---

### Task 4: Documentation Synchronization & Modernization

**Files:**
- Modify: `docs/05-benchmarking-and-performance.md`
- Modify: `README.md`
- Modify: `docs/03-architecture.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: Latest empirical values from `history.csv` and `best_of_3/wan.csv`.
- Produces: Synchronized performance guide, README, architecture spec, and changelog.

- [ ] **Step 1: Update `docs/05-benchmarking-and-performance.md`**
  - Synchronize Section 2 Head-to-Head Comparison Table with fresh AWS metrics.
  - Update Section 1 throughput multipliers and clean-link vs degraded-link analysis.
  - Update Section 3 Testbed 2 with single-stream line-rate scaling via parallel crypto worker pool.
  - Synchronize 10-contender comparison matrix under 0% and 5% loss.

- [ ] **Step 2: Update `README.md`**
  - Synchronize Performance & Benchmark Highlights bullets (multipliers, latency, scaling).
  - Update collapsible raw WAN benchmark data table.
  - Update references to multi-core scaling and parallel crypto worker pool.

- [ ] **Step 3: Update `docs/03-architecture.md`**
  - Add documentation of `OutboundCryptoPool` and `InboundCryptoPool` subsystems.
  - Detail lock-free SPSC queues, ROB sequence decoupling, and zero-allocation fixed buffers.
  - Document `crypto_workers` configuration options in `yipd.conf` and CLI flags.

- [ ] **Step 4: Update `CHANGELOG.md`**
  - Document all benchmarking, asset generation, and documentation updates under `[Unreleased]`.

- [ ] **Step 5: Run full workspace test suite and lint checks**
  Run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`.

- [ ] **Step 6: Commit documentation updates**
  Commit with message `docs(bench, arch): synchronize benchmark guide, README, and architecture specs (#263)`.

---

### Task 5: Final Review & Pull Request Submission

**Files:**
- Workspace repository

- [ ] **Step 1: Branch preparation**
  Create feature branch `docs/bench-aws-wan-sync-263` and push commits.

- [ ] **Step 2: Open Pull Request**
  Open PR targeting `main` referencing Issue #263 with complete summary and verification evidence.

- [ ] **Step 3: CI Monitoring**
  Monitor GitHub Actions CI checks until all checks pass green.
