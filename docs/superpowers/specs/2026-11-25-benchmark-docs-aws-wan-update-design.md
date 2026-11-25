# Specification: Benchmark Suite Update, AWS Inter-Region WAN Sweeps, and Documentation Modernization

**Issue**: #263 (`docs(bench): update documentation, AWS inter-region benchmarks, and WAN netem results`)
**Status**: Draft / Under Review
**Date**: 2026-11-25

---

## 1. Executive Summary

This specification defines the complete end-to-end update of the `yip` benchmarking suite, multi-region AWS WAN dataset, deterministic SVG visual assets, architectural specifications, and crate API documentation.

Following the merge of PR #295 (Issue #252), which introduced the parallel cryptographic worker pool for single-stream line-rate scaling, the project documentation and performance figures require comprehensive synchronization. This effort executes a fresh automated AWS inter-region sweep across `us-east-1` and `us-west-2`, regenerates all deterministic SVG benchmark charts, refreshes the core architecture guide (`docs/03-architecture.md`), modernizes `README.md` and `docs/05-benchmarking-and-performance.md`, and updates crate API documentation and code examples with zero rustdoc warnings.

---

## 2. Requirements & Scope

### 2.1 Functional Requirements

1. **AWS Inter-Region WAN Benchmarking**:
   - Provision ephemeral EC2 `t3.small` instances across `us-east-1` (North Virginia) and `us-west-2` (Oregon) with Debian AMIs using `crates/yip-bench/wan/aws-up.sh`.
   - Provision `yipd` (with parallel crypto pool and AVX2 SIMD acceleration), Linux kernel `wireguard` (`wg0`), and `openvpn` via `provision.sh`.
   - Execute the automated netem packet loss matrix (0%, 1%, 3%, 5%, 10%) measuring single-stream TCP, 4-stream TCP, 200M UDP saturation, idle and loaded RTT latency, and loss suppression via `run-wan-bench.sh`.
   - Reduce results into `crates/yip-bench/wan/results/history.csv`, `crates/yip-bench/wan/results/best_of_3/wan.csv`, and `crates/yip-bench/RESULTS.md` via `collect.sh`.
   - Guarantee 100% clean teardown of all cloud resources (instances, security groups, temporary keypairs) via `aws-down.sh`.

2. **Deterministic SVG Asset Regeneration**:
   - Execute `crates/yip-bench/generate-graphs.py` to regenerate:
     - `assets/bench-throughput-loss.svg` (and raster PNG)
     - `assets/bench-fec-recovery.svg` (and raster PNG)
     - `assets/bench-multicore-scaling.svg` (and raster PNG)
     - `assets/bench-latency-jitter.svg` (and raster PNG)
   - Ensure strict XML determinism verified by `python3 crates/yip-bench/generate-graphs.py --check`.

3. **Performance Guide & Benchmark Documentation Refresh**:
   - Update `docs/05-benchmarking-and-performance.md` to synchronize:
     - Head-to-head empirical comparison tables with the latest AWS run data.
     - Multi-core scaling tables reflecting 40.27 Gbps AF_XDP Zero-Copy and the parallel crypto worker pool.
     - Single-stream throughput explanations highlighting the removal of the 2.35 Gbps single-core bottleneck.
     - 10-contender comparison matrix under clean and 5% packet loss conditions.
   - Update `README.md` benchmark highlights, narrative, and collapsible summary tables.

4. **Architecture Documentation & Configuration**:
   - Update `docs/03-architecture.md` with the parallel cryptographic pipeline subsystem:
     - `OutboundCryptoPool` architecture (round-robin task distribution, SPSC ring queues, sequence-stamped reorder buffer).
     - `InboundCryptoPool` architecture (parallel authenticated open and loss-tolerant anti-replay window commit).
     - Runtime configuration: `crypto_workers = "auto"` or numeric $N$, and `--crypto-workers` CLI override flag.

5. **Crate API Documentation & Examples**:
   - Resolve unresolved intra-doc link `WireCodec` in `bin/yipd/src/dataplane.rs`.
   - Add rustdoc documentation and usage examples to new public types and methods across `crates/yip-crypto`, `crates/yip-transport`, and `bin/yipd::crypto_pool`.
   - Verify `cargo doc --workspace --no-deps` completes with zero warnings.

### 2.2 Invariants & Constraints

- **Strictly Zero Emojis**: No emojis permitted in code, documentation, commit messages, PR descriptions, or comments.
- **Safety**: `#![forbid(unsafe_code)]` / `#![deny(unsafe_code)]` strictly preserved across all safe crates.
- **Zero Cloud Leakage**: All ephemeral EC2 instances, security groups, and keypairs created during the benchmark run must be cleanly deleted upon completion or error.
- **No Tagging or Release**: Work must not tag releases or publish crates without explicit user authorization.

---

## 3. Detailed Architecture & Workflows

### 3.1 AWS WAN Benchmark Pipeline

```
[aws-up.sh]
    │  - Generates temp Ed25519 keypair
    │  - Creates VPC security groups (UDP 51833-51835, TCP 22, TCP 5201)
    │  - Spawns t3.small instances in us-east-1 and us-west-2
    │  - Emits wan.env and results/.aws-session.json
    ▼
[provision.sh]
    │  - Applies net.core.rmem_max / wmem_max = 16 MiB
    │  - Copies release binary yipd to both nodes
    │  - Configures wireguard and openvpn tunnels
    ▼
[run-wan-bench.sh]
    │  - Runs 3 iterations per metric to filter hypervisor jitter
    │  - Sweeps netem loss: 0%, 1%, 3%, 5%, 10%
    │  - Records iperf3 TCP/UDP and ICMP ping latencies
    ▼
[collect.sh]
    │  - Extracts best-of-3 values
    │  - Appends to history.csv
    │  - Updates best_of_3/wan.csv and RESULTS.md
    ▼
[aws-down.sh] (ALWAYS EXECUTED VIA TRAP OR FINALIZER)
    │  - Terminates EC2 instances
    │  - Deletes security groups
    │  - Wipes temp private keys
```

### 3.2 Asset Regeneration Workflow

```
[history.csv + sharding-scale.csv + latency-jitter.csv]
    │
    ▼
[generate-graphs.py]
    │
    ├──> assets/bench-throughput-loss.svg / .png
    ├──> assets/bench-fec-recovery.svg / .png
    ├──> assets/bench-multicore-scaling.svg / .png
    └──> assets/bench-latency-jitter.svg / .png
    │
    ▼
[python3 generate-graphs.py --check] (Validates XML determinism)
```

### 3.3 Documentation Synchronization Map

| File | Section | Updates |
| :--- | :--- | :--- |
| `docs/05-benchmarking-and-performance.md` | §2 Head-to-Head Table | Update baseline, WireGuard, OpenVPN, and yip throughput, latency, and loss metrics from fresh AWS run. |
| `docs/05-benchmarking-and-performance.md` | §3 Testbeds & Scaling | Document single-stream line-rate scaling via parallel crypto worker pool. |
| `docs/05-benchmarking-and-performance.md` | §2 Contenders Table | Synchronize 10-contender comparison matrix under 0% and 5% loss. |
| `README.md` | Performance Highlights | Update bullet multipliers, P99 latency, and single-stream throughput statements. |
| `README.md` | WAN Summary Table | Update collapsible markdown table with fresh AWS sweep metrics. |
| `docs/03-architecture.md` | Cryptographic Pipeline | Add `OutboundCryptoPool` and `InboundCryptoPool` diagrams, queue flows, and configuration directives. |
| `bin/yipd/src/dataplane.rs` | Rustdoc | Fix unresolved link to `WireCodec` with valid intra-doc link `crate::codec::WireCodec`. |

---

## 4. Verification & Acceptance Criteria

1. **Cloud Execution & Teardown**:
   - `aws-up.sh`, `provision.sh`, `run-wan-bench.sh`, `collect.sh`, and `aws-down.sh` succeed.
   - `aws ec2 describe-instances` confirms 0 instances remaining in both regions.
2. **Data & Asset Integrity**:
   - `history.csv` updated with fresh timestamp and commit.
   - `python3 crates/yip-bench/generate-graphs.py --check` exits with code 0.
3. **Documentation Coherence**:
   - No contradictory throughput or latency claims between `README.md`, `RESULTS.md`, and `05-benchmarking-and-performance.md`.
4. **Rustdoc Verification**:
   - `cargo doc --workspace --no-deps` completes with 0 warnings.
5. **Quality Gates**:
   - `cargo test --workspace` passes.
   - `cargo clippy --workspace --all-targets -- -D warnings` clean.
