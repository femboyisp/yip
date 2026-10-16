# WAN Benchmark Automated Harness & Ephemeral Multi-Region Testing — Design Spec

**Date:** 2026-10-16
**Status:** Approved (design), pre-implementation
**Issue:** #109 (test/bench: the one real WAN benchmark is not reproducible from the repo)

---

## 1. Goal & Motivation

Produce an honest, reproducible, and automated Wide Area Network (WAN) benchmark harness that measures **yip** against **WireGuard**, **OpenVPN**, and a **no-tunnel baseline** across real internet paths.

### Key Objectives
1. **Reproducibility**: Reconstruct, scrub, and commit the complete benchmark harness under `crates/yip-bench/wan/` (`lib.sh`, `provision.sh`, `run-wan-bench.sh`, `collect.sh`, `teardown.sh`, `wan.env.example`).
2. **Dual-Mode Provisioning**:
   - **Mode A (Static VPS)**: Point the harness at pre-configured Linux hosts (e.g., the historical Utah ↔ Las Vegas Debian 13 VPSes) using SSH key authentication.
   - **Mode B (Ephemeral AWS EC2)**: Optionally provision on-demand EC2 instances across configurable multi-region pairs (e.g., `us-east-1` ↔ `us-west-2`), run the full suite, and automatically terminate all instances and security resources on completion.
3. **CI Automation & Trend History**:
   - An automated GitHub Actions workflow (`.github/workflows/wan-benchmark.yml`) supporting `push: branches: [main]` and `workflow_dispatch`.
   - Graceful skip guards if cloud credentials or host secrets are unset.
   - Commits updated results (`RESULTS-wan.md`, `history.csv`) back to `main` with `[skip ci]`.
   - Forensic artifact archiving with 30-day retention.
4. **Documentation Accuracy**:
   - Remove stale RaptorQ references from `crates/yip-bench/README.md` and embed the real WAN benchmark results.

---

## 2. Architecture & File Structure

All suite files reside under `crates/yip-bench/wan/`:

```
crates/yip-bench/
├── RESULTS-wan.md                     # Committed reduced markdown tables & analysis
├── README.md                          # Updated hot-path & WAN benchmark docs
└── wan/
    ├── .gitignore                     # Ignores wan.env, ephemeral keys, and temp configs
    ├── wan.env.example                # Scrubbed host template (RFC 5737 doc IPs)
    ├── lib.sh                         # Common SSH, remote exec, logging, and CSV routines
    ├── provision.sh                   # Remote host package install, socket tuning, overlay setup
    ├── run-wan-bench.sh               # Execution matrix (throughput, latency, netem loss)
    ├── collect.sh                     # CSV reduction to RESULTS-wan.md & readme-snippet.md
    ├── teardown.sh                    # Remote tunnel, systemd unit, and netem qdisc teardown
    ├── aws-up.sh                      # Ephemeral AWS EC2 launch & security group setup
    ├── aws-down.sh                    # Ephemeral AWS EC2 guaranteed termination
    └── results/
        ├── history.csv                # Tracked multi-run historical time-series data
        ├── readme-snippet.md          # 4-column summary snippet for root README
        └── <timestamp>/               # Raw per-run outputs (wan.csv, logs)
```

---

## 3. Ephemeral AWS Multi-Region Provisioning

### 3.1 `aws-up.sh`
- **Region Configuration**: Accepts two region arguments (default: `us-east-1` and `us-west-2`).
- **AMI Discovery**: Dynamically resolves the latest official Debian 12 (Bookworm) minimal AMI per region via `aws ec2 describe-images`.
- **Instance Sizing**: Defaults to `t3.small` (2 vCPU, 2 GB RAM x86_64), providing fair comparability with standard 1–2 core cloud VPS tiers.
- **Resource Tagging**: Applies `TAG="yip-wan-bench-${RUN_ID}"` across all created resources.
- **Security Groups**:
  - Ingress:
    - `22/tcp` restricted to the runner’s public IP (`curl -s https://checkip.amazonaws.com`).
    - `51833/udp` (Yip), `51834/udp` (WireGuard), `51835/udp` (OpenVPN), `5201/tcp+udp` (iperf3) authorized between the two instances' public IPs.
- **Key Pair**: Generates a temporary ED25519 keypair locally, imports it into both regions, and restricts permissions to `chmod 600`.
- **Environment Output**: Generates `crates/yip-bench/wan/wan.env` with instance IPs and region labels (`HOST_A_LABEL="AWS us-east-1"`, `HOST_B_LABEL="AWS us-west-2"`).
- **Session State**: Saves metadata to `results/.aws-session.json` for deterministic teardown.

### 3.2 `aws-down.sh`
- Reads instance IDs, security group IDs, and keypair names from `results/.aws-session.json` (or queries by `TAG`).
- Terminates instances via `aws ec2 terminate-instances` in parallel.
- Waits for instance state `terminated`.
- Deletes security groups and key pairs.
- Removes local temporary private keys.
- **Guaranteed Execution**: Driven via shell traps on `EXIT INT TERM` and GitHub Actions `if: always()`.

---

## 4. Host Provisioning & Network Overlays

### 4.1 System Provisioning (`provision.sh`)
- **Binary Shipment**: Compiles `yipd` locally in `--release` mode and atomically deploys to `/usr/local/bin/yipd` on both hosts via `scp` and `mv -f`.
- **Fair Host Tuning**:
  ```bash
  sysctl -qw net.core.rmem_max=16777216 \
             net.core.wmem_max=16777216 \
             net.core.netdev_max_backlog=5000
  ```
  Disclosed in results: ensures yipd's 4 MiB socket buffers take effect without kernel throttling.
- **Packages**: Idempotently installs `wireguard-tools`, `openvpn`, `iperf3`, and `mgen`.

### 4.2 Three Co-existing Overlays
Each tunnel is assigned its own dedicated `/30` overlay:
1. **Yip**:
   - Subnet: `10.77.0.0/30` (`10.77.0.1` ↔ `10.77.0.2`).
   - Outer Transport: UDP port `51833`, MTU 1380, `transport=raw` (epoll driver).
2. **WireGuard**:
   - Subnet: `10.77.1.0/30` (`10.77.1.1` ↔ `10.77.1.2`).
   - Outer Transport: UDP port `51834`, MTU 1380, Linux in-kernel module.
3. **OpenVPN**:
   - Subnet: `10.77.2.0/30` (`10.77.2.1` ↔ `10.77.2.2`).
   - Outer Transport: UDP port `51835`, MTU 1380, static-key P2P mode, AES-256-GCM.

### 4.3 Pre-flight Verification
Runs ICMP ping checks across all three tunnels (`A -> B`). If any overlay fails to achieve 0% loss, the run halts immediately with diagnostic logs before executing the benchmark matrix.

---

## 5. Benchmark Execution Matrix (`run-wan-bench.sh`)

Evaluates all four targets: `baseline` (direct public IP), `yip`, `wireguard`, and `openvpn`.

1. **TCP Throughput**:
   - Single-stream: `iperf3 -c <dst> -p 5201 -t 12 -P 1 -J`
   - Multi-stream: `iperf3 -c <dst> -p 5201 -t 12 -P 4 -J`
2. **UDP Throughput, Jitter, & Packet Loss**:
   - `iperf3 -c <dst> -p 5201 -u -b 200M -t 10 -J`
3. **Latency & Latency Under Load**:
   - Idle: `ping -c 15 -i 0.2 <dst>`
   - Loaded: `ping -c 25 -i 0.2 <dst>` with concurrent background `iperf3` saturating the link.
4. **Sender CPU Utilization**:
   - Delta of `/proc/stat` on Host A during a 6-second saturated TCP transmission.
5. **Netem Loss Resilience Sweep**:
   - Injected loss percentages: `0%`, `1%`, `3%`, `5%`, `10%`.
   - **Control Traffic Protection**: Loss is applied exclusively to Host B's public destination IP using a 4-band `prio` qdisc with `u32` filter on the outer egress interface. Host control SSH connections are completely unaffected.
   - Measures:
     - Effective ping packet loss (`ping -c 100 -i 0.05`).
     - TCP goodput under loss (`iperf3 -t 12`).

---

## 6. Results Reduction & Scrubbing (`collect.sh`)

- Python-based parser reading raw `wan.csv` and historical data.
- **Privacy & Scrubbing**: Uses `HOST_A_LABEL` and `HOST_B_LABEL` (e.g. `Debian 13 (Utah)` ↔ `Debian 13 (Las Vegas)`, or `AWS us-east-1` ↔ `AWS us-west-2`) across all generated markdown documents. Raw public IPs are never written to git-tracked files.
- **Output Artifacts**:
  - `crates/yip-bench/RESULTS-wan.md`: Full comparative tables (Clean-path throughput, latency under load, and netem loss resilience).
  - `crates/yip-bench/wan/results/readme-snippet.md`: Summary table for the root `README.md`.
  - Appends to `crates/yip-bench/wan/results/history.csv`.

---

## 7. GitHub Actions Workflow (`.github/workflows/wan-benchmark.yml`)

### 7.1 Triggers & Parameters
- `push: branches: [main]`
- `workflow_dispatch`:
  - `mode`: `aws` (default) or `static`.
  - `region_a`: Default `us-east-1`.
  - `region_b`: Default `us-west-2`.

### 7.2 Graceful Absence Guards
If required secrets (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` for AWS mode, or `WAN_HOST_A` / `WAN_SSH_KEY` for static mode) are absent:
- Prints a clear notice: `::notice::WAN benchmark skipped — required infrastructure secrets not configured`.
- Exits 0 cleanly.

### 7.3 Guaranteed Teardown & Commit Back
- Teardown steps run with `if: always()`, ensuring `teardown.sh` and `aws-down.sh` execute even upon benchmark failure or cancellation.
- Commits updated `RESULTS-wan.md` and `crates/yip-bench/wan/results/` using `github-actions[bot]` with message `bench(wan): record automated WAN benchmark results [skip ci]`.
- Uploads forensic CSVs and engine logs with 30-day retention via `actions/upload-artifact@v4`.

---

## 8. Documentation Hardening

- **`crates/yip-bench/README.md`**:
  - Eliminates stale RaptorQ references (~18x discrepancy from the removed codec in #50).
  - Explains the GF(256) Cauchy systematic Reed–Solomon implementation and P+Q fast-path measurements.
  - Links to `RESULTS-wan.md`.
- **Root `README.md`**:
  - Embeds the verified WAN benchmark comparison table.

---

## 9. Verification & Success Criteria

1. `bash -n` validation on all shell scripts (`lib.sh`, `provision.sh`, `run-wan-bench.sh`, `collect.sh`, `teardown.sh`, `aws-up.sh`, `aws-down.sh`).
2. Execution of `collect.sh` against historical `wan.csv` verifying clean generation of `RESULTS-wan.md` and `readme-snippet.md`.
3. Validation of `.github/workflows/wan-benchmark.yml` syntax and graceful skip behavior.
4. Clean workspace checks: `cargo test --all`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and `cargo deny check`.
