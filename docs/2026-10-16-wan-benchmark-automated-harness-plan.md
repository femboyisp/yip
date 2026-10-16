# WAN Benchmark Automated Harness & Ephemeral AWS Multi-Region Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconstruct, scrub, and commit the reproducible WAN benchmark harness under `crates/yip-bench/wan/`, implement ephemeral AWS EC2 multi-region provisioning and teardown, automate execution in GitHub Actions on push and dispatch, and update benchmark documentation.

**Architecture:** A dual-mode harness supporting static VPS hosts (via `wan.env` / SSH secrets) and ephemeral AWS EC2 instances across arbitrary region pairs via lightweight AWS CLI scripts (`aws-up.sh` / `aws-down.sh`). The harness deploys release `yipd`, WireGuard, and OpenVPN over three distinct `/30` overlays on tuned hosts, runs an iperf3 and netem loss matrix with SSH control protection, and reduces results to scrubbed markdown tables and trend lines.

**Tech Stack:** Bash (`set -euo pipefail`), Python 3 (`json`, `csv`), AWS CLI (`aws ec2`), `iperf3`, `iproute2` (`tc netem`), `wireguard-tools`, `openvpn`, GitHub Actions (`workflow_dispatch`, `actions/upload-artifact@v4`).

## Global Constraints

- Zero secrets, private SSH keys, or raw infrastructure IP addresses committed to git repository files; committed artifacts use location labels (`HOST_A_LABEL`, `HOST_B_LABEL`).
- Safe Netem: Injected packet loss on Host A must be scoped strictly to Host B's outer IP via `prio` qdisc and `u32` filter so the control SSH session is never throttled or dropped.
- Guaranteed Teardown: All AWS resources (instances, security groups, keypairs) must be cleaned up deterministically via shell trap and `if: always()` in CI.
- Graceful Skip: Missing credentials in CI must emit a clean skip (exit 0) rather than failing the run.
- Strictly `#![forbid(unsafe_code)]` preserved across all workspace crates.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` clean, `cargo fmt --check` clean, `cargo deny check` clean.

---

### Task 1: Core WAN Harness Reconstruction & Scrubbing

**Files:**
- Create: `crates/yip-bench/wan/.gitignore`
- Create: `crates/yip-bench/wan/wan.env.example`
- Create: `crates/yip-bench/wan/lib.sh`
- Create: `crates/yip-bench/wan/provision.sh`
- Create: `crates/yip-bench/wan/run-wan-bench.sh`
- Create: `crates/yip-bench/wan/collect.sh`
- Create: `crates/yip-bench/wan/teardown.sh`
- Create: `crates/yip-bench/wan/results/history.csv`
- Create: `crates/yip-bench/RESULTS-wan.md`

**Interfaces:**
- Consumes: Release `yipd` binary (`target/release/yipd`), host connection details in `wan.env`.
- Produces: `results/<ts>/wan.csv`, `RESULTS-wan.md`, `results/readme-snippet.md`, overlay network devices `yipbench0`, `wgbench`, `tunovpn0`.

- [ ] **Step 1: Create `.gitignore` and `wan.env.example`**

Write `crates/yip-bench/wan/.gitignore`:
```gitignore
wan.env
results/.yipconf/
results/.wgconf/
results/.aws-session.json
id_ed25519_wan*
```

Write `crates/yip-bench/wan/wan.env.example` using RFC 5737 documentation IPs and descriptive labels:
```bash
# WAN benchmark host pair template — copy to wan.env and fill in.
HOST_A=203.0.113.10
HOST_B=198.51.100.20
HOST_A_LABEL="VPS-A (Region A)"
HOST_B_LABEL="VPS-B (Region B)"
SSH_USER=root
SSH_KEY=$HOME/.ssh/id_ed25519
YIP_PORT=51833
WG_PORT=51834
OVPN_PORT=51835
OVERLAY_MTU=1380
```

- [ ] **Step 2: Create `lib.sh` and `teardown.sh`**

Write `crates/yip-bench/wan/lib.sh` with strict error handling, remote exec helpers (`A`, `B`, `Aq`, `Bq`, `put_A`, `put_B`), logging, and `csv_row`:
```bash
set -euo pipefail
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/../../.." && pwd)"

if [[ -f "$SUITE_DIR/wan.env" ]]; then
    # shellcheck disable=SC1091
    . "$SUITE_DIR/wan.env"
else
    echo "FATAL: $SUITE_DIR/wan.env not found — copy wan.env.example or run aws-up.sh." >&2
    exit 1
fi
: "${HOST_A:?}" "${HOST_B:?}" "${SSH_USER:?}" "${SSH_KEY:?}"
: "${YIP_PORT:=51833}" "${WG_PORT:=51834}" "${OVPN_PORT:=51835}" "${OVERLAY_MTU:=1380}"

YIP_A=10.77.0.1  YIP_B=10.77.0.2
WG_A=10.77.1.1   WG_B=10.77.1.2
OVPN_A=10.77.2.1 OVPN_B=10.77.2.2

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new
          -o ServerAliveInterval=5 -i "$SSH_KEY")

A() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_A" "$@"; }
B() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_B" "$@"; }
Aq() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_A" "$@" || true; }
Bq() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_B" "$@" || true; }
put_A() { scp -q "${SSH_OPTS[@]}" "$1" "$SSH_USER@$HOST_A:$2"; }
put_B() { scp -q "${SSH_OPTS[@]}" "$1" "$SSH_USER@$HOST_B:$2"; }

log()  { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[1;31m[%s] FATAL:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

CSV_HEADER="ts,host_pair,commit,tunnel,profile,param,metric,value,conditions"
csv_row() {
    local ts commit
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    commit="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    printf '%s,%s->%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$ts" "$HOST_A" "$HOST_B" "$commit" "$1" "$2" "$3" "$4" "$5" "$6" \
        >> "$CSV_FILE"
}
```

Write `crates/yip-bench/wan/teardown.sh` to cleanly stop `yipbench-*` services, bring down `wgbench`, flush netem, and delete interfaces.

- [ ] **Step 3: Create `provision.sh` and `run-wan-bench.sh`**

Write `crates/yip-bench/wan/provision.sh`:
- Idempotently builds release `yipd` locally if missing (`cargo build --release -p yipd`).
- Deploys `yipd` via atomic replacement to `/usr/local/bin/yipd`.
- Installs `wireguard-tools`, `openvpn`, `iperf3`, `mgen`.
- Tunes `rmem_max=16777216`, `wmem_max=16777216`, and `netdev_max_backlog=5000`.
- Sets up `yip` (`10.77.0.0/30`), `wireguard` (`10.77.1.0/30`), `openvpn` (`10.77.2.0/30`).
- Verifies 0% loss connectivity across all 3 overlays.

Write `crates/yip-bench/wan/run-wan-bench.sh`:
- Measures baseline, yip, wireguard, and openvpn.
- Drives TCP 1-stream, TCP 4-stream, UDP 200M, latency idle/loaded, CPU headroom.
- Runs netem loss sweep (0%, 1%, 3%, 5%, 10%) on Host A egress strictly targeting Host B's outer IP:
  ```bash
  tc qdisc add dev $EGRESS root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
  tc qdisc add dev $EGRESS parent 1:4 handle 40: netem loss ${1}%
  tc filter add dev $EGRESS parent 1:0 protocol ip prio 1 u32 match ip dst $HOST_B/32 flowid 1:4
  ```

- [ ] **Step 4: Create `collect.sh` with IP Scrubbing and Historical CSV Appending**

Write `crates/yip-bench/wan/collect.sh`:
- Parses raw CSV, maps `HOST_A` / `HOST_B` to `HOST_A_LABEL` / `HOST_B_LABEL`.
- Emits markdown tables to `crates/yip-bench/RESULTS-wan.md`.
- Generates `crates/yip-bench/wan/results/readme-snippet.md`.
- Appends run entries to `crates/yip-bench/wan/results/history.csv`.

- [ ] **Step 5: Verify Harness Scripts & Populate Initial Baseline**

Make all scripts executable:
```bash
chmod +x crates/yip-bench/wan/*.sh
```
Run syntax checks:
```bash
bash -n crates/yip-bench/wan/lib.sh
bash -n crates/yip-bench/wan/provision.sh
bash -n crates/yip-bench/wan/run-wan-bench.sh
bash -n crates/yip-bench/wan/collect.sh
bash -n crates/yip-bench/wan/teardown.sh
```
Test `collect.sh` against historical `crates/yip-bench/wan/results/20260715T061415Z/wan.csv` and verify `RESULTS-wan.md` is generated cleanly with scrubbed labels.

- [ ] **Step 6: Commit Core WAN Harness**

```bash
git add crates/yip-bench/wan/ crates/yip-bench/RESULTS-wan.md
git commit -m "feat(bench): reconstruct scrubbed WAN benchmark harness and reduction pipeline (#109)"
```

---

### Task 2: Ephemeral AWS EC2 Multi-Region Automation

**Files:**
- Create: `crates/yip-bench/wan/aws-up.sh`
- Create: `crates/yip-bench/wan/aws-down.sh`
- Create: `crates/yip-bench/wan/tests/test-aws-harness-args.sh`

**Interfaces:**
- Consumes: AWS CLI environment credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`).
- Produces: Ephemeral EC2 instances in Region A & Region B, temporary security groups, `wan.env`, `results/.aws-session.json`.

- [ ] **Step 1: Implement `aws-up.sh`**

Create `crates/yip-bench/wan/aws-up.sh`:
- Options: `--region-a <reg>` (default `us-east-1`), `--region-b <reg>` (default `us-west-2`), `--instance-type <type>` (default `t3.small`).
- Validates AWS CLI presence (`command -v aws`).
- Determines runner public IP via `curl -s https://checkip.amazonaws.com` (or AWS lookup).
- Resolves latest Debian 12 minimal AMI for each region:
  ```bash
  aws ec2 describe-images --region "$reg" --owners 136113030149 \
    --filters "Name=name,Values=debian-12-*-*" "Name=architecture,Values=x86_64" \
    --query "sort_by(Images, &CreationDate)[-1].ImageId" --output text
  ```
- Generates ephemeral keypair `id_ed25519_wan` via `ssh-keygen -t ed25519 -N "" -f ...`.
- Imports keypair into Region A and Region B.
- Creates Security Groups `yip-wan-sg-${RUN_ID}` in each region.
- Launches instances, waits for `instance-running`, and fetches public IPs.
- Configures SG ingress between instance IPs for UDP 51833, 51834, 51835, and TCP/UDP 5201.
- Writes `wan.env` and `results/.aws-session.json`.

- [ ] **Step 2: Implement `aws-down.sh`**

Create `crates/yip-bench/wan/aws-down.sh`:
- Reads `results/.aws-session.json`.
- Terminates both instances: `aws ec2 terminate-instances --region "$reg" --instance-ids "$inst_id"`.
- Waits for `instance-terminated`.
- Deletes security groups and keypairs.
- Removes local ephemeral private key and `results/.aws-session.json`.
- Safe idempotence: never errors if resources are already deleted.

- [ ] **Step 3: Create `test-aws-harness-args.sh` Unit Tests**

Write `crates/yip-bench/wan/tests/test-aws-harness-args.sh`:
- Validates `--help`, invalid region handling, argument parsing without making cloud calls.
- Validates `aws-down.sh` missing-state graceful handling.

- [ ] **Step 4: Verify Script Syntax and Unit Tests**

```bash
chmod +x crates/yip-bench/wan/aws-up.sh crates/yip-bench/wan/aws-down.sh crates/yip-bench/wan/tests/test-aws-harness-args.sh
bash -n crates/yip-bench/wan/aws-up.sh
bash -n crates/yip-bench/wan/aws-down.sh
bash crates/yip-bench/wan/tests/test-aws-harness-args.sh
```

- [ ] **Step 5: Commit Ephemeral AWS Automation**

```bash
git add crates/yip-bench/wan/aws-up.sh crates/yip-bench/wan/aws-down.sh crates/yip-bench/wan/tests/
git commit -m "feat(bench): add ephemeral AWS EC2 multi-region provisioning and teardown (#109)"
```

---

### Task 3: GitHub Actions Automation & CI Secret Absence Guards

**Files:**
- Create: `.github/workflows/wan-benchmark.yml`

**Interfaces:**
- Consumes: GitHub Secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `WAN_HOST_A`, `WAN_HOST_B`, `WAN_SSH_KEY`.
- Produces: Automated benchmark run, committed results on `main` with `[skip ci]`, durable artifact `wan-benchmark-report`.

- [ ] **Step 1: Write `.github/workflows/wan-benchmark.yml`**

Create `.github/workflows/wan-benchmark.yml`:
```yaml
name: WAN Benchmark
on:
  push:
    branches: [main]
    paths:
      - 'crates/yip-bench/wan/**'
      - 'bin/yipd/**'
      - 'crates/yip-transport/**'
      - 'crates/yip-wire/**'
  workflow_dispatch:
    inputs:
      mode:
        description: 'Benchmark target mode (aws or static)'
        required: true
        default: 'aws'
        type: choice
        options:
          - aws
          - static
      region_a:
        description: 'AWS Region A (for aws mode)'
        required: false
        default: 'us-east-1'
      region_b:
        description: 'AWS Region B (for aws mode)'
        required: false
        default: 'us-west-2'

permissions:
  contents: write

jobs:
  wan-benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Check infrastructure secrets availability
        id: check-secrets
        run: |
          MODE="${{ inputs.mode || 'aws' }}"
          if [ "$MODE" = "aws" ]; then
            if [ -z "${{ secrets.AWS_ACCESS_KEY_ID }}" ] || [ -z "${{ secrets.AWS_SECRET_ACCESS_KEY }}" ]; then
              echo "skip=true" >> $GITHUB_OUTPUT
              echo "::notice::WAN benchmark skipped — AWS credentials not configured in secrets"
            else
              echo "skip=false" >> $GITHUB_OUTPUT
            fi
          else
            if [ -z "${{ secrets.WAN_HOST_A }}" ] || [ -z "${{ secrets.WAN_SSH_KEY }}" ]; then
              echo "skip=true" >> $GITHUB_OUTPUT
              echo "::notice::WAN benchmark skipped — Static VPS secrets not configured"
            else
              echo "skip=false" >> $GITHUB_OUTPUT
            fi
          fi

      - uses: dtolnay/rust-toolchain@stable
        if: steps.check-secrets.outputs.skip != 'true'

      - name: Build release yipd
        if: steps.check-secrets.outputs.skip != 'true'
        run: cargo build --release -p yipd

      - name: Configure AWS credentials
        if: steps.check-secrets.outputs.skip != 'true' && (inputs.mode == 'aws' || github.event_name == 'push')
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ inputs.region_a || 'us-east-1' }}

      - name: Provision Ephemeral AWS Instances
        if: steps.check-secrets.outputs.skip != 'true' && (inputs.mode == 'aws' || github.event_name == 'push')
        run: |
          bash crates/yip-bench/wan/aws-up.sh \
            --region-a "${{ inputs.region_a || 'us-east-1' }}" \
            --region-b "${{ inputs.region_b || 'us-west-2' }}"

      - name: Configure Static VPS Environment
        if: steps.check-secrets.outputs.skip != 'true' && inputs.mode == 'static'
        run: |
          mkdir -p ~/.ssh
          echo "${{ secrets.WAN_SSH_KEY }}" > ~/.ssh/id_ed25519
          chmod 600 ~/.ssh/id_ed25519
          cat <<EOF > crates/yip-bench/wan/wan.env
          HOST_A=${{ secrets.WAN_HOST_A }}
          HOST_B=${{ secrets.WAN_HOST_B }}
          HOST_A_LABEL="${{ secrets.WAN_HOST_A_LABEL || 'VPS-A' }}"
          HOST_B_LABEL="${{ secrets.WAN_HOST_B_LABEL || 'VPS-B' }}"
          SSH_USER="${{ secrets.WAN_SSH_USER || 'root' }}"
          SSH_KEY=~/.ssh/id_ed25519
          EOF

      - name: Provision Tunnels and Overlays
        if: steps.check-secrets.outputs.skip != 'true'
        run: bash crates/yip-bench/wan/provision.sh

      - name: Run WAN Benchmark Matrix
        if: steps.check-secrets.outputs.skip != 'true'
        run: bash crates/yip-bench/wan/run-wan-bench.sh

      - name: Reduce Results & Generate Markdown
        if: steps.check-secrets.outputs.skip != 'true'
        run: bash crates/yip-bench/wan/collect.sh

      - name: Teardown Overlays
        if: always() && steps.check-secrets.outputs.skip != 'true'
        run: bash crates/yip-bench/wan/teardown.sh || true

      - name: Teardown Ephemeral AWS Instances
        if: always() && steps.check-secrets.outputs.skip != 'true' && (inputs.mode == 'aws' || github.event_name == 'push')
        run: bash crates/yip-bench/wan/aws-down.sh || true

      - name: Commit Updated Benchmark Results to main
        if: steps.check-secrets.outputs.skip != 'true'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add crates/yip-bench/RESULTS-wan.md crates/yip-bench/wan/results/
          if ! git diff --staged --quiet; then
            git commit -m "bench(wan): record automated WAN benchmark results [skip ci]"
            git push origin main
          fi

      - name: Upload WAN Benchmark Artifacts
        if: always() && steps.check-secrets.outputs.skip != 'true'
        uses: actions/upload-artifact@v4
        with:
          name: wan-benchmark-report
          path: |
            crates/yip-bench/RESULTS-wan.md
            crates/yip-bench/wan/results/
          retention-days: 30
```

- [ ] **Step 2: Validate GitHub Actions Workflow Syntax**

Run actionlint / yaml validation:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/wan-benchmark.yml'))"
```

- [ ] **Step 3: Commit Workflow**

```bash
git add .github/workflows/wan-benchmark.yml
git commit -m "ci(bench): add automated WAN benchmark workflow with secret guards and teardown (#109)"
```

---

### Task 4: Documentation Hardening & Baseline Trend Commit

**Files:**
- Modify: `crates/yip-bench/README.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `ROADMAP.md`

**Interfaces:**
- Updates documentation to remove stale RaptorQ references and embeds the reproducible WAN benchmark comparison table.

- [ ] **Step 1: Update `crates/yip-bench/README.md`**

Replace stale RaptorQ text with current GF(256) Cauchy Reed-Solomon and P+Q fast-path measurements. Add WAN benchmark section linking `RESULTS-wan.md` and reproduction instructions.

- [ ] **Step 2: Embed Snippet in Root `README.md`**

Embed `crates/yip-bench/wan/results/readme-snippet.md` into `README.md`'s comparison section.

- [ ] **Step 3: Update `CHANGELOG.md` and `ROADMAP.md`**

Document Issue #109 completion under `## [Unreleased]`.

- [ ] **Step 4: Run Full Workspace Verification**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo deny check
```

- [ ] **Step 5: Commit Documentation Updates**

```bash
git add crates/yip-bench/README.md README.md CHANGELOG.md ROADMAP.md
git commit -m "docs(bench): update WAN benchmark results, remove stale RaptorQ references (#109)"
```
