# Multi-Engine DPI Verification Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a comprehensive 4-engine DPI verification panel (nDPI, tshark, Suricata, Zeek) that evaluates PCAP captures across all 4 `yip` transport modes (`raw/obf`, `quic`, `tls`, `relay`), generates a unified verdict matrix, and enforces anti-DPI gates in CI.

**Architecture:** A unified shell script [`bin/yipd/tests/run-multi-dpi-oracle.sh`](file:///home/zoa/projects/femboy/yip/bin/yipd/tests/run-multi-dpi-oracle.sh) provides both offline multi-engine PCAP evaluation and live netns traffic capture across the 4 transport modes. The script analyzes flow protocols, protocol hierarchies, IDS alerts, and connection logs to enforce zero VPN leaks and accurate protocol mimicry, emitting a markdown verdict table and exiting non-zero on any violation. CI is updated to install tshark, Suricata, and Zeek, execute the harness, and upload forensic PCAPs/logs.

**Tech Stack:** Bash (`set -euo pipefail`), `tcpdump`, `iproute2`, `tshark` (Wireshark CLI), `suricata`, `zeek`, `ndpiReader` (nDPI), GitHub Actions.

## Global Constraints

- Zero wire format or protocol changes across all client, server, and relay modes.
- Strictly `#![forbid(unsafe_code)]` preserved across all workspace crates.
- Clean execution in both offline PCAP mode and live netns capture mode.
- Non-root executions must cleanly SKIP netns capture when permissions are missing.
- When run in CI, all 4 engines must be present and executed without skipping.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes, `cargo deny check` passes.

---

### Task 1: Multi-Engine Analyzer Logic & Parser Gating in `bin/yipd/tests/run-multi-dpi-oracle.sh`

**Files:**
- Create: `bin/yipd/tests/run-multi-dpi-oracle.sh`
- Create: `bin/yipd/tests/test-multi-dpi-oracle-parsers.sh`

**Interfaces:**
- CLI Interface: `run-multi-dpi-oracle.sh [--pcap-dir <dir> | <yipd-binary> <ndpiReader-binary> [out-dir]]`
- Engine Evaluators:
  - `eval_ndpi <transport> <pcap> <out_dir>`: runs `ndpiReader -i <pcap> -v 2`, checks for expected protocol and absence of `NDPI_OBFUSCATED_TRAFFIC` or VPN categories.
  - `eval_tshark <transport> <pcap> <out_dir>`: runs `tshark -r <pcap> -q -z io,phs` and field extractions, asserts expected protocol hierarchy and absence of VPN dissectors.
  - `eval_suricata <transport> <pcap> <out_dir>`: runs `suricata -r <pcap> -l <out_dir> -k none --runmode single`, parses `eve.json` for 0 alerts and expected `app_proto`.
  - `eval_zeek <transport> <pcap> <out_dir>`: runs `zeek -C -r <pcap> local`, verifies 0 notices in `notice.log` and expected service in `conn.log` / `ssl.log`.
  - `format_verdict_table`: emits ASCII and Markdown tables with the 16 evaluation cells.

- [ ] **Step 1: Write parser unit tests with fixture PCAPs**
  Create `bin/yipd/tests/test-multi-dpi-oracle-parsers.sh` verifying that:
  - Evaluation functions cleanly identify installed vs missing tools.
  - Output parsers correctly report PASS on compliant captures and FAIL when a violation is present (e.g. an injected VPN alert in eve.json or unexpected protocol in tshark).

- [ ] **Step 2: Implement core analyzer logic in `run-multi-dpi-oracle.sh`**
  - Implement engine detection (`check_tool`).
  - Implement `eval_ndpi`, `eval_tshark`, `eval_suricata`, `eval_zeek`.
  - Implement verdict recording and markdown summary table generation.
  - Implement exit code handling (exit 0 if all cells pass or skip-when-tool-missing outside CI; exit 1 if any cell fails).

- [ ] **Step 3: Run parser tests and verify**
  Run: `bash bin/yipd/tests/test-multi-dpi-oracle-parsers.sh`
  Confirm all assertions pass cleanly.

- [ ] **Step 4: Commit**
  `git add bin/yipd/tests/run-multi-dpi-oracle.sh bin/yipd/tests/test-multi-dpi-oracle-parsers.sh`
  `git commit -m "feat(dpi): implement multi-engine offline evaluation logic and verdict table (#70)"`

---

### Task 2: Live Netns Capture Pipeline for the 4 Transports in `run-multi-dpi-oracle.sh`

**Files:**
- Modify: `bin/yipd/tests/run-multi-dpi-oracle.sh`

**Interfaces:**
- Consumes: `eval_ndpi`, `eval_tshark`, `eval_suricata`, `eval_zeek` from Task 1.
- Produces: Live netns capture routines for:
  - `capture_raw_obf <yipd-bin> <pcap_out>`: Spawns netns veth pair, launches two `yipd` instances with `transport=direct` + `obf_psk`, drives bidirectional ping, captures trace with `tcpdump`.
  - `capture_quic <yipd-bin> <pcap_out>`: Spawns netns veth pair, launches two `yipd` instances with `transport=quic` (ALPN `h3`), drives bidirectional ping, captures trace.
  - `capture_tls <yipd-bin> <pcap_out>`: Spawns netns veth pair, launches two `yipd` instances with `transport=tls` (BoringSSL REALITY mimicry), drives bidirectional ping, captures trace.
  - `capture_relay <yipd-bin> <pcap_out>`: Spawns rendezvous server and client peers, drives traffic through authenticated TLS Trojan front, captures trace.

- [ ] **Step 1: Implement netns topology & capture routines**
  Add netns orchestration to `bin/yipd/tests/run-multi-dpi-oracle.sh`:
  - Check for root/`CAP_NET_ADMIN` (skip capture if non-root, unless `--pcap-dir` is provided).
  - Add cleanup trap guaranteeing namespace, interface, and background process teardown.
  - Drive real traffic bursts for all 4 transports and capture `raw-obf.pcap`, `quic.pcap`, `tls.pcap`, `relay.pcap`.

- [ ] **Step 2: Connect capture pipeline to the 4-engine evaluation loop**
  When invoked with `<yipd-binary>` and `<ndpiReader-binary>`, automatically capture all 4 traces, store them in the output artifact directory, and run the 4-engine evaluation panel against each trace.

- [ ] **Step 3: Test locally**
  Run: `sudo bash bin/yipd/tests/run-multi-dpi-oracle.sh ./target/release/yipd ./refrences/nDPI/example/ndpiReader /tmp/multi-dpi-test`
  Verify that available engines (e.g. tshark, nDPI) run and report PASS, and unavailable engines cleanly report SKIP.

- [ ] **Step 4: Commit**
  `git add bin/yipd/tests/run-multi-dpi-oracle.sh`
  `git commit -m "feat(dpi): add netns live capture pipeline for 4 transport modes (#70)"`

---

### Task 3: CI Workflow Integration, Toolchain Pinning & Full Verification

**Files:**
- Modify: `.github/workflows/integration.yml`

**Interfaces:**
- Installs: `tshark`, `suricata`, and pinned LTS `zeek`.
- Invokes: `bin/yipd/tests/run-multi-dpi-oracle.sh` in the `dpi-undetectability` job.
- Uploads: Artifact package `multi-engine-dpi-report` with PCAPs, engine logs, and `verdict-summary.md`.

- [ ] **Step 1: Update `.github/workflows/integration.yml`**
  - Add installation step for `tshark` (`DEBIAN_FRONTEND=noninteractive`), `suricata`, and official `zeek` LTS packages from openSUSE OBS.
  - Add `/opt/zeek/bin` to `PATH`.
  - Update `dpi-undetectability` job to invoke `run-multi-dpi-oracle.sh`.
  - Add honesty guard checking that no engine was skipped in CI.
  - Add `actions/upload-artifact@v4` step uploading `/tmp/multi-dpi-artifacts` with retention 14 days.

- [ ] **Step 2: Workspace Verification**
  Run full workspace validation:
  - `cargo test --all`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo fmt --check`
  - `cargo deny check`

- [ ] **Step 3: Commit**
  `git add .github/workflows/integration.yml`
  `git commit -m "ci(dpi): add tshark, Suricata, and Zeek to DPI verification job (#70)"`
