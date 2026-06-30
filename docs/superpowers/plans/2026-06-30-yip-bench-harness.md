# Benchmark Harness (`yip-bench`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the measurement harness that validates yip's thesis — low per-operation latency, and **loss recovery / flat behavior under packet loss where plain tunnels degrade** — via in-process micro-benchmarks of the hot path plus a `tc netem` sweep comparing the yip tunnel against kernel WireGuard.

**Architecture:** Two layers. (1) **Criterion micro-benchmarks** (`benches/`) measure per-operation cost of the hot path — AEAD seal/open, RaptorQ encode/decode, wire frame/deframe, classify — in-process, no privileges, runnable in CI. (2) A **sudo-gated netns + netem harness** (a bash orchestrator + a Rust test wrapper, like M6's tunnel test) stands up the yip tunnel and a kernel-WireGuard tunnel over identical veth+netem profiles, runs `ping -c N` across each at several loss rates, parses per-packet RTTs, and emits a comparison table: yip's FEC recovers a fraction of lost packets (lower effective loss) while WireGuard passes the loss straight through.

**Tech Stack:** Rust, `criterion` (cached 0.5.1), `tc netem`, kernel WireGuard (`wg`/`wg-quick`, installed), `ping`, network namespaces.

## Global Constraints

- License MPL-2.0. The bench crate may use `criterion` as a dev-dep. No `as` casts in any committed Rust (use `try_from`/parse). The micro-benches are dev-only; they must not become a runtime dep of any shipped crate.
- Lints: workspace set, CI `--deny warnings`. Files UTF-8/LF/final-newline/no-trailing-ws.
- Commits imperative+capitalized ≤72-char subject, body ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Pre-commit hook runs fmt+clippy+test.
- **Honesty:** the netns comparison must run BOTH tunnels for real (no mock); if a contender can't be set up in an environment, the harness SKIPs that contender with a logged reason — it never fabricates numbers. The Rust wrapper SKIPs entirely when not root.

## Verified environment facts (spiked)

- `tc qdisc add ... netem` works under `sudo -n`.
- Kernel WireGuard: `wg`/`wg-quick` installed, `modprobe wireguard` succeeds. → the comparison baseline is available.
- `criterion 0.5.1` is cached in the cargo registry (no download).
- `ping -c N -W T` works (used by the M6 tunnel test); per-packet RTT lines are parseable; the summary reports loss%.
- NOT available: `iperf3` (throughput → deferred), and `n2n`/`zerotier`/`openvpn` (extra contenders → deferred). The harness must degrade gracefully (skip-with-reason) when a tool is absent.

---

### Task 1: `yip-bench` crate + hot-path Criterion micro-benchmarks

**Files:**
- Create: `crates/yip-bench/Cargo.toml`
- Create: `crates/yip-bench/src/lib.rs` (shared fixtures)
- Create: `crates/yip-bench/benches/hotpath.rs`
- Modify: root `Cargo.toml` (it already globs `crates/*`, so no member edit needed)

**Interfaces:**
- Produces a benchable harness: Criterion groups for `aead_seal`, `aead_open`, `raptorq_encode`, `raptorq_decode`, `wire_frame`, `wire_deframe`, `classify`. `src/lib.rs` exposes small fixture builders (an established `Session`, a `Codec`, a `Transport`, a sample inner packet) reused by the benches, plus a trivial unit test so the crate has hermetic coverage.

- [ ] **Step 1: Write the failing test**

`crates/yip-bench/src/lib.rs`:

```rust
//! Shared fixtures for the yip hot-path micro-benchmarks.
use yip_crypto::{generate_keypair, Handshake, Session};

/// Build an established initiator/responder session pair for sealing/opening benches.
pub fn established_pair() -> (Session, Session) {
    let rk = generate_keypair();
    let ik = generate_keypair();
    let mut ini = Handshake::initiator(&ik.private, &rk.public).expect("init");
    let mut res = Handshake::responder(&rk.private).expect("resp");
    let m1 = ini.write_message().expect("m1");
    res.read_message(&m1).expect("read m1");
    let m2 = res.write_message().expect("m2");
    ini.read_message(&m2).expect("read m2");
    (ini.into_session().expect("a"), res.into_session().expect("b"))
}

/// A representative small inner packet (an IPv4 UDP datagram, DSCP EF).
pub fn sample_inner(len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len.max(20)];
    p[0] = 0x45;
    p[1] = 46 << 2;
    p[9] = 17;
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixtures_build() {
        let (mut a, mut b) = established_pair();
        let s = a.seal(b"x").unwrap();
        assert_eq!(b.open(s.counter, &s.ciphertext).unwrap(), b"x");
        assert_eq!(sample_inner(64).len(), 64);
    }
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-bench` (after creating the Cargo.toml)
Expected: FAIL to resolve until the crate exists.

- [ ] **Step 3: Create the crate + Cargo.toml**

`crates/yip-bench/Cargo.toml`:

```toml
[package]
name = "yip-bench"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
publish = false

[dependencies]
yip-crypto = { path = "../yip-crypto" }
yip-wire = { path = "../yip-wire" }
yip-transport = { path = "../yip-transport" }

[dev-dependencies]
criterion = "0.5.1"

[[bench]]
name = "hotpath"
harness = false

[lints]
workspace = true
```

- [ ] **Step 4: Write the benches**

`crates/yip-bench/benches/hotpath.rs` — Criterion benches using the fixtures. Cover: AEAD seal + open (1300-byte payload), RaptorQ encode + decode (via `Transport::encode`/`decode` of a sealed ciphertext), wire `frame`/`deframe` (a `Codec` with fixed keys + a representative `Frame`), and `classify`. Example skeleton (the implementer fills all groups):

```rust
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use yip_bench::{established_pair, sample_inner};
use yip_transport::Transport;
use yip_wire::{Codec, Frame, WireCodec};

fn bench_aead(c: &mut Criterion) {
    let (mut a, mut b) = established_pair();
    let payload = vec![7u8; 1300];
    c.bench_function("aead_seal_1300", |bn| bn.iter(|| black_box(a.seal(black_box(&payload)).unwrap())));
    let sealed = a.seal(&payload).unwrap();
    c.bench_function("aead_open_1300", |bn| {
        bn.iter(|| {
            // re-seal each iter so the counter advances and the replay window accepts it
            let s = a.seal(&payload).unwrap();
            black_box(b.open(s.counter, &s.ciphertext).ok());
        })
    });
}

fn bench_wire(c: &mut Criterion) {
    let codec = Codec::new([1u8; 16], [2u8; 16]);
    let frame = Frame { conn_tag: 1, object_id: 0, payload_id: [0; 4], flags: 0, payload: vec![9u8; 1300] };
    c.bench_function("wire_frame_1300", |bn| bn.iter(|| black_box(codec.frame(black_box(&frame)))));
    let dg = codec.frame(&frame);
    c.bench_function("wire_deframe_1300", |bn| bn.iter(|| black_box(codec.deframe(black_box(&dg)).unwrap())));
}

fn bench_fec_and_classify(c: &mut Criterion) {
    let (mut a, _b) = established_pair();
    let inner = sample_inner(1300);
    let sealed = a.seal(&inner).unwrap();
    let mut tx = Transport::new(vec![]);
    c.bench_function("transport_encode_1300", |bn| {
        bn.iter(|| black_box(tx.encode(black_box(&sealed.ciphertext), black_box(&inner), false, 0)))
    });
    // classify alone is exercised inside encode; a dedicated classify bench can call a public
    // classify path if exposed, else this encode bench covers it.
}

criterion_group!(benches, bench_aead, bench_wire, bench_fec_and_classify);
criterion_main!(benches);
```

Notes for the implementer: the `aead_open` bench must advance the counter each iteration (the replay window rejects a repeated counter) — the skeleton does this. If a cleaner per-iteration setup exists in this Criterion version (`iter_batched`), prefer it to avoid counting the seal in the open measurement; document the choice.

- [ ] **Step 5: Run the test + a quick bench smoke**

Run: `cargo test -p yip-bench` (the fixture test passes).
Run: `cargo bench -p yip-bench -- --warm-up-time 1 --measurement-time 2 --sample-size 10` (a fast smoke run; confirm all groups produce numbers without panicking). Record a few representative ns/op figures in the commit/report.
Then `cargo clippy -p yip-bench --all-targets -- -D warnings` — clean.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-bench
git commit -m "Add yip-bench crate with hot-path micro-benchmarks

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: netem latency-and-loss harness for the yip tunnel

**Files:**
- Create: `crates/yip-bench/tests/netem_bench.rs`
- Create: `crates/yip-bench/tests/run-yip-netem.sh`

**Interfaces:**
- A sudo-gated test that runs the yip tunnel (reusing the `yipd` binary + the M6 netns pattern) across a `tc netem` loss sweep, `ping -c 100` across the tunnel at each loss rate, parses per-packet RTTs + effective loss, and prints a results table. Skips when not root.

- [ ] **Step 1: Write the harness script**

`crates/yip-bench/tests/run-yip-netem.sh` (`set -euo pipefail`, trap cleanup): takes the `yipd` binary path. Builds the M6 two-netns + veth topology (reuse the structure from `bin/yipd/tests/run-netns-tunnel.sh` — generate keys via `yipd --genkey`, start both daemons, bring up `yip0` tunnel IPs). Then for each loss rate in `0 1 3 5 10` (percent): apply `tc qdisc replace dev <veth> root netem loss <X>% delay 5ms` on BOTH veth ends, run `ip netns exec yipB ping -c 100 -i 0.05 -W 1 10.9.0.1`, capture the output, parse the summary line (`N received, M% packet loss`) and the rtt line (`min/avg/max/mdev`). Print a row: `loss%=X  yip_effective_loss=M%  rtt_avg=...  rtt_max=...`. The key signal: yip's effective ping loss should be BELOW the injected netem loss (FEC recovered some). Tear down in the trap.

- [ ] **Step 2: Write the Rust wrapper**

`crates/yip-bench/tests/netem_bench.rs`:

```rust
//! Measures the yip tunnel's ping latency + effective loss under tc netem.
//! Requires root (netns + netem + TUN); SKIPs otherwise.
use std::process::Command;

#[test]
fn yip_tunnel_under_netem_loss() {
    let is_root = Command::new("id").arg("-u").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0").unwrap_or(false);
    if !is_root {
        eprintln!("SKIP yip_tunnel_under_netem_loss: needs root");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-yip-netem.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(status.success(), "yip netem harness failed");
}
```

Note: `CARGO_BIN_EXE_yipd` is only set for tests in the `yipd` package. Since this test is in `yip-bench`, reference the binary another way — add `yipd = { path = "../../bin/yipd" }` is not valid for a bin. Instead: the script builds yipd itself (`cargo build -p yipd` then uses `target/debug/yipd`), OR the test passes the repo-root-relative path `target/debug/yipd` after ensuring it's built. The implementer picks the robust approach (simplest: the script runs `cargo build -p yipd --quiet` and uses `target/debug/yipd`).

- [ ] **Step 3: Run unprivileged (SKIPs) then under sudo (real)**

Run: `cargo test -p yip-bench --test netem_bench` → builds + SKIPs.
Run under sudo (build the test bin, `sudo -E <bin> yip_tunnel_under_netem_loss --nocapture --test-threads=1`). Confirm the sweep runs and prints the table; confirm at a nonzero netem loss the yip effective ping loss is at or below the injected loss (FEC working). If yip does NOT reduce loss at all, investigate (the realtime class's proactive repair ratio may need the ping flow to be classified Realtime and to carry repair symbols) — but do NOT fake the numbers; report what you observe. Clean up netns/qdiscs.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/tests
git commit -m "Add netem latency-and-loss harness for the yip tunnel

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: kernel-WireGuard contender + the comparison table

**Files:**
- Modify: `crates/yip-bench/tests/run-yip-netem.sh` → generalize, or
- Create: `crates/yip-bench/tests/run-compare.sh` + extend `netem_bench.rs`

**Interfaces:**
- The same netem sweep run against a kernel-WireGuard tunnel built in a parallel netns pair (`wg genkey`, `ip link add wg0 type wireguard`, `wg set`, peer endpoints over a second veth), producing a side-by-side table: at each netem loss rate, `yip_effective_loss` vs `wg_effective_loss` and `yip_rtt` vs `wg_rtt`. The headline: yip's FEC keeps effective loss below WireGuard's at the same injected loss.

- [ ] **Step 1: Add the WireGuard tunnel setup**

In a `run-compare.sh` (or extended script): if `wg` is available and `modprobe wireguard` succeeds, build a WG tunnel between two netns over a dedicated veth (standard `ip link add dev wg0 type wireguard` + `wg set wg0 private-key ... peer ... allowed-ips ... endpoint ...` + tunnel IPs). If WG is unavailable, SKIP the WG column with a logged reason (do not fail the whole harness). Apply the SAME `tc netem loss X% delay 5ms` profiles to the WG veth as to the yip veth.

- [ ] **Step 2: Run both, emit the comparison table**

For each loss in `0 1 3 5 10`: ping across the yip tunnel and across the WG tunnel (same `-c 100`), parse both, print a row: `| loss% | yip_loss% | wg_loss% | yip_rtt_avg | wg_rtt_avg |`. Save the table to `crates/yip-bench/RESULTS.md` (or print to stdout and have the test capture it).

- [ ] **Step 3: Run under sudo + verify the thesis**

Run the harness under sudo. Verify the table populates for both tunnels and that yip's effective loss is ≤ WireGuard's at nonzero injected loss (the FEC advantage). Record the actual observed table in the report. If the WG tunnel can't be established here, SKIP the WG column with the reason and note yip's standalone numbers — do not fabricate the WG side.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/tests
git commit -m "Compare yip vs kernel WireGuard under netem loss

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: results doc + CI wiring

**Files:**
- Create: `crates/yip-bench/RESULTS.md`
- Modify: `.github/workflows/integration.yml`, `CHANGELOG.md`, `README.md`

**Interfaces:**
- A committed `RESULTS.md` summarizing the micro-bench figures + the netem comparison table (from a real run); a CI job that runs the micro-benches (a fast `cargo bench` smoke to catch regressions/compile breaks) hermetically, plus the sudo-gated netem comparison under the existing integration honesty-guard pattern.

- [ ] **Step 1: Write `RESULTS.md`**

Capture the actual numbers from Tasks 1–3: a table of hot-path ns/op (AEAD, RaptorQ, wire, classify) and the yip-vs-WireGuard netem loss/RTT table. Clearly label the environment (kernel, CPU) and note deferred items (iperf3 throughput; n2n/ZeroTier/OpenVPN contenders).

- [ ] **Step 2: CI — micro-benches smoke (hermetic) + sudo netem job**

In `.github/workflows/integration.yml` (or a new `bench.yml`): a hermetic job running `cargo bench -p yip-bench -- --warm-up-time 1 --measurement-time 1 --sample-size 10` (fast — proves the benches compile and run, not a perf gate). And a sudo-gated job running the `netem_bench` test binary under `sudo -E ... --test-threads=1` with the honesty guard (install `wireguard-tools` + load the module on the runner if needed; if the runner can't, the WG column SKIPs with a reason but the yip side still runs).

- [ ] **Step 3: Changelog + README**

`CHANGELOG.md` under `### Added`:

```markdown
- `yip-bench`: hot-path micro-benchmarks and a `tc netem` latency/loss harness
  comparing the yip tunnel against kernel WireGuard.
```

In `README.md`, change the roadmap's `Next` line to mark the benchmark harness done and point to `crates/yip-bench/RESULTS.md`.

- [ ] **Step 4: Full gate + commit**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo shear && cargo deny check`
Expected: all clean (the criterion dev-dep adds tree entries — confirm `cargo deny` licenses still pass; add any new license to `deny.toml`'s allow-list with a comment if needed).

```bash
git add crates/yip-bench/RESULTS.md .github/workflows/integration.yml CHANGELOG.md README.md
git commit -m "Record benchmark results and wire benches into CI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Scope coverage:** hot-path per-op latency via Criterion ✓ (T1); yip tunnel latency + effective-loss under netem ✓ (T2); the headline yip-vs-WireGuard loss-recovery comparison ✓ (T3); committed results + CI ✓ (T4). **Deferred-by-design (noted in RESULTS.md):** iperf3 throughput (iperf3 absent); the L2 contenders n2n/ZeroTier and OpenVPN (not installed); and the TCP-under-loss latency-spike comparison (needs iperf3/a TCP load) — these are follow-ons once the tools are present.

**Honesty guardrails:** the netns harness runs both tunnels for real; a missing contender (WG, or others) SKIPs with a logged reason and never fabricates numbers; the Rust wrappers SKIP entirely when not root, and CI's honesty guard fails on an unexpected skip — consistent with the M4/M6 conventions.

**Placeholder scan:** the bench skeletons are concrete; the implementer fills all Criterion groups and the WG setup. The `CARGO_BIN_EXE_yipd` cross-package caveat is called out with the build-yipd-in-script resolution.

**Definition of done:** `cargo test --workspace` green (bench fixture test + sudo-gated harness skips cleanly unprivileged); `cargo bench -p yip-bench` produces hot-path numbers; under sudo the netem harness runs the yip tunnel (and WireGuard where available) and emits a comparison table showing yip's FEC reducing effective loss; `RESULTS.md` records real figures; whole-workspace fmt/clippy/shear/deny green; CI passes.

---

### Task 5: scp (TCP) throughput comparison under netem loss

**Files:**
- Create: `crates/yip-bench/tests/run-scp-compare.sh`
- Modify: `crates/yip-bench/tests/netem_bench.rs` (add `scp_throughput_comparison` test), `crates/yip-bench/README.md`, `.github/workflows/integration.yml`

**Why:** The latency/loss sweep uses ICMP (no retransmit). A TCP file copy (scp) shows the *throughput* thesis: under loss WireGuard's TCP collapses (retransmits + congestion backoff) while yip's FEC hides the loss from TCP, so throughput holds. This is the bulk/L2 case the design targets.

**Verified scp-in-netns mechanics (spiked, works under sudo):**
```sh
ssh-keygen -t ed25519 -f host -N '' -q
ssh-keygen -t ed25519 -f client -N '' -q ; cat client.pub > authkeys ; chmod 600 authkeys host
# sshd in the RECEIVER netns, bound on the tunnel IP, key-only, no PAM:
ip netns exec <recv_ns> /usr/sbin/sshd -p 2222 -h host \
  -o PidFile=sshd.pid -o AuthorizedKeysFile=authkeys -o UsePAM=no \
  -o PasswordAuthentication=no -o StrictModes=no -o PermitRootLogin=yes -E sshd.log
# scp from the SENDER netns over the TUNNEL IP, timed, non-interactive:
ip netns exec <send_ns> scp -q -P 2222 -i client \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  payload root@<recv_tunnel_ip>:/tmp/payload.copy
```
50MB over loopback measured ~155 MB/s with integrity OK.

**Interfaces:** a sudo-gated `scp_throughput_comparison` test (SKIPs unless root) shelling out to `run-scp-compare.sh`, which:
- Reuses the yip + WireGuard two-netns topology from `run-compare.sh`.
- Uses a modest payload (e.g. `dd if=/dev/zero ... bs=1M count=20` = 20 MB) so transfers stay bounded; wrap each scp in `timeout 120` and treat a timeout/failure as "throughput ≈ 0 (collapsed)" rather than failing the whole harness.
- For each loss in `0 5 10` %: apply `tc netem loss X% delay 5ms` to both tunnels' veths, run sshd in each receiver netns (yip recv = the netns holding tunnel IP 10.9.0.1; wg recv = the netns holding 10.99.0.1), scp the payload over each tunnel, time it, compute MB/s.
- Emit `| loss% | yip_MBps | wg_MBps |` to stdout and append to the curated `crates/yip-bench/README.md` (a new "## scp throughput" section) — and verify integrity (`cmp`) on at least the 0% transfers.
- `set -euo pipefail`, trap cleanup killing ALL sshd + daemons and deleting ALL netns. If `scp`/`sshd` absent, SKIP with a reason.

- [ ] **Step 1:** Write `run-scp-compare.sh` (base it on `run-compare.sh` for the topology) + the `scp_throughput_comparison` test in `netem_bench.rs` (mirror the existing root-gated tests).
- [ ] **Step 2:** Run unprivileged → SKIPs+passes. Run under sudo for real → produces the throughput table. CONFIRM the thesis direction: at 0% yip and WG are comparable (yip maybe lower from FEC overhead); at 5-10% yip throughput >> WG (WG collapses). Capture the REAL table; if the direction doesn't hold, report what you observe — do NOT fake it. Verify no leaked netns/sshd processes (`pgrep sshd`, `ip netns list` clean after).
- [ ] **Step 3:** Add the throughput table + interpretation to `crates/yip-bench/README.md` (honest: note payload size, timeout, that scp adds SSH crypto on top of both tunnels equally). Add a CI step running the scp test under sudo (honesty guard). `cargo clippy`/`fmt` clean.
- [ ] **Step 4:** Commit `Add scp throughput comparison to the netem harness` (body ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`).
