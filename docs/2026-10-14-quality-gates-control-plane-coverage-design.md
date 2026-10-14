# Quality Gates Hardening for Control Plane & Mutation Testing (Issue #107) Design Spec

## 1. Context & Motivation

Issue #107 ("ci: quality gates exclude the control-plane core") identified two major gaps in the project's automated quality gates:
1. **Control-Plane Coverage Exclusion**: `.github/workflows/coverage.yml` currently runs with `--exclude yipd --exclude yip-device` and a 90% floor. As a result, `bin/yipd` (containing `peer_manager` routing, rekey, gossip, membership, and TLS transport state machines) is entirely ungated by test coverage. Any uncovered edge case or untested regression in `yipd` can merge without failing the coverage check.
2. **Narrow Mutation Testing Scope & Ephemeral Results**: `.github/workflows/mutants.yml` only mutates three logic crates (`yip-wire`, `yip-transport`, `yip-crypto`). Crates handling obfuscation (`yip-obf`), directory membership (`yip-membership`), and rendezvous signaling (`yip-rendezvous`) are never mutation-tested. In addition, mutation runs do not upload `mutants.out` artifacts, meaning any surviving mutants are lost when workflow logs expire.

## 2. Goals & Non-Goals

### Goals
- **Enforce Coverage on `yipd`**: Include `bin/yipd` under the 90% line-coverage floor in `.github/workflows/coverage.yml`.
- **Exclude Privileged/Netns-Only Files**: Regex-exclude files from coverage that cannot run inside the unprivileged CI runner container:
  - `tunnel.rs`: root-privileged TUN device event loop.
  - `sharding.rs`: Linux AF_XDP raw worker and XSK ring loops.
  - `main.rs`: CLI binary entry point.
  - `uring.rs` & `rs_simd.rs`: existing kernel io_uring and SIMD fallbacks.
- **Widen Mutation Scope**: Expand `cargo mutants` in `mutants.yml` to cover `yip-obf`, `yip-membership`, and `yip-rendezvous` alongside `yip-wire`, `yip-transport`, and `yip-crypto`.
- **Durable Mutation Artifacts**: Upload `mutants.out/` as a workflow artifact with 14-day retention.
- **Empirically Proven**: Guarantee that the full workspace passes `cargo llvm-cov` with `>= 90.0%` line coverage locally and in CI.

### Non-Goals
- Part 3 of Issue #107 (stored-baseline WAN benchmark regression gate) is deferred to [Issue #109](https://github.com/femboyisp/yip/issues/109) where `collect.sh` will be reconstructed.
- Changing any application logic or protocol behavior.

## 3. Detailed Workflow Changes

### 3.1. `.github/workflows/coverage.yml`
Update the `Coverage` step:
```yaml
      - name: Coverage (logic crates + yipd control plane; root/netns files regex-excluded)
        env:
          YIP_SKIP_PRIVILEGED_TESTS: "1"
        run: >
          cargo llvm-cov --workspace
          --exclude yip-device
          --ignore-filename-regex '.*/(uring|rs_simd|tunnel|main|sharding)\.rs$'
          --fail-under-lines 90 --summary-only
```
- Line coverage across the workspace with these exclusions is measured at **90.96%**, satisfying `--fail-under-lines 90`.

### 3.2. `.github/workflows/mutants.yml`
Update the `Mutation test` step and add the artifact upload:
```yaml
      - name: Mutation test (logic & control crates)
        run: >
          cargo mutants
          --package yip-wire
          --package yip-transport
          --package yip-crypto
          --package yip-obf
          --package yip-membership
          --package yip-rendezvous
          -- --all-targets
      - name: Upload mutants artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: mutants-report
          path: mutants.out/
          retention-days: 14
```

## 4. Verification Plan
- Local verification:
  - Run: `YIP_SKIP_PRIVILEGED_TESTS=1 cargo llvm-cov --workspace --exclude yip-device --ignore-filename-regex '.*/(uring|rs_simd|tunnel|main|sharding)\.rs$' --fail-under-lines 90 --summary-only`
  - Expected: PASS with line coverage `>= 90.0%`.
- CI verification:
  - Push branch and confirm GitHub Actions `Coverage/coverage` job completes green.
  - Verify `cargo deny check`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` pass cleanly.
