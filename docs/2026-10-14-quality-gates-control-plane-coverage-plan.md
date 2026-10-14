# Quality Gates Hardening for Control Plane & Mutation Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce the 90% test coverage floor on `bin/yipd`'s control plane in `.github/workflows/coverage.yml` with appropriate netns exclusions, widen `mutants.yml` to cover `yip-obf`, `yip-membership`, and `yip-rendezvous`, and archive mutation test reports as durable workflow artifacts.

**Architecture:** Update GitHub Actions CI configurations: `.github/workflows/coverage.yml` removes `--exclude yipd` and excludes unprivileged-untestable netns files via `--ignore-filename-regex '.*/(uring|rs_simd|tunnel|main|sharding)\.rs$'`, keeping `--fail-under-lines 90`. `.github/workflows/mutants.yml` expands package coverage to 6 core logic/control crates and captures `mutants.out/` via `actions/upload-artifact@v4`.

**Tech Stack:** GitHub Actions, cargo-llvm-cov, cargo-mutants.

## Global Constraints

- Zero wire format or application logic changes.
- Must satisfy `--fail-under-lines 90` on workspace line coverage when running `cargo llvm-cov`.
- Retain all existing container environment compatibility (`YIP_SKIP_PRIVILEGED_TESTS: "1"`).
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes, `cargo deny check` passes.

---

### Task 1: Enforce Coverage Floor on `yipd` in `.github/workflows/coverage.yml`

**Files:**
- Modify: `.github/workflows/coverage.yml:37-43`

**Interfaces:**
- Consumes: `cargo llvm-cov` CLI arguments
- Produces: Updated `Coverage` CI workflow step including `bin/yipd`

- [ ] **Step 1: Update `.github/workflows/coverage.yml`**

In `.github/workflows/coverage.yml`, update the `Coverage` step from:
```yaml
      - name: Coverage (logic crates; uring driver netns-gated)
        env:
          YIP_SKIP_PRIVILEGED_TESTS: "1"
        run: >
          cargo llvm-cov --workspace
          --exclude yip-device --exclude yipd
          --ignore-filename-regex '.*/(uring|rs_simd)\.rs$'
          --fail-under-lines 90 --summary-only
```
to:
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

- [ ] **Step 2: Run local verification command**

Run:
```bash
YIP_SKIP_PRIVILEGED_TESTS=1 cargo llvm-cov --workspace --exclude yip-device --ignore-filename-regex '.*/(uring|rs_simd|tunnel|main|sharding)\.rs$' --fail-under-lines 90 --summary-only
```
Expected: PASS with total line coverage >= 90.0% (empirical baseline is 90.96%).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/coverage.yml
git commit -m "ci(coverage): include yipd control plane with netns regex exclusions (#107)"
```

---

### Task 2: Widen Mutation Testing & Add Durable Artifact Upload in `.github/workflows/mutants.yml`

**Files:**
- Modify: `.github/workflows/mutants.yml:23-28`

**Interfaces:**
- Consumes: `cargo mutants` CLI arguments and `actions/upload-artifact@v4` action
- Produces: Updated `Mutation testing` CI workflow

- [ ] **Step 1: Update `.github/workflows/mutants.yml`**

In `.github/workflows/mutants.yml`, update the `Mutation test` step to include `yip-obf`, `yip-membership`, and `yip-rendezvous`, and add the artifact upload step:
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

- [ ] **Step 2: Validate YAML syntax & workspace formatting**

Run: `git diff .github/workflows/`
Run: `cargo test --all`
Run: `cargo clippy --all-targets -- -D warnings`
Run: `cargo fmt --check`
Run: `cargo deny check`
Expected: All clean, 0 warnings.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/mutants.yml
git commit -m "ci(mutants): widen mutation testing packages and upload artifacts (#107)"
```

---

## Plan Self-Review Checklist

1. **Spec Coverage**: Both coverage enforcement on `yipd` and mutation testing expansion + artifact upload are covered in Tasks 1 and 2.
2. **No Placeholders**: Exact YAML snippets and commands specified.
3. **Execution Readiness**: Both tasks have verified local command steps and expected outputs.
