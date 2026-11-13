# Phase 1: Verification, Invariants, and Hotpath Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Phase 1 verification architecture: eliminate dataplane hotpath stderr stalls via atomic counters (Issue #211), build `crates/yip-verify` with scoped thread-local allocation and syscall tracking, establish a DHAT zero-allocation PR gate, wire `yip-wire` fuzzing into CI via Bolero, and widen coverage and mutation testing with diff-scoped PR gating (Issue #107).

**Architecture:** Ingress and tick error paths in `bin/yipd/src/dataplane.rs` replace synchronous `eprintln!` calls with lock-free atomic counters and enforce `#![deny(clippy::print_stderr, clippy::print_stdout)]`. A new workspace crate `crates/yip-verify` provides `TrackingAllocator` with thread-local gates and `assert_no_alloc!`, `assert_no_blocking_io!`, and `assert_bounded_ops!` assertion macros. A DHAT test suite in `crates/yip-bench` enforces zero allocations on the hotpath during PR CI. `crates/yip-wire` introduces Bolero property tests wired directly into `cargo test`, and `.github/workflows/` and `.cargo/mutants.toml` are expanded to cover `yipd`, `yip-obf`, `yip-membership`, and `yip-rendezvous` with diff-scoped gating.

**Tech Stack:** Rust 2021 edition, `dhat = "0.3.3"`, `bolero = "0.12"`, `libc = "0.2"`, `cargo-mutants`, `cargo-llvm-cov`.

## Global Constraints

- Strictly ZERO emojis in any commit message, code comment, test description, or documentation.
- Maintain `#![forbid(unsafe_code)]` across all crates except `crates/yip-io`.
- No dynamic heap allocations on the packet processing hotpath.
- Deny `clippy::print_stderr` and `clippy::print_stdout` in `dataplane.rs` and core data-plane crates.
- All code changes must pass `cargo fmt -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `cargo deny check`.
- Never push directly to `main`; all changes must be submitted via feature branches and pull requests.

---

### Task 1: Replace Synchronous eprintln! with Atomic Counters in Dataplane (Issue #211)

**Files:**
- Modify: `bin/yipd/src/dataplane.rs:1-850`
- Modify: `bin/yipd/src/main.rs:1-100`
- Test: `bin/yipd/tests/dataplane_counters_test.rs`

**Interfaces:**
- Consumes: Dataplane event loop in `bin/yipd/src/dataplane.rs`.
- Produces: `DataPlaneCounters` struct with lock-free `AtomicU64` metrics; `#![deny(clippy::print_stderr, clippy::print_stdout)]` static gate on `dataplane.rs`.

- [ ] **Step 1: Write unit test asserting atomic counters increment on malformed ingress datagrams**

```rust
// bin/yipd/tests/dataplane_counters_test.rs
use std::sync::atomic::Ordering;
use yip_crypto::Session;
use yipd::dataplane::{DataPlane, DataPlaneCounters};

#[test]
fn test_dataplane_counters_increment_on_malformed_packets() {
    let counters = DataPlaneCounters::default();
    assert_eq!(counters.ingress_deframe_errors.load(Ordering::Relaxed), 0);
    assert_eq!(counters.ingress_open_errors.load(Ordering::Relaxed), 0);

    // Simulate error recording
    counters.ingress_deframe_errors.fetch_add(1, Ordering::Relaxed);
    counters.ingress_open_errors.fetch_add(2, Ordering::Relaxed);

    assert_eq!(counters.ingress_deframe_errors.load(Ordering::Relaxed), 1);
    assert_eq!(counters.ingress_open_errors.load(Ordering::Relaxed), 2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test dataplane_counters_test`
Expected: FAIL with `unresolved import yipd::dataplane::DataPlaneCounters`.

- [ ] **Step 3: Implement DataPlaneCounters and replace all eprintln! in dataplane.rs**

In `bin/yipd/src/dataplane.rs`:
Add at top:
```rust
#![deny(clippy::print_stderr, clippy::print_stdout)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Lock-free atomic counters for data-plane ingress and egress error conditions.
#[derive(Debug, Default)]
pub struct DataPlaneCounters {
    pub ingress_deframe_errors: AtomicU64,
    pub ingress_frame_to_symbol_errors: AtomicU64,
    pub ingress_open_errors: AtomicU64,
    pub ingress_control_short_errors: AtomicU64,
    pub ingress_control_malformed_errors: AtomicU64,
    pub ingress_seal_errors: AtomicU64,
    pub tick_seal_errors: AtomicU64,
}
```

Add `pub counters: Arc<DataPlaneCounters>` to `DataPlane` struct and initialize it in `DataPlane::new`.
Replace lines 465, 474, 499, 528, 540, 556, 702, 754, 759, 778, 820 in `dataplane.rs` with atomic increments:
- `self.counters.ingress_deframe_errors.fetch_add(1, Ordering::Relaxed);`
- `self.counters.ingress_frame_to_symbol_errors.fetch_add(1, Ordering::Relaxed);`
- `self.counters.ingress_open_errors.fetch_add(1, Ordering::Relaxed);`
- `self.counters.ingress_control_short_errors.fetch_add(1, Ordering::Relaxed);`
- `self.counters.ingress_control_malformed_errors.fetch_add(1, Ordering::Relaxed);`
- `self.counters.ingress_seal_errors.fetch_add(1, Ordering::Relaxed);`
- `self.counters.tick_seal_errors.fetch_add(1, Ordering::Relaxed);`

- [ ] **Step 4: Run clippy and tests to verify they pass**

Run: `cargo clippy -p yipd --all-targets -- -D warnings`
Run: `cargo test --test dataplane_counters_test`
Expected: PASS with 0 warnings and tests passing.

- [ ] **Step 5: Commit changes**

```bash
git add bin/yipd/src/dataplane.rs bin/yipd/tests/dataplane_counters_test.rs
git commit -m "perf(dataplane): replace synchronous eprintln logging with atomic counters (#211)"
```

---

### Task 2: Implement crates/yip-verify Invariant Assertion Engine

**Files:**
- Create: `crates/yip-verify/Cargo.toml`
- Create: `crates/yip-verify/src/lib.rs`
- Create: `crates/yip-verify/src/alloc.rs`
- Create: `crates/yip-verify/src/syscall.rs`
- Create: `crates/yip-verify/src/steps.rs`
- Modify: `Cargo.toml:1-100`
- Test: `crates/yip-verify/tests/invariant_harness_tests.rs`

**Interfaces:**
- Consumes: `libc` for Linux `getrusage(RUSAGE_THREAD)`.
- Produces: `TrackingAllocator`, `assert_no_alloc!`, `assert_no_blocking_io!`, `assert_bounded_ops!`.

- [ ] **Step 1: Write unit tests for yip-verify invariant macros**

```rust
// crates/yip-verify/tests/invariant_harness_tests.rs
use std::alloc::System;
use yip_verify::{assert_bounded_ops, assert_no_alloc, assert_no_blocking_io, TrackingAllocator};

#[global_allocator]
static GLOBAL: TrackingAllocator<System> = TrackingAllocator(System);

#[test]
fn test_assert_no_alloc_passes_on_stack_operations() {
    assert_no_alloc!({
        let mut arr = [0u8; 1024];
        arr[0] = 42;
        assert_eq!(arr[0], 42);
    });
}

#[test]
#[should_panic(expected = "heap allocations")]
fn test_assert_no_alloc_panics_on_vector_allocation() {
    assert_no_alloc!({
        let v = vec![1u8, 2, 3, 4];
        assert_eq!(v.len(), 4);
    });
}

#[test]
fn test_assert_bounded_ops_tracks_steps() {
    assert_bounded_ops!(max_steps = 10, {
        for _ in 0..5 {
            yip_verify::record_algorithmic_step();
        }
    });
}

#[test]
#[should_panic(expected = "exceeded bound")]
fn test_assert_bounded_ops_panics_when_exceeded() {
    assert_bounded_ops!(max_steps = 3, {
        for _ in 0..5 {
            yip_verify::record_algorithmic_step();
        }
    });
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-verify`
Expected: FAIL with missing package `yip-verify`.

- [ ] **Step 3: Implement crates/yip-verify modules and register in root Cargo.toml**

In `crates/yip-verify/Cargo.toml`:
```toml
[package]
name = "yip-verify"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
publish = false

[dependencies]
libc = "0.2"

[lints]
workspace = true
```

Add `yip-verify = { version = "0.1.0", path = "crates/yip-verify" }` to `[workspace.dependencies]` in root `Cargo.toml`.

In `crates/yip-verify/src/alloc.rs`:
Implement `TrackingAllocator<A>` with thread-local gates (`TRACKING_ENABLED`), reentrancy protection, `realloc` interception, and `AllocationScopeGuard` as specified in Section 4.1 of the design document.

In `crates/yip-verify/src/syscall.rs`:
Implement `get_thread_rusage()` wrapping `libc::getrusage(libc::RUSAGE_THREAD, &mut usage)` and `assert_no_blocking_io!`.

In `crates/yip-verify/src/steps.rs`:
Implement `OPERATION_STEPS` thread-local step counter, `record_algorithmic_step()`, `reset_step_counter()`, `get_step_counter()`, and `assert_bounded_ops!`.

In `crates/yip-verify/src/lib.rs`:
Export all modules, types, and macros.

- [ ] **Step 4: Run cargo test to verify invariant harness passes**

Run: `cargo test -p yip-verify`
Expected: PASS (including both normal and `should_panic` tests).

- [ ] **Step 5: Commit changes**

```bash
git add Cargo.toml crates/yip-verify/
git commit -m "feat(verify): introduce crates/yip-verify zero-allocation and bounded-ops invariant harness"
```

---

### Task 3: Deterministic Zero-Allocation PR Gate via DHAT

**Files:**
- Modify: `crates/yip-bench/Cargo.toml`
- Create: `crates/yip-bench/tests/zero_alloc_hotpath.rs`
- Modify: `.github/workflows/ci.yml:60-90`
- Modify: `.forgejo/workflows/ci.yml:60-90`

**Interfaces:**
- Consumes: `Codec` from `crates/yip-wire`, `Transport` from `crates/yip-transport`, `Session` from `crates/yip-crypto`.
- Produces: `zero_alloc_hotpath` test asserting `dhat::assert_eq!(stats.total_blocks, 0)` and `dhat::assert_eq!(stats.total_bytes, 0)`.

- [ ] **Step 1: Write DHAT zero-allocation test in yip-bench**

```rust
// crates/yip-bench/tests/zero_alloc_hotpath.rs
use dhat::DhatAlloc;
use yip_bench::established_pair;
use yip_wire::{Codec, Frame, WireCodec};

#[global_allocator]
static ALLOC: DhatAlloc = DhatAlloc;

#[test]
fn test_zero_alloc_hotpath_framing() {
    let _profiler = dhat::Profiler::builder().testing().build();

    let codec = Codec::new([1u8; 16], [2u8; 16]);
    let frame = Frame {
        conn_tag: 1,
        object_id: 0,
        payload_id: [0; 4],
        flags: 0,
        payload: vec![9u8; 1200],
    };
    let datagram = codec.frame(&frame);

    // Enter zero-allocation evaluated region
    let _stats_before = dhat::get_stats().unwrap();

    let deframed = codec.deframe(&datagram).expect("valid frame deframes");
    assert_eq!(deframed.conn_tag, 1);

    let stats_after = dhat::get_stats().unwrap();
    // Verify no blocks or bytes were allocated inside the deframing hotpath
    assert_eq!(
        stats_after.total_blocks - _stats_before.total_blocks,
        0,
        "Heap allocations detected on deframing hotpath"
    );
}
```

- [ ] **Step 2: Add dhat dependency to crates/yip-bench/Cargo.toml**

```toml
[dev-dependencies]
dhat = "0.3.3"
```

- [ ] **Step 3: Run test locally to verify zero allocations**

Run: `cargo test -p yip-bench --test zero_alloc_hotpath`
Expected: PASS with 0 allocations detected.

- [ ] **Step 4: Add DHAT check to ci.yml and .forgejo/workflows/ci.yml**

In `.github/workflows/ci.yml` and `.forgejo/workflows/ci.yml` under the `build-test` job:
Add:
```yaml
      - name: DHAT zero-allocation hotpath gate
        run: cargo test -p yip-bench --test zero_alloc_hotpath
```

- [ ] **Step 5: Commit changes**

```bash
git add crates/yip-bench/Cargo.toml crates/yip-bench/tests/zero_alloc_hotpath.rs .github/workflows/ci.yml .forgejo/workflows/ci.yml
git commit -m "ci(bench): add DHAT zero-allocation hotpath test and PR gate"
```

---

### Task 4: Bolero-Unified Wire Deframe Fuzzing & Property Test

**Files:**
- Modify: `crates/yip-wire/Cargo.toml`
- Create: `crates/yip-wire/tests/bolero_deframe.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `.forgejo/workflows/ci.yml`

**Interfaces:**
- Consumes: `Codec::deframe` and `Codec::frame` from `crates/yip-wire`.
- Produces: Unified Bolero property test running on arbitrary byte inputs.

- [ ] **Step 1: Write Bolero fuzzing & property test in yip-wire**

```rust
// crates/yip-wire/tests/bolero_deframe.rs
use bolero::check;
use yip_wire::{Codec, WireCodec};

#[test]
fn bolero_deframe_never_panics_and_roundtrips() {
    check!().with_type::<Vec<u8>>().for_each(|data| {
        let codec = Codec::new([0x11; 16], [0x22; 16]);
        if let Ok(frame) = codec.deframe(data) {
            let reframed = codec.frame(&frame);
            let again = codec.deframe(&reframed).expect("re-framed frame must deframe cleanly");
            assert_eq!(frame, again);
        }
    });
}
```

- [ ] **Step 2: Add bolero dev-dependency to crates/yip-wire/Cargo.toml**

```toml
[dev-dependencies]
bolero = "0.12"
```

- [ ] **Step 3: Run Bolero property test in test mode**

Run: `cargo test -p yip-wire --test bolero_deframe`
Expected: PASS with 1,000+ iterations executed without panics.

- [ ] **Step 4: Commit changes**

```bash
git add crates/yip-wire/Cargo.toml crates/yip-wire/tests/bolero_deframe.rs
git commit -m "test(wire): add Bolero property and deframe fuzzing harness"
```

---

### Task 5: Coverage & Mutation Testing Expansion with Diff-Scoped PR Gating (Issue #107)

**Files:**
- Modify: `.cargo/mutants.toml`
- Modify: `.github/workflows/coverage.yml`
- Modify: `.forgejo/workflows/coverage.yml`
- Modify: `.github/workflows/mutants.yml`
- Modify: `.forgejo/workflows/mutants.yml`

**Interfaces:**
- Consumes: `cargo-mutants`, `cargo-llvm-cov`.
- Produces: Coverage across `yipd`, `yip-obf`, `yip-membership`, and `yip-rendezvous`; diff-scoped PR mutation gate.

- [ ] **Step 1: Update coverage.yml to include yipd and remaining crates**

In `.github/workflows/coverage.yml` and `.forgejo/workflows/coverage.yml`:
Update the run command from:
`--exclude yip-device`
To:
`--package yip-wire --package yip-transport --package yip-crypto --package yip-obf --package yip-membership --package yip-rendezvous --package yipd`

- [ ] **Step 2: Update .cargo/mutants.toml to include yipd packages and exclude equivalent mutants**

Add `package = ["yip-wire", "yip-transport", "yip-crypto", "yip-obf", "yip-membership", "yip-rendezvous", "yipd"]` to `.cargo/mutants.toml`.

- [ ] **Step 3: Add diff-scoped pull_request trigger and step to mutants.yml**

In `.github/workflows/mutants.yml` and `.forgejo/workflows/mutants.yml`:
Add `pull_request:` trigger:
```yaml
on:
  pull_request:
    paths:
      - 'crates/**'
      - 'bin/**'
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:
```
Add conditional step for pull requests:
```yaml
      - name: Diff-scoped mutation test on PR
        if: github.event_name == 'pull_request'
        run: |
          git fetch origin ${{ github.base_ref }}
          git diff origin/${{ github.base_ref }}...HEAD > pr.diff
          cargo mutants --in-diff pr.diff --in-place --baseline=skip
```

- [ ] **Step 4: Commit changes**

```bash
git add .cargo/mutants.toml .github/workflows/ .forgejo/workflows/
git commit -m "ci(mutants): expand coverage and mutation testing to yipd with diff-scoped PR gate (#107)"
```

---

### Task 6: Comprehensive Verification & Whole-Branch Review

**Files:**
- Entire workspace

- [ ] **Step 1: Run format check across workspace**

Run: `cargo fmt -- --check`
Expected: PASS.

- [ ] **Step 2: Run clippy across workspace with all targets**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS with 0 warnings.

- [ ] **Step 3: Run full workspace tests**

Run: `cargo test --workspace`
Expected: PASS with all tests green.

- [ ] **Step 4: Run cargo deny check**

Run: `cargo deny check`
Expected: PASS.

- [ ] **Step 5: Verify git cleanliness and push branch**

```bash
git status
git push origin <branch-name>
gh pr create
```
