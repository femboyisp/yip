# Phase 2: Data-Plane Zero-Copy Pipelines, Concurrency & Formal Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 2 of the verification and optimization architecture: eliminate all remaining ingress and transmit heap allocations (Issues #208, #209, #213, #214), instrument lock-free SPSC queues under Loom for weak-memory concurrency verification, and add Miri strict-provenance and Kani symbolic equivalence proofs.

**Architecture:** Ingress packet processing in `bin/yipd/src/dataplane.rs` integrates `FrameRef` and `Session::open_into` to decrypt directly into pre-allocated scratch buffers with zero heap allocations. `FecEncoder` in `crates/yip-transport/src/fec.rs` adopts a reusable `FecScratchArena` eliminating `Vec<Vec<u8>>` shard cloning on transmit. `ObjectTable` transitions from linear-probing backward shifts to a bounded circular slot map with arena-backed repair shards. `MacTable::sweep` replaces its O(N) allocation scan with O(k) tail eviction, and `SentLog` optimizes range scans with binary search. `crates/yip-io/src/spsc.rs` adds Loom instrumentation for atomic ordering proofs, and Kani verifies SIMD Galois Field equivalence.

**Tech Stack:** Rust 2021 edition, `loom = "0.7"`, `kani = "0.57"`, `dhat = "0.3.3"`, `cargo-mutants`.

## Global Constraints

- Strictly ZERO emojis in any commit message, code comment, test description, or documentation.
- Maintain `#![forbid(unsafe_code)]` across all crates except `crates/yip-io` and documented test harnesses in `crates/yip-verify`.
- No dynamic heap allocations on packet processing hotpaths (`assert_no_alloc!` enforced).
- Deny `clippy::print_stderr` and `clippy::print_stdout` in `dataplane.rs` and data-plane crates.
- All code changes must pass `cargo fmt -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `cargo deny check`.
- Never push directly to `main`; all changes must be submitted via feature branches and pull requests.

---

### Task 1: Zero-Copy Ingress AEAD Decryption via open_into (Issue #209)

**Files:**
- Modify: `bin/yipd/src/dataplane.rs:470-575`
- Modify: `bin/yipd/src/wire_glue.rs:45-80`
- Test: `bin/yipd/tests/ingress_zero_alloc_test.rs`

**Interfaces:**
- Consumes: `FrameRef` from `crates/yip-wire`, `Session::open_into` from `crates/yip-crypto`.
- Produces: Zero-allocation packet ingress path in `DataPlane::on_udp_datagram`.

- [ ] **Step 1: Write integration test asserting zero allocations on ingress deframing and decryption**

```rust
// bin/yipd/tests/ingress_zero_alloc_test.rs
use std::alloc::System;
use yip_verify::{assert_no_alloc, TrackingAllocator};
use yipd::dataplane::DataPlane;

#[global_allocator]
static ALLOC: TrackingAllocator<System> = TrackingAllocator(System);

#[test]
fn test_dataplane_ingress_performs_zero_allocations_on_hotpath() {
    // Verified under assert_no_alloc! once warm
}
```

- [ ] **Step 2: Add frame_ref_to_symbol in wire_glue.rs**

In `bin/yipd/src/wire_glue.rs`:
Add:
```rust
/// Parse a received borrowed frame into `(Symbol, u64, FlowClass)` without allocating intermediate buffers.
pub fn frame_ref_to_symbol(frame: &yip_wire::FrameRef<'_>) -> Option<(Symbol, u64, FlowClass)> {
    if frame.payload.len() < 12 {
        return None;
    }
    let counter = u64::from_be_bytes(frame.payload[0..8].try_into().ok()?);
    let object_size = u32::from_be_bytes(frame.payload[8..12].try_into().ok()?);
    let sym = Symbol {
        object_id: frame.object_id,
        object_size,
        payload_id: frame.payload_id,
        data: frame.payload[12..].to_vec(),
    };
    Some((sym, counter, flags_to_class(frame.flags)))
}
```

- [ ] **Step 3: Update DataPlane::on_udp_datagram to use deframe_borrowed and open_into**

In `bin/yipd/src/dataplane.rs`:
Replace `self.codec.deframe(wire)` with `self.codec.deframe_borrowed(wire)`.
Replace:
```rust
let inner = match self.session.open(counter, &ciphertext) {
    Ok(p) => p,
...
};
self.inner_scratch.clear();
self.inner_scratch.extend_from_slice(&inner);
```
With:
```rust
self.inner_scratch.clear();
if self.session.open_into(counter, &ciphertext, &mut self.inner_scratch).is_err() {
    self.counters.ingress_open_errors.fetch_add(1, Ordering::Relaxed);
    return Outcome::None;
}
```
And for control packets:
Add `pub(crate) control_scratch: Vec<u8>` to `DataPlane` and use `self.session.open_into(counter, ct, &mut self.control_scratch)`.

- [ ] **Step 4: Verify test passes and clippy is clean**

Run: `cargo clippy -p yipd --all-targets -- -D warnings`
Run: `cargo test -p yipd`
Expected: PASS with 0 warnings.

- [ ] **Step 5: Commit changes**

```bash
git add bin/yipd/src/dataplane.rs bin/yipd/src/wire_glue.rs bin/yipd/tests/ingress_zero_alloc_test.rs
git commit -m "perf(dataplane): eliminate ingress heap allocations via FrameRef and open_into (#209)"
```

---

### Task 2: Zero-Allocation Scratch Arena for FecEncoder (Issue #208)

**Files:**
- Modify: `crates/yip-transport/src/fec.rs:90-230`
- Test: `crates/yip-transport/tests/fec_zero_alloc_test.rs`

**Interfaces:**
- Consumes: `FecEncoder` in `crates/yip-transport`.
- Produces: `FecScratchArena` avoiding per-packet `Vec<Vec<u8>>` shard allocations on transmit.

- [ ] **Step 1: Write unit test asserting zero allocations on FecEncoder::encode**

```rust
// crates/yip-transport/tests/fec_zero_alloc_test.rs
use std::alloc::System;
use yip_transport::{FecEncoder, FlowParams};
use yip_verify::{assert_no_alloc, TrackingAllocator};

#[global_allocator]
static ALLOC: TrackingAllocator<System> = TrackingAllocator(System);

#[test]
fn test_fec_encoder_encode_zero_alloc_with_arena() {
    // Assert zero allocations during systematic and repair symbol generation
}
```

- [ ] **Step 2: Implement FecScratchArena in crates/yip-transport/src/fec.rs**

Add `FecScratchArena` with pre-allocated shard buffers (`Vec<Vec<u8>>` or flat buffer of size $256 \times \text{max\_shard\_len}$).
Integrate arena into `FecEncoder`:
- Replaces `split_source` allocations by slicing directly from input or populating pre-allocated arena slices.
- `encode_repair` writes directly into pre-allocated repair slots.

- [ ] **Step 3: Run tests to verify correctness and zero allocation**

Run: `cargo test -p yip-transport --test fec_zero_alloc_test`
Run: `cargo bench --bench fec_reassemble -- --test`
Expected: PASS.

- [ ] **Step 4: Commit changes**

```bash
git add crates/yip-transport/src/fec.rs crates/yip-transport/tests/fec_zero_alloc_test.rs
git commit -m "perf(transport): zero-allocation scratch arena for FecEncoder on packet transmit path (#208)"
```

---

### Task 3: Bounded Circular Ring-Buffer ObjectTable & Zero-Copy Repair Shards (Issue #213)

**Files:**
- Modify: `crates/yip-transport/src/fec.rs:270-430`
- Test: `crates/yip-transport/tests/object_table_test.rs`

**Interfaces:**
- Consumes: `ObjectTable` in `crates/yip-transport/src/fec.rs`.
- Produces: Circular slot-map `ObjectTable` with O(1) eviction and bounded repair-shard buffer reuse.

- [ ] **Step 1: Write unit tests for circular ObjectTable eviction and lookup**

Verify insertions, removals, overwrites, capacity eviction, and boundary lookups match all `ObjectTable` contracts.

- [ ] **Step 2: Implement circular slot-map ObjectTable**

Replace backward-shift linear probing with a circular slot array where object IDs map directly to slot indices via modulo masking, with generational or key-tag validation.
In `ObjState`, replace `repair_shards: Vec<(u16, Vec<u8>)>` with fixed pre-allocated shard slots to eliminate clones during packet loss.

- [ ] **Step 3: Run tests to verify all FEC reassembly tests pass**

Run: `cargo test -p yip-transport`
Expected: PASS across all 40+ unit and property tests.

- [ ] **Step 4: Commit changes**

```bash
git add crates/yip-transport/src/fec.rs crates/yip-transport/tests/object_table_test.rs
git commit -m "perf(transport): circular ring-buffer ObjectTable and zero-copy repair buffering (#213)"
```

---

### Task 4: O(1) Tail-Eviction MacTable::sweep and Monotonic SentLog Accounting (Issue #214)

**Files:**
- Modify: `bin/yipd/src/mac_table.rs:115-150`
- Modify: `crates/yip-transport/src/retxbuf.rs:1-120`
- Test: `bin/yipd/tests/mac_table_sweep_test.rs`

**Interfaces:**
- Consumes: `MacTable` in `yipd`, `SentLog` in `yip-transport`.
- Produces: O(1) tail-eviction `sweep(now_ms)` and binary-search class counting.

- [ ] **Step 1: Write test for O(1) tail-eviction in MacTable**

Assert that `sweep` evicts all expired items from the list tail without allocating a `Vec` or iterating over the entire hash index.

- [ ] **Step 2: Implement O(1) tail eviction in MacTable::sweep**

In `bin/yipd/src/mac_table.rs`:
```rust
pub(crate) fn sweep(&mut self, now_ms: u64) {
    let ttl_ms = self.ttl_ms;
    while self.tail != NIL {
        let last_seen = self.nodes[self.tail].entry.last_seen_ms;
        if now_ms.saturating_sub(last_seen) > ttl_ms {
            let mac = self.nodes[self.tail].mac;
            self.remove(mac);
        } else {
            break;
        }
    }
}
```

- [ ] **Step 3: Optimize SentLog window scan with binary search**

In `crates/yip-transport/src/retxbuf.rs`:
Replace linear scan over `VecDeque` with `partition_point` binary search over monotonic counter sequence.

- [ ] **Step 4: Verify tests pass**

Run: `cargo test -p yipd --bin yipd mac_table`
Run: `cargo test -p yip-transport`
Expected: PASS.

- [ ] **Step 5: Commit changes**

```bash
git add bin/yipd/src/mac_table.rs crates/yip-transport/src/retxbuf.rs
git commit -m "perf(dataplane): O(1) tail-eviction MAC table sweep and monotonic binary search SentLog (#214)"
```

---

### Task 5: Loom Weak-Memory Concurrency Verification on spsc.rs

**Files:**
- Modify: `crates/yip-io/Cargo.toml`
- Modify: `crates/yip-io/src/spsc.rs:1-80`
- Create: `crates/yip-io/tests/loom_spsc.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `.forgejo/workflows/ci.yml`

**Interfaces:**
- Consumes: `RingBuffer` in `crates/yip-io/src/spsc.rs`.
- Produces: Exhaustive permutation verification of lock-free queue under Loom.

- [ ] **Step 1: Write Loom concurrent push/pop permutation test**

```rust
// crates/yip-io/tests/loom_spsc.rs
#[cfg(loom)]
#[test]
fn loom_spsc_concurrent_push_pop_permutation() {
    loom::model(|| {
        let (mut tx, mut rx) = yip_io::spsc::spsc_channel::<u32, 2>();
        let handle = loom::thread::spawn(move || {
            let _ = tx.push(10);
            let _ = tx.push(20);
        });
        let _ = rx.pop();
        let _ = rx.pop();
        handle.join().unwrap();
    });
}
```

- [ ] **Step 2: Add loom conditional imports in crates/yip-io/src/spsc.rs**

Add `#[cfg(loom)]` conditional compilation for atomics and `UnsafeCell`.
Add `loom = { version = "0.7", optional = true }` under `[dependencies]` in `crates/yip-io/Cargo.toml`.

- [ ] **Step 3: Run Loom test locally**

Run: `RUSTFLAGS="--cfg loom" cargo test -p yip-io --test loom_spsc`
Expected: PASS with all permutations explored.

- [ ] **Step 4: Add Loom step to CI workflows**

In `.github/workflows/ci.yml` and `.forgejo/workflows/ci.yml`:
Add:
```yaml
      - name: Loom weak-memory SPSC verification
        run: RUSTFLAGS="--cfg loom" cargo test --package yip-io --test loom_spsc
```

- [ ] **Step 5: Commit changes**

```bash
git add crates/yip-io/Cargo.toml crates/yip-io/src/spsc.rs crates/yip-io/tests/loom_spsc.rs .github/workflows/ .forgejo/workflows/
git commit -m "test(io): add Loom weak-memory permutation verification for lock-free SPSC queue"
```

---

### Task 6: Miri Strict-Provenance & Kani Symbolic Verification

**Files:**
- Create: `crates/yip-transport/src/rs_simd_kani.rs`
- Modify: `crates/yip-transport/Cargo.toml`
- Modify: `.github/workflows/ci.yml`
- Modify: `.forgejo/workflows/ci.yml`

**Interfaces:**
- Consumes: `rs_simd` and scalar `rs` in `crates/yip-transport`.
- Produces: Kani formal proof of SIMD Galois Field equivalence; Miri strict provenance verification.

- [ ] **Step 1: Write Kani equivalence proof harness for SIMD Galois multiplication**

Verify that for any arbitrary coefficient $c \in [0, 255]$ and input bytes, SIMD lookup tables match scalar Galois Field multiplication byte-for-byte.

- [ ] **Step 2: Add Miri strict-provenance CI test step**

In `.github/workflows/ci.yml` and `.forgejo/workflows/ci.yml`:
Add:
```yaml
      - name: Miri strict-provenance memory check
        run: cargo +nightly miri test --package yip-wire --package yip-verify
        env:
          MIRIFLAGS: "-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check"
```

- [ ] **Step 3: Verify Miri runs cleanly locally**

Run: `cargo +nightly miri test -p yip-verify`
Expected: PASS with 0 undefined behavior or provenance warnings.

- [ ] **Step 4: Commit changes**

```bash
git add crates/yip-transport/ .github/workflows/ .forgejo/workflows/
git commit -m "verify: add Kani Galois Field SIMD equivalence proof and Miri strict-provenance CI gate"
```

---

### Task 7: Comprehensive Verification & Whole-Branch Review

**Files:**
- Entire workspace

- [ ] **Step 1: Run format check across workspace**

Run: `cargo fmt -- --check`
Expected: PASS.

- [ ] **Step 2: Run clippy across workspace**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS with 0 warnings.

- [ ] **Step 3: Run full workspace test suite**

Run: `cargo test --workspace`
Expected: PASS with all tests green.

- [ ] **Step 4: Run cargo deny and cargo shear**

Run: `cargo deny check && cargo shear`
Expected: PASS.

- [ ] **Step 5: Push branch and open PR**

```bash
git push origin <branch-name>
gh pr create
```
