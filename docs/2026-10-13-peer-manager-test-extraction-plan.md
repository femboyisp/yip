# Extract PeerManager Mod Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the 2,290 lines of integration-style tests from `bin/yipd/src/peer_manager/mod.rs` into `bin/yipd/src/peer_manager/tests.rs` with zero runtime behavior changes.

**Architecture:** Create `bin/yipd/src/peer_manager/tests.rs` containing the existing tests from `mod tests`. Replace the inline module definition in `bin/yipd/src/peer_manager/mod.rs` with `#[cfg(test)] mod tests;`.

**Tech Stack:** Rust, `bin/yipd`.

## Global Constraints

- Zero production code behavior changes.
- Zero visibility changes needed: `use super::*;` inside `tests.rs` preserves private access within `peer_manager`.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes.

---

### Task 1: Extract Integration Tests into `tests.rs` (#120)

**Files:**
- Create: `bin/yipd/src/peer_manager/tests.rs`
- Modify: `bin/yipd/src/peer_manager/mod.rs`
- Test: `bin/yipd/src/peer_manager/tests.rs`

**Interfaces:**
- `peer_manager::tests`: Submodule containing all integration tests previously defined in `mod.rs`.

- [ ] **Step 1: Create `bin/yipd/src/peer_manager/tests.rs`**

Extract the inner contents of `mod tests { ... }` from `bin/yipd/src/peer_manager/mod.rs` (lines 1614 to end) into `bin/yipd/src/peer_manager/tests.rs`.
Ensure the imports at the top of `tests.rs` start with:
```rust
use super::testutil::*;
use super::*;
use crate::handshake::Established;
use crate::wire_glue::derive_wire_keys;
use yip_crypto::{generate_keypair, Handshake};
```

- [ ] **Step 2: Update `bin/yipd/src/peer_manager/mod.rs`**

Replace `mod tests { ... }` with:
```rust
#[cfg(test)]
pub(crate) mod testutil;

#[cfg(test)]
mod tests;
```

- [ ] **Step 3: Run peer_manager tests to verify compilation and execution**

Run: `cargo test -p yipd peer_manager::tests`
Expected: All tests pass.

- [ ] **Step 4: Run clippy and format check**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Expected: Clean output.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/peer_manager/mod.rs bin/yipd/src/peer_manager/tests.rs
git commit -m "refactor(peer_manager): extract mod tests into peer_manager/tests.rs (#120)"
```

---

### Task 2: Full Workspace Verification (#120)

**Files:**
- Test: Workspace test suite

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --all`
Expected: 100% PASS.

- [ ] **Step 2: Run workspace clippy and fmt**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: 100% PASS.
