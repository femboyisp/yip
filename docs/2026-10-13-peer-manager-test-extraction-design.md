# Design Specification: Extract PeerManager Integration Tests (#120)

- **Date:** 2026-10-13
- **Author:** Antigravity / Pair Programming
- **Target Issue:** [#120](https://github.com/femboyisp/yip/issues/120) — "Follow-up: extract peer_manager mod tests into peer_manager/tests.rs"
- **Target Branch:** `refactor/extract-peer-manager-mod-tests`

---

## 1. Context & Motivation

Following the `peer_manager` module split (#108, PR #119), `bin/yipd/src/peer_manager/` was partitioned into concern files (`handshake.rs`, `rekey.rs`, `relay.rs`, `routing.rs`, `obf.rs`, `gossip.rs`, `testutil.rs`).

However, `bin/yipd/src/peer_manager/mod.rs` remains at 3,906 lines because lines 1613–3906 contain ~2,290 lines of integration tests in `#[cfg(test)] mod tests { ... }`. These tests exercise cross-cutting workflows (`on_udp`, `on_tun`, and `tick`) and do not belong to any single concern file.

Extracting these tests into `bin/yipd/src/peer_manager/tests.rs` brings `mod.rs` down to ~1,610 lines of production code, cleanly separating production definitions from cross-cutting test suites.

---

## 2. Invariants & Scope

1. **Zero Production Behavior Changes:**
   No runtime logic, data structures, or API contracts in `PeerManager` are altered.
2. **Zero Visibility / Access Breaks:**
   Because `tests.rs` is declared as `#[cfg(test)] mod tests;` inside `bin/yipd/src/peer_manager/mod.rs`, it is a child submodule of `crate::peer_manager`. `use super::*;` inside `tests.rs` preserves access to all private struct fields and methods on `PeerManager`, as well as `pub(super)` methods defined across the concern files.
3. **Pristine Test Parity:**
   All unit and integration test assertions, names, and execution paths remain identical.

---

## 3. Architecture & File Structure

```
bin/yipd/src/peer_manager/
├── mod.rs          # Reduced to ~1,610 lines; declares `#[cfg(test)] mod tests;`
├── tests.rs        # NEW: ~2,290 lines containing integration tests previously in mod.rs
├── handshake.rs
├── rekey.rs
├── relay.rs
├── routing.rs
├── obf.rs
├── gossip.rs
└── testutil.rs
```

---

## 4. Verification Plan

- `cargo test -p yipd peer_manager::tests`
- Full test suite: `cargo test --all`
- Linter & Formatting: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
