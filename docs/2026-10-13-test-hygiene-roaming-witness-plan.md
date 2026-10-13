# Test Hygiene and Roaming Positive Witness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a direct positive witness for endpoint relearning in `run-netns-roaming.sh`, and prune 7 structurally dead test wrappers in `tunnel_netns.rs`.

**Architecture:** In `bin/yipd/src/peer_manager/routing.rs`, log endpoint migration in `relearn_endpoint`. In `bin/yipd/tests/run-netns-roaming.sh`, assert that peer B's log contains this positive witness. In `bin/yipd/tests/tunnel_netns.rs`, remove `ndpi_reader_bin()` and the 7 dead test functions.

**Tech Stack:** Rust, Bash, Linux network namespaces.

## Global Constraints

- Zero wire format changes across all features.
- Positive witness verification: prove M2 endpoint relearning directly.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes.

---

### Task 1: Positive Roaming Witness in `relearn_endpoint` & `run-netns-roaming.sh` (#110 Part 1)

**Files:**
- Modify: `bin/yipd/src/peer_manager/routing.rs`
- Modify: `bin/yipd/tests/run-netns-roaming.sh`
- Test: `bin/yipd/src/peer_manager/routing.rs`

- [ ] **Step 1: Update `relearn_endpoint` in `bin/yipd/src/peer_manager/routing.rs`**

In `bin/yipd/src/peer_manager/routing.rs`:
```rust
if let Some(ref mut ep) = self.peers[idx].endpoint {
    if ep.ip() != src.ip() {
        ep.set_ip(src.ip());
        let new_endpoint = *ep;
        if let PeerState::Established(epochs) = &mut self.peers[idx].state {
            epochs.set_peer_addr(new_endpoint);
        }
        eprintln!("peer_manager: relearn_endpoint: peer {idx} roamed to {new_endpoint}");
    }
}
```

- [ ] **Step 2: Add positive witness assertion in `bin/yipd/tests/run-netns-roaming.sh`**

In `bin/yipd/tests/run-netns-roaming.sh` (after the `rebind_continuity` assertion):
```bash
# ── assertion: positive witness — B logged that it relearned A's new IP ─────
if grep -qE "relearn_endpoint: peer [0-9]+ roamed to ${IP_A2}:" "$LOG_B"; then
    echo "[PASS] positive witness: yipRoamB logged endpoint relearn for roamed source ${IP_A2}"
else
    echo "[FAIL] positive witness: yipRoamB did not log endpoint relearn for ${IP_A2}"
    dump_logs
    exit 1
fi
```

- [ ] **Step 3: Run unit tests to verify compilation and execution**

Run: `cargo test -p yipd peer_manager::routing::tests`
Expected: PASS

- [ ] **Step 4: Run clippy and format check**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Expected: Clean output.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/peer_manager/routing.rs bin/yipd/tests/run-netns-roaming.sh
git commit -m "feat(roaming): add positive witness for endpoint relearn in routing and test (#110)"
```

---

### Task 2: Prune Structurally Dead Wrappers in `tunnel_netns.rs` (#110 Part 2)

**Files:**
- Modify: `bin/yipd/tests/tunnel_netns.rs`

- [ ] **Step 1: Remove dead wrappers from `bin/yipd/tests/tunnel_netns.rs`**

Delete:
- `fn ndpi_reader_bin()`
- `fn dpi_undetectability()`
- `fn quic_classified_as_quic()`
- `fn tls_classified_as_tls()`
- `fn port_plausibility_oracle()`
- `fn reality_probe_serves_decoy()`
- `fn relay_tls_tunnel_ping()`
- `fn relay_reality_tunnel_ping()`

- [ ] **Step 2: Run test suite to verify active wrappers**

Run: `cargo test -p yipd --test tunnel_netns`
Expected: 20 passed.

- [ ] **Step 3: Run clippy and format check**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Expected: Clean output.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/tests/tunnel_netns.rs
git commit -m "test(netns): delete 7 structurally dead wrappers and unused ndpi helper (#110)"
```

---

### Task 3: Full Workspace Verification (#110)

**Files:**
- Test: Full workspace test suite

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --all`
Expected: 100% PASS.

- [ ] **Step 2: Run workspace clippy and fmt**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: 100% PASS.
