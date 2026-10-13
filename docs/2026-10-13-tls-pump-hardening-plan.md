# TLS Transport Pump Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the completed-idle slot hold availability vulnerability in `transport=tls` by enforcing an inner-handshake completion deadline in `pump()`, and surface explicit operational warnings for multi-peer TLS configurations.

**Architecture:** Add `PeerManager::is_peer_established` in `peer_manager/mod.rs`. In `tls.rs`, pass `peer_public` to `pump()`, track inner session establishment, and tear down any connection that fails to complete an inner Noise-IK handshake within `INNER_HANDSHAKE_TIMEOUT` (10s). Log warnings in both `run_tls` and `Config::from_str` when `transport=tls` is configured with multiple peers.

**Tech Stack:** Rust, `bin/yipd`, `boring`.

## Global Constraints

- Zero wire format changes across all features.
- Fail-closed security invariants: tear down completed-idle TLS connections after 10s to restore slot availability.
- Non-blocking design: all operations remain non-blocking.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes.

---

### Task 1: `PeerManager::is_peer_established` & Multi-Peer Config Warning (#61 Part 1)

**Files:**
- Modify: `bin/yipd/src/peer_manager/mod.rs`
- Modify: `bin/yipd/src/config.rs`
- Test: `bin/yipd/src/peer_manager/tests.rs`
- Test: `bin/yipd/src/config.rs`

**Interfaces:**
- Produces:
  - `PeerManager::is_peer_established(&self, pubkey: &[u8; 32]) -> bool`

- [ ] **Step 1: Write failing unit test in `bin/yipd/src/peer_manager/tests.rs`**

```rust
#[test]
fn is_peer_established_reports_correct_state() {
    let local = generate_keypair();
    let peer_kp = generate_keypair();
    let peer = peer_cfg(1, "10.0.0.1:1000");
    let pm = PeerManager::new(
        &local,
        &[peer],
        Mode::Tun,
        test_keys(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        DEFAULT_DATA_SYMBOL_SIZE,
    );
    assert!(!pm.is_peer_established(&peer_kp.public));
}
```

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `cargo test -p yipd peer_manager::tests::is_peer_established_reports_correct_state`
Expected: FAIL (method not found)

- [ ] **Step 3: Implement `is_peer_established` and multi-peer warning**

In `bin/yipd/src/peer_manager/mod.rs`:
```rust
/// Returns true if the peer with public key `pubkey` has an Established session.
pub fn is_peer_established(&self, pubkey: &[u8; 32]) -> bool {
    self.peers
        .iter()
        .any(|p| p.pubkey == *pubkey && matches!(p.state, PeerState::Established(_)))
}
```

In `bin/yipd/src/config.rs`:
In `Config::from_str`:
```rust
if transport == TransportMode::Tls && peers.len() > 1 {
    eprintln!(
        "yipd: warning: transport=tls configured with {} peers, but transport=tls \
         currently serves only the first peer; remaining peers will be ignored",
        peers.len()
    );
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd peer_manager::tests::is_peer_established_reports_correct_state`
Expected: PASS

- [ ] **Step 5: Run clippy and format check**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Expected: Clean output.

- [ ] **Step 6: Commit**

```bash
git add bin/yipd/src/peer_manager/mod.rs bin/yipd/src/peer_manager/tests.rs bin/yipd/src/config.rs
git commit -m "feat(peer_manager): expose is_peer_established and warn on multi-peer TLS config (#61)"
```

---

### Task 2: Inner Handshake Deadline & Runtime Warning in `tls.rs` (#61 Part 2)

**Files:**
- Modify: `bin/yipd/src/tls.rs`
- Test: `bin/yipd/src/tls.rs`

**Interfaces:**
- `pub(crate) const INNER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);`
- `pump(stream: SslStream<TcpStream>, poller: &Epoll, tun_fd: RawFd, manager: &mut PeerManager, peer_addr: SocketAddr, peer_public: [u8; 32], start: Instant) -> io::Result<()>`

- [ ] **Step 1: Write unit test in `bin/yipd/src/tls.rs`**

Add unit test verifying inner handshake deadline:
```rust
#[test]
fn drive_inner_handshake_timeout_on_idle_stream() {
    // Tests that a completed outer TLS connection where peer sends no inner Noise-IK
    // packets tears down after INNER_HANDSHAKE_TIMEOUT.
}
```

- [ ] **Step 2: Implement deadline in `pump()` and runtime warning in `run_tls`**

In `bin/yipd/src/tls.rs`:
1. Define:
   `pub(crate) const INNER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);`
2. In `run_tls`:
   ```rust
   if peers.len() > 1 {
       eprintln!(
           "tls: warning: transport=tls currently serves only the first configured peer ({}); \
            {} additional peer(s) will be ignored",
           peer_addr,
           peers.len() - 1
       );
   }
   ```
   Pass `peer_public` to `pump`.
3. In `pump`:
   Accept `peer_public: [u8; 32]`.
   Track `conn_start = Instant::now()`, `mut inner_confirmed = false`.
   When `manager.on_udp` runs:
   ```rust
   if manager.is_peer_established(&peer_public) {
       inner_confirmed = true;
   }
   ```
   In loop:
   ```rust
   if !inner_confirmed && conn_start.elapsed() >= INNER_HANDSHAKE_TIMEOUT {
       eprintln!(
           "tls: inner handshake did not complete within {INNER_HANDSHAKE_TIMEOUT:?}, tearing down"
       );
       return Ok(());
   }
   ```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p yipd tls::tests`
Expected: PASS

- [ ] **Step 4: Run clippy and format check**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Expected: Clean output.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/tls.rs
git commit -m "fix(tls): enforce inner handshake deadline in pump and warn on multi-peer (#61)"
```

---

### Task 3: Full Workspace Verification (#61)

**Files:**
- Test: Workspace test suite

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --all`
Expected: 100% PASS.

- [ ] **Step 2: Run workspace clippy and fmt**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: 100% PASS.
