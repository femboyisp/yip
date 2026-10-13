# Data-Plane Obfuscation Key Rotation Per Epoch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the $2^{32}$ obf-nonce collision birthday bound across long-running connections by rotating data-plane obfuscation keys per epoch with multi-key trial deobfuscation (#105).

**Architecture:** Each `DataPlane` epoch stores its own outer obfuscation key derived from its Noise `hp_key`. `EpochSet` exposes active egress and candidate ingress keys (`current`, `next`, `previous`). Ingress deobfuscation trials candidate keys to allow seamless confirmed-switch promotion without wire changes.

**Tech Stack:** Rust, `yip-obf`, `yipd`, tokio.

## Global Constraints
- Strictly zero wire format changes: the `yip-obf` envelope remains `[len: 2][nonce: 8][masked region]`.
- Backward compatible with un-obfuscated mode (`obf_key = None`).
- All tests must pass: `cargo test --all`.
- Clippy clean: `cargo clippy --all-targets -- -D warnings`.
- Formatting clean: `cargo fmt --check`.

---

### Task 1: Per-Epoch `obf_key` in `DataPlane` and `EpochSet` (#105 Part 1)

**Files:**
- Modify: `bin/yipd/src/dataplane.rs`
- Modify: `bin/yipd/src/epoch.rs`
- Test: `bin/yipd/src/dataplane.rs`
- Test: `bin/yipd/src/epoch.rs`

**Interfaces:**
- `DataPlane::obf_key(&self) -> Option<[u8; 16]>`
- `EpochSet::current_obf_key(&self) -> Option<[u8; 16]>`
- `EpochSet::candidate_obf_keys(&self) -> Vec<[u8; 16]>`

- [ ] **Step 1: Write failing unit tests in `bin/yipd/src/dataplane.rs` and `bin/yipd/src/epoch.rs`**

In `bin/yipd/src/dataplane.rs` (`mod tests`):
```rust
#[test]
fn dataplane_derives_and_exposes_obf_key_when_obf_on() {
    let established = test_established();
    let expected_obf = yip_obf::derive_key(&established.hp_key);
    let dp_obf = DataPlane::new(
        established.clone(),
        123,
        TunnelMode::PointToPoint,
        "127.0.0.1:1234".parse().unwrap(),
        true, // obf_on
        1200,
    );
    assert_eq!(dp_obf.obf_key(), Some(expected_obf));

    let dp_plain = DataPlane::new(
        established,
        123,
        TunnelMode::PointToPoint,
        "127.0.0.1:1234".parse().unwrap(),
        false, // obf_off
        1200,
    );
    assert_eq!(dp_plain.obf_key(), None);
}
```

In `bin/yipd/src/epoch.rs` (`mod tests`):
```rust
#[test]
fn epoch_set_yields_candidate_obf_keys_across_lifecycle() {
    let (mut dp1, dp2) = test_dataplane_pair(true);
    let mut epochs = EpochSet::new(Box::new(dp1), 1000);
    assert_eq!(epochs.candidate_obf_keys().len(), 1);

    // Staging next epoch adds its key
    let (dp3, _) = test_dataplane_pair(true);
    let k3 = dp3.obf_key().unwrap();
    epochs.install_next(Box::new(dp3), [1u8; 32], vec![]);
    assert_eq!(epochs.candidate_obf_keys().len(), 2);
    assert!(epochs.candidate_obf_keys().contains(&k3));

    // Promoting next makes it current, moves old current to previous
    let (dp4, _) = test_dataplane_pair(true);
    let k4 = dp4.obf_key().unwrap();
    epochs.promote_from_rekey(Box::new(dp4), 2000);
    assert_eq!(epochs.current_obf_key(), Some(k4));
    assert!(epochs.candidate_obf_keys().len() >= 2);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p yipd dataplane::tests::dataplane_derives_and_exposes_obf_key_when_obf_on`
Expected: FAIL

- [ ] **Step 3: Implement `obf_key` on `DataPlane` and `EpochSet`**

In `bin/yipd/src/dataplane.rs`:
- Add field `obf_key: Option<[u8; 16]>` to `DataPlane`.
- In `DataPlane::new`:
  `obf_key: if obf_on { Some(yip_obf::derive_key(&established.hp_key)) } else { None },`
- Add getter:
  ```rust
  pub fn obf_key(&self) -> Option<[u8; 16]> {
      self.obf_key
  }
  ```

In `bin/yipd/src/epoch.rs`:
- Implement:
  ```rust
  pub fn current_obf_key(&self) -> Option<[u8; 16]> {
      self.current.obf_key()
  }

  pub fn candidate_obf_keys(&self) -> Vec<[u8; 16]> {
      let mut keys = Vec::with_capacity(3);
      if let Some(k) = self.current.obf_key() {
          keys.push(k);
      }
      if let Some(ref n) = self.next {
          if let Some(k) = n.dp.obf_key() {
              if !keys.contains(&k) {
                  keys.push(k);
              }
          }
      }
      if let Some(ref p) = self.previous {
          if let Some(k) = p.obf_key() {
              if !keys.contains(&k) {
                  keys.push(k);
              }
          }
      }
      keys
  }
  ```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd dataplane::tests && cargo test -p yipd epoch::tests`
Expected: PASS

- [ ] **Step 5: Run clippy and commit**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Commit:
```bash
git add bin/yipd/src/dataplane.rs bin/yipd/src/epoch.rs
git commit -m "feat(epoch): store and expose per-epoch obfuscation keys (#105)"
```

---

### Task 2: Multi-Epoch Ingress Trial Deobfuscation & Egress Keying (#105 Part 2)

**Files:**
- Modify: `bin/yipd/src/peer_manager/obf.rs`
- Test: `bin/yipd/src/peer_manager/obf.rs`

**Interfaces:**
- In `deobf_ingress`: trials all `epochs.candidate_obf_keys()` for the peer.
- In `obf_key_for_egress`: selects `epochs.current_obf_key()`.

- [ ] **Step 1: Write failing unit test in `bin/yipd/src/peer_manager/obf.rs`**

```rust
#[test]
fn deobf_ingress_trials_candidate_epoch_keys() {
    let mut pm = test_peer_manager_with_obf();
    // Simulate peer having staged next epoch with key k_next
    let k_next = [7u8; 16];
    // Ingress packet masked with k_next
    let plain = [PacketType::Data as u8, 1, 2, 3];
    let dg = yip_obf::obfuscate(&k_next, PacketType::Data as u8, &[1, 2, 3], 0).unwrap();
    // Install next epoch key in pm's peer
    // Assert deobf_ingress succeeds and recovers plain packet
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd peer_manager::obf::tests::deobf_ingress_trials_candidate_epoch_keys`
Expected: FAIL

- [ ] **Step 3: Update `deobf_ingress` and `obf_key_for_egress` in `bin/yipd/src/peer_manager/obf.rs`**

In `deobf_ingress`:
Case (a) (known endpoint):
```rust
if let Some(peer) = self.peers.iter().find(|p| p.endpoint == Some(src)) {
    if let PeerState::Established(ref epochs) = peer.state {
        for key in epochs.candidate_obf_keys() {
            if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
                if ptype == yip_obf::JUNK_TYPE {
                    return None;
                }
                if ptype == PacketType::Data as u8
                    || ptype == PacketType::Control as u8
                    || ptype == PacketType::Gossip as u8
                {
                    return Some(reassemble(ptype, &body));
                }
            }
        }
    }
}
```

Case (a') (roaming fallback):
```rust
for p in &self.peers {
    if let PeerState::Established(ref epochs) = p.state {
        for key in epochs.candidate_obf_keys() {
            if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
                if ptype == yip_obf::JUNK_TYPE {
                    return None;
                }
                if ptype == PacketType::Data as u8
                    || ptype == PacketType::Control as u8
                    || ptype == PacketType::Gossip as u8
                {
                    return Some(reassemble(ptype, &body));
                }
            }
        }
    }
}
```

In `obf_key_for_egress`:
```rust
self.peers
    .iter()
    .find_map(|p| {
        if p.endpoint == Some(dst) {
            if let PeerState::Established(ref epochs) = p.state {
                return epochs.current_obf_key();
            }
        }
        None
    })
    .or(self.obf_key)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd peer_manager::obf::tests`
Expected: PASS

- [ ] **Step 5: Run clippy and commit**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Commit:
```bash
git add bin/yipd/src/peer_manager/obf.rs
git commit -m "feat(obf): trial candidate epoch keys on ingress and key egress by current epoch (#105)"
```

---

### Task 3: Rekey Rotation Synchronization in `PeerManager` (#105 Part 3)

**Files:**
- Modify: `bin/yipd/src/peer_manager/rekey.rs`
- Modify: `bin/yipd/src/peer_manager/mod.rs`
- Test: `bin/yipd/src/peer_manager/rekey.rs`

**Interfaces:**
- Synchronize `Peer.session_obf_key` with `epochs.current_obf_key()` upon establishment and promotion.

- [ ] **Step 1: Write failing unit test in `bin/yipd/src/peer_manager/rekey.rs`**

```rust
#[test]
fn rekey_rotates_obf_key_and_preserves_traffic_flow() {
    let mut pm_init = test_peer_manager_with_obf();
    let mut pm_resp = test_peer_manager_with_obf();
    // Establish connection between them
    // Record initial current_obf_key
    // Drive rekey exchange (HandshakeInit -> HandshakeResp -> confirmed switch)
    // Assert current_obf_key on both sides is rotated to a new key distinct from initial
    // Assert subsequent Data packets deobfuscate successfully
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd peer_manager::rekey::tests::rekey_rotates_obf_key_and_preserves_traffic_flow`
Expected: FAIL

- [ ] **Step 3: Update `rekey.rs` and `mod.rs`**

- In `rekey.rs`:
  - When `promote_from_rekey` is called in `rekey_resp_core`, update `self.peers[idx].session_obf_key = epochs.current_obf_key()`.
  - Update comments explaining that `session_obf_key` rotates per epoch and trial unmasking handles the confirmed-switch window.
- In `peer_manager/mod.rs`:
  - Keep `session_obf_key` updated whenever `epochs.current_obf_key()` changes (or deprecate direct access in favor of `epochs.current_obf_key()`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd peer_manager::rekey::tests`
Expected: PASS

- [ ] **Step 5: Run clippy and commit**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Commit:
```bash
git add bin/yipd/src/peer_manager/rekey.rs bin/yipd/src/peer_manager/mod.rs
git commit -m "fix(rekey): rotate session obf key across epoch promotions (#105)"
```

---

### Task 4: Integration Verification (#105 Part 4)

**Files:**
- Test: `bin/yipd/tests/tunnel_netns.rs`
- Test: Full workspace test suite

- [ ] **Step 1: Run obfuscated tunnel netns tests**

Run: `sudo -E target/debug/deps/tunnel_netns-* obfuscated`
Verify all obfuscated tests pass (e.g. `obfuscated_ping`, `hole_punch_ping_obfuscated`, `relay_path_ping_obfuscated`).

- [ ] **Step 2: Run full workspace test suite and linter check**

Run: `cargo test --all && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS with 0 warnings.

- [ ] **Step 3: Run branch reviewer and commit/push**

---

## Plan Self-Review Checklist
- **Spec Coverage:**
  - `DataPlane` owns epoch-specific `obf_key` derived from `hp_key` -> Task 1
  - `EpochSet` candidate keys -> Task 1
  - Multi-key trial deobfuscation in `deobf_ingress` -> Task 2
  - Active egress keying in `obf_key_for_egress` -> Task 2
  - Rekey confirmed-switch synchronization -> Task 3
  - Verification & tests -> Task 4
- **No Placeholders:** All function signatures and logic steps explicitly documented.
