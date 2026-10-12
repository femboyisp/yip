# Identity Binding and Discovery Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate TLS-front relay registration (#101), bind resolver probing to signed endpoints and gate `PunchTo` (#102), and align CA trust anchors across verification paths (#106).

**Architecture:**
- `Membership::verify_record` verifies against `self.ca_pubkeys` (the configured CA anchor), with load-time validation ensuring consistency between `ca_public` and `roots`.
- `on_rdv` feeds signed `record.endpoints` as primary candidates before unauthenticated `reflexive`, and gates proactive `begin_handshake` in `PunchTo` on verified directory presence.
- `classify_first_frame` on `yip-rendezvous`'s TLS front requires and verifies `RegisterSigned` in rooted mesh mode (rejecting bare `Register`), and `relay_client` emits signed registrations when membership is active.

**Tech Stack:** Rust (edition 2021), tokio, Ed25519, ChaCha20-Poly1305 / Noise-IK.

## Global Constraints

- Wire codecs must remain strictly backward-compatible.
- In rooted mode, unauthenticated legacy `Register` on the TLS front must be rejected (classified as Decoy).
- All modified code must pass `cargo test --all`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check`.

---

### Task 1: CA Anchor Alignment & Validation (#106)

**Files:**
- Modify: `bin/yipd/src/membership.rs`
- Modify: `bin/yipd/src/config.rs`
- Test: `bin/yipd/src/membership.rs` (unit tests)
- Test: `bin/yipd/src/config.rs` (unit tests)

**Interfaces:**
- `Membership::verify_record(&self, r: &Record, now_secs: u64) -> bool` verifies against `self.ca_pubkeys`.
- `Config::validate` checks that `ca_public` is represented in `roots` when both are present.

- [ ] **Step 1: Write failing unit test in `bin/yipd/src/membership.rs`**

```rust
#[test]
fn verify_record_uses_ca_pubkeys_anchor() {
    let ca = ca_signing_key();
    let ca_pub = ca.verifying_key().to_bytes();
    let other_root = [99u8; 32];
    let roots = RootSet { roots: vec![(other_root, addr("198.51.100.1:9000"))] };
    let m = test_membership_with_roots(vec![ca_pub], roots);
    let rec = m.sign_registration(1);
    assert!(m.verify_record(&rec, now_secs()));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd membership::tests::verify_record_uses_ca_pubkeys_anchor`
Expected: FAIL (because `verify_record` previously only looked at `roots.roots`).

- [ ] **Step 3: Update `Membership::verify_record` and add config validation**

In `bin/yipd/src/membership.rs`:
```rust
    pub fn verify_record(&self, r: &Record, now_secs: u64) -> bool {
        let mut ca_pubkeys = self.ca_pubkeys.clone();
        for (pk, _) in &self.roots.roots {
            if !ca_pubkeys.contains(pk) {
                ca_pubkeys.push(*pk);
            }
        }
        r.verify(&ca_pubkeys, &self.network_id, now_secs, clock_skew_secs())
            .is_ok()
    }
```
In `bin/yipd/src/config.rs`: Add validation warning/check in `validate_mesh_config`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd membership::tests::verify_record_uses_ca_pubkeys_anchor`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/membership.rs bin/yipd/src/config.rs
git commit -m "fix(mesh): unify CA trust anchors between verify_record and verify_cert (#106)"
```

---

### Task 2: Resolver Signed Endpoints Priority & PunchTo Reflection Gate (#102)

**Files:**
- Modify: `bin/yipd/src/peer_manager/relay.rs`
- Test: `bin/yipd/src/peer_manager/relay.rs` (unit tests)

**Interfaces:**
- In `on_rdv`: `PeerCandidate` prioritizes `record.endpoints`; `PunchTo` requires recognized peer in directory before calling `begin_handshake`.

- [ ] **Step 1: Write failing unit tests in `bin/yipd/src/peer_manager/relay.rs`**

```rust
#[test]
fn peer_candidate_probes_signed_endpoints_first() {
    let mut pm = test_peer_manager_with_membership();
    let peer_node = [42u8; 16];
    let signed_ep1 = addr("198.51.100.10:41000");
    let signed_ep2 = addr("198.51.100.11:41000");
    let reflexive = addr("203.0.113.50:50000");
    let rec = mint_record_with_endpoints(peer_node, vec![signed_ep1, signed_ep2]);
    let event = RdvEvent::PeerCandidate { node: peer_node, addr: reflexive, record: Some(rec) };
    pm.on_rdv_event(event, 0);
    let candidates = pm.get_peer_candidates(&peer_node);
    assert_eq!(candidates[0], signed_ep1);
    assert_eq!(candidates[1], signed_ep2);
    assert_eq!(candidates[2], reflexive);
}

#[test]
fn punch_to_refuses_unrecognized_node() {
    let mut pm = test_peer_manager_with_membership();
    let unknown_node = [99u8; 16];
    let target_addr = addr("203.0.113.77:40000");
    let out = pm.on_rdv_event(RdvEvent::PunchTo { node: unknown_node, addr: target_addr }, 0);
    assert!(matches!(out, DispatchOut::None));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd peer_manager::relay::tests::punch_to_refuses_unrecognized_node`
Expected: FAIL

- [ ] **Step 3: Update `on_rdv` in `bin/yipd/src/peer_manager/relay.rs`**

In `RdvEvent::PeerCandidate`:
- When verified `record` is present:
  - Iterate over `record.endpoints`, calling `self.peers[idx].path.on_peer_candidate(ep, now_ms)`.
  - Also call `self.peers[idx].path.on_peer_candidate(addr, now_ms)`.
In `RdvEvent::PunchTo`:
- In mesh mode (`self.membership.is_some()`):
  - Check `self.by_node.get(&node)`. If `None`, drop immediately.
  - Check if `node` exists in `membership.directory` or is a configured static peer. If not recognized, drop without calling `begin_handshake`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd peer_manager::relay::tests`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/peer_manager/relay.rs
git commit -m "fix(mesh): probe signed endpoints and gate PunchTo against reflection (#102)"
```

---

### Task 3: Server-Side TLS Trojan Front `RegisterSigned` Classification (#101 Part 1)

**Files:**
- Modify: `bin/yip-rendezvous/src/conn.rs`
- Modify: `bin/yip-rendezvous/src/conn_tunnel.rs`
- Test: `bin/yip-rendezvous/src/conn.rs` (unit tests)

**Interfaces:**
- `classify_first_frame`: in rooted mode, requires and verifies `RegisterSigned`; in rootless mode, allows `Register`.

- [ ] **Step 1: Write failing unit tests in `bin/yip-rendezvous/src/conn.rs`**

```rust
#[test]
fn classify_first_frame_accepts_valid_register_signed_in_rooted_mode() {
    let (ca_pub, net_id, rec, _) = valid_registration();
    let server = Arc::new(Mutex::new(RendezvousServer::new_with_roots(0, vec![ca_pub], net_id)));
    let buf = frame_obf_message(&obf_key, &Message::RegisterSigned { record: rec.clone() });
    let classified = classify_first_frame(&buf, &obf_key, &mut server.lock().unwrap(), 0);
    assert!(matches!(classified, Classify::Upgrade { node, .. } if node == rec.node_id));
}

#[test]
fn classify_first_frame_rejects_unsigned_register_in_rooted_mode() {
    let (ca_pub, net_id, _, _) = valid_registration();
    let server = Arc::new(Mutex::new(RendezvousServer::new_with_roots(0, vec![ca_pub], net_id)));
    let buf = frame_obf_message(&obf_key, &Message::Register { node: [1u8; 16], counter: 1 });
    let classified = classify_first_frame(&buf, &obf_key, &mut server.lock().unwrap(), 0);
    assert!(matches!(classified, Classify::Decoy));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-rendezvous-bin conn::tests::classify_first_frame_accepts_valid_register_signed_in_rooted_mode`
Expected: FAIL

- [ ] **Step 3: Update `classify_first_frame` in `bin/yip-rendezvous/src/conn.rs`**

Decode both `Message::Register` and `Message::RegisterSigned`:
- If `server.roots_cfg.is_some()`:
  - If `Register`: return `Classify::Decoy`.
  - If `RegisterSigned { record }`:
    - Verify cert and signature: `record.verify(...)`. If err, return `Classify::Decoy`.
    - Verify sequence bounds: `min_seq <= record.seq <= max_seq`. If err, return `Classify::Decoy`.
    - Call `server.register_if_fresh_tls(record.node_id, record.seq, now_ms)`. If false, return `Classify::Decoy`.
    - Return `Classify::Upgrade { node: record.node_id, reply }`.
- If `server.roots_cfg.is_none()`:
  - Accept `Register` as before.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-rendezvous-bin`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yip-rendezvous/src/conn.rs bin/yip-rendezvous/src/conn_tunnel.rs
git commit -m "fix(relay): require RegisterSigned on TLS front in rooted mode (#101)"
```

---

### Task 4: Client-Side `RegisterSigned` Over TLS Relay (#101 Part 2)

**Files:**
- Modify: `bin/yipd/src/relay_client.rs`
- Modify: `bin/yipd/src/main.rs`
- Test: `bin/yipd/src/relay_client.rs` (unit tests)

**Interfaces:**
- `spawn_relay_client`: pass registration minter / membership reference so client emits `RegisterSigned` when mesh configured.

- [ ] **Step 1: Write failing unit test in `bin/yipd/src/relay_client.rs`**

```rust
#[test]
fn relay_client_emits_register_signed_when_membership_present() {
    let membership = test_membership();
    let frame = build_first_frame(&obf_key, &membership, 1);
    let msg = decode_frame(&obf_key, &frame).unwrap();
    assert!(matches!(msg, Message::RegisterSigned { .. }));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd relay_client::tests::relay_client_emits_register_signed_when_membership_present`
Expected: FAIL

- [ ] **Step 3: Update `relay_client.rs` to support `RegisterSigned`**

Add `RegMinter` closure or enum to `RelayClientCfg`:
- In `frame_register`: if membership/minter is present, call `minter(seq)` -> `Message::RegisterSigned { record }`.
- Otherwise fallback to `Message::Register { node, counter }`.
- Update `main.rs` when spawning relay client to pass membership minter.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd relay_client::tests`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/relay_client.rs bin/yipd/src/main.rs
git commit -m "feat(relay): emit RegisterSigned from relay_client in mesh mode (#101)"
```

---

### Task 5: End-to-End Integration & Netns Verification

**Files:**
- Modify: `bin/yipd/tests/run-netns-registration-hijack.sh`
- Test: `cargo test --all`
- Test: `bin/yipd/tests/run-netns-registration-hijack.sh`

- [ ] **Step 1: Add TLS relay hijack test to `run-netns-registration-hijack.sh`**

Extend `run-netns-registration-hijack.sh`:
- Attacker S attempts to register as node A over the TLS front using unsigned `Register`.
- Assert that the TLS front classifies S as decoy, and A remains fully reachable and unhijacked.

- [ ] **Step 2: Run workspace test suite and netns test**

Run: `cargo test --all && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS with 0 warnings.

- [ ] **Step 3: Commit**

```bash
git add bin/yipd/tests/run-netns-registration-hijack.sh
git commit -m "test: verify TLS front registration hijack rejection (#101)"
```

---

## Plan Self-Review Checklist
- **Spec Coverage:**
  - #106 CA anchor alignment -> Task 1
  - #102 Signed endpoints & PunchTo reflection gate -> Task 2
  - #101 TLS-front server verification -> Task 3
  - #101 TLS-front client emission -> Task 4
  - Integration & Netns verification -> Task 5
- **No Placeholders:** All code, paths, commands, and assertions explicitly written.
