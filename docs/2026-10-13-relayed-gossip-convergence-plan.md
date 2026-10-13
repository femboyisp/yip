# Relayed Gossip Ingestion and Convergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest inbound `PacketType::Gossip` datagrams arriving over the rendezvous relay, feed them to `Membership::on_gossip`, and route replies back encapsulated through the relay so relay-only members converge membership.

**Architecture:** Extend `PeerManager::on_relayed` in `bin/yipd/src/peer_manager/relay.rs` to detect `payload[0] == PacketType::Gossip as u8` when membership is enabled. Implement `relayed_gossip` which verifies the peer is `Established`, decodes `GossipMsg`, ingests into `Membership`, and encapsulates up to `MAX_GOSSIP_REPLIES` via `relay_wrap` destined for the rendezvous server.

**Tech Stack:** Rust, `bin/yipd`, `yip-membership`, `yip-rendezvous`, `yip-crypto`.

## Global Constraints

- Zero wire format changes across all features.
- Fail-closed security invariants: strictly gate gossip ingestion to peers in `PeerState::Established`.
- Non-blocking design: no blocking calls in the data-plane / relay event dispatch.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes.

---

### Task 1: Inbound Relayed Gossip Demux & Ingestion in `PeerManager` (#40)

**Files:**
- Modify: `bin/yipd/src/peer_manager/relay.rs`
- Test: `bin/yipd/src/peer_manager/relay.rs` (`mod tests`)

**Interfaces:**
- Consumes:
  - `on_relayed(&mut self, src_node: NodeId, payload: &[u8], now_ms: u64) -> DispatchOut<'_>`
  - `GossipMsg::decode(bytes: &[u8]) -> Option<GossipMsg>`
  - `Membership::on_gossip(&mut self, msg: GossipMsg, now_s: u64) -> Vec<GossipMsg>`
  - `PeerManager::relay_wrap(&mut self, peer_idx: usize, payload: Vec<u8>) -> Option<EgressDatagram>`
  - `MAX_GOSSIP_REPLIES: usize = 4`
- Produces:
  - `PeerManager::relayed_gossip(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_>`

- [ ] **Step 1: Write the failing tests in `bin/yipd/src/peer_manager/relay.rs`**

Add unit tests in `bin/yipd/src/peer_manager/relay.rs` (`mod tests`):
```rust
#[test]
fn relayed_gossip_ingests_and_emits_relay_wrapped_replies() {
    let local = generate_keypair();
    let peer_kp = generate_keypair();
    let cfg_peer = PeerConfig {
        public_key: peer_kp.public,
        endpoint: None,
    };
    let (mut pm, _sent) = pm_with_mock_rdv(&local, &[cfg_peer]);

    // Establish a session over relay
    let t1 = crate::handshake::now_tai64n();
    let (_hs1, init_pkt_1) = HandshakeState::start_initiator(
        &peer_kp.private,
        &local.public,
        &init_payload_with_ts(t1, &[]),
    )
    .unwrap();
    let out1 = pm.on_udp(mock_server(), &relay_deliver(&peer_kp, init_pkt_1), 0);
    assert!(has_relayed_handshake_resp(&out1));
    assert!(pm.peers[0].relay);
    assert!(matches!(pm.peers[0].state, PeerState::Established(_)));

    // Send a relayed Gossip PullRequest
    let pull = GossipMsg::PullRequest {
        wanted: vec![local.public],
    };
    let mut gossip_bytes = vec![PacketType::Gossip as u8];
    pull.encode(&mut gossip_bytes);

    let out2 = pm.on_udp(mock_server(), &relay_deliver(&peer_kp, gossip_bytes), 10);
    // With membership None in pm_with_mock_rdv, it should return None.
    assert!(matches!(out2, DispatchOut::None));
}

#[test]
fn relayed_gossip_refuses_non_established_peer() {
    let local = generate_keypair();
    let peer_kp = generate_keypair();
    let cfg_peer = PeerConfig {
        public_key: peer_kp.public,
        endpoint: None,
    };
    let (mut pm, _sent) = pm_with_mock_rdv(&local, &[cfg_peer]);
    assert!(matches!(pm.peers[0].state, PeerState::Idle));

    let pull = GossipMsg::PullRequest {
        wanted: vec![local.public],
    };
    let mut gossip_bytes = vec![PacketType::Gossip as u8];
    pull.encode(&mut gossip_bytes);

    let out = pm.on_udp(mock_server(), &relay_deliver(&peer_kp, gossip_bytes), 0);
    assert!(matches!(out, DispatchOut::None));
}
```
And add `relayed_gossip_with_membership_emits_relay_wrapped_replies` using `pm_with_mock_rdv_and_membership` (or wiring membership).

- [ ] **Step 2: Run tests to verify they fail or don't compile**

Run: `cargo test -p yipd peer_manager::relay::tests::relayed_gossip`
Expected: FAIL or compile error

- [ ] **Step 3: Implement `relayed_gossip` and demux in `relay.rs`**

In `bin/yipd/src/peer_manager/relay.rs`:
In `on_relayed`:
```rust
if payload[0] == PacketType::HandshakeInit as u8 {
    self.relayed_handshake_init(idx, payload, now_ms)
} else if payload[0] == PacketType::HandshakeResp as u8 {
    self.relayed_handshake_resp(idx, payload, now_ms)
} else if self.membership.is_some() && payload[0] == PacketType::Gossip as u8 {
    self.relayed_gossip(idx, payload, now_ms)
} else {
    self.relayed_data(idx, payload, now_ms)
}
```

Implement `relayed_gossip`:
```rust
fn relayed_gossip(&mut self, idx: usize, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
    if !matches!(self.peers[idx].state, PeerState::Established(_)) {
        return DispatchOut::None;
    }
    let Some(msg) = GossipMsg::decode(&dg[1..]) else {
        return DispatchOut::None;
    };
    let replies = match self.membership.as_mut() {
        Some(m) => m.on_gossip(msg, now_secs()),
        None => return DispatchOut::None,
    };
    if replies.is_empty() {
        return DispatchOut::None;
    }
    self.egress.clear();
    for reply in replies.iter().take(MAX_GOSSIP_REPLIES) {
        let mut bytes = Vec::new();
        bytes.push(PacketType::Gossip as u8);
        reply.encode(&mut bytes);
        if let Some(d) = self.relay_wrap(idx, bytes) {
            self.egress.push(d);
        }
    }
    if self.egress.is_empty() {
        DispatchOut::None
    } else {
        DispatchOut::Udp(&self.egress)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd peer_manager::relay::tests::relayed_gossip`
Expected: PASS

- [ ] **Step 5: Run full workspace tests and linters**

Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
Expected: 0 warnings, clean fmt

- [ ] **Step 6: Commit**

```bash
git add bin/yipd/src/peer_manager/relay.rs
git commit -m "feat(mesh): ingest relayed gossip and emit relay-wrapped replies (#40)"
```

---

### Task 2: Verification across Workspace & Integration Tests (#40)

**Files:**
- Test: Full workspace test suite

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --all`
Expected: 100% PASS

- [ ] **Step 2: Run full clippy check**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: 100% clean

- [ ] **Step 3: Verification gate completion**
