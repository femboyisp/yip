# Design Specification: Relayed Gossip Ingestion and Convergence (#40)

- **Date:** 2026-10-13
- **Author:** Antigravity / Pair Programming
- **Target Issue:** [#40](https://github.com/femboyisp/yip/issues/40) — "2c: relayed gossip is silently dropped (relay-only members don't converge)"
- **Target Branch:** `feat/relayed-gossip-convergence`

---

## 1. Context & Motivation

In mesh configurations (`yipd` with membership enabled), peer reachability can be direct, punch-mediated, or relay-mediated. When nodes reside behind symmetric NATs or restrictive firewalls, connectivity is established exclusively via the rendezvous relay server (`PathKind::Relayed`).

In the current implementation:
1. Outbound periodic gossip (`tick_gossip` in `bin/yipd/src/peer_manager/gossip.rs`) identifies established relayed peers in `gossip_targets()` and emits digests wrapped in `RelaySend` datagrams addressed to the rendezvous server.
2. When the destination node receives the relayed frame, it arrives as `RdvEvent::Relayed { src: src_node, payload }` into `on_relayed` (`bin/yipd/src/peer_manager/relay.rs`).
3. `on_relayed` checks whether the payload is `HandshakeInit` or `HandshakeResp`. If neither, it unconditionally routes the payload into `relayed_data(idx, payload, now_ms)`.
4. `relayed_data` passes the payload to `EpochSet::inbound_open`, which expects an authenticated/encrypted data-plane datagram (`conn_tag` + AEAD/FEC ciphertext).
5. Because `PacketType::Gossip` does not match the data-plane wire format, it is rejected by `DataPlane::on_udp_datagram` as malformed and dropped (`DispatchOut::None`).

Consequently, a node reachable **only** through the relay never ingests gossip datagrams from peers and never replies, preventing directory synchronization and mesh convergence across relayed paths.

---

## 2. Invariants & Security Constraints

1. **Established Peer Restriction:**
   Direct gossip (`on_gossip` in `gossip.rs`) restricts ingestion to `Established` peers to mitigate unauthenticated packet reflection and CPU-exhaustion amplification (e.g. spoofed `PullRequest` forcing `Records` generation and certificate verification). Inbound relayed gossip must enforce this exact same invariant: `matches!(self.peers[idx].state, PeerState::Established(_))`. Relayed gossip from `Idle` or `Handshaking` peers must be dropped.

2. **Zero Wire Format Changes:**
   All wire codecs (`PacketType::Gossip`, `GossipMsg`, `RendezvousMsg::RelaySend`, `RendezvousMsg::RelayDeliver`) remain strictly unchanged.

3. **Return Path Integrity:**
   Replies to a relayed gossip request must be encapsulated via `self.relay_wrap(idx, bytes)` to route back through the rendezvous relay to `src_node`, preserving symmetry and non-routable endpoint concealment.

4. **Resource Bounding:**
   Replies are strictly bounded by `MAX_GOSSIP_REPLIES` (existing constant: 4) to prevent packet bursts.

---

## 3. Architecture & Data Flow

```
[Rendezvous Server]
        │
        │ UDP (RelayDeliver { src: src_node, payload: [Gossip, ...] })
        ▼
[PeerManager::on_rdv]
        │
        ▼
[PeerManager::on_relayed(src_node, payload)]
        │
        ├── by_node.get(&src_node) -> Some(idx)
        │
        ├── payload[0] == HandshakeInit -> relayed_handshake_init
        ├── payload[0] == HandshakeResp -> relayed_handshake_resp
        ├── membership.is_some() && payload[0] == Gossip -> relayed_gossip (NEW)
        └── else -> relayed_data
```

### Flow in `relayed_gossip`:
1. Check `matches!(self.peers[idx].state, PeerState::Established(_))`. Return `DispatchOut::None` if false.
2. Decode `GossipMsg::decode(&dg[1..])`. Return `DispatchOut::None` if invalid.
3. Pass `msg` to `self.membership.as_mut().unwrap().on_gossip(msg, now_secs())`.
4. If replies are non-empty:
   - Clear `self.egress`.
   - For each reply up to `MAX_GOSSIP_REPLIES`:
     - Construct framed buffer: `[PacketType::Gossip as u8, ...reply.encode...]`.
     - Call `self.relay_wrap(idx, bytes)`.
     - Push to `self.egress`.
   - Return `DispatchOut::Udp(&self.egress)`.
5. Return `DispatchOut::None` if no replies were generated.

---

## 4. Detailed Component Changes

### `bin/yipd/src/peer_manager/relay.rs`

1. **Update `on_relayed` Demux:**
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

2. **Implement `relayed_gossip`:**
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

---

## 5. Verification Plan

### Unit Tests (`bin/yipd/src/peer_manager/relay.rs`)
- `relayed_gossip_ingests_and_emits_relay_wrapped_replies`:
  Verify that when an established relayed peer sends a `PullRequest`, directory entries are read and wrapped `Records` datagrams are dispatched to `self.server_addr()`.
- `relayed_gossip_refuses_non_established_peer`:
  Verify that an unestablished peer (in `PeerState::Idle`) sending a relayed `PacketType::Gossip` frame is rejected and emits no egress.
- `relayed_gossip_drops_malformed_payload`:
  Verify that malformed/truncated payloads fail-closed without panics.

### Workspace Verification
- `cargo test -p yipd peer_manager::relay::tests`
- Full test suite: `cargo test --all`
- Linter & Formatting: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
