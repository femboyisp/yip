# Identity Binding and Discovery Routing Design (Issues #101, #102, #106)

**Status:** Approved design spec
**Date:** 2026-10-12
**Target Issues:**
- [#101: security(relay): TLS-front registration is unauthenticated](https://github.com/femboyisp/yip/issues/101)
- [#102: security(mesh): resolver probes the unauthenticated PeerInfo.reflexive; PunchTo has no record gate](https://github.com/femboyisp/yip/issues/102)
- [#106: security(mesh): verify_record and verify_cert derive their CA anchor from different operator inputs](https://github.com/femboyisp/yip/issues/106)

---

## 1. Overview & Context

In `yip`, peers can reach each other via direct UDP hole punching or via an obfuscated TLS relay front. While the UDP rendezvous path was hardened in milestone #37, three related discovery and routing vulnerabilities remain open:

1. **#101 (TLS-Front Registration Route Hijack):**
   `classify_first_frame` on the TLS Trojan front accepts a bare unsigned `Register { node, counter }` gated only on knowledge of the shared `obf_psk`. `conn_tunnel.rs` inserts `routes.insert(node, tx)` based entirely on the unauthenticated `node` field. Any client with `obf_psk` can claim any peer's `NodeId` and hijack all relayed frames for that node.
2. **#102 (Resolver Probing & PunchTo Reflection Vector):**
   In `on_rdv`, when a `PeerCandidate` arrives with a verified `Record`, `yipd` discards the signed `record.endpoints` and probes only the unauthenticated `reflexive` address. Furthermore, `PunchTo` immediately triggers `begin_handshake` toward whatever address the server provides, with no record gate or authentication check, creating a handshake reflection primitive.
3. **#106 (CA Anchor Divergence):**
   `verify_cert` checks against `self.ca_pubkeys`, while `verify_record` checks against `self.roots`. If an operator defines bootstrap peers in `roots` but omits the CA key, certificates verify during Noise handshakes, but records silently fail to verify during discovery.

---

## 2. Architecture & Components

### 2.1 TLS-Front Registration Authentication (#101)

#### Component: `bin/yip-rendezvous/src/conn.rs`
- In `classify_first_frame(buf, obf_key, server, now_ms)`:
  - If `server.roots_cfg.is_some()` (mesh/rooted mode):
    - Unsigned `Message::Register` is dropped (returns `Classify::Decoy`).
    - `Message::RegisterSigned { record }` is accepted iff:
      1. `record.verify(ca_pubkeys, network_id, now_secs, REGISTRATION_SKEW_SECS)` succeeds.
      2. `record.seq` is within the wall-clock window (`now_wall_ms - (REG_TTL_MS + SKEW) ..= now_wall_ms + SKEW`).
      3. `server.register_if_fresh_tls(record.node_id, record.seq, now_ms)` returns `true`.
    - Returns `Classify::Upgrade { node: record.node_id, reply }`, where `reply` frames and echoes `RegisterSigned { record }`.
  - If `server.roots_cfg.is_none()` (legacy mode):
    - Continues to accept `Message::Register { node, counter }`.

#### Component: `bin/yip-rendezvous/src/conn_tunnel.rs`
- `routes.insert(node, tx)` now binds routes strictly to cryptographically verified node identities in mesh mode.

#### Component: `bin/yipd/src/relay_client.rs`
- When `membership` is present, `relay_client` encodes and sends `Message::RegisterSigned { record }` with `membership.sign_registration(seq)`. In non-mesh mode, it falls back to `Message::Register`.

---

### 2.2 Resolver Signed Endpoints Binding & PunchTo Gate (#102)

#### Component: `bin/yipd/src/peer_manager/relay.rs`
- In `on_rdv` on `RdvEvent::PeerCandidate { node, addr, record }`:
  - When `record` is verified in mesh mode:
    - For each endpoint in `record.endpoints`: call `self.peers[idx].path.on_peer_candidate(ep, now_ms)`.
    - Also register `addr` (`reflexive`) as a secondary candidate: `self.peers[idx].path.on_peer_candidate(addr, now_ms)`.
- In `on_rdv` on `RdvEvent::PunchTo { node, addr }`:
  - In mesh mode (`self.membership.is_some()`):
    - Check if `node` is known in `membership.directory` or is a configured peer in `self.by_node`.
    - Only trigger proactive `begin_handshake(idx, addr, false, now_ms)` if `node` is recognized and verified.
    - If `node` is unrecognized, drop without initiating outbound handshakes.

---

### 2.3 CA Anchor Alignment (#106)

#### Component: `bin/yipd/src/membership.rs`
- In `Membership::verify_record`:
  - Verify against `&self.ca_pubkeys` (or the union of `self.ca_pubkeys` and any CA keys in `self.roots`), ensuring `verify_record` and `verify_cert` share the same authoritative CA anchor.

#### Component: `bin/yipd/src/config.rs`
- In config parsing / validation:
  - If both `ca_public` and `roots` are configured, verify that `ca_public` is present in `roots.roots`. If missing, emit a clear load-time warning / error.
  - Update `docs/configuration.md` with explicit notes explaining that standalone rendezvous servers use the root set as the trusted CA anchor.

---

## 3. Testing & Verification Plan

1. **Unit Tests:**
   - `bin/yip-rendezvous/src/conn.rs`:
     - `classify_first_frame_accepts_valid_register_signed`
     - `classify_first_frame_rejects_unsigned_register_in_rooted_mode`
     - `classify_first_frame_rejects_forged_or_squatted_signed_record`
   - `bin/yipd/src/peer_manager/relay.rs`:
     - `peer_candidate_probes_signed_endpoints_first`
     - `punch_to_refuses_unrecognized_node`
   - `bin/yipd/src/membership.rs`:
     - `verify_record_succeeds_with_configured_ca_public`
2. **Netns Integration Tests:**
   - `run-netns-registration-hijack.sh`: Extend with a TLS front hijack scenario verifying that forged or unsigned registrations over the TLS relay front are rejected and do not steal routes.
   - Run full workspace test suite `cargo test --all` and linter checks.
