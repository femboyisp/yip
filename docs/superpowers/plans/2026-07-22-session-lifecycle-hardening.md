# Session-lifecycle hardening (#36 + #41) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the #36 path-switch half-open black hole (preserve the in-flight Noise ephemeral across a path re-target) and the #41 cert-revocation lag (re-verify certs on rekey + a periodic liveness sweep), both now unblocked by the merged 9a/#91 rekey machinery.

**Architecture:** Two independent fixes in `bin/yipd/src/peer_manager.rs`, plus one read-only helper on `bin/yipd/src/membership.rs`. #36 adds a `retarget_handshake` helper that re-points an in-flight `Handshaking` attempt at a new path **without** minting a fresh ephemeral (resend the existing `init_pkt`), and the two tick escalation arms call it instead of `Idle` + `begin_handshake`. #41 adds a `drop_session` helper, re-verifies the initiator's cert in the rekey arms (drop on failure), and adds a periodic `member_cert_valid` sweep over Established mesh peers (roots exempt).

**Tech Stack:** Rust, `#![forbid(unsafe_code)]`; snow Noise-IK (handshake); `yip-membership` (certs/directory); netns integration tests under both the poll and `YIP_USE_URING=1` drivers.

## Global Constraints

- `#![forbid(unsafe_code)]` — NO `unsafe`.
- NO `as` casts, except the pre-existing `PacketType::X as u8` idiom.
- NO bare `#[allow]` — use `#[expect(reason = "...")]`.
- Run `cargo fmt` before every commit; do NOT `--no-verify` to skip fmt.
- `cargo clippy -p yipd --all-targets -- -D warnings` must be clean.
- NO wire-format change. `yip-crypto`, `yip-wire`, `bin/yipd/src/handshake.rs` UNCHANGED.
- Both fixes are no-ops when `membership.is_none()` (#41) or no handshake is in flight (#36) — 2a/2b/2c byte-identical otherwise.
- `yipd` is a binary crate: test with `cargo test -p yipd --bin yipd` (NOT `--lib`).
- Known env flake: the `yip-io` uring loopback test may fail unrelated to yipd; acceptable only if it is the sole failure and the code is fmt-clean.

---

### Task 1: #36 — `retarget_handshake` helper + wire the two escalation arms

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (add `retarget_handshake`; replace the two escalation arms in `tick_dispatch` at the in-flight-handshake block, ~2607 `PathAction::Relay` and ~2646 `PathAction::Probe(addr) if addr != target`)
- Test: `bin/yipd/src/peer_manager.rs` (the in-crate `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `HandshakingState { hs, init_pkt: Vec<u8>, target: SocketAddr, started_ms, last_sent_ms, retry_ms, retries }`; `Peer.relay: bool`; `Peer.endpoint: Option<SocketAddr>`; `begin_handshake(&mut self, idx, target: SocketAddr, via_relay: bool, now_ms) -> Option<Vec<EgressDatagram>>`; `relay_wrap(&mut self, idx, raw: Vec<u8>) -> Option<EgressDatagram>`; `EgressDatagram { fate: u16, dst: SocketAddr, bytes: Vec<u8> }`.
- Produces: `retarget_handshake(&mut self, idx: usize, new_target: SocketAddr, via_relay: bool, now_ms: u64) -> Option<Vec<EgressDatagram>>`.

- [ ] **Step 1: Write the failing test — retarget preserves the ephemeral (byte-identical `init_pkt`) and updates target/relay**

Add to the `tests` module. Use the existing test scaffolding — look at how nearby tests build a `PeerManager` with a rendezvous and drive a peer into `Handshaking` (e.g. `pm_with_mock_rdv` / the escalation tests). The assertion: a `Handshaking` peer re-targeted to relay resends the **same** `init_pkt` bytes it was already holding, and flips `relay` to `true`, and does NOT reset `started_ms`.

```rust
#[test]
fn retarget_handshake_preserves_ephemeral_and_flips_relay() {
    // A peer mid-handshake toward a direct candidate.
    let (mut pm, idx) = pm_handshaking_direct_peer([7u8; 32], "10.0.0.9:9000", 100);
    let (orig_init, orig_started, orig_target) = match &pm.peers[idx].state {
        PeerState::Handshaking(h) => (h.init_pkt.clone(), h.started_ms, h.target),
        _ => panic!("peer must be Handshaking"),
    };
    let server = pm.server_addr();

    // Re-target to the relay (Punch->Relay escalation).
    let out = pm.retarget_handshake(idx, server, true, 5_000).expect("emits an Init");

    // Ephemeral preserved: the resent Init is byte-identical, still Handshaking,
    // started_ms unchanged (the 90s give-up clock keeps running).
    match &pm.peers[idx].state {
        PeerState::Handshaking(h) => {
            assert_eq!(h.init_pkt, orig_init, "init_pkt (ephemeral) must be preserved");
            assert_eq!(h.started_ms, orig_started, "started_ms must not reset on re-target");
            assert_eq!(h.target, server, "target must update to the new path");
            assert_ne!(h.target, orig_target);
        }
        _ => panic!("peer must stay Handshaking"),
    }
    assert!(pm.peers[idx].relay, "relay flag must be set for a relay re-target");
    assert!(pm.peers[idx].endpoint.is_none(), "relay re-target clears endpoint (anti-mismatch)");
    // The emitted datagram is the relay-wrapped Init (a RelaySend), carrying the SAME ephemeral.
    assert!(has_relayed_handshake_init(Some(&out)), "must emit a relay-wrapped Init");
}
```

If `pm_handshaking_direct_peer` does not exist, add a small test helper alongside the other `pm_*` helpers that builds a `PeerManager` with a `MockRdv`, inserts one peer, and drives it to `Handshaking` on a direct endpoint (mirror the setup the existing escalation tests use). `has_relayed_handshake_init` already exists (used by the rekey tests).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yipd --bin yipd retarget_handshake_preserves_ephemeral_and_flips_relay`
Expected: FAIL — `retarget_handshake` does not exist yet.

- [ ] **Step 3: Implement `retarget_handshake`**

Add this method to `impl PeerManager` (near `begin_handshake`):

```rust
/// Re-point an in-flight handshake at `new_target` over the given path,
/// PRESERVING the Noise ephemeral: resend the existing `init_pkt` rather than
/// drawing a fresh one, so a responder that already adopted us on the old path
/// completes us via its `cached_resp` (#36). Falls back to a fresh
/// `begin_handshake` only when no handshake is in flight (Idle/cold).
///
/// `started_ms` is intentionally NOT reset — the `HANDSHAKE_TOTAL_MS` give-up
/// clock keeps running across re-targets (a re-target does not buy a fresh
/// 90 s). On a `via_relay` re-target `endpoint` is cleared: a late direct
/// `[HandshakeResp]` for this same ephemeral must not complete us onto a now
/// `relay`-flagged peer (that would mismatch egress — data-plane egress is
/// re-wrapped by the `relay` flag, not the stamped dst).
fn retarget_handshake(
    &mut self,
    idx: usize,
    new_target: SocketAddr,
    via_relay: bool,
    now_ms: u64,
) -> Option<Vec<EgressDatagram>> {
    let PeerState::Handshaking(h) = &mut self.peers[idx].state else {
        // No handshake in flight: a fresh attempt is correct here.
        return self.begin_handshake(idx, new_target, via_relay, now_ms);
    };
    h.target = new_target;
    let init_pkt = h.init_pkt.clone();
    self.peers[idx].relay = via_relay;
    if via_relay {
        self.peers[idx].endpoint = None;
        return self.relay_wrap(idx, init_pkt).map(|d| vec![d]);
    }
    Some(vec![EgressDatagram {
        fate: 0,
        dst: new_target,
        bytes: init_pkt,
    }])
}
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cargo test -p yipd --bin yipd retarget_handshake_preserves_ephemeral_and_flips_relay`
Expected: PASS.

- [ ] **Step 5: Wire the two escalation arms to `retarget_handshake`**

In `tick_dispatch`'s in-flight-handshake escalation block, replace the `PathAction::Relay` arm (currently sets `state = Idle`, clears `endpoint`, `begin_handshake(i, server, true)`) with:

```rust
PathAction::Relay => {
    // Escalate the in-flight direct/punch attempt to the relay, PRESERVING
    // the ephemeral (#36): resend the same Init over the relay so a responder
    // already Established on the old path completes us via its cached_resp.
    // `retarget_handshake` clears `endpoint` (anti-mismatch) as the old
    // Idle+begin_handshake path did.
    let server = self.server_addr();
    if let Some(dgs) = self.retarget_handshake(i, server, true, now_ms) {
        self.tick_egress.extend(dgs);
    }
    continue;
}
```

And replace the `PathAction::Probe(addr) if addr != target` arm (currently `state = Idle`, `begin_handshake(i, addr, false)`) with:

```rust
PathAction::Probe(addr) if addr != target => {
    // The SM chose a *different* candidate: re-target the in-flight attempt,
    // PRESERVING the ephemeral (#36) instead of abandoning it to a fresh one.
    if let Some(dgs) = self.retarget_handshake(i, addr, false, now_ms) {
        self.tick_egress.extend(dgs);
    }
    continue;
}
```

- [ ] **Step 6: Write the failing test — an Established responder completes a re-targeted initiator via `cached_resp`**

This is the end-to-end #36 mechanism at the unit level: a responder that is `Established` (holding `cached_resp` for ephemeral E1) replays that resp when the same Init (E1) arrives over the relay, and the initiator's re-target used the same E1. Model it as: build a responder `pm_r` that has completed as responder for initiator A (so `cached_resp` + `cached_resp_init_eph` are set and it is `Established`), then deliver A's **relay-wrapped** Init (same `init_pkt`/E1) and assert `pm_r` replays its cached resp (a `RelaySend`) rather than minting a new session or dropping.

```rust
#[test]
fn established_responder_completes_retargeted_initiator_via_cached_resp() {
    // Responder that adopted initiator A and is Established, caching resp for A's ephemeral.
    let (mut pm_r, a_init_pkt) = responder_established_for_initiator([3u8; 32], [4u8; 32], 100);
    let tag_before = established_tag(&pm_r, 0);

    // A re-targeted to relay and resent the SAME init (E1). It arrives relay-wrapped.
    let relayed = wrap_relay_deliver(&pm_r, &a_init_pkt); // src = A's node
    let out = pm_r.on_udp(mock_server(), &relayed, 5_000).map(<[EgressDatagram]>::to_vec);

    // Responder replays its cached resp (a RelaySend) — completing A — and does
    // NOT churn a new session: current tag unchanged.
    assert!(has_relayed_handshake_resp(out.as_deref()), "must replay cached resp over the relay");
    assert_eq!(established_tag(&pm_r, 0), tag_before, "current session must be untouched");
}
```

Reuse existing helpers where they exist (`mock_server`, `established_tag`, the relay-deliver wrapping used by the Task-2 relay-rekey tests, `has_relayed_handshake_resp` or the equivalent used by those tests). Add small helpers only if none exists.

- [ ] **Step 7: Run it — verify it passes (the cached-resp replay already works via `rekey_init_core` case 1)**

Run: `cargo test -p yipd --bin yipd established_responder_completes_retargeted_initiator_via_cached_resp`
Expected: PASS — this asserts the responder side already replays `cached_resp` for a matching ephemeral (the mechanism #36's fix relies on); no responder-side code change is needed. If it fails, the test setup does not match `cached_resp_init_eph` — fix the setup, not the production code.

- [ ] **Step 8: Full suite + clippy + fmt, then commit**

```bash
cargo test -p yipd --bin yipd
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "fix(hardening.36): preserve the in-flight ephemeral across a path re-target"
```
Expected: all green.

---

### Task 2: #41(a) — `drop_session` helper + re-verify the cert in a received rekey Init

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (add `drop_session`; re-verify in `handle_handshake_init`'s Established arm and `relayed_handshake_init`'s Established arm)
- Test: `bin/yipd/src/peer_manager.rs` (`tests` module)

**Interfaces:**
- Consumes: `EpochSet { current: Box<DataPlane>, next: Option<NextEpoch>, previous: Option<Box<DataPlane>> }`; `NextEpoch { dp: Box<DataPlane> }`; `DataPlane::conn_tag(&self) -> u64`; `responder_cert_ok(&self, payload: &[u8], peer_pub: [u8; 32]) -> bool`; `by_tag: HashMap<u64, usize>`.
- Produces: `drop_session(&mut self, idx: usize)`.

- [ ] **Step 1: Write the failing test — a rekey Init with an invalid cert drops the session**

A mesh (`membership.is_some()`) Established peer receiving a rekey Init whose payload is NOT a currently-valid cert loses its session (reverts to `Idle`, its `by_tag` entry gone, no resp emitted). Model an expired/invalid cert by passing a payload that `responder_cert_ok` rejects (e.g. a cert past `not_after`, or empty bytes when membership is enabled — `Cert::decode` fails → `responder_cert_ok` returns false).

```rust
#[test]
fn rekey_init_with_invalid_cert_drops_session() {
    // Mesh Established peer, current old enough that accept_rekey_init would pass.
    let (mut pm, tag) = pm_mesh_established_peer([5u8; 32], [6u8; 32], /*age past interval/2*/ 100_000);
    assert_eq!(established_tag(&pm, 0), Some(tag));

    // A rekey Init from that peer carrying an INVALID cert payload (membership on).
    let init = rekey_init_with_payload(&pm, 0, /*payload=*/ b"not-a-valid-cert");
    let out = pm.on_udp(peer_src(&pm, 0), &init, 200_000).map(<[EgressDatagram]>::to_vec);

    // Session dropped: Idle, by_tag entry gone, no resp emitted.
    assert!(matches!(pm.peers[0].state, PeerState::Idle), "invalid-cert rekey drops the session");
    assert!(!pm.by_tag.values().any(|&i| i == 0), "the peer's conn_tag is removed from by_tag");
    assert!(out.map_or(true, |o| o.is_empty()), "no resp for a revoked rekey");
}
```

Use the existing mesh-peer test scaffolding (the 2c admission tests build a `PeerManager` with `membership: Some(..)` and mint certs via the CA test helpers). If a `pm_mesh_established_peer` / `rekey_init_with_payload` helper does not exist, add minimal ones next to the existing 2c/rekey test helpers.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yipd --bin yipd rekey_init_with_invalid_cert_drops_session`
Expected: FAIL — the rekey path currently ignores the cert; the peer stays Established.

- [ ] **Step 3: Implement `drop_session`**

Add to `impl PeerManager` (collect tags first to avoid a `by_tag` vs `peers` borrow conflict):

```rust
/// Tear down a peer's live session: remove every `conn_tag` it holds
/// (current + any in-flight `next` + grace `previous`) from `by_tag`, and
/// revert the peer to `Idle`. Idempotent for a non-Established peer.
/// Re-admission is guarded by the cold-start cert check, so a revoked peer
/// cannot re-establish.
fn drop_session(&mut self, idx: usize) {
    let tags: Vec<u64> = if let PeerState::Established(epochs) = &self.peers[idx].state {
        let mut t = vec![epochs.current.conn_tag()];
        if let Some(n) = epochs.next.as_ref() {
            t.push(n.dp.conn_tag());
        }
        if let Some(p) = epochs.previous.as_ref() {
            t.push(p.conn_tag());
        }
        t
    } else {
        Vec::new()
    };
    for tag in tags {
        self.by_tag.remove(&tag);
    }
    self.peers[idx].state = PeerState::Idle;
}
```

- [ ] **Step 4: Re-verify the cert in both rekey Established arms**

In `handle_handshake_init` (the direct path), the Established arm currently destructures `initiator_payload` and calls `handle_rekey_init(...)`. Before that call, guard on the cert:

```rust
PeerState::Established(_) => {
    // #41: a mid-session rekey Init must carry a currently-valid cert (mesh
    // mode). A revoked/expired member presenting a stale cert loses its
    // session within a rekey interval instead of at process restart.
    if !self.responder_cert_ok(&initiator_payload, remote_static) {
        self.drop_session(idx);
        return DispatchOut::None;
    }
    let init_eph = crate::handshake::init_ephemeral(dg).expect(
        "start_responder already parsed dg's msg1; its leading 32 bytes are `e`",
    );
    self.handle_rekey_init(idx, src, established, resp_pkt, now_ms, init_eph)
}
```

In `relayed_handshake_init`, the Established arm currently discards `_initiator_payload`. Un-discard it (rename to `initiator_payload` in the destructure at the top of the function) and add the same guard before the `rekey_init_core(...)` call:

```rust
PeerState::Established(_) => {
    if !self.responder_cert_ok(&initiator_payload, remote_static) {
        self.drop_session(idx);
        return DispatchOut::None;
    }
    let Some(init_eph) = crate::handshake::init_ephemeral(dg) else {
        return DispatchOut::None; // malformed Init
    };
    self.rekey_init_core(idx, established, resp_pkt, init_eph, now_ms, self.server_addr(), true)
}
```

`responder_cert_ok` returns `true` when `membership.is_none()`, so this is a no-op for pure 2a/2b.

- [ ] **Step 5: Run the invalid-cert test + a valid-cert control**

Add a control test asserting a VALID cert still rekeys normally (peer stays Established, its session rotates):

```rust
#[test]
fn rekey_init_with_valid_cert_still_rekeys() {
    let (mut pm, _tag) = pm_mesh_established_peer([5u8; 32], [6u8; 32], 100_000);
    let init = rekey_init_with_payload(&pm, 0, &valid_cert_bytes(&pm, 0));
    let _ = pm.on_udp(peer_src(&pm, 0), &init, 200_000);
    assert!(matches!(pm.peers[0].state, PeerState::Established(_)), "valid cert rekeys, no drop");
}
```

Run: `cargo test -p yipd --bin yipd rekey_init_with_`
Expected: both PASS.

- [ ] **Step 6: Full suite + clippy + fmt, then commit**

```bash
cargo test -p yipd --bin yipd
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "fix(hardening.41): re-verify cert on rekey Init, drop session on failure"
```
Expected: all green.

---

### Task 3: #41(b) — `Membership::member_cert_valid` + periodic liveness sweep

**Files:**
- Modify: `bin/yipd/src/membership.rs` (add `member_cert_valid`)
- Modify: `bin/yipd/src/peer_manager.rs` (add the sweep to `tick_dispatch`; uses `drop_session` from Task 2)
- Test: both files' `tests` modules

**Interfaces:**
- Consumes (membership.rs): `self.roots: RootSet` (`self.roots.roots: Vec<([u8;32], SocketAddr)>`); `self.directory: HashMap<NodeId, Record>` (`Record.cert: Cert`); `self.verify_cert(&Cert, &[u8;32], u64) -> bool`; `yip_membership::node_id(&[u8;32]) -> NodeId`.
- Consumes (peer_manager.rs): `drop_session(&mut self, idx)`; `now_secs() -> u64` (real wall clock); `now_ms` (the `tick` monotonic clock); `Peer.pubkey: [u8;32]`; `membership: Option<Membership>`; `rekey_interval_ms: u64`.
- Produces: `Membership::member_cert_valid(&self, pubkey: &[u8; 32], now: u64) -> bool`; a new `PeerManager.last_cert_sweep_ms: u64` field (init `0` in `new`).

**Clock note:** the sweep verifies certs at `now_secs()` (real wall clock), so unit-test fixtures must encode expiry via the cert's `not_after` — an expired peer's cert gets `not_after` in the past (e.g. `1`), a valid peer's gets `not_after` far in the future — rather than trying to control the wall clock. The sweep *throttle* uses `now_ms` (the `tick` monotonic clock the test passes in).

- [ ] **Step 1: Write the failing test — `member_cert_valid` is true for a live record / a root, false for an expired member**

Add to `membership.rs`'s `tests` module (it already mints records/certs via CA test helpers):

```rust
#[test]
fn member_cert_valid_tracks_directory_and_roots() {
    let (m, live_pubkey, root_pubkey, expired_pubkey, now) = membership_with_live_root_and_expired();
    assert!(m.member_cert_valid(&live_pubkey, now), "a live directory record is valid");
    assert!(m.member_cert_valid(&root_pubkey, now), "a root is always admissible (exempt)");
    assert!(!m.member_cert_valid(&expired_pubkey, now), "an expired/absent member is invalid");
    let never_seen = [0xAAu8; 32];
    assert!(!m.member_cert_valid(&never_seen, now), "an unknown non-root member is invalid");
}
```

Build the fixture from the existing test CA helpers: insert one still-valid record, include one pubkey in the `roots` set, and either omit the expired member's record or insert one whose cert `not_after < now`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yipd --bin yipd member_cert_valid_tracks_directory_and_roots`
Expected: FAIL — `member_cert_valid` does not exist.

- [ ] **Step 3: Implement `member_cert_valid`**

Add to `impl Membership` in `membership.rs`:

```rust
/// Whether `pubkey` is still an admissible member at wall-clock `now`:
/// `true` if it is an always-admit root, OR the directory holds a valid
/// (unexpired, verifying) cert for it. `false` only when a non-root member's
/// record was evicted (expired) or its cert no longer verifies — i.e.
/// revoked-by-non-renewal. Folding the root check in here keeps roots exempt
/// from the #41 liveness sweep (they have no directory-cert dependency).
pub fn member_cert_valid(&self, pubkey: &[u8; 32], now: u64) -> bool {
    if self.roots.roots.iter().any(|(pk, _)| pk == pubkey) {
        return true;
    }
    match self.directory.get(&node_id(pubkey)) {
        Some(rec) => self.verify_cert(&rec.cert, pubkey, now),
        None => false,
    }
}
```

- [ ] **Step 4: Run the membership test — verify it passes**

Run: `cargo test -p yipd --bin yipd member_cert_valid_tracks_directory_and_roots`
Expected: PASS.

- [ ] **Step 5: Write the failing test — the tick sweep drops an Established mesh peer whose cert expired, leaves a valid one**

Add to `peer_manager.rs`'s `tests`:

```rust
#[test]
fn tick_sweep_drops_established_peer_with_expired_cert() {
    // Two Established mesh peers: peer 0's directory cert is expired, peer 1's is valid.
    let (mut pm, tag1) = pm_mesh_two_established_one_expired([1u8; 32], [2u8; 32]);
    pm.tick(500_000); // a tick past the sweep cadence, now_secs shows peer 0 expired
    assert!(matches!(pm.peers[0].state, PeerState::Idle), "expired-cert peer's session is dropped");
    assert!(!pm.by_tag.values().any(|&i| i == 0), "its conn_tag is removed");
    assert_eq!(established_tag(&pm, 1), Some(tag1), "the valid peer is untouched");
}

#[test]
fn tick_sweep_is_noop_without_membership() {
    // Pure 2a/2b: no membership -> no sweep, Established peers untouched.
    let (mut pm, tag) = pm_with_established_peer([1u8; 32], [2u8; 32], 100);
    pm.tick(500_000);
    assert_eq!(established_tag(&pm, 0), Some(tag), "membership-off: sweep is a no-op");
}
```

- [ ] **Step 6: Run to verify the sweep test fails**

Run: `cargo test -p yipd --bin yipd tick_sweep_drops_established_peer_with_expired_cert`
Expected: FAIL — no sweep exists.

- [ ] **Step 7: Implement the sweep in `tick_dispatch`**

Add a periodic cert-liveness sweep to `tick_dispatch`, **throttled** to at most once per `rekey_interval_ms` (each `member_cert_valid` does an Ed25519 `verify_cert`, and `tick` can run often on the busy-poll path — do not verify every Established peer every tick). Add a `last_cert_sweep_ms: u64` field to `PeerManager` (init `0` in `new`), and gate the sweep on the interval. Two-phase collect-then-drop so the `membership` borrow ends before `drop_session`:

```rust
// ── #41 cert-liveness sweep: drop any Established mesh peer whose cert has
// expired / been revoked (roots exempt), so a revoked member loses its
// session within a rekey interval rather than at process restart. Throttled
// to once per rekey interval (verify_cert is not free). No-op when membership
// is disabled (pure 2a/2b).
if self.membership.is_some()
    && now_ms.saturating_sub(self.last_cert_sweep_ms) >= self.rekey_interval_ms
{
    self.last_cert_sweep_ms = now_ms;
    let now_s = now_secs();
    let m = self.membership.as_ref().expect("checked is_some above");
    let stale: Vec<usize> = self
        .peers
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            matches!(p.state, PeerState::Established(_)) && !m.member_cert_valid(&p.pubkey, now_s)
        })
        .map(|(i, _)| i)
        .collect();
    for i in stale {
        self.drop_session(i);
    }
}
```

Place this block once per `tick_dispatch` invocation, before or after the per-peer escalation loop (not inside it). The `m` borrow ends when `stale` is built, so the subsequent `self.drop_session(i)` (which needs `&mut self`) does not conflict. Note the tests drive `tick` at a time well past `rekey_interval_ms` (default 120_000 ms, or set `YIP_REKEY_INTERVAL_MS` low) so the throttle does not suppress the swept behavior — `tick_sweep_drops_established_peer_with_expired_cert` calls `pm.tick(500_000)`, comfortably past the first interval from `last_cert_sweep_ms = 0`.

- [ ] **Step 8: Run the sweep tests — verify they pass**

Run: `cargo test -p yipd --bin yipd tick_sweep_`
Expected: both PASS.

- [ ] **Step 9: Full suite + clippy + fmt, then commit**

```bash
cargo test -p yipd --bin yipd
cargo clippy -p yipd --all-targets -- -D warnings
cargo clippy -p yipd --bin yipd -- -D warnings   # covers membership.rs too
cargo fmt
git add bin/yipd/src/peer_manager.rs bin/yipd/src/membership.rs
git commit -m "fix(hardening.41): periodic member cert-liveness sweep (roots exempt)"
```
Expected: all green.

---

### Task 4: netns money tests (#36 convergence + #41 revocation) + CI

**Files:**
- Create: `bin/yipd/tests/run-netns-pathswitch-rehandshake.sh` (#36)
- Create: `bin/yipd/tests/run-netns-cert-revocation.sh` (#41)
- Modify: `.github/workflows/integration.yml`
- Test: the two scripts (run under `sudo`, both drivers)

**Interfaces:**
- Consumes: the release `yipd` binary + `yip-rendezvous` binary; the existing netns helpers in the sibling scripts (`run-netns-relay.sh` topology, `run-netns-rekey.sh` cadence + driver parameterization, `run-netns-discovery.sh` for the mesh/cert setup used by #41).

- [ ] **Step 1: Read the fork sources**

Read `bin/yipd/tests/run-netns-relay.sh` (relay-forced 3-netns topology: A/B/R, no direct A↔B, R drops punch → blind relay), `bin/yipd/tests/run-netns-rekey.sh` (both-driver parameterization via `YIP_USE_URING`, `set -euo pipefail`/`trap` cleanup, ping-loss parsing, `[PASS]`/`[FAIL]` conventions), and `bin/yipd/tests/run-netns-discovery.sh` (mesh CA/cert/roots config + `yip-ca` cert minting, short cert validity).

- [ ] **Step 2: Write `run-netns-pathswitch-rehandshake.sh` (#36)**

Reproduce the #36 scenario: A and B rendezvous-only; arrange for B to adopt the responder role and go `Established` while B→A's `HandshakeResp` is lost through A's punch window, forcing A to escalate to the relay. With the fix, A **converges** (its ping to B succeeds) instead of black-holing. Concretely: block the direct + punch A↔B paths (as `run-netns-relay.sh` does) but allow B to see A's initial Init and reply (so B goes Established) while dropping that first reply to A for the punch window; then a steady `ping -i 0.2 -c 50` A→B must reach ≥98% delivery once A relay-escalates and completes via B's cached_resp. `set -euo pipefail`, `trap` cleanup of the three namespaces + daemons. Assert: (1) A reaches `Established` (grep A's stderr for a session-up marker, or the ping succeeds), (2) ping ≥98% delivered (convergence), (3) fail (`exit 1`) if A never converges within the window. Run for BOTH drivers (read `YIP_USE_URING` from env, pass through to the daemons).

If deterministically dropping "only B→A's first resp through the punch window" is impractical in netns, an acceptable equivalent: force the escalation path (block direct+punch so both peers must relay) and assert A converges over the relay with the SAME ephemeral it started with — grep both daemons' stderr to confirm A completed without a fresh cold-start cycle (no repeated give-up/restart log lines). Document which variant you implemented in the script header.

- [ ] **Step 3: Write `run-netns-cert-revocation.sh` (#41)**

Fork `run-netns-discovery.sh`'s mesh setup: two mesh members A and B with CA-signed certs (`yip-ca`), a short cert validity window (e.g. `not_after` a few seconds out) and a low `YIP_REKEY_INTERVAL_MS` (e.g. 2000). Establish A↔B (ping succeeds), then let A's cert **expire** (do not renew it in the directory). Within one rekey interval after expiry, B must **drop** its session to A: assert that a steady ping A→B that was flowing STOPS being delivered (or B's stderr logs the session drop) within `~rekey_interval + cert_validity` of expiry, and that A cannot re-establish (its re-handshake is rejected at admission). `set -euo pipefail`, `trap` cleanup. BOTH drivers.

- [ ] **Step 4: Run both scripts under sudo (both drivers)**

```bash
cargo build --release -p yipd
cargo build --release -p yip-rendezvous
sudo bash bin/yipd/tests/run-netns-pathswitch-rehandshake.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-pathswitch-rehandshake.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo bash bin/yipd/tests/run-netns-cert-revocation.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-cert-revocation.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
```
Expected: `PASS`, exit 0 on all four. The arq/netns tests use the RELEASE binary — rebuild release after any yipd change. If the environment cannot run netns (sudo/namespace denied), capture the exact blocker and report DONE_WITH_CONCERNS.

- [ ] **Step 5: Wire CI + commit**

Add both scripts to `.github/workflows/integration.yml` alongside the sibling netns steps (both drivers, same SKIP/`[FAIL]` honesty guards as the `run-netns-rekey.sh` steps).

```bash
chmod +x bin/yipd/tests/run-netns-pathswitch-rehandshake.sh bin/yipd/tests/run-netns-cert-revocation.sh
git add bin/yipd/tests/run-netns-pathswitch-rehandshake.sh bin/yipd/tests/run-netns-cert-revocation.sh .github/workflows/integration.yml
git commit -m "test(hardening): netns money tests — #36 path-switch convergence + #41 cert revocation"
```

---

## After all tasks

- Final whole-branch review (opus) over the branch delta (base = `main` at the branch point). Focus: #36's ephemeral-preservation is behavior-preserving for the non-escalation paths (the Idle/cold path still `begin_handshake`s fresh; the 90 s give-up is unchanged); the relay re-target's `endpoint` clear preserves the anti-mismatch invariant; #41's `drop_session` removes ALL of a peer's `by_tag` entries (no stale tag routes to a dropped peer); both fixes are byte-identical no-ops with membership off / no handshake in flight; the sweep exempts roots.
- Push; open a PR based on `main`. Leave it for the user; do NOT merge; no "not merging" line.
- Update the `yip-control-plane-status` memory (#36 + #41 resolved).

## Global test/verify discipline

- Run build/clippy/fmt and the netns money tests under BOTH the poll and `YIP_USE_URING=1` drivers; the netns tests use the RELEASE `yipd` — rebuild release after every yipd change or you test a stale binary.
- The full 2a/2b/2c + 9a/#91 netns suite (triangle, relay, discovery, admission-reject, root-outage, rekey, relay-rekey) must stay green; membership-off runs must be byte-identical.
