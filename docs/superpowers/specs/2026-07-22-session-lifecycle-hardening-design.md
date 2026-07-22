# Session-lifecycle hardening (#36 + #41) — design spec

**Date:** 2026-07-22
**Status:** design (pending user review)
**Issues:** #36 (2b: path-switch re-initiation half-opens a session), #41 (2c: cert revocation lag exceeds cert lifetime without session rekey).
**Depends on:** session rekey (9a PR #90 + #91 PR #92, both merged to `main`) — the epoch/rekey machinery and the idempotent-ephemeral `cached_resp`/`accept_rekey_init` logic these fixes build on.
**Scope:** `bin/yipd/src/peer_manager.rs` (both fixes) + a small read-only helper on `bin/yipd/src/membership.rs` (#41). No wire-format change; `yip-crypto`/`yip-wire`/`handshake.rs` unchanged. Both fixes are **no-ops when membership is `None`** (#41) or when no handshake is in flight (#36) — 2a/2b/2c byte-identical otherwise.

## Goal

Two residual limitations, both filed as "needs session rekey," are now unblocked by the merged rekey machinery:

- **#36** — a path switch (Punch→Relay, Punch(C1)→Punch(C2), Direct→Relay …) re-initiates the handshake with a **fresh** Noise ephemeral. If the remote already adopted the responder role and is `Established`, it only replays a `cached_resp` keyed to our *original* ephemeral; our `read_response` fails, we revert to `Idle` and re-escalate — a silent bidirectional black hole with the remote falsely "up," recoverable only by process restart.
- **#41** — a cert-admitted mesh peer's `Established` session persists for the daemon's lifetime. Rekey re-uses the session identity without re-checking the cert, and a revoked (non-renewed, cert-expired) member keeps its live session until process restart.

Fix both so a path-switching peer converges (#36) and a revoked member's session drops within a rekey interval (#41).

## Background (current state, from `peer_manager.rs`)

- **`HandshakingState`** holds `hs: HandshakeState` (the Noise state, holding the one drawn ephemeral), `init_pkt: Vec<u8>` (the framed `[HandshakeInit]`, "resent verbatim on retry"), `target: SocketAddr`, plus retransmit bookkeeping. The peer's `relay: bool` selects relay-wrapped vs direct egress. The retransmit arm in `tick_dispatch` already resends `init_pkt` to `target` (relay-wrapped when `relay`).
- **Path re-target today:** the escalation arms (`PathAction::Probe(addr) if addr != target` ~2646; the `Probe`/`Relay` arms in the escalation helpers ~935/982/2197/2546) do `state = PeerState::Idle; begin_handshake(idx, new_addr, via_relay, now_ms)` — and `begin_handshake` calls `start_initiator`, drawing a **fresh** ephemeral. That fresh ephemeral is the #36 bug.
- **`rekey_init_core`** decision tree for an `Established` peer receiving a `[HandshakeInit]`: (1) `init_eph == cached_resp_init_eph` → replay `cached_resp` (cold-start retransmit); (2) `next_cached_resp_for(init_eph)` → replay cached rekey resp; (3) `!accept_rekey_init` (current < interval/2 old) → replay `cached_resp`, no new session; (4) else install `next`. So resending the **same** `init_pkt` (original ephemeral) over a new path hits case (1) and completes us — the mechanism #36's fix relies on.
- **`HANDSHAKE_TOTAL_MS`** (90 s) give-up already reverts a doomed attempt to `Idle`; the next attempt is then legitimately fresh.
- **Cert admission:** cold-start `handle_handshake_init` verifies the initiator's cert payload (`verify_cert` against `remote_static` at `now_secs()`) and admits/rejects pre-session; `responder_cert_ok(payload, peer_pub)` is the existing helper (returns `true` when membership is `None`). The **rekey** arms currently discard `_initiator_payload` — no re-verification.
- **Membership** (`membership.rs`): the directory holds `Record`s (each carrying a `Cert`) keyed by `node_id`, with an expiry sweep that evicts expired records. `verify_cert(&cert, &static_key, now)` and `resolve(&Ipv6Addr)` exist; there is no by-pubkey cert-validity check yet.

## Design

### Fix #36 — preserve the in-flight ephemeral across a path re-target

Add a helper that re-points an **already in-flight** handshake at a new path without minting a fresh ephemeral:

```rust
/// Re-point an in-flight handshake at `new_target` over the given path,
/// PRESERVING the Noise ephemeral (resend the existing `init_pkt`), so a
/// responder that already adopted us on the old path completes us via its
/// `cached_resp` (#36). Falls back to a fresh `begin_handshake` only when no
/// handshake is in flight (Idle/cold). Returns the egress to emit, if any.
fn retarget_handshake(
    &mut self,
    idx: usize,
    new_target: SocketAddr,
    via_relay: bool,
    now_ms: u64,
) -> Option<Vec<EgressDatagram>>;
```

Behavior:
- **Peer is `Handshaking`:** mutate the existing `HandshakingState` in place — set `target = new_target`, set the peer's `relay = via_relay` — leaving `hs` and `init_pkt` untouched (the ephemeral is preserved). Emit the existing `init_pkt`: relay-wrapped via `relay_wrap(idx, init_pkt.clone())` when `via_relay` (a `None` skips this send; the retransmit arm retries) **and clear `endpoint = None`** (a late direct Resp for this same ephemeral must not complete us onto a now-`relay`-flagged peer — the #91 mismatch class); else `EgressDatagram { fate: 0, dst: new_target, bytes: init_pkt.clone() }` **and re-stamp `endpoint = Some(new_target)`** (as `begin_handshake`'s direct branch does — `handle_handshake_resp` matches an inbound Resp against `endpoint == Some(src)`, so a Resp from the new candidate must find the peer). Do **not** reset `started_ms` (the 90 s give-up clock keeps running across re-targets — a re-target does not buy a fresh 90 s), but **do** reset `last_sent_ms = now_ms` so the retransmit arm does not fire an immediate redundant copy of the just-resent Init (which would also break anti-DPI timing jitter).
- **Peer is `Idle` (or otherwise not `Handshaking`):** delegate to `begin_handshake(idx, new_target, via_relay, now_ms)` (fresh ephemeral) — unchanged from today.

Replace the "`state = Idle; begin_handshake(new_addr)`" re-target pattern at the escalation/re-target arms with `retarget_handshake`. The cold-start entry points (`on_tun`'s Idle branch, initial `begin_handshake`) are unchanged — only *re-targets of an in-flight attempt* change.

**Why this is safe (no new attack surface):** resending the same `init_pkt` is exactly what the retransmit arm already does every `HANDSHAKE_RETRY_MS`; the only change is that the destination/path may differ. A responder that is `Established` replays its `cached_resp` (case 1) and we complete; a responder that never adopted us treats it as a fresh cold-start `Init` and adopts us normally. No responder-side gate (`accept_rekey_init`) is touched, so the 9a anti-hijack posture and the #34 anti-replay question are untouched. Ephemeral reuse remains bounded by the unchanged 90 s `HANDSHAKE_TOTAL_MS` give-up.

**Responder-side relay adoption (required to close the headline scenario).** Ephemeral preservation fixes A's side, but #91's path-consistency gate blocks B's: `relayed_handshake_init`'s `Established` arm only completes when `peers[idx].relay` is already `true`, and B (adopted as responder over *punch*) is `relay == false`, so B fail-closed-drops A's relayed Init instead of replaying `cached_resp`. And even if B replayed, B's egress would stay direct to A's now-dead punch address (the reverse black hole). So the `Established` arm gains one adoption case: **a direct-established peer (`relay == false`) receiving a relayed cold-start RETRANSMIT of the Init that built our session — `init_eph == cached_resp_init_eph` — adopts the relay for our egress (`peers[idx].relay = true`) and lets `rekey_init_core` case (1) replay `cached_resp` over the relay.** So B→A data now flows over the relay too. A relayed Init with a *new* ephemeral (a genuine rekey, or an attack) against a direct peer is NOT adopted — it stays fail-closed (`DispatchOut::None`), preserving #91's guard for the session-churning case. `cached_resp_init_eph` is set only on a responder cold-start, so this applies exactly to the responder-adopter that #36 describes; an initiator-established peer (no cached resp) fails closed.

The adopted arm becomes (replacing the two-arm gate):

```rust
PeerState::Established(_) => {
    let Some(init_eph) = crate::handshake::init_ephemeral(dg) else {
        return DispatchOut::None; // malformed Init
    };
    // #36: a relayed cold-start RETRANSMIT of the Init that built our session
    // means the initiator moved to relay-only — adopt the relay for our egress
    // so B->A also flows over it (else B keeps sending to A's dead punch addr).
    if !self.peers[idx].relay && self.peers[idx].cached_resp_init_eph == Some(init_eph) {
        self.peers[idx].relay = true;
    }
    if self.peers[idx].relay {
        self.rekey_init_core(idx, established, resp_pkt, init_eph, now_ms, self.server_addr(), true)
    } else {
        DispatchOut::None // new-ephemeral relayed Init vs a direct peer: #91 fail-closed
    }
}
```

**Security tradeoff (accepted).** An attacker who captures A's original punch Init (E1) can replay it over the relay to force B to adopt the relay for A (a path *downgrade*, direct→relay). This is a bounded DoS — data still reaches the *real* A (`relay_wrap` addresses A's registered node via the server, not the attacker), no hijack, `current`'s session keys unchanged — of the same class as the #34 anti-replay gap. Two precise consequences, both accepted (they ride with #34, an authenticated endpoint):
- **The downgrade is persistent for the session's life,** not transient: `relay` is reset to `false` for a live peer only on a fresh `Handshaking → Established` transition over direct (a full re-establishment), which rekey never routes through. So once forced, B routes A over the relay until the session tears down.
- **It also degrades direct rekey.** Once `relay == true`, `handle_handshake_init`'s `PeerState::Established(_) if !self.peers[idx].relay` gate makes B fail-closed-drop A's *direct* rekey Inits, so rekey with A can only proceed over the relay (or, if A is the rekey initiator over direct, is denied — `current` survives, rotation is delayed). No data loss (A→B direct data still decrypts by `conn_tag` regardless of `relay`; B→A flows over the relay).

A *rekey* Init arriving over the relay after A moved (new ephemeral, ~120 s later) is a distinct, rarer residual not covered here — it also rides with #34.

**Data flow (the reported #36 scenario, now converging):** A and B rendezvous-only; B adopts responder over punch and is `Established` (`relay == false`, `cached_resp_init_eph == E1`), but B→A `HandshakeResp` is lost through A's `PUNCH_MS` window. A escalates to relay: `retarget_handshake(idx, server, via_relay = true)` re-points A's in-flight `Handshaking(E1)` at the relay and resends `init_pkt(E1)` relay-wrapped. B receives it; the `Established` arm sees `init_eph == cached_resp_init_eph` on a `relay == false` peer → adopts `relay = true` → `rekey_init_core` case (1) replays `cached_resp(E1)` relay-wrapped. A `read_response(E1)` succeeds → A `Established` (relay). Both directions now flow over the relay. Converged.

### Fix #41 — cert re-verification on rekey + periodic liveness sweep

Two complementary mechanisms; both are no-ops when `membership.is_none()`.

**(a) Re-verify the cert in a received rekey `Init`.** In the `Established`/rekey arms of `handle_handshake_init` and `relayed_handshake_init`, stop discarding the initiator payload: run `responder_cert_ok(initiator_payload, remote_static)`. On failure (a revoked/expired member presenting a stale or invalid cert), **reject the rekey and drop the live session**: revert the peer to `PeerState::Idle` and remove its `current` `conn_tag` from `by_tag`. Do not emit a resp. A valid cert proceeds through the normal rekey path unchanged.

**(b) Periodic cert-liveness sweep.** Add a read-only helper to `Membership`:

```rust
/// Whether `pubkey` is still an admissible member at wall-clock `now`:
/// `true` if it is an always-admit root, OR the directory holds a valid
/// (unexpired, verifying) cert for it. `false` only when a non-root member's
/// record has been evicted (expired) or its cert no longer verifies — i.e.
/// revoked-by-non-renewal. Used by the Established-mesh-peer liveness sweep
/// (#41). Folding the root check in here keeps roots exempt (they have no
/// directory-cert dependency — they would otherwise be swept spuriously).
pub fn member_cert_valid(&self, pubkey: &[u8; 32], now: u64) -> bool;
```

In `tick`, on the same cadence the rekey scheduler already runs (a periodic sweep at roughly the rekey interval; exact cadence fixed in the plan), for each `Established` peer in a mesh deployment (`membership.is_some()`), call `member_cert_valid(&peer.pubkey, now_secs())`. If it returns `false`, **drop the session** (revert to `Idle`, remove the `by_tag` entry). This catches the case (a) misses: a revoked peer that is the rekey *loser* and never sends an `Init`.

**Only cert-dependent peers are affected.** In mesh mode every `Established` peer was admitted by a verified cert (cold-start admission runs `verify_cert` when `membership.is_some()`), so `member_cert_valid` holds for every legitimately-admitted peer and returns `false` only once that cert lapses. Always-admit **roots** are exempt via the helper's root check (they have no directory-cert to expire). The sweep is a whole no-op when `membership.is_none()` — a pure 2a/2b deployment has no certs and no sweep.

**Re-admission is already guarded.** A dropped revoked peer cannot re-establish: the cold-start admission path re-verifies the cert (`verify_cert` at `handle_handshake_init`), which a revoked/expired member fails. So dropping to `Idle` + clearing `by_tag` is sufficient; the peer simply can no longer handshake.

## Error handling

- **#36:** a `relay_wrap` `None` (no rendezvous) on re-target skips only that send — the peer stays `Handshaking`, the retransmit arm retries next tick, and the 90 s give-up still bounds the attempt. No panic; no session torn down (there is no live session — the peer is mid-handshake).
- **#41:** a malformed/missing cert payload on rekey → `responder_cert_ok` returns `false` → treated as an invalid cert → session dropped (fail-closed: an unverifiable rekey does not keep the session alive). The sweep's `member_cert_valid` returning `false` for a transiently-absent record (e.g. a not-yet-gossiped renewal) would drop a still-valid peer's session; mitigated by the existing `CERT_VALIDITY_SKEW` widening and the fact that a dropped valid peer simply re-handshakes and re-admits with its current cert (availability blip, not a black hole). Both fixes are no-ops when membership is disabled.

## Testing / adversary

- **#36 unit:** (1) a `Handshaking` peer re-targeted from direct to relay resends the **byte-identical** `init_pkt` (ephemeral preserved), not a fresh one, and updates `target`/`relay`; `started_ms` is unchanged. (2) An `Established` responder holding `cached_resp` for `E1` completes a re-targeted initiator that resends `init_pkt(E1)` over the relay. (3) An `Idle` peer re-targeted falls through to a fresh `begin_handshake`.
- **#41 unit:** (1) a rekey `Init` carrying an expired/invalid cert drops the session (peer → `Idle`, `by_tag` entry gone, no resp); a valid cert rekeys normally. (2) `member_cert_valid` is `true` for a live record, `false` after the record expires/evicts. (3) the tick sweep drops an `Established` mesh peer whose directory record expired and leaves a valid one untouched. (4) all #41 paths are no-ops when `membership` is `None`.
- **netns money tests:** (#36) reproduce the reported scenario — block B→A `HandshakeResp` through A's punch window, force the relay escalation — and assert A **converges** (ping succeeds, no black hole) instead of looping to give-up. (#41) a mesh member whose cert expires mid-session loses its session within a rekey interval (its traffic stops being delivered; re-handshake is rejected at admission). Both drivers (poll + `YIP_USE_URING=1`); release `yipd`.
- **Regression:** the 2a/2b/2c and 9a/#91 netns suites (triangle, relay, discovery, rekey, relay-rekey) stay green; membership-off runs are byte-identical.

## Risks

- **#36 touches the security-critical escalation path.** Mitigation: the change is a strict narrowing — re-target now preserves the ephemeral (resend the same `init_pkt`, which the retransmit arm already does) instead of minting a fresh one; no responder-side gate changes; the full 2b escalation netns suite is the regression net. The 90 s give-up (unchanged) still forces a fresh ephemeral for a genuinely dead attempt.
- **#41 sweep could drop a still-valid peer** if its renewed record has not yet gossiped in. Mitigation: `CERT_VALIDITY_SKEW` widening + the drop is a recoverable re-handshake, not a black hole; the sweep runs at the coarse rekey cadence, not per-packet.
- **#41 (a) and (b) overlap** for the rekey-winner case (both would drop a revoked initiator). Harmless — dropping an already-dropped/Idle session is idempotent; (b) exists for the loser case (a) cannot see.

## Non-goals

- #34 (anti-replay timestamp + authenticated endpoint) — not required by approach C for #36; the age gate is untouched. Filed separately.
- Active revocation lists / a revocation gossip message — #41 uses revocation-by-cert-expiry (the 2c model); an explicit revocation channel is out of scope.
- Session roaming (migrating an `Established` peer to a new path without a re-handshake) — a separate feature; #36 is specifically the mid-handshake escalation black hole.

## Success criteria

1. A path-switching peer whose responder is already `Established` **converges** (completes over the new path via the responder's `cached_resp`) instead of black-holing; ephemeral preserved across re-targets, fresh only after the unchanged 90 s give-up.
2. A rekey `Init` with an invalid/expired cert drops the live session; a periodic sweep drops an `Established` mesh peer whose cert has expired/been revoked — so a revoked member loses its session within a rekey interval, not at process restart.
3. Both fixes are no-ops with membership disabled and when no handshake is in flight (2a/2b/2c byte-identical); no wire-format change; `yip-crypto`/`yip-wire`/`handshake.rs` unchanged.
4. `forbid-unsafe`; no `as` casts (except the pre-existing `PacketType::X as u8` idiom); no bare `#[allow]`; clippy `-D warnings` clean; both-driver netns green.
