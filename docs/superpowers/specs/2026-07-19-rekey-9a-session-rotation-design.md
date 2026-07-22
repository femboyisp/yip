# Milestone 9a — classical session rekey (~120s rotation) + epoch handling — design spec

**Date:** 2026-07-19
**Status:** design (pending user review)
**Issue:** #9 (session rekey + PQ-hybrid handshake) — this spec is **9a (classical rekey)**; PQ-hybrid is **9b**, a separate later cycle.
**Scope:** `bin/yipd` (the real work: rekey scheduling + epoch state/routing in `PeerManager`/`DataPlane`) + minimal `yip-crypto`/`handshake` surface. No wire-format change.

## Goal

The daemon does one Noise-IK handshake per peer at session start and never rekeys, so a session's keys (and its `conn_tag`) live forever. 9a adds **~120s session rotation** for forward secrecy: each peer periodically runs a fresh mid-session Noise-IK handshake, producing a new **epoch** (fresh keys, fresh `conn_tag`, fresh counter + replay window). An **overlap window** keeps the previous epoch alive for inbound so in-flight packets still decrypt across the switch. `conn_tag` rotates per epoch — the linkability fix (an observer no longer sees one stable 64-bit tag per peer for the connection's lifetime) falls out for free.

## Non-goals (explicit)

- **PQ-hybrid handshake (McEliece + ML-KEM → PSK)** — that is **9b**, built on this milestone's rekey machinery.
- **Full handshake anti-replay / authenticated endpoint learning (#34)** — its endpoint-hijack half is already mitigated by 2b's "endpoint committed only by a completed Noise handshake" invariant; the remaining timestamp-anti-replay is a separate hardening piece. 9a includes only a minimal rekey-local DoS guard (below), not #34.
- **#36 (path-switch half-open), #41 (revocation lag)** — these benefit from rekey existing but are not implemented here.
- **No wire-format change.** An explicit epoch/key-id field in the header would be a fresh, near-static byte for a DPI to fingerprint — regressing the anti-DPI work. The `conn_tag` (already per-epoch and header-protected) is the epoch discriminator.

## Background (current state)

- `yip-crypto`: a `Handshake` (Noise-IK via `snow`) → `into_session()` → a `Session` with fresh send/recv keys, `send_counter = 0`, and a fresh WireGuard-style `ReplayWindow`. A new handshake is a new `Session` — the mechanism already exists.
- `bin/yipd/src/handshake.rs`: `run_initiator`/`run_responder` (and the `start_initiator`/`read_response`/`start_responder` step-functions) yield an `Established { session, auth_key, hp_key, remote_static }`, from which `DataPlane::from_established` builds a `DataPlane` that owns the `Session`, the `yip_wire::Codec`, and the derived `conn_tag` (`conn_tag_from_keys(auth_key, hp_key)`).
- `bin/yipd/src/peer_manager.rs`: `PeerState` per peer is `Idle` → `Handshaking(Box<Handshaking>)` → `Established(Box<DataPlane>)`. Inbound is demuxed **by source address → peer**, then that peer's `DataPlane` opens the frame (AEAD-authenticated). Glare (both sides initiating at once) is resolved by static-key order. `HANDSHAKE_RETRY_MS = 1000`, `HANDSHAKE_TOTAL_MS = 90_000`.

## Design

### 1. Epoch set — `Established` holds up to three epochs

Replace `PeerState::Established(Box<DataPlane>)` with `PeerState::Established(Box<EpochSet>)`:

```rust
struct EpochSet {
    /// The epoch used for OUTBOUND (the newest confirmed epoch).
    current: Box<DataPlane>,
    /// When `current` was installed (monotonic ms) — drives the rekey schedule.
    current_created_ms: u64,
    /// Responder only: a new epoch derived from a received rekey Init but NOT yet
    /// used for sending — promoted to `current` on the first inbound frame that
    /// decrypts under it (confirming the peer switched). `None` otherwise.
    next: Option<Box<DataPlane>>,
    /// The just-superseded epoch, kept RECEIVE-ONLY through the grace window so
    /// in-flight/reordered old-epoch frames still open. Retired at `previous_retire_ms`.
    previous: Option<Box<DataPlane>>,
    previous_retire_ms: u64,
    /// Initiator only: an in-flight rekey handshake (retransmit Init until Resp or
    /// give up). `None` when no rekey is in flight. Caps rekey to ONE in flight.
    rekey: Option<RekeyInFlight>,
}

struct RekeyInFlight {
    handshake: Handshaking,   // the same step-function state used for cold-start
    init_pkt: Vec<u8>,        // retransmitted every HANDSHAKE_RETRY_MS
    started_ms: u64,
    last_sent_ms: u64,
}
```

At most three `DataPlane`s coexist briefly: `current`, `next` (responder mid-switch), `previous` (grace). Outside a rekey, only `current` exists.

### 2. Inbound routing — try current, then next, then previous

`PeerManager` already routes an inbound datagram to a peer by source address. Within the peer, try the epochs in order and use whichever authenticates (each `DataPlane::on_udp_datagram` fails closed on a wrong key, so a mismatch is a cheap failed AEAD/MAC, not a misdecrypt):

1. `current` — the common case (steady state: one try).
2. `next` (if present) — a **successful** open here means the peer has switched to the new epoch → **promote** (§4, responder path).
3. `previous` (if present and not yet retired) — in-flight old-epoch frames during overlap.

Only during the few-second overlap are there 2–3 tries; steady state is one. No wire change; `conn_tag` (per-epoch) is what makes the epochs distinguishable to their own codecs.

### 3. Rekey scheduling + trigger (initiator side)

In `PeerManager::tick` (the existing per-peer time-driven pass), for each `Established` peer:

- **Trigger:** `now - current_created_ms >= REKEY_INTERVAL_MS` (120_000) AND `rekey.is_none()` AND **this side is the glare-winner** (the same static-key-order tiebreak the cold-start handshake uses, so only one side initiates and both don't rekey simultaneously).
- **Loser fallback (asymmetric-liveness safety):** if the glare-*loser* observes `current` aging past a hard ceiling (`2 × REKEY_INTERVAL_MS`) with no rekey — the winner is silent/dead but this side still carries traffic — the loser initiates instead, so rotation can't stall on a one-sided-silent winner. (In the common case the winner rekeys first and the loser only ever responds; a genuinely idle session carries no traffic and needs no rotation.)
- **Start:** build a fresh initiator `Handshaking` for the peer's `remote_static`, send its Init, set `rekey = Some(RekeyInFlight{..})`. The current session keeps carrying traffic throughout — **rekey never interrupts the live session.**
- **Retransmit / give up:** identical to cold-start — resend `init_pkt` every `HANDSHAKE_RETRY_MS`, abandon the rekey attempt after `HANDSHAKE_TOTAL_MS` (set `rekey = None`, keep `current`, retry at the next interval). A failed rekey is never fatal: the session keeps running on the current epoch.

**One-rekey-in-flight DoS guard (the only #34-adjacent hardening in 9a):** `rekey.is_some()` blocks starting another; a replayed/spoofed rekey Init cannot make a peer thrash into repeated speculative handshakes because (a) the responder already holds at most one `next`, and (b) a fresh `next` is only derived when the current epoch is at least, say, `REKEY_INTERVAL_MS/2` old (ignore rekey Inits against a very fresh `current`). This bounds attacker-induced handshake CPU without full timestamp anti-replay.

### 4. The outbound-switch policy (WireGuard confirmed-switch)

In Noise-IK the responder derives the new session when it processes the Init (as it sends msg2); the initiator derives it on reading msg2. The switch is asymmetric so it survives a lost msg2:

- **Initiator, on rekey completion (read the Resp):** it now holds the new epoch AND knows the responder installed it (the responder sent the Resp). **Switch outbound immediately:** `previous = Some(current)`, `previous_retire_ms = now + PREVIOUS_EPOCH_GRACE_MS`, `current = <new epoch>`, `rekey = None`. Send the next outbound frame (or, if idle, one cover/keepalive frame) on the new epoch to prompt the responder's switch.
- **Responder, on receiving a rekey Init from an already-`Established` peer:** run the responder step → a new `DataPlane`; store it as `next` (do **not** switch sending yet); reply with the Resp. Keep sending on `current`.
- **Responder, on the first inbound frame that decrypts under `next` (§2 step 2):** the initiator has completed and switched → **promote:** `previous = Some(current)`, `previous_retire_ms = now + GRACE`, `current = next.take()`, `next = None`.

If msg2 is lost: the initiator never completes (stays on the old epoch, retries the Init); the responder holds a `next` it never promotes (both sides still on the old epoch — no black-hole). The stale `next` is dropped when a later rekey supersedes it or on peer teardown.

### 5. Overlap, retirement, and conn_tag rotation

- **`previous`** is receive-only and retired when `now >= previous_retire_ms` (`PREVIOUS_EPOCH_GRACE_MS`, e.g. 15_000 — generous vs. reordering/loss, bounded). Retiring = drop the `DataPlane` (and its keys).
- **`conn_tag`** rotates automatically: the new epoch's `DataPlane` derives a new `conn_tag` from its own keys. `PeerManager`'s `conn_tag → peer` map (kept for tests/logging) is updated on promotion; routing itself stays source-address-primary, so no lookup depends on the old tag.
- **`obf`/cover-traffic (3b) and path state (2b)** are per-peer, not per-epoch — unchanged across rekey. Only the `DataPlane`/`Session`/`Codec`/`conn_tag` rotate.

### 6. `yip-crypto` / `handshake.rs` surface (minimal)

The rotation is entirely daemon-driven; `yip-crypto` already exposes everything needed (`Handshake` → `into_session` → `Session`). The only additions are in `bin/yipd`:
- `DataPlane` gains no new field (its creation time is tracked by `EpochSet.current_created_ms` in `PeerManager`, where the schedule lives).
- Reuse `handshake.rs`'s existing initiator/responder step-functions verbatim for the rekey handshake — a rekey is a normal handshake whose result happens to install into an existing `EpochSet` rather than a fresh `Idle` peer.

## Error handling (fail-closed, never drop a working session)

- A rekey handshake that fails/times out → `rekey = None`, **keep `current`**, retry next interval. Rekey failure must never tear down a working session.
- A rekey Init that arrives for a non-`Established` peer is the ordinary cold-start path (unchanged).
- Glare during rekey (both timers fire): the static-key loser defers — it accepts the winner's rekey Init as responder (deriving `next`) and abandons/does-not-start its own initiator rekey, exactly as cold-start glare resolves.
- All epoch `DataPlane`s fail closed on inbound (wrong-key → failed AEAD → try next epoch; no misdecrypt, no panic on attacker bytes — the existing `DataPlane::on_udp_datagram` guarantees hold per epoch).
- Counter/replay are per-epoch (per `Session`); a counter value is only meaningful within one epoch's `DataPlane`, so the "counter resets on rekey" ambiguity cannot cause a cross-epoch replay accept.

## Testing / adversary

- **Unit (pure/fast):** epoch routing (`EpochSet` tries current→next→previous, uses the one that authenticates); the WireGuard switch state machine (initiator promotes on completion; responder derives `next` on Init and promotes on first `next`-decrypt; lost-msg2 leaves both on old epoch, no black-hole); `previous` retirement at the grace deadline; the one-rekey-in-flight guard (a second rekey trigger while one is in flight is a no-op; a rekey Init against a too-fresh `current` is ignored).
- **netns money tests (sudo, both poll + `YIP_USE_URING=1` drivers, CI-gated — the repo's standard bar):**
  - **rekey_continuity:** two peers exchange a steady packet stream while the rekey interval is set low (test override, e.g. 2s) for several rotations; assert **zero** application-visible packet loss across each rotation and that the on-wire `conn_tag` actually changes between epochs (linkability rotation observed).
  - **rekey_under_loss:** the same with netem loss on the path during the rekey window; assert the session survives (old epoch covers in-flight; a lost msg2 just retries) and traffic continues.
  - **rekey_conn_tag_rotates:** capture datagrams across a rotation; assert the header `conn_tag` (as an observer sees the masked header change) differs pre/post rotation for the same peer.
- **No regression:** the existing 2a/2b/2c netns money tests (triangle, relay/punch, discovery) stay green with rekey enabled at the production interval.

## Risks

- **State-machine complexity** (three coexisting epochs, asymmetric switch). Mitigation: keep the WireGuard model verbatim (well-understood), model it as a small pure `EpochSet` state machine that's unit-tested independently of I/O, and make rekey-failure a no-op on the live session.
- **Overlap window sizing:** too short → reordered old-epoch frames dropped mid-switch; too long → keys linger. Mitigation: `PREVIOUS_EPOCH_GRACE_MS` generous-but-bounded (≈15s), a named tunable constant.
- **Interaction with cover-traffic/obf timing (3b):** the extra rekey handshake packets must not create a new timing tell. Mitigation: rekey Init/Resp ride the same obf envelope + jittered send timing as cold-start handshakes (reuse the existing path), so they are not a new fingerprint.

## Success criteria

1. An `Established` peer runs a fresh Noise-IK handshake ~every `REKEY_INTERVAL_MS` (120s), producing a new epoch, **without interrupting** the live session; rekey failure is a no-op that retries.
2. Inbound decrypts across the switch with zero application-visible loss (old epoch covers in-flight); outbound follows the WireGuard confirmed-switch (initiator on completion, responder on first new-epoch inbound); lost-msg2 does not black-hole.
3. `conn_tag` rotates per epoch (linkability fix), verified on the wire; each epoch has its own counter/replay window with no cross-epoch replay accept.
4. A replayed/spoofed rekey Init cannot force repeated speculative handshakes (one-in-flight + too-fresh-current guard).
5. No wire-format change; no `as`/`unsafe`/bare-`allow`; clippy clean. netns rekey-continuity + rekey-under-loss pass on both drivers; existing 2a/2b/2c tests stay green.
6. PQ-hybrid (9b), full #34, #36, #41 are **out of scope** and untouched.
