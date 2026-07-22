# Relay-path session rekey completion (#91) — design spec

**Date:** 2026-07-19
**Status:** design (pending user review)
**Issue:** #91 (a milestone 9a follow-up).
**Depends on / stacks on:** 9a (PR #90, branch `feat/rekey-9a-session-rotation`, unmerged) — the epoch/rekey machinery + the idempotent-ephemeral Critical fix.
**Scope:** `bin/yipd` (`peer_manager.rs`). No wire-format change; `yip-crypto`/`yip-wire`/`handshake.rs` unchanged (except reusing 9a's `handshake::init_ephemeral`).

## Goal

9a rotates each peer's Noise-IK session ~every 120s for forward secrecy, but **relay-reached peers are gated out** of rekey scheduling: `drive_rekey_schedule` returns early on `relay`, because rekey *completion* was only wired into the direct handshake handlers, never the relay ones. #91 wires relay-path rekey completion so **relay-only sessions also rotate**, then removes the gate — reusing the direct path's security-critical idempotent logic rather than duplicating it.

## Background (current state, post-9a)

- **Direct rekey completion exists:** `handle_rekey_init` (an Established peer receiving a `[HandshakeInit]`: `cached_resp_init_eph` cold-start dedup → `next_cached_resp_for` rekey-retransmit dedup → `accept_rekey_init` gate → build new-epoch `DataPlane` + `install_next` + emit the Resp) and `handle_rekey_resp` (take the `RekeyInFlight` out → `read_response` → `promote_from_rekey` → update the `conn_tag → peer` map → prime the new epoch). Both emit datagrams **directly** (`EgressDatagram { dst: src, bytes }`) and build the new `DataPlane` with `peer_addr = src`.
- **Relay handlers do NOT rekey:** `relayed_handshake_init`'s `Established` arm just resends `cached_resp` (relay-wrapped) for any relayed Init; `relayed_handshake_resp` drops anything against a non-`Handshaking` peer.
- **The schedule gate:** `drive_rekey_schedule` has `if relay { return; }` at the top, and its Init emit/retransmit is direct-only (`EgressDatagram { dst: endpoint }`) — the 9a Critical fix deleted the (then-dead) relay-wrap branches once the gate made them unreachable.
- Helpers: `relay_wrap(idx, raw) -> Option<EgressDatagram>` (relay egress; `None` if no rendezvous), `server_addr() -> SocketAddr` (the relay placeholder used as a relay `DataPlane`'s `peer_addr`).

## Design

### 1. Extract the rekey-completion cores, parameterized by an egress mode

The rekey-init and rekey-resp logic is **byte-identical** between direct and relay except (a) how a datagram is emitted and (b) the new `DataPlane`'s `peer_addr`. Capture that difference in one small enum and extract two shared helpers:

```rust
/// How a rekey handler addresses its egress + the new epoch's DataPlane.
enum RekeyEgress {
    /// Direct peer: emit straight to `addr`; the new DataPlane's peer_addr = addr.
    Direct(SocketAddr),
    /// Relay-reached peer: emit via `relay_wrap`; the new DataPlane's peer_addr =
    /// `server_addr()` (a placeholder — relay egress is always re-wrapped, so it
    /// is never used as a real dst).
    Relay,
}
```

- `rekey_init_core(&mut self, idx, established, resp_pkt, init_eph, now_ms, egress: RekeyEgress) -> DispatchOut<'_>` — the current `handle_rekey_init` body, with every datagram emit routed through a small `emit(&mut self, idx, bytes, &egress) -> DispatchOut` that produces either `EgressDatagram { dst: addr, bytes }` (Direct) or `relay_wrap(idx, bytes)` (Relay; `None` ⇒ `DispatchOut::None`, a clean no-op), and the new `DataPlane`'s `peer_addr` taken from `egress` (`addr` vs `server_addr()`).
- `rekey_resp_core(&mut self, idx, dg, now_ms, egress: RekeyEgress) -> DispatchOut<'_>` — the current `handle_rekey_resp` body: take the `RekeyInFlight` out, `read_response`, build the new `DataPlane` (`peer_addr` from `egress`), `promote_from_rekey`, update the `conn_tag → peer` map, and prime the new epoch by emitting one frame through `egress`.

`handle_rekey_init`/`handle_rekey_resp` become thin wrappers passing `RekeyEgress::Direct(src)`. This keeps the **idempotent-ephemeral convergence guarantee (the 9a Critical fix) in exactly one place** — important because relay paths reorder more, making that idempotency load-bearing for relay.

### 2. Wire the relay handlers to the cores

- **`relayed_handshake_init`, `Established` arm:** it already runs `start_responder` → `(established, resp_pkt)`. Instead of blindly resending `cached_resp`, compute `init_eph = handshake::init_ephemeral(dg)` and call `rekey_init_core(idx, established, resp_pkt, init_eph, now_ms, RekeyEgress::Relay)`. The core's cold-start-`cached_resp` dedup + rekey-retransmit dedup + `accept_rekey_init` gate subsume the old unconditional-resend behavior (a cold-start Init retransmit still resends `cached_resp`; a genuine rekey Init installs `next`).
- **`relayed_handshake_resp`:** add an `Established`-with-`rekey`-in-flight branch that calls `rekey_resp_core(idx, dg, now_ms, RekeyEgress::Relay)`; the existing non-`Handshaking` drop stays for the no-rekey case.

### 3. Remove the schedule gate + restore the relay Init emit

In `drive_rekey_schedule`: delete `if relay { return; }`. For the Init send and each retransmit, emit via `relay_wrap(idx, init_pkt)` when `relay`, else the existing direct `EgressDatagram { dst: endpoint }` — the relay-wrap branches the 9a fix removed, re-added now that they're reachable. A `relay_wrap` `None` just skips that send (retransmits next tick). Same obf/jitter as the direct Init (no new fingerprint). Glare-winner tiebreak (`local_pub < peer.pubkey`), one-in-flight, loser-fallback, and give-up are unchanged — they already apply to all Established peers.

## Error handling (fail-closed — the 9a invariants hold for relay too)

- A relay rekey that can't emit (`relay_wrap` `None`, no rendezvous), whose `read_response`/admission fails, or that times out → **no-op on the live session** (keep `current`; retransmit/abandon). Rekey never tears down a working relay session.
- **Idempotency covers relay reordering:** a reordered/duplicate relay rekey Init resends the cached Resp (via `next_cached_resp_for`) rather than minting a second `next`, so the two peers converge on one session — exactly the 9a Critical-fix guarantee, now exercised on the higher-reordering relay path.
- **Residual (not reopened here):** a spoofed/stray relay `[HandshakeResp]` can abandon an in-flight rekey (rekey-liveness only — `current` untouched, session survives, rotation delayed). Same **Important-1** as the direct path; rides with #34 (authenticated endpoint).
- No panic on the connection path; the relay `DataPlane`'s `server_addr()` placeholder is never used as a real dst (relay egress is always `relay_wrap`ped), matching the cold-start relay path.

## Testing / adversary

- **Unit:** drive `rekey_init_core`/`rekey_resp_core` through `RekeyEgress::Relay`: (a) a relay rekey Init retransmit (identical ephemeral) resends the cached Resp and does NOT build a second `next` (idempotent); a new ephemeral builds a new `next`. (b) a relay rekey Resp completes → `promote_from_rekey` (new epoch, old→previous, `conn_tag` map updated). (c) a `relay_wrap`-`None` emit is a clean no-op (no state change). (d) the direct-path wrappers still pass `RekeyEgress::Direct` — existing 9a direct rekey tests stay green unchanged (behavior-preserving extraction).
- **netns money test (the gate):** a **relay-forced** topology — block the direct + hole-punch paths so the two peers *must* carry traffic over the rendezvous relay — with `YIP_REKEY_INTERVAL_MS` low and a steady stream: assert **0% (≤1%) packet loss across ~10 rotations over the relay**, and the `rekey_epoch_witness` tool confirms distinct rekey rounds on the **relayed** wire. Both the poll and `YIP_USE_URING=1` drivers; CI-wired. Fork the existing relay netns test (`run-netns-reality-relay.sh`/`run-netns-relay*.sh`) + the 9a `run-netns-rekey.sh`.
- **Regression:** existing 9a direct rekey tests + the 2a/2b/2c relay/triangle/discovery netns tests stay green.

## Risks

- **Extraction refactor touches the security-critical direct rekey path.** Mitigation: the extraction is behavior-preserving for `Direct` (the wrappers pass `Direct(src)`); the full existing 9a direct-rekey unit + netns suite is the regression net, and the shared core keeps the idempotent-convergence logic single-sourced (a duplicate would risk the relay copy drifting from the Critical fix).
- **Relay reordering** is worse than direct, so a rekey round may take longer to converge; the ephemeral-keyed idempotency handles it (no divergence), and the loser-fallback/retransmit cover a lost relay Init/Resp.
- **`relay_wrap` `None`** (rendezvous temporarily unavailable) silently skips a rekey send; acceptable — the session keeps running on `current` and rekey retries when the relay returns.

## Non-goals

- Important-1 rekey-liveness hardening (spoofed-Resp) — #34.
- No wire-format change; no `yip-crypto`/`yip-wire` change.
- PQ-hybrid handshake — 9b.

## Success criteria

1. Relay-reached Established peers schedule + COMPLETE a mid-session rekey (Init via `relay_wrap`, `rekey_init_core`/`rekey_resp_core` through `RekeyEgress::Relay`), rotating their session with the same confirmed-switch + idempotency as direct peers; the `drive_rekey_schedule` relay gate is removed.
2. The rekey-completion logic is single-sourced (shared cores), so the idempotent-convergence guarantee is not duplicated; direct-path behavior is unchanged (existing 9a direct tests green).
3. Fail-closed: a relay rekey that can't emit/complete/times-out is a no-op on the live session; relay reordering does not diverge the peers (idempotency).
4. netns relay-forced money test: 0% loss across ~10 rotations over the relay, distinct rekey rounds on the relayed wire, both drivers.
5. `forbid-unsafe`; no `as` (except the pre-existing `PacketType::X as u8` idiom); no bare `#[allow]`; clippy clean.
