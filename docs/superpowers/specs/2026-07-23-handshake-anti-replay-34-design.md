# Handshake anti-replay + authenticated endpoint learning (#34) — design spec

**Date:** 2026-07-23
**Status:** design (pending user review)
**Issue:** #34 (handshake hardening; anchor for #36's downgrade tradeoff, #37, #64).
**Depends on:** 9a (PR #90) + #91 (PR #92) rekey machinery, and #36 (PR #95) — all merged to `main`. This milestone modifies their handshake-admission / rekey-completion / relay-adoption code.
**Scope:** `bin/yipd/src/peer_manager.rs` (admission, rekey, escalation), `bin/yipd/src/handshake.rs` (msg1 payload framing helpers). No change to `yip-crypto` (Noise) or `yip-wire`. The timestamp rides **inside** the encrypted Noise msg1 payload — no new cleartext field, no `PacketType`/framing change.

## Goal

The Noise-IK handshake carries no anti-replay token. Two consequences:

1. **Endpoint hijack via replay.** `handle_handshake_init` learns a peer's endpoint from the datagram source (`endpoint = src`) after admission. An on-path adversary who captures one genuine `HandshakeInit` from peer P can replay it from a spoofed source S: `start_responder` succeeds, admission passes (recovers P's real static key), and our outbound for P is redirected to S.
2. **No safe session rebuild on genuine peer restart.** A replayed old `Init` is indistinguishable from a genuine re-initiation, so an `Established` responder cannot rebuild on a peer restart (rebuilding on any differing `Init` would let a replay tear down a live session — a DoS). 9a/#36 work around specific loss/escalation cases with ephemeral-preservation hacks, but a genuine restart mid-session still can't be recovered until timeout, and #36 carries an accepted attacker-induced downgrade tradeoff.

Add a monotonic wall-clock timestamp (WireGuard TAI64N-style) to the initiation; reject any `Init` not strictly newer than the last accepted from that static key. Then: gate endpoint learning on a fresh `Init`, enable safe session rebuild on a newer `Init`, and **retire #36's ephemeral-preservation hack and its downgrade tradeoff** by inverting it to fresh-Init-then-rebuild.

## Background (current state)

- **msg1 payload:** built as `Membership::own_cert_bytes()` (a raw encoded `Cert`) in mesh mode, or **empty** in 2a/2b; consumed by `responder_cert_ok` via `Cert::decode(payload)`. It already rides inside Noise's encrypted msg1.
- **Admission (`handle_handshake_init` / `relayed_handshake_init`):** `start_responder` → `(established, resp_pkt, remote_static, initiator_payload)`; static-key match or cert admits; on cold-start establish, `endpoint = Some(src)` (peer_manager.rs ~1759, ~2045). Established peers route through the rekey path.
- **Rekey completion (`rekey_init_core`):** (1) `cached_resp_init_eph` cold-start dedup → replay `cached_resp`; (2) `next_cached_resp_for` rekey-retransmit dedup; (3) `accept_rekey_init` **age gate** (`current ≥ interval/2`) — reject-as-too-fresh else build `next`.
- **#36 (PR #95):** `retarget_handshake` preserves the in-flight ephemeral across a path re-target (resend the same `init_pkt`); `relayed_handshake_init`'s Established arm adopts the relay + replays `cached_resp` on a relayed cold-start **retransmit** (`init_eph == cached_resp_init_eph`). Accepted tradeoff: an attacker replaying a captured Init forces a persistent direct→relay downgrade.
- **Per-peer state:** `Peer { pubkey, endpoint, state, cached_resp_init_eph, relay, … }`. No anti-replay state.

## Design

### 1. Wire: msg1 payload = `[TAI64N ts (12 B)] ‖ [optional cert]`

Add helpers to `handshake.rs`:
- `now_tai64n() -> [u8; 12]` — the current wall clock as TAI64N: 8-byte big-endian seconds (`2^62 + unix_secs`) ‖ 4-byte big-endian nanoseconds. Big-endian so lexicographic byte comparison is chronological.
- `frame_init_payload(cert: &[u8]) -> Vec<u8>` — `now_tai64n() ‖ cert` (cert empty in 2a/2b).
- `parse_init_payload(payload: &[u8]) -> Option<([u8; 12], &[u8])>` — split the 12-byte ts prefix from the cert remainder; `None` if `payload.len() < 12` (fail-closed).

`begin_handshake` and the rekey scheduler (`drive_rekey_schedule`) build the payload via `frame_init_payload(own_cert_bytes-or-empty)` instead of the raw cert. The responder calls `parse_init_payload` on `initiator_payload` before `responder_cert_ok` (which now receives the cert remainder, unchanged). msg2 (response) is unchanged — anti-replay protects only the initiation (the responder answers a fresh init; WireGuard model).

### 2. State: `Peer.last_accepted_init_ts: Option<[u8; 12]>`

The greatest TAI64N ts accepted from this peer, in-memory (no persistence — WireGuard's model; after a responder restart there is no live session to protect, so `None` safely re-accepts). Compared by `<=`/`>` on the 12-byte big-endian arrays.

### 3. The unified freshness gate (replaces the 9a age gate)

A single helper `accept_fresh_init(peer_idx, ts) -> bool`: `true` iff `last_accepted_init_ts` is `None` (first Init) or `ts > last_accepted_init_ts`. It is the discriminator for **building a new session** (cold-start with a new ephemeral, rekey, or restart-rebuild):

- **Seen ephemeral** (retransmit: `init_eph == cached_resp_init_eph`, or matches an in-flight `next`) → replay `cached_resp` as today. **No ts check, no ts update** — a retransmit is byte-identical (same ts) and must not be rejected.
- **New ephemeral + `accept_fresh_init`** → build/rebuild the session; **set `last_accepted_init_ts = ts`** on acceptance.
- **New ephemeral + not fresh** (`ts <= last`) → **reject** (silent drop): a stale replay, or a peer with a backwards clock (same failure mode as WireGuard). `current` untouched, no endpoint update.

`accept_rekey_init`'s age gate (`current ≥ interval/2`) is **removed**: it was a proxy for "not a replay" absent anti-replay; the ts check is the real thing, and an attacker cannot forge a fresh-ts new-ephemeral Init (it requires the peer's static key), so the anti-churn purpose is also covered.

### 4. Endpoint gating

`endpoint = Some(src)` is set **only on a fresh accepted Init** (inside the accept branch, after `accept_fresh_init` passes). A replayed old Init is rejected before this point → no redirect. (Relay-reached peers are unaffected — they set `relay`/`server_addr()`, not `endpoint`.)

### 5. by_tag eviction on rebuild

When a fresh-ts new-ephemeral Init rebuilds an `Established` peer's session, the old session's `conn_tag` (and any `next`/`previous`) is removed from `by_tag` before inserting the new one — reuse the `drop_session`/`promote_from_rekey` tag-bookkeeping so no stale tag routes to the superseded session. (Resolves the issue's `by_tag`-eviction note.)

### 6. #36 retirement (inverted to fresh-Init + safe rebuild)

- **`retarget_handshake` drops ephemeral-preservation.** On a path re-target, the initiator sends a **fresh** Init (new ephemeral + newer ts) — via `begin_handshake` — instead of resending the same `init_pkt`. This was the original #36 *bug*, now *safe* because the responder rebuilds on the fresh-ts new-ephemeral Init rather than replaying a stale `cached_resp`. `retarget_handshake` is either removed (callers revert to `begin_handshake`) or reduced to just updating the path/relay target with a fresh Init; the escalation arms (`PathAction::Relay`, `PathAction::Probe(addr) if addr != target`) call the fresh path.
- **Responder-side relay adoption re-gated on freshness.** `relayed_handshake_init`'s Established arm: a relayed **fresh-ts new-ephemeral** Init against a `relay == false` peer → **rebuild** the session (new `DataPlane`) **and** adopt the relay (`relay = true`, egress via `relay_wrap`). A **replay** (old ts, or the `cached_resp_init_eph` retransmit) → **not** adopted (rejected by the freshness gate) → **no downgrade**. The #95 `cached_resp_init_eph`-retransmit adoption path is removed (superseded).
- **The accepted downgrade tradeoff is deleted** — an attacker replaying a captured Init can no longer force a path change; only a genuine fresh-ts Init (which requires the static key) rebuilds/adopts.

The `is_root` / cert-exemption logic (#41, #96) is untouched — it operates on the cert remainder after ts parsing.

## Error handling

- **Fail-closed parsing:** a payload shorter than 12 bytes, or otherwise unparseable, → reject the Init (silent drop), `current` and `endpoint` untouched.
- **Stale replay:** rejected before any state mutation — no endpoint update, no session build/teardown, no `by_tag` change.
- **Retransmit safety:** the seen-ephemeral (`cached_resp_init_eph`/`next`) replay paths are unchanged and bypass the ts check, so the 2a/9a loss-wedge + idempotent-convergence guarantees hold.
- **No panic on the wire path.** TAI64N comparison is a byte-array compare; parsing uses `.get(..)`.
- **Clock behavior:** a peer whose clock jumps backwards (bad NTP / restart with a bad RTC) cannot handshake until its clock passes the last-accepted ts — the WireGuard behavior, accepted. No skew-tolerance window (unlike cert validity): the check is strict monotonicity per peer, not a validity window.

## Testing / adversary

- **Unit:**
  1. First Init (no `last_accepted_init_ts`) is accepted; `last_accepted_init_ts` recorded; `endpoint` learned from `src`.
  2. A **replayed** Init (same bytes, same ts) from a **spoofed src** against an Established peer is **rejected**: `endpoint` unchanged, session intact, `last_accepted_init_ts` unchanged (retransmit path if the ephemeral matches → replays cached_resp to `src` but still does NOT change `endpoint`; a captured *older* Init with a since-superseded ephemeral → rejected outright).
  3. A **genuine restart** (new ephemeral + newer ts) rebuilds the Established peer's session: new epoch, old `by_tag` evicted, `endpoint` re-learned.
  4. A retransmit (seen ephemeral, same ts) still replays `cached_resp` (loss-wedge unregressed).
  5. `parse_init_payload` rejects a < 12-byte payload; `accept_fresh_init` boundary (`ts == last` rejected, `ts == last+1ns` accepted).
  6. #36 path-switch: an escalating peer sending a fresh-ts Init over the relay converges via **rebuild**; a **replayed** escalation Init (old ts) is rejected → no relay adoption (downgrade closed).
  7. The ts applies to **all** modes (no membership-off exemption, unlike #41): a 2a/2b peer still establishes with a `[ts]`-only payload (empty cert), and its replays are rejected the same way.
- **netns money tests (both drivers, release yipd):**
  - **endpoint-hijack:** a captured `Init` replayed from a third namespace with a spoofed source does NOT redirect the victim's traffic (the peer stays reachable at its real endpoint).
  - **restart recovery:** a peer killed and restarted mid-session (fresh ephemeral + newer ts) re-establishes within a bounded window and traffic resumes — previously stuck until timeout.
  - **#36 regression:** the path-switch convergence test (`run-netns-pathswitch-rehandshake.sh`) still converges (now via fresh-Init rebuild, not ephemeral-preservation).
- **Regression:** the full 9a/#91/#36/#41 unit + netns suites stay green (this milestone modifies their admission/rekey/adoption paths — the suite is the net).

## Risks

- **Modifies the core handshake-admission + rekey-completion + #36/#95 relay-adoption code** — the highest-blast-radius change since 9a. Mitigation: the freshness gate is a *narrowing* (it only adds a reject condition to the new-session-build paths; retransmit/replay-cached paths are untouched), the 9a age gate it replaces is strictly subsumed, and the full merged netns/unit suite is the regression net. Land behind that suite; final whole-branch opus review focused on the admission decision tree.
- **Clock dependency** — a peer with a badly-backwards clock can't handshake. Accepted (WireGuard's model); documented. Not a concern for the anti-DPI/NTP-typical deployment.
- **#36 inversion touches just-shipped code** — removing the ephemeral-preservation + `cached_resp_init_eph` adoption is a real behavior change; the #36 netns test is rewritten to assert convergence-via-rebuild, and a new test asserts a replayed escalation Init is refused.
- **Wire break** — pre-#34 nodes can't handshake with #34 nodes (payload framing differs). Expected for a security milestone; a mixed fleet is a deploy concern, not a code one.

## Non-goals

- No cross-restart *counter* persistence (wall-clock ts needs none).
- No msg2 (response) anti-replay (the responder answers a fresh init; not needed).
- #37 (authenticated rendezvous registration) and #64 (obf discriminator) — separate issues that *build on* #34's authenticated endpoint but are out of scope here.
- No change to the rekey *schedule* (still ~120 s, glare-winner) — only how the responder *validates* a rekey/rebuild Init.

## Success criteria

1. A replayed `HandshakeInit` from a spoofed source cannot redirect a peer's endpoint or tear down / rebuild its live session (rejected by the freshness gate); proven by a netns money test.
2. A genuine peer restart (fresh ephemeral + newer ts) safely rebuilds the session within a bounded window; proven by a netns money test.
3. The 9a age gate is replaced by the ts freshness check; the retransmit/idempotent-convergence and 2a loss-wedge guarantees are unregressed.
4. #36 is inverted to fresh-Init + safe rebuild: its path-switch scenario still converges, its ephemeral-preservation + `cached_resp_init_eph` relay-adoption code is removed, and its accepted downgrade tradeoff is closed (a replayed escalation Init is refused).
5. The timestamp rides inside the encrypted Noise payload — no cleartext fingerprint, no `PacketType`/wire-framing change; `yip-crypto`/`yip-wire` unchanged.
6. `forbid-unsafe`; no `as` casts (except the pre-existing `PacketType::X as u8` idiom); no bare `#[allow]`; clippy `-D warnings` clean; both-driver netns green.
