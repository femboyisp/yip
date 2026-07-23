# Handshake anti-replay + authenticated endpoint (#34) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-peer anti-replay timestamp to the handshake initiation, gate endpoint-learning and session-rebuild on freshness, and invert #36 to fresh-Init + safe-rebuild.

**Architecture:** A 12-byte TAI64N wall-clock timestamp rides inside the encrypted Noise msg1 payload (prefixed to the existing optional cert). The responder stores the greatest ts accepted per peer and uses a `ts > last` freshness check as the single "build a new session" discriminator — replacing the 9a age gate — while retransmit/`cached_resp` paths (seen ephemeral) bypass it. Endpoint learning and session rebuild happen only on a fresh accepted Init; #36's ephemeral-preservation + relay-adoption become fresh-Init + freshness-gated rebuild.

**Tech Stack:** Rust, `#![forbid(unsafe_code)]`; Noise-IK via `yip-crypto` (unchanged); netns integration tests under poll + `YIP_USE_URING=1`.

## Global Constraints

- `#![forbid(unsafe_code)]` — NO `unsafe`.
- NO `as` casts, except the pre-existing `PacketType::X as u8` idiom.
- NO bare `#[allow]` — use `#[expect(reason = "...")]`.
- Run `cargo fmt` before every commit; never `--no-verify` to skip fmt.
- `cargo clippy -p yipd --all-targets -- -D warnings` clean.
- NO change to `yip-crypto` (Noise) or `yip-wire`. The timestamp rides INSIDE the encrypted Noise msg1 payload — no new cleartext field, no `PacketType`/framing change.
- `yipd` is a binary crate: test with `cargo test -p yipd --bin yipd` (NOT `--lib`).
- The ts applies to ALL modes (2a/2b/2c) — there is no membership-off exemption (unlike #41's cert checks). A 2a/2b peer's payload becomes `[ts]` with an empty cert remainder.
- Known env flake: the `yip-io` uring loopback test may fail unrelated to yipd; acceptable only if it is the sole failure and the code is fmt-clean.
- Regression net: the full 9a/#91/#36/#41 unit + netns suites must stay green — this milestone modifies their admission/rekey/adoption paths.

---

### Task 1: TAI64N + msg1 payload framing helpers (pure, in `handshake.rs`)

**Files:**
- Modify: `bin/yipd/src/handshake.rs` (add `now_tai64n`, `frame_init_payload`, `parse_init_payload` + unit tests)

**Interfaces:**
- Produces: `pub fn now_tai64n() -> [u8; 12]`; `pub fn frame_init_payload(cert: &[u8]) -> Vec<u8>`; `pub fn parse_init_payload(payload: &[u8]) -> Option<([u8; 12], &[u8])>`; `pub const TAI64N_LEN: usize = 12`.

- [ ] **Step 1: Write the failing tests**

Add to `handshake.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn tai64n_is_big_endian_monotonic_and_roundtrips() {
    // frame/parse roundtrip: ts prefix split from the cert remainder.
    let cert = b"a-cert-blob";
    let framed = frame_init_payload(cert);
    assert_eq!(framed.len(), TAI64N_LEN + cert.len());
    let (ts, rest) = parse_init_payload(&framed).expect("parses");
    assert_eq!(rest, cert);
    assert_eq!(&framed[..TAI64N_LEN], &ts);

    // empty cert (2a/2b): payload is exactly the 12-byte ts.
    let framed_empty = frame_init_payload(&[]);
    assert_eq!(framed_empty.len(), TAI64N_LEN);
    let (_ts, rest) = parse_init_payload(&framed_empty).expect("parses");
    assert!(rest.is_empty());

    // big-endian so lexicographic byte-compare is chronological: a later
    // wall-clock ts compares strictly greater than an earlier one.
    let earlier = now_tai64n();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let later = now_tai64n();
    assert!(later > earlier, "TAI64N must increase with wall-clock and byte-compare");
}

#[test]
fn parse_init_payload_rejects_short_payload() {
    assert!(parse_init_payload(&[0u8; TAI64N_LEN - 1]).is_none());
    assert!(parse_init_payload(&[]).is_none());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd handshake::tests::tai64n`
Expected: FAIL — helpers not defined.

- [ ] **Step 3: Implement the helpers**

```rust
/// TAI64N label length: 8-byte seconds + 4-byte nanoseconds.
pub const TAI64N_LEN: usize = 12;

/// The current wall clock as a TAI64N label: big-endian `2^62 + unix_secs`
/// (8 bytes) followed by big-endian nanoseconds (4 bytes). Big-endian so that
/// a lexicographic byte comparison of two labels is chronological. Wall-clock
/// based, so it survives a peer restart (a fresh Init is always newer in real
/// time) with no persisted state. A clock that jumps backwards yields a label
/// that a peer with a higher last-accepted label will reject — the WireGuard
/// behavior, accepted.
pub fn now_tai64n() -> [u8; TAI64N_LEN] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs().wrapping_add(1u64 << 62);
    let nanos = now.subsec_nanos();
    let mut out = [0u8; TAI64N_LEN];
    out[..8].copy_from_slice(&secs.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

/// Build the msg1 Noise payload: the anti-replay TAI64N label followed by the
/// (optional) membership cert. Empty `cert` (2a/2b) yields a 12-byte payload.
pub fn frame_init_payload(cert: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAI64N_LEN + cert.len());
    out.extend_from_slice(&now_tai64n());
    out.extend_from_slice(cert);
    out
}

/// Split a received msg1 payload into `(ts_label, cert_remainder)`.
/// `None` (fail-closed) if it is shorter than the 12-byte label.
pub fn parse_init_payload(payload: &[u8]) -> Option<([u8; TAI64N_LEN], &[u8])> {
    let ts: [u8; TAI64N_LEN] = payload.get(..TAI64N_LEN)?.try_into().ok()?;
    Some((ts, &payload[TAI64N_LEN..]))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p yipd --bin yipd handshake::tests`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt
cargo clippy -p yipd --all-targets -- -D warnings
git add bin/yipd/src/handshake.rs
git commit -m "feat(anti-replay.34): TAI64N + msg1 payload framing helpers"
```

---

### Task 2: wire the payload framing into build + consume (no freshness gate yet)

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` — the two payload-BUILD sites (`begin_handshake` ~705, `drive_rekey_schedule` ~878) and the responder CONSUME path (parse the ts off `initiator_payload`/`responder_payload` before `responder_cert_ok`).

**Interfaces:**
- Consumes: `handshake::frame_init_payload`, `handshake::parse_init_payload`, `handshake::TAI64N_LEN` (Task 1).
- Produces: msg1 payloads are now `[ts ‖ cert]`; the cert remainder is what `responder_cert_ok` / `Cert::decode` see. This task establishes the wire format end-to-end (all 4 handshake variants still establish); the ts is parsed but NOT yet enforced (Task 3 adds the freshness gate). A parse failure (< 12 B) drops the Init.

- [ ] **Step 1: Write the failing test**

The end-to-end invariant: a normal handshake still completes with the new framing, and a cert-bearing (mesh) handshake still admits by cert (the cert remainder is intact after ts stripping). Mirror an existing establish test (e.g. the 2c admission test or `initiator_rejects_responder_with_bad_cert`'s positive counterpart) but assert it still establishes with the framed payload.

```rust
#[test]
fn framed_init_payload_still_establishes_and_admits_by_cert() {
    // A mesh initiator's Init now carries [ts || cert]; the responder strips
    // the ts and admits by the cert remainder exactly as before. (Build a
    // mesh PeerManager pair as the 2c admission tests do; drive an Init->Resp
    // exchange; assert both reach Established.)
    // ... reuse the 2c admission scaffolding ...
}
```

If building a full pair is heavy, at minimum assert the responder-side parse: an Init whose payload is `frame_init_payload(&valid_cert_bytes)` admits (cert recovered from `parse_init_payload(...).1`), and an Init whose payload is a raw cert with NO ts prefix now FAILS to admit (the first 12 cert bytes are mis-read as a ts, so the cert remainder no longer decodes) — proving the framing is enforced on the consume side.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd framed_init_payload_still_establishes`
Expected: FAIL — build sites still send a raw cert; the responder still `Cert::decode`s the whole payload.

- [ ] **Step 3: Implement — build side**

At BOTH payload-build sites, wrap the cert with `frame_init_payload`. `begin_handshake` (~705):

```rust
        let cert = self
            .membership
            .as_ref()
            .map(Membership::own_cert_bytes)
            .unwrap_or_default();
        let payload = crate::handshake::frame_init_payload(&cert);
        let (hs, init_pkt) =
            match HandshakeState::start_initiator(&self.local_priv, &pubkey, &payload) {
```

`drive_rekey_schedule` (~878): identical wrap of its `own_cert_bytes`-or-default into `frame_init_payload(&cert)` before `start_initiator`.

Leave the msg2 (responder `resp_payload`) build UNCHANGED — anti-replay protects only the initiation.

- [ ] **Step 4: Implement — consume side**

Every responder path that reads the initiator's msg1 payload must parse the ts off first. The initiator payload is destructured from `start_responder` as `initiator_payload` in `handle_handshake_init` (~1571) and `relayed_handshake_init` (~1090). Immediately after `start_responder` succeeds, split it:

```rust
        // #34: the msg1 payload is [ts || cert]. Split the anti-replay label
        // off; the cert remainder is what admission checks. A payload too
        // short to hold the label is malformed — fail closed.
        let Some((init_ts, initiator_cert)) = crate::handshake::parse_init_payload(&initiator_payload) else {
            return DispatchOut::None;
        };
```

Then replace every downstream use of `initiator_payload` as the cert with `initiator_cert` (the `responder_cert_ok(&initiator_cert, remote_static)` calls, and the `Cert::decode(&initiator_cert)` in the cold-start admission `None => { ... }` arm). Bind `init_ts` for Task 3 (unused this task — prefix `_init_ts` or `#[expect(unused)]` is NOT needed if Task 2 and 3 are one commit; if separate, name it `_init_ts` and Task 3 renames).

**Note:** msg2's responder cert is checked via `responder_cert_ok(&responder_payload, ...)` on the initiator side — the responder payload is NOT ts-framed (msg2 has no anti-replay), so those sites are UNCHANGED.

- [ ] **Step 5: Run tests + full suite**

Run: `cargo test -p yipd --bin yipd`
Expected: PASS — all establish tests green with the new framing; any test that hand-builds a raw-cert msg1 payload must be updated to `frame_init_payload(&cert)` (these are legitimate test-scaffolding updates — the wire format changed).

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt
cargo clippy -p yipd --all-targets -- -D warnings
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(anti-replay.34): frame [ts||cert] into msg1; responder strips the ts"
```

---

### Task 3: freshness gate (replace the age gate) + endpoint gating + by_tag eviction

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (new `Peer.last_accepted_init_ts` field + init; `accept_fresh_init` helper; freshness gate in `rekey_init_core` replacing `accept_rekey_init`; endpoint-learning moved into the fresh-accept branch; by_tag eviction on rebuild)
- Modify: `bin/yipd/src/epoch.rs` (remove/deprecate `accept_rekey_init`'s age gate — see Step 4)

**Interfaces:**
- Consumes: `handshake::parse_init_payload` output `init_ts: [u8; 12]` (Task 2).
- Produces: `Peer.last_accepted_init_ts: Option<[u8; 12]>`; `fn accept_fresh_init(&self, idx: usize, ts: &[u8; 12]) -> bool`. After this task, a new-ephemeral Init builds a session only when `ts > last_accepted_init_ts`; retransmit/`cached_resp` paths bypass; endpoint is learned only on a fresh accept.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn stale_replayed_init_is_rejected_and_endpoint_unchanged() {
    // An Established peer (last_accepted_init_ts = T1). A NEW-ephemeral Init
    // carrying an OLDER ts T0 < T1 from a SPOOFED src is rejected: session
    // intact (established_tag unchanged), endpoint unchanged, last ts unchanged.
    // (Build an Established peer via the existing helper; splice
    // last_accepted_init_ts = a known label; craft a new-ephemeral Init whose
    // frame_init_payload uses an older label; deliver from a spoofed src.)
}

#[test]
fn fresh_new_ephemeral_init_rebuilds_and_relearns_endpoint() {
    // An Established peer receiving a NEW-ephemeral Init with ts > last
    // rebuilds: new epoch, old by_tag entry evicted, endpoint = the new src,
    // last_accepted_init_ts = the new ts.
}

#[test]
fn retransmit_still_replays_cached_resp_regardless_of_ts() {
    // A retransmit (init_eph == cached_resp_init_eph, same ts) still replays
    // cached_resp and does NOT reject / does NOT change endpoint or last ts.
}
```

Reuse the 9a/#91 rekey test scaffolding (`pm_with_established_peer`, `established_tag`, the cached-resp helpers). For the ts labels, use `handshake::now_tai64n()` and hand-decremented/incremented arrays.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd stale_replayed_init_is_rejected`
Expected: FAIL — no freshness gate; a new-ephemeral Init against an Established peer currently goes through the age gate, not a ts check.

- [ ] **Step 3: Add the field + helper**

`Peer` struct: add `last_accepted_init_ts: Option<[u8; 12]>` (doc: "#34: greatest TAI64N label accepted in a session-building Init from this peer; in-memory, gates rebuild/rekey and endpoint learning"). Initialize `None` at every `Peer` construction site (grep `Peer {` / the peer-builder — there are a few: config peers, `admit_member`, test helpers).

Add to `impl PeerManager`:

```rust
/// #34 anti-replay: whether `ts` is strictly newer than the greatest label
/// we have accepted in a session-building Init from peer `idx` (or the first
/// such Init). Retransmit/`cached_resp` paths do NOT call this — they replay
/// without a freshness check.
fn accept_fresh_init(&self, idx: usize, ts: &[u8; 12]) -> bool {
    match self.peers[idx].last_accepted_init_ts {
        None => true,
        Some(last) => *ts > last,
    }
}
```

- [ ] **Step 4: Wire the freshness gate into `rekey_init_core` + thread `init_ts`**

Thread `init_ts: [u8; 12]` into `rekey_init_core` (add a param) from both callers (`handle_rekey_init` wrapper / the `relayed_handshake_init` Established arm), which get it from Task 2's `parse_init_payload`. In `rekey_init_core`, the decision tree becomes:

1. `cached_resp_init_eph == Some(init_eph)` → replay `cached_resp` (unchanged; **no ts check, no ts update**).
2. `next_cached_resp_for(init_eph)` → replay cached rekey resp (unchanged; no ts check).
3. **Replace** `if !epochs.accept_rekey_init(now_ms, self.rekey_interval_ms) { ...replay cached_resp... }` **with** `if !self.accept_fresh_init(idx, &init_ts) { return DispatchOut::None; }` — a stale/replayed new-ephemeral Init is now a **silent drop** (not a cached_resp replay), because it is either an attacker replay or a backwards-clock peer.
4. Build the new session (rebuild) — and here **set `self.peers[idx].last_accepted_init_ts = Some(init_ts)`** and evict the old `by_tag` entries before inserting the new (reuse the `drop_session` tag-collection or the existing `promote_from_rekey` `by_tag.remove(old_tag)`), so no stale tag routes to the superseded session.

Remove `accept_rekey_init` from `epoch.rs` (and its test) once no caller remains — grep to confirm `rekey_init_core` was its only caller. Update the doc comment on `EpochSet` that references the age gate.

- [ ] **Step 5: Gate endpoint learning on a fresh accept**

The direct cold-start establish arm of `handle_handshake_init` currently sets `self.peers[idx].endpoint = Some(src)` unconditionally (~1759). Move/guard it so `endpoint` is set only when this Init was a fresh accept: for a cold-start (Idle/Handshaking peer), the first Init is always fresh (`last_accepted_init_ts` is `None`) → accept + set `last_accepted_init_ts = Some(init_ts)` + `endpoint = Some(src)`. A cold-start Init that is NOT fresh (a replay against a peer that already has a `last_accepted_init_ts` but is somehow Idle — e.g. after a give-up) must NOT set `endpoint`. Concretely: add `if !self.accept_fresh_init(idx, &init_ts) { return DispatchOut::None; }` at the top of the cold-start establish arm, and set `last_accepted_init_ts = Some(init_ts)` alongside the existing `endpoint = Some(src)`.

- [ ] **Step 6: Run tests + full suite**

Run: `cargo test -p yipd --bin yipd`
Expected: PASS. The 9a rekey tests that relied on the age gate (`accept_rekey_init_ignores_too_fresh_current`, `tick_*rekey*` timing) must be updated: a rekey now completes on a fresh-ts Init regardless of `current` age — rewrite those to assert freshness-gated completion (a fresh-ts new-ephemeral rekey Init completes; a stale-ts one is dropped). These are legitimate updates (the age gate was replaced by design).

- [ ] **Step 7: fmt, clippy, commit**

```bash
cargo fmt
cargo clippy -p yipd --all-targets -- -D warnings
git add bin/yipd/src/peer_manager.rs bin/yipd/src/epoch.rs
git commit -m "feat(anti-replay.34): ts freshness gate replaces the age gate; endpoint learned only on a fresh Init"
```

---

### Task 4: #36 retirement — fresh-Init inversion + freshness-gated relay adoption

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (`retarget_handshake`, the two tick escalation arms, `relayed_handshake_init`'s Established arm; the #36 unit tests)

**Interfaces:**
- Consumes: the freshness gate + `accept_fresh_init` (Task 3), `begin_handshake`.
- Produces: path re-targets send a fresh Init (new ephemeral + newer ts); a direct-established responder rebuilds + adopts the relay only on a fresh-ts new-ephemeral relayed Init; the `cached_resp_init_eph` relay-adoption and the ephemeral-preservation are removed; the downgrade tradeoff is closed.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn path_switch_sends_fresh_init_and_responder_rebuilds() {
    // A Handshaking peer re-targeted to a new path now emits a Init with a
    // DIFFERENT ephemeral (fresh) than before — NOT the byte-identical resend
    // Task-1(#36) asserted. (Inverse of the removed
    // `retarget_handshake_preserves_ephemeral_and_flips_relay`.)
}

#[test]
fn relayed_fresh_init_adopts_relay_and_rebuilds_but_replay_does_not() {
    // A direct-established (relay=false) responder receiving a relayed
    // NEW-ephemeral FRESH-ts Init rebuilds + adopts relay (relay=true, new
    // epoch). A relayed replay (old ts, OR the old cached_resp_init_eph
    // retransmit) does NOT adopt relay and does NOT rebuild (freshness gate) —
    // the downgrade is closed.
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd path_switch_sends_fresh_init`
Expected: FAIL — `retarget_handshake` still preserves the ephemeral; the relayed arm still adopts on the `cached_resp_init_eph` retransmit.

- [ ] **Step 3: Invert `retarget_handshake`**

On a path re-target of an in-flight `Handshaking` attempt, send a **fresh** Init instead of resending `init_pkt`. Simplest: the escalation arms (`PathAction::Relay`, `PathAction::Probe(addr) if addr != target`) revert to `state = Idle; begin_handshake(idx, new_target, via_relay, now_ms)` (a fresh ephemeral + fresh ts via Task-2's framed payload), and `retarget_handshake` is removed (or reduced to a thin `begin_handshake` wrapper that also updates `relay`/`endpoint`). The old #36 concern (a fresh ephemeral orphaned the responder's `cached_resp`) is now resolved by the responder REBUILDING on the fresh Init (Task 3 + Step 4), so preservation is unnecessary. Keep the relay branch's `endpoint = None` clear (a fresh direct Resp must not complete onto a relay-flagged peer — still valid).

- [ ] **Step 4: Re-gate the relayed relay-adoption on freshness**

In `relayed_handshake_init`'s Established arm (the #95/#36 adoption), REPLACE the `!self.peers[idx].relay && self.peers[idx].cached_resp_init_eph == Some(init_eph)` adoption condition with a freshness-gated rebuild: a relayed **new-ephemeral** Init (not a seen-ephemeral retransmit) that `accept_fresh_init(idx, &init_ts)` → set `relay = true`, `endpoint = None`, and route to `rekey_init_core(.., via_relay = true)` which (with Task 3) rebuilds the session (fresh ts) and sets `last_accepted_init_ts`. A retransmit (seen ephemeral) → replay `cached_resp` over the relay as today (no adoption change). A stale-ts new-ephemeral relayed Init → dropped by the freshness gate (no adoption, no downgrade). Remove the `cached_resp_init_eph`-retransmit-triggered relay adoption entirely.

- [ ] **Step 5: Rewrite the #36 unit tests**

The #36 tests from PR #95 assert ephemeral-preservation + retransmit-adoption, which are now removed. Replace:
- `retarget_handshake_preserves_ephemeral_and_flips_relay` → `path_switch_sends_fresh_init_and_responder_rebuilds` (Step 1).
- `established_responder_completes_retargeted_initiator_via_cached_resp` → retained only if it still models a retransmit; otherwise fold into the rebuild test.
- `direct_established_responder_adopts_relay_on_relayed_cold_start_retransmit` → `relayed_fresh_init_adopts_relay_and_rebuilds_but_replay_does_not` (Step 1) — adoption is now on a fresh Init, and a replay is refused.
- Keep `direct_established_responder_ignores_relayed_new_ephemeral_init` semantics as the stale-ts case (a new-ephemeral relayed Init with a non-fresh ts is refused).

- [ ] **Step 6: Run tests + full suite**

Run: `cargo test -p yipd --bin yipd`
Expected: PASS.

- [ ] **Step 7: fmt, clippy, commit**

```bash
cargo fmt
cargo clippy -p yipd --all-targets -- -D warnings
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(anti-replay.34): retire #36 — fresh-Init + freshness-gated rebuild; downgrade closed"
```

---

### Task 5: netns money tests (endpoint-hijack refused, restart recovery, #36 convergence) + CI

**Files:**
- Create: `bin/yipd/tests/run-netns-replay-hijack.sh` (endpoint-hijack + restart)
- Modify: `bin/yipd/tests/run-netns-pathswitch-rehandshake.sh` (#36 now converges via rebuild — update assertions), `.github/workflows/integration.yml`

- [ ] **Step 1: Read fork sources**

Read `bin/yipd/tests/run-netns-relay.sh` / `run-netns-punch.sh` (two-peer + a third namespace for the spoofed replay source), `run-netns-rekey.sh` (both-driver parameterization, `set -euo pipefail`/`trap`, `[PASS]`/`[FAIL]`), and the current `run-netns-pathswitch-rehandshake.sh` (its ephemeral-preservation assertion — `DISTINCT_INIT_EPHEMERALS=1` — is now WRONG; the #36 fix now uses a FRESH ephemeral on escalation).

- [ ] **Step 2: Write `run-netns-replay-hijack.sh`**

Two peers A/B establish. Capture one of A's `HandshakeInit` datagrams (tcpdump on the A↔B link). From a THIRD namespace with a spoofed source, replay the captured Init at B. Assert: (1) B does NOT redirect A's traffic to the spoof source — a steady `ping A→B` keeps flowing (≤1% loss) throughout the replay, proving B's `endpoint` for A was not hijacked; (2) B's stderr shows the replay was refused (add a one-line marker on the freshness-gate drop if none exists, behind existing handshake logging). Then, a **restart** leg: kill A, restart it (fresh ephemeral + newer wall-clock ts), assert A↔B re-establishes and ping resumes within a bounded window (previously stuck until B's attempt timed out). `set -euo pipefail`, `trap` cleanup. BOTH drivers.

- [ ] **Step 3: Update `run-netns-pathswitch-rehandshake.sh`**

The #36 path-switch still must CONVERGE (ping A→B succeeds over the relay), but now via a FRESH-ephemeral rebuild, not ephemeral preservation. Remove/invert the `DISTINCT_INIT_EPHEMERALS=1` assertion (A now legitimately draws a fresh ephemeral on escalation); assert convergence (ping ≥98%) + relay-forwarded>0 as before. Update the header note.

- [ ] **Step 4: Run under sudo (both drivers)**

```bash
cargo build --release -p yipd
sudo bash bin/yipd/tests/run-netns-replay-hijack.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-replay-hijack.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo bash bin/yipd/tests/run-netns-pathswitch-rehandshake.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-pathswitch-rehandshake.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
```
Expected: PASS, exit 0 all four. Rebuild release after any yipd change. If the environment can't run netns, capture the exact blocker and report DONE_WITH_CONCERNS.

- [ ] **Step 5: Wire CI + commit**

Add `run-netns-replay-hijack.sh` to `.github/workflows/integration.yml` next to the sibling netns steps (both drivers, same SKIP/`[FAIL]` guards). `chmod +x`.

```bash
chmod +x bin/yipd/tests/run-netns-replay-hijack.sh
git add bin/yipd/tests/run-netns-replay-hijack.sh bin/yipd/tests/run-netns-pathswitch-rehandshake.sh .github/workflows/integration.yml
git commit -m "test(anti-replay.34): netns — endpoint-hijack refused, restart recovery, #36 rebuild"
```

---

## After all tasks

- Final whole-branch review (opus) over the branch delta (base = `main` at the branch point). Focus: the admission decision tree (freshness gate placement — retransmit/`cached_resp` paths bypass, new-ephemeral paths gated; the age gate is fully removed and its churn-bound is covered by the un-forgeable fresh-ts requirement); endpoint learning strictly on a fresh accept; `by_tag` eviction leaves no stale tag; the #36 inversion closes the downgrade (a replayed escalation Init is refused) without regressing convergence; the ts rides only inside the encrypted payload (no cleartext/framing change); no `unsafe`/`as`/bare-`allow`.
- Push; open a PR based on `main`. Leave it for the user; do NOT merge; no "not merging" line.
- Update `yip-control-plane-status` memory (#34 done; #36 retired/inverted; age gate replaced).

## Global test/verify discipline

- Run build/clippy/fmt and the netns money tests under BOTH poll and `YIP_USE_URING=1`; netns uses the RELEASE `yipd` — rebuild release after every yipd change.
- The full 9a/#91/#36/#41 netns + unit suite must stay green; this milestone modifies their admission/rekey/adoption paths, so treat any red there as a real regression, not a test to relax.
