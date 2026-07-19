# Relay-path session rekey completion (#91) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let relay-reached peers complete a mid-session rekey (so relay-only sessions get forward-secrecy rotation), by sharing the direct path's rekey-completion cores and un-gating relay scheduling.

**Architecture:** Extract the existing `handle_rekey_init`/`handle_rekey_resp` bodies into shared `rekey_init_core`/`rekey_resp_core` helpers parameterized by a `via_relay: bool` (the only divergence is the datagram emit — `EgressDatagram{dst}` vs `relay_wrap` — and the new `DataPlane`'s `peer_addr`). Wire the relay handlers to those cores, and remove the `drive_rekey_schedule` relay gate (restoring relay-wrapped Init sends). The 9a idempotent-ephemeral convergence logic stays single-sourced.

**Tech Stack:** Rust, `bin/yipd` (`peer_manager.rs`), Noise-IK (unchanged), netns integration tests.

## Global Constraints

- `#![forbid(unsafe_code)]` — NO `unsafe`, NO `as` casts (except the pre-existing pervasive `PacketType::X as u8` enum-discriminant idiom), NO bare `#[allow]` (use `#[expect(reason = "...")]`).
- Reuse `yip-crypto` / `yip-wire` / `bin/yipd/src/handshake.rs` UNCHANGED (only `handshake::init_ephemeral` is reused). NO wire-format change.
- **Fail-closed:** a relay rekey that can't emit (`relay_wrap` `None`), fails `read_response`/admission, or times out is a **NO-OP on the live session** (keep `current`). The 9a ephemeral-keyed idempotency (cold-start `cached_resp_init_eph` dedup, `next_cached_resp_for` rekey-retransmit dedup, `accept_rekey_init` gate) MUST stay intact and single-sourced inside `rekey_init_core` — it is what keeps relay reordering from diverging the peers.
- Out of scope (do NOT touch): Important-1 spoofed-Resp hardening (rides #34); PQ-hybrid (9b).
- Every task: `cargo build -p yipd`, `cargo clippy -p yipd --all-targets -- -D warnings`, `cargo fmt` (**run fmt — do not `--no-verify` unformatted code**). Netns verifies BOTH the poll and `YIP_USE_URING=1` drivers; netns uses the **RELEASE** yipd (rebuild release after yipd changes).
- Branch `feat/rekey-9a-relay-completion` stacks on 9a (PR #90). Leave the PR for the user; do NOT merge; no "not merging" line.
- **Known pre-existing flake:** two `yip-io::uring::tests::uring_*` loopback tests flake under load (unrelated crate). Commit `--no-verify` ONLY if that is the sole blocker AND the code is `cargo fmt`-clean.

---

### Task 1: Extract the shared rekey-completion cores (behavior-preserving)

Pull the `handle_rekey_init`/`handle_rekey_resp` bodies into `rekey_init_core`/`rekey_resp_core` parameterized by `via_relay: bool`, with a single egress helper. The Direct path stays byte-identical.

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (`handle_rekey_init` ~1573, `handle_rekey_resp` ~1797; add the two cores + one egress helper)

**Interfaces:**
- Produces:
  - `fn push_rekey_egress(&mut self, idx: usize, bytes: Vec<u8>, via_relay: bool, direct_dst: SocketAddr)` — pushes ONE egress datagram into `self.egress`: `via_relay` ⇒ `if let Some(d) = self.relay_wrap(idx, bytes) { self.egress.push(d) }` (a `None` is a clean skip); else ⇒ `self.egress.push(EgressDatagram { fate: 0, dst: direct_dst, bytes })`.
  - `fn rekey_init_core(&mut self, idx: usize, established: Established, resp_pkt: Vec<u8>, init_eph: [u8; 32], now_ms: u64, direct_src: SocketAddr, via_relay: bool) -> DispatchOut<'_>`
  - `fn rekey_resp_core(&mut self, idx: usize, dg: &[u8], now_ms: u64, via_relay: bool) -> DispatchOut<'_>`

- [ ] **Step 1: Add the egress helper**

Add to `impl PeerManager` (near `relay_wrap`):

```rust
/// Emit one rekey-related datagram into `self.egress`: relay-wrapped when
/// `via_relay` (a `relay_wrap` `None` is a clean skip — the rekey just
/// retries), else addressed directly to `direct_dst`. Used by the rekey
/// cores so the Direct/Relay split lives in exactly one place.
fn push_rekey_egress(&mut self, idx: usize, bytes: Vec<u8>, via_relay: bool, direct_dst: SocketAddr) {
    if via_relay {
        if let Some(d) = self.relay_wrap(idx, bytes) {
            self.egress.push(d);
        }
    } else {
        self.egress.push(EgressDatagram {
            fate: 0,
            dst: direct_dst,
            bytes,
        });
    }
}
```

- [ ] **Step 2: Extract `rekey_init_core`**

Rename `handle_rekey_init`'s body into `rekey_init_core` with the new signature, replacing (a) the new `DataPlane`'s `peer_addr` and (b) every direct `self.egress.push(EgressDatagram{ dst: src, .. })` with the helper. `peer_addr = if via_relay { self.server_addr() } else { direct_src }`. The three dedup/gate resend paths and the install-and-emit path each become `self.egress.clear(); self.push_rekey_egress(idx, <bytes>, via_relay, direct_src); DispatchOut::Udp(&self.egress)` (guard `Udp` with a non-empty check so a relay `None` skip returns `DispatchOut::None`). The idempotent logic (`cached_resp_init_eph`, `next_cached_resp_for`, `accept_rekey_init`) is UNCHANGED. Concretely the shape becomes:

```rust
fn rekey_init_core(
    &mut self,
    idx: usize,
    established: Established,
    resp_pkt: Vec<u8>,
    init_eph: [u8; 32],
    now_ms: u64,
    direct_src: SocketAddr,
    via_relay: bool,
) -> DispatchOut<'_> {
    let peer_addr = if via_relay { self.server_addr() } else { direct_src };

    // Cold-start retransmit dedup (unchanged logic; emit via helper).
    if self.peers[idx].cached_resp_init_eph == Some(init_eph) {
        self.egress.clear();
        if let Some(resp) = self.peers[idx].cached_resp.clone() {
            self.push_rekey_egress(idx, resp, via_relay, peer_addr);
        }
        return if self.egress.is_empty() { DispatchOut::None } else { DispatchOut::Udp(&self.egress) };
    }

    let PeerState::Established(epochs) = &mut self.peers[idx].state else {
        unreachable!("rekey_init_core is only called for an Established peer")
    };

    // Rekey-retransmit dedup (same round → resend cached resp, no second `next`).
    if let Some(cached) = epochs.next_cached_resp_for(&init_eph).map(<[u8]>::to_vec) {
        self.egress.clear();
        self.push_rekey_egress(idx, cached, via_relay, peer_addr);
        return if self.egress.is_empty() { DispatchOut::None } else { DispatchOut::Udp(&self.egress) };
    }

    // Too-fresh: fall back to resending the cold-start cached resp.
    let PeerState::Established(epochs) = &self.peers[idx].state else { unreachable!() };
    if !epochs.accept_rekey_init(now_ms, self.rekey_interval_ms) {
        self.egress.clear();
        if let Some(resp) = self.peers[idx].cached_resp.clone() {
            self.push_rekey_egress(idx, resp, via_relay, peer_addr);
        }
        return if self.egress.is_empty() { DispatchOut::None } else { DispatchOut::Udp(&self.egress) };
    }

    // Genuine new rekey round: build + install `next`, emit the Resp.
    let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
    let dp = Box::new(DataPlane::new(
        established, conn_tag, self.mode, peer_addr, self.obf_key.is_some(), self.data_symbol_size,
    ));
    let PeerState::Established(epochs) = &mut self.peers[idx].state else { unreachable!() };
    epochs.install_next(dp, init_eph, resp_pkt.clone());

    self.egress.clear();
    self.push_rekey_egress(idx, resp_pkt, via_relay, peer_addr);
    if self.egress.is_empty() { DispatchOut::None } else { DispatchOut::Udp(&self.egress) }
}
```

(Match the EXACT current borrow-juggling of `handle_rekey_init` — the multiple `let PeerState::Established(epochs)` re-borrows are already how it threads `&mut self` around `self.egress`/`self.peers`. Keep them; only the emit + `peer_addr` change.)

- [ ] **Step 3: Extract `rekey_resp_core`**

Rename `handle_rekey_resp`'s body into `rekey_resp_core(idx, dg, now_ms, via_relay)`. Two changes only: `peer_addr = if via_relay { self.server_addr() } else { rk.target }`; and the prime-emit loop pushes each `dp.on_tun_packet(..)` datagram via the helper (`via_relay` ⇒ `relay_wrap` its `.bytes`; else push as-is since its `dst` is already `peer_addr = rk.target`). Everything else (`epochs.rekey.take()`, `read_response`, `responder_cert_ok`, `promote_from_rekey`, `by_tag.remove(old)/insert(new)`) is UNCHANGED:

```rust
fn rekey_resp_core(&mut self, idx: usize, dg: &[u8], now_ms: u64, via_relay: bool) -> DispatchOut<'_> {
    let rk = {
        let PeerState::Established(epochs) = &mut self.peers[idx].state else {
            unreachable!("rekey_resp_core is only called for an Established peer")
        };
        match epochs.rekey.take() { Some(rk) => rk, None => return DispatchOut::None }
    };
    let peer_addr = if via_relay { self.server_addr() } else { rk.target };

    let (established, responder_payload) = match rk.hs.read_response(dg) {
        Ok(t) => t,
        Err(e) => { eprintln!("peer_manager: rekey read_response failed: {e}"); return DispatchOut::None; }
    };
    if !self.responder_cert_ok(&responder_payload, self.peers[idx].pubkey) {
        eprintln!("peer_manager: rekey responder cert rejected");
        return DispatchOut::None;
    }

    let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
    let mut dp = Box::new(DataPlane::new(
        established, conn_tag, self.mode, peer_addr, self.obf_key.is_some(), self.data_symbol_size,
    ));

    // Prime the new epoch (BEFORE dp moves into promote_from_rekey), emitting via the helper.
    let pending = std::mem::take(&mut self.peers[idx].pending_tun);
    self.egress.clear();
    let primed: Vec<Vec<u8>> = if pending.is_empty() {
        dp.on_tun_packet(&[], now_ms).iter().map(|d| d.bytes.clone()).collect()
    } else {
        pending.iter().flat_map(|inner| dp.on_tun_packet(inner, now_ms).iter().map(|d| d.bytes.clone()).collect::<Vec<_>>()).collect()
    };
    for bytes in primed {
        self.push_rekey_egress(idx, bytes, via_relay, peer_addr);
    }

    let old_tag = {
        let PeerState::Established(epochs) = &mut self.peers[idx].state else { unreachable!() };
        let old_tag = epochs.current().conn_tag();
        epochs.promote_from_rekey(dp, now_ms);
        old_tag
    };
    self.by_tag.remove(&old_tag);
    self.by_tag.insert(conn_tag, idx);

    if self.egress.is_empty() { DispatchOut::None } else { DispatchOut::Udp(&self.egress) }
}
```

- [ ] **Step 4: Make the direct handlers thin wrappers**

Replace `handle_rekey_init`'s body with `self.rekey_init_core(idx, established, resp_pkt, init_eph, now_ms, src, false)` (keep its existing signature/params). Replace `handle_rekey_resp`'s body with `self.rekey_resp_core(idx, dg, now_ms, false)`.

- [ ] **Step 5: Build + run the full suite (behavior-preserving gate)**

Run: `cargo build -p yipd` then `cargo test -p yipd`
Expected: PASS — every existing 9a direct-rekey unit test + all 2a/2b/2c tests stay green. The Direct path (`via_relay = false`) is byte-identical: `peer_addr = direct_src` and `push_rekey_egress(false)` = the old `EgressDatagram{ dst: src }`. If a test broke, the extraction changed Direct behavior — fix the extraction, not the test.

- [ ] **Step 6: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "refactor(rekey.91): extract rekey_init_core/rekey_resp_core (via_relay) — Direct path unchanged"
```

---

### Task 2: Wire the relay handlers to the cores

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (`relayed_handshake_init` Established arm ~1011, `relayed_handshake_resp` ~1074; add tests)

**Interfaces:**
- Consumes: `rekey_init_core`/`rekey_resp_core` (Task 1); `handshake::init_ephemeral`.

- [ ] **Step 1: Write the failing tests**

Add to `peer_manager.rs` tests (drive real relayed handshake packets, mirroring the existing `handle_rekey_init`/`resp` tests but through the relay handlers — use a relay-Established peer, `relay = true`):

```rust
#[test]
fn relay_rekey_init_retransmit_is_idempotent_new_ephemeral_builds_new_next() {
    // A relay-Established responder receives a rekey Init → builds `next`, sends a
    // relay-wrapped Resp. A RETRANSMIT (identical bytes → identical ephemeral)
    // resends the SAME cached Resp and does NOT replace `next` (conn_tag of `next`
    // unchanged). A NEW ephemeral (a genuinely new round) DOES build a new `next`.
}

#[test]
fn relay_rekey_resp_completes_and_promotes() {
    // A relay-Established peer with a rekey in flight receives the matching
    // relayed [HandshakeResp] → current becomes the new epoch (new conn_tag),
    // previous == old, rekey == None, by_tag updated.
}

#[test]
fn relay_rekey_emit_is_noop_when_relay_wrap_returns_none() {
    // With no rendezvous configured (relay_wrap → None), a relay rekey Init at an
    // Established peer produces no egress and does not corrupt state (current intact).
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --lib peer_manager::tests::relay_rekey`
Expected: FAIL — the relay handlers don't route to the cores yet.

- [ ] **Step 3: Wire `relayed_handshake_init`**

In its `Established` arm, replace the unconditional `cached_resp` resend with the core. After it computes `(established, resp_pkt)` from `start_responder`, add `let init_eph = crate::handshake::init_ephemeral(dg);` and call the core:

```rust
PeerState::Established(_) => {
    let Some(init_eph) = crate::handshake::init_ephemeral(dg) else {
        return DispatchOut::None; // malformed Init
    };
    self.rekey_init_core(idx, established, resp_pkt, init_eph, now_ms, self.server_addr(), true)
}
```

The core's `cached_resp_init_eph` dedup subsumes the old behavior: a cold-start Init retransmit (its ephemeral matches `cached_resp_init_eph`, set when the relay cold-start cached its resp) still resends `cached_resp`; a genuine rekey Init installs `next`. (`established`/`resp_pkt` are the ones this arm already built via `start_responder`; keep that construction.)

- [ ] **Step 4: Wire `relayed_handshake_resp`**

Add an Established-with-rekey-in-flight branch BEFORE the existing non-`Handshaking` drop:

```rust
if matches!(&self.peers[idx].state, PeerState::Established(epochs) if epochs.rekey.is_some()) {
    return self.rekey_resp_core(idx, dg, now_ms, true);
}
```

Keep the rest unchanged (a Resp for an Established peer with no rekey in flight still drops).

- [ ] **Step 5: Run tests**

Run: `cargo test -p yipd --lib peer_manager::` then `cargo test -p yipd`
Expected: PASS (the 3 new relay tests + all existing green).

- [ ] **Step 6: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(rekey.91): complete relay-path rekey (relayed_handshake_init/resp → cores)"
```

---

### Task 3: Remove the schedule gate + restore the relay Init emit

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (`drive_rekey_schedule` ~734; remove/replace the 9a `tick_does_not_rekey_relay_peer` test)

**Interfaces:**
- Consumes: `relay_wrap`, `server_addr`.

- [ ] **Step 1: Update the tests**

The 9a test `tick_does_not_rekey_relay_peer` asserted a relay peer does NOT rekey — now it DOES. Replace it with the inverse:

```rust
#[test]
fn tick_schedules_rekey_for_relay_winner_via_relay_wrap() {
    // An Established RELAY (relay = true) glare-winner peer, rekey_interval_ms small,
    // advanced past the interval → tick emits a RELAY-WRAPPED [HandshakeInit]
    // (a RelaySend to the rendezvous, per has_relayed_handshake_init), EpochSet.rekey
    // is Some, and `current` is intact. (Requires rendezvous configured so relay_wrap
    // returns Some — mirror the relay-peer test setup.)
}
```

Reuse the `has_relayed_handshake_init` helper (added in 9a) to detect the relay-wrapped Init.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --lib peer_manager::tests::tick_schedules_rekey_for_relay_winner_via_relay_wrap`
Expected: FAIL — the relay gate still returns early, no Init emitted.

- [ ] **Step 3: Remove the gate + restore relay-wrap Init emit**

In `drive_rekey_schedule`: delete the `if relay { return; }` block. Then, where it builds and emits the Init (and in the retransmit arm), branch on `relay`:
- `relay == false` (direct): unchanged — `target = self.peers[idx].endpoint` (return if `None`), emit `EgressDatagram { fate: 0, dst: target, bytes: init_pkt.clone() }`, set `RekeyInFlight.target = target`.
- `relay == true`: emit via `self.relay_wrap(idx, init_pkt.clone())` (a `None` skips this send — retransmit next tick; do NOT abort the round). Set `RekeyInFlight.target = self.server_addr()` (nominal — `rekey_resp_core` uses `server_addr()` for a relay peer's `peer_addr` anyway).
Apply the same `relay` branch in the retransmit arm (resend `rekey.init_pkt` verbatim, relay-wrapped when `relay`). Obf/jitter/glare-winner/one-in-flight/loser-fallback are unchanged.

- [ ] **Step 4: Run tests**

Run: `cargo test -p yipd`
Expected: PASS (the new relay-schedules test + all existing green; the old `tick_does_not_rekey_relay_peer` is gone).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(rekey.91): schedule + relay-wrap rekey Init for relay peers (remove the gate)"
```

---

### Task 4: netns relay-forced money test

Prove relay-only sessions rotate loss-free over the rendezvous relay.

**Files:**
- Create: `bin/yipd/tests/run-netns-rekey-relay.sh` (fork the relay + 9a rekey tests)
- Modify: `.github/workflows/integration.yml`

- [ ] **Step 1: Read the fork sources**

Read `bin/yipd/tests/run-netns-reality-relay.sh` (or `run-netns-relay*.sh`) — a two-peer topology where traffic goes over the rendezvous relay because the direct/punch paths can't connect — and the 9a `run-netns-rekey.sh` (fast `YIP_REKEY_INTERVAL_MS`, the `rekey_epoch_witness` on-wire proof, both-driver parameterization, ≤1%-loss + distinct-rounds assertions).

- [ ] **Step 2: Write `run-netns-rekey-relay.sh`**

`set -euo pipefail`, `trap` cleanup. Combine the two: a relay-forced topology (block the direct + hole-punch paths so the two peers MUST relay) launched with `YIP_REKEY_INTERVAL_MS=2000`, for BOTH drivers. Assertions (non-zero exit on failure):
1. **relay rekey continuity:** `ping -i 0.2 -c 100` A→B over the relay → ≤1% loss across ~10 rotations (relay carries the traffic AND the rekey handshakes; a rotation that black-holed the relay session would drop many).
2. **distinct rekey rounds actually happened:** note that on a relay path the `[HandshakeInit]`/`[HandshakeResp]` are wrapped INSIDE a `RelaySend`/`RelayDeliver` envelope, so the 9a `rekey_epoch_witness` (which parses a bare Init at `pkt[1..33]`) will NOT see the ephemeral directly on the peer↔relay veth. Prove rotation by one of (implementer's choice, document it): (a) extend `rekey_epoch_witness` (or a small sibling) to unwrap the `RelaySend`/`RelayDeliver` envelope and then read the inner Init/Resp ephemeral → `COMPLETED_ROUNDS >= 3`; OR (b) a log-based proof — grep both yipd peers' stderr for the rekey-completion path (e.g. a `promote_from_rekey`/rekey-completed marker; add a one-line `eprintln!` behind the existing rekey logging if none exists) and assert ≥3 completed rotations across the run, corroborated by the continuous ≤1% loss (a black-holed rotation would spike loss). Prefer (a) if the envelope is easy to strip; (b) is an acceptable, robust fallback.

- [ ] **Step 3: Run under sudo (both drivers)**

Run: `cargo build --release -p yipd` then `sudo bash bin/yipd/tests/run-netns-rekey-relay.sh` and `sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-rekey-relay.sh`
Expected: `PASS`, exit 0 on both. If the environment can't run netns, capture the exact blocker and report DONE_WITH_CONCERNS (controller decides).

- [ ] **Step 4: Wire CI + commit**

Add the script to `.github/workflows/integration.yml` alongside the sibling netns steps (both drivers, SKIP/`[FAIL]` guards like the 9a rekey step).

```bash
chmod +x bin/yipd/tests/run-netns-rekey-relay.sh
git add bin/yipd/tests/run-netns-rekey-relay.sh .github/workflows/integration.yml
git commit -m "test(rekey.91): netns relay-forced money test — loss-free rotation over the relay"
```

---

## After all tasks

- Final whole-branch review (opus) over the branch delta, focused on: the extraction being behavior-preserving for Direct (the security-critical idempotent path is single-sourced, not duplicated); relay rekey being fail-closed (a `relay_wrap` `None`/failed/timed-out rekey is a no-op on the live session); relay reordering not diverging the peers (idempotency exercised on the relay path); the gate removal not perturbing direct scheduling.
- Push; open a PR **stacked on #90** (base = `feat/rekey-9a-session-rotation`). Leave it for the user; do NOT merge; no "not merging" line.
- Update `yip-control-plane-status` memory (#91 done: relay peers now rotate) and note the 9a follow-up #91 is resolved.

## Self-Review notes

- **Behavior-preservation hinges on `via_relay = false` being byte-identical to the old direct handlers** — the extraction changes only `peer_addr` (`direct_src`/`rk.target`, unchanged for Direct) and the emit (`push_rekey_egress(false)` = the old `EgressDatagram{dst}`). The full 9a direct-rekey suite is the net.
- **`relay_wrap` returns `Option`** — every relay emit path treats `None` as a clean skip (retry next tick), never an abort or a partial-state commit. This is the fail-closed guarantee for relay.
- **Idempotency is single-sourced** — `rekey_init_core` holds the `cached_resp_init_eph`/`next_cached_resp_for`/`accept_rekey_init` logic once; both direct and relay get the exact convergence guarantee, so the relay copy can't drift from the 9a Critical fix.
