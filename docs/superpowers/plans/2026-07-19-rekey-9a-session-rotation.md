# Milestone 9a — classical session rekey (~120s) + epoch handling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rotate each peer's Noise-IK session ~every 120s (forward secrecy + per-epoch `conn_tag` rotation) with an old→new overlap so in-flight packets still decrypt — driven entirely from the daemon, with no wire-format change.

**Architecture:** A new pure `EpochSet` state machine (`bin/yipd/src/epoch.rs`) holds up to three `DataPlane` epochs (`current` for send, `next` = responder's unconfirmed new epoch, `previous` = receive-only grace). `PeerState::Established` carries a `Box<EpochSet>` instead of a `Box<DataPlane>`. `PeerManager::tick` schedules a mid-session rekey handshake (reusing the existing handshake machinery) and the completion paths promote epochs per the WireGuard confirmed-switch rule.

**Tech Stack:** Rust, `bin/yipd`, `yip-crypto` (unchanged), `snow` Noise-IK (unchanged), netns integration tests.

## Global Constraints

- `#![forbid(unsafe_code)]` (outside yip-io/yip-device) — NO `unsafe`, NO `as` casts, NO bare `#[allow]` (use `#[expect(reason = "...")]`).
- **Reuse `yip-crypto` and `bin/yipd/src/handshake.rs` UNCHANGED** — 9a only calls them (a rekey is an ordinary handshake whose result installs into an existing `EpochSet`).
- **NO wire-format change** (`yip-wire` untouched) — `conn_tag` is per-epoch already and is the epoch discriminator.
- **Fail-closed:** a rekey that fails/times out is a **no-op on the live session** (keep `current`, retry next interval) — rekey MUST NEVER tear down a working session. Every epoch `DataPlane` fails closed on inbound (wrong key → failed AEAD → try next epoch; no misdecrypt, no panic on attacker bytes).
- Constants: `REKEY_INTERVAL_MS = 120_000`, `PREVIOUS_EPOCH_GRACE_MS = 15_000`. The interval is **test-overridable** via the `YIP_REKEY_INTERVAL_MS` env var read once at `PeerManager` construction (default `REKEY_INTERVAL_MS`), matching the `YIP_USE_URING` netns-override precedent.
- Every task: `cargo build`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt` (**run fmt — do not `--no-verify` unformatted code**). Verify from ground truth: netns under BOTH the poll and `YIP_USE_URING=1` drivers; arq/netns use the **RELEASE** yipd (rebuild release after any yipd change).
- Out of scope (do NOT touch): PQ-hybrid (9b), full #34 handshake-timestamp anti-replay, #36, #41.
- Branch off `main`. Leave the PR for the user; do NOT merge; no "not merging" line.
- **Known pre-existing flake:** the pre-commit hook runs the whole workspace suite; two `yip-io::uring::tests::uring_*` loopback tests flake under load (unrelated crate). Commit `--no-verify` ONLY if that is the sole blocker AND the code is `cargo fmt`-clean.

---

### Task 1: The `EpochSet` pure state machine

The crux — I/O-free, heavily unit-tested, defines the API Tasks 2–4 consume.

**Files:**
- Create: `bin/yipd/src/epoch.rs`
- Modify: `bin/yipd/src/main.rs` (or wherever `mod` declarations live — add `mod epoch;`)

**Interfaces:**
- Consumes: `crate::dataplane::{DataPlane, Outcome}`, `yip_io::poll::EgressDatagram`.
- Produces:
  - `pub struct EpochSet { current, current_created_ms, next, previous, previous_retire_ms, rekey }` (fields `pub(crate)` as needed by Tasks 3–4).
  - `pub struct RekeyInFlight { pub hs: crate::handshake::HandshakeState, pub init_pkt: Vec<u8>, pub started_ms: u64, pub last_sent_ms: u64, pub retry_ms: u64, pub target: std::net::SocketAddr }`
  - `pub enum EpochInbound { None, Tun(Vec<u8>), Send(Vec<Vec<u8>>), TunThenSend(Vec<u8>, Vec<Vec<u8>>) }`
  - `EpochSet::new(current: Box<DataPlane>, now_ms) -> Self`
  - `EpochSet::inbound_open(&mut self, dg: &[u8], now_ms) -> EpochInbound`
  - `EpochSet::current_mut(&mut self) -> &mut DataPlane` and `current(&self) -> &DataPlane` (outbound/conn_tag)
  - `EpochSet::promote_from_rekey(&mut self, new_dp: Box<DataPlane>, now_ms)` (initiator switch)
  - `EpochSet::install_next(&mut self, new_dp: Box<DataPlane>)` (responder unconfirmed)
  - `EpochSet::retire_previous_if_due(&mut self, now_ms)`
  - `EpochSet::needs_rekey(&self, now_ms, is_glare_winner: bool, interval_ms: u64) -> bool`
  - `EpochSet::accept_rekey_init(&self, now_ms, interval_ms: u64) -> bool` (responder: ignore an Init against a too-fresh `current`)

- [ ] **Step 1: Write the failing tests**

Create `bin/yipd/src/epoch.rs` with a `#[cfg(test)] mod tests` up front. Use a tiny test-double `DataPlane` is not possible (it's concrete), so the tests use REAL `DataPlane`s built from an in-process handshake — reuse the existing `bin/yipd/src/dataplane.rs` test helper pattern (`established_pair()` around dataplane.rs:660 builds two talking `DataPlane`s via a real Noise-IK handshake). Expose a crate-visible test builder if needed. The behaviors to lock (write these first, watch them fail to compile / fail):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a fresh pair of talking DataPlanes (a "new epoch") on demand.
    // Reuse dataplane::tests::established_pair-style construction (two DataPlanes
    // whose sessions seal/open for each other). Return (a_side, b_side).
    fn epoch_pair() -> (Box<DataPlane>, Box<DataPlane>) { /* real handshake, as in dataplane tests */ }

    #[test]
    fn steady_state_inbound_uses_current_only() {
        // Only `current`; a frame sealed by the peer's current opens via inbound_open,
        // and there is no next/previous (one try).
    }

    #[test]
    fn initiator_promote_switches_outbound_and_grace_keeps_previous() {
        // promote_from_rekey(new) => current==new, previous==old, previous_retire_ms==now+GRACE.
        // A frame under the OLD epoch still opens (previous), a frame under NEW opens (current).
    }

    #[test]
    fn responder_install_next_then_first_inbound_promotes() {
        // install_next(new): current unchanged (still sends old); inbound under `next`
        // that yields a non-None outcome PROMOTES next->current (old->previous).
    }

    #[test]
    fn lost_msg2_leaves_both_on_old_no_blackhole() {
        // install_next(new) but NEVER feed a `next` frame => no promotion; current stays old,
        // and old-epoch frames still open. (Models a lost msg2: responder holds an unused next.)
    }

    #[test]
    fn previous_retired_at_grace_deadline() {
        // After promote, retire_previous_if_due(now < retire) keeps previous;
        // retire_previous_if_due(now >= retire) drops it (old-epoch frame no longer opens).
    }

    #[test]
    fn needs_rekey_trigger_and_one_in_flight_guard() {
        // age<interval => false; age>=interval && winner && rekey.is_none() => true;
        // rekey.is_some() => false (one-in-flight); loser && age>=2*interval => true (fallback);
        // loser && age in [interval, 2*interval) => false.
    }

    #[test]
    fn accept_rekey_init_ignores_too_fresh_current() {
        // age < interval/2 => false (ignore a rekey Init against a very fresh current);
        // age >= interval/2 => true.
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --lib epoch::`
Expected: FAIL — `epoch` module / types not defined.

- [ ] **Step 3: Implement `EpochSet`**

```rust
//! The per-peer session-epoch set (milestone 9a). Holds the live `current`
//! DataPlane plus, during a ~120s rekey overlap, an optional responder-side
//! `next` (derived from a rekey Init, not yet used for sending) and an
//! optional receive-only `previous` (the just-superseded epoch, kept for
//! in-flight frames until a grace deadline). Pure/I-O-free: `PeerManager`
//! drives the schedule and feeds it handshake results.

use std::net::SocketAddr;

use crate::dataplane::{DataPlane, Outcome};
use crate::handshake::HandshakeState;

/// Production rekey cadence (§ Global Constraints). Test-overridden via
/// `YIP_REKEY_INTERVAL_MS` at `PeerManager` construction.
pub const REKEY_INTERVAL_MS: u64 = 120_000;
/// How long the superseded `previous` epoch stays open for inbound after a
/// switch — generous vs. reordering/loss, bounded so keys don't linger.
pub const PREVIOUS_EPOCH_GRACE_MS: u64 = 15_000;

/// An in-flight initiator rekey handshake, held alongside the live `current`
/// so the session never pauses. Mirrors `HandshakingState`'s retransmit fields.
pub struct RekeyInFlight {
    pub hs: HandshakeState,
    pub init_pkt: Vec<u8>,
    pub started_ms: u64,
    pub last_sent_ms: u64,
    pub retry_ms: u64,
    pub target: SocketAddr,
}

/// Owned inbound result (the `PeerManager` demux already copies the borrowed
/// `Outcome` into owned Vecs at its call sites, so returning owned here is
/// free — and it sidesteps the multi-epoch borrow-return limitation).
pub enum EpochInbound {
    None,
    Tun(Vec<u8>),
    Send(Vec<Vec<u8>>),
    TunThenSend(Vec<u8>, Vec<Vec<u8>>),
}

pub struct EpochSet {
    pub(crate) current: Box<DataPlane>,
    pub(crate) current_created_ms: u64,
    pub(crate) next: Option<Box<DataPlane>>,
    pub(crate) previous: Option<Box<DataPlane>>,
    pub(crate) previous_retire_ms: u64,
    pub(crate) rekey: Option<RekeyInFlight>,
}

impl EpochSet {
    pub fn new(current: Box<DataPlane>, now_ms: u64) -> Self {
        Self {
            current,
            current_created_ms: now_ms,
            next: None,
            previous: None,
            previous_retire_ms: 0,
            rekey: None,
        }
    }

    pub fn current(&self) -> &DataPlane {
        &self.current
    }
    pub fn current_mut(&mut self) -> &mut DataPlane {
        &mut self.current
    }

    /// Convert a borrowed `Outcome` into the owned `EpochInbound` (same copies
    /// the caller already performed). Returns `None` for `Outcome::None`.
    fn own(outcome: Outcome<'_>) -> EpochInbound {
        match outcome {
            Outcome::None => EpochInbound::None,
            Outcome::TunWrite(b) => EpochInbound::Tun(b.to_vec()),
            Outcome::Send(pkts) => {
                EpochInbound::Send(pkts.iter().map(|d| d.bytes.clone()).collect())
            }
            Outcome::TunWriteThenSend(b, pkts) => {
                EpochInbound::TunThenSend(b.to_vec(), pkts.iter().map(|d| d.bytes.clone()).collect())
            }
        }
    }

    /// Open an inbound datagram against the epochs in order (current, then the
    /// responder's `next`, then the grace `previous`). Each `DataPlane` fails
    /// closed on a wrong key (cheap failed AEAD, no misdecrypt), so a wrong
    /// epoch simply yields `Outcome::None` and we try the next. A NON-None
    /// result under `next` means the peer has switched to the new epoch →
    /// promote it (responder confirmed-switch). Steady state (no next/previous)
    /// is a single try, identical to today.
    pub fn inbound_open(&mut self, dg: &[u8], now_ms: u64) -> EpochInbound {
        // current
        let out = Self::own(self.current.on_udp_datagram(dg, now_ms));
        if !matches!(out, EpochInbound::None) {
            return out;
        }
        // next (responder-side unconfirmed new epoch)
        if self.next.is_some() {
            let out = Self::own(
                self.next
                    .as_mut()
                    .expect("checked is_some")
                    .on_udp_datagram(dg, now_ms),
            );
            if !matches!(out, EpochInbound::None) {
                // Confirmed: promote next -> current, old current -> previous.
                let new = self.next.take().expect("checked is_some");
                let old = std::mem::replace(&mut self.current, new);
                self.current_created_ms = now_ms;
                self.previous = Some(old);
                self.previous_retire_ms = now_ms.saturating_add(PREVIOUS_EPOCH_GRACE_MS);
                return out;
            }
        }
        // previous (grace)
        if let Some(prev) = self.previous.as_mut() {
            return Self::own(prev.on_udp_datagram(dg, now_ms));
        }
        EpochInbound::None
    }

    /// Initiator switch on rekey completion: it now holds `new` AND knows the
    /// responder installed it (the responder sent the Resp), so switch outbound
    /// immediately; the old epoch becomes receive-only `previous`.
    pub fn promote_from_rekey(&mut self, new_dp: Box<DataPlane>, now_ms: u64) {
        let old = std::mem::replace(&mut self.current, new_dp);
        self.current_created_ms = now_ms;
        self.previous = Some(old);
        self.previous_retire_ms = now_ms.saturating_add(PREVIOUS_EPOCH_GRACE_MS);
        self.rekey = None;
    }

    /// Responder: a new epoch derived from a received rekey Init, kept for
    /// inbound but NOT used for sending until confirmed (see `inbound_open`).
    pub fn install_next(&mut self, new_dp: Box<DataPlane>) {
        self.next = Some(new_dp);
    }

    pub fn retire_previous_if_due(&mut self, now_ms: u64) {
        if self.previous.is_some() && now_ms >= self.previous_retire_ms {
            self.previous = None;
        }
    }

    /// Initiator schedule: rekey when `current` is old enough, none in flight,
    /// and this side is the glare-winner — OR the loser-fallback fires
    /// (`current` aged past 2× the interval and the winner never rekeyed).
    pub fn needs_rekey(&self, now_ms: u64, is_glare_winner: bool, interval_ms: u64) -> bool {
        if self.rekey.is_some() {
            return false;
        }
        let age = now_ms.saturating_sub(self.current_created_ms);
        if is_glare_winner {
            age >= interval_ms
        } else {
            age >= interval_ms.saturating_mul(2)
        }
    }

    /// Responder guard: ignore a rekey Init that arrives against a very fresh
    /// `current` (< interval/2 old) — bounds attacker-induced speculative
    /// handshakes without full timestamp anti-replay (#34).
    pub fn accept_rekey_init(&self, now_ms: u64, interval_ms: u64) -> bool {
        now_ms.saturating_sub(self.current_created_ms) >= interval_ms / 2
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p yipd --lib epoch::`
Expected: PASS — all epoch state-machine tests green.

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/epoch.rs bin/yipd/src/main.rs
git commit -m "feat(rekey.9a): EpochSet state machine (current/next/previous, WireGuard confirmed-switch)"
```

---

### Task 2: Swap `Established(Box<DataPlane>)` → `Established(Box<EpochSet>)` and route through it

Type-driven refactor: change the variant, then let the compiler surface every site and apply one transformation rule each. Behavior-preserving for the no-rekey case (steady state = one epoch).

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (the `PeerState` enum ~174; ~30 `Established(...)` sites; the cold-start completion sites ~875/929/1311/1381; the inbound sites 956/1082/1131; test helpers `fake_established_dataplane` at ~2447/3004/3142/3771 and the conn_tag accessor ~2549)

**Interfaces:**
- Consumes: `crate::epoch::{EpochSet, EpochInbound}` (Task 1).
- Produces: `PeerState::Established(Box<EpochSet>)`.

- [ ] **Step 1: Change the enum variant**

In `peer_manager.rs`:

```rust
enum PeerState {
    Idle,
    Handshaking(Box<HandshakingState>),
    Established(Box<crate::epoch::EpochSet>),
}
```

- [ ] **Step 2: Run the build to enumerate every broken site**

Run: `cargo build -p yipd 2>&1 | grep -E "error|Established" | head -60`
Expected: a list of ~25–30 sites. Apply these transformation rules (the compiler is the checklist):
- `matches!(state, PeerState::Established(_))` — **unchanged** (still matches).
- A site binding `PeerState::Established(dp)` then calling `dp.on_udp_datagram(dg, now)` (sites 956, 1082, 1131) → bind `epochs` and call `epochs.inbound_open(dg, now)`, matching on `EpochInbound` instead of `Outcome`. The three inbound sites currently produce `(Some(buf.to_vec()), ...)` / `(None, pkts...clone())` — map `EpochInbound::{None,Tun,Send,TunThenSend}` to the same owned tuples (the `.to_vec()`/`.clone()` now happen inside `inbound_open`, so just move the owned Vecs through).
- A site using `dp.on_tun_packet(...)` / `dp.conn_tag()` / any other `&DataPlane` method for OUTBOUND or metadata (e.g. 953→outbound, 2549 conn_tag) → `epochs.current_mut().on_tun_packet(...)` / `epochs.current().conn_tag()`.
- **Construction:** cold-start handshake completion that did `self.peers[idx].state = PeerState::Established(dp)` (sites ~875, 929, 1311, 1381) → `PeerState::Established(Box::new(EpochSet::new(dp, now_ms)))`. `dp` there is the `Box<DataPlane>` freshly built from the handshake — wrap it as the sole `current` epoch.
- **Test helpers:** `fake_established_dataplane(...)` returns a `Box<DataPlane>`; the sites that build `PeerState::Established(Box::new(fake_established_dataplane(..)))` → `PeerState::Established(Box::new(EpochSet::new(Box::new(fake_established_dataplane(..)), now)))`. Use a fixed `now` (e.g. `0`) in these test builders. The conn_tag test accessor (2549) → `epochs.current().conn_tag()`.

- [ ] **Step 3: Iterate build until clean**

Run: `cargo build -p yipd`
Expected: compiles. Every `Established`-binding site now goes through `EpochSet`.

- [ ] **Step 4: Run the FULL suite (behavior-preserving gate)**

Run: `cargo test -p yipd` (and the workspace: `cargo test -p yip-crypto -p yip-io`)
Expected: PASS — every existing 2a/2b/2c unit test stays green. Steady state has only `current`, so `inbound_open` is a single try and behavior is identical. If a test that reached into `Established(dp)` broke, it was coupling to the old shape — repoint it at `.current()`.

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "refactor(rekey.9a): PeerState::Established carries an EpochSet; route in/out through current epoch"
```

---

### Task 3: Rekey scheduling in `PeerManager::tick`

Schedule the mid-session rekey handshake without disturbing the live `current` epoch.

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (`tick`/`tick_dispatch` ~1767/1913; add a `rekey_interval_ms` field + `YIP_REKEY_INTERVAL_MS` read at construction; add a rekey-initiation helper; `begin_handshake` ~617 is the reference for building the initiator handshake)

**Interfaces:**
- Consumes: `EpochSet::{needs_rekey, retire_previous_if_due}`, `RekeyInFlight`, the existing `HandshakeState::start_initiator` + glare tiebreak.
- Produces: rekey Init egress datagrams; `EpochSet.rekey` populated while a rekey is in flight.

- [ ] **Step 1: Write the failing test**

Add to `peer_manager.rs` tests: with `rekey_interval_ms` set small (e.g. 100), an `Established` peer that is the glare-winner, advanced past the interval via `tick(now)`, emits a `[HandshakeInit]` and its `EpochSet.rekey` becomes `Some` while `current` is unchanged; a second `tick` before completion does NOT emit another Init (one-in-flight). A non-winner peer does not rekey until `2*interval`.

```rust
#[test]
fn tick_initiates_rekey_for_established_winner_once() {
    // Build a PeerManager with one Established winner peer (fake_established_dataplane),
    // rekey_interval_ms = 100, current_created_ms = 0.
    // tick(150): expect an egress [HandshakeInit]; EpochSet.rekey.is_some(); current intact.
    // tick(160): expect NO new Init (still one in flight).
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --lib peer_manager::tests::tick_initiates_rekey_for_established_winner_once`
Expected: FAIL — no rekey scheduling yet.

- [ ] **Step 3: Add the interval field + rekey initiation**

- Add `rekey_interval_ms: u64` to `PeerManager`; in the constructor set it from `std::env::var("YIP_REKEY_INTERVAL_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(crate::epoch::REKEY_INTERVAL_MS)`.
- Determine `is_glare_winner` with the **existing** static-key-order tiebreak used by the cold-start handshake (find how `begin_handshake`/glare compares `self.local_priv`/`self.public` vs `peer.pubkey` — reuse that exact comparison; do not invent a new one).
- In `tick_dispatch` (or `tick`), for each `Established` peer: call `retire_previous_if_due(now)`; if `epochs.needs_rekey(now, is_glare_winner, self.rekey_interval_ms)`, start a rekey: build `(hs, init_pkt) = HandshakeState::start_initiator(&self.local_priv, &peer.pubkey, &cert_payload)` (same `cert_payload` as `begin_handshake`), frame the Init toward the peer's committed endpoint/relay exactly as `begin_handshake` does, set `epochs.rekey = Some(RekeyInFlight { hs, init_pkt, started_ms: now, last_sent_ms: now, retry_ms: <jittered as cold-start>, target })`, and emit the Init datagram.
- **Retransmit / give up:** in the same tick pass, for an `Established` peer with `rekey = Some`, if `now - last_sent_ms >= retry_ms` resend `init_pkt` (update `last_sent_ms`, re-roll `retry_ms` like cold-start); if `now - started_ms >= HANDSHAKE_TOTAL_MS`, abandon (`epochs.rekey = None`) — keep `current`, retry at the next interval.
- The rekey Init rides the SAME obf/relay wrapping + `jitter_ms` timing as the cold-start Init (reuse `relay_wrap`/`jitter_ms`) — no new fingerprint.

- [ ] **Step 4: Run tests**

Run: `cargo test -p yipd --lib peer_manager::` then `cargo test -p yipd`
Expected: PASS (new rekey-scheduling test + all existing green).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(rekey.9a): schedule mid-session rekey in tick (winner-initiates, one-in-flight, loser-fallback)"
```

---

### Task 4: Rekey handshake completion wiring

Complete the confirmed-switch: initiator promotes on Resp; responder installs `next` on a rekey Init.

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (`handle_handshake_resp` ~1321, `handle_handshake_init` ~1182 — the arms that currently see an already-`Established` peer)

**Interfaces:**
- Consumes: `EpochSet::{promote_from_rekey, install_next, accept_rekey_init}`; `HandshakeState::read_response`/`start_responder` (unchanged); `DataPlane::new` + `conn_tag_from_keys` (the cold-start completion pattern).
- Produces: promoted epochs; updated `conn_tag → peer` map.

- [ ] **Step 1: Write the failing tests**

Two in-process tests (build two `PeerManager`s or drive the handshake packets directly, mirroring existing handshake tests):
```rust
#[test]
fn rekey_resp_promotes_initiator_and_keeps_previous_for_grace() {
    // An Established winner with rekey in flight receives the matching [HandshakeResp]:
    // EpochSet.current becomes the NEW epoch (new conn_tag), previous == old epoch,
    // rekey == None. A frame under the OLD keys still opens (previous); NEW keys open (current).
}

#[test]
fn rekey_init_on_established_installs_next_without_switching_send() {
    // An Established responder (current old enough per accept_rekey_init) receives a rekey
    // [HandshakeInit]: it emits a [HandshakeResp], EpochSet.next.is_some(), current UNCHANGED
    // (still sends old). A too-fresh current (< interval/2) ignores the Init (no next, no Resp).
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --lib peer_manager::tests::rekey_resp_promotes_initiator_and_keeps_previous_for_grace`
Expected: FAIL.

- [ ] **Step 3: Implement completion**

- **`handle_handshake_resp` for an `Established` peer with `epochs.rekey = Some`:** `read_response` consumes the handshake by value, so **take the `RekeyInFlight` out** first (`let Some(rk) = epochs.rekey.take() else { return … }`) and call `rk.hs.read_response(resp_pkt)` → `Established { session, auth_key, hp_key, .. }`; build the new `Box<DataPlane>` exactly as cold-start does (`DataPlane::new(established, conn_tag_from_keys(&auth_key,&hp_key), mode, peer_addr, obf_on, symbol_size)`); call `epochs.promote_from_rekey(new_dp, now)`; update the `conn_tag → peer` map (remove old tag, insert new); emit the peer's next outbound frame or one keepalive on the new epoch (`epochs.current_mut()`), so the responder receives a `next`-epoch frame and switches. If `read_response` errors, `epochs.rekey = None` (no-op, keep `current`).
- **`handle_handshake_init` for an already-`Established` peer:** if `!epochs.accept_rekey_init(now, self.rekey_interval_ms)`, ignore (return no Resp). Otherwise run `HandshakeState::start_responder(&self.local_priv, init_pkt, ...)` → `(Established, resp_pkt)` (same admission/cert-verify as cold-start), build the new `Box<DataPlane>`, `epochs.install_next(new_dp)` (do NOT touch `current`), and emit `resp_pkt`. The responder's switch happens later inside `inbound_open` (Task 1) on the first `next`-epoch frame.
- Do NOT change the cold-start (non-`Established`) arms of these handlers.

- [ ] **Step 4: Run tests**

Run: `cargo test -p yipd`
Expected: PASS (both completion tests + all existing green).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(rekey.9a): complete rekey — initiator promote on Resp, responder install_next on Init"
```

---

### Task 5: netns money tests (the end-to-end gate)

Prove rotation is loss-free and the `conn_tag` actually rotates on the wire.

**Files:**
- Create: `bin/yipd/tests/run-netns-rekey.sh` (fork the closest existing peer-to-peer tunnel test)
- Modify: `.github/workflows/integration.yml` (add the step alongside the sibling netns tests)

- [ ] **Step 1: Read the existing tunnel netns test to reuse plumbing**

Run: `ls bin/yipd/tests/run-netns-*.sh` and read `run-netns-tunnel.sh` (two peers, a steady ping/data stream, both drivers). Reuse its namespace/veth setup, the two-peer config, and its packet-count/ping assertions.

- [ ] **Step 2: Write `run-netns-rekey.sh`**

`set -euo pipefail`, trap-cleanup namespaces. Launch both yipd peers with **`YIP_REKEY_INTERVAL_MS=2000`** (fast rotation) — for BOTH the poll and `YIP_USE_URING=1` driver (parameterize like the sibling scripts). Assertions (non-zero exit on any failure):
1. **rekey_continuity:** run a steady stream (e.g. `ping -i 0.2 -c 100` A→B, ~20s = ~10 rotations) and assert **0% (or below a strict threshold, e.g. ≤1) packet loss** across the whole run — the session survives many rotations with no application-visible gap.
2. **conn_tag rotation:** `tcpdump`/capture the UDP payloads on the veth during the run; assert the first 8 header bytes (the masked `conn_tag`, as an on-path observer sees them) take **more than one distinct value** over the run for the same peer pair (i.e. it rotated), whereas a single-epoch run would show one. (A coarse check: `sort -u` of the first-8-bytes hex across captured data datagrams has >1 line.)

Add a second script or a netem branch for **rekey_under_loss** (10% netem loss on the veth during the run) asserting the ping stream still completes (session survives; lost msg2 just retries).

- [ ] **Step 3: Run under sudo (both drivers)**

Run: `sudo bash bin/yipd/tests/run-netns-rekey.sh` and `sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-rekey.sh`
Expected: `PASS`, exit 0 on both. (Rebuild the RELEASE yipd first — `cargo build --release -p yipd` — the netns scripts use the release binary.)
If the environment cannot run netns (no root/kernel), capture the exact blocker and report DONE_WITH_CONCERNS; the controller decides whether to run it or defer.

- [ ] **Step 4: Confirm no regression + wire CI**

Run the existing `run-netns-tunnel.sh` / triangle / relay tests at the PRODUCTION interval (no `YIP_REKEY_INTERVAL_MS`) to confirm rekey-at-120s doesn't perturb them (they run <120s so rekey never fires, but confirm green). Add the new script to `.github/workflows/integration.yml` next to the sibling netns steps (grep the workflow for `run-netns`).

- [ ] **Step 5: Commit**

```bash
chmod +x bin/yipd/tests/run-netns-rekey.sh
git add bin/yipd/tests/run-netns-rekey.sh .github/workflows/integration.yml
git commit -m "test(rekey.9a): netns money test — loss-free rotation + on-wire conn_tag rotation"
```

---

## After all tasks

- Final whole-branch review (opus) over the branch delta, focused on: the `EpochSet` switch state machine (no black-hole on lost msg2; promotion only on confirmed `next` inbound; `previous` retirement), rekey-never-tears-down-a-working-session, the glare-winner/loser-fallback trigger, and behavior-preservation of the steady-state (single-epoch) path (2a/2b/2c green).
- Push; open a PR off `main`. Leave it for the user; do NOT merge; no "not merging" line.
- Update `yip-control-plane-status` memory (9a rekey shipped; conn_tag rotates per epoch; 9b = PQ-hybrid next; #34/#36/#41 still open but now have the rekey machinery to ride).

## Self-Review notes

- **Borrow-checker:** `inbound_open` returns OWNED `EpochInbound` (not a borrowed `Outcome`) precisely so the try-current→next→previous chain compiles on stable Rust — and it is free because the three `on_udp_datagram` caller sites already `.to_vec()`/`.clone()` the outcome. Steady state stays a single `on_udp_datagram` call.
- **Promotion signal:** the responder promotes `next`→`current` on the first `next` frame that yields a **non-None** outcome (a decoded inner packet or an ARQ send) — `Outcome::None` is ambiguous (auth-fail vs partial-FEC), so a bare auth-success is not used as the trigger; promotion is at worst delayed to the first fully-decoded new-epoch packet, which is harmless (the responder keeps sending old until then, the initiator receives it on `previous`).
- **No cross-epoch replay:** each epoch's counter/replay window lives in its own `Session`; a counter value is only meaningful within one `DataPlane`, so trying a frame against the wrong epoch fails AEAD (never a replay-accept).
