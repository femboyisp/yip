# Authenticated Endpoint Roaming (M2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a peer's `endpoint` follow a legitimate address change (NAT rebind / mobility), gated on cryptographic authentication, so a roamed peer recovers on the first authenticated packet instead of black-holing until re-handshake.

**Architecture:** WireGuard's roaming rule — update `peers[idx].endpoint` to a datagram's source **only** when that datagram decrypts and passes the AEAD replay window (a successful `EpochSet::inbound_open`, which internally runs `SessionKeys::open` → `ReplayWindow::check_and_set`). A replayed or spoofed packet fails and cannot move the endpoint. Additionally, the obfuscated-ingress key selector (`deobf_ingress`) is given a trial-key fallback so a roamed peer's data can be deobfuscated when the `endpoint == src` fast-path misses — mirroring the plaintext demux's existing roaming fallback loop.

**Tech Stack:** Rust, `bin/yipd` (binary crate), `crates/yip-obf`, `crates/yip-crypto` (unchanged — the replay window already exists).

## Global Constraints

- `#![forbid(unsafe_code)]`; no `as` casts except `PacketType::X as u8`; no bare `#[allow]` (use `#[expect(reason = …)]`).
- RUN `cargo fmt` (never `--no-verify`); `cargo clippy -- -D warnings` must be clean.
- `yipd` is a BINARY: test with `cargo test -p yipd --bin yipd`.
- netns money tests use the RELEASE binary under BOTH the poll and `YIP_USE_URING=1` drivers; rebuild release after every yipd change.
- Preserve #34: an unauthenticated Init still must never move an Established peer's `endpoint`. Only an AEAD-authenticated, non-replayed data/control packet may.
- Leave the PR for the user to review + merge; no "not merging" line.

## File Structure

- `bin/yipd/src/peer_manager.rs` — the roaming relearn (in `dispatch_established` + the roaming fallback loop in `handle_data_or_control`) and the `deobf_ingress` trial-key fallback. All changes live here.
- `bin/yipd/tests/run-netns-roaming.sh` — new netns money test (mid-session rebind recovery, obf path).
- `.github/workflows/integration.yml` — wire the new netns test.

---

### Task 1: Relearn `endpoint` on an authenticated inbound packet

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` — `dispatch_established` (~1471) and `handle_data_or_control`'s roaming fallback loop (~1535).
- Test: same file's `#[cfg(test)] mod tests`.

**Interfaces:**
- Consumes: `fn route_data(&self, src: SocketAddr, dg: &[u8]) -> Option<usize>` (~1452); `fn dispatch_established(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_>` (~1471); `EpochSet::inbound_open` returns `EpochInbound` — a non-`None` variant means the packet authenticated and passed the replay window.
- Produces: a private helper `fn relearn_endpoint(&mut self, idx: usize, src: SocketAddr)` used at both authenticated-decrypt sites.

**Context:** `dispatch_established` is called from `handle_data_or_control` (~1512) with the `idx` from `route_data(src, …)` — but `src` is not currently passed in. Thread `src` down so the relearn has it. `route_data` demuxes by `by_tag` (address-independent) first, so a roamed peer's plaintext data already reaches `dispatch_established`; the relearn heals the *stale endpoint* that would otherwise misdirect `drive_rekey_schedule`'s initiator rekeys and the obf key selector.

- [ ] **Step 1: Write the failing test — authenticated packet from a new src updates endpoint**

Add to the tests module. Use the existing test helpers that establish two peers (search the test module for an existing `establish_*`/`handshake_*` helper that yields a `PeerManager` with one `Established` direct peer at index 0 and a known `endpoint`; reuse it — do not invent a new establishment path). The test drives one authenticated data datagram from a NEW source address and asserts `endpoint` moved.

```rust
#[test]
fn authenticated_data_from_new_src_roams_endpoint() {
    // Two direct peers, established; peer[0].endpoint == old_ep.
    let (mut pm_r, mut pm_i, old_ep, _new_ep) = established_pair_for_roaming();
    // Initiator sends a real data packet; capture its on-wire bytes.
    let data = pm_i.on_tun_packet(&sample_inner_v6_packet()); // yields EgressDatagram(s)
    let dg = first_udp_bytes(&data);
    let new_src = addr("198.51.100.222:60000");
    assert_ne!(new_src, old_ep);
    // Deliver from the NEW source.
    let _ = pm_r.on_udp(new_src, &dg, 1_000);
    assert_eq!(
        pm_r.peers[0].endpoint,
        Some(new_src),
        "endpoint must follow an authenticated packet from a new source",
    );
}
```

If no `established_pair_for_roaming`/`sample_inner_v6_packet`/`first_udp_bytes` helper exists, write minimal ones next to the test by reusing the module's existing establishment helper and the existing `on_tun_packet` path (grep the test module for how other tests craft a data datagram — several already do).

- [ ] **Step 2: Run it — expect FAIL** (`endpoint` stays `old_ep`).

Run: `cargo test -p yipd --bin yipd authenticated_data_from_new_src_roams_endpoint`
Expected: FAIL — `endpoint` is still `Some(old_ep)`.

- [ ] **Step 3: Add the relearn helper and call it at both authenticated-decrypt sites**

Add the helper (place it next to `dispatch_established`):

```rust
/// WireGuard-style roaming: after a datagram has AUTHENTICATED and passed
/// the replay window (a non-`None` `inbound_open`), point a direct peer's
/// `endpoint` at the observed source. A `relay` peer's `endpoint` is a
/// rendezvous placeholder and must not roam. Gated on `src` differing so
/// steady-state traffic is a no-op. This never runs for an unauthenticated
/// Init (that path does not call `inbound_open`), preserving #34.
fn relearn_endpoint(&mut self, idx: usize, src: SocketAddr) {
    if !self.peers[idx].relay && self.peers[idx].endpoint != Some(src) {
        self.peers[idx].endpoint = Some(src);
    }
}
```

Thread `src` into `dispatch_established` and call the helper when `inbound_open` returns a non-`None` variant. Change the signature to `fn dispatch_established(&mut self, idx: usize, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_>` and, inside, capture whether the open authenticated before building the borrowed return:

```rust
fn dispatch_established(&mut self, idx: usize, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
    let PeerState::Established(epochs) = &mut self.peers[idx].state else {
        return DispatchOut::None;
    };
    let opened = epochs.inbound_open(dg, now_ms);
    if !matches!(opened, crate::epoch::EpochInbound::None) {
        self.relearn_endpoint(idx, src); // authenticated → safe to roam
    }
    match opened {
        crate::epoch::EpochInbound::None => DispatchOut::None,
        crate::epoch::EpochInbound::Tun(buf) => {
            self.tun_scratch = buf;
            DispatchOut::Tun(&self.tun_scratch)
        }
        crate::epoch::EpochInbound::Send(dgs) => {
            self.egress = dgs;
            DispatchOut::Udp(&self.egress)
        }
        crate::epoch::EpochInbound::TunThenSend(buf, dgs) => {
            self.tun_scratch = buf;
            self.egress = dgs;
            DispatchOut::Both(&self.tun_scratch, &self.egress)
        }
    }
}
```

Update its call site (~1512) to pass `src`: `return self.dispatch_established(idx, src, dg, now_ms);`.

In the roaming fallback loop (~1535-1568), after a `hit` is found for `idx`, call `self.relearn_endpoint(idx, src);` before materializing the borrowed return (the `epochs` borrow has already ended by then).

- [ ] **Step 4: Run — expect PASS.**

Run: `cargo test -p yipd --bin yipd authenticated_data_from_new_src_roams_endpoint`
Expected: PASS.

- [ ] **Step 5: Write the anti-hijack regression tests**

```rust
#[test]
fn replayed_data_from_spoofed_src_does_not_roam_endpoint() {
    let (mut pm_r, mut pm_i, old_ep, _new) = established_pair_for_roaming();
    let data = pm_i.on_tun_packet(&sample_inner_v6_packet());
    let dg = first_udp_bytes(&data);
    // First delivery from the legit endpoint authenticates and is consumed.
    let _ = pm_r.on_udp(old_ep, &dg, 1_000);
    // REPLAY the same datagram from a spoofed source: fails the replay window.
    let spoof = addr("203.0.113.66:5555");
    let _ = pm_r.on_udp(spoof, &dg, 1_001);
    assert_eq!(pm_r.peers[0].endpoint, Some(old_ep),
        "a replayed packet must not move the endpoint");
}

#[test]
fn relay_peer_endpoint_does_not_roam() {
    // A relay-established peer: relearn_endpoint must be a no-op.
    let (mut pm, relay_idx, placeholder) = established_relay_peer();
    // Any authenticated inbound from a different src must NOT move it.
    pm.relearn_endpoint(relay_idx, addr("198.51.100.9:7000"));
    assert_eq!(pm.peers[relay_idx].endpoint, placeholder);
}
```

Reuse existing relay-establishment test helpers if present (search for `relay` in the test module — the #91/#36 tests establish relay peers). If `established_relay_peer` does not exist, adapt the closest existing relay-peer test setup; the assertion is what matters — a relay peer's `endpoint` is unchanged by `relearn_endpoint`.

Also assert #34 is preserved with an existing-style Init test: an unauthenticated Init from a spoofed src against the Established responder still does not move `endpoint` (the pre-existing `stale_replayed_cold_start_init_does_not_hijack_endpoint`-style guard already covers the Init path; add a one-line comment referencing it rather than duplicating, since M2 does not touch the Init path).

- [ ] **Step 6: Run all three + the full suite.**

Run: `cargo test -p yipd --bin yipd`
Expected: all pass, including the pre-existing #34/#91 endpoint tests (they must stay green — M2 must not regress the Init-path immovability).

- [ ] **Step 7: fmt + clippy + commit**

```bash
cargo fmt
cargo clippy -p yipd --bin yipd -- -D warnings
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(roaming.m2): endpoint follows an authenticated, non-replayed inbound packet"
```

---

### Task 2: `deobf_ingress` trial-key fallback for a roamed peer

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` — `deobf_ingress` (~2455).
- Test: same file's tests module.

**Interfaces:**
- Consumes: `fn deobf_ingress(&self, src: SocketAddr, dg: &[u8]) -> Option<Vec<u8>>`; each peer's `session_obf_key: Option<[u8;32]>`; `yip_obf::deobfuscate(&key, dg) -> Option<(u8, Vec<u8>)>`; `yip_obf::JUNK_TYPE`; `PacketType::{Data,Control,Gossip}`.
- Produces: unchanged signature; the function now also finds the key by trial when the `endpoint == src` fast-path misses.

**Context:** Under obfuscation, `deobf_ingress` step (a) selects a peer's `session_obf_key` by `p.endpoint == Some(src)`. A roamed peer's new src fails that match, and step (b) (network key) only accepts handshake types — so the roamed peer's Data is dropped before it can ever authenticate and relearn its endpoint. The fix: when (a) misses, trial every Established peer's `session_obf_key` for a `Data`/`Control`/`Gossip` result, exactly as the plaintext demux's roaming fallback loop trials every peer's codec. A wrong key yields `None`/garbage and the inner AEAD verify drops it safely (the function's own doc-comment already states this invariant), so the trial cannot mis-dispatch.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn deobf_finds_roamed_peer_session_key_by_trial() {
    // Established, obfuscation ON; peer[0].endpoint == old_ep with a session_obf_key.
    let (pm, key, plaintext_data_dg) = established_obf_peer_with_data();
    // Obfuscate a Data datagram under the peer's session key.
    let obf = yip_obf::obfuscate(&key, PacketType::Data as u8, &plaintext_data_dg).unwrap();
    // Arrive from a NEW src that does NOT match endpoint.
    let roamed = addr("198.51.100.231:41111");
    let out = pm.deobf_ingress(roamed, &obf);
    assert!(out.is_some(), "roamed peer's data must deobfuscate via trial fallback");
}
```

Reuse an existing obf-enabled establishment helper if the test module has one (search for `session_obf_key` / `obf_key` in tests). If none, construct a minimal `PeerManager` with `obf_key = Some(..)` and one Established peer carrying a known `session_obf_key`, mirroring the closest existing obf test.

- [ ] **Step 2: Run — expect FAIL** (returns `None`, key not found by endpoint match).

Run: `cargo test -p yipd --bin yipd deobf_finds_roamed_peer_session_key_by_trial`
Expected: FAIL.

- [ ] **Step 3: Add the trial fallback**

After step (a)'s `endpoint == src` block returns nothing, and before (b)'s network-key block, insert a trial over Established peers' session keys:

```rust
// (a') Roaming fallback: no endpoint match, but the datagram may be a
// roamed Established peer's Data/Control/Gossip under its session key.
// Trial each Established peer's session key; a wrong key yields None or a
// garbage type that the type-set + inner verify drop safely (same
// invariant as `handle_data_or_control`'s plaintext roaming loop).
for p in &self.peers {
    if !matches!(p.state, PeerState::Established(_)) {
        continue;
    }
    let Some(key) = p.session_obf_key else { continue };
    if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
        if ptype == yip_obf::JUNK_TYPE {
            return None;
        }
        if ptype == PacketType::Data as u8
            || ptype == PacketType::Control as u8
            || ptype == PacketType::Gossip as u8
        {
            return Some(reassemble(ptype, &body));
        }
    }
}
```

Place this so it does not shadow the existing endpoint fast-path (which stays first for the common case). Keep (b)'s network-key handshake branch after it.

- [ ] **Step 4: Run — expect PASS.**

Run: `cargo test -p yipd --bin yipd deobf_finds_roamed_peer_session_key_by_trial`
Expected: PASS.

- [ ] **Step 5: Guard test — a non-roamed junk/foreign datagram still drops**

```rust
#[test]
fn deobf_trial_does_not_accept_foreign_datagram() {
    let (pm, _key, _d) = established_obf_peer_with_data();
    let garbage = vec![0xABu8; 64];
    assert!(pm.deobf_ingress(addr("203.0.113.9:9"), &garbage).is_none(),
        "a datagram under no known session key must not deobfuscate");
}
```

- [ ] **Step 6: Run the full suite.**

Run: `cargo test -p yipd --bin yipd`
Expected: all pass; the existing obf tests (`run-netns-obf-mismatch` peers, JUNK handling) stay green.

- [ ] **Step 7: fmt + clippy + commit**

```bash
cargo fmt
cargo clippy -p yipd --bin yipd -- -D warnings
git add bin/yipd/src/peer_manager.rs
git commit -m "feat(roaming.m2): deobf_ingress trials session keys so a roamed peer's data is found"
```

---

### Task 3: netns money test — mid-session NAT rebind recovery (obf) + CI

**Files:**
- Create: `bin/yipd/tests/run-netns-roaming.sh`
- Modify: `.github/workflows/integration.yml`

**Interfaces:**
- Consumes: the two-peer direct/punch netns harness pattern (fork `bin/yipd/tests/run-netns-punch.sh` or `run-netns-tunnel.sh`); the both-driver parameterization + `set -euo pipefail` + `trap` + `[PASS]`/`[FAIL]`/SKIP conventions from `run-netns-rekey.sh`.
- Produces: an exit-gated assertion that a rebound peer recovers.

**Context:** A and B are direct, established, obfuscation ON. Change A's source address mid-session (re-NAT: move A's egress to a new address via a NAT/veth reconfiguration, or restart A's socket bound to a new port that the topology SNATs differently) WITHOUT tearing down the session, then keep A sending. Assert B keeps delivering (ping A→B resumes with ≤1% loss over a measured window that spans the rebind), proving B relearned A's endpoint and deobfuscated A's data from the new source.

- [ ] **Step 1: Read the fork sources**

Read `run-netns-punch.sh` (two-peer direct topology, obf config), `run-netns-tunnel.sh` (steady ping harness), and `run-netns-rekey.sh` (both-driver param + guards). Identify how existing tests enable obfuscation in the yipd config (`obf_psk`/`obf_key`) — the roaming test MUST run with obfuscation ON, since that is the path M2's Task 2 heals.

- [ ] **Step 2: Write `run-netns-roaming.sh`**

Topology: A and B in separate netns with a direct path, obf enabled. Establish, warm up a ping A→B. Then change A's observed source address (e.g. reconfigure the SNAT/veth so A's packets now arrive at B from a new address, or bounce A's UDP bind to a new port with a matching SNAT change) — the key is that B sees A's authenticated data arrive from a NEW `src` while the session (keys, conn_tag) is unchanged. Run a measured `ping A→B -i0.2 -c100` spanning the rebind. Assertions (each non-zero exit on failure, `[PASS]`/`[FAIL]` markers): (1) measured loss ≤1% (a separate one-time warm-up ping before the rebind absorbs any single-packet transition and is NOT counted); (2) B's stderr shows no persistent drop after the rebind (optional: assert the ping simply succeeds — the loss bound is the real gate). `set -euo pipefail`, `trap` cleanup, SKIP when not root. Parameterize BOTH drivers via `YIP_USE_URING`.

- [ ] **Step 3: Run under sudo, both drivers**

```bash
cargo build --release -p yipd -p yip-rendezvous
sudo bash bin/yipd/tests/run-netns-roaming.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-roaming.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
```
Expected: PASS, exit 0 both. If the environment cannot run netns, capture the exact blocker and report DONE_WITH_CONCERNS.

- [ ] **Step 4: Wire CI + commit**

Add the new test to `.github/workflows/integration.yml` next to the sibling netns steps (both drivers, same SKIP/`[FAIL]` guards). `chmod +x`.

```bash
chmod +x bin/yipd/tests/run-netns-roaming.sh
git add bin/yipd/tests/run-netns-roaming.sh .github/workflows/integration.yml
git commit -m "test(roaming.m2): netns — mid-session NAT rebind recovers on the obf path"
```

---

## After all tasks

- Final whole-branch review (opus) over the M2 delta. Focus: the relearn fires ONLY on a non-`None` `inbound_open` (authenticated + replay-passed); relay peers never roam; the Init path is untouched (#34 immovability preserved); the `deobf_ingress` trial cannot mis-dispatch (wrong key → safe drop); no `unsafe`/`as`/bare-`allow`.
- This is one PR of the authenticated-reachability milestone (the other is #37). Leave it for the user; no "not merging" line.
