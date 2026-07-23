# Signed Rendezvous Registration (#37) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the rendezvous registration-overwrite DoS (#37): require a member-signed `Record` to register in a mesh, verified against the CA roots server-side (reachability) and re-verified peer-side on lookup (targeting integrity).

**Architecture:** The registration IS a `membership::Record` (`{node_id, cert, endpoints, seq, sig}`) — already member-signed, cert-carrying, and `seq`-monotonic, with `Record::verify(ca_pubkeys, network_id, now, skew)` performing cert-vs-roots + signature + `node_id == node_id(cert.member_pubkey)` (squatting closed). A new `RegisterSigned` message carries it; `PeerInfo` gains an optional `record`. The rendezvous server, when configured with roots (mesh mode), verifies before storing and drops legacy unsigned `Register`; without roots it keeps the legacy identity-agnostic path (non-mesh byte-identical). Option 3 defense-in-depth: peers re-verify the returned record before probing.

**Tech Stack:** Rust — `crates/yip-rendezvous` (proto + server), `crates/yip-membership` (Record/RootSet, reused), `bin/yip-rendezvous` (server binary/args), `bin/yipd` (client: `rendezvous.rs` + `peer_manager.rs` + `membership.rs`).

## Global Constraints

- `#![forbid(unsafe_code)]`; no `as` casts except `PacketType::X as u8`; no bare `#[allow]` (use `#[expect(reason = …)]`).
- RUN `cargo fmt`; `cargo clippy -- -D warnings` clean across the workspace.
- `yipd` is a BINARY: `cargo test -p yipd --bin yipd`. `yip-rendezvous` lib: `cargo test -p yip-rendezvous`.
- Clock split: TTL/rate use monotonic `now_ms`; cert/record validity uses wall-clock `now_secs`. Reuse the `YIP_CERT_SKEW_SECS`-driven skew convention from #41 where a skew is needed.
- No new crypto — reuse `Record`, `Record::verify`, `RootSet::verify_rootset`, `build_signed_record`.
- Mesh-only: signing is required only when membership/roots are configured. Non-mesh keeps the legacy unsigned `Register`, byte-identical.
- netns money tests use RELEASE binaries under BOTH poll and `YIP_USE_URING=1`.
- Leave the PR for the user; no "not merging" line.

## File Structure

- `crates/yip-rendezvous/src/proto.rs` — `Tag::RegisterSigned = 7`, `Message::RegisterSigned { record }`, optional `record` on `Message::PeerInfo`, codec + tests.
- `crates/yip-rendezvous/src/server.rs` — roots/network_id config, `new_with_roots`, `RegisterSigned` verify+store, legacy-drop-when-rooted, `PeerInfo` carries stored record.
- `crates/yip-membership/src/lib.rs` (+ re-exports) — nothing new required; `Record`/`build_signed_record` already exist. (Server uses `Record::verify` directly.)
- `bin/yipd/src/membership.rs` — `sign_registration(seq)` + `verify_record(record, now_secs)` accessors on `Membership`.
- `bin/yipd/src/rendezvous.rs` — `register` threads a signed `Record`; `parse` verifies `PeerInfo.record`.
- `bin/yipd/src/peer_manager.rs` — mint the registration record (monotonic seq) and pass it to `register`; give `parse`'s verifier the membership context.
- `bin/yip-rendezvous/src/main.rs` — `--roots <file>` + `--network-id <hex16>` args; load + `verify_rootset`; construct via `new_with_roots`.
- `bin/yipd/tests/run-netns-registration-hijack.sh` + `.github/workflows/integration.yml`.

---

### Task 1: `RegisterSigned` message + optional `PeerInfo.record` (proto codec)

**Files:**
- Modify: `crates/yip-rendezvous/src/proto.rs`
- Test: same file's `#[cfg(test)] mod tests`.

**Interfaces:**
- Consumes: `membership::Record` with `Record::encode(&self, &mut Vec<u8>)` / `Record::decode(&[u8]) -> Option<Record>`; existing `put_addr`/`take_addr`, `Tag` enum, `encode`/`decode`.
- Produces: `Message::RegisterSigned { record: Record }` (`Tag = 7`); `Message::PeerInfo { node, reflexive, record: Option<Record> }`.

**Context:** `yip-rendezvous` must depend on `yip-membership` (add to its `Cargo.toml` if not already a dependency — check first). `Record::encode` writes a self-delimiting form? It writes `record_signing_body` + sig; `Record::decode` requires an exact slice. For embedding in a message, length-prefix the encoded record with a `u16` (mirror how `record_signing_body` length-prefixes the cert), so decode can slice it exactly.

- [ ] **Step 1: Add the dependency + tag.** Confirm `yip-membership` is in `crates/yip-rendezvous/Cargo.toml`; add it if missing. Add `RegisterSigned = 7` to `Tag`.

- [ ] **Step 2: Write the failing roundtrip tests**

```rust
#[test]
fn register_signed_roundtrips() {
    let rec = sample_record(); // build a minimal valid-shaped Record (see helper note)
    roundtrip(Message::RegisterSigned { record: rec });
}

#[test]
fn peerinfo_with_record_roundtrips() {
    roundtrip(Message::PeerInfo {
        node: [7u8; 16],
        reflexive: addr("198.51.100.7:41000"),
        record: Some(sample_record()),
    });
}

#[test]
fn peerinfo_without_record_roundtrips_and_is_backward_compatible() {
    roundtrip(Message::PeerInfo {
        node: [7u8; 16],
        reflexive: addr("198.51.100.7:41000"),
        record: None,
    });
}
```

`sample_record()`: build a `Record` with a decode-valid shape (a real cert via the membership test helpers, or the smallest cert `Record::decode` accepts). Reuse `yip-membership`'s own test fixtures if exposed; otherwise construct one inline mirroring `record.rs`'s `make_signed_record`.

- [ ] **Step 3: Run — expect FAIL** (variants/fields don't exist). `cargo test -p yip-rendezvous register_signed_roundtrips`

- [ ] **Step 4: Implement the codec**

In `encode`: for `RegisterSigned`, push `Tag::RegisterSigned as u8`, then encode the record into a scratch `Vec`, push its `u16` big-endian length, then the bytes. For `PeerInfo`, after the existing `node` + `reflexive`, push a presence byte (`1` then the length-prefixed record when `Some`, else `0`).

In `decode`: add the `RegisterSigned` arm (read `u16` len, slice, `Record::decode`, `None` on failure — fail closed). For `PeerInfo`, read the trailing presence byte; if `1`, read the length-prefixed record (fail closed on truncation/invalid); if absent (legacy datagram with no trailing byte) treat as `None` — so an old-format `PeerInfo` still decodes. Guard every slice with a length check (`buf.get(range)?`), matching the file's existing panic-free decode style.

- [ ] **Step 5: Run — expect PASS**, plus the existing `decode_rejects_garbage_and_truncation` / `decode_rejects_invalid_address_family` stay green. Add a truncation test: a `RegisterSigned` whose length prefix exceeds the buffer returns `None`.

- [ ] **Step 6: fmt + clippy + commit**

```bash
cargo fmt && cargo clippy -p yip-rendezvous -- -D warnings
git add crates/yip-rendezvous/src/proto.rs crates/yip-rendezvous/Cargo.toml
git commit -m "feat(rdv.37): RegisterSigned message + optional PeerInfo.record (codec)"
```

---

### Task 2: Server verifies `RegisterSigned` against roots; legacy-drop when rooted

**Files:**
- Modify: `crates/yip-rendezvous/src/server.rs`
- Test: same file's tests module.

**Interfaces:**
- Consumes: `Record::verify(&[[u8;32]], &[u8;16], now_secs, skew) -> Result<(), CertError>`; `register_if_fresh(node, counter, src, now_ms) -> bool`; `Reg { addr, expiry_ms, last_counter }`.
- Produces: `RendezvousServer::new_with_roots(now_ms, ca_pubkeys: Vec<[u8;32]>, network_id: [u8;16]) -> Self`; `Reg` gains `record: Option<Record>`; `handle` gains a wall-clock `now_secs` parameter (thread it from callers) OR store it — see step 3.

**Context:** The server currently has no wall-clock. `Record::verify` needs `now_secs` for validity. Add `now_secs` as a parameter to `handle` (update all call sites, including the binary and tests) — cleanest and keeps the monotonic/wall split explicit. Store `Option<(Vec<[u8;32]>, [u8;16])>` as `roots_cfg`. Reuse the #41 skew source for the skew value (a `clock_skew_secs()`-style constant/env; if the rendezvous crate has no access to it, define a local `REGISTRATION_SKEW_SECS` mirroring the default and document the parity).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn rooted_server_accepts_valid_signed_register_and_serves_it() {
    let (ca_pub, network_id, rec, member_src) = valid_registration(); // helper mints a Record + its CA
    let mut s = RendezvousServer::new_with_roots(0, vec![ca_pub], network_id);
    let _ = s.handle(member_src, Message::RegisterSigned { record: rec.clone() }, 0, now_secs(0));
    let out = s.handle(addr("203.0.113.9:5"), Message::Lookup { node: rec.node_id }, 10, now_secs(10));
    assert!(out.iter().any(|(_, m)| matches!(m,
        Message::PeerInfo { reflexive, record: Some(r), .. }
            if *reflexive == member_src && r.node_id == rec.node_id)));
}

#[test]
fn rooted_server_rejects_forged_signature() {
    let (ca_pub, network_id, mut rec, member_src) = valid_registration();
    rec.sig[0] ^= 0xFF; // corrupt the signature
    let mut s = RendezvousServer::new_with_roots(0, vec![ca_pub], network_id);
    let _ = s.handle(member_src, Message::RegisterSigned { record: rec.clone() }, 0, now_secs(0));
    // Not stored → lookup yields NotFound.
    let out = s.handle(addr("203.0.113.9:5"), Message::Lookup { node: rec.node_id }, 10, now_secs(10));
    assert!(out.iter().all(|(_, m)| !matches!(m, Message::PeerInfo { .. })));
}

#[test]
fn rooted_server_rejects_overwrite_by_non_holder() {
    // Victim registers; attacker sends RegisterSigned for the victim's node_id
    // signed by a DIFFERENT (valid-CA) member key → node_id != node_id(attacker cert) → rejected.
    let (ca_pub, network_id, victim, victim_src) = valid_registration();
    let attacker = registration_for_other_member(ca_pub, network_id, victim.node_id); // node_id mismatch
    let mut s = RendezvousServer::new_with_roots(0, vec![ca_pub], network_id);
    let _ = s.handle(victim_src, Message::RegisterSigned { record: victim.clone() }, 0, now_secs(0));
    let _ = s.handle(addr("203.0.113.66:9"), Message::RegisterSigned { record: attacker }, 1, now_secs(1));
    let out = s.handle(addr("203.0.113.9:5"), Message::Lookup { node: victim.node_id }, 2, now_secs(2));
    assert!(out.iter().any(|(_, m)| matches!(m,
        Message::PeerInfo { reflexive, .. } if *reflexive == victim_src)),
        "victim's real registration must survive the overwrite attempt");
}

#[test]
fn rooted_server_drops_legacy_unsigned_register() {
    let (ca_pub, network_id, _rec, _src) = valid_registration();
    let mut s = RendezvousServer::new_with_roots(0, vec![ca_pub], network_id);
    let _ = s.handle(addr("203.0.113.66:9"), Message::Register { node: [1u8;16], counter: 9 }, 0, now_secs(0));
    let out = s.handle(addr("203.0.113.9:5"), Message::Lookup { node: [1u8;16] }, 1, now_secs(1));
    assert!(out.iter().all(|(_, m)| !matches!(m, Message::PeerInfo { .. })),
        "a rooted (mesh) server must not accept unsigned registrations");
}

#[test]
fn rootless_server_keeps_legacy_register() {
    let mut s = RendezvousServer::new(0); // no roots
    let a = [1u8;16];
    let _ = s.handle(addr("198.51.100.7:41000"), Message::Register { node: a, counter: 1 }, 0, now_secs(0));
    let out = s.handle(addr("203.0.113.9:5"), Message::Lookup { node: a }, 1, now_secs(1));
    assert!(out.iter().any(|(_, m)| matches!(m, Message::PeerInfo { .. })));
}
```

Provide `valid_registration()` / `registration_for_other_member()` / `now_secs()` helpers in the test module, minting real certs+records with a test CA (reuse `yip-membership` record/cert test patterns; a `mk_ca`/`mk_cert`/`build_signed_record` chain like `peer_manager.rs`'s test helpers).

- [ ] **Step 2: Run — expect FAIL** (`new_with_roots`, `record` field, `now_secs` param don't exist).

- [ ] **Step 3: Implement**

Add `roots_cfg: Option<(Vec<[u8; 32]>, [u8; 16])>` to `RendezvousServer`; `new` sets `None`; add `new_with_roots`. Add `record: Option<Record>` to `Reg`. Thread `now_secs: u64` through `handle`. In the match:

- `Message::RegisterSigned { record }`: only meaningful when `roots_cfg.is_some()`. Verify `record.verify(&ca_pubkeys, &network_id, now_secs, REGISTRATION_SKEW_SECS)`; on `Ok`, call `register_if_fresh(record.node_id, record.seq, src, now_ms)` and, if it accepted, store the `record` in that node's `Reg`. On `Err` or when rootless, drop (no store, no reply).
- `Message::Register { node, counter }`: if `roots_cfg.is_some()`, DROP (mesh requires signed). Else behave exactly as today.
- `Message::Lookup { node }`: build `PeerInfo { node, reflexive: reg.addr, record: reg.record.clone() }`.

Keep rate-limit + capacity checks unchanged and applied before verification (cheap DoS guard first).

- [ ] **Step 4: Run — expect PASS.** Update any existing `handle(...)` test call sites to pass `now_secs`.

- [ ] **Step 5: fmt + clippy + commit**

```bash
cargo fmt && cargo clippy -p yip-rendezvous -- -D warnings
git add crates/yip-rendezvous/src/server.rs
git commit -m "feat(rdv.37): rooted server verifies RegisterSigned, drops unsigned; PeerInfo carries the record"
```

---

### Task 3: Server binary — `--roots` / `--network-id`; wall-clock threading

**Files:**
- Modify: `bin/yip-rendezvous/src/main.rs` (and wherever `server.handle(...)` is invoked in the UDP loop / `conn_tunnel.rs` if it calls `handle`).
- Test: an arg-parse unit test if the binary has a testable parse fn; otherwise a smoke assertion.

**Interfaces:**
- Consumes: `RootSet::decode(&[u8]) -> Option<RootSet>`, `RootSet::verify_rootset(&[[u8;32]]) -> bool`, `RootSet.roots: Vec<([u8;32], SocketAddr)>`, `RendezvousServer::new_with_roots`.
- Produces: server started in mesh mode when `--roots` + `--network-id` are given.

**Context:** The roots file is a signed `RootSet` (same artifact yipd loads). The CA pubkeys are `roots.roots.iter().map(|(pk, _)| *pk).collect()`. The rootset is self-consistency-checked with `verify_rootset(&ca_pubkeys)` at load (it is self-signed by one of its own CA keys — mirror how yipd validates it; check `bin/yipd/src/config.rs` / `membership.rs` for the exact load+verify sequence and replicate it).

- [ ] **Step 1:** Read `bin/yipd`'s roots load+verify path (`config.rs` / `membership.rs`) to copy the exact decode + `verify_rootset` sequence and the `--network-id` hex parsing (16 bytes).

- [ ] **Step 2:** Add `--roots <path>` and `--network-id <hex32chars>` to the arg parser. When both present: read the file, `RootSet::decode`, derive `ca_pubkeys`, `verify_rootset` (exit with a clear error if it fails), parse the network id, and construct `RendezvousServer::new_with_roots(now_ms, ca_pubkeys, network_id)`. When absent: `RendezvousServer::new(now_ms)` (legacy). Thread the wall-clock `now_secs` into each `handle` call in the receive loop (monotonic `now_ms` stays for TTL/rate).

- [ ] **Step 3:** Build + a quick manual/smoke check.

```bash
cargo build -p yip-rendezvous
cargo test -p yip-rendezvous
```

- [ ] **Step 4: commit**

```bash
cargo fmt && cargo clippy -p yip-rendezvous -- -D warnings
git add bin/yip-rendezvous/src/main.rs
git commit -m "feat(rdv.37): server --roots/--network-id enable mesh-mode signed registration"
```

---

### Task 4: `Membership` accessors — mint + verify a registration record

**Files:**
- Modify: `bin/yipd/src/membership.rs`
- Test: same file's tests module.

**Interfaces:**
- Consumes: existing `build_signed_record(cert, endpoints, seq, sign_priv) -> Record`, `self.own_cert: Cert`, `self.sign_priv: [u8;32]`, `self.network_id: [u8;16]`, `self.roots: RootSet`, `self.own_node_id`.
- Produces: `pub fn sign_registration(&self, seq: u64) -> Record`; `pub fn verify_record(&self, r: &Record, now_secs: u64) -> bool`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn sign_registration_is_verifiable_against_own_roots() {
    let m = test_membership(); // existing helper that builds a Membership with a test CA
    let rec = m.sign_registration(5);
    assert_eq!(rec.node_id, m.own_node_id());
    assert!(m.verify_record(&rec, now_secs()));
}

#[test]
fn verify_record_rejects_foreign_ca() {
    let m = test_membership();
    let foreign = record_signed_by_unrelated_ca();
    assert!(!m.verify_record(&foreign, now_secs()));
}
```

Add `own_node_id()` accessor if not present (there may already be one). Reuse the module's existing membership test constructor.

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

```rust
/// Mint a fresh, self-signed registration `Record` at `seq` (the rendezvous
/// freshness counter). Reuses the gossip record machinery — same cert, same
/// endpoints, monotonic `seq`.
pub fn sign_registration(&self, seq: u64) -> Record {
    build_signed_record(self.own_cert.clone(), self.own_endpoints(), seq, &self.sign_priv)
}

/// Verify a registration/directory `Record` against our own roots + network,
/// at wall-clock `now_secs`. True iff the cert chains to a root, the record
/// signature is valid, and the node_id binds the cert (squatting closed).
pub fn verify_record(&self, r: &Record, now_secs: u64) -> bool {
    let ca_pubkeys: Vec<[u8; 32]> = self.roots.roots.iter().map(|(pk, _)| *pk).collect();
    r.verify(&ca_pubkeys, &self.network_id, now_secs, clock_skew_secs()).is_ok()
}
```

If `own_endpoints` is not stored separately (it was moved into `own_record` at construction), either store `own_endpoints` on the struct or mint from `self.own_record.endpoints.clone()`. Use `clock_skew_secs()` (the #41 skew source); import/reuse it.

- [ ] **Step 4: Run — expect PASS**, plus the full `cargo test -p yipd --bin yipd` membership suite.

- [ ] **Step 5: commit**

```bash
cargo fmt && cargo clippy -p yipd --bin yipd -- -D warnings
git add bin/yipd/src/membership.rs
git commit -m "feat(membership.37): sign_registration + verify_record accessors"
```

---

### Task 5: Client — send `RegisterSigned`; verify `PeerInfo.record` before probing

**Files:**
- Modify: `bin/yipd/src/rendezvous.rs`, `bin/yipd/src/peer_manager.rs`
- Test: `rendezvous.rs` tests module + a `peer_manager.rs` integration-style test.

**Interfaces:**
- Consumes: `Rendezvous::register(&mut self, node: NodeId) -> Option<EgressDatagram>` (trait, ~38), `parse(&self, dg: &[u8]) -> RdvEvent` (~41), `RdvEvent::PeerCandidate`; `Membership::sign_registration` / `verify_record` (Task 4).
- Produces: `register` carries a signed `Record` in mesh mode; `parse` drops a `PeerInfo` whose `record` fails verification (mesh mode).

**Context:** The trait's `register(node)` cannot build a record itself (no membership). Two coherent options — pick **(A)**: change the trait to `register(&mut self, node: NodeId, signed: Option<Record>) -> Option<EgressDatagram>`; `PeerManager` mints `signed` from `self.membership` with a monotonic per-registration seq and passes it. In mesh mode `signed` is `Some` → emit `RegisterSigned`; else `None` → legacy `Register { node, counter }`. For `parse`, the `Rendezvous` impl cannot verify (no roots), so it must surface the raw `record` to `PeerManager`, which verifies via `Membership::verify_record` before acting — add the `record` to `RdvEvent::PeerCandidate` (or verify inside `PeerManager`'s rdv-event handling where membership is in scope) and drop the candidate when verification fails.

- [ ] **Step 1: Write failing tests**

```rust
// rendezvous.rs
#[test]
fn register_emits_signed_when_record_present() {
    let mut r = ConfiguredServerRendezvous::new(server());
    let me = [3u8; 16];
    let rec = sample_record_with_node(me);
    let dg = r.register(me, Some(rec.clone())).expect("Some");
    let msg = decode_to_server(&dg);
    assert!(matches!(msg, Some(Message::RegisterSigned { record }) if record.node_id == me));
}

#[test]
fn register_falls_back_to_unsigned_without_record() {
    let mut r = ConfiguredServerRendezvous::new(server());
    let me = [3u8; 16];
    let dg = r.register(me, None).expect("Some");
    assert!(matches!(decode_to_server(&dg), Some(Message::Register { node, .. }) if node == me));
}
```

For `PeerManager`: a test that a `PeerInfo` carrying a record failing `verify_record` does NOT produce a peer candidate / probe, and one carrying a valid record does. Reuse the peer_manager rdv test helpers (search for `RdvEvent`/`PeerCandidate`/`on_rdv` in tests).

- [ ] **Step 2: Run — expect FAIL** (signature change / verification not wired).

- [ ] **Step 3: Implement**

Change the `Rendezvous::register` signature to take `signed: Option<Record>`; update both impls (`ConfiguredServerRendezvous`, the TLS-relay `register` returns `None` as today) and the `PeerManager` call site. In `PeerManager`, hold a monotonic `reg_seq: u64` (bump per registration emit); when membership is present, `signed = Some(self.membership.as_ref().unwrap().sign_registration(reg_seq))`. Surface `PeerInfo.record` through `parse`/`RdvEvent` and, in the `PeerManager` handler that turns a `PeerCandidate` into a probe, call `membership.verify_record(&record, now_secs)` and drop on failure (mesh mode only; non-mesh has no record to verify).

- [ ] **Step 4: Run — expect PASS**, plus full `cargo test -p yipd --bin yipd`.

- [ ] **Step 5: commit**

```bash
cargo fmt && cargo clippy -p yipd --bin yipd -- -D warnings
git add bin/yipd/src/rendezvous.rs bin/yipd/src/peer_manager.rs
git commit -m "feat(rdv.37): client sends RegisterSigned + verifies PeerInfo.record before probing"
```

---

### Task 6: netns money test — registration-overwrite refused, victim reachable + CI

**Files:**
- Create: `bin/yipd/tests/run-netns-registration-hijack.sh`
- Modify: `.github/workflows/integration.yml`

**Interfaces:**
- Consumes: the mesh discovery netns harness (fork `run-netns-discovery.sh`, which already bootstraps a CA/roots mesh via rendezvous); `yip-ca` for minting certs; the both-driver + guard conventions.
- Produces: an exit-gated assertion that a forged overwrite is refused and the victim stays reachable.

**Context:** Start a rooted rendezvous server (`--roots`/`--network-id`). Two members A and B establish via signed registration + discovery. An attacker process (a third netns, holding NO valid member cert, or a valid member cert for a DIFFERENT node_id) sends a `RegisterSigned`/`Register` claiming A's node_id from its own address. Assert: (1) the server refuses it (A's lookup still returns A's real address); (2) B→A connectivity is uninterrupted (steady ping ≤1% loss across the attack window). Both drivers.

- [ ] **Step 1:** Read `run-netns-discovery.sh` for the mesh bootstrap (CA, roots file, per-node certs, rendezvous startup) and `run-netns-cert-revocation.sh` for the both-driver/guard pattern and `yip-ca` usage.

- [ ] **Step 2:** Write `run-netns-registration-hijack.sh`: bootstrap a rooted rendezvous + A + B (signed registration path), establish + warm ping. From an attacker netns, replay/forge a `Register`/`RegisterSigned` for A's node_id. Assert the server drops it (A's `Lookup` reflexive is unchanged — capture via a small probe or via A staying pingable from B) and the measured ping B→A stays ≤1% loss. `set -euo pipefail`, `trap`, SKIP-when-not-root, both drivers.

- [ ] **Step 3: Run under sudo, both drivers**

```bash
cargo build --release -p yipd -p yip-rendezvous
sudo bash bin/yipd/tests/run-netns-registration-hijack.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
sudo YIP_USE_URING=1 bash bin/yipd/tests/run-netns-registration-hijack.sh "$(pwd)/target/release/yipd" "$(pwd)/target/release/yip-rendezvous"
```
Expected: PASS both. If netns cannot run here, capture the blocker and report DONE_WITH_CONCERNS.

- [ ] **Step 4: Wire CI + commit**

```bash
chmod +x bin/yipd/tests/run-netns-registration-hijack.sh
git add bin/yipd/tests/run-netns-registration-hijack.sh .github/workflows/integration.yml
git commit -m "test(rdv.37): netns — forged registration refused, victim stays reachable"
```

---

## After all tasks

- Final whole-branch review (opus) over the #37 delta. Focus: `Record::verify` is applied before any store (server) and before any probe (peer); the rooted server drops BOTH forged signed and legacy unsigned registers; squatting is closed (node_id binds the cert inside `Record::verify`); the reflexive address stays server-observed (not signed — backstopped by handshake-commit) and this is intended; non-mesh path is byte-identical (legacy `Register`/no-record `PeerInfo`); clock split correct (secs for validity, ms for TTL/rate); no `unsafe`/`as`/bare-`allow`; panic-free decode.
- This is one PR of the authenticated-reachability milestone (the other is M2). Leave it for the user; no "not merging" line.
