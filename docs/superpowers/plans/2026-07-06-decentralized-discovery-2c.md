# Milestone 2c: Decentralized Discovery — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the yip peer set dynamic — a node discovers other CA-certified members via a gossip-replicated signed directory and admits them by verifying a membership cert presented in the handshake, with no static per-peer config.

**Architecture:** A new `crates/yip-membership` lib holds the cert/record/root-set formats + Ed25519 verification + gossip wire messages. An offline `bin/yip-ca` issues certs. `bin/yipd/src/membership.rs` maintains the gossip directory and cert verification. The Noise handshake gains a cert payload (initiator in msg1, responder in msg2) so admission stays pre-session. `PeerManager` gains a runtime `admit_member` and consults `Membership` in `on_tun` (resolve→admit→2b lazy handshake) and `handle_handshake_init` (verify the presented cert). Absent mesh config → pure 2a/2b, byte-identical.

**Tech Stack:** Rust, `ed25519-dalek` (2.x, cert/record signing), `blake2` (=0.10.6, node ids), `snow`/`yip-crypto` Noise-IK (extended to carry a handshake payload), the merged 2b `PathState`/rendezvous, netns for integration.

## Global Constraints

- `yipd`, `yip-membership`, `yip-ca` stay `#![forbid(unsafe_code)]`; `unsafe` only in `yip-io`/`yip-device`.
- No `as` numeric casts except a message-type/`PacketType` discriminant `as u8`.
- **Anti-hijack invariant (from 2b):** discovery supplies a *candidate* identity + cert + address; the Noise-IK handshake still gates every session; an established session's egress is never redirected without a fresh completed handshake over the new path.
- **Cert admission is PRE-session:** the responder verifies the presented cert *before it replies* (exactly where 2a's static-allowlist check runs today) — a peer with no valid cert never gets a session.
- **Record-authenticity chain:** CA (Ed25519) → cert (binds member X25519 + Ed25519 keys) → gossip record (Ed25519-signed by the cert's `member_sign_pubkey`). Every link independently verifiable.
- **Wall-clock for cert validity:** `not_before`/`not_after` are Unix-seconds wall-clock; verification takes a `now: u64` (seconds) from `SystemTime` with a small skew tolerance — distinct from 2a/2b's monotonic `now_ms`.
- **Offline CA:** the CA signing key is only ever used by `bin/yip-ca`; it never appears in `yipd`/`yip-membership` runtime or config (only the CA *public* key is configured).
- **No data-plane / wire regression:** with no mesh config (`cert`/`ca_public`/`roots` absent) behavior is byte-identical 2a/2b — the single-peer `tunnel_netns` tests, `triangle_full_mesh_ping`, and the 2b `relay_path_ping`/`hole_punch_ping` stay green under BOTH `poll` and `YIP_USE_URING=1`.
- The `arq_recovers_bulk_loss` netns test uses the **release** `yipd` (rebuild `--release` after any yipd change).
- Green bar every task: `cargo fmt --all --check`, `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p <crate>`.
- Deferred / non-goals (do NOT build): threshold CA (#39), signed revocation records, LAN-multicast discovery, Kademlia DHT, anti-DPI of the gossip/cert wire (#3), gossip-graph metadata privacy, PoW sybil-hardening, Yggdrasil-tree routing (would break 2a `node_addr`).

**Sandbox note for implementers:** the pre-commit hook runs a workspace `cargo test` that trips on 2 pre-existing, unrelated `yip-io` io_uring memlock tests in this sandbox (they pass in CI). If the hook blocks ONLY on those, commit `--no-verify` after confirming your own crate + clippy + fmt are green. Validate io_uring behavior via netns runs, not the yip-io loopback unit tests.

---

## File Structure

- `crates/yip-membership/` (NEW lib): `src/lib.rs`, `src/cert.rs` (Cert/RootSet + Ed25519 verify), `src/record.rs` (Record sign/verify), `src/gossip.rs` (Digest/PullRequest/Records codec), `src/ids.rs` (node_id/node_addr derivation reused by the directory).
- `bin/yip-ca/` (NEW bin): `src/main.rs` (genkey / sign-cert / sign-roots).
- `crates/yip-crypto/src/lib.rs` (MODIFY): `write_message(payload)` / `read_message(msg)->payload` — carry a Noise handshake app payload.
- `bin/yipd/src/handshake.rs` (MODIFY): thread an optional cert payload through the step-functions.
- `bin/yipd/src/membership.rs` (NEW): the directory + `resolve` + `verify_cert` + gossip driving.
- `bin/yipd/src/config.rs` (MODIFY): `ca_public`, `cert`, `roots`.
- `bin/yipd/src/peer_manager.rs` (MODIFY): `admit_member`, `on_tun` resolve-and-admit, `handle_handshake_init` cert admission, gossip demux.
- `bin/yipd/src/tunnel.rs`, `bin/yipd/src/main.rs` (MODIFY): build/pass `Membership`, `mod membership;`.
- `bin/yipd/tests/{run-netns-discovery.sh,run-netns-admission-reject.sh,run-netns-root-outage.sh}` (NEW) + `tunnel_netns.rs` + `.github/workflows/integration.yml` (MODIFY).

---

### Task 1: `yip-membership` — Cert, RootSet + Ed25519 verification

**Files:**
- Create: `crates/yip-membership/Cargo.toml`, `src/lib.rs`, `src/ids.rs`, `src/cert.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `pub type NodeId = [u8;16]; pub fn node_id(pubkey:&[u8;32])->NodeId` (= `BLAKE2s("yip-rdv-v1"||pubkey)[..16]`, matching 2b's rendezvous id), `pub fn node_addr(pubkey:&[u8;32])->std::net::Ipv6Addr` (= `0xfd || BLAKE2s("yip-addr-v1"||pubkey)[..15]`, matching 2a).
  - `pub struct Cert { pub version:u8, pub member_pubkey:[u8;32], pub member_sign_pubkey:[u8;32], pub network_id:[u8;16], pub not_before:u64, pub not_after:u64, pub tags:Vec<(u8,Vec<u8>)>, pub ca_sig:[u8;64] }`
  - `pub fn cert_signing_body(c:&Cert)->Vec<u8>` (canonical bytes the CA signs = everything except `ca_sig`), `Cert::encode(&self,&mut Vec<u8>)`, `Cert::decode(&[u8])->Option<Cert>`.
  - `pub enum CertError { BadSig, Expired, NotYetValid, WrongNetwork, WrongMember }`
  - `pub fn verify_cert(c:&Cert, ca_pubkeys:&[[u8;32]], network_id:&[u8;16], member_pubkey:&[u8;32], now:u64, skew:u64) -> Result<(),CertError>` — Ed25519-verify `ca_sig` over `cert_signing_body` against ANY of `ca_pubkeys`; check `not_before <= now+skew && now < not_after+skew`; check `network_id` matches; check `c.member_pubkey == member_pubkey` (the cert covers the key presenting it).
  - `pub struct RootSet { pub roots:Vec<([u8;32],std::net::SocketAddr)>, pub version:u64, pub ca_sig:[u8;64] }` + `rootset_signing_body`, `encode`/`decode`, `pub fn verify_rootset(&self, ca_pubkeys:&[[u8;32]])->bool`.

- [ ] **Step 1: Create the crate.** `crates/yip-membership/Cargo.toml`:

```toml
[package]
name = "yip-membership"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
blake2 = { workspace = true }
ed25519-dalek = { version = "2.1", default-features = false }

[dev-dependencies]
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
rand_core = { version = "0.6", features = ["getrandom"] }

[lints]
workspace = true
```

`src/lib.rs`:
```rust
//! yip mesh membership: CA-signed certificates, member-signed directory
//! records, the signed root set, and the gossip wire codec. Pure (no I/O);
//! shared by `yipd`, its membership module, and the `yip-ca` tool.
#![forbid(unsafe_code)]

pub mod cert;
pub mod ids;
pub mod record;
pub mod gossip;

pub use cert::{verify_cert, Cert, CertError, RootSet};
pub use ids::{node_addr, node_id, NodeId};
pub use record::Record;
```
(`record`/`gossip` are Task 2 — create empty `pub mod` stubs `record.rs`/`gossip.rs` with just a doc comment so the crate builds; Task 2 fills them. Actually simplest: add `pub mod record; pub mod gossip;` only when those files exist — for Task 1, comment those two `pub use`/`pub mod` lines and add them in Task 2. Leave a `// task 2: pub mod record; pub mod gossip;` marker.)

- [ ] **Step 2: `ids.rs`** — copy the two derivations verbatim (they already exist in `bin/yipd/src/addr.rs` for node_addr and `crates/yip-rendezvous/src/proto.rs` for node_id; reproduce here so the lib is self-contained):

```rust
//! Key-derived identifiers, matching 2a's `node_addr` and 2b's `node_id`.
use std::net::Ipv6Addr;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;

pub type NodeId = [u8; 16];

pub fn node_id(pubkey: &[u8; 32]) -> NodeId {
    let mut h = Blake2sVar::new(16).expect("16 valid");
    h.update(b"yip-rdv-v1");
    h.update(pubkey);
    let mut out = [0u8; 16];
    h.finalize_variable(&mut out).expect("len ok");
    out
}

pub fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr {
    let mut h = Blake2sVar::new(15).expect("15 valid");
    h.update(b"yip-addr-v1");
    h.update(pubkey);
    let mut d = [0u8; 15];
    h.finalize_variable(&mut d).expect("len ok");
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    o[1..].copy_from_slice(&d);
    Ipv6Addr::from(o)
}
```

- [ ] **Step 3: Write failing tests** in `cert.rs` (round-trip + verify matrix):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn ca() -> SigningKey { SigningKey::generate(&mut OsRng) }

    fn make_cert(ca: &SigningKey, member: [u8;32], net: [u8;16], nb: u64, na: u64) -> Cert {
        let mut c = Cert {
            version: 1, member_pubkey: member, member_sign_pubkey: [9u8;32],
            network_id: net, not_before: nb, not_after: na, tags: vec![], ca_sig: [0u8;64],
        };
        let sig = ca.sign(&cert_signing_body(&c));
        c.ca_sig = sig.to_bytes();
        c
    }

    #[test]
    fn cert_roundtrips() {
        let c = make_cert(&ca(), [1u8;32], [7u8;16], 100, 200);
        let mut buf = Vec::new();
        c.encode(&mut buf);
        assert_eq!(Cert::decode(&buf), Some(c));
    }

    #[test]
    fn valid_cert_verifies_and_matrix_of_failures() {
        let ca = ca();
        let ca_pub = ca.verifying_key().to_bytes();
        let member = [1u8;32];
        let net = [7u8;16];
        let c = make_cert(&ca, member, net, 100, 200);
        // valid at now=150
        assert!(verify_cert(&c, &[ca_pub], &net, &member, 150, 0).is_ok());
        // expired
        assert_eq!(verify_cert(&c, &[ca_pub], &net, &member, 250, 0), Err(CertError::Expired));
        // not yet valid
        assert_eq!(verify_cert(&c, &[ca_pub], &net, &member, 50, 0), Err(CertError::NotYetValid));
        // skew lets a just-expired cert pass within tolerance
        assert!(verify_cert(&c, &[ca_pub], &net, &member, 205, 10).is_ok());
        // wrong network
        assert_eq!(verify_cert(&c, &[ca_pub], &[8u8;16], &member, 150, 0), Err(CertError::WrongNetwork));
        // cert doesn't cover the presented key
        assert_eq!(verify_cert(&c, &[ca_pub], &net, &[2u8;32], 150, 0), Err(CertError::WrongMember));
        // wrong CA
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert_eq!(verify_cert(&c, &[other], &net, &member, 150, 0), Err(CertError::BadSig));
        // tampered body
        let mut t = c.clone();
        t.not_after = 9999;
        assert_eq!(verify_cert(&t, &[ca_pub], &net, &member, 150, 0), Err(CertError::BadSig));
    }
}
```

- [ ] **Step 4: Run → fail; implement `cert.rs`.** The `Cert`/`RootSet` structs, a length-prefixed canonical encoding for `cert_signing_body` (fixed fields in declared order; `tags` as a `u16` count then each `(u8 tag, u16 len, bytes)`; the body excludes `ca_sig`), `encode`/`decode` (the body + the 64-byte sig), and `verify_cert` using `ed25519_dalek::{VerifyingKey, Signature}` (`VerifyingKey::from_bytes(ca_pubkey).and_then(|vk| vk.verify_strict(&body, &Signature::from_bytes(&c.ca_sig)))`). Order of checks: sig first (→ `BadSig`), then member-match (`WrongMember`), network (`WrongNetwork`), validity window (`NotYetValid`/`Expired`). Implement `RootSet` analogously (`rootset_signing_body` = version + each root's (pubkey, encoded SocketAddr, using a `put_addr`/`take_addr` like `yip-rendezvous`'s proto), `verify_rootset` verifies `ca_sig` over that body against any ca_pubkey). No `as` casts; use `u16::try_from`/`to_be_bytes`.

- [ ] **Step 5: Run → pass; build/clippy/fmt clean; commit.**

```bash
cargo test -p yip-membership && cargo clippy -p yip-membership --all-targets -- -D warnings && cargo fmt --all --check
git add crates/yip-membership Cargo.lock
git commit -m "feat(yip-membership): CA-signed cert + root set + Ed25519 verification (2c)"
```

---

### Task 2: `yip-membership` — Record + gossip wire messages

**Files:**
- Create: `crates/yip-membership/src/record.rs`, `src/gossip.rs`; Modify: `src/lib.rs` (uncomment `pub mod record; pub mod gossip;` + the `Record` re-export)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `crate::cert::{Cert, verify_cert, CertError}`, `crate::ids::NodeId`.
- Produces:
  - `pub struct Record { pub node_id:NodeId, pub cert:Cert, pub endpoints:Vec<std::net::SocketAddr>, pub seq:u64, pub sig:[u8;64] }` + `record_signing_body` (all fields except `sig`), `encode`/`decode`, `pub fn sign(body:&[u8], member_sign_priv:&[u8;32])->[u8;64]`, `pub fn verify(&self, ca_pubkeys:&[[u8;32]], network_id:&[u8;16], now:u64, skew:u64)->Result<(),CertError>` (verify the embedded `cert` via `verify_cert` for `cert.member_pubkey`, then Ed25519-verify `sig` over `record_signing_body` against `cert.member_sign_pubkey`; also check `node_id == node_id(&cert.member_pubkey)`).
  - `pub enum GossipMsg { Digest(Vec<(NodeId,u64)>), PullRequest(Vec<NodeId>), Records(Vec<Record>) }` + `encode`/`decode` (leading discriminant byte `as u8`; length-prefixed vecs).

- [ ] **Step 1: Failing tests** — Record sign/verify (valid; tampered endpoints → fail; wrong member-sign key → fail; wrong node_id → fail), GossipMsg round-trip for all three variants. (Reuse the Task-1 test helpers to mint a signed cert; add a member Ed25519 signing key whose public goes in `cert.member_sign_pubkey`.)
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement `record.rs` + `gossip.rs`** per the interfaces. `record_signing_body` = `node_id ‖ cert.encode ‖ endpoints(count+each addr) ‖ seq`. `GossipMsg::encode` = discriminant + length-prefixed contents; `decode` returns `Option`. No `as` except the discriminant. Uncomment the lib.rs `pub mod`/`pub use`.
- [ ] **Step 4: Run → pass; build/clippy/fmt; commit** (`feat(yip-membership): signed directory record + gossip wire messages (2c)`).

---

### Task 3: `bin/yip-ca` — offline CA binary

**Files:**
- Create: `bin/yip-ca/Cargo.toml`, `src/main.rs`
- Test: `bin/yip-ca/tests/roundtrip.rs`

**Interfaces:**
- Consumes: `yip_membership::{Cert, RootSet, cert_signing_body, rootset_signing_body}`; `ed25519-dalek` (signing).
- Produces: binary `yip-ca` with subcommands `genkey`, `sign-cert`, `sign-roots`.

- [ ] **Step 1: Cargo.toml** — package `yip-ca` (bin name `yip-ca`), deps `yip-membership = { path = "../../crates/yip-membership" }`, `ed25519-dalek = { version = "2.1", features = ["rand_core"] }`, `rand_core = { version = "0.6", features = ["getrandom"] }`. `#![forbid(unsafe_code)]`.
- [ ] **Step 2: Failing round-trip test** `tests/roundtrip.rs`: run `yip-ca genkey` (capture ca priv/pub hex), `yip-ca sign-cert --member <hex32> --member-sign <hex32> --network <hex16> --days 30` (capture the emitted cert bytes, e.g. base64/hex on stdout or a file), then `yip_membership::Cert::decode` it and `verify_cert` against the ca pub → Ok. Spawn the binary via `env!("CARGO_BIN_EXE_yip-ca")`.
- [ ] **Step 3: Implement `main.rs`** — arg parsing (match on first arg like `yipd`/`yip-rendezvous`): `genkey` prints `ca_private=<hex>` / `ca_public=<hex>` (Ed25519 `SigningKey::generate(&mut OsRng)`); `sign-cert` reads `--member`/`--member-sign`/`--network`/`--days` (+ `--ca-private <hex>` or from stdin/env), builds a `Cert{version:1, .., not_before: now, not_after: now + days*86400, tags:vec![]}`, signs `cert_signing_body`, prints the encoded cert as hex; `sign-roots` reads a simple roots file (lines `pubkey_hex endpoint`) + version + ca-private, builds+signs a `RootSet`, prints encoded hex. Use `SystemTime::now()` for `now` (wall-clock seconds). Emit clear usage on bad args (exit 2).
- [ ] **Step 4: Run → pass; build/clippy/fmt; commit** (`feat(yip-ca): offline CA — genkey, sign-cert, sign-roots (2c)`).

---

### Task 4: Noise handshake cert payload (yip-crypto + handshake.rs)

**Files:**
- Modify: `crates/yip-crypto/src/lib.rs` (`write_message`/`read_message` gain a payload), `bin/yipd/src/handshake.rs` (thread an optional payload through the step-functions)
- Test: inline in both

**Interfaces:**
- Consumes: existing `Handshake` (snow).
- Produces:
  - `yip_crypto::Handshake::write_message(&mut self, payload:&[u8]) -> Result<Vec<u8>,CryptoError>` (was no-arg; now passes `payload` to snow).
  - `yip_crypto::Handshake::read_message(&mut self, msg:&[u8]) -> Result<Vec<u8>,CryptoError>` (was `-> Result<()>`; now returns the decrypted app payload).
  - `HandshakeState::start_initiator(local_priv, peer_pub, payload:&[u8]) -> io::Result<(Self, Vec<u8>)>` (cert bytes in msg1).
  - `HandshakeState::start_responder(local_priv, init_pkt, resp_payload:&[u8]) -> io::Result<(Established, Vec<u8>, [u8;32], Vec<u8>)>` — returns `(established, resp_pkt, remote_static, initiator_payload)` (the extra `Vec<u8>` = the cert the initiator presented in msg1; responder's own cert goes out in msg2 via `resp_payload`).
  - `HandshakeState::read_response(self, resp_pkt) -> io::Result<(Established, Vec<u8>)>` — returns `(established, responder_payload)` (the responder's cert from msg2).

- [ ] **Step 1: Failing test** in `yip-crypto`: an initiator→responder round-trip where msg1 carries payload `b"cert-A"` and msg2 carries `b"cert-B"`; assert `responder.read_message(msg1)` returns `b"cert-A"` and `initiator.read_message(msg2)` returns `b"cert-B"`, and both still `into_session()` to matching keys. (Noise-IK encrypts these payloads — msg1 under the es handshake state, msg2 fully — so this also documents that certs aren't sent in cleartext.)
- [ ] **Step 2: Run → fail; extend yip-crypto.** Change `write_message` to `write_message(&mut self, payload:&[u8])` (pass `payload` instead of `&[]` to snow's `write_message`). Change `read_message` to return the payload: snow's `read_message(msg, &mut buf)` returns the payload length `n`; return `buf[..n].to_vec()`. Update the crate's own tests + the blocking `run_initiator`/`run_responder` and any internal callers to pass `&[]` / bind-and-ignore the returned payload (non-mesh callers are unaffected in behavior).
- [ ] **Step 3: Thread through `handshake.rs` step-functions** per the Produces signatures — `start_initiator` writes `payload` into msg1; `start_responder` reads msg1's payload (return it as `initiator_payload`) and writes `resp_payload` into msg2; `read_response` reads msg2's payload (return it as `responder_payload`). Update the existing callers of these step-functions in `peer_manager.rs` to pass `&[]` and bind the new return tuple element to `_` **for now** (Task 6 supplies the real cert + consumes the payload). Keep the blocking `run_initiator`/`run_responder` (used by their own tests) working — they pass `&[]`.
- [ ] **Step 4: Run all → pass; full gate incl. netns (no behavior change with empty payloads).**

```bash
cargo test -p yip-crypto -p yipd --bins
cargo build --release -p yipd
BIN=$(ls -t target/debug/deps/tunnel_netns-* | grep -v '\.d$' | head -1)
for E in "" "YIP_USE_URING=1"; do for t in ping_across_yipd_tunnel triangle_full_mesh_ping relay_path_ping; do echo -n "$E $t: "; sudo -E env $E "$BIN" "$t" --exact --test-threads=1 2>&1 | grep -oE "test result: (ok|FAILED)"; done; done
```
Expected: all green (empty payloads = byte-compatible handshake). clippy/fmt clean.
- [ ] **Step 5: Commit** (`feat(yip-crypto,yipd): carry an app payload in the Noise handshake (2c cert seam)`).

---

### Task 5: `membership.rs` directory + gossip + config

**Files:**
- Create: `bin/yipd/src/membership.rs`; Modify: `bin/yipd/src/config.rs` (`ca_public`/`cert`/`roots`), `bin/yipd/src/main.rs` (`mod membership;`), `bin/yipd/Cargo.toml` (dep `yip-membership`)
- Test: inline `#[cfg(test)]` in both

**Interfaces:**
- Consumes: `yip_membership::{Cert, Record, RootSet, GossipMsg, verify_cert, node_id, node_addr, NodeId, CertError}`.
- Produces:
  - `pub struct MemberInfo { pub pubkey:[u8;32], pub endpoints:Vec<SocketAddr> }`
  - `pub struct Membership { /* directory, ca_pubkeys, network_id, own record, roots, skew */ }`
  - `pub fn new(ca_pubkeys:Vec<[u8;32]>, network_id:[u8;16], own_cert:Cert, own_sign_priv:[u8;32], roots:RootSet, own_endpoints:Vec<SocketAddr>) -> Self`
  - `pub fn resolve(&self, addr:&Ipv6Addr) -> Option<MemberInfo>` (directory lookup by node_addr).
  - `pub fn verify_cert(&self, cert:&Cert, static_key:&[u8;32], now:u64) -> bool` (wraps `yip_membership::verify_cert` with the configured ca_pubkeys/network/skew).
  - `pub fn own_cert_bytes(&self) -> Vec<u8>` (this node's cert, encoded — for the handshake payload).
  - `pub fn ingest_record(&mut self, rec:Record, now:u64) -> bool` (verify + insert if newer seq / not expired; return true if the directory changed).
  - `pub fn on_gossip(&mut self, msg:GossipMsg, now:u64) -> Vec<GossipMsg>` (Digest→reply PullRequest for unknown/stale; PullRequest→reply Records; Records→ingest each; returns messages to send back).
  - `pub fn tick_digest(&mut self, now:u64) -> Option<GossipMsg>` (periodic digest to send to gossip partners; debounced).
  - `pub fn roots(&self) -> &[([u8;32],SocketAddr)]` (for bootstrap + always-admit).

- [ ] **Step 1: config** — add `ca_public: Vec<[u8;32]>`, `cert: Option<Cert>` (loaded+decoded from the `cert=<path>` file), `roots: Option<RootSet>` (from `roots=<path>`), and the node's Ed25519 record-signing private key `member_sign_private: Option<[u8;32]>` (from a `member_sign_private=<hex>` key, generated alongside the X25519 key) to `Config`. Parse `ca_public=<hex>` (repeatable), `cert=<path>`, `roots=<path>`, `network_id=<hex16>`. Mesh mode = cert+ca_public+roots+member_sign_private all present. Add config-parse unit tests (mesh fields present → Some; absent → None/empty; a bad cert file → parse error).
- [ ] **Step 2: failing membership unit tests** (no sockets): (a) `ingest_record` accepts a valid record and `resolve(node_addr(pubkey))` returns its endpoints; (b) a higher-`seq` record supersedes a lower one; a lower-seq is ignored; (c) an expired-cert record is rejected/evicted; (d) a record with a bad member-sig or wrong CA is rejected; (e) `on_gossip(Digest)` returns a `PullRequest` for a node_id the local directory lacks or has a lower seq for; (f) `verify_cert` accepts the node's own cert and rejects a wrong-CA cert; (g) **anti-entropy convergence**: two `Membership`s exchanging `tick_digest`→`on_gossip` rounds converge to the same directory.
- [ ] **Step 3: Run → fail; implement `membership.rs`** — the directory `HashMap<NodeId,Record>` keyed by node_id, a secondary `HashMap<Ipv6Addr,NodeId>` for `resolve` (both derived from each record's `cert.member_pubkey` via `node_id`/`node_addr`), seq-supersession + expiry eviction in `ingest_record`, the `on_gossip`/`tick_digest` anti-entropy, `verify_cert` delegating to the lib with a `SKEW` const (e.g. `const CLOCK_SKEW_SECS:u64 = 300;`). Include the node's own record (built from `own_cert`/`own_endpoints`/`seq`, signed with `own_sign_priv`) in the directory + digests.
- [ ] **Step 4: Run → pass; build/clippy/fmt; commit** (`feat(yipd): membership directory + gossip anti-entropy + mesh config (2c)`).

---

### Task 6: `PeerManager` wiring — runtime admission + cert-in-handshake + gossip demux

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs`, `bin/yipd/src/tunnel.rs`
- Test: inline `#[cfg(test)]` in `peer_manager.rs`

The integration crux. Read `peer_manager.rs` in full first; keep ALL 2a/2b logic intact. Behavior to implement:

1. **`PeerManager` gains `membership: Option<Membership>`** (param on `new`, built in `tunnel.rs` from config; `None` ⇒ pure 2a/2b, every membership branch skipped ⇒ byte-identical), and a **`SystemTime`-derived wall-clock `now_secs`** helper for cert validity (distinct from the monotonic `now_ms`).

2. **Runtime admission — `admit_member(&mut self, pubkey:[u8;32], endpoints:Vec<SocketAddr>, now_ms)`**: the peer-table mutation `PeerManager` lacks today — push a new `Peer` (Idle, `endpoint = endpoints.first().copied()`, fresh `PathState::new(has_direct = !endpoints.is_empty(), has_rendezvous, now_ms)` with `on_direct_addr` for each endpoint), register `by_addr`/`by_node`. Idempotent (no-op if the pubkey is already a peer).

3. **`on_tun` resolve-and-admit**: when `route_tun_index` finds no peer for the inner dst and `membership.is_some()`, call `membership.resolve(inner_dst_node_addr)`; if `Some(info)` → `admit_member(info.pubkey, info.endpoints, now)` then re-drive the normal lazy-handshake path (the just-admitted peer is now Idle with a candidate → the existing 2b escalation fires). If `None` → current drop/buffer behavior.

4. **`handle_handshake_init` cert admission**: the initiator's cert arrives as the msg1 payload (Task 4's `start_responder` now returns it). Admission becomes: `remote_static` matches a configured/root peer **OR** the presented cert verifies (`membership.verify_cert(&cert, &remote_static, now_secs)`); on the cert path, `admit_member(remote_static, cert endpoints/none, now_ms)` if not already a peer, before completing. The responder presents ITS cert as the msg2 payload (`membership.own_cert_bytes()`). Drop (no reply) if neither path admits — PRE-session, exactly as today's allowlist drop. The initiator side (`start_initiator`) presents `membership.own_cert_bytes()` in msg1; `read_response` gets the responder's cert (verify it too — mutual).

5. **Gossip demux**: a new `PacketType::Gossip` (or route gossip inside established sessions). Simplest: gossip rides as an authenticated in-session control message — on a decrypted gossip frame from an Established peer, call `membership.on_gossip(msg, now)` and send back any returned `GossipMsg`s to that peer (relay-wrapped if the peer is `Relayed`). From `tick`, periodically emit `membership.tick_digest(now)` to a sample of Established peers + attempt a handshake to a root (bootstrap) if the directory is empty/stale. Keep it simple and bounded.

6. **Anti-hijack unchanged**: membership only ever supplies a *candidate* pubkey+cert+endpoints; the Noise handshake still gates the session; an Established peer's committed egress is never redirected by a gossip/resolve event.

- [ ] **Step 1: mock-Membership unit tests** (a `Membership` built with an in-test CA + certs, no sockets): (a) `on_tun` to an unknown mesh addr that `resolve`s → admits a peer + emits a handshake Init; (b) `handle_handshake_init` with a valid presented cert admits + replies; with an invalid/absent cert (and not a configured peer) drops with no reply/session; (c) NO membership configured → `on_tun`/`handle_handshake_init` behave exactly as 2a/2b (unknown addr dropped, only configured keys admitted); (d) anti-hijack: an Established peer isn't disturbed by a resolve/gossip event.
- [ ] **Step 2: Run → fail; implement** points 1–6. Update the Task-4 step-function call sites to pass the real cert payload and consume the returned peer cert.
- [ ] **Step 3: `tunnel.rs`** builds `Option<Membership>` from config (cert+ca_public+roots+member_sign_private all present) and passes it into `PeerManager::new`.
- [ ] **Step 4: Full gate — unit + the 2a/2b no-regression netns suite both drivers** (rebuild `--release`):

```bash
cargo test -p yipd --bins
cargo build --release -p yipd
BIN=$(ls -t target/debug/deps/tunnel_netns-* | grep -v '\.d$' | head -1)
for E in "" "YIP_USE_URING=1"; do for t in ping_across_yipd_tunnel ping_across_yipd_tunnel_under_loss arq_recovers_bulk_loss l2_tap_ping_or_arp_across_tunnel triangle_full_mesh_ping relay_path_ping hole_punch_ping; do echo -n "$E $t: "; timeout 120 sudo -E env $E "$BIN" "$t" --exact --test-threads=1 2>&1 | grep -oE "test result: (ok|FAILED)"; done; done
```
Expected: all 14 `ok` (no mesh config in these → byte-identical 2a/2b). clippy/fmt clean.
- [ ] **Step 5: Commit** (`feat(yipd): wire membership discovery + cert admission into PeerManager (2c)`).

---

### Task 7: netns money tests — dynamic discovery + admission + root-outage + CI

**Files:**
- Create: `bin/yipd/tests/{run-netns-discovery.sh,run-netns-admission-reject.sh,run-netns-root-outage.sh}`
- Modify: `bin/yipd/tests/tunnel_netns.rs`, `.github/workflows/integration.yml`

Mirror `run-netns-triangle.sh`/`run-netns-relay.sh` for boilerplate. Each test: mint a CA (`yip-ca genkey`), issue member certs (`yip-ca sign-cert`) for each node, sign a root set (`yip-ca sign-roots`) naming a seed root node, write per-node configs with `ca_public`/`cert`/`roots`/`network_id`/`member_sign_private` (NO `[peer]` for the peers being discovered), assign each TUN its `node_addr/128` + `fd00::/8` route (via `yipd --addr`), start the seed root + the nodes, and drive traffic. `set -euo pipefail`, cleanup trap, root-gated SKIP line.

- [ ] **Step 1: `run-netns-discovery.sh`** (headline) — nodes A, B, and a seed root R (R may just be a third yipd that both list in `roots`). A and B have **no `[peer]` entry for each other** — only certs + the root set. Bring up; A `ping -6` B's `node_addr`. Expect: A bootstraps to R, gossip converges (A learns B's record), A resolves B → admits → cert-verified handshake → ping flows. **Assert** ping succeeds AND (load-bearing) A had no static config for B (grep A's config to prove B's key isn't there). Generous ping window for gossip convergence + handshake (like the 2b warm-up tolerance).
- [ ] **Step 2: `run-netns-admission-reject.sh`** — a node X with NO cert (or an expired / wrong-CA cert) attempts to reach an in-network node Y. **Assert** the handshake is refused and no tunnel forms (ping FAILS / Y's log shows a rejected/cert-invalid admission). Load-bearing: proves the gate.
- [ ] **Step 3: `run-netns-root-outage.sh`** — A and B discover each other via R, confirm connectivity, then `kill` R and (re)establish/continue A↔B traffic. **Assert** A↔B connectivity survives R's death (directory already converged).
- [ ] **Step 4: Rust harness** in `tunnel_netns.rs` — add `discovery_dynamic_ping`, `admission_rejects_uncertified`, `discovery_survives_root_outage` mirroring `triangle_full_mesh_ping` (root-gated SKIP; invoke `bash <script> <yipd> <yip-ca>` — resolve `yip-ca` by path like `yip-rendezvous` since `CARGO_BIN_EXE_yip-ca` is cross-package). Ping-only ⇒ debug binary fine.
- [ ] **Step 5: CI** — add the three test names to the `netns-tunnel-test` loop in `integration.yml` (both drivers; honesty guard covers them); add a `cargo build -p yip-ca` step (mirroring the `yip-rendezvous-bin` build step) so the binary exists.
- [ ] **Step 6: Run all three under BOTH drivers + confirm no 2a/2b regression; commit** (`test(yipd): netns dynamic-discovery + admission + root-outage, gated both drivers (2c)`).

---

## Self-Review

**Spec coverage:** yip-membership cert/record/rootset+verify → Tasks 1–2 ✅; gossip wire → Task 2 ✅; offline yip-ca → Task 3 ✅; cert-in-handshake payload → Task 4 ✅; directory+gossip+config → Task 5 ✅; PeerManager runtime admission + cert admission + gossip demux + tunnel wiring → Task 6 ✅; netns discovery/admission/root-outage/no-regression + CI → Task 7 ✅. Trust model (offline CA, signed roots, chain) realized across Tasks 1/3/5/6. Wall-clock skew → Tasks 1 (`verify` takes `now`,`skew`) + 6 (`now_secs`). Anti-hijack preserved → Task 6 point 6. All non-goals excluded.

**Placeholder scan:** the Task-1 lib.rs "comment `pub mod record/gossip` until Task 2" is an explicit, resolved sequencing note (Task 2 Step "uncomment"), not a placeholder; every code step carries complete code or a precise interface + test list. Tasks 5–6 are integration tasks specified by interface + behavior + test assertions (like the 2b plan's integration tasks), not vague directives.

**Type consistency:** `NodeId=[u8;16]` (Tasks 1,2,5,6); `Cert`/`Record`/`RootSet`/`GossipMsg` field names identical across Tasks 1,2,3,5,6; `verify_cert(cert, ca_pubkeys, network_id, member_pubkey, now, skew)` used consistently (lib in Task 1, wrapped by `Membership::verify_cert(cert, static_key, now)` in Task 5, called in Task 6); the handshake step-function signature changes (Task 4) are consumed with the real cert in Task 6; `Membership`'s methods (`resolve`/`verify_cert`/`own_cert_bytes`/`ingest_record`/`on_gossip`/`tick_digest`) defined in Task 5, consumed in Task 6. `admit_member` defined + used in Task 6.

**Note for the implementer:** Task 4 changes `yip_crypto::Handshake::{write_message,read_message}` and the `handshake.rs` step-function signatures — the one cross-crate API change; all existing callers pass `&[]`/ignore the returned payload so 2a/2b behavior is unchanged, and Task 6 supplies the real cert. Everything else is additive.
