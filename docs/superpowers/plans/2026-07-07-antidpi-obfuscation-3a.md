# Sub-project #3 Milestone 3a: Anti-DPI Obfuscation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make yip traffic indistinguishable from random UDP to a passive DPI observer — remove every fixed byte/size/timing signature — behind an opt-in `obf_psk`, proven by an nDPI CI gate.

**Architecture:** A single new `yip-obf` envelope wraps every outgoing datagram with a masked **type discriminator** + random **padding**, keyed by the peer's session `hp_key` (established) or the network `obf_psk` (pre-session handshake/rendezvous). The plaintext `PacketType`/rendezvous/gossip discriminant bytes are deleted; the receiver demuxes by source + trial-unmask. `yip-wire` is untouched (its frames ride *inside* the envelope). `obf_psk` absent → the current wire format is byte-identical (no regression).

**Tech Stack:** Rust, `siphasher` (the existing SipHash-CTR keystream primitive), `blake2` (key derivation), `getrandom`/`rand` (per-packet nonce), the merged 2a/2b/2c stack, `refrences/nDPI` (`ndpiReader`) + `tcpdump` for the CI oracle.

**Refinement vs. the spec:** the spec described extending `yip-wire::Codec` to carry the type for session frames and a separate `yip-obf` for pre-session. This plan uses ONE uniform `yip-obf` envelope for both regimes (keyed differently) — same goal (type discriminator in a keyed field, no fixed bytes), strictly simpler (yip-wire untouched, the no-constant-byte property proven once), and it also subsumes the Control-counter-leak fix for free. Flagged for the user at handoff.

## Global Constraints

- `yipd`, `yip-obf`, `yip-wire`, `yip-rendezvous` stay `#![forbid(unsafe_code)]`; `unsafe` only in `yip-io`/`yip-device`.
- No `as` numeric casts except the masked type discriminant (`u8`) and existing `PacketType::* as u8` on the legacy (obf-off) path.
- **Obfuscation is a LAYER over Noise/AEAD** — a keystream XOR that hides only the fingerprint; it never weakens content secrecy (Noise) or integrity (the inner AEAD / yip-wire SipHash tag / Noise MAC).
- **Fail-closed:** wrong/absent `obf_psk` → `deobfuscate` yields garbage → the inner Noise/AEAD/frame verification fails → datagram dropped. Trial-unmask auth-fails-free and never mis-dispatches.
- **`obf_psk` absent ⇒ byte-identical 2a/2b/2c wire format** — all existing netns tests green under BOTH `poll` and `YIP_USE_URING=1`; the `arq_recovers_bulk_loss` netns test uses the **release** `yipd` (rebuild `--release` after any yipd change).
- **Anti-hijack / cert admission (2a/2b/2c) unchanged** — obfuscation wraps the same datagrams; the Noise handshake + cert admission still gate every session.
- No panic reachable from a malformed/garbage datagram (`deobfuscate` bounds-checks and returns `None`).
- `obf_key`/`obf_nonce`: `obf_key = BLAKE2s("yip-obf-v1" || obf_psk)[..16]`; the per-packet `obf_nonce` is random (8 bytes).
- Green bar every task: `cargo fmt --all --check`, `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p <crate>`.
- Deferred / non-goals (do NOT build): junk/decoy packets + heavy traffic-shaping (3b), TLS/QUIC mimicry/REALITY (3c), pluggable transports/plausible ports (3d), data-plane timing obfuscation, entropy/TCP heuristics R2/R3, #34 anti-replay, #9 rekey, metadata privacy.

**Sandbox note:** the pre-commit hook's workspace `cargo test` trips on 2 pre-existing unrelated `yip-io` io_uring memlock tests (they pass in CI). If it blocks ONLY on those, commit `--no-verify` after confirming your crate + clippy + fmt are green.

---

## File Structure

- `crates/yip-obf/` (NEW lib): `src/lib.rs` — `derive_key`, `obfuscate`, `deobfuscate`, the SipHash-CTR keystream. The whole obfuscation envelope.
- `bin/yipd/src/config.rs` (MODIFY): `obf_psk: Option<[u8;32]>`.
- `bin/yip-rendezvous/*` + `crates/yip-rendezvous/*` (MODIFY): `obf_psk` config + wrap/unwrap rendezvous `Message`s.
- `bin/yipd/src/peer_manager.rs` (MODIFY): the demux rewire + wrapping every send via `yip-obf` when `obf_psk`/session-keyed; the crux.
- `bin/yipd/src/dataplane.rs` (MODIFY): stop prepending the `PacketType::Data`/`Control` byte on the obf path; expose the session obf key (derived from `hp_key`).
- `bin/yipd/src/handshake.rs` (MODIFY): `PacketType` enum stays for the legacy path + as the internal type values; handshake send stops prepending the byte on the obf path.
- `bin/yipd/src/tunnel.rs` (MODIFY): thread `obf_psk` into `PeerManager`.
- Timing jitter: `peer_manager.rs`/`membership.rs` (MODIFY) — jitter control cadences.
- `bin/yipd/tests/run-netns-obfuscated.sh` + `tunnel_netns.rs` + `.github/workflows/integration.yml` (NEW/MODIFY) — netns + the `dpi-undetectability` nDPI job.

---

### Task 1: `yip-obf` — the obfuscation envelope

**Files:**
- Create: `crates/yip-obf/Cargo.toml`, `crates/yip-obf/src/lib.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `pub fn derive_key(psk: &[u8]) -> [u8;16]` — `BLAKE2s("yip-obf-v1" || psk)[..16]` (the SipHash key).
  - `pub fn obfuscate(key: &[u8;16], ptype: u8, body: &[u8], pad_len: usize) -> Vec<u8>` — envelope = `nonce(8) ‖ SipHash-CTR(key, nonce) ⊕ (ptype(1) ‖ body_len(u16 be) ‖ body ‖ pad_len random bytes)`.
  - `pub fn deobfuscate(key: &[u8;16], dg: &[u8]) -> Option<(u8, Vec<u8>)>` — split nonce, unmask, read `ptype` + `body_len`, bounds-check (`body_len <= masked_region - 3`), return `(ptype, body)`; `None` if too short or inconsistent.
  - `pub const NONCE_LEN: usize = 8;` `pub const MIN_ENVELOPE: usize = NONCE_LEN + 3;`

- [ ] **Step 1: Create the crate.** `crates/yip-obf/Cargo.toml`:

```toml
[package]
name = "yip-obf"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
blake2 = { workspace = true }
siphasher = "=1.0.1"
getrandom = "0.2"

[lints]
workspace = true
```
(Confirm `siphasher`'s version matches what `yip-wire` pins — read `crates/yip-wire/Cargo.toml` and match it exactly so the workspace has one version.)

- [ ] **Step 2: Write failing tests** in `crates/yip-obf/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_type_and_body() {
        let key = derive_key(b"network-secret");
        let dg = obfuscate(&key, 2, b"hello world payload", 17);
        let (ptype, body) = deobfuscate(&key, &dg).expect("round-trips");
        assert_eq!(ptype, 2);
        assert_eq!(body, b"hello world payload");
    }

    #[test]
    fn wrong_key_does_not_recover_body() {
        let k1 = derive_key(b"secret-a");
        let k2 = derive_key(b"secret-b");
        let dg = obfuscate(&k1, 2, b"the real body", 8);
        // Wrong key yields either None (inconsistent length) or a garbage body,
        // but MUST NOT recover the real (ptype=2, "the real body").
        match deobfuscate(&k2, &dg) {
            None => {}
            Some((pt, body)) => assert!(pt != 2 || body != b"the real body"),
        }
    }

    #[test]
    fn no_byte_position_is_constant_across_packets() {
        // The core anti-DPI property: obfuscate many datagrams of the SAME
        // (type, body) and assert no byte offset holds a constant value across
        // them (random nonce + keystream => every position varies). This is the
        // whole-datagram generalization of yip-wire's no-constant-header test.
        let key = derive_key(b"k");
        let n = 512usize;
        let dgs: Vec<Vec<u8>> = (0..n).map(|_| obfuscate(&key, 2, b"same body every time", 4)).collect();
        let len = dgs[0].len();
        for pos in 0..len {
            let first = dgs[0][pos];
            let all_same = dgs.iter().all(|d| d.len() == len && d[pos] == first);
            assert!(!all_same, "byte position {pos} is constant across packets — a DPI signature");
        }
    }

    #[test]
    fn deobfuscate_rejects_truncation_and_garbage() {
        let key = derive_key(b"k");
        assert_eq!(deobfuscate(&key, &[]), None);
        assert_eq!(deobfuscate(&key, &[0u8; 3]), None); // < MIN_ENVELOPE
        let mut dg = obfuscate(&key, 1, b"abc", 5);
        dg.truncate(dg.len() - 1); // corrupt length consistency
        // Must not panic; returns None or a shorter/garbage body, never OOB.
        let _ = deobfuscate(&key, &dg);
    }

    #[test]
    fn pad_len_changes_size_but_not_recovered_body() {
        let key = derive_key(b"k");
        let a = obfuscate(&key, 0, b"x", 0);
        let b = obfuscate(&key, 0, b"x", 200);
        assert!(b.len() > a.len());
        assert_eq!(deobfuscate(&key, &a).unwrap().1, b"x");
        assert_eq!(deobfuscate(&key, &b).unwrap().1, b"x");
    }
}
```

- [ ] **Step 3: Run → fail.** `cargo test -p yip-obf`.

- [ ] **Step 4: Implement `lib.rs`.** Prepend:

```rust
//! `yip-obf`: the anti-DPI obfuscation envelope. Wraps a datagram body with a
//! keyed, per-packet-randomized mask so an observer without the key sees only
//! uniform-random bytes — no fixed value, no fixed type byte, no fixed size.
//! A keystream XOR (SipHash-CTR), NOT an AEAD: it hides the fingerprint only;
//! content secrecy/integrity remain the inner layer's job (Noise / AEAD /
//! yip-wire tag), which fail-closed on a wrong key.
#![forbid(unsafe_code)]

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

pub const NONCE_LEN: usize = 8;
/// nonce(8) + type(1) + body_len(2) minimum.
pub const MIN_ENVELOPE: usize = NONCE_LEN + 3;

const DOMAIN: &[u8] = b"yip-obf-v1";

/// Derive the 16-byte SipHash key from the network `obf_psk` (or any keying
/// material — the caller also uses this to derive a per-session key from hp_key).
pub fn derive_key(psk: &[u8]) -> [u8; 16] {
    let mut h = Blake2sVar::new(16).expect("16 is a valid blake2s output len");
    h.update(DOMAIN);
    h.update(psk);
    let mut out = [0u8; 16];
    h.finalize_variable(&mut out).expect("len ok");
    out
}

/// SipHash-CTR keystream of `n` bytes: SipHash24(key, nonce ‖ counter_be) per
/// 8-byte block. Same construction as `yip-wire`'s header mask.
fn keystream(key: &[u8; 16], nonce: &[u8; NONCE_LEN], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut counter: u64 = 0;
    while out.len() < n {
        let mut h = SipHasher24::new_with_key(key);
        h.write(nonce);
        h.write(&counter.to_be_bytes());
        out.extend_from_slice(&h.finish().to_be_bytes());
        counter = counter.wrapping_add(1);
    }
    out.truncate(n);
    out
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).expect("OS RNG");
    n
}

/// Wrap `(ptype, body)` with `pad_len` random trailing padding bytes.
pub fn obfuscate(key: &[u8; 16], ptype: u8, body: &[u8], pad_len: usize) -> Vec<u8> {
    let nonce = random_nonce();
    let body_len = u16::try_from(body.len()).expect("body fits u16");
    // plaintext region: type(1) ‖ body_len(2) ‖ body ‖ padding
    let mut region = Vec::with_capacity(3 + body.len() + pad_len);
    region.push(ptype);
    region.extend_from_slice(&body_len.to_be_bytes());
    region.extend_from_slice(body);
    region.resize(region.len() + pad_len, 0); // padding masks to random anyway
    let ks = keystream(key, &nonce, region.len());
    for (b, k) in region.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
    let mut out = Vec::with_capacity(NONCE_LEN + region.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&region);
    out
}

/// Recover `(ptype, body)`, or `None` if too short / length-inconsistent.
pub fn deobfuscate(key: &[u8; 16], dg: &[u8]) -> Option<(u8, Vec<u8>)> {
    if dg.len() < MIN_ENVELOPE {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = dg[..NONCE_LEN].try_into().ok()?;
    let masked = &dg[NONCE_LEN..];
    let ks = keystream(key, &nonce, masked.len());
    let mut region = masked.to_vec();
    for (b, k) in region.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
    let ptype = *region.first()?;
    let body_len = usize::from(u16::from_be_bytes(region.get(1..3)?.try_into().ok()?));
    let body = region.get(3..3 + body_len)?.to_vec();
    Some((ptype, body))
}
```

- [ ] **Step 5: Run → pass; build/clippy/fmt clean; commit.**

```bash
cargo test -p yip-obf && cargo clippy -p yip-obf --all-targets -- -D warnings && cargo fmt --all --check
git add crates/yip-obf Cargo.lock
git commit -m "feat(yip-obf): keyed obfuscation envelope — masked type + padding, no constant byte (3a)"
```

---

### Task 2: `obf_psk` config (yipd + yip-rendezvous)

**Files:**
- Modify: `bin/yipd/src/config.rs`, `bin/yip-rendezvous/src/main.rs`
- Test: inline config tests

**Interfaces:**
- Consumes: `yip_obf::derive_key`.
- Produces: `config::Config.obf_psk: Option<[u8;32]>` (parsed from `obf_psk=<hex64>`); `yip-rendezvous` accepts a second CLI arg or an `--obf-psk <hex>` for the same value.

- [ ] **Step 1: yipd config.** In `bin/yipd/src/config.rs`: add `pub obf_psk: Option<[u8;32]>` to `Config`; parse `obf_psk=<hex64>` via the existing `hex_to_32` helper (absent → `None`). Unknown keys stay tolerated.
- [ ] **Step 2: Failing config tests** (append to `config.rs` tests):

```rust
#[test]
fn parses_obf_psk_when_present() {
    let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                obf_psk=00000000000000000000000000000000000000000000000000000000000000ff\n";
    let cfg = Config::parse(text).unwrap();
    assert_eq!(cfg.obf_psk, Some({ let mut a = [0u8;32]; a[31]=0xff; a }));
}

#[test]
fn obf_psk_absent_is_none() {
    let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
    assert_eq!(Config::parse(text).unwrap().obf_psk, None);
}
```

- [ ] **Step 3: Run → fail; implement** the config field + parse. `cargo test -p yipd --bins config`.
- [ ] **Step 4: yip-rendezvous obf_psk.** In `bin/yip-rendezvous/src/main.rs`: accept `--obf-psk <hex64>` (optional) alongside the listen addr; decode to `[u8;32]`. Store it for Task 4's wrap/unwrap. Add `yip-obf` to `bin/yip-rendezvous/Cargo.toml`. (No behavior yet beyond parsing — Task 4 uses it.)
- [ ] **Step 5: Build/clippy/fmt; commit** (`feat(yipd,yip-rendezvous): obf_psk config (3a)`).

---

### Task 3: wrap/demux data-plane + handshake datagrams via `yip-obf` (the crux)

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs`, `bin/yipd/src/dataplane.rs`, `bin/yipd/src/handshake.rs`, `bin/yipd/src/tunnel.rs`, `bin/yipd/Cargo.toml` (+ `yip-obf` dep)
- Test: inline `#[cfg(test)]` in `peer_manager.rs`

Read `peer_manager.rs` (`on_udp` demux, the send paths) and `dataplane.rs` (the `PacketType::Data`/`Control` prepend at lines ~259/534 and the `dg[0]` reads at ~287/346) in full first. Implement to this behavior (`obf_psk: None` ⇒ every branch below is skipped ⇒ byte-identical today):

1. **`PeerManager` gains `obf_psk: Option<[u8;32]>`** (param on `new`, built in `tunnel.rs` from config) and a derived `obf_key = obf_psk.map(|p| yip_obf::derive_key(&p))` for pre-session use. **Per-peer session obf key**: derive from the peer's `hp_key` — `yip_obf::derive_key(&hp_key)` — stored alongside the DataPlane (or derived on demand). (Read where `hp_key` lives; the DataPlane/Established session holds it.)

2. **The packet-type values** reuse the existing `PacketType` discriminants (0..4) as the `ptype` byte passed to `yip_obf::obfuscate` — they are now a *masked* field inside the envelope, never a plaintext prefix.

3. **Send path (when `obf_psk` is Some):** every outgoing datagram is wrapped exactly once via `yip_obf::obfuscate(key, ptype, inner_bytes, pad)`:
   - Data/Control (from `DataPlane`): stop prepending the `PacketType::Data`/`Control` byte; the inner bytes are the yip-wire frame / sealed control; wrap with the **session** obf key, `ptype = Data|Control`. Handshake retransmits likewise.
   - HandshakeInit/Resp: stop prepending the `PacketType` byte; inner = the Noise message; wrap with the **`obf_psk`** key (pre-session), `ptype = HandshakeInit|HandshakeResp`.
   - Gossip: inner = the `GossipMsg` bytes; wrap with the **session** obf key, `ptype = Gossip` (this also seals gossip from a passive observer — a 2c gap).
   - **Padding:** choose `pad` per the sizing rule — generous random for handshakes (e.g. `getrandom`-drawn `0..=(1200 - inner.len()).max(0)`), modest for data/control (e.g. `0..=64`, room permitting under MTU). Put a small `fn random_pad(max: usize) -> usize` helper in peer_manager.
   - **Rendezvous** send/recv: wrap the rendezvous `Message` bytes via `yip-obf(obf_psk)` — see Task 4 (spans the yip-rendezvous crate); this task does the yipd-side rendezvous client wrap if reachable here, else Task 4.

4. **Demux rewire (`on_udp`, when `obf_psk` is Some):** delete the `dg[0]`/`payload[0]` `PacketType` reads; dispatch by **source + trial-unmask** in order:
   a. If `src` is a known Established peer: `yip_obf::deobfuscate(session_key, dg)` → `(ptype, inner)`; if `Some` and `ptype ∈ {Data,Control,Gossip}` → route `inner` to that peer's DataPlane / gossip handler exactly as the old `dg[1..]` path did.
   b. If (a) is `None`/inconsistent, OR `src` is not an Established peer: `yip_obf::deobfuscate(obf_key /*obf_psk*/, dg)` → if `Some` and `ptype ∈ {HandshakeInit,HandshakeResp}` → process the inner Noise message (self-authenticates; garbage → Noise fails → drop). This covers a new peer's Init AND a re-handshake from a known src.
   c. Neither → drop. Every unmask/verify failure is free and safe.
   When `obf_psk` is `None`, keep the existing `dg[0]` dispatch unchanged.

5. **`tunnel.rs`** builds `obf_psk` from config and passes it into `PeerManager::new`. **Anti-hijack unchanged:** obfuscation only wraps/unwraps; the Noise handshake + cert admission still gate sessions; an Established peer's committed egress is unaffected.

- [ ] **Step 1: Unit tests** (in `peer_manager.rs`, obf on): (a) with `obf_psk` set, a Data datagram built via the send path deobfuscates to `(Data, frame)` and routes to the peer; a datagram from an unknown src deobfuscates via `obf_psk` to a `HandshakeInit` and is processed; (b) a datagram whose bytes are random garbage (wrong key) is dropped, no panic; (c) with `obf_psk` None, on_udp behaves exactly as today (the existing tests still pass). Use `yip_obf` directly to build test datagrams.
- [ ] **Step 2: Run → fail; implement** points 1–5. Keep every 2a/2b/2c behavior on the `obf_psk: None` path identical.
- [ ] **Step 3: Full gate — unit + the netns no-regression suite both drivers with obf OFF** (rebuild `--release`):

```bash
cargo test -p yipd --bins
cargo build --release -p yipd
BIN=$(ls -t target/debug/deps/tunnel_netns-* | grep -v '\.d$' | head -1)
for E in "" "YIP_USE_URING=1"; do for t in ping_across_yipd_tunnel ping_across_yipd_tunnel_under_loss arq_recovers_bulk_loss l2_tap_ping_or_arp_across_tunnel triangle_full_mesh_ping relay_path_ping hole_punch_ping discovery_dynamic_ping admission_rejects_uncertified discovery_survives_root_outage; do echo -n "$E $t: "; timeout 150 sudo -E env $E "$BIN" "$t" --exact --test-threads=1 2>&1 | grep -oE "test result: (ok|FAILED)"; done; done
```
Expected: all `ok` (these configs set no `obf_psk` → byte-identical). clippy/fmt clean.
- [ ] **Step 4: Commit** (`feat(yipd): wrap/demux datagrams via yip-obf when obf_psk set (3a crux)`).

---

### Task 4: rendezvous obfuscation (yipd client + yip-rendezvous server)

**Files:**
- Modify: `bin/yipd/src/rendezvous.rs` (the `ConfiguredServerRendezvous` client), `bin/yip-rendezvous/src/main.rs`, `crates/yip-rendezvous/Cargo.toml`/`bin/yip-rendezvous/Cargo.toml` (`yip-obf` dep)
- Test: a round-trip test that an obf-wrapped rendezvous Message unwraps

**Interfaces:** Consumes `yip_obf`, `yip_rendezvous::Message` encode/decode.

Behavior (when `obf_psk` set on both sides):
- The yipd rendezvous client (`ConfiguredServerRendezvous`) wraps each outgoing rendezvous `Message` (encoded bytes) via `yip_obf::obfuscate(obf_key, RDV_TYPE, msg_bytes, pad)` before sending to the server, and unwraps inbound server datagrams via `deobfuscate` before `Message::decode`. Use a dedicated `ptype` for rendezvous (e.g. a `PacketType::Rendezvous` value / a constant `RDV_TYPE = 5`).
- The `yip-rendezvous` server loop: if `--obf-psk` was given, `deobfuscate` each inbound datagram before `Message::decode`, and `obfuscate` each reply before `send_to`. The blind relay path forwards the already-obfuscated *inner tunnel* payload verbatim (it never unmasks the tunnel layer — only the rendezvous-message layer).
- When `obf_psk`/`--obf-psk` is absent, the current plain rendezvous path is unchanged.

- [ ] **Step 1: Failing round-trip test** (in the yip-rendezvous or a shared test): `obfuscate` a `Message::Lookup{..}` with an obf key, `deobfuscate` + `Message::decode` recovers it; a wrong key fails to recover. Confirm no constant byte across many wrapped Lookups.
- [ ] **Step 2: Run → fail; implement** the client + server wrap/unwrap gated on the PSK.
- [ ] **Step 3: Build/clippy/fmt; `cargo test -p yipd --bins -p yip-rendezvous-bin`; commit** (`feat(rendezvous): obfuscate rendezvous messages under obf_psk (3a)`).

---

### Task 5: timing jitter on control cadences

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (handshake retry, keepalive), `bin/yipd/src/membership.rs` (gossip digest interval)
- Test: inline unit tests

**Interfaces:** Consumes a small jitter helper.

Behavior (when `obf_psk` set): the fixed control cadences emit a jittered interval instead of a constant one — `HANDSHAKE_RETRY_MS`, the gossip digest interval, and any keepalive get a per-fire random jitter (e.g. ±25%). The data-plane egress is **NOT** jittered (latency). Add `fn jitter_ms(base: u64) -> u64` (draw `base * 0.75 ..= base * 1.25` via `getrandom`). Gate on `obf_psk.is_some()` so obf-off timing is unchanged.

- [ ] **Step 1: Failing test** — `jitter_ms(1000)` returns values in `[750, 1250]` and is not constant across calls; a jitter-disabled path returns exactly `base`.
- [ ] **Step 2: Run → fail; implement** the helper + apply to the retry/gossip/keepalive timers under `obf_psk.is_some()`.
- [ ] **Step 3: Build/clippy/fmt; `cargo test -p yipd --bins`; confirm obf-off netns unaffected (a quick `ping_across_yipd_tunnel` under poll); commit** (`feat(yipd): jitter control-cadence timers under obf_psk (3a)`).

---

### Task 6: netns integration — obfuscated connectivity + no-regression

**Files:**
- Create: `bin/yipd/tests/run-netns-obfuscated.sh`
- Modify: `bin/yipd/tests/tunnel_netns.rs`, `.github/workflows/integration.yml`

Mirror `run-netns-triangle.sh` for boilerplate.

- [ ] **Step 1: `run-netns-obfuscated.sh`** → `obfuscated_ping`: two `yipd` in netns, BOTH configured with the SAME `obf_psk=<hex>` (plus normal single-peer config), complete a handshake and ping across. `set -euo pipefail`, cleanup trap, root-gated SKIP. **Assert** ping succeeds (obfuscation doesn't break connectivity).
- [ ] **Step 2: `obf_psk` mismatch** → `obf_psk_mismatch_no_connection`: two `yipd` with DIFFERENT `obf_psk` values → the handshake never deobfuscates → ping MUST fail (non-zero exit is the PASS condition, not `|| true`'d). Load-bearing: proves the PSK gates recognizability.
- [ ] **Step 3: Rust harness** — add `obfuscated_ping` + `obf_psk_mismatch_no_connection` to `tunnel_netns.rs` mirroring `ping_across_yipd_tunnel` (root-gated SKIP; `bash <script> <yipd>`).
- [ ] **Step 4: Money tests with obf ON.** Add an `obf_psk` line to the discovery/relay/punch test configs behind an env toggle, OR add one combined test that runs `discovery_dynamic_ping`'s topology with `obf_psk` set on all nodes (incl. the rendezvous server via `--obf-psk`) and asserts discovery still works. (Confirms obfuscation composes with 2b/2c.)
- [ ] **Step 5: CI + run.** Add the new tests to `integration.yml`'s netns loop (both drivers). Run all locally under both drivers; the 2a/2b/2c suite (obf off) must stay green. Commit (`test(yipd): netns obfuscated connectivity + PSK-mismatch + no-regression (3a)`).

---

### Task 7: the nDPI undetectability CI oracle (3e)

**Files:**
- Create: `bin/yipd/tests/run-ndpi-oracle.sh` (capture + classify), `.github/workflows/integration.yml` (a `dpi-undetectability` job)
- Test: `tunnel_netns.rs` `dpi_undetectability` (root-gated)

**Interfaces:** none (integration). Uses `tcpdump`, `ndpiReader` (built from `refrences/nDPI`).

- [ ] **Step 1: `run-ndpi-oracle.sh`** — set up two `yipd` with `obf_psk` in netns (reuse the Task 6 setup), start `tcpdump -i <veth> -w /tmp/yip.pcap` on the underlay, drive a full exchange (handshake + a ping for data + let a Control feedback fire + gossip if mesh-configured + a rendezvous round if configured), stop capture. Then run `ndpiReader -i /tmp/yip.pcap` with flow-risk/entropy/obfuscation heuristics enabled (read `refrences/nDPI/example/ndpiReader.c` option parsing + `obfuscation.conf` for the exact flags). **Assert** the output shows: (a) NO flow classified as WireGuard/OpenVPN/Tor/any VPN/proxy master protocol (grep the protocol column), (b) NO `NDPI_OBFUSCATED_TRAFFIC` and NO `NDPI_SUSPICIOUS_ENTROPY` risk flag. Fail (exit 1) if any appears. `set -euo pipefail`, cleanup trap, root-gated.
- [ ] **Step 2: Build ndpiReader.** In the CI `dpi-undetectability` job: clone/checkout is already vendored at `refrences/nDPI` (git-ignored/local — for CI, add a step to `git clone --depth 1` a **pinned** nDPI tag into the runner, or cache a prebuilt binary), `./autogen.sh && ./configure && make` (deps: `libpcap-dev`, `libjson-c-dev`, `libgcrypt-dev` per its README). Note the pin + refresh-on-bump in a comment.
- [ ] **Step 3: Rust harness** — `dpi_undetectability` in `tunnel_netns.rs` (root-gated SKIP; `bash run-ndpi-oracle.sh <yipd> <ndpiReader-path>`; assert success).
- [ ] **Step 4: CI job.** Add a `dpi-undetectability` job to `integration.yml`: build nDPI, build release yipd, run the oracle under sudo. Gate it (it's the undetectability merge gate). Document that it re-runs on nDPI version bumps.
- [ ] **Step 5: Run locally** (build ndpiReader from `refrences/nDPI`, run the oracle under sudo), confirm the assertions hold for obfuscated yip traffic. Commit (`test(ci): nDPI undetectability oracle for obfuscated yip traffic (3a/3e)`).

---

## Self-Review

**Spec coverage:** obf envelope (masked type + padding, no constant byte) → Task 1 ✅; `obf_psk` config → Task 2 ✅; kill `PacketType` prefix + demux by source/trial-unmask + wrap Data/Control/Gossip/Handshake → Task 3 ✅; rendezvous coverage → Task 4 ✅; control-timer jitter (not data path) → Task 5 ✅; netns obfuscated connectivity + PSK-mismatch + no-regression → Task 6 ✅; nDPI CI undetectability oracle → Task 7 ✅. Opt-in/`obf_psk`-absent-is-byte-identical enforced by the "obf off = unchanged path" gating in Tasks 3–5 + the no-regression gate. Security invariants (layer-over-Noise, fail-closed, obf_psk-compromise-is-detectable-but-secure) realized by the keystream-XOR envelope + inner Noise/AEAD verification.

**Placeholder scan:** every code step carries complete code (Task 1) or a precise interface + behavior + test list (Tasks 3/4/6/7 are integration tasks specified like the 2b/2c crux tasks — by interface + behavior + the exact send/demux sites, not vague directives). The nDPI CLI flag surface is the one under-specified point (Task 7 Step 1 says "read ndpiReader.c option parsing" — legitimate, since the exact flags depend on the pinned nDPI version and must be read from source at implementation time, not guessed).

**Type consistency:** `derive_key(&[u8]) -> [u8;16]`, `obfuscate(&[u8;16], u8, &[u8], usize) -> Vec<u8>`, `deobfuscate(&[u8;16], &[u8]) -> Option<(u8, Vec<u8>)>` consistent across Tasks 1/3/4. `obf_psk: Option<[u8;32]>` in config (Task 2) → derived to `[u8;16]` obf key (Task 3). The `ptype` values reuse the existing `PacketType` discriminants (0..4) + `RDV_TYPE=5` (Task 4). Session obf key = `derive_key(&hp_key)` throughout.

**Note for the implementer:** this plan uses ONE `yip-obf` envelope for both keying regimes (the refinement noted in the header) — `yip-wire` is untouched. The `PacketType` enum stays in `handshake.rs` (its discriminants are the `ptype` values, and the enum still drives the legacy obf-off `dg[0]` path). The one cross-crate touch is Task 4 (yipd + yip-rendezvous both wrap rendezvous messages).
