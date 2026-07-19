# REALITY.5b — ServerHello Emission + Server Key Schedule Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a byte-matching ServerHello for an authed REALITY connection (dest's structure, the relay's own key_share) and derive the server-side TLS 1.3 handshake keys — for groups X25519MLKEM768 (4588) + X25519 (29).

**Architecture:** A new `yip_utls::server` module: `server_key_share` does the relay's server-side KEX (ML-KEM Encapsulate + X25519, reusing REALITY.2's exact hybrid combiner), and `emit_server_hello` rebuilds the ServerHello verbatim from the captured `ServerHelloShape` (substituting a fresh random, the client's session_id echo, and the relay's key_share value) then derives keys via the reused `derive_handshake_keys`. `yip-rendezvous`'s ClientHello parser gains the client's ML-KEM ek (needed for 4588 encapsulation).

**Tech Stack:** Rust; `yip_utls` (reuses `handshake::derive_handshake_keys`/`transcript_hash`/`parse_server_hello`, `wire::HelloWriter`, the `x25519-dalek`/`ml-kem` primitives + combiner); `yip-rendezvous` (ClientHello parse).

## Global Constraints

- `#![forbid(unsafe_code)]` everywhere except `yip-io`/`yip-device` — NO `unsafe`.
- NO `as` numeric casts — use `try_from`/`to_be_bytes`/`from_be_bytes`/`usize::from`.
- NO bare `#[allow(...)]` — use `#[expect(reason = "...")]`.
- **Reuse REALITY.2's key schedule + hybrid combiner UNCHANGED.** The combiner is `shared = mlkem_ss ‖ x25519_ss` (ML-KEM first, 64 bytes for 4588; 32 bytes for X25519). `derive_handshake_keys(ecdhe, transcript_hash_ch_sh, suite)` is reused as-is.
- **Scope: groups 4588 + X25519 ONLY.** Any other group → `Error::UnsupportedGroup`. P256/P384 + HelloRetryRequest are deferred to #84.
- **No encrypted-flight emission (5c) and no `tls_front` wiring (5d)** in this milestone. 5b is the ServerHello + key-schedule primitive + the ClientHello ek extraction.
- The client's key_share values that `emit_server_hello`/`server_key_share` consume are passed in as params; 5d feeds the real parsed client values.
- Every task ends green: relevant `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt`.
- REALITY.2 client tests + JA4 diff stay green (5b is additive/server-side).
- Stacked on 5a. **Never merge the PR** — open it, leave it for the user.

**Spec:** `docs/superpowers/specs/2026-07-17-reality-5b-serverhello-emit-design.md`. Read it before starting.

**Ground-truth constants (in `crates/yip-utls/src/handshake.rs`):** `GROUP_X25519 = 0x001d`, `GROUP_X25519MLKEM768 = 4588`, `MLKEM768_CIPHERTEXT_LEN = 1088`, `EXT_KEY_SHARE = 51`; `MLKEM768_EK_LEN = 1184` (in `hello.rs`). The X25519 public/shared are 32 bytes.

---

### Task 1: Server KEX — `server_key_share` (`yip-utls::server`)

The relay's server-side key exchange: generate its ephemeral, return its key_share bytes + the ECDHE shared secret.

**Files:**
- Create: `crates/yip-utls/src/server.rs`
- Modify: `crates/yip-utls/src/lib.rs` (`pub mod server;` + re-export)
- Modify: `crates/yip-utls/src/error.rs` (add `UnsupportedGroup`)
- Modify: `crates/yip-utls/src/handshake.rs` (make `GROUP_X25519`/`GROUP_X25519MLKEM768`/`MLKEM768_CIPHERTEXT_LEN` `pub(crate)` if not already, so `server.rs` can use them — they're already `pub`/`const`; confirm)

**Interfaces:**
- Produces: `pub fn server_key_share(group: u16, client_x25519: &[u8; 32], client_mlkem_ek: Option<&[u8]>, rng: &mut dyn RandomSource) -> Result<(Vec<u8>, Vec<u8>), Error>` — returns `(server_key_share_bytes, shared_secret)`.
- Produces: `Error::UnsupportedGroup`.

- [ ] **Step 1: Add `Error::UnsupportedGroup`**

In `crates/yip-utls/src/error.rs`, add to the enum: `UnsupportedGroup(u16)`, its `Display` arm (`Error::UnsupportedGroup(g) => write!(f, "REALITY server cannot key TLS group {g}")`), and `None` in `source()`.

- [ ] **Step 2: Write the failing KEX tests**

Create `crates/yip-utls/src/server.rs` with a test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::RandomSource; // or wherever RandomSource lives — match the crate

    // A deterministic test RNG (mirror the one hello.rs/stream.rs tests use).
    struct SeqRng(u8);
    impl RandomSource for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) { for b in buf.iter_mut() { *b = self.0; self.0 = self.0.wrapping_add(1); } }
    }

    #[test]
    fn server_key_share_x25519_shapes() {
        let client_x = [7u8; 32];
        let (ks, ss) = server_key_share(0x001d, &client_x, None, &mut SeqRng(1)).unwrap();
        assert_eq!(ks.len(), 32);   // server x25519 public
        assert_eq!(ss.len(), 32);   // x25519 shared
    }

    #[test]
    fn server_key_share_4588_shapes() {
        // A real client ML-KEM ek (generate one, as the client does).
        use ml_kem::{KemCore, MlKem768, EncodedSizeUser};
        let mut r = crate::stream::MlKemRng::default(); // reuse the crate's ml-kem RNG bridge if present; else a test RNG
        let (_dk, ek) = MlKem768::generate(&mut r);
        let ek_bytes = ek.as_bytes().to_vec();
        let client_x = [9u8; 32];
        let (ks, ss) = server_key_share(4588, &client_x, Some(&ek_bytes), &mut SeqRng(1)).unwrap();
        assert_eq!(ks.len(), 1088 + 32); // ct ‖ x25519 public
        assert_eq!(ss.len(), 64);        // mlkem_ss(32) ‖ x25519_ss(32)
    }

    #[test]
    fn server_key_share_rejects_unsupported_group_and_missing_ek() {
        assert!(matches!(server_key_share(23, &[0;32], None, &mut SeqRng(1)), Err(Error::UnsupportedGroup(23))));
        assert!(server_key_share(4588, &[0;32], None, &mut SeqRng(1)).is_err()); // 4588 needs ek
    }
}
```

Adjust the `RandomSource`/`MlKemRng` imports to the crate's actual paths (read `hello.rs`/`stream.rs` for the exact `RandomSource` trait + how the client builds the ML-KEM keypair).

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p yip-utls server::tests`
Expected: FAIL — `cannot find function server_key_share`.

- [ ] **Step 4: Implement `server_key_share`**

```rust
//! REALITY.5b: the relay's server-side TLS 1.3 key exchange for an authed
//! connection — the mirror of `yip_utls`'s client KEX (`stream.rs`). Generates
//! the relay's own ephemeral so the relay holds the session keys, while the
//! ServerHello it goes into (see `emit_server_hello`) byte-matches dest's.
use crate::error::Error;
use crate::handshake::{GROUP_X25519, GROUP_X25519MLKEM768, MLKEM768_CIPHERTEXT_LEN};
use crate::hello::RandomSource; // the crate's RandomSource trait
use ml_kem::kem::Encapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

/// The relay's server-side KEX for `group`. Returns `(server_key_share_bytes,
/// shared_secret)`: the key_share to put in the ServerHello, and the ECDHE
/// secret for `derive_handshake_keys`. `shared_secret` uses REALITY.2's exact
/// combiner (`mlkem_ss ‖ x25519_ss` for 4588). Groups other than 4588/29 →
/// `Err(UnsupportedGroup)` (#84 defers those).
pub fn server_key_share(
    group: u16,
    client_x25519: &[u8; 32],
    client_mlkem_ek: Option<&[u8]>,
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // Fresh X25519 ephemeral (raw bytes → x25519-dalek, as the client does).
    let mut eph = [0u8; 32];
    rng.fill(&mut eph);
    let server_secret = x25519_dalek::StaticSecret::from(eph);
    let server_x25519_pub = x25519_dalek::PublicKey::from(&server_secret).to_bytes();
    let x25519_ss = server_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(*client_x25519))
        .to_bytes();

    match group {
        GROUP_X25519 => Ok((server_x25519_pub.to_vec(), x25519_ss.to_vec())),
        GROUP_X25519MLKEM768 => {
            let ek_bytes = client_mlkem_ek
                .ok_or(Error::Protocol("group 4588 requires the client's ML-KEM ek"))?;
            // Decode the client's encapsulation key, encapsulate against it.
            let encoded = ml_kem::Encoded::<
                <MlKem768 as KemCore>::EncapsulationKey,
            >::try_from(ek_bytes)
                .map_err(|_| Error::Protocol("client ML-KEM ek is the wrong length"))?;
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&encoded);
            // ml-kem's Encapsulate needs an RNG; bridge our RandomSource (reuse
            // the crate's MlKemRng adapter from stream.rs, or a small local one).
            let mut kem_rng = /* the crate's RandomSource→RngCore bridge */;
            let (ct, mlkem_ss) = ek
                .encapsulate(&mut kem_rng)
                .map_err(|_| Error::Protocol("ML-KEM encapsulation failed"))?;
            // server key_share = ct(1088) ‖ x25519_pub(32).
            let mut ks = Vec::with_capacity(MLKEM768_CIPHERTEXT_LEN + 32);
            ks.extend_from_slice(ct.as_slice());
            ks.extend_from_slice(&server_x25519_pub);
            // shared = mlkem_ss ‖ x25519_ss (REALITY.2's combiner order).
            let mut ss = Vec::with_capacity(64);
            ss.extend_from_slice(mlkem_ss.as_slice());
            ss.extend_from_slice(&x25519_ss);
            Ok((ks, ss))
        }
        other => Err(Error::UnsupportedGroup(other)),
    }
}
```

IMPLEMENTER: the ML-KEM `Encapsulate` RNG bridge — reuse the exact `RandomSource`→`RngCore` adapter `stream.rs` already uses for `MlKem768::generate` (find it; it's the `MlKemRng`/latched-error bridge). Confirm the `Encoded`/`from_bytes`/`encapsulate` call shapes against `ml-kem` 0.2.3 (the client `decapsulate` side in `stream.rs` is the mirror — match its types). The three tests (shapes + reject) are the gate; make them pass for real.

- [ ] **Step 5: Run to verify they pass + clippy + fmt + commit**

Run: `cargo test -p yip-utls server` → PASS.

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt -p yip-utls
git add crates/yip-utls/src/server.rs crates/yip-utls/src/lib.rs crates/yip-utls/src/error.rs
git commit -m "feat(reality.5b): server_key_share — server-side KEX (ML-KEM Encapsulate + X25519, 4588/29)"
```

---

### Task 2: `emit_server_hello` + round-trip proof (`yip-utls::server`)

Rebuild the ServerHello from the captured shape and derive server keys; prove a REALITY.2 client derives the same keys.

**Files:**
- Modify: `crates/yip-utls/src/server.rs` (`emit_server_hello`)

**Interfaces:**
- Consumes: `server_key_share` (Task 1); `ServerHelloShape` (5a); `wire::HelloWriter`; `handshake::{transcript_hash, derive_handshake_keys, HandshakeKeys}`.
- Produces: `pub fn emit_server_hello(shape, client_hello_msg, client_legacy_session_id, client_x25519, client_mlkem_ek, rng) -> Result<(Vec<u8>, HandshakeKeys), Error>`.

- [ ] **Step 1: Write the failing round-trip + byte-match tests**

Add to `server.rs` tests. Build a `ServerHelloShape` fixture (both a 4588 and a 29 variant — reuse Task-1-style helpers / the 5a `build_test_server_hello` shape helpers), a client ML-KEM keypair + X25519 keypair, and a stand-in `client_hello_msg`:

```rust
    #[test]
    fn emit_server_hello_roundtrips_x25519() { roundtrip(0x001d); }
    #[test]
    fn emit_server_hello_roundtrips_4588() { roundtrip(4588); }

    fn roundtrip(group: u16) {
        // Client keypairs (as connect generates them).
        let mut mlkem_rng = /* crate MlKemRng */;
        let (client_dk, client_ek) = MlKem768::generate(&mut mlkem_rng);
        let client_ek_bytes = client_ek.as_bytes().to_vec();
        let mut cx = [0u8; 32]; SeqRng(3).fill(&mut cx);
        let client_secret = x25519_dalek::StaticSecret::from(cx);
        let client_x_pub = x25519_dalek::PublicKey::from(&client_secret).to_bytes();

        let shape = shape_fixture(group); // cipher 0x1301, ordered exts incl. key_share(group)+GREASE
        let client_hello_msg = vec![0x01, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]; // any fixed bytes
        let sid = vec![0x11; 32];

        let mek = if group == 4588 { Some(client_ek_bytes.as_slice()) } else { None };
        let (sh_msg, server_keys) =
            emit_server_hello(&shape, &client_hello_msg, &sid, &client_x_pub, mek, &mut SeqRng(1)).unwrap();

        // CLIENT side (the round-trip proof): parse the emitted ServerHello,
        // run the client KEX (decapsulate/DH), combine, derive — must match.
        let shi = crate::handshake::parse_server_hello(&sh_msg[..]).unwrap(); // suite/group/server_key_share
        let ecdhe: Vec<u8> = if group == 4588 {
            let (ct, sx) = shi.server_key_share.split_at(1088);
            let mlkem_ss = client_dk.decapsulate(&ct.try_into().unwrap()).unwrap();
            let sxp: [u8;32] = sx.try_into().unwrap();
            let x_ss = client_secret.diffie_hellman(&x25519_dalek::PublicKey::from(sxp)).to_bytes();
            [&mlkem_ss[..], &x_ss[..]].concat()
        } else {
            let sxp: [u8;32] = shi.server_key_share.as_slice().try_into().unwrap();
            client_secret.diffie_hellman(&x25519_dalek::PublicKey::from(sxp)).to_bytes().to_vec()
        };
        let mut transcript = client_hello_msg.clone(); transcript.extend_from_slice(&sh_msg);
        let th = crate::handshake::transcript_hash(&transcript, shi.suite);
        let client_keys = crate::handshake::derive_handshake_keys(&ecdhe, &th, shi.suite);

        // Both sides derive the IDENTICAL handshake keys.
        assert_eq!(server_keys.server_key, client_keys.server_key);
        assert_eq!(server_keys.client_key, client_keys.client_key);
        assert_eq!(server_keys.server_iv, client_keys.server_iv);
        assert_eq!(server_keys.client_iv, client_keys.client_iv);
    }

    #[test]
    fn emit_server_hello_byte_matches_shape_except_substituted_fields() {
        // Re-parse the emitted ServerHello via parse_server_hello_shape; assert
        // cipher/compression/extension-order (incl. GREASE) equal the source
        // shape; the key_share ext body differs (relay's value) and the echoed
        // session_id equals the client's.
    }
```

(Match the exact `MlKemRng`/`RandomSource` names + the `parse_server_hello` return type from the crate.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p yip-utls server::tests::emit_server_hello`
Expected: FAIL — `cannot find function emit_server_hello`.

- [ ] **Step 3: Implement `emit_server_hello`**

```rust
use crate::template::ServerHelloShape;
use crate::handshake::{derive_handshake_keys, transcript_hash, HandshakeKeys};
use crate::wire::HelloWriter;

const EXT_KEY_SHARE: u16 = 0x0033;
const LEGACY_VERSION_TLS12: u16 = 0x0303;
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// Emit a byte-matching ServerHello from `shape` (dest's captured structure)
/// with the relay's own key_share + a fresh random + the client's session_id
/// echo, and derive the server-side handshake keys. Returns the ServerHello
/// handshake message + `HandshakeKeys` (server seals with `server_key`, opens
/// the client with `client_key`).
pub fn emit_server_hello(
    shape: &ServerHelloShape,
    client_hello_msg: &[u8],
    client_legacy_session_id: &[u8],
    client_x25519: &[u8; 32],
    client_mlkem_ek: Option<&[u8]>,
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, HandshakeKeys), Error> {
    let (server_ks, shared) =
        server_key_share(shape.key_share_group, client_x25519, client_mlkem_ek, rng)?;

    let mut body = HelloWriter::new();
    body.u16(LEGACY_VERSION_TLS12);
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    body.bytes(&random);
    // legacy_session_id_echo: echo the client's, per RFC 8446.
    let sid_len = u8::try_from(client_legacy_session_id.len())
        .map_err(|_| Error::Protocol("client legacy_session_id exceeds 255 bytes"))?;
    body.u8_prefixed(|w| w.bytes(client_legacy_session_id));
    let _ = sid_len; // (u8_prefixed writes the length; keep the bound check above)
    body.u16(shape.cipher_suite);
    // ServerHello has a single legacy_compression_method byte.
    body.bytes(&[shape.legacy_compression_method]);
    // Extensions, verbatim from the shape EXCEPT key_share (relay's value).
    body.u16_prefixed(|w| {
        for (id, ext_body) in &shape.extensions {
            w.u16(*id);
            if *id == EXT_KEY_SHARE {
                // ServerHello key_share ext body = group(2) ‖ u16 len ‖ key_share.
                w.u16_prefixed(|w| {
                    w.u16(shape.key_share_group);
                    w.u16_prefixed(|w| w.bytes(&server_ks));
                });
            } else {
                w.u16_prefixed(|w| w.bytes(ext_body));
            }
        }
    });
    let body = body.into_bytes();

    // Wrap as a handshake message: 0x02 ‖ u24 len ‖ body.
    let mut sh_msg = Vec::with_capacity(4 + body.len());
    sh_msg.push(HANDSHAKE_TYPE_SERVER_HELLO);
    let len = u32::try_from(body.len()).map_err(|_| Error::Protocol("ServerHello body exceeds u24"))?;
    sh_msg.extend_from_slice(&len.to_be_bytes()[1..]);
    sh_msg.extend_from_slice(&body);

    // Derive keys over transcript = ClientHello ‖ ServerHello.
    let mut transcript = Vec::with_capacity(client_hello_msg.len() + sh_msg.len());
    transcript.extend_from_slice(client_hello_msg);
    transcript.extend_from_slice(&sh_msg);
    let th = transcript_hash(&transcript, shape.cipher_suite);
    let keys = derive_handshake_keys(&shared, &th, shape.cipher_suite);
    Ok((sh_msg, keys))
}
```

IMPLEMENTER: verify the ServerHello key_share extension body layout against `parse_server_hello` (it reads `group ‖ len ‖ key_exchange` — mirror that exactly so the round-trip parse succeeds). Confirm `HelloWriter`'s `u8_prefixed`/`u16_prefixed`/`bytes`/`u16` signatures. The round-trip test failing means a layout mismatch — fix the emission, not the test.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p yip-utls server` → PASS (both round-trips + byte-match). Then `cargo test -p yip-utls` (JA4 diff + all REALITY.2/4b tests green — 5b is additive).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt -p yip-utls
git add crates/yip-utls/src/server.rs
git commit -m "feat(reality.5b): emit_server_hello — byte-matching ServerHello + server key schedule (round-trip proven)"
```

---

### Task 3: Extract the client's ML-KEM ek (`yip-rendezvous`)

The server needs the client's ML-KEM ek (for 4588 encapsulation) from the ClientHello. Add it to `ClientHelloInfo`.

**Files:**
- Modify: `bin/yip-rendezvous/src/reality.rs` (`ClientHelloInfo.key_share_mlkem_ek` + extraction in `parse_client_hello`)

**Interfaces:**
- Produces: `ClientHelloInfo.key_share_mlkem_ek: Option<Vec<u8>>` (the client's group-4588 encapsulation key, 1184 bytes).

- [ ] **Step 1: Write the failing parse test**

Add to `reality.rs` tests. Build a fixture ClientHello with a key_share extension containing a group-4588 entry (`mlkem_ek(1184) ‖ x25519(32)`) and assert extraction:

```rust
    #[test]
    fn parse_client_hello_extracts_mlkem_ek() {
        // Reuse the existing ClientHello test builder; add a 4588 key_share entry
        // of exactly 1184+32 bytes (mlkem_ek ‖ x25519).
        let mlkem_ek = vec![0xAB; 1184];
        let x25519 = [0xCD; 32];
        let ch = build_test_client_hello_with_4588_key_share(&mlkem_ek, &x25519);
        let info = parse_client_hello(&ch).expect("parse");
        assert_eq!(info.key_share_mlkem_ek.as_deref(), Some(&mlkem_ek[..]));
        assert_eq!(info.key_share_x25519, Some(x25519));
    }

    #[test]
    fn parse_client_hello_mlkem_ek_wrong_length_is_none() {
        // A 4588 entry that isn't 1184+32 bytes → key_share_mlkem_ek == None.
    }
```

Add/extend the ClientHello test builder to include a 4588 key_share entry. If the existing `reality.rs` tests already build ClientHellos, extend that helper.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yip-rendezvous-bin reality::tests::parse_client_hello_extracts_mlkem_ek`
Expected: FAIL — no field `key_share_mlkem_ek`.

- [ ] **Step 3: Implement the extraction**

Add `pub key_share_mlkem_ek: Option<Vec<u8>>` to `ClientHelloInfo`. In `parse_client_hello`, where the `key_share` extension's entries are walked (it already extracts `key_share_x25519` for group 0x001d), also handle group `4588` (`GROUP_X25519MLKEM768`): its `key_exchange` is `mlkem_ek(1184) ‖ x25519(32)`; if the entry length is exactly `1184 + 32`, set `key_share_mlkem_ek = Some(first 1184 bytes)` (and the x25519 could also be taken here, but keep the existing `key_share_x25519` logic for group 0x001d). Fail-closed: wrong length → leave `None` (no panic; bounded `.get()`). Initialize the new field to `None` at every `ClientHelloInfo { .. }` construction site.

- [ ] **Step 4: Run to verify it passes + full suite**

Run: `cargo test -p yip-rendezvous-bin reality` → PASS. Then full `cargo test -p yip-rendezvous-bin` (existing reality/auth tests green — the new field is additive; anti-replay/4b untouched).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings
cargo fmt
git add bin/yip-rendezvous/src/reality.rs
git commit -m "feat(reality.5b): extract client ML-KEM ek from ClientHello (for group-4588 server KEX)"
```

---

## Self-Review

**1. Spec coverage:**
- §1 server KEX (4588 ML-KEM Encapsulate + X25519, combiner reuse, unsupported→Err) → Task 1. ✓
- §2 emit_server_hello (verbatim shape + fresh random + client session_id echo + relay key_share; derive keys) + round-trip + byte-match → Task 2. ✓
- §3 ClientHelloInfo ML-KEM ek extraction → Task 3. ✓
- Testing (KEX shapes, round-trip both groups, byte-match, parse) → Tasks 1–3. ✓
- Scope 4588+29 only; P256/P384+HRR = #84 (Err for others) → Task 1. ✓
- Non-goals (5c encrypted flight, 5d wiring) — no task emits the flight or touches tls_front. ✓
- Reuse key schedule/combiner unchanged → Tasks 1–2 (derive_handshake_keys/transcript_hash reused; combiner replicated in the same order). ✓

**2. Placeholder scan:** Two IMPLEMENTER-confirm points — the ML-KEM `Encapsulate` RNG bridge (reuse `stream.rs`'s existing `MlKemRng` adapter) and the exact `ml-kem`/`HelloWriter` call shapes — are flagged with the concrete source to mirror (the client `decapsulate` side / `parse_server_hello`) and the gating test (the round-trip fails on any layout mismatch). No `unimplemented!`/TODO in shipped code.

**3. Type consistency:** `server_key_share(group, client_x25519, client_mlkem_ek, rng) -> Result<(Vec<u8>, Vec<u8>), Error>` (Task 1) is consumed by `emit_server_hello` (Task 2) with those exact params; `emit_server_hello`'s return `(Vec<u8>, HandshakeKeys)` and `ServerHelloShape`/`HandshakeKeys` fields (`server_key`/`client_key`/`server_iv`/`client_iv`/`suite`) match REALITY.2/5a. `key_share_mlkem_ek: Option<Vec<u8>>` (Task 3) is what 5d will feed to `emit_server_hello`'s `client_mlkem_ek`.

**Flags for the user at handoff:**
1. **The ML-KEM `Encapsulate` RNG bridge** — reuse `stream.rs`'s existing `RandomSource`→`RngCore` adapter; the round-trip test (client `decapsulate` must recover the same secret the server `encapsulate`d) is the correctness gate.
2. **The round-trip test replicates the client KEX inline** (rather than call `connect`, which does a full handshake) — a faithful stand-in for the client side; it proves both sides derive identical `HandshakeKeys`.
