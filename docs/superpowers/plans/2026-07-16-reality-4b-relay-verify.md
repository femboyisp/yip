# REALITY.4b — Client-Side Relay Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a yip client cryptographically verify it is talking to the genuine relay (holder of `relay_reality_priv`) via a `shared`-secret-derived ECDSA-P256 `CertificateVerify`, default-ON and fail-closed, without weakening the un-authed-prober camouflage.

**Architecture:** The relay proves possession of `relay_reality_priv` by signing the standard TLS 1.3 `CertificateVerify` with an ECDSA-P256 key deterministically derived from the seal's ECDH `shared` secret; the client (hand-rolled `yip_utls`) re-derives the same key, pins the leaf to it, and verifies the signature — fail-closed on every edge, with a browser-faithful alert + jittered give-up on failure. The server always binds (re-forges the leaf per-connection with the derived key); anti-replay from REALITY.3 keeps replays off the authed path.

**Tech Stack:** Rust; `p256` (new dep in `yip-utls` — ECDSA-P256 keygen/verify + PKCS8); `ring::hkdf` (existing); `rcgen`/`boring`/`tokio-boring` (server, existing); `yip_utls` hand-rolled TLS 1.3 (existing).

## Global Constraints

- `#![forbid(unsafe_code)]` everywhere except `yip-io`/`yip-device` — NO `unsafe`.
- NO `as` numeric casts — use `try_from`/`to_be_bytes`/`from_be_bytes`.
- NO bare `#[allow(...)]` — use `#[expect(reason = "...")]`.
- **Derived key = ECDSA-P256** (`ecdsa_secp256r1_sha256`, `0x0403` — Chrome-advertised; do NOT use Ed25519, which breaks the cleartext ClientHello fingerprint).
- **Derivation must be deterministic, uniform, constant-time, and client↔server-identical:** `HKDF-SHA256-Expand(ikm=shared, info="yip-reality-cert-v1", L=48)` → constant-time wide reduction to a P-256 scalar; degenerate-zero maps deterministically to `1`.
- **`verify` defaults ON**, is client-local, NEVER negotiated on the wire.
- Client verification is **fail-closed on every edge**; ECDSA scheme is **hard-pinned** `ecdsa_secp256r1_sha256` (ignore the cert-declared scheme).
- Anti-replay (REALITY.3 `ReplayGuard` + `ts_min` gate) stays in force — do NOT change it.
- Cert-flight **size**-padding is **out of scope** (deferred to REALITY.5 / #76). Do not add padding.
- `yip_utls` stays byte-faithful: the ClientHello (JA4 diff test) MUST stay green.
- Every task ends green: relevant `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt`.
- Stacked on REALITY.4a (merged). **Never merge the PR** — open it, leave it for the user.

**Spec:** `docs/superpowers/specs/2026-07-16-reality-4b-relay-verify-design.md`. Read it (esp. §1–§4 + Risks) before starting.

---

### Task 1: `derive_cert_key` — shared ECDSA-P256 derivation (`yip-utls::auth`)

The cryptographic core: both client and server derive the identical ECDSA-P256 keypair from `shared`. Pure, deterministic, heavily unit-tested. No networking.

**Files:**
- Modify: `crates/yip-utls/Cargo.toml` (add `p256`)
- Modify: `crates/yip-utls/src/auth.rs` (add `derive_cert_key` + `shared_secret` + expose `shared` from `open_recover`)

**Interfaces:**
- Produces:
  - `pub fn shared_secret(reality_pub: &[u8;32], eph_priv: &[u8;32]) -> [u8;32]` — the X25519 ECDH the seal already uses (client side).
  - `pub fn derive_cert_key(shared: &[u8;32]) -> DerivedCertKey` where `DerivedCertKey { pub pkcs8_der: Vec<u8>, pub public_sec1: Vec<u8> }` — `pkcs8_der` feeds `rcgen::KeyPair::from_der` (server); `public_sec1` is the SEC1-encoded P-256 public key the client pins (uncompressed, 65 bytes).
  - `pub fn open_recover_shared(reality_priv, eph_pub, client_random, session_id, short_ids, now_min, skew_min) -> Option<([u8;8], u64, [u8;32])>` — like `open_recover` but also returns the `shared` bytes (server side).

- [ ] **Step 1: Add `p256` to `crates/yip-utls/Cargo.toml`**

Under `[dependencies]`:

```toml
# REALITY.4b: ECDSA-P256 (ecdsa_secp256r1_sha256, the Chrome-advertised sig alg)
# for the shared-secret-derived cert key — client verify + server binding.
# `pkcs8` lets the server hand the derived key to rcgen; `ecdsa` for verify.
p256 = { version = "0.13", features = ["ecdsa", "pkcs8"] }
```

- [ ] **Step 2: Write the failing derivation tests**

Add to `crates/yip-utls/src/auth.rs` tests:

```rust
    #[test]
    fn derive_cert_key_is_deterministic_and_agrees() {
        let shared = [0x5a_u8; 32];
        let a = derive_cert_key(&shared);
        let b = derive_cert_key(&shared);
        assert_eq!(a.pkcs8_der, b.pkcs8_der, "deterministic pkcs8");
        assert_eq!(a.public_sec1, b.public_sec1, "deterministic pubkey");
        // The SEC1 public key is an uncompressed P-256 point: 0x04 ‖ X(32) ‖ Y(32).
        assert_eq!(a.public_sec1.len(), 65);
        assert_eq!(a.public_sec1[0], 0x04);
        // Different shared → different key.
        let c = derive_cert_key(&[0x5b; 32]);
        assert_ne!(a.public_sec1, c.public_sec1);
    }

    #[test]
    fn derived_pkcs8_and_pubkey_are_a_valid_p256_pair() {
        use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
        let d = derive_cert_key(&[7u8; 32]);
        // pkcs8 loads as a signing key; public_sec1 loads as its verifying key;
        // a signature by one verifies under the other → they are a real pair.
        let sk = SigningKey::from_pkcs8_der(&d.pkcs8_der).expect("pkcs8 loads");
        let vk = VerifyingKey::from_sec1_bytes(&d.public_sec1).expect("sec1 loads");
        assert_eq!(vk, *sk.verifying_key());
        let sig: Signature = sk.sign(b"reality-4b probe");
        assert!(vk.verify(b"reality-4b probe", &sig).is_ok());
    }
```

(Use whatever `pkcs8` import path `p256` exposes — `p256::pkcs8::DecodePrivateKey` / `SigningKey::from_pkcs8_der`. Adjust to the real API.)

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p yip-utls auth::tests::derive_cert_key auth::tests::derived_pkcs8`
Expected: FAIL — `cannot find function derive_cert_key`.

- [ ] **Step 4: Implement `shared_secret` + `derive_cert_key`**

```rust
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;

/// The X25519 ECDH shared secret the seal is keyed on (client side): the same
/// value the server recovers via `open_recover_shared`.
pub fn shared_secret(reality_pub: &[u8; 32], eph_priv: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*eph_priv);
    secret
        .diffie_hellman(&PublicKey::from(*reality_pub))
        .to_bytes()
}

/// The ECDSA-P256 keypair both sides derive from `shared` for REALITY.4b relay
/// verification. Deterministic, uniform, constant-time (RustCrypto p256).
pub struct DerivedCertKey {
    /// PKCS#8 DER of the private key — feeds `rcgen::KeyPair::from_der` (server).
    pub pkcs8_der: Vec<u8>,
    /// Uncompressed SEC1 public key (`0x04 ‖ X ‖ Y`, 65 bytes) — the client pins
    /// the presented leaf's key to this.
    pub public_sec1: Vec<u8>,
}

/// Derive the ECDSA-P256 keypair from `shared`:
/// `okm = HKDF-Expand(shared, "yip-reality-cert-v1", 48)`, wide-reduced mod n
/// to a scalar (RFC 9380 §5 style — 48 bytes gives < 2⁻¹²⁸ bias and both sides
/// land identically). The ~2⁻²⁵⁶ zero case maps to 1 (deterministic; never
/// diverges). Constant-time throughout (no data-dependent branch on the scalar).
pub fn derive_cert_key(shared: &[u8; 32]) -> DerivedCertKey {
    // HKDF-Expand 48 bytes with the cert-key domain-separation info string.
    let okm48 = hkdf_expand_48(shared, b"yip-reality-cert-v1");
    // Wide-reduce the 48 bytes to a P-256 scalar. IMPLEMENTER: use the exact
    // RustCrypto p256 wide-reduction API — e.g. build a `p256::Scalar` from the
    // 48-byte input via `Reduce<U384>` / `Scalar::reduce_bytes`, or
    // `elliptic_curve::bigint`. The scalar MUST be reduced mod n and non-zero
    // (map zero→1). Then `SigningKey::from(NonZeroScalar)`.
    let signing_key = signing_key_from_wide(&okm48); // see helper below
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .expect("a freshly-built P-256 signing key always encodes to PKCS#8")
        .as_bytes()
        .to_vec();
    let public_sec1 = signing_key
        .verifying_key()
        .to_encoded_point(false) // uncompressed
        .as_bytes()
        .to_vec();
    DerivedCertKey { pkcs8_der, public_sec1 }
}
```

Add the two helpers. `hkdf_expand_48` mirrors `derive_aead_key`'s `ring::hkdf` usage but with a 48-byte output type and the cert info string:

```rust
struct Okm48;
impl hkdf::KeyType for Okm48 {
    fn len(&self) -> usize { 48 }
}
fn hkdf_expand_48(shared: &[u8; 32], info: &[u8]) -> [u8; 48] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"").extract(shared);
    let okm = prk.expand(&[info], Okm48).expect("48 bytes within HKDF-SHA256 limit");
    let mut out = [0u8; 48];
    okm.fill(&mut out).expect("Okm48::len() == out.len()");
    out
}

/// Wide-reduce 48 bytes to a non-zero P-256 scalar and build a `SigningKey`.
/// IMPLEMENTER: verify the exact p256/elliptic-curve API. The intent:
/// interpret the 48 bytes big-endian, reduce mod the curve order n
/// (constant-time), map 0→1, and construct `SigningKey` from that scalar
/// (`SigningKey::from_bytes(&scalar.to_bytes())` or `from(NonZeroScalar)`).
fn signing_key_from_wide(wide: &[u8; 48]) -> SigningKey {
    // e.g. using p256::Scalar's Reduce impl (pseudocode — confirm the trait/path):
    //   let scalar = p256::Scalar::reduce_bytes_wide(wide);  // mod n, CT
    //   let nz = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar))
    //              .unwrap_or_else(|| NonZeroScalar::new(Scalar::ONE).unwrap());
    //   SigningKey::from(nz)
    unimplemented_wide_reduction(wide)
}
```

IMPLEMENTER NOTE: the `signing_key_from_wide` body is the one place you must confirm the real RustCrypto API (the crate exposes wide reduction via `elliptic_curve::scalar` / `Reduce`; if a direct 48-byte reduction isn't available, expand to 64 bytes and use `Reduce<U512>`, or reduce a `crypto_bigint::U384`). The `derive_cert_key_is_deterministic_and_agrees` + `derived_pkcs8_and_pubkey_are_a_valid_p256_pair` tests are the correctness gate — make them pass with a genuine mod-n reduction, do NOT stub. Replace the `unimplemented_wide_reduction` placeholder with the real reduction.

- [ ] **Step 5: Add `open_recover_shared` (expose `shared` server-side)**

Refactor `open_recover` to compute via a shared helper, and add:

```rust
/// Like `open_recover`, but also returns the X25519 `shared` bytes (for the
/// REALITY.4b server binding, which derives the cert key from it).
pub fn open_recover_shared(
    reality_priv: &[u8; 32],
    eph_pub: &[u8; 32],
    client_random: &[u8; 32],
    session_id: &[u8],
    short_ids: &[[u8; 8]],
    now_min: u64,
    skew_min: u64,
) -> Option<([u8; 8], u64, [u8; 32])> {
    let secret = StaticSecret::from(*reality_priv);
    let shared = secret.diffie_hellman(&PublicKey::from(*eph_pub)).to_bytes();
    // ... the existing open_recover body, keyed on `shared`, returning
    //     Some((short_id, ts_min, shared)) on success ...
}
```

Re-express `open_recover` as `open_recover_shared(...).map(|(s, t, _)| (s, t))` so behavior stays identical (existing tests green).

- [ ] **Step 6: Run tests, clippy, fmt, commit**

Run: `cargo test -p yip-utls auth` (new + existing seal/open tests green).
Run: `cargo clippy -p yip-utls --all-targets -- -D warnings` and `cargo fmt -p yip-utls`.

```bash
git add crates/yip-utls/Cargo.toml crates/yip-utls/src/auth.rs
git commit -m "feat(reality.4b): derive_cert_key (ECDSA-P256 from shared) + expose shared from open_recover"
```

---

### Task 2: Client `CertificateVerify` verification (`yip-utls::stream` + `error`)

`connect` gains `verify: bool`; when on, pin the leaf key to the derived pubkey and verify the `CertificateVerify` signature — fail-closed, hard-pinned, with a browser alert on failure. The crux client task.

**Files:**
- Modify: `crates/yip-utls/src/error.rs` (add `RealityVerify`)
- Modify: `crates/yip-utls/src/stream.rs` (`connect(verify)`, capture leaf + verify CertVerify, browser alert)
- Test: `crates/yip-utls/src/stream.rs` unit tests + a transcript KAT

**Interfaces:**
- Consumes: `auth::derive_cert_key`, `auth::shared_secret` (Task 1); `handshake::transcript_hash`; the existing server-flight read loop.
- Produces: `connect<S>(stream, sni, server_reality_pub, short_id, verify: bool) -> Result<RealityStream<S>, Error>` (new `verify` param); `Error::RealityVerify(&'static str)`.

- [ ] **Step 1: Add the error variant**

In `crates/yip-utls/src/error.rs`, add to `enum Error`:

```rust
    /// REALITY.4b relay verification failed (leaf key mismatch, bad
    /// CertificateVerify, wrong scheme, or a missing/malformed message). The
    /// caller must treat the relay as unauthenticated and NOT tunnel.
    RealityVerify(&'static str),
```

Add its `Display` arm (`Error::RealityVerify(m) => write!(f, "REALITY relay verification failed: {m}")`) and `None` in `source()` (like `Protocol`).

- [ ] **Step 2: Write the failing verify tests**

REALITY.2 has an in-process mock-TLS-server test harness in `stream.rs` (find the test that drives `connect` against a local mock server — around the `ch_sh_transcript` test / the coverage-task mock server). Extend it so the mock server can bind the REALITY.4b cert: it derives `auth::derive_cert_key(shared)`, presents a leaf whose key is that P-256 key, and signs `CertificateVerify` with it (ecdsa_secp256r1_sha256). Then:

```rust
    // verify=true against a correctly-binding mock server → connect succeeds.
    #[tokio::test]
    async fn connect_verify_accepts_correct_binder() { /* drive mock binder, connect(verify=true) → Ok */ }

    // verify=true against a server presenting a WRONG leaf key → RealityVerify.
    #[tokio::test]
    async fn connect_verify_rejects_wrong_key() { /* mock presents a random P-256 key → Err(RealityVerify) */ }

    // verify=true with a CertificateVerify signed by the wrong key → RealityVerify.
    #[tokio::test]
    async fn connect_verify_rejects_bad_signature() { /* right leaf key, sig by another key → Err(RealityVerify) */ }

    // verify=false against the same wrong-key server → still Ok (zero-cert-auth).
    #[tokio::test]
    async fn connect_no_verify_ignores_cert() { /* wrong key, verify=false → Ok */ }
```

Because standing up a full binding mock server is involved, ALSO add a pure **KAT** that exercises the verification predicate directly against a recorded-or-locally-generated (transcript, leaf-pubkey, CertVerify-signature) triple:

```rust
    // KAT: reconstruct the RFC 8446 §4.4.3 signed content and verify a known-good
    // ECDSA-P256 CertificateVerify by the derived key; a one-byte transcript
    // perturbation must flip it to reject (guards the §4.4.3 boundary).
    #[test]
    fn certverify_predicate_kat() { /* build with p256 signer, verify_certificate_verify(...) == Ok; perturb → Err */ }
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p yip-utls stream::tests::connect_verify stream::tests::certverify_predicate`
Expected: FAIL — `connect` takes 4 args / `verify_certificate_verify` missing.

- [ ] **Step 4: Implement the verification predicate + wire it into `connect`**

Add a pure helper (unit-testable) in `stream.rs`:

```rust
/// Verify a TLS 1.3 server `CertificateVerify` for REALITY.4b: the leaf's key
/// must be exactly `expected_pubkey_sec1` (the derived P-256 key), and the
/// signature must verify over the RFC 8446 §4.4.3 signed content with
/// `ecdsa_secp256r1_sha256` HARD-PINNED (the announced scheme is ignored).
/// Fail-closed on every edge.
fn verify_certificate_verify(
    expected_pubkey_sec1: &[u8],
    leaf_spki_pubkey_sec1: &[u8],   // extracted from the server's Certificate leaf
    transcript_hash_through_cert: &[u8], // Transcript-Hash(ClientHello…Certificate)
    signature_der: &[u8],           // the CertificateVerify signature bytes
) -> Result<(), Error> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    // 1. Pin the leaf key to the derived key (constant-time compare of the SEC1 bytes).
    if leaf_spki_pubkey_sec1 != expected_pubkey_sec1 {
        return Err(Error::RealityVerify("leaf key does not match the derived REALITY key"));
    }
    // 2. Reconstruct the §4.4.3 signed content: 0x20*64 ‖ context ‖ 0x00 ‖ hash.
    let mut signed = Vec::with_capacity(64 + 34 + 1 + transcript_hash_through_cert.len());
    signed.extend_from_slice(&[0x20u8; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0x00);
    signed.extend_from_slice(transcript_hash_through_cert);
    // 3. Verify with ecdsa_secp256r1_sha256 hard-pinned (Verifier hashes SHA-256).
    let vk = VerifyingKey::from_sec1_bytes(expected_pubkey_sec1)
        .map_err(|_| Error::RealityVerify("derived key is not a valid P-256 point"))?;
    let sig = Signature::from_der(signature_der)
        .map_err(|_| Error::RealityVerify("CertificateVerify signature is not valid DER ECDSA"))?;
    vk.verify(&signed, &sig)
        .map_err(|_| Error::RealityVerify("CertificateVerify signature does not verify"))
}
```

In `connect`, thread the new `verify: bool` param and, when true, during the server-flight read loop (`stream.rs` ~line 381–422): capture the **Certificate** message's leaf and its SPKI P-256 point (bounded parse — fail-closed, no panic; reuse the crate's `Reader` discipline), and compute `Transcript-Hash(ClientHello…Certificate)` (the running transcript up to but NOT including CertificateVerify — you already accumulate the flight; take the hash at the point just before the CertificateVerify message). When the **CertificateVerify** message arrives, extract its signature and call `verify_certificate_verify(&auth::derive_cert_key(&shared).public_sec1, leaf_pubkey, &transcript_thru_cert, &sig)?`. `shared` is `auth::shared_secret(server_reality_pub, &eph_priv)` (already available — the seal uses it). On any `Err(Error::RealityVerify(_))`, send a browser-faithful TLS alert (Step 5) and return the error. When `verify=false`, skip all of this (today's behavior).

Fail-closed specifics (each → `Err(Error::RealityVerify(...))`, never accept): missing Certificate or CertificateVerify message; leaf key not a P-256 point / wrong type; unparseable cert; empty/oversized fields. Bound every length.

- [ ] **Step 5: Browser-faithful alert on verification failure**

When verification fails, before returning, write a TLS `alert` record matching what a mainstream browser sends on a certificate failure. IMPLEMENTER: capture the exact alert a real browser emits on a TLS 1.3 cert failure and pin it; the candidate is `bad_certificate` (level `fatal`(2), description `42`) as an encrypted alert (record type 21, encrypted under the handshake/app keys as appropriate at this point in the handshake). Add a `send_alert(&mut stream, desc)` helper that seals the 2-byte alert (`[level, desc]`) as an alert record and writes it, then the connection closes. Document the pinned value + how it was captured. (If capturing proves infeasible in-env, pin `bad_certificate(42)` and leave a note that REALITY.5's fidelity pass should re-verify it.)

- [ ] **Step 6: Run tests, clippy, fmt, confirm JA4 diff still green, commit**

Run: `cargo test -p yip-utls` (new verify tests + the KAT + all existing incl. the JA4 diff test — verify=off path must be byte-unchanged so JA4/JA3 diff stays green).
Run: `cargo clippy -p yip-utls --all-targets -- -D warnings` and `cargo fmt -p yip-utls`.

```bash
git add crates/yip-utls/src/error.rs crates/yip-utls/src/stream.rs
git commit -m "feat(reality.4b): client CertificateVerify verification (hard-pinned ECDSA-P256, fail-closed) + browser alert"
```

---

### Task 3: Server per-connection binding (`yip-rendezvous`)

The relay always binds on authed connections: expose `shared`, re-forge the leaf per-connection with the derived key, terminate TLS with it. Anti-replay unchanged.

**Files:**
- Modify: `bin/yip-rendezvous/src/reality.rs` (add `reality_auth_recover_shared` returning `shared`)
- Modify: `bin/yip-rendezvous/src/reality_cert.rs` (`RealityCertCache::fields_for` exposing cached `StolenFields`; `build_forged_acceptor_with_pkcs8(fields, pkcs8_der)`)
- Modify: `bin/yip-rendezvous/src/tls_front.rs` (`run_reality_conn`: derive key from `shared`, re-forge per-connection, accept with it)

**Interfaces:**
- Consumes: `yip_utls::auth::open_recover_shared`, `yip_utls::auth::derive_cert_key` (Task 1).
- Produces: `reality::reality_auth_recover_shared(...) -> Option<(u64, [u8;32])>` (ts_min + shared); `RealityCertCache::fields_for(sni) -> Option<Arc<StolenFields>>`; `build_forged_acceptor_with_pkcs8(fields, pkcs8_der) -> Result<SslAcceptor, String>`.

- [ ] **Step 1: Expose `shared` from the auth check (`reality.rs`)**

Add alongside `reality_auth_recover`:

```rust
/// Like `reality_auth_recover` but also returns the X25519 `shared` bytes, for
/// the REALITY.4b per-connection cert binding.
pub fn reality_auth_recover_shared(
    reality_priv: &[u8; 32],
    info: &ClientHelloInfo,
    short_ids: &[[u8; 8]],
    now_unix_min: u64,
    skew_min: u64,
) -> Option<(u64, [u8; 32])> {
    let eph_pub = info.key_share_x25519?;
    yip_utls::auth::open_recover_shared(
        reality_priv, &eph_pub, &info.client_random, &info.legacy_session_id,
        short_ids, now_unix_min, skew_min,
    )
    .map(|(_short_id, ts_min, shared)| (ts_min, shared))
}
```

Test: on a valid seal, `reality_auth_recover_shared` returns the same `ts_min` as `reality_auth_recover` plus a 32-byte `shared` equal to `X25519(reality_priv, eph_pub)`.

- [ ] **Step 2: Cache `StolenFields` + a keyed acceptor builder (`reality_cert.rs`)**

`RealityCertCache` currently caches `Arc<SslAcceptor>` per SNI. Add the cached `StolenFields` so per-connection re-forging needs no `dest` re-fetch. Change `CacheEntry` to also hold `fields: Arc<StolenFields>` (derive `StolenFields: Clone` or wrap in `Arc` at insert), add:

```rust
/// The cached StolenFields for `sni` (REALITY.4b per-connection re-forge).
pub fn fields_for(&self, sni: &str) -> Option<Arc<StolenFields>> {
    let g = self.entries.read().expect("cert cache lock poisoned");
    g.get(sni).map(|e| Arc::clone(&e.fields))
}
```

And a keyed acceptor builder that forges the leaf with an externally-supplied key (the derived PKCS8):

```rust
/// Build a TLS-1.3-only acceptor whose forged leaf is signed by `pkcs8_der`
/// (the REALITY.4b shared-secret-derived ECDSA-P256 key), rather than the
/// cache's fixed ephemeral key. Same field-copying as `build_forged_acceptor`.
pub fn build_forged_acceptor_with_pkcs8(
    fields: &StolenFields,
    pkcs8_der: &[u8],
) -> Result<SslAcceptor, String> {
    let key = rcgen::KeyPair::from_der(pkcs8_der).map_err(|e| format!("derived key: {e}"))?;
    // ... identical to build_forged_acceptor's body but using `key` ...
}
```

(Refactor `build_forged_acceptor` to delegate to this with the cache's fixed key, to stay DRY.) IMPLEMENTER: confirm `rcgen::KeyPair::from_der` accepts p256 PKCS8 (rcgen supports ECDSA-P256 keys); if the exact constructor differs (`from_pkcs8_der` / `from_der`), use the real one. Test: `build_forged_acceptor_with_pkcs8` with a `derive_cert_key(shared).pkcs8_der` yields an acceptor whose leaf public key equals `derive_cert_key(shared).public_sec1`.

- [ ] **Step 3: Re-forge per-connection in `run_reality_conn` (`tls_front.rs`)**

In `run_reality_conn`, the authed branch currently uses `certs.acceptor_for(sni)`. For REALITY.4b, when authed: call `reality::reality_auth_recover_shared(...)` to get `(ts_min, shared)`; after the replay-guard `Decision::Accept`, fetch `certs.fields_for(sni)`, derive `let dk = yip_utls::auth::derive_cert_key(&shared);`, build a **per-connection** acceptor `build_forged_acceptor_with_pkcs8(&fields, &dk.pkcs8_der)`, and `tokio_boring::accept` with it (instead of the cached fixed-key acceptor). Everything else (anti-replay, splice-on-unknown-SNI, the auth decision) is unchanged. The server ALWAYS binds (no `verify` flag server-side). If `fields_for` returns `None` (SNI not warmed), splice (as today).

Test (integration-lite, in `tls_front.rs`): an authed connection is terminated with a per-connection acceptor whose leaf key equals `derive_cert_key(shared).public_sec1` for that connection's `shared`. (Mirror the existing `decide_authed` / reality front tests; assert the presented leaf key matches the derived key.)

- [ ] **Step 4: Run tests, clippy, fmt, commit**

Run: `cargo test -p yip-rendezvous-bin` (new + existing reality tests green; anti-replay untouched).
Run: `cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings` and `cargo fmt`.

```bash
git add bin/yip-rendezvous/src/reality.rs bin/yip-rendezvous/src/reality_cert.rs bin/yip-rendezvous/src/tls_front.rs
git commit -m "feat(reality.4b): server per-connection cert binding (derive key from shared, re-forge leaf)"
```

---

### Task 4: Client config + fallback (`yipd`)

`verify=on|off` on `reality://` (default ON), thread it to `connect`, and jittered give-up on `RealityVerify`.

**Files:**
- Modify: `bin/yipd/src/config.rs` (`Rendezvous::Reality` gains `verify: bool`; parse `verify=on|off`)
- Modify: `bin/yipd/src/relay_client.rs` (`spawn_reality`/`run_reality` thread `verify`; jittered backoff on `RealityVerify`)
- Modify: `bin/yipd/src/tunnel.rs` (pass `verify` through the `Reality` arm)

**Interfaces:**
- Consumes: `yip_utls::connect(..., verify)` (Task 2); `Rendezvous::Reality { .., verify }`.

- [ ] **Step 1: Parse `verify=on|off` (`config.rs`)**

REALITY.4a's `parse_reality_rendezvous` currently REJECTS `verify=` as 4b-only. Replace that rejection with real parsing: add `verify: bool` to `Rendezvous::Reality`, default `true` when absent, accept `verify=on`/`verify=true`→true and `verify=off`/`verify=false`→false, error on any other value. Emit a **warn** (eprintln) at config load when `verify=off` is set (the downgrade caveat). Update the 4a tests that asserted `verify=` is rejected (they now assert it parses); add tests: `verify=off` → `verify: false` + warning path; absent → `verify: true`; `verify=bogus` → error.

```rust
"verify" => {
    verify = Some(match value {
        "on" | "true" => true,
        "off" | "false" => false,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData,
            "reality:// verify must be on|off")),
    });
}
```

and after the loop `let verify = verify.unwrap_or(true);` → `Rendezvous::Reality { .., verify }`. Warn on `!verify`.

- [ ] **Step 2: Thread `verify` to `connect` + jittered backoff (`relay_client.rs`, `tunnel.rs`)**

`tunnel.rs`'s `Reality` arm destructures `verify` and passes it to `spawn_reality`; `spawn_reality`/`run_reality` carry `verify: bool` and call `yip_utls::connect(tcp, sni, pubkey, short_id, verify)`. On `Err(e)` from connect, distinguish `RealityVerify`: for it, apply a **jittered** long backoff (not the fixed `INITIAL/MAX_BACKOFF_MS` ladder) — e.g. a base of several minutes ± a random jitter — or stop dialing that relay, and log "relay verification failed — not the genuine REALITY relay". IMPLEMENTER: derive the jitter without `Math.random`-style nondeterminism concerns — use `getrandom` for the jitter (yipd already depends on it). Other errors keep the existing backoff. Add a unit test that a `RealityVerify` outcome selects the jittered/long path (factor the backoff-selection into a pure `fn backoff_for(err) -> Duration`-style helper and test it).

- [ ] **Step 3: Run, clippy, fmt, commit**

Run: `cargo test -p yipd` (config verify tests + relay_client backoff test + existing green).
Run: `cargo clippy -p yipd --all-targets -- -D warnings` and `cargo fmt`.

```bash
git add bin/yipd/src/config.rs bin/yipd/src/relay_client.rs bin/yipd/src/tunnel.rs
git commit -m "feat(reality.4b): verify=on|off config (default ON) + jittered give-up on verify failure"
```

---

### Task 5: netns end-to-end + docs

Prove verify=on tunnels through a real relay, and a wrong key fails closed with no tunnel/no storm. Document.

**Files:**
- Modify: `bin/yipd/tests/run-netns-reality-relay.sh` (add verify=on money test + wrong-key negative)
- Modify: `bin/yipd/example.config`, `docs/configuration.md`

- [ ] **Step 1: Extend the netns harness**

Extend REALITY.4a's `run-netns-reality-relay.sh` (root/netns). Add: (a) a **verify=on money test** — two UDP-blocked peers tunnel through the real REALITY relay with `reality://…&verify=on` (relay binds the derived cert; client verifies; ping succeeds; relay-forwarded > 0). (b) a **wrong-relay-key negative** — the relay runs with a DIFFERENT `--reality-private-key` than the client's `pbk` while the client uses `verify=on`: the seal-open fails server-side → spliced to dest → the client's verify never even runs (no authed cert) → **no tunnel**; assert the ping fails within a bounded timeout and the client does NOT retry-storm (bounded connection attempts). Reuse the pinned keypair helper from 4a; derive a second mismatched key. Wire into CI next to the 4a step.

- [ ] **Step 2: Run it (root/netns; else note CI-gated)**

Run: `sudo bash bin/yipd/tests/run-netns-reality-relay.sh <yipd> <yip-rendezvous>` (after `cargo build --release -p yipd -p yip-rendezvous-bin`).
Expected: verify=on money test passes; wrong-key negative fails-closed. If netns/root unavailable, note it's CI-gated.

- [ ] **Step 3: Docs**

`docs/configuration.md`: document `verify=on|off` (default ON, client-local, browser-fallback + jittered give-up, the `verify=off` downgrade caveat, and that cert-flight size fidelity is REALITY.5). `example.config`: uncomment `verify` on the `reality://` example with a one-line note. Note SCT/size limits as already documented.

- [ ] **Step 4: Full suite, clippy, fmt, commit**

Run: `cargo test -p yip-utls -p yip-rendezvous-bin -p yipd` and `cargo clippy --workspace --all-targets -- -D warnings`.

```bash
git add bin/yipd/tests/run-netns-reality-relay.sh bin/yipd/example.config docs/configuration.md .github/workflows/
git commit -m "feat(reality.4b): netns verify=on money + wrong-key fail-closed tests + docs"
```

---

## Self-Review

**1. Spec coverage:**
- §1 derived key (ECDSA-P256, 48-byte constant-time wide reduction, both-sides-identical) → Task 1. ✓
- §2 server always-binds per-connection re-forge + expose `shared` + StolenFields cache → Task 3. ✓ Anti-replay unchanged (explicit). ✓
- §3 client hard-pinned fail-closed verify + KAT → Task 2. ✓
- §4 config `verify=on|off` default ON + warn + browser alert + jittered fallback → Tasks 2 (alert) + 4 (config/backoff). ✓
- Testing (derivation agree, verify pass/fail edges, KAT, netns money + wrong-key) → Tasks 1,2,5. ✓
- Docs → Task 5. ✓
- Deferred: cert-flight size-padding (REALITY.5) — NOT in any task, by design. ✓

**2. Placeholder scan:** Two intentional IMPLEMENTER-confirm points — `signing_key_from_wide` (the exact p256 wide-reduction API) and the pinned browser alert value — are flagged with the concrete approach + the test that gates them, NOT left vague. The `unimplemented_wide_reduction`/`unimplemented!` marker in Task 1 Step 4 is explicitly called out as "replace with the real reduction; the tests are the gate," not shipped. No other placeholders.

**3. Type consistency:** `DerivedCertKey { pkcs8_der, public_sec1 }`, `shared_secret`, `derive_cert_key`, `open_recover_shared` (Task 1) are consumed with those exact names/shapes in `verify_certificate_verify`/`connect` (Task 2), `reality_auth_recover_shared`/`fields_for`/`build_forged_acceptor_with_pkcs8` (Task 3), and `Rendezvous::Reality { .., verify }` (Task 4). `connect`'s new 5th param `verify: bool` is threaded Task 2 → Task 4.

**Flags for the user at handoff:**
1. **`signing_key_from_wide`** — the one crypto-API spot the implementer confirms against real `p256`/`elliptic-curve`; the deterministic-agreement + valid-pair tests are the correctness gate.
2. **The browser alert value** — pinned capture-driven (candidate `bad_certificate(42)`); REALITY.5's fidelity pass should re-verify.
3. **`rcgen::KeyPair::from_der` with p256 PKCS8** — confirm the exact constructor accepts the derived ECDSA-P256 key.
