# REALITY.5c — encrypted server-flight emission + server-side stream — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hand-roll the relay's encrypted TLS 1.3 server flight (EncryptedExtensions / Certificate / CertificateVerify / Finished) sealed under the 5b handshake keys and framed to byte-match `dest`'s captured record lengths, plus the server-side data-phase stream — completing the server handshake so the authed REALITY path no longer needs BoringSSL.

**Architecture:** Six additive changes to `yip-utls`: expose `server_hs_traffic`; a padding-aware `record_seal_padded`; a `sign_certificate_verify` (the signing mirror of 4b's verifier); `emit_server_flight` (assemble + seal + greedy-frame to `record_lengths`); a role-agnostic `RealityStream` rename (egress/ingress) with a server constructor; and a `serve` entry point proven by driving the existing `connect_verify_*` round-trip suite through the new production code.

**Tech Stack:** Rust, `yip-utls` crate (`forbid-unsafe`), `ring` (AEAD/HKDF/HMAC), `p256` (ECDSA-P256), `tokio` (async test I/O), `rcgen` (test-only leaf building).

## Global Constraints

- `#![forbid(unsafe_code)]` — NO `unsafe`, NO `as` casts, NO bare `#[allow]` (use `#[expect(reason = "...")]`).
- Reuse REALITY.2's `record_seal` / `finished_verify_data` / `derive_application_keys` and 4b's §4.4.3 signed-content construction **unchanged**.
- Fidelity strategy (user-approved): match `EncryptedFlightShape::record_lengths` **exactly**; EE/CertVerify/Finished are natural-sized, the difference absorbed by TLS 1.3 record padding; over-capacity/malformed template → `Err` (fail-safe, 5d splices). `17` = 1 inner content-type + 16-byte AEAD tag (all three TLS 1.3 suites).
- 5c seals the **entire** flight under the 5b **handshake** keys (`HandshakeKeys::server_key`/`server_iv`) — `record_lengths` covers only the handshake-key `{EE, Cert, CertVerify, Finished}` records; no app-key sealing for the flight, no NewSessionTicket.
- Scope: `yip-utls` only. NO `yip-rendezvous` wiring, NO rcgen leaf forging in production code, NO epoll pump — all 5d. NO post-`Finished` NST. NO P256/P384+HRR (#84).
- Every task: `cargo test -p yip-utls` green, `cargo clippy -p yip-utls --all-targets -- -D warnings` clean, `cargo fmt`.
- Branch is stacked on 5b (PR #85). Leave the PR for the user; do NOT merge; no "not merging" line in the PR body.
- **Known pre-existing flake (NOT yours):** the workspace pre-commit hook runs the whole suite, which currently fails only on two `yip-io::uring::tests::uring_*` loopback tests (237 < 256 datagrams under load, unrelated crate, confirmed on clean base). If the commit is blocked *solely* by those, commit with `--no-verify` and say so. Any `yip-utls` failure is yours.

---

### Task 1: Expose `server_hs_traffic` on `HandshakeKeys`

The server `Finished`'s `verify_data` needs the server handshake-traffic secret as its base. `derive_handshake_keys` already computes it (`s_hs`) but discards it. Expose it. Purely additive — 5b `emit_server_hello` and client `connect` don't read it.

**Files:**
- Modify: `crates/yip-utls/src/handshake.rs` (`HandshakeKeys` struct ~487-494; `derive_handshake_keys` return ~551-559)

**Interfaces:**
- Produces: `HandshakeKeys { ..., pub server_hs_traffic: Vec<u8> }` — the server handshake-traffic secret (32 bytes for SHA-256 suites, 48 for SHA-384), sibling of the existing `client_hs_traffic`.

- [ ] **Step 1: Write the failing test**

Add to `handshake.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn handshake_keys_expose_distinct_server_hs_traffic() {
    let ecdhe = [7u8; 32];
    let transcript = transcript_hash(b"client-hello||server-hello", SUITE_AES_128_GCM_SHA256);
    let hk = derive_handshake_keys(&ecdhe, &transcript, SUITE_AES_128_GCM_SHA256);
    assert!(!hk.server_hs_traffic.is_empty(), "server_hs_traffic must be populated");
    assert_eq!(hk.server_hs_traffic.len(), hk.client_hs_traffic.len());
    assert_ne!(
        hk.server_hs_traffic, hk.client_hs_traffic,
        "server and client handshake-traffic secrets must differ"
    );
}
```

(`SUITE_AES_128_GCM_SHA256` is already a const in this module — the existing `record_seal_then_open_round_trips_all_suites` test uses it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-utls --lib handshake::tests::handshake_keys_expose_distinct_server_hs_traffic`
Expected: FAIL — no field `server_hs_traffic` on `HandshakeKeys`.

- [ ] **Step 3: Add the field + populate it**

In the `HandshakeKeys` struct, after `pub client_hs_traffic: Vec<u8>,` add:

```rust
    /// The server handshake-traffic secret (`s hs traffic`) — the base secret
    /// for the SERVER `Finished`'s `verify_data` (REALITY.5c). Sibling of
    /// `client_hs_traffic`; both are 32 bytes (SHA-256) or 48 (SHA-384).
    pub server_hs_traffic: Vec<u8>,
```

Update the doc comment above the struct to mention it alongside `client_hs_traffic` if it enumerates fields. In `derive_handshake_keys`'s returned struct literal, after `client_hs_traffic: c_hs,` add `server_hs_traffic: s_hs,` (the `s_hs` local already exists and is only borrowed — `&s_hs` — when deriving `server_key`/`server_iv`, so it is free to move into the struct at the return).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-utls --lib handshake::` then `cargo test -p yip-utls`
Expected: PASS (all existing handshake/stream/server tests still green — the field is additive).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt
git add crates/yip-utls/src/handshake.rs
git commit -m "feat(reality.5c): expose server_hs_traffic on HandshakeKeys (server Finished base secret)"
```

---

### Task 2: `record_seal_padded` — padding-aware record seal

The shipped `record_seal` builds `inner = plaintext ‖ content_type` (no padding). 5c needs to append TLS 1.3 record padding to hit `dest`'s exact record lengths. Add a padding-aware sibling and make `record_seal` delegate to it, so the existing `record_seal` KATs cover the `pad_len = 0` path.

**Files:**
- Modify: `crates/yip-utls/src/handshake.rs` (`record_seal` ~674-711)

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub fn record_seal_padded(key: &[u8], iv: &[u8; 12], seq: u64, suite: u16, content_type: u8, content: &[u8], pad_len: usize) -> Result<Vec<u8>, Error>` — inner = `content ‖ content_type ‖ 0×pad_len`, sealed; the returned ciphertext-payload length is exactly `content.len() + 1 + pad_len + 16`.

- [ ] **Step 1: Write the failing tests**

Add to `handshake.rs`'s `mod tests`:

```rust
#[test]
fn record_seal_padded_opens_to_content_with_padding_stripped() {
    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];
    let content = b"encrypted-extensions-bytes";
    let pad_len = 40usize;
    let sealed = record_seal_padded(
        &key, &iv, 0, SUITE_AES_128_GCM_SHA256, 0x16, content, pad_len,
    )
    .unwrap();
    // Ciphertext-payload length is content ‖ content_type(1) ‖ pad ‖ tag(16).
    assert_eq!(sealed.len(), content.len() + 1 + pad_len + 16);
    // record_open strips the padding + content-type and recovers the content.
    let mut payload = sealed.clone();
    let opened = record_open(&key, &iv, 0, SUITE_AES_128_GCM_SHA256, 0x17, &mut payload).unwrap();
    assert_eq!(opened, content);
}

#[test]
fn record_seal_padded_zero_equals_record_seal() {
    let key = [0x01u8; 16];
    let iv = [0x02u8; 12];
    let content = b"finished-msg";
    let via_padded =
        record_seal_padded(&key, &iv, 5, SUITE_AES_128_GCM_SHA256, 0x16, content, 0).unwrap();
    let via_plain = record_seal(&key, &iv, 5, SUITE_AES_128_GCM_SHA256, 0x16, content).unwrap();
    assert_eq!(via_padded, via_plain);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-utls --lib handshake::tests::record_seal_padded`
Expected: FAIL — `record_seal_padded` not found.

- [ ] **Step 3: Implement `record_seal_padded` + delegate `record_seal`**

Replace the body of `record_seal` and add the padded variant. The only change vs the current `record_seal` is that `inner` gains `pad_len` trailing zero bytes AFTER the content-type, and the length math follows:

```rust
/// Like [`record_seal`], but appends `pad_len` zero bytes of TLS 1.3 record
/// padding after the inner content-type (RFC 8446 §5.4), so the sealed
/// record's ciphertext-payload length is exactly
/// `content.len() + 1 + pad_len + tag_len`. Used by REALITY.5c to frame the
/// server flight to `dest`'s captured per-record lengths.
pub fn record_seal_padded(
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    suite: u16,
    content_type: u8,
    content: &[u8],
    pad_len: usize,
) -> Result<Vec<u8>, Error> {
    let alg = algorithm_for_suite(suite)?;
    let unbound = UnboundKey::new(alg, key).map_err(|_| Error::Crypto)?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce = make_nonce(iv, seq);

    let mut inner = Vec::with_capacity(content.len() + 1 + pad_len);
    inner.extend_from_slice(content);
    inner.push(content_type);
    inner.resize(inner.len() + pad_len, 0u8);

    let total_len = inner.len() + alg.tag_len();
    let len_bytes = u16::try_from(total_len)
        .map_err(|_| Error::RecordTooLarge)?
        .to_be_bytes();
    let aad_bytes = [
        CONTENT_TYPE_APPLICATION_DATA,
        0x03,
        0x03,
        len_bytes[0],
        len_bytes[1],
    ];

    less_safe
        .seal_in_place_append_tag(nonce, Aad::from(aad_bytes), &mut inner)
        .map_err(|_| Error::Crypto)?;

    Ok(inner)
}

/// Seals a TLS 1.3 protected record with no record padding. Thin wrapper over
/// [`record_seal_padded`] with `pad_len = 0`.
pub fn record_seal(
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    suite: u16,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    record_seal_padded(key, iv, seq, suite, content_type, plaintext, 0)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-utls --lib handshake::` then `cargo test -p yip-utls`
Expected: PASS — the new KATs plus every existing `record_seal`/`record_open`/round-trip test (the delegation is behavior-preserving for `pad_len = 0`).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt
git add crates/yip-utls/src/handshake.rs
git commit -m "feat(reality.5c): record_seal_padded (TLS record padding); record_seal delegates"
```

---

### Task 3: `sign_certificate_verify` — the signing mirror of 4b's verifier

Sign the server `CertificateVerify` (RFC 8446 §4.4.3) with the derived ECDSA-P256 key, over the exact signed content the shipped `verify_certificate_verify` reconstructs. This carries the 4b binding. Co-locate it with `verify_certificate_verify` in `stream.rs` so the KAT can call that private verifier.

**Files:**
- Modify: `crates/yip-utls/src/stream.rs` (add `sign_certificate_verify` next to `verify_certificate_verify` ~607; add tests in `mod tests`)

**Interfaces:**
- Consumes: the shipped private `fn verify_certificate_verify(expected_pubkey_sec1, leaf_spki_pubkey_sec1, transcript_hash_through_cert, signature_der) -> Result<(), Error>` (for the KAT only).
- Produces: `pub fn sign_certificate_verify(signing_key: &p256::ecdsa::SigningKey, transcript_hash_through_certificate: &[u8]) -> Result<Vec<u8>, Error>` — returns the DER ECDSA signature. NO `suite` arg (p256 signs SHA-256 internally; 4b hard-pins the scheme).

- [ ] **Step 1: Write the failing tests**

Add to `stream.rs`'s `mod tests`:

```rust
#[test]
fn sign_certificate_verify_is_accepted_by_the_verifier() {
    use p256::ecdsa::SigningKey;
    let signing_key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let pubkey_sec1 = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let transcript = transcript_hash(b"ch||sh||ee||cert", SUITE_AES_128_GCM_SHA256);

    let sig = sign_certificate_verify(&signing_key, &transcript).unwrap();

    // The shipped verifier accepts it for the same transcript + pinned key.
    verify_certificate_verify(&pubkey_sec1, &pubkey_sec1, &transcript, &sig)
        .expect("a self-signed CertificateVerify must verify");
}

#[test]
fn sign_certificate_verify_rejected_for_wrong_key_and_tampered_transcript() {
    use p256::ecdsa::SigningKey;
    let signing_key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let other_key = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let other_pub = other_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let transcript = transcript_hash(b"ch||sh||ee||cert", SUITE_AES_128_GCM_SHA256);
    let sig = sign_certificate_verify(&signing_key, &transcript).unwrap();

    // Wrong pinned key → RealityVerify.
    assert!(verify_certificate_verify(&other_pub, &other_pub, &transcript, &sig).is_err());

    // Tampered transcript (verify against a different hash) → RealityVerify.
    let signer_pub = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let tampered = transcript_hash(b"different-transcript", SUITE_AES_128_GCM_SHA256);
    assert!(verify_certificate_verify(&signer_pub, &signer_pub, &tampered, &sig).is_err());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-utls --lib stream::tests::sign_certificate_verify`
Expected: FAIL — `sign_certificate_verify` not found.

- [ ] **Step 3: Implement `sign_certificate_verify`**

Add next to `verify_certificate_verify` in `stream.rs`. It builds the identical §4.4.3 signed content and signs:

```rust
/// The signing counterpart of [`verify_certificate_verify`]: sign the TLS 1.3
/// server `CertificateVerify` (RFC 8446 §4.4.3) with the derived ECDSA-P256
/// key `signing_key` (from `auth::derive_cert_key(shared)`), over the SAME
/// signed content the verifier reconstructs. This IS the REALITY.4b binding,
/// server side — the client pins the presented leaf's SPKI to this key and
/// verifies this signature. `ecdsa_secp256r1_sha256` (scheme 0x0403) is fixed:
/// `p256::ecdsa::SigningKey` signs SHA-256 internally, so no `suite` is needed
/// (the caller uses `suite` only to compute `transcript_hash_through_certificate`).
pub fn sign_certificate_verify(
    signing_key: &p256::ecdsa::SigningKey,
    transcript_hash_through_certificate: &[u8],
) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::{signature::Signer, Signature};

    let mut signed = Vec::with_capacity(64 + 33 + 1 + transcript_hash_through_certificate.len());
    signed.extend_from_slice(&[0x20u8; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0x00);
    signed.extend_from_slice(transcript_hash_through_certificate);

    let sig: Signature = signing_key
        .try_sign(&signed)
        .map_err(|_| Error::Crypto)?;
    Ok(sig.to_der().as_bytes().to_vec())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-utls --lib stream::tests::sign_certificate_verify` then `cargo test -p yip-utls`
Expected: PASS.

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt
git add crates/yip-utls/src/stream.rs
git commit -m "feat(reality.5c): sign_certificate_verify — signing mirror of the 4b verifier"
```

---

### Task 4: `emit_server_flight` — assemble, seal, and frame the encrypted flight

Build EE/Certificate/CertificateVerify/Finished, seal them under the 5b handshake keys, and greedily frame them across `dest`'s captured `record_lengths` (padding to hit each length exactly), prefixed with the middlebox CCS.

**Files:**
- Modify: `crates/yip-utls/src/error.rs` (add `FlightTooLarge` variant)
- Modify: `crates/yip-utls/src/stream.rs` (add `ServerFlight` struct + `emit_server_flight` + tests)

**Interfaces:**
- Consumes: `HandshakeKeys` (Task 1, incl. `server_hs_traffic`); `record_seal_padded` (Task 2); `sign_certificate_verify` (Task 3); `EncryptedFlightShape` + `CertChainShape` (`crate::template`); `finished_verify_data`, `derive_application_keys`, `transcript_hash`, `ApplicationKeys` (`crate::handshake`); `record_header`, `CHANGE_CIPHER_SPEC_RECORD`, `CONTENT_TYPE_HANDSHAKE`, `CONTENT_TYPE_APPLICATION_DATA`, `LEGACY_RECORD_VERSION` (already in `stream.rs`).
- Produces:
  - `pub struct ServerFlight { pub wire: Vec<u8>, pub app_keys: ApplicationKeys }`
  - `pub fn emit_server_flight(keys: &HandshakeKeys, flight_shape: &EncryptedFlightShape, cert_chain: &CertChainShape, forged_leaf_der: &[u8], cert_signing_key: &p256::ecdsa::SigningKey, transcript_ch_sh: &[u8]) -> Result<ServerFlight, Error>`
  - `Error::FlightTooLarge`

- [ ] **Step 1: Add the `Error::FlightTooLarge` variant**

In `crates/yip-utls/src/error.rs`, add a variant to the `Error` enum (near `Protocol`), a `Display` arm, and include it in the fatal/non-retryable classification match alongside `Protocol` / `RealityVerify` (grep the file for `Error::Protocol` to find every match arm that enumerates variants and add `FlightTooLarge` beside it):

```rust
    /// The forged server flight's plaintext does not fit the captured
    /// `dest` record framing (`sum(record_lengths[i] - 17)` < flight bytes,
    /// or a malformed `record_lengths`). REALITY.5c fail-safe: 5d degrades
    /// this connection to splice-only.
    FlightTooLarge,
```

Display arm:

```rust
            Error::FlightTooLarge => {
                write!(f, "REALITY/TLS server flight exceeds the captured dest record framing")
            }
```

- [ ] **Step 2: Write the failing tests**

Add to `stream.rs`'s `mod tests`. These build a real `HandshakeKeys` via `derive_handshake_keys`, a P-256 signing key, and a fixture `EncryptedFlightShape` whose `record_lengths` include an inflated final record and leave the last record as pure padding.

```rust
// Shared fixture: derive real handshake keys + a leaf whose SPKI is the
// signing key, so the emitted Certificate is well-formed.
fn emit_flight_fixture() -> (HandshakeKeys, p256::ecdsa::SigningKey, Vec<u8>, Vec<u8>) {
    let ecdhe = [7u8; 32];
    let transcript_ch_sh = b"raw-clienthello-bytes||raw-serverhello-bytes".to_vec();
    let th = transcript_hash(&transcript_ch_sh, SUITE_AES_128_GCM_SHA256);
    let keys = derive_handshake_keys(&ecdhe, &th, SUITE_AES_128_GCM_SHA256);
    let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]).unwrap();
    // A real leaf whose key is the signing key (test-only helper already used
    // by the verify tests). `leaf_der_for_key` takes an rcgen KeyPair built
    // from the p256 pkcs8.
    use p256::pkcs8::EncodePrivateKey as _;
    let pkcs8 = signing_key.to_pkcs8_der().unwrap();
    let leaf_key = rcgen::KeyPair::try_from(pkcs8.as_bytes()).unwrap();
    let leaf_der = leaf_der_for_key(&leaf_key);
    (keys, signing_key, leaf_der, transcript_ch_sh)
}

#[test]
fn emit_server_flight_matches_record_lengths_and_reopens_to_messages() {
    let (keys, signing_key, leaf_der, transcript_ch_sh) = emit_flight_fixture();
    // Generously sized records: 3 records, last two mostly/entirely padding.
    let shape = crate::template::EncryptedFlightShape {
        record_lengths: vec![600, 600, 4096],
        encrypted_extensions_len: 0,
        certificate_len: 0,
        certificate_verify_len: 0,
        finished_len: 0,
    };
    let cert_chain = crate::template::CertChainShape {
        leaf_der_len: leaf_der.len(),
        intermediates_der: Vec::new(),
    };

    let flight = emit_server_flight(
        &keys, &shape, &cert_chain, &leaf_der, &signing_key, &transcript_ch_sh,
    )
    .unwrap();

    // First record is the middlebox CCS, byte-for-byte.
    assert_eq!(&flight.wire[..CHANGE_CIPHER_SPEC_RECORD.len()], &CHANGE_CIPHER_SPEC_RECORD);

    // Walk the sealed records after the CCS: each record's header length field
    // MUST equal record_lengths[i]; re-open each under the handshake server key
    // and concatenate the recovered plaintext.
    let mut off = CHANGE_CIPHER_SPEC_RECORD.len();
    let mut recovered = Vec::new();
    for (i, &rlen) in shape.record_lengths.iter().enumerate() {
        let hdr = &flight.wire[off..off + RECORD_HEADER_LEN];
        assert_eq!(hdr[0], CONTENT_TYPE_APPLICATION_DATA);
        let len_field = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
        assert_eq!(len_field, rlen, "record {i} outer length must match record_lengths");
        let mut payload =
            flight.wire[off + RECORD_HEADER_LEN..off + RECORD_HEADER_LEN + rlen].to_vec();
        let opened = record_open(
            &keys.server_key, &keys.server_iv, u64::try_from(i).unwrap(),
            keys.suite, CONTENT_TYPE_APPLICATION_DATA, &mut payload,
        )
        .unwrap();
        recovered.extend_from_slice(&opened);
        off += RECORD_HEADER_LEN + rlen;
    }
    assert_eq!(off, flight.wire.len(), "no trailing bytes after the framed records");

    // The recovered plaintext begins with EncryptedExtensions (0x08),
    // Certificate (0x0b), CertificateVerify (0x0f), Finished (0x14) in order.
    assert_eq!(recovered[0], 0x08, "first message is EncryptedExtensions");
    // Walk the four handshake messages by their u24 length prefixes.
    let mut p = 0usize;
    let mut types = Vec::new();
    while p + 4 <= recovered.len() {
        let ty = recovered[p];
        if ty == 0 { break; } // reached padding stripped? (shouldn't; padding was per-record)
        let len = (usize::from(recovered[p + 1]) << 16)
            | (usize::from(recovered[p + 2]) << 8)
            | usize::from(recovered[p + 3]);
        types.push(ty);
        p += 4 + len;
        if types.len() == 4 { break; }
    }
    assert_eq!(types, vec![0x08, 0x0b, 0x0f, 0x14]);
}

#[test]
fn emit_server_flight_rejects_malformed_or_over_capacity_framing() {
    let (keys, signing_key, leaf_der, transcript_ch_sh) = emit_flight_fixture();
    let cert_chain = crate::template::CertChainShape {
        leaf_der_len: leaf_der.len(),
        intermediates_der: Vec::new(),
    };
    let mk = |record_lengths: Vec<usize>| crate::template::EncryptedFlightShape {
        record_lengths,
        encrypted_extensions_len: 0,
        certificate_len: 0,
        certificate_verify_len: 0,
        finished_len: 0,
    };

    // Empty record_lengths → Err (not panic).
    assert!(emit_server_flight(&keys, &mk(vec![]), &cert_chain, &leaf_der, &signing_key, &transcript_ch_sh).is_err());
    // A record length below the 17-byte AEAD/content-type floor → Err.
    assert!(emit_server_flight(&keys, &mk(vec![10]), &cert_chain, &leaf_der, &signing_key, &transcript_ch_sh).is_err());
    // Total capacity far below the flight size → FlightTooLarge.
    let err = emit_server_flight(&keys, &mk(vec![20, 20]), &cert_chain, &leaf_der, &signing_key, &transcript_ch_sh)
        .unwrap_err();
    assert!(matches!(err, Error::FlightTooLarge));
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p yip-utls --lib stream::tests::emit_server_flight`
Expected: FAIL — `emit_server_flight` / `ServerFlight` not found.

- [ ] **Step 4: Implement `ServerFlight` + `emit_server_flight`**

Add to `stream.rs` (near `capture_dest_flight`). Uses two tiny local helpers for handshake-message framing:

```rust
/// The output of [`emit_server_flight`]: the wire bytes to send (CCS ‖ sealed
/// handshake-key records) and the application traffic keys for the data phase.
pub struct ServerFlight {
    pub wire: Vec<u8>,
    pub app_keys: handshake::ApplicationKeys,
}

/// Wrap a handshake-message body as `type ‖ u24 len ‖ body`.
fn handshake_message(msg_type: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u32::try_from(body.len()).map_err(|_| Error::RecordTooLarge)?;
    if body.len() > 0xFF_FFFF {
        return Err(Error::RecordTooLarge);
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&len.to_be_bytes()[1..]); // u24
    out.extend_from_slice(body);
    Ok(out)
}

/// A single `CertificateEntry`: `u24 cert_data_len ‖ der ‖ u16 ext_len(0)`.
fn certificate_entry(der: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u32::try_from(der.len()).map_err(|_| Error::RecordTooLarge)?;
    if der.len() > 0xFF_FFFF {
        return Err(Error::RecordTooLarge);
    }
    let mut out = Vec::with_capacity(3 + der.len() + 2);
    out.extend_from_slice(&len.to_be_bytes()[1..]); // u24
    out.extend_from_slice(der);
    out.extend_from_slice(&[0x00, 0x00]); // empty entry extensions
    Ok(out)
}

/// REALITY.5c: assemble the encrypted server flight (EE/Certificate/
/// CertificateVerify/Finished), seal it under `keys` handshake keys, and frame
/// it to byte-match `flight_shape.record_lengths` (padding each record to its
/// captured length), prefixed with the middlebox-compat CCS. Returns the wire
/// bytes + the derived application keys. Fail-closed: a malformed or
/// too-small `record_lengths` → `Err` (5d degrades to splice).
pub fn emit_server_flight(
    keys: &HandshakeKeys,
    flight_shape: &crate::template::EncryptedFlightShape,
    cert_chain: &crate::template::CertChainShape,
    forged_leaf_der: &[u8],
    cert_signing_key: &p256::ecdsa::SigningKey,
    transcript_ch_sh: &[u8],
) -> Result<ServerFlight, Error> {
    let suite = keys.suite;

    // 1. EncryptedExtensions: empty extensions list.
    let ee = handshake_message(0x08, &[0x00, 0x00])?;

    // 2. Certificate: empty context ‖ u24 list-len ‖ leaf entry ‖ intermediates.
    let mut cert_list = certificate_entry(forged_leaf_der)?;
    for inter in &cert_chain.intermediates_der {
        cert_list.extend_from_slice(&certificate_entry(inter)?);
    }
    let mut cert_body = Vec::with_capacity(1 + 3 + cert_list.len());
    cert_body.push(0x00); // certificate_request_context length = 0
    let list_len = u32::try_from(cert_list.len()).map_err(|_| Error::RecordTooLarge)?;
    if cert_list.len() > 0xFF_FFFF {
        return Err(Error::RecordTooLarge);
    }
    cert_body.extend_from_slice(&list_len.to_be_bytes()[1..]); // u24
    cert_body.extend_from_slice(&cert_list);
    let certificate = handshake_message(0x0b, &cert_body)?;

    // 3. CertificateVerify over the transcript through Certificate.
    let mut tr = transcript_ch_sh.to_vec();
    tr.extend_from_slice(&ee);
    tr.extend_from_slice(&certificate);
    let th_cert = transcript_hash(&tr, suite);
    let sig = sign_certificate_verify(cert_signing_key, &th_cert)?;
    let mut cv_body = Vec::with_capacity(2 + 2 + sig.len());
    cv_body.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256
    cv_body.extend_from_slice(&u16::try_from(sig.len()).map_err(|_| Error::RecordTooLarge)?.to_be_bytes());
    cv_body.extend_from_slice(&sig);
    let certificate_verify = handshake_message(0x0f, &cv_body)?;

    // 4. Finished over the transcript through CertificateVerify.
    tr.extend_from_slice(&certificate_verify);
    let th_cv = transcript_hash(&tr, suite);
    let verify_data = handshake::finished_verify_data(&keys.server_hs_traffic, &th_cv, suite);
    let finished = handshake_message(0x14, &verify_data)?;

    // Application keys over the transcript through the server Finished.
    tr.extend_from_slice(&finished);
    let th_fin = transcript_hash(&tr, suite);
    let app_keys = handshake::derive_application_keys(&keys.handshake_secret, &th_fin, suite);

    // The contiguous handshake-message plaintext to frame.
    let mut hs_stream = Vec::with_capacity(ee.len() + certificate.len() + certificate_verify.len() + finished.len());
    hs_stream.extend_from_slice(&ee);
    hs_stream.extend_from_slice(&certificate);
    hs_stream.extend_from_slice(&certificate_verify);
    hs_stream.extend_from_slice(&finished);

    // 5. Greedy record framing to match record_lengths exactly.
    if flight_shape.record_lengths.is_empty() {
        return Err(Error::Protocol("empty record_lengths in captured flight template"));
    }
    let mut wire = CHANGE_CIPHER_SPEC_RECORD.to_vec();
    let mut off = 0usize;
    for (i, &rlen) in flight_shape.record_lengths.iter().enumerate() {
        // cap = plaintext(+padding) budget for this record (excludes content-type + tag).
        let cap = rlen
            .checked_sub(17)
            .ok_or(Error::Protocol("record length below the 17-byte AEAD floor"))?;
        let remaining = hs_stream.len() - off;
        let chunk_len = remaining.min(cap);
        let chunk = &hs_stream[off..off + chunk_len];
        let pad_len = cap - chunk_len; // once hs_stream is exhausted, chunk_len=0 → pad_len=cap (pure-padding record)
        let seq = u64::try_from(i).map_err(|_| Error::Protocol("record index overflow"))?;
        let sealed = record_seal_padded(
            &keys.server_key, &keys.server_iv, seq, suite,
            CONTENT_TYPE_HANDSHAKE, chunk, pad_len,
        )?;
        let hdr = record_header(CONTENT_TYPE_APPLICATION_DATA, LEGACY_RECORD_VERSION, sealed.len())?;
        wire.extend_from_slice(&hdr);
        wire.extend_from_slice(&sealed);
        off += chunk_len;
    }
    if off < hs_stream.len() {
        // The flight did not fit the captured record framing.
        return Err(Error::FlightTooLarge);
    }

    Ok(ServerFlight { wire, app_keys })
}
```

Add the needed imports to `stream.rs`'s `use crate::handshake::{...}` line: `record_seal_padded`, `ApplicationKeys`, `derive_application_keys`, `finished_verify_data` (whichever are not already imported — check the existing `use` at the top of `stream.rs` first and add only the missing names).

**Note the highlighted greedy property:** once `off` reaches `hs_stream.len()`, every subsequent record gets `chunk_len = 0` and `pad_len = cap`, producing pure-padding records of exactly the requested size — preserving `dest`'s record count and each length even when our flight is shorter than dest's.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p yip-utls --lib stream::tests::emit_server_flight` then `cargo test -p yip-utls`
Expected: PASS.

- [ ] **Step 6: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt
git add crates/yip-utls/src/error.rs crates/yip-utls/src/stream.rs
git commit -m "feat(reality.5c): emit_server_flight — assemble+seal+frame the encrypted flight to record_lengths"
```

---

### Task 5: Role-agnostic `RealityStream` (egress/ingress) + constructors

Rename the stream's direction-specific fields so the same state machine serves both roles, and add constructors. Pure mechanical rename + additive constructors — behavior-identical; the existing client/round-trip tests are the regression net.

**Files:**
- Modify: `crates/yip-utls/src/stream.rs` (`RealityStream` struct ~1216-1240; its `impl` `poll_*` methods; the `connect` construction ~984-998; the two test literals ~1652-1681)

**Interfaces:**
- Consumes: `ApplicationKeys` (`crate::handshake`).
- Produces:
  - `RealityStream` fields renamed: `client_key/client_iv/client_seq` → `egress_key/egress_iv/egress_seq`; `server_key/server_iv/server_seq` → `ingress_key/ingress_iv/ingress_seq`.
  - `RealityStream::<S>::client(inner: S, ak: ApplicationKeys) -> Self` (egress = client keys, ingress = server keys — the connect direction).
  - `RealityStream::<S>::server(inner: S, ak: ApplicationKeys) -> Self` (egress = server keys, ingress = client keys — the serve direction).

- [ ] **Step 1: Rename the fields**

In the `RealityStream` struct definition rename the six fields (and update their doc comments to say "egress" / "ingress" rather than "client" / "server"). Then update every use inside the `impl RealityStream` methods:
- `poll_fill_read_buf` opens ingress records → `self.ingress_key` / `self.ingress_iv` / `self.ingress_seq`.
- `poll_write` seals egress records → `this.egress_key` / `this.egress_iv` / `this.egress_seq`.

Grep to find every occurrence so none are missed:

```bash
grep -n "\.client_key\|\.client_iv\|\.client_seq\|\.server_key\|\.server_iv\|\.server_seq\|client_key:\|client_iv:\|client_seq:\|server_key:\|server_iv:\|server_seq:" crates/yip-utls/src/stream.rs
```

Only occurrences **on a `RealityStream` value / literal** get renamed — do NOT touch `hk.server_key` / `ak.client_key` etc. (those are `HandshakeKeys` / `ApplicationKeys` field names, unchanged).

- [ ] **Step 2: Add the constructors + convert the `connect` literal**

Add to `impl<S: AsyncRead + AsyncWrite + Unpin> RealityStream<S>` (or a plain `impl<S> RealityStream<S>` — no bounds needed to construct):

```rust
    /// Build the CLIENT-role stream (used by [`connect`]): egress sealed with
    /// the client application key, ingress opened with the server's.
    fn client(inner: S, ak: handshake::ApplicationKeys) -> Self {
        RealityStream {
            inner,
            suite: ak.suite,
            egress_key: ak.client_key,
            egress_iv: ak.client_iv,
            egress_seq: 0,
            ingress_key: ak.server_key,
            ingress_iv: ak.server_iv,
            ingress_seq: 0,
            raw_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_off: 0,
        }
    }

    /// Build the SERVER-role stream (used by [`serve`]): egress sealed with the
    /// server application key, ingress opened with the client's — the mirror of
    /// [`client`].
    fn server(inner: S, ak: handshake::ApplicationKeys) -> Self {
        RealityStream {
            inner,
            suite: ak.suite,
            egress_key: ak.server_key,
            egress_iv: ak.server_iv,
            egress_seq: 0,
            ingress_key: ak.client_key,
            ingress_iv: ak.client_iv,
            ingress_seq: 0,
            raw_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_off: 0,
        }
    }
```

Replace the `connect` construction (`Ok(RealityStream { inner: stream, ... })` ~984) with `Ok(RealityStream::client(stream, ak))`.

- [ ] **Step 3: Update the two test literals**

In `reality_stream_round_trips_over_duplex` (~1652, 1667), rename `client_key/client_iv/client_seq` → `egress_key/egress_iv/egress_seq` and `server_key/server_iv/server_seq` → `ingress_key/ingress_iv/ingress_seq` in both `RealityStream { .. }` literals (the semantic mapping is unchanged — A's egress is what B ingests).

- [ ] **Step 4: Run the full suite to prove the rename is behavior-preserving**

Run: `cargo test -p yip-utls`
Expected: PASS — every existing test (client `connect`, verify round-trips, JA4-diff, 5a/5b, the duplex round-trip) stays green. This is the regression gate for the rename.

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt
git add crates/yip-utls/src/stream.rs
git commit -m "refactor(reality.5c): role-agnostic RealityStream (egress/ingress) + client/server constructors"
```

---

### Task 6: `serve` + drive the verify round-trip suite through 5c (THE GATE)

Compose `emit_server_flight` + write + drain the client's CCS/Finished + build the server stream into a single `serve` entry point, then refactor the shared test mock `run_mock_tls13_server_with_cert` to emit its flight **through `serve`/`emit_server_flight`** — so the four shipped `connect_verify_*` round-trip tests exercise real 5c code end-to-end (the correctness gate). Add a bidirectional data assertion.

**Files:**
- Modify: `crates/yip-utls/src/stream.rs` (add `serve`; refactor `run_mock_tls13_server_with_cert` ~2180-end; add a bidirectional round-trip test)

**Interfaces:**
- Consumes: `emit_server_flight` / `ServerFlight` (Task 4); `RealityStream::server` (Task 5); `read_raw_record`, `record_open`, `HandshakeKeys` (existing).
- Produces: `pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(stream: S, keys: &HandshakeKeys, flight_shape: &EncryptedFlightShape, cert_chain: &CertChainShape, forged_leaf_der: &[u8], cert_signing_key: &p256::ecdsa::SigningKey, transcript_ch_sh: &[u8]) -> Result<RealityStream<S>, Error>`

- [ ] **Step 1: Implement `serve`**

Add to `stream.rs`. It emits the flight, writes it, drains the client's CCS + Finished (contents unchecked — zero client-auth, symmetric with how `connect` drains the server's Finished), and returns the server-role stream. The client sends exactly a CCS record then one sealed handshake (Finished) record:

```rust
/// REALITY.5c server entry point — the mirror of [`connect`]. Emits the
/// encrypted server flight (via [`emit_server_flight`]) framed to `dest`'s
/// captured record lengths, writes it, drains the client's middlebox CCS +
/// `Finished` (contents UNCHECKED — the outer TLS is zero client-auth by
/// design, exactly as `connect` never checks the server's `Finished`), and
/// returns the server-role [`RealityStream`] on the derived application keys.
/// The ServerHello (REALITY.5b `emit_server_hello`) and `transcript_ch_sh`
/// (raw ClientHello ‖ ServerHello) must already have been produced/sent by
/// the caller (5d).
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    keys: &HandshakeKeys,
    flight_shape: &crate::template::EncryptedFlightShape,
    cert_chain: &crate::template::CertChainShape,
    forged_leaf_der: &[u8],
    cert_signing_key: &p256::ecdsa::SigningKey,
    transcript_ch_sh: &[u8],
) -> Result<RealityStream<S>, Error> {
    let flight = emit_server_flight(
        keys, flight_shape, cert_chain, forged_leaf_der, cert_signing_key, transcript_ch_sh,
    )?;
    stream.write_all(&flight.wire).await?;

    // Drain the client's CCS + sealed Finished. The client sends a CCS record
    // (skipped) then exactly one application-data record carrying the sealed
    // Finished, opened under the CLIENT handshake key; its contents are not
    // validated (zero client-auth).
    let mut client_hs_seq = 0u64;
    loop {
        let (record_type, mut payload) = read_raw_record(&mut stream).await?;
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(Error::Protocol("expected the client's sealed Finished record"));
        }
        // Open (and discard) the client Finished — proves it is well-framed
        // under the negotiated key; contents intentionally unchecked.
        record_open(
            &keys.client_key, &keys.client_iv, client_hs_seq, keys.suite,
            record_type, &mut payload,
        )?;
        client_hs_seq = client_hs_seq
            .checked_add(1)
            .ok_or(Error::Protocol("client handshake sequence overflow"))?;
        break;
    }

    Ok(RealityStream::server(stream, flight.app_keys))
}
```

- [ ] **Step 2: Refactor `run_mock_tls13_server_with_cert` to emit its flight through 5c**

The mock currently hand-rolls EE/Certificate/CertificateVerify/Finished, seals them in one record, and hand-drives the app-data echo (roughly lines 2274 to the end of the function). Replace that tail — everything from the `ee_msg`/certificate construction through the sealed-flight write and the client-Finished drain and the echo setup — with a call to `serve`, keeping the per-behavior `(leaf_der, signing_key)` selection that already exists (~2255-2272). Concretely, after the mock has `hk`, `ch_sh_transcript`, `derived`, and the `(leaf_key_pkcs8, signing_key_pkcs8)` pair:

```rust
    // Build the (forged leaf, signing key) pair per behavior — unchanged.
    let leaf_key = rcgen::KeyPair::try_from(leaf_key_pkcs8.as_slice()).unwrap();
    let leaf_der = leaf_der_for_key(&leaf_key);
    use p256::pkcs8::DecodePrivateKey as _;
    let cert_signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&signing_key_pkcs8).unwrap();

    let intermediates = if include_intermediate {
        let intermediate_key = rcgen::KeyPair::generate().unwrap();
        vec![leaf_der_for_key(&intermediate_key)]
    } else {
        Vec::new()
    };
    let flight_shape = crate::template::EncryptedFlightShape {
        record_lengths: vec![600, 4096], // comfortably larger than the flight; exercises padding
        encrypted_extensions_len: 0,
        certificate_len: 0,
        certificate_verify_len: 0,
        finished_len: 0,
    };
    let cert_chain = crate::template::CertChainShape {
        leaf_der_len: leaf_der.len(),
        intermediates_der: intermediates,
    };
    // transcript_ch_sh = the RAW ClientHello ‖ ServerHello bytes (ch_sh_transcript),
    // NOT the hash — emit_server_flight hashes internally.
    //
    // IMPORTANT: do NOT `.expect()` on serve. For the reject behaviors
    // (WrongLeafKey / BadSignature) the client verifies, FAILS, and drops the
    // connection WITHOUT sending its Finished — so `serve` (which drains the
    // client Finished) returns Err. That is the correct outcome for those
    // tests (they assert the CLIENT `connect` returns Err); the server task
    // must simply exit cleanly, not panic. `if let Ok` handles both paths.
    if let Ok(mut server) = serve(
        io, &hk, &flight_shape, &cert_chain, &leaf_der, &cert_signing_key, &ch_sh_transcript,
    )
    .await
    {
        // Echo whatever the client sends (robust to any ping size the
        // round-trip tests use), proving the server-app egress seal + client
        // ingress open both work.
        let mut buf = [0u8; 64];
        if let Ok(n) = server.read(&mut buf).await {
            if n > 0 {
                let _ = server.write_all(&buf[..n]).await;
                let _ = server.flush().await;
            }
        }
    }
```

Remove the now-dead hand-rolled flight/seal/drain/echo code and any locals it alone used (e.g. `server_flight_plain`, `sealed_flight`, `transcript_thru_sfin`, the manual app-key derivation, `build_certificate_message*`, `build_certificate_verify_message` calls — but leave those test *helpers* defined if other tests use them; grep before deleting a helper). `ch_sh_transcript` is consumed by `serve`; if a later line still needs it, clone before the call. Ensure `io` is `mut` as required by `serve`'s `stream.write_all`.

Note: the mock must still produce the raw `ch_sh_transcript` as `ch_msg ‖ sh_msg` (it already does at ~2241-2243) and derive `hk` (~2245) — those stay. The ServerHello it hand-rolls (~2196-2238) stays (5c consumes a ready ServerHello; wiring 5b's `emit_server_hello` in is 5d's job).

- [ ] **Step 3: Add a bidirectional round-trip assertion**

The existing `connect_verify_accepts_correct_binder` only checks client→server→echo. Add a focused test proving BOTH directions over the real 5c server stream (server-initiated write):

```rust
#[tokio::test]
async fn serve_round_trips_application_data_both_directions() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [3u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    // Server: hand-rolled ServerHello + 5c serve (reuses the refactored mock,
    // CorrectBinder → the client must verify the 4b binding).
    let server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::CorrectBinder,
        false,
    ));

    let mut s = connect(client_io, "example.com", &server_reality_pub, [1u8; 8], true)
        .await
        .expect("correctly-bound relay verifies");

    // client → server → echo (server's echo path in the mock).
    s.write_all(b"PING").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");

    server_task.await.unwrap();
}
```

(The server→client direction is proven by the echo — the server's `write_all` in the refactored mock seals under the server-app egress key and the client opens it with its ingress key. If you prefer an explicit server-first write, add a variant mock; the echo already exercises both seal directions.)

- [ ] **Step 4: Run the full suite (the gate)**

Run: `cargo test -p yip-utls`
Expected: PASS — in particular `connect_verify_accepts_correct_binder`, `connect_verify_accepts_correct_binder_with_intermediate_chain`, `connect_verify_rejects_wrong_key`, `connect_verify_rejects_bad_signature`, `connect_no_verify_ignores_cert`, and the new `serve_round_trips_application_data_both_directions` — all now driving the real `emit_server_flight`/`serve` code. The reject tests prove the 4b binding still fails closed when the server presents a wrong leaf key / bad signature *through 5c's emission*.

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt
git add crates/yip-utls/src/stream.rs
git commit -m "feat(reality.5c): serve — server flight + drain + stream; verify round-trip suite runs through 5c"
```

---

## After all tasks

- Final whole-branch review (opus) over the 5c delta (base = 5b tip / PR #85 head), focused on: KEX/transcript correctness (CertVerify + Finished over the right boundaries), fail-closed framing (`FlightTooLarge`, `< 17`, empty), the role rename being behavior-preserving, and the verify-reject tests genuinely failing closed through the new emission path.
- Push the branch; open a PR **stacked on #85** (base = `feat/reality-5b-serverhello-emit`). Leave it for the user; do NOT merge; no "not merging" line.
- Update the ledger + `yip-antidpi-status.md` memory (5c complete; 5d = wire into `tls_front`, forge the leaf to `leaf_der_len`, honor the 5d checklist from 5b: key the 4588 DH against the bundled x25519 / OS-CSPRNG rng).

## Self-Review notes (carried from spec)

- **Greedy chunking of an empty remaining stream** yields pure-padding records of the exact requested size (`chunk_len = 0`, `pad_len = cap`) — preserving `dest`'s record count + lengths. Highlighted in Task 4 Step 4.
- **`record_open` already strips trailing padding** (`while payload.last() == Some(&0) { payload.pop(); }`), so the shipped client consumes 5c's padded records with no change — the round-trip suite (Task 6) is the proof.
