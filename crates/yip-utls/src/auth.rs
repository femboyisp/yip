//! Shared REALITY auth codec: the ChaCha20-Poly1305 seal carried in a TLS
//! `ClientHello`'s `legacy_session_id`, keyed by an X25519 ECDH between the
//! client's ephemeral key-share and the server's REALITY key.
//!
//! [`seal`] is the client side (used by `yip-utls`'s REALITY-mimicking
//! `ClientHello` crafting, REALITY.2); [`open`] is the server side (used by
//! `yip-rendezvous`'s `reality_auth_open`, REALITY.1). Both must derive the
//! identical AEAD key and plaintext layout or the client's seal will never
//! open on the server — this module is the single source of truth for that
//! scheme so it cannot drift between the two crates.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::{bigint::U256, scalar::FromUintUnchecked, Curve};
use p256::pkcs8::EncodePrivateKey;
use p256::{NistP256, NonZeroScalar, Scalar};
use ring::hkdf;
use x25519_dalek::{PublicKey, StaticSecret};

/// HKDF-SHA256 output length marker for a 32-byte key (`ring::hkdf::KeyType`
/// requires a concrete type carrying the desired length).
struct Aead32Key;

impl hkdf::KeyType for Aead32Key {
    fn len(&self) -> usize {
        32
    }
}

/// Domain-separation info string for the REALITY AEAD key derivation.
const HKDF_INFO: &[u8] = b"yip-reality-v1";

/// `HKDF-SHA256(salt=b"", ikm=shared, info="yip-reality-v1", len=32)`.
fn derive_aead_key(shared: &[u8; 32]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"");
    let prk = salt.extract(shared);
    // `Aead32Key::len()` is a constant 32, matching `out`'s length, so
    // `expand`/`fill` cannot fail here.
    let okm = prk
        .expand(&[HKDF_INFO], Aead32Key)
        .expect("32-byte OKM is well within the HKDF-SHA256 output-length limit");
    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .expect("Aead32Key::len() matches out.len()");
    out
}

/// HKDF-SHA256 output length marker for the 48-byte cert-key wide-reduction
/// input (`ring::hkdf::KeyType` requires a concrete type carrying the desired
/// length; see [`Aead32Key`] for the 32-byte AEAD-key counterpart).
struct Okm48;

impl hkdf::KeyType for Okm48 {
    fn len(&self) -> usize {
        48
    }
}

/// Domain-separation info string for the REALITY.4b relay cert-key
/// derivation (distinct from [`HKDF_INFO`], the AEAD-key info string, so the
/// two derivations can never collide even though both are keyed on the same
/// `shared`).
const CERT_KEY_HKDF_INFO: &[u8] = b"yip-reality-cert-v1";

/// `HKDF-SHA256(salt=b"", ikm=shared, info=info, len=48)`. 48 bytes (rather
/// than 32) so the subsequent mod-`n` reduction to a P-256 scalar has
/// negligible (< 2⁻¹²⁸) bias — see [`signing_key_from_wide`].
fn hkdf_expand_48(shared: &[u8; 32], info: &[u8]) -> [u8; 48] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"");
    let prk = salt.extract(shared);
    // `Okm48::len()` is a constant 48, matching `out`'s length, so
    // `expand`/`fill` cannot fail here.
    let info_slices = [info];
    let okm = prk
        .expand(&info_slices, Okm48)
        .expect("48-byte OKM is well within the HKDF-SHA256 output-length limit");
    let mut out = [0u8; 48];
    okm.fill(&mut out).expect("Okm48::len() matches out.len()");
    out
}

/// Wide-reduce 48 bytes (384 bits, big-endian) to a non-zero P-256 scalar and
/// build a [`SigningKey`] from it.
///
/// Zero-extends the 384-bit input to 512 bits (two 256-bit halves) and
/// reduces it mod the curve order `n` via
/// [`crypto_bigint`]'s `Uint::const_rem_wide` (`p256::elliptic_curve::bigint::U256`).
/// That routine is a fixed-modulus long division — per its own doc comment,
/// "when used with a fixed `rhs`, this function is constant-time with
/// respect to `self`" — and our `rhs` (the curve order) is a fixed constant,
/// so the reduction has no data-dependent branching on the secret input.
/// Since 48 bytes of uniform input reduced mod a ~256-bit `n` has < 2⁻¹²⁸
/// bias versus a truly uniform scalar (RFC 9380 §5-style wide reduction),
/// both sides land on the identical scalar with overwhelming probability.
///
/// The ~2⁻²⁵⁶ case where the reduced scalar is exactly zero is mapped
/// deterministically to `1` (via `NonZeroScalar::new(..).unwrap_or_else`,
/// which is itself constant-time: the fallback closure always runs and the
/// selection is a `ConditionallySelectable` mux, not a branch) so both sides
/// always agree and the derivation never diverges or fails.
fn signing_key_from_wide(wide: &[u8; 48]) -> SigningKey {
    let mut padded = [0u8; 64];
    padded[16..].copy_from_slice(wide);
    let upper = U256::from_be_slice(&padded[..32]);
    let lower = U256::from_be_slice(&padded[32..]);
    let (remainder, _rhs_is_nonzero) = U256::const_rem_wide((lower, upper), &NistP256::ORDER);

    let scalar = Scalar::from_uint_unchecked(remainder);
    let nonzero = NonZeroScalar::new(scalar)
        .unwrap_or_else(|| NonZeroScalar::new(Scalar::ONE).expect("Scalar::ONE is never zero"));
    SigningKey::from(nonzero)
}

/// The ECDSA-P256 keypair both sides derive from `shared` for REALITY.4b
/// relay verification. Deterministic, uniform, constant-time (RustCrypto
/// `p256`).
pub struct DerivedCertKey {
    /// PKCS#8 DER of the private key — feeds `rcgen::KeyPair::try_from(&[u8])`
    /// (server; `from_der` parses an SPKI *public* key, not this private key).
    pub pkcs8_der: Vec<u8>,
    /// Uncompressed SEC1 public key (`0x04 ‖ X ‖ Y`, 65 bytes) — the client
    /// pins the presented leaf's key to this.
    pub public_sec1: Vec<u8>,
}

/// Derive the ECDSA-P256 keypair from `shared`:
/// `okm = HKDF-Expand(shared, "yip-reality-cert-v1", 48)`, wide-reduced mod
/// `n` to a scalar (RFC 9380 §5 style — 48 bytes gives < 2⁻¹²⁸ bias and both
/// sides land identically). The ~2⁻²⁵⁶ zero case maps to 1 (deterministic;
/// never diverges). Constant-time throughout (no data-dependent branch on
/// the scalar) — see [`signing_key_from_wide`].
pub fn derive_cert_key(shared: &[u8; 32]) -> DerivedCertKey {
    let okm48 = hkdf_expand_48(shared, CERT_KEY_HKDF_INFO);
    let signing_key = signing_key_from_wide(&okm48);

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
    DerivedCertKey {
        pkcs8_der,
        public_sec1,
    }
}

/// The X25519 ECDH shared secret the seal is keyed on (client side): the
/// same value the server recovers via [`open_recover_shared`].
pub fn shared_secret(reality_pub: &[u8; 32], eph_priv: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*eph_priv);
    *secret
        .diffie_hellman(&PublicKey::from(*reality_pub))
        .as_bytes()
}

/// Length of the REALITY auth plaintext: `short_id (8) || ts_min (8, LE)`.
const PLAINTEXT_LEN: usize = 16;
/// Length of the sealed `legacy_session_id`: 16-byte plaintext + 16-byte
/// ChaCha20-Poly1305 tag.
const SESSION_ID_LEN: usize = 32;

/// Client-side REALITY auth seal: produce the 32-byte `legacy_session_id`
/// that [`open`] accepts for the given `server_reality_pub`/`eph_priv` ECDH
/// pair, `short_id`, and `ts_min`.
pub fn seal(
    server_reality_pub: &[u8; 32],
    eph_priv: &[u8; 32],
    client_random: &[u8; 32],
    short_id: [u8; 8],
    ts_min: u64,
) -> [u8; 32] {
    let secret = StaticSecret::from(*eph_priv);
    let shared = secret.diffie_hellman(&PublicKey::from(*server_reality_pub));
    let aead_key = derive_aead_key(shared.as_bytes());

    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext[..8].copy_from_slice(&short_id);
    plaintext[8..].copy_from_slice(&ts_min.to_le_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .expect("aead_key is exactly 32 bytes, ChaCha20Poly1305's required key length");
    let nonce = Nonce::from_slice(&client_random[..12]);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: b"",
            },
        )
        .expect("ChaCha20Poly1305 seal of a 16-byte plaintext cannot fail");
    sealed
        .try_into()
        .expect("16-byte plaintext + 16-byte tag == 32 bytes")
}

/// Like [`open`], but returns the recovered `(short_id, ts_min)` on success
/// (for callers that need the timestamp, e.g. anti-replay's cross-restart
/// belt). Same fail-closed checks as `open`. The wire format is unchanged.
/// A thin wrapper over [`open_recover_shared`] that drops the `shared`
/// bytes — behavior-identical to the pre-REALITY.4b implementation.
pub fn open_recover(
    reality_priv: &[u8; 32],
    eph_pub: &[u8; 32],
    client_random: &[u8; 32],
    session_id: &[u8],
    short_ids: &[[u8; 8]],
    now_min: u64,
    skew_min: u64,
) -> Option<([u8; 8], u64)> {
    open_recover_shared(
        reality_priv,
        eph_pub,
        client_random,
        session_id,
        short_ids,
        now_min,
        skew_min,
    )
    .map(|(short_id, ts_min, _shared)| (short_id, ts_min))
}

/// Like [`open_recover`], but also returns the X25519 `shared` bytes (for
/// the REALITY.4b server binding, which derives the cert key from it via
/// [`derive_cert_key`]). Same fail-closed checks and wire format as
/// `open_recover`; that function is now expressed in terms of this one.
pub fn open_recover_shared(
    reality_priv: &[u8; 32],
    eph_pub: &[u8; 32],
    client_random: &[u8; 32],
    session_id: &[u8],
    short_ids: &[[u8; 8]],
    now_min: u64,
    skew_min: u64,
) -> Option<([u8; 8], u64, [u8; 32])> {
    if session_id.len() != SESSION_ID_LEN {
        return None;
    }

    let secret = StaticSecret::from(*reality_priv);
    let shared = secret.diffie_hellman(&PublicKey::from(*eph_pub));
    let aead_key = derive_aead_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .expect("aead_key is exactly 32 bytes, ChaCha20Poly1305's required key length");
    let nonce_bytes = client_random.get(..12)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: session_id,
                aad: b"",
            },
        )
        .ok()?;
    if plaintext.len() != PLAINTEXT_LEN {
        return None;
    }

    let short_id = <[u8; 8]>::try_from(plaintext.get(..8)?).ok()?;
    let ts_bytes = <[u8; 8]>::try_from(plaintext.get(8..16)?).ok()?;
    let ts_min = u64::from_le_bytes(ts_bytes);

    if !short_ids.contains(&short_id) {
        return None;
    }
    if ts_min.abs_diff(now_min) > skew_min {
        return None;
    }

    Some((short_id, ts_min, *shared.as_bytes()))
}

/// Server-side REALITY auth check. True iff `session_id` opens under the
/// shared key derived from `reality_priv` and `eph_pub` (the ClientHello's
/// x25519 key-share), AND the recovered `short_id` is in `short_ids`, AND
/// `|ts_min - now_min| <= skew_min`.
///
/// Fail-closed: a wrong-length `session_id`, failed AEAD open, unknown
/// `short_id`, or out-of-skew timestamp all return `false`. A bool wrapper
/// over [`open_recover`] — see that function for the recovered `ts_min`.
pub fn open(
    reality_priv: &[u8; 32],
    eph_pub: &[u8; 32],
    client_random: &[u8; 32],
    session_id: &[u8],
    short_ids: &[[u8; 8]],
    now_min: u64,
    skew_min: u64,
) -> bool {
    open_recover(
        reality_priv,
        eph_pub,
        client_random,
        session_id,
        short_ids,
        now_min,
        skew_min,
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// x25519 base-point scalar multiplication, used only by tests to derive
    /// a public key from a raw private scalar (mirrors what a real client
    /// or server would compute for its key).
    fn pubkey_of(priv_key: &[u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(*priv_key)).as_bytes()
    }

    #[test]
    fn seal_then_open_round_trips_with_matching_keys() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let now = 1_000_000u64;

        let session_id = seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        assert!(open(
            &reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[short_id],
            now,
            60
        ));
    }

    #[test]
    fn client_shared_secret_matches_server_open_recover_shared() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let now = 1_000_000u64;

        let client_shared = shared_secret(&reality_pub, &eph_priv);

        let session_id = seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        let (_short_id, _ts_min, server_shared) = open_recover_shared(
            &reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[short_id],
            now,
            60,
        )
        .expect("valid seal opens");

        assert_eq!(
            client_shared, server_shared,
            "client and server must derive the identical shared secret"
        );
    }

    #[test]
    fn wrong_reality_key_is_rejected() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let wrong_reality_priv = [12u8; 32];
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [6u8; 8];
        let now = 1_000_000u64;

        let session_id = seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        assert!(!open(
            &wrong_reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[short_id],
            now,
            60
        ));
    }

    #[test]
    fn unknown_short_id_is_rejected() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [1u8; 8];
        let other_short_id = [2u8; 8];
        let now = 1_000_000u64;

        let session_id = seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        assert!(!open(
            &reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[other_short_id],
            now,
            60
        ));
    }

    #[test]
    fn stale_timestamp_outside_skew_is_rejected() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [4u8; 8];
        let ts_min = 1_000_000u64;
        let skew_min = 5u64;

        let session_id = seal(&reality_pub, &eph_priv, &client_random, short_id, ts_min);
        assert!(open(
            &reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[short_id],
            ts_min + skew_min,
            skew_min
        ));
        assert!(!open(
            &reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[short_id],
            ts_min + skew_min + 1,
            skew_min
        ));
    }

    #[test]
    fn tampered_session_id_is_rejected() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [5u8; 8];
        let now = 1_000_000u64;

        let mut session_id = seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        session_id[0] ^= 0xFF; // flip a byte

        assert!(!open(
            &reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[short_id],
            now,
            60
        ));
    }

    #[test]
    fn open_recover_returns_ts_and_short_id() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ts_min = 12_345u64;

        let session_id = seal(&reality_pub, &eph_priv, &client_random, short_id, ts_min);
        let got = open_recover(
            &reality_priv,
            &eph_pub,
            &client_random,
            &session_id,
            &[short_id],
            ts_min,
            10,
        );
        assert_eq!(got, Some((short_id, ts_min)));

        // Wrong short_id ⇒ None.
        assert_eq!(
            open_recover(
                &reality_priv,
                &eph_pub,
                &client_random,
                &session_id,
                &[[0u8; 8]],
                ts_min,
                10,
            ),
            None
        );
    }

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
        use p256::ecdsa::{
            signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey,
        };
        use p256::pkcs8::DecodePrivateKey;
        let d = derive_cert_key(&[7u8; 32]);
        // pkcs8 loads as a signing key; public_sec1 loads as its verifying key;
        // a signature by one verifies under the other → they are a real pair.
        let sk = SigningKey::from_pkcs8_der(&d.pkcs8_der).expect("pkcs8 loads");
        let vk = VerifyingKey::from_sec1_bytes(&d.public_sec1).expect("sec1 loads");
        assert_eq!(vk, *sk.verifying_key());
        let sig: Signature = sk.sign(b"reality-4b probe");
        assert!(vk.verify(b"reality-4b probe", &sig).is_ok());
    }

    #[test]
    fn wrong_length_session_id_is_rejected() {
        let reality_priv = [11u8; 32];
        let eph_pub = [1u8; 32];
        assert!(!open(
            &reality_priv,
            &eph_pub,
            &[0u8; 32],
            &[0u8; 10],
            &[[0u8; 8]],
            0,
            60
        ));
    }
}
