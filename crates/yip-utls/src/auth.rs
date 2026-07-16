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
pub fn open_recover(
    reality_priv: &[u8; 32],
    eph_pub: &[u8; 32],
    client_random: &[u8; 32],
    session_id: &[u8],
    short_ids: &[[u8; 8]],
    now_min: u64,
    skew_min: u64,
) -> Option<([u8; 8], u64)> {
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

    Some((short_id, ts_min))
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
