//! REALITY-style TLS front: a pure, unit-testable TLS 1.3 `ClientHello`
//! parser plus the REALITY auth check that lets a relay distinguish an
//! authenticated client from an active prober *before* terminating TLS.
//!
//! Both halves are pure/sync (no networking): the parser turns raw handshake
//! bytes into structured fields (fail-closed — malformed/truncated/attacker
//! input yields `None`, never a panic), and the auth check verifies a
//! ChaCha20-Poly1305 seal carried in `legacy_session_id`, keyed by an X25519
//! ECDH between the client's ephemeral key-share and the relay's REALITY
//! private key. Later tasks wire this into the async TLS front.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "REALITY.1 Task 1: pure parser + auth core, exercised by its own unit tests; \
                   not yet called from main.rs — later tasks wire it into the async TLS front"
    )
)]
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ring::hkdf;
use x25519_dalek::{PublicKey, StaticSecret};

/// The fields of a TLS 1.3 `ClientHello` this front needs. Anything not
/// listed here (cipher suites, compression methods, other extensions) is
/// parsed only far enough to skip past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// The `server_name` extension's host, if present and valid UTF-8.
    pub sni: Option<String>,
    /// The 32-byte `random` field.
    pub client_random: [u8; 32],
    /// The `legacy_session_id` field (TLS 1.3 compatibility session id).
    /// Carries the REALITY auth seal when present and 32 bytes long.
    pub legacy_session_id: Vec<u8>,
    /// The x25519 (group `0x001d`) entry from the `key_share` extension, if
    /// present and exactly 32 bytes.
    pub key_share_x25519: Option<[u8; 32]>,
}

/// TLS extension type for `server_name` (SNI).
const EXT_SERVER_NAME: u16 = 0x0000;
/// TLS extension type for `key_share`.
const EXT_KEY_SHARE: u16 = 0x0033;
/// Named group id for x25519 in `key_share` entries.
const GROUP_X25519: u16 = 0x001d;
/// `HandshakeType::client_hello`.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Parse a single TLS handshake-record payload (the fragment of a record
/// whose `ContentType` was 22/handshake) as a TLS 1.3 `ClientHello`.
///
/// Fail-closed: returns `None` on any malformed, truncated, or
/// out-of-bounds input. Never panics on attacker-controlled bytes — every
/// slice access goes through `.get(..)?`, never direct indexing.
pub fn parse_client_hello(msg: &[u8]) -> Option<ClientHelloInfo> {
    let &handshake_type = msg.first()?;
    if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }
    let len_bytes = msg.get(1..4)?;
    let body_len = u24_be(len_bytes)?;
    // The declared body must exactly fill the rest of the buffer (this
    // parser handles one already-defragmented handshake message, not a
    // stream), and everything we read below stays inside it.
    let body = msg.get(4..4 + body_len)?;

    // legacy_version (2 bytes): present but unchecked — TLS 1.3
    // ClientHellos always set it to 0x0303 for middlebox compatibility, and
    // rejecting on it would just make the parser easier to fingerprint.
    let rest = body.get(2..)?;

    let client_random: [u8; 32] = rest.get(..32)?.try_into().ok()?;
    let rest = rest.get(32..)?;

    let &sidlen = rest.first()?;
    let sidlen = usize::from(sidlen);
    let legacy_session_id = rest.get(1..1 + sidlen)?.to_vec();
    let rest = rest.get(1 + sidlen..)?;

    // cipher_suites: u16 length prefix, skip the body.
    let cs_len = u16_be(rest.get(..2)?)?;
    let rest = rest.get(2 + usize::from(cs_len)..)?;

    // compression_methods: u8 length prefix, skip the body.
    let &cm_len = rest.first()?;
    let rest = rest.get(1 + usize::from(cm_len)..)?;

    // extensions: u16 length prefix, then that many bytes of extensions.
    let ext_total_len = usize::from(u16_be(rest.get(..2)?)?);
    let extensions = rest.get(2..2 + ext_total_len)?;

    let (sni, key_share_x25519) = parse_extensions(extensions)?;

    Some(ClientHelloInfo {
        sni,
        client_random,
        legacy_session_id,
        key_share_x25519,
    })
}

/// Walk the extensions block, extracting `server_name` and `key_share`
/// (x25519 entry only). Returns `None` if the block is malformed; a missing
/// extension is not malformed, it's just absent from the returned tuple.
fn parse_extensions(mut buf: &[u8]) -> Option<(Option<String>, Option<[u8; 32]>)> {
    let mut sni = None;
    let mut key_share_x25519 = None;
    while !buf.is_empty() {
        let ext_type = u16_be(buf.get(..2)?)?;
        let ext_len = usize::from(u16_be(buf.get(2..4)?)?);
        let ext_body = buf.get(4..4 + ext_len)?;
        match ext_type {
            EXT_SERVER_NAME => sni = parse_server_name(ext_body),
            EXT_KEY_SHARE => key_share_x25519 = parse_key_share_x25519(ext_body),
            _ => {}
        }
        buf = buf.get(4 + ext_len..)?;
    }
    Some((sni, key_share_x25519))
}

/// Parse a `server_name` extension body: `list_len(u16) | name_type(u8) |
/// name_len(u16) | name_bytes`. Only the first (and per-spec, only) entry is
/// read. Returns `None` for a malformed body, or if the type isn't
/// `host_name (0)`, or if the bytes aren't valid UTF-8 — SNI is then treated
/// as absent, but the caller still returns the rest of the `ClientHelloInfo`.
fn parse_server_name(body: &[u8]) -> Option<String> {
    let _list_len = u16_be(body.get(..2)?)?;
    let &name_type = body.get(2)?;
    if name_type != 0 {
        return None;
    }
    let name_len = usize::from(u16_be(body.get(3..5)?)?);
    let name_bytes = body.get(5..5 + name_len)?;
    std::str::from_utf8(name_bytes).ok().map(str::to_owned)
}

/// Parse a `key_share` (ClientHello) extension body: `client_shares_len(u16)
/// | entries...`, each entry `group(u16) | key_len(u16) | key_bytes`. Finds
/// the x25519 (`0x001d`) entry whose key is exactly 32 bytes.
fn parse_key_share_x25519(body: &[u8]) -> Option<[u8; 32]> {
    let shares_len = usize::from(u16_be(body.get(..2)?)?);
    let mut entries = body.get(2..2 + shares_len)?;
    while !entries.is_empty() {
        let group = u16_be(entries.get(..2)?)?;
        let key_len = usize::from(u16_be(entries.get(2..4)?)?);
        let key_bytes = entries.get(4..4 + key_len)?;
        if group == GROUP_X25519 {
            if let Ok(key) = <[u8; 32]>::try_from(key_bytes) {
                return Some(key);
            }
        }
        entries = entries.get(4 + key_len..)?;
    }
    None
}

/// Big-endian `u16` from exactly 2 bytes.
fn u16_be(b: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(b.try_into().ok()?))
}

/// Big-endian `u24` from exactly 3 bytes, widened to `usize`.
fn u24_be(b: &[u8]) -> Option<usize> {
    let [a, b0, c] = <[u8; 3]>::try_from(b).ok()?;
    Some((usize::from(a) << 16) | (usize::from(b0) << 8) | usize::from(c))
}

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

/// Server-side REALITY auth check. True iff `info.legacy_session_id` opens
/// under the shared key derived from `reality_priv` and the ClientHello's
/// x25519 key-share, AND the recovered `short_id` is in `short_ids`, AND
/// `|ts_min - now_unix_min| <= skew_min`.
///
/// Fail-closed: any missing key-share, wrong-length session id, failed AEAD
/// open, unknown short_id, or out-of-skew timestamp returns `false`.
pub fn reality_auth_open(
    reality_priv: &[u8; 32],
    info: &ClientHelloInfo,
    short_ids: &[[u8; 8]],
    now_unix_min: u64,
    skew_min: u64,
) -> bool {
    let Some(client_pub) = info.key_share_x25519 else {
        return false;
    };
    if info.legacy_session_id.len() != SESSION_ID_LEN {
        return false;
    }

    let secret = StaticSecret::from(*reality_priv);
    let shared = secret.diffie_hellman(&PublicKey::from(client_pub));
    let aead_key = derive_aead_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .expect("aead_key is exactly 32 bytes, ChaCha20Poly1305's required key length");
    let Some(nonce_bytes) = info.client_random.get(..12) else {
        return false;
    };
    let nonce = Nonce::from_slice(nonce_bytes);

    let Ok(plaintext) = cipher.decrypt(
        nonce,
        Payload {
            msg: &info.legacy_session_id,
            aad: b"",
        },
    ) else {
        return false;
    };
    if plaintext.len() != PLAINTEXT_LEN {
        return false;
    }

    let Some(short_id) = plaintext.get(..8).and_then(|s| <[u8; 8]>::try_from(s).ok()) else {
        return false;
    };
    let Some(ts_bytes) = plaintext
        .get(8..16)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
    else {
        return false;
    };
    let ts_min = u64::from_le_bytes(ts_bytes);

    if !short_ids.contains(&short_id) {
        return false;
    }

    ts_min.abs_diff(now_unix_min) <= skew_min
}

/// Inverse of `reality_auth_open`, for tests (and the REALITY.2 client
/// later): produce the 32-byte `legacy_session_id` that `reality_auth_open`
/// accepts for the given `reality_pub`/`eph_priv` ECDH pair, `short_id`, and
/// `ts_min`.
#[cfg(test)]
pub fn reality_seal(
    reality_pub: &[u8; 32],
    eph_priv: &[u8; 32],
    client_random: &[u8; 32],
    short_id: [u8; 8],
    ts_min: u64,
) -> [u8; 32] {
    let secret = StaticSecret::from(*eph_priv);
    let shared = secret.diffie_hellman(&PublicKey::from(*reality_pub));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// x25519 base-point scalar multiplication, used only by tests to derive
    /// a public key from a raw private scalar (mirrors what a real client
    /// would compute for its ephemeral key-share).
    fn pubkey_of(priv_key: &[u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(*priv_key)).as_bytes()
    }

    /// Build a minimal, well-formed TLS 1.3 ClientHello handshake-record
    /// payload: legacy_version, random, session_id, one cipher suite, no
    /// compression, and (optionally) `server_name` / `key_share` extensions.
    fn build_client_hello(
        client_random: [u8; 32],
        session_id: &[u8],
        sni: Option<&str>,
        key_share_x25519: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&client_random);
        body.push(u8::try_from(session_id.len()).unwrap());
        body.extend_from_slice(session_id);
        // cipher_suites: one suite (TLS_AES_128_GCM_SHA256).
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        // compression_methods: null only.
        body.push(1);
        body.push(0x00);

        let mut exts = Vec::new();
        if let Some(host) = sni {
            let mut ext_body = Vec::new();
            let name_len = u16::try_from(host.len()).unwrap();
            let list_len = name_len + 3;
            ext_body.extend_from_slice(&list_len.to_be_bytes());
            ext_body.push(0); // name_type = host_name
            ext_body.extend_from_slice(&name_len.to_be_bytes());
            ext_body.extend_from_slice(host.as_bytes());

            exts.extend_from_slice(&super::EXT_SERVER_NAME.to_be_bytes());
            exts.extend_from_slice(&u16::try_from(ext_body.len()).unwrap().to_be_bytes());
            exts.extend_from_slice(&ext_body);
        }
        if let Some(key) = key_share_x25519 {
            let mut ext_body = Vec::new();
            let entries_len = 4u16 + 32;
            ext_body.extend_from_slice(&entries_len.to_be_bytes());
            ext_body.extend_from_slice(&super::GROUP_X25519.to_be_bytes());
            ext_body.extend_from_slice(&32u16.to_be_bytes());
            ext_body.extend_from_slice(&key);

            exts.extend_from_slice(&super::EXT_KEY_SHARE.to_be_bytes());
            exts.extend_from_slice(&u16::try_from(ext_body.len()).unwrap().to_be_bytes());
            exts.extend_from_slice(&ext_body);
        }
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);

        let mut msg = Vec::new();
        msg.push(super::HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = u32::try_from(body.len()).unwrap();
        msg.extend_from_slice(&body_len.to_be_bytes()[1..]); // u24 BE
        msg.extend_from_slice(&body);
        msg
    }

    // ---- Part A: parser ----

    #[test]
    fn parses_minimal_client_hello_with_sni_and_key_share() {
        let client_random = [7u8; 32];
        let session_id = [9u8; 32];
        let key_share = [3u8; 32];
        let msg = build_client_hello(
            client_random,
            &session_id,
            Some("example.com"),
            Some(key_share),
        );

        let info = parse_client_hello(&msg).expect("well-formed ClientHello must parse");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.client_random, client_random);
        assert_eq!(info.legacy_session_id, session_id.to_vec());
        assert_eq!(info.key_share_x25519, Some(key_share));
    }

    #[test]
    fn parses_client_hello_missing_optional_extensions() {
        let msg = build_client_hello([1u8; 32], &[2u8; 32], None, None);
        let info = parse_client_hello(&msg).expect("must parse without sni/key_share");
        assert_eq!(info.sni, None);
        assert_eq!(info.key_share_x25519, None);
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse_client_hello(&[]), None);
    }

    #[test]
    fn rejects_one_byte_input() {
        assert_eq!(parse_client_hello(&[0x01]), None);
    }

    #[test]
    fn rejects_session_id_length_lying_past_buffer() {
        let mut msg = build_client_hello([4u8; 32], &[5u8; 32], None, None);
        // The session-id length byte sits right after legacy_version(2) +
        // random(32) in the body, i.e. at msg offset 4 + 2 + 32 = 38.
        msg[38] = 0xFF; // claim a 255-byte session id that isn't there
        assert_eq!(parse_client_hello(&msg), None);
    }

    #[test]
    fn rejects_key_share_len_lying_past_buffer() {
        let mut msg = build_client_hello([6u8; 32], &[8u8; 32], None, Some([1u8; 32]));
        // Corrupt the last byte (part of the 32-byte key) into a huge
        // trailing chunk isn't enough on its own; instead, truncate the
        // message so the key_share extension's declared length overruns.
        let cut = msg.len() - 5;
        msg.truncate(cut);
        assert_eq!(parse_client_hello(&msg), None);
    }

    #[test]
    fn rejects_wrong_handshake_type() {
        let mut msg = build_client_hello([1u8; 32], &[2u8; 32], None, None);
        msg[0] = 0x02; // server_hello, not client_hello
        assert_eq!(parse_client_hello(&msg), None);
    }

    #[test]
    fn rejects_declared_length_overrunning_buffer() {
        let mut msg = build_client_hello([1u8; 32], &[2u8; 32], None, None);
        // Bump the u24 length field so it claims more body than is present.
        msg[3] = 0xFF;
        assert_eq!(parse_client_hello(&msg), None);
    }

    // ---- Part B: REALITY auth ----

    #[test]
    fn seal_then_open_round_trips_with_matching_keys() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let now = 1_000_000u64;

        let session_id = reality_seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        let info = ClientHelloInfo {
            sni: None,
            client_random,
            legacy_session_id: session_id.to_vec(),
            key_share_x25519: Some(eph_pub),
        };

        assert!(reality_auth_open(
            &reality_priv,
            &info,
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

        let session_id = reality_seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        let info = ClientHelloInfo {
            sni: None,
            client_random,
            legacy_session_id: session_id.to_vec(),
            key_share_x25519: Some(eph_pub),
        };

        assert!(!reality_auth_open(
            &reality_priv,
            &info,
            &[other_short_id],
            now,
            60
        ));
    }

    #[test]
    fn stale_timestamp_outside_skew_is_rejected_within_skew_is_accepted() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [4u8; 8];
        let ts_min = 1_000_000u64;
        let skew_min = 5u64;

        let session_id = reality_seal(&reality_pub, &eph_priv, &client_random, short_id, ts_min);
        let info = ClientHelloInfo {
            sni: None,
            client_random,
            legacy_session_id: session_id.to_vec(),
            key_share_x25519: Some(eph_pub),
        };

        // Exactly at the skew boundary: accepted.
        assert!(reality_auth_open(
            &reality_priv,
            &info,
            &[short_id],
            ts_min + skew_min,
            skew_min
        ));
        // One minute past the boundary: rejected.
        assert!(!reality_auth_open(
            &reality_priv,
            &info,
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

        let mut session_id = reality_seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        session_id[0] ^= 0xFF; // flip a byte

        let info = ClientHelloInfo {
            sni: None,
            client_random,
            legacy_session_id: session_id.to_vec(),
            key_share_x25519: Some(eph_pub),
        };

        assert!(!reality_auth_open(
            &reality_priv,
            &info,
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

        let session_id = reality_seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        let info = ClientHelloInfo {
            sni: None,
            client_random,
            legacy_session_id: session_id.to_vec(),
            key_share_x25519: Some(eph_pub),
        };

        assert!(!reality_auth_open(
            &wrong_reality_priv,
            &info,
            &[short_id],
            now,
            60
        ));
    }

    #[test]
    fn missing_key_share_is_rejected() {
        let reality_priv = [11u8; 32];
        let info = ClientHelloInfo {
            sni: None,
            client_random: [0u8; 32],
            legacy_session_id: vec![0u8; SESSION_ID_LEN],
            key_share_x25519: None,
        };
        assert!(!reality_auth_open(&reality_priv, &info, &[[0u8; 8]], 0, 60));
    }

    #[test]
    fn wrong_length_session_id_is_rejected() {
        let reality_priv = [11u8; 32];
        let info = ClientHelloInfo {
            sni: None,
            client_random: [0u8; 32],
            legacy_session_id: vec![0u8; 10], // not 32 bytes
            key_share_x25519: Some([1u8; 32]),
        };
        assert!(!reality_auth_open(&reality_priv, &info, &[[0u8; 8]], 0, 60));
    }
}
