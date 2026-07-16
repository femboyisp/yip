//! REALITY-style TLS front: a pure, unit-testable TLS 1.3 `ClientHello`
//! parser plus the REALITY auth check that lets a relay distinguish an
//! authenticated client from an active prober *before* terminating TLS.
//!
//! Both halves are pure/sync (no networking): the parser turns raw handshake
//! bytes into structured fields (fail-closed — malformed/truncated/attacker
//! input yields `None`, never a panic), and the auth check verifies a
//! ChaCha20-Poly1305 seal carried in `legacy_session_id`, keyed by an X25519
//! ECDH between the client's ephemeral key-share and the relay's REALITY
//! private key. The seal/open codec itself lives in `yip_utls::auth`
//! (REALITY.2 Task 5) — shared with the `yip-utls` client so the seal the
//! client writes is byte-identical to what this server opens. Wired into the
//! async TLS front by `tls_front::run_reality_conn` (REALITY.1 Task 3).

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
    // The declared body must EXACTLY fill the rest of the buffer (this parser
    // handles one already-defragmented handshake message, not a stream):
    // reject trailing bytes rather than silently ignoring them (fail-closed).
    // `4 + body_len` cannot overflow — `body_len` is a u24 (≤ 0xFF_FFFF).
    if 4 + body_len != msg.len() {
        return None;
    }
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

/// Length of the sealed `legacy_session_id`: matches
/// `yip_utls::auth`'s 16-byte plaintext + 16-byte ChaCha20-Poly1305 tag.
/// Kept here only as a documented literal for this module's tests.
#[cfg(test)]
const SESSION_ID_LEN: usize = 32;

/// Like [`reality_auth_open`] but returns the recovered `ts_min` on success
/// (for the anti-replay cross-restart belt). `None` ⇒ not authenticated.
///
/// Fail-closed: any missing key-share, wrong-length session id, failed AEAD
/// open, unknown short_id, or out-of-skew timestamp returns `None`. Delegates
/// to `yip_utls::auth::open_recover` (REALITY.2 Task 5) — the shared codec
/// also used by the `yip-utls` client's seal, so this server accepts exactly
/// what that client produces.
pub fn reality_auth_recover(
    reality_priv: &[u8; 32],
    info: &ClientHelloInfo,
    short_ids: &[[u8; 8]],
    now_unix_min: u64,
    skew_min: u64,
) -> Option<u64> {
    let eph_pub = info.key_share_x25519?;
    yip_utls::auth::open_recover(
        reality_priv,
        &eph_pub,
        &info.client_random,
        &info.legacy_session_id,
        short_ids,
        now_unix_min,
        skew_min,
    )
    .map(|(_short_id, ts_min)| ts_min)
}

/// Server-side REALITY auth check. True iff `info.legacy_session_id` opens
/// under the shared key derived from `reality_priv` and the ClientHello's
/// x25519 key-share, AND the recovered `short_id` is in `short_ids`, AND
/// `|ts_min - now_unix_min| <= skew_min`.
///
/// Fail-closed: any missing key-share, wrong-length session id, failed AEAD
/// open, unknown short_id, or out-of-skew timestamp returns `false`. A bool
/// wrapper over [`reality_auth_recover`].
pub fn reality_auth_open(
    reality_priv: &[u8; 32],
    info: &ClientHelloInfo,
    short_ids: &[[u8; 8]],
    now_unix_min: u64,
    skew_min: u64,
) -> bool {
    reality_auth_recover(reality_priv, info, short_ids, now_unix_min, skew_min).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

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

    /// Like `build_client_hello`, but takes the fully-assembled extensions
    /// block verbatim instead of building it from `sni`/`key_share_x25519` —
    /// gives the parser-edge-case tests full control over malformed or
    /// multi-entry extension bytes that `build_client_hello`'s API can't
    /// express (REALITY.1 Task 5, deferred parser coverage).
    fn build_client_hello_with_raw_exts(
        client_random: [u8; 32],
        session_id: &[u8],
        raw_exts: &[u8],
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
        body.extend_from_slice(&u16::try_from(raw_exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(raw_exts);

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

    /// The interop proof for REALITY.2 Task 5: seal via `yip_utls::auth::seal`
    /// (the client-side codec) into an authed `ClientHelloInfo`, then assert
    /// this server's `reality_auth_open` accepts it end-to-end — proving the
    /// client seal opens on the server path with the shared `yip_utls::auth`
    /// codec, not just within `yip-utls`'s own same-crate round-trip test.
    #[test]
    fn client_seal_from_yip_utls_auth_opens_on_the_server_path() {
        let reality_priv = [11u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [22u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [33u8; 32];
        let short_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let now = 1_000_000u64;

        let session_id =
            yip_utls::auth::seal(&reality_pub, &eph_priv, &client_random, short_id, now);
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

        let session_id =
            yip_utls::auth::seal(&reality_pub, &eph_priv, &client_random, short_id, now);
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

        let session_id =
            yip_utls::auth::seal(&reality_pub, &eph_priv, &client_random, short_id, ts_min);
        let info = ClientHelloInfo {
            sni: None,
            client_random,
            legacy_session_id: session_id.to_vec(),
            key_share_x25519: Some(eph_pub),
        };

        // Client clock in the PAST (now > ts): at the boundary accepted, past it rejected.
        assert!(reality_auth_open(
            &reality_priv,
            &info,
            &[short_id],
            ts_min + skew_min,
            skew_min
        ));
        assert!(!reality_auth_open(
            &reality_priv,
            &info,
            &[short_id],
            ts_min + skew_min + 1,
            skew_min
        ));
        // Client clock in the FUTURE (now < ts): at the boundary accepted, past it
        // rejected. Guards the unsigned-underflow trap — a regression from
        // `abs_diff` to a naive `ts - now` would wrap and wrongly accept/reject here.
        assert!(reality_auth_open(
            &reality_priv,
            &info,
            &[short_id],
            ts_min - skew_min,
            skew_min
        ));
        assert!(!reality_auth_open(
            &reality_priv,
            &info,
            &[short_id],
            ts_min - skew_min - 1,
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

        let mut session_id =
            yip_utls::auth::seal(&reality_pub, &eph_priv, &client_random, short_id, now);
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

        let session_id =
            yip_utls::auth::seal(&reality_pub, &eph_priv, &client_random, short_id, now);
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

    // ---- Part C: parse -> auth end-to-end on a realistic sealed hello
    // (REALITY.1 Task 5, Test 2) ----

    /// Parses AND authenticates a byte-accurate ClientHello whose
    /// `legacy_session_id` is a real `yip_utls::auth::seal` output and whose
    /// `key_share` carries the matching ephemeral public key — proves
    /// `parse_client_hello` -> `reality_auth_open` end-to-end on realistic
    /// wire bytes, not just a hand-set `ClientHelloInfo`.
    #[test]
    fn parses_and_authenticates_a_realistic_sealed_client_hello() {
        let reality_priv = [21u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let eph_priv = [23u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [44u8; 32];
        let short_id = [9u8; 8];
        let now = 2_000_000u64;

        let session_id =
            yip_utls::auth::seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        let msg = build_client_hello(
            client_random,
            &session_id,
            Some("example.com"),
            Some(eph_pub),
        );

        let info = parse_client_hello(&msg).expect("realistic sealed ClientHello must parse");
        assert!(reality_auth_open(
            &reality_priv,
            &info,
            &[short_id],
            now,
            10
        ));
    }

    /// Same realistic hello as above, but authenticated against the WRONG
    /// REALITY private key: must be rejected (the ECDH shared secret differs,
    /// so the AEAD open fails).
    #[test]
    fn realistic_sealed_client_hello_rejected_under_wrong_reality_key() {
        let reality_priv = [21u8; 32];
        let reality_pub = pubkey_of(&reality_priv);
        let wrong_reality_priv = [99u8; 32];
        let eph_priv = [23u8; 32];
        let eph_pub = pubkey_of(&eph_priv);
        let client_random = [44u8; 32];
        let short_id = [9u8; 8];
        let now = 2_000_000u64;

        let session_id =
            yip_utls::auth::seal(&reality_pub, &eph_priv, &client_random, short_id, now);
        let msg = build_client_hello(
            client_random,
            &session_id,
            Some("example.com"),
            Some(eph_pub),
        );

        let info = parse_client_hello(&msg).expect("realistic sealed ClientHello must parse");
        assert!(!reality_auth_open(
            &wrong_reality_priv,
            &info,
            &[short_id],
            now,
            10
        ));
    }

    // ---- Part D: deferred parser-edge coverage (REALITY.1 Task 5, Test 3) ----

    /// A `key_share` entry with the x25519 group but `key_len != 32` must be
    /// ignored (not force-cast into a 32-byte key), yielding
    /// `key_share_x25519 == None` — but the rest of the hello still parses.
    #[test]
    fn key_share_entry_with_wrong_length_yields_no_key_share() {
        let mut entry = Vec::new();
        entry.extend_from_slice(&super::GROUP_X25519.to_be_bytes());
        entry.extend_from_slice(&16u16.to_be_bytes()); // key_len = 16, not 32
        entry.extend_from_slice(&[0xABu8; 16]);

        let mut ks_body = Vec::new();
        ks_body.extend_from_slice(&u16::try_from(entry.len()).unwrap().to_be_bytes());
        ks_body.extend_from_slice(&entry);

        let mut exts = Vec::new();
        exts.extend_from_slice(&super::EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(ks_body.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&ks_body);

        let msg = build_client_hello_with_raw_exts([1u8; 32], &[2u8; 32], &exts);
        let info = parse_client_hello(&msg)
            .expect("a wrong-length key_share entry must not fail the whole parse");
        assert_eq!(info.key_share_x25519, None);
    }

    /// `key_share` may carry several supported-group entries; the x25519 one
    /// need not be first. `parse_key_share_x25519` must keep scanning past a
    /// non-x25519 entry and still find the x25519 key.
    #[test]
    fn key_share_x25519_entry_after_non_x25519_entry_is_found() {
        const GROUP_SECP256R1: u16 = 0x0017;
        let other_key = [0xCCu8; 65]; // arbitrary non-x25519 entry content
        let x25519_key = [0x42u8; 32];

        let mut entries = Vec::new();
        entries.extend_from_slice(&GROUP_SECP256R1.to_be_bytes());
        entries.extend_from_slice(&u16::try_from(other_key.len()).unwrap().to_be_bytes());
        entries.extend_from_slice(&other_key);
        entries.extend_from_slice(&super::GROUP_X25519.to_be_bytes());
        entries.extend_from_slice(&32u16.to_be_bytes());
        entries.extend_from_slice(&x25519_key);

        let mut ks_body = Vec::new();
        ks_body.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_be_bytes());
        ks_body.extend_from_slice(&entries);

        let mut exts = Vec::new();
        exts.extend_from_slice(&super::EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(ks_body.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&ks_body);

        let msg = build_client_hello_with_raw_exts([3u8; 32], &[4u8; 32], &exts);
        let info = parse_client_hello(&msg).expect("multi-entry key_share must parse");
        assert_eq!(info.key_share_x25519, Some(x25519_key));
    }

    /// A `server_name` whose bytes aren't valid UTF-8 must yield `sni ==
    /// None` (not an error/panic), while the rest of `ClientHelloInfo` still
    /// parses (`Some`).
    #[test]
    fn invalid_utf8_server_name_yields_no_sni_but_still_parses() {
        let name_bytes: &[u8] = &[0xFF, 0xFE, 0x00, 0x01]; // not valid UTF-8
        let name_len = u16::try_from(name_bytes.len()).unwrap();
        let list_len = name_len + 3;

        let mut sn_body = Vec::new();
        sn_body.extend_from_slice(&list_len.to_be_bytes());
        sn_body.push(0); // name_type = host_name
        sn_body.extend_from_slice(&name_len.to_be_bytes());
        sn_body.extend_from_slice(name_bytes);

        let mut exts = Vec::new();
        exts.extend_from_slice(&super::EXT_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(sn_body.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&sn_body);

        let msg = build_client_hello_with_raw_exts([5u8; 32], &[6u8; 32], &exts);
        let info =
            parse_client_hello(&msg).expect("invalid-UTF-8 SNI must not fail the whole parse");
        assert_eq!(info.sni, None);
    }

    /// An extension whose declared `ext_len` overruns the extensions block —
    /// while the outer u24 body length is internally consistent (matches the
    /// actual message length) — must be rejected, not silently truncated or
    /// panicked on.
    #[test]
    fn extension_len_overrunning_extensions_block_is_rejected() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x1234u16.to_be_bytes()); // arbitrary unknown ext type
        exts.extend_from_slice(&100u16.to_be_bytes()); // ext_len claims 100 bytes...
                                                       // ...but `exts` ends here: no body bytes actually follow.

        let msg = build_client_hello_with_raw_exts([7u8; 32], &[8u8; 32], &exts);
        assert_eq!(parse_client_hello(&msg), None);
    }
}
