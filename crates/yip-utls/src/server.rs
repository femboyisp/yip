//! REALITY.5b: the relay's server-side TLS 1.3 key exchange for an authed
//! connection — the mirror of `yip_utls`'s client KEX (`stream.rs`). Generates
//! the relay's own ephemeral so the relay holds the session keys, while the
//! `ServerHello` it goes into (see `emit_server_hello`) byte-matches dest's.

use crate::error::Error;
use crate::handshake::{
    derive_handshake_keys, transcript_hash, HandshakeKeys, GROUP_X25519, GROUP_X25519MLKEM768,
    MLKEM768_CIPHERTEXT_LEN,
};
use crate::hello::RandomSource;
use crate::template::ServerHelloShape;
use crate::wire::HelloWriter;
use ml_kem::kem::Encapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

/// The `key_share` extension's registered TLS extension ID (RFC 8446 §4.2.8).
const EXT_KEY_SHARE: u16 = 0x0033;
/// `ServerHello.legacy_version` is fixed at TLS 1.2's wire value for TLS 1.3
/// (the real version is negotiated via `supported_versions`; RFC 8446 §4.1.3).
const LEGACY_VERSION_TLS12: u16 = 0x0303;
/// The `ServerHello` handshake message type (RFC 8446 §4).
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// Bridges the caller's [`RandomSource`] to the `rand_core::CryptoRngCore`
/// bound `ml_kem`'s `Encapsulate` needs. Unlike [`crate::stream`]'s
/// `MlKemRng` (which is hardwired to the OS CSPRNG for `connect`'s
/// production use), this wraps whatever [`RandomSource`] the caller passed
/// `server_key_share` — the OS CSPRNG in production, or a deterministic
/// seeded RNG in tests — so every byte `server_key_share` produces, X25519
/// and ML-KEM alike, is attributable to its one `rng` argument.
struct RandomSourceRng<'a>(&'a mut dyn RandomSource);

impl rand_core::RngCore for RandomSourceRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for RandomSourceRng<'_> {}

/// The relay's server-side KEX for `group`. Returns `(server_key_share_bytes,
/// shared_secret)`: the key_share to put in the `ServerHello`, and the ECDHE
/// secret for `derive_handshake_keys`. `shared_secret` uses REALITY.2's exact
/// combiner (`mlkem_ss ‖ x25519_ss` for 4588 — see `stream.rs`'s client KEX,
/// which this mirrors: the client `decapsulate`s what this `encapsulate`s).
/// Groups other than `4588`/`29` → `Err(UnsupportedGroup)`.
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
            let ek_bytes = client_mlkem_ek.ok_or(Error::Protocol(
                "group 4588 requires the client's ML-KEM ek",
            ))?;
            // Decode the client's encapsulation key, encapsulate against it.
            let encoded =
                ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(ek_bytes)
                    .map_err(|_| Error::Protocol("client ML-KEM ek is the wrong length"))?;
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&encoded);
            let mut kem_rng = RandomSourceRng(rng);
            let (ct, mlkem_ss) = ek
                .encapsulate(&mut kem_rng)
                .map_err(|()| Error::Protocol("ML-KEM encapsulation failed"))?;
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

/// Rebuilds a byte-matching `ServerHello` handshake message from `shape` (the
/// captured structure of a real `dest`'s flight — REALITY.5a) and derives the
/// relay's server-side handshake keys. Every field of `shape` is reproduced
/// VERBATIM (cipher suite, compression method, extension list in wire order
/// incl. any GREASE extension) EXCEPT: a fresh 32-byte `random`, the client's
/// `legacy_session_id` echoed back (per RFC 8446 §4.1.3 — NOT the template's
/// captured session id, which belonged to a different connection), and the
/// `key_share` extension's body, whose key-exchange VALUE is replaced by the
/// relay's own ([`server_key_share`]) so the relay (not the real `dest`) holds
/// the session keys.
///
/// Returns the `ServerHello` handshake message (`0x02 ‖ u24 len ‖ body` — the
/// caller wraps it in a plaintext TLS record) and the [`HandshakeKeys`]
/// derived over `transcript_hash(client_hello_msg ‖ server_hello_msg,
/// shape.cipher_suite)`. A real [`crate::stream`]-style client that parses
/// this message and runs its own key exchange against the embedded
/// `key_share` derives the IDENTICAL keys (proven by this module's
/// round-trip tests) — the crux correctness property of REALITY.5b.
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

    if client_legacy_session_id.len() > usize::from(u8::MAX) {
        return Err(Error::Protocol(
            "client legacy_session_id exceeds 255 bytes",
        ));
    }

    let mut body = HelloWriter::new();
    body.u16(LEGACY_VERSION_TLS12);
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    body.bytes(&random);
    // legacy_session_id_echo: echo the client's, per RFC 8446 §4.1.3 — NOT
    // the shape's captured (different-connection) session id.
    body.u8_prefixed(|w| w.bytes(client_legacy_session_id));
    body.u16(shape.cipher_suite);
    body.u8(shape.legacy_compression_method);
    // Extensions, verbatim from the shape EXCEPT key_share (relay's value).
    body.u16_prefixed(|w| {
        for (id, ext_body) in &shape.extensions {
            w.u16(*id);
            if *id == EXT_KEY_SHARE {
                // ServerHello key_share ext body: group(2) ‖ u16 key_len ‖
                // key — the exact layout `parse_server_hello` reads.
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

    // Wrap as a handshake message: 0x02 ‖ u24 len ‖ body. The length is a u24,
    // so guard against the u24 ceiling (0xFF_FFFF) — NOT u32::MAX — or the high
    // byte would be silently dropped, emitting a truncated length.
    if body.len() > 0xFF_FFFF {
        return Err(Error::Protocol("ServerHello body exceeds u24"));
    }
    let mut sh_msg = Vec::with_capacity(4 + body.len());
    sh_msg.push(HANDSHAKE_TYPE_SERVER_HELLO);
    let len =
        u32::try_from(body.len()).map_err(|_| Error::Protocol("ServerHello body exceeds u24"))?;
    sh_msg.extend_from_slice(&len.to_be_bytes()[1..]);
    sh_msg.extend_from_slice(&body);

    // Derive keys over transcript = ClientHello ‖ ServerHello (both full
    // handshake messages, not records).
    let mut transcript = Vec::with_capacity(client_hello_msg.len() + sh_msg.len());
    transcript.extend_from_slice(client_hello_msg);
    transcript.extend_from_slice(&sh_msg);
    let th = transcript_hash(&transcript, shape.cipher_suite);
    let keys = derive_handshake_keys(&shared, &th, shape.cipher_suite);
    Ok((sh_msg, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::RandomSource;
    use crate::template::ServerHelloShape;
    use ml_kem::kem::Decapsulate;

    /// A deterministic test RNG (mirrors the one `hello.rs`/`stream.rs` tests
    /// use): fills every buffer with a counting byte sequence starting at the
    /// given seed.
    struct SeqRng(u8);
    impl RandomSource for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    /// A `ServerHelloShape` fixture: cipher `TLS_AES_128_GCM_SHA256`, ordered
    /// extensions `supported_versions ‖ key_share(group) ‖ GREASE` (the
    /// `key_share` body's group matches `group`; its key bytes are a dummy
    /// placeholder — `emit_server_hello` substitutes the relay's own value).
    fn shape_fixture(group: u16) -> ServerHelloShape {
        let key_len: u16 = if group == GROUP_X25519MLKEM768 {
            u16::try_from(MLKEM768_CIPHERTEXT_LEN + 32).expect("fits u16")
        } else {
            32
        };
        let mut key_share_body = Vec::new();
        key_share_body.extend_from_slice(&group.to_be_bytes());
        key_share_body.extend_from_slice(&key_len.to_be_bytes());
        key_share_body.extend(std::iter::repeat_n(0xAB, usize::from(key_len)));

        ServerHelloShape {
            cipher_suite: 0x1301,
            legacy_compression_method: 0x00,
            extensions: vec![
                (0x002b_u16, vec![0x03, 0x04]), // supported_versions -> TLS 1.3
                (0x0033_u16, key_share_body),   // key_share
                (0x2a2a_u16, vec![]),           // GREASE, empty
            ],
            key_share_group: group,
        }
    }

    #[test]
    fn emit_server_hello_roundtrips_x25519() {
        roundtrip(0x001d);
    }
    #[test]
    fn emit_server_hello_roundtrips_4588() {
        roundtrip(4588);
    }

    fn roundtrip(group: u16) {
        // Client keypairs (as `stream::connect` generates them).
        let mut mlkem_rng = crate::stream::MlKemRng::default();
        let (client_dk, client_ek) = MlKem768::generate(&mut mlkem_rng);
        let client_ek_bytes = client_ek.as_bytes().to_vec();
        let mut cx = [0u8; 32];
        SeqRng(3).fill(&mut cx);
        let client_secret = x25519_dalek::StaticSecret::from(cx);
        let client_x_pub = x25519_dalek::PublicKey::from(&client_secret).to_bytes();

        let shape = shape_fixture(group);
        let client_hello_msg = vec![0x01, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let sid = vec![0x11; 32];

        let mek = if group == 4588 {
            Some(client_ek_bytes.as_slice())
        } else {
            None
        };
        let (sh_msg, server_keys) = emit_server_hello(
            &shape,
            &client_hello_msg,
            &sid,
            &client_x_pub,
            mek,
            &mut SeqRng(1),
        )
        .unwrap();

        // CLIENT side (the round-trip proof): parse the emitted ServerHello,
        // run the client KEX (decapsulate/DH), combine, derive — must match.
        let shi = crate::handshake::parse_server_hello(&sh_msg[..]).unwrap();
        let ecdhe: Vec<u8> = if group == 4588 {
            let (ct, sx) = shi.server_key_share.split_at(1088);
            let ciphertext = ct.try_into().unwrap();
            let mlkem_ss = client_dk.decapsulate(&ciphertext).unwrap();
            let sxp: [u8; 32] = sx.try_into().unwrap();
            let x_ss = client_secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(sxp))
                .to_bytes();
            [&mlkem_ss[..], &x_ss[..]].concat()
        } else {
            let sxp: [u8; 32] = shi.server_key_share.as_slice().try_into().unwrap();
            client_secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(sxp))
                .to_bytes()
                .to_vec()
        };
        let mut transcript = client_hello_msg.clone();
        transcript.extend_from_slice(&sh_msg);
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
        let shape = shape_fixture(0x001d);
        let client_hello_msg = vec![0x01, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let sid = vec![0x22; 32];
        let client_x_pub = [5u8; 32];

        let (sh_msg, _keys) = emit_server_hello(
            &shape,
            &client_hello_msg,
            &sid,
            &client_x_pub,
            None,
            &mut SeqRng(1),
        )
        .unwrap();

        // Re-parse via parse_server_hello_shape: cipher/compression/extension
        // order (incl. GREASE) must equal the source shape.
        let parsed = crate::handshake::parse_server_hello_shape(&sh_msg).unwrap();
        assert_eq!(parsed.cipher_suite, shape.cipher_suite);
        assert_eq!(
            parsed.legacy_compression_method,
            shape.legacy_compression_method
        );
        assert_eq!(parsed.key_share_group, shape.key_share_group);
        let parsed_ids: Vec<u16> = parsed.extensions.iter().map(|(id, _)| *id).collect();
        let shape_ids: Vec<u16> = shape.extensions.iter().map(|(id, _)| *id).collect();
        assert_eq!(parsed_ids, shape_ids);

        // Every extension body matches the shape verbatim EXCEPT key_share
        // (the relay's own value replaces the captured placeholder).
        for ((pid, pbody), (sid_ext, sbody)) in
            parsed.extensions.iter().zip(shape.extensions.iter())
        {
            assert_eq!(pid, sid_ext);
            if *pid == 0x0033 {
                assert_ne!(pbody, sbody, "key_share body must be the relay's own value");
            } else {
                assert_eq!(pbody, sbody);
            }
        }

        // legacy_session_id_echo equals the client's, not the (nonexistent)
        // template session_id. ServerHello body layout: handshake
        // header(4) ‖ legacy_version(2) ‖ random(32) ‖ sid_len(1) ‖ sid.
        let sid_len = usize::from(sh_msg[4 + 2 + 32]);
        let sid_start = 4 + 2 + 32 + 1;
        assert_eq!(&sh_msg[sid_start..sid_start + sid_len], sid.as_slice());
    }

    #[test]
    fn server_key_share_x25519_shapes() {
        let client_x = [7u8; 32];
        let (ks, ss) = server_key_share(0x001d, &client_x, None, &mut SeqRng(1)).unwrap();
        assert_eq!(ks.len(), 32); // server x25519 public
        assert_eq!(ss.len(), 32); // x25519 shared
    }

    #[test]
    fn server_key_share_4588_shapes() {
        // A real client ML-KEM ek (generate one, as the client does).
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let mut r = crate::stream::MlKemRng::default();
        let (_dk, ek) = MlKem768::generate(&mut r);
        let ek_bytes = ek.as_bytes().to_vec();
        let client_x = [9u8; 32];
        let (ks, ss) = server_key_share(4588, &client_x, Some(&ek_bytes), &mut SeqRng(1)).unwrap();
        assert_eq!(ks.len(), 1088 + 32); // ct ‖ x25519 public
        assert_eq!(ss.len(), 64); // mlkem_ss(32) ‖ x25519_ss(32)
    }

    #[test]
    fn server_key_share_rejects_unsupported_group_and_missing_ek() {
        assert!(matches!(
            server_key_share(23, &[0; 32], None, &mut SeqRng(1)),
            Err(Error::UnsupportedGroup(23))
        ));
        assert!(server_key_share(4588, &[0; 32], None, &mut SeqRng(1)).is_err());
        // 4588 needs ek
    }
}
