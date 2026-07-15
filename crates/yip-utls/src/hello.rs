//! Deterministic, byte-faithful Chrome-150 TLS ClientHello crafter (REALITY.2
//! Task 3).
//!
//! Every extension's *content* here is fixed to match real Chrome 150
//! captures (see `docs/superpowers/specs/reality-2-chrome150-fingerprint.txt`),
//! with one deliberate, documented exception: `X25519MLKEM768` (`4588`) is
//! dropped from `key_share` (and, to stay consistent, from `supported_groups`
//! too) because this crate can't forge a canonically-valid ML-KEM-768 key —
//! see [`key_share_body`]'s and [`supported_groups_body`]'s doc comments for
//! why sending one anyway got REALITY.2 Task 8's live test killed by real
//! ML-KEM-strict servers. Only the *order* of the real extensions is
//! randomized per connection via a Fisher–Yates shuffle seeded from the
//! caller's [`RandomSource`] — the fingerprint reference documents three real
//! Chrome captures with three different JA3 hashes (order-sensitive) but one
//! stable JA4 (order-insensitive, it sorts): modern Chrome/BoringSSL permutes
//! its ClientHello extension order every connection, keeping one GREASE
//! extension first and one last. A FIXED extension order here would make yip
//! MORE fingerprintable than real Chrome — defeating the point of this
//! crafter.

use crate::wire::HelloWriter;

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const LEGACY_VERSION_TLS12: u16 = 0x0303;

const GROUP_X25519: u16 = 29;
const GROUP_SECP256R1: u16 = 23;
const GROUP_SECP384R1: u16 = 24;

const ECH_ENC_LEN: usize = 32;
const ECH_PAYLOAD_LEN: usize = 160;

const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SCT: u16 = 18;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_ALPS: u16 = 17613;
const EXT_ECH: u16 = 65037;
const EXT_RENEGOTIATION_INFO: u16 = 65281;

/// The fixed cipher suite list (excluding the leading GREASE entry `craft`
/// draws from `rng`), in Chrome-150's exact order.
const CIPHER_SUITES: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

/// Chrome-150's `signature_algorithms` list: 11 entries, including the 3
/// post-quantum ML-DSA algorithms (`0904`,`0905`,`0906`) Chrome 150 added
/// (Chrome 149 has only 8 — see the fingerprint reference's "THIRD CAPTURE"
/// note; this is why we pin to 150).
const SIGNATURE_ALGORITHMS: [u16; 11] = [
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// Supplies randomness to [`craft`]. Implement with a seeded PRNG for
/// byte-reproducible tests, or the OS CSPRNG for production use.
pub trait RandomSource {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Per-connection inputs to [`craft`] that Chrome-150's fixed fingerprint
/// does not itself determine.
pub struct ClientHelloParams {
    pub sni: String,
    pub key_share_x25519_pub: [u8; 32],
    pub legacy_session_id: [u8; 32],
    /// The 32-byte `random` field written into the ClientHello body.
    /// Callers that seal a REALITY auth payload (`auth::seal`) keyed by
    /// `client_random` MUST pass that exact same value here — the server
    /// derives its AEAD nonce from the ClientHello's `random` field, so the
    /// sealed value and the wire value must be identical or the seal will
    /// never open.
    pub client_random: [u8; 32],
}

/// Crafts a byte-faithful Chrome-150 ClientHello **handshake message**
/// (`0x01 ‖ u24 len ‖ body`). GREASE values and the decorative
/// MLKEM768/ECH filler are drawn from `rng`; the 16 real extensions are
/// shuffled into a per-connection order also driven by `rng`. Deterministic:
/// the same `rng` sequence always produces the same bytes.
pub fn craft(params: &ClientHelloParams, rng: &mut dyn RandomSource) -> Vec<u8> {
    let mut body = HelloWriter::new();

    body.u16(LEGACY_VERSION_TLS12);
    body.bytes(&params.client_random);

    body.u8_prefixed(|w| w.bytes(&params.legacy_session_id));

    body.u16_prefixed(|w| {
        w.u16(grease(rng));
        for &cs in &CIPHER_SUITES {
            w.u16(cs);
        }
    });

    body.u8_prefixed(|w| w.u8(0x00)); // compression: null only

    let mut extensions = build_extensions(params, rng);
    shuffle(rng, &mut extensions);

    body.u16_prefixed(|w| {
        write_grease_extension(w, rng);
        for (id, ext_body) in &extensions {
            w.u16(*id);
            w.u16_prefixed(|w| w.bytes(ext_body));
        }
        write_grease_extension(w, rng);
    });

    wrap_handshake_message(body.into_bytes())
}

fn wrap_handshake_message(body: Vec<u8>) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    let len = u32::try_from(body.len()).expect("ClientHello body fits u24");
    msg.extend_from_slice(&len.to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// Builds the 16 real (non-GREASE) extensions as `(id, body)` pairs, in an
/// arbitrary construction order — `craft` shuffles this list before writing
/// it, so this order is never observed on the wire.
///
/// `supported_groups` and `key_share` each carry a leading GREASE entry, and
/// RFC 8701 §3.4 requires those two GREASE values to be the *same* codepoint
/// within one `ClientHello` (real Chrome captures confirm this — see
/// `docs/superpowers/specs/reality-2-chrome150-fingerprint.txt`'s
/// `GREASE(0x7a7a)` appearing in both extensions' comments). Drawing it once
/// here and threading it into both builders — rather than each calling
/// [`grease`] independently — is not just fingerprint fidelity: real TLS 1.3
/// servers (confirmed against Cloudflare, Google, `www.microsoft.com`, and a
/// local `openssl s_server`) cross-check the two and kill the connection
/// with `illegal_parameter`/`decode_error` on a mismatch.
fn build_extensions(params: &ClientHelloParams, rng: &mut dyn RandomSource) -> Vec<(u16, Vec<u8>)> {
    let groups_key_share_grease = grease(rng);
    vec![
        (EXT_SCT, Vec::new()),
        (EXT_ALPS, protocol_list_body(&["h2"])),
        (
            EXT_SUPPORTED_GROUPS,
            supported_groups_body(groups_key_share_grease),
        ),
        (EXT_EC_POINT_FORMATS, ec_point_formats_body()),
        (EXT_PSK_KEY_EXCHANGE_MODES, vec![0x01, 0x01]),
        (EXT_SERVER_NAME, server_name_body(&params.sni)),
        (EXT_ECH, ech_body(rng)),
        (EXT_SESSION_TICKET, Vec::new()),
        (EXT_SIGNATURE_ALGORITHMS, signature_algorithms_body()),
        (EXT_ALPN, protocol_list_body(&["h2", "http/1.1"])),
        (EXT_COMPRESS_CERTIFICATE, compress_certificate_body()),
        (EXT_SUPPORTED_VERSIONS, supported_versions_body(rng)),
        (EXT_RENEGOTIATION_INFO, vec![0x00]),
        (EXT_EXTENDED_MASTER_SECRET, Vec::new()),
        (EXT_STATUS_REQUEST, status_request_body()),
        (
            EXT_KEY_SHARE,
            key_share_body(params, rng, groups_key_share_grease),
        ),
    ]
}

/// `(name_list_len: u16) ‖ (name_len: u8 ‖ name)*` — shared shape of the
/// ALPS (17613) and ALPN (16) extension bodies.
fn protocol_list_body(protocols: &[&str]) -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u16_prefixed(|w| {
        for p in protocols {
            w.u8_prefixed(|w| w.bytes(p.as_bytes()));
        }
    });
    w.into_bytes()
}

/// `supported_groups` (RFC 8446 §4.2.7): GREASE, then the three classical
/// curves this crate actually completes a handshake for. Real Chrome-150
/// also lists `X25519MLKEM768` (`4588`) first — deliberately NOT included
/// here; see [`key_share_body`]'s doc comment for why advertising it without
/// a real ML-KEM-768 key share gets this crate HelloRetryRequest'd (not
/// simply ignored) by ML-KEM-preferring servers like Cloudflare and Google,
/// which this client has no way to complete (no ML-KEM keygen, and REALITY.2
/// is a one-round-trip design — HRR is a second round trip). This is a real,
/// intentional fingerprint gap (JA3's curve list differs from real Chrome-150;
/// JA4 is unaffected — it never hashes `supported_groups` content, only
/// extension IDs/cipher IDs/signature algorithms) traded for actually
/// completing handshakes against real, currently-deployed PQ-preferring
/// TLS 1.3 servers.
fn supported_groups_body(grease_value: u16) -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u16_prefixed(|w| {
        w.u16(grease_value);
        w.u16(GROUP_X25519);
        w.u16(GROUP_SECP256R1);
        w.u16(GROUP_SECP384R1);
    });
    w.into_bytes()
}

fn ec_point_formats_body() -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u8_prefixed(|w| w.u8(0x00));
    w.into_bytes()
}

fn server_name_body(sni: &str) -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u16_prefixed(|w| {
        w.u8(0x00); // name_type = host_name
        w.u16_prefixed(|w| w.bytes(sni.as_bytes()));
    });
    w.into_bytes()
}

/// Decorative Encrypted Client Hello (ECH) "GREASE ECH" filler: a
/// plausibly-shaped outer extension (HPKE cipher suite, config id, KEM
/// `enc`, and an encrypted-payload-sized blob), all drawn from `rng`. Chrome
/// sends real GREASE ECH when it has no ECH config to use; content is
/// opaque, so shape (not exact bytes) is what matters here — EXCEPT the
/// leading `ECHClientHelloType` tag, which ECH-terminating servers (e.g.
/// Cloudflare, Google) actually parse: it MUST be `outer` (`0x00`), which is
/// the only variant carrying the `cipher_suite`/`config_id`/`enc`/`payload`
/// fields this function writes (`inner`, `0x01`, is an empty struct — a real
/// TLS 1.3 server that supports ECH treats `outer` tagged as `inner` with
/// trailing bytes as `decode_error` and kills the connection before
/// `ServerHello`, exactly as real Chrome's GREASE ECH does not do).
fn ech_body(rng: &mut dyn RandomSource) -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u8(0x00); // ECHClientHelloType::outer (draft-ietf-tls-esni)
    w.u16(0x0001); // HPKE KDF: HKDF-SHA256
    w.u16(0x0001); // HPKE AEAD: AES-128-GCM

    let mut config_id = [0u8; 1];
    rng.fill(&mut config_id);
    w.u8(config_id[0]);

    w.u16_prefixed(|w| {
        let mut enc = [0u8; ECH_ENC_LEN];
        rng.fill(&mut enc);
        w.bytes(&enc);
    });
    w.u16_prefixed(|w| {
        let mut payload = vec![0u8; ECH_PAYLOAD_LEN];
        rng.fill(&mut payload);
        w.bytes(&payload);
    });
    w.into_bytes()
}

fn signature_algorithms_body() -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u16_prefixed(|w| {
        for &alg in &SIGNATURE_ALGORITHMS {
            w.u16(alg);
        }
    });
    w.into_bytes()
}

/// `certificate_compression_algorithms<1..2^8-1>` (RFC 8879), one entry:
/// brotli (`0x0002`).
fn compress_certificate_body() -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u8_prefixed(|w| w.u16(0x0002));
    w.into_bytes()
}

fn supported_versions_body(rng: &mut dyn RandomSource) -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u8_prefixed(|w| {
        w.u16(grease(rng));
        w.u16(0x0304); // TLS 1.3
        w.u16(0x0303); // TLS 1.2
    });
    w.into_bytes()
}

/// `status_request` (RFC 6066): OCSP, empty responder-id and extensions
/// lists — `01 0000 0000`.
fn status_request_body() -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u8(0x01); // certificate_status_type = ocsp
    w.u16(0x0000); // responder_id_list length
    w.u16(0x0000); // request_extensions length
    w.into_bytes()
}

/// `key_share` (RFC 8446 §4.2.8): GREASE (1 random byte, the SAME codepoint
/// as `supported_groups`'s leading GREASE entry — see [`build_extensions`]),
/// then X25519 carrying the caller's real public key.
///
/// Real Chrome also sends a THIRD entry here for `X25519MLKEM768` (`4588`),
/// carrying an actual ML-KEM-768 encapsulation key it generated. This crate
/// does not implement ML-KEM keygen, and REALITY.2 Task 8's live test
/// against real servers proved *why* that entry can't just be random filler
/// bytes the way GREASE fillers elsewhere in this module are: unlike GREASE
/// (an intentionally-unknown codepoint every RFC 8701-aware server ignores),
/// group `4588` is a REAL, registered group that Cloudflare and Google's
/// edges actively parse and validate — FIPS 203's `ByteDecode_12` requires
/// each encoded coefficient to be canonically reduced mod `q = 3329`, and a
/// uniformly-random 1184-byte blob fails that check on virtually every
/// connection. Sending a garbage `4588` key_share entry got this crate's
/// ClientHello killed with `decode_error`/`illegal_parameter` by every major
/// ML-KEM-strict server tested (`www.microsoft.com`, which apparently
/// doesn't validate that deeply, was the one exception). `4588` is still
/// listed in `supported_groups` (byte-faithful to real Chrome, and
/// unobserved by JA3/JA4 either way since neither inspects `key_share`
/// content) — the client is just truthfully NOT also offering a key share
/// for it, which RFC 8446 explicitly permits (a client may list more
/// `supported_groups` than it sends optimistic `key_share` entries for).
fn key_share_body(
    params: &ClientHelloParams,
    rng: &mut dyn RandomSource,
    grease_value: u16,
) -> Vec<u8> {
    let mut w = HelloWriter::new();
    w.u16_prefixed(|w| {
        w.u16(grease_value);
        w.u16_prefixed(|w| {
            let mut data = [0u8; 1];
            rng.fill(&mut data);
            w.bytes(&data);
        });

        w.u16(GROUP_X25519);
        w.u16_prefixed(|w| w.bytes(&params.key_share_x25519_pub));
    });
    w.into_bytes()
}

fn write_grease_extension(w: &mut HelloWriter, rng: &mut dyn RandomSource) {
    w.u16(grease(rng));
    w.u16_prefixed(|_| {});
}

/// A GREASE value per RFC 8701: `0x?a?a` with both nibble-pairs equal. Draws
/// one random nibble from `rng` and repeats it in both bytes.
fn grease(rng: &mut dyn RandomSource) -> u16 {
    let mut b = [0u8; 1];
    rng.fill(&mut b);
    let nibble = b[0] & 0x0f;
    let byte = (nibble << 4) | 0x0a;
    u16::from_be_bytes([byte, byte])
}

/// Fisher–Yates shuffle, deterministic given `rng`'s output sequence. This
/// is the mechanism behind Chrome/BoringSSL's per-connection extension-order
/// permutation (see module docs): same seed -> same order every time, but a
/// different seed -> a different order, so JA3 varies connection-to-connection
/// exactly like real Chrome while JA4 (which sorts before hashing) stays
/// stable.
fn shuffle<T>(rng: &mut dyn RandomSource, items: &mut [T]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = rand_index(rng, i + 1);
        items.swap(i, j);
    }
}

/// A uniform-ish index in `0..bound`, computed from 4 random bytes via
/// Lemire's multiply-shift method (no modulo bias, no `as` casts).
fn rand_index(rng: &mut dyn RandomSource, bound: usize) -> usize {
    let mut buf = [0u8; 4];
    rng.fill(&mut buf);
    let val = u64::from(u32::from_be_bytes(buf));
    let bound = u64::try_from(bound).expect("shuffle bound fits u64");
    let scaled = (val * bound) >> 32;
    usize::try_from(scaled).expect("scaled index fits usize")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64 PRNG for reproducible tests. Not
    /// cryptographically secure — that's fine, it's a test double for
    /// [`RandomSource`], not the production implementation.
    struct TestRng(u64);

    impl TestRng {
        fn new(seed: u64) -> Self {
            // xorshift64 requires a non-zero state.
            Self(seed | 1)
        }

        fn next_byte(&mut self) -> u8 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0.to_le_bytes()[0]
        }
    }

    impl RandomSource for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.next_byte();
            }
        }
    }

    fn test_params() -> ClientHelloParams {
        ClientHelloParams {
            sni: "example.com".to_string(),
            key_share_x25519_pub: [0x42; 32],
            legacy_session_id: [0x99; 32],
            client_random: [0x77; 32],
        }
    }

    fn is_grease(v: u16) -> bool {
        (v & 0x0f0f) == 0x0a0a
    }

    /// The 16 real extension ids `craft` must emit exactly once each,
    /// between the leading and trailing GREASE, in SOME per-connection order.
    const REAL_EXT_IDS: [u16; 16] = [
        18, 17613, 10, 11, 45, 0, 65037, 35, 13, 16, 27, 43, 65281, 23, 5, 51,
    ];

    struct Parsed {
        version: u16,
        session_id: Vec<u8>,
        ciphers: Vec<u16>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    /// A minimal parser mirroring the exact layout `craft` writes, used only
    /// to assert structural properties in these tests. (`ja::*` — checked by
    /// Task 4 — keeps its own parser private and is the real fingerprint
    /// cross-check.)
    fn parse(msg: &[u8]) -> Parsed {
        assert_eq!(msg[0], HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = (usize::from(msg[1]) << 16) | (usize::from(msg[2]) << 8) | usize::from(msg[3]);
        let body = &msg[4..4 + len];
        assert_eq!(body.len(), len);

        let version = u16::from_be_bytes([body[0], body[1]]);
        let mut i = 2 + 32; // skip version, client_random

        let sid_len = usize::from(body[i]);
        i += 1;
        let session_id = body[i..i + sid_len].to_vec();
        i += sid_len;

        let cs_len = usize::from(u16::from_be_bytes([body[i], body[i + 1]]));
        i += 2;
        let cs_end = i + cs_len;
        let mut ciphers = Vec::new();
        while i < cs_end {
            ciphers.push(u16::from_be_bytes([body[i], body[i + 1]]));
            i += 2;
        }

        let cm_len = usize::from(body[i]);
        i += 1 + cm_len;

        let ext_total_len = usize::from(u16::from_be_bytes([body[i], body[i + 1]]));
        i += 2;
        let ext_end = i + ext_total_len;
        let mut extensions = Vec::new();
        while i < ext_end {
            let ext_type = u16::from_be_bytes([body[i], body[i + 1]]);
            let ext_len = usize::from(u16::from_be_bytes([body[i + 2], body[i + 3]]));
            let ext_body = body[i + 4..i + 4 + ext_len].to_vec();
            extensions.push((ext_type, ext_body));
            i += 4 + ext_len;
        }
        assert_eq!(i, ext_end);

        Parsed {
            version,
            session_id,
            ciphers,
            extensions,
        }
    }

    fn parse_u16_len16_list(body: &[u8]) -> Vec<u16> {
        let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
        body[2..2 + len]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    fn parse_key_share_entries(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
        let mut i = 2;
        let end = 2 + len;
        let mut out = Vec::new();
        while i < end {
            let group = u16::from_be_bytes([body[i], body[i + 1]]);
            let data_len = usize::from(u16::from_be_bytes([body[i + 2], body[i + 3]]));
            let data = body[i + 4..i + 4 + data_len].to_vec();
            out.push((group, data));
            i += 4 + data_len;
        }
        out
    }

    #[test]
    fn craft_produces_well_formed_chrome150_hello() {
        let params = test_params();
        let mut rng = TestRng::new(0xC0FFEE);
        let msg = craft(&params, &mut rng);
        let parsed = parse(&msg);

        assert_eq!(parsed.version, 0x0303);
        assert_eq!(parsed.session_id, params.legacy_session_id.to_vec());

        // Cipher list: leading GREASE + the fixed 15 -> 16 entries total.
        assert_eq!(parsed.ciphers.len(), 16);
        assert!(is_grease(parsed.ciphers[0]));
        assert_eq!(&parsed.ciphers[1..], &CIPHER_SUITES);

        // Extension count: 16 real + 1 leading GREASE + 1 trailing GREASE.
        assert_eq!(parsed.extensions.len(), 18);
        assert!(is_grease(parsed.extensions.first().unwrap().0));
        assert!(is_grease(parsed.extensions.last().unwrap().0));

        // The 16 real ids appear exactly once each, in SOME order, between
        // the two GREASE bookends -- the whole point of Task 3 is that this
        // order is NOT fixed (see module docs / the permutation finding).
        let mut real_ids: Vec<u16> = parsed.extensions[1..parsed.extensions.len() - 1]
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert!(real_ids.iter().all(|id| !is_grease(*id)));
        real_ids.sort_unstable();
        let mut expected = REAL_EXT_IDS.to_vec();
        expected.sort_unstable();
        assert_eq!(real_ids, expected);

        // supported_groups (ext 10): GREASE,29,23,24. NOT 4588
        // (X25519MLKEM768) — see supported_groups_body's doc comment: this
        // crate deliberately doesn't advertise a group it can't back with a
        // real key share, since ML-KEM-preferring real servers (Cloudflare,
        // Google) respond with a HelloRetryRequest this one-round-trip
        // client can't complete rather than silently accepting X25519.
        let groups_body = &parsed
            .extensions
            .iter()
            .find(|(id, _)| *id == EXT_SUPPORTED_GROUPS)
            .unwrap()
            .1;
        let groups = parse_u16_len16_list(groups_body);
        assert_eq!(groups.len(), 4);
        assert!(is_grease(groups[0]));
        assert_eq!(
            &groups[1..],
            &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]
        );

        // key_share (ext 51): GREASE(1B), 29(our 32B pub). NOT 4588
        // (X25519MLKEM768) — see key_share_body's doc comment: this crate
        // can't forge a canonically-valid ML-KEM-768 key, and real
        // ML-KEM-strict servers (Cloudflare, Google) reject a random one.
        let ks_body = &parsed
            .extensions
            .iter()
            .find(|(id, _)| *id == EXT_KEY_SHARE)
            .unwrap()
            .1;
        let entries = parse_key_share_entries(ks_body);
        assert_eq!(entries.len(), 2);
        assert!(is_grease(entries[0].0));
        assert_eq!(entries[0].1.len(), 1);
        assert_eq!(entries[1].0, GROUP_X25519);
        assert_eq!(entries[1].1, params.key_share_x25519_pub.to_vec());

        // RFC 8701 §3.4: the GREASE codepoint in `key_share`'s leading entry
        // MUST be the SAME value as `supported_groups`'s leading GREASE
        // entry. A mismatch here (independently-drawn GREASE values) is
        // exactly the bug REALITY.2 Task 8's live test against real
        // Cloudflare/Google/Microsoft servers (and a local openssl s_server)
        // exposed: every one of them killed the connection with
        // illegal_parameter/decode_error rather than silently ignoring the
        // unrecognized-but-inconsistent GREASE group.
        assert_eq!(
            groups[0], entries[0].0,
            "supported_groups and key_share must share one GREASE codepoint (RFC 8701 §3.4)"
        );
    }

    #[test]
    fn craft_is_deterministic_for_a_fixed_seed() {
        let params = test_params();
        let a = craft(&params, &mut TestRng::new(42));
        let b = craft(&params, &mut TestRng::new(42));
        assert_eq!(a, b);
    }

    #[test]
    fn craft_permutes_extension_order_across_seeds() {
        let params = test_params();
        let a = craft(&params, &mut TestRng::new(1));
        let b = craft(&params, &mut TestRng::new(2));

        let order_a: Vec<u16> = parse(&a).extensions.into_iter().map(|(id, _)| id).collect();
        let order_b: Vec<u16> = parse(&b).extensions.into_iter().map(|(id, _)| id).collect();

        assert_ne!(
            order_a, order_b,
            "different seeds must permute the extension order (a fixed order would be \
             MORE fingerprintable than real Chrome, which shuffles every connection)"
        );
    }
}
