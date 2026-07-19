//! TLS 1.3 client key schedule + record layer primitives (RFC 8446), built on
//! `ring`. This module implements the RFC 8446 mechanics only: parsing a
//! `ServerHello`, the HKDF-based key schedule (§7.1), and the AEAD record
//! layer (§5.2/§5.3). It does not drive a socket or a full handshake state
//! machine — that is Task 7's job (REALITY.2), which composes these
//! primitives around the byte-faithful `ClientHello` crafted by [`crate::hello`].
//!
//! Scope is deliberately narrow: TLS 1.3 only, X25519 key exchange only, and
//! exactly the three cipher suites Chrome/BoringSSL and this crate's crafted
//! `ClientHello` offer — `TLS_AES_128_GCM_SHA256` (`0x1301`),
//! `TLS_AES_256_GCM_SHA384` (`0x1302`), and `TLS_CHACHA20_POLY1305_SHA256`
//! (`0x1303`). Everything here is fail-closed: malformed or out-of-scope
//! server input is a `Result::Err`, never a panic.

use ring::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use ring::{digest, hmac};

const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const EXT_KEY_SHARE: u16 = 51;
/// `X25519` (RFC 8446 §4.2.7 / RFC 7748).
pub const GROUP_X25519: u16 = 0x001d;
/// `X25519MLKEM768` (draft-kwiatkowski-tls-ecdhe-mlkem), the hybrid PQ group
/// real Chrome 150 sends as its primary key share. Server `key_share` for
/// this group is `mlkem768_ciphertext(1088) ‖ x25519_public(32)` = 1120
/// bytes.
pub const GROUP_X25519MLKEM768: u16 = 4588;
/// Byte length of an ML-KEM-768 ciphertext (FIPS 203 §7.2). `pub(crate)`
/// so [`crate::server`] (REALITY.5b's server-side KEX, the mirror of this
/// module's client-side group-4588 handling) can size the server
/// `key_share`'s ciphertext prefix without duplicating the constant.
pub(crate) const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// Byte length of an X25519 public value (RFC 7748).
const X25519_LEN: usize = 32;
const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const SUITE_AES_256_GCM_SHA384: u16 = 0x1302;
const SUITE_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// TLS 1.3 record-layer content types (RFC 8446 §5.1), used both as the AAD
/// "outer type" and as the trailing byte of the `TLSInnerPlaintext` that
/// [`record_seal`]/[`record_open`] append/strip.
const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

/// Everything that can go wrong parsing untrusted server bytes or performing
/// a record-layer AEAD operation. Every fallible function in this module is
/// fail-closed: it returns `Err` rather than panicking on malformed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Ran off the end of the buffer while reading a fixed-size or
    /// length-prefixed field.
    Truncated,
    /// The handshake message's type byte was not `0x02` (`ServerHello`).
    WrongHandshakeType,
    /// The negotiated cipher suite is not one of the three this module
    /// supports (`0x1301`, `0x1302`, `0x1303`).
    UnsupportedCipherSuite,
    /// The `key_share` extension's group was neither `x25519` (`0x001d`) nor
    /// `X25519MLKEM768` (`4588`).
    UnsupportedGroup,
    /// The `key_share` extension's key length did not match its group: 32
    /// bytes for `x25519`, 1120 bytes (`1088` ML-KEM-768 ciphertext ‖ `32`
    /// X25519 public) for `X25519MLKEM768`.
    BadKeyShareLength,
    /// The `ServerHello` had no `key_share` extension (51) at all.
    MissingKeyShare,
    /// A record's ciphertext+tag length does not fit the AAD's 16-bit length
    /// field.
    RecordTooLarge,
    /// AEAD seal or open failed (auth tag mismatch on open, or an
    /// unexpected key-construction failure on seal).
    Crypto,
    /// After stripping trailing zero padding, no content-type byte remained
    /// — an empty or all-zero `TLSInnerPlaintext`.
    EmptyInnerPlaintext,
    /// ML-KEM-768 decapsulation of the server's `X25519MLKEM768` (`4588`)
    /// ciphertext failed — a malformed/corrupted ciphertext, or (per FIPS
    /// 203's implicit-rejection design) a mismatched decapsulation key.
    MlKemDecapsulation,
    /// The recovered inner content type was none of `handshake` (0x16),
    /// `application_data` (0x17), or `alert` (0x15) — e.g. `change_cipher_spec`
    /// (0x14), which RFC 8446 never protects (it's only ever sent/accepted
    /// plaintext, for middlebox compatibility).
    UnexpectedContentType,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::Truncated => "truncated TLS field",
            Error::WrongHandshakeType => "not a ServerHello handshake message",
            Error::UnsupportedCipherSuite => "unsupported TLS 1.3 cipher suite",
            Error::UnsupportedGroup => "key_share group is neither x25519 nor X25519MLKEM768",
            Error::BadKeyShareLength => "key_share key length does not match its group",
            Error::MissingKeyShare => "ServerHello has no key_share extension",
            Error::RecordTooLarge => "record ciphertext+tag length exceeds u16",
            Error::Crypto => "AEAD seal/open failed",
            Error::EmptyInnerPlaintext => "TLSInnerPlaintext has no content-type byte",
            Error::MlKemDecapsulation => {
                "ML-KEM-768 decapsulation of the server's ciphertext failed"
            }
            Error::UnexpectedContentType => "unexpected TLS record content type",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// ServerHello parsing
// ---------------------------------------------------------------------------

/// The fields Task 7/Task 9's key schedule needs out of a `ServerHello`: the
/// negotiated cipher suite, the negotiated `key_share` group, and the
/// server's raw key-share bytes for that group — 32 bytes (X25519 public) for
/// group `29`, or 1120 bytes (`mlkem768_ciphertext(1088) ‖ x25519_public(32)`)
/// for group `4588`. The caller ([`crate::stream::connect`]) interprets
/// `server_key_share` according to `group`; this module only validates that
/// the length matches the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloInfo {
    pub suite: u16,
    pub group: u16,
    pub server_key_share: Vec<u8>,
}

/// A bounds-checked, panic-free cursor over a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn u8(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Ok(u16::from_be_bytes([hi, lo]))
    }

    fn u24(&mut self) -> Result<usize, Error> {
        let a = self.u8()?;
        let b = self.u8()?;
        let c = self.u8()?;
        Ok((usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(out)
    }
}

/// The common bounded walk [`parse_server_hello`] and
/// [`parse_server_hello_shape`] share: `0x02 ‖ u24 len ‖ version(2) ‖
/// random(32) ‖ sid_len(1)+sid ‖ cipher_suite(2) ‖ comp(1) ‖ ext_len(2)`,
/// stopping just before the extensions block. Returns the negotiated cipher
/// suite (already validated to be one of the three this crate supports), the
/// raw compression-method byte, and the still-TLV-encoded extensions bytes
/// (borrowed from `record_payload`, so callers walk them independently).
/// Fail-closed on any malformed or out-of-scope field.
fn parse_server_hello_header(record_payload: &[u8]) -> Result<(u16, u8, &[u8]), Error> {
    let mut r = Reader::new(record_payload);

    let msg_type = r.u8()?;
    if msg_type != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(Error::WrongHandshakeType);
    }
    let len = r.u24()?;
    let body = r.take(len)?;

    let mut b = Reader::new(body);
    let _legacy_version = b.u16()?;
    let _random = b.take(32)?;

    let sid_len = usize::from(b.u8()?);
    let _session_id = b.take(sid_len)?;

    let suite = b.u16()?;
    if suite != SUITE_AES_128_GCM_SHA256
        && suite != SUITE_AES_256_GCM_SHA384
        && suite != SUITE_CHACHA20_POLY1305_SHA256
    {
        return Err(Error::UnsupportedCipherSuite);
    }

    let compression_method = b.u8()?;

    let ext_len = usize::from(b.u16()?);
    let ext_bytes = b.take(ext_len)?;

    Ok((suite, compression_method, ext_bytes))
}

/// Parses a `ServerHello` handshake message: `0x02 ‖ u24 len ‖ version(2) ‖
/// random(32) ‖ sid_len(1)+sid ‖ cipher_suite(2) ‖ comp(1) ‖ ext_len(2) ‖
/// exts`. Requires the negotiated suite to be one of the three this crate
/// supports, and requires exactly one `key_share`(51) extension entry with
/// group x25519 (`0x001d`, 32-byte key) or `X25519MLKEM768` (`4588`,
/// 1120-byte key). Fail-closed on any malformed or out-of-scope field.
pub fn parse_server_hello(record_payload: &[u8]) -> Result<ServerHelloInfo, Error> {
    let (suite, _compression_method, ext_bytes) = parse_server_hello_header(record_payload)?;

    let mut server_key_share = None;
    let mut e = Reader::new(ext_bytes);
    while !e.is_empty() {
        let ext_type = e.u16()?;
        let ext_body_len = usize::from(e.u16()?);
        let ext_body = e.take(ext_body_len)?;

        if ext_type == EXT_KEY_SHARE {
            let mut k = Reader::new(ext_body);
            let group = k.u16()?;
            let key_len = usize::from(k.u16()?);
            let key = k.take(key_len)?;

            let expected_len = match group {
                GROUP_X25519 => X25519_LEN,
                GROUP_X25519MLKEM768 => MLKEM768_CIPHERTEXT_LEN + X25519_LEN,
                _ => return Err(Error::UnsupportedGroup),
            };
            if key.len() != expected_len {
                return Err(Error::BadKeyShareLength);
            }
            server_key_share = Some((group, key.to_vec()));
        }
    }

    let (group, server_key_share) = server_key_share.ok_or(Error::MissingKeyShare)?;
    Ok(ServerHelloInfo {
        suite,
        group,
        server_key_share,
    })
}

/// Like [`parse_server_hello`] but captures the FULL ServerHello structure
/// (ordered extensions incl. GREASE, compression) for REALITY.5 mimicry. The
/// per-connection `random` and `key_share` VALUE are not returned here (5b
/// substitutes the relay's own); the `key_share` group IS
/// (`key_share_group`). Shares [`parse_server_hello_header`]'s bounded walk
/// with `parse_server_hello`, so both stay byte-identical up through the
/// extensions block; this variant additionally walks every extension
/// (including ones `parse_server_hello` ignores, like GREASE) and records
/// `(ext_id, ext_body)` in wire order, plus the compression-method byte.
/// Requires a `key_share`(51) extension to be present (fail-closed, like
/// `parse_server_hello`); unlike `parse_server_hello` it does NOT validate
/// the key_share length against the group — it captures structure, not
/// crypto material.
pub fn parse_server_hello_shape(
    record_payload: &[u8],
) -> Result<crate::template::ServerHelloShape, Error> {
    let (cipher_suite, legacy_compression_method, ext_bytes) =
        parse_server_hello_header(record_payload)?;

    let mut extensions = Vec::new();
    let mut key_share_group = None;
    let mut e = Reader::new(ext_bytes);
    while !e.is_empty() {
        let ext_type = e.u16()?;
        let ext_body_len = usize::from(e.u16()?);
        let ext_body = e.take(ext_body_len)?;

        if ext_type == EXT_KEY_SHARE {
            let mut k = Reader::new(ext_body);
            key_share_group = Some(k.u16()?);
        }

        extensions.push((ext_type, ext_body.to_vec()));
    }

    let key_share_group = key_share_group.ok_or(Error::MissingKeyShare)?;
    Ok(crate::template::ServerHelloShape {
        cipher_suite,
        legacy_compression_method,
        extensions,
        key_share_group,
    })
}

// ---------------------------------------------------------------------------
// HKDF (TLS 1.3 flavored, RFC 8446 §7.1 / RFC 5869)
// ---------------------------------------------------------------------------

/// `SHA-256(m)`. A convenience wrapper for the RFC 8448 test vectors (all of
/// which negotiate `TLS_AES_128_GCM_SHA256`) — the real handshake path uses
/// [`transcript_hash`], which picks the hash tied to the negotiated suite.
pub fn sha256(m: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, m);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// The RFC 8446 §7.1 "Hash" the *entire* key schedule (transcript hash,
/// `HKDF-Extract`/`HKDF-Expand`, `Derive-Secret`) MUST use for a given
/// negotiated suite: SHA-256 for `TLS_AES_128_GCM_SHA256` (`0x1301`) and
/// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`), SHA-384 for
/// `TLS_AES_256_GCM_SHA384` (`0x1302`) — the suite name literally encodes
/// it. A client that always used SHA-256 derives the wrong keys for `0x1302`
/// and fails to decrypt the server's very first handshake record; this is
/// exactly the bug REALITY.2 Task 8's live test against `www.microsoft.com`
/// (which negotiates `0x1302`) exposed as `AEAD seal/open failed`.
/// `parse_server_hello` already restricts a negotiated suite to
/// `{0x1301, 0x1302, 0x1303}` before this is reached on the real handshake
/// path; treating any other value as the SHA-256 case is a defensive
/// default for callers that bypass that check, not a silent correctness gap
/// on the real path.
fn digest_algorithm_for_suite(suite: u16) -> &'static digest::Algorithm {
    if suite == SUITE_AES_256_GCM_SHA384 {
        &digest::SHA384
    } else {
        &digest::SHA256
    }
}

/// The `ring::hmac::Algorithm` (HMAC keyed with the same hash — see
/// [`digest_algorithm_for_suite`]) `HKDF-Extract`/`HKDF-Expand` use for a
/// negotiated suite.
fn hmac_algorithm_for_suite(suite: u16) -> hmac::Algorithm {
    if suite == SUITE_AES_256_GCM_SHA384 {
        hmac::HMAC_SHA384
    } else {
        hmac::HMAC_SHA256
    }
}

/// `Hash(m)` for the negotiated `suite`'s key-schedule hash (RFC 8446 §7.1).
/// 32 bytes for SHA-256-hash suites, 48 for `TLS_AES_256_GCM_SHA384`.
pub fn transcript_hash(m: &[u8], suite: u16) -> Vec<u8> {
    digest::digest(digest_algorithm_for_suite(suite), m)
        .as_ref()
        .to_vec()
}

/// `HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm)` (RFC 5869 §2.2), using
/// the negotiated `suite`'s key-schedule hash.
fn hkdf_extract_for_suite(salt: &[u8], ikm: &[u8], suite: u16) -> Vec<u8> {
    let key = hmac::Key::new(hmac_algorithm_for_suite(suite), salt);
    hmac::sign(&key, ikm).as_ref().to_vec()
}

/// `HKDF-Extract(salt, ikm) = HMAC-SHA256(salt, ikm)` (RFC 5869 §2.2) — the
/// SHA-256-only convenience wrapper the RFC 8448 test vectors use.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hkdf_extract_for_suite(salt, ikm, SUITE_AES_128_GCM_SHA256)
        .try_into()
        .expect("SHA-256 HMAC output is always 32 bytes")
}

/// `HKDF-Expand(prk, info, len)` (RFC 5869 §2.3): `T(0) = ""`, `T(n) =
/// HMAC-Hash(prk, T(n-1) ‖ info ‖ n)`, output = `T(1) ‖ T(2) ‖ …` truncated
/// to `len`, using the negotiated `suite`'s key-schedule hash.
fn hkdf_expand_for_suite(prk: &[u8], info: &[u8], len: usize, suite: u16) -> Vec<u8> {
    let key = hmac::Key::new(hmac_algorithm_for_suite(suite), prk);
    let mut out = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 0;
    while out.len() < len {
        counter = counter.checked_add(1).expect(
            "HKDF-Expand: requested length exceeds 255 * hash-output-size; \
             far beyond any TLS 1.3 key/iv/secret this module ever derives",
        );
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&prev);
        ctx.update(info);
        ctx.update(&[counter]);
        let tag = ctx.sign();
        prev = tag.as_ref().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

/// `HKDF-Expand-Label(secret, label, context, len)` (RFC 8446 §7.1):
/// `HkdfLabel = u16(len) ‖ u8(len("tls13 "+label)) ‖ "tls13 "+label ‖
/// u8(len(context)) ‖ context`, then `HKDF-Expand(secret, HkdfLabel, len)`,
/// using the negotiated `suite`'s key-schedule hash.
fn hkdf_expand_label_for_suite(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
    suite: u16,
) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    let len_u16 = u16::try_from(len).expect(
        "hkdf_expand_label: len is always a TLS 1.3 key/iv/secret size (<=48) here, well within u16",
    );
    info.extend_from_slice(&len_u16.to_be_bytes());
    let label_len = u8::try_from(full_label.len())
        .expect("hkdf_expand_label: \"tls13 \" + label is far under 255 bytes for this module's fixed labels");
    info.push(label_len);
    info.extend_from_slice(&full_label);
    let context_len = u8::try_from(context.len()).expect(
        "hkdf_expand_label: context is a transcript hash (32 or 48 bytes) or empty, well within u8",
    );
    info.push(context_len);
    info.extend_from_slice(context);

    hkdf_expand_for_suite(secret, &info, len, suite)
}

/// `HKDF-Expand-Label(secret, label, context, len)` (RFC 8446 §7.1), fixed
/// to SHA-256 — the convenience wrapper the RFC 8448 test vectors use.
pub fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    hkdf_expand_label_for_suite(secret, label, context, len, SUITE_AES_128_GCM_SHA256)
}

/// `Derive-Secret(secret, label, transcript_hash) = HKDF-Expand-Label(secret,
/// label, transcript_hash, Hash.length)` (RFC 8446 §7.1), using the
/// negotiated `suite`'s key-schedule hash and output length (32 bytes for
/// SHA-256-hash suites, 48 for `TLS_AES_256_GCM_SHA384`).
fn derive_secret_for_suite(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
    suite: u16,
) -> Vec<u8> {
    let hash_len = digest_algorithm_for_suite(suite).output_len();
    hkdf_expand_label_for_suite(secret, label, transcript_hash, hash_len, suite)
}

/// `Derive-Secret(secret, label, transcript_hash) =
/// HKDF-Expand-Label(secret, label, transcript_hash, 32)` (RFC 8446 §7.1),
/// fixed to SHA-256 — the convenience wrapper the RFC 8448 test vectors use.
pub fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> [u8; 32] {
    let v = derive_secret_for_suite(secret, label, transcript_hash, SUITE_AES_128_GCM_SHA256);
    v.try_into()
        .expect("SHA-256 Derive-Secret output is always 32 bytes")
}

fn iv12(v: Vec<u8>) -> [u8; 12] {
    v.try_into()
        .expect("hkdf_expand_label(..., 12) always returns exactly 12 bytes")
}

/// AEAD key length for a suite: 16 bytes for `TLS_AES_128_GCM_SHA256`
/// (`0x1301`), 32 bytes for `TLS_AES_256_GCM_SHA384` (`0x1302`) and
/// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`). `parse_server_hello` already
/// restricts a negotiated suite to `{0x1301, 0x1302, 0x1303}` before this is
/// reached on the real handshake path; treating any other value as the
/// 32-byte case is a defensive default for callers that bypass that check,
/// not a silent correctness gap on the real path.
fn key_len_for_suite(suite: u16) -> usize {
    if suite == SUITE_AES_128_GCM_SHA256 {
        16
    } else {
        32
    }
}

// ---------------------------------------------------------------------------
// Key schedule (RFC 8446 §7.1)
// ---------------------------------------------------------------------------

/// The client/server handshake traffic keys, plus the handshake secret
/// itself (needed as an input to [`derive_application_keys`]) and the raw
/// client/server handshake traffic secrets (needed by Task 7's `connect`, via
/// [`finished_verify_data`], to derive the client `Finished` message, and by
/// REALITY.5c's server-side logic to derive the server `Finished`'s verify_data).
/// `handshake_secret`/`client_hs_traffic`/`server_hs_traffic` are 32 bytes for
/// SHA-256-hash suites, 48 bytes for `TLS_AES_256_GCM_SHA384` (`0x1302`) —
/// hence `Vec<u8>` rather than a fixed-size array.
pub struct HandshakeKeys {
    pub client_key: Vec<u8>,
    pub client_iv: [u8; 12],
    pub server_key: Vec<u8>,
    pub server_iv: [u8; 12],
    pub suite: u16,
    pub handshake_secret: Vec<u8>,
    pub client_hs_traffic: Vec<u8>,
    /// The server handshake-traffic secret (`s hs traffic`) — the base secret
    /// for the SERVER `Finished`'s `verify_data` (REALITY.5c). Sibling of
    /// `client_hs_traffic`; both are 32 bytes (SHA-256) or 48 (SHA-384).
    pub server_hs_traffic: Vec<u8>,
}

/// Derives the TLS 1.3 handshake traffic keys from the ECDHE (or hybrid
/// ECDHE+ML-KEM) shared secret and the transcript hash of `ClientHello ‖
/// ServerHello`:
///
/// ```text
/// early      = HKDF-Extract(0, 0)
/// derived    = Derive-Secret(early, "derived", Hash(""))
/// hs         = HKDF-Extract(derived, ecdhe)
/// c_hs       = Derive-Secret(hs, "c hs traffic", transcript_hash_ch_sh)
/// s_hs       = Derive-Secret(hs, "s hs traffic", transcript_hash_ch_sh)
/// {c,s}_key  = HKDF-Expand-Label({c,s}_hs, "key", "", key_len)
/// {c,s}_iv   = HKDF-Expand-Label({c,s}_hs, "iv",  "", 12)
/// ```
///
/// `ecdhe` is 32 bytes for a plain X25519 exchange (group `29`), or 64 bytes
/// (`mlkem_shared_secret(32) ‖ x25519_shared_secret(32)`) for the
/// `X25519MLKEM768` hybrid (group `4588`) — `HKDF-Extract` accepts arbitrary-
/// length IKM (RFC 5869 §2.2), so no other step of the schedule changes
/// shape.
///
/// Every step here uses the `suite`-selected hash (RFC 8446 §7.1) — see
/// [`digest_algorithm_for_suite`].
pub fn derive_handshake_keys(
    ecdhe: &[u8],
    transcript_hash_ch_sh: &[u8],
    suite: u16,
) -> HandshakeKeys {
    let hash_len = digest_algorithm_for_suite(suite).output_len();
    let zeros = vec![0u8; hash_len];
    let empty_hash = transcript_hash(b"", suite);

    let early = hkdf_extract_for_suite(&zeros, &zeros, suite);
    let derived = derive_secret_for_suite(&early, b"derived", &empty_hash, suite);
    let handshake_secret = hkdf_extract_for_suite(&derived, ecdhe, suite);

    let c_hs = derive_secret_for_suite(
        &handshake_secret,
        b"c hs traffic",
        transcript_hash_ch_sh,
        suite,
    );
    let s_hs = derive_secret_for_suite(
        &handshake_secret,
        b"s hs traffic",
        transcript_hash_ch_sh,
        suite,
    );

    let key_len = key_len_for_suite(suite);
    let client_key = hkdf_expand_label_for_suite(&c_hs, b"key", b"", key_len, suite);
    let server_key = hkdf_expand_label_for_suite(&s_hs, b"key", b"", key_len, suite);
    let client_iv = iv12(hkdf_expand_label_for_suite(&c_hs, b"iv", b"", 12, suite));
    let server_iv = iv12(hkdf_expand_label_for_suite(&s_hs, b"iv", b"", 12, suite));

    HandshakeKeys {
        client_key,
        client_iv,
        server_key,
        server_iv,
        suite,
        handshake_secret,
        client_hs_traffic: c_hs,
        server_hs_traffic: s_hs,
    }
}

/// Computes the client `Finished` message's `verify_data = HMAC(finished_key,
/// transcript_hash)`, where `finished_key = HKDF-Expand-Label(base_secret,
/// "finished", "", Hash.length)` (RFC 8446 §4.4.4) — using the negotiated
/// `suite`'s hash/HMAC throughout, matching the rest of the key schedule.
/// `base_secret` is [`HandshakeKeys::client_hs_traffic`] for the client
/// `Finished` (the only one this crate ever sends — it never validates the
/// server's `Finished` contents; see [`crate::stream::connect`]'s module doc).
pub fn finished_verify_data(base_secret: &[u8], transcript_hash: &[u8], suite: u16) -> Vec<u8> {
    let hash_len = digest_algorithm_for_suite(suite).output_len();
    let finished_key = hkdf_expand_label_for_suite(base_secret, b"finished", b"", hash_len, suite);
    let key = hmac::Key::new(hmac_algorithm_for_suite(suite), &finished_key);
    hmac::sign(&key, transcript_hash).as_ref().to_vec()
}

/// The client/server application traffic keys.
pub struct ApplicationKeys {
    pub client_key: Vec<u8>,
    pub client_iv: [u8; 12],
    pub server_key: Vec<u8>,
    pub server_iv: [u8; 12],
    pub suite: u16,
}

/// Derives the TLS 1.3 application traffic keys from the handshake secret
/// (as returned in [`HandshakeKeys::handshake_secret`]) and the transcript
/// hash through the server's `Finished` message:
///
/// ```text
/// derived    = Derive-Secret(handshake_secret, "derived", Hash(""))
/// master     = HKDF-Extract(derived, 0)
/// c_ap       = Derive-Secret(master, "c ap traffic", transcript_hash_through_sfin)
/// s_ap       = Derive-Secret(master, "s ap traffic", transcript_hash_through_sfin)
/// {c,s}_key  = HKDF-Expand-Label({c,s}_ap, "key", "", key_len)
/// {c,s}_iv   = HKDF-Expand-Label({c,s}_ap, "iv",  "", 12)
/// ```
pub fn derive_application_keys(
    handshake_secret: &[u8],
    transcript_hash_through_sfin: &[u8],
    suite: u16,
) -> ApplicationKeys {
    let hash_len = digest_algorithm_for_suite(suite).output_len();
    let zeros = vec![0u8; hash_len];
    let empty_hash = transcript_hash(b"", suite);
    let derived = derive_secret_for_suite(handshake_secret, b"derived", &empty_hash, suite);
    let master = hkdf_extract_for_suite(&derived, &zeros, suite);

    let c_ap = derive_secret_for_suite(
        &master,
        b"c ap traffic",
        transcript_hash_through_sfin,
        suite,
    );
    let s_ap = derive_secret_for_suite(
        &master,
        b"s ap traffic",
        transcript_hash_through_sfin,
        suite,
    );

    let key_len = key_len_for_suite(suite);
    let client_key = hkdf_expand_label_for_suite(&c_ap, b"key", b"", key_len, suite);
    let server_key = hkdf_expand_label_for_suite(&s_ap, b"key", b"", key_len, suite);
    let client_iv = iv12(hkdf_expand_label_for_suite(&c_ap, b"iv", b"", 12, suite));
    let server_iv = iv12(hkdf_expand_label_for_suite(&s_ap, b"iv", b"", 12, suite));

    ApplicationKeys {
        client_key,
        client_iv,
        server_key,
        server_iv,
        suite,
    }
}

// ---------------------------------------------------------------------------
// Record layer (RFC 8446 §5.2/§5.3)
// ---------------------------------------------------------------------------

/// Selects the AEAD algorithm for a negotiated suite. Deliberately keyed on
/// the *suite*, not the key length: `TLS_AES_256_GCM_SHA384` (`0x1302`) and
/// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) both use 32-byte keys, so key
/// length alone cannot disambiguate them — a real bug this crate shipped
/// with until the REALITY.2 Task 8 live test against `www.microsoft.com`
/// (which negotiates `0x1302`) exposed it.
fn algorithm_for_suite(suite: u16) -> Result<&'static ring::aead::Algorithm, Error> {
    match suite {
        SUITE_AES_128_GCM_SHA256 => Ok(&AES_128_GCM),
        SUITE_AES_256_GCM_SHA384 => Ok(&AES_256_GCM),
        SUITE_CHACHA20_POLY1305_SHA256 => Ok(&CHACHA20_POLY1305),
        _ => Err(Error::UnsupportedCipherSuite),
    }
}

/// `nonce = iv XOR seq`, with `seq` encoded big-endian and right-aligned
/// into the low 8 bytes of the 12-byte IV (RFC 8446 §5.3).
fn make_nonce(iv: &[u8; 12], seq: u64) -> Nonce {
    let mut nonce_bytes = *iv;
    let seq_be = seq.to_be_bytes();
    for (n, s) in nonce_bytes[4..].iter_mut().zip(seq_be.iter()) {
        *n ^= s;
    }
    Nonce::assume_unique_for_key(nonce_bytes)
}

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

/// Seals `plaintext` as a TLS 1.3 protected record with no record padding.
/// Thin wrapper over [`record_seal_padded`] with `pad_len = 0`.
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

/// Opens a TLS 1.3 protected record. `record_type` is the *outer* record
/// type read from the record header on the wire (always `0x17` for TLS 1.3
/// post-`ServerHello` records) and is used to reconstruct the AAD; `payload`
/// is the record's ciphertext+tag body (mutated in place as scratch space).
/// Strips the TLS 1.3 inner padding on success — trailing zero bytes, then
/// the real content-type byte — and requires that byte to be `handshake`
/// (0x16) or `application_data` (0x17). Returns the recovered content only;
/// use [`record_open_typed`] when the caller also needs to know which of the
/// two the recovered content type was (e.g. to skip a post-handshake
/// `NewSessionTicket` interleaved with application-data records).
pub fn record_open(
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    suite: u16,
    record_type: u8,
    payload: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    record_open_typed(key, iv, seq, suite, record_type, payload)
        .map(|(_content_type, content)| content)
}

/// Identical to [`record_open`], but also returns the recovered TLS 1.3
/// inner content type — `0x16` handshake, `0x17` application_data, or `0x15`
/// alert (RFC 8446 §5.2: once traffic keys are in place, alerts are
/// protected records too, carried inside `TLSInnerPlaintext` exactly like
/// handshake/application-data content, NOT sent as a distinct plaintext
/// outer record) — instead of discarding it after validation. Callers that
/// don't care which of the three it was can use [`record_open`].
pub fn record_open_typed(
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    suite: u16,
    record_type: u8,
    payload: &mut Vec<u8>,
) -> Result<(u8, Vec<u8>), Error> {
    let alg = algorithm_for_suite(suite)?;
    let unbound = UnboundKey::new(alg, key).map_err(|_| Error::Crypto)?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce = make_nonce(iv, seq);

    let len_bytes = u16::try_from(payload.len())
        .map_err(|_| Error::RecordTooLarge)?
        .to_be_bytes();
    let aad_bytes = [record_type, 0x03, 0x03, len_bytes[0], len_bytes[1]];

    let plaintext_len = less_safe
        .open_in_place(nonce, Aad::from(aad_bytes), payload.as_mut_slice())
        .map_err(|_| Error::Crypto)?
        .len();
    payload.truncate(plaintext_len);

    while payload.last() == Some(&0) {
        payload.pop();
    }
    let content_type = payload.pop().ok_or(Error::EmptyInnerPlaintext)?;
    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::UnexpectedContentType);
    }

    Ok((content_type, core::mem::take(payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string with no separators into bytes. Test-only helper
    /// so the RFC 8448 vectors below can be pasted as flat hex, matching the
    /// RFC's own byte dumps as closely as possible for easy cross-checking.
    fn hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string must have an even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit pair"))
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex(s).try_into().expect("32-byte hex vector")
    }

    // -- RFC 8448 §3 "Simple 1-RTT Handshake" vectors -----------------------
    //
    // Every hex string below was extracted programmatically (not
    // hand-transcribed) from the RFC 8448 text via a small script that pulls
    // whitespace-separated 2-hex-digit tokens out of the labeled byte-dump
    // blocks, to avoid manual transcription errors in security-sensitive
    // constants.

    /// `{server} send handshake record` payload: the ServerHello handshake
    /// message itself (`0x02 ‖ u24 len ‖ body`), 90 octets.
    const RFC8448_SERVER_HELLO_MSG: &str = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";

    /// The x25519 ECDHE shared secret (`{server} extract secret
    /// "handshake"`'s IKM), 32 octets.
    const RFC8448_ECDHE_SHARED_SECRET: &str =
        "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";

    /// `Hash(ClientHello ‖ ServerHello)`, 32 octets.
    const RFC8448_TRANSCRIPT_CH_SH: &str =
        "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";

    const RFC8448_EARLY_SECRET: &str =
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    const RFC8448_DERIVED_FOR_HANDSHAKE: &str =
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
    const RFC8448_HANDSHAKE_SECRET: &str =
        "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    const RFC8448_CLIENT_HS_TRAFFIC_SECRET: &str =
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    const RFC8448_SERVER_HS_TRAFFIC_SECRET: &str =
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    const RFC8448_SERVER_HS_KEY: &str = "3fce516009c21727d0f2e4e86ee403bc";
    const RFC8448_SERVER_HS_IV: &str = "5d313eb2671276ee13000b30";
    const RFC8448_CLIENT_HS_KEY: &str = "dbfaa693d1762c5b666af5d950258d01";
    const RFC8448_CLIENT_HS_IV: &str = "5bd3c71b836e0b76bb73265f";

    const RFC8448_TRANSCRIPT_THROUGH_SFIN: &str =
        "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";
    const RFC8448_CLIENT_AP_TRAFFIC_SECRET: &str =
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    const RFC8448_SERVER_AP_TRAFFIC_SECRET: &str =
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
    const RFC8448_SERVER_AP_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
    const RFC8448_SERVER_AP_IV: &str = "cf782b88dd83549aadf1e984";
    const RFC8448_CLIENT_AP_KEY: &str = "17422dda596ed5d9acd890e3c63f5051";
    const RFC8448_CLIENT_AP_IV: &str = "5b78923dee08579033e523d9";

    /// `{server} send handshake record` "complete record" for the
    /// EncryptedExtensions/Certificate/CertificateVerify/Finished flight:
    /// `17 03 03 02 a2` header ‖ 674-byte ciphertext+tag, seq 0 under the
    /// server handshake traffic key/iv.
    const RFC8448_EE_RECORD_FULL: &str = "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b";

    /// The plaintext that record decrypts to: `EncryptedExtensions ‖
    /// Certificate ‖ CertificateVerify ‖ Finished`, 657 octets (before the
    /// `0x16` content-type byte record_open strips).
    const RFC8448_EE_PLAINTEXT: &str = "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";

    /// Builds a minimal `ServerHello` handshake-message payload (`0x02 ‖ u24
    /// len ‖ { legacy_version(0x0303) ‖ random(32) ‖ session_id(u8 len +
    /// bytes) ‖ cipher_suite(2) ‖ compression(1) ‖ ext(u16 len + list) }`)
    /// for [`parse_server_hello_shape`] tests — a hand-rolled fixture rather
    /// than an RFC 8448 vector, since those tests need to control the exact
    /// ordered extension list (incl. GREASE) `parse_server_hello` itself
    /// doesn't capture.
    fn build_test_server_hello(cipher: u16, compression: u8, exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id: empty
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(compression);

        let mut ext_bytes = Vec::new();
        for (id, data) in exts {
            ext_bytes.extend_from_slice(&id.to_be_bytes());
            let data_len = u16::try_from(data.len()).expect("test ext body fits u16");
            ext_bytes.extend_from_slice(&data_len.to_be_bytes());
            ext_bytes.extend_from_slice(data);
        }
        let ext_len = u16::try_from(ext_bytes.len()).expect("test ext block fits u16");
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(&ext_bytes);

        let mut msg = Vec::new();
        msg.push(HANDSHAKE_TYPE_SERVER_HELLO);
        let len_bytes = u32::try_from(body.len())
            .expect("test body fits u24")
            .to_be_bytes();
        msg.extend_from_slice(&len_bytes[1..]); // u24 big-endian (drop the MSB of the u32)
        msg.extend_from_slice(&body);
        msg
    }

    /// Builds a `key_share` extension body (`group(2) ‖ key_len(2) ‖ key`) —
    /// a fixed-size dummy key, since `parse_server_hello_shape` only reads
    /// the group and does not validate key length against it.
    fn key_share_ext_body(group: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&group.to_be_bytes());
        let key = [0u8; 32];
        let key_len = u16::try_from(key.len()).expect("test key fits u16");
        v.extend_from_slice(&key_len.to_be_bytes());
        v.extend_from_slice(&key);
        v
    }

    #[test]
    fn parse_server_hello_shape_captures_ordered_extensions() {
        // handshake msg: type(0x02) ‖ u24 len ‖ { legacy_version(0x0303) ‖ random(32)
        //   ‖ session_id(u8 len + bytes) ‖ cipher_suite(2) ‖ compression(1) ‖ ext(u16 len + list) }
        let sh = build_test_server_hello(
            0x1301, // cipher
            0x00,   // compression
            &[
                (0x002b_u16, vec![0x03, 0x04]), // supported_versions -> TLS 1.3
                (0x0033_u16, key_share_ext_body(0x001d)), // key_share, group X25519(29)
                (0x2a2a_u16, vec![]),           // a GREASE extension, empty
            ],
        );
        let shape = parse_server_hello_shape(&sh).expect("parse");
        assert_eq!(shape.cipher_suite, 0x1301);
        assert_eq!(shape.legacy_compression_method, 0x00);
        assert_eq!(shape.key_share_group, 0x001d);
        // Order + ids preserved (incl. the GREASE ext at its position).
        let ids: Vec<u16> = shape.extensions.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0x002b, 0x0033, 0x2a2a]);
    }

    #[test]
    fn parse_server_hello_reads_rfc8448_vector() {
        let info = parse_server_hello(&hex(RFC8448_SERVER_HELLO_MSG)).expect("valid ServerHello");
        assert_eq!(info.suite, SUITE_AES_128_GCM_SHA256);
        assert_eq!(info.group, GROUP_X25519);
        assert_eq!(
            info.server_key_share,
            hex32("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f").to_vec()
        );
    }

    #[test]
    fn parse_server_hello_rejects_wrong_handshake_type() {
        let mut msg = hex(RFC8448_SERVER_HELLO_MSG);
        msg[0] = 0x01; // ClientHello type, not ServerHello
        assert_eq!(
            parse_server_hello(&msg).unwrap_err(),
            Error::WrongHandshakeType
        );
    }

    #[test]
    fn parse_server_hello_rejects_truncated_input() {
        let msg = hex(RFC8448_SERVER_HELLO_MSG);
        assert_eq!(
            parse_server_hello(&msg[..10]).unwrap_err(),
            Error::Truncated
        );
    }

    #[test]
    fn parse_server_hello_rejects_unsupported_cipher_suite() {
        let mut msg = hex(RFC8448_SERVER_HELLO_MSG);
        // Cipher suite bytes sit right after version(2)+random(32)+sid_len(1)=35,
        // at offset 4 (handshake header) + 35 = 39.
        msg[39] = 0xc0;
        msg[40] = 0x2b; // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (not TLS 1.3)
        assert_eq!(
            parse_server_hello(&msg).unwrap_err(),
            Error::UnsupportedCipherSuite
        );
    }

    #[test]
    fn hkdf_extract_matches_rfc8448_early_secret() {
        let zeros = [0u8; 32];
        assert_eq!(hkdf_extract(&zeros, &zeros), hex32(RFC8448_EARLY_SECRET));
    }

    #[test]
    fn derive_secret_matches_rfc8448_derived_for_handshake() {
        let early = hex32(RFC8448_EARLY_SECRET);
        let empty_hash = sha256(b"");
        assert_eq!(
            derive_secret(&early, b"derived", &empty_hash),
            hex32(RFC8448_DERIVED_FOR_HANDSHAKE)
        );
    }

    #[test]
    fn hkdf_extract_matches_rfc8448_handshake_secret() {
        let derived = hex32(RFC8448_DERIVED_FOR_HANDSHAKE);
        let ecdhe = hex32(RFC8448_ECDHE_SHARED_SECRET);
        assert_eq!(
            hkdf_extract(&derived, &ecdhe),
            hex32(RFC8448_HANDSHAKE_SECRET)
        );
    }

    /// The end-to-end KAT: feed the RFC 8448-published ECDHE shared secret
    /// and ClientHello‖ServerHello transcript hash into
    /// `derive_handshake_keys` and assert every output field — including
    /// `handshake_secret` itself — reproduces the RFC's published values.
    #[test]
    fn derive_handshake_keys_matches_rfc8448_full_vector() {
        let ecdhe = hex32(RFC8448_ECDHE_SHARED_SECRET);
        let transcript = hex(RFC8448_TRANSCRIPT_CH_SH);

        let keys = derive_handshake_keys(&ecdhe, &transcript, SUITE_AES_128_GCM_SHA256);

        assert_eq!(keys.handshake_secret, hex32(RFC8448_HANDSHAKE_SECRET));
        assert_eq!(keys.server_key, hex(RFC8448_SERVER_HS_KEY));
        assert_eq!(keys.server_iv, iv12(hex(RFC8448_SERVER_HS_IV)));
        assert_eq!(keys.client_key, hex(RFC8448_CLIENT_HS_KEY));
        assert_eq!(keys.client_iv, iv12(hex(RFC8448_CLIENT_HS_IV)));
        assert_eq!(keys.suite, SUITE_AES_128_GCM_SHA256);
        assert_eq!(
            keys.client_hs_traffic,
            hex32(RFC8448_CLIENT_HS_TRAFFIC_SECRET)
        );

        // Sanity-check the traffic secrets themselves too (not just their
        // key/iv expansions), matching RFC 8448's intermediate values.
        let empty_hash = sha256(b"");
        let derived = derive_secret(&hex32(RFC8448_EARLY_SECRET), b"derived", &empty_hash);
        let hs = hkdf_extract(&derived, &ecdhe);
        let c_hs = derive_secret(&hs, b"c hs traffic", &transcript);
        let s_hs = derive_secret(&hs, b"s hs traffic", &transcript);
        assert_eq!(c_hs, hex32(RFC8448_CLIENT_HS_TRAFFIC_SECRET));
        assert_eq!(s_hs, hex32(RFC8448_SERVER_HS_TRAFFIC_SECRET));
    }

    /// Second end-to-end KAT: application traffic keys, derived from the
    /// handshake secret and the transcript hash through the server's
    /// Finished message.
    #[test]
    fn derive_application_keys_matches_rfc8448_full_vector() {
        let handshake_secret = hex32(RFC8448_HANDSHAKE_SECRET);
        let transcript = hex(RFC8448_TRANSCRIPT_THROUGH_SFIN);

        let keys =
            derive_application_keys(&handshake_secret, &transcript, SUITE_AES_128_GCM_SHA256);

        assert_eq!(keys.server_key, hex(RFC8448_SERVER_AP_KEY));
        assert_eq!(keys.server_iv, iv12(hex(RFC8448_SERVER_AP_IV)));
        assert_eq!(keys.client_key, hex(RFC8448_CLIENT_AP_KEY));
        assert_eq!(keys.client_iv, iv12(hex(RFC8448_CLIENT_AP_IV)));

        let empty_hash = sha256(b"");
        let derived = derive_secret(&handshake_secret, b"derived", &empty_hash);
        let master = hkdf_extract(&derived, &[0u8; 32]);
        let c_ap = derive_secret(&master, b"c ap traffic", &transcript);
        let s_ap = derive_secret(&master, b"s ap traffic", &transcript);
        assert_eq!(c_ap, hex32(RFC8448_CLIENT_AP_TRAFFIC_SECRET));
        assert_eq!(s_ap, hex32(RFC8448_SERVER_AP_TRAFFIC_SECRET));
    }

    /// RFC 8448's "Simple 1-RTT Handshake" example only demonstrates
    /// `TLS_AES_128_GCM_SHA256`, so there's no published vector to KAT
    /// `TLS_AES_256_GCM_SHA384`'s key schedule against directly. This locks
    /// the *shape* and *hash-algorithm selection* RFC 8446 §7.1 requires
    /// instead: every secret/hash the `0x1302` key schedule touches must be
    /// SHA-384-sized (48 bytes), and must differ from what the SAME ECDHE
    /// input produces under `0x1301`'s SHA-256 schedule — proving `suite`
    /// actually selects the hash rather than being an unused label. This is
    /// exactly the bug REALITY.2 Task 8's live test against a real server
    /// (`www.microsoft.com`, which negotiates `0x1302`) exposed: this crate
    /// always used SHA-256 internally regardless of suite, so it derived the
    /// wrong keys and failed to decrypt the server's first handshake record.
    #[test]
    fn derive_handshake_keys_uses_sha384_for_aes256_gcm_suite() {
        let ecdhe = [0x11u8; 32];

        let transcript_384 = transcript_hash(b"some transcript", SUITE_AES_256_GCM_SHA384);
        assert_eq!(
            transcript_384.len(),
            48,
            "SHA-384 transcript hash is 48 bytes"
        );
        let keys_384 = derive_handshake_keys(&ecdhe, &transcript_384, SUITE_AES_256_GCM_SHA384);
        assert_eq!(keys_384.handshake_secret.len(), 48);
        assert_eq!(keys_384.client_hs_traffic.len(), 48);
        assert_eq!(keys_384.client_key.len(), 32, "AES-256-GCM key is 32 bytes");
        assert_eq!(keys_384.server_key.len(), 32);

        let transcript_256 = transcript_hash(b"some transcript", SUITE_AES_128_GCM_SHA256);
        assert_eq!(
            transcript_256.len(),
            32,
            "SHA-256 transcript hash is 32 bytes"
        );
        let keys_256 = derive_handshake_keys(&ecdhe, &transcript_256, SUITE_AES_128_GCM_SHA256);
        assert_eq!(keys_256.handshake_secret.len(), 32);
        assert_ne!(
            keys_384.handshake_secret[..32],
            keys_256.handshake_secret[..],
            "the same ECDHE input must derive a DIFFERENT handshake_secret under a \
             different suite's hash — same value here would mean `suite` isn't \
             actually selecting SHA-384"
        );
    }

    /// `derive_handshake_keys` must also accept a 64-byte IKM — the
    /// `X25519MLKEM768` hybrid shared secret (`mlkem_ss(32) ‖ x25519_ss(32)`,
    /// REALITY.2 Task 9) — and produce correctly-sized, and DIFFERENT, keys
    /// from what the same suite derives from a 32-byte plain-X25519 IKM.
    /// `HKDF-Extract`'s IKM has no fixed length requirement (RFC 5869 §2.2),
    /// so this is purely a shape/non-collision check, not a published KAT (no
    /// hybrid vector exists yet the way RFC 8448 covers plain X25519).
    #[test]
    fn derive_handshake_keys_accepts_64_byte_hybrid_ecdhe() {
        let hybrid_ecdhe = [0x22u8; 64];
        let plain_ecdhe = [0x22u8; 32];
        let transcript = transcript_hash(b"some transcript", SUITE_AES_128_GCM_SHA256);

        let keys_hybrid =
            derive_handshake_keys(&hybrid_ecdhe, &transcript, SUITE_AES_128_GCM_SHA256);
        let keys_plain = derive_handshake_keys(&plain_ecdhe, &transcript, SUITE_AES_128_GCM_SHA256);

        assert_eq!(keys_hybrid.handshake_secret.len(), 32);
        assert_eq!(keys_hybrid.client_key.len(), 16);
        assert_eq!(keys_hybrid.server_key.len(), 16);
        assert_ne!(
            keys_hybrid.handshake_secret, keys_plain.handshake_secret,
            "a 64-byte hybrid IKM must derive a DIFFERENT handshake_secret than the \
             32-byte prefix alone — proving all 64 bytes are actually consumed"
        );
    }

    /// The strongest KAT in this module: `record_open` against a REAL
    /// TLS 1.3 ciphertext record from RFC 8448 (the server's
    /// EncryptedExtensions/Certificate/CertificateVerify/Finished flight,
    /// sequence number 0 under the server handshake traffic key/iv), and
    /// assert it recovers the RFC's published plaintext exactly.
    #[test]
    fn record_open_decrypts_rfc8448_server_flight() {
        let full = hex(RFC8448_EE_RECORD_FULL);
        // 5-byte outer record header: 17 03 03 02 a2.
        let (header, ciphertext) = full.split_at(5);
        assert_eq!(header, [0x17, 0x03, 0x03, 0x02, 0xa2]);

        let key = hex(RFC8448_SERVER_HS_KEY);
        let iv = iv12(hex(RFC8448_SERVER_HS_IV));
        let mut payload = ciphertext.to_vec();

        let plaintext = record_open(&key, &iv, 0, SUITE_AES_128_GCM_SHA256, 0x17, &mut payload)
            .expect("valid record");
        assert_eq!(plaintext, hex(RFC8448_EE_PLAINTEXT));
    }

    #[test]
    fn record_open_rejects_tampered_ciphertext() {
        let full = hex(RFC8448_EE_RECORD_FULL);
        let (_, ciphertext) = full.split_at(5);
        let key = hex(RFC8448_SERVER_HS_KEY);
        let iv = iv12(hex(RFC8448_SERVER_HS_IV));

        let mut payload = ciphertext.to_vec();
        let last = payload.len() - 1;
        payload[last] ^= 0xFF; // flip a tag byte
        assert_eq!(
            record_open(&key, &iv, 0, SUITE_AES_128_GCM_SHA256, 0x17, &mut payload).unwrap_err(),
            Error::Crypto
        );
    }

    #[test]
    fn record_seal_then_open_round_trips_all_suites() {
        for suite in [
            SUITE_AES_128_GCM_SHA256,
            SUITE_AES_256_GCM_SHA384,
            SUITE_CHACHA20_POLY1305_SHA256,
        ] {
            let key_len = key_len_for_suite(suite);
            let key = vec![0x42u8; key_len];
            let iv = [0x24u8; 12];
            let plaintext = b"hello REALITY handshake test vector";

            let mut sealed =
                record_seal(&key, &iv, 7, suite, CONTENT_TYPE_HANDSHAKE, plaintext).expect("seal");
            let opened = record_open(
                &key,
                &iv,
                7,
                suite,
                CONTENT_TYPE_APPLICATION_DATA,
                &mut sealed,
            )
            .expect("open");
            assert_eq!(opened, plaintext);
        }
    }

    /// `TLS_AES_256_GCM_SHA384` (`0x1302`) and `TLS_CHACHA20_POLY1305_SHA256`
    /// (`0x1303`) both use 32-byte keys — the AEAD algorithm MUST be chosen
    /// from the negotiated suite, not inferred from key length, or a
    /// same-length-but-wrong-algorithm open would silently corrupt data (or,
    /// as actually happened here, fail to interoperate with any real server
    /// that negotiates AES-256-GCM).
    #[test]
    fn record_open_rejects_wrong_suite_for_same_key_length() {
        let key = vec![0x55u8; 32];
        let iv = [0x66u8; 12];
        let sealed = record_seal(
            &key,
            &iv,
            0,
            SUITE_AES_256_GCM_SHA384,
            CONTENT_TYPE_APPLICATION_DATA,
            b"payload",
        )
        .expect("seal under AES-256-GCM");
        let mut wrong_suite_payload = sealed.clone();
        assert_eq!(
            record_open(
                &key,
                &iv,
                0,
                SUITE_CHACHA20_POLY1305_SHA256,
                CONTENT_TYPE_APPLICATION_DATA,
                &mut wrong_suite_payload,
            )
            .unwrap_err(),
            Error::Crypto,
            "opening an AES-256-GCM record as ChaCha20-Poly1305 must fail, not silently \
             misinterpret ciphertext as plaintext"
        );
    }

    #[test]
    fn record_open_rejects_wrong_sequence_number() {
        let key = vec![0x11u8; 32];
        let iv = [0x22u8; 12];
        let mut sealed = record_seal(
            &key,
            &iv,
            0,
            SUITE_CHACHA20_POLY1305_SHA256,
            CONTENT_TYPE_APPLICATION_DATA,
            b"payload",
        )
        .expect("seal at seq 0");
        assert_eq!(
            record_open(
                &key,
                &iv,
                1,
                SUITE_CHACHA20_POLY1305_SHA256,
                CONTENT_TYPE_APPLICATION_DATA,
                &mut sealed,
            )
            .unwrap_err(),
            Error::Crypto
        );
    }

    #[test]
    fn record_open_rejects_all_zero_inner_plaintext() {
        // A record whose inner plaintext is entirely zero padding (no
        // content-type byte survives stripping) must fail closed rather
        // than panic.
        let key = vec![0x33u8; 16];
        let iv = [0x44u8; 12];
        let mut sealed =
            record_seal(&key, &iv, 0, SUITE_AES_128_GCM_SHA256, 0x00, b"").expect("seal");
        // record_seal appends content_type=0x00 with no other payload, so
        // the stripped inner plaintext is empty -> EmptyInnerPlaintext.
        assert_eq!(
            record_open(
                &key,
                &iv,
                0,
                SUITE_AES_128_GCM_SHA256,
                CONTENT_TYPE_APPLICATION_DATA,
                &mut sealed,
            )
            .unwrap_err(),
            Error::EmptyInnerPlaintext
        );
    }

    #[test]
    fn handshake_keys_expose_distinct_server_hs_traffic() {
        let ecdhe = [7u8; 32];
        let transcript = transcript_hash(b"client-hello||server-hello", SUITE_AES_128_GCM_SHA256);
        let hk = derive_handshake_keys(&ecdhe, &transcript, SUITE_AES_128_GCM_SHA256);
        assert!(
            !hk.server_hs_traffic.is_empty(),
            "server_hs_traffic must be populated"
        );
        assert_eq!(hk.server_hs_traffic.len(), hk.client_hs_traffic.len());
        assert_ne!(
            hk.server_hs_traffic, hk.client_hs_traffic,
            "server and client handshake-traffic secrets must differ"
        );
    }

    #[test]
    fn record_seal_padded_opens_to_content_with_padding_stripped() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let content = b"encrypted-extensions-bytes";
        let pad_len = 40usize;
        let sealed = record_seal_padded(
            &key,
            &iv,
            0,
            SUITE_AES_128_GCM_SHA256,
            0x16,
            content,
            pad_len,
        )
        .unwrap();
        // Ciphertext-payload length is content ‖ content_type(1) ‖ pad ‖ tag(16).
        assert_eq!(sealed.len(), content.len() + 1 + pad_len + 16);
        // record_open strips the padding + content-type and recovers the content.
        let mut payload = sealed.clone();
        let opened =
            record_open(&key, &iv, 0, SUITE_AES_128_GCM_SHA256, 0x17, &mut payload).unwrap();
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
}
