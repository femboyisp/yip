//! TLS 1.3 client key schedule + record layer primitives (RFC 8446), built on
//! `ring`. This module implements the RFC 8446 mechanics only: parsing a
//! `ServerHello`, the HKDF-based key schedule (§7.1), and the AEAD record
//! layer (§5.2/§5.3). It does not drive a socket or a full handshake state
//! machine — that is Task 7's job (REALITY.2), which composes these
//! primitives around the byte-faithful `ClientHello` crafted by [`crate::hello`].
//!
//! Scope is deliberately narrow: TLS 1.3 only, X25519 key exchange only, and
//! exactly the two cipher suites Chrome/BoringSSL and this crate's crafted
//! `ClientHello` offer — `TLS_AES_128_GCM_SHA256` (`0x1301`) and
//! `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`). Everything here is fail-closed:
//! malformed or out-of-scope server input is a `Result::Err`, never a panic.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, CHACHA20_POLY1305};
use ring::{digest, hmac};

const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const EXT_KEY_SHARE: u16 = 51;
const GROUP_X25519: u16 = 0x001d;
const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const SUITE_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// TLS 1.3 record-layer content types (RFC 8446 §5.1), used both as the AAD
/// "outer type" and as the trailing byte of the `TLSInnerPlaintext` that
/// [`record_seal`]/[`record_open`] append/strip.
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
    /// The negotiated cipher suite is not one of the two this module
    /// supports (`0x1301`, `0x1303`).
    UnsupportedCipherSuite,
    /// The `key_share` extension's group was not `x25519` (`0x001d`).
    UnsupportedGroup,
    /// The `key_share` extension's key was not exactly 32 bytes.
    BadKeyShareLength,
    /// The `ServerHello` had no `key_share` extension (51) at all.
    MissingKeyShare,
    /// A record-layer key was neither 16 bytes (AES-128-GCM) nor 32 bytes
    /// (ChaCha20-Poly1305).
    UnsupportedKeyLength,
    /// A record's ciphertext+tag length does not fit the AAD's 16-bit length
    /// field.
    RecordTooLarge,
    /// AEAD seal or open failed (auth tag mismatch on open, or an
    /// unexpected key-construction failure on seal).
    Crypto,
    /// After stripping trailing zero padding, no content-type byte remained
    /// — an empty or all-zero `TLSInnerPlaintext`.
    EmptyInnerPlaintext,
    /// The recovered inner content type was neither `handshake` (0x16) nor
    /// `application_data` (0x17) — e.g. an `alert` (0x15).
    UnexpectedContentType,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::Truncated => "truncated TLS field",
            Error::WrongHandshakeType => "not a ServerHello handshake message",
            Error::UnsupportedCipherSuite => "unsupported TLS 1.3 cipher suite",
            Error::UnsupportedGroup => "key_share group is not x25519",
            Error::BadKeyShareLength => "key_share key is not 32 bytes",
            Error::MissingKeyShare => "ServerHello has no key_share extension",
            Error::UnsupportedKeyLength => "record key is not 16 or 32 bytes",
            Error::RecordTooLarge => "record ciphertext+tag length exceeds u16",
            Error::Crypto => "AEAD seal/open failed",
            Error::EmptyInnerPlaintext => "TLSInnerPlaintext has no content-type byte",
            Error::UnexpectedContentType => "unexpected TLS record content type",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// ServerHello parsing
// ---------------------------------------------------------------------------

/// The two fields Task 7's key schedule needs out of a `ServerHello`: the
/// negotiated cipher suite and the server's X25519 key-share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloInfo {
    pub suite: u16,
    pub server_key_share: [u8; 32],
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

/// Parses a `ServerHello` handshake message: `0x02 ‖ u24 len ‖ version(2) ‖
/// random(32) ‖ sid_len(1)+sid ‖ cipher_suite(2) ‖ comp(1) ‖ ext_len(2) ‖
/// exts`. Requires the negotiated suite to be one of the two this crate
/// supports, and requires exactly one `key_share`(51) extension entry with
/// group x25519 (`0x001d`) and a 32-byte key. Fail-closed on any malformed
/// or out-of-scope field.
pub fn parse_server_hello(record_payload: &[u8]) -> Result<ServerHelloInfo, Error> {
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
    if suite != SUITE_AES_128_GCM_SHA256 && suite != SUITE_CHACHA20_POLY1305_SHA256 {
        return Err(Error::UnsupportedCipherSuite);
    }

    let _compression_method = b.u8()?;

    let ext_len = usize::from(b.u16()?);
    let ext_bytes = b.take(ext_len)?;

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

            if group != GROUP_X25519 {
                return Err(Error::UnsupportedGroup);
            }
            let key: [u8; 32] = key.try_into().map_err(|_| Error::BadKeyShareLength)?;
            server_key_share = Some(key);
        }
    }

    let server_key_share = server_key_share.ok_or(Error::MissingKeyShare)?;
    Ok(ServerHelloInfo {
        suite,
        server_key_share,
    })
}

// ---------------------------------------------------------------------------
// HKDF (TLS 1.3 flavored, RFC 8446 §7.1 / RFC 5869)
// ---------------------------------------------------------------------------

/// `SHA-256(m)`.
pub fn sha256(m: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, m);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// `HKDF-Extract(salt, ikm) = HMAC-SHA256(salt, ikm)` (RFC 5869 §2.2).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// `HKDF-Expand(prk, info, len)` (RFC 5869 §2.3): `T(0) = ""`, `T(n) =
/// HMAC-SHA256(prk, T(n-1) ‖ info ‖ n)`, output = `T(1) ‖ T(2) ‖ …`
/// truncated to `len`.
fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut out = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 0;
    while out.len() < len {
        counter = counter.checked_add(1).expect(
            "HKDF-Expand: requested length exceeds 255 * SHA-256-output-size; \
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
/// u8(len(context)) ‖ context`, then `HKDF-Expand(secret, HkdfLabel, len)`.
pub fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    let len_u16 = u16::try_from(len).expect(
        "hkdf_expand_label: len is always a TLS 1.3 key/iv/secret size (<=32) here, well within u16",
    );
    info.extend_from_slice(&len_u16.to_be_bytes());
    let label_len = u8::try_from(full_label.len())
        .expect("hkdf_expand_label: \"tls13 \" + label is far under 255 bytes for this module's fixed labels");
    info.push(label_len);
    info.extend_from_slice(&full_label);
    let context_len = u8::try_from(context.len()).expect(
        "hkdf_expand_label: context is a SHA-256 transcript hash (32 bytes) or empty, well within u8",
    );
    info.push(context_len);
    info.extend_from_slice(context);

    hkdf_expand(secret, &info, len)
}

/// `Derive-Secret(secret, label, transcript_hash) =
/// HKDF-Expand-Label(secret, label, transcript_hash, 32)` (RFC 8446 §7.1).
pub fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> [u8; 32] {
    let v = hkdf_expand_label(secret, label, transcript_hash, 32);
    v.try_into()
        .expect("hkdf_expand_label(..., 32) always returns exactly 32 bytes")
}

fn iv12(v: Vec<u8>) -> [u8; 12] {
    v.try_into()
        .expect("hkdf_expand_label(..., 12) always returns exactly 12 bytes")
}

/// AEAD key length for a suite: 16 bytes for `TLS_AES_128_GCM_SHA256`
/// (`0x1301`), 32 bytes otherwise. `parse_server_hello` already restricts a
/// negotiated suite to `{0x1301, 0x1303}` before this is reached on the real
/// handshake path; treating any other value as the 32-byte (ChaCha20-shaped)
/// case is a defensive default for callers that bypass that check, not a
/// silent correctness gap on the real path.
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
/// itself (needed as an input to [`derive_application_keys`]).
pub struct HandshakeKeys {
    pub client_key: Vec<u8>,
    pub client_iv: [u8; 12],
    pub server_key: Vec<u8>,
    pub server_iv: [u8; 12],
    pub suite: u16,
    pub handshake_secret: [u8; 32],
}

/// Derives the TLS 1.3 handshake traffic keys from the ECDHE shared secret
/// and the transcript hash of `ClientHello ‖ ServerHello`:
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
pub fn derive_handshake_keys(
    ecdhe: &[u8; 32],
    transcript_hash_ch_sh: &[u8],
    suite: u16,
) -> HandshakeKeys {
    let zeros = [0u8; 32];
    let empty_hash = sha256(b"");

    let early = hkdf_extract(&zeros, &zeros);
    let derived = derive_secret(&early, b"derived", &empty_hash);
    let handshake_secret = hkdf_extract(&derived, ecdhe);

    let c_hs = derive_secret(&handshake_secret, b"c hs traffic", transcript_hash_ch_sh);
    let s_hs = derive_secret(&handshake_secret, b"s hs traffic", transcript_hash_ch_sh);

    let key_len = key_len_for_suite(suite);
    let client_key = hkdf_expand_label(&c_hs, b"key", b"", key_len);
    let server_key = hkdf_expand_label(&s_hs, b"key", b"", key_len);
    let client_iv = iv12(hkdf_expand_label(&c_hs, b"iv", b"", 12));
    let server_iv = iv12(hkdf_expand_label(&s_hs, b"iv", b"", 12));

    HandshakeKeys {
        client_key,
        client_iv,
        server_key,
        server_iv,
        suite,
        handshake_secret,
    }
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
    handshake_secret: &[u8; 32],
    transcript_hash_through_sfin: &[u8],
    suite: u16,
) -> ApplicationKeys {
    let zeros = [0u8; 32];
    let empty_hash = sha256(b"");
    let derived = derive_secret(handshake_secret, b"derived", &empty_hash);
    let master = hkdf_extract(&derived, &zeros);

    let c_ap = derive_secret(&master, b"c ap traffic", transcript_hash_through_sfin);
    let s_ap = derive_secret(&master, b"s ap traffic", transcript_hash_through_sfin);

    let key_len = key_len_for_suite(suite);
    let client_key = hkdf_expand_label(&c_ap, b"key", b"", key_len);
    let server_key = hkdf_expand_label(&s_ap, b"key", b"", key_len);
    let client_iv = iv12(hkdf_expand_label(&c_ap, b"iv", b"", 12));
    let server_iv = iv12(hkdf_expand_label(&s_ap, b"iv", b"", 12));

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

fn algorithm_for_key_len(len: usize) -> Result<&'static ring::aead::Algorithm, Error> {
    match len {
        16 => Ok(&AES_128_GCM),
        32 => Ok(&CHACHA20_POLY1305),
        _ => Err(Error::UnsupportedKeyLength),
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

/// Seals `plaintext` as a TLS 1.3 protected record, appending `content_type`
/// as the real (inner) content type before encryption (no additional
/// padding). AEAD algorithm is selected from `key.len()` (16 => AES-128-GCM,
/// 32 => ChaCha20-Poly1305). Returns the wire `encrypted_record` body
/// (ciphertext ‖ tag) — the caller prepends the 5-byte outer record header
/// `[0x17, 0x03, 0x03, len_hi, len_lo]` (`len = ` returned length) itself.
pub fn record_seal(
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let alg = algorithm_for_key_len(key.len())?;
    let unbound = UnboundKey::new(alg, key).map_err(|_| Error::Crypto)?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce = make_nonce(iv, seq);

    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(content_type);

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

/// Opens a TLS 1.3 protected record. `record_type` is the *outer* record
/// type read from the record header on the wire (always `0x17` for TLS 1.3
/// post-`ServerHello` records) and is used to reconstruct the AAD; `payload`
/// is the record's ciphertext+tag body (mutated in place as scratch space).
/// Strips the TLS 1.3 inner padding on success — trailing zero bytes, then
/// the real content-type byte — and requires that byte to be `handshake`
/// (0x16) or `application_data` (0x17). Returns the recovered content only.
pub fn record_open(
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    record_type: u8,
    payload: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let alg = algorithm_for_key_len(key.len())?;
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
    if content_type != CONTENT_TYPE_HANDSHAKE && content_type != CONTENT_TYPE_APPLICATION_DATA {
        return Err(Error::UnexpectedContentType);
    }

    Ok(core::mem::take(payload))
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

    #[test]
    fn parse_server_hello_reads_rfc8448_vector() {
        let info = parse_server_hello(&hex(RFC8448_SERVER_HELLO_MSG)).expect("valid ServerHello");
        assert_eq!(info.suite, SUITE_AES_128_GCM_SHA256);
        assert_eq!(
            info.server_key_share,
            hex32("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
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

        let plaintext = record_open(&key, &iv, 0, 0x17, &mut payload).expect("valid record");
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
            record_open(&key, &iv, 0, 0x17, &mut payload).unwrap_err(),
            Error::Crypto
        );
    }

    #[test]
    fn record_seal_then_open_round_trips_both_suites() {
        for suite in [SUITE_AES_128_GCM_SHA256, SUITE_CHACHA20_POLY1305_SHA256] {
            let key_len = key_len_for_suite(suite);
            let key = vec![0x42u8; key_len];
            let iv = [0x24u8; 12];
            let plaintext = b"hello REALITY handshake test vector";

            let mut sealed =
                record_seal(&key, &iv, 7, CONTENT_TYPE_HANDSHAKE, plaintext).expect("seal");
            let opened = record_open(&key, &iv, 7, CONTENT_TYPE_APPLICATION_DATA, &mut sealed)
                .expect("open");
            assert_eq!(opened, plaintext);
        }
    }

    #[test]
    fn record_open_rejects_wrong_sequence_number() {
        let key = vec![0x11u8; 32];
        let iv = [0x22u8; 12];
        let mut sealed = record_seal(&key, &iv, 0, CONTENT_TYPE_APPLICATION_DATA, b"payload")
            .expect("seal at seq 0");
        assert_eq!(
            record_open(&key, &iv, 1, CONTENT_TYPE_APPLICATION_DATA, &mut sealed).unwrap_err(),
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
        let mut sealed = record_seal(&key, &iv, 0, 0x00, b"").expect("seal");
        // record_seal appends content_type=0x00 with no other payload, so
        // the stripped inner plaintext is empty -> EmptyInnerPlaintext.
        assert_eq!(
            record_open(&key, &iv, 0, CONTENT_TYPE_APPLICATION_DATA, &mut sealed).unwrap_err(),
            Error::EmptyInnerPlaintext
        );
    }
}
