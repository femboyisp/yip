//! JA3 and JA4 TLS-fingerprint computation over a raw ClientHello handshake
//! message (`0x01 ‖ u24 len ‖ body`). Pure, fail-closed parsing — malformed
//! or truncated input yields `None`, never a panic (`unsafe_code` is
//! crate-forbidden and there is nothing here that would need it).
//!
//! JA3: <https://github.com/salesforce/ja3>. JA4:
//! <https://github.com/FoxIO-LLC/ja4> (`JA4_r` raw form is the ground truth
//! we cross-check field ordering against; see
//! `docs/superpowers/specs/reality-2-chrome150-fingerprint.txt`).

use md5::Md5;
use sha2::{Digest, Sha256};

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

/// GREASE values per RFC 8701: any 16-bit value `v` with `(v & 0x0f0f) ==
/// 0x0a0a`. JA3 and JA4 both exclude GREASE from every list they hash.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

/// Fields pulled out of a ClientHello that JA3/JA4 need. Everything here is
/// still in wire order and NOT GREASE-filtered — filtering happens at the
/// `ja3`/`ja4` call sites, since the two fingerprints filter slightly
/// different subsets (JA4 doesn't filter `signature_algorithms`, for
/// instance).
struct ParsedHello {
    version: u16,
    ciphers: Vec<u16>,
    ext_types: Vec<u16>,
    groups: Vec<u16>,
    ec_point_formats: Vec<u8>,
    sni_present: bool,
    alpn: Option<String>,
    supported_versions: Vec<u16>,
    sig_algs: Vec<u16>,
}

/// The JA3 decimal fingerprint string: `SSLVersion,Ciphers,Extensions,
/// EllipticCurves,ECPointFormats`, the middle four `-`-joined decimal lists,
/// GREASE excluded from all four. `None` on a malformed/truncated ClientHello.
pub fn ja3(hello_msg: &[u8]) -> Option<String> {
    let p = parse(hello_msg)?;
    let ciphers = filter_grease(&p.ciphers);
    let exts = filter_grease(&p.ext_types);
    let groups = filter_grease(&p.groups);
    Some(format!(
        "{},{},{},{},{}",
        p.version,
        join_dec_u16(&ciphers),
        join_dec_u16(&exts),
        join_dec_u16(&groups),
        join_dec_u8(&p.ec_point_formats),
    ))
}

/// Lowercase hex MD5 of the [`ja3`] string. `None` propagates from `ja3`.
pub fn ja3_hash(hello_msg: &[u8]) -> Option<String> {
    let s = ja3(hello_msg)?;
    let mut hasher = Md5::new();
    hasher.update(s.as_bytes());
    Some(hex_string(&hasher.finalize()))
}

/// The JA4 fingerprint string:
/// `<protocol><version><sni><cipher_count><ext_count><alpn>_<hash_a>_<hash_b>`.
/// `protocol` is always `t` (TLS-over-TCP; yip's TLS-mimicry is TCP-carried).
/// `version` is the highest entry in `supported_versions` (ext 43), GREASE
/// excluded, falling back to `legacy_version` if that extension is absent.
/// `hash_a` is the first 12 hex chars of `sha256` over the sorted,
/// comma-joined, 4-hex-digit non-GREASE cipher IDs. `hash_b` is the first 12
/// hex chars of `sha256` over the sorted, comma-joined, 4-hex-digit
/// non-GREASE extension IDs (excluding SNI and ALPN), then `_`, then the
/// in-order comma-joined 4-hex-digit `signature_algorithms` IDs.
pub fn ja4(hello_msg: &[u8]) -> Option<String> {
    let p = parse(hello_msg)?;

    let ciphers = filter_grease(&p.ciphers);
    let ext_types = filter_grease(&p.ext_types);
    let versions = filter_grease(&p.supported_versions);

    let version_source = versions.iter().copied().max().unwrap_or(p.version);
    let version_code = ja4_version_code(version_source);

    let sni = if p.sni_present { 'd' } else { 'i' };
    let cipher_count = ciphers.len().min(99);
    let ext_count = ext_types.len().min(99);
    let alpn = p.alpn.as_deref().unwrap_or("00");

    let prefix = format!("t{version_code}{sni}{cipher_count:02}{ext_count:02}{alpn}");

    let hash_a = if ciphers.is_empty() {
        "0".repeat(12)
    } else {
        let mut sorted = ciphers.clone();
        sorted.sort_unstable();
        sha256_hex12(&join_hex4(&sorted))
    };

    let mut hashed_exts: Vec<u16> = ext_types
        .iter()
        .copied()
        .filter(|&v| v != EXT_SERVER_NAME && v != EXT_ALPN)
        .collect();
    hashed_exts.sort_unstable();
    let hash_b_input = format!("{}_{}", join_hex4(&hashed_exts), join_hex4(&p.sig_algs));
    let hash_b = sha256_hex12(&hash_b_input);

    Some(format!("{prefix}_{hash_a}_{hash_b}"))
}

/// Maps a TLS version number to its JA4 two-character code. Unknown values
/// (including the case where neither `supported_versions` nor a recognized
/// `legacy_version` is available) fall back to `"00"`, matching the JA4 spec's
/// treatment of an indeterminate version.
fn ja4_version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn filter_grease(vals: &[u16]) -> Vec<u16> {
    vals.iter().copied().filter(|&v| !is_grease(v)).collect()
}

fn join_dec_u16(vals: &[u16]) -> String {
    vals.iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn join_dec_u8(vals: &[u8]) -> String {
    vals.iter().map(u8::to_string).collect::<Vec<_>>().join("-")
}

fn join_hex4(vals: &[u16]) -> String {
    vals.iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hex = hex_string(&hasher.finalize());
    hex.get(..12).map_or(hex.clone(), str::to_owned)
}

/// Parses the ClientHello handshake message down to the fields JA3/JA4 need.
/// `None` on any malformed or truncated input — every accessor here is a
/// `.get(..)?`, never an indexing panic.
fn parse(hello_msg: &[u8]) -> Option<ParsedHello> {
    let &handshake_type = hello_msg.first()?;
    if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }
    let body_len = u24_be(hello_msg.get(1..4)?)?;
    if 4 + body_len != hello_msg.len() {
        return None;
    }
    let body = hello_msg.get(4..4 + body_len)?;

    let version = u16_be(body.get(..2)?)?;
    let rest = body.get(2..)?;
    let rest = rest.get(32..)?; // skip client_random

    let &sid_len = rest.first()?;
    let rest = rest.get(1 + usize::from(sid_len)..)?;

    let cs_len = usize::from(u16_be(rest.get(..2)?)?);
    let ciphers = parse_u16_list(rest.get(2..2 + cs_len)?)?;
    let rest = rest.get(2 + cs_len..)?;

    let &cm_len = rest.first()?;
    let rest = rest.get(1 + usize::from(cm_len)..)?;

    let ext_total_len = usize::from(u16_be(rest.get(..2)?)?);
    let extensions = rest.get(2..2 + ext_total_len)?;

    let mut ext_types = Vec::new();
    let mut groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut sni_present = false;
    let mut alpn = None;
    let mut supported_versions = Vec::new();
    let mut sig_algs = Vec::new();

    let mut buf = extensions;
    while !buf.is_empty() {
        let ext_type = u16_be(buf.get(..2)?)?;
        let ext_len = usize::from(u16_be(buf.get(2..4)?)?);
        let ext_body = buf.get(4..4 + ext_len)?;
        ext_types.push(ext_type);
        match ext_type {
            EXT_SERVER_NAME => sni_present = true,
            EXT_SUPPORTED_GROUPS => groups = parse_u16_len16_list(ext_body)?,
            EXT_EC_POINT_FORMATS => ec_point_formats = parse_u8_len8_list(ext_body)?,
            EXT_SIGNATURE_ALGORITHMS => sig_algs = parse_u16_len16_list(ext_body)?,
            EXT_ALPN => alpn = parse_first_alpn(ext_body),
            EXT_SUPPORTED_VERSIONS => supported_versions = parse_u16_len8_list(ext_body)?,
            _ => {}
        }
        buf = buf.get(4 + ext_len..)?;
    }

    Some(ParsedHello {
        version,
        ciphers,
        ext_types,
        groups,
        ec_point_formats,
        sni_present,
        alpn,
        supported_versions,
        sig_algs,
    })
}

/// A bare run of big-endian `u16` values filling the whole slice (the
/// caller already consumed the list's own length prefix).
fn parse_u16_list(mut buf: &[u8]) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        out.push(u16_be(buf.get(..2)?)?);
        buf = buf.get(2..)?;
    }
    Some(out)
}

/// `list_len(u16) | u16 items...` — used by `supported_groups` (ext 10) and
/// `signature_algorithms` (ext 13).
fn parse_u16_len16_list(body: &[u8]) -> Option<Vec<u16>> {
    let list_len = usize::from(u16_be(body.get(..2)?)?);
    parse_u16_list(body.get(2..2 + list_len)?)
}

/// `list_len(u8) | u16 items...` — used by `supported_versions` (ext 43).
fn parse_u16_len8_list(body: &[u8]) -> Option<Vec<u16>> {
    let &list_len = body.first()?;
    parse_u16_list(body.get(1..1 + usize::from(list_len))?)
}

/// `list_len(u8) | u8 items...` — used by `ec_point_formats` (ext 11).
fn parse_u8_len8_list(body: &[u8]) -> Option<Vec<u8>> {
    let &list_len = body.first()?;
    body.get(1..1 + usize::from(list_len)).map(<[u8]>::to_vec)
}

/// `application_layer_protocol_negotiation` (ext 16) body: `list_len(u16) |
/// (name_len(u8) | name_bytes)...`. Only the first protocol name is kept,
/// truncated to its first 2 characters as JA4 requires.
fn parse_first_alpn(body: &[u8]) -> Option<String> {
    let list_len = usize::from(u16_be(body.get(..2)?)?);
    let list = body.get(2..2 + list_len)?;
    let &name_len = list.first()?;
    let name = list.get(1..1 + usize::from(name_len))?;
    let s = std::str::from_utf8(name).ok()?;
    Some(s.chars().take(2).collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::HelloWriter;

    /// Builds a tiny, hand-verifiable ClientHello handshake message:
    ///
    /// - ciphers: `[GREASE, 0x1301, 0x1302]`
    /// - extensions (wire order): `[GREASE, server_name(0), supported_groups(10)
    ///   =[GREASE,29,23], ec_point_formats(11)=[0], signature_algorithms(13)
    ///   =[0x0403,0x0804], alpn(16)="h2", supported_versions(43)=[GREASE,0x0304]]`
    ///
    /// GREASE entries prove the filter; the rest is deliberately small enough
    /// to hand-compute (values below verified with `md5sum`/`sha256sum`, see
    /// task report).
    fn tiny_hello() -> Vec<u8> {
        let mut body = HelloWriter::new();
        body.u16(0x0303); // legacy_version
        body.bytes(&[0u8; 32]); // client_random
        body.u8_prefixed(|_| {}); // empty session_id

        body.u16_prefixed(|w| {
            w.u16(0x0a0a); // GREASE cipher
            w.u16(0x1301);
            w.u16(0x1302);
        });

        body.u8_prefixed(|w| {
            w.u8(0x00); // compression: null
        });

        body.u16_prefixed(|w| {
            // GREASE extension, empty body.
            w.u16(0x0a0a);
            w.u16_prefixed(|_| {});

            // server_name (ext 0)
            w.u16(0);
            w.u16_prefixed(|w| {
                w.u16_prefixed(|w| {
                    w.u8(0); // name_type = host_name
                    w.u16_prefixed(|w| w.bytes(b"example.com"));
                });
            });

            // supported_groups (ext 10)
            w.u16(10);
            w.u16_prefixed(|w| {
                w.u16_prefixed(|w| {
                    w.u16(0x0a0a); // GREASE
                    w.u16(0x001d); // x25519 = 29
                    w.u16(0x0017); // secp256r1 = 23
                });
            });

            // ec_point_formats (ext 11)
            w.u16(11);
            w.u16_prefixed(|w| {
                w.u8_prefixed(|w| w.u8(0x00));
            });

            // signature_algorithms (ext 13)
            w.u16(13);
            w.u16_prefixed(|w| {
                w.u16_prefixed(|w| {
                    w.u16(0x0403);
                    w.u16(0x0804);
                });
            });

            // alpn (ext 16)
            w.u16(16);
            w.u16_prefixed(|w| {
                w.u16_prefixed(|w| {
                    w.u8_prefixed(|w| w.bytes(b"h2"));
                });
            });

            // supported_versions (ext 43)
            w.u16(43);
            w.u16_prefixed(|w| {
                w.u8_prefixed(|w| {
                    w.u16(0x0a0a); // GREASE
                    w.u16(0x0304); // TLS 1.3
                });
            });
        });

        let body_bytes = body.into_bytes();
        let mut msg = Vec::with_capacity(4 + body_bytes.len());
        msg.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = u32::try_from(body_bytes.len()).expect("tiny hello fits u24");
        msg.extend_from_slice(&len.to_be_bytes()[1..]);
        msg.extend_from_slice(&body_bytes);
        msg
    }

    #[test]
    fn ja3_of_known_hello_matches() {
        let hello = tiny_hello();
        // version 771 (0x0303), ciphers 4865/4866 (GREASE cipher excluded),
        // extensions 0-10-11-13-16-43 in wire order (GREASE ext excluded),
        // groups 29-23 (GREASE group excluded), ec point format 0.
        assert_eq!(
            ja3(&hello).unwrap(),
            "771,4865-4866,0-10-11-13-16-43,29-23,0"
        );
    }

    #[test]
    fn ja3_hash_is_md5_of_ja3_string() {
        let hello = tiny_hello();
        // md5sum of the ja3 string above, verified out-of-band.
        assert_eq!(
            ja3_hash(&hello).unwrap(),
            "8b85ec5fe3da506907f3cac65cd06803"
        );
    }

    #[test]
    fn ja4_of_known_hello_matches() {
        let hello = tiny_hello();
        // t + version(13, from non-GREASE supported_versions) + sni(d) +
        // cipher_count(02) + ext_count(06) + alpn(h2), then hash_a over
        // sorted "1301,1302" and hash_b over sorted non-SNI/ALPN exts
        // "000a,000b,000d,002b" + "_" + sig_algs "0403,0804" (sha256, first
        // 12 hex chars each — verified out-of-band with sha256sum).
        assert_eq!(ja4(&hello).unwrap(), "t13d0206h2_62ed6f6ca7ad_fb71836bce29");
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(ja3(&[]), None);
        assert_eq!(ja3_hash(&[]), None);
        assert_eq!(ja4(&[]), None);
    }

    #[test]
    fn rejects_truncated_input() {
        let hello = tiny_hello();
        let truncated = &hello[..hello.len() - 5];
        assert_eq!(ja3(truncated), None);
        assert_eq!(ja4(truncated), None);
    }

    #[test]
    fn rejects_wrong_handshake_type() {
        let mut hello = tiny_hello();
        hello[0] = 0x02; // ServerHello, not ClientHello
        assert_eq!(ja3(&hello), None);
    }
}
