//! Certificate and SPKI parsing and flight scanning for REALITY handshake verification.

use crate::error::Error;
use crate::stream::record::MAX_HANDSHAKE_MSG_LEN;

/// Handshake message type for `Certificate` (RFC 8446 §4.4.2).
pub(crate) const HS_TYPE_CERTIFICATE: u8 = 0x0b;

/// Handshake message type for `CertificateVerify` (RFC 8446 §4.4.3).
pub(crate) const HS_TYPE_CERTIFICATE_VERIFY: u8 = 0x0f;

/// A generous sanity bound on a single leaf certificate's DER length — real
/// leaf certs are a few KiB; 64 KiB is generous headroom. Bounds
/// [`certificate_leaf_der`]'s allocation against a hostile/MITM peer (the
/// outer TLS is zero-server-auth) claiming an absurd `cert_data` length
/// within the already-bounded server flight — defense in depth alongside
/// [`MAX_SERVER_FLIGHT_LEN`]/[`MAX_HANDSHAKE_MSG_LEN`].
pub(crate) const MAX_LEAF_CERT_DER_LEN: usize = 64 * 1024;

/// What REALITY.4b verification needs out of the server's
/// EncryptedExtensions/Certificate/CertificateVerify/Finished flight: the
/// leaf certificate's raw DER, the byte offset in the flight at which the
/// `CertificateVerify` message begins (the RFC 8446 §4.4.3 transcript
/// boundary — everything strictly before this offset is
/// `Transcript-Hash(ClientHello‥Certificate)`), and the `CertificateVerify`
/// message's raw `signature` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertFlightInfo {
    /// Byte offset in the flight where `Certificate` ends (and `CertificateVerify` begins).
    pub(crate) cert_msg_end: usize,
    /// Byte offset in the flight where `CertificateVerify` begins (identical to `cert_msg_end`).
    pub(crate) certverify_start: usize,
    /// The leaf certificate's raw DER.
    pub(crate) leaf_der: Vec<u8>,
    /// The raw `signature` field extracted from `CertificateVerify`.
    pub(crate) signature: Vec<u8>,
}

/// Scans `hs_flight` (see `find_finished_end` for its shape — the
/// concatenation of the server's decrypted post-`ServerHello` handshake
/// messages) for the first `Certificate` message and the `CertificateVerify`
/// message, extracting what `verify_reality_binding` needs from each.
/// Fail-closed: a missing message, truncated field, or an out-of-bounds
/// value is `Err(Error::RealityVerify(_))`; every access is bounds-checked
/// (`.get`, never direct indexing past a validated point) so hostile bytes
/// cannot panic this.
pub(crate) fn scan_cert_flight(hs_flight: &[u8]) -> Result<CertFlightInfo, Error> {
    let mut pos = 0;
    let mut leaf_der: Option<Vec<u8>> = None;

    while hs_flight.len() >= pos + 4 {
        let msg_type = hs_flight[pos];
        let len = (usize::from(hs_flight[pos + 1]) << 16)
            | (usize::from(hs_flight[pos + 2]) << 8)
            | usize::from(hs_flight[pos + 3]);
        if len > MAX_HANDSHAKE_MSG_LEN {
            return Err(Error::RealityVerify(
                "server handshake message exceeds sane length bound",
            ));
        }
        let body_start = pos + 4;
        let msg_end = body_start + len;
        let Some(body) = hs_flight.get(body_start..msg_end) else {
            break; // not fully buffered — cannot happen on an already-complete flight
        };

        if msg_type == HS_TYPE_CERTIFICATE && leaf_der.is_none() {
            leaf_der = Some(certificate_leaf_der(body)?);
        }
        if msg_type == HS_TYPE_CERTIFICATE_VERIFY {
            let signature = certificate_verify_signature(body)?;
            let leaf_der = leaf_der.ok_or(Error::RealityVerify(
                "server flight is missing a Certificate message",
            ))?;
            return Ok(CertFlightInfo {
                cert_msg_end: pos,
                certverify_start: pos,
                leaf_der,
                signature,
            });
        }
        pos = msg_end;
    }

    Err(Error::RealityVerify(
        "server flight is missing a CertificateVerify message",
    ))
}

/// Extracts every `CertificateEntry`'s raw DER from a `Certificate` message
/// body (RFC 8446 §4.4.2): `context_len(1) ‖ context ‖ list_len(3) ‖
/// [cert_data_len(3) ‖ cert_data ‖ ext_len(2) ‖ ext]…`. Returns
/// `(leaf_der, intermediates_der)` — the FIRST entry is the leaf, every
/// SUBSEQUENT entry is returned verbatim, in chain order, as
/// `intermediates_der`. Fail-closed on truncation, an empty list, or a leaf
/// exceeding [`MAX_LEAF_CERT_DER_LEN`] — this bound is intentionally NOT
/// applied to intermediates (real intermediate CA certs can legitimately run
/// larger than a leaf), which are instead bounded by the already-enforced
/// [`MAX_HANDSHAKE_MSG_LEN`]/[`MAX_SERVER_FLIGHT_LEN`] on the whole
/// message/flight.
pub(crate) fn certificate_chain_ders(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), Error> {
    let ctx_len = usize::from(
        *body
            .first()
            .ok_or(Error::RealityVerify("truncated Certificate message"))?,
    );
    let list_len_start = 1 + ctx_len;
    let list_len_bytes = body
        .get(list_len_start..list_len_start + 3)
        .ok_or(Error::RealityVerify("truncated Certificate message"))?;
    let list_len = (usize::from(list_len_bytes[0]) << 16)
        | (usize::from(list_len_bytes[1]) << 8)
        | usize::from(list_len_bytes[2]);
    let list_start = list_len_start + 3;
    let list_end = list_start + list_len;
    let list = body
        .get(list_start..list_end)
        .ok_or(Error::RealityVerify("truncated Certificate list"))?;

    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while let Some(cd_len_bytes) = list.get(i..i + 3) {
        let cd_len = (usize::from(cd_len_bytes[0]) << 16)
            | (usize::from(cd_len_bytes[1]) << 8)
            | usize::from(cd_len_bytes[2]);
        let cert_start = i + 3;
        let cert_end = cert_start + cd_len;
        let cert_data = list
            .get(cert_start..cert_end)
            .ok_or(Error::RealityVerify("truncated certificate entry"))?;
        let ext_len_bytes = list
            .get(cert_end..cert_end + 2)
            .ok_or(Error::RealityVerify(
                "truncated certificate entry extensions",
            ))?;
        let ext_len = usize::from(u16::from_be_bytes([ext_len_bytes[0], ext_len_bytes[1]]));
        let ext_start = cert_end + 2;
        let ext_end = ext_start + ext_len;
        if ext_end > list.len() {
            return Err(Error::RealityVerify(
                "truncated certificate entry extensions",
            ));
        }
        entries.push(cert_data.to_vec());
        i = ext_end;
    }

    let mut iter = entries.into_iter();
    let leaf = iter
        .next()
        .ok_or(Error::RealityVerify("empty Certificate list"))?;
    if leaf.is_empty() || leaf.len() > MAX_LEAF_CERT_DER_LEN {
        return Err(Error::RealityVerify(
            "leaf certificate length out of bounds",
        ));
    }
    Ok((leaf, iter.collect()))
}

/// Extracts the first `CertificateEntry`'s raw DER (the leaf) from a
/// `Certificate` message body (RFC 8446 §4.4.2): `context_len(1) ‖ context
/// ‖ list_len(3) ‖ [cert_data_len(3) ‖ cert_data ‖ ext_len(2) ‖ ext]…`.
/// Fail-closed on truncation, an empty list, or a leaf exceeding
/// [`MAX_LEAF_CERT_DER_LEN`]. A thin wrapper over
/// [`certificate_chain_ders`] (REALITY.5a), which does the identical walk
/// but also returns any subsequent chain certs; [`scan_cert_flight`] (and,
/// through it, REALITY.4b's verify path) only ever needs the leaf, so it
/// keeps calling this narrower name.
pub(crate) fn certificate_leaf_der(body: &[u8]) -> Result<Vec<u8>, Error> {
    certificate_chain_ders(body).map(|(leaf, _intermediates)| leaf)
}

/// Extracts the `signature` field from a `CertificateVerify` message body
/// (RFC 8446 §4.4.3): `algorithm(2) ‖ signature_len(2) ‖ signature`. The
/// `algorithm` field is intentionally never returned — REALITY.4b hard-pins
/// `ecdsa_secp256r1_sha256` and never reads/trusts the server's announced
/// scheme (see `verify_certificate_verify`). Fail-closed on truncation or
/// an empty signature.
pub(crate) fn certificate_verify_signature(body: &[u8]) -> Result<Vec<u8>, Error> {
    let sig_len_bytes = body
        .get(2..4)
        .ok_or(Error::RealityVerify("truncated CertificateVerify message"))?;
    let sig_len = usize::from(u16::from_be_bytes([sig_len_bytes[0], sig_len_bytes[1]]));
    let sig = body.get(4..4 + sig_len).ok_or(Error::RealityVerify(
        "truncated CertificateVerify signature",
    ))?;
    if sig.is_empty() {
        return Err(Error::RealityVerify("empty CertificateVerify signature"));
    }
    Ok(sig.to_vec())
}

/// Extracts the P-256 subject public key from a leaf certificate's DER (RFC
/// 5280 `Certificate` → `TBSCertificate` → `SubjectPublicKeyInfo`), returned
/// as uncompressed SEC1 bytes (`0x04 ‖ X ‖ Y`, 65 bytes) — the same encoding
/// `auth::derive_cert_key`'s `public_sec1` uses, so the two can be
/// compared byte-for-byte.
///
/// Walks the DER with the `der` crate's bounds-checked, panic-free reader
/// (never hand-rolled ASN.1 length arithmetic on untrusted bytes):
/// `TBSCertificate`'s fields are read sequentially — `[0] EXPLICIT Version`
/// is OPTIONAL (default v1), so it is skipped only when present, otherwise
/// the field just peeked at IS `serialNumber` — up through
/// `subjectPublicKeyInfo`, whose raw TLV is handed to
/// [`p256::ecdsa::VerifyingKey::from_public_key_der`]. That call itself
/// fail-closes on "not an EC key", "not the P-256 curve OID", and "not a
/// valid point on the curve" — this function does not duplicate any of
/// those checks.
pub(crate) fn spki_sec1_pubkey_from_der(cert_der: &[u8]) -> Result<Vec<u8>, Error> {
    use der::{AnyRef, Decode, Reader, SliceReader, Tag, Tagged};
    use p256::pkcs8::DecodePublicKey;

    let bad_der = || Error::RealityVerify("leaf certificate is not valid DER");

    let mut top = SliceReader::new(cert_der).map_err(|_| bad_der())?;
    let cert_any = AnyRef::decode(&mut top).map_err(|_| bad_der())?;
    if cert_any.tag() != Tag::Sequence {
        return Err(bad_der());
    }

    let mut cert_body = SliceReader::new(cert_any.value()).map_err(|_| bad_der())?;
    let tbs_any = AnyRef::decode(&mut cert_body).map_err(|_| bad_der())?;
    if tbs_any.tag() != Tag::Sequence {
        return Err(bad_der());
    }

    let mut tbs = SliceReader::new(tbs_any.value()).map_err(|_| bad_der())?;

    // version [0] EXPLICIT is OPTIONAL; if present, consume+discard it — the
    // NEXT field is then serialNumber. If absent, the field already peeked
    // at (still unconsumed) IS serialNumber.
    let first_tag = der::Tag::peek(&tbs).map_err(|_| bad_der())?;
    if first_tag.is_context_specific() {
        tbs.tlv_bytes().map_err(|_| bad_der())?; // version
    }
    tbs.tlv_bytes().map_err(|_| bad_der())?; // serialNumber
    tbs.tlv_bytes().map_err(|_| bad_der())?; // signature AlgorithmIdentifier
    tbs.tlv_bytes().map_err(|_| bad_der())?; // issuer
    tbs.tlv_bytes().map_err(|_| bad_der())?; // validity
    tbs.tlv_bytes().map_err(|_| bad_der())?; // subject
    let spki_der = tbs.tlv_bytes().map_err(|_| bad_der())?; // subjectPublicKeyInfo

    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der).map_err(|_| {
        Error::RealityVerify("leaf certificate's public key is not a valid P-256 SPKI")
    })?;
    Ok(vk.to_sec1_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cert_body(ctx: &[u8], entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(u8::try_from(ctx.len()).unwrap());
        body.extend_from_slice(ctx);

        let mut list = Vec::new();
        for (cert, exts) in entries {
            let cert_len = u32::try_from(cert.len()).unwrap().to_be_bytes();
            list.extend_from_slice(&cert_len[1..]);
            list.extend_from_slice(cert);
            let ext_len = u16::try_from(exts.len()).unwrap().to_be_bytes();
            list.extend_from_slice(&ext_len);
            list.extend_from_slice(exts);
        }

        let list_len = u32::try_from(list.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&list_len[1..]);
        body.extend_from_slice(&list);
        body
    }

    fn build_cert_verify_body(alg: u16, sig: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&alg.to_be_bytes());
        let sig_len = u16::try_from(sig.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&sig_len);
        body.extend_from_slice(sig);
        body
    }

    fn build_hs_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(4 + body.len());
        msg.push(msg_type);
        let len_be = u32::try_from(body.len()).unwrap().to_be_bytes();
        msg.extend_from_slice(&len_be[1..]);
        msg.extend_from_slice(body);
        msg
    }

    #[test]
    fn certificate_chain_ders_parses_leaf_and_intermediates() {
        let leaf = vec![0x11u8; 32];
        let inter1 = vec![0x22u8; 24];
        let inter2 = vec![0x33u8; 16];
        let body = build_cert_body(
            &[],
            &[(&leaf, &[]), (&inter1, &[0x00, 0x01]), (&inter2, &[])],
        );

        let (parsed_leaf, intermediates) = certificate_chain_ders(&body).expect("parse chain");
        assert_eq!(parsed_leaf, leaf);
        assert_eq!(intermediates, vec![inter1, inter2]);
    }

    #[test]
    fn certificate_chain_ders_leaf_only() {
        let leaf = vec![0x42u8; 64];
        let body = build_cert_body(&[0xAA], &[(&leaf, &[])]);

        let (parsed_leaf, intermediates) = certificate_chain_ders(&body).expect("parse leaf only");
        assert_eq!(parsed_leaf, leaf);
        assert!(intermediates.is_empty());
    }

    #[test]
    fn certificate_chain_ders_rejects_empty_list() {
        let body = build_cert_body(&[], &[]);
        assert!(matches!(
            certificate_chain_ders(&body),
            Err(Error::RealityVerify("empty Certificate list"))
        ));
    }

    #[test]
    fn certificate_chain_ders_rejects_truncated_body() {
        assert!(matches!(
            certificate_chain_ders(&[]),
            Err(Error::RealityVerify("truncated Certificate message"))
        ));

        // Context length byte says 5 bytes follow, but none do
        assert!(matches!(
            certificate_chain_ders(&[0x05]),
            Err(Error::RealityVerify("truncated Certificate message"))
        ));

        // List length header claims 100 bytes, but body ends
        let truncated_list = [0x00, 0x00, 0x00, 0x64, 0x01, 0x02];
        assert!(matches!(
            certificate_chain_ders(&truncated_list),
            Err(Error::RealityVerify("truncated Certificate list"))
        ));
    }

    #[test]
    fn certificate_chain_ders_rejects_truncated_entry_or_extensions() {
        // Entry claims 20 bytes cert_data, only has 2
        let mut list = Vec::new();
        list.extend_from_slice(&[0x00, 0x00, 0x14, 0x01, 0x02]);
        let mut body = vec![0x00];
        let list_len = u32::try_from(list.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&list_len[1..]);
        body.extend_from_slice(&list);

        assert!(matches!(
            certificate_chain_ders(&body),
            Err(Error::RealityVerify("truncated certificate entry"))
        ));

        // Entry has valid cert_data, but extension length claims beyond list
        let mut list2 = Vec::new();
        list2.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x02]); // 2 bytes cert
        list2.extend_from_slice(&[0x00, 0x10]); // 16 bytes extensions claimed, 0 follow
        let mut body2 = vec![0x00];
        let list2_len = u32::try_from(list2.len()).unwrap().to_be_bytes();
        body2.extend_from_slice(&list2_len[1..]);
        body2.extend_from_slice(&list2);

        assert!(matches!(
            certificate_chain_ders(&body2),
            Err(Error::RealityVerify(
                "truncated certificate entry extensions"
            ))
        ));
    }

    #[test]
    fn certificate_chain_ders_rejects_oversized_leaf() {
        let huge_leaf = vec![0x99u8; MAX_LEAF_CERT_DER_LEN + 1];
        let body = build_cert_body(&[], &[(&huge_leaf, &[])]);
        assert!(matches!(
            certificate_chain_ders(&body),
            Err(Error::RealityVerify(
                "leaf certificate length out of bounds"
            ))
        ));
    }

    #[test]
    fn certificate_chain_ders_rejects_zero_length_leaf() {
        let empty_leaf = vec![];
        let body = build_cert_body(&[], &[(&empty_leaf, &[])]);
        assert!(matches!(
            certificate_chain_ders(&body),
            Err(Error::RealityVerify(
                "leaf certificate length out of bounds"
            ))
        ));
    }

    #[test]
    fn certificate_leaf_der_returns_leaf_bytes() {
        let leaf = vec![0x55u8; 48];
        let inter = vec![0x66u8; 32];
        let body = build_cert_body(&[], &[(&leaf, &[]), (&inter, &[])]);
        assert_eq!(certificate_leaf_der(&body).unwrap(), leaf);
    }

    #[test]
    fn certificate_verify_signature_extracts_signature() {
        let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let body = build_cert_verify_body(0x0403, &sig);
        assert_eq!(certificate_verify_signature(&body).unwrap(), sig);
    }

    #[test]
    fn certificate_verify_signature_rejects_truncated_or_empty() {
        // Less than 4 bytes
        assert!(matches!(
            certificate_verify_signature(&[0x04, 0x03]),
            Err(Error::RealityVerify("truncated CertificateVerify message"))
        ));

        // Sig length 10, but only 2 bytes follow
        assert!(matches!(
            certificate_verify_signature(&[0x04, 0x03, 0x00, 0x0A, 0x01, 0x02]),
            Err(Error::RealityVerify(
                "truncated CertificateVerify signature"
            ))
        ));

        // Empty signature (sig_len = 0)
        assert!(matches!(
            certificate_verify_signature(&[0x04, 0x03, 0x00, 0x00]),
            Err(Error::RealityVerify("empty CertificateVerify signature"))
        ));
    }

    #[test]
    fn scan_cert_flight_extracts_leaf_signature_and_offsets() {
        let ee_msg = build_hs_msg(0x08, &[0x00, 0x00]); // EncryptedExtensions
        let leaf = vec![0x2Au8; 50];
        let cert_body = build_cert_body(&[], &[(&leaf, &[])]);
        let cert_msg = build_hs_msg(HS_TYPE_CERTIFICATE, &cert_body);
        let sig = vec![0x77u8; 64];
        let cv_body = build_cert_verify_body(0x0403, &sig);
        let cv_msg = build_hs_msg(HS_TYPE_CERTIFICATE_VERIFY, &cv_body);
        let fin_msg = build_hs_msg(0x14, &[0x99u8; 32]); // Finished

        let mut flight = Vec::new();
        flight.extend_from_slice(&ee_msg);
        flight.extend_from_slice(&cert_msg);
        let expected_cv_offset = flight.len();
        flight.extend_from_slice(&cv_msg);
        flight.extend_from_slice(&fin_msg);

        let info = scan_cert_flight(&flight).expect("scan cert flight");
        assert_eq!(info.leaf_der, leaf);
        assert_eq!(info.signature, sig);
        assert_eq!(info.certverify_start, expected_cv_offset);
        assert_eq!(info.cert_msg_end, expected_cv_offset);
    }

    #[test]
    fn scan_cert_flight_rejects_missing_messages() {
        // Flight with only EE and Finished
        let ee_msg = build_hs_msg(0x08, &[0x00, 0x00]);
        let fin_msg = build_hs_msg(0x14, &[0x99u8; 32]);
        let mut flight1 = Vec::new();
        flight1.extend_from_slice(&ee_msg);
        flight1.extend_from_slice(&fin_msg);

        assert!(matches!(
            scan_cert_flight(&flight1),
            Err(Error::RealityVerify(
                "server flight is missing a CertificateVerify message"
            ))
        ));

        // Flight with CertificateVerify before Certificate
        let cv_body = build_cert_verify_body(0x0403, &[0x01; 64]);
        let cv_msg = build_hs_msg(HS_TYPE_CERTIFICATE_VERIFY, &cv_body);
        let mut flight2 = Vec::new();
        flight2.extend_from_slice(&ee_msg);
        flight2.extend_from_slice(&cv_msg);

        assert!(matches!(
            scan_cert_flight(&flight2),
            Err(Error::RealityVerify(
                "server flight is missing a Certificate message"
            ))
        ));
    }

    #[test]
    fn scan_cert_flight_rejects_oversized_handshake_message() {
        // Message with header claiming > MAX_HANDSHAKE_MSG_LEN
        let mut flight = Vec::new();
        flight.push(HS_TYPE_CERTIFICATE);
        flight.extend_from_slice(&[0x10, 0x00, 0x01]); // 1_048_577 > 1 << 20
        flight.extend_from_slice(&[0x00; 10]);

        assert!(matches!(
            scan_cert_flight(&flight),
            Err(Error::RealityVerify(
                "server handshake message exceeds sane length bound"
            ))
        ));
    }

    #[test]
    fn spki_sec1_pubkey_from_der_extracts_p256_public_key() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "test.local");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();

        let sec1 = spki_sec1_pubkey_from_der(cert.der()).expect("spki extraction");
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
        assert_eq!(sec1, key.public_key_raw());
    }

    #[test]
    fn spki_sec1_pubkey_from_der_rejects_invalid_der() {
        assert!(matches!(
            spki_sec1_pubkey_from_der(&[]),
            Err(Error::RealityVerify("leaf certificate is not valid DER"))
        ));

        assert!(matches!(
            spki_sec1_pubkey_from_der(&[0x01, 0x02, 0x03]),
            Err(Error::RealityVerify("leaf certificate is not valid DER"))
        ));

        // Valid DER integer, but not sequence
        let der_int = [0x02, 0x01, 0x05];
        assert!(matches!(
            spki_sec1_pubkey_from_der(&der_int),
            Err(Error::RealityVerify("leaf certificate is not valid DER"))
        ));
    }
}
