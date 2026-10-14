//! Flight shape scanning and server flight emission.

use crate::error::Error;
use crate::handshake::{
    self, derive_application_keys, finished_verify_data, record_seal_padded, transcript_hash,
    ApplicationKeys, HandshakeKeys,
};
use crate::stream::cert::{
    certificate_chain_ders, HS_TYPE_CERTIFICATE, HS_TYPE_CERTIFICATE_VERIFY,
};
use crate::stream::record::{
    record_header, CHANGE_CIPHER_SPEC_RECORD, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_HANDSHAKE, HS_TYPE_FINISHED, LEGACY_RECORD_VERSION, MAX_HANDSHAKE_MSG_LEN,
};
use crate::stream::sig::sign_certificate_verify;
use crate::template::{CertChainShape, EncryptedFlightShape};

/// Handshake message type for `EncryptedExtensions` (RFC 8446 §4.3.1).
pub(crate) const HS_TYPE_ENCRYPTED_EXTENSIONS: u8 = 0x08;

/// REALITY.5a Task 2: what capturing a dest's server flight needs beyond
/// [`crate::stream::cert::scan_cert_flight`] (which REALITY.4b's verify path already relies on and
/// which this does not alter) — per-message plaintext lengths (each `4 +
/// body_len`, the handshake-message length INCLUDING its own 4-byte header —
/// matching [`crate::template::EncryptedFlightShape`]'s length fields) plus
/// the full cert chain shape (leaf DER + every subsequent chain cert's DER
/// verbatim; see [`CertChainShape`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightShapeScan {
    /// The leaf certificate's raw DER (first `CertificateEntry` in the
    /// `Certificate` message's cert list).
    pub leaf_der: Vec<u8>,
    /// The leaf DER's length + every subsequent chain cert's DER, verbatim.
    pub cert_chain: CertChainShape,
    /// `EncryptedExtensions` message length, incl. its 4-byte header.
    pub ee_len: usize,
    /// `Certificate` message length, incl. its 4-byte header.
    pub cert_len: usize,
    /// `CertificateVerify` message length, incl. its 4-byte header.
    pub cert_verify_len: usize,
    /// `Finished` message length, incl. its 4-byte header.
    pub finished_len: usize,
}

/// Scans `hs_flight` (see [`crate::stream::record::find_finished_end`] for its shape) for
/// REALITY.5a's flight-shape capture: per-message plaintext lengths of
/// EncryptedExtensions/Certificate/CertificateVerify/Finished, plus the
/// leaf certificate's DER and every subsequent chain cert's DER verbatim
/// (see [`certificate_chain_ders`]). Mirrors [`crate::stream::cert::scan_cert_flight`]'s bounded
/// `while hs_flight.len() >= pos + 4` walk over `msg_type ‖ u24 len ‖ body`,
/// but records EVERY message's length rather than stopping at the first
/// `CertificateVerify`. Fail-closed: a missing `Certificate` message,
/// truncated field, or out-of-bounds value is `Err(Error::RealityVerify(_))`;
/// every access is bounds-checked (`.get`, never direct indexing past a
/// validated point) so hostile bytes cannot panic this.
pub fn scan_flight_shape(hs_flight: &[u8]) -> Result<FlightShapeScan, Error> {
    let mut pos = 0;
    let mut leaf_der: Option<Vec<u8>> = None;
    let mut intermediates_der: Vec<Vec<u8>> = Vec::new();
    let mut ee_len = 0usize;
    let mut cert_len = 0usize;
    let mut cert_verify_len = 0usize;
    let mut finished_len = 0usize;

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
        let total_len = 4 + len;

        match msg_type {
            HS_TYPE_ENCRYPTED_EXTENSIONS => ee_len = total_len,
            HS_TYPE_CERTIFICATE => {
                cert_len = total_len;
                let (leaf, chain) = certificate_chain_ders(body)?;
                leaf_der = Some(leaf);
                intermediates_der = chain;
            }
            HS_TYPE_CERTIFICATE_VERIFY => cert_verify_len = total_len,
            HS_TYPE_FINISHED => finished_len = total_len,
            _ => {}
        }

        pos = msg_end;
    }

    let leaf_der = leaf_der.ok_or(Error::RealityVerify(
        "server flight is missing a Certificate message",
    ))?;
    let leaf_der_len = leaf_der.len();

    Ok(FlightShapeScan {
        leaf_der,
        cert_chain: CertChainShape {
            leaf_der_len,
            intermediates_der,
        },
        ee_len,
        cert_len,
        cert_verify_len,
        finished_len,
    })
}

/// The output of [`emit_server_flight`]: the wire bytes to send (CCS ‖ sealed
/// handshake-key records) and the application traffic keys for the data phase.
pub struct ServerFlight {
    pub wire: Vec<u8>,
    pub app_keys: ApplicationKeys,
}

/// The 3-byte big-endian TLS `uint24` length prefix for `n`, guarding the real
/// `0xFF_FFFF` ceiling (not just `u32::MAX`, which `u32::try_from` alone would
/// permit and then silently truncate). `Err(MessageTooLarge)` on overflow —
/// the handshake-MESSAGE framing layer, distinct from the record-layer u16.
pub(crate) fn u24_len(n: usize) -> Result<[u8; 3], Error> {
    if n > 0xFF_FFFF {
        return Err(Error::MessageTooLarge);
    }
    let bytes = u32::try_from(n)
        .map_err(|_| Error::MessageTooLarge)?
        .to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}

/// Wrap a handshake-message body as `type ‖ u24 len ‖ body`.
pub(crate) fn handshake_message(msg_type: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u24_len(body.len())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&len); // u24
    out.extend_from_slice(body);
    Ok(out)
}

/// A single `CertificateEntry`: `u24 cert_data_len ‖ der ‖ u16 ext_len(0)`.
pub(crate) fn certificate_entry(der: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u24_len(der.len())?;
    let mut out = Vec::with_capacity(3 + der.len() + 2);
    out.extend_from_slice(&len); // u24
    out.extend_from_slice(der);
    out.extend_from_slice(&[0x00, 0x00]); // empty entry extensions
    Ok(out)
}

/// REALITY.5c: assemble the encrypted server flight (EncryptedExtensions/
/// Certificate/CertificateVerify/Finished), seal it under `keys`'s handshake
/// keys, and frame it to byte-match `flight_shape.record_lengths` (padding
/// each record to its captured length), prefixed with the middlebox-compat
/// CCS. Returns the wire bytes + the derived application keys. Fail-closed: a
/// malformed or too-small `record_lengths` → `Err` (5d degrades to splice).
pub fn emit_server_flight(
    keys: &HandshakeKeys,
    flight_shape: &EncryptedFlightShape,
    cert_chain: &CertChainShape,
    forged_leaf_der: &[u8],
    cert_signing_key: &p256::ecdsa::SigningKey,
    transcript_ch_sh: &[u8],
) -> Result<ServerFlight, Error> {
    let suite = keys.suite;

    // 1. EncryptedExtensions: empty extensions list.
    let ee = handshake_message(0x08, &[0x00, 0x00])?;

    // 2. Certificate: empty context ‖ u24 list-len ‖ leaf entry ‖ intermediates.
    let mut cert_list = certificate_entry(forged_leaf_der)?;
    for inter in &cert_chain.intermediates_der {
        cert_list.extend_from_slice(&certificate_entry(inter)?);
    }
    let mut cert_body = Vec::with_capacity(1 + 3 + cert_list.len());
    cert_body.push(0x00); // certificate_request_context length = 0
    cert_body.extend_from_slice(&u24_len(cert_list.len())?); // u24
    cert_body.extend_from_slice(&cert_list);
    let certificate = handshake_message(0x0b, &cert_body)?;

    // 3. CertificateVerify over the transcript through Certificate.
    let mut tr = transcript_ch_sh.to_vec();
    tr.extend_from_slice(&ee);
    tr.extend_from_slice(&certificate);
    let th_cert = transcript_hash(&tr, suite);
    let sig = sign_certificate_verify(cert_signing_key, &th_cert)?;
    let mut cv_body = Vec::with_capacity(2 + 2 + sig.len());
    cv_body.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256
    cv_body.extend_from_slice(
        &u16::try_from(sig.len())
            .map_err(|_| handshake::Error::RecordTooLarge)?
            .to_be_bytes(),
    );
    cv_body.extend_from_slice(&sig);
    let certificate_verify = handshake_message(0x0f, &cv_body)?;

    // 4. Finished over the transcript through CertificateVerify.
    tr.extend_from_slice(&certificate_verify);
    let th_cv = transcript_hash(&tr, suite);
    let verify_data = finished_verify_data(&keys.server_hs_traffic, &th_cv, suite);
    let finished = handshake_message(0x14, &verify_data)?;

    // Application keys over the transcript through the server Finished.
    tr.extend_from_slice(&finished);
    let th_fin = transcript_hash(&tr, suite);
    let app_keys = derive_application_keys(&keys.handshake_secret, &th_fin, suite);

    // The contiguous handshake-message plaintext to frame.
    let mut hs_stream = Vec::with_capacity(
        ee.len() + certificate.len() + certificate_verify.len() + finished.len(),
    );
    hs_stream.extend_from_slice(&ee);
    hs_stream.extend_from_slice(&certificate);
    hs_stream.extend_from_slice(&certificate_verify);
    hs_stream.extend_from_slice(&finished);

    // 5. Greedy record framing to match record_lengths exactly.
    if flight_shape.record_lengths.is_empty() {
        return Err(Error::Protocol(
            "empty record_lengths in captured flight template",
        ));
    }
    let mut wire = CHANGE_CIPHER_SPEC_RECORD.to_vec();
    let mut off = 0usize;
    for (i, &rlen) in flight_shape.record_lengths.iter().enumerate() {
        // cap = plaintext(+padding) budget for this record (excludes content-type + tag).
        let cap = rlen.checked_sub(17).ok_or(Error::Protocol(
            "record length below the 17-byte AEAD floor",
        ))?;
        let remaining = hs_stream.len() - off;
        // The client (`connect`) reads records only until it sees `Finished`, then
        // switches to the application keys. So the `Finished` tail MUST land in the
        // LAST record — otherwise trailing handshake-key padding records would be
        // left unread and then fail to open under the app key. Reserve one content
        // byte for every later record so content is never exhausted early; the last
        // record always receives the tail. (Leading records may still be pure
        // padding — that is fine, they precede `Finished` and the client reads them.)
        let records_after = flight_shape.record_lengths.len() - 1 - i;
        let chunk_len = cap.min(remaining.saturating_sub(records_after));
        let chunk = &hs_stream[off..off + chunk_len];
        let pad_len = cap - chunk_len; // once hs_stream is exhausted, chunk_len=0 → pad_len=cap (pure-padding record)
        let seq = u64::try_from(i).map_err(|_| Error::Protocol("record index overflow"))?;
        let sealed = record_seal_padded(
            &keys.server_key,
            &keys.server_iv,
            seq,
            suite,
            CONTENT_TYPE_HANDSHAKE,
            chunk,
            pad_len,
        )?;
        let hdr = record_header(
            CONTENT_TYPE_APPLICATION_DATA,
            LEGACY_RECORD_VERSION,
            sealed.len(),
        )?;
        wire.extend_from_slice(&hdr);
        wire.extend_from_slice(&sealed);
        off += chunk_len;
    }
    if off < hs_stream.len() {
        // The flight did not fit the captured record framing.
        return Err(Error::FlightTooLarge);
    }

    Ok(ServerFlight { wire, app_keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{derive_handshake_keys, record_open};
    use crate::stream::record::RECORD_HEADER_LEN;

    fn build_certificate_verify_message(signature_der: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0403u16.to_be_bytes());
        let sig_len = u16::try_from(signature_der.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&sig_len);
        body.extend_from_slice(signature_der);

        let mut msg = Vec::new();
        msg.push(HS_TYPE_CERTIFICATE_VERIFY);
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        msg.extend_from_slice(&len[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    fn build_test_server_flight(
        ee_body: &[u8],
        certs: &[Vec<u8>],
        cert_verify_sig_len: usize,
        finished_len: usize,
    ) -> Vec<u8> {
        let mut ee_msg = Vec::new();
        ee_msg.push(HS_TYPE_ENCRYPTED_EXTENSIONS);
        let ee_len = u32::try_from(ee_body.len()).unwrap().to_be_bytes();
        ee_msg.extend_from_slice(&ee_len[1..]);
        ee_msg.extend_from_slice(ee_body);

        let mut cert_list = Vec::new();
        for cert in certs {
            let cd_len = u32::try_from(cert.len()).unwrap().to_be_bytes();
            cert_list.extend_from_slice(&cd_len[1..]);
            cert_list.extend_from_slice(cert);
            cert_list.extend_from_slice(&0u16.to_be_bytes()); // no per-cert extensions
        }
        let mut cert_body = Vec::new();
        cert_body.push(0); // certificate_request_context: empty
        let list_len = u32::try_from(cert_list.len()).unwrap().to_be_bytes();
        cert_body.extend_from_slice(&list_len[1..]);
        cert_body.extend_from_slice(&cert_list);

        let mut cert_msg = Vec::new();
        cert_msg.push(HS_TYPE_CERTIFICATE);
        let cert_msg_len = u32::try_from(cert_body.len()).unwrap().to_be_bytes();
        cert_msg.extend_from_slice(&cert_msg_len[1..]);
        cert_msg.extend_from_slice(&cert_body);

        let cert_verify_msg = build_certificate_verify_message(&vec![0xCCu8; cert_verify_sig_len]);

        let verify_data = vec![0xABu8; finished_len];
        let mut finished_msg = Vec::with_capacity(4 + verify_data.len());
        finished_msg.push(HS_TYPE_FINISHED);
        let fin_len = u32::try_from(verify_data.len()).unwrap().to_be_bytes();
        finished_msg.extend_from_slice(&fin_len[1..]);
        finished_msg.extend_from_slice(&verify_data);

        let mut flight = Vec::new();
        flight.extend_from_slice(&ee_msg);
        flight.extend_from_slice(&cert_msg);
        flight.extend_from_slice(&cert_verify_msg);
        flight.extend_from_slice(&finished_msg);
        flight
    }

    fn leaf_der_for_key(key: &rcgen::KeyPair) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "mock-reality-relay.test");
        params.distinguished_name = dn;
        let cert = params.self_signed(key).unwrap();
        cert.der().as_ref().to_vec()
    }

    fn emit_flight_fixture() -> (HandshakeKeys, p256::ecdsa::SigningKey, Vec<u8>, Vec<u8>) {
        const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;

        let ecdhe = [7u8; 32];
        let transcript_ch_sh = b"raw-clienthello-bytes||raw-serverhello-bytes".to_vec();
        let th = transcript_hash(&transcript_ch_sh, SUITE_AES_128_GCM_SHA256);
        let keys = derive_handshake_keys(&ecdhe, &th, SUITE_AES_128_GCM_SHA256);
        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        use p256::pkcs8::EncodePrivateKey as _;
        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        let leaf_key = rcgen::KeyPair::try_from(pkcs8.as_bytes()).unwrap();
        let leaf_der = leaf_der_for_key(&leaf_key);
        (keys, signing_key, leaf_der, transcript_ch_sh)
    }

    /// REALITY.5a Task 2: `scan_flight_shape` must record each message's
    /// total wire length (header included) and must split the Certificate
    /// message's cert list into `leaf_der` (first entry) +
    /// `intermediates_der` (every subsequent entry, verbatim).
    #[test]
    fn scan_flight_shape_records_lengths_and_verbatim_intermediates() {
        let leaf = vec![0xAAu8; 40];
        let inter = vec![0xBBu8; 30];
        let flight = build_test_server_flight(
            /*ee_body=*/ &[0x00, 0x00], // empty EE
            /*certs=*/ &[leaf.clone(), inter.clone()], // leaf + 1 intermediate
            /*cert_verify_sig_len=*/ 70,
            /*finished_len=*/ 32,
        );
        let s = scan_flight_shape(&flight).expect("scan");
        assert_eq!(s.leaf_der, leaf);
        assert_eq!(s.cert_chain.leaf_der_len, 40);
        assert_eq!(s.cert_chain.intermediates_der, vec![inter]); // verbatim
                                                                 // Per-message lengths include the 4-byte handshake header.
        assert_eq!(s.ee_len, 4 + 2);
        assert!(s.cert_len > 0 && s.cert_verify_len > 0 && s.finished_len > 0);
    }

    /// A leaf-only chain (no intermediates) must yield an empty
    /// `intermediates_der`, not an error or a spurious entry.
    #[test]
    fn scan_flight_shape_leaf_only_chain_has_no_intermediates() {
        let leaf = vec![0x11u8; 20];
        let flight = build_test_server_flight(&[0x00, 0x00], std::slice::from_ref(&leaf), 64, 32);
        let s = scan_flight_shape(&flight).expect("scan");
        assert_eq!(s.leaf_der, leaf);
        assert_eq!(s.cert_chain.leaf_der_len, 20);
        assert!(s.cert_chain.intermediates_der.is_empty());
    }

    /// A flight missing the `Certificate` message entirely must fail closed,
    /// not panic or silently return an empty leaf.
    #[test]
    fn scan_flight_shape_rejects_flight_without_certificate() {
        // Only EncryptedExtensions ‖ Finished — no Certificate/CertVerify.
        let mut flight = Vec::new();
        flight.extend_from_slice(&[HS_TYPE_ENCRYPTED_EXTENSIONS, 0x00, 0x00, 0x00]);
        flight.push(HS_TYPE_FINISHED);
        flight.extend_from_slice(&[0x00, 0x00, 0x20]);
        flight.extend_from_slice(&[0xABu8; 32]);

        assert!(matches!(
            scan_flight_shape(&flight),
            Err(Error::RealityVerify(_))
        ));
    }

    #[test]
    fn emit_server_flight_matches_record_lengths_and_reopens_to_messages() {
        let (keys, signing_key, leaf_der, transcript_ch_sh) = emit_flight_fixture();
        // Generously sized records: 3 records, last two mostly/entirely padding.
        let shape = EncryptedFlightShape {
            record_lengths: vec![600, 600, 4096],
            encrypted_extensions_len: 0,
            certificate_len: 0,
            certificate_verify_len: 0,
            finished_len: 0,
        };
        let cert_chain = CertChainShape {
            leaf_der_len: leaf_der.len(),
            intermediates_der: Vec::new(),
        };

        let flight = emit_server_flight(
            &keys,
            &shape,
            &cert_chain,
            &leaf_der,
            &signing_key,
            &transcript_ch_sh,
        )
        .unwrap();

        // First record is the middlebox CCS, byte-for-byte.
        assert_eq!(
            &flight.wire[..CHANGE_CIPHER_SPEC_RECORD.len()],
            &CHANGE_CIPHER_SPEC_RECORD
        );

        // Walk the sealed records after the CCS: each record's header length field
        // MUST equal record_lengths[i]; re-open each under the handshake server key
        // and concatenate the recovered plaintext.
        let mut off = CHANGE_CIPHER_SPEC_RECORD.len();
        let mut recovered = Vec::new();
        for (i, &rlen) in shape.record_lengths.iter().enumerate() {
            let hdr = &flight.wire[off..off + RECORD_HEADER_LEN];
            assert_eq!(hdr[0], CONTENT_TYPE_APPLICATION_DATA);
            let len_field = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
            assert_eq!(
                len_field, rlen,
                "record {i} outer length must match record_lengths"
            );
            let mut payload =
                flight.wire[off + RECORD_HEADER_LEN..off + RECORD_HEADER_LEN + rlen].to_vec();
            let opened = record_open(
                &keys.server_key,
                &keys.server_iv,
                u64::try_from(i).unwrap(),
                keys.suite,
                CONTENT_TYPE_APPLICATION_DATA,
                &mut payload,
            )
            .unwrap();
            recovered.extend_from_slice(&opened);
            off += RECORD_HEADER_LEN + rlen;
        }
        assert_eq!(
            off,
            flight.wire.len(),
            "no trailing bytes after the framed records"
        );

        // The recovered plaintext begins with EncryptedExtensions (0x08),
        // Certificate (0x0b), CertificateVerify (0x0f), Finished (0x14) in order.
        assert_eq!(recovered[0], 0x08, "first message is EncryptedExtensions");
        // Walk the four handshake messages by their u24 length prefixes.
        let mut p = 0usize;
        let mut types = Vec::new();
        while p + 4 <= recovered.len() {
            let ty = recovered[p];
            if ty == 0 {
                break; // reached padding stripped? (shouldn't; padding was per-record)
            }
            let len = (usize::from(recovered[p + 1]) << 16)
                | (usize::from(recovered[p + 2]) << 8)
                | usize::from(recovered[p + 3]);
            types.push(ty);
            p += 4 + len;
            if types.len() == 4 {
                break;
            }
        }
        assert_eq!(types, vec![0x08, 0x0b, 0x0f, 0x14]);
    }

    #[test]
    fn u24_len_encodes_and_guards_the_ceiling() {
        assert_eq!(u24_len(0).unwrap(), [0x00, 0x00, 0x00]);
        assert_eq!(u24_len(1).unwrap(), [0x00, 0x00, 0x01]);
        assert_eq!(u24_len(0x01_02_03).unwrap(), [0x01, 0x02, 0x03]);
        // Exactly the u24 ceiling is allowed; one over → MessageTooLarge.
        assert_eq!(u24_len(0xFF_FFFF).unwrap(), [0xFF, 0xFF, 0xFF]);
        assert!(matches!(u24_len(0x1_00_00_00), Err(Error::MessageTooLarge)));
    }

    #[test]
    fn emit_server_flight_rejects_malformed_or_over_capacity_framing() {
        let (keys, signing_key, leaf_der, transcript_ch_sh) = emit_flight_fixture();
        let cert_chain = CertChainShape {
            leaf_der_len: leaf_der.len(),
            intermediates_der: Vec::new(),
        };
        let mk = |record_lengths: Vec<usize>| EncryptedFlightShape {
            record_lengths,
            encrypted_extensions_len: 0,
            certificate_len: 0,
            certificate_verify_len: 0,
            finished_len: 0,
        };

        // Empty record_lengths → Err (not panic).
        assert!(emit_server_flight(
            &keys,
            &mk(vec![]),
            &cert_chain,
            &leaf_der,
            &signing_key,
            &transcript_ch_sh
        )
        .is_err());
        // A record length below the 17-byte AEAD/content-type floor → Err.
        assert!(emit_server_flight(
            &keys,
            &mk(vec![10]),
            &cert_chain,
            &leaf_der,
            &signing_key,
            &transcript_ch_sh
        )
        .is_err());
        // Total capacity far below the flight size → FlightTooLarge.
        // (`ServerFlight` deliberately does not derive `Debug` — it carries the
        // application traffic keys — so this checks the error variant via
        // `matches!` rather than `Result::unwrap_err`, which would require
        // `ServerFlight: Debug`.)
        let result = emit_server_flight(
            &keys,
            &mk(vec![20, 20]),
            &cert_chain,
            &leaf_der,
            &signing_key,
            &transcript_ch_sh,
        );
        assert!(matches!(result, Err(Error::FlightTooLarge)));
    }
}
