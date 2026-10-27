//! CertificateVerify signature verification & creation, and REALITY binding verification.

use crate::error::Error;
use crate::handshake::{self, transcript_hash};
use crate::stream::cert::{scan_cert_flight, spki_sec1_pubkey_from_der};

/// Verify a TLS 1.3 server `CertificateVerify` for REALITY.4b: the leaf's
/// key must be exactly `expected_pubkey_sec1` (the shared-secret-derived
/// P-256 key — see [`crate::auth::derive_cert_key`]), and the signature must verify
/// over the RFC 8446 §4.4.3 signed content with `ecdsa_secp256r1_sha256`
/// HARD-PINNED — the `SignatureScheme` the server's `CertificateVerify`
/// message itself announces is never read or trusted. Fail-closed on every
/// edge: a leaf-key mismatch, a malformed DER signature, or a signature
/// that does not verify are all `Err(Error::RealityVerify(_))`, never `Ok`.
pub(crate) fn verify_certificate_verify(
    expected_pubkey_sec1: &[u8],
    leaf_spki_pubkey_sec1: &[u8],
    transcript_hash_through_cert: &[u8],
    signature_der: &[u8],
) -> Result<(), Error> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    // 1. Pin the leaf key to the derived key (byte comparison — the derived
    // key is always a valid P-256 point by construction, so an exact match
    // also proves the leaf key is one).
    if leaf_spki_pubkey_sec1 != expected_pubkey_sec1 {
        return Err(Error::RealityVerify(
            "leaf key does not match the derived REALITY key",
        ));
    }

    // 2. Reconstruct the §4.4.3 signed content: 0x20*64 ‖ context ‖ 0x00 ‖ hash.
    let mut signed = Vec::with_capacity(64 + 34 + 1 + transcript_hash_through_cert.len());
    signed.extend_from_slice(&[0x20u8; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0x00);
    signed.extend_from_slice(transcript_hash_through_cert);

    // 3. Verify with ecdsa_secp256r1_sha256 hard-pinned (`Verifier::verify`
    // for `ecdsa::Signature<NistP256>` hashes SHA-256 internally, matching
    // ecdsa_secp256r1_sha256 exactly; the announced SignatureScheme from the
    // wire is never consulted).
    let vk = VerifyingKey::from_sec1_bytes(expected_pubkey_sec1)
        .map_err(|_| Error::RealityVerify("derived key is not a valid P-256 point"))?;
    let sig = Signature::from_der(signature_der)
        .map_err(|_| Error::RealityVerify("CertificateVerify signature is not valid DER ECDSA"))?;
    vk.verify(&signed, &sig)
        .map_err(|_| Error::RealityVerify("CertificateVerify signature does not verify"))
}

/// The signing counterpart of `verify_certificate_verify`: sign the TLS 1.3
/// server `CertificateVerify` (RFC 8446 §4.4.3) with the derived ECDSA-P256
/// key `signing_key` (from `crate::auth::derive_cert_key(shared)`), over the SAME
/// signed content the verifier reconstructs. This IS the REALITY.4b binding,
/// server side — the client pins the presented leaf's SPKI to this key and
/// verifies this signature. `ecdsa_secp256r1_sha256` (scheme 0x0403) is fixed:
/// `p256::ecdsa::SigningKey` signs SHA-256 internally, so no `suite` is needed
/// (the caller uses `suite` only to compute `transcript_hash_through_certificate`).
pub fn sign_certificate_verify(
    signing_key: &p256::ecdsa::SigningKey,
    transcript_hash_through_certificate: &[u8],
) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::{signature::Signer, Signature};

    let mut signed = Vec::with_capacity(64 + 33 + 1 + transcript_hash_through_certificate.len());
    signed.extend_from_slice(&[0x20u8; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0x00);
    signed.extend_from_slice(transcript_hash_through_certificate);

    let sig: Signature = signing_key
        .try_sign(&signed)
        .map_err(|_| Error::Handshake(handshake::Error::Crypto))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Orchestrates REALITY.4b `CertificateVerify` verification: locates the
/// Certificate/CertificateVerify messages in `hs_flight` (see
/// [`scan_cert_flight`]), extracts the leaf's P-256 SPKI (see
/// [`spki_sec1_pubkey_from_der`]), computes `Transcript-Hash(ClientHello‥
/// Certificate)` at the exact RFC 8446 §4.4.3 boundary `scan_cert_flight`
/// reports, and checks it against `expected_pubkey_sec1` (see
/// [`verify_certificate_verify`]). `ch_sh_transcript` is the raw
/// `ClientHello ‖ ServerHello` bytes `connect` already accumulates —
/// `Transcript-Hash(ClientHello‥Certificate)` is `transcript_hash` of that
/// prefix concatenated with `hs_flight` up to (not including)
/// `certverify_start`.
pub(crate) fn verify_reality_binding(
    hs_flight: &[u8],
    ch_sh_transcript: &[u8],
    suite: u16,
    expected_pubkey_sec1: &[u8],
) -> Result<(), Error> {
    let flight = scan_cert_flight(hs_flight)?;
    let leaf_pubkey_sec1 = spki_sec1_pubkey_from_der(&flight.leaf_der)?;

    let mut thru_cert = Vec::with_capacity(ch_sh_transcript.len() + flight.certverify_start);
    thru_cert.extend_from_slice(ch_sh_transcript);
    thru_cert.extend_from_slice(&hs_flight[..flight.certverify_start]);
    let transcript_thru_cert = transcript_hash(&thru_cert, suite);

    verify_certificate_verify(
        expected_pubkey_sec1,
        &leaf_pubkey_sec1,
        &transcript_thru_cert,
        &flight.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use crate::stream::cert::{HS_TYPE_CERTIFICATE, HS_TYPE_CERTIFICATE_VERIFY};
    use p256::pkcs8::EncodePrivateKey;

    fn build_cert_body(leaf_der: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0); // certificate_request_context: empty
        let mut list = Vec::new();
        let cert_len = u32::try_from(leaf_der.len()).unwrap().to_be_bytes();
        list.extend_from_slice(&cert_len[1..]);
        list.extend_from_slice(leaf_der);
        list.extend_from_slice(&0u16.to_be_bytes()); // no per-cert extensions
        let list_len = u32::try_from(list.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&list_len[1..]);
        body.extend_from_slice(&list);
        body
    }

    fn build_cert_verify_body(sig: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256
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

    fn leaf_der_for_key(key: &rcgen::KeyPair) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "mock-reality.test");
        params.distinguished_name = dn;
        params.self_signed(key).unwrap().der().to_vec()
    }

    /// REALITY.4b Task 3: KAT test for `verify_certificate_verify`.
    ///
    /// Drives the verification path on a fixture constructed against the
    /// exact RFC 8446 §4.4.3 signed-content rule:
    ///   0x20 * 64 ‖ "TLS 1.3, server CertificateVerify" ‖ 0x00 ‖ transcript
    ///
    /// Confirms that:
    /// 1. A valid P-256 signature over that signed content verifies against
    ///    the derived key.
    /// 2. Any one-byte perturbation of the transcript flips the verdict to
    ///    `Err(Error::RealityVerify(_))` (this is the single most common
    ///    failure mode of transcript-binding bugs, where the hashing boundary
    ///    is off by a record header or message header; cryptographically it
    ///    is silent, since it always signs/verifies SOME 32/48-byte string —
    ///    it just isn't the one RFC 8446 actually requires).
    #[test]
    fn certverify_predicate_kat() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;

        let shared = [0x42u8; 32];
        let derived = auth::derive_cert_key(&shared);
        let signing_key =
            SigningKey::from_pkcs8_der(&derived.pkcs8_der).expect("derived pkcs8 loads");

        // A stand-in "transcript hash" — the predicate treats it as opaque
        // bytes, so any fixed value proves the point.
        let transcript = [0x11u8; 32].to_vec();

        let mut signed = Vec::with_capacity(64 + 34 + 1 + transcript.len());
        signed.extend_from_slice(&[0x20u8; 64]);
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed.push(0x00);
        signed.extend_from_slice(&transcript);

        let signature: Signature = signing_key.sign(&signed);
        let signature_der = signature.to_der().as_ref().to_vec();

        assert!(verify_certificate_verify(
            &derived.public_sec1,
            &derived.public_sec1,
            &transcript,
            &signature_der,
        )
        .is_ok());

        let mut perturbed = transcript.clone();
        perturbed[0] ^= 0xFF;
        assert!(
            matches!(
                verify_certificate_verify(
                    &derived.public_sec1,
                    &derived.public_sec1,
                    &perturbed,
                    &signature_der,
                ),
                Err(Error::RealityVerify(_))
            ),
            "a one-byte transcript perturbation must flip the verdict to Err"
        );
    }

    #[test]
    fn sign_certificate_verify_is_accepted_by_the_verifier() {
        use p256::ecdsa::SigningKey;
        const SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

        let signing_key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let pubkey_sec1 = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let transcript = transcript_hash(b"ch||sh||ee||cert", SUITE);

        let sig = sign_certificate_verify(&signing_key, &transcript).unwrap();

        // The shipped verifier accepts it for the same transcript + pinned key.
        verify_certificate_verify(&pubkey_sec1, &pubkey_sec1, &transcript, &sig)
            .expect("a self-signed CertificateVerify must verify");
    }

    #[test]
    fn sign_certificate_verify_rejected_for_wrong_key_and_tampered_transcript() {
        use p256::ecdsa::SigningKey;
        const SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

        let signing_key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let other_key = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let other_pub = other_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let transcript = transcript_hash(b"ch||sh||ee||cert", SUITE);
        let sig = sign_certificate_verify(&signing_key, &transcript).unwrap();

        // Wrong pinned key → RealityVerify.
        assert!(verify_certificate_verify(&other_pub, &other_pub, &transcript, &sig).is_err());

        // Tampered transcript (verify against a different hash) → RealityVerify.
        let signer_pub = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let tampered = transcript_hash(b"different-transcript", SUITE);
        assert!(verify_certificate_verify(&signer_pub, &signer_pub, &tampered, &sig).is_err());
    }

    #[test]
    fn verify_reality_binding_success() {
        const SUITE: u16 = 0x1301;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_bytes()).unwrap();
        let leaf_der = leaf_der_for_key(&key_pair);
        let pubkey_sec1 = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();

        let ch_sh_transcript = b"client_hello_and_server_hello_bytes".to_vec();

        let ee_msg = build_hs_msg(0x08, &[0x00, 0x00]);
        let cert_body = build_cert_body(&leaf_der);
        let cert_msg = build_hs_msg(HS_TYPE_CERTIFICATE, &cert_body);

        let mut thru_cert = Vec::new();
        thru_cert.extend_from_slice(&ch_sh_transcript);
        thru_cert.extend_from_slice(&ee_msg);
        thru_cert.extend_from_slice(&cert_msg);
        let th_cert = transcript_hash(&thru_cert, SUITE);

        let sig = sign_certificate_verify(&signing_key, &th_cert).unwrap();
        let cv_body = build_cert_verify_body(&sig);
        let cv_msg = build_hs_msg(HS_TYPE_CERTIFICATE_VERIFY, &cv_body);

        let mut hs_flight = Vec::new();
        hs_flight.extend_from_slice(&ee_msg);
        hs_flight.extend_from_slice(&cert_msg);
        hs_flight.extend_from_slice(&cv_msg);

        assert!(verify_reality_binding(&hs_flight, &ch_sh_transcript, SUITE, &pubkey_sec1).is_ok());
    }

    #[test]
    fn verify_reality_binding_rejects_wrong_key() {
        const SUITE: u16 = 0x1301;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_bytes()).unwrap();
        let leaf_der = leaf_der_for_key(&key_pair);

        let other_key = p256::ecdsa::SigningKey::from_slice(&[0x44u8; 32]).unwrap();
        let other_pub = other_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();

        let ch_sh_transcript = b"client_hello_and_server_hello_bytes".to_vec();

        let ee_msg = build_hs_msg(0x08, &[0x00, 0x00]);
        let cert_body = build_cert_body(&leaf_der);
        let cert_msg = build_hs_msg(HS_TYPE_CERTIFICATE, &cert_body);

        let mut thru_cert = Vec::new();
        thru_cert.extend_from_slice(&ch_sh_transcript);
        thru_cert.extend_from_slice(&ee_msg);
        thru_cert.extend_from_slice(&cert_msg);
        let th_cert = transcript_hash(&thru_cert, SUITE);

        let sig = sign_certificate_verify(&signing_key, &th_cert).unwrap();
        let cv_body = build_cert_verify_body(&sig);
        let cv_msg = build_hs_msg(HS_TYPE_CERTIFICATE_VERIFY, &cv_body);

        let mut hs_flight = Vec::new();
        hs_flight.extend_from_slice(&ee_msg);
        hs_flight.extend_from_slice(&cert_msg);
        hs_flight.extend_from_slice(&cv_msg);

        assert!(matches!(
            verify_reality_binding(&hs_flight, &ch_sh_transcript, SUITE, &other_pub),
            Err(Error::RealityVerify(
                "leaf key does not match the derived REALITY key"
            ))
        ));
    }

    #[test]
    fn verify_reality_binding_rejects_tampered_transcript() {
        const SUITE: u16 = 0x1301;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_bytes()).unwrap();
        let leaf_der = leaf_der_for_key(&key_pair);
        let pubkey_sec1 = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();

        let ch_sh_transcript = b"client_hello_and_server_hello_bytes".to_vec();

        let ee_msg = build_hs_msg(0x08, &[0x00, 0x00]);
        let cert_body = build_cert_body(&leaf_der);
        let cert_msg = build_hs_msg(HS_TYPE_CERTIFICATE, &cert_body);

        let mut thru_cert = Vec::new();
        thru_cert.extend_from_slice(&ch_sh_transcript);
        thru_cert.extend_from_slice(&ee_msg);
        thru_cert.extend_from_slice(&cert_msg);
        let th_cert = transcript_hash(&thru_cert, SUITE);

        let sig = sign_certificate_verify(&signing_key, &th_cert).unwrap();
        let cv_body = build_cert_verify_body(&sig);
        let cv_msg = build_hs_msg(HS_TYPE_CERTIFICATE_VERIFY, &cv_body);

        let mut hs_flight = Vec::new();
        hs_flight.extend_from_slice(&ee_msg);
        hs_flight.extend_from_slice(&cert_msg);
        hs_flight.extend_from_slice(&cv_msg);

        let tampered_ch_sh = b"tampered_hello_bytes".to_vec();
        assert!(matches!(
            verify_reality_binding(&hs_flight, &tampered_ch_sh, SUITE, &pubkey_sec1),
            Err(Error::RealityVerify(
                "CertificateVerify signature does not verify"
            ))
        ));
    }

    #[test]
    fn verify_reality_binding_rejects_corrupted_signature() {
        const SUITE: u16 = 0x1301;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_bytes()).unwrap();
        let leaf_der = leaf_der_for_key(&key_pair);
        let pubkey_sec1 = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();

        let ch_sh_transcript = b"client_hello_and_server_hello_bytes".to_vec();

        let ee_msg = build_hs_msg(0x08, &[0x00, 0x00]);
        let cert_body = build_cert_body(&leaf_der);
        let cert_msg = build_hs_msg(HS_TYPE_CERTIFICATE, &cert_body);

        let mut thru_cert = Vec::new();
        thru_cert.extend_from_slice(&ch_sh_transcript);
        thru_cert.extend_from_slice(&ee_msg);
        thru_cert.extend_from_slice(&cert_msg);
        let th_cert = transcript_hash(&thru_cert, SUITE);

        let mut sig = sign_certificate_verify(&signing_key, &th_cert).unwrap();
        if let Some(last) = sig.last_mut() {
            *last ^= 0xFF;
        }
        let cv_body = build_cert_verify_body(&sig);
        let cv_msg = build_hs_msg(HS_TYPE_CERTIFICATE_VERIFY, &cv_body);

        let mut hs_flight = Vec::new();
        hs_flight.extend_from_slice(&ee_msg);
        hs_flight.extend_from_slice(&cert_msg);
        hs_flight.extend_from_slice(&cv_msg);

        assert!(
            verify_reality_binding(&hs_flight, &ch_sh_transcript, SUITE, &pubkey_sec1).is_err()
        );
    }
}
