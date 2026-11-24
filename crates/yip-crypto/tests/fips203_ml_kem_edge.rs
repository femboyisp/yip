#![forbid(unsafe_code)]

//! NIST FIPS 203 ML-KEM edge vector and implicit rejection test suite.
//!
//! Validates:
//! - Section 7.2 ByteDecode_12 boundary rejections: all 12-bit coefficients must be strictly < 3329
//!   across ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
//! - Section 7.3 Implicit rejection: decapsulation of invalid or corrupted ciphertexts produces
//!   pseudorandom shared secrets rather than failing or returning fixed error values.
//! - Post-quantum Noise handshake integration: rejection of invalid encapsulation keys and
//!   rejection of corrupted handshake messages across initiator and responder roles.

use std::collections::HashSet;

use yip_crypto::handshake::{
    InitiatorHandshake, ResponderHandshake, FLIGHT_1_BASE_LEN, FLIGHT_2_BASE_LEN,
};
use yip_crypto::{
    generate_keypair, generate_pq_keypair, generate_pq_keypair_for_algo,
    generate_pq_keypair_from_seed_for_algo, pq_decapsulate, pq_encapsulate,
    pq_encapsulate_deterministic, CryptoError, Handshake, PqCiphertext, PqEncapsKey,
    PqKemAlgorithm,
};

/// Set a 12-bit coefficient in an ML-KEM encapsulation key.
fn set_coeff_12(ek: &mut PqEncapsKey, coeff_idx: usize, val: u16) {
    let algo = ek.algorithm().expect("valid algorithm for ek");
    let max_coeffs = (algo.bytedecode12_bytes_len() / 3) * 2;
    assert!(
        coeff_idx < max_coeffs,
        "coefficient index {coeff_idx} out of bounds for {max_coeffs} coefficients"
    );
    let chunk_idx = coeff_idx / 2;
    let byte_offset = chunk_idx * 3;
    if coeff_idx.is_multiple_of(2) {
        ek.0[byte_offset] = (val & 0xFF) as u8;
        ek.0[byte_offset + 1] = (ek.0[byte_offset + 1] & 0xF0) | (((val >> 8) & 0x0F) as u8);
    } else {
        ek.0[byte_offset + 1] = (ek.0[byte_offset + 1] & 0x0F) | (((val & 0x0F) << 4) as u8);
        ek.0[byte_offset + 2] = ((val >> 4) & 0xFF) as u8;
    }
}

/// Decode a 12-bit coefficient from an ML-KEM encapsulation key.
fn get_coeff_12(ek: &PqEncapsKey, coeff_idx: usize) -> u16 {
    let algo = ek.algorithm().expect("valid algorithm for ek");
    let max_coeffs = (algo.bytedecode12_bytes_len() / 3) * 2;
    assert!(
        coeff_idx < max_coeffs,
        "coefficient index {coeff_idx} out of bounds for {max_coeffs} coefficients"
    );
    let chunk_idx = coeff_idx / 2;
    let byte_offset = chunk_idx * 3;
    if coeff_idx.is_multiple_of(2) {
        u16::from(ek.0[byte_offset]) | ((u16::from(ek.0[byte_offset + 1]) & 0x0F) << 8)
    } else {
        (u16::from(ek.0[byte_offset + 1]) >> 4) | (u16::from(ek.0[byte_offset + 2]) << 4)
    }
}

#[test]
fn test_coeff_12_encode_decode_roundtrip() {
    for algo in [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ] {
        let (mut ek, _dk) = generate_pq_keypair_for_algo(algo);
        let max_coeffs = (algo.bytedecode12_bytes_len() / 3) * 2;
        let test_indices = [0, 1, 128, 255, 256, max_coeffs - 2, max_coeffs - 1];
        for &val in &[0u16, 1, 1000, 3328, 3329, 3330, 4000, 4095] {
            for &coeff_idx in &test_indices {
                set_coeff_12(&mut ek, coeff_idx, val);
                assert_eq!(
                    get_coeff_12(&ek, coeff_idx),
                    val,
                    "coefficient roundtrip failed at index {coeff_idx} for val {val} on {algo:?}"
                );
            }
        }
    }
}

// =============================================================================
// 1. Encapsulation Key ByteDecode_12 Boundary Rejections
// =============================================================================

#[test]
fn test_bytedecode12_coefficient_modulus_boundary_rejections() {
    // FIPS 203 Section 7.2 ByteDecode_12 requires all 12-bit coefficients to be strictly < 3329.
    // Invalid values to test: 3329 (q), 3330 (q+1), 4000, 4095 (max 12-bit value).
    let invalid_coeffs: [u16; 4] = [3329, 3330, 4000, 4095];
    let deterministic_m = [0x42u8; 32];

    for algo in [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ] {
        let max_coeffs = (algo.bytedecode12_bytes_len() / 3) * 2;
        let test_positions = [
            ("start d0", 0),
            ("start d1", 1),
            ("poly 0 middle", 128),
            ("poly 0 end", 255),
            ("poly 1 start", 256),
            ("poly last start", max_coeffs - 2),
            ("poly last end", max_coeffs - 1),
        ];

        for &(label, pos) in &test_positions {
            for &invalid_val in &invalid_coeffs {
                let (mut ek, _dk) = generate_pq_keypair_for_algo(algo);
                set_coeff_12(&mut ek, pos, invalid_val);

                let det_res = pq_encapsulate_deterministic(&ek, &deterministic_m);
                assert_eq!(
                    det_res,
                    Err(CryptoError::Handshake),
                    "pq_encapsulate_deterministic must reject coefficient {invalid_val} at {label} (pos {pos}) on {algo:?}"
                );

                let rnd_res = pq_encapsulate(&ek);
                assert_eq!(
                    rnd_res,
                    Err(CryptoError::Handshake),
                    "pq_encapsulate must reject coefficient {invalid_val} at {label} (pos {pos}) on {algo:?}"
                );
            }
        }
    }
}

#[test]
fn test_bytedecode12_valid_boundary_accepted() {
    // 3328 is q - 1, which is strictly < 3329 and should satisfy the ByteDecode_12 check.
    for algo in [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ] {
        let (mut ek, _dk) = generate_pq_keypair_for_algo(algo);
        let deterministic_m = [0x55u8; 32];
        let max_coeffs = (algo.bytedecode12_bytes_len() / 3) * 2;

        set_coeff_12(&mut ek, 0, 3328);
        set_coeff_12(&mut ek, max_coeffs - 1, 3328);

        let res = pq_encapsulate_deterministic(&ek, &deterministic_m);
        assert!(
            res.is_ok(),
            "valid coefficient 3328 (q-1) must pass ByteDecode_12 modulus validation for {algo:?}"
        );
    }
}

#[test]
fn test_bytedecode12_all_coefficients_mutated_rejection() {
    for algo in [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ] {
        let (mut ek, _dk) = generate_pq_keypair_for_algo(algo);
        let deterministic_m = [0x99u8; 32];
        let poly_bytes = algo.bytedecode12_bytes_len();

        ek.0[..poly_bytes].fill(0xFF);

        assert_eq!(
            pq_encapsulate_deterministic(&ek, &deterministic_m),
            Err(CryptoError::Handshake),
            "all-0xFF coefficient array must be rejected for {algo:?}"
        );
        assert_eq!(
            pq_encapsulate(&ek),
            Err(CryptoError::Handshake),
            "all-0xFF coefficient array must be rejected by random encapsulation for {algo:?}"
        );
    }
}

// =============================================================================
// 2. FIPS 203 Section 7.3 Implicit Rejection
// =============================================================================

#[test]
fn test_fips203_implicit_rejection_properties() {
    for algo in [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ] {
        let seed = [0x37u8; 64];
        let (ek, dk) = generate_pq_keypair_from_seed_for_algo(algo, &seed);
        let m = [0x7au8; 32];

        // 1. Encapsulate valid (ct, true_shared_secret)
        let (valid_ct, true_shared_secret) =
            pq_encapsulate_deterministic(&ek, &m).expect("valid encapsulation");

        // 2. Decapsulate valid ct: assert result equals true_shared_secret
        let decaps_ss = pq_decapsulate(&dk, &valid_ct).expect("decapsulate valid ciphertext");
        assert_eq!(
            *true_shared_secret, *decaps_ss,
            "valid ciphertext must decapsulate to true shared secret for {algo:?}"
        );

        let mut rejected_keys: HashSet<[u8; 32]> = HashSet::new();
        let ct_len = algo.ciphertext_len();

        let bit_flip_locations: &[(usize, u8)] = &[
            (0, 0x01),
            (0, 0x80),
            (1, 0x08),
            (ct_len / 4, 0x04),
            (ct_len / 2, 0x10),
            (ct_len - 1, 0x01),
            (ct_len - 1, 0x80),
        ];

        for &(byte_idx, bit_mask) in bit_flip_locations {
            let mut corrupted_ct = valid_ct.clone();
            corrupted_ct.0[byte_idx] ^= bit_mask;

            let res = pq_decapsulate(&dk, &corrupted_ct);
            assert!(
                res.is_ok(),
                "FIPS 203 implicit rejection must return pseudorandom key for bit flip on {algo:?}"
            );
            let k_rejected = *res.unwrap();
            assert_ne!(
                k_rejected, *true_shared_secret,
                "corrupted ciphertext at byte {byte_idx} must not yield true shared secret on {algo:?}"
            );
            assert!(
                rejected_keys.insert(k_rejected),
                "implicit rejection produced colliding key for bit flip at byte {byte_idx} on {algo:?}"
            );
        }

        // Entire block zeroed or inverted
        let zero_ct = PqCiphertext(vec![0u8; ct_len]);
        let res_zero = pq_decapsulate(&dk, &zero_ct);
        assert!(res_zero.is_ok());
        let k_zero = *res_zero.unwrap();
        assert_ne!(k_zero, *true_shared_secret);
        assert!(rejected_keys.insert(k_zero));

        let mut inverted_ct = valid_ct.clone();
        for byte in &mut inverted_ct.0 {
            *byte = !*byte;
        }
        let res_inverted = pq_decapsulate(&dk, &inverted_ct);
        assert!(res_inverted.is_ok());
        let k_inverted = *res_inverted.unwrap();
        assert_ne!(k_inverted, *true_shared_secret);
        assert!(rejected_keys.insert(k_inverted));

        let all_ff_ct = PqCiphertext(vec![0xFFu8; ct_len]);
        let res_ff = pq_decapsulate(&dk, &all_ff_ct);
        assert!(res_ff.is_ok());
        let k_ff = *res_ff.unwrap();
        assert_ne!(k_ff, *true_shared_secret);
        assert!(rejected_keys.insert(k_ff));

        assert!(
            rejected_keys.len() >= bit_flip_locations.len() + 3,
            "every distinct corrupted ciphertext must produce a distinct rejected shared secret on {algo:?}"
        );
    }
}

// =============================================================================
// 3. Noise Handshake Edge-Vector Integration
// =============================================================================

#[test]
fn test_noise_handshake_rejects_malformed_ml_kem_encaps_key() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (valid_pq_ek, _responder_pq_dk) = generate_pq_keypair();
    let psk = [0x42u8; 32];
    let prologue = b"fips203-edge-vector-test-prologue";

    let test_mutations = [
        ("poly 0 start", 0, 3329),
        ("poly 0 middle", 128, 3330),
        ("poly 0/1 boundary", 255, 4000),
        ("poly 1 start", 256, 4095),
        ("poly last end", 767, 3329),
    ];

    for &(label, pos, bad_coeff) in &test_mutations {
        let mut malformed_ek = valid_pq_ek.clone();
        set_coeff_12(&mut malformed_ek, pos, bad_coeff);

        let mut initiator = InitiatorHandshake::new(
            &initiator_static.private,
            &responder_static.public,
            &malformed_ek.0,
            &psk,
            prologue,
        )
        .expect("initiator initialization succeeds with raw byte inputs");

        let mut out_msg = [0u8; 2048];
        let write_res = initiator.write_message_1(b"test-payload", &mut out_msg);
        assert_eq!(
            write_res,
            Err(CryptoError::Handshake),
            "InitiatorHandshake must abort on malformed encapsulation key ({label}, coeff {bad_coeff})"
        );

        assert_eq!(
            initiator.write_message_1(b"retry", &mut out_msg),
            Err(CryptoError::Handshake)
        );
    }
}

#[test]
fn test_noise_handshake_rejects_corrupted_ml_kem_ciphertext_via_implicit_rejection() {
    for algo in [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ] {
        let initiator_static = generate_keypair();
        let responder_static = generate_keypair();
        let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair_for_algo(algo);
        let responder_dk_bytes = responder_pq_dk.to_bytes();
        let psk = [0x11u8; 32];
        let prologue = b"implicit-rejection-handshake-test";

        let mut initiator = InitiatorHandshake::new(
            &initiator_static.private,
            &responder_static.public,
            &responder_pq_ek.0,
            &psk,
            prologue,
        )
        .expect("initiator initialization");

        let payload = b"critical-control-plane-credentials";
        let base_len = algo.flight_1_base_len();
        let mut msg1 = vec![0u8; base_len + payload.len()];
        let n1 = initiator
            .write_message_1(payload, &mut msg1)
            .expect("write_message_1");

        let ct_len = algo.ciphertext_len();
        let corruption_offsets = [80, 81, 80 + ct_len / 4, 80 + ct_len / 2, 80 + ct_len - 1];

        for &offset in &corruption_offsets {
            let mut corrupted_msg = msg1.clone();
            corrupted_msg[offset] ^= 0x55;

            let mut responder = ResponderHandshake::new(
                &responder_static.private,
                &responder_pq_ek.0,
                &psk,
                prologue,
            )
            .expect("responder initialization");

            let mut payload_out = vec![0u8; payload.len() + 32];
            let read_res = responder.read_message_1(
                &corrupted_msg[..n1],
                &responder_dk_bytes,
                &mut payload_out,
            );

            assert_eq!(
                read_res,
                Err(CryptoError::Decrypt),
                "tampered ML-KEM ciphertext at offset {offset} must trigger MAC decryption failure for {algo:?}"
            );

            let mut msg2 = [0u8; 256];
            assert_eq!(
                responder.write_message_2(&[], &mut msg2),
                Err(CryptoError::Handshake)
            );
        }
    }
}

#[test]
fn test_noise_handshake_rejects_truncated_handshake_flights() {
    for algo in [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ] {
        let initiator_static = generate_keypair();
        let responder_static = generate_keypair();
        let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair_for_algo(algo);
        let responder_dk_bytes = responder_pq_dk.to_bytes();
        let psk = [0x22u8; 32];
        let prologue = b"truncation-test-prologue";

        let mut initiator = InitiatorHandshake::new(
            &initiator_static.private,
            &responder_static.public,
            &responder_pq_ek.0,
            &psk,
            prologue,
        )
        .expect("initiator initialization");

        let base_len = algo.flight_1_base_len();
        let mut msg1 = vec![0u8; base_len];
        let n1 = initiator
            .write_message_1(&[], &mut msg1)
            .expect("write_message_1");

        let mut responder = ResponderHandshake::new(
            &responder_static.private,
            &responder_pq_ek.0,
            &psk,
            prologue,
        )
        .expect("responder initialization");

        let mut payload_out = [0u8; 32];
        for cut in [0, 1, 32, 80, 500, base_len - 1] {
            let res = responder.read_message_1(&msg1[..cut], &responder_dk_bytes, &mut payload_out);
            assert_eq!(
                res,
                Err(CryptoError::Handshake),
                "truncated Flight 1 of length {cut} must be rejected with Handshake error for {algo:?}"
            );
        }

        let mut fresh_responder = ResponderHandshake::new(
            &responder_static.private,
            &responder_pq_ek.0,
            &psk,
            prologue,
        )
        .expect("fresh responder");
        fresh_responder
            .read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload_out)
            .expect("valid flight 1");

        let mut msg2 = [0u8; FLIGHT_2_BASE_LEN];
        let n2 = fresh_responder
            .write_message_2(&[], &mut msg2)
            .expect("write_message_2");

        for cut in [0, 1, 16, 31, FLIGHT_2_BASE_LEN - 1] {
            let mut fresh_initiator = InitiatorHandshake::new(
                &initiator_static.private,
                &responder_static.public,
                &responder_pq_ek.0,
                &psk,
                prologue,
            )
            .expect("fresh initiator");
            let mut tmp = vec![0u8; base_len];
            fresh_initiator.write_message_1(&[], &mut tmp).unwrap();

            let res = fresh_initiator.read_message_2(&msg2[..cut], &mut payload_out);
            assert_eq!(
                res,
                Err(CryptoError::Handshake),
                "truncated Flight 2 of length {cut} must be rejected with Handshake error for {algo:?}"
            );
        }

        let res = initiator.read_message_2(&msg2[..n2], &mut payload_out);
        assert!(res.is_ok());
        assert!(initiator.is_finished());
        assert!(fresh_responder.is_finished());
    }
}

#[test]
fn test_noise_handshake_rejects_corrupted_payload_and_tags() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x33u8; 32];
    let prologue = b"tag-corruption-prologue";

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("initiator initialization");

    let payload = b"authenticated-content";
    let mut msg1 = vec![0u8; FLIGHT_1_BASE_LEN + payload.len()];
    let n1 = initiator
        .write_message_1(payload, &mut msg1)
        .expect("write_message_1");

    // Test corruption of static key tag (offset 64..80)
    let mut bad_s_tag = msg1.clone();
    bad_s_tag[70] ^= 0x01;
    let mut responder1 = ResponderHandshake::new(
        &responder_static.private,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("responder");
    let mut payload_out = vec![0u8; payload.len()];
    assert_eq!(
        responder1.read_message_1(&bad_s_tag[..n1], &responder_dk_bytes, &mut payload_out),
        Err(CryptoError::Decrypt)
    );

    // Test corruption of payload ciphertext
    let ct_len = responder_pq_ek.algorithm().unwrap().ciphertext_len();
    let payload_offset = 80 + ct_len;
    let mut bad_payload = msg1.clone();
    bad_payload[payload_offset] ^= 0x01;
    let mut responder2 = ResponderHandshake::new(
        &responder_static.private,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("responder");
    assert_eq!(
        responder2.read_message_1(&bad_payload[..n1], &responder_dk_bytes, &mut payload_out),
        Err(CryptoError::Decrypt)
    );

    // Test corruption of payload Poly1305 MAC tag (last 16 bytes)
    let mut bad_payload_tag = msg1.clone();
    let tag_idx = n1 - 1;
    bad_payload_tag[tag_idx] ^= 0x80;
    let mut responder3 = ResponderHandshake::new(
        &responder_static.private,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("responder");
    assert_eq!(
        responder3.read_message_1(
            &bad_payload_tag[..n1],
            &responder_dk_bytes,
            &mut payload_out
        ),
        Err(CryptoError::Decrypt)
    );
}

#[test]
fn test_high_level_handshake_rejects_corrupted_ml_kem_ciphertext() {
    let init_kp = generate_keypair();
    let resp_kp = generate_keypair();

    let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
    let mut res = Handshake::responder(&resp_kp.private).unwrap();

    let payload = b"high-level-handshake-test-payload";
    let mut msg1 = ini.write_message(payload).unwrap();

    // ML-KEM ciphertext starts at offset 80
    msg1[80] ^= 0x01;

    let read_res = res.read_message(&msg1);
    assert!(
        read_res.is_err(),
        "tampered ML-KEM ciphertext must cause Handshake::read_message to fail"
    );
    assert_eq!(read_res, Err(CryptoError::Decrypt));
}
