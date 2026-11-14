#![forbid(unsafe_code)]

//! NIST FIPS 203 ML-KEM-512 edge vector and implicit rejection test suite.
//!
//! Validates:
//! - Section 7.2 ByteDecode_12 boundary rejections: all 12-bit coefficients must be strictly < 3329.
//! - Section 7.3 Implicit rejection: decapsulation of invalid or corrupted ciphertexts produces
//!   pseudorandom shared secrets rather than failing or returning fixed error values.
//! - Post-quantum Noise handshake integration: rejection of invalid encapsulation keys and
//!   rejection of corrupted handshake messages across initiator and responder roles.

use std::collections::HashSet;

use yip_crypto::handshake::{
    InitiatorHandshake, ResponderHandshake, FLIGHT_1_BASE_LEN, FLIGHT_2_BASE_LEN,
};
use yip_crypto::{
    generate_keypair, generate_pq_keypair, generate_pq_keypair_from_seed, pq_decapsulate,
    pq_encapsulate, pq_encapsulate_deterministic, CryptoError, Handshake, PqCiphertext,
    PqEncapsKey, PQ_CIPHERTEXT_LEN,
};

/// Set a 12-bit coefficient in the first 768 bytes of an ML-KEM-512 encapsulation key.
///
/// The 768-byte coefficient array consists of 256 three-byte chunks encoding two 12-bit
/// coefficients each (512 coefficients total: 256 for polynomial 0, 256 for polynomial 1).
fn set_coeff_12(ek: &mut PqEncapsKey, coeff_idx: usize, val: u16) {
    assert!(
        coeff_idx < 512,
        "coefficient index out of bounds for 768-byte coefficient array"
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

/// Decode a 12-bit coefficient from the first 768 bytes of an ML-KEM-512 encapsulation key.
fn get_coeff_12(ek: &PqEncapsKey, coeff_idx: usize) -> u16 {
    assert!(
        coeff_idx < 512,
        "coefficient index out of bounds for 768-byte coefficient array"
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
    let (mut ek, _dk) = generate_pq_keypair();
    for &val in &[0u16, 1, 1000, 3328, 3329, 3330, 4000, 4095] {
        for coeff_idx in [0, 1, 128, 255, 256, 384, 510, 511] {
            set_coeff_12(&mut ek, coeff_idx, val);
            assert_eq!(
                get_coeff_12(&ek, coeff_idx),
                val,
                "coefficient roundtrip failed at index {coeff_idx} for val {val}"
            );
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

    // Representative positions across the 768-byte (512 coefficients) array:
    // - Polynomial 0: start (0, 1), middle (128), end (254, 255)
    // - Polynomial 1: start (256, 257), middle (384), end (510, 511)
    let test_positions = [
        ("poly 0 start d0", 0),
        ("poly 0 start d1", 1),
        ("poly 0 middle", 128),
        ("poly 0 end d0", 254),
        ("poly 0 end d1 / boundary", 255),
        ("poly 1 start d0 / boundary", 256),
        ("poly 1 start d1", 257),
        ("poly 1 middle", 384),
        ("poly 1 end d0", 510),
        ("poly 1 end d1 (last coeff)", 511),
    ];

    for &(label, pos) in &test_positions {
        for &invalid_val in &invalid_coeffs {
            let (mut ek, _dk) = generate_pq_keypair();
            set_coeff_12(&mut ek, pos, invalid_val);

            // Assert that pq_encapsulate_deterministic strictly returns Err(CryptoError::Handshake)
            let det_res = pq_encapsulate_deterministic(&ek, &deterministic_m);
            assert_eq!(
                det_res,
                Err(CryptoError::Handshake),
                "pq_encapsulate_deterministic must reject coefficient {invalid_val} at {label} (pos {pos})"
            );

            // Assert that non-deterministic pq_encapsulate also strictly returns Err(CryptoError::Handshake)
            let rnd_res = pq_encapsulate(&ek);
            assert_eq!(
                rnd_res,
                Err(CryptoError::Handshake),
                "pq_encapsulate must reject coefficient {invalid_val} at {label} (pos {pos})"
            );
        }
    }
}

#[test]
fn test_bytedecode12_valid_boundary_accepted() {
    // 3328 is q - 1, which is strictly < 3329 and should satisfy the ByteDecode_12 check.
    let (mut ek, _dk) = generate_pq_keypair();
    let deterministic_m = [0x55u8; 32];

    // Set coefficient 0 and coefficient 511 to 3328 (valid upper boundary)
    set_coeff_12(&mut ek, 0, 3328);
    set_coeff_12(&mut ek, 511, 3328);

    let res = pq_encapsulate_deterministic(&ek, &deterministic_m);
    assert!(
        res.is_ok(),
        "valid coefficient 3328 (q-1) must pass ByteDecode_12 modulus validation"
    );
}

#[test]
fn test_bytedecode12_all_coefficients_mutated_rejection() {
    let (mut ek, _dk) = generate_pq_keypair();
    let deterministic_m = [0x99u8; 32];

    // Set all 512 coefficients to 4095 (0x0FFF)
    ek.0[..768].fill(0xFF);

    assert_eq!(
        pq_encapsulate_deterministic(&ek, &deterministic_m),
        Err(CryptoError::Handshake),
        "all-0xFF coefficient array must be rejected"
    );
    assert_eq!(
        pq_encapsulate(&ek),
        Err(CryptoError::Handshake),
        "all-0xFF coefficient array must be rejected by random encapsulation"
    );
}

// =============================================================================
// 2. FIPS 203 Section 7.3 Implicit Rejection
// =============================================================================

#[test]
fn test_fips203_implicit_rejection_properties() {
    let seed = [0x37u8; 64];
    let (ek, dk) = generate_pq_keypair_from_seed(&seed);
    let m = [0x7au8; 32];

    // 1. Encapsulate valid (ct, true_shared_secret)
    let (valid_ct, true_shared_secret) =
        pq_encapsulate_deterministic(&ek, &m).expect("valid encapsulation");

    // 2. Decapsulate valid ct: assert result equals true_shared_secret
    let decaps_ss = pq_decapsulate(&dk, &valid_ct).expect("decapsulate valid ciphertext");
    assert_eq!(
        *true_shared_secret, *decaps_ss,
        "valid ciphertext must decapsulate to true shared secret"
    );

    // Track all rejected shared secrets to assert that distinct corrupted ciphertexts
    // produce distinct pseudorandom keys with zero collisions (no fixed default error value).
    let mut rejected_keys: HashSet<[u8; 32]> = HashSet::new();

    // 3. Single-bit flips across diverse positions in the 768-byte ciphertext
    let bit_flip_locations: &[(usize, u8)] = &[
        (0, 0x01),   // byte 0, bit 0
        (0, 0x80),   // byte 0, bit 7
        (1, 0x08),   // byte 1, bit 3
        (50, 0x04),  // poly 0 intermediate
        (128, 0x10), // poly 0 intermediate
        (383, 0x01), // poly 0 boundary (last byte of poly 0)
        (383, 0x80), // poly 0 boundary bit 7
        (384, 0x01), // poly 1 boundary (first byte of poly 1)
        (384, 0x40), // poly 1 boundary bit 6
        (500, 0x02), // poly 1 intermediate
        (700, 0x20), // poly 1 intermediate
        (767, 0x01), // last byte, bit 0
        (767, 0x80), // last byte, bit 7
    ];

    for &(byte_idx, bit_mask) in bit_flip_locations {
        let mut corrupted_ct = valid_ct.clone();
        corrupted_ct.0[byte_idx] ^= bit_mask;

        let res = pq_decapsulate(&dk, &corrupted_ct);
        assert!(
            res.is_ok(),
            "FIPS 203 implicit rejection must not return error channel for bit flip at byte {byte_idx}"
        );
        let k_rejected = *res.unwrap();

        assert_ne!(
            k_rejected, *true_shared_secret,
            "corrupted ciphertext at byte {byte_idx} must not yield true shared secret"
        );

        let inserted = rejected_keys.insert(k_rejected);
        assert!(
            inserted,
            "implicit rejection produced colliding key for bit flip at byte {byte_idx}"
        );
    }

    // 4. Entire block zeroed or inverted
    let zero_ct = PqCiphertext([0u8; PQ_CIPHERTEXT_LEN]);
    let res_zero = pq_decapsulate(&dk, &zero_ct);
    assert!(
        res_zero.is_ok(),
        "implicit rejection must handle all-zero ciphertext without panic or error"
    );
    let k_zero = *res_zero.unwrap();
    assert_ne!(k_zero, *true_shared_secret);
    assert!(rejected_keys.insert(k_zero));

    let mut inverted_ct = valid_ct.clone();
    for byte in &mut inverted_ct.0 {
        *byte = !*byte;
    }
    let res_inverted = pq_decapsulate(&dk, &inverted_ct);
    assert!(
        res_inverted.is_ok(),
        "implicit rejection must handle inverted ciphertext without panic or error"
    );
    let k_inverted = *res_inverted.unwrap();
    assert_ne!(k_inverted, *true_shared_secret);
    assert!(rejected_keys.insert(k_inverted));

    let all_ff_ct = PqCiphertext([0xFFu8; PQ_CIPHERTEXT_LEN]);
    let res_ff = pq_decapsulate(&dk, &all_ff_ct);
    assert!(res_ff.is_ok());
    let k_ff = *res_ff.unwrap();
    assert_ne!(k_ff, *true_shared_secret);
    assert!(rejected_keys.insert(k_ff));

    // 5. Truncated or modified polynomial vectors (within the 768-byte representation)
    // Modified polynomial 0 vector (bytes 0..384 zeroed)
    let mut poly0_zeroed = valid_ct.clone();
    poly0_zeroed.0[..384].fill(0);
    let res_poly0 = pq_decapsulate(&dk, &poly0_zeroed);
    assert!(res_poly0.is_ok());
    let k_poly0 = *res_poly0.unwrap();
    assert_ne!(k_poly0, *true_shared_secret);
    assert!(rejected_keys.insert(k_poly0));

    // Modified polynomial 1 vector (bytes 384..768 zeroed)
    let mut poly1_zeroed = valid_ct.clone();
    poly1_zeroed.0[384..].fill(0);
    let res_poly1 = pq_decapsulate(&dk, &poly1_zeroed);
    assert!(res_poly1.is_ok());
    let k_poly1 = *res_poly1.unwrap();
    assert_ne!(k_poly1, *true_shared_secret);
    assert!(rejected_keys.insert(k_poly1));

    // Swapped polynomial vectors (c1 and c2 swapped)
    let mut swapped_ct = valid_ct.clone();
    let (left, right) = swapped_ct.0.split_at_mut(384);
    left.swap_with_slice(right);
    let res_swapped = pq_decapsulate(&dk, &swapped_ct);
    assert!(res_swapped.is_ok());
    let k_swapped = *res_swapped.unwrap();
    assert_ne!(k_swapped, *true_shared_secret);
    assert!(rejected_keys.insert(k_swapped));

    // Verification of no fixed default error value:
    // Assert all distinct corrupted ciphertexts produced strictly distinct rejected keys.
    assert!(
        rejected_keys.len() >= bit_flip_locations.len() + 6,
        "every distinct corrupted ciphertext must produce a distinct rejected shared secret"
    );
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

    // Test positions across poly 0, poly 1, middle, and end
    let test_mutations = [
        ("poly 0 start", 0, 3329),
        ("poly 0 middle", 128, 3330),
        ("poly 0/1 boundary", 255, 4000),
        ("poly 1 start", 256, 4095),
        ("poly 1 end", 511, 3329),
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

        let mut out_msg = [0u8; 1024];
        let write_res = initiator.write_message_1(b"test-payload", &mut out_msg);
        assert_eq!(
            write_res,
            Err(CryptoError::Handshake),
            "InitiatorHandshake must abort on malformed encapsulation key ({label}, coeff {bad_coeff})"
        );

        // After failure, state machine is aborted and further operations must fail
        assert_eq!(
            initiator.write_message_1(b"retry", &mut out_msg),
            Err(CryptoError::Handshake)
        );
    }
}

#[test]
fn test_noise_handshake_rejects_corrupted_ml_kem_ciphertext_via_implicit_rejection() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
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
    let mut msg1 = vec![0u8; FLIGHT_1_BASE_LEN + payload.len()];
    let n1 = initiator
        .write_message_1(payload, &mut msg1)
        .expect("write_message_1");

    // Flight 1 layout:
    // [0..32]: ephemeral e_i
    // [32..64]: encrypted s_i
    // [64..80]: s_i tag
    // [80..848]: ML-KEM-512 ciphertext (768 bytes)
    // [848..848+len]: encrypted payload
    // [848+len..848+len+16]: payload tag

    // Corrupt positions inside the 768-byte ML-KEM ciphertext span [80..848]:
    let corruption_offsets = [
        80,  // start of ML-KEM ciphertext
        81,  // second byte
        200, // poly 0 interior
        463, // poly 0 end
        464, // poly 1 start
        700, // poly 1 interior
        847, // last byte of ML-KEM ciphertext
    ];

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
        let read_res =
            responder.read_message_1(&corrupted_msg[..n1], &responder_dk_bytes, &mut payload_out);

        // Due to implicit rejection, decapsulation generates a pseudo-random ss_kem,
        // causing k_3 derivation to diverge. Decryption of the payload MAC tag strictly fails with Decrypt error.
        assert_eq!(
            read_res,
            Err(CryptoError::Decrypt),
            "tampered ML-KEM ciphertext at offset {offset} must trigger MAC decryption failure"
        );

        // Responder state must transition to Failed and reject subsequent write_message_2
        let mut msg2 = [0u8; 256];
        assert_eq!(
            responder.write_message_2(&[], &mut msg2),
            Err(CryptoError::Handshake)
        );
    }
}

#[test]
fn test_noise_handshake_rejects_truncated_handshake_flights() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
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

    let mut msg1 = vec![0u8; FLIGHT_1_BASE_LEN];
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

    // Flight 1 truncation tests
    let mut payload_out = [0u8; 32];
    for cut in [0, 1, 32, 80, 500, FLIGHT_1_BASE_LEN - 1] {
        let res = responder.read_message_1(&msg1[..cut], &responder_dk_bytes, &mut payload_out);
        assert_eq!(
            res,
            Err(CryptoError::Handshake),
            "truncated Flight 1 of length {cut} must be rejected with Handshake error"
        );
    }

    // Now complete Flight 1 with fresh responder
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

    // Flight 2 truncation tests
    for cut in [0, 1, 16, 31, FLIGHT_2_BASE_LEN - 1] {
        let mut fresh_initiator = InitiatorHandshake::new(
            &initiator_static.private,
            &responder_static.public,
            &responder_pq_ek.0,
            &psk,
            prologue,
        )
        .expect("fresh initiator");
        let mut tmp = vec![0u8; FLIGHT_1_BASE_LEN];
        fresh_initiator.write_message_1(&[], &mut tmp).unwrap();

        let res = fresh_initiator.read_message_2(&msg2[..cut], &mut payload_out);
        assert_eq!(
            res,
            Err(CryptoError::Handshake),
            "truncated Flight 2 of length {cut} must be rejected with Handshake error"
        );
    }

    // Valid Flight 2 completes successfully
    let res = initiator.read_message_2(&msg2[..n2], &mut payload_out);
    assert!(res.is_ok());
    assert!(initiator.is_finished());
    assert!(fresh_responder.is_finished());
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

    // Test corruption of payload ciphertext (offset 848..848+payload.len())
    let mut bad_payload = msg1.clone();
    bad_payload[848] ^= 0x01;
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

    // ML-KEM ciphertext starts at offset 80 and is 768 bytes long
    msg1[80] ^= 0x01;

    let read_res = res.read_message(&msg1);
    assert!(
        read_res.is_err(),
        "tampered ML-KEM ciphertext must cause Handshake::read_message to fail"
    );
    assert_eq!(read_res, Err(CryptoError::Decrypt));
}
