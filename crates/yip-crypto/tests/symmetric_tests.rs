use yip_crypto::SymmetricState;
use zeroize::Zeroize;

#[test]
fn test_protocol_name_initialization() {
    let protocol_name = b"PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3";
    let expected_hash = blake3::hash(protocol_name);

    let state = SymmetricState::new(protocol_name);
    assert_eq!(state.ck, *expected_hash.as_bytes());
    assert_eq!(state.h, *expected_hash.as_bytes());

    // Deterministic on distinct protocol names
    let short_name = b"Noise_Test";
    let short_expected = blake3::hash(short_name);
    let short_state = SymmetricState::new(short_name);
    assert_eq!(short_state.ck, *short_expected.as_bytes());
    assert_eq!(short_state.h, *short_expected.as_bytes());
    assert_ne!(state.ck, short_state.ck);
}

#[test]
fn test_mix_hash_updates_deterministically() {
    let mut state = SymmetricState::new(b"test_protocol");
    let initial_ck = state.ck;
    let initial_h = state.h;

    let chunk1 = b"handshake prologue payload";
    state.mix_hash(chunk1);

    // Chaining key must not change during mix_hash
    assert_eq!(state.ck, initial_ck);

    // h must equal blake3(initial_h || chunk1)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&initial_h);
    hasher.update(chunk1);
    let expected_h1 = *hasher.finalize().as_bytes();
    assert_eq!(state.h, expected_h1);

    // Chaining a second mix_hash
    let chunk2 = b"ephemeral key 32 bytes placeholder";
    state.mix_hash(chunk2);

    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(&expected_h1);
    hasher2.update(chunk2);
    let expected_h2 = *hasher2.finalize().as_bytes();
    assert_eq!(state.h, expected_h2);
    assert_eq!(state.ck, initial_ck);
}

#[test]
fn test_mix_key_ratchet_and_emission() {
    let mut state = SymmetricState::new(b"test_protocol");
    let ck_before = state.ck;
    let h_before = state.h;
    let ikm = [0x42u8; 32];

    let k = state.mix_key(&ikm);

    // Domain tag 0x01 with keyed hasher on old ck
    let mut hasher = blake3::Hasher::new_keyed(&ck_before);
    hasher.update(&[0x01]);
    hasher.update(&ikm);
    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    assert_eq!(state.ck, out[0..32]);
    assert_eq!(k, out[32..64]);

    // ck should change, h must not change during mix_key
    assert_ne!(state.ck, ck_before);
    assert_eq!(state.h, h_before);
    assert_ne!(k, [0u8; 32]);
    assert_ne!(state.ck, k);
}

#[test]
fn test_mix_key_and_hash_ratchet_and_emission() {
    let mut state = SymmetricState::new(b"test_protocol");
    let ck_before = state.ck;
    let h_before = state.h;
    let psk = [0x7au8; 32];

    let k = state.mix_key_and_hash(&psk);

    // Domain tag 0x02 with keyed hasher on old ck
    let mut hasher = blake3::Hasher::new_keyed(&ck_before);
    hasher.update(&[0x02]);
    hasher.update(&psk);
    let mut out = [0u8; 96];
    hasher.finalize_xof().fill(&mut out);

    let expected_ck = &out[0..32];
    let temp_h = &out[32..64];
    let expected_k = &out[64..96];

    let mut h_hasher = blake3::Hasher::new();
    h_hasher.update(&h_before);
    h_hasher.update(temp_h);
    let expected_h = *h_hasher.finalize().as_bytes();

    assert_eq!(state.ck, expected_ck);
    assert_eq!(state.h, expected_h);
    assert_eq!(k, expected_k);
    assert_ne!(state.ck, ck_before);
    assert_ne!(state.h, h_before);
}

#[test]
fn test_split_derives_distinct_directional_keys() {
    let state = SymmetricState::new(b"test_protocol");
    let ck_before = state.ck;

    let (k_send, k_recv) = state.split();

    // Domain tag 0x03 with keyed hasher on state.ck
    let mut hasher = blake3::Hasher::new_keyed(&ck_before);
    hasher.update(&[0x03]);
    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    assert_eq!(k_send, out[0..32]);
    assert_eq!(k_recv, out[32..64]);
    assert_ne!(k_send, k_recv);
    assert_ne!(k_send, [0u8; 32]);
    assert_ne!(k_recv, [0u8; 32]);

    // Split borrows &self so ck is unmodified
    assert_eq!(state.ck, ck_before);
}

#[test]
fn test_rekey_forward_secrecy() {
    let current_key = [0x55u8; 32];
    let next_key = SymmetricState::rekey(&current_key);

    // Domain tag 0x04 with keyed hasher on current_key
    let mut hasher = blake3::Hasher::new_keyed(&current_key);
    hasher.update(&[0x04]);
    let mut expected_next = [0u8; 32];
    hasher.finalize_xof().fill(&mut expected_next);

    assert_eq!(next_key, expected_next);
    assert_ne!(next_key, current_key);
    assert_ne!(next_key, [0u8; 32]);

    // Subsequent rekey produces yet another distinct key
    let next_next_key = SymmetricState::rekey(&next_key);
    assert_ne!(next_next_key, next_key);
    assert_ne!(next_next_key, current_key);
}

#[test]
fn test_domain_separation() {
    let test_material = [0x99u8; 32];

    // Initialize state with test_material as ck
    let mut state1 = SymmetricState {
        ck: test_material,
        h: [0x11u8; 32],
    };
    let mut state2 = state1.clone();
    let state3 = state1.clone();

    // Tag 0x01 (mix_key)
    let k_mix_key = state1.mix_key(&test_material);

    // Tag 0x02 (mix_key_and_hash)
    let k_mix_key_and_hash = state2.mix_key_and_hash(&test_material);

    // Tag 0x03 (split)
    let (k_send, k_recv) = state3.split();

    // Tag 0x04 (rekey)
    let k_rekey = SymmetricState::rekey(&test_material);

    // All emitted keys must be pairwise distinct
    assert_ne!(k_mix_key, k_mix_key_and_hash);
    assert_ne!(k_mix_key, k_send);
    assert_ne!(k_mix_key, k_recv);
    assert_ne!(k_mix_key, k_rekey);

    assert_ne!(k_mix_key_and_hash, k_send);
    assert_ne!(k_mix_key_and_hash, k_recv);
    assert_ne!(k_mix_key_and_hash, k_rekey);

    assert_ne!(k_send, k_recv);
    assert_ne!(k_send, k_rekey);
    assert_ne!(k_recv, k_rekey);

    // Chaining keys ratcheted under different tags must also differ
    assert_ne!(state1.ck, state2.ck);
    assert_ne!(state1.ck, k_send);
}

#[test]
fn test_zeroize_and_clone() {
    let mut state = SymmetricState::new(b"test_protocol");
    let cloned = state.clone();
    assert_eq!(cloned.ck, state.ck);
    assert_eq!(cloned.h, state.h);

    // Explicit zeroize on state
    state.zeroize();
    assert_eq!(state.ck, [0u8; 32]);
    assert_eq!(state.h, [0u8; 32]);

    // Cloned state must retain original data
    assert_ne!(cloned.ck, [0u8; 32]);
    assert_ne!(cloned.h, [0u8; 32]);
}
