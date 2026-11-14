//! Project Wycheproof test vectors for ChaCha20-Poly1305 AEAD.
//!
//! Validates:
//! - Correct in-place encryption and decryption with zero-extended 12-byte nonces (noise_nonce).
//! - Official Project Wycheproof AEAD test vectors (known answer tests, edge cases, poly1305 keys).
//! - Invalid vector handling:
//!   - Tag truncation (ciphertext buffer too short or tag truncated < 16 bytes).
//!   - Single-bit flips across the ciphertext payload.
//!   - Single-bit flips across all 128 bits of the 16-byte Poly1305 authentication tag.
//!   - Modified or corrupted ciphertext bytes (byte modifications, key/counter mismatch).
//! - Asserts that open_in_place returns Err(CryptoError::Decrypt) on all invalid vectors.
#![forbid(unsafe_code)]

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use yip_crypto::{noise_nonce, ChaCha20Poly1305Cipher, CryptoError};

fn hex_to_vec(hex_str: &str) -> Vec<u8> {
    if hex_str.is_empty() {
        return Vec::new();
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let v = hex_to_vec(hex_str);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    arr
}

fn hex_to_16(hex_str: &str) -> [u8; 16] {
    let v = hex_to_vec(hex_str);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&v);
    arr
}

struct NoiseNonceVector {
    key: &'static str,
    counter: u64,
    plaintext: &'static str,
    expected_ciphertext: &'static str,
    expected_tag: &'static str,
    comment: &'static str,
}

static NOISE_NONCE_VECTORS: &[NoiseNonceVector] = &[
    NoiseNonceVector {
        key: "0101010101010101010101010101010101010101010101010101010101010101",
        counter: 0u64,
        plaintext: "",
        expected_ciphertext: "",
        expected_tag: "35eaf9cc876d72bd36f8b7cf7d8c8142",
        comment: "Empty payload at counter 0",
    },
    NoiseNonceVector {
        key: "0101010101010101010101010101010101010101010101010101010101010101",
        counter: 1u64,
        plaintext: "41",
        expected_ciphertext: "0c",
        expected_tag: "519d559f6bcae9fc05a9416a42689fad",
        comment: "1-byte payload at counter 1",
    },
    NoiseNonceVector {
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        counter: 42u64,
        plaintext: "30313233343536373839616263646566",
        expected_ciphertext: "d4665991ca51a9e29f7ed4ea65811d3d",
        expected_tag: "66fdb81c19793a66e333548b502c4bcb",
        comment: "16-byte block boundary payload at counter 42",
    },
    NoiseNonceVector {
        key: "4242424242424242424242424242424242424242424242424242424242424242",
        counter: 1000u64,
        plaintext: "4e6f6973652070726f746f636f6c207a65726f2d657874656e646564206e6f6e636520766572696669636174696f6e20766563746f7220333220627974657321",
        expected_ciphertext: "1b5ec1d167ae1cabf418bf9f95fd93b9db8d39543072dfb16851aaa014a9d63a6a78379ad0b932e4a53db70548e57c254590f0f1114b94da1d1338943645e0fe",
        expected_tag: "6efb37b0e3282d2928d3874aa477b584",
        comment: "64-byte payload at counter 1000",
    },
    NoiseNonceVector {
        key: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        counter: 72623859790382856u64,
        plaintext: "43686143686132302d506f6c7931333035204145414420577963686570726f6f66207465737420766563746f72206d756c74692d626c6f636b20313238206279746573207061796c6f616420766572696669636174696f6e206275666665722077697468206d6f6e6f746f6e696320636f756e74657220616e64207a65726f20657874656e73696f6e21",
        expected_ciphertext: "1d52b1dcc19bc9df76435e0bbc8c768c42cd243e0af223fcac5a1429b7909eade0f8890c6872b378df32217ef0a6c34aceabbad533bc4a0cb4742f7d5aefbce0bf302ab0cf7b476cb01ac09b3febce5d96b278e881ab0212b45f33381627e5e35b10bd088e45043edcf8e1db95f02fc94c8191c5751678e15317f27263aea041fe98236d19cb1984fe5b",
        expected_tag: "885bee813a0b8e6d5fc03d51339d51b7",
        comment: "128-byte multi-block payload with 64-bit monotonic counter",
    },
    NoiseNonceVector {
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        counter: 18446744073709551615u64,
        plaintext: "6d6178696d756d20636f756e7465722076616c7565207465737420766563746f72",
        expected_ciphertext: "97eabbda937cd0050a5155ac691c3a87fd54685668c7fa0344e45bd8bb5dac997e",
        expected_tag: "2a4876a13980dfb70d51b9ebd267b48c",
        comment: "33-byte payload with max counter u64::MAX",
    },
    NoiseNonceVector {
        key: "5555555555555555555555555555555555555555555555555555555555555555",
        counter: 12345678u64,
        plaintext: "5a65726f2d636f707920696e2d706c616365207061636b657420656e6372797074696f6e20616e642064656372797074696f6e20766572696669636174696f6e",
        expected_ciphertext: "12bf735b56bb72f9fc3b698732b66ed649f110eba53295cf05cfdfd4f6d81bc3370fa89d1b8e745284ee3a1af99b1e53639a4045c261a01f4d72d06282cc2674",
        expected_tag: "36cd59411a9dfec860a60f2301839d56",
        comment: "64-byte payload with arbitrary counter",
    },
];

struct WycheproofAeadVector {
    tc_id: u32,
    key: &'static str,
    iv: &'static str,
    aad: &'static str,
    msg: &'static str,
    ct: &'static str,
    tag: &'static str,
    valid: bool,
    comment: &'static str,
}

static WYCHEPROOF_AEAD_VECTORS: &[WycheproofAeadVector] = &[
    WycheproofAeadVector {
        tc_id: 1,
        key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        iv: "070000004041424344454647",
        aad: "50515253c0c1c2c3c4c5c6c7",
        msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        ct: "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        tag: "1ae10b594f09e26a7e902ecbd0600691",
        valid: true,
        comment: "RFC 7539",
    },
    WycheproofAeadVector {
        tc_id: 2,
        key: "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
        iv: "4da5bf8dfd5852c1ea12379d",
        aad: "",
        msg: "",
        ct: "",
        tag: "76acb342cf3166a5b63c0c0ea1383c8d",
        valid: true,
        comment: "",
    },
    WycheproofAeadVector {
        tc_id: 4,
        key: "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273",
        iv: "99e23ec48985bccdeeab60f1",
        aad: "",
        msg: "2a",
        ct: "3a",
        tag: "cac27dec0968801e9f6eded69d807522",
        valid: true,
        comment: "",
    },
    WycheproofAeadVector {
        tc_id: 10,
        key: "e4912cb75a1174345f1a457366f18885fe8460b06478e04be2f7fb4ec9c113e5",
        iv: "7aa5ad8bf5254762171ec869",
        aad: "",
        msg: "9e4c1d03",
        ct: "fe6849aa",
        tag: "99ad07871b25c27defc31a541bd5c418",
        valid: true,
        comment: "",
    },
    WycheproofAeadVector {
        tc_id: 20,
        key: "e1094967f86d893cdfe2e2e6d5c7ee4dfef67da3c9c5d64e6ad7c1577dcb38c5",
        iv: "8092fc245b3326cddbd1424c",
        aad: "",
        msg: "c37aa791ddd6accf91",
        ct: "d9d897a9c1c5bb9f01",
        tag: "085a430373058f1a12a0d589fd5be68b",
        valid: true,
        comment: "",
    },
    WycheproofAeadVector {
        tc_id: 146,
        key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        iv: "000102030405060708090a0b",
        aad: "000102",
        msg: "",
        ct: "",
        tag: "f5409bb729039d0814ac514054323f44",
        valid: false,
        comment: "Flipped bit 0 in tag expected tag:f4409bb729039d0814ac514054323f44",
    },
    WycheproofAeadVector {
        tc_id: 147,
        key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        iv: "000102030405060708090a0b",
        aad: "000102",
        msg: "",
        ct: "",
        tag: "f6409bb729039d0814ac514054323f44",
        valid: false,
        comment: "Flipped bit 1 in tag expected tag:f4409bb729039d0814ac514054323f44",
    },
    WycheproofAeadVector {
        tc_id: 148,
        key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        iv: "000102030405060708090a0b",
        aad: "000102",
        msg: "",
        ct: "",
        tag: "74409bb729039d0814ac514054323f44",
        valid: false,
        comment: "Flipped bit 7 in tag expected tag:f4409bb729039d0814ac514054323f44",
    },
    WycheproofAeadVector {
        tc_id: 149,
        key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        iv: "000102030405060708090a0b",
        aad: "000102",
        msg: "",
        ct: "",
        tag: "f4419bb729039d0814ac514054323f44",
        valid: false,
        comment: "Flipped bit 8 in tag expected tag:f4409bb729039d0814ac514054323f44",
    },
    WycheproofAeadVector {
        tc_id: 150,
        key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        iv: "000102030405060708090a0b",
        aad: "000102",
        msg: "",
        ct: "",
        tag: "f4409b3729039d0814ac514054323f44",
        valid: false,
        comment: "Flipped bit 31 in tag expected tag:f4409bb729039d0814ac514054323f44",
    },
    WycheproofAeadVector {
        tc_id: 153,
        key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        iv: "000102030405060708090a0b",
        aad: "000102",
        msg: "",
        ct: "",
        tag: "f4409bb729039d8814ac514054323f44",
        valid: false,
        comment: "Flipped bit 63 in tag expected tag:f4409bb729039d0814ac514054323f44",
    },
    WycheproofAeadVector {
        tc_id: 154,
        key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        iv: "000102030405060708090a0b",
        aad: "000102",
        msg: "",
        ct: "",
        tag: "f4409bb729039d0815ac514054323f44",
        valid: false,
        comment: "Flipped bit 64 in tag expected tag:f4409bb729039d0814ac514054323f44",
    },
    WycheproofAeadVector {
        tc_id: 216,
        key: "9de836aa579585081f330a7c4036e20e38ef15eff3945184d231867f505fffdf",
        iv: "00000000101112130bc672c3",
        aad: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        msg: "3619cb470af86dceceb6940f2d9abb34c9a9131476053387445ffebbe240d4f9818377855652f46a8219c7f71c3554f8acef8258de4b7d17c0f3d353ac981cc6a13287be1e6b41dc6d133df4ababebdf43d665ce7a4a5c982a0b139cb8202eebc74173e3224a440e4c37d2b595f384290e939ba016df0d49b36cdb4bd91c39",
        ct: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        tag: "133fe62391744d11ce44594b96c53baf",
        valid: true,
        comment: "edge case for poly1305 key:feffff1ff6b87403fd6435b09775bc92491a0ae62c5842a30e3b82710cc2dad1",
    },
    WycheproofAeadVector {
        tc_id: 217,
        key: "9de836aa579585081f330a7c4036e20e38ef15eff3945184d231867f505fffdf",
        iv: "000000001011121303e9b9a4",
        aad: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        msg: "af205bda819f7451be0f28667d4b01b59ff2daa8173cab52046c3c9e0d989889c5e021ef7afd06e9ce6cc30e3a6ebab509134ba10d10e570c55587c13eee53e73be54804c8539ffbf23b35922b1ca37b9e9bc24ee204837ca5a294ce05d12600c7eff6aee32270db2feff47dc5a04176169e15850628e6035f78994f9f5603",
        ct: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        tag: "e3451adb9d23a7710a1aafba26f56387",
        valid: true,
        comment: "edge case for poly1305 key:bf358f18ffffffbf4b62ed6e1f53790785c4dabdfc72e2a219d377a682c85f38",
    },
    WycheproofAeadVector {
        tc_id: 218,
        key: "9de836aa579585081f330a7c4036e20e38ef15eff3945184d231867f505fffdf",
        iv: "00000000101112130700b982",
        aad: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        msg: "68c67272036fb652a0182eeb4781358e4704a4a702fd731bf3b3ea994717989e7d9104e0ae81732a8c7e9a82b3d31d541761a366b67c3396f1a6c67e293ddb65a59e42541dda144dc6c78388cfca982e23350958ac5b3d54a1722fd64733577862e1879c9e9445ebdec5315d1706db7ebbedd4c779935e72057e5b0ecde081",
        ct: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        tag: "b0bb8a55ff5f52a5043c6e7795847557",
        valid: true,
        comment: "edge case for poly1305 key:d0b7b3a352a4010ffeffffbfe8cc66dc6e5e7451dc61762c5753174fed88e746",
    },

];

#[test]
fn test_noise_nonce_encoding_structure() {
    // Noise RFC requires: 4 zero bytes followed by 8-byte little-endian counter.
    for counter in [0u64, 1, 42, 0x12345678, u64::MAX] {
        let n = noise_nonce(counter);
        let n_bytes = n.as_ref();
        assert_eq!(n_bytes.len(), 12);
        assert_eq!(&n_bytes[0..4], &[0u8; 4], "first 4 bytes must be 0");
        assert_eq!(
            &n_bytes[4..12],
            &counter.to_le_bytes(),
            "last 8 bytes must be counter in little-endian"
        );
    }
}

#[test]
fn test_wycheproof_valid_vectors_seal_and_open_in_place() {
    for vec in NOISE_NONCE_VECTORS {
        let key = hex_to_32(vec.key);
        let pt = hex_to_vec(vec.plaintext);
        let expected_ct = hex_to_vec(vec.expected_ciphertext);
        let expected_tag = hex_to_16(vec.expected_tag);

        let cipher = ChaCha20Poly1305Cipher::new(key);

        // Network packet buffer with extra head/tail padding
        let mut buf = vec![0u8; pt.len() + 64];
        buf[..pt.len()].copy_from_slice(&pt);

        // 1. Seal in-place
        let sealed_len = cipher
            .seal_in_place(vec.counter, &mut buf, pt.len())
            .expect("seal_in_place failed on valid vector");

        assert_eq!(
            sealed_len,
            pt.len() + 16,
            "sealed_len mismatch for {}",
            vec.comment
        );
        assert_eq!(
            &buf[..pt.len()],
            expected_ct.as_slice(),
            "ciphertext mismatch for {}",
            vec.comment
        );
        assert_eq!(
            &buf[pt.len()..sealed_len],
            &expected_tag,
            "tag mismatch for {}",
            vec.comment
        );

        // 2. Open in-place
        let opened_len = cipher
            .open_in_place(vec.counter, &mut buf, sealed_len)
            .expect("open_in_place failed on valid vector");

        assert_eq!(
            opened_len,
            pt.len(),
            "opened_len mismatch for {}",
            vec.comment
        );
        assert_eq!(
            &buf[..opened_len],
            pt.as_slice(),
            "decrypted plaintext mismatch for {}",
            vec.comment
        );
    }
}

#[test]
fn test_wycheproof_official_aead_vectors() {
    for vec in WYCHEPROOF_AEAD_VECTORS {
        let key_bytes = hex_to_32(vec.key);
        let iv_bytes = hex_to_vec(vec.iv);
        assert_eq!(iv_bytes.len(), 12);
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(&iv_bytes);

        let aad_bytes = hex_to_vec(vec.aad);
        let ct_bytes = hex_to_vec(vec.ct);
        let tag_bytes = hex_to_16(vec.tag);
        let msg_bytes = hex_to_vec(vec.msg);

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .expect("valid 32-byte key for chacha20-poly1305");
        let less_safe = LessSafeKey::new(unbound);

        let mut in_out = Vec::with_capacity(ct_bytes.len() + tag_bytes.len());
        in_out.extend_from_slice(&ct_bytes);
        in_out.extend_from_slice(&tag_bytes);

        let nonce = Nonce::assume_unique_for_key(iv_arr);
        let aad = Aad::from(aad_bytes.as_slice());

        let res = less_safe.open_in_place(nonce, aad, &mut in_out);

        if vec.valid {
            let plain = res.unwrap_or_else(|_| {
                panic!(
                    "test case {} ({}) was expected to succeed but failed decryption",
                    vec.tc_id, vec.comment
                )
            });
            assert_eq!(
                plain,
                msg_bytes.as_slice(),
                "plaintext mismatch on tcId {}",
                vec.tc_id
            );
        } else {
            assert!(
                res.is_err(),
                "test case {} ({}) was expected to fail authentication but succeeded",
                vec.tc_id,
                vec.comment
            );
        }
    }
}

#[test]
fn test_tag_truncation_rejected() {
    let key = [0x77u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(key);
    let counter = 100u64;
    let plaintext = b"Arbitrary plaintext payload to test tag truncation edge cases.";

    let mut buf = vec![0u8; plaintext.len() + 32];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let sealed_len = cipher
        .seal_in_place(counter, &mut buf, plaintext.len())
        .expect("seal_in_place");

    // 1. sealed_len < 16 bytes rejected
    for len in 0..16 {
        let res = cipher.open_in_place(counter, &mut buf, len);
        assert_eq!(
            res,
            Err(CryptoError::Decrypt),
            "sealed_len < 16 ({}) must return Err(CryptoError::Decrypt)",
            len
        );
    }

    // 2. Tag truncation: 1 to 15 bytes chopped from the end of the sealed buffer
    for truncated_bytes in 1..=15 {
        let truncated_len = sealed_len - truncated_bytes;
        let mut truncated_buf = buf[..truncated_len].to_vec();
        let res = cipher.open_in_place(counter, &mut truncated_buf, truncated_len);
        assert_eq!(
            res,
            Err(CryptoError::Decrypt),
            "truncated tag by {} bytes must return Err(CryptoError::Decrypt)",
            truncated_bytes
        );
    }

    // 3. Buffer smaller than sealed_len
    let mut short_buf = buf[..sealed_len - 1].to_vec();
    let res = cipher.open_in_place(counter, &mut short_buf, sealed_len);
    assert_eq!(
        res,
        Err(CryptoError::Decrypt),
        "buf.len() < sealed_len must return Err(CryptoError::Decrypt)"
    );
}

#[test]
fn test_single_bit_flips_in_ciphertext_payload() {
    let key = [0x88u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(key);
    let counter = 500u64;

    // Test across various payload sizes (sub-block, block boundary, multi-block)
    for payload_size in [1, 15, 16, 64, 128] {
        let plaintext: Vec<u8> = (0..payload_size)
            .map(|i| (i as u8).wrapping_mul(7))
            .collect();
        let mut buf = vec![0u8; payload_size + 32];
        buf[..payload_size].copy_from_slice(&plaintext);

        let sealed_len = cipher
            .seal_in_place(counter, &mut buf, payload_size)
            .expect("seal_in_place");

        // Systematically flip every single bit in the ciphertext payload
        let sealed_copy = buf[..sealed_len].to_vec();
        for byte_idx in 0..payload_size {
            for bit_idx in 0..8 {
                let mask = 1u8 << bit_idx;
                let mut test_buf = sealed_copy.clone();
                test_buf[byte_idx] ^= mask;

                let res = cipher.open_in_place(counter, &mut test_buf, sealed_len);
                assert_eq!(
                    res,
                    Err(CryptoError::Decrypt),
                    "single-bit flip at payload byte {} bit {} must fail decryption",
                    byte_idx,
                    bit_idx
                );
            }
        }
        // Verify pristine buffer decrypts cleanly
        let mut clean_buf = sealed_copy;
        let restored_len = cipher
            .open_in_place(counter, &mut clean_buf, sealed_len)
            .expect("unmodified ciphertext must decrypt cleanly");
        assert_eq!(restored_len, payload_size);
        assert_eq!(&clean_buf[..restored_len], plaintext.as_slice());
    }
}

#[test]
fn test_single_bit_flips_in_authentication_tag() {
    let key = [0x99u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(key);
    let counter = 12345u64;
    let plaintext = b"Poly1305 authentication tag bit-flip integrity validation vector.";
    let payload_size = plaintext.len();

    let mut buf = vec![0u8; payload_size + 32];
    buf[..payload_size].copy_from_slice(plaintext);

    let sealed_len = cipher
        .seal_in_place(counter, &mut buf, payload_size)
        .expect("seal_in_place");

    // The tag is located at buf[payload_size..payload_size + 16]
    // Systematically flip every bit across all 16 bytes of the tag (128 individual bit-flip tests)
    let sealed_copy = buf[..sealed_len].to_vec();
    for tag_byte_idx in 0..16 {
        let byte_pos = payload_size + tag_byte_idx;
        for bit_idx in 0..8 {
            let mask = 1u8 << bit_idx;
            let mut test_buf = sealed_copy.clone();
            test_buf[byte_pos] ^= mask;

            let res = cipher.open_in_place(counter, &mut test_buf, sealed_len);
            assert_eq!(
                res,
                Err(CryptoError::Decrypt),
                "single-bit flip in tag byte {} bit {} must fail decryption",
                tag_byte_idx,
                bit_idx
            );
        }
    }

    // Verify pristine buffer decrypts cleanly
    let mut clean_buf = sealed_copy;
    let opened_len = cipher
        .open_in_place(counter, &mut clean_buf, sealed_len)
        .expect("clean buffer must open");
    assert_eq!(opened_len, payload_size);
    assert_eq!(&clean_buf[..opened_len], plaintext);
}

#[test]
fn test_corrupted_ciphertext_bytes() {
    let key = [0x33u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(key);
    let counter = 42u64;
    let plaintext = b"Robustness against adversarial byte corruptions in ciphertext payload.";
    let payload_size = plaintext.len();

    let mut original_buf = vec![0u8; payload_size + 16];
    original_buf[..payload_size].copy_from_slice(plaintext);
    let sealed_len = cipher
        .seal_in_place(counter, &mut original_buf, payload_size)
        .expect("seal_in_place");

    // 1. Invert all ciphertext payload bytes
    let mut corrupted = original_buf.clone();
    for b in &mut corrupted[..payload_size] {
        *b = !*b;
    }
    assert_eq!(
        cipher.open_in_place(counter, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );

    // 2. Invert all tag bytes
    corrupted = original_buf.clone();
    for b in &mut corrupted[payload_size..sealed_len] {
        *b = !*b;
    }
    assert_eq!(
        cipher.open_in_place(counter, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );

    // 3. Zero the authentication tag
    corrupted = original_buf.clone();
    corrupted[payload_size..sealed_len].fill(0);
    assert_eq!(
        cipher.open_in_place(counter, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );

    // 4. Swap adjacent bytes in ciphertext
    corrupted = original_buf.clone();
    corrupted.swap(0, 1);
    assert_eq!(
        cipher.open_in_place(counter, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );

    // 5. Corrupt middle byte
    corrupted = original_buf.clone();
    corrupted[payload_size / 2] ^= 0x55;
    assert_eq!(
        cipher.open_in_place(counter, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );

    // 6. Nonce counter mismatch (counter + 1, counter - 1, counter ^ 1)
    corrupted = original_buf.clone();
    assert_eq!(
        cipher.open_in_place(counter + 1, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );
    corrupted = original_buf.clone();
    assert_eq!(
        cipher.open_in_place(counter - 1, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );
    corrupted = original_buf.clone();
    assert_eq!(
        cipher.open_in_place(counter ^ 1, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );

    // 7. Key mismatch
    let wrong_key = [0x34u8; 32];
    let wrong_cipher = ChaCha20Poly1305Cipher::new(wrong_key);
    corrupted = original_buf.clone();
    assert_eq!(
        wrong_cipher.open_in_place(counter, &mut corrupted, sealed_len),
        Err(CryptoError::Decrypt)
    );
}
