//! Project Wycheproof test vectors for X25519 (RFC 7748).
//!
//! Validates:
//! - Valid Diffie-Hellman vectors (normal KATs, edge case scalar multiplications, twist points).
//! - Low-order points:
//!   - Order 1: 0x00...00, 0x00...80, and p = 2^255-19 coordinates.
//!   - Order 2: 0x01...00, 0xe0eb..., and p+1 = 2^255-18 coordinates.
//!   - Order 4: 0x5f9c... and p-1 = 2^255-20 coordinates.
//!   - Order 8: 0x00...00 with high bit variations and 8-torsion points.
//! - Non-canonical coordinate values (u >= 2^255 - 19, e.g. 2^255 - 18, 2^255 - 1, 2^256 - 1).
//! - Verification that x25519_dalek produces non-contributory outputs (all-zero) or canonical points as expected by RFC 7748 and Wycheproof.
//! - Verification that yip-crypto handshake machines reject low-order points with CryptoError::InvalidKey.
#![forbid(unsafe_code)]

use x25519_dalek::{PublicKey, StaticSecret};
use yip_crypto::handshake::{InitiatorHandshake, ResponderHandshake};
use yip_crypto::{generate_keypair, generate_pq_keypair, CryptoError};

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let mut arr = [0u8; 32];
    for (i, chunk) in (0..hex_str.len()).step_by(2).enumerate() {
        arr[i] = u8::from_str_radix(&hex_str[chunk..chunk + 2], 16).expect("valid hex");
    }
    arr
}

struct X25519TestVector {
    tc_id: u32,
    public: &'static str,
    private: &'static str,
    shared: &'static str,
    comment: &'static str,
}

static VALID_DIFFIE_HELLMAN_VECTORS: &[X25519TestVector] = &[
    X25519TestVector {
        tc_id: 1,
        public: "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
        private: "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
        shared: "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320",
        comment: "normal case",
    },
    X25519TestVector {
        tc_id: 2,
        public: "63aa40c6e38346c5caf23a6df0a5e6c80889a08647e551b3563449befcfc9733",
        private: "d85d8c061a50804ac488ad774ac716c3f5ba714b2712e048491379a500211958",
        shared: "279df67a7c4611db4708a0e8282b195e5ac0ed6f4b2f292c6fbd0acac30d1332",
        comment: "public key on twist",
    },
    X25519TestVector {
        tc_id: 3,
        public: "0f83c36fded9d32fadf4efa3ae93a90bb5cfa66893bc412c43fa7287dbb99779",
        private: "c8b45bfd32e55325d9fd648cb302848039000b390e44d521e58aab3b29a6964b",
        shared: "4bc7e01e7d83d6cf67632bf90033487a5fc29eba5328890ea7b1026d23b9a45f",
        comment: "public key on twist",
    },
    X25519TestVector {
        tc_id: 4,
        public: "0b8211a2b6049097f6871c6c052d3c5fc1ba17da9e32ae458403b05bb283092a",
        private: "f876e34bcbe1f47fbc0fddfd7c1e1aa53d57bfe0f66d243067b424bb6210be51",
        shared: "119d37ed4b109cbd6418b1f28dea83c836c844715cdf98a3a8c362191debd514",
        comment: "public key on twist",
    },
    X25519TestVector {
        tc_id: 8,
        public: "0300000000000000000000000000000000000000000000000000000000000000",
        private: "e09d57a914e3c29036fd9a442ba526b5cdcdf28216153e636c10677acab6bd6a",
        shared: "a29d8dad28d590cd3017aa97a4761f851bf1d3672b042a4256a45881e2ad9035",
        comment: "public key on twist",
    },
    X25519TestVector {
        tc_id: 12,
        public: "ffffff0f00000000000000000000000000000000000000000000000000000000",
        private: "d0d31c491cbd39271859b4a63a316826507b1db8c701709fd0ffe3eb21c4467c",
        shared: "9f8954868158ec62b6b586b8cae1d67d1b9f4c03d5b3ca0393cee71accc9ab65",
        comment: "public key on twist",
    },
    X25519TestVector {
        tc_id: 16,
        public: "ffffffffffffffff000000000000000000000000000000000000000000000000",
        private: "68964bca51465bf0f5ba524b1482ceff0e960a1ed9f48dcc30f1608d0e501a50",
        shared: "25ff9a6631b143dbdbdc207b38e38f832ae079a52a618c534322e77345fd9049",
        comment: "public key on twist",
    },
    X25519TestVector {
        tc_id: 20,
        public: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000",
        private: "d88a441e706f606ae7f630f8b21f3c2554739e3e549f804118c03771f608017b",
        shared: "ff1b509a0a1a54726086f1e1c0acf040ab463a2a542e5d54e92c6df8126cf636",
        comment: "public key on twist",
    },
];

static LOW_ORDER_VECTORS: &[X25519TestVector] = &[
    X25519TestVector {
        tc_id: 32,
        public: "0000000000000000000000000000000000000000000000000000000000000000",
        private: "88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key = 0 (SmallPublicKey, LowOrderPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 33,
        public: "0100000000000000000000000000000000000000000000000000000000000000",
        private: "48232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e48184f",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key = 1 (SmallPublicKey, LowOrderPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 63,
        public: "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        private: "e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 64,
        public: "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        private: "387355d995616090503aafad49da01fb3dc3eda962704eaee6b86f9e20c92579",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 65,
        public: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "c8fe0df92ae68a03023fc0c9adb9557d31be7feed0d3ab36c558143daf4dbb40",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, Twist, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 66,
        public: "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        private: "c8d74acde5934e64b9895d5ff7afbffd7f704f7dfccff7ac28fa62a1e6410347",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, NonCanonicalPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 67,
        public: "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        private: "b85649d5120e01e8ccaf7b2fb8d81b62e8ad6f3d5c0553fdde1906cb9d79c050",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, NonCanonicalPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 68,
        public: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "2064b2f4c9dc97ec7cf58932fdfa3265ba6ea4d11f0259b8efc8afb35db88c48",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, NonCanonicalPublic, SpecialPublicKey, ZeroSharedSecret, Twist)",
    },
    X25519TestVector {
        tc_id: 69,
        public: "0000000000000000000000000000000000000000000000000000000000000000",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 70,
        public: "0100000000000000000000000000000000000000000000000000000000000000",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 71,
        public: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret, Twist)",
    },
    X25519TestVector {
        tc_id: 72,
        public: "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 73,
        public: "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 74,
        public: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 75,
        public: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 76,
        public: "0000000000000000000000000000000000000000000000000000000000000080",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 77,
        public: "0100000000000000000000000000000000000000000000000000000000000080",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 78,
        public: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret, Twist)",
    },
    X25519TestVector {
        tc_id: 79,
        public: "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 80,
        public: "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 81,
        public: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 82,
        public: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key with low order (LowOrderPublic, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 83,
        public: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "40ff586e73d61f0960dc2d763ac19e98225f1194f6fe43d5dd97ad55b3d35961",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key == 0 (SmallPublicKey, LowOrderPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 84,
        public: "0000000000000000000000000000000000000000000000000000000000000080",
        private: "7887889bac4c629a101d3724f2ed8b98d936fde79e1a1f77d86779626bf8f263",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key == 0 (SmallPublicKey, LowOrderPublic, NonCanonicalPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 85,
        public: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "584fceaebae944bfe93b2e0d0a575f706ce5ada1da2b1311c3b421f9186c7a6f",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key == 1 (SmallPublicKey, LowOrderPublic, NonCanonicalPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
    X25519TestVector {
        tc_id: 86,
        public: "0100000000000000000000000000000000000000000000000000000000000080",
        private: "e07971ee820e48b0b266d8be3cdbbb5e900a43f59ee8535c6572418615de4962",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        comment: "public key == 1 (SmallPublicKey, LowOrderPublic, NonCanonicalPublic, SpecialPublicKey, ZeroSharedSecret)",
    },
];

static NON_CANONICAL_VECTORS: &[X25519TestVector] = &[
    X25519TestVector {
        tc_id: 87,
        public: "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "0016b62af5cabde8c40938ebf2108e05d27fa0533ed85d70015ad4ad39762d54",
        shared: "b4d10e832714972f96bd3382e4d082a21a8333a16315b3ffb536061d2482360d",
        comment: "non-canonical public key (NonCanonicalPublic, Twist, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 88,
        public: "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "d83650ba7cec115881916255e3fa5fa0d6b8dcf968731bd2c9d2aec3f561f649",
        shared: "515eac8f1ed0b00c70762322c3ef86716cd2c51fe77cec3d31b6388bc6eea336",
        comment: "non-canonical public key (NonCanonicalPublic, Twist, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 89,
        public: "f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "88dd14e2711ebd0b0026c651264ca965e7e3da5082789fbab7e24425e7b4377e",
        shared: "6919992d6a591e77b3f2bacbd74caf3aea4be4802b18b2bc07eb09ade3ad6662",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 90,
        public: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        private: "98c2b08cbac14e15953154e3b558d42bb1268a365b0ef2f22725129d8ac5cb7f",
        shared: "9c034fcd8d3bf69964958c0105161fcb5d1ea5b8f8abb371491e42a7684c2322",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 91,
        public: "0200000000000000000000000000000000000000000000000000000000000080",
        private: "c0697b6f05e0f3433b44ea352f20508eb0623098a7770853af5ca09727340c4e",
        shared: "ed18b06da512cab63f22d2d51d77d99facd3c4502e4abf4e97b094c20a9ddf10",
        comment: "non-canonical public key (NonCanonicalPublic, Twist, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 92,
        public: "0300000000000000000000000000000000000000000000000000000000000080",
        private: "18422b58a18e0f4519b7a887b8cfb649e0bfe4b34d75963350a9944e5b7f5b7e",
        shared: "448ce410fffc7e6149c5abec0ad5f3607dfde8a34e2ac3243c3009176168b432",
        comment: "non-canonical public key (NonCanonicalPublic, Twist, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 93,
        public: "0400000000000000000000000000000000000000000000000000000000000080",
        private: "20620d82487707bedf9ee3549e95cb9390d2618f50cf6acba47ffaa103224a6f",
        shared: "03a633df01480d0d5048d92f51b20dc1d11f73e9515c699429b90a4f6903122a",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 94,
        public: "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "285a6a7ceeb7122f2c78d99c53b2a902b490892f7dff326f89d12673c3101b53",
        shared: "9b01287717d72f4cfb583ec85f8f936849b17d978dbae7b837db56a62f100a68",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 95,
        public: "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "c8e0330ae9dceeff887fba761225879a4bd2e0db08799244136e4721b2c88970",
        shared: "dfe60831c9f4f96c816e51048804dbdc27795d760eced75ef575cbe3b464054b",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey, Twist)",
    },
    X25519TestVector {
        tc_id: 96,
        public: "dcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "10db6210fc1fb13382472fa1787b004b5d11868ab3a79510e0cee30f4a6df26b",
        shared: "50bfa826ca77036dd2bbfd092c3f78e2e4a1f980d7c8e78f2f14dca3cce5cc3c",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 97,
        public: "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "9041c6e044a277df8466275ca8b5ee0da7bc028648054ade5c592add3057474e",
        shared: "13da5695a4c206115409b5277a934782fe985fa050bc902cba5616f9156fe277",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey, Twist)",
    },
    X25519TestVector {
        tc_id: 98,
        public: "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "b8d499041a6713c0f6f876db7406587fdb44582f9542356ae89cfa958a34d266",
        shared: "63483b5d69236c63cddbed33d8e22baecc2b0ccf886598e863c844d2bf256704",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey)",
    },
    X25519TestVector {
        tc_id: 99,
        public: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        private: "c85f08e60c845f82099141a66dc4583d2b1040462c544d33d0453b20b1a6377e",
        shared: "e9db74bc88d0d9bf046ddd13f943bccbe6dbb47d49323f8dfeedc4a694991a3c",
        comment: "non-canonical public key (NonCanonicalPublic, SpecialPublicKey)",
    },
];

#[test]
fn test_wycheproof_valid_diffie_hellman_vectors() {
    for vec in VALID_DIFFIE_HELLMAN_VECTORS {
        let priv_bytes = hex_to_32(vec.private);
        let pub_bytes = hex_to_32(vec.public);
        let expected_shared = hex_to_32(vec.shared);

        let secret = StaticSecret::from(priv_bytes);
        let public = PublicKey::from(pub_bytes);
        let shared = secret.diffie_hellman(&public);

        assert_eq!(
            shared.as_bytes(),
            &expected_shared,
            "DH output mismatch on valid vector tcId {} ({})",
            vec.tc_id,
            vec.comment
        );
    }
}

#[test]
fn test_wycheproof_low_order_points_produce_non_contributory_output() {
    for vec in LOW_ORDER_VECTORS {
        let priv_bytes = hex_to_32(vec.private);
        let pub_bytes = hex_to_32(vec.public);
        let expected_shared = hex_to_32(vec.shared);

        // Wycheproof asserts that all low-order public keys produce an all-zero shared secret
        assert_eq!(
            expected_shared, [0u8; 32],
            "expected shared secret must be all-zero for low order point tcId {}",
            vec.tc_id
        );

        let secret = StaticSecret::from(priv_bytes);
        let public = PublicKey::from(pub_bytes);
        let shared = secret.diffie_hellman(&public);

        assert_eq!(
            shared.as_bytes(),
            &[0u8; 32],
            "x25519_dalek must produce non-contributory (all-zero) output on low order point tcId {} ({})",
            vec.tc_id,
            vec.comment
        );
    }
}

#[test]
fn test_wycheproof_low_order_points_by_order_group() {
    // Specific representative points by exact subgroup order
    // Order 1: 0x00...00 and high-bit variation 0x00...80, and p = 2^255 - 19
    let order_1_points: &[[u8; 32]] = &[
        hex_to_32("0000000000000000000000000000000000000000000000000000000000000000"),
        hex_to_32("0000000000000000000000000000000000000000000000000000000000000080"),
        hex_to_32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex_to_32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];

    // Order 2: 0x01...00, 0xe0eb..., and p + 1 = 2^255 - 18
    let order_2_points: &[[u8; 32]] = &[
        hex_to_32("0100000000000000000000000000000000000000000000000000000000000000"),
        hex_to_32("0100000000000000000000000000000000000000000000000000000000000080"),
        hex_to_32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex_to_32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"),
        hex_to_32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex_to_32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];

    // Order 4: 0x5f9c... and p - 1 = 2^255 - 20
    let order_4_points: &[[u8; 32]] = &[
        hex_to_32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex_to_32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"),
        hex_to_32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex_to_32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];

    let priv_key = hex_to_32("c8a9d5a91091ad851c6687b379427ee01916b41a785d13de1d986b687c3cd2e0");
    let secret = StaticSecret::from(priv_key);

    for (group_name, points) in [
        ("Order 1", order_1_points),
        ("Order 2", order_2_points),
        ("Order 4", order_4_points),
    ] {
        for (idx, pt) in points.iter().enumerate() {
            let public = PublicKey::from(*pt);
            let shared = secret.diffie_hellman(&public);
            assert_eq!(
                shared.as_bytes(),
                &[0u8; 32],
                "{} point #{} must produce non-contributory (all-zero) shared secret",
                group_name,
                idx
            );
        }
    }
}

#[test]
fn test_wycheproof_non_canonical_coordinates() {
    for vec in NON_CANONICAL_VECTORS {
        let priv_bytes = hex_to_32(vec.private);
        let pub_bytes = hex_to_32(vec.public);
        let expected_shared = hex_to_32(vec.shared);

        let secret = StaticSecret::from(priv_bytes);
        let public = PublicKey::from(pub_bytes);
        let shared = secret.diffie_hellman(&public);

        assert_eq!(
            shared.as_bytes(),
            &expected_shared,
            "x25519_dalek must produce canonical point on non-canonical coordinate tcId {} ({})",
            vec.tc_id,
            vec.comment
        );
    }
}

#[test]
fn test_handshake_rejects_low_order_points() {
    let initiator_static = generate_keypair();
    let (responder_pq_ek, _responder_pq_dk) = generate_pq_keypair();
    let psk = [0x55u8; 32];

    // Check all low order points when used as responder public key in InitiatorHandshake
    for vec in LOW_ORDER_VECTORS {
        let low_order_public = hex_to_32(vec.public);

        let mut initiator = InitiatorHandshake::new(
            &initiator_static.private,
            &low_order_public,
            &responder_pq_ek.0,
            &psk,
            &[],
        )
        .expect("initiator creation");

        let mut msg1 = [0u8; 1024];
        let res = initiator.write_message_1(&[], &mut msg1);
        assert_eq!(
            res,
            Err(CryptoError::InvalidKey),
            "InitiatorHandshake must reject low-order public key tcId {} ({})",
            vec.tc_id,
            vec.comment
        );
    }
}

#[test]
fn test_responder_rejects_low_order_ephemeral_points() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    // Create a valid flight 1 message
    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator creation");

    let mut valid_msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(&[], &mut valid_msg1)
        .expect("write_message_1");

    // Replace ephemeral public key (bytes 0..32 of flight 1) with each low-order point
    for vec in LOW_ORDER_VECTORS {
        let low_order_point = hex_to_32(vec.public);
        let mut tampered_msg1 = valid_msg1[..n1].to_vec();
        tampered_msg1[..32].copy_from_slice(&low_order_point);

        let mut responder =
            ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
                .expect("responder creation");

        let mut payload1_out = [0u8; 64];
        let res = responder.read_message_1(&tampered_msg1, &responder_dk_bytes, &mut payload1_out);

        // When ephemeral key is replaced with low-order point, DH computation rejects it
        // either via InvalidKey (all-zero DH) or Decrypt/Handshake (auth failure)
        assert!(
            res.is_err(),
            "ResponderHandshake must reject tampered low-order ephemeral point tcId {}",
            vec.tc_id
        );
    }
}
