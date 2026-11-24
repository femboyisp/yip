//! Post-quantum hybrid Noise handshake state machine.
//!
//! Implements the hybrid post-quantum Noise pattern with:
//! - Diffie-Hellman: X25519 with constant-time low-order point rejection.
//! - KEM: FIPS 203 ML-KEM (ML-KEM-768 default, ML-KEM-1024 high-security, ML-KEM-512 compatible).
//! - AEAD: ChaCha20-Poly1305 with transcript hash binding.
//! - Ratchet: Keyed BLAKE3 extendable-output function (XOF) with 1-byte domain tags.
//!
//! Operates on stack buffers with zero heap allocations during flight 1 / flight 2 processing.

use std::str::FromStr;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::session::{Session, SessionPair};
use crate::symmetric::SymmetricState;
use crate::{pq_decapsulate_to_slice, pq_encapsulate_to_slice, CryptoError};

/// Default protocol identifier string (ML-KEM-768).
pub const PROTOCOL_NAME: &[u8] = b"PQNoise_IKpsk2_25519_MLKEM768_ChaChaPoly_BLAKE3";

/// Protocol identifier string for ML-KEM-768.
pub const PROTOCOL_NAME_MLKEM768: &[u8] = b"PQNoise_IKpsk2_25519_MLKEM768_ChaChaPoly_BLAKE3";

/// Protocol identifier string for ML-KEM-1024.
pub const PROTOCOL_NAME_MLKEM1024: &[u8] = b"PQNoise_IKpsk2_25519_MLKEM1024_ChaChaPoly_BLAKE3";

/// Protocol identifier string for ML-KEM-512.
pub const PROTOCOL_NAME_MLKEM512: &[u8] = b"PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3";

/// Length of the X25519 public key in bytes.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of the Poly1305 authentication tag in bytes.
pub const POLY1305_TAG_LEN: usize = 16;

/// ML-KEM-512 encapsulation key length (FIPS 203).
pub const MLKEM512_ENCAPS_KEY_LEN: usize = 800;
/// ML-KEM-512 ciphertext length (FIPS 203).
pub const MLKEM512_CIPHERTEXT_LEN: usize = 768;
/// ML-KEM-512 expanded decapsulation key length (FIPS 203).
pub const MLKEM512_DECAPS_KEY_LEN: usize = 1632;
/// ML-KEM-512 base flight 1 message length (32 + 48 + 768 + 16 = 864 bytes).
pub const MLKEM512_FLIGHT_1_BASE_LEN: usize = 864;

/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const MLKEM768_ENCAPS_KEY_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 expanded decapsulation key length (FIPS 203).
pub const MLKEM768_DECAPS_KEY_LEN: usize = 2400;
/// ML-KEM-768 base flight 1 message length (32 + 48 + 1088 + 16 = 1184 bytes).
pub const MLKEM768_FLIGHT_1_BASE_LEN: usize = 1184;

/// ML-KEM-1024 encapsulation key length (FIPS 203).
pub const MLKEM1024_ENCAPS_KEY_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length (FIPS 203).
pub const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
/// ML-KEM-1024 expanded decapsulation key length (FIPS 203).
pub const MLKEM1024_DECAPS_KEY_LEN: usize = 3168;
/// ML-KEM-1024 base flight 1 message length (32 + 48 + 1568 + 16 = 1664 bytes).
pub const MLKEM1024_FLIGHT_1_BASE_LEN: usize = 1664;

/// Default minimum/base length of Flight 1 message (zero-length application payload) using ML-KEM-768:
/// 32 bytes (ephemeral e_i) + 48 bytes (encrypted static s_i + tag)
/// + 1088 bytes (ML-KEM-768 ciphertext) + 16 bytes (payload MAC tag) = 1184 bytes.
pub const FLIGHT_1_BASE_LEN: usize = MLKEM768_FLIGHT_1_BASE_LEN;

/// Minimum/base length of Flight 2 message (zero-length application payload):
/// 32 bytes (ephemeral e_r) + 16 bytes (payload MAC tag) = 48 bytes.
pub const FLIGHT_2_BASE_LEN: usize = 48;

/// Supported post-quantum KEM parameter sets (FIPS 203).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PqKemAlgorithm {
    /// ML-KEM-512 (NIST Category 1, AES-128 equivalent).
    MlKem512,
    /// ML-KEM-768 (NIST Category 3, AES-192 equivalent) - default.
    #[default]
    MlKem768,
    /// ML-KEM-1024 (NIST Category 5, AES-256 equivalent).
    MlKem1024,
}

impl PqKemAlgorithm {
    /// Encapsulation key length in bytes.
    pub const fn encaps_key_len(&self) -> usize {
        match self {
            Self::MlKem512 => MLKEM512_ENCAPS_KEY_LEN,
            Self::MlKem768 => MLKEM768_ENCAPS_KEY_LEN,
            Self::MlKem1024 => MLKEM1024_ENCAPS_KEY_LEN,
        }
    }

    /// Ciphertext length in bytes.
    pub const fn ciphertext_len(&self) -> usize {
        match self {
            Self::MlKem512 => MLKEM512_CIPHERTEXT_LEN,
            Self::MlKem768 => MLKEM768_CIPHERTEXT_LEN,
            Self::MlKem1024 => MLKEM1024_CIPHERTEXT_LEN,
        }
    }

    /// Expanded decapsulation key length in bytes.
    pub const fn decaps_key_len(&self) -> usize {
        match self {
            Self::MlKem512 => MLKEM512_DECAPS_KEY_LEN,
            Self::MlKem768 => MLKEM768_DECAPS_KEY_LEN,
            Self::MlKem1024 => MLKEM1024_DECAPS_KEY_LEN,
        }
    }

    /// Base length of Flight 1 message with zero-length payload.
    pub const fn flight_1_base_len(&self) -> usize {
        match self {
            Self::MlKem512 => MLKEM512_FLIGHT_1_BASE_LEN,
            Self::MlKem768 => MLKEM768_FLIGHT_1_BASE_LEN,
            Self::MlKem1024 => MLKEM1024_FLIGHT_1_BASE_LEN,
        }
    }

    /// Byte length of the polynomial vector checked for ByteDecode_12 (384 * k bytes).
    pub const fn bytedecode12_bytes_len(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1152,
            Self::MlKem1024 => 1536,
        }
    }

    /// Protocol identifier string.
    pub const fn protocol_name(&self) -> &'static [u8] {
        match self {
            Self::MlKem512 => PROTOCOL_NAME_MLKEM512,
            Self::MlKem768 => PROTOCOL_NAME_MLKEM768,
            Self::MlKem1024 => PROTOCOL_NAME_MLKEM1024,
        }
    }

    /// BLAKE3 key derivation context string for deterministic seed expansion.
    pub const fn kdf_context(&self) -> &'static str {
        match self {
            Self::MlKem512 => "yip-compat-mlkem512-v1",
            Self::MlKem768 => "yip-compat-mlkem768-v1",
            Self::MlKem1024 => "yip-compat-mlkem1024-v1",
        }
    }

    /// Canonical lowercase string identifier.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MlKem512 => "mlkem512",
            Self::MlKem768 => "mlkem768",
            Self::MlKem1024 => "mlkem1024",
        }
    }
}

impl std::fmt::Display for PqKemAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PqKemAlgorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "mlkem512" => Ok(Self::MlKem512),
            "mlkem768" => Ok(Self::MlKem768),
            "mlkem1024" => Ok(Self::MlKem1024),
            _ => Err(CryptoError::Handshake),
        }
    }
}

/// Execute constant-time X25519 Diffie-Hellman and reject all-zero (low-order) output.
fn constant_time_dh(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let secret = x25519_dalek::StaticSecret::from(*priv_bytes);
    let public = x25519_dalek::PublicKey::from(*pub_bytes);
    let shared = secret.diffie_hellman(&public);
    let mut dh_bytes = *shared.as_bytes();

    if bool::from(dh_bytes.ct_eq(&[0u8; 32])) {
        dh_bytes.zeroize();
        return Err(CryptoError::InvalidKey);
    }
    Ok(dh_bytes)
}

/// ChaCha20-Poly1305 in-place encryption with detached authentication tag.
fn encrypt_and_tag(
    key: &[u8; 32],
    ad: &[u8; 32],
    plaintext_in_out: &mut [u8],
    tag_out: &mut [u8; 16],
) -> Result<(), CryptoError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce = Nonce::from([0u8; 12]);
    let inout = InOutBuf::from(&mut *plaintext_in_out);
    let tag = cipher
        .encrypt_inout_detached(&nonce, ad, inout)
        .map_err(|_| CryptoError::Handshake)?;
    tag_out.copy_from_slice(tag.as_slice());
    Ok(())
}

/// ChaCha20-Poly1305 in-place decryption with detached authentication tag.
fn decrypt_and_verify(
    key: &[u8; 32],
    ad: &[u8; 32],
    ciphertext_in_out: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce = Nonce::from([0u8; 12]);
    let poly_tag = Tag::from(*tag);
    let inout = InOutBuf::from(&mut *ciphertext_in_out);
    cipher
        .decrypt_inout_detached(&nonce, ad, inout, &poly_tag)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(())
}

/// Initiator handshake state progression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitiatorState {
    ReadyToWrite1,
    ReadyToRead2,
    Completed,
    Failed,
}

/// Hybrid post-quantum Noise initiator handshake state machine.
pub struct InitiatorHandshake {
    algorithm: PqKemAlgorithm,
    static_private: [u8; 32],
    static_public: [u8; 32],
    remote_static: [u8; 32],
    remote_pq_ek: [u8; MLKEM1024_ENCAPS_KEY_LEN],
    remote_pq_ek_len: usize,
    psk: [u8; 32],
    symmetric: SymmetricState,
    ephemeral_private: Option<[u8; 32]>,
    flight_1_keys: Option<([u8; 32], [u8; 32], [u8; 32])>,
    state: InitiatorState,
    transport_keys: Option<([u8; 32], [u8; 32])>,
}

impl Drop for InitiatorHandshake {
    fn drop(&mut self) {
        self.abort();
    }
}

impl InitiatorHandshake {
    /// Create a new initiator handshake, inferring the KEM algorithm from `remote_pq_ek.len()`.
    ///
    /// Mixes prologue, responder static public key, and responder ML-KEM encapsulation key.
    pub fn new(
        static_private: &[u8; 32],
        remote_static: &[u8; 32],
        remote_pq_ek: &[u8],
        psk: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        let algo = match remote_pq_ek.len() {
            MLKEM512_ENCAPS_KEY_LEN => PqKemAlgorithm::MlKem512,
            MLKEM768_ENCAPS_KEY_LEN => PqKemAlgorithm::MlKem768,
            MLKEM1024_ENCAPS_KEY_LEN => PqKemAlgorithm::MlKem1024,
            _ => return Err(CryptoError::Handshake),
        };
        Self::new_with_algo(
            algo,
            static_private,
            remote_static,
            remote_pq_ek,
            psk,
            prologue,
        )
    }

    /// Create a new initiator handshake with an explicit KEM algorithm.
    pub fn new_with_algo(
        algo: PqKemAlgorithm,
        static_private: &[u8; 32],
        remote_static: &[u8; 32],
        remote_pq_ek: &[u8],
        psk: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        if remote_pq_ek.len() != algo.encaps_key_len() {
            return Err(CryptoError::Handshake);
        }
        let sec = x25519_dalek::StaticSecret::from(*static_private);
        let static_public = x25519_dalek::PublicKey::from(&sec).to_bytes();

        let mut symmetric = SymmetricState::new(algo.protocol_name());
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(remote_static);
        symmetric.mix_hash(remote_pq_ek);

        let mut ek_buf = [0u8; MLKEM1024_ENCAPS_KEY_LEN];
        ek_buf[..remote_pq_ek.len()].copy_from_slice(remote_pq_ek);

        Ok(Self {
            algorithm: algo,
            static_private: *static_private,
            static_public,
            remote_static: *remote_static,
            remote_pq_ek: ek_buf,
            remote_pq_ek_len: remote_pq_ek.len(),
            psk: *psk,
            symmetric,
            ephemeral_private: None,
            flight_1_keys: None,
            state: InitiatorState::ReadyToWrite1,
            transport_keys: None,
        })
    }

    /// Configured ML-KEM algorithm.
    pub fn algorithm(&self) -> PqKemAlgorithm {
        self.algorithm
    }

    /// Remote ML-KEM encapsulation key slice.
    pub fn remote_pq_ek(&self) -> &[u8] {
        &self.remote_pq_ek[..self.remote_pq_ek_len]
    }

    /// Abort the handshake, zeroizing sensitive state material.
    pub fn abort(&mut self) {
        self.static_private.zeroize();
        self.psk.zeroize();
        self.remote_pq_ek.zeroize();
        if let Some(mut eph) = self.ephemeral_private.take() {
            eph.zeroize();
        }
        if let Some((mut k1, mut k2, mut k3)) = self.flight_1_keys.take() {
            k1.zeroize();
            k2.zeroize();
            k3.zeroize();
        }
        if let Some((mut k1, mut k2)) = self.transport_keys.take() {
            k1.zeroize();
            k2.zeroize();
        }
        self.symmetric.zeroize();
        self.state = InitiatorState::Failed;
    }

    /// Produce Flight 1 handshake message into `out`.
    ///
    /// Output buffer must have capacity for at least `self.algorithm().flight_1_base_len() + payload.len()` bytes.
    pub fn write_message_1(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let rng = SystemRandom::new();
        let mut eph_priv = [0u8; 32];
        if rng.fill(&mut eph_priv).is_err() {
            self.abort();
            return Err(CryptoError::Handshake);
        }
        self.write_message_1_with_ephemeral(payload, out, eph_priv, None)
    }

    /// Produce Flight 1 handshake message using explicit ephemeral private key and optional KEM seed.
    ///
    /// Used for deterministic test vector generation and verification.
    /// Operates entirely on stack buffers with zero heap allocations.
    pub fn write_message_1_with_ephemeral(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        eph_priv: [u8; 32],
        kem_seed: Option<[u8; 32]>,
    ) -> Result<usize, CryptoError> {
        if self.state != InitiatorState::ReadyToWrite1 {
            return Err(CryptoError::Handshake);
        }

        let base_len = self.algorithm.flight_1_base_len();
        let total_len = base_len
            .checked_add(payload.len())
            .ok_or(CryptoError::Handshake)?;
        if out.len() < total_len {
            return Err(CryptoError::Handshake);
        }

        // 1. Process ephemeral keypair e_i
        let mut eph_priv_buf = eph_priv;
        let eph_secret = x25519_dalek::StaticSecret::from(eph_priv_buf);
        let eph_pub = x25519_dalek::PublicKey::from(&eph_secret).to_bytes();

        out[0..32].copy_from_slice(&eph_pub);
        self.symmetric.mix_hash(&eph_pub);

        // 2. es: DH(e_i, rs_x25519)
        let mut dh_es = match constant_time_dh(&eph_priv_buf, &self.remote_static) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv_buf.zeroize();
                self.abort();
                return Err(e);
            }
        };
        let mut k_1 = self.symmetric.mix_key(&dh_es);
        dh_es.zeroize();

        // 3. s: Encrypt s_i.public (32 B) with k_1 (ad = h)
        let mut s_buf = self.static_public;
        let mut s_tag = [0u8; 16];
        if let Err(e) = encrypt_and_tag(&k_1, &self.symmetric.h, &mut s_buf, &mut s_tag) {
            k_1.zeroize();
            eph_priv_buf.zeroize();
            self.abort();
            return Err(e);
        }
        let k_1_copy = k_1;
        k_1.zeroize();
        out[32..64].copy_from_slice(&s_buf);
        out[64..80].copy_from_slice(&s_tag);
        self.symmetric.mix_hash(&out[32..80]);

        // 4. ss: DH(s_i, rs_x25519)
        let mut dh_ss = match constant_time_dh(&self.static_private, &self.remote_static) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv_buf.zeroize();
                self.abort();
                return Err(e);
            }
        };
        let mut k_2 = self.symmetric.mix_key(&dh_ss);
        dh_ss.zeroize();
        let k_2_copy = k_2;
        k_2.zeroize();

        // 5. skem: Encapsulate against rs_mlkem
        let ct_len = self.algorithm.ciphertext_len();
        let ct_start = 80;
        let ct_end = ct_start + ct_len;
        let mut ss_kem = [0u8; 32];
        let encaps_res = match kem_seed {
            Some(m) => pq_encapsulate_to_slice(
                self.algorithm,
                &self.remote_pq_ek[..self.remote_pq_ek_len],
                &m,
                &mut out[ct_start..ct_end],
                &mut ss_kem,
            ),
            None => {
                let rng = SystemRandom::new();
                let mut m = [0u8; 32];
                if rng.fill(&mut m).is_err() {
                    eph_priv_buf.zeroize();
                    self.abort();
                    return Err(CryptoError::Handshake);
                }
                let res = pq_encapsulate_to_slice(
                    self.algorithm,
                    &self.remote_pq_ek[..self.remote_pq_ek_len],
                    &m,
                    &mut out[ct_start..ct_end],
                    &mut ss_kem,
                );
                m.zeroize();
                res
            }
        };
        if let Err(e) = encaps_res {
            eph_priv_buf.zeroize();
            self.abort();
            return Err(e);
        }
        self.symmetric.mix_hash(&out[ct_start..ct_end]);
        let mut k_3 = self.symmetric.mix_key(&ss_kem);
        ss_kem.zeroize();
        let k_3_copy = k_3;

        // 6. payload: Encrypt application payload with k_3 (ad = h)
        let payload_offset = ct_end;
        let payload_end = payload_offset + payload.len();
        let tag_end = payload_end + 16;
        out[payload_offset..payload_end].copy_from_slice(payload);
        let mut payload_tag = [0u8; 16];
        if let Err(e) = encrypt_and_tag(
            &k_3,
            &self.symmetric.h,
            &mut out[payload_offset..payload_end],
            &mut payload_tag,
        ) {
            k_3.zeroize();
            eph_priv_buf.zeroize();
            self.abort();
            return Err(e);
        }
        k_3.zeroize();
        out[payload_end..tag_end].copy_from_slice(&payload_tag);
        self.symmetric.mix_hash(&out[payload_offset..tag_end]);

        self.flight_1_keys = Some((k_1_copy, k_2_copy, k_3_copy));
        self.ephemeral_private = Some(eph_priv_buf);
        self.state = InitiatorState::ReadyToRead2;
        Ok(total_len)
    }

    /// Consume Flight 2 handshake message from Responder, writing the decrypted payload into `payload_out`.
    ///
    /// Returns the number of decrypted payload bytes.
    pub fn read_message_2(
        &mut self,
        msg: &[u8],
        payload_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.state != InitiatorState::ReadyToRead2 {
            return Err(CryptoError::Handshake);
        }

        if msg.len() < FLIGHT_2_BASE_LEN {
            self.abort();
            return Err(CryptoError::Handshake);
        }

        let mut eph_priv = match self.ephemeral_private.take() {
            Some(p) => p,
            None => {
                self.abort();
                return Err(CryptoError::Handshake);
            }
        };

        // 1. Parse ephemeral e_r (32 B)
        let mut e_r = [0u8; 32];
        e_r.copy_from_slice(&msg[0..32]);
        self.symmetric.mix_hash(&e_r);

        // 2. ee: DH(e_i, e_r)
        let mut dh_ee = match constant_time_dh(&eph_priv, &e_r) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv.zeroize();
                self.abort();
                return Err(e);
            }
        };
        eph_priv.zeroize();
        let mut k_4 = self.symmetric.mix_key(&dh_ee);
        dh_ee.zeroize();
        k_4.zeroize();

        // 3. se: DH(s_i, e_r)
        let mut dh_se = match constant_time_dh(&self.static_private, &e_r) {
            Ok(dh) => dh,
            Err(e) => {
                self.abort();
                return Err(e);
            }
        };
        let mut k_5 = self.symmetric.mix_key(&dh_se);
        dh_se.zeroize();
        k_5.zeroize();

        // 4. psk: mix_key_and_hash(&psk)
        let mut k_6 = self.symmetric.mix_key_and_hash(&self.psk);

        // 5. payload: Decrypt application payload with k_6 (ad = h)
        let payload_len = msg.len() - FLIGHT_2_BASE_LEN;
        if payload_out.len() < payload_len {
            k_6.zeroize();
            self.abort();
            return Err(CryptoError::Handshake);
        }

        let payload_offset = 32;
        let payload_end = payload_offset + payload_len;
        let tag_end = payload_end + 16;

        payload_out[..payload_len].copy_from_slice(&msg[payload_offset..payload_end]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&msg[payload_end..tag_end]);

        if let Err(e) = decrypt_and_verify(
            &k_6,
            &self.symmetric.h,
            &mut payload_out[..payload_len],
            &tag,
        ) {
            k_6.zeroize();
            payload_out[..payload_len].zeroize();
            self.abort();
            return Err(e);
        }
        k_6.zeroize();
        self.symmetric.mix_hash(&msg[payload_offset..tag_end]);

        // 6. Split transport keys
        let (k_send, k_recv) = self.symmetric.split();
        self.transport_keys = Some((k_send, k_recv));
        self.state = InitiatorState::Completed;
        Ok(payload_len)
    }

    /// Extract symmetric split keys `(k1, k2)` identical on both peers.
    pub fn split(&self) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        self.transport_keys.ok_or(CryptoError::Handshake)
    }

    /// Extract directional transport keys `(k_send, k_recv)` for the initiator.
    pub fn transport_keys(&self) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        self.transport_keys.ok_or(CryptoError::Handshake)
    }

    /// Handshake hash for channel binding.
    pub fn channel_binding(&self) -> [u8; 32] {
        self.symmetric.h
    }

    /// Local static public key.
    pub fn local_static(&self) -> [u8; 32] {
        self.static_public
    }

    /// Remote static public key.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        Some(self.remote_static)
    }

    /// Returns whether the handshake has completed and transport keys are ready.
    pub fn is_finished(&self) -> bool {
        self.state == InitiatorState::Completed
    }

    /// Access intermediate flight 1 cipher keys (k1, k2, k3) if flight 1 has been written.
    pub fn flight_1_keys(&self) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
        self.flight_1_keys
    }

    /// Access the underlying symmetric state machine.
    pub fn symmetric_state(&self) -> &SymmetricState {
        &self.symmetric
    }

    /// Convert completed handshake into an established [`SessionPair`].
    pub fn into_session_pair(self) -> Result<SessionPair, CryptoError> {
        let (mut k_send, mut k_recv) = self.transport_keys()?;
        let pair = SessionPair::from_raw_keys(&k_send, &k_recv);
        k_send.zeroize();
        k_recv.zeroize();
        Ok(pair)
    }

    /// Convert completed handshake into an AEAD [`Session`].
    pub fn into_session(self) -> Result<Session, CryptoError> {
        let pair = self.into_session_pair()?;
        Ok(pair.into_session(0, 1))
    }
}

/// Responder handshake state progression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponderState {
    ReadyToRead1,
    ReadyToWrite2,
    Completed,
    Failed,
}

/// Hybrid post-quantum Noise responder handshake state machine.
pub struct ResponderHandshake {
    algorithm: PqKemAlgorithm,
    static_private: [u8; 32],
    static_public: [u8; 32],
    local_pq_ek: [u8; MLKEM1024_ENCAPS_KEY_LEN],
    local_pq_ek_len: usize,
    psk: [u8; 32],
    symmetric: SymmetricState,
    remote_static: Option<[u8; 32]>,
    remote_ephemeral: Option<[u8; 32]>,
    state: ResponderState,
    transport_keys: Option<([u8; 32], [u8; 32])>,
}

impl Drop for ResponderHandshake {
    fn drop(&mut self) {
        self.abort();
    }
}

impl ResponderHandshake {
    /// Create a new responder handshake, inferring the KEM algorithm from `local_pq_ek.len()`.
    ///
    /// Mixes prologue, responder static public key, and responder ML-KEM encapsulation key.
    pub fn new(
        static_private: &[u8; 32],
        local_pq_ek: &[u8],
        psk: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        let algo = match local_pq_ek.len() {
            MLKEM512_ENCAPS_KEY_LEN => PqKemAlgorithm::MlKem512,
            MLKEM768_ENCAPS_KEY_LEN => PqKemAlgorithm::MlKem768,
            MLKEM1024_ENCAPS_KEY_LEN => PqKemAlgorithm::MlKem1024,
            _ => return Err(CryptoError::Handshake),
        };
        Self::new_with_algo(algo, static_private, local_pq_ek, psk, prologue)
    }

    /// Create a new responder handshake with an explicit KEM algorithm.
    pub fn new_with_algo(
        algo: PqKemAlgorithm,
        static_private: &[u8; 32],
        local_pq_ek: &[u8],
        psk: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        if local_pq_ek.len() != algo.encaps_key_len() {
            return Err(CryptoError::Handshake);
        }
        let sec = x25519_dalek::StaticSecret::from(*static_private);
        let static_public = x25519_dalek::PublicKey::from(&sec).to_bytes();

        let mut symmetric = SymmetricState::new(algo.protocol_name());
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(&static_public);
        symmetric.mix_hash(local_pq_ek);

        let mut ek_buf = [0u8; MLKEM1024_ENCAPS_KEY_LEN];
        ek_buf[..local_pq_ek.len()].copy_from_slice(local_pq_ek);

        Ok(Self {
            algorithm: algo,
            static_private: *static_private,
            static_public,
            local_pq_ek: ek_buf,
            local_pq_ek_len: local_pq_ek.len(),
            psk: *psk,
            symmetric,
            remote_static: None,
            remote_ephemeral: None,
            state: ResponderState::ReadyToRead1,
            transport_keys: None,
        })
    }

    /// Configured ML-KEM algorithm.
    pub fn algorithm(&self) -> PqKemAlgorithm {
        self.algorithm
    }

    /// Abort the handshake, zeroizing sensitive state material.
    pub fn abort(&mut self) {
        self.static_private.zeroize();
        self.psk.zeroize();
        self.local_pq_ek.zeroize();
        if let Some(mut eph) = self.remote_ephemeral.take() {
            eph.zeroize();
        }
        if let Some((mut k1, mut k2)) = self.transport_keys.take() {
            k1.zeroize();
            k2.zeroize();
        }
        self.symmetric.zeroize();
        self.remote_static = None;
        self.state = ResponderState::Failed;
    }

    /// Consume Flight 1 handshake message from Initiator using ML-KEM decapsulation key `dk`.
    ///
    /// Decrypts static public key and application payload into `payload_out`.
    /// Operates entirely on stack buffers with zero heap allocations.
    pub fn read_message_1(
        &mut self,
        msg: &[u8],
        dk: &[u8],
        payload_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.state != ResponderState::ReadyToRead1 {
            return Err(CryptoError::Handshake);
        }

        let base_len = self.algorithm.flight_1_base_len();
        if msg.len() < base_len {
            self.abort();
            return Err(CryptoError::Handshake);
        }

        if dk.len() != self.algorithm.decaps_key_len() {
            self.abort();
            return Err(CryptoError::Handshake);
        }

        // 1. Parse ephemeral e_i (32 B)
        let mut e_i = [0u8; 32];
        e_i.copy_from_slice(&msg[0..32]);
        self.symmetric.mix_hash(&e_i);

        // 2. es: DH(s_r, e_i)
        let mut dh_es = match constant_time_dh(&self.static_private, &e_i) {
            Ok(dh) => dh,
            Err(e) => {
                self.abort();
                return Err(e);
            }
        };
        let mut k_1 = self.symmetric.mix_key(&dh_es);
        dh_es.zeroize();

        // 3. s: Decrypt s_i.public (32 B) with k_1 (ad = h)
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&msg[32..64]);
        let mut s_tag = [0u8; 16];
        s_tag.copy_from_slice(&msg[64..80]);

        if let Err(e) = decrypt_and_verify(&k_1, &self.symmetric.h, &mut s_buf, &s_tag) {
            k_1.zeroize();
            self.abort();
            return Err(e);
        }
        k_1.zeroize();
        self.symmetric.mix_hash(&msg[32..80]);
        let s_i = s_buf;

        // 4. ss: DH(s_r, s_i)
        let mut dh_ss = match constant_time_dh(&self.static_private, &s_i) {
            Ok(dh) => dh,
            Err(e) => {
                self.abort();
                return Err(e);
            }
        };
        let mut k_2 = self.symmetric.mix_key(&dh_ss);
        dh_ss.zeroize();
        k_2.zeroize();

        // 5. skem: Decapsulate ML-KEM ciphertext
        let ct_len = self.algorithm.ciphertext_len();
        let ct_start = 80;
        let ct_end = ct_start + ct_len;
        let ct_bytes = &msg[ct_start..ct_end];

        let mut ss_kem = [0u8; 32];
        if let Err(e) = pq_decapsulate_to_slice(self.algorithm, dk, ct_bytes, &mut ss_kem) {
            self.abort();
            return Err(e);
        }
        self.symmetric.mix_hash(ct_bytes);

        let mut k_3 = self.symmetric.mix_key(&ss_kem);
        ss_kem.zeroize();

        // 6. payload: Decrypt application payload with k_3 (ad = h)
        let payload_len = msg.len() - base_len;
        if payload_out.len() < payload_len {
            k_3.zeroize();
            self.abort();
            return Err(CryptoError::Handshake);
        }

        let payload_offset = ct_end;
        let payload_end = payload_offset + payload_len;
        let tag_end = payload_end + 16;

        payload_out[..payload_len].copy_from_slice(&msg[payload_offset..payload_end]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&msg[payload_end..tag_end]);

        if let Err(e) = decrypt_and_verify(
            &k_3,
            &self.symmetric.h,
            &mut payload_out[..payload_len],
            &tag,
        ) {
            k_3.zeroize();
            payload_out[..payload_len].zeroize();
            self.abort();
            return Err(e);
        }
        k_3.zeroize();
        self.symmetric.mix_hash(&msg[payload_offset..tag_end]);

        self.remote_static = Some(s_i);
        self.remote_ephemeral = Some(e_i);
        self.state = ResponderState::ReadyToWrite2;
        Ok(payload_len)
    }

    /// Produce Flight 2 handshake message into `out`.
    ///
    /// Output buffer must have capacity for at least `FLIGHT_2_BASE_LEN + payload.len()` bytes.
    /// Returns the number of bytes written (`48 + payload.len()`).
    pub fn write_message_2(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let rng = SystemRandom::new();
        let mut eph_priv = [0u8; 32];
        if rng.fill(&mut eph_priv).is_err() {
            self.abort();
            return Err(CryptoError::Handshake);
        }
        self.write_message_2_with_ephemeral(payload, out, eph_priv)
    }

    /// Produce Flight 2 handshake message into `out` with an explicit ephemeral private key.
    ///
    /// Used for deterministic test vector generation and verification.
    /// Operates entirely on stack buffers with zero heap allocations.
    pub fn write_message_2_with_ephemeral(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        eph_priv: [u8; 32],
    ) -> Result<usize, CryptoError> {
        if self.state != ResponderState::ReadyToWrite2 {
            return Err(CryptoError::Handshake);
        }

        let total_len = FLIGHT_2_BASE_LEN
            .checked_add(payload.len())
            .ok_or(CryptoError::Handshake)?;
        if out.len() < total_len {
            return Err(CryptoError::Handshake);
        }

        let e_i = match self.remote_ephemeral.take() {
            Some(e) => e,
            None => {
                self.abort();
                return Err(CryptoError::Handshake);
            }
        };

        let remote_static = match self.remote_static {
            Some(s) => s,
            None => {
                self.abort();
                return Err(CryptoError::Handshake);
            }
        };

        // 1. Process ephemeral keypair e_r
        let mut eph_priv_buf = eph_priv;
        let eph_secret = x25519_dalek::StaticSecret::from(eph_priv_buf);
        let eph_pub = x25519_dalek::PublicKey::from(&eph_secret).to_bytes();

        out[0..32].copy_from_slice(&eph_pub);
        self.symmetric.mix_hash(&eph_pub);

        // 2. ee: DH(e_r, e_i)
        let mut dh_ee = match constant_time_dh(&eph_priv_buf, &e_i) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv_buf.zeroize();
                self.abort();
                return Err(e);
            }
        };
        let mut k_4 = self.symmetric.mix_key(&dh_ee);
        dh_ee.zeroize();
        k_4.zeroize();

        // 3. se: DH(e_r, s_i)
        let mut dh_se = match constant_time_dh(&eph_priv_buf, &remote_static) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv_buf.zeroize();
                self.abort();
                return Err(e);
            }
        };
        eph_priv_buf.zeroize();
        let mut k_5 = self.symmetric.mix_key(&dh_se);
        dh_se.zeroize();
        k_5.zeroize();

        // 4. psk: mix_key_and_hash(&psk)
        let mut k_6 = self.symmetric.mix_key_and_hash(&self.psk);

        // 5. payload: Encrypt application payload with k_6 (ad = h)
        let payload_offset = 32;
        let payload_end = payload_offset + payload.len();
        let tag_end = payload_end + 16;
        out[payload_offset..payload_end].copy_from_slice(payload);
        let mut payload_tag = [0u8; 16];
        if let Err(e) = encrypt_and_tag(
            &k_6,
            &self.symmetric.h,
            &mut out[payload_offset..payload_end],
            &mut payload_tag,
        ) {
            k_6.zeroize();
            self.abort();
            return Err(e);
        }
        k_6.zeroize();
        out[payload_end..tag_end].copy_from_slice(&payload_tag);
        self.symmetric.mix_hash(&out[payload_offset..tag_end]);

        // 6. Split transport keys
        let (k_send, k_recv) = self.symmetric.split();
        self.transport_keys = Some((k_send, k_recv));
        self.state = ResponderState::Completed;
        Ok(total_len)
    }

    /// Extract symmetric split keys `(k1, k2)` identical on both peers.
    pub fn split(&self) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        self.transport_keys.ok_or(CryptoError::Handshake)
    }

    /// Extract directional transport keys `(k_send, k_recv)` for the responder.
    ///
    /// For the responder, element 0 is the send key (responder-to-initiator)
    /// and element 1 is the receive key (initiator-to-responder).
    pub fn transport_keys(&self) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let (k1, k2) = self.transport_keys.ok_or(CryptoError::Handshake)?;
        Ok((k2, k1))
    }

    /// Handshake hash for channel binding.
    pub fn channel_binding(&self) -> [u8; 32] {
        self.symmetric.h
    }

    /// Local static public key.
    pub fn local_static(&self) -> [u8; 32] {
        self.static_public
    }

    /// Local ML-KEM encapsulation key bytes.
    pub fn local_pq_ek(&self) -> &[u8] {
        &self.local_pq_ek[..self.local_pq_ek_len]
    }

    /// Authenticated remote static public key learned from Flight 1.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.remote_static
    }

    /// Returns whether the handshake has completed and transport keys are ready.
    pub fn is_finished(&self) -> bool {
        self.state == ResponderState::Completed
    }

    /// Access the underlying symmetric state machine.
    pub fn symmetric_state(&self) -> &SymmetricState {
        &self.symmetric
    }

    /// Convert completed handshake into an established [`SessionPair`].
    pub fn into_session_pair(self) -> Result<SessionPair, CryptoError> {
        let (mut k_send, mut k_recv) = self.transport_keys()?;
        let pair = SessionPair::from_raw_keys(&k_send, &k_recv);
        k_send.zeroize();
        k_recv.zeroize();
        Ok(pair)
    }

    /// Convert completed handshake into an AEAD [`Session`].
    pub fn into_session(self) -> Result<Session, CryptoError> {
        let pair = self.into_session_pair()?;
        Ok(pair.into_session(0, 1))
    }
}
