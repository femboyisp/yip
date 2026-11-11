//! Post-quantum hybrid Noise handshake state machine (`PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3`).
//!
//! Implements the hybrid post-quantum Noise pattern with:
//! - Diffie-Hellman: X25519 with constant-time low-order point rejection.
//! - KEM: ML-KEM-512 (FIPS 203) encapsulation and decapsulation.
//! - AEAD: ChaCha20-Poly1305 with transcript hash binding.
//! - Ratchet: Keyed BLAKE3 extendable-output function (XOF) with 1-byte domain tags.
//!
//! Operates on stack buffers with zero heap allocations during the handshake.

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use ml_kem::kem::Decapsulate;
use ml_kem::ml_kem_512;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::symmetric::SymmetricState;
use crate::{pq_encapsulate, CryptoError, PqEncapsKey, Session, PQ_ENCAPS_KEY_LEN};

/// Protocol identifier string.
pub const PROTOCOL_NAME: &[u8] = b"PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3";

/// Length of the X25519 public key in bytes.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of the Poly1305 authentication tag in bytes.
pub const POLY1305_TAG_LEN: usize = 16;

/// Minimum/base length of Flight 1 message (zero-length application payload):
/// 32 bytes (ephemeral e_i) + 48 bytes (encrypted static s_i + tag)
/// + 768 bytes (ML-KEM-512 ciphertext) + 16 bytes (payload MAC tag) = 864 bytes.
pub const FLIGHT_1_BASE_LEN: usize = 864;

/// Minimum/base length of Flight 2 message (zero-length application payload):
/// 32 bytes (ephemeral e_r) + 16 bytes (payload MAC tag) = 48 bytes.
pub const FLIGHT_2_BASE_LEN: usize = 48;

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
    static_private: [u8; 32],
    static_public: [u8; 32],
    remote_static: [u8; 32],
    remote_pq_ek: [u8; PQ_ENCAPS_KEY_LEN],
    psk: [u8; 32],
    symmetric: SymmetricState,
    ephemeral_private: Option<[u8; 32]>,
    state: InitiatorState,
    transport_keys: Option<([u8; 32], [u8; 32])>,
}

impl Drop for InitiatorHandshake {
    fn drop(&mut self) {
        self.abort();
    }
}

impl InitiatorHandshake {
    /// Create a new initiator handshake.
    ///
    /// Mixes prologue, responder static public key, and responder ML-KEM-512 encapsulation key.
    pub fn new(
        static_private: &[u8; 32],
        remote_static: &[u8; 32],
        remote_pq_ek: &[u8; PQ_ENCAPS_KEY_LEN],
        psk: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        let sec = x25519_dalek::StaticSecret::from(*static_private);
        let static_public = x25519_dalek::PublicKey::from(&sec).to_bytes();

        let mut symmetric = SymmetricState::new(PROTOCOL_NAME);
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(remote_static);
        symmetric.mix_hash(remote_pq_ek);

        Ok(Self {
            static_private: *static_private,
            static_public,
            remote_static: *remote_static,
            remote_pq_ek: *remote_pq_ek,
            psk: *psk,
            symmetric,
            ephemeral_private: None,
            state: InitiatorState::ReadyToWrite1,
            transport_keys: None,
        })
    }

    /// Abort the handshake, zeroizing sensitive state material.
    pub fn abort(&mut self) {
        self.static_private.zeroize();
        self.psk.zeroize();
        if let Some(mut eph) = self.ephemeral_private.take() {
            eph.zeroize();
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
    /// Output buffer must have capacity for at least `FLIGHT_1_BASE_LEN + payload.len()` bytes.
    /// Returns the number of bytes written (`864 + payload.len()`).
    pub fn write_message_1(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.state != InitiatorState::ReadyToWrite1 {
            return Err(CryptoError::Handshake);
        }

        let total_len = FLIGHT_1_BASE_LEN
            .checked_add(payload.len())
            .ok_or(CryptoError::Handshake)?;
        if out.len() < total_len {
            return Err(CryptoError::Handshake);
        }

        // 1. Generate ephemeral keypair e_i
        let rng = SystemRandom::new();
        let mut eph_priv = [0u8; 32];
        if rng.fill(&mut eph_priv).is_err() {
            self.abort();
            return Err(CryptoError::Handshake);
        }
        let eph_secret = x25519_dalek::StaticSecret::from(eph_priv);
        let eph_pub = x25519_dalek::PublicKey::from(&eph_secret).to_bytes();

        out[0..32].copy_from_slice(&eph_pub);
        self.symmetric.mix_hash(&eph_pub);

        // 2. es: DH(e_i, rs_x25519)
        let mut dh_es = match constant_time_dh(&eph_priv, &self.remote_static) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv.zeroize();
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
            eph_priv.zeroize();
            self.abort();
            return Err(e);
        }
        k_1.zeroize();
        out[32..64].copy_from_slice(&s_buf);
        out[64..80].copy_from_slice(&s_tag);
        self.symmetric.mix_hash(&out[32..80]);

        // 4. ss: DH(s_i, rs_x25519)
        let mut dh_ss = match constant_time_dh(&self.static_private, &self.remote_static) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv.zeroize();
                self.abort();
                return Err(e);
            }
        };
        let mut k_2 = self.symmetric.mix_key(&dh_ss);
        dh_ss.zeroize();
        k_2.zeroize();

        // 5. skem: Encapsulate against rs_mlkem512
        let (pq_ct, pq_ss) = match pq_encapsulate(&PqEncapsKey(self.remote_pq_ek)) {
            Ok(res) => res,
            Err(e) => {
                eph_priv.zeroize();
                self.abort();
                return Err(e);
            }
        };
        out[80..848].copy_from_slice(&pq_ct.0);
        self.symmetric.mix_hash(&pq_ct.0);
        let mut ss_kem = *pq_ss;
        let mut k_3 = self.symmetric.mix_key(&ss_kem);
        ss_kem.zeroize();

        // 6. payload: Encrypt application payload with k_3 (ad = h)
        let payload_offset = 848;
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
            eph_priv.zeroize();
            self.abort();
            return Err(e);
        }
        k_3.zeroize();
        out[payload_end..tag_end].copy_from_slice(&payload_tag);
        self.symmetric.mix_hash(&out[payload_offset..tag_end]);

        self.ephemeral_private = Some(eph_priv);
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

    /// Convert completed handshake into an AEAD [`Session`].
    pub fn into_session(self) -> Result<Session, CryptoError> {
        let (mut k_send, mut k_recv) = self.transport_keys()?;
        let session = Session::from_raw_keys(&k_send, &k_recv, 0, 1);
        k_send.zeroize();
        k_recv.zeroize();
        session
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
    static_private: [u8; 32],
    static_public: [u8; 32],
    local_pq_ek: [u8; PQ_ENCAPS_KEY_LEN],
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
    /// Create a new responder handshake.
    ///
    /// Mixes prologue, responder static public key, and responder ML-KEM-512 encapsulation key.
    pub fn new(
        static_private: &[u8; 32],
        local_pq_ek: &[u8; PQ_ENCAPS_KEY_LEN],
        psk: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        let sec = x25519_dalek::StaticSecret::from(*static_private);
        let static_public = x25519_dalek::PublicKey::from(&sec).to_bytes();

        let mut symmetric = SymmetricState::new(PROTOCOL_NAME);
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(&static_public);
        symmetric.mix_hash(local_pq_ek);

        Ok(Self {
            static_private: *static_private,
            static_public,
            local_pq_ek: *local_pq_ek,
            psk: *psk,
            symmetric,
            remote_static: None,
            remote_ephemeral: None,
            state: ResponderState::ReadyToRead1,
            transport_keys: None,
        })
    }

    /// Abort the handshake, zeroizing sensitive state material.
    pub fn abort(&mut self) {
        self.static_private.zeroize();
        self.psk.zeroize();
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

    /// Consume Flight 1 handshake message from Initiator using ML-KEM-512 decapsulation key `dk`.
    ///
    /// Decrypts static public key and application payload into `payload_out`.
    /// On any MAC or key validation failure, intermediate state is wiped and an error returned.
    #[expect(deprecated)]
    pub fn read_message_1(
        &mut self,
        msg: &[u8],
        dk: &[u8; 1632],
        payload_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use ml_kem::ExpandedKeyEncoding;
        if self.state != ResponderState::ReadyToRead1 {
            return Err(CryptoError::Handshake);
        }

        if msg.len() < FLIGHT_1_BASE_LEN {
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

        // 5. skem: Decapsulate ML-KEM-512 ciphertext
        let mut ct_bytes = [0u8; 768];
        ct_bytes.copy_from_slice(&msg[80..848]);

        let dk_arr = ml_kem::array::Array::from(*dk);
        let decaps_key =
            ml_kem_512::DecapsulationKey::from_expanded_bytes(&dk_arr).map_err(|_| {
                self.abort();
                CryptoError::Handshake
            })?;
        let ct_arr = ml_kem::array::Array::from(ct_bytes);
        let mut ss_kem: [u8; 32] = decaps_key.decapsulate(&ct_arr).into();
        self.symmetric.mix_hash(&ct_bytes);

        let mut k_3 = self.symmetric.mix_key(&ss_kem);
        ss_kem.zeroize();

        // 6. payload: Decrypt application payload with k_3 (ad = h)
        let payload_len = msg.len() - FLIGHT_1_BASE_LEN;
        if payload_out.len() < payload_len {
            k_3.zeroize();
            self.abort();
            return Err(CryptoError::Handshake);
        }

        let payload_offset = 848;
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

        // 1. Generate ephemeral keypair e_r
        let rng = SystemRandom::new();
        let mut eph_priv = [0u8; 32];
        if rng.fill(&mut eph_priv).is_err() {
            self.abort();
            return Err(CryptoError::Handshake);
        }
        let eph_secret = x25519_dalek::StaticSecret::from(eph_priv);
        let eph_pub = x25519_dalek::PublicKey::from(&eph_secret).to_bytes();

        out[0..32].copy_from_slice(&eph_pub);
        self.symmetric.mix_hash(&eph_pub);

        // 2. ee: DH(e_r, e_i)
        let mut dh_ee = match constant_time_dh(&eph_priv, &e_i) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv.zeroize();
                self.abort();
                return Err(e);
            }
        };
        let mut k_4 = self.symmetric.mix_key(&dh_ee);
        dh_ee.zeroize();
        k_4.zeroize();

        // 3. se: DH(e_r, s_i)
        let mut dh_se = match constant_time_dh(&eph_priv, &remote_static) {
            Ok(dh) => dh,
            Err(e) => {
                eph_priv.zeroize();
                self.abort();
                return Err(e);
            }
        };
        eph_priv.zeroize();
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

    /// Local ML-KEM-512 encapsulation key.
    pub fn local_pq_ek(&self) -> &[u8; PQ_ENCAPS_KEY_LEN] {
        &self.local_pq_ek
    }

    /// Authenticated remote static public key learned from Flight 1.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.remote_static
    }

    /// Convert completed handshake into an AEAD [`Session`].
    pub fn into_session(self) -> Result<Session, CryptoError> {
        let (mut k_send, mut k_recv) = self.transport_keys()?;
        let session = Session::from_raw_keys(&k_send, &k_recv, 0, 1);
        k_send.zeroize();
        k_recv.zeroize();
        session
    }
}
