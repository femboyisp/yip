//! Post-quantum hybrid Noise handshake and AEAD session crypto for the yip data plane.
//!
//! Establishing a [`Session`] requires completing a PQNoise handshake ([`InitiatorHandshake`]
//! or [`ResponderHandshake`]); the session then seals/opens inner frames with explicit per-frame
//! nonces and a sliding anti-replay window. Directional [`SessionPair`] engines handle zero-copy
//! in-place payload AEAD and 120s epoch rekeying using BLAKE3 in keyed mode.
#![forbid(unsafe_code)]

pub mod handshake;
pub mod session;
pub mod symmetric;

pub use handshake::{
    InitiatorHandshake, ResponderHandshake, FLIGHT_1_BASE_LEN, FLIGHT_2_BASE_LEN, POLY1305_TAG_LEN,
    PROTOCOL_NAME, X25519_PUBLIC_KEY_LEN,
};
pub use session::{
    noise_nonce, rekey_transport_key, ChaCha20Poly1305Cipher, ReplayProfile, ReplayWindow, Sealed,
    Session, SessionPair, REPLAY_WINDOW_BITS, REPLAY_WINDOW_BITS_HIGH_THROUGHPUT,
    REPLAY_WINDOW_BITS_STANDARD, REPLAY_WORDS, REPLAY_WORDS_HIGH_THROUGHPUT, REPLAY_WORDS_STANDARD,
};
pub use symmetric::SymmetricState;

#[expect(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{
    array::Array,
    kem::{Decapsulate, Kem, KeyExport},
    ml_kem_512::{self, MlKem512},
};
use zeroize::{Zeroize, Zeroizing};

/// An X25519 static keypair (32-byte private and public halves).
#[derive(Debug, Clone)]
pub struct Keypair {
    /// X25519 private key.
    pub private: [u8; 32],
    /// X25519 public key.
    pub public: [u8; 32],
}

/// Generate a fresh X25519 static keypair.
pub fn generate_keypair() -> Keypair {
    let rng = ring::rand::SystemRandom::new();
    let mut private = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut private).expect("keypair generation");
    let secret = x25519_dalek::StaticSecret::from(private);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    Keypair { private, public }
}

/// ML-KEM-512 encapsulation key length in bytes (FIPS 203).
pub const PQ_ENCAPS_KEY_LEN: usize = 800;

/// ML-KEM-512 ciphertext length in bytes (FIPS 203).
pub const PQ_CIPHERTEXT_LEN: usize = 768;

/// ML-KEM-512 shared secret length in bytes (FIPS 203).
pub const PQ_SHARED_SECRET_LEN: usize = 32;

/// ML-KEM-512 decapsulation key length in bytes (FIPS 203).
pub const PQ_DECAPS_KEY_LEN: usize = 1632;

/// An ML-KEM-512 public encapsulation key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqEncapsKey(pub [u8; PQ_ENCAPS_KEY_LEN]);

/// An ML-KEM-512 private decapsulation key wrapped in zeroizing memory.
pub struct PqDecapsKey(pub(crate) Option<Box<ml_kem_512::DecapsulationKey>>);

impl Drop for PqDecapsKey {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            drop(inner);
        }
    }
}

impl zeroize::Zeroize for PqDecapsKey {
    fn zeroize(&mut self) {
        if let Some(inner) = self.0.take() {
            drop(inner);
        }
    }
}

impl zeroize::ZeroizeOnDrop for PqDecapsKey {}

impl PqDecapsKey {
    /// Export the 1632-byte expanded ML-KEM-512 decapsulation key bytes.
    #[expect(deprecated)]
    pub fn to_bytes(&self) -> [u8; PQ_DECAPS_KEY_LEN] {
        use ml_kem::ExpandedKeyEncoding;
        let dk = self.0.as_ref().expect("PqDecapsKey uninitialized");
        let arr = dk.to_expanded_bytes();
        let mut out = [0u8; PQ_DECAPS_KEY_LEN];
        out.copy_from_slice(arr.as_slice());
        out
    }

    /// Import an expanded ML-KEM-512 decapsulation key from 1632 bytes.
    #[expect(deprecated)]
    pub fn from_bytes(bytes: &[u8; PQ_DECAPS_KEY_LEN]) -> Result<Self, CryptoError> {
        use ml_kem::ExpandedKeyEncoding;
        let arr = ml_kem::array::Array::from(*bytes);
        let dk = ml_kem_512::DecapsulationKey::from_expanded_bytes(&arr)
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Self(Some(Box::new(dk))))
    }
}

impl std::fmt::Debug for PqDecapsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PqDecapsKey([REDACTED])")
    }
}

/// An ML-KEM-512 encapsulated ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCiphertext(pub [u8; PQ_CIPHERTEXT_LEN]);

/// Generate a fresh ML-KEM-512 keypair.
pub fn generate_pq_keypair() -> (PqEncapsKey, PqDecapsKey) {
    let (dk, ek) = MlKem512::generate_keypair();
    let ek_bytes = ek.to_bytes();
    let mut ek_arr = [0u8; PQ_ENCAPS_KEY_LEN];
    ek_arr.copy_from_slice(ek_bytes.as_slice());
    (PqEncapsKey(ek_arr), PqDecapsKey(Some(Box::new(dk))))
}

/// Generate an ML-KEM-512 keypair from a 64-byte seed.
pub fn generate_pq_keypair_from_seed(seed: &[u8; 64]) -> (PqEncapsKey, PqDecapsKey) {
    let arr = Array::from(*seed);
    let dk = ml_kem_512::DecapsulationKey::from_seed(arr);
    let ek = dk.encapsulation_key();
    let ek_bytes = ek.to_bytes();
    let mut ek_arr = [0u8; PQ_ENCAPS_KEY_LEN];
    ek_arr.copy_from_slice(ek_bytes.as_slice());
    (PqEncapsKey(ek_arr), PqDecapsKey(Some(Box::new(dk))))
}

/// Encapsulate a shared secret toward `ek` using a deterministic 32-byte seed `m`,
/// producing `(ciphertext, shared_secret)`.
///
/// Explicitly validates FIPS 203 Section 7.2 ByteDecode_12 (all 12-bit coefficients < 3329)
/// across the first 768 bytes before invoking key encapsulation.
pub fn pq_encapsulate_deterministic(
    ek: &PqEncapsKey,
    m: &[u8; 32],
) -> Result<(PqCiphertext, Zeroizing<[u8; PQ_SHARED_SECRET_LEN]>), CryptoError> {
    // FIPS 203 Section 7.2: ByteDecode_12 modulus check (all 12-bit coeffs < 3329)
    for chunk in ek.0[..768].as_chunks::<3>().0 {
        let d0 = u16::from(chunk[0]) | ((u16::from(chunk[1]) & 0x0F) << 8);
        let d1 = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);
        if d0 >= 3329 || d1 >= 3329 {
            return Err(CryptoError::Handshake);
        }
    }

    let ek_arr = Array::from(ek.0);
    let key = ml_kem_512::EncapsulationKey::new(&ek_arr).map_err(|_| CryptoError::Handshake)?;
    let m_arr = Array::from(*m);
    let (ct, ss) = key.encapsulate_deterministic(&m_arr);
    let ss = Zeroizing::new(ss);
    let mut ct_arr = [0u8; PQ_CIPHERTEXT_LEN];
    ct_arr.copy_from_slice(ct.as_slice());
    let mut ss_arr = Zeroizing::new([0u8; PQ_SHARED_SECRET_LEN]);
    ss_arr.copy_from_slice(ss.as_slice());
    Ok((PqCiphertext(ct_arr), ss_arr))
}

/// Encapsulate a shared secret toward `ek`, producing `(ciphertext, shared_secret)`.
///
/// Explicitly validates FIPS 203 Section 7.2 ByteDecode_12 (all 12-bit coefficients < 3329)
/// across the first 768 bytes before invoking key encapsulation.
pub fn pq_encapsulate(
    ek: &PqEncapsKey,
) -> Result<(PqCiphertext, Zeroizing<[u8; PQ_SHARED_SECRET_LEN]>), CryptoError> {
    let rng = ring::rand::SystemRandom::new();
    let mut m = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut m).map_err(|_| CryptoError::Handshake)?;
    let res = pq_encapsulate_deterministic(ek, &m);
    m.zeroize();
    res
}

/// Decapsulate `ct` using `dk`, recovering the 32-byte shared secret wrapped in zeroizing memory.
pub fn pq_decapsulate(
    dk: &PqDecapsKey,
    ct: &PqCiphertext,
) -> Result<Zeroizing<[u8; PQ_SHARED_SECRET_LEN]>, CryptoError> {
    let ct_arr = Array::from(ct.0);
    let dk_box = dk.0.as_ref().ok_or(CryptoError::Handshake)?;
    let ss = Zeroizing::new(dk_box.decapsulate(&ct_arr));
    let mut ss_arr = Zeroizing::new([0u8; PQ_SHARED_SECRET_LEN]);
    ss_arr.copy_from_slice(ss.as_slice());
    Ok(ss_arr)
}

/// Errors from the crypto layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD tag did not verify / decryption failed.
    #[error("decryption failed")]
    Decrypt,
    /// Nonce/counter outside the anti-replay window (replayed or too old).
    #[error("replayed message")]
    Replay,
    /// Handshake step failed (bad message, wrong state, or key error).
    #[error("handshake failed")]
    Handshake,
    /// Cryptographic key was invalid (e.g. low-order point or invalid encoding).
    #[error("invalid key")]
    InvalidKey,
}

/// Unified handshake interface driving native post-quantum hybrid key exchange.
pub struct Handshake {
    role: HandshakeRole,
}

enum HandshakeRole {
    Initiator(Box<InitiatorHandshake>),
    Responder(Box<(ResponderHandshake, [u8; PQ_DECAPS_KEY_LEN])>),
}

impl Handshake {
    /// Begin as the initiator, which knows the responder's static public key.
    pub fn initiator(
        local_private: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> Result<Handshake, CryptoError> {
        let mut hasher = blake3::Hasher::new_derive_key("yip-compat-mlkem512-v1");
        hasher.update(peer_public);
        let mut seed_bytes = [0u8; 64];
        hasher.finalize_xof().fill(&mut seed_bytes);
        let seed = ml_kem::Seed::from(seed_bytes);
        let dk = ml_kem_512::DecapsulationKey::from_seed(seed);
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let mut ek = [0u8; PQ_ENCAPS_KEY_LEN];
        ek.copy_from_slice(ek_bytes.as_slice());

        let inner = InitiatorHandshake::new(local_private, peer_public, &ek, &[0u8; 32], &[])?;
        Ok(Handshake {
            role: HandshakeRole::Initiator(Box::new(inner)),
        })
    }

    /// Begin as the responder; learns the initiator's static key during the handshake.
    pub fn responder(local_private: &[u8; 32]) -> Result<Handshake, CryptoError> {
        let sec = x25519_dalek::StaticSecret::from(*local_private);
        let local_public = x25519_dalek::PublicKey::from(&sec).to_bytes();

        let mut hasher = blake3::Hasher::new_derive_key("yip-compat-mlkem512-v1");
        hasher.update(&local_public);
        let mut seed_bytes = [0u8; 64];
        hasher.finalize_xof().fill(&mut seed_bytes);
        let seed = ml_kem::Seed::from(seed_bytes);
        let dk = ml_kem_512::DecapsulationKey::from_seed(seed);
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let mut ek = [0u8; PQ_ENCAPS_KEY_LEN];
        ek.copy_from_slice(ek_bytes.as_slice());
        #[expect(deprecated)]
        let dk_bytes = dk.to_expanded_bytes();
        let mut dk_arr = [0u8; PQ_DECAPS_KEY_LEN];
        dk_arr.copy_from_slice(dk_bytes.as_slice());

        let inner = ResponderHandshake::new(local_private, &ek, &[0u8; 32], &[])?;
        Ok(Handshake {
            role: HandshakeRole::Responder(Box::new((inner, dk_arr))),
        })
    }

    /// Produce the next handshake message to send to the peer.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match &mut self.role {
            HandshakeRole::Initiator(ini) => {
                let mut out = vec![0u8; FLIGHT_1_BASE_LEN + payload.len()];
                let n = ini.write_message_1(payload, &mut out)?;
                out.truncate(n);
                Ok(out)
            }
            HandshakeRole::Responder(boxed) => {
                let (res, _) = &mut **boxed;
                let mut out = vec![0u8; FLIGHT_2_BASE_LEN + payload.len()];
                let n = res.write_message_2(payload, &mut out)?;
                out.truncate(n);
                Ok(out)
            }
        }
    }

    /// Consume a handshake message received from the peer, returning the decrypted app payload.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match &mut self.role {
            HandshakeRole::Responder(boxed) => {
                let (res, dk) = &mut **boxed;
                let mut out = vec![0u8; msg.len()];
                let n = res.read_message_1(msg, dk, &mut out)?;
                out.truncate(n);
                Ok(out)
            }
            HandshakeRole::Initiator(ini) => {
                let mut out = vec![0u8; msg.len()];
                let n = ini.read_message_2(msg, &mut out)?;
                out.truncate(n);
                Ok(out)
            }
        }
    }

    /// Whether the handshake has completed and a session can be derived.
    pub fn is_finished(&self) -> bool {
        match &self.role {
            HandshakeRole::Initiator(ini) => ini.is_finished(),
            HandshakeRole::Responder(boxed) => boxed.0.is_finished(),
        }
    }

    /// The peer's authenticated static public key, if learned yet.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        match &self.role {
            HandshakeRole::Initiator(ini) => ini.remote_static(),
            HandshakeRole::Responder(boxed) => boxed.0.remote_static(),
        }
    }

    /// The Noise channel-binding hash identical on both peers after handshake completion.
    pub fn channel_binding(&self) -> [u8; 32] {
        match &self.role {
            HandshakeRole::Initiator(ini) => ini.channel_binding(),
            HandshakeRole::Responder(boxed) => boxed.0.channel_binding(),
        }
    }

    /// Extract directional transport keys (k_send, k_recv).
    pub fn raw_split_keys(&self) -> ([u8; 32], [u8; 32]) {
        match &self.role {
            HandshakeRole::Initiator(ini) => ini.transport_keys().unwrap_or(([0u8; 32], [0u8; 32])),
            HandshakeRole::Responder(boxed) => {
                boxed.0.transport_keys().unwrap_or(([0u8; 32], [0u8; 32]))
            }
        }
    }

    /// Convert a completed handshake into an established [`SessionPair`].
    pub fn into_session_pair(self) -> Result<SessionPair, CryptoError> {
        match self.role {
            HandshakeRole::Initiator(ini) => ini.into_session_pair(),
            HandshakeRole::Responder(boxed) => boxed.0.into_session_pair(),
        }
    }

    /// Convert a completed handshake into an AEAD [`Session`].
    pub fn into_session(self) -> Result<Session, CryptoError> {
        match self.role {
            HandshakeRole::Initiator(ini) => ini.into_session(),
            HandshakeRole::Responder(boxed) => boxed.0.into_session(),
        }
    }
}

/// Test-only helper: drive a full initiator/responder handshake to completion
/// and return the two established sessions.
#[cfg(test)]
pub(crate) fn test_session_pair() -> (Session, Session) {
    let resp_kp = generate_keypair();
    let init_kp = generate_keypair();
    let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
    let mut res = Handshake::responder(&resp_kp.private).unwrap();
    let m1 = ini.write_message(&[]).unwrap();
    let _ = res.read_message(&m1).unwrap();
    let m2 = res.write_message(&[]).unwrap();
    let _ = ini.read_message(&m2).unwrap();
    (ini.into_session().unwrap(), res.into_session().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypairs_are_distinct_32_byte_keys() {
        let a = generate_keypair();
        let b = generate_keypair();
        assert_eq!(a.private.len(), 32);
        assert_eq!(a.public.len(), 32);
        assert_ne!(a.private, b.private, "two keypairs differ");
        assert_ne!(a.public, [0u8; 32], "public key is not all-zero");
    }

    #[test]
    fn session_seal_and_open_in_place_with_stride() {
        let (k_send, k_recv) = ([0x11u8; 32], [0x22u8; 32]);
        let mut s_tx = Session::from_raw_keys(&k_send, &k_recv, 2, 4).unwrap();
        let mut s_rx = Session::from_raw_keys(&k_recv, &k_send, 0, 1).unwrap();

        let mut buf = vec![0u8; 64];
        buf[..10].copy_from_slice(b"0123456789");

        let c1 = s_tx.seal_in_place(&mut buf, 10).unwrap();
        assert_eq!(c1, 2);
        let plain_len = s_rx.open_in_place(c1, &mut buf, 26).unwrap();
        assert_eq!(plain_len, 10);
        assert_eq!(&buf[..10], b"0123456789");

        // Next counter with stride 4
        buf[..10].copy_from_slice(b"abcdefghij");
        let c2 = s_tx.seal_in_place(&mut buf, 10).unwrap();
        assert_eq!(c2, 6);
        let plain_len2 = s_rx.open_in_place(c2, &mut buf, 26).unwrap();
        assert_eq!(plain_len2, 10);
        assert_eq!(&buf[..10], b"abcdefghij");

        // Replay of c2 should fail
        assert!(s_rx.open_in_place(c2, &mut buf, 26).is_err());
    }

    #[test]
    fn replay_window_accepts_fresh_rejects_replays_and_old() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.latest(), 0);
        assert_eq!(w.floor(), 0);
        assert!(w.check_and_set(0), "first counter accepted");
        assert_eq!(w.latest(), 0);
        assert_eq!(w.floor(), 0);
        assert!(!w.check_and_set(0), "exact replay rejected");
        assert!(w.check_and_set(1), "next in order accepted");
        assert_eq!(w.latest(), 1);
        assert!(w.check_and_set(5), "jump ahead accepted");
        assert_eq!(w.latest(), 5);
        assert!(w.check_and_set(3), "in-window out-of-order accepted");
        assert!(!w.check_and_set(3), "replay of out-of-order rejected");
        assert!(w.check_and_set(100), "large advance accepted");
        assert_eq!(w.latest(), 100);
        assert!(
            !w.check_and_set(5),
            "counter now far below window rejected as too old"
        );

        let big = 200_000u64;
        w.commit(big);
        assert_eq!(w.latest(), big);
        assert_eq!(w.floor(), big - (w.profile().bits() - 1));
        assert!(w.check(w.floor()));
        assert!(!w.check(w.floor() - 1));
    }

    #[test]
    fn session_replay_latest_and_floor() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let mut s = Session::from_raw_keys(&k1, &k2, 0, 1).unwrap();
        assert_eq!(s.send_counter(), 0);
        assert_eq!(s.replay_latest(), 0);
        assert_eq!(s.replay_floor(), 0);

        let sealed = s.seal(b"hello").unwrap();
        assert_eq!(sealed.counter, 0);
        assert_eq!(s.send_counter(), 1);

        let mut s_peer = Session::from_raw_keys(&k2, &k1, 0, 1).unwrap();
        let sealed_peer = s_peer.seal(b"reply").unwrap();
        let opened = s
            .open(sealed_peer.counter, &sealed_peer.ciphertext)
            .unwrap();
        assert_eq!(opened, b"reply");
        assert_eq!(s.replay_latest(), 0);
        assert_eq!(s.replay_floor(), 0);
    }

    #[test]
    fn replay_window_advance_then_replay_old_counter_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(10), "counter 10 accepted as first");
        assert!(w.check_and_set(15), "advance to 15 accepted");
        assert!(
            !w.check_and_set(10),
            "replay of counter 10 after advance to 15 rejected"
        );
    }

    #[test]
    fn replay_window_new_latest_immediately_replayable_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(10), "first packet at 10");
        assert!(w.check_and_set(9), "counter 9 accepted in-order-ish");
        assert!(w.check_and_set(11), "advance to 11 accepted");
        assert!(!w.check_and_set(11), "replay of new latest 11 rejected");
    }

    #[test]
    fn replay_window_in_window_replay_rejected_after_advance() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(10), "first packet");
        assert!(w.check_and_set(15), "advance to 15");
        assert!(!w.check_and_set(10), "in-window replay at diff=5 rejected");
    }

    #[test]
    fn handshake_not_finished_before_message_exchange() {
        let kp = generate_keypair();
        let res = Handshake::responder(&kp.private).unwrap();
        assert!(
            !res.is_finished(),
            "responder reports not-finished before any messages"
        );
        let ini = Handshake::initiator(&kp.private, &kp.public).unwrap();
        assert!(
            !ini.is_finished(),
            "initiator reports not-finished before any messages"
        );
    }

    #[test]
    fn handshake_payload_round_trips_and_sessions_match() {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();
        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let m1 = ini.write_message(b"cert-A").unwrap();
        let got_a = res.read_message(&m1).unwrap();
        assert_eq!(got_a, b"cert-A");

        let m2 = res.write_message(b"cert-B").unwrap();
        let got_b = ini.read_message(&m2).unwrap();
        assert_eq!(got_b, b"cert-B");

        assert_eq!(ini.channel_binding(), res.channel_binding());
        let mut ini_session = ini.into_session().unwrap();
        let mut res_session = res.into_session().unwrap();
        let sealed = ini_session.seal(b"payload round-trip ok").unwrap();
        assert_eq!(
            res_session
                .open(sealed.counter, &sealed.ciphertext)
                .unwrap(),
            b"payload round-trip ok"
        );
    }

    #[test]
    fn session_seals_and_opens_roundtrip() {
        let (mut a, mut b) = test_session_pair();
        let s = a.seal(b"inner packet").unwrap();
        assert_eq!(s.counter, 0, "first counter is 0");
        assert_eq!(b.open(s.counter, &s.ciphertext).unwrap(), b"inner packet");
    }

    #[test]
    fn session_opens_out_of_order() {
        let (mut a, mut b) = test_session_pair();
        let s0 = a.seal(b"zero").unwrap();
        let s1 = a.seal(b"one").unwrap();
        assert_eq!(s1.counter, 1);
        assert_eq!(b.open(s1.counter, &s1.ciphertext).unwrap(), b"one");
        assert_eq!(b.open(s0.counter, &s0.ciphertext).unwrap(), b"zero");
    }

    #[test]
    fn session_rejects_replay() {
        let (mut a, mut b) = test_session_pair();
        let s = a.seal(b"x").unwrap();
        assert!(b.open(s.counter, &s.ciphertext).is_ok());
        assert_eq!(b.open(s.counter, &s.ciphertext), Err(CryptoError::Replay));
    }

    #[test]
    fn session_rejects_tampered_ciphertext() {
        let (mut a, mut b) = test_session_pair();
        let s = a.seal(b"y").unwrap();
        let mut bad = s.ciphertext.clone();
        bad[0] ^= 0x01;
        assert_eq!(b.open(s.counter, &bad), Err(CryptoError::Decrypt));
    }

    #[test]
    fn forged_frame_does_not_advance_replay_window() {
        let (mut a, mut b) = test_session_pair();
        let s0 = a.seal(b"zero").unwrap();
        let s1 = a.seal(b"one").unwrap();

        assert_eq!(b.open(s0.counter, &s0.ciphertext).unwrap(), b"zero");

        let garbage = vec![0u8; s0.ciphertext.len()];
        assert_eq!(
            b.open(1_000_000, &garbage),
            Err(CryptoError::Decrypt),
            "forged frame fails AEAD"
        );

        assert_eq!(
            b.open(s1.counter, &s1.ciphertext).unwrap(),
            b"one",
            "legit frame still opens after forged far-future injection"
        );
    }

    #[test]
    fn forged_frame_does_not_advance_replay_window_open_into() {
        let (mut a, mut b) = test_session_pair();
        let s0 = a.seal(b"zero").unwrap();
        let s1 = a.seal(b"one").unwrap();
        let mut out = Vec::new();

        b.open_into(s0.counter, &s0.ciphertext, &mut out).unwrap();
        assert_eq!(out, b"zero");

        let garbage = vec![0u8; s0.ciphertext.len()];
        assert_eq!(
            b.open_into(1_000_000, &garbage, &mut out),
            Err(CryptoError::Decrypt),
            "forged frame fails AEAD"
        );

        b.open_into(s1.counter, &s1.ciphertext, &mut out).unwrap();
        assert_eq!(
            out, b"one",
            "legit frame still opens after forged injection"
        );
    }

    #[test]
    fn channel_binding_matches_on_both_peers() {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();
        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();
        let m1 = ini.write_message(&[]).unwrap();
        let _ = res.read_message(&m1).unwrap();
        let m2 = res.write_message(&[]).unwrap();
        let _ = ini.read_message(&m2).unwrap();
        assert!(ini.is_finished() && res.is_finished());
        assert_eq!(
            ini.channel_binding(),
            res.channel_binding(),
            "both peers derive the same binding"
        );
        assert_ne!(ini.channel_binding(), [0u8; 32]);
    }

    #[test]
    fn channel_binding_is_transcript_dependent_not_constant() {
        fn complete_binding() -> [u8; 32] {
            let resp_kp = generate_keypair();
            let init_kp = generate_keypair();
            let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
            let mut res = Handshake::responder(&resp_kp.private).unwrap();
            let m1 = ini.write_message(&[]).unwrap();
            let _ = res.read_message(&m1).unwrap();
            let m2 = res.write_message(&[]).unwrap();
            let _ = ini.read_message(&m2).unwrap();
            assert!(ini.is_finished() && res.is_finished());
            let binding = ini.channel_binding();
            assert_eq!(binding, res.channel_binding());
            binding
        }

        let binding_a = complete_binding();
        let binding_b = complete_binding();
        assert_ne!(binding_a, [1u8; 32]);
        assert_ne!(binding_b, [1u8; 32]);
        assert_ne!(binding_a, binding_b);
    }

    #[test]
    fn ik_handshake_completes_and_authenticates_initiator() {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();

        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let msg1 = ini.write_message(&[]).unwrap();
        let _ = res.read_message(&msg1).unwrap();
        let msg2 = res.write_message(&[]).unwrap();
        let _ = ini.read_message(&msg2).unwrap();

        assert!(ini.is_finished() && res.is_finished());
        assert_eq!(res.remote_static(), Some(init_kp.public));
    }

    #[test]
    fn seal_is_byte_identical_across_a_reference_session() {
        let (mut a, mut b) = crate::test_session_pair();
        for ctr in 0u64..8 {
            let s = a.seal(&[0x5Au8; 64]).unwrap();
            assert_eq!(s.counter, ctr);
            assert_eq!(b.open(s.counter, &s.ciphertext).unwrap(), vec![0x5Au8; 64]);
        }
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let (mut a, mut b) = crate::test_session_pair();
        let s = a.seal(b"secret").unwrap();
        let mut bad = s.ciphertext.clone();
        bad[0] ^= 1;
        assert_eq!(b.open(s.counter, &bad), Err(CryptoError::Decrypt));
    }

    #[test]
    fn open_rejects_replay_and_opens_out_of_order() {
        let (mut a, mut b) = crate::test_session_pair();
        let s0 = a.seal(b"zero").unwrap();
        let s1 = a.seal(b"one").unwrap();
        assert_eq!(b.open(s1.counter, &s1.ciphertext).unwrap(), b"one");
        assert_eq!(b.open(s0.counter, &s0.ciphertext).unwrap(), b"zero");
        assert_eq!(b.open(s1.counter, &s1.ciphertext), Err(CryptoError::Replay));
    }

    #[test]
    fn session_seal_and_rekey_roundtrip() {
        let (mut a, mut b) = crate::test_session_pair();
        let p1 = b"pre-rekey packet payload";
        let s1 = a.seal(p1).unwrap();
        assert_eq!(b.open(s1.counter, &s1.ciphertext).unwrap(), p1);

        // Rekey both sides (120s epoch ratchet)
        a.rekey();
        b.rekey();

        let p2 = b"post-rekey epoch 1 packet payload";
        let s2 = a.seal(p2).unwrap();
        assert_eq!(b.open(s2.counter, &s2.ciphertext).unwrap(), p2);
    }

    #[test]
    fn seal_into_matches_seal_and_opens() {
        let (mut a, mut b) = crate::test_session_pair();
        let mut sbuf = Vec::new();
        let ctr = a.seal_into(b"reuse me", &mut sbuf).unwrap();
        let mut obuf = Vec::new();
        b.open_into(ctr, &sbuf, &mut obuf).unwrap();
        assert_eq!(obuf, b"reuse me");
    }

    #[test]
    fn test_wide_replay_window_jitter_and_rejection() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        w.commit(0);

        assert!(w.check(100_000));
        w.commit(100_000);

        assert!(w.check(50_000));
        w.commit(50_000);
        assert!(!w.check(50_000));
        assert!(!w.check(0));

        assert!(w.check(250_000));
        w.commit(250_000);
        assert!(!w.check(100_000));
    }

    #[test]
    fn test_seal_with_counter_and_open_with_window() {
        let (a, b) = crate::test_session_pair();
        let payload = b"concurrent multi-worker payload";
        let sealed = a.seal_with_counter(42, payload).unwrap();
        assert_eq!(sealed.counter, 42);

        let mut replay = ReplayWindow::new();
        let decrypted = b
            .open_with_window(sealed.counter, &sealed.ciphertext, &mut replay)
            .unwrap();
        assert_eq!(decrypted, payload);

        assert_eq!(
            b.open_with_window(sealed.counter, &sealed.ciphertext, &mut replay),
            Err(CryptoError::Replay)
        );
    }

    #[test]
    fn test_chacha20_poly1305_cipher_in_place() {
        let key = [0x5au8; 32];
        let cipher = ChaCha20Poly1305Cipher::new(key);
        let mut buffer = [0u8; 128];
        let plaintext = b"zero-copy in-place packet buffer payload";
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let counter = 100u64;
        let sealed_len = cipher
            .seal_in_place(counter, &mut buffer, plaintext.len())
            .expect("seal_in_place should succeed");
        assert_eq!(sealed_len, plaintext.len() + 16);
        assert_ne!(&buffer[..plaintext.len()], plaintext);

        let mut replay = ReplayWindow::new();
        let plain_len = cipher
            .open_in_place_with_window(counter, &mut buffer, sealed_len, &mut replay)
            .expect("open_in_place_with_window should succeed");
        assert_eq!(plain_len, plaintext.len());
        assert_eq!(&buffer[..plain_len], plaintext);

        assert_eq!(
            cipher.open_in_place_with_window(counter, &mut buffer, sealed_len, &mut replay),
            Err(CryptoError::Replay)
        );
    }

    #[test]
    fn test_chacha20_poly1305_cipher_debug_and_boundaries() {
        let key = [0x5au8; 32];
        let cipher = ChaCha20Poly1305Cipher::new(key);
        let debug_str = format!("{cipher:?}");
        assert!(debug_str.contains("ChaCha20Poly1305Cipher"));

        let mut buf = [0u8; 32];
        assert_eq!(cipher.seal_in_place(1, &mut buf[..16], 0).unwrap(), 16);
        assert_eq!(
            cipher.seal_in_place(1, &mut buf[..15], 0),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            cipher.open_in_place(1, &mut buf, 15),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            cipher.open_in_place(1, &mut buf, 0),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            cipher.open_in_place(1, &mut buf[..10], 16),
            Err(CryptoError::Decrypt)
        );

        let mut exact = [0u8; 16];
        cipher.seal_in_place(2, &mut exact, 0).unwrap();
        assert_eq!(cipher.open_in_place(2, &mut exact, 16).unwrap(), 0);
    }

    #[test]
    fn test_seal_into_with_counter_and_open_into_with_window() {
        let (a, b) = crate::test_session_pair();
        let payload = b"buffer test payload";
        let mut sealed_buf = Vec::new();
        a.seal_into_with_counter(42, payload, &mut sealed_buf)
            .unwrap();
        assert_ne!(sealed_buf, payload);
        assert_eq!(sealed_buf.len(), payload.len() + 16);

        let mut replay = ReplayWindow::new();
        let mut out = Vec::new();
        b.open_into_with_window(42, &sealed_buf, &mut replay, &mut out)
            .unwrap();
        assert_eq!(out, payload);

        out.clear();
        let err = b.open_into_with_window(42, &sealed_buf, &mut replay, &mut out);
        assert_eq!(err, Err(CryptoError::Replay));
        assert!(out.is_empty());

        let mut bad_buf = sealed_buf.clone();
        bad_buf[0] ^= 1;
        let mut fresh_replay = ReplayWindow::new();
        let bad_err = b.open_into_with_window(43, &bad_buf, &mut fresh_replay, &mut out);
        assert_eq!(bad_err, Err(CryptoError::Decrypt));
    }

    #[test]
    fn test_replay_window_word_idx_distinct_words() {
        let mut w = ReplayWindow::new();
        w.commit(0);
        assert!(w.check(64));
        assert!(w.check(128));
        w.commit(64);
        assert!(!w.check(64));
        assert!(!w.check(0));
        assert!(w.check(128));
    }

    #[test]
    fn test_promote_to_high_throughput_preserves_multi_word_state() {
        let mut w = ReplayWindow::new_with_profile(ReplayProfile::Standard);
        w.commit(100);
        w.commit(200);
        w.commit(1000);
        w.commit(1500);
        w.promote_to_high_throughput();
        assert_eq!(w.profile(), ReplayProfile::HighThroughput);

        assert!(!w.check(100));
        assert!(!w.check(200));
        assert!(!w.check(1000));
        assert!(!w.check(1500));

        assert!(w.check(101));
        assert!(w.check(201));
        assert!(w.check(1001));
        assert!(w.check(1499));
    }

    #[test]
    fn test_promote_to_high_throughput_large_latest() {
        let mut w = ReplayWindow::new_with_profile(ReplayProfile::Standard);
        let latest = 200 * 64 + 10;
        w.commit(latest);
        w.promote_to_high_throughput();

        assert!(
            w.check(72 * 64 + 10),
            "counter 72 * 64 + 10 was never committed and must be acceptable"
        );

        let mut w2 = ReplayWindow::new_with_profile(ReplayProfile::Standard);
        w2.commit(73 * 64 + 10);
        w2.commit(latest);
        w2.promote_to_high_throughput();
        assert!(!w2.check(latest), "latest must still be marked seen");
        assert!(
            !w2.check(73 * 64 + 10),
            "tail counter in word 73 must be marked seen"
        );
    }

    #[test]
    fn test_replay_window_circular_word_clearing() {
        let mut w = ReplayWindow::new_with_profile(ReplayProfile::Standard);
        w.commit(69);
        assert!(!w.check(69));

        w.commit(8192 + 74);
        assert!(!w.check(8192 + 74));

        assert!(
            w.check(8192 + 69),
            "counter 8192 + 69 must not be blocked by stale bit from counter 69"
        );
    }

    #[test]
    fn test_replay_window_consecutive_word_clearing() {
        let mut w = ReplayWindow::new_with_profile(ReplayProfile::Standard);
        w.commit(130);
        w.commit(8192 + 70);
        w.commit(8192 + 135);
        assert!(
            w.check(8192 + 130),
            "counter 8192 + 130 must be accepted after word 2 is overtaken and cleared"
        );

        w.commit(5000);
        w.commit(5001);
        w.commit(5100);
        assert!(!w.check(5001), "counter 5001 must still be marked seen");
    }

    #[test]
    fn test_session_set_stride_and_send_counter() {
        let (mut a, _) = crate::test_session_pair();
        assert_eq!(a.send_counter(), 0);
        assert_ne!(a.send_counter(), 1);

        a.set_stride(5, 4);
        assert_eq!(a.stride(), 4);
        assert_eq!(a.send_counter(), 5);

        a.set_stride(10, 0);
        assert_eq!(a.stride(), 1);
        assert_eq!(a.send_counter(), 5);

        a.set_stride(3, 4);
        assert_eq!(a.stride(), 4);
        assert_eq!(a.send_counter(), 7);
        assert_eq!(a.send_counter() % 4, 3);

        a.set_stride(1, 8);
        assert_eq!(a.stride(), 8);
        assert_eq!(a.send_counter(), 9);
        assert_eq!(a.send_counter() % 8, 1);
    }

    #[test]
    fn test_session_seal_in_place_and_open_in_place_boundaries() {
        let (mut a, mut b) = crate::test_session_pair();
        let mut buf = [0u8; 32];
        let ctr = a.seal_in_place(&mut buf[..16], 0).unwrap();
        assert_eq!(ctr, 0);

        assert_eq!(
            a.seal_in_place(&mut buf[..15], 0),
            Err(CryptoError::Decrypt)
        );

        assert_eq!(b.open_in_place(0, &mut buf, 15), Err(CryptoError::Decrypt));
        assert_eq!(b.open_in_place(0, &mut buf, 0), Err(CryptoError::Decrypt));

        assert_eq!(
            b.open_in_place(0, &mut buf[..10], 16),
            Err(CryptoError::Decrypt)
        );

        let mut exact = [0u8; 16];
        let ctr2 = a.seal_in_place(&mut exact, 0).unwrap();
        assert_eq!(b.open_in_place(ctr2, &mut exact, 16).unwrap(), 0);
    }

    #[test]
    fn pq_keypair_encapsulate_decapsulate_roundtrip() {
        let (ek, dk) = generate_pq_keypair();
        assert_eq!(ek.0.len(), PQ_ENCAPS_KEY_LEN);

        let (ct, ss_sender) = pq_encapsulate(&ek).expect("encapsulation succeeds");
        assert_eq!(ct.0.len(), PQ_CIPHERTEXT_LEN);
        assert_eq!(ss_sender.len(), PQ_SHARED_SECRET_LEN);

        let ss_recipient = pq_decapsulate(&dk, &ct).expect("decapsulation succeeds");
        assert_eq!(
            *ss_sender, *ss_recipient,
            "both sides agree on 32-byte shared secret"
        );
    }

    #[test]
    fn pq_encapsulate_rejects_fips203_invalid_modulus() {
        let (mut ek, _dk) = generate_pq_keypair();
        ek.0[0] = 0xFF;
        ek.0[1] = 0x0F;
        let res = pq_encapsulate(&ek);
        assert!(
            res.is_err(),
            "encapsulation must reject coefficient >= 3329"
        );
    }

    #[test]
    fn pq_decapsulate_implicit_rejection_on_tampered_ciphertext() {
        let (ek, dk) = generate_pq_keypair();
        let (mut ct, ss_sender) = pq_encapsulate(&ek).expect("encapsulation succeeds");

        ct.0[0] ^= 0x01;
        let ss_recipient =
            pq_decapsulate(&dk, &ct).expect("decapsulation succeeds via implicit rejection");
        assert_ne!(
            *ss_sender, *ss_recipient,
            "FIPS 203 implicit rejection must yield a distinct pseudorandom secret on tampered ciphertext"
        );
    }

    #[test]
    fn pq_decaps_key_debug_redacted() {
        let (_ek, dk) = generate_pq_keypair();
        assert_eq!(format!("{:?}", dk), "PqDecapsKey([REDACTED])");
    }

    #[test]
    fn pq_encapsulate_rejects_fips203_invalid_modulus_second_coeff() {
        let (mut ek, _dk) = generate_pq_keypair();
        ek.0[0] = 0x00;
        ek.0[1] = 0xF0;
        ek.0[2] = 0xFF;
        let res = pq_encapsulate(&ek);
        assert!(
            res.is_err(),
            "encapsulation must reject second coefficient >= 3329"
        );
    }

    #[test]
    fn pq_hybrid_handshake_roundtrip_with_payload() {
        let init_kp = generate_keypair();
        let resp_kp = generate_keypair();

        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let cert_a = b"initiator-test-certificate-128b";
        let cert_b = b"responder-test-certificate-128b";

        // Msg 1: Initiator -> Responder
        let msg1 = ini.write_message(cert_a).unwrap();
        assert_eq!(msg1.len(), FLIGHT_1_BASE_LEN + cert_a.len());

        let p1 = res.read_message(&msg1).unwrap();
        assert_eq!(p1, cert_a);
        assert_eq!(res.remote_static(), Some(init_kp.public));

        // Msg 2: Responder -> Initiator
        let msg2 = res.write_message(cert_b).unwrap();
        assert_eq!(msg2.len(), FLIGHT_2_BASE_LEN + cert_b.len());

        let p2 = ini.read_message(&msg2).unwrap();
        assert_eq!(p2, cert_b);
        assert_eq!(ini.remote_static(), Some(resp_kp.public));

        assert!(ini.is_finished());
        assert!(res.is_finished());
        assert_eq!(ini.channel_binding(), res.channel_binding());

        let (ini_send, ini_recv) = ini.raw_split_keys();
        let (res_send, res_recv) = res.raw_split_keys();
        assert_eq!(ini_send, res_recv);
        assert_eq!(ini_recv, res_send);

        let mut ini_session = ini.into_session().unwrap();
        let mut res_session = res.into_session().unwrap();
        let sealed = ini_session.seal(b"quantum safe transport payload").unwrap();
        let opened = res_session
            .open(sealed.counter, &sealed.ciphertext)
            .unwrap();
        assert_eq!(opened, b"quantum safe transport payload");
    }

    #[test]
    fn pq_hybrid_handshake_rejects_tampered_ciphertext() {
        let init_kp = generate_keypair();
        let resp_kp = generate_keypair();

        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let msg1 = ini.write_message(b"certA").unwrap();
        let _ = res.read_message(&msg1).unwrap();
        let mut msg2 = res.write_message(b"certB").unwrap();

        msg2[10] ^= 0x01;
        let err = ini.read_message(&msg2);
        assert!(
            err.is_err(),
            "tampered msg2 must fail handshake verification"
        );
    }

    #[test]
    fn pq_handshake_read_message_rejects_truncated_message() {
        let init_kp = generate_keypair();
        let resp_kp = generate_keypair();

        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let msg1 = ini.write_message(b"certA").unwrap();
        assert!(res.read_message(&msg1[..10]).is_err());

        // A failed read_message aborts that handshake state.
        // Use a fresh pair to test initiator rejection of truncated msg2.
        let mut ini2 = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res2 = Handshake::responder(&resp_kp.private).unwrap();
        let msg1_2 = ini2.write_message(b"certA").unwrap();
        let _ = res2.read_message(&msg1_2).unwrap();
        let msg2 = res2.write_message(b"certB").unwrap();

        let truncated = vec![0u8; FLIGHT_2_BASE_LEN - 1];
        assert!(ini2.read_message(&truncated).is_err());
        assert!(ini2.read_message(&msg2[..FLIGHT_2_BASE_LEN - 1]).is_err());
    }

    #[test]
    fn session_check_replay_is_non_committing() {
        let (a, mut b) = crate::test_session_pair();
        assert!(b.check_replay(1));
        assert!(b.check_replay(1));

        let sealed = a.seal_with_counter(1, b"hello").unwrap();
        let opened = b.open(sealed.counter, &sealed.ciphertext).unwrap();
        assert_eq!(opened, b"hello");

        assert!(!b.check_replay(1));
    }
}
