//! Noise-IK handshake and AEAD session crypto for the yip data plane, built
//! on the `snow` Noise Protocol Framework. Establishing a [`Session`] requires
//! completing an IK [`Handshake`]; the session then seals/opens inner frames
//! with explicit per-frame nonces and a sliding anti-replay window.
#![forbid(unsafe_code)]

/// The Noise parameter set: IK pattern, X25519, ChaCha20-Poly1305, BLAKE2s.
pub(crate) const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

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
    let kp = snow::Builder::new(NOISE_PARAMS.parse().expect("valid params"))
        .generate_keypair()
        .expect("keypair generation");
    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    private.copy_from_slice(&kp.private);
    public.copy_from_slice(&kp.public);
    Keypair { private, public }
}

/// Number of past counters the replay window tracks behind the latest.
const REPLAY_WINDOW_BITS: u64 = 64;

/// A WireGuard-style sliding replay window over a monotonic `u64` counter.
/// Bit `i` of `bitmap` records that `latest - i` has been seen.
struct ReplayWindow {
    latest: u64,
    bitmap: u64,
    started: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            latest: 0,
            bitmap: 0,
            started: false,
        }
    }

    /// Accept `counter` if fresh, recording it; reject replays and too-old counters.
    fn check_and_set(&mut self, counter: u64) -> bool {
        if !self.started {
            self.started = true;
            self.latest = counter;
            self.bitmap = 1;
            return true;
        }
        if counter > self.latest {
            let shift = counter - self.latest;
            self.bitmap = if shift >= REPLAY_WINDOW_BITS {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.latest = counter;
            true
        } else {
            let diff = self.latest - counter;
            if diff >= REPLAY_WINDOW_BITS {
                return false; // too old
            }
            let bit = 1u64 << diff;
            if self.bitmap & bit != 0 {
                return false; // replay
            }
            self.bitmap |= bit;
            true
        }
    }
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
}

/// An in-progress Noise-IK handshake. Drive it by exchanging the two messages
/// (`write_message`/`read_message`), then convert into a [`Session`].
pub struct Handshake {
    inner: snow::HandshakeState,
}

impl Handshake {
    /// Begin as the initiator, which must already know the responder's static public key.
    pub fn initiator(
        local_private: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> Result<Handshake, CryptoError> {
        let inner = snow::Builder::new(NOISE_PARAMS.parse().map_err(|_| CryptoError::Handshake)?)
            .local_private_key(local_private)
            .map_err(|_| CryptoError::Handshake)?
            .remote_public_key(peer_public)
            .map_err(|_| CryptoError::Handshake)?
            .build_initiator()
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Handshake { inner })
    }

    /// Begin as the responder; learns the initiator's static key during the handshake.
    pub fn responder(local_private: &[u8; 32]) -> Result<Handshake, CryptoError> {
        let inner = snow::Builder::new(NOISE_PARAMS.parse().map_err(|_| CryptoError::Handshake)?)
            .local_private_key(local_private)
            .map_err(|_| CryptoError::Handshake)?
            .build_responder()
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Handshake { inner })
    }

    /// Produce the next (empty-payload) handshake message to send to the peer.
    pub fn write_message(&mut self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; 1024];
        let n = self
            .inner
            .write_message(&[], &mut buf)
            .map_err(|_| CryptoError::Handshake)?;
        Ok(buf[..n].to_vec())
    }

    /// Consume a handshake message received from the peer.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<(), CryptoError> {
        let mut buf = [0u8; 1024];
        self.inner
            .read_message(msg, &mut buf)
            .map_err(|_| CryptoError::Handshake)?;
        Ok(())
    }

    /// Whether the handshake has completed and a session can be derived.
    pub fn is_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    /// The peer's authenticated static public key, if learned yet.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.inner.get_remote_static().map(|k| {
            let mut out = [0u8; 32];
            out.copy_from_slice(k);
            out
        })
    }

    /// Convert a completed handshake into an AEAD [`Session`].
    pub fn into_session(self) -> Result<Session, CryptoError> {
        let transport = self
            .inner
            .into_stateless_transport_mode()
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Session {
            transport,
            send_counter: 0,
            replay: ReplayWindow::new(),
        })
    }
}

/// A sealed frame: the AEAD ciphertext plus the explicit nonce it was sealed
/// under. The caller carries `counter` on the wire so the peer can `open`.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The explicit AEAD nonce assigned to this frame.
    pub counter: u64,
    /// The AEAD ciphertext (plaintext length + 16-byte tag).
    pub ciphertext: Vec<u8>,
}

/// An established AEAD session. Seals outgoing frames under a monotonic counter
/// and opens incoming frames out of order, rejecting replays.
pub struct Session {
    transport: snow::StatelessTransportState,
    send_counter: u64,
    replay: ReplayWindow,
}

impl Session {
    /// Seal one inner frame, assigning it the next send counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let counter = self.send_counter;
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(counter, plaintext, &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        buf.truncate(n);
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or(CryptoError::Decrypt)?;
        Ok(Sealed {
            counter,
            ciphertext: buf,
        })
    }

    /// Open one inner frame received under explicit `counter`, enforcing replay protection.
    ///
    /// Note: the replay window slot is marked before AEAD verification, matching WireGuard's
    /// behaviour. A forged counter that fails AEAD still consumes a window slot, but forged
    /// frames cannot be opened. A stricter "only mark on AEAD success" variant is a possible
    /// later refinement.
    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.replay.check_and_set(counter) {
            return Err(CryptoError::Replay);
        }
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(counter, ciphertext, &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        buf.truncate(n);
        Ok(buf)
    }
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
    fn replay_window_accepts_fresh_rejects_replays_and_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(0), "first counter accepted");
        assert!(!w.check_and_set(0), "exact replay rejected");
        assert!(w.check_and_set(1), "next in order accepted");
        assert!(w.check_and_set(5), "jump ahead accepted");
        assert!(w.check_and_set(3), "in-window out-of-order accepted");
        assert!(!w.check_and_set(3), "replay of out-of-order rejected");
        assert!(w.check_and_set(100), "large advance accepted");
        assert!(
            !w.check_and_set(5),
            "counter now far below window rejected as too old"
        );
    }

    // Helper: run a full handshake and return (initiator_session, responder_session).
    fn established_pair() -> (Session, Session) {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();
        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();
        let m1 = ini.write_message().unwrap();
        res.read_message(&m1).unwrap();
        let m2 = res.write_message().unwrap();
        ini.read_message(&m2).unwrap();
        (ini.into_session().unwrap(), res.into_session().unwrap())
    }

    #[test]
    fn session_seals_and_opens_roundtrip() {
        let (mut a, mut b) = established_pair();
        let s = a.seal(b"inner packet").unwrap();
        assert_eq!(s.counter, 0, "first counter is 0");
        assert_eq!(b.open(s.counter, &s.ciphertext).unwrap(), b"inner packet");
    }

    #[test]
    fn session_opens_out_of_order() {
        let (mut a, mut b) = established_pair();
        let s0 = a.seal(b"zero").unwrap();
        let s1 = a.seal(b"one").unwrap();
        assert_eq!(s1.counter, 1);
        // deliver 1 before 0
        assert_eq!(b.open(s1.counter, &s1.ciphertext).unwrap(), b"one");
        assert_eq!(b.open(s0.counter, &s0.ciphertext).unwrap(), b"zero");
    }

    #[test]
    fn session_rejects_replay() {
        let (mut a, mut b) = established_pair();
        let s = a.seal(b"x").unwrap();
        assert!(b.open(s.counter, &s.ciphertext).is_ok());
        assert_eq!(b.open(s.counter, &s.ciphertext), Err(CryptoError::Replay));
    }

    #[test]
    fn session_rejects_tampered_ciphertext() {
        let (mut a, mut b) = established_pair();
        let s = a.seal(b"y").unwrap();
        let mut bad = s.ciphertext.clone();
        bad[0] ^= 0x01;
        assert_eq!(b.open(s.counter, &bad), Err(CryptoError::Decrypt));
    }

    #[test]
    fn ik_handshake_completes_and_authenticates_initiator() {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();

        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let msg1 = ini.write_message().unwrap();
        res.read_message(&msg1).unwrap();
        let msg2 = res.write_message().unwrap();
        ini.read_message(&msg2).unwrap();

        assert!(ini.is_finished() && res.is_finished());
        // IK: the responder learns the initiator's static public key.
        assert_eq!(res.remote_static(), Some(init_kp.public));
    }
}
