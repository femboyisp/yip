//! Noise-IK handshake and AEAD session crypto for the yip data plane, built
//! on the `snow` Noise Protocol Framework. Establishing a [`Session`] requires
//! completing an IK [`Handshake`]; the session then seals/opens inner frames
//! with explicit per-frame nonces and a sliding anti-replay window.
//!
//! `snow` drives the Noise handshake only. Once the handshake completes, the two
//! secret transport keys are extracted via snow's `dangerously_get_raw_split()`
//! (the same HKDF-derived bytes snow's own `split()` uses internally) and handed
//! to `ring`'s asm ChaCha20-Poly1305 for the data-plane hot path, keyed with the
//! Noise nonce convention (4 zero bytes ++ 8-byte little-endian counter). This is
//! byte-identical to snow's own transport state but faster.
#![forbid(unsafe_code)]

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

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

    /// Would `counter` be accepted right now? Read-only — does **not** mutate the
    /// window. On the receive path this gates AEAD verification cheaply, and the
    /// slot is only committed (via [`commit`](Self::commit)) once the frame
    /// authenticates, so a forged counter cannot advance the window.
    fn check(&self, counter: u64) -> bool {
        if !self.started {
            return true;
        }
        if counter > self.latest {
            true
        } else {
            let diff = self.latest - counter;
            if diff >= REPLAY_WINDOW_BITS {
                return false; // too old
            }
            self.bitmap & (1u64 << diff) == 0 // false ⇒ already seen (replay)
        }
    }

    /// Record `counter` as seen, advancing the window. The caller MUST have
    /// confirmed acceptance via [`check`](Self::check) first (and, on the
    /// receive path, AEAD verification); `counter` is therefore never too-old
    /// here, so the in-window shift is always in range.
    fn commit(&mut self, counter: u64) {
        if !self.started {
            self.started = true;
            self.latest = counter;
            self.bitmap = 1;
            return;
        }
        if counter > self.latest {
            let shift = counter - self.latest;
            self.bitmap = if shift >= REPLAY_WINDOW_BITS {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.latest = counter;
        } else {
            let diff = self.latest - counter;
            self.bitmap |= 1u64 << diff;
        }
    }

    /// Atomic check-and-set: accept `counter` if fresh, recording it. The receive
    /// path deliberately does **not** use this — it splits into
    /// [`check`](Self::check) → AEAD → [`commit`](Self::commit) so a forged frame
    /// cannot advance the window before it authenticates. Retained as a compact
    /// way to exercise the sliding-window math directly in unit tests.
    #[cfg(test)]
    fn check_and_set(&mut self, counter: u64) -> bool {
        if self.check(counter) {
            self.commit(counter);
            true
        } else {
            false
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

    /// Produce the next handshake message to send to the peer, carrying
    /// `payload` as the Noise app payload (encrypted per the pattern's
    /// current handshake state — msg1 under `es`, msg2 fully).
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; 4096];
        let n = self
            .inner
            .write_message(payload, &mut buf)
            .map_err(|_| CryptoError::Handshake)?;
        Ok(buf[..n].to_vec())
    }

    /// Consume a handshake message received from the peer, returning the
    /// decrypted app payload it carried (empty if none was written).
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; 4096];
        let n = self
            .inner
            .read_message(msg, &mut buf)
            .map_err(|_| CryptoError::Handshake)?;
        Ok(buf[..n].to_vec())
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

    /// The Noise channel-binding hash (snow's handshake hash), identical on both
    /// peers after the handshake completes. Use it to derive subkeys (e.g. the
    /// wire codec keys) bound to this session.
    pub fn channel_binding(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.inner.get_handshake_hash());
        out
    }

    /// Convert a completed handshake into an AEAD [`Session`].
    ///
    /// Extracts the two secret Noise transport keys via snow's raw split and
    /// builds `ring` AEAD keys from them directly; snow's own transport state is
    /// not used for the data plane. Per snow's split convention, element 0 of
    /// the pair is the initiator's send key (= responder's receive key) and
    /// element 1 is the responder's send key (= initiator's receive key), so
    /// the mapping below is role-dependent.
    pub fn into_session(mut self) -> Result<Session, CryptoError> {
        let is_initiator = self.inner.is_initiator();
        let (k0, k1) = self.inner.dangerously_get_raw_split();
        let (k_send, k_recv) = if is_initiator { (k0, k1) } else { (k1, k0) };
        let send =
            UnboundKey::new(&CHACHA20_POLY1305, &k_send).map_err(|_| CryptoError::Handshake)?;
        let recv =
            UnboundKey::new(&CHACHA20_POLY1305, &k_recv).map_err(|_| CryptoError::Handshake)?;
        Ok(Session {
            send_key: LessSafeKey::new(send),
            recv_key: LessSafeKey::new(recv),
            send_counter: 0,
            replay: ReplayWindow::new(),
        })
    }
}

/// Noise ChaChaPoly nonce: 4 zero bytes ++ 8-byte little-endian counter.
fn noise_nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(n)
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
///
/// Uses `ring`'s ChaCha20-Poly1305 keyed by the Noise Split() transport keys
/// (see [`Handshake::into_session`]) rather than snow's own transport state.
pub struct Session {
    send_key: LessSafeKey,
    recv_key: LessSafeKey,
    send_counter: u64,
    replay: ReplayWindow,
}

impl Session {
    /// Seal one inner frame, assigning it the next send counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let counter = self.send_counter;
        let mut buf = plaintext.to_vec();
        self.send_key
            .seal_in_place_append_tag(noise_nonce(counter), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
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
    /// The replay window is checked read-only *before* AEAD, then committed only
    /// *after* the frame authenticates (matching WireGuard, which advances its
    /// window post-decrypt). This ordering prevents a forged frame carrying an
    /// arbitrary counter from advancing the window and starving legitimate
    /// packets — an off-path DoS the mark-before-auth ordering was open to.
    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.replay.check(counter) {
            return Err(CryptoError::Replay);
        }
        let mut buf = ciphertext.to_vec();
        let plain = self
            .recv_key
            .open_in_place(noise_nonce(counter), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        self.replay.commit(counter);
        Ok(plain.to_vec())
    }

    /// Seal into a caller-owned reusable buffer (no per-call allocation).
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<u64, CryptoError> {
        let counter = self.send_counter;
        out.clear();
        out.extend_from_slice(plaintext);
        self.send_key
            .seal_in_place_append_tag(noise_nonce(counter), Aad::empty(), out)
            .map_err(|_| CryptoError::Decrypt)?;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or(CryptoError::Decrypt)?;
        Ok(counter)
    }

    /// Open into a caller-owned reusable buffer (no per-call allocation).
    pub fn open_into(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        if !self.replay.check(counter) {
            return Err(CryptoError::Replay);
        }
        out.clear();
        out.extend_from_slice(ciphertext);
        let n = {
            let plain = self
                .recv_key
                .open_in_place(noise_nonce(counter), Aad::empty(), out)
                .map_err(|_| CryptoError::Decrypt)?;
            plain.len()
        };
        self.replay.commit(counter);
        out.truncate(n);
        Ok(())
    }
}

/// Test-only helper: drive a full initiator/responder handshake to completion
/// and return the two established sessions. Mirrors `yip_bench::established_pair`.
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

    /// Advancing the window from counter A to B and then replaying A must be
    /// rejected.  Kills the `shift = counter + latest` mutant on the advance
    /// path (line 60) and the `bitmap << shift` → `bitmap >> shift` mutant on
    /// the same path (line 64): both mutations misplace the old-counter bits so
    /// the replay is no longer detected.
    #[test]
    fn replay_window_advance_then_replay_old_counter_rejected() {
        let mut w = ReplayWindow::new();
        // Establish counter 10 as the first-ever packet.
        assert!(w.check_and_set(10), "counter 10 accepted as first");
        // Advance to counter 15 (shift = 5 in real code; shift = 25 under the
        // `counter + latest` mutant, and bits shift wrong under `>> shift`).
        assert!(w.check_and_set(15), "advance to 15 accepted");
        // Counter 10 is now diff=5 from latest=15; its bit must still be set.
        assert!(
            !w.check_and_set(10),
            "replay of counter 10 after advance to 15 rejected"
        );
    }

    /// After advancing the window to a new latest, an immediate replay of that
    /// latest counter must be rejected.  Kills the `bitmap | 1` → `bitmap & 1`
    /// and `bitmap | 1` → `bitmap ^ 1` mutants: both can leave bit-0 of the
    /// new bitmap unset, making the just-accepted counter replayable.
    #[test]
    fn replay_window_new_latest_immediately_replayable_rejected() {
        let mut w = ReplayWindow::new();
        // Build a window where counter 9 is also recorded (bit 1 will be set
        // at latest=10), so that when we advance to 11 the shifted bitmap has
        // its LSB = 1.  Under `^ 1` that would clear bit-0, leaving latest-11
        // unprotected.
        assert!(w.check_and_set(10), "first packet at 10");
        assert!(w.check_and_set(9), "counter 9 accepted in-order-ish");
        // Advance from 10 to 11: shift=1, old bitmap has bit-1 set (counter 9).
        // `bitmap << 1` yields a value with LSB = old-bit-1 = 1.
        // Under `^ 1` that XORs the LSB back to 0, so the replay check below
        // would wrongly accept.
        assert!(w.check_and_set(11), "advance to 11 accepted");
        assert!(!w.check_and_set(11), "replay of new latest 11 rejected");
    }

    /// The `diff = self.latest - counter` on the in-window path (line 69) must
    /// use subtraction, not addition.  With `diff = latest + counter` the
    /// diff is 25 (not 5) for latest=15 counter=10, so bit-5 (which is set)
    /// is not checked and the replay slips through.
    #[test]
    fn replay_window_in_window_replay_rejected_after_advance() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(10), "first packet");
        assert!(w.check_and_set(15), "advance to 15");
        // Counter 10 is 5 below the new latest; real diff = 5, mutant diff = 25.
        // Both are < 64, but bit-5 is set while bit-25 is not.
        assert!(!w.check_and_set(10), "in-window replay at diff=5 rejected");
    }

    /// A freshly-built responder `Handshake` must not report `is_finished`
    /// before any messages have been exchanged.  Kills the mutant that
    /// replaces the `is_finished` body with `true` (line 150).
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
        // msg1 carries an app payload (the initiator's cert, in 2c); msg2
        // carries a different one (the responder's cert). Noise-IK encrypts
        // both (msg1 under `es`, msg2 fully), so this also documents that
        // certs never appear in cleartext on the wire.
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

        // Both sides derive the same channel binding (proof the payloads
        // didn't perturb the handshake transcript) before consuming into a
        // transport-mode session, then prove the sessions actually talk.
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
        // deliver 1 before 0
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

    /// A forged frame carrying a large counter but garbage ciphertext must fail
    /// AEAD *without* advancing the anti-replay window. Otherwise an off-path
    /// attacker who injects one such frame slides `latest` far forward, so every
    /// subsequent legitimate packet is rejected as "too old" — a session-killing
    /// DoS. The window slot must only be committed after AEAD verification.
    #[test]
    fn forged_frame_does_not_advance_replay_window() {
        let (mut a, mut b) = test_session_pair();
        let s0 = a.seal(b"zero").unwrap();
        let s1 = a.seal(b"one").unwrap();

        // Establish the receive window with a legitimate frame.
        assert_eq!(b.open(s0.counter, &s0.ciphertext).unwrap(), b"zero");

        // Off-path attacker injects a forged frame at a far-future counter.
        let garbage = vec![0u8; s0.ciphertext.len()];
        assert_eq!(
            b.open(1_000_000, &garbage),
            Err(CryptoError::Decrypt),
            "forged frame fails AEAD"
        );

        // The forged frame must not have moved the window: the next legitimate
        // in-flight frame still opens.
        assert_eq!(
            b.open(s1.counter, &s1.ciphertext).unwrap(),
            b"one",
            "legit frame still opens after forged far-future injection"
        );
    }

    /// Same invariant on the alloc-free `open_into` path.
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
        // IK: the responder learns the initiator's static public key.
        assert_eq!(res.remote_static(), Some(init_kp.public));
    }

    #[test]
    fn seal_is_byte_identical_across_a_reference_session() {
        // Two independently-built sessions from the same handshake produce the same
        // keystream for the same counter+plaintext; a receiver opens what a sender seals.
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
        assert_eq!(b.open(s1.counter, &s1.ciphertext).unwrap(), b"one"); // out of order
        assert_eq!(b.open(s0.counter, &s0.ciphertext).unwrap(), b"zero");
        assert_eq!(b.open(s1.counter, &s1.ciphertext), Err(CryptoError::Replay));
        // replay
    }

    /// Durable KAT (spec §5): the production `Session`'s `ring` ChaCha20-Poly1305
    /// output must be byte-for-byte identical to snow's own transport AEAD, for
    /// both handshake directions and several counters. This is the regression
    /// guard for `Handshake::into_session`'s role-dependent key mapping and for
    /// `noise_nonce`'s counter encoding: a swapped send/recv mapping or a
    /// big-endian (or otherwise wrong) nonce would still round-trip internally
    /// (seal/open use the same buggy convention on both sides) but would no
    /// longer match snow's genuine output, which this test would catch.
    ///
    /// `yip_crypto::Handshake` doesn't expose its inner `snow::HandshakeState`
    /// (nor the raw split keys) through its public API, and snow's
    /// `into_stateless_transport_mode()` / `into_session()` each consume the
    /// `HandshakeState` they're called on, so a single completed handshake can't
    /// yield both a production `Session` *and* a snow reference transport for
    /// the same peer. Instead we drive two independent, byte-identical
    /// handshakes side by side: snow's `fixed_ephemeral_key_for_testing_only`
    /// pins each peer's ephemeral key so the production `Handshake` (built by
    /// hand here, using the same private `inner` field the rest of this module
    /// uses) and a bare `snow::HandshakeState` reference derive the exact same
    /// transport keys from the exact same static+ephemeral inputs. The lockstep
    /// message-equality asserts below confirm the two handshakes really are
    /// identical, not just similarly configured.
    #[test]
    fn session_seal_is_byte_identical_to_snow_write_message_both_directions() {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();

        // Fixed (not secret) ephemeral scalars: same value reused by both the
        // production handshake and the snow reference handshake below, so the
        // two derive identical transport keys. X25519 clamps any 32 bytes into
        // a valid scalar, so the exact value doesn't matter.
        let e_init = [0x11u8; 32];
        let e_resp = [0x22u8; 32];

        let build_initiator = |e: &[u8]| {
            snow::Builder::new(NOISE_PARAMS.parse().unwrap())
                .local_private_key(&init_kp.private)
                .unwrap()
                .remote_public_key(&resp_kp.public)
                .unwrap()
                .fixed_ephemeral_key_for_testing_only(e)
                .build_initiator()
                .unwrap()
        };
        let build_responder = |e: &[u8]| {
            snow::Builder::new(NOISE_PARAMS.parse().unwrap())
                .local_private_key(&resp_kp.private)
                .unwrap()
                .fixed_ephemeral_key_for_testing_only(e)
                .build_responder()
                .unwrap()
        };

        // --- Production side: real `Handshake`s, hand-built here (same-crate
        // access to the private `inner` field) so the fixed ephemerals apply. ---
        let mut ini = Handshake {
            inner: build_initiator(&e_init),
        };
        let mut res = Handshake {
            inner: build_responder(&e_resp),
        };
        let m1 = ini.write_message(&[]).unwrap();
        let _ = res.read_message(&m1).unwrap();
        let m2 = res.write_message(&[]).unwrap();
        let _ = ini.read_message(&m2).unwrap();
        assert!(ini.is_finished() && res.is_finished());

        // --- Reference side: independent raw snow HandshakeStates, same
        // static + fixed-ephemeral inputs, driven through the same two
        // messages in lockstep. ---
        let mut snow_ini = build_initiator(&e_init);
        let mut snow_res = build_responder(&e_resp);
        let mut buf = [0u8; 4096];
        let n = snow_ini.write_message(&[], &mut buf).unwrap();
        let snow_m1 = buf[..n].to_vec();
        assert_eq!(snow_m1, m1, "lockstep: reference msg1 == production msg1");
        let n = snow_res.read_message(&snow_m1, &mut buf).unwrap();
        let _ = &buf[..n];
        let n = snow_res.write_message(&[], &mut buf).unwrap();
        let snow_m2 = buf[..n].to_vec();
        assert_eq!(snow_m2, m2, "lockstep: reference msg2 == production msg2");
        let n = snow_ini.read_message(&snow_m2, &mut buf).unwrap();
        let _ = &buf[..n];
        assert!(snow_ini.is_handshake_finished() && snow_res.is_handshake_finished());

        // Sanity: both independently-driven handshakes derive the identical
        // Noise split keys before either is consumed below.
        assert_eq!(
            ini.inner.dangerously_get_raw_split(),
            snow_ini.dangerously_get_raw_split(),
            "production and reference derive identical split keys"
        );

        // Convert: production side through the real `into_session()` (the
        // code path under test); reference side through snow's own
        // `into_stateless_transport_mode()` (snow's genuine transport AEAD).
        let mut ini_session = ini.into_session().unwrap();
        let mut res_session = res.into_session().unwrap();
        let snow_ini_ref = snow_ini.into_stateless_transport_mode().unwrap();
        let snow_res_ref = snow_res.into_stateless_transport_mode().unwrap();

        let plaintext: Vec<u8> = (0u8..200).collect();

        // initiator -> responder: production seal byte-identical to snow's
        // write_message (initiator role), and the responder session opens it.
        for ctr in 0u64..=4 {
            let sealed = ini_session.seal(&plaintext).unwrap();
            assert_eq!(sealed.counter, ctr);
            let mut snow_out = vec![0u8; plaintext.len() + 16];
            let n = snow_ini_ref
                .write_message(ctr, &plaintext, &mut snow_out)
                .unwrap();
            snow_out.truncate(n);
            assert_eq!(
                sealed.ciphertext, snow_out,
                "initiator->responder ciphertext byte-identical to snow at counter {ctr}"
            );
            assert_eq!(
                res_session
                    .open(sealed.counter, &sealed.ciphertext)
                    .unwrap(),
                plaintext,
                "responder opens what the initiator sealed at counter {ctr}"
            );
        }

        // responder -> initiator: the symmetric case.
        for ctr in 0u64..=4 {
            let sealed = res_session.seal(&plaintext).unwrap();
            assert_eq!(sealed.counter, ctr);
            let mut snow_out = vec![0u8; plaintext.len() + 16];
            let n = snow_res_ref
                .write_message(ctr, &plaintext, &mut snow_out)
                .unwrap();
            snow_out.truncate(n);
            assert_eq!(
                sealed.ciphertext, snow_out,
                "responder->initiator ciphertext byte-identical to snow at counter {ctr}"
            );
            assert_eq!(
                ini_session
                    .open(sealed.counter, &sealed.ciphertext)
                    .unwrap(),
                plaintext,
                "initiator opens what the responder sealed at counter {ctr}"
            );
        }
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
}
