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

/// Standard profile replay window parameters (1 KB bitmap).
pub const REPLAY_WINDOW_BITS_STANDARD: u64 = 8_192;
pub const REPLAY_WORDS_STANDARD: usize = 128;

/// HighThroughput profile replay window parameters (16 KB bitmap).
pub const REPLAY_WINDOW_BITS_HIGH_THROUGHPUT: u64 = 131_072;
pub const REPLAY_WORDS_HIGH_THROUGHPUT: usize = 2048;

/// Number of past counters the replay window tracks behind the latest in HighThroughput mode.
pub const REPLAY_WINDOW_BITS: u64 = REPLAY_WINDOW_BITS_HIGH_THROUGHPUT;
pub const REPLAY_WORDS: usize = REPLAY_WORDS_HIGH_THROUGHPUT;

/// Sizing profile for the sliding replay window bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayProfile {
    /// 1 KB bitmap tracking 8,192 bits behind the latest seen counter.
    /// Fits tightly into L1/L2 cache for standard latency-critical connections.
    Standard,
    /// 16 KB bitmap tracking 131,072 bits behind the latest seen counter.
    /// Designed for multi-gigabit multi-core pipelines absorbing high burst jitter.
    HighThroughput,
}

impl ReplayProfile {
    /// Number of past counters tracked behind the latest counter.
    #[inline]
    pub const fn bits(self) -> u64 {
        match self {
            Self::Standard => REPLAY_WINDOW_BITS_STANDARD,
            Self::HighThroughput => REPLAY_WINDOW_BITS_HIGH_THROUGHPUT,
        }
    }

    /// Number of 64-bit words in the circular ring bitmap.
    #[inline]
    pub const fn words(self) -> usize {
        match self {
            Self::Standard => REPLAY_WORDS_STANDARD,
            Self::HighThroughput => REPLAY_WORDS_HIGH_THROUGHPUT,
        }
    }
}

/// A wide sliding replay window over a monotonic `u64` counter using a circular word ring.
#[derive(Clone)]
pub struct ReplayWindow {
    profile: ReplayProfile,
    latest: u64,
    bitmap: Box<[u64]>,
    started: bool,
}

impl ReplayWindow {
    /// Create a replay window with the default `HighThroughput` profile (16 KB / 131,072 bits).
    pub fn new() -> Self {
        Self::new_with_profile(ReplayProfile::HighThroughput)
    }

    /// Create a replay window configured with a specific sizing profile.
    pub fn new_with_profile(profile: ReplayProfile) -> Self {
        let words = profile.words();
        Self {
            profile,
            latest: 0,
            bitmap: vec![0u64; words].into_boxed_slice(),
            started: false,
        }
    }

    /// Current sizing profile of the replay window.
    pub fn profile(&self) -> ReplayProfile {
        self.profile
    }

    /// Dynamically promote window capacity to `HighThroughput` (16 KB / 131,072 bits).
    /// Preserves all previously seen counters without dropping replay protection.
    pub fn promote_to_high_throughput(&mut self) {
        if self.profile == ReplayProfile::HighThroughput {
            return;
        }
        let old_words = self.bitmap.len();
        let new_words = ReplayProfile::HighThroughput.words();
        let mut new_bitmap = vec![0u64; new_words].into_boxed_slice();

        if self.started {
            let latest_word = self.latest / 64;
            let start_word = latest_word.saturating_sub((old_words - 1) as u64);
            for w in start_word..=latest_word {
                let old_idx = (w as usize) & (old_words - 1);
                let new_idx = (w as usize) & (new_words - 1);
                new_bitmap[new_idx] = self.bitmap[old_idx];
            }
        }

        self.profile = ReplayProfile::HighThroughput;
        self.bitmap = new_bitmap;
    }

    #[inline]
    fn word_idx(&self, counter: u64) -> usize {
        ((counter / 64) as usize) & (self.bitmap.len() - 1)
    }

    #[inline]
    fn bit_mask(counter: u64) -> u64 {
        1u64 << (counter % 64)
    }

    /// Would `counter` be accepted right now? Read-only — does not mutate state.
    pub fn check(&self, counter: u64) -> bool {
        if !self.started {
            return true;
        }
        if counter > self.latest {
            true
        } else {
            let diff = self.latest - counter;
            if diff >= self.profile.bits() {
                return false; // too old
            }
            let idx = self.word_idx(counter);
            let mask = Self::bit_mask(counter);
            (self.bitmap[idx] & mask) == 0
        }
    }

    /// Record `counter` as seen, advancing the window. Must be preceded by check().
    pub fn commit(&mut self, counter: u64) {
        if !self.started {
            self.started = true;
            self.latest = counter;
            let idx = self.word_idx(counter);
            self.bitmap[idx] = Self::bit_mask(counter);
            return;
        }

        if counter > self.latest {
            let diff = counter - self.latest;
            let window_bits = self.profile.bits();
            let total_words = self.bitmap.len();
            if diff >= window_bits {
                // Large leap: clear entire bitmap
                self.bitmap.fill(0);
            } else {
                // Clear any words in the circular ring that were overtaken
                let old_word = self.latest / 64;
                let new_word = counter / 64;
                if new_word > old_word {
                    let words_to_clear = ((new_word - old_word) as usize).min(total_words);
                    for w in 1..=words_to_clear {
                        let idx = ((old_word + w as u64) as usize) & (total_words - 1);
                        self.bitmap[idx] = 0;
                    }
                }
            }
            self.latest = counter;
            let idx = self.word_idx(counter);
            self.bitmap[idx] |= Self::bit_mask(counter);
        } else {
            let diff = self.latest - counter;
            if diff < self.profile.bits() {
                let idx = self.word_idx(counter);
                self.bitmap[idx] |= Self::bit_mask(counter);
            }
        }
    }

    /// Convenience helper to check and commit a counter in one step.
    /// Used by test harnesses and benchmark suites.
    pub fn check_and_set(&mut self, counter: u64) -> bool {
        if self.check(counter) {
            self.commit(counter);
            true
        } else {
            false
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
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
    inner: std::sync::Mutex<snow::HandshakeState>,
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
        Ok(Handshake {
            inner: std::sync::Mutex::new(inner),
        })
    }

    /// Begin as the responder; learns the initiator's static key during the handshake.
    pub fn responder(local_private: &[u8; 32]) -> Result<Handshake, CryptoError> {
        let inner = snow::Builder::new(NOISE_PARAMS.parse().map_err(|_| CryptoError::Handshake)?)
            .local_private_key(local_private)
            .map_err(|_| CryptoError::Handshake)?
            .build_responder()
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Handshake {
            inner: std::sync::Mutex::new(inner),
        })
    }

    /// Produce the next handshake message to send to the peer, carrying
    /// `payload` as the Noise app payload (encrypted per the pattern's
    /// current handshake state — msg1 under `es`, msg2 fully).
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; 4096];
        let n = self
            .inner
            .get_mut()
            .expect("handshake lock")
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
            .get_mut()
            .expect("handshake lock")
            .read_message(msg, &mut buf)
            .map_err(|_| CryptoError::Handshake)?;
        Ok(buf[..n].to_vec())
    }

    /// Whether the handshake has completed and a session can be derived.
    pub fn is_finished(&self) -> bool {
        self.inner
            .lock()
            .expect("handshake lock")
            .is_handshake_finished()
    }

    /// The peer's authenticated static public key, if learned yet.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("handshake lock")
            .get_remote_static()
            .map(|k| {
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
        out.copy_from_slice(
            self.inner
                .lock()
                .expect("handshake lock")
                .get_handshake_hash(),
        );
        out
    }

    /// Extract the two raw 32-byte secret Noise transport keys (send key, recv key)
    /// derived from the handshake.
    pub fn raw_split_keys(&self) -> ([u8; 32], [u8; 32]) {
        let mut inner = self.inner.lock().expect("handshake lock");
        let is_initiator = inner.is_initiator();
        let (k0, k1) = inner.dangerously_get_raw_split();
        if is_initiator {
            (k0, k1)
        } else {
            (k1, k0)
        }
    }

    /// Convert a completed handshake into an AEAD [`Session`].
    ///
    /// Extracts the two secret Noise transport keys via snow's raw split and
    /// builds `ring` AEAD keys from them directly; snow's own transport state is
    /// not used for the data plane. Per snow's split convention, element 0 of
    /// the pair is the initiator's send key (= responder's receive key) and
    /// element 1 is the responder's send key (= initiator's receive key), so
    /// the mapping below is role-dependent.
    pub fn into_session(self) -> Result<Session, CryptoError> {
        let (k_send, k_recv) = self.raw_split_keys();
        Session::from_raw_keys(&k_send, &k_recv, 0, 1)
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
    stride: u64,
    replay: ReplayWindow,
}

impl Session {
    /// Construct a session directly from raw 32-byte send and receive keys,
    /// with an explicit start counter and stride increment (e.g. for worker sharding).
    pub fn from_raw_keys(
        k_send: &[u8; 32],
        k_recv: &[u8; 32],
        start_counter: u64,
        stride: u64,
    ) -> Result<Self, CryptoError> {
        let send =
            UnboundKey::new(&CHACHA20_POLY1305, k_send).map_err(|_| CryptoError::Handshake)?;
        let recv =
            UnboundKey::new(&CHACHA20_POLY1305, k_recv).map_err(|_| CryptoError::Handshake)?;
        Ok(Session {
            send_key: LessSafeKey::new(send),
            recv_key: LessSafeKey::new(recv),
            send_counter: start_counter,
            stride: if stride == 0 { 1 } else { stride },
            replay: ReplayWindow::new(),
        })
    }

    /// Reconfigure the send counter and stride increment for this session.
    pub fn set_stride(&mut self, start_counter: u64, stride: u64) {
        let stride = if stride == 0 { 1 } else { stride };
        if self.send_counter == 0 {
            self.send_counter = start_counter;
        } else {
            let rem = self.send_counter % stride;
            let target_rem = start_counter % stride;
            let diff = if rem <= target_rem {
                target_rem - rem
            } else {
                stride - (rem - target_rem)
            };
            self.send_counter = self.send_counter.saturating_add(diff);
        }
        self.stride = stride;
    }

    /// The current nonce stride increment.
    pub fn stride(&self) -> u64 {
        self.stride
    }

    /// The current send counter.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Seal one inner frame, assigning it the next send counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let counter = self.send_counter;
        let mut buf = plaintext.to_vec();
        self.send_key
            .seal_in_place_append_tag(noise_nonce(counter), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        self.send_counter = self
            .send_counter
            .checked_add(self.stride)
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
            .checked_add(self.stride)
            .ok_or(CryptoError::Decrypt)?;
        Ok(counter)
    }

    /// Seal one inner frame under an explicit counter, without mutating internal counter.
    /// This allows multi-threaded workers sharing a single peer connection to seal
    /// concurrently using nonces dispensed from a ChunkedNonceDispenser.
    pub fn seal_with_counter(&self, counter: u64, plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let mut buf = plaintext.to_vec();
        self.send_key
            .seal_in_place_append_tag(noise_nonce(counter), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(Sealed {
            counter,
            ciphertext: buf,
        })
    }

    /// Seal into a caller-owned reusable buffer under an explicit counter.
    pub fn seal_into_with_counter(
        &self,
        counter: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        out.clear();
        out.extend_from_slice(plaintext);
        self.send_key
            .seal_in_place_append_tag(noise_nonce(counter), Aad::empty(), out)
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(())
    }

    /// Open one inner frame received under explicit counter against a caller-provided replay window.
    pub fn open_with_window(
        &self,
        counter: u64,
        ciphertext: &[u8],
        replay: &mut ReplayWindow,
    ) -> Result<Vec<u8>, CryptoError> {
        if !replay.check(counter) {
            return Err(CryptoError::Replay);
        }
        let mut buf = ciphertext.to_vec();
        let plain = self
            .recv_key
            .open_in_place(noise_nonce(counter), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        replay.commit(counter);
        Ok(plain.to_vec())
    }

    /// Open into a caller-owned reusable buffer under explicit counter against a caller-provided replay window.
    pub fn open_into_with_window(
        &self,
        counter: u64,
        ciphertext: &[u8],
        replay: &mut ReplayWindow,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        if !replay.check(counter) {
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
        replay.commit(counter);
        out.truncate(n);
        Ok(())
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

    /// Seal plaintext in-place inside `buf[..plaintext_len]`, writing the 16-byte Poly1305
    /// authentication tag immediately following the ciphertext into `buf[plaintext_len..plaintext_len + 16]`.
    ///
    /// The buffer must have capacity of at least `plaintext_len + 16` bytes.
    /// Returns the explicit counter assigned to this frame.
    pub fn seal_in_place(
        &mut self,
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<u64, CryptoError> {
        let counter = self.send_counter;
        let total_len = plaintext_len.checked_add(16).ok_or(CryptoError::Decrypt)?;
        if buf.len() < total_len {
            return Err(CryptoError::Decrypt);
        }
        let (in_out, tag_out) = buf[..total_len].split_at_mut(plaintext_len);
        let tag = self
            .send_key
            .seal_in_place_separate_tag(noise_nonce(counter), Aad::empty(), in_out)
            .map_err(|_| CryptoError::Decrypt)?;
        tag_out.copy_from_slice(tag.as_ref());
        self.send_counter = self
            .send_counter
            .checked_add(self.stride)
            .ok_or(CryptoError::Decrypt)?;
        Ok(counter)
    }

    /// Open and authenticate ciphertext in-place inside `buf[..sealed_len]`, enforcing anti-replay.
    ///
    /// Expects the 16-byte Poly1305 authentication tag at the end of the ciphertext:
    /// `buf[sealed_len - 16..sealed_len]`.
    /// Returns the decrypted plaintext length (`sealed_len - 16`).
    pub fn open_in_place(
        &mut self,
        counter: u64,
        buf: &mut [u8],
        sealed_len: usize,
    ) -> Result<usize, CryptoError> {
        if !self.replay.check(counter) {
            return Err(CryptoError::Replay);
        }
        if sealed_len < 16 || buf.len() < sealed_len {
            return Err(CryptoError::Decrypt);
        }
        let plain = self
            .recv_key
            .open_in_place(noise_nonce(counter), Aad::empty(), &mut buf[..sealed_len])
            .map_err(|_| CryptoError::Decrypt)?;
        self.replay.commit(counter);
        Ok(plain.len())
    }
}

/// ChaCha20-Poly1305 AEAD cipher supporting zero-copy in-place encryption and decryption
/// directly within pre-allocated network packet buffers (such as AF_XDP UMEM chunks).
pub struct ChaCha20Poly1305Cipher {
    key: LessSafeKey,
}

impl std::fmt::Debug for ChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305Cipher")
            .finish_non_exhaustive()
    }
}

impl ChaCha20Poly1305Cipher {
    /// Creates a new cipher instance from a 32-byte symmetric key.
    pub fn new(key: [u8; 32]) -> Self {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key)
            .expect("32-byte key is valid for ChaCha20-Poly1305");
        Self {
            key: LessSafeKey::new(unbound),
        }
    }

    /// Seal plaintext in-place inside `buf[..plaintext_len]`, writing the 16-byte Poly1305
    /// authentication tag immediately following the ciphertext into `buf[plaintext_len..plaintext_len + 16]`.
    ///
    /// The buffer must have capacity of at least `plaintext_len + 16` bytes.
    /// Returns the total sealed ciphertext length (`plaintext_len + 16`).
    pub fn seal_in_place(
        &self,
        counter: u64,
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        let total_len = plaintext_len.checked_add(16).ok_or(CryptoError::Decrypt)?;
        if buf.len() < total_len {
            return Err(CryptoError::Decrypt);
        }
        let (in_out, tag_out) = buf[..total_len].split_at_mut(plaintext_len);
        let tag = self
            .key
            .seal_in_place_separate_tag(noise_nonce(counter), Aad::empty(), in_out)
            .map_err(|_| CryptoError::Decrypt)?;
        tag_out.copy_from_slice(tag.as_ref());
        Ok(total_len)
    }

    /// Open and authenticate ciphertext in-place inside `buf[..sealed_len]`.
    ///
    /// Expects the 16-byte Poly1305 authentication tag at the end of the ciphertext:
    /// `buf[sealed_len - 16..sealed_len]`.
    /// Returns the decrypted plaintext length (`sealed_len - 16`).
    pub fn open_in_place(
        &self,
        counter: u64,
        buf: &mut [u8],
        sealed_len: usize,
    ) -> Result<usize, CryptoError> {
        if sealed_len < 16 || buf.len() < sealed_len {
            return Err(CryptoError::Decrypt);
        }
        let plain = self
            .key
            .open_in_place(noise_nonce(counter), Aad::empty(), &mut buf[..sealed_len])
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(plain.len())
    }

    /// Open and authenticate ciphertext in-place, verifying against a sliding anti-replay window.
    ///
    /// The replay window is checked before AEAD decryption and committed only upon
    /// successful authentication.
    pub fn open_in_place_with_window(
        &self,
        counter: u64,
        buf: &mut [u8],
        sealed_len: usize,
        replay: &mut ReplayWindow,
    ) -> Result<usize, CryptoError> {
        if !replay.check(counter) {
            return Err(CryptoError::Replay);
        }
        let plain_len = self.open_in_place(counter, buf, sealed_len)?;
        replay.commit(counter);
        Ok(plain_len)
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

    /// `channel_binding` must be a genuine, transcript-dependent hash — not a
    /// constant. Kills the `replace channel_binding -> [u8; 32] with [1; 32]`
    /// mutant (line 207): two independently-keyed handshakes must derive
    /// DIFFERENT bindings, and neither may equal the all-ones constant.
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
        assert_ne!(
            binding_a, [1u8; 32],
            "channel_binding must not be the constant [1; 32]"
        );
        assert_ne!(
            binding_b, [1u8; 32],
            "channel_binding must not be the constant [1; 32]"
        );
        assert_ne!(
            binding_a, binding_b,
            "two independent handshakes (different keys/transcripts) must \
             derive different channel bindings"
        );
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
            inner: std::sync::Mutex::new(build_initiator(&e_init)),
        };
        let mut res = Handshake {
            inner: std::sync::Mutex::new(build_responder(&e_resp)),
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
            ini.inner.lock().unwrap().dangerously_get_raw_split(),
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

    #[test]
    fn test_wide_replay_window_jitter_and_rejection() {
        let mut w = ReplayWindow::new();
        // Initially accepts 0
        assert!(w.check(0));
        w.commit(0);

        // Advance latest to 100,000
        assert!(w.check(100_000));
        w.commit(100_000);

        // Packet 50,000 (diff = 50,000 < 131,072) must be accepted
        assert!(w.check(50_000));
        w.commit(50_000);

        // Duplicate 50,000 must be rejected
        assert!(!w.check(50_000));

        // Packet 0 is now 100,000 behind, which is < 131,072, but it was already seen
        assert!(!w.check(0));

        // Advance to 250,000
        assert!(w.check(250_000));
        w.commit(250_000);

        // Packet 100,000 is 150,000 behind (>= 131,072), must be rejected as too old
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

        // Replay attempt must fail
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

        // Replay rejection
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
        // Exact buffer length (buf.len() == plaintext_len + 16): must succeed
        assert_eq!(cipher.seal_in_place(1, &mut buf[..16], 0).unwrap(), 16);

        // Buffer smaller than total_len (buf.len() < plaintext_len + 16): must fail
        assert_eq!(
            cipher.seal_in_place(1, &mut buf[..15], 0),
            Err(CryptoError::Decrypt)
        );

        // open_in_place: sealed_len < 16 must fail
        assert_eq!(
            cipher.open_in_place(1, &mut buf, 15),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            cipher.open_in_place(1, &mut buf, 0),
            Err(CryptoError::Decrypt)
        );

        // open_in_place: buf.len() < sealed_len must fail (even when sealed_len >= 16)
        assert_eq!(
            cipher.open_in_place(1, &mut buf[..10], 16),
            Err(CryptoError::Decrypt)
        );

        // open_in_place: exact boundary sealed_len == 16 and buf.len() == 16
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

        // Replay attempt must fail and not modify output buffer
        out.clear();
        let err = b.open_into_with_window(42, &sealed_buf, &mut replay, &mut out);
        assert_eq!(err, Err(CryptoError::Replay));
        assert!(out.is_empty());

        // Forged tag must fail
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
        // Counters across different word indices (64, 128) must not falsely collide with 0
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
        // Case 1: latest_word is small (< old_words = 128 words).
        // latest_word = 10, so saturating_sub(127) == 0.
        // Under mutant `old_words + 1` = 129, saturating_sub(129) == 0 (no diff).
        // But under mutant `old_words / 1` = 128, saturating_sub(128) == 0.
        //
        // Case 2: latest_word >= old_words (e.g. latest_word = 200).
        // start_word should be 200 - 127 = 73.
        // Under mutant `+`: (old_words + 1) = 129 -> 200 - 129 = 71.
        // Under mutant `/`: (old_words / 1) = 128 -> 200 - 128 = 72.
        // Counter at word 72 is (72 * 64). Under the correct code (start_word = 73),
        // word 72 is NOT copied (it's older than 127 words from latest).
        // BUT wait: in standard window of 128 words, word 72 is diff = 200 - 72 = 128 words = 8192 bits!
        // 8192 bits is beyond standard window bits (8192), so its slot in old_bitmap is actually word 200's slot!
        // Notice: 72 & 127 = 72. 200 & 127 = 72!
        // If word 72 is copied to new_bitmap[72], while word 200 is copied to new_bitmap[200],
        // then word 72 in new_bitmap would receive the contents of old_bitmap[72]!
        // In the correct code (start_word = 73), word 72 is NOT visited, so new_bitmap[72] is 0!
        // Under mutant `+` or `/`: start_word <= 72, so loop visits w = 72 and copies old_bitmap[72] into new_bitmap[72]!
        // Therefore, counter (72 * 64 + bit) would falsely appear as committed in new_bitmap!
        let mut w = ReplayWindow::new_with_profile(ReplayProfile::Standard);
        let latest = 200 * 64 + 10;
        w.commit(latest);
        w.promote_to_high_throughput();

        // Counter at word 72 (e.g. 72 * 64 + 10) was never committed (it is 128 words older than latest).
        // In correct code, new_bitmap[72] == 0, so check(72 * 64 + 10) is true (not seen, acceptable).
        // Under mutant `-` -> `+` or `/`, w = 72 is included in the loop, copying old_bitmap[72] (which has bit 10 set from latest!)
        // into new_bitmap[72], so check(72 * 64 + 10) would falsely return false (already seen)!
        assert!(
            w.check(72 * 64 + 10),
            "counter 72 * 64 + 10 was never committed and must be acceptable"
        );

        // Also test that actual valid tail counter (word 73: 73 * 64 + 10) was committed and preserved:
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

        // Kills: replace - with + in diff = counter - self.latest
        w.commit(3000);
        w.commit(3001);
        w.commit(3500); // 3500 - 3001 = 499 < 8192. Under +, 3500 + 3001 = 6501, wait!
                        // Under +, diff = 3500 + 3001 = 6501, which is < 8192! We need counter + latest >= 8192:
                        // Say latest = 5000, counter = 5100: diff = 5100 - 5000 = 100 < 8192.
                        // Under +, diff = 5100 + 5000 = 10100 >= 8192 (large leap clears bitmap!).
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

        // Initial configuration on fresh session (send_counter == 0):
        a.set_stride(5, 4);
        assert_eq!(a.stride(), 4);
        assert_eq!(a.send_counter(), 5);

        // Stride 0 falls back to 1:
        // send_counter was 5. With stride 1, target_rem = 10 % 1 = 0, rem = 5 % 1 = 0.
        // send_counter remains 5.
        a.set_stride(10, 0);
        assert_eq!(a.stride(), 1);
        assert_eq!(a.send_counter(), 5);

        // Reconfiguration with send_counter > 0 and rem <= target_rem:
        // currently send_counter is 5.
        // stride = 4, start_counter = 3.
        // rem = 5 % 4 = 1.
        // target_rem = 3 % 4 = 3.
        // rem (1) <= target_rem (3) -> diff = 3 - 1 = 2.
        // send_counter becomes 5 + 2 = 7. 7 % 4 == 3.
        a.set_stride(3, 4);
        assert_eq!(a.stride(), 4);
        assert_eq!(a.send_counter(), 7);
        assert_eq!(a.send_counter() % 4, 3);

        // Reconfiguration with send_counter > 0 and rem > target_rem where (rem - target_rem) > 1:
        // currently send_counter is 7.
        // Let's set stride = 8, start_counter = 1.
        // rem = 7 % 8 = 7.
        // target_rem = 1 % 8 = 1.
        // rem (7) > target_rem (1) -> (rem - target_rem) = 6.
        // Correct diff: 8 - 6 = 2. send_counter becomes 7 + 2 = 9. 9 % 8 = 1.
        // Mutant diff: 8 / 6 = 1. send_counter becomes 7 + 1 = 8. 8 % 8 = 0 != 1.
        a.set_stride(1, 8);
        assert_eq!(a.stride(), 8);
        assert_eq!(a.send_counter(), 9);
        assert_eq!(a.send_counter() % 8, 1);
    }

    #[test]
    fn test_session_seal_in_place_and_open_in_place_boundaries() {
        let (mut a, mut b) = crate::test_session_pair();
        let mut buf = [0u8; 32];
        // Exact length buf.len() == plaintext_len + 16: succeeds
        let ctr = a.seal_in_place(&mut buf[..16], 0).unwrap();
        assert_eq!(ctr, 0);

        // Buffer smaller than total_len: fails
        assert_eq!(
            a.seal_in_place(&mut buf[..15], 0),
            Err(CryptoError::Decrypt)
        );

        // open_in_place: sealed_len < 16 fails
        assert_eq!(b.open_in_place(0, &mut buf, 15), Err(CryptoError::Decrypt));
        assert_eq!(b.open_in_place(0, &mut buf, 0), Err(CryptoError::Decrypt));

        // open_in_place: buf.len() < sealed_len fails
        assert_eq!(
            b.open_in_place(0, &mut buf[..10], 16),
            Err(CryptoError::Decrypt)
        );

        // open_in_place: exact boundary sealed_len == 16 and buf.len() == 16: succeeds
        let mut exact = [0u8; 16];
        let ctr2 = a.seal_in_place(&mut exact, 0).unwrap();
        assert_eq!(b.open_in_place(ctr2, &mut exact, 16).unwrap(), 0);
    }
}
