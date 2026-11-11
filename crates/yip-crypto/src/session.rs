//! AEAD session management, directional transport ciphers, sliding replay windows, and rekeying.
//!
//! Provides [`Session`], [`SessionPair`], [`ChaCha20Poly1305Cipher`], and [`ReplayWindow`].
//! Transport sessions are established from completed Noise handshakes via `split()`
//! and support monotonic sequence counters and 120s epoch rekeying via BLAKE3 ratchet (domain tag `0x04`).

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zeroize::{Zeroize, Zeroizing};

use crate::symmetric::SymmetricState;
use crate::CryptoError;

/// Noise ChaChaPoly nonce: 4 zero bytes ++ 8-byte little-endian counter.
pub fn noise_nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(n)
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

    /// Would `counter` be accepted right now? Read-only - does not mutate state.
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

    /// Returns the greatest counter accepted so far (or 0 if unstarted).
    pub fn latest(&self) -> u64 {
        self.latest
    }

    /// Returns the minimum counter that could be accepted without being rejected as too old.
    pub fn floor(&self) -> u64 {
        if !self.started {
            0
        } else {
            self.latest
                .saturating_sub(self.profile.bits().saturating_sub(1))
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
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

/// Rekey a 32-byte transport key using BLAKE3 in keyed mode with domain tag `0x04`.
///
/// Implements 120s epoch rekeying for forward secrecy.
pub fn rekey_transport_key(current_key: &[u8; 32]) -> [u8; 32] {
    SymmetricState::rekey(current_key)
}

/// Directional AEAD transport ciphers derived from the Noise handshake `split()` output.
///
/// Contains directional [`ChaCha20Poly1305Cipher`] instances for transmission and reception,
/// along with zeroizing storage of current transport key bytes for 120s epoch rekeying.
pub struct SessionPair {
    /// Directional send cipher engine.
    pub send: ChaCha20Poly1305Cipher,
    /// Directional receive cipher engine.
    pub recv: ChaCha20Poly1305Cipher,
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SessionPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPair")
            .field("send", &self.send)
            .field("recv", &self.recv)
            .finish_non_exhaustive()
    }
}

impl SessionPair {
    /// Create a new session pair from 32-byte send and receive transport keys.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send: ChaCha20Poly1305Cipher::new(send_key),
            recv: ChaCha20Poly1305Cipher::new(recv_key),
            send_key: Zeroizing::new(send_key),
            recv_key: Zeroizing::new(recv_key),
        }
    }

    /// Construct from raw 32-byte key references.
    pub fn from_raw_keys(k_send: &[u8; 32], k_recv: &[u8; 32]) -> Self {
        Self::new(*k_send, *k_recv)
    }

    /// Current send key.
    pub fn send_key(&self) -> &[u8; 32] {
        &self.send_key
    }

    /// Current receive key.
    pub fn recv_key(&self) -> &[u8; 32] {
        &self.recv_key
    }

    /// Rekey the send cipher using BLAKE3 tag `0x04`.
    pub fn rekey_send(&mut self) {
        let mut next = rekey_transport_key(&self.send_key);
        self.send = ChaCha20Poly1305Cipher::new(next);
        self.send_key = Zeroizing::new(next);
        next.zeroize();
    }

    /// Rekey the recv cipher using BLAKE3 tag `0x04`.
    pub fn rekey_recv(&mut self) {
        let mut next = rekey_transport_key(&self.recv_key);
        self.recv = ChaCha20Poly1305Cipher::new(next);
        self.recv_key = Zeroizing::new(next);
        next.zeroize();
    }

    /// Rekey both send and receive ciphers using BLAKE3 tag `0x04`.
    pub fn rekey(&mut self) {
        self.rekey_send();
        self.rekey_recv();
    }

    /// Convert into a full stateful [`Session`] with anti-replay tracking.
    pub fn into_session(self, start_counter: u64, stride: u64) -> Session {
        Session::from_session_pair(self, start_counter, stride)
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
///
/// Built around directional [`ChaCha20Poly1305Cipher`] engines keyed by Noise `split()`
/// transport keys and supports 120s epoch rekeying via BLAKE3 ratchet (tag `0x04`).
pub struct Session {
    pair: SessionPair,
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
        let pair = SessionPair::from_raw_keys(k_send, k_recv);
        Ok(Self::from_session_pair(pair, start_counter, stride))
    }

    /// Construct a session from an established [`SessionPair`].
    pub fn from_session_pair(pair: SessionPair, start_counter: u64, stride: u64) -> Self {
        Session {
            pair,
            send_counter: start_counter,
            stride: if stride == 0 { 1 } else { stride },
            replay: ReplayWindow::new(),
        }
    }

    /// Access the underlying directional [`SessionPair`].
    pub fn pair(&self) -> &SessionPair {
        &self.pair
    }

    /// Access mutable reference to the underlying [`SessionPair`].
    pub fn pair_mut(&mut self) -> &mut SessionPair {
        &mut self.pair
    }

    /// Consume into the underlying [`SessionPair`].
    pub fn into_pair(self) -> SessionPair {
        self.pair
    }

    /// Current send transport key.
    pub fn send_key(&self) -> &[u8; 32] {
        self.pair.send_key()
    }

    /// Current receive transport key.
    pub fn recv_key(&self) -> &[u8; 32] {
        self.pair.recv_key()
    }

    /// Rekey the send cipher using BLAKE3 tag `0x04`.
    pub fn rekey_send(&mut self) {
        self.pair.rekey_send();
    }

    /// Rekey the receive cipher using BLAKE3 tag `0x04`.
    pub fn rekey_recv(&mut self) {
        self.pair.rekey_recv();
    }

    /// Rekey both send and receive transport keys using BLAKE3 tag `0x04`.
    pub fn rekey(&mut self) {
        self.pair.rekey();
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
        let total_len = plaintext
            .len()
            .checked_add(16)
            .ok_or(CryptoError::Decrypt)?;
        buf.resize(total_len, 0);
        self.pair
            .send
            .seal_in_place(counter, &mut buf, plaintext.len())?;
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
    /// *after* the frame authenticates.
    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.replay.check(counter) {
            return Err(CryptoError::Replay);
        }
        let mut buf = ciphertext.to_vec();
        let plain_len = self
            .pair
            .recv
            .open_in_place(counter, &mut buf, ciphertext.len())?;
        self.replay.commit(counter);
        buf.truncate(plain_len);
        Ok(buf)
    }

    /// Check whether `counter` is valid within the anti-replay window without committing it.
    #[inline]
    pub fn check_replay(&self, counter: u64) -> bool {
        self.replay.check(counter)
    }

    /// Returns the greatest counter seen by the anti-replay window.
    pub fn replay_latest(&self) -> u64 {
        self.replay.latest()
    }

    /// Returns the lowest counter acceptable by the anti-replay window without being too old.
    pub fn replay_floor(&self) -> u64 {
        self.replay.floor()
    }

    /// Seal into a caller-owned reusable buffer (no per-call allocation).
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<u64, CryptoError> {
        let counter = self.send_counter;
        let total_len = plaintext
            .len()
            .checked_add(16)
            .ok_or(CryptoError::Decrypt)?;
        out.clear();
        out.resize(total_len, 0);
        out[..plaintext.len()].copy_from_slice(plaintext);
        self.pair
            .send
            .seal_in_place(counter, out, plaintext.len())?;
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
        let total_len = plaintext
            .len()
            .checked_add(16)
            .ok_or(CryptoError::Decrypt)?;
        let mut buf = vec![0u8; total_len];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        self.pair
            .send
            .seal_in_place(counter, &mut buf, plaintext.len())?;
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
        let total_len = plaintext
            .len()
            .checked_add(16)
            .ok_or(CryptoError::Decrypt)?;
        out.clear();
        out.resize(total_len, 0);
        out[..plaintext.len()].copy_from_slice(plaintext);
        self.pair
            .send
            .seal_in_place(counter, out, plaintext.len())?;
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
        let plain_len = self
            .pair
            .recv
            .open_in_place(counter, &mut buf, ciphertext.len())?;
        replay.commit(counter);
        buf.truncate(plain_len);
        Ok(buf)
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
        let plain_len = self
            .pair
            .recv
            .open_in_place(counter, out, ciphertext.len())?;
        replay.commit(counter);
        out.truncate(plain_len);
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
        let plain_len = self
            .pair
            .recv
            .open_in_place(counter, out, ciphertext.len())?;
        self.replay.commit(counter);
        out.truncate(plain_len);
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
        self.pair.send.seal_in_place(counter, buf, plaintext_len)?;
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
        self.pair
            .recv
            .open_in_place_with_window(counter, buf, sealed_len, &mut self.replay)
    }
}
