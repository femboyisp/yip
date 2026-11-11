//! Core symmetric state and domain-separated BLAKE3 XOF ratchet.
//!
//! Implements the symmetric state machine for Noise-like handshakes using
//! BLAKE3 in keyed mode with extendable output (XOF) and 1-byte domain separation tags.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric state maintaining the chaining key (`ck`) and handshake hash (`h`).
///
/// All operations operate entirely on stack-allocated fixed arrays with zero
/// dynamic heap allocations. Derives [`Clone`], [`Zeroize`], and [`ZeroizeOnDrop`]
/// so that key material is scrubbed from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricState {
    /// 32-byte chaining key for ratchet operations.
    pub ck: [u8; 32],
    /// 32-byte rolling handshake transcript hash.
    pub h: [u8; 32],
}

impl SymmetricState {
    /// Initialize a new `SymmetricState` from a protocol name.
    ///
    /// Sets both `ck` and `h` to the BLAKE3 hash of `protocol_name`.
    pub fn new(protocol_name: &[u8]) -> Self {
        let h = blake3::hash(protocol_name);
        Self {
            ck: *h.as_bytes(),
            h: *h.as_bytes(),
        }
    }

    /// Mix arbitrary data into the transcript hash `h`.
    ///
    /// Computes `h = blake3(h || data)`. The chaining key `ck` is unmodified.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h.copy_from_slice(hasher.finalize().as_bytes());
    }

    /// Mix input key material `ikm` into `ck` and emit a 32-byte cipher key `k`.
    ///
    /// Uses keyed BLAKE3 with domain separation tag `0x01` and generates 64 bytes
    /// of extendable output:
    /// - Bytes 0..32 become the new chaining key `ck`.
    /// - Bytes 32..64 are returned as the cipher key `k`.
    ///
    /// Intermediate stack buffers are zeroized before returning.
    pub fn mix_key(&mut self, ikm: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.ck);
        hasher.update(&[0x01]);
        hasher.update(ikm);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);

        self.ck.copy_from_slice(&out[0..32]);
        let mut k = [0u8; 32];
        k.copy_from_slice(&out[32..64]);
        out.zeroize();
        k
    }

    /// Mix pre-shared key material `psk` into `ck`, update transcript hash `h`,
    /// and emit a 32-byte cipher key `k`.
    ///
    /// Uses keyed BLAKE3 with domain separation tag `0x02` and generates 96 bytes
    /// of extendable output:
    /// - Bytes 0..32 become the new chaining key `ck`.
    /// - Bytes 32..64 are mixed into transcript hash `h` via `mix_hash`.
    /// - Bytes 64..96 are returned as the cipher key `k`.
    ///
    /// Intermediate stack buffers are zeroized before returning.
    pub fn mix_key_and_hash(&mut self, psk: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.ck);
        hasher.update(&[0x02]);
        hasher.update(psk);
        let mut out = [0u8; 96];
        hasher.finalize_xof().fill(&mut out);

        self.ck.copy_from_slice(&out[0..32]);
        let mut temp_h = [0u8; 32];
        temp_h.copy_from_slice(&out[32..64]);
        self.mix_hash(&temp_h);
        temp_h.zeroize();

        let mut k = [0u8; 32];
        k.copy_from_slice(&out[64..96]);
        out.zeroize();
        k
    }

    /// Split the chaining key `ck` into two directional 32-byte transport keys.
    ///
    /// Uses keyed BLAKE3 with domain separation tag `0x03` and generates 64 bytes
    /// of extendable output:
    /// - Bytes 0..32: initiator-to-responder transport key (`k_send`).
    /// - Bytes 32..64: responder-to-initiator transport key (`k_recv`).
    ///
    /// Intermediate stack buffers are zeroized before returning.
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        let mut hasher = blake3::Hasher::new_keyed(&self.ck);
        hasher.update(&[0x03]);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);

        let mut k_send = [0u8; 32];
        let mut k_recv = [0u8; 32];
        k_send.copy_from_slice(&out[0..32]);
        k_recv.copy_from_slice(&out[32..64]);
        out.zeroize();
        (k_send, k_recv)
    }

    /// Derive the next 32-byte transport key for epoch rotation / forward secrecy.
    ///
    /// Uses keyed BLAKE3 keyed by `current_key` with domain separation tag `0x04`
    /// and generates 32 bytes of extendable output.
    pub fn rekey(current_key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(current_key);
        hasher.update(&[0x04]);
        let mut next_key = [0u8; 32];
        hasher.finalize_xof().fill(&mut next_key);
        next_key
    }
}
