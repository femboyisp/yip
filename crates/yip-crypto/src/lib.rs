//! AEAD session crypto for the yip data plane. M3 wires this to gotatun's
//! audited Noise-IK core; this milestone fixes the public surface.
#![forbid(unsafe_code)]

/// Errors from opening a sealed message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD tag did not verify / decryption failed.
    #[error("decryption failed")]
    Decrypt,
    /// Nonce/counter outside the anti-replay window.
    #[error("replayed message")]
    Replay,
}

/// An established, rekeying AEAD session between two peers. Implemented in M3.
pub trait Session {
    /// AEAD-encrypt an inner frame for transmission.
    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8>;
    /// AEAD-decrypt a received ciphertext, enforcing anti-replay.
    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_error_is_comparable() {
        assert_eq!(CryptoError::Replay, CryptoError::Replay);
        assert_ne!(CryptoError::Replay, CryptoError::Decrypt);
    }
}
