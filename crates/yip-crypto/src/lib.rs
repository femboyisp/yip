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
}
