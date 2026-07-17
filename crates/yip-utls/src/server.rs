//! REALITY.5b: the relay's server-side TLS 1.3 key exchange for an authed
//! connection — the mirror of `yip_utls`'s client KEX (`stream.rs`). Generates
//! the relay's own ephemeral so the relay holds the session keys, while the
//! `ServerHello` it goes into (see `emit_server_hello`) byte-matches dest's.

use crate::error::Error;
use crate::handshake::{GROUP_X25519, GROUP_X25519MLKEM768, MLKEM768_CIPHERTEXT_LEN};
use crate::hello::RandomSource;
use ml_kem::kem::Encapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

/// Bridges the caller's [`RandomSource`] to the `rand_core::CryptoRngCore`
/// bound `ml_kem`'s `Encapsulate` needs. Unlike [`crate::stream`]'s
/// `MlKemRng` (which is hardwired to the OS CSPRNG for `connect`'s
/// production use), this wraps whatever [`RandomSource`] the caller passed
/// `server_key_share` — the OS CSPRNG in production, or a deterministic
/// seeded RNG in tests — so every byte `server_key_share` produces, X25519
/// and ML-KEM alike, is attributable to its one `rng` argument.
struct RandomSourceRng<'a>(&'a mut dyn RandomSource);

impl rand_core::RngCore for RandomSourceRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for RandomSourceRng<'_> {}

/// The relay's server-side KEX for `group`. Returns `(server_key_share_bytes,
/// shared_secret)`: the key_share to put in the `ServerHello`, and the ECDHE
/// secret for `derive_handshake_keys`. `shared_secret` uses REALITY.2's exact
/// combiner (`mlkem_ss ‖ x25519_ss` for 4588 — see `stream.rs`'s client KEX,
/// which this mirrors: the client `decapsulate`s what this `encapsulate`s).
/// Groups other than `4588`/`29` → `Err(UnsupportedGroup)`.
pub fn server_key_share(
    group: u16,
    client_x25519: &[u8; 32],
    client_mlkem_ek: Option<&[u8]>,
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // Fresh X25519 ephemeral (raw bytes → x25519-dalek, as the client does).
    let mut eph = [0u8; 32];
    rng.fill(&mut eph);
    let server_secret = x25519_dalek::StaticSecret::from(eph);
    let server_x25519_pub = x25519_dalek::PublicKey::from(&server_secret).to_bytes();
    let x25519_ss = server_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(*client_x25519))
        .to_bytes();

    match group {
        GROUP_X25519 => Ok((server_x25519_pub.to_vec(), x25519_ss.to_vec())),
        GROUP_X25519MLKEM768 => {
            let ek_bytes = client_mlkem_ek.ok_or(Error::Protocol(
                "group 4588 requires the client's ML-KEM ek",
            ))?;
            // Decode the client's encapsulation key, encapsulate against it.
            let encoded =
                ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(ek_bytes)
                    .map_err(|_| Error::Protocol("client ML-KEM ek is the wrong length"))?;
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&encoded);
            let mut kem_rng = RandomSourceRng(rng);
            let (ct, mlkem_ss) = ek
                .encapsulate(&mut kem_rng)
                .map_err(|()| Error::Protocol("ML-KEM encapsulation failed"))?;
            // server key_share = ct(1088) ‖ x25519_pub(32).
            let mut ks = Vec::with_capacity(MLKEM768_CIPHERTEXT_LEN + 32);
            ks.extend_from_slice(ct.as_slice());
            ks.extend_from_slice(&server_x25519_pub);
            // shared = mlkem_ss ‖ x25519_ss (REALITY.2's combiner order).
            let mut ss = Vec::with_capacity(64);
            ss.extend_from_slice(mlkem_ss.as_slice());
            ss.extend_from_slice(&x25519_ss);
            Ok((ks, ss))
        }
        other => Err(Error::UnsupportedGroup(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::RandomSource;

    /// A deterministic test RNG (mirrors the one `hello.rs`/`stream.rs` tests
    /// use): fills every buffer with a counting byte sequence starting at the
    /// given seed.
    struct SeqRng(u8);
    impl RandomSource for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn server_key_share_x25519_shapes() {
        let client_x = [7u8; 32];
        let (ks, ss) = server_key_share(0x001d, &client_x, None, &mut SeqRng(1)).unwrap();
        assert_eq!(ks.len(), 32); // server x25519 public
        assert_eq!(ss.len(), 32); // x25519 shared
    }

    #[test]
    fn server_key_share_4588_shapes() {
        // A real client ML-KEM ek (generate one, as the client does).
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
        let mut r = crate::stream::MlKemRng::default();
        let (_dk, ek) = MlKem768::generate(&mut r);
        let ek_bytes = ek.as_bytes().to_vec();
        let client_x = [9u8; 32];
        let (ks, ss) = server_key_share(4588, &client_x, Some(&ek_bytes), &mut SeqRng(1)).unwrap();
        assert_eq!(ks.len(), 1088 + 32); // ct ‖ x25519 public
        assert_eq!(ss.len(), 64); // mlkem_ss(32) ‖ x25519_ss(32)
    }

    #[test]
    fn server_key_share_rejects_unsupported_group_and_missing_ek() {
        assert!(matches!(
            server_key_share(23, &[0; 32], None, &mut SeqRng(1)),
            Err(Error::UnsupportedGroup(23))
        ));
        assert!(server_key_share(4588, &[0; 32], None, &mut SeqRng(1)).is_err());
        // 4588 needs ek
    }
}
