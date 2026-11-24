//! In-session authenticated encrypted control envelope codec.
#![forbid(unsafe_code)]

use crate::handshake::PacketType;
use yip_crypto::{ChaCha20Poly1305Cipher, ReplayWindow};

/// Inner payload type for gossip anti-entropy records.
pub const INNER_TYPE_GOSSIP: u8 = 0x01;

/// Minimum valid length for an encrypted control frame:
/// 1 (packet type) + 8 (nonce) + 16 (Poly1305 tag) + 3 (inner type + payload length header).
pub const MIN_CONTROL_FRAME_LEN: usize = 1 + 8 + 16 + 3;

/// Errors arising during decoding and verification of encrypted control frames.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlError {
    /// Datagram shorter than `MIN_CONTROL_FRAME_LEN`.
    ShortDatagram,
    /// Packet type prefix is not `PacketType::EncryptedControl`.
    InvalidPacketType,
    /// Frame nonce rejected by anti-replay sliding window.
    Replay,
    /// Cryptographic authentication failed (tampered or wrong key).
    Crypto,
    /// Inner payload header specifies length exceeding decrypted plaintext.
    MalformedInner,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::ShortDatagram => write!(f, "datagram too short for control frame"),
            ControlError::InvalidPacketType => {
                write!(f, "invalid packet type for encrypted control")
            }
            ControlError::Replay => write!(f, "control frame nonce rejected by replay window"),
            ControlError::Crypto => write!(f, "cryptographic authentication failed"),
            ControlError::MalformedInner => write!(f, "malformed inner control frame"),
        }
    }
}

impl std::error::Error for ControlError {}

/// Derive directional 32-byte symmetric control keys for initiator and responder
/// from an established 16-byte session `auth_key`.
///
/// Returns `(initiator_key, responder_key)`.
pub fn derive_control_keys(auth_key: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let mut kdf_init = blake3::Hasher::new_derive_key("yip-v1-ctrl-initiator");
    kdf_init.update(auth_key);
    let mut kdf_resp = blake3::Hasher::new_derive_key("yip-v1-ctrl-responder");
    kdf_resp.update(auth_key);
    (
        *kdf_init.finalize().as_bytes(),
        *kdf_resp.finalize().as_bytes(),
    )
}

/// In-session encrypted control codec with uniform padding and anti-replay protection.
pub struct ControlCodec {
    send_cipher: ChaCha20Poly1305Cipher,
    recv_cipher: ChaCha20Poly1305Cipher,
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

impl std::fmt::Debug for ControlCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlCodec")
            .field("send_cipher", &"[redacted]")
            .field("recv_cipher", &"[redacted]")
            .field("send_key", &"[redacted]")
            .field("recv_key", &"[redacted]")
            .finish()
    }
}

impl Clone for ControlCodec {
    fn clone(&self) -> Self {
        Self::new(self.send_key, self.recv_key)
    }
}

impl ControlCodec {
    /// Creates a new control codec with directional symmetric keys.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_cipher: ChaCha20Poly1305Cipher::new(send_key),
            recv_cipher: ChaCha20Poly1305Cipher::new(recv_key),
            send_key,
            recv_key,
        }
    }

    /// Seal an inner payload into an encrypted control frame with uniform padding.
    ///
    /// The frame body is padded out to `target_bucket` (or the minimum payload length
    /// if the target bucket is smaller than required).
    pub fn seal(
        &self,
        nonce: u64,
        inner_type: u8,
        payload: &[u8],
        target_bucket: usize,
    ) -> Vec<u8> {
        let inner_len = payload.len();
        assert!(
            inner_len <= u16::MAX as usize,
            "control payload exceeds maximum u16 length"
        );
        let min_plain_len = 3 + inner_len;
        let plain_len = min_plain_len.max(target_bucket.saturating_sub(1 + 8 + 16));
        let mut buf = vec![0u8; plain_len + 16];
        buf[0] = inner_type;
        buf[1..3].copy_from_slice(&(inner_len as u16).to_be_bytes());
        buf[3..3 + inner_len].copy_from_slice(payload);
        // Trailing bytes in buf[3 + inner_len..plain_len] remain 0x00 padding

        self.send_cipher
            .seal_in_place(nonce, &mut buf, plain_len)
            .expect("seal buffer capacity is sufficient");

        let mut out = Vec::with_capacity(1 + 8 + buf.len());
        out.push(PacketType::EncryptedControl as u8);
        out.extend_from_slice(&nonce.to_le_bytes());
        out.extend_from_slice(&buf);
        out
    }

    /// Open and verify an encrypted control frame, updating the anti-replay window upon success.
    ///
    /// Returns `(inner_type, payload)` with padding cleanly stripped.
    pub fn open(
        &self,
        replay: &mut ReplayWindow,
        datagram: &[u8],
    ) -> Result<(u8, Vec<u8>), ControlError> {
        if datagram.len() < MIN_CONTROL_FRAME_LEN {
            return Err(ControlError::ShortDatagram);
        }
        if datagram[0] != PacketType::EncryptedControl as u8 {
            return Err(ControlError::InvalidPacketType);
        }
        let nonce = u64::from_le_bytes(datagram[1..9].try_into().unwrap());
        if !replay.check(nonce) {
            return Err(ControlError::Replay);
        }

        let mut cipher_buf = datagram[9..].to_vec();
        let cipher_len = cipher_buf.len();
        let plain_len = self
            .recv_cipher
            .open_in_place(nonce, &mut cipher_buf, cipher_len)
            .map_err(|_| ControlError::Crypto)?;

        if plain_len < 3 {
            return Err(ControlError::MalformedInner);
        }

        let inner_type = cipher_buf[0];
        let payload_len = u16::from_be_bytes(cipher_buf[1..3].try_into().unwrap()) as usize;
        if payload_len > plain_len - 3 {
            return Err(ControlError::MalformedInner);
        }

        replay.commit(nonce);
        Ok((inner_type, cipher_buf[3..3 + payload_len].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_control_keys_properties() {
        let auth_key = [0x42u8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        assert_ne!(
            init_key, resp_key,
            "initiator and responder keys must differ"
        );

        let (init_key_2, resp_key_2) = derive_control_keys(&auth_key);
        assert_eq!(init_key, init_key_2, "key derivation must be deterministic");
        assert_eq!(resp_key, resp_key_2, "key derivation must be deterministic");

        let auth_key_diff = [0x43u8; 16];
        let (init_key_diff, resp_key_diff) = derive_control_keys(&auth_key_diff);
        assert_ne!(init_key, init_key_diff);
        assert_ne!(resp_key, resp_key_diff);
    }

    #[test]
    fn test_roundtrip_seal_and_open() {
        let auth_key = [0x55u8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let init_codec = ControlCodec::new(init_key, resp_key);
        let resp_codec = ControlCodec::new(resp_key, init_key);

        let payload = b"anti-entropy-gossip-payload";
        let nonce = 1u64;
        let sealed = init_codec.seal(nonce, INNER_TYPE_GOSSIP, payload, 128);

        let mut replay = ReplayWindow::new();
        let (inner_type, opened) = resp_codec
            .open(&mut replay, &sealed)
            .expect("open should succeed");
        assert_eq!(inner_type, INNER_TYPE_GOSSIP);
        assert_eq!(opened, payload);

        // Reverse direction: responder seals to initiator
        let resp_payload = b"reply-gossip-digest";
        let resp_nonce = 1u64;
        let resp_sealed = resp_codec.seal(resp_nonce, INNER_TYPE_GOSSIP, resp_payload, 128);

        let mut init_replay = ReplayWindow::new();
        let (r_type, r_opened) = init_codec
            .open(&mut init_replay, &resp_sealed)
            .expect("initiator open should succeed");
        assert_eq!(r_type, INNER_TYPE_GOSSIP);
        assert_eq!(r_opened, resp_payload);
    }

    #[test]
    fn test_padding_verification() {
        let auth_key = [0x77u8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let init_codec = ControlCodec::new(init_key, resp_key);
        let resp_codec = ControlCodec::new(resp_key, init_key);

        let payload = b"small payload";
        let mut replay = ReplayWindow::new();

        for bucket in [64, 128, 256, 512] {
            let sealed = init_codec.seal(bucket as u64, INNER_TYPE_GOSSIP, payload, bucket);
            assert_eq!(
                sealed.len(),
                bucket,
                "sealed datagram length must match target_bucket"
            );

            let (inner_type, opened) = resp_codec
                .open(&mut replay, &sealed)
                .expect("open padded frame");
            assert_eq!(inner_type, INNER_TYPE_GOSSIP);
            assert_eq!(opened, payload, "unpadded payload must match original");
        }

        // Target bucket smaller than minimum frame size does not truncate
        let min_expected = 1 + 8 + 16 + 3 + payload.len();
        let sealed_min = init_codec.seal(999, INNER_TYPE_GOSSIP, payload, 0);
        assert_eq!(sealed_min.len(), min_expected);
        let (inner_type, opened_min) = resp_codec
            .open(&mut replay, &sealed_min)
            .expect("open unpadded frame");
        assert_eq!(inner_type, INNER_TYPE_GOSSIP);
        assert_eq!(opened_min, payload);
    }

    #[test]
    fn test_replay_rejection() {
        let auth_key = [0x88u8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let init_codec = ControlCodec::new(init_key, resp_key);
        let resp_codec = ControlCodec::new(resp_key, init_key);

        let payload = b"replay test";
        let sealed = init_codec.seal(42, INNER_TYPE_GOSSIP, payload, 128);

        let mut replay = ReplayWindow::new();
        assert!(resp_codec.open(&mut replay, &sealed).is_ok());

        // Second attempt with identical nonce must be rejected
        let err = resp_codec.open(&mut replay, &sealed).unwrap_err();
        assert_eq!(err, ControlError::Replay);
    }

    #[test]
    fn test_tamper_rejection() {
        let auth_key = [0x99u8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let init_codec = ControlCodec::new(init_key, resp_key);
        let resp_codec = ControlCodec::new(resp_key, init_key);

        let payload = b"tamper test payload";
        let sealed = init_codec.seal(100, INNER_TYPE_GOSSIP, payload, 128);
        let mut replay = ReplayWindow::new();

        // Tamper ciphertext byte
        let mut tampered_cipher = sealed.clone();
        tampered_cipher[12] ^= 0x01;
        assert_eq!(
            resp_codec.open(&mut replay, &tampered_cipher).unwrap_err(),
            ControlError::Crypto
        );

        // Tamper authentication tag byte
        let mut tampered_tag = sealed.clone();
        *tampered_tag.last_mut().unwrap() ^= 0x80;
        assert_eq!(
            resp_codec.open(&mut replay, &tampered_tag).unwrap_err(),
            ControlError::Crypto
        );

        // Tamper nonce byte
        let mut tampered_nonce = sealed.clone();
        tampered_nonce[1] ^= 0x01;
        assert_eq!(
            resp_codec.open(&mut replay, &tampered_nonce).unwrap_err(),
            ControlError::Crypto
        );

        // Tamper packet type prefix
        let mut tampered_type = sealed.clone();
        tampered_type[0] = 0x01; // Not EncryptedControl
        assert_eq!(
            resp_codec.open(&mut replay, &tampered_type).unwrap_err(),
            ControlError::InvalidPacketType
        );

        // Truncated frame
        let truncated = &sealed[..MIN_CONTROL_FRAME_LEN - 1];
        assert_eq!(
            resp_codec.open(&mut replay, truncated).unwrap_err(),
            ControlError::ShortDatagram
        );
    }

    #[test]
    fn test_key_isolation() {
        let auth_key = [0xAAu8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let init_codec = ControlCodec::new(init_key, resp_key);
        let resp_codec = ControlCodec::new(resp_key, init_key);

        let payload = b"isolation test";
        let sealed = init_codec.seal(1, INNER_TYPE_GOSSIP, payload, 128);

        let mut replay = ReplayWindow::new();

        // Initiator cannot open frames sealed with its own send key
        assert_eq!(
            init_codec.open(&mut replay, &sealed).unwrap_err(),
            ControlError::Crypto
        );

        // Unrelated session keys cannot open frames
        let other_auth_key = [0xBBu8; 16];
        let (other_init, other_resp) = derive_control_keys(&other_auth_key);
        let other_codec = ControlCodec::new(other_resp, other_init);
        assert_eq!(
            other_codec.open(&mut replay, &sealed).unwrap_err(),
            ControlError::Crypto
        );

        // Intended recipient can open
        assert!(resp_codec.open(&mut replay, &sealed).is_ok());
    }

    #[test]
    fn test_empty_payload() {
        let auth_key = [0xCCu8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let init_codec = ControlCodec::new(init_key, resp_key);
        let resp_codec = ControlCodec::new(resp_key, init_key);

        let sealed = init_codec.seal(5, INNER_TYPE_GOSSIP, &[], 64);
        let mut replay = ReplayWindow::new();
        let (inner_type, opened) = resp_codec
            .open(&mut replay, &sealed)
            .expect("open empty payload");
        assert_eq!(inner_type, INNER_TYPE_GOSSIP);
        assert!(opened.is_empty());
    }

    #[test]
    fn test_malformed_inner_payload_length() {
        let auth_key = [0xDDu8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let send_cipher = ChaCha20Poly1305Cipher::new(init_key);
        let resp_codec = ControlCodec::new(resp_key, init_key);

        // Build a plaintext where inner payload length (200) exceeds plain_len - 3 (which is 5)
        let plain_len = 8usize; // 3 byte header + 5 bytes
        let mut buf = vec![0u8; plain_len + 16];
        buf[0] = INNER_TYPE_GOSSIP;
        buf[1..3].copy_from_slice(&200u16.to_be_bytes()); // Claims 200 bytes, but only 5 available
        send_cipher.seal_in_place(1, &mut buf, plain_len).unwrap();

        let mut datagram = Vec::with_capacity(1 + 8 + buf.len());
        datagram.push(PacketType::EncryptedControl as u8);
        datagram.extend_from_slice(&1u64.to_le_bytes());
        datagram.extend_from_slice(&buf);

        let mut replay = ReplayWindow::new();
        assert_eq!(
            resp_codec.open(&mut replay, &datagram).unwrap_err(),
            ControlError::MalformedInner
        );
        // Nonce was not committed due to validation failure
        assert!(replay.check(1), "uncommitted nonce should still be valid");
    }

    #[test]
    fn test_control_codec_debug_redacted() {
        let auth_key = [0x42u8; 16];
        let (init_key, resp_key) = derive_control_keys(&auth_key);
        let codec = ControlCodec::new(init_key, resp_key);
        let debug_str = format!("{codec:?}");
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains(&format!("{:02x?}", init_key)));
        assert!(!debug_str.contains(&format!("{:02x?}", resp_key)));
    }
}
