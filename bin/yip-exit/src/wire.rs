//! Wire-compatible YIP mobile datapath framing and anti-replay verification.

use subtle::ConstantTimeEq;

pub const PACKET_TYPE_DATA: u8 = 2;
pub const PACKET_TYPE_CONTROL: u8 = 3;
pub const PACKET_TYPE_DECOY: u8 = 5;

pub const CONTROL_FLAG_REGISTER: u8 = 0x01;
pub const CONTROL_FLAG_ACK: u8 = 0x02;

pub const HEADER_LEN: usize = 28;
pub const AUTH_TAG_LEN: usize = 16;
pub const MIN_PACKET_LEN: usize = HEADER_LEN + AUTH_TAG_LEN;

/// Parsed wire format header of a YIP mobile datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub packet_type: u8,
    pub flags: u8,
    pub epoch: u64,
    pub nonce: u64,
    pub sender_id: [u8; 8],
    pub payload_len: u16,
}

impl PacketHeader {
    /// Serializes the header into a 28-byte wire buffer.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = self.packet_type;
        buf[1] = self.flags;
        buf[2..10].copy_from_slice(&self.epoch.to_le_bytes());
        buf[10..18].copy_from_slice(&self.nonce.to_le_bytes());
        buf[18..26].copy_from_slice(&self.sender_id);
        buf[26..28].copy_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    /// Parses a 28-byte wire buffer into a `PacketHeader`.
    pub fn from_bytes(buf: &[u8; HEADER_LEN]) -> Self {
        let packet_type = buf[0];
        let flags = buf[1];
        let epoch = u64::from_le_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        let nonce = u64::from_le_bytes([
            buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        ]);
        let sender_id = [
            buf[18], buf[19], buf[20], buf[21], buf[22], buf[23], buf[24], buf[25],
        ];
        let payload_len = u16::from_le_bytes([buf[26], buf[27]]);
        Self {
            packet_type,
            flags,
            epoch,
            nonce,
            sender_id,
            payload_len,
        }
    }
}

/// Derives the 32-byte mobile mesh traffic secret from a `network_id`.
pub fn derive_mesh_secret(network_id: &str) -> [u8; 32] {
    blake3::derive_key("yip-v2-mobile-mesh-secret", network_id.as_bytes())
}

/// Encrypts or decrypts payload bytes using BLAKE3 keyed XOF keystream.
pub fn xor_keystream(
    key: &[u8; 32],
    epoch: u64,
    nonce: u64,
    sender_id: &[u8; 8],
    input: &[u8],
) -> Vec<u8> {
    let mut kdf = blake3::Hasher::new_keyed(key);
    kdf.update(b"yip-v1-keystream");
    kdf.update(&epoch.to_le_bytes());
    kdf.update(&nonce.to_le_bytes());
    kdf.update(sender_id);
    let mut xof = kdf.finalize_xof();

    let mut out = input.to_vec();
    let mut keystream = vec![0u8; input.len()];
    xof.fill(&mut keystream);
    for (b, k) in out.iter_mut().zip(keystream.iter()) {
        *b ^= k;
    }
    out
}

/// Computes a 16-byte BLAKE3 keyed MAC over the header and payload.
pub fn compute_auth_tag(
    key: &[u8; 32],
    header_bytes: &[u8; HEADER_LEN],
    body: &[u8],
) -> [u8; AUTH_TAG_LEN] {
    let mut mac = blake3::Hasher::new_keyed(key);
    mac.update(b"yip-v1-authtag");
    mac.update(header_bytes);
    mac.update(body);
    let full = mac.finalize();
    let mut tag = [0u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&full.as_bytes()[..AUTH_TAG_LEN]);
    tag
}

/// Verifies a 16-byte authentication tag in constant time.
pub fn verify_auth_tag(
    key: &[u8; 32],
    header_bytes: &[u8; HEADER_LEN],
    body: &[u8],
    tag: &[u8; AUTH_TAG_LEN],
) -> bool {
    let expected = compute_auth_tag(key, header_bytes, body);
    bool::from(expected.ct_eq(tag))
}

/// Encodes an authenticated and encrypted data frame.
pub fn encode_data_packet(
    key: &[u8; 32],
    epoch: u64,
    nonce: u64,
    sender_id: [u8; 8],
    plaintext: &[u8],
) -> Vec<u8> {
    let header = PacketHeader {
        packet_type: PACKET_TYPE_DATA,
        flags: 0,
        epoch,
        nonce,
        sender_id,
        payload_len: u16::try_from(plaintext.len()).unwrap_or(u16::MAX),
    };
    let header_bytes = header.to_bytes();
    let ciphertext = xor_keystream(key, epoch, nonce, &sender_id, plaintext);
    let tag = compute_auth_tag(key, &header_bytes, &ciphertext);

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len() + AUTH_TAG_LEN);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    out
}

/// Encodes an authenticated control frame (plaintext payload, MAC-verified).
pub fn encode_control_packet(
    key: &[u8; 32],
    flags: u8,
    epoch: u64,
    nonce: u64,
    sender_id: [u8; 8],
    payload: &[u8],
) -> Vec<u8> {
    let header = PacketHeader {
        packet_type: PACKET_TYPE_CONTROL,
        flags,
        epoch,
        nonce,
        sender_id,
        payload_len: u16::try_from(payload.len()).unwrap_or(u16::MAX),
    };
    let header_bytes = header.to_bytes();
    let tag = compute_auth_tag(key, &header_bytes, payload);

    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(payload);
    out.extend_from_slice(&tag);
    out
}

/// 256-bit sliding anti-replay window.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    replay_floor: u64,
    latest_counter: u64,
    bitmap: [u64; 4],
}

impl ReplayWindow {
    /// Checks whether `nonce` is fresh without mutating state.
    pub fn check(&self, nonce: u64) -> bool {
        if nonce == 0 || nonce <= self.replay_floor {
            return false;
        }
        if nonce <= self.latest_counter {
            let diff = self.latest_counter - nonce;
            if diff >= 256 {
                return false;
            }
            let word = usize::try_from(diff / 64).unwrap_or(0);
            let bit = usize::try_from(diff % 64).unwrap_or(0);
            if (self.bitmap[word] & (1u64 << bit)) != 0 {
                return false;
            }
        }
        true
    }

    /// Commits a verified `nonce` into the sliding window.
    pub fn commit(&mut self, nonce: u64) {
        if nonce > self.latest_counter {
            let shift = usize::try_from(nonce - self.latest_counter).unwrap_or(256);
            if shift >= 256 {
                self.bitmap = [0; 4];
            } else {
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                let mut next = [0u64; 4];
                for i in 0..4 {
                    if i + word_shift < 4 {
                        next[i + word_shift] |= self.bitmap[i] << bit_shift;
                    }
                    if bit_shift > 0 && i + word_shift + 1 < 4 {
                        next[i + word_shift + 1] |= self.bitmap[i] >> (64 - bit_shift);
                    }
                }
                self.bitmap = next;
            }
            self.bitmap[0] |= 1u64;
            self.latest_counter = nonce;
            self.replay_floor = self.latest_counter.saturating_sub(256);
        } else if nonce > self.replay_floor {
            let diff = self.latest_counter - nonce;
            if diff < 256 {
                let word = usize::try_from(diff / 64).unwrap_or(0);
                let bit = usize::try_from(diff % 64).unwrap_or(0);
                self.bitmap[word] |= 1u64 << bit;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_packet_round_trip_and_auth() {
        let key = derive_mesh_secret("sandbox-mesh");
        let sender = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = b"\x45\x00\x00\x20hello-world";
        let frame = encode_data_packet(&key, 1, 42, sender, payload);

        let header_bytes: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let hdr = PacketHeader::from_bytes(&header_bytes);
        assert_eq!(hdr.packet_type, PACKET_TYPE_DATA);
        assert_eq!(hdr.nonce, 42);
        assert_eq!(hdr.sender_id, sender);
        assert_eq!(hdr.payload_len as usize, payload.len());

        let body = &frame[HEADER_LEN..HEADER_LEN + payload.len()];
        let tag: [u8; AUTH_TAG_LEN] = frame[HEADER_LEN + payload.len()..].try_into().unwrap();
        assert!(verify_auth_tag(&key, &header_bytes, body, &tag));

        let plain = xor_keystream(&key, hdr.epoch, hdr.nonce, &hdr.sender_id, body);
        assert_eq!(plain, payload);
    }

    #[test]
    fn test_replay_window_rejects_duplicates_and_zero() {
        let mut win = ReplayWindow::default();
        assert!(!win.check(0));
        assert!(win.check(1));
        win.commit(1);
        assert!(!win.check(1));
        assert!(win.check(5));
        win.commit(5);
        assert!(win.check(3));
        win.commit(3);
        assert!(!win.check(3));
    }
}
