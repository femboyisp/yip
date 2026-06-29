//! Wire framing for the yip data plane: keyed header-protection and
//! coverage-based authentication. Behavior lands in milestone M2; this
//! milestone establishes the public surface later crates depend on.
#![forbid(unsafe_code)]

use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// A single on-wire frame carrying one FEC symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Epoch-rotating keyed token selecting the session/decoder.
    pub conn_tag: u64,
    /// Which pipelined FEC object this symbol belongs to.
    pub object_id: u16,
    /// RaptorQ payload identifier (SBN + ESI), opaque to the wire layer.
    pub payload_id: [u8; 4],
    /// Symbol kind / control bits (source/repair, feedback, ARQ).
    pub flags: u8,
    /// The ciphertext symbol payload.
    pub payload: Vec<u8>,
}

/// Length of the logical (and protected) frame header in bytes.
pub const HEADER_LEN: usize = 15;
/// Length of the trailing coverage-auth tag in bytes.
pub const TAG_LEN: usize = 8;
/// Smallest valid frame: header + tag, empty payload.
pub const MIN_FRAME: usize = HEADER_LEN + TAG_LEN;

/// Serialize the logical header (big-endian, fixed layout).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used in M2 codec implementation")
)]
fn write_header(frame: &Frame) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..8].copy_from_slice(&frame.conn_tag.to_be_bytes());
    out[8..10].copy_from_slice(&frame.object_id.to_be_bytes());
    out[10..14].copy_from_slice(&frame.payload_id);
    out[14] = frame.flags;
    out
}

/// Parse the logical header fields back out.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used in M2 codec implementation")
)]
fn read_header(bytes: &[u8; HEADER_LEN]) -> (u64, u16, [u8; 4], u8) {
    let conn_tag = u64::from_be_bytes(bytes[0..8].try_into().expect("8 bytes"));
    let object_id = u16::from_be_bytes(bytes[8..10].try_into().expect("2 bytes"));
    let payload_id: [u8; 4] = bytes[10..14].try_into().expect("4 bytes");
    let flags = bytes[14];
    (conn_tag, object_id, payload_id, flags)
}

/// Compute the 8-byte coverage-auth tag over `covered` under `auth_key`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the Codec in M2 Task 4")
)]
fn auth_tag(auth_key: &[u8; 16], covered: &[u8]) -> [u8; TAG_LEN] {
    let mut hasher = SipHasher24::new_with_key(auth_key);
    hasher.write(covered);
    hasher.finish().to_be_bytes()
}

/// Generate `n` mask bytes as a SipHash-CTR keystream under `hp_key`,
/// seeded by `sample`. Block i = SipHash24(hp_key, sample ‖ i_be_u32).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the Codec in M2 Task 4")
)]
fn keystream(hp_key: &[u8; 16], sample: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut counter: u32 = 0;
    while out.len() < n {
        let mut hasher = SipHasher24::new_with_key(hp_key);
        hasher.write(sample);
        hasher.write(&counter.to_be_bytes());
        out.extend_from_slice(&hasher.finish().to_be_bytes());
        counter += 1;
    }
    out.truncate(n);
    out
}

/// XOR `mask` into `buf` byte-for-byte (`buf.len()` must be `<= mask.len()`).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the Codec in M2 Task 4")
)]
fn xor_in_place(buf: &mut [u8], mask: &[u8]) {
    for (b, m) in buf.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
}

/// Errors from decoding a wire datagram.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// Coverage-auth tag did not verify.
    #[error("authentication failed")]
    AuthFailed,
    /// Datagram was too short or structurally invalid.
    #[error("malformed datagram")]
    Malformed,
}

/// Encodes [`Frame`]s to datagrams and back. Implemented in M2.
pub trait WireCodec {
    /// Serialize and header-protect a frame into a wire datagram.
    fn frame(&self, frame: &Frame) -> Vec<u8>;
    /// Authenticate, deprotect, and parse a datagram into a [`Frame`].
    fn deframe(&self, datagram: &[u8]) -> Result<Frame, WireError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_tag_is_keyed_and_covers_input() {
        let k1 = [1u8; 16];
        let k2 = [2u8; 16];
        let a = auth_tag(&k1, b"hello");
        let b = auth_tag(&k1, b"hello");
        let c = auth_tag(&k1, b"hellp"); // one byte different
        let d = auth_tag(&k2, b"hello"); // different key
        assert_eq!(a, b, "deterministic for same key+input");
        assert_ne!(a, c, "changes when covered bytes change");
        assert_ne!(a, d, "changes when key changes");
    }

    #[test]
    fn frame_carries_object_id() {
        let frame = Frame {
            conn_tag: 7,
            object_id: 42,
            payload_id: [0; 4],
            flags: 0,
            payload: vec![1, 2, 3],
        };
        assert_eq!(frame.object_id, 42);
    }

    #[test]
    fn keystream_masks_reversibly_and_hides_constants() {
        let hp = [3u8; 16];
        let sample = [0xAAu8; TAG_LEN];
        let mut header = [0u8; HEADER_LEN]; // all-zero "constant" header
        let mask = keystream(&hp, &sample, HEADER_LEN);
        assert_eq!(mask.len(), HEADER_LEN);
        xor_in_place(&mut header, &mask);
        assert_ne!(
            header, [0u8; HEADER_LEN],
            "constant header is hidden after masking"
        );
        // XOR again with the same mask restores the original
        xor_in_place(&mut header, &mask);
        assert_eq!(header, [0u8; HEADER_LEN], "masking is reversible");
        // a different sample yields a different stream
        let mask2 = keystream(&hp, &[0xBBu8; TAG_LEN], HEADER_LEN);
        assert_ne!(mask, mask2);
    }

    #[test]
    fn header_roundtrips() {
        let frame = Frame {
            conn_tag: 0x0102_0304_0506_0708,
            object_id: 0xABCD,
            payload_id: [9, 8, 7, 6],
            flags: 0x5A,
            payload: vec![],
        };
        let bytes = write_header(&frame);
        assert_eq!(bytes.len(), HEADER_LEN);
        let (conn_tag, object_id, payload_id, flags) = read_header(&bytes);
        assert_eq!(conn_tag, frame.conn_tag);
        assert_eq!(object_id, frame.object_id);
        assert_eq!(payload_id, frame.payload_id);
        assert_eq!(flags, frame.flags);
    }
}
