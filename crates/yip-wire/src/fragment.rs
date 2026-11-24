//! Handshake message fragmentation and reassembly.
//!
//! Required when post-quantum handshake flights (e.g. ML-KEM-1024 Flight 1 = 1664 bytes)
//! exceed standard Ethernet MTU (1500 bytes) or constrained path MTUs.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::WireError;

/// Length of the handshake fragment header in bytes.
pub const FRAGMENT_HEADER_LEN: usize = 12;

/// Packet type discriminant for fragmented handshake messages.
pub const PACKET_TYPE_HANDSHAKE_FRAG: u8 = 5;

/// A single handshake message fragment with wire header.
///
/// Wire layout:
/// - `[0]`: packet_type (u8, `PACKET_TYPE_HANDSHAKE_FRAG = 5`)
/// - `[1]`: target_packet_type (u8, e.g. 0 for `HandshakeInit`, 1 for `HandshakeResp`)
/// - `[2..6]`: message_id (u32, big-endian)
/// - `[6]`: frag_index (u8, 0-indexed)
/// - `[7]`: total_frags (u8, 1..=64)
/// - `[8..10]`: total_len (u16, big-endian unfragmented payload length)
/// - `[10..12]`: offset (u16, big-endian byte offset in unfragmented payload)
/// - `[12..]`: fragment payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFragment {
    /// Target packet type (e.g. 0 for Init, 1 for Resp).
    pub target_packet_type: u8,
    /// Random or sequential message identifier linking fragments.
    pub message_id: u32,
    /// 0-indexed fragment number.
    pub frag_index: u8,
    /// Total number of fragments.
    pub total_frags: u8,
    /// Total length of the original unfragmented payload (excluding discriminant).
    pub total_len: u16,
    /// Byte offset of this fragment in the original payload.
    pub offset: u16,
    /// Chunk payload bytes.
    pub payload: Vec<u8>,
}

impl HandshakeFragment {
    /// Serialize this fragment into an outgoing datagram buffer.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(FRAGMENT_HEADER_LEN + self.payload.len());
        out.push(PACKET_TYPE_HANDSHAKE_FRAG);
        out.push(self.target_packet_type);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.push(self.frag_index);
        out.push(self.total_frags);
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.payload);
    }

    /// Parse a fragment from a received datagram.
    pub fn decode(datagram: &[u8]) -> Result<Self, WireError> {
        if datagram.len() < FRAGMENT_HEADER_LEN {
            return Err(WireError::Malformed);
        }
        if datagram[0] != PACKET_TYPE_HANDSHAKE_FRAG {
            return Err(WireError::Malformed);
        }
        let target_packet_type = datagram[1];
        let message_id = u32::from_be_bytes(
            datagram[2..6]
                .try_into()
                .map_err(|_| WireError::Malformed)?,
        );
        let frag_index = datagram[6];
        let total_frags = datagram[7];
        let total_len = u16::from_be_bytes(
            datagram[8..10]
                .try_into()
                .map_err(|_| WireError::Malformed)?,
        );
        let offset = u16::from_be_bytes(
            datagram[10..12]
                .try_into()
                .map_err(|_| WireError::Malformed)?,
        );

        if total_frags == 0 || frag_index >= total_frags || total_frags > 64 {
            return Err(WireError::Malformed);
        }
        let payload_len = datagram.len() - FRAGMENT_HEADER_LEN;
        if (offset as usize)
            .checked_add(payload_len)
            .ok_or(WireError::Malformed)?
            > total_len as usize
        {
            return Err(WireError::Malformed);
        }
        let payload = datagram[FRAGMENT_HEADER_LEN..].to_vec();

        Ok(Self {
            target_packet_type,
            message_id,
            frag_index,
            total_frags,
            total_len,
            offset,
            payload,
        })
    }
}

/// Chunk a complete handshake datagram (starting with its packet type byte, e.g. `[HandshakeInit, msg1...]`)
/// into multiple [`HandshakeFragment`] packets if it exceeds `max_packet_len`.
///
/// If `full_datagram.len() <= max_packet_len`, returns `vec![full_datagram.to_vec()]` unfragmented.
pub fn chunk_handshake_datagram(
    full_datagram: &[u8],
    max_packet_len: usize,
    message_id: u32,
) -> Vec<Vec<u8>> {
    if full_datagram.len() <= max_packet_len {
        return vec![full_datagram.to_vec()];
    }
    if full_datagram.is_empty() {
        return Vec::new();
    }

    let target_packet_type = full_datagram[0];
    let payload = &full_datagram[1..];
    let total_len = match u16::try_from(payload.len()) {
        Ok(l) => l,
        Err(_) => return vec![full_datagram.to_vec()],
    };

    let max_chunk_payload = max_packet_len.saturating_sub(FRAGMENT_HEADER_LEN).max(64);
    let total_frags = payload.len().div_ceil(max_chunk_payload) as u8;

    let mut frags = Vec::with_capacity(total_frags as usize);
    for (i, chunk) in payload.chunks(max_chunk_payload).enumerate() {
        let frag = HandshakeFragment {
            target_packet_type,
            message_id,
            frag_index: i as u8,
            total_frags,
            total_len,
            offset: (i * max_chunk_payload) as u16,
            payload: chunk.to_vec(),
        };
        let mut encoded = Vec::with_capacity(FRAGMENT_HEADER_LEN + chunk.len());
        frag.encode(&mut encoded);
        frags.push(encoded);
    }
    frags
}

/// Maximum concurrent active reassembly sessions tracked to prevent memory exhaustion DoS.
pub const MAX_REASSEMBLY_SESSIONS: usize = 256;

/// Manages in-progress reassembly of fragmented handshake messages.
#[derive(Debug, Clone)]
pub struct HandshakeReassembler {
    sessions: HashMap<u32, InProgressReassembly>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct InProgressReassembly {
    target_packet_type: u8,
    total_len: u16,
    total_frags: u8,
    received_count: u8,
    received_mask: u64,
    buffer: Vec<u8>,
    updated_at: Instant,
}

impl Default for HandshakeReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeReassembler {
    /// Create a new reassembler with default 5-second fragment TTL.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            ttl: Duration::from_secs(5),
        }
    }

    /// Create a new reassembler with custom fragment TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl,
        }
    }

    /// Process a received datagram.
    ///
    /// - If it is a fragment (first byte is [`PACKET_TYPE_HANDSHAKE_FRAG`]):
    ///   Decodes the fragment and records it. When all fragments for the message arrive,
    ///   returns `Ok(Some(reconstructed_datagram))` starting with the original packet type discriminant.
    ///   Otherwise returns `Ok(None)` while waiting for remaining fragments.
    /// - If it is not a fragment: returns `Ok(Some(datagram.to_vec()))` immediately.
    pub fn process_datagram(&mut self, datagram: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
        if datagram.is_empty() {
            return Err(WireError::Malformed);
        }
        if datagram[0] != PACKET_TYPE_HANDSHAKE_FRAG {
            return Ok(Some(datagram.to_vec()));
        }

        let frag = HandshakeFragment::decode(datagram)?;
        self.add_fragment(&frag)
    }

    /// Ingest a decoded [`HandshakeFragment`].
    pub fn add_fragment(&mut self, frag: &HandshakeFragment) -> Result<Option<Vec<u8>>, WireError> {
        let now = Instant::now();
        self.sessions
            .retain(|_, s| now.duration_since(s.updated_at) < self.ttl);

        if frag.total_frags == 0 || frag.total_frags > 64 || frag.frag_index >= frag.total_frags {
            return Err(WireError::Malformed);
        }

        if !self.sessions.contains_key(&frag.message_id)
            && self.sessions.len() >= MAX_REASSEMBLY_SESSIONS
        {
            if let Some((&oldest_id, _)) = self.sessions.iter().min_by_key(|(_, s)| s.updated_at) {
                self.sessions.remove(&oldest_id);
            }
        }

        let entry = self
            .sessions
            .entry(frag.message_id)
            .or_insert_with(|| InProgressReassembly {
                target_packet_type: frag.target_packet_type,
                total_len: frag.total_len,
                total_frags: frag.total_frags,
                received_count: 0,
                received_mask: 0,
                buffer: vec![0u8; frag.total_len as usize],
                updated_at: now,
            });

        if entry.target_packet_type != frag.target_packet_type
            || entry.total_len != frag.total_len
            || entry.total_frags != frag.total_frags
        {
            return Err(WireError::Malformed);
        }

        let bit = 1u64 << frag.frag_index;
        if (entry.received_mask & bit) == 0 {
            let start = frag.offset as usize;
            let end = start + frag.payload.len();
            if end > entry.buffer.len() {
                return Err(WireError::Malformed);
            }
            entry.buffer[start..end].copy_from_slice(&frag.payload);
            entry.received_mask |= bit;
            entry.received_count += 1;
            entry.updated_at = now;
        }

        if entry.received_count == entry.total_frags {
            let completed = self.sessions.remove(&frag.message_id).unwrap();
            let mut out = Vec::with_capacity(1 + completed.buffer.len());
            out.push(completed.target_packet_type);
            out.extend_from_slice(&completed.buffer);
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unfragmented_passthrough() {
        let mut reassembler = HandshakeReassembler::new();
        let original = vec![0u8, 1, 2, 3, 4, 5];
        let res = reassembler.process_datagram(&original).unwrap();
        assert_eq!(res, Some(original));
    }

    #[test]
    fn test_chunk_and_reassemble_in_order() {
        let mut data = vec![0u8]; // HandshakeInit discriminant
        data.extend((0..1664).map(|i| (i % 256) as u8)); // 1664 bytes payload

        let chunks = chunk_handshake_datagram(&data, 1200, 0x12345678);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].len() <= 1200);
        assert!(chunks[1].len() <= 1200);

        let mut reassembler = HandshakeReassembler::new();
        let r1 = reassembler.process_datagram(&chunks[0]).unwrap();
        assert_eq!(r1, None);

        let r2 = reassembler.process_datagram(&chunks[1]).unwrap();
        assert_eq!(r2, Some(data));
    }

    #[test]
    fn test_chunk_and_reassemble_out_of_order() {
        let mut data = vec![1u8]; // HandshakeResp discriminant
        data.extend((0..2000).map(|i| (i % 256) as u8));

        let chunks = chunk_handshake_datagram(&data, 800, 0xABCDEF01);
        assert!(chunks.len() >= 3);

        let mut reassembler = HandshakeReassembler::new();
        // Feed all except chunks[0] in reverse order
        for chunk in chunks[1..].iter().rev() {
            let r = reassembler.process_datagram(chunk).unwrap();
            assert_eq!(r, None);
        }
        // Feed the first chunk last
        let final_res = reassembler.process_datagram(&chunks[0]).unwrap();
        assert_eq!(final_res, Some(data));
    }

    #[test]
    fn test_duplicate_fragments_ignored() {
        let mut data = vec![0u8];
        data.extend((0..1500).map(|i| (i % 256) as u8));

        let chunks = chunk_handshake_datagram(&data, 1000, 0x55555555);
        assert_eq!(chunks.len(), 2);

        let mut reassembler = HandshakeReassembler::new();
        assert_eq!(reassembler.process_datagram(&chunks[0]).unwrap(), None);
        // Duplicate chunk 0
        assert_eq!(reassembler.process_datagram(&chunks[0]).unwrap(), None);
        // Chunk 1 finishes
        assert_eq!(
            reassembler.process_datagram(&chunks[1]).unwrap(),
            Some(data)
        );
    }

    #[test]
    fn test_malformed_fragments_rejected() {
        let mut reassembler = HandshakeReassembler::new();
        // Too short
        assert_eq!(
            reassembler.process_datagram(&[5, 0, 1]),
            Err(WireError::Malformed)
        );

        // Invalid frag_index >= total_frags
        let bad_frag = vec![
            5, 0, 0, 0, 0, 1, // type, target, id
            2, 2, // frag 2 of 2 (0-indexed so 2 is invalid)
            0, 10, // total_len 10
            0, 0, // offset 0
            1, 2, 3,
        ];
        assert_eq!(
            reassembler.process_datagram(&bad_frag),
            Err(WireError::Malformed)
        );
    }

    #[test]
    fn test_reassembly_session_cap_dos_protection() {
        let mut reassembler = HandshakeReassembler::new();
        // Insert 300 distinct message IDs (1 fragment of 2 each)
        for id in 0..300u32 {
            let frag = HandshakeFragment {
                target_packet_type: 0,
                message_id: id,
                frag_index: 0,
                total_frags: 2,
                total_len: 200,
                offset: 0,
                payload: vec![0x42; 100],
            };
            let mut enc = Vec::new();
            frag.encode(&mut enc);
            assert_eq!(reassembler.process_datagram(&enc).unwrap(), None);
        }
        // Sessions must be capped at MAX_REASSEMBLY_SESSIONS
        assert!(reassembler.sessions.len() <= MAX_REASSEMBLY_SESSIONS);
    }

    #[test]
    fn test_fragment_offset_overflow_rejected() {
        let mut reassembler = HandshakeReassembler::new();
        // offset (150) + payload len (100) = 250 > total_len (200)
        let frag = HandshakeFragment {
            target_packet_type: 0,
            message_id: 42,
            frag_index: 1,
            total_frags: 2,
            total_len: 200,
            offset: 150,
            payload: vec![0x99; 100],
        };
        let mut enc = Vec::new();
        frag.encode(&mut enc);
        assert_eq!(
            reassembler.process_datagram(&enc),
            Err(WireError::Malformed)
        );
    }

    #[test]
    fn test_fragment_metadata_mismatch_rejected() {
        let mut reassembler = HandshakeReassembler::new();
        let frag1 = HandshakeFragment {
            target_packet_type: 0,
            message_id: 100,
            frag_index: 0,
            total_frags: 2,
            total_len: 200,
            offset: 0,
            payload: vec![1; 100],
        };
        let mut enc1 = Vec::new();
        frag1.encode(&mut enc1);
        assert_eq!(reassembler.process_datagram(&enc1).unwrap(), None);

        // Same message_id, but target_packet_type mismatched (1 instead of 0)
        let frag2 = HandshakeFragment {
            target_packet_type: 1,
            message_id: 100,
            frag_index: 1,
            total_frags: 2,
            total_len: 200,
            offset: 100,
            payload: vec![2; 100],
        };
        let mut enc2 = Vec::new();
        frag2.encode(&mut enc2);
        assert_eq!(
            reassembler.process_datagram(&enc2),
            Err(WireError::Malformed)
        );
    }
}
