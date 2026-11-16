//! Reverse TCP ACK coalescing and redundant cumulative ACK compression on TUN egress.
//!
//! High-throughput forward TCP transfers (5-10 Gbps) generate a reverse flood of
//! hundreds of thousands of pure 40-byte TCP ACKs per second. In standard tunnels,
//! every pure ACK incurs individual encryption, AEAD framing, and UDP socket calls.
//!
//! [`AckCompressor`] aggregates same-flow pure TCP ACKs within a read burst,
//! compressing redundant intermediate cumulative ACKs when a strictly higher
//! cumulative acknowledgment number arrives without selective ACK (SACK) blocks
//! and without window updates.
//!
//! Guarantees:
//! - Zero heap allocations on the hot path (all buffers inline, fixed-capacity).
//! - Duplicate ACKs (identical ACK numbers) are strictly preserved for TCP Fast Retransmit.
//! - SACK blocks and window updates are never compressed.
//! - Safe Rust (`#![deny(unsafe_code)]` / `#![forbid(unsafe_code)]` compatible).

use crate::tun_offload::FlowKey;

/// Maximum packet size in bytes for a pure TCP ACK (IP header + TCP header + options).
pub const MAX_ACK_PACKET_LEN: usize = 128;

/// Maximum number of distinct concurrent flows tracked in the ACK compressor ring.
pub const MAX_TRACKED_ACK_FLOWS: usize = 16;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_URG: u8 = 0x20;

/// Returns true if sequence number `s1` is strictly after `s2` in RFC 793 wrapping arithmetic.
#[inline]
pub fn seq_after(s1: u32, s2: u32) -> bool {
    (s1.wrapping_sub(s2) as i32) > 0
}

/// Returns true if sequence number `s1` is strictly before `s2` in RFC 793 wrapping arithmetic.
#[inline]
pub fn seq_before(s1: u32, s2: u32) -> bool {
    (s1.wrapping_sub(s2) as i32) < 0
}

/// An individual buffered pure TCP ACK packet.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BufferedAck {
    pub(crate) key: FlowKey,
    pub(crate) seq: u32,
    pub(crate) ack_num: u32,
    pub(crate) window: u16,
    pub(crate) len: usize,
    pub(crate) data: [u8; MAX_ACK_PACKET_LEN],
}

impl BufferedAck {
    pub const fn new() -> Self {
        Self {
            key: FlowKey::EMPTY,
            seq: 0,
            ack_num: 0,
            window: 0,
            len: 0,
            data: [0u8; MAX_ACK_PACKET_LEN],
        }
    }
}

impl Default for BufferedAck {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata extracted from a candidate TCP packet for ACK compression evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParsedAckMeta {
    pub(crate) key: FlowKey,
    pub(crate) seq: u32,
    pub(crate) ack_num: u32,
    pub(crate) window: u16,
    pub(crate) is_pure_ack: bool,
    pub(crate) has_sack: bool,
}

/// Check if a TCP options slice contains a Selective Acknowledgment (SACK) option (Kind 5).
#[inline]
pub fn has_sack_option(tcp_opts: &[u8]) -> bool {
    let mut i = 0;
    while i < tcp_opts.len() {
        let kind = tcp_opts[i];
        if kind == 0 {
            // End of option list
            break;
        }
        if kind == 1 {
            // NOP
            i += 1;
            continue;
        }
        if i + 1 >= tcp_opts.len() {
            break;
        }
        let len = usize::from(tcp_opts[i + 1]);
        if len < 2 || i.saturating_add(len) > tcp_opts.len() {
            break;
        }
        if kind == 5 {
            // Option 5: SACK (RFC 2018)
            return true;
        }
        i += len;
    }
    false
}

/// Inspect an IP packet (IPv4 or IPv6) to determine if it is a pure TCP ACK.
pub(crate) fn parse_ack_meta(pkt: &[u8]) -> Option<ParsedAckMeta> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 || pkt[9] != 6 {
                return None; // Not IPv4 or not TCP
            }
            let ihl = usize::from(pkt[0] & 0x0F) * 4;
            if ihl < 20 || pkt.len() < ihl + 20 {
                return None;
            }
            // Check IP fragmentation
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if (frag & 0x2000) != 0 || (frag & 0x1FFF) != 0 {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
            if total_len < ihl + 20 || pkt.len() < total_len {
                return None;
            }
            let tcp = &pkt[ihl..total_len];
            let data_off = usize::from(tcp[12] >> 4) * 4;
            if data_off < 20 || tcp.len() < data_off {
                return None;
            }
            let flags = tcp[13];
            let payload_len = tcp.len() - data_off;
            let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            let window = u16::from_be_bytes([tcp[14], tcp[15]]);
            let has_sack = has_sack_option(&tcp[20..data_off]);

            let is_pure_ack = payload_len == 0
                && (flags & TCP_FLAG_ACK) != 0
                && (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_URG)) == 0;

            Some(ParsedAckMeta {
                key: FlowKey::V4 {
                    src: [pkt[12], pkt[13], pkt[14], pkt[15]],
                    dst: [pkt[16], pkt[17], pkt[18], pkt[19]],
                    sport,
                    dport,
                },
                seq,
                ack_num,
                window,
                is_pure_ack,
                has_sack,
            })
        }
        6 => {
            if pkt.len() < 40 || pkt[6] != 6 {
                return None; // Not IPv6 or not TCP
            }
            let ipv6_payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            let total_len = 40 + ipv6_payload_len;
            if total_len < 60 || pkt.len() < total_len {
                return None;
            }
            let tcp = &pkt[40..total_len];
            let data_off = usize::from(tcp[12] >> 4) * 4;
            if data_off < 20 || tcp.len() < data_off {
                return None;
            }
            let flags = tcp[13];
            let payload_len = tcp.len() - data_off;
            let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            let window = u16::from_be_bytes([tcp[14], tcp[15]]);
            let has_sack = has_sack_option(&tcp[20..data_off]);

            let is_pure_ack = payload_len == 0
                && (flags & TCP_FLAG_ACK) != 0
                && (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_URG)) == 0;

            let mut src = [0u8; 16];
            src.copy_from_slice(&pkt[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&pkt[24..40]);

            Some(ParsedAckMeta {
                key: FlowKey::V6 {
                    src,
                    dst,
                    sport,
                    dport,
                },
                seq,
                ack_num,
                window,
                is_pure_ack,
                has_sack,
            })
        }
        _ => None,
    }
}

/// Zero-allocation, inline compressor for pure TCP cumulative acknowledgments.
#[derive(Clone, Copy, Debug)]
pub struct AckCompressor {
    slots: [Option<BufferedAck>; MAX_TRACKED_ACK_FLOWS],
    count: usize,
}

impl AckCompressor {
    /// Create a new, empty ACK compressor.
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_TRACKED_ACK_FLOWS],
            count: 0,
        }
    }

    /// Process an egress packet through the compressor.
    ///
    /// If `pkt` is a redundant pure cumulative ACK, it replaces the existing buffered ACK
    /// for that flow without emitting. If `pkt` cannot be compressed (data packet, SACK,
    /// duplicate ACK, window update, non-TCP), any buffered ACK for that flow is flushed,
    /// and `pkt` is passed to `emit` immediately.
    pub fn push<F>(&mut self, pkt: &[u8], mut emit: F)
    where
        F: FnMut(&[u8]),
    {
        if pkt.is_empty() {
            return;
        }

        let meta = parse_ack_meta(pkt);

        match meta {
            Some(m) if m.is_pure_ack && !m.has_sack && pkt.len() <= MAX_ACK_PACKET_LEN => {
                // Look for an existing slot matching this flow
                for slot in self.slots.iter_mut().flatten() {
                    if slot.key == m.key {
                        // Check if the new ACK strictly advances the cumulative acknowledgment
                        // with matching window size (pure cumulative progression)
                        if seq_after(m.ack_num, slot.ack_num) && m.window == slot.window {
                            // Redundant cumulative ACK compression: replace old ACK with new ACK
                            slot.seq = m.seq;
                            slot.ack_num = m.ack_num;
                            slot.window = m.window;
                            slot.len = pkt.len();
                            slot.data[..pkt.len()].copy_from_slice(pkt);
                            return;
                        } else {
                            // Duplicate ACK (m.ack_num == slot.ack_num) or window change:
                            // Flush the buffered ACK immediately to preserve DupACK signaling or window updates
                            let buf_data = &slot.data[..slot.len];
                            emit(buf_data);
                            // Replace slot with new ACK
                            slot.seq = m.seq;
                            slot.ack_num = m.ack_num;
                            slot.window = m.window;
                            slot.len = pkt.len();
                            slot.data[..pkt.len()].copy_from_slice(pkt);
                            return;
                        }
                    }
                }

                // Flow not currently tracked: buffer into an empty slot
                for slot_opt in self.slots.iter_mut() {
                    if slot_opt.is_none() {
                        let mut new_slot = BufferedAck::new();
                        new_slot.key = m.key;
                        new_slot.seq = m.seq;
                        new_slot.ack_num = m.ack_num;
                        new_slot.window = m.window;
                        new_slot.len = pkt.len();
                        new_slot.data[..pkt.len()].copy_from_slice(pkt);
                        *slot_opt = Some(new_slot);
                        self.count += 1;
                        return;
                    }
                }

                // Table full: evict slot 0 and place new ACK into slot 0
                if let Some(old) = self.slots[0].take() {
                    emit(&old.data[..old.len]);
                }
                let mut new_slot = BufferedAck::new();
                new_slot.key = m.key;
                new_slot.seq = m.seq;
                new_slot.ack_num = m.ack_num;
                new_slot.window = m.window;
                new_slot.len = pkt.len();
                new_slot.data[..pkt.len()].copy_from_slice(pkt);
                self.slots[0] = Some(new_slot);
            }

            Some(m) => {
                // TCP packet that is not a pure non-SACK cumulative ACK (e.g. data, SACK, SYN, FIN, RST).
                // Flush any buffered ACK for this flow to maintain relative ordering
                for slot_opt in self.slots.iter_mut() {
                    if let Some(slot) = slot_opt {
                        if slot.key == m.key {
                            let buf_data = &slot.data[..slot.len];
                            emit(buf_data);
                            *slot_opt = None;
                            self.count = self.count.saturating_sub(1);
                            break;
                        }
                    }
                }
                emit(pkt);
            }

            None => {
                // Non-TCP packet (UDP, ICMP, etc.): pass through immediately
                emit(pkt);
            }
        }
    }

    /// Flush all held buffered ACKs into `emit`.
    pub fn flush<F>(&mut self, mut emit: F)
    where
        F: FnMut(&[u8]),
    {
        if self.count == 0 {
            return;
        }
        for slot_opt in self.slots.iter_mut() {
            if let Some(slot) = slot_opt.take() {
                emit(&slot.data[..slot.len]);
            }
        }
        self.count = 0;
    }

    /// Returns the number of currently buffered ACKs awaiting emission.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no ACKs are currently buffered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for AckCompressor {
    fn default() -> Self {
        Self::new()
    }
}
