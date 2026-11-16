//! Flow-aware ingress micro-reorder buffer.
//!
//! Absorbs network jitter, packet reordering, and multi-queue hashing skew by
//! holding out-of-order TCP segments per 4-tuple up to a micro-deadline (1.5-2.0 ms),
//! then delivering contiguous runs in strictly monotonic sequence order.
//!
//! Guarantees zero dynamic allocations during steady-state packet processing on the hot path.

use crate::classify::FlowKey;

/// Maximum number of out-of-order slots buffered per flow.
pub const MAX_FLOW_REORDER_SLOTS: usize = 16;

/// Maximum number of concurrent flows actively tracked in the reorder table.
pub const MAX_CONCURRENT_TRACKED_FLOWS: usize = 64;

/// Maximum packet size in bytes that can be held in an individual reorder slot.
pub const MAX_SLOT_PACKET_LEN: usize = 2048;

/// Standard IEEE 802.3 Ethernet frame header length in bytes.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Default micro-reorder eviction deadline in milliseconds for typical network paths.
pub const DEFAULT_REORDER_DEADLINE_MS: u64 = 10;

const EMPTY_FLOW_KEY: FlowKey = FlowKey {
    src: [0u8; 16],
    dst: [0u8; 16],
    src_port: 0,
    dst_port: 0,
    proto: 0,
};

/// An individual buffered packet slot.
#[derive(Clone, Copy, Debug)]
pub struct ReorderSlot {
    /// Starting TCP sequence number of the buffered packet.
    pub seq: u32,
    /// TCP sequence length (payload len + SYN/FIN) for sequence tracking.
    pub seg_len: u32,
    /// Total packet length stored in `data`.
    pub len: u16,
    /// Whether this slot currently holds a valid packet.
    pub valid: bool,
    /// Bounded inline buffer holding the raw packet data.
    pub data: [u8; MAX_SLOT_PACKET_LEN],
}

impl ReorderSlot {
    pub const fn new() -> Self {
        Self {
            seq: 0,
            seg_len: 0,
            len: 0,
            valid: false,
            data: [0u8; MAX_SLOT_PACKET_LEN],
        }
    }
}

impl Default for ReorderSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// State tracking for a single TCP directional flow.
#[derive(Debug)]
pub struct FlowReorderState {
    /// 5-tuple identifying this flow.
    pub key: FlowKey,
    /// Next expected TCP sequence number for in-order delivery.
    pub expected_seq: u32,
    /// Timestamp in milliseconds when buffered packets for this flow expire.
    pub deadline_ms: u64,
    /// Timestamp in milliseconds when this flow was last observed.
    pub last_seen_ms: u64,
    /// Whether sequence tracking has been initialized for this flow.
    pub initialized: bool,
    /// Fixed-size table of buffered out-of-order slots.
    pub slots: [ReorderSlot; MAX_FLOW_REORDER_SLOTS],
    /// Number of valid slots currently held for this flow.
    pub slot_count: usize,
}

impl FlowReorderState {
    pub const fn new() -> Self {
        Self {
            key: EMPTY_FLOW_KEY,
            expected_seq: 0,
            deadline_ms: 0,
            last_seen_ms: 0,
            initialized: false,
            slots: [ReorderSlot::new(); MAX_FLOW_REORDER_SLOTS],
            slot_count: 0,
        }
    }

    /// Reset all state and invalidate all buffered slots.
    pub fn reset(&mut self) {
        self.initialized = false;
        self.deadline_ms = 0;
        self.slot_count = 0;
        for slot in &mut self.slots {
            slot.valid = false;
        }
    }
}

impl Default for FlowReorderState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result outcome of processing an ingress packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReorderOutcome {
    /// Packet bypassed reordering directly (e.g. non-TCP, control flags, empty payload).
    Bypassed,
    /// Packet was emitted in sequence (and optionally drained buffered slots).
    InOrder,
    /// Packet was buffered awaiting missing sequence numbers.
    Buffered,
    /// Packet triggered a buffer flush or eviction.
    Flushed,
    /// Duplicate or stale packet.
    Duplicate,
}

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

/// Returns true if sequence number `s1` is greater than or equal to `s2`.
#[inline]
pub fn seq_geq(s1: u32, s2: u32) -> bool {
    (s1.wrapping_sub(s2) as i32) >= 0
}

/// Returns true if sequence number `s1` is less than or equal to `s2`.
#[inline]
pub fn seq_leq(s1: u32, s2: u32) -> bool {
    (s1.wrapping_sub(s2) as i32) <= 0
}

struct ParsedTcp {
    key: FlowKey,
    seq: u32,
    payload_len: usize,
    seg_len: u32,
    syn: bool,
    rst: bool,
    fin: bool,
}

fn parse_tcp(packet: &[u8], l2: bool) -> Option<ParsedTcp> {
    let ip = if l2 {
        let ethertype = u16::from_be_bytes([*packet.get(12)?, *packet.get(13)?]);
        match ethertype {
            0x0800 | 0x86DD => packet.get(ETHERNET_HEADER_LEN..)?,
            _ => return None,
        }
    } else {
        packet
    };

    let version = ip.first()? >> 4;
    let (proto, tcp_bytes, src, dst) = match version {
        4 => {
            let ihl_byte = *ip.first()?;
            let ihl = usize::from(ihl_byte & 0x0F) * 4;
            if ihl < 20 {
                return None;
            }
            let ip_header = ip.get(..ihl)?;
            let total_len = u16::from_be_bytes([ip_header[2], ip_header[3]]) as usize;
            let ip_packet = if total_len != 0 {
                ip.get(..total_len)?
            } else {
                ip
            };
            let tcp_slice = ip_packet.get(ihl..)?;
            let proto = ip_header[9];
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src[..4].copy_from_slice(&ip_header[12..16]);
            dst[..4].copy_from_slice(&ip_header[16..20]);
            (proto, tcp_slice, src, dst)
        }
        6 => {
            let ip_header = ip.get(..40)?;
            let payload_len_field = u16::from_be_bytes([ip_header[4], ip_header[5]]) as usize;
            let next_hdr = ip_header[6];
            let ip_packet = if payload_len_field != 0 {
                let total = 40 + payload_len_field;
                ip.get(..total)?
            } else {
                ip
            };
            let tcp_slice = ip_packet.get(40..)?;
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&ip_header[8..24]);
            dst.copy_from_slice(&ip_header[24..40]);
            (next_hdr, tcp_slice, src, dst)
        }
        _ => return None,
    };

    if proto != 6 {
        return None;
    }

    let tcp_header = tcp_bytes.get(..20)?;
    let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
    let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);
    let seq = u32::from_be_bytes([tcp_header[4], tcp_header[5], tcp_header[6], tcp_header[7]]);
    let data_offset = usize::from(tcp_header[12] >> 4) * 4;
    if data_offset < 20 {
        return None;
    }
    let tcp_full_header = tcp_bytes.get(..data_offset)?;
    let flags = tcp_full_header[13];
    let fin = (flags & 0x01) != 0;
    let syn = (flags & 0x02) != 0;
    let rst = (flags & 0x04) != 0;
    let payload_len = tcp_bytes.len() - data_offset;
    let fin_advance: u32 = if fin { 1 } else { 0 };
    let seg_len = (payload_len as u32) + fin_advance;

    Some(ParsedTcp {
        key: FlowKey {
            src,
            dst,
            src_port,
            dst_port,
            proto: 6,
        },
        seq,
        payload_len,
        seg_len,
        syn,
        rst,
        fin,
    })
}

fn drain_contiguous_slots<F>(flow: &mut FlowReorderState, emit: &mut F)
where
    F: FnMut(&[u8]),
{
    while let Some(idx) = flow
        .slots
        .iter()
        .position(|slot| slot.valid && slot.seq == flow.expected_seq)
    {
        let slot = &mut flow.slots[idx];
        let seg_len = slot.seg_len;
        emit(&slot.data[..slot.len as usize]);
        flow.expected_seq = slot.seq.wrapping_add(seg_len);
        slot.valid = false;
        flow.slot_count = flow.slot_count.saturating_sub(1);
    }

    if flow.slot_count == 0 {
        flow.deadline_ms = 0;
    }
}

/// Zero-allocation flow-aware micro-reorder buffer.
pub struct ReorderBuffer {
    micro_deadline_ms: u64,
    flows: Box<[FlowReorderState; MAX_CONCURRENT_TRACKED_FLOWS]>,
}

impl ReorderBuffer {
    /// Create a new reorder buffer with the specified eviction deadline in milliseconds.
    pub fn new(micro_deadline_ms: u64) -> Self {
        let flows: Vec<FlowReorderState> = (0..MAX_CONCURRENT_TRACKED_FLOWS)
            .map(|_| FlowReorderState::new())
            .collect();
        let flows = flows
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("size mismatch"));
        Self {
            micro_deadline_ms: micro_deadline_ms.max(1),
            flows,
        }
    }

    /// Return the active micro-reorder eviction deadline in milliseconds.
    #[inline]
    pub fn deadline_ms(&self) -> u64 {
        self.micro_deadline_ms
    }

    /// Dynamically update the micro-reorder eviction deadline in milliseconds.
    #[inline]
    pub fn set_deadline_ms(&mut self, deadline_ms: u64) {
        self.micro_deadline_ms = deadline_ms.max(1);
    }

    fn flush_flow_slots<F>(&mut self, flow_idx: usize, emit: &mut F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let flow = &mut self.flows[flow_idx];
        if flow.slot_count == 0 {
            flow.deadline_ms = 0;
            return 0;
        }

        let mut indices = [0usize; MAX_FLOW_REORDER_SLOTS];
        let mut count = 0;
        for (i, slot) in flow.slots.iter().enumerate() {
            if slot.valid {
                indices[count] = i;
                count += 1;
            }
        }

        // Sort slot indices by sequence number in ascending RFC 793 order
        indices[..count].sort_by(|&a, &b| {
            let seq_a = flow.slots[a].seq;
            let seq_b = flow.slots[b].seq;
            let diff = seq_a.wrapping_sub(seq_b) as i32;
            diff.cmp(&0)
        });

        let mut flushed = 0;
        for &idx in &indices[..count] {
            let slot = &mut flow.slots[idx];
            let seg_len = slot.seg_len;
            emit(&slot.data[..slot.len as usize]);
            let slot_end = slot.seq.wrapping_add(seg_len);
            if seq_after(slot_end, flow.expected_seq) {
                flow.expected_seq = slot_end;
            }
            slot.valid = false;
            flushed += 1;
        }

        flow.slot_count = 0;
        flow.deadline_ms = 0;
        flushed
    }

    fn find_or_create_flow<F>(&mut self, key: &FlowKey, now_ms: u64, emit: &mut F) -> usize
    where
        F: FnMut(&[u8]),
    {
        // 1. Look for matching initialized flow
        for (i, flow) in self.flows.iter_mut().enumerate() {
            if flow.initialized && flow.key == *key {
                flow.last_seen_ms = now_ms;
                return i;
            }
        }

        // 2. Look for an unused slot
        for (i, flow) in self.flows.iter_mut().enumerate() {
            if !flow.initialized {
                flow.key = key.clone();
                flow.last_seen_ms = now_ms;
                flow.expected_seq = 0;
                flow.deadline_ms = 0;
                flow.slot_count = 0;
                for s in &mut flow.slots {
                    s.valid = false;
                }
                return i;
            }
        }

        // 3. Table full: evict strictly oldest LRU flow (lowest index wins ties)
        let mut lru_idx = 0;
        let mut min_last_seen = self.flows[0].last_seen_ms;
        for (idx, f) in self.flows.iter().enumerate().skip(1) {
            if f.last_seen_ms < min_last_seen {
                min_last_seen = f.last_seen_ms;
                lru_idx = idx;
            }
        }

        self.flush_flow_slots(lru_idx, emit);
        let flow = &mut self.flows[lru_idx];
        flow.key = key.clone();
        flow.initialized = false;
        flow.last_seen_ms = now_ms;
        flow.expected_seq = 0;
        flow.deadline_ms = 0;
        flow.slot_count = 0;
        for s in &mut flow.slots {
            s.valid = false;
        }
        lru_idx
    }

    /// Process an ingress packet through the reorder buffer.
    ///
    /// Packets that arrive in order or cannot be reordered are passed to `emit` immediately.
    /// Out-of-order packets are buffered until missing packets arrive or the deadline expires.
    pub fn process<F>(
        &mut self,
        packet: &[u8],
        l2: bool,
        now_ms: u64,
        mut emit: F,
    ) -> ReorderOutcome
    where
        F: FnMut(&[u8]),
    {
        let Some(parsed) = parse_tcp(packet, l2) else {
            emit(packet);
            return ReorderOutcome::Bypassed;
        };

        // TCP RST resets matching flow and bypasses
        if parsed.rst {
            for flow in self.flows.iter_mut() {
                if flow.initialized && flow.key == parsed.key {
                    flow.reset();
                    break;
                }
            }
            emit(packet);
            return ReorderOutcome::Bypassed;
        }

        // TCP SYN initializes/updates sequence and bypasses
        if parsed.syn {
            let flow_idx = self.find_or_create_flow(&parsed.key, now_ms, &mut emit);
            let flow = &mut self.flows[flow_idx];
            flow.expected_seq = parsed.seq.wrapping_add(1);
            flow.initialized = true;
            flow.slot_count = 0;
            flow.deadline_ms = 0;
            for s in &mut flow.slots {
                s.valid = false;
            }
            emit(packet);
            return ReorderOutcome::Bypassed;
        }

        // Pure ACK (no payload and no FIN) bypasses reordering
        if parsed.payload_len == 0 && !parsed.fin {
            emit(packet);
            return ReorderOutcome::Bypassed;
        }

        let flow_idx = self.find_or_create_flow(&parsed.key, now_ms, &mut emit);
        let flow = &mut self.flows[flow_idx];

        // Uninitialized flow: initialize with this packet's sequence range
        if !flow.initialized {
            flow.expected_seq = parsed.seq.wrapping_add(parsed.seg_len);
            flow.initialized = true;
            flow.last_seen_ms = now_ms;
            emit(packet);
            return ReorderOutcome::InOrder;
        }

        flow.last_seen_ms = now_ms;

        // In-order packet
        if parsed.seq == flow.expected_seq {
            emit(packet);
            flow.expected_seq = parsed.seq.wrapping_add(parsed.seg_len);
            drain_contiguous_slots(flow, &mut emit);
            return ReorderOutcome::InOrder;
        }
        // Out-of-order gap in the future
        if seq_after(parsed.seq, flow.expected_seq) {
            let deadline_expired = flow.deadline_ms != 0 && now_ms >= flow.deadline_ms;
            let buffer_full = flow.slot_count >= MAX_FLOW_REORDER_SLOTS;

            if buffer_full || deadline_expired {
                self.flush_flow_slots(flow_idx, &mut emit);
                let flow = &mut self.flows[flow_idx];

                if parsed.seq == flow.expected_seq {
                    emit(packet);
                    flow.expected_seq = parsed.seq.wrapping_add(parsed.seg_len);
                    return ReorderOutcome::Flushed;
                } else if seq_after(parsed.seq, flow.expected_seq) {
                    if packet.len() <= MAX_SLOT_PACKET_LEN {
                        let slot = &mut flow.slots[0];
                        slot.seq = parsed.seq;
                        slot.seg_len = parsed.seg_len;
                        slot.len = packet.len() as u16;
                        slot.valid = true;
                        slot.data[..packet.len()].copy_from_slice(packet);
                        flow.slot_count = 1;
                        flow.deadline_ms = now_ms.saturating_add(self.micro_deadline_ms);
                        return ReorderOutcome::Flushed;
                    } else {
                        emit(packet);
                        flow.expected_seq = parsed.seq.wrapping_add(parsed.seg_len);
                        return ReorderOutcome::Flushed;
                    }
                } else {
                    emit(packet);
                    let seq_end = parsed.seq.wrapping_add(parsed.seg_len);
                    if seq_after(seq_end, flow.expected_seq) {
                        flow.expected_seq = seq_end;
                    }
                    return ReorderOutcome::Flushed;
                }
            } else if packet.len() <= MAX_SLOT_PACKET_LEN {
                for slot in flow.slots.iter() {
                    if slot.valid && slot.seq == parsed.seq {
                        return ReorderOutcome::Duplicate;
                    }
                }

                for slot in flow.slots.iter_mut() {
                    if !slot.valid {
                        slot.seq = parsed.seq;
                        slot.seg_len = parsed.seg_len;
                        slot.len = packet.len() as u16;
                        slot.valid = true;
                        slot.data[..packet.len()].copy_from_slice(packet);
                        flow.slot_count += 1;
                        if flow.deadline_ms == 0 {
                            flow.deadline_ms = now_ms.saturating_add(self.micro_deadline_ms);
                        }
                        return ReorderOutcome::Buffered;
                    }
                }

                return ReorderOutcome::Buffered;
            } else {
                emit(packet);
                let seq_end = parsed.seq.wrapping_add(parsed.seg_len);
                if seq_after(seq_end, flow.expected_seq) {
                    flow.expected_seq = seq_end;
                }
                return ReorderOutcome::Bypassed;
            }
        }

        // Retransmitted / duplicate / old packet (seq_before(parsed.seq, flow.expected_seq) or exact match)
        emit(packet);
        if seq_before(parsed.seq, flow.expected_seq) {
            let seq_end = parsed.seq.wrapping_add(parsed.seg_len);
            if seq_after(seq_end, flow.expected_seq) {
                flow.expected_seq = seq_end;
                drain_contiguous_slots(flow, &mut emit);
                return ReorderOutcome::InOrder;
            }
            return ReorderOutcome::Duplicate;
        }

        ReorderOutcome::Duplicate
    }

    /// Check all active flows for expired reorder deadlines and flush held slots.
    ///
    /// Returns the total number of packets flushed.
    pub fn poll_timeouts<F>(&mut self, now_ms: u64, mut emit: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let mut total_flushed = 0;
        for i in 0..MAX_CONCURRENT_TRACKED_FLOWS {
            if self.flows[i].initialized
                && self.flows[i].deadline_ms != 0
                && now_ms >= self.flows[i].deadline_ms
            {
                total_flushed += self.flush_flow_slots(i, &mut emit);
            }
        }
        total_flushed
    }
}

impl Default for ReorderBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_REORDER_DEADLINE_MS)
    }
}
