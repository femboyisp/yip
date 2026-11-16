//! Local TUN `virtio_net_hdr` (GSO/GRO) framing + the RX coalescer / TX splitter.
//! Purely local to the yipd↔kernel-TUN boundary — never touches the wire.

pub const VNET_HDR_LEN: usize = 10;
pub const GSO_NONE: u8 = 0;
pub const GSO_TCPV4: u8 = 1;
pub const GSO_TCPV6: u8 = 4;
pub const GSO_UDP_L4: u8 = 5;
pub const F_NEEDS_CSUM: u8 = 1;
pub const F_DATA_VALID: u8 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

pub type VnetHdr = VirtioNetHdr;

/// Slices a GSO super-packet payload into segments of at most `mss` bytes.
///
/// Returns an empty vector if `buf` is empty. If `mss == 0`, returns a single slice containing `buf`.
pub fn slice_gso_payload(buf: &[u8], mss: usize) -> Vec<&[u8]> {
    if buf.is_empty() {
        return Vec::new();
    }
    if mss == 0 {
        return vec![buf];
    }
    buf.chunks(mss).collect()
}

/// Slices a GSO super-packet into segments of at most `mss` bytes.
#[inline]
pub fn slice_gso_packet(buf: &[u8], mss: usize) -> Vec<&[u8]> {
    slice_gso_payload(buf, mss)
}

pub fn read_vnet_hdr(buf: &[u8]) -> Option<VirtioNetHdr> {
    if buf.len() < VNET_HDR_LEN {
        return None;
    }
    let u16h = |a: usize| u16::from_ne_bytes([buf[a], buf[a + 1]]);
    Some(VirtioNetHdr {
        flags: buf[0],
        gso_type: buf[1],
        hdr_len: u16h(2),
        gso_size: u16h(4),
        csum_start: u16h(6),
        csum_offset: u16h(8),
    })
}

pub fn write_vnet_hdr(h: &VirtioNetHdr, out: &mut [u8]) {
    assert!(out.len() >= VNET_HDR_LEN);
    out[0] = h.flags;
    out[1] = h.gso_type;
    out[2..4].copy_from_slice(&h.hdr_len.to_ne_bytes());
    out[4..6].copy_from_slice(&h.gso_size.to_ne_bytes());
    out[6..8].copy_from_slice(&h.csum_start.to_ne_bytes());
    out[8..10].copy_from_slice(&h.csum_offset.to_ne_bytes());
}

pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
pub(crate) const TCP_FLAG_PSH: u8 = 0x08;
pub(crate) const TCP_FLAG_URG: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowKey {
    V4 {
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
    },
    V6 {
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
    },
}

impl FlowKey {
    pub const EMPTY: Self = Self::V4 {
        src: [0; 4],
        dst: [0; 4],
        sport: 0,
        dport: 0,
    };
}

impl Default for FlowKey {
    fn default() -> Self {
        Self::EMPTY
    }
}

pub(crate) struct Ipv4Tcp<'a> {
    pub ip_hdr_len: usize,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read only by parse_ipv4_tcp_extracts_fields; split_gro/Coalescer derive \
                      the segment header length from payload_off instead"
        )
    )]
    pub tcp_hdr_len: usize,
    pub total_len: usize,
    pub key: FlowKey,
    pub seq: u32,
    pub flags: u8,
    pub payload_off: usize,
    pub payload_len: usize,
    pub bytes: &'a [u8],
}

pub(crate) fn parse_ipv4_tcp(pkt: &[u8]) -> Option<Ipv4Tcp<'_>> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    if pkt[9] != 6 {
        return None;
    } // not TCP
      // fragmentation: MF (bit) or non-zero frag offset in bytes 6..8
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if (frag & 0x2000) != 0 || (frag & 0x1FFF) != 0 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if total_len < ihl || pkt.len() < total_len {
        return None;
    }
    if total_len < ihl + 20 {
        return None;
    }
    let t = ihl;
    let data_off = usize::from(pkt[t + 12] >> 4) * 4;
    if data_off < 20 || total_len < ihl + data_off {
        return None;
    }
    let sport = u16::from_be_bytes([pkt[t], pkt[t + 1]]);
    let dport = u16::from_be_bytes([pkt[t + 2], pkt[t + 3]]);
    let seq = u32::from_be_bytes([pkt[t + 4], pkt[t + 5], pkt[t + 6], pkt[t + 7]]);
    let flags = pkt[t + 13];
    let payload_off = ihl + data_off;
    Some(Ipv4Tcp {
        ip_hdr_len: ihl,
        tcp_hdr_len: data_off,
        total_len,
        key: FlowKey::V4 {
            src: [pkt[12], pkt[13], pkt[14], pkt[15]],
            dst: [pkt[16], pkt[17], pkt[18], pkt[19]],
            sport,
            dport,
        },
        seq,
        flags,
        payload_off,
        payload_len: total_len - payload_off,
        bytes: pkt,
    })
}

pub(crate) struct Ipv6Tcp<'a> {
    pub ip_hdr_len: usize,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read only by parse_ipv6_tcp_extracts_fields; split_gro/Coalescer derive \
                      the segment header length from payload_off instead"
        )
    )]
    pub tcp_hdr_len: usize,
    pub total_len: usize,
    pub key: FlowKey,
    pub seq: u32,
    pub flags: u8,
    pub payload_off: usize,
    pub payload_len: usize,
    pub bytes: &'a [u8],
}

pub(crate) fn parse_ipv6_tcp(pkt: &[u8]) -> Option<Ipv6Tcp<'_>> {
    if pkt.len() < 40 || (pkt[0] >> 4) != 6 {
        return None;
    }
    if pkt[6] != 6 {
        return None;
    }
    let ipv6_payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    let total_len = 40 + ipv6_payload_len;
    if total_len < 60 || pkt.len() < total_len {
        return None;
    }
    let t = 40;
    let data_off = usize::from(pkt[t + 12] >> 4) * 4;
    if data_off < 20 || total_len < 40 + data_off {
        return None;
    }
    let sport = u16::from_be_bytes([pkt[t], pkt[t + 1]]);
    let dport = u16::from_be_bytes([pkt[t + 2], pkt[t + 3]]);
    let seq = u32::from_be_bytes([pkt[t + 4], pkt[t + 5], pkt[t + 6], pkt[t + 7]]);
    let flags = pkt[t + 13];
    let payload_off = 40 + data_off;
    let mut src = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Tcp {
        ip_hdr_len: 40,
        tcp_hdr_len: data_off,
        total_len,
        key: FlowKey::V6 {
            src,
            dst,
            sport,
            dport,
        },
        seq,
        flags,
        payload_off,
        payload_len: total_len - payload_off,
        bytes: pkt,
    })
}

pub(crate) struct Ipv4Udp<'a> {
    pub ip_hdr_len: usize,
    pub total_len: usize,
    pub key: FlowKey,
    pub payload_off: usize,
    pub payload_len: usize,
    pub bytes: &'a [u8],
}

pub(crate) fn parse_ipv4_udp(pkt: &[u8]) -> Option<Ipv4Udp<'_>> {
    if pkt.len() < 28 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 || pkt[9] != 17 {
        return None;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if (frag & 0x3FFF) != 0 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if pkt.len() < total_len || total_len < ihl + 8 {
        return None;
    }
    let u = ihl;
    let udp_len = usize::from(u16::from_be_bytes([pkt[u + 4], pkt[u + 5]]));
    if udp_len < 8 || total_len < ihl + udp_len {
        return None;
    }
    let sport = u16::from_be_bytes([pkt[u], pkt[u + 1]]);
    let dport = u16::from_be_bytes([pkt[u + 2], pkt[u + 3]]);
    let payload_off = ihl + 8;
    Some(Ipv4Udp {
        ip_hdr_len: ihl,
        total_len,
        key: FlowKey::V4 {
            src: [pkt[12], pkt[13], pkt[14], pkt[15]],
            dst: [pkt[16], pkt[17], pkt[18], pkt[19]],
            sport,
            dport,
        },
        payload_off,
        payload_len: udp_len - 8,
        bytes: pkt,
    })
}

pub(crate) struct Ipv6Udp<'a> {
    pub ip_hdr_len: usize,
    pub total_len: usize,
    pub key: FlowKey,
    pub payload_off: usize,
    pub payload_len: usize,
    pub bytes: &'a [u8],
}

pub(crate) fn parse_ipv6_udp_opt(pkt: &[u8], allow_zero_csum: bool) -> Option<Ipv6Udp<'_>> {
    if pkt.len() < 48 || (pkt[0] >> 4) != 6 || pkt[6] != 17 {
        return None;
    }
    let ipv6_payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    let total_len = 40 + ipv6_payload_len;
    if total_len < 48 || pkt.len() < total_len {
        return None;
    }
    let u = 40;
    let udp_len = usize::from(u16::from_be_bytes([pkt[u + 4], pkt[u + 5]]));
    if udp_len < 8 || udp_len > ipv6_payload_len {
        return None;
    }
    // RFC 8200 section 8.1: IPv6 UDP checksum must not be 0 unless kernel/caller offloaded
    // via F_NEEDS_CSUM (where csum field may be 0 or unpopulated before hardware/NIC fills it).
    let csum = u16::from_be_bytes([pkt[u + 6], pkt[u + 7]]);
    if csum == 0 && !allow_zero_csum {
        return None;
    }
    let sport = u16::from_be_bytes([pkt[u], pkt[u + 1]]);
    let dport = u16::from_be_bytes([pkt[u + 2], pkt[u + 3]]);
    let mut src = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Udp {
        ip_hdr_len: 40,
        total_len,
        key: FlowKey::V6 {
            src,
            dst,
            sport,
            dport,
        },
        payload_off: 48,
        payload_len: udp_len - 8,
        bytes: pkt,
    })
}

pub(crate) fn parse_ipv6_udp(pkt: &[u8]) -> Option<Ipv6Udp<'_>> {
    parse_ipv6_udp_opt(pkt, false)
}

/// Accumulate 16-bit words in network-byte-order across `data` into a 32-bit sum.
/// Any trailing odd byte is treated as `byte << 8` per RFC 768 / RFC 1071.
#[inline]
pub(crate) fn sum_16(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(u16::from(data[i]) << 8);
    }
    sum
}

/// Fold a 32-bit accumulated sum down to 16 bits and invert (one's complement).
#[inline]
pub(crate) fn fold_csum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum & 0xFFFF).expect("folded sum fits u16")
}

/// Precompute the invariant word sum of an IPv4 header (excluding `total_len`,
/// `ip_id`, and `checksum`), allowing O(1) checksum computation across GSO slices.
#[inline]
pub(crate) fn ipv4_base_sum(hdr: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    sum += u32::from(u16::from_be_bytes([hdr[0], hdr[1]]));
    sum += u32::from(u16::from_be_bytes([hdr[6], hdr[7]]));
    sum += u32::from(u16::from_be_bytes([hdr[8], hdr[9]]));
    sum += u32::from(u16::from_be_bytes([hdr[12], hdr[13]]));
    sum += u32::from(u16::from_be_bytes([hdr[14], hdr[15]]));
    sum += u32::from(u16::from_be_bytes([hdr[16], hdr[17]]));
    sum += u32::from(u16::from_be_bytes([hdr[18], hdr[19]]));
    sum += sum_16(&hdr[20..]);
    sum
}

/// Compute the IPv4 header checksum from a precomputed base sum, total length, and IP-ID.
#[inline]
pub(crate) fn ipv4_checksum_with_base(base_sum: u32, total_len: u16, ip_id: u16) -> u16 {
    fold_csum(base_sum + u32::from(total_len) + u32::from(ip_id))
}

pub(crate) fn ipv4_checksum(hdr: &mut [u8]) {
    hdr[10] = 0;
    hdr[11] = 0;
    let sum = sum_16(hdr);
    let ck = fold_csum(sum);
    hdr[10..12].copy_from_slice(&ck.to_be_bytes());
}

pub(crate) fn tcp_checksum(pkt: &mut [u8], ip_hdr_len: usize) {
    let total = pkt.len();
    let tcp_off = ip_hdr_len;
    // zero the checksum field
    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let tcp_len = total - tcp_off;
    let mut sum: u32 = 0;
    // pseudo-header: src(4)+dst(4)+zero+proto(6)+tcp_len
    for i in (12..20).step_by(2) {
        sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
    }
    sum += u32::from(6u16);
    sum += u32::try_from(tcp_len).expect("tcp_len fits u32") & 0xFFFF;
    sum += sum_16(&pkt[tcp_off..total]);
    let ck = fold_csum(sum);
    pkt[tcp_off + 16..tcp_off + 18].copy_from_slice(&ck.to_be_bytes());
}

pub(crate) fn ipv6_tcp_checksum(pkt: &mut [u8]) {
    if pkt.len() < 60 {
        return;
    }
    let total = pkt.len();
    let tcp_off = 40;
    // zero the checksum field
    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let tcp_len = total - tcp_off;
    let mut sum: u32 = 0;
    // pseudo-header: src(16) + dst(16) + upper-layer packet length (4) + zero(3) + next_header(1)
    for i in (8..40).step_by(2) {
        sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
    }
    let tcp_len_u32 = u32::try_from(tcp_len).expect("tcp_len fits u32");
    sum += tcp_len_u32 >> 16;
    sum += tcp_len_u32 & 0xFFFF;
    sum += u32::from(6u16);
    sum += sum_16(&pkt[tcp_off..total]);
    let ck = fold_csum(sum);
    pkt[tcp_off + 16..tcp_off + 18].copy_from_slice(&ck.to_be_bytes());
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "kept for tests and reference checksum verification"
    )
)]
pub(crate) fn udp_checksum(pkt: &mut [u8], ip_hdr_len: usize) {
    if pkt.len() < ip_hdr_len + 8 {
        return;
    }
    let total = pkt.len();
    let udp_off = ip_hdr_len;
    // zero the checksum field
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let udp_len = total - udp_off;
    let mut sum: u32 = 0;
    // pseudo-header: src(4) + dst(4) + zero(1) + proto(17) + udp_len(2)
    for i in (12..20).step_by(2) {
        sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
    }
    sum += u32::from(17u16);
    sum += u32::try_from(udp_len).expect("udp_len fits u32") & 0xFFFF;
    sum += sum_16(&pkt[udp_off..total]);
    let mut ck = fold_csum(sum);
    if ck == 0 {
        ck = 0xFFFF;
    }
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&ck.to_be_bytes());
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "kept for tests and reference checksum verification"
    )
)]
pub(crate) fn ipv6_udp_checksum(pkt: &mut [u8]) {
    if pkt.len() < 48 {
        return;
    }
    let total = pkt.len();
    let udp_off = 40;
    // zero the checksum field
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let udp_len = total - udp_off;
    let mut sum: u32 = 0;
    // pseudo-header: src(16) + dst(16) + upper-layer packet length (4) + zero(3) + next_header(1)
    for i in (8..40).step_by(2) {
        sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
    }
    let udp_len_u32 = u32::try_from(udp_len).expect("udp_len fits u32");
    sum += udp_len_u32 >> 16;
    sum += udp_len_u32 & 0xFFFF;
    sum += u32::from(17u16);
    sum += sum_16(&pkt[udp_off..total]);
    let mut ck = fold_csum(sum);
    if ck == 0 {
        ck = 0xFFFF;
    }
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&ck.to_be_bytes());
}

/// Compute the uncomplemented 16-bit one's-complement pseudo-header checksum sum
/// over IPv4/IPv6 source, destination, protocol number (`proto`), and upper-layer length (`l4_len`).
pub(crate) fn pseudo_header_checksum(key: &FlowKey, proto: u8, l4_len: u32) -> u16 {
    let mut sum: u32 = 0;
    match key {
        FlowKey::V4 { src, dst, .. } => {
            sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
            sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
            sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
            sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
            sum += u32::from(proto);
            sum += l4_len;
        }
        FlowKey::V6 { src, dst, .. } => {
            for i in (0..16).step_by(2) {
                sum += u32::from(u16::from_be_bytes([src[i], src[i + 1]]));
            }
            for i in (0..16).step_by(2) {
                sum += u32::from(u16::from_be_bytes([dst[i], dst[i + 1]]));
            }
            sum += l4_len >> 16;
            sum += l4_len & 0xFFFF;
            sum += u32::from(proto);
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    u16::try_from(sum & 0xFFFF).expect("folded sum fits u16")
}

pub(crate) fn udp_pseudo_header_checksum(key: &FlowKey, udp_len: u16) -> u16 {
    pseudo_header_checksum(key, 17, u32::from(udp_len))
}

pub(crate) fn tcp_pseudo_header_checksum(key: &FlowKey, tcp_len: u32) -> u16 {
    pseudo_header_checksum(key, 6, tcp_len)
}

enum ParsedTcp<'a> {
    V4(Ipv4Tcp<'a>),
    V6(Ipv6Tcp<'a>),
}

impl<'a> ParsedTcp<'a> {
    #[inline]
    fn key(&self) -> FlowKey {
        match self {
            Self::V4(x) => x.key,
            Self::V6(x) => x.key,
        }
    }

    #[inline]
    fn seq(&self) -> u32 {
        match self {
            Self::V4(x) => x.seq,
            Self::V6(x) => x.seq,
        }
    }

    #[inline]
    fn flags(&self) -> u8 {
        match self {
            Self::V4(x) => x.flags,
            Self::V6(x) => x.flags,
        }
    }

    #[inline]
    fn ip_hdr_len(&self) -> usize {
        match self {
            Self::V4(x) => x.ip_hdr_len,
            Self::V6(x) => x.ip_hdr_len,
        }
    }

    #[inline]
    fn payload_off(&self) -> usize {
        match self {
            Self::V4(x) => x.payload_off,
            Self::V6(x) => x.payload_off,
        }
    }

    #[inline]
    fn payload_len(&self) -> usize {
        match self {
            Self::V4(x) => x.payload_len,
            Self::V6(x) => x.payload_len,
        }
    }

    #[inline]
    fn total_len(&self) -> usize {
        match self {
            Self::V4(x) => x.total_len,
            Self::V6(x) => x.total_len,
        }
    }

    #[inline]
    fn bytes(&self) -> &'a [u8] {
        match self {
            Self::V4(x) => x.bytes,
            Self::V6(x) => x.bytes,
        }
    }
}

enum ParsedUdp<'a> {
    V4(Ipv4Udp<'a>),
    V6(Ipv6Udp<'a>),
}

impl<'a> ParsedUdp<'a> {
    #[inline]
    fn key(&self) -> FlowKey {
        match self {
            Self::V4(x) => x.key,
            Self::V6(x) => x.key,
        }
    }

    #[inline]
    fn ip_hdr_len(&self) -> usize {
        match self {
            Self::V4(x) => x.ip_hdr_len,
            Self::V6(x) => x.ip_hdr_len,
        }
    }

    #[inline]
    fn payload_off(&self) -> usize {
        match self {
            Self::V4(x) => x.payload_off,
            Self::V6(x) => x.payload_off,
        }
    }

    #[inline]
    fn payload_len(&self) -> usize {
        match self {
            Self::V4(x) => x.payload_len,
            Self::V6(x) => x.payload_len,
        }
    }

    #[inline]
    fn total_len(&self) -> usize {
        match self {
            Self::V4(x) => x.total_len,
            Self::V6(x) => x.total_len,
        }
    }

    #[inline]
    fn bytes(&self) -> &'a [u8] {
        match self {
            Self::V4(x) => x.bytes,
            Self::V6(x) => x.bytes,
        }
    }
}

enum ParsedPacket<'a> {
    Tcp(ParsedTcp<'a>),
    Udp(ParsedUdp<'a>),
}

fn parse_ip_packet(pkt: &[u8]) -> Option<ParsedPacket<'_>> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            match pkt[9] {
                6 => parse_ipv4_tcp(pkt).map(|x| ParsedPacket::Tcp(ParsedTcp::V4(x))),
                17 => parse_ipv4_udp(pkt).map(|x| ParsedPacket::Udp(ParsedUdp::V4(x))),
                _ => None,
            }
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            match pkt[6] {
                6 => parse_ipv6_tcp(pkt).map(|x| ParsedPacket::Tcp(ParsedTcp::V6(x))),
                17 => parse_ipv6_udp(pkt).map(|x| ParsedPacket::Udp(ParsedUdp::V6(x))),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Complete a partial (`F_NEEDS_CSUM`) L4 checksum in `pkt` (an L3 packet) as
/// delivered by a vnet_hdr TUN read. The 16-bit field at `csum_start +
/// csum_offset` holds the pseudo-header partial sum; the final checksum is the
/// one's-complement of the folded internet-checksum sum over `pkt[csum_start..]`
/// (which includes that partial field). A computed 0 on a UDP packet (proto 17)
/// is transmitted as `0xFFFF` per RFC 768. Malformed offsets are left untouched.
fn complete_partial_csum(pkt: &mut [u8], csum_start: usize, csum_offset: usize) {
    let field = csum_start + csum_offset;
    if csum_start >= pkt.len() || field + 2 > pkt.len() {
        return;
    }
    let region = &pkt[csum_start..];
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < region.len() {
        sum += u32::from(u16::from_be_bytes([region[i], region[i + 1]]));
        i += 2;
    }
    if i < region.len() {
        sum += u32::from(u16::from(region[i]) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let mut ck = !u16::try_from(sum & 0xFFFF).expect("folded sum fits u16");
    let is_udp = (pkt.first().map(|&b| b >> 4) == Some(4) && pkt.get(9) == Some(&17))
        || (pkt.first().map(|&b| b >> 4) == Some(6) && pkt.get(6) == Some(&17));
    if ck == 0 && is_udp {
        ck = 0xFFFF; // UDP: 0 means "no checksum", the real zero is 0xFFFF
    }
    pkt[field..field + 2].copy_from_slice(&ck.to_be_bytes());
}

pub fn split_gro(frame: &[u8], out: &mut Vec<u8>, offsets: &mut Vec<(usize, usize)>) -> bool {
    out.clear();
    offsets.clear();
    let Some(h) = read_vnet_hdr(frame) else {
        return false;
    };
    let body = &frame[VNET_HDR_LEN..];
    if h.gso_type == GSO_NONE || h.gso_size == 0 {
        let start = out.len();
        out.extend_from_slice(body);
        // A vnet_hdr read with F_NEEDS_CSUM carries an *incomplete* L4 checksum
        // (the kernel offloaded it): the 16-bit field at csum_start+csum_offset
        // holds the pseudo-header partial. We complete it here, because this
        // packet is about to be encrypted and shipped over the wire — the far
        // end writes it back to its TUN as a plain (F_NEEDS_CSUM=0) frame and its
        // kernel/apps expect a valid checksum. Without this, large offloaded
        // packets (e.g. bulk transfers) arrive with a bad checksum and are
        // silently dropped, while tiny packets the kernel checksums in full
        // (e.g. pings) pass — the classic vnet_hdr read-side gotcha.
        if (h.flags & F_NEEDS_CSUM) != 0 {
            let len = out.len() - start;
            complete_partial_csum(
                &mut out[start..start + len],
                usize::from(h.csum_start),
                usize::from(h.csum_offset),
            );
        }
        offsets.push((start, body.len()));
        return true;
    }
    if h.gso_type == GSO_TCPV4 {
        let Some(x) = parse_ipv4_tcp(body) else {
            return false;
        };
        let seg = usize::from(h.gso_size);
        let hdr = x.payload_off; // ip_hdr_len + tcp_hdr_len
        let payload = &body[x.payload_off..x.payload_off + x.payload_len];
        let mut seq = x.seq;
        let mut ip_id = u16::from_be_bytes([body[4], body[5]]);
        let base_sum = ipv4_base_sum(&body[..x.ip_hdr_len]);
        let mut off = 0usize;
        while off < payload.len() {
            let n = seg.min(payload.len() - off);
            let start = out.len();
            out.extend_from_slice(&body[..hdr]); // clone IP+TCP header
            out.extend_from_slice(&payload[off..off + n]);
            let s = &mut out[start..start + hdr + n];
            // patch IP total-length, IP ID, TCP seq; recompute both checksums
            let total = u16::try_from(hdr + n).expect("segment fits u16");
            s[2..4].copy_from_slice(&total.to_be_bytes());
            s[4..6].copy_from_slice(&ip_id.to_be_bytes());
            s[x.ip_hdr_len + 4..x.ip_hdr_len + 8].copy_from_slice(&seq.to_be_bytes());
            let ip_ck = ipv4_checksum_with_base(base_sum, total, ip_id);
            s[10..12].copy_from_slice(&ip_ck.to_be_bytes());
            tcp_checksum(s, x.ip_hdr_len);
            offsets.push((start, hdr + n));
            seq = seq.wrapping_add(u32::try_from(n).expect("n fits u32"));
            ip_id = ip_id.wrapping_add(1);
            off += n;
        }
        return true;
    }
    if h.gso_type == GSO_TCPV6 {
        let Some(x) = parse_ipv6_tcp(body) else {
            return false;
        };
        let seg = usize::from(h.gso_size);
        let hdr = x.payload_off; // 40 + tcp_hdr_len
        let payload = &body[x.payload_off..x.payload_off + x.payload_len];
        let mut seq = x.seq;
        let mut off = 0usize;
        while off < payload.len() {
            let n = seg.min(payload.len() - off);
            let start = out.len();
            out.extend_from_slice(&body[..hdr]); // clone IPv6 + TCP header
            out.extend_from_slice(&payload[off..off + n]);
            let s = &mut out[start..start + hdr + n];
            let ipv6_payload_len = u16::try_from((hdr - 40) + n).expect("segment fits u16");
            s[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
            s[44..48].copy_from_slice(&seq.to_be_bytes());
            ipv6_tcp_checksum(s);
            offsets.push((start, hdr + n));
            seq = seq.wrapping_add(u32::try_from(n).expect("n fits u32"));
            off += n;
        }
        return true;
    }
    if h.gso_type == GSO_UDP_L4 {
        let seg = usize::from(h.gso_size);
        if seg == 0 || body.is_empty() {
            return false;
        }
        match body[0] >> 4 {
            4 => {
                let Some(x) = parse_ipv4_udp(body) else {
                    return false;
                };
                if x.payload_len == 0 {
                    return false;
                }
                let hdr = x.payload_off;
                let payload = &body[x.payload_off..x.payload_off + x.payload_len];
                let mut ip_id = u16::from_be_bytes([body[4], body[5]]);
                let base_sum = ipv4_base_sum(&body[..x.ip_hdr_len]);
                // Precalculate invariant pseudo-header + UDP header sum
                let sport = u16::from_be_bytes([body[x.ip_hdr_len], body[x.ip_hdr_len + 1]]);
                let dport = u16::from_be_bytes([body[x.ip_hdr_len + 2], body[x.ip_hdr_len + 3]]);
                let mut pseudo_base: u32 = 0;
                for i in (12..20).step_by(2) {
                    pseudo_base += u32::from(u16::from_be_bytes([body[i], body[i + 1]]));
                }
                pseudo_base += 17u32 + u32::from(sport) + u32::from(dport);

                let mut off = 0usize;
                while off < payload.len() {
                    let n = seg.min(payload.len() - off);
                    let payload_chunk = &payload[off..off + n];
                    let start = out.len();
                    out.extend_from_slice(&body[..hdr]);
                    out.extend_from_slice(payload_chunk);
                    let s = &mut out[start..start + hdr + n];
                    let total = u16::try_from(hdr + n).expect("segment fits u16");
                    s[2..4].copy_from_slice(&total.to_be_bytes());
                    s[4..6].copy_from_slice(&ip_id.to_be_bytes());
                    let udp_len = u16::try_from(8 + n).expect("udp len fits u16");
                    s[x.ip_hdr_len + 4..x.ip_hdr_len + 6].copy_from_slice(&udp_len.to_be_bytes());
                    let ip_ck = ipv4_checksum_with_base(base_sum, total, ip_id);
                    s[10..12].copy_from_slice(&ip_ck.to_be_bytes());

                    // Fast UDP checksum: pseudo_base + 2 * udp_len + sum_16(payload_chunk)
                    let udp_csum_raw = pseudo_base + 2 * u32::from(udp_len) + sum_16(payload_chunk);
                    let mut udp_ck = fold_csum(udp_csum_raw);
                    if udp_ck == 0 {
                        udp_ck = 0xFFFF;
                    }
                    s[x.ip_hdr_len + 6..x.ip_hdr_len + 8].copy_from_slice(&udp_ck.to_be_bytes());

                    offsets.push((start, hdr + n));
                    ip_id = ip_id.wrapping_add(1);
                    off += n;
                }
                return true;
            }
            6 => {
                let allow_zero = (h.flags & F_NEEDS_CSUM) != 0;
                let Some(x) = parse_ipv6_udp_opt(body, allow_zero) else {
                    return false;
                };
                if x.payload_len == 0 {
                    return false;
                }
                let hdr = x.payload_off;
                let payload = &body[x.payload_off..x.payload_off + x.payload_len];
                let sport = u16::from_be_bytes([body[40], body[41]]);
                let dport = u16::from_be_bytes([body[42], body[43]]);
                let mut pseudo_base: u32 = 0;
                for i in (8..40).step_by(2) {
                    pseudo_base += u32::from(u16::from_be_bytes([body[i], body[i + 1]]));
                }
                pseudo_base += 17u32 + u32::from(sport) + u32::from(dport);

                let mut off = 0usize;
                while off < payload.len() {
                    let n = seg.min(payload.len() - off);
                    let payload_chunk = &payload[off..off + n];
                    let start = out.len();
                    out.extend_from_slice(&body[..hdr]);
                    out.extend_from_slice(payload_chunk);
                    let s = &mut out[start..start + hdr + n];
                    let udp_len = u16::try_from(8 + n).expect("segment fits u16");
                    s[4..6].copy_from_slice(&udp_len.to_be_bytes());
                    s[44..46].copy_from_slice(&udp_len.to_be_bytes());

                    // Fast IPv6 UDP checksum: pseudo_base + 2 * udp_len + sum_16(payload_chunk)
                    let udp_csum_raw = pseudo_base + 2 * u32::from(udp_len) + sum_16(payload_chunk);
                    let mut udp_ck = fold_csum(udp_csum_raw);
                    if udp_ck == 0 {
                        udp_ck = 0xFFFF;
                    }
                    s[46..48].copy_from_slice(&udp_ck.to_be_bytes());

                    offsets.push((start, hdr + n));
                    off += n;
                }
                return true;
            }
            _ => return false,
        }
    }
    false
}

pub const MAX_GSO_SEGMENTS: usize = 64;
pub const MAX_GSO_PAYLOAD: usize = 65_535;
pub const MAX_UDP_GSO_PAYLOAD: usize = 65_507;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingKind {
    Singleton,
    Tcp,
    Udp,
}

pub struct Coalescer {
    pending: Vec<u8>, // [vnet_hdr | ip+l4 hdr | payloads]; empty => nothing pending
    out: Vec<u8>,     // holds a flushed frame for the returned borrow
    has_pending: bool,
    kind: PendingKind,
    sealed: bool, // pending cannot be extended (boundary flags/sealed/max limits)
    key: FlowKey,
    next_seq: u32,
    gso_size: u16,
    ip_hdr_len: usize,
    l3_hdr_len: usize, // ip_hdr_len + l4_hdr_len (payload offset within the L3 packet)
    segs: usize,
    has_uso: bool,
}

impl Coalescer {
    pub fn new(has_uso: bool) -> Self {
        Self {
            // Allocate headroom for virtio_net_hdr (10 bytes) + maximum L3/L4 headers
            // (up to 60 bytes IPv4/IPv6 + 60 bytes TCP options) + maximum payload.
            pending: Vec::with_capacity(MAX_GSO_PAYLOAD + 256),
            out: Vec::with_capacity(MAX_GSO_PAYLOAD + 256),
            has_pending: false,
            kind: PendingKind::Singleton,
            sealed: false,
            key: FlowKey::default(),
            next_seq: 0,
            gso_size: 0,
            ip_hdr_len: 0,
            l3_hdr_len: 0,
            segs: 0,
            has_uso,
        }
    }

    pub fn has_uso(&self) -> bool {
        self.has_uso
    }

    pub fn set_has_uso(&mut self, has_uso: bool) {
        self.has_uso = has_uso;
    }

    fn finalize_pending(&mut self) {
        if !self.has_pending {
            return;
        }
        match self.kind {
            PendingKind::Tcp => {
                if self.segs == 1 {
                    let h = VnetHdr::default();
                    write_vnet_hdr(&h, &mut self.pending[..VNET_HDR_LEN]);
                } else {
                    let ip = VNET_HDR_LEN;
                    let l3_len = self.pending.len() - VNET_HDR_LEN;
                    let tcp_len =
                        u32::try_from(l3_len.saturating_sub(self.ip_hdr_len)).unwrap_or(u32::MAX);
                    let csum = tcp_pseudo_header_checksum(&self.key, tcp_len);
                    let tcp_off = ip + self.ip_hdr_len;
                    self.pending[tcp_off + 16..tcp_off + 18].copy_from_slice(&csum.to_be_bytes());

                    match self.key {
                        FlowKey::V4 { .. } => {
                            let total = u16::try_from(l3_len).unwrap_or(u16::MAX);
                            self.pending[ip + 2..ip + 4].copy_from_slice(&total.to_be_bytes());
                            ipv4_checksum(&mut self.pending[ip..ip + self.ip_hdr_len]);
                            let h = VnetHdr {
                                flags: F_NEEDS_CSUM,
                                gso_type: GSO_TCPV4,
                                hdr_len: u16::try_from(self.l3_hdr_len).unwrap_or(0),
                                gso_size: self.gso_size,
                                csum_start: u16::try_from(self.ip_hdr_len).unwrap_or(0),
                                csum_offset: 16,
                            };
                            write_vnet_hdr(&h, &mut self.pending[..VNET_HDR_LEN]);
                        }
                        FlowKey::V6 { .. } => {
                            let ipv6_payload_len =
                                u16::try_from(l3_len.saturating_sub(40)).unwrap_or(u16::MAX);
                            self.pending[ip + 4..ip + 6]
                                .copy_from_slice(&ipv6_payload_len.to_be_bytes());
                            let h = VnetHdr {
                                flags: F_NEEDS_CSUM,
                                gso_type: GSO_TCPV6,
                                hdr_len: u16::try_from(self.l3_hdr_len).unwrap_or(0),
                                gso_size: self.gso_size,
                                csum_start: 40,
                                csum_offset: 16,
                            };
                            write_vnet_hdr(&h, &mut self.pending[..VNET_HDR_LEN]);
                        }
                    }
                }
            }
            PendingKind::Udp => {
                let ip = VNET_HDR_LEN;
                let l3_len = self.pending.len() - VNET_HDR_LEN;
                if self.segs == 1 {
                    let h = VnetHdr::default();
                    write_vnet_hdr(&h, &mut self.pending[..VNET_HDR_LEN]);
                } else {
                    let udp_len =
                        u16::try_from(l3_len - self.ip_hdr_len).expect("udp_len fits u16");
                    let csum = udp_pseudo_header_checksum(&self.key, udp_len);
                    let udp_off = ip + self.ip_hdr_len;
                    self.pending[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
                    self.pending[udp_off + 6..udp_off + 8].copy_from_slice(&csum.to_be_bytes());

                    match self.key {
                        FlowKey::V4 { .. } => {
                            let total = u16::try_from(l3_len).unwrap_or(u16::MAX);
                            self.pending[ip + 2..ip + 4].copy_from_slice(&total.to_be_bytes());
                            ipv4_checksum(&mut self.pending[ip..ip + self.ip_hdr_len]);
                            let h = VnetHdr {
                                flags: F_NEEDS_CSUM,
                                gso_type: GSO_UDP_L4,
                                hdr_len: u16::try_from(self.l3_hdr_len).unwrap_or(0),
                                gso_size: self.gso_size,
                                csum_start: u16::try_from(self.ip_hdr_len).unwrap_or(0),
                                csum_offset: 6,
                            };
                            write_vnet_hdr(&h, &mut self.pending[..VNET_HDR_LEN]);
                        }
                        FlowKey::V6 { .. } => {
                            let ipv6_payload_len =
                                u16::try_from(l3_len.saturating_sub(40)).unwrap_or(u16::MAX);
                            self.pending[ip + 4..ip + 6]
                                .copy_from_slice(&ipv6_payload_len.to_be_bytes());
                            let h = VnetHdr {
                                flags: F_NEEDS_CSUM,
                                gso_type: GSO_UDP_L4,
                                hdr_len: u16::try_from(self.l3_hdr_len).unwrap_or(0),
                                gso_size: self.gso_size,
                                csum_start: 40,
                                csum_offset: 6,
                            };
                            write_vnet_hdr(&h, &mut self.pending[..VNET_HDR_LEN]);
                        }
                    }
                }
            }
            PendingKind::Singleton => {}
        }
    }

    /// Finalize the pending run into `self.out` and return the borrow (or None).
    fn take_pending(&mut self) -> Option<&[u8]> {
        if !self.has_pending {
            return None;
        }
        self.finalize_pending();
        std::mem::swap(&mut self.pending, &mut self.out);
        self.pending.clear();
        self.has_pending = false;
        Some(&self.out)
    }

    fn start_tcp_run(&mut self, x: &ParsedTcp<'_>, sealed: bool) {
        self.pending.clear();
        self.pending.resize(VNET_HDR_LEN, 0);
        self.pending.extend_from_slice(&x.bytes()[..x.total_len()]); // full first L3 packet
        self.has_pending = true;
        self.kind = PendingKind::Tcp;
        self.sealed = sealed;
        self.key = x.key();
        self.ip_hdr_len = x.ip_hdr_len();
        self.l3_hdr_len = x.payload_off();
        self.gso_size = u16::try_from(x.payload_len()).unwrap_or(0);
        self.next_seq = x
            .seq()
            .wrapping_add(u32::try_from(x.payload_len()).unwrap_or(0));
        self.segs = 1;
    }

    fn start_udp_run(&mut self, x: &ParsedUdp<'_>, sealed: bool) {
        self.pending.clear();
        self.pending.resize(VNET_HDR_LEN, 0);
        self.pending.extend_from_slice(&x.bytes()[..x.total_len()]); // full first L3 packet
        self.has_pending = true;
        self.kind = PendingKind::Udp;
        self.sealed = sealed;
        self.key = x.key();
        self.ip_hdr_len = x.ip_hdr_len();
        self.l3_hdr_len = x.payload_off();
        self.gso_size = u16::try_from(x.payload_len()).unwrap_or(0);
        self.next_seq = 0;
        self.segs = 1;
    }

    fn start_singleton(&mut self, pkt: &[u8]) {
        self.pending.clear();
        self.pending.resize(VNET_HDR_LEN, 0);
        write_vnet_hdr(
            &VnetHdr {
                gso_type: GSO_NONE,
                ..VnetHdr::default()
            },
            &mut self.pending,
        );
        self.pending.extend_from_slice(pkt);
        self.has_pending = true;
        self.kind = PendingKind::Singleton;
        self.sealed = true;
    }

    pub fn push(&mut self, pkt: &[u8]) -> Option<&[u8]> {
        if pkt.is_empty() {
            return None;
        }
        let parsed = parse_ip_packet(pkt);
        // Can this packet extend the current pending run?
        if self.has_pending && !self.sealed {
            match self.kind {
                PendingKind::Tcp => {
                    if let Some(ParsedPacket::Tcp(x)) = &parsed {
                        let cont = x.payload_len() > 0
                            && (x.flags()
                                & (TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_URG))
                                == 0
                            && x.key() == self.key
                            && x.seq() == self.next_seq
                            && x.payload_off() == self.l3_hdr_len
                            && self.segs < MAX_GSO_SEGMENTS
                            && (self.pending.len() - VNET_HDR_LEN - self.l3_hdr_len)
                                + x.payload_len()
                                <= MAX_GSO_PAYLOAD;
                        if cont {
                            self.pending.extend_from_slice(
                                &x.bytes()[x.payload_off()..x.payload_off() + x.payload_len()],
                            );
                            self.next_seq = self
                                .next_seq
                                .wrapping_add(u32::try_from(x.payload_len()).unwrap_or(0));
                            self.segs += 1;
                            return None;
                        }
                    }
                }
                PendingKind::Udp => {
                    if self.has_uso {
                        if let Some(ParsedPacket::Udp(x)) = &parsed {
                            let gso_size = usize::from(self.gso_size);
                            let cur_payload = self.pending.len() - VNET_HDR_LEN - self.l3_hdr_len;
                            let cont = x.payload_len() > 0
                                && x.key() == self.key
                                && x.payload_off() == self.l3_hdr_len
                                && self.segs < MAX_GSO_SEGMENTS
                                && cur_payload + x.payload_len() <= MAX_UDP_GSO_PAYLOAD
                                && self.l3_hdr_len + cur_payload + x.payload_len() <= 65_535
                                && x.payload_len() <= gso_size;
                            if cont {
                                self.pending.extend_from_slice(
                                    &x.bytes()[x.payload_off()..x.payload_off() + x.payload_len()],
                                );
                                self.segs += 1;
                                if x.payload_len() < gso_size
                                    || self.segs >= MAX_GSO_SEGMENTS
                                    || (self.pending.len() - VNET_HDR_LEN - self.l3_hdr_len)
                                        >= MAX_UDP_GSO_PAYLOAD
                                    || (self.pending.len() - VNET_HDR_LEN) >= 65_535
                                {
                                    self.sealed = true;
                                }
                                return None;
                            }
                        }
                    }
                }
                PendingKind::Singleton => {}
            }
        }
        // Cannot extend: flush the pending run (if any), then start a new one from `pkt`.
        let had_pending = self.has_pending;
        if had_pending {
            self.finalize_pending();
            std::mem::swap(&mut self.pending, &mut self.out);
            self.pending.clear();
            self.has_pending = false;
        }
        match &parsed {
            Some(ParsedPacket::Tcp(x)) if x.payload_len() > 0 => {
                let sealed =
                    (x.flags() & (TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_URG)) != 0;
                self.start_tcp_run(x, sealed);
            }
            Some(ParsedPacket::Udp(x)) if x.payload_len() > 0 && self.has_uso => {
                self.start_udp_run(x, false);
            }
            _ => self.start_singleton(pkt),
        }
        if had_pending {
            Some(&self.out)
        } else {
            None
        }
    }

    pub fn flush(&mut self) -> Option<&[u8]> {
        self.take_pending()
    }
}

impl Default for Coalescer {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Internet-checksum fold of a 16-bit word sum over `data`.
    fn csum16(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
            i += 2;
        }
        if i < data.len() {
            sum += u32::from(u16::from(data[i]) << 8);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        u16::try_from(sum & 0xFFFF).unwrap()
    }

    #[test]
    fn complete_partial_csum_matches_full_udp_checksum() {
        // IPv4(20) + UDP(8) + payload, csum_start=20, csum_offset=6.
        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        p[8] = 64;
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1111u16.to_be_bytes()); // sport
        p[22..24].copy_from_slice(&2222u16.to_be_bytes()); // dport
        p[24..26].copy_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
        p[28..].copy_from_slice(&payload);

        // Pseudo-header 16-bit sum: src + dst + proto + udp_len.
        let mut pseudo = vec![0u8; 12];
        pseudo[..4].copy_from_slice(&[10, 0, 0, 1]);
        pseudo[4..8].copy_from_slice(&[10, 0, 0, 2]);
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
        let pseudo_sum = csum16(&pseudo);

        // Reference full UDP checksum (field zeroed): ~fold(pseudo + L4-with-zero-field).
        let good = !{
            let mut s = u32::from(pseudo_sum) + u32::from(csum16(&p[20..]));
            while (s >> 16) != 0 {
                s = (s & 0xFFFF) + (s >> 16);
            }
            u16::try_from(s & 0xFFFF).unwrap()
        };

        // Kernel delivers F_NEEDS_CSUM with the field pre-seeded to the pseudo sum.
        p[20 + 6..20 + 8].copy_from_slice(&pseudo_sum.to_be_bytes());
        complete_partial_csum(&mut p, 20, 6);
        let completed = u16::from_be_bytes([p[26], p[27]]);
        assert_eq!(
            completed, good,
            "completed checksum must equal the full UDP checksum"
        );
    }

    #[test]
    fn complete_partial_csum_zero_checksum_udp_rfc_handling() {
        // When one's-complement sum folds to 0xFFFF, !sum == 0x0000.
        // RFC 768 / RFC 8200: For UDP, an evaluated checksum of 0 is converted to 0xFFFF.
        // For non-UDP (e.g. TCP), it remains 0x0000.
        //
        // Case 1: IPv4 UDP -> must be 0xFFFF
        let mut v4_udp = vec![0u8; 28];
        v4_udp[0] = 0x45;
        v4_udp[9] = 17; // UDP
        v4_udp[20..22].copy_from_slice(&0xFFFFu16.to_be_bytes()); // sum over [20..] will fold to 0xFFFF
        complete_partial_csum(&mut v4_udp, 20, 6);
        assert_eq!(
            u16::from_be_bytes([v4_udp[26], v4_udp[27]]),
            0xFFFF,
            "IPv4 UDP zero checksum must become 0xFFFF"
        );

        // Case 2: IPv4 TCP -> must remain 0x0000
        let mut v4_tcp = vec![0u8; 28];
        v4_tcp[0] = 0x45;
        v4_tcp[9] = 6; // TCP
        v4_tcp[20..22].copy_from_slice(&0xFFFFu16.to_be_bytes());
        complete_partial_csum(&mut v4_tcp, 20, 6);
        assert_eq!(
            u16::from_be_bytes([v4_tcp[26], v4_tcp[27]]),
            0x0000,
            "IPv4 TCP zero checksum must remain 0x0000"
        );

        // Case 3: IPv6 UDP -> must be 0xFFFF
        let mut v6_udp = vec![0u8; 48];
        v6_udp[0] = 0x60;
        v6_udp[6] = 17; // UDP
        v6_udp[40..42].copy_from_slice(&0xFFFFu16.to_be_bytes());
        complete_partial_csum(&mut v6_udp, 40, 6);
        assert_eq!(
            u16::from_be_bytes([v6_udp[46], v6_udp[47]]),
            0xFFFF,
            "IPv6 UDP zero checksum must become 0xFFFF"
        );

        // Case 4: IPv6 TCP -> must remain 0x0000
        let mut v6_tcp = vec![0u8; 48];
        v6_tcp[0] = 0x60;
        v6_tcp[6] = 6; // TCP
        v6_tcp[40..42].copy_from_slice(&0xFFFFu16.to_be_bytes());
        complete_partial_csum(&mut v6_tcp, 40, 6);
        assert_eq!(
            u16::from_be_bytes([v6_tcp[46], v6_tcp[47]]),
            0x0000,
            "IPv6 TCP zero checksum must remain 0x0000"
        );
    }

    #[test]
    fn complete_partial_csum_rejects_out_of_bounds_offsets() {
        let original = vec![
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 1, 2, 3, 4,
            5, 6, 7, 8,
        ];
        let mut p1 = original.clone();
        // csum_start >= pkt.len()
        complete_partial_csum(&mut p1, 28, 0);
        assert_eq!(p1, original, "must return early without mutating packet");

        let mut p2 = original.clone();
        // csum_start < pkt.len() but field + 2 > pkt.len() (csum_start = 20, offset = 7 -> field = 27, field + 2 = 29 > 28)
        complete_partial_csum(&mut p2, 20, 7);
        assert_eq!(
            p2, original,
            "must return early when checksum field overflows packet slice"
        );
    }

    fn mk_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let ihl = 20usize;
        let thl = 20usize;
        let total = ihl + thl + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4, IHL=5
        p[2..4].copy_from_slice(&(u16::try_from(total).unwrap()).to_be_bytes());
        p[8] = 64;
        p[9] = 6; // TTL, proto=TCP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        // TCP
        let t = ihl;
        p[t..t + 2].copy_from_slice(&sport.to_be_bytes());
        p[t + 2..t + 4].copy_from_slice(&dport.to_be_bytes());
        p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        p[t + 12] = 0x50; // data offset = 5 (20 bytes)
        p[t + 13] = flags;
        p[t + 20..].copy_from_slice(payload);
        ipv4_checksum(&mut p[..ihl]);
        p
    }

    #[test]
    fn parse_ipv4_tcp_extracts_fields() {
        let p = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            TCP_FLAG_PSH,
            b"hello",
        );
        let x = parse_ipv4_tcp(&p).expect("parse");
        assert_eq!(
            x.key,
            FlowKey::V4 {
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
                sport: 1234,
                dport: 80
            }
        );
        assert_eq!(x.seq, 1000);
        assert_eq!(x.flags & TCP_FLAG_PSH, TCP_FLAG_PSH);
        assert_eq!(x.ip_hdr_len, 20);
        assert_eq!(x.tcp_hdr_len, 20);
        assert_eq!(x.payload_len, 5);
        assert_eq!(
            &x.bytes[x.payload_off..x.payload_off + x.payload_len],
            b"hello"
        );
    }

    #[test]
    fn parse_rejects_non_tcp_and_fragments() {
        let mut udp = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 0, 0, b"x");
        udp[9] = 17; // proto=UDP
        assert!(parse_ipv4_tcp(&udp).is_none());
        let mut frag = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 0, 0, b"x");
        frag[6] = 0x20; // MF set
        assert!(parse_ipv4_tcp(&frag).is_none());
    }

    #[test]
    fn ipv4_checksum_is_valid() {
        let p = mk_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1, 2, 0, 0, b"z");
        // A correct IPv4 checksum makes the one's-complement sum of the header 0xFFFF.
        let sum: u32 = p[..20]
            .chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
            .sum();
        let folded = u16::try_from((sum & 0xFFFF) + (sum >> 16)).expect("folded sum fits u16");
        assert_eq!(folded, 0xFFFF);
    }

    #[test]
    fn vnet_hdr_roundtrip() {
        let h = VnetHdr {
            flags: F_NEEDS_CSUM,
            gso_type: GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1400,
            csum_start: 20,
            csum_offset: 16,
        };
        let mut buf = [0u8; VNET_HDR_LEN];
        write_vnet_hdr(&h, &mut buf);
        let got = read_vnet_hdr(&buf).expect("parse");
        assert_eq!(got.gso_type, GSO_TCPV4);
        assert_eq!(got.gso_size, 1400);
        assert_eq!(got.hdr_len, 40);
        assert_eq!(got.csum_start, 20);
        assert_eq!(got.csum_offset, 16);
        assert_eq!(got.flags, F_NEEDS_CSUM);
    }

    #[test]
    fn read_vnet_hdr_rejects_short() {
        assert!(read_vnet_hdr(&[0u8; VNET_HDR_LEN - 1]).is_none());
    }

    // Helper: run a sequence of packets through a Coalescer, collecting every emitted frame
    // (both push-flushes and the final flush), returned as owned Vecs.
    fn run_coalescer(pkts: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut c = Coalescer::new(false);
        let mut out = Vec::new();
        for p in pkts {
            if let Some(f) = c.push(p) {
                out.push(f.to_vec());
            }
        }
        if let Some(f) = c.flush() {
            out.push(f.to_vec());
        }
        out
    }

    #[test]
    fn coalesces_contiguous_same_flow() {
        // three 100-byte segments, seq 0,100,200 — must merge into ONE super-frame.
        let p0 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0xAA; 100]);
        let p1 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 100, 0, &[0xBB; 100]);
        let p2 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 200, 0, &[0xCC; 100]);
        let out = run_coalescer(&[p0, p1, p2]);
        assert_eq!(out.len(), 1, "one coalesced super-frame");
        let h = read_vnet_hdr(&out[0]).unwrap();
        assert_eq!(h.gso_type, GSO_TCPV4);
        assert_eq!(h.gso_size, 100);
        // super-frame payload = 300 bytes after vnet_hdr + IP(20) + TCP(20)
        assert_eq!(out[0].len(), VNET_HDR_LEN + 20 + 20 + 300);
    }

    #[test]
    fn flushes_on_seq_gap() {
        let p0 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0; 100]);
        let gap = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 500, 0, &[0; 100]); // non-contiguous
        assert_eq!(run_coalescer(&[p0, gap]).len(), 2);
    }

    #[test]
    fn flushes_on_flow_change() {
        let a = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0; 100]);
        let b = mk_tcp([10, 0, 0, 1], [10, 0, 0, 3], 9, 80, 0, 0, &[0; 100]); // different dst
        assert_eq!(run_coalescer(&[a, b]).len(), 2);
    }

    #[test]
    fn psh_and_fin_force_immediate_flush() {
        let p0 = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            0,
            TCP_FLAG_PSH,
            &[0; 100],
        );
        let p1 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 100, 0, &[0; 100]);
        // p0 has PSH → emitted immediately as its own frame; p1 starts a new run flushed at end.
        assert_eq!(run_coalescer(&[p0, p1]).len(), 2);
    }

    #[test]
    fn coalescer_flags_and_zero_payload_prevent_coalescing() {
        let p_norm = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0xAA; 100]);
        let p_fin = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            100,
            TCP_FLAG_FIN,
            &[0xBB; 100],
        );
        let p_rst = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            100,
            TCP_FLAG_RST,
            &[0xBB; 100],
        );
        let p_urg = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            100,
            TCP_FLAG_URG,
            &[0xBB; 100],
        );
        let p_psh = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            100,
            TCP_FLAG_PSH,
            &[0xBB; 100],
        );
        let p_zero = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 100, 0, &[]);

        // Pushing a packet with any boundary flag or zero payload must NOT coalesce into p_norm
        assert_eq!(run_coalescer(&[p_norm.clone(), p_fin.clone()]).len(), 2);
        assert_eq!(run_coalescer(&[p_norm.clone(), p_rst.clone()]).len(), 2);
        assert_eq!(run_coalescer(&[p_norm.clone(), p_urg.clone()]).len(), 2);
        assert_eq!(run_coalescer(&[p_norm.clone(), p_psh.clone()]).len(), 2);
        assert_eq!(run_coalescer(&[p_norm.clone(), p_zero.clone()]).len(), 2);

        // Pushing a packet starting a run with any boundary flag must seal the run so subsequent normal packet cannot coalesce
        let p_next = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 200, 0, &[0xCC; 100]);
        assert_eq!(run_coalescer(&[p_fin, p_next.clone()]).len(), 2);
        assert_eq!(run_coalescer(&[p_rst, p_next.clone()]).len(), 2);
        assert_eq!(run_coalescer(&[p_urg, p_next.clone()]).len(), 2);

        // A standalone zero-payload TCP packet must be emitted as a singleton, not GSO_TCPV4
        let out = run_coalescer(&[p_zero]);
        assert_eq!(out.len(), 1);
        let h = read_vnet_hdr(&out[0]).unwrap();
        assert_eq!(
            h.gso_type, GSO_NONE,
            "zero payload must not start a TCP GSO superframe"
        );
    }

    #[test]
    fn coalescer_max_segments_and_max_payload_bounds() {
        let mut c = Coalescer::new(false);
        // 1. Max segments boundary: MAX_GSO_SEGMENTS = 64
        for i in 0..64 {
            let p = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, i * 10, 0, &[0x11; 10]);
            let res = c.push(&p);
            assert!(
                res.is_none(),
                "first 64 segments should coalesce without flush"
            );
        }
        // Segment 65 must flush the 64-segment coalesced run
        let p65 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 640, 0, &[0x11; 10]);
        let flushed = c.push(&p65);
        assert!(
            flushed.is_some(),
            "65th segment must flush the max-segment run"
        );
        assert_eq!(read_vnet_hdr(flushed.unwrap()).unwrap().gso_size, 10);

        // 2. Max payload boundary: MAX_GSO_PAYLOAD = 65535
        let mut c2 = Coalescer::new(false);
        let p_large = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            0,
            0,
            &vec![0x22; 60_000],
        );
        assert!(c2.push(&p_large).is_none());
        // Second segment would make payload 60000 + 6000 = 66000 > 65535
        let p_overflow = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            60_000,
            0,
            &vec![0x33; 6_000],
        );
        let flushed2 = c2.push(&p_overflow);
        assert!(
            flushed2.is_some(),
            "exceeding MAX_GSO_PAYLOAD must flush pending run"
        );
    }

    #[test]
    fn non_tcp_is_singleton_passthrough() {
        let mut udp = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0; 100]);
        udp[9] = 17;
        let out = run_coalescer(&[udp.clone()]);
        assert_eq!(out.len(), 1);
        // singleton: gso_type NONE, body == original packet bytes exactly
        assert_eq!(read_vnet_hdr(&out[0]).unwrap().gso_type, GSO_NONE);
        assert_eq!(&out[0][VNET_HDR_LEN..], &udp[..]);
    }

    #[test]
    fn split_none_passthrough() {
        let pkt = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, TCP_FLAG_PSH, b"hi");
        let mut frame = vec![0u8; VNET_HDR_LEN];
        write_vnet_hdr(
            &VnetHdr {
                gso_type: GSO_NONE,
                ..Default::default()
            },
            &mut frame,
        );
        frame.extend_from_slice(&pkt);
        let (mut out, mut offs) = (Vec::new(), Vec::new());
        assert!(split_gro(&frame, &mut out, &mut offs));
        assert_eq!(offs.len(), 1);
        assert_eq!(&out[offs[0].0..offs[0].0 + offs[0].1], &pkt[..]);
    }

    fn verify_ipv4_tcp_checksum(pkt: &[u8]) -> bool {
        if pkt.len() < 40 {
            return false;
        }
        let ip_hdr_len = usize::from(pkt[0] & 0x0F) * 4;
        if pkt.len() < ip_hdr_len + 20 {
            return false;
        }
        let tcp_len = pkt.len() - ip_hdr_len;
        let mut sum: u32 = 0;
        for i in (12..20).step_by(2) {
            sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
        }
        sum += u32::from(6u16);
        sum += u32::try_from(tcp_len).expect("tcp_len fits u32") & 0xFFFF;
        sum += sum_16(&pkt[ip_hdr_len..]);
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        (sum & 0xFFFF) == 0xFFFF
    }

    #[test]
    fn tcp_checksum_calculation_and_verification() {
        let mut pkt = mk_tcp(
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            8080,
            443,
            100,
            0x10,
            b"test tcp payload 1234",
        );
        tcp_checksum(&mut pkt, 20);
        assert!(verify_ipv4_tcp_checksum(&pkt));
    }

    #[test]
    fn split_gro_segments_and_checksums() {
        // one super-frame: gso_size=100, 250 bytes payload → segments of 100,100,50.
        let mut big = mk_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            9,
            80,
            1000,
            0,
            &vec![0xEE; 250],
        );
        // fix IP total-length already set by mk_tcp; build the framed input:
        let mut frame = vec![0u8; VNET_HDR_LEN];
        write_vnet_hdr(
            &VnetHdr {
                flags: F_NEEDS_CSUM,
                gso_type: GSO_TCPV4,
                hdr_len: 40,
                gso_size: 100,
                csum_start: 20,
                csum_offset: 16,
            },
            &mut frame,
        );
        frame.extend_from_slice(&big);
        let (mut out, mut offs) = (Vec::new(), Vec::new());
        assert!(split_gro(&frame, &mut out, &mut offs));
        assert_eq!(offs.len(), 3);
        // each segment parses as valid IPv4/TCP with the right seq + payload size
        let sizes = [100usize, 100, 50];
        let mut expect_seq = 1000u32;
        for (i, &(s, l)) in offs.iter().enumerate() {
            let seg = &out[s..s + l];
            let x = parse_ipv4_tcp(seg).expect("valid segment");
            assert_eq!(x.payload_len, sizes[i]);
            assert_eq!(x.seq, expect_seq);
            expect_seq += u32::try_from(sizes[i]).unwrap();
            // IP checksum valid (header folds to 0xFFFF)
            let sum: u32 = seg[..20]
                .chunks(2)
                .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
                .sum();
            assert_eq!(
                u16::try_from((sum & 0xFFFF) + (sum >> 16)).expect("folded sum fits u16"),
                0xFFFF
            );
            assert!(
                verify_ipv4_tcp_checksum(seg),
                "TCP segment checksum must be valid"
            );
        }
        let _ = &mut big;
    }

    #[test]
    fn split_then_coalesce_roundtrip() {
        // Distinct (non-constant) bytes so any off-by-one/duplication bug is caught.
        let payload: Vec<u8> = (0..250usize)
            .map(|i| u8::try_from(i % 256).expect("fits u8"))
            .collect();
        let big = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 1000, 0, &payload);
        let mut frame = vec![0u8; VNET_HDR_LEN];
        write_vnet_hdr(
            &VnetHdr {
                flags: F_NEEDS_CSUM,
                gso_type: GSO_TCPV4,
                hdr_len: 40,
                gso_size: 100,
                csum_start: 20,
                csum_offset: 16,
            },
            &mut frame,
        );
        frame.extend_from_slice(&big);

        let (mut out, mut offs) = (Vec::new(), Vec::new());
        assert!(split_gro(&frame, &mut out, &mut offs));
        assert_eq!(offs.len(), 3, "100,100,50-byte segments");

        // Feed each split segment (a raw IP/TCP packet, no vnet_hdr) through the Coalescer,
        // exactly as the poll RX path would after receiving them off the wire.
        let mut c = Coalescer::new(false);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for &(s, l) in &offs {
            let seg = &out[s..s + l];
            if let Some(f) = c.push(seg) {
                frames.push(f.to_vec());
            }
        }
        if let Some(f) = c.flush() {
            frames.push(f.to_vec());
        }

        // Reassemble the coalesced TCP payload bytes and compare to the original, byte-exact.
        let mut coalesced_payload = Vec::new();
        for f in &frames {
            let body = &f[VNET_HDR_LEN..];
            let x = parse_ipv4_tcp(body).expect("valid coalesced frame");
            coalesced_payload
                .extend_from_slice(&body[x.payload_off..x.payload_off + x.payload_len]);
        }
        assert_eq!(coalesced_payload, payload);
    }

    fn mk_ipv6_tcp(
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let ip_len = 40usize;
        let tcp_len = 20usize;
        let total = ip_len + tcp_len + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x60; // Version = 6, Traffic Class = 0
        let payload_len = u16::try_from(tcp_len + payload.len()).unwrap();
        p[4..6].copy_from_slice(&payload_len.to_be_bytes());
        p[6] = 6; // Next Header = TCP
        p[7] = 64; // Hop Limit
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        // TCP
        let t = ip_len;
        p[t..t + 2].copy_from_slice(&sport.to_be_bytes());
        p[t + 2..t + 4].copy_from_slice(&dport.to_be_bytes());
        p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        p[t + 12] = 0x50; // data offset = 5 (20 bytes)
        p[t + 13] = flags;
        p[t + 20..].copy_from_slice(payload);
        ipv6_tcp_checksum(&mut p);
        p
    }

    fn verify_ipv6_tcp_checksum(pkt: &[u8]) -> bool {
        if pkt.len() < 60 {
            return false;
        }
        let tcp_len = pkt.len() - 40;
        let mut sum: u32 = 0;
        for i in (8..40).step_by(2) {
            sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
        }
        let tcp_len_u32 = u32::try_from(tcp_len).unwrap();
        sum += tcp_len_u32 >> 16;
        sum += tcp_len_u32 & 0xFFFF;
        sum += u32::from(6u16);
        for c in pkt[40..].chunks(2) {
            let w = if c.len() == 2 {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from(c[0]) << 8
            };
            sum += u32::from(w);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        (sum & 0xFFFF) == 0xFFFF
    }

    #[test]
    fn parse_ipv6_tcp_extracts_fields() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let p = mk_ipv6_tcp(src, dst, 0x9876, 0x5432, 0x12345678, TCP_FLAG_PSH, b"hello");
        let x = parse_ipv6_tcp(&p).expect("parse");
        assert_eq!(
            x.key,
            FlowKey::V6 {
                src,
                dst,
                sport: 0x9876,
                dport: 0x5432,
            }
        );
        assert_eq!(x.seq, 0x12345678);
        assert_eq!(x.flags & TCP_FLAG_PSH, TCP_FLAG_PSH);
        assert_eq!(x.ip_hdr_len, 40);
        assert_eq!(x.tcp_hdr_len, 20);
        assert_eq!(x.payload_len, 5);
        assert_eq!(
            &x.bytes[x.payload_off..x.payload_off + x.payload_len],
            b"hello"
        );

        // Boundary test: minimal valid 60-byte IPv6 TCP packet with zero payload
        let p_min = mk_ipv6_tcp(src, dst, 0x9876, 0x5432, 0x12345678, 0, b"");
        assert_eq!(p_min.len(), 60);
        let x_min = parse_ipv6_tcp(&p_min).expect("parse 60-byte minimal packet");
        assert_eq!(x_min.total_len, 60);
        assert_eq!(x_min.payload_len, 0);
        assert_eq!(x_min.tcp_hdr_len, 20);
    }

    #[test]
    fn parse_ipv6_tcp_rejects_malformed() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let p = mk_ipv6_tcp(src, dst, 1234, 80, 1000, 0, b"data");

        // Short packet
        assert!(parse_ipv6_tcp(&p[..39]).is_none());
        assert!(parse_ipv6_tcp(&p[..40]).is_none()); // exactly 40 bytes, missing TCP header
        assert!(parse_ipv6_tcp(&p[..55]).is_none());
        assert!(parse_ipv6_tcp(&p[..59]).is_none()); // exactly 59 bytes, 1 byte short of minimal TCP header

        // Wrong version (IPv4)
        let mut bad_ver = p.clone();
        bad_ver[0] = 0x45;
        assert!(parse_ipv6_tcp(&bad_ver).is_none());

        // Wrong next header (UDP 17 instead of TCP 6)
        let mut bad_proto = p.clone();
        bad_proto[6] = 17;
        assert!(parse_ipv6_tcp(&bad_proto).is_none());

        // Payload length claims more bytes than packet length
        let mut bad_len = p.clone();
        bad_len[4..6].copy_from_slice(&9999u16.to_be_bytes());
        assert!(parse_ipv6_tcp(&bad_len).is_none());

        // Payload length claims less than TCP header minimum
        let mut short_len = p.clone();
        short_len[4..6].copy_from_slice(&10u16.to_be_bytes());
        assert!(parse_ipv6_tcp(&short_len).is_none());

        // TCP data offset too small (< 20 bytes)
        let mut bad_off = p.clone();
        bad_off[40 + 12] = 0x40; // 16 bytes
        assert!(parse_ipv6_tcp(&bad_off).is_none());

        // TCP data offset exceeds packet length
        let mut huge_off = p.clone();
        huge_off[40 + 12] = 0xF0; // 60 bytes, total length is only 40 + 20 + 4 = 64
        huge_off[4..6].copy_from_slice(&24u16.to_be_bytes());
        assert!(parse_ipv6_tcp(&huge_off).is_none());
    }

    #[test]
    fn ipv6_tcp_checksum_calculation_known_vectors() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        // Vector 1: SYN with empty payload
        let mut syn = mk_ipv6_tcp(src, dst, 1234, 80, 1, 0x02, b"");
        syn[40 + 8..40 + 12].copy_from_slice(&0u32.to_be_bytes()); // ack = 0
        syn[40 + 14..40 + 16].copy_from_slice(&64240u16.to_be_bytes()); // win = 64240
        syn[40 + 18..40 + 20].copy_from_slice(&0u16.to_be_bytes()); // urg = 0
        ipv6_tcp_checksum(&mut syn);
        let csum_syn = u16::from_be_bytes([syn[56], syn[57]]);
        assert_eq!(
            csum_syn, 0x545a,
            "computed checksum must match manual vector"
        );
        assert!(verify_ipv6_tcp_checksum(&syn));

        // Vector 2: PSH+ACK with 5 bytes odd payload b"hello"
        let mut psh = mk_ipv6_tcp(src, dst, 1234, 80, 1, 0x18, b"hello");
        psh[40 + 8..40 + 12].copy_from_slice(&0u32.to_be_bytes()); // ack = 0
        psh[40 + 14..40 + 16].copy_from_slice(&64240u16.to_be_bytes()); // win = 64240
        psh[40 + 18..40 + 20].copy_from_slice(&0u16.to_be_bytes()); // urg = 0
        ipv6_tcp_checksum(&mut psh);
        let csum_psh = u16::from_be_bytes([psh[56], psh[57]]);
        assert_eq!(
            csum_psh, 0x106d,
            "computed checksum must match manual vector"
        );
        assert!(verify_ipv6_tcp_checksum(&psh));
    }

    #[test]
    fn split_gro_ipv6_tcp_segments_and_checksums() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        // 3000-byte frame: IPv6 (40) + TCP (20) + 2940 bytes payload
        let payload = vec![0x42u8; 2940];
        let big = mk_ipv6_tcp(src, dst, 1234, 80, 1000, 0, &payload);
        assert_eq!(big.len(), 3000);

        let mut frame = vec![0u8; VNET_HDR_LEN];
        write_vnet_hdr(
            &VnetHdr {
                flags: F_NEEDS_CSUM,
                gso_type: GSO_TCPV6,
                hdr_len: 60,
                gso_size: 1000,
                csum_start: 40,
                csum_offset: 16,
            },
            &mut frame,
        );
        frame.extend_from_slice(&big);

        let (mut out, mut offs) = (Vec::new(), Vec::new());
        assert!(split_gro(&frame, &mut out, &mut offs));
        assert_eq!(offs.len(), 3);

        let expected_payload_lens = [1000usize, 1000, 940];
        let mut expect_seq = 1000u32;
        for (i, &(s, l)) in offs.iter().enumerate() {
            let seg = &out[s..s + l];
            let x = parse_ipv6_tcp(seg).expect("valid ipv6 tcp segment");
            assert_eq!(x.payload_len, expected_payload_lens[i]);
            assert_eq!(x.seq, expect_seq);
            expect_seq += u32::try_from(expected_payload_lens[i]).unwrap();
            let seg_ipv6_payload_len = u16::from_be_bytes([seg[4], seg[5]]);
            assert_eq!(
                seg_ipv6_payload_len,
                u16::try_from(20 + expected_payload_lens[i]).unwrap()
            );
            assert!(
                verify_ipv6_tcp_checksum(seg),
                "segment {} must have valid ipv6 tcp checksum",
                i
            );
        }
    }

    #[test]
    fn coalesces_contiguous_same_flow_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let p0 = mk_ipv6_tcp(src, dst, 9, 80, 0, 0, &[0xAA; 100]);
        let p1 = mk_ipv6_tcp(src, dst, 9, 80, 100, 0, &[0xBB; 100]);
        let p2 = mk_ipv6_tcp(src, dst, 9, 80, 200, 0, &[0xCC; 100]);

        let out = run_coalescer(&[p0, p1, p2]);
        assert_eq!(out.len(), 1, "one coalesced ipv6 super-frame");
        let h = read_vnet_hdr(&out[0]).unwrap();
        assert_eq!(h.gso_type, GSO_TCPV6);
        assert_eq!(h.gso_size, 100);
        assert_eq!(h.csum_start, 40);
        assert_eq!(h.csum_offset, 16);
        assert_eq!(h.flags, F_NEEDS_CSUM);
        // super-frame payload: vnet_hdr (10) + IPv6 (40) + TCP (20) + 300 bytes
        assert_eq!(out[0].len(), VNET_HDR_LEN + 40 + 20 + 300);

        let body = &out[0][VNET_HDR_LEN..];
        let ipv6_payload_len = u16::from_be_bytes([body[4], body[5]]);
        assert_eq!(ipv6_payload_len, 320); // 20 TCP hdr + 300 payload
        assert_eq!(&body[60..160], &[0xAA; 100]);
        assert_eq!(&body[160..260], &[0xBB; 100]);
        assert_eq!(&body[260..360], &[0xCC; 100]);
    }

    #[test]
    fn flushes_on_seq_gap_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let p0 = mk_ipv6_tcp(src, dst, 9, 80, 0, 0, &[0; 100]);
        let gap = mk_ipv6_tcp(src, dst, 9, 80, 500, 0, &[0; 100]);
        assert_eq!(run_coalescer(&[p0, gap]).len(), 2);
    }

    #[test]
    fn flushes_on_flow_change_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst_b = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let a = mk_ipv6_tcp(src, dst_a, 9, 80, 0, 0, &[0; 100]);
        let b = mk_ipv6_tcp(src, dst_b, 9, 80, 0, 0, &[0; 100]);
        assert_eq!(run_coalescer(&[a, b]).len(), 2);
    }

    #[test]
    fn psh_and_fin_force_immediate_flush_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let p0 = mk_ipv6_tcp(src, dst, 9, 80, 0, TCP_FLAG_PSH, &[0; 100]);
        let p1 = mk_ipv6_tcp(src, dst, 9, 80, 100, 0, &[0; 100]);
        assert_eq!(run_coalescer(&[p0, p1]).len(), 2);

        let p2 = mk_ipv6_tcp(src, dst, 9, 80, 0, TCP_FLAG_FIN, &[0; 100]);
        let p3 = mk_ipv6_tcp(src, dst, 9, 80, 100, 0, &[0; 100]);
        assert_eq!(run_coalescer(&[p2, p3]).len(), 2);
    }

    #[test]
    fn non_tcp_is_singleton_passthrough_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut udp = mk_ipv6_tcp(src, dst, 9, 80, 0, 0, &[0; 100]);
        udp[6] = 17; // UDP
        let out = run_coalescer(&[udp.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(read_vnet_hdr(&out[0]).unwrap().gso_type, GSO_NONE);
        assert_eq!(&out[0][VNET_HDR_LEN..], &udp[..]);
    }

    #[test]
    fn split_then_coalesce_roundtrip_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let payload: Vec<u8> = (0..2500usize)
            .map(|i| u8::try_from(i % 251).expect("fits u8"))
            .collect();
        let big = mk_ipv6_tcp(src, dst, 9, 80, 1000, 0, &payload);
        let mut frame = vec![0u8; VNET_HDR_LEN];
        write_vnet_hdr(
            &VnetHdr {
                flags: F_NEEDS_CSUM,
                gso_type: GSO_TCPV6,
                hdr_len: 60,
                gso_size: 1000,
                csum_start: 40,
                csum_offset: 16,
            },
            &mut frame,
        );
        frame.extend_from_slice(&big);

        let (mut out, mut offs) = (Vec::new(), Vec::new());
        assert!(split_gro(&frame, &mut out, &mut offs));
        assert_eq!(offs.len(), 3, "1000,1000,500-byte segments");

        let mut c = Coalescer::new(false);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for &(s, l) in &offs {
            let seg = &out[s..s + l];
            if let Some(f) = c.push(seg) {
                frames.push(f.to_vec());
            }
        }
        if let Some(f) = c.flush() {
            frames.push(f.to_vec());
        }

        let mut coalesced_payload = Vec::new();
        for f in &frames {
            let body = &f[VNET_HDR_LEN..];
            let x = parse_ipv6_tcp(body).expect("valid coalesced frame");
            coalesced_payload
                .extend_from_slice(&body[x.payload_off..x.payload_off + x.payload_len]);
        }
        assert_eq!(coalesced_payload, payload);
    }

    #[test]
    fn complete_partial_csum_matches_full_ipv6_tcp_checksum() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let tcp_len = 20 + payload.len();
        let total = 40 + tcp_len;
        let mut p = vec![0u8; total];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&u16::try_from(tcp_len).unwrap().to_be_bytes());
        p[6] = 6; // TCP
        p[7] = 64;
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        // TCP
        p[40..42].copy_from_slice(&1234u16.to_be_bytes());
        p[42..44].copy_from_slice(&80u16.to_be_bytes());
        p[44..48].copy_from_slice(&1000u32.to_be_bytes());
        p[40 + 12] = 0x50;
        p[60..].copy_from_slice(&payload);

        let mut expected = p.clone();
        ipv6_tcp_checksum(&mut expected);
        let expected_csum = u16::from_be_bytes([expected[56], expected[57]]);

        // Kernel pseudo-header sum seeded in checksum field at offset 56:
        let mut pseudo = vec![0u8; 40];
        pseudo[..16].copy_from_slice(&src);
        pseudo[16..32].copy_from_slice(&dst);
        pseudo[32..36].copy_from_slice(&u32::try_from(tcp_len).unwrap().to_be_bytes());
        pseudo[39] = 6;
        let pseudo_sum = csum16(&pseudo);

        p[56..58].copy_from_slice(&pseudo_sum.to_be_bytes());
        complete_partial_csum(&mut p, 40, 16);
        let completed = u16::from_be_bytes([p[56], p[57]]);
        assert_eq!(completed, expected_csum);
    }

    #[test]
    fn flushes_on_ip_version_change() {
        let v4_a1 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0xAA; 100]);
        let v4_a2 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 100, 0, &[0xAA; 100]);
        let src_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let v6_a1 = mk_ipv6_tcp(src_v6, dst_v6, 9, 80, 0, 0, &[0xBB; 100]);
        let v6_a2 = mk_ipv6_tcp(src_v6, dst_v6, 9, 80, 100, 0, &[0xBB; 100]);
        let v4_b1 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 200, 0, &[0xCC; 100]);
        let v4_b2 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 300, 0, &[0xCC; 100]);

        let out = run_coalescer(&[v4_a1, v4_a2, v6_a1, v6_a2, v4_b1, v4_b2]);
        assert_eq!(out.len(), 3, "IPv4 and IPv6 flows must never coalesce");
        assert_eq!(read_vnet_hdr(&out[0]).unwrap().gso_type, GSO_TCPV4);
        assert_eq!(read_vnet_hdr(&out[1]).unwrap().gso_type, GSO_TCPV6);
        assert_eq!(read_vnet_hdr(&out[2]).unwrap().gso_type, GSO_TCPV4);
    }

    #[test]
    fn test_coalescer_tcp_single_segment_emitted_as_gso_none_with_intact_checksum() {
        let p_v4 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0x42; 500]);
        let out_v4 = run_coalescer(std::slice::from_ref(&p_v4));
        assert_eq!(out_v4.len(), 1);
        let h_v4 = read_vnet_hdr(&out_v4[0]).unwrap();
        assert_eq!(h_v4.gso_type, GSO_NONE);
        assert_eq!(h_v4.gso_size, 0);
        assert_eq!(h_v4.flags, 0);
        assert_eq!(&out_v4[0][VNET_HDR_LEN..], &p_v4[..]);

        let src_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let p_v6 = mk_ipv6_tcp(src_v6, dst_v6, 9, 80, 0, 0, &[0x99; 500]);
        let out_v6 = run_coalescer(std::slice::from_ref(&p_v6));
        assert_eq!(out_v6.len(), 1);
        let h_v6 = read_vnet_hdr(&out_v6[0]).unwrap();
        assert_eq!(h_v6.gso_type, GSO_NONE);
        assert_eq!(h_v6.gso_size, 0);
        assert_eq!(h_v6.flags, 0);
        assert_eq!(&out_v6[0][VNET_HDR_LEN..], &p_v6[..]);
    }

    #[test]
    fn test_coalescer_tcp_pseudo_header_checksum_seeding() {
        let p0 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 0, 0, &[0xAA; 500]);
        let p1 = mk_tcp([10, 0, 0, 1], [10, 0, 0, 2], 9, 80, 500, 0, &[0xBB; 500]);
        let out = run_coalescer(&[p0, p1]);
        assert_eq!(out.len(), 1);
        let h = read_vnet_hdr(&out[0]).unwrap();
        assert_eq!(h.gso_type, GSO_TCPV4);
        assert_eq!(h.flags, F_NEEDS_CSUM);
        let body = &out[0][VNET_HDR_LEN..];
        let sum: u32 = body[..20]
            .chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
            .sum();
        let folded = u16::try_from((sum & 0xFFFF) + (sum >> 16)).expect("folded sum fits u16");
        assert_eq!(folded, 0xFFFF);

        let tcp_len = 20 + 1000;
        let expected_pseudo = tcp_pseudo_header_checksum(
            &FlowKey::V4 {
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
                sport: 9,
                dport: 80,
            },
            tcp_len,
        );
        let seeded = u16::from_be_bytes([body[20 + 16], body[20 + 17]]);
        assert_eq!(seeded, expected_pseudo);
    }

    #[test]
    fn test_pseudo_header_checksum_known_vectors() {
        let v4_key = FlowKey::V4 {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            sport: 9,
            dport: 80,
        };
        assert_eq!(pseudo_header_checksum(&v4_key, 6, 1000), 0x17f1);
        assert_eq!(tcp_pseudo_header_checksum(&v4_key, 1000), 0x17f1);

        let src_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let v6_key = FlowKey::V6 {
            src: src_v6,
            dst: dst_v6,
            sport: 9,
            dport: 80,
        };
        assert_eq!(pseudo_header_checksum(&v6_key, 6, 70000), 0x6cec);
        assert_eq!(tcp_pseudo_header_checksum(&v6_key, 70000), 0x6cec);
    }

    #[test]
    fn test_coalescer_push_empty_slice_returns_none() {
        let mut c = Coalescer::new(false);
        assert!(c.push(&[]).is_none());
        assert!(c.flush().is_none());
    }

    #[test]
    fn coalescer_steady_state_never_reallocates_max_ipv6() {
        let mut c = Coalescer::new(false);
        let initial_pending_cap = c.pending.capacity();
        let initial_out_cap = c.out.capacity();

        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        // 45 segments of 1440 bytes = 64,800 bytes
        let mut seq = 0u32;
        for _ in 0..45 {
            let p = mk_ipv6_tcp(src, dst, 1234, 80, seq, 0, &[0x11; 1440]);
            assert!(c.push(&p).is_none());
            seq += 1440;
        }

        // 1 final segment of 735 bytes to reach exactly MAX_GSO_PAYLOAD (65,535 bytes)
        let last = mk_ipv6_tcp(src, dst, 1234, 80, seq, 0, &[0x22; 735]);
        assert!(c.push(&last).is_none());

        assert_eq!(
            c.pending.capacity(),
            initial_pending_cap,
            "pending capacity must not reallocate when coalescing to MAX_GSO_PAYLOAD"
        );

        let out = c.flush().expect("must flush coalesced superpacket");
        assert_eq!(out.len(), VNET_HDR_LEN + 40 + 20 + MAX_GSO_PAYLOAD);
        assert_eq!(
            c.out.capacity(),
            initial_out_cap,
            "out capacity must not reallocate"
        );
    }

    fn mk_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let ihl = 20usize;
        let uhl = 8usize;
        let total = ihl + uhl + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4, IHL=5
        p[2..4].copy_from_slice(&(u16::try_from(total).unwrap()).to_be_bytes());
        p[4..6].copy_from_slice(&0x1111u16.to_be_bytes()); // ID
        p[8] = 64; // TTL
        p[9] = 17; // proto=UDP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        // UDP
        p[ihl..ihl + 2].copy_from_slice(&sport.to_be_bytes());
        p[ihl + 2..ihl + 4].copy_from_slice(&dport.to_be_bytes());
        let udp_len = u16::try_from(uhl + payload.len()).unwrap();
        p[ihl + 4..ihl + 6].copy_from_slice(&udp_len.to_be_bytes());
        p[ihl + 8..].copy_from_slice(payload);
        ipv4_checksum(&mut p[..ihl]);
        udp_checksum(&mut p, ihl);
        p
    }

    fn mk_ipv6_udp(
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let ip_len = 40usize;
        let uhl = 8usize;
        let total = ip_len + uhl + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x60; // Version = 6
        let payload_len = u16::try_from(uhl + payload.len()).unwrap();
        p[4..6].copy_from_slice(&payload_len.to_be_bytes());
        p[6] = 17; // Next Header = UDP
        p[7] = 64; // Hop Limit
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        // UDP
        p[ip_len..ip_len + 2].copy_from_slice(&sport.to_be_bytes());
        p[ip_len + 2..ip_len + 4].copy_from_slice(&dport.to_be_bytes());
        p[ip_len + 4..ip_len + 6].copy_from_slice(&payload_len.to_be_bytes());
        p[ip_len + 8..].copy_from_slice(payload);
        ipv6_udp_checksum(&mut p);
        p
    }

    #[test]
    fn parse_ipv4_udp_extracts_fields() {
        let p = mk_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 5678, b"hello udp");
        let x = parse_ipv4_udp(&p).expect("parse");
        assert_eq!(
            x.key,
            FlowKey::V4 {
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
                sport: 1234,
                dport: 5678,
            }
        );
        assert_eq!(x.ip_hdr_len, 20);
        assert_eq!(x.total_len, 20 + 8 + 9);
        assert_eq!(x.payload_off, 28);
        assert_eq!(x.payload_len, 9);
        assert_eq!(
            &x.bytes[x.payload_off..x.payload_off + x.payload_len],
            b"hello udp"
        );
    }

    #[test]
    fn parse_ipv6_udp_extracts_fields() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let p = mk_ipv6_udp(src, dst, 3333, 4444, b"ipv6 payload");
        let x = parse_ipv6_udp(&p).expect("parse");
        assert_eq!(
            x.key,
            FlowKey::V6 {
                src,
                dst,
                sport: 3333,
                dport: 4444,
            }
        );
        assert_eq!(x.ip_hdr_len, 40);
        assert_eq!(x.total_len, 40 + 8 + 12);
        assert_eq!(x.payload_off, 48);
        assert_eq!(x.payload_len, 12);
        assert_eq!(
            &x.bytes[x.payload_off..x.payload_off + x.payload_len],
            b"ipv6 payload"
        );
    }

    #[test]
    fn parse_ipv6_udp_rejects_zero_checksum() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut p = mk_ipv6_udp(src, dst, 3333, 4444, b"test");
        p[46] = 0;
        p[47] = 0;
        assert!(
            parse_ipv6_udp(&p).is_none(),
            "RFC 8200 section 8.1 forbids zero checksum"
        );
    }

    fn verify_ipv6_udp_checksum(pkt: &[u8]) -> bool {
        if pkt.len() < 48 {
            return false;
        }
        let udp_len = pkt.len() - 40;
        let mut sum: u32 = 0;
        for i in (8..40).step_by(2) {
            sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
        }
        let udp_len_u32 = u32::try_from(udp_len).unwrap();
        sum += udp_len_u32 >> 16;
        sum += udp_len_u32 & 0xFFFF;
        sum += u32::from(17u16);
        sum += sum_16(&pkt[40..]);
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        (sum & 0xFFFF) == 0xFFFF
    }

    #[test]
    fn ipv6_udp_checksum_calculation_and_verification() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut pkt = mk_ipv6_udp(src, dst, 5001, 5002, b"verifiable payload 1234567890");
        assert!(verify_ipv6_udp_checksum(&pkt));

        pkt[46] = 0;
        pkt[47] = 0;
        ipv6_udp_checksum(&mut pkt);
        assert!(verify_ipv6_udp_checksum(&pkt));
        let ck = u16::from_be_bytes([pkt[46], pkt[47]]);
        assert_ne!(ck, 0);
    }

    #[test]
    fn udp_checksum_rfc768_zero_becomes_ffff() {
        // Construct IPv4 UDP packet where pseudo-header + UDP data sum folds to 0xFFFF,
        // so !sum is 0x0000, which RFC 768 mandates must be sent as 0xFFFF.
        let mut p = vec![0u8; 28 + 2];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&30u16.to_be_bytes());
        p[9] = 17;
        // Pseudo header: src(4) + dst(4) + 17 + udp_len(10)
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1000u16.to_be_bytes()); // sport
        p[22..24].copy_from_slice(&2000u16.to_be_bytes()); // dport
        p[24..26].copy_from_slice(&10u16.to_be_bytes()); // udp_len = 10 (8 + 2)

        // Calculate sum so far without payload:
        let mut sum: u32 = 0;
        for i in (12..20).step_by(2) {
            sum += u32::from(u16::from_be_bytes([p[i], p[i + 1]]));
        }
        sum += 17u32;
        sum += 10u32;
        // UDP hdr without checksum field:
        sum += u32::from(1000u16);
        sum += u32::from(2000u16);
        sum += u32::from(10u16);
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // Needed word to make total sum fold to 0xFFFF:
        let needed = !u16::try_from(sum & 0xFFFF).unwrap();
        p[28..30].copy_from_slice(&needed.to_be_bytes());

        udp_checksum(&mut p, 20);
        let csum = u16::from_be_bytes([p[26], p[27]]);
        assert_eq!(
            csum, 0xFFFF,
            "RFC 768: 0x0000 checksum must be converted to 0xFFFF"
        );
    }

    #[test]
    fn ipv4_base_sum_and_incremental_checksum_matches_full_checksum() {
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        hdr[1] = 0x00;
        hdr[6] = 0x40; // DF
        hdr[7] = 0x00;
        hdr[8] = 64; // TTL
        hdr[9] = 17; // proto UDP
        hdr[12..16].copy_from_slice(&[192, 168, 1, 100]);
        hdr[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let base_sum = ipv4_base_sum(&hdr);

        // Test over various total_len and ip_id pairs
        for total_len in [28u16, 576, 1420, 1500, 65535] {
            for ip_id in [0u16, 1, 0x1234, 0x8000, 0xFFFF] {
                let fast_ck = ipv4_checksum_with_base(base_sum, total_len, ip_id);

                let mut full_hdr = hdr;
                full_hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
                full_hdr[4..6].copy_from_slice(&ip_id.to_be_bytes());
                ipv4_checksum(&mut full_hdr);
                let full_ck = u16::from_be_bytes([full_hdr[10], full_hdr[11]]);

                assert_eq!(
                    fast_ck, full_ck,
                    "fast base_sum checksum must match full ipv4_checksum for len={total_len}, id={ip_id}"
                );
            }
        }
    }

    #[test]
    fn ipv4_base_sum_with_options_matches_full_checksum() {
        // 24-byte header (IHL = 6: 20 bytes standard + 4 bytes NOP options)
        let mut hdr = [0u8; 24];
        hdr[0] = 0x46;
        hdr[1] = 0x00;
        hdr[6] = 0x40;
        hdr[7] = 0x00;
        hdr[8] = 64;
        hdr[9] = 6; // TCP
        hdr[12..16].copy_from_slice(&[172, 16, 0, 1]);
        hdr[16..20].copy_from_slice(&[172, 16, 0, 2]);
        hdr[20..24].copy_from_slice(&[1, 1, 1, 1]); // NOP options

        let base_sum = ipv4_base_sum(&hdr);

        let total_len = 1440u16;
        let ip_id = 0xabcd;
        let fast_ck = ipv4_checksum_with_base(base_sum, total_len, ip_id);

        let mut full_hdr = hdr;
        full_hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
        full_hdr[4..6].copy_from_slice(&ip_id.to_be_bytes());
        ipv4_checksum(&mut full_hdr);
        let full_ck = u16::from_be_bytes([full_hdr[10], full_hdr[11]]);

        assert_eq!(fast_ck, full_ck);
    }
}
