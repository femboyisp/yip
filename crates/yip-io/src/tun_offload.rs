//! Local TUN `virtio_net_hdr` (GSO/GRO) framing + the RX coalescer / TX splitter.
//! Purely local to the yipd↔kernel-TUN boundary — never touches the wire.

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the poll TUN path in Task 5")
)]
pub(crate) const VNET_HDR_LEN: usize = 10;
#[expect(
    dead_code,
    reason = "wired into the poll TUN path in Task 5; not exercised by this task's tests"
)]
pub(crate) const GSO_NONE: u8 = 0;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the poll TUN path in Task 5")
)]
pub(crate) const GSO_TCPV4: u8 = 1;
#[expect(
    dead_code,
    reason = "wired into the poll TUN path in Task 5; not exercised by this task's tests"
)]
pub(crate) const GSO_TCPV6: u8 = 4;
#[expect(
    dead_code,
    reason = "wired into the poll TUN path in Task 5; not exercised by this task's tests"
)]
pub(crate) const GSO_UDP_L4: u8 = 5;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the poll TUN path in Task 5")
)]
pub(crate) const F_NEEDS_CSUM: u8 = 1;
#[expect(
    dead_code,
    reason = "wired into the poll TUN path in Task 5; not exercised by this task's tests"
)]
pub(crate) const F_DATA_VALID: u8 = 2;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the poll TUN path in Task 5")
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct VnetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the poll TUN path in Task 5")
)]
pub(crate) fn read_vnet_hdr(buf: &[u8]) -> Option<VnetHdr> {
    if buf.len() < VNET_HDR_LEN {
        return None;
    }
    let u16h = |a: usize| u16::from_ne_bytes([buf[a], buf[a + 1]]);
    Some(VnetHdr {
        flags: buf[0],
        gso_type: buf[1],
        hdr_len: u16h(2),
        gso_size: u16h(4),
        csum_start: u16h(6),
        csum_offset: u16h(8),
    })
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the poll TUN path in Task 5")
)]
pub(crate) fn write_vnet_hdr(h: &VnetHdr, out: &mut [u8]) {
    assert!(out.len() >= VNET_HDR_LEN);
    out[0] = h.flags;
    out[1] = h.gso_type;
    out[2..4].copy_from_slice(&h.hdr_len.to_ne_bytes());
    out[4..6].copy_from_slice(&h.gso_size.to_ne_bytes());
    out[6..8].copy_from_slice(&h.csum_start.to_ne_bytes());
    out[8..10].copy_from_slice(&h.csum_offset.to_ne_bytes());
}

#[expect(
    dead_code,
    reason = "used by the coalescer in Task 3; not exercised by this task's tests"
)]
pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
#[expect(
    dead_code,
    reason = "used by the coalescer in Task 3; not exercised by this task's tests"
)]
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the coalescer/splitter in Tasks 3-4")
)]
pub(crate) const TCP_FLAG_PSH: u8 = 0x08;
#[expect(
    dead_code,
    reason = "used by the coalescer in Task 3; not exercised by this task's tests"
)]
pub(crate) const TCP_FLAG_URG: u8 = 0x20;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the coalescer/splitter in Tasks 3-4")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlowKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the coalescer/splitter in Tasks 3-4")
)]
pub(crate) struct Ipv4Tcp<'a> {
    pub ip_hdr_len: usize,
    pub tcp_hdr_len: usize,
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "used by the coalescer/splitter in Tasks 3-4; not read by this task's tests"
        )
    )]
    pub total_len: usize,
    pub key: FlowKey,
    pub seq: u32,
    pub flags: u8,
    pub payload_off: usize,
    pub payload_len: usize,
    pub bytes: &'a [u8],
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the coalescer/splitter in Tasks 3-4")
)]
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
        key: FlowKey {
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

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the coalescer/splitter in Tasks 3-4")
)]
pub(crate) fn ipv4_checksum(hdr: &mut [u8]) {
    hdr[10] = 0;
    hdr[11] = 0;
    let mut sum: u32 = 0;
    for c in hdr.chunks(2) {
        let word = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from(c[0]) << 8
        };
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let ck = !u16::try_from(sum & 0xFFFF).expect("folded sum fits u16");
    hdr[10..12].copy_from_slice(&ck.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

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
            FlowKey {
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
}
