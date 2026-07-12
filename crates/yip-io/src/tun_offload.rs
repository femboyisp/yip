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

#[cfg(test)]
mod tests {
    use super::*;

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
