use yip_io::tun_offload::{
    split_gro, write_vnet_hdr, VirtioNetHdr, F_NEEDS_CSUM, GSO_UDP_L4, VNET_HDR_LEN,
};

fn verify_ipv4_checksum(hdr: &[u8]) -> bool {
    let mut sum: u32 = 0;
    for c in hdr.chunks(2) {
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

fn verify_ipv4_udp_checksum(pkt: &[u8], ip_hdr_len: usize) -> bool {
    let udp_len = pkt.len() - ip_hdr_len;
    let mut sum: u32 = 0;
    for i in (12..20).step_by(2) {
        sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
    }
    sum += u32::from(17u16);
    sum += u32::try_from(udp_len).unwrap() & 0xFFFF;
    for c in pkt[ip_hdr_len..].chunks(2) {
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
fn test_split_gro_rejects_gso_size_zero_or_malformed() {
    let mut frame = vec![0u8; VNET_HDR_LEN + 40];
    let hdr = VirtioNetHdr {
        gso_type: GSO_UDP_L4,
        gso_size: 0,
        ..Default::default()
    };
    write_vnet_hdr(&hdr, &mut frame);

    let mut out = Vec::new();
    let mut offsets = Vec::new();
    assert!(split_gro(&frame, &mut out, &mut offsets));
    assert_eq!(offsets.len(), 1);

    // Empty body with non-zero gso_size
    let mut frame_empty = vec![0u8; VNET_HDR_LEN];
    let hdr_empty = VirtioNetHdr {
        gso_type: GSO_UDP_L4,
        gso_size: 1400,
        ..Default::default()
    };
    write_vnet_hdr(&hdr_empty, &mut frame_empty);
    assert!(!split_gro(&frame_empty, &mut out, &mut offsets));

    // Truncated body with non-zero gso_size
    let mut frame_truncated = vec![0u8; VNET_HDR_LEN + 10];
    write_vnet_hdr(&hdr_empty, &mut frame_truncated);
    assert!(!split_gro(&frame_truncated, &mut out, &mut offsets));
}

#[test]
fn test_split_gro_slices_ipv4_udp_superpacket() {
    let mut out = Vec::new();
    let mut offsets = Vec::new();

    let ip_hdr_len = 20;
    let udp_hdr_len = 8;
    let payload = vec![0xABu8; 2800];
    let total_len = ip_hdr_len + udp_hdr_len + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

    pkt[20..22].copy_from_slice(&5000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&5001u16.to_be_bytes());
    let udp_len = (udp_hdr_len + payload.len()) as u16;
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(&payload);

    let mut frame = vec![0u8; VNET_HDR_LEN + pkt.len()];
    let hdr = VirtioNetHdr {
        flags: F_NEEDS_CSUM,
        gso_type: GSO_UDP_L4,
        hdr_len: 28,
        gso_size: 1400,
        csum_start: 20,
        csum_offset: 6,
    };
    write_vnet_hdr(&hdr, &mut frame);
    frame[VNET_HDR_LEN..].copy_from_slice(&pkt);

    assert!(split_gro(&frame, &mut out, &mut offsets));
    assert_eq!(
        offsets.len(),
        2,
        "2800 bytes sliced by 1400 must produce 2 datagrams"
    );
    assert_eq!(offsets[0].1, 28 + 1400);
    assert_eq!(offsets[1].1, 28 + 1400);

    let seg0 = &out[offsets[0].0..offsets[0].0 + offsets[0].1];
    let seg1 = &out[offsets[1].0..offsets[1].0 + offsets[1].1];

    assert_eq!(&seg0[4..6], &0x1234u16.to_be_bytes());
    assert_eq!(&seg1[4..6], &0x1235u16.to_be_bytes());

    assert_eq!(&seg0[2..4], &(1428u16).to_be_bytes());
    assert_eq!(&seg1[2..4], &(1428u16).to_be_bytes());

    assert_eq!(&seg0[24..26], &(1408u16).to_be_bytes());
    assert_eq!(&seg1[24..26], &(1408u16).to_be_bytes());

    assert!(verify_ipv4_checksum(&seg0[..20]));
    assert!(verify_ipv4_checksum(&seg1[..20]));

    assert!(verify_ipv4_udp_checksum(seg0, 20));
    assert!(verify_ipv4_udp_checksum(seg1, 20));

    assert_eq!(&seg0[28..], &payload[..1400]);
    assert_eq!(&seg1[28..], &payload[1400..]);
}

#[test]
fn test_split_gro_slices_ipv4_udp_with_trailing_short_segment() {
    let mut out = Vec::new();
    let mut offsets = Vec::new();

    let ip_hdr_len = 20;
    let udp_hdr_len = 8;
    let payload = vec![0xCDu8; 2500];
    let total_len = ip_hdr_len + udp_hdr_len + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x4321u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[192, 168, 1, 10]);
    pkt[16..20].copy_from_slice(&[192, 168, 1, 20]);

    pkt[20..22].copy_from_slice(&8000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&9000u16.to_be_bytes());
    let udp_len = (udp_hdr_len + payload.len()) as u16;
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(&payload);

    let mut frame = vec![0u8; VNET_HDR_LEN + pkt.len()];
    let hdr = VirtioNetHdr {
        flags: F_NEEDS_CSUM,
        gso_type: GSO_UDP_L4,
        hdr_len: 28,
        gso_size: 1000,
        csum_start: 20,
        csum_offset: 6,
    };
    write_vnet_hdr(&hdr, &mut frame);
    frame[VNET_HDR_LEN..].copy_from_slice(&pkt);

    assert!(split_gro(&frame, &mut out, &mut offsets));
    assert_eq!(
        offsets.len(),
        3,
        "2500 bytes sliced by 1000 must produce 3 datagrams"
    );
    assert_eq!(offsets[0].1, 28 + 1000);
    assert_eq!(offsets[1].1, 28 + 1000);
    assert_eq!(offsets[2].1, 28 + 500);

    for (i, &(start, len)) in offsets.iter().enumerate() {
        let seg = &out[start..start + len];
        assert!(verify_ipv4_checksum(&seg[..20]));
        assert!(verify_ipv4_udp_checksum(seg, 20));
        let expected_id = 0x4321u16.wrapping_add(i as u16);
        assert_eq!(&seg[4..6], &expected_id.to_be_bytes());
    }
}

#[test]
fn test_split_gro_slices_ipv6_udp_superpacket() {
    let mut out = Vec::new();
    let mut offsets = Vec::new();

    let ip_hdr_len = 40;
    let udp_hdr_len = 8;
    let payload = vec![0xEFu8; 2800];
    let udp_len = (udp_hdr_len + payload.len()) as u16;
    let total_len = ip_hdr_len + udp_hdr_len + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&udp_len.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pkt[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    pkt[40..42].copy_from_slice(&6000u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&6001u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&udp_len.to_be_bytes());
    pkt[46..48].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[48..].copy_from_slice(&payload);

    let mut frame = vec![0u8; VNET_HDR_LEN + pkt.len()];
    let hdr = VirtioNetHdr {
        flags: F_NEEDS_CSUM,
        gso_type: GSO_UDP_L4,
        hdr_len: 48,
        gso_size: 1400,
        csum_start: 40,
        csum_offset: 6,
    };
    write_vnet_hdr(&hdr, &mut frame);
    frame[VNET_HDR_LEN..].copy_from_slice(&pkt);

    assert!(split_gro(&frame, &mut out, &mut offsets));
    assert_eq!(
        offsets.len(),
        2,
        "2800 bytes sliced by 1400 must produce 2 datagrams"
    );
    assert_eq!(offsets[0].1, 48 + 1400);
    assert_eq!(offsets[1].1, 48 + 1400);

    let seg0 = &out[offsets[0].0..offsets[0].0 + offsets[0].1];
    let seg1 = &out[offsets[1].0..offsets[1].0 + offsets[1].1];

    assert_eq!(&seg0[4..6], &(1408u16).to_be_bytes());
    assert_eq!(&seg1[4..6], &(1408u16).to_be_bytes());

    assert_eq!(&seg0[44..46], &(1408u16).to_be_bytes());
    assert_eq!(&seg1[44..46], &(1408u16).to_be_bytes());

    let csum0 = u16::from_be_bytes([seg0[46], seg0[47]]);
    let csum1 = u16::from_be_bytes([seg1[46], seg1[47]]);
    assert_ne!(
        csum0, 0,
        "RFC 8200 section 8.1 forbids zero checksum on IPv6"
    );
    assert_ne!(
        csum1, 0,
        "RFC 8200 section 8.1 forbids zero checksum on IPv6"
    );

    assert!(verify_ipv6_udp_checksum(seg0));
    assert!(verify_ipv6_udp_checksum(seg1));

    assert_eq!(&seg0[48..], &payload[..1400]);
    assert_eq!(&seg1[48..], &payload[1400..]);
}

#[test]
fn test_split_gro_rejects_ipv6_zero_checksum() {
    let mut out = Vec::new();
    let mut offsets = Vec::new();

    let ip_hdr_len = 40;
    let udp_hdr_len = 8;
    let payload = vec![0xEFu8; 1000];
    let udp_len = (udp_hdr_len + payload.len()) as u16;
    let total_len = ip_hdr_len + udp_hdr_len + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&udp_len.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pkt[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    pkt[40..42].copy_from_slice(&6000u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&6001u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&udp_len.to_be_bytes());
    // Zero checksum on IPv6 UDP is forbidden per RFC 8200 section 8.1
    pkt[46..48].copy_from_slice(&0u16.to_be_bytes());
    pkt[48..].copy_from_slice(&payload);

    let mut frame = vec![0u8; VNET_HDR_LEN + pkt.len()];
    let hdr = VirtioNetHdr {
        flags: F_NEEDS_CSUM,
        gso_type: GSO_UDP_L4,
        hdr_len: 48,
        gso_size: 500,
        csum_start: 40,
        csum_offset: 6,
    };
    write_vnet_hdr(&hdr, &mut frame);
    frame[VNET_HDR_LEN..].copy_from_slice(&pkt);

    assert!(
        !split_gro(&frame, &mut out, &mut offsets),
        "split_gro must reject IPv6 UDP superpacket with zero checksum"
    );
}
