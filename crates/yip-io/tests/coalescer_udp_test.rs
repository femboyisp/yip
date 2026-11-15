use yip_io::tun_offload::{
    read_vnet_hdr, split_gro, Coalescer, F_NEEDS_CSUM, GSO_UDP_L4, MAX_GSO_SEGMENTS,
    MAX_UDP_GSO_PAYLOAD, VNET_HDR_LEN,
};

fn compute_ipv4_checksum(hdr: &mut [u8]) {
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

fn compute_udp_checksum(pkt: &mut [u8], ip_hdr_len: usize) {
    let total = pkt.len();
    let udp_off = ip_hdr_len;
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let udp_len = total - udp_off;
    let mut sum: u32 = 0;
    for i in (12..20).step_by(2) {
        sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
    }
    sum += u32::from(17u16);
    sum += u32::try_from(udp_len).expect("udp_len fits u32") & 0xFFFF;
    for c in pkt[udp_off..total].chunks(2) {
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
    let mut ck = !u16::try_from(sum & 0xFFFF).expect("folded fits u16");
    if ck == 0 {
        ck = 0xFFFF;
    }
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&ck.to_be_bytes());
}

fn compute_ipv6_udp_checksum(pkt: &mut [u8]) {
    let total = pkt.len();
    let udp_off = 40;
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let udp_len = total - udp_off;
    let mut sum: u32 = 0;
    for i in (8..40).step_by(2) {
        sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
    }
    let udp_len_u32 = u32::try_from(udp_len).expect("udp_len fits u32");
    sum += udp_len_u32 >> 16;
    sum += udp_len_u32 & 0xFFFF;
    sum += u32::from(17u16);
    for c in pkt[udp_off..total].chunks(2) {
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
    let mut ck = !u16::try_from(sum & 0xFFFF).expect("folded fits u16");
    if ck == 0 {
        ck = 0xFFFF;
    }
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&ck.to_be_bytes());
}

fn mk_ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ihl = 20usize;
    let uhl = 8usize;
    let total = ihl + uhl + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(u16::try_from(total).unwrap()).to_be_bytes());
    p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[ihl..ihl + 2].copy_from_slice(&sport.to_be_bytes());
    p[ihl + 2..ihl + 4].copy_from_slice(&dport.to_be_bytes());
    let udp_len = u16::try_from(uhl + payload.len()).unwrap();
    p[ihl + 4..ihl + 6].copy_from_slice(&udp_len.to_be_bytes());
    p[ihl + 8..].copy_from_slice(payload);
    compute_ipv4_checksum(&mut p[..ihl]);
    compute_udp_checksum(&mut p, ihl);
    p
}

fn mk_ipv6_udp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ip_len = 40usize;
    let uhl = 8usize;
    let total = ip_len + uhl + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x60;
    let payload_len = u16::try_from(uhl + payload.len()).unwrap();
    p[4..6].copy_from_slice(&payload_len.to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(&src);
    p[24..40].copy_from_slice(&dst);
    p[ip_len..ip_len + 2].copy_from_slice(&sport.to_be_bytes());
    p[ip_len + 2..ip_len + 4].copy_from_slice(&dport.to_be_bytes());
    p[ip_len + 4..ip_len + 6].copy_from_slice(&payload_len.to_be_bytes());
    p[ip_len + 8..].copy_from_slice(payload);
    compute_ipv6_udp_checksum(&mut p);
    p
}

#[test]
fn test_coalescer_aggregates_ipv4_udp_datagrams_with_trailing_short_segment() {
    let mut coalescer = Coalescer::new();

    let src = [192, 168, 1, 10];
    let dst = [192, 168, 1, 20];
    let sport = 443;
    let dport = 5000;

    let p1 = mk_ipv4_udp(src, dst, sport, dport, &[0xAA; 1400]);
    let p2 = mk_ipv4_udp(src, dst, sport, dport, &[0xBB; 1400]);
    let p3 = mk_ipv4_udp(src, dst, sport, dport, &[0xCC; 600]);

    assert!(coalescer.push(&p1).is_none());
    assert!(coalescer.push(&p2).is_none());
    assert!(coalescer.push(&p3).is_none());

    let flushed = coalescer.flush().expect("burst must flush superpacket");
    let hdr = read_vnet_hdr(flushed).expect("valid vnet hdr");
    assert_eq!(hdr.gso_type, GSO_UDP_L4);
    assert_eq!(hdr.gso_size, 1400);
    assert_eq!(hdr.flags, F_NEEDS_CSUM);
    assert_eq!(hdr.hdr_len, 28);
    assert_eq!(hdr.csum_start, 20);
    assert_eq!(hdr.csum_offset, 6);

    let expected_len = VNET_HDR_LEN + 28 + 1400 + 1400 + 600;
    assert_eq!(flushed.len(), expected_len);

    let body = &flushed[VNET_HDR_LEN..];
    let total_len = u16::from_be_bytes([body[2], body[3]]);
    assert_eq!(total_len as usize, 28 + 3400);
    let udp_len = u16::from_be_bytes([body[24], body[25]]);
    assert_eq!(udp_len as usize, 8 + 3400);

    let payload = &body[28..];
    assert_eq!(payload.len(), 3400);
    assert_eq!(&payload[..1400], &[0xAA; 1400]);
    assert_eq!(&payload[1400..2800], &[0xBB; 1400]);
    assert_eq!(&payload[2800..], &[0xCC; 600]);
}

#[test]
fn test_coalescer_trailing_short_segment_flushes_on_next_push() {
    let mut coalescer = Coalescer::new();

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let p1 = mk_ipv4_udp(src, dst, 1000, 2000, &[0x11; 1200]);
    let p2 = mk_ipv4_udp(src, dst, 1000, 2000, &[0x22; 400]);
    let p3 = mk_ipv4_udp(src, dst, 1000, 2000, &[0x33; 1200]);

    assert!(coalescer.push(&p1).is_none());
    assert!(coalescer.push(&p2).is_none());

    let flushed = coalescer
        .push(&p3)
        .expect("sealed run flushes on next push");
    let hdr = read_vnet_hdr(flushed).expect("valid vnet hdr");
    assert_eq!(hdr.gso_type, GSO_UDP_L4);
    assert_eq!(hdr.gso_size, 1200);
    assert_eq!(flushed.len(), VNET_HDR_LEN + 28 + 1200 + 400);

    let flushed2 = coalescer.flush().expect("must flush p3");
    let hdr2 = read_vnet_hdr(flushed2).expect("valid vnet hdr");
    assert_eq!(hdr2.gso_type, GSO_UDP_L4);
    assert_eq!(hdr2.gso_size, 1200);
    assert_eq!(flushed2.len(), VNET_HDR_LEN + 28 + 1200);
}

#[test]
fn test_coalescer_aggregates_ipv6_udp_datagrams_with_trailing_short_segment() {
    let mut coalescer = Coalescer::new();

    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let sport = 8080;
    let dport = 9090;

    let p1 = mk_ipv6_udp(src, dst, sport, dport, &[0xAA; 1280]);
    let p2 = mk_ipv6_udp(src, dst, sport, dport, &[0xBB; 1280]);
    let p3 = mk_ipv6_udp(src, dst, sport, dport, &[0xCC; 256]);

    assert!(coalescer.push(&p1).is_none());
    assert!(coalescer.push(&p2).is_none());
    assert!(coalescer.push(&p3).is_none());

    let flushed = coalescer.flush().expect("flush ipv6 udp burst");
    let hdr = read_vnet_hdr(flushed).expect("valid vnet hdr");
    assert_eq!(hdr.gso_type, GSO_UDP_L4);
    assert_eq!(hdr.gso_size, 1280);
    assert_eq!(hdr.flags, F_NEEDS_CSUM);
    assert_eq!(hdr.hdr_len, 48);
    assert_eq!(hdr.csum_start, 40);
    assert_eq!(hdr.csum_offset, 6);

    let expected_len = VNET_HDR_LEN + 48 + 1280 + 1280 + 256;
    assert_eq!(flushed.len(), expected_len);

    let body = &flushed[VNET_HDR_LEN..];
    let ipv6_payload_len = u16::from_be_bytes([body[4], body[5]]);
    assert_eq!(ipv6_payload_len as usize, 8 + 1280 + 1280 + 256);
    let udp_len = u16::from_be_bytes([body[44], body[45]]);
    assert_eq!(udp_len as usize, 8 + 1280 + 1280 + 256);
}

#[test]
fn test_coalescer_udp_flushes_on_flow_mismatch() {
    let mut coalescer = Coalescer::new();

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let p1 = mk_ipv4_udp(src, dst, 5000, 6000, &[0x11; 500]);
    let p2 = mk_ipv4_udp(src, dst, 5001, 6000, &[0x22; 500]);

    assert!(coalescer.push(&p1).is_none());
    let flushed = coalescer.push(&p2).expect("mismatch flushes p1");
    let hdr = read_vnet_hdr(flushed).expect("hdr");
    assert_eq!(hdr.gso_type, GSO_UDP_L4);
    assert_eq!(hdr.gso_size, 500);
    assert_eq!(flushed.len(), VNET_HDR_LEN + 28 + 500);

    let flushed2 = coalescer.flush().expect("flushes p2");
    assert_eq!(read_vnet_hdr(flushed2).unwrap().gso_type, GSO_UDP_L4);
    assert_eq!(read_vnet_hdr(flushed2).unwrap().gso_size, 500);
    assert_eq!(flushed2.len(), VNET_HDR_LEN + 28 + 500);
}

#[test]
fn test_coalescer_udp_flushes_on_larger_payload() {
    let mut coalescer = Coalescer::new();

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let p1 = mk_ipv4_udp(src, dst, 5000, 6000, &[0x11; 1000]);
    let p2 = mk_ipv4_udp(src, dst, 5000, 6000, &[0x22; 1200]);

    assert!(coalescer.push(&p1).is_none());
    let flushed = coalescer.push(&p2).expect("larger payload cannot append");
    assert_eq!(read_vnet_hdr(flushed).unwrap().gso_type, GSO_UDP_L4);
    assert_eq!(read_vnet_hdr(flushed).unwrap().gso_size, 1000);
    assert_eq!(flushed.len(), VNET_HDR_LEN + 28 + 1000);

    let flushed2 = coalescer.flush().expect("flushes p2");
    assert_eq!(read_vnet_hdr(flushed2).unwrap().gso_type, GSO_UDP_L4);
    assert_eq!(read_vnet_hdr(flushed2).unwrap().gso_size, 1200);
    assert_eq!(flushed2.len(), VNET_HDR_LEN + 28 + 1200);
}

#[test]
fn test_coalescer_udp_max_segment_cap_64() {
    let mut coalescer = Coalescer::new();

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let p = mk_ipv4_udp(src, dst, 7000, 8000, &[0x55; 100]);

    for _ in 0..MAX_GSO_SEGMENTS {
        assert!(coalescer.push(&p).is_none());
    }

    let flushed = coalescer.push(&p).expect("65th segment flushes batch");
    let hdr = read_vnet_hdr(flushed).expect("hdr");
    assert_eq!(hdr.gso_type, GSO_UDP_L4);
    assert_eq!(hdr.gso_size, 100);
    assert_eq!(flushed.len(), VNET_HDR_LEN + 28 + (64 * 100));

    let flushed2 = coalescer.flush().expect("flushes 65th");
    assert_eq!(read_vnet_hdr(flushed2).unwrap().gso_type, GSO_UDP_L4);
    assert_eq!(read_vnet_hdr(flushed2).unwrap().gso_size, 100);
    assert_eq!(flushed2.len(), VNET_HDR_LEN + 28 + 100);
}

#[test]
fn test_coalescer_udp_payload_cap_65507() {
    assert_eq!(MAX_UDP_GSO_PAYLOAD, 65_507);
    let mut coalescer = Coalescer::new();

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let p_full = mk_ipv4_udp(src, dst, 9000, 9001, &[0x77; 1400]);

    // 46 segments * 1400 bytes = 64,400 bytes
    for _ in 0..46 {
        assert!(coalescer.push(&p_full).is_none());
    }

    // 65,507 - 64,400 = 1,107 bytes trailing short segment
    let p_short = mk_ipv4_udp(src, dst, 9000, 9001, &[0x88; 1107]);
    assert!(coalescer.push(&p_short).is_none());

    // Run is now sealed at 65,507 bytes payload. Next push must flush it.
    let p_next = mk_ipv4_udp(src, dst, 9000, 9001, &[0x99; 1400]);
    let flushed = coalescer.push(&p_next).expect("must flush at payload cap");
    let hdr = read_vnet_hdr(flushed).expect("hdr");
    assert_eq!(hdr.gso_type, GSO_UDP_L4);
    assert_eq!(hdr.gso_size, 1400);
    assert_eq!(flushed.len(), VNET_HDR_LEN + 28 + 65_507);
}

#[test]
fn test_coalescer_udp_zero_payload_is_singleton() {
    let mut coalescer = Coalescer::new();
    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let p_zero = mk_ipv4_udp(src, dst, 5000, 6000, &[]);

    assert!(coalescer.push(&p_zero).is_none());
    let flushed = coalescer.flush().expect("flush zero payload");
    let hdr = read_vnet_hdr(flushed).expect("hdr");
    assert_eq!(hdr.gso_type, 0); // GSO_NONE
    assert_eq!(flushed.len(), VNET_HDR_LEN + 28);
}

#[test]
fn test_coalescer_udp_pseudo_header_checksum_seeding() {
    let mut coalescer = Coalescer::new();
    let src = [192, 168, 1, 10];
    let dst = [192, 168, 1, 20];
    let p1 = mk_ipv4_udp(src, dst, 443, 5000, &[0xAA; 1400]);
    let p2 = mk_ipv4_udp(src, dst, 443, 5000, &[0xBB; 600]);

    assert!(coalescer.push(&p1).is_none());
    assert!(coalescer.push(&p2).is_none());

    let flushed = coalescer.flush().expect("flush");
    let body = &flushed[VNET_HDR_LEN..];

    // Total UDP length is 8 + 2000 = 2008
    let udp_len = 2008u16;
    let expected_pseudo = {
        let mut sum: u32 = 0;
        sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
        sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
        sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
        sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
        sum += 17u32;
        sum += u32::from(udp_len);
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16
    };

    let seeded_csum = u16::from_be_bytes([body[26], body[27]]);
    assert_eq!(
        seeded_csum, expected_pseudo,
        "uncomplemented pseudo-header checksum seeded at UDP csum field"
    );
}

#[test]
fn test_coalescer_udp_roundtrip_with_split_gro() {
    let mut coalescer = Coalescer::new();

    let src = [192, 168, 2, 1];
    let dst = [192, 168, 2, 2];
    let sport = 12345;
    let dport = 54321;

    let p1 = mk_ipv4_udp(src, dst, sport, dport, &[0x11; 1400]);
    let p2 = mk_ipv4_udp(src, dst, sport, dport, &[0x22; 1400]);
    let p3 = mk_ipv4_udp(src, dst, sport, dport, &[0x33; 500]);

    assert!(coalescer.push(&p1).is_none());
    assert!(coalescer.push(&p2).is_none());
    assert!(coalescer.push(&p3).is_none());

    let frame = coalescer.flush().expect("must flush");

    let mut out = Vec::new();
    let mut offsets = Vec::new();
    assert!(split_gro(frame, &mut out, &mut offsets));
    assert_eq!(offsets.len(), 3);

    let seg1 = &out[offsets[0].0..offsets[0].0 + offsets[0].1];
    let seg2 = &out[offsets[1].0..offsets[1].0 + offsets[1].1];
    let seg3 = &out[offsets[2].0..offsets[2].0 + offsets[2].1];

    assert_eq!(&seg1[28..], &[0x11; 1400]);
    assert_eq!(&seg2[28..], &[0x22; 1400]);
    assert_eq!(&seg3[28..], &[0x33; 500]);
}
