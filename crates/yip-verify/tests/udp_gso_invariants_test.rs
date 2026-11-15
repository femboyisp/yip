#![forbid(unsafe_code)]

use std::alloc::System;

use yip_io::tun_offload::{
    read_vnet_hdr, split_gro, Coalescer, F_NEEDS_CSUM, GSO_NONE, GSO_UDP_L4, MAX_GSO_SEGMENTS,
    MAX_UDP_GSO_PAYLOAD, VNET_HDR_LEN,
};
use yip_verify::{assert_no_alloc, TrackingAllocator};

#[global_allocator]
static GLOBAL: TrackingAllocator<System> = TrackingAllocator(System);

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
    sum += u32::try_from(udp_len).expect("udp_len fits u32") & 0xFFFF;
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
    let udp_len_u32 = u32::try_from(udp_len).expect("udp_len fits u32");
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

fn make_ipv4_udp(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ihl = 20usize;
    let uhl = 8usize;
    let total = ihl + uhl + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(u16::try_from(total).expect("total fits u16")).to_be_bytes());
    p[4..6].copy_from_slice(&ip_id.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[ihl..ihl + 2].copy_from_slice(&sport.to_be_bytes());
    p[ihl + 2..ihl + 4].copy_from_slice(&dport.to_be_bytes());
    let udp_len = u16::try_from(uhl + payload.len()).expect("udp_len fits u16");
    p[ihl + 4..ihl + 6].copy_from_slice(&udp_len.to_be_bytes());
    p[ihl + 8..].copy_from_slice(payload);
    compute_ipv4_checksum(&mut p[..ihl]);
    compute_udp_checksum(&mut p, ihl);
    p
}

fn make_ipv6_udp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ip_len = 40usize;
    let uhl = 8usize;
    let total = ip_len + uhl + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x60;
    let payload_len = u16::try_from(uhl + payload.len()).expect("payload_len fits u16");
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
fn test_udp_gso_ipv4_algebraic_identity_varying_payload_sizes_and_trailing() {
    let mut coalescer = Coalescer::new(true);
    let mut out = Vec::new();
    let mut offsets = Vec::new();

    let src = [10, 0, 1, 5];
    let dst = [10, 0, 2, 9];
    let sport = 8080u16;
    let dport = 9090u16;

    // Test a matrix of full-segment payload sizes and trailing short segment variations
    let test_configs: &[(usize, usize, usize)] = &[
        // (gso_size, full_segment_count, trailing_size)
        (1, 4, 0),
        (7, 3, 4),
        (64, 5, 23),
        (256, 4, 128),
        (512, 6, 0),
        (1000, 3, 450),
        (1400, 10, 750),
        (1400, 1, 0),
        (1400, 1, 500),
    ];

    for &(gso_size, full_count, trailing_size) in test_configs {
        let mut original_packets = Vec::new();
        let start_ip_id = 0x3000u16;

        for i in 0..full_count {
            let ip_id = start_ip_id.wrapping_add(i as u16);
            let mut payload = vec![0u8; gso_size];
            for (byte_idx, b) in payload.iter_mut().enumerate() {
                *b = ((i * 31 + byte_idx * 7 + 0x41) & 0xFF) as u8;
            }
            original_packets.push(make_ipv4_udp(src, dst, sport, dport, ip_id, &payload));
        }

        if trailing_size > 0 {
            let i = full_count;
            let ip_id = start_ip_id.wrapping_add(i as u16);
            let mut payload = vec![0u8; trailing_size];
            for (byte_idx, b) in payload.iter_mut().enumerate() {
                *b = ((i * 31 + byte_idx * 11 + 0x7B) & 0xFF) as u8;
            }
            original_packets.push(make_ipv4_udp(src, dst, sport, dport, ip_id, &payload));
        }

        for pkt in &original_packets {
            assert!(coalescer.push(pkt).is_none());
        }

        let flushed = coalescer.flush().expect("burst must flush superpacket");
        let vnet_hdr = read_vnet_hdr(flushed).expect("valid vnet header");

        if original_packets.len() > 1 {
            assert_eq!(vnet_hdr.gso_type, GSO_UDP_L4);
            assert_eq!(vnet_hdr.gso_size, gso_size as u16);
            assert_eq!(vnet_hdr.flags, F_NEEDS_CSUM);
            assert_eq!(vnet_hdr.csum_start, 20);
            assert_eq!(vnet_hdr.csum_offset, 6);
        } else {
            assert_eq!(vnet_hdr.gso_type, GSO_NONE);
            assert_eq!(vnet_hdr.gso_size, 0);
            assert_eq!(vnet_hdr.flags, 0);
        }

        let split_ok = split_gro(flushed, &mut out, &mut offsets);
        assert!(split_ok, "split_gro must succeed");
        assert_eq!(
            offsets.len(),
            original_packets.len(),
            "sliced datagram count must match input burst"
        );

        for (idx, &(start, len)) in offsets.iter().enumerate() {
            let sliced = &out[start..start + len];
            let original = &original_packets[idx];

            assert_eq!(
                sliced.len(),
                original.len(),
                "sliced datagram length must match original"
            );

            // Byte-for-byte identity across the full IP packet
            assert_eq!(
                sliced, original,
                "sliced datagram must match original datagram byte-for-byte"
            );

            // Verify specific headers and payloads
            assert_eq!(sliced[0], 0x45);
            assert_eq!(&sliced[12..16], &src);
            assert_eq!(&sliced[16..20], &dst);
            assert_eq!(u16::from_be_bytes([sliced[20], sliced[21]]), sport);
            assert_eq!(u16::from_be_bytes([sliced[22], sliced[23]]), dport);

            let expected_payload_len = original.len() - 28;
            assert_eq!(
                u16::from_be_bytes([sliced[24], sliced[25]]) as usize,
                8 + expected_payload_len
            );
            assert_eq!(&sliced[28..], &original[28..]);

            // Checksum validation
            assert!(
                verify_ipv4_checksum(&sliced[..20]),
                "IPv4 header checksum must fold to 0xFFFF"
            );
            assert!(
                verify_ipv4_udp_checksum(sliced, 20),
                "UDP checksum must fold to 0xFFFF per RFC 768"
            );
        }
    }
}

#[test]
fn test_udp_gso_ipv6_algebraic_identity_varying_payload_sizes_and_trailing() {
    let mut coalescer = Coalescer::new(true);
    let mut out = Vec::new();
    let mut offsets = Vec::new();

    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let sport = 11223u16;
    let dport = 33445u16;

    let test_configs: &[(usize, usize, usize)] = &[
        (1, 3, 0),
        (16, 4, 9),
        (128, 5, 64),
        (512, 4, 0),
        (1280, 4, 256),
        (1400, 8, 400),
    ];

    for &(gso_size, full_count, trailing_size) in test_configs {
        let mut original_packets = Vec::new();

        for i in 0..full_count {
            let mut payload = vec![0u8; gso_size];
            for (byte_idx, b) in payload.iter_mut().enumerate() {
                *b = ((i * 47 + byte_idx * 13 + 0x2A) & 0xFF) as u8;
            }
            original_packets.push(make_ipv6_udp(src, dst, sport, dport, &payload));
        }

        if trailing_size > 0 {
            let i = full_count;
            let mut payload = vec![0u8; trailing_size];
            for (byte_idx, b) in payload.iter_mut().enumerate() {
                *b = ((i * 47 + byte_idx * 17 + 0x93) & 0xFF) as u8;
            }
            original_packets.push(make_ipv6_udp(src, dst, sport, dport, &payload));
        }

        for pkt in &original_packets {
            assert!(coalescer.push(pkt).is_none());
        }

        let flushed = coalescer.flush().expect("burst must flush superpacket");
        let vnet_hdr = read_vnet_hdr(flushed).expect("valid vnet header");

        if original_packets.len() > 1 || trailing_size == 0 {
            assert_eq!(vnet_hdr.gso_type, GSO_UDP_L4);
            assert_eq!(vnet_hdr.gso_size, gso_size as u16);
            assert_eq!(vnet_hdr.flags, F_NEEDS_CSUM);
            assert_eq!(vnet_hdr.csum_start, 40);
            assert_eq!(vnet_hdr.csum_offset, 6);
        }

        let split_ok = split_gro(flushed, &mut out, &mut offsets);
        assert!(split_ok, "split_gro must succeed");
        assert_eq!(
            offsets.len(),
            original_packets.len(),
            "sliced datagram count must match input burst"
        );

        for (idx, &(start, len)) in offsets.iter().enumerate() {
            let sliced = &out[start..start + len];
            let original = &original_packets[idx];

            assert_eq!(
                sliced.len(),
                original.len(),
                "sliced datagram length must match original"
            );

            assert_eq!(
                sliced, original,
                "sliced datagram must match original IPv6 datagram byte-for-byte"
            );

            assert_eq!(sliced[0] >> 4, 6);
            assert_eq!(&sliced[8..24], &src);
            assert_eq!(&sliced[24..40], &dst);
            assert_eq!(u16::from_be_bytes([sliced[40], sliced[41]]), sport);
            assert_eq!(u16::from_be_bytes([sliced[42], sliced[43]]), dport);

            let expected_payload_len = original.len() - 48;
            assert_eq!(
                u16::from_be_bytes([sliced[44], sliced[45]]) as usize,
                8 + expected_payload_len
            );
            assert_eq!(&sliced[48..], &original[48..]);

            let csum = u16::from_be_bytes([sliced[46], sliced[47]]);
            assert_ne!(
                csum, 0,
                "RFC 8200 section 8.1 requires non-zero UDP checksum in IPv6"
            );
            assert!(
                verify_ipv6_udp_checksum(sliced),
                "IPv6 UDP checksum must fold to 0xFFFF per RFC 8200"
            );
        }
    }
}

#[test]
fn test_udp_gso_max_segment_limit_64() {
    let mut coalescer = Coalescer::new(true);
    let mut out = Vec::new();
    let mut offsets = Vec::new();

    let src = [192, 168, 100, 1];
    let dst = [192, 168, 100, 2];
    let sport = 5000u16;
    let dport = 6000u16;
    let seg_payload_len = 1000usize;
    let start_ip_id = 0x5000u16;

    let mut original_64 = Vec::with_capacity(MAX_GSO_SEGMENTS);
    for i in 0..MAX_GSO_SEGMENTS {
        let ip_id = start_ip_id.wrapping_add(i as u16);
        let mut payload = vec![0u8; seg_payload_len];
        for (byte_idx, b) in payload.iter_mut().enumerate() {
            *b = ((i * 19 + byte_idx * 3 + 1) & 0xFF) as u8;
        }
        original_64.push(make_ipv4_udp(src, dst, sport, dport, ip_id, &payload));
    }

    // Pushing exactly 64 segments must all coalesce into a single pending run
    for pkt in &original_64 {
        assert!(coalescer.push(pkt).is_none());
    }

    let flushed = coalescer
        .flush()
        .expect("64 segments burst must flush superpacket");
    let vnet_hdr = read_vnet_hdr(flushed).expect("valid vnet header");
    assert_eq!(vnet_hdr.gso_type, GSO_UDP_L4);
    assert_eq!(vnet_hdr.gso_size, seg_payload_len as u16);
    assert_eq!(
        flushed.len(),
        VNET_HDR_LEN + 28 + (MAX_GSO_SEGMENTS * seg_payload_len)
    );

    assert!(split_gro(flushed, &mut out, &mut offsets));
    assert_eq!(offsets.len(), MAX_GSO_SEGMENTS);

    for (idx, &(start, len)) in offsets.iter().enumerate() {
        let sliced = &out[start..start + len];
        let original = &original_64[idx];
        assert_eq!(sliced, original);
        assert!(verify_ipv4_checksum(&sliced[..20]));
        assert!(verify_ipv4_udp_checksum(sliced, 20));
    }

    // Now test pushing 65 segments: 65th must immediately flush the 64-segment superpacket
    for pkt in &original_64 {
        assert!(coalescer.push(pkt).is_none());
    }

    let p65 = make_ipv4_udp(
        src,
        dst,
        sport,
        dport,
        start_ip_id.wrapping_add(64),
        &vec![0xEE; seg_payload_len],
    );

    let flushed_64 = coalescer
        .push(&p65)
        .expect("65th push must flush the 64-segment run");
    assert_eq!(read_vnet_hdr(flushed_64).expect("hdr").gso_type, GSO_UDP_L4);
    assert_eq!(
        flushed_64.len(),
        VNET_HDR_LEN + 28 + (MAX_GSO_SEGMENTS * seg_payload_len)
    );

    let flushed_remaining = coalescer.flush().expect("flushes remaining 65th segment");
    let hdr_remaining = read_vnet_hdr(flushed_remaining).expect("hdr");
    assert_eq!(hdr_remaining.gso_type, GSO_NONE);
    assert_eq!(hdr_remaining.gso_size, 0);
    assert_eq!(hdr_remaining.flags, 0);
    assert_eq!(flushed_remaining.len(), VNET_HDR_LEN + 28 + seg_payload_len);
    assert_eq!(&flushed_remaining[VNET_HDR_LEN..], &p65[..]);
}

#[test]
fn test_udp_gso_steady_state_zero_allocation_hotpath() {
    let mut coalescer = Coalescer::new(true);
    let mut out = Vec::with_capacity(MAX_UDP_GSO_PAYLOAD + 256);
    let mut offsets = Vec::with_capacity(MAX_GSO_SEGMENTS + 16);

    let src_v4 = [10, 20, 30, 40];
    let dst_v4 = [50, 60, 70, 80];
    let sport = 4433u16;
    let dport = 8443u16;

    // Warm-up batch: 5 IPv4 segments (4 x 1400 + 1 x 600 trailing)
    let mut warmup_v4 = Vec::with_capacity(5);
    for i in 0..4 {
        let payload = vec![0x33u8; 1400];
        warmup_v4.push(make_ipv4_udp(
            src_v4,
            dst_v4,
            sport,
            dport,
            0x1000 + i,
            &payload,
        ));
    }
    let p_short_v4 = make_ipv4_udp(src_v4, dst_v4, sport, dport, 0x1004, &vec![0x44u8; 600]);
    warmup_v4.push(p_short_v4);

    // Warm up coalescer and split_gro buffers
    for pkt in &warmup_v4 {
        coalescer.push(pkt);
    }
    if let Some(flushed) = coalescer.flush() {
        split_gro(flushed, &mut out, &mut offsets);
    }

    // Steady-state IPv4 verification under TrackingAllocator: strictly 0 heap allocations
    for _ in 0..100 {
        assert_no_alloc!({
            for pkt in &warmup_v4 {
                let res = coalescer.push(pkt);
                assert!(res.is_none());
            }
            let flushed = coalescer.flush().expect("burst flushes superpacket");
            let split_ok = split_gro(flushed, &mut out, &mut offsets);
            assert!(split_ok);
            assert_eq!(offsets.len(), warmup_v4.len());
        });
    }

    // Prepare IPv6 batch: 4 x 1280 + 1 x 320 trailing
    let src_v6 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_v6 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut warmup_v6 = Vec::with_capacity(5);
    for _ in 0..4 {
        let payload = vec![0x55u8; 1280];
        warmup_v6.push(make_ipv6_udp(src_v6, dst_v6, sport, dport, &payload));
    }
    let p_short_v6 = make_ipv6_udp(src_v6, dst_v6, sport, dport, &vec![0x66u8; 320]);
    warmup_v6.push(p_short_v6);

    // Warm up IPv6
    for pkt in &warmup_v6 {
        coalescer.push(pkt);
    }
    if let Some(flushed) = coalescer.flush() {
        split_gro(flushed, &mut out, &mut offsets);
    }

    // Steady-state IPv6 verification under TrackingAllocator: strictly 0 heap allocations
    for _ in 0..100 {
        assert_no_alloc!({
            for pkt in &warmup_v6 {
                let res = coalescer.push(pkt);
                assert!(res.is_none());
            }
            let flushed = coalescer.flush().expect("burst flushes superpacket");
            let split_ok = split_gro(flushed, &mut out, &mut offsets);
            assert!(split_ok);
            assert_eq!(offsets.len(), warmup_v6.len());
        });
    }

    // Verify last split output integrity
    assert_eq!(offsets.len(), 5);
    let seg0 = &out[offsets[0].0..offsets[0].0 + offsets[0].1];
    assert_eq!(seg0.len(), 48 + 1280);
    let seg4 = &out[offsets[4].0..offsets[4].0 + offsets[4].1];
    assert_eq!(seg4.len(), 48 + 320);
    assert_eq!(&seg4[48..], &[0x66u8; 320]);
}
