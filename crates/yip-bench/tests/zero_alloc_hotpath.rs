//! Deterministic zero-allocation hotpath verification gate under DHAT.
#![forbid(unsafe_code)]

use dhat::Alloc as DhatAlloc;
use yip_io::tun_offload::{split_gro, Coalescer};
use yip_wire::{Codec, Frame, WireCodec};

#[global_allocator]
static ALLOC: DhatAlloc = DhatAlloc;

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

#[test]
fn test_zero_alloc_hotpath_framing() {
    let _profiler = dhat::Profiler::builder().testing().build();

    let codec = Codec::new([1u8; 16], [2u8; 16]);
    let frame = Frame {
        conn_tag: 1,
        object_id: 0,
        payload_id: [0; 4],
        flags: 0,
        payload: vec![9u8; 1200],
    };
    let datagram = codec.frame(&frame);

    // Enter zero-allocation evaluated region for wire deframing
    let stats_before = dhat::HeapStats::get();

    let deframed = codec
        .deframe_borrowed(&datagram)
        .expect("valid frame deframes");
    assert_eq!(deframed.conn_tag, 1);
    assert_eq!(deframed.payload, &frame.payload[..]);

    let stats_after = dhat::HeapStats::get();
    // Verify no blocks or bytes were allocated inside the deframing hotpath
    assert_eq!(
        stats_after.total_blocks - stats_before.total_blocks,
        0,
        "Heap allocations detected on deframing hotpath (blocks)"
    );
    assert_eq!(
        stats_after.total_bytes - stats_before.total_bytes,
        0,
        "Heap allocations detected on deframing hotpath (bytes)"
    );

    // Verify looped execution also remains strictly zero-allocation
    let loop_before = dhat::HeapStats::get();
    for _ in 0..100 {
        let borrowed = codec
            .deframe_borrowed(&datagram)
            .expect("valid frame deframes in loop");
        assert_eq!(borrowed.conn_tag, 1);
        assert_eq!(borrowed.payload.len(), 1200);
    }
    let loop_after = dhat::HeapStats::get();
    assert_eq!(
        loop_after.total_blocks - loop_before.total_blocks,
        0,
        "Heap allocations detected on looped deframing hotpath (blocks)"
    );
    assert_eq!(
        loop_after.total_bytes - loop_before.total_bytes,
        0,
        "Heap allocations detected on looped deframing hotpath (bytes)"
    );

    // Enter zero-allocation evaluated region for UDP GSO coalescing and GRO splitting
    let src = [192, 168, 10, 1];
    let dst = [192, 168, 10, 2];
    let sport = 8080u16;
    let dport = 9090u16;

    let datagrams: Vec<Vec<u8>> = vec![
        make_ipv4_udp(src, dst, sport, dport, 0x1000, &[0xAA; 1400]),
        make_ipv4_udp(src, dst, sport, dport, 0x1001, &[0xBB; 1400]),
        make_ipv4_udp(src, dst, sport, dport, 0x1002, &[0xCC; 1400]),
        make_ipv4_udp(src, dst, sport, dport, 0x1003, &[0xDD; 600]),
    ];

    let mut coalescer = Coalescer::new(true);
    let mut out = Vec::with_capacity(70_000);
    let mut offsets = Vec::with_capacity(128);

    // Warm-up phase
    for pkt in &datagrams {
        coalescer.push(pkt);
    }
    if let Some(flushed) = coalescer.flush() {
        split_gro(flushed, &mut out, &mut offsets);
    }

    // Single-shot UDP GSO verification under DHAT
    let udp_stats_before = dhat::HeapStats::get();

    for pkt in &datagrams {
        let pushed = coalescer.push(pkt);
        assert!(pushed.is_none());
    }
    let flushed = coalescer.flush().expect("valid burst flushes");
    let split_ok = split_gro(flushed, &mut out, &mut offsets);
    assert!(split_ok);
    assert_eq!(offsets.len(), datagrams.len());

    let udp_stats_after = dhat::HeapStats::get();
    assert_eq!(
        udp_stats_after.total_blocks - udp_stats_before.total_blocks,
        0,
        "Heap allocations detected on UDP GSO hotpath (blocks)"
    );
    assert_eq!(
        udp_stats_after.total_bytes - udp_stats_before.total_bytes,
        0,
        "Heap allocations detected on UDP GSO hotpath (bytes)"
    );

    // Looped UDP GSO verification under DHAT (100 iterations)
    let udp_loop_before = dhat::HeapStats::get();
    for _ in 0..100 {
        for pkt in &datagrams {
            let pushed = coalescer.push(pkt);
            assert!(pushed.is_none());
        }
        let flushed = coalescer.flush().expect("valid burst flushes in loop");
        let split_ok = split_gro(flushed, &mut out, &mut offsets);
        assert!(split_ok);
        assert_eq!(offsets.len(), datagrams.len());
    }
    let udp_loop_after = dhat::HeapStats::get();
    assert_eq!(
        udp_loop_after.total_blocks - udp_loop_before.total_blocks,
        0,
        "Heap allocations detected on looped UDP GSO hotpath (blocks)"
    );
    assert_eq!(
        udp_loop_after.total_bytes - udp_loop_before.total_bytes,
        0,
        "Heap allocations detected on looped UDP GSO hotpath (bytes)"
    );

    // Prevent compiler from optimizing away the loop results
    let last_seg = &out[offsets[3].0..offsets[3].0 + offsets[3].1];
    assert_eq!(last_seg.len(), datagrams[3].len());
    assert_eq!(&last_seg[28..], &[0xDD; 600]);
}
