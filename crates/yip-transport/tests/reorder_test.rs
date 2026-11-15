use yip_transport::reorder::{
    seq_after, seq_before, seq_geq, seq_leq, FlowReorderState, ReorderBuffer, ReorderOutcome,
    ReorderSlot, MAX_CONCURRENT_TRACKED_FLOWS, MAX_FLOW_REORDER_SLOTS, MAX_SLOT_PACKET_LEN,
};

fn make_ipv4_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let ip_total_len = 20 + 20 + payload.len();
    let mut pkt = vec![0u8; ip_total_len];
    pkt[0] = 0x45; // IPv4, header len = 5 (20 bytes)
    pkt[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 6; // Protocol = TCP
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);

    // TCP Header at offset 20
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&0u32.to_be_bytes()); // ack
    pkt[32] = 0x50; // data offset = 5 (20 bytes), flags = 0
    pkt[33] = 0x18; // ACK + PSH
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes()); // window

    pkt[40..].copy_from_slice(payload);
    pkt
}

fn make_ipv6_tcp_packet(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let l4_len = 20 + payload.len();
    let total_len = 40 + l4_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60; // IPv6, tc=0, flow=0
    pkt[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
    pkt[6] = 6; // Next header = TCP
    pkt[7] = 64; // Hop limit
    pkt[8..24].copy_from_slice(&src_ip);
    pkt[24..40].copy_from_slice(&dst_ip);

    // TCP Header at offset 40
    pkt[40..42].copy_from_slice(&sport.to_be_bytes());
    pkt[42..44].copy_from_slice(&dport.to_be_bytes());
    pkt[44..48].copy_from_slice(&seq.to_be_bytes());
    pkt[48..52].copy_from_slice(&0u32.to_be_bytes());
    pkt[52] = 0x50; // data offset = 5 (20 bytes)
    pkt[53] = 0x18; // ACK + PSH
    pkt[54..56].copy_from_slice(&65535u16.to_be_bytes());

    pkt[60..].copy_from_slice(payload);
    pkt
}

fn wrap_l2(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut eth = vec![0u8; 14 + payload.len()];
    eth[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst MAC
    eth[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src MAC
    eth[12..14].copy_from_slice(&ethertype.to_be_bytes());
    eth[14..].copy_from_slice(payload);
    eth
}

#[test]
fn test_seq_arithmetic_helpers_exhaustive() {
    assert!(!seq_after(10, 10));
    assert!(seq_after(11, 10));
    assert!(!seq_after(10, 11));

    assert!(!seq_before(10, 10));
    assert!(seq_before(9, 10));
    assert!(!seq_before(10, 9));

    assert!(seq_geq(10, 10));
    assert!(seq_geq(11, 10));
    assert!(!seq_geq(9, 10));

    assert!(seq_leq(10, 10));
    assert!(seq_leq(9, 10));
    assert!(!seq_leq(11, 10));

    // Wraparound around 0 and u32::MAX
    assert!(seq_after(0, u32::MAX));
    assert!(!seq_after(u32::MAX, 0));
    assert!(seq_before(u32::MAX, 0));
    assert!(!seq_before(0, u32::MAX));

    assert!(seq_geq(0, u32::MAX));
    assert!(!seq_geq(u32::MAX, 0));
    assert!(seq_leq(u32::MAX, 0));
    assert!(!seq_leq(0, u32::MAX));
}

#[test]
fn test_non_tcp_traffic_bypasses_reordering_immediately() {
    let mut rb = ReorderBuffer::new(2);
    let mut udp_pkt = vec![0u8; 40];
    udp_pkt[0] = 0x45;
    udp_pkt[9] = 17; // UDP
    let mut emitted = Vec::new();
    let outcome = rb.process(&udp_pkt, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(outcome, ReorderOutcome::Bypassed);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], udp_pkt);
}

#[test]
fn test_in_order_tcp_traffic_emits_immediately() {
    let mut rb = ReorderBuffer::new(2);
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1000, &[0xAA; 100]);
    let p2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1100, &[0xBB; 100]);
    let mut emitted = Vec::new();

    let outcome1 = rb.process(&p1, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(outcome1, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p1);

    emitted.clear();
    let outcome2 = rb.process(&p2, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(outcome2, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p2);
}

#[test]
fn test_out_of_order_tcp_buffers_and_drains_on_hole_fill() {
    let mut rb = ReorderBuffer::new(2);
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1000, &[0x11; 100]);
    let p2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1100, &[0x22; 100]);
    let p3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1200, &[0x33; 100]);
    let p4 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1300, &[0x44; 100]);

    let mut emitted = Vec::new();
    let o1 = rb.process(&p1, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(o1, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);

    // p3 arrives before p2 (gap at 1100)
    emitted.clear();
    let o3 = rb.process(&p3, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(o3, ReorderOutcome::Buffered);
    assert!(emitted.is_empty(), "p3 must be buffered pending p2");

    // p2 arrives (fills hole) -> must emit p2 and buffered p3 in exact sequence
    emitted.clear();
    let o2 = rb.process(&p2, false, 102, |p| emitted.push(p.to_vec()));
    assert_eq!(o2, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 2, "hole fill must emit p2 and p3");
    assert_eq!(emitted[0], p2);
    assert_eq!(emitted[1], p3);

    // Next expected sequence must be 1300: p4 must emit in order immediately
    emitted.clear();
    let o4 = rb.process(&p4, false, 103, |p| emitted.push(p.to_vec()));
    assert_eq!(o4, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p4);
}

#[test]
fn test_reorder_timeout_eviction_flushes_slots() {
    let mut rb = ReorderBuffer::new(2); // 2ms deadline
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1000, &[0x11; 100]);
    let p3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1200, &[0x33; 100]);
    let p4 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1300, &[0x44; 100]);

    rb.process(&p1, false, 100, |_| {});

    let mut emitted = Vec::new();
    let o3 = rb.process(&p3, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(o3, ReorderOutcome::Buffered);
    assert!(emitted.is_empty());

    // At 101 ms: not expired yet
    let flushed1 = rb.poll_timeouts(101, |p| emitted.push(p.to_vec()));
    assert_eq!(flushed1, 0);
    assert!(emitted.is_empty());

    // At 102 ms (100 + 2): deadline expired, must flush p3
    let flushed2 = rb.poll_timeouts(102, |p| emitted.push(p.to_vec()));
    assert_eq!(flushed2, 1);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p3);

    // Expected sequence must be 1300 after flushing p3 (1200 + 100)
    emitted.clear();
    let o4 = rb.process(&p4, false, 103, |p| emitted.push(p.to_vec()));
    assert_eq!(o4, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p4);
}

#[test]
fn test_out_of_order_packet_when_deadline_expired_flushes() {
    let mut rb = ReorderBuffer::new(2); // 2ms deadline
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1000, &[0x11; 100]);
    let p3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1200, &[0x33; 100]);
    let p5 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1400, &[0x55; 100]);

    rb.process(&p1, false, 100, |_| {});
    // Buffer p3 at t=100 (deadline_ms = 102)
    rb.process(&p3, false, 100, |_| {});

    // At t=103 ms (>= 102), p5 arrives: must trigger deadline flush of p3 inside process()
    let mut emitted = Vec::new();
    let o = rb.process(&p5, false, 103, |p| emitted.push(p.to_vec()));
    assert_eq!(o, ReorderOutcome::Flushed);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p3);
}

#[test]
fn test_reorder_slot_overflow_flushes() {
    let mut rb = ReorderBuffer::new(10);
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 1000, &[0x11; 50]);
    rb.process(&p1, false, 100, |_| {});

    let mut emitted = Vec::new();
    // Fill all slots with out-of-order packets
    for i in 1..=MAX_FLOW_REORDER_SLOTS {
        let seq = 1000 + (i as u32 * 100);
        let p = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, seq, &[0x42; 50]);
        let o = rb.process(&p, false, 100, |pkt| emitted.push(pkt.to_vec()));
        assert_eq!(o, ReorderOutcome::Buffered);
    }
    // All MAX_FLOW_REORDER_SLOTS slots are now filled
    assert!(emitted.is_empty());

    // 17th out-of-order packet causes overflow eviction
    let overflow_p =
        make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, 5000, &[0x99; 50]);
    let o_over = rb.process(&overflow_p, false, 100, |pkt| emitted.push(pkt.to_vec()));
    assert_eq!(o_over, ReorderOutcome::Flushed);
    assert_eq!(
        emitted.len(),
        MAX_FLOW_REORDER_SLOTS,
        "overflow must flush buffered slots"
    );
}

#[test]
fn test_l2_ethernet_tcp_reordering() {
    let mut rb = ReorderBuffer::new(2);
    let p1_inner = make_ipv4_tcp_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        4000,
        80,
        2000,
        &[0x11; 60],
    );
    let p2_inner = make_ipv4_tcp_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        4000,
        80,
        2060,
        &[0x22; 60],
    );
    let p3_inner = make_ipv4_tcp_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        4000,
        80,
        2120,
        &[0x33; 60],
    );

    let p1 = wrap_l2(0x0800, &p1_inner);
    let p2 = wrap_l2(0x0800, &p2_inner);
    let p3 = wrap_l2(0x0800, &p3_inner);

    let mut emitted = Vec::new();
    rb.process(&p1, true, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p1);

    // p3 out of order
    emitted.clear();
    rb.process(&p3, true, 100, |p| emitted.push(p.to_vec()));
    assert!(emitted.is_empty());

    // p2 arrives
    rb.process(&p2, true, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 2);
    assert_eq!(emitted[0], p2);
    assert_eq!(emitted[1], p3);

    // Non-IP L2 packet (e.g. ARP 0x0806) bypasses directly
    emitted.clear();
    let arp = wrap_l2(0x0806, &[0x00; 28]);
    let o_arp = rb.process(&arp, true, 102, |p| emitted.push(p.to_vec()));
    assert_eq!(o_arp, ReorderOutcome::Bypassed);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], arp);
}

#[test]
fn test_ipv6_tcp_reordering_and_drain() {
    let mut rb = ReorderBuffer::new(5);
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    let p1 = make_ipv6_tcp_packet(src, dst, 9000, 443, 50_000, &[0xAA; 80]);
    let p2 = make_ipv6_tcp_packet(src, dst, 9000, 443, 50_080, &[0xBB; 80]);
    let p3 = make_ipv6_tcp_packet(src, dst, 9000, 443, 50_160, &[0xCC; 80]);

    let mut emitted = Vec::new();
    rb.process(&p1, false, 200, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p1);

    // Deliver p3 first
    emitted.clear();
    rb.process(&p3, false, 201, |p| emitted.push(p.to_vec()));
    assert!(emitted.is_empty());

    // Hole filled by p2
    rb.process(&p2, false, 202, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 2);
    assert_eq!(emitted[0], p2);
    assert_eq!(emitted[1], p3);
}

#[test]
fn test_tcp_syn_and_rst_handling() {
    let mut rb = ReorderBuffer::new(5);
    // Create SYN packet: payload empty, flags SYN (0x02)
    let mut syn_pkt = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 10_000, &[]);
    syn_pkt[33] = 0x02; // SYN flag

    let mut emitted = Vec::new();
    let o_syn = rb.process(&syn_pkt, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(o_syn, ReorderOutcome::Bypassed);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], syn_pkt);

    // Next data packet should expect seq = 10_001
    emitted.clear();
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 10_001, &[0x55; 100]);
    let o1 = rb.process(&p1, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(o1, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p1);

    // Send RST packet: flags RST (0x04)
    emitted.clear();
    let mut rst_pkt = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 10_101, &[]);
    rst_pkt[33] = 0x04; // RST
    let o_rst = rb.process(&rst_pkt, false, 102, |p| emitted.push(p.to_vec()));
    assert_eq!(o_rst, ReorderOutcome::Bypassed);
    assert_eq!(emitted.len(), 1);
}

#[test]
fn test_pure_ack_bypasses_reordering() {
    let mut rb = ReorderBuffer::new(5);
    let p_data = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 50]);
    rb.process(&p_data, false, 100, |_| {});

    // Pure ACK: payload len = 0, flags = ACK (0x10)
    let p_ack = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 5000, &[]);
    let mut emitted = Vec::new();
    let o_ack = rb.process(&p_ack, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(o_ack, ReorderOutcome::Bypassed);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p_ack);
}

#[test]
fn test_duplicate_and_overlapping_packets() {
    let mut rb = ReorderBuffer::new(5);
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 100]);
    let mut emitted = Vec::new();
    rb.process(&p1, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 1);

    // Exact duplicate packet (seq 1000, len 100, expected 1100) -> dropped
    emitted.clear();
    let o_dup = rb.process(&p1, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(o_dup, ReorderOutcome::Duplicate);
    assert!(emitted.is_empty(), "exact duplicate must be dropped");

    // Overlapping retransmission (seq 1050, len 100 -> ends at 1150 > expected 1100)
    emitted.clear();
    let p_overlap =
        make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1050, &[0x22; 100]);
    let o_overlap = rb.process(&p_overlap, false, 102, |p| emitted.push(p.to_vec()));
    assert_eq!(o_overlap, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p_overlap);

    // Next expected sequence should be 1150
    emitted.clear();
    let p3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1150, &[0x33; 50]);
    let o3 = rb.process(&p3, false, 103, |p| emitted.push(p.to_vec()));
    assert_eq!(o3, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p3);
}

#[test]
fn test_duplicate_in_buffer_slot() {
    let mut rb = ReorderBuffer::new(10);
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 100]);
    let p3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1200, &[0x33; 100]);

    rb.process(&p1, false, 100, |_| {});
    let o3 = rb.process(&p3, false, 100, |_| {});
    assert_eq!(o3, ReorderOutcome::Buffered);

    // Send identical p3 again while still buffered
    let mut emitted = Vec::new();
    let o_dup = rb.process(&p3, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(o_dup, ReorderOutcome::Duplicate);
    assert!(emitted.is_empty());
}

#[test]
fn test_sequence_wrapping_arithmetic() {
    let mut rb = ReorderBuffer::new(5);
    // Near u32::MAX
    let seq_start = u32::MAX - 50; // 4294967245
    let p1 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        seq_start,
        &[0x11; 100],
    );
    // seq_start + 100 = 49 (wrapped)
    let p2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 49, &[0x22; 100]);
    let p3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 149, &[0x33; 100]);

    let mut emitted = Vec::new();
    rb.process(&p1, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 1);

    // Send p3 (out of order, wrapped)
    emitted.clear();
    rb.process(&p3, false, 101, |p| emitted.push(p.to_vec()));
    assert!(emitted.is_empty());

    // Send p2 (fills hole)
    rb.process(&p2, false, 102, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 2);
    assert_eq!(emitted[0], p2);
    assert_eq!(emitted[1], p3);
}

#[test]
fn test_multiple_concurrent_flows() {
    let mut rb = ReorderBuffer::new(10);
    // Flow A: 5001 -> 80
    let a1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 80, 1000, &[0xAA; 50]);
    let a2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 80, 1050, &[0xAB; 50]);
    let a3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 80, 1100, &[0xAC; 50]);

    // Flow B: 5002 -> 80
    let b1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5002, 80, 9000, &[0xBA; 50]);
    let b2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5002, 80, 9050, &[0xBB; 50]);

    let mut emitted = Vec::new();
    rb.process(&a1, false, 100, |p| emitted.push(p.to_vec()));
    rb.process(&b1, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 2);

    // Out of order on Flow A
    emitted.clear();
    rb.process(&a3, false, 101, |p| emitted.push(p.to_vec()));
    assert!(emitted.is_empty());

    // In order on Flow B: must NOT affect Flow A
    rb.process(&b2, false, 102, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], b2);

    // Hole fill on Flow A
    emitted.clear();
    rb.process(&a2, false, 103, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 2);
    assert_eq!(emitted[0], a2);
    assert_eq!(emitted[1], a3);
}

#[test]
fn test_lru_eviction_tie_breaker_first_slot() {
    let mut rb = ReorderBuffer::new(10);
    // Flow 0: port 1000 at timestamp 100, buffer a gap packet
    let p_f0 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, 1000, &[0x11; 50]);
    rb.process(&p_f0, false, 100, |_| {});
    let p_f0_gap = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, 1200, &[0xAA; 50]);
    rb.process(&p_f0_gap, false, 100, |_| {});

    // Flow 1: port 1001 at timestamp 100, buffer a gap packet
    let p_f1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1001, 80, 1000, &[0x22; 50]);
    rb.process(&p_f1, false, 100, |_| {});
    let p_f1_gap = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1001, 80, 1200, &[0xBB; 50]);
    rb.process(&p_f1_gap, false, 100, |_| {});

    // Fill remaining flows (2..64) at timestamp 200
    for i in 2..MAX_CONCURRENT_TRACKED_FLOWS {
        let p = make_ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1000 + i as u16,
            80,
            1000,
            &[0x33; 50],
        );
        rb.process(&p, false, 200, |_| {});
    }

    // Both Flow 0 (index 0) and Flow 1 (index 1) have last_seen_ms = 100.
    // The strict inequality `f.last_seen_ms < min_last_seen` must keep index 0 as LRU victim.
    let mut emitted = Vec::new();
    let p_new = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 9999, 80, 5000, &[0x99; 50]);
    let o = rb.process(&p_new, false, 300, |p| emitted.push(p.to_vec()));
    assert_eq!(o, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 2);
    assert_eq!(
        emitted[0], p_f0_gap,
        "Flow 0 (lowest index) must be evicted on equal timestamp"
    );
    assert_eq!(emitted[1], p_new);
}

#[test]
fn test_ipv4_trailing_padding() {
    let mut rb = ReorderBuffer::new(5);
    let mut p = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 40]);
    // Append 20 bytes of Ethernet padding beyond total_len (60 bytes)
    p.extend_from_slice(&[0u8; 20]);
    let mut emitted = Vec::new();
    let o = rb.process(&p, false, 100, |pkt| emitted.push(pkt.to_vec()));
    assert_eq!(o, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
}

#[test]
fn test_flow_table_lru_eviction() {
    let mut rb = ReorderBuffer::new(10);
    let mut emitted = Vec::new();

    // Fill table with MAX_CONCURRENT_TRACKED_FLOWS distinct flows
    for i in 0..MAX_CONCURRENT_TRACKED_FLOWS {
        let p = make_ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1000 + i as u16,
            80,
            1000,
            &[0x11; 50],
        );
        rb.process(&p, false, 100 + i as u64, |pkt| emitted.push(pkt.to_vec()));
    }
    assert_eq!(emitted.len(), MAX_CONCURRENT_TRACKED_FLOWS);

    // Next flow triggers LRU eviction of the oldest flow (port 1000)
    emitted.clear();
    let p_new = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 9999, 80, 1000, &[0x22; 50]);
    let o_new = rb.process(&p_new, false, 200, |pkt| emitted.push(pkt.to_vec()));
    assert_eq!(o_new, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p_new);
}

#[test]
fn test_lru_eviction_strictly_oldest() {
    let mut rb = ReorderBuffer::new(10);
    // Fill all 64 flows with monotonic timestamps 100..163
    for i in 0..MAX_CONCURRENT_TRACKED_FLOWS {
        let p = make_ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1000 + i as u16,
            80,
            1000,
            &[0x11; 50],
        );
        rb.process(&p, false, 100 + i as u64, |_| {});
    }

    // Buffer an out-of-order packet on Flow 1 (port 1001, timestamp 101)
    let p_f1_gap = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1001, 80, 1500, &[0xAA; 50]);
    let o_f1 = rb.process(&p_f1_gap, false, 101, |_| {});
    assert_eq!(o_f1, ReorderOutcome::Buffered);

    // Touch flow 0 (port 1000) with in-order packet at timestamp 500
    let p_f0 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, 1050, &[0x11; 50]);
    let o_f0 = rb.process(&p_f0, false, 500, |_| {});
    assert_eq!(o_f0, ReorderOutcome::InOrder);

    // Flow 1 (port 1001, timestamp 101) is now the strictly oldest flow in the table
    // Add flow 65 (port 9999) at timestamp 600 -> must evict Flow 1 and flush its buffered slot
    let mut emitted = Vec::new();
    let p_new = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 9999, 80, 2000, &[0x22; 50]);
    let o_new = rb.process(&p_new, false, 600, |p| emitted.push(p.to_vec()));
    assert_eq!(o_new, ReorderOutcome::InOrder);
    assert_eq!(
        emitted.len(),
        2,
        "eviction of Flow 1 must flush its buffered packet and emit p_new"
    );
    assert_eq!(emitted[0], p_f1_gap);
    assert_eq!(emitted[1], p_new);

    // Flow 0 was touched at 500 and must NOT have been evicted.
    // If Flow 0 is retained, sending an out-of-order packet (gap) must return Buffered!
    let p_f0_gap = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 80, 1300, &[0x33; 50]);
    let o_f0_gap = rb.process(&p_f0_gap, false, 700, |_| {});
    assert_eq!(
        o_f0_gap,
        ReorderOutcome::Buffered,
        "retained Flow 0 must buffer out-of-order packet"
    );

    // Flow 1 was evicted, so a new packet on Flow 1 is uninitialized and must return InOrder!
    let p_f1_reinit =
        make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1001, 80, 3000, &[0x44; 50]);
    let o_f1_reinit = rb.process(&p_f1_reinit, false, 701, |_| {});
    assert_eq!(
        o_f1_reinit,
        ReorderOutcome::InOrder,
        "evicted Flow 1 is reinitialized"
    );
}

#[test]
fn test_rst_flow_isolation() {
    let mut rb = ReorderBuffer::new(10);
    // Establish Flow A (port 5001) at index 0 and Flow B (port 5002) at index 1
    let p_a1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 80, 1000, &[0x11; 100]);
    let p_b1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5002, 80, 2000, &[0x22; 100]);
    rb.process(&p_a1, false, 100, |_| {});
    rb.process(&p_b1, false, 100, |_| {});

    // Send RST specifically for Flow B (at index 1)
    let mut rst_b = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5002, 80, 2100, &[]);
    rst_b[33] = 0x04; // RST
    let o_rst = rb.process(&rst_b, false, 101, |_| {});
    assert_eq!(o_rst, ReorderOutcome::Bypassed);

    // Flow A (index 0) must NOT be reset: sending a packet with a gap (seq 1300 > expected 1100) must return Buffered
    let p_a_gap = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 80, 1300, &[0xAA; 50]);
    let o_a_gap = rb.process(&p_a_gap, false, 102, |_| {});
    assert_eq!(
        o_a_gap,
        ReorderOutcome::Buffered,
        "Flow A was not reset and must buffer gap"
    );

    // Flow B (index 1) WAS reset: sending a packet with a gap is treated as uninitialized and returns InOrder
    let p_b_reinit =
        make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5002, 80, 5000, &[0xBB; 50]);
    let o_b_reinit = rb.process(&p_b_reinit, false, 103, |_| {});
    assert_eq!(
        o_b_reinit,
        ReorderOutcome::InOrder,
        "Flow B was reset and must be reinitialized"
    );
}

#[test]
fn test_partial_drain_and_deadline_retention() {
    let mut rb = ReorderBuffer::new(5); // 5ms deadline
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 100]);
    let p2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1100, &[0x22; 100]);
    let p3 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1200, &[0x33; 100]);
    let p5 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1400, &[0x55; 100]);

    rb.process(&p1, false, 100, |_| {});
    // Buffer p3 (hole at 1100) and p5 (hole at 1300)
    rb.process(&p3, false, 100, |_| {});
    rb.process(&p5, false, 100, |_| {});

    // Now deliver p2 -> fills hole for p3, so p2 and p3 emit!
    // But p5 remains buffered awaiting 1300!
    let mut emitted = Vec::new();
    let o2 = rb.process(&p2, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(o2, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 2);
    assert_eq!(emitted[0], p2);
    assert_eq!(emitted[1], p3);

    // At 104 ms (100 + 5 = 105), deadline not yet expired
    emitted.clear();
    let flushed1 = rb.poll_timeouts(104, |p| emitted.push(p.to_vec()));
    assert_eq!(flushed1, 0);
    assert!(emitted.is_empty());

    // At 105 ms, deadline expires for p5: must flush p5
    let flushed2 = rb.poll_timeouts(105, |p| emitted.push(p.to_vec()));
    assert_eq!(flushed2, 1);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p5);
}

#[test]
fn test_tcp_fin_advance_and_reorder() {
    let mut rb = ReorderBuffer::new(5);
    // Data packet with FIN flag (flags = ACK + FIN = 0x11)
    let mut p_fin = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 50]);
    p_fin[33] = 0x11; // FIN + ACK

    let mut emitted = Vec::new();
    let o = rb.process(&p_fin, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(o, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);

    // Expected sequence must advance by 50 (payload) + 1 (FIN) = 51 -> expected = 1051
    emitted.clear();
    let p_next = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1051, &[0x22; 40]);
    let o_next = rb.process(&p_next, false, 101, |p| emitted.push(p.to_vec()));
    assert_eq!(o_next, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p_next);

    // Pure FIN packet (0 payload + FIN)
    let mut p_pure_fin = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1091, &[]);
    p_pure_fin[33] = 0x11; // FIN + ACK
    emitted.clear();
    let o_pure_fin = rb.process(&p_pure_fin, false, 102, |p| emitted.push(p.to_vec()));
    assert_eq!(o_pure_fin, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);

    // Expected sequence must advance by 0 + 1 = 1 -> expected = 1092
    emitted.clear();
    let p_after_pure_fin =
        make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1092, &[0x33; 20]);
    let o_after = rb.process(&p_after_pure_fin, false, 103, |p| emitted.push(p.to_vec()));
    assert_eq!(o_after, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);
}

#[test]
fn test_malformed_and_boundary_packets() {
    let mut rb = ReorderBuffer::new(5);

    // L2 packet shorter than 14 bytes
    let short_l2 = vec![0u8; 13];
    assert_eq!(
        rb.process(&short_l2, true, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // L2 packet exactly 14 bytes with invalid ethertype
    let l2_14 = vec![0u8; 14];
    assert_eq!(
        rb.process(&l2_14, true, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv4 packet shorter than 20 bytes
    let short_v4 = vec![0x45; 19];
    assert_eq!(
        rb.process(&short_v4, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv4 with ihl < 20 (e.g. 16: byte 0 = 0x44)
    let mut bad_ihl = vec![0u8; 40];
    bad_ihl[0] = 0x44; // IHL = 4 (16 bytes < 20)
    assert_eq!(
        rb.process(&bad_ihl, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv4 with ihl = 24 (byte 0 = 0x46), but buffer len is 20 (< ihl)
    let mut bad_ihl_len = vec![0u8; 20];
    bad_ihl_len[0] = 0x46;
    assert_eq!(
        rb.process(&bad_ihl_len, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv4 total_len < ihl
    let mut bad_tot_len = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[]);
    bad_tot_len[2..4].copy_from_slice(&10u16.to_be_bytes()); // total_len 10 < ihl 20
    assert_eq!(
        rb.process(&bad_tot_len, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv4 total_len > ip.len()
    let mut bad_tot_len2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[]);
    bad_tot_len2[2..4].copy_from_slice(&200u16.to_be_bytes()); // total_len 200 > actual 40
    assert_eq!(
        rb.process(&bad_tot_len2, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv4 with total_len == 0 (GSO style): must succeed and process in-order
    let mut gso_v4 =
        make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 3456, 80, 5000, &[0x42; 50]);
    gso_v4[2..4].copy_from_slice(&0u16.to_be_bytes());
    let mut emitted = Vec::new();
    let o_gso = rb.process(&gso_v4, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(o_gso, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);

    // IPv6 packet shorter than 40 bytes
    let short_v6 = vec![0x60; 39];
    assert_eq!(
        rb.process(&short_v6, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv6 truncated (payload_len_field > 0 but ip.len() < 40 + payload_len)
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut trunc_v6 = make_ipv6_tcp_packet(src, dst, 8080, 80, 1000, &[0x11; 40]);
    trunc_v6[4..6].copy_from_slice(&500u16.to_be_bytes()); // payload len 500 > actual
    assert_eq!(
        rb.process(&trunc_v6, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // IPv6 with payload_len_field == 0 (GSO style): must succeed and process in-order
    let mut gso_v6 = make_ipv6_tcp_packet(src, dst, 8081, 80, 8000, &[0x11; 50]);
    gso_v6[4..6].copy_from_slice(&0u16.to_be_bytes());
    emitted.clear();
    let o_gso_v6 = rb.process(&gso_v6, false, 100, |p| emitted.push(p.to_vec()));
    assert_eq!(o_gso_v6, ReorderOutcome::InOrder);
    assert_eq!(emitted.len(), 1);

    // TCP header shorter than 20 bytes (e.g. total_len = 39, IHL=20 -> TCP len = 19)
    let mut short_tcp = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[]);
    short_tcp.truncate(39);
    short_tcp[2..4].copy_from_slice(&39u16.to_be_bytes());
    assert_eq!(
        rb.process(&short_tcp, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // TCP with data_offset < 20 (e.g. data offset = 16: tcp[12] = 0x40)
    let mut bad_data_off =
        make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 20]);
    bad_data_off[32] = 0x40; // offset 16 < 20
    assert_eq!(
        rb.process(&bad_data_off, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );

    // TCP with tcp.len() < data_offset (e.g. data offset = 32: tcp[12] = 0x80, but packet is 40 bytes)
    let mut bad_data_off2 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[]);
    bad_data_off2[32] = 0x80; // offset 32 > 20
    assert_eq!(
        rb.process(&bad_data_off2, false, 100, |_| {}),
        ReorderOutcome::Bypassed
    );
}

#[test]
fn test_reorder_slot_and_flow_state_defaults() {
    let slot = ReorderSlot::default();
    assert!(!slot.valid);
    assert_eq!(slot.seq, 0);
    assert_eq!(slot.len, 0);

    let mut flow = FlowReorderState::default();
    assert!(!flow.initialized);
    assert_eq!(flow.slot_count, 0);
    assert_eq!(flow.expected_seq, 0);
    assert_eq!(flow.deadline_ms, 0);
    assert_eq!(flow.last_seen_ms, 0);

    flow.initialized = true;
    flow.slot_count = 5;
    flow.deadline_ms = 100;
    flow.reset();
    assert!(!flow.initialized);
    assert_eq!(flow.slot_count, 0);
    assert_eq!(flow.deadline_ms, 0);

    let mut rb = ReorderBuffer::default();
    assert_eq!(rb.process(&[], false, 0, |_| {}), ReorderOutcome::Bypassed);
    assert_eq!(rb.poll_timeouts(100, |_| {}), 0);
}

#[test]
fn test_oversized_packet_bypasses_buffering() {
    let mut rb = ReorderBuffer::new(5);
    // Initialize flow
    let p1 = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, &[0x11; 50]);
    rb.process(&p1, false, 100, |_| {});

    // Create packet larger than MAX_SLOT_PACKET_LEN
    let oversized_payload = vec![0x99; MAX_SLOT_PACKET_LEN + 10];
    let p_over = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        2000,
        &oversized_payload,
    );
    let mut emitted = Vec::new();
    let o = rb.process(&p_over, false, 101, |p| emitted.push(p.to_vec()));
    // Cannot be buffered because of size constraint, so emits immediately / flushes
    assert_eq!(o, ReorderOutcome::Bypassed);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], p_over);
}
