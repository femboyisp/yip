use yip_io::ack_coalesce::{has_sack_option, seq_after, seq_before, AckCompressor};

#[expect(clippy::too_many_arguments)]
fn make_ipv4_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    window: u16,
    flags: u8,
    payload: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let tcp_hdr_len = 20 + options.len();
    assert_eq!(tcp_hdr_len % 4, 0);
    let total_len = 20 + tcp_hdr_len + payload.len();

    let mut buf = vec![0u8; total_len];
    // IPv4 header
    buf[0] = 0x45;
    buf[1] = 0x00;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF set
    buf[8] = 64; // TTL
    buf[9] = 6; // TCP
    buf[12..16].copy_from_slice(&src_ip);
    buf[16..20].copy_from_slice(&dst_ip);

    // TCP header
    let tcp = &mut buf[20..20 + tcp_hdr_len];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((tcp_hdr_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    if !options.is_empty() {
        tcp[20..20 + options.len()].copy_from_slice(options);
    }

    if !payload.is_empty() {
        buf[20 + tcp_hdr_len..].copy_from_slice(payload);
    }

    buf
}

#[expect(clippy::too_many_arguments)]
fn make_ipv6_tcp_packet(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    window: u16,
    flags: u8,
    payload: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let tcp_hdr_len = 20 + options.len();
    assert_eq!(tcp_hdr_len % 4, 0);
    let payload_len = tcp_hdr_len + payload.len();
    let total_len = 40 + payload_len;

    let mut buf = vec![0u8; total_len];
    // IPv6 header
    buf[0] = 0x60;
    buf[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    buf[6] = 6; // TCP
    buf[7] = 64; // Hop limit
    buf[8..24].copy_from_slice(&src_ip);
    buf[24..40].copy_from_slice(&dst_ip);

    // TCP header
    let tcp = &mut buf[40..40 + tcp_hdr_len];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((tcp_hdr_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    if !options.is_empty() {
        tcp[20..20 + options.len()].copy_from_slice(options);
    }

    if !payload.is_empty() {
        buf[40 + tcp_hdr_len..].copy_from_slice(payload);
    }

    buf
}

#[test]
fn test_seq_arithmetic() {
    assert!(seq_after(100, 50));
    assert!(seq_before(50, 100));
    assert!(!seq_after(100, 100));
    assert!(!seq_before(100, 100));

    // RFC 793 wrapping around 2^32 boundary
    let near_max = u32::MAX - 10;
    let wrapped = 15;
    assert!(seq_after(wrapped, near_max));
    assert!(seq_before(near_max, wrapped));
}

#[test]
fn test_has_sack_option() {
    // Kind 1 = NOP, Kind 5 = SACK
    assert!(!has_sack_option(&[]));
    assert!(!has_sack_option(&[1, 1, 1, 1])); // 4 NOPs
    assert!(!has_sack_option(&[2, 4, 0x05, 0xb4])); // MSS option (Kind 2, Len 4)

    // SACK option: Kind 5, length 10 (1 block of 8 bytes)
    let sack_opt = [1, 1, 5, 10, 0, 0, 0, 10, 0, 0, 0, 20];
    assert!(has_sack_option(&sack_opt));
}

#[test]
fn test_ack_compressor_compresses_pure_cumulative_acks() {
    let mut compressor = AckCompressor::new();
    let mut emitted: Vec<Vec<u8>> = Vec::new();

    let p1 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        1000,
        65535,
        0x10, // ACK
        &[],
        &[],
    );
    let p2 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        2000,
        65535,
        0x10, // ACK
        &[],
        &[],
    );
    let p3 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        3000,
        65535,
        0x10, // ACK
        &[],
        &[],
    );

    compressor.push(&p1, |p| emitted.push(p.to_vec()));
    compressor.push(&p2, |p| emitted.push(p.to_vec()));
    compressor.push(&p3, |p| emitted.push(p.to_vec()));

    // Nothing emitted yet: all compressed into the highest cumulative ACK
    assert_eq!(emitted.len(), 0);
    assert_eq!(compressor.len(), 1);

    compressor.flush(|p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 1);
    assert_eq!(compressor.len(), 0);

    // Verify the single emitted packet has ack = 3000
    let emitted_tcp = &emitted[0][20..40];
    let ack_num = u32::from_be_bytes([
        emitted_tcp[8],
        emitted_tcp[9],
        emitted_tcp[10],
        emitted_tcp[11],
    ]);
    assert_eq!(ack_num, 3000);
}

#[test]
fn test_ack_compressor_strictly_preserves_duplicate_acks() {
    let mut compressor = AckCompressor::new();
    let mut emitted: Vec<Vec<u8>> = Vec::new();

    let p1 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        1000,
        65535,
        0x10,
        &[],
        &[],
    );
    // 3 duplicate ACKs with identical ack_num = 1000
    let dup1 = p1.clone();
    let dup2 = p1.clone();
    let dup3 = p1.clone();

    compressor.push(&p1, |p| emitted.push(p.to_vec()));
    // First ACK buffered: 0 emitted
    assert_eq!(emitted.len(), 0);

    compressor.push(&dup1, |p| emitted.push(p.to_vec()));
    // DupACK: previous ACK flushed immediately, dup1 buffered: 1 emitted
    assert_eq!(emitted.len(), 1);

    compressor.push(&dup2, |p| emitted.push(p.to_vec()));
    // DupACK: dup1 flushed immediately, dup2 buffered: 2 emitted
    assert_eq!(emitted.len(), 2);

    compressor.push(&dup3, |p| emitted.push(p.to_vec()));
    // DupACK: dup2 flushed immediately, dup3 buffered: 3 emitted
    assert_eq!(emitted.len(), 3);

    compressor.flush(|p| emitted.push(p.to_vec()));
    // Final flush emits dup3: total 4 packets emitted (all 3 DupACKs strictly preserved)
    assert_eq!(emitted.len(), 4);
    for pkt in &emitted {
        let ack_num = u32::from_be_bytes([pkt[28], pkt[29], pkt[30], pkt[31]]);
        assert_eq!(ack_num, 1000);
    }
}

#[test]
fn test_ack_compressor_never_compresses_sack_or_window_updates() {
    let mut compressor = AckCompressor::new();
    let mut emitted: Vec<Vec<u8>> = Vec::new();

    let p1 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        1000,
        65535,
        0x10,
        &[],
        &[],
    );
    compressor.push(&p1, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 0);

    // SACK option packet (Kind 5)
    let sack_opt = [1, 1, 5, 10, 0, 0, 0, 10, 0, 0, 0, 20];
    let sack_pkt = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        2000,
        65535,
        0x10,
        &[],
        &sack_opt,
    );
    // SACK packet must flush p1 and emit sack_pkt immediately
    compressor.push(&sack_pkt, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 2);
    assert_eq!(compressor.len(), 0);

    // Window update packet (ack_num advances, but window changes)
    let p3 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        3000,
        65535,
        0x10,
        &[],
        &[],
    );
    let win_update = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        4000,
        32768, // Window shrunk
        0x10,
        &[],
        &[],
    );
    compressor.push(&p3, |p| emitted.push(p.to_vec()));
    assert_eq!(compressor.len(), 1);

    compressor.push(&win_update, |p| emitted.push(p.to_vec()));
    // Window change flushes p3 and buffers win_update
    assert_eq!(emitted.len(), 3);

    compressor.flush(|p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 4);
}

#[test]
fn test_ack_compressor_data_packets_flush_matching_flow() {
    let mut compressor = AckCompressor::new();
    let mut emitted: Vec<Vec<u8>> = Vec::new();

    let p1 = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        1000,
        65535,
        0x10,
        &[],
        &[],
    );
    compressor.push(&p1, |p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 0);

    let data_pkt = make_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1,
        1000,
        65535,
        0x18, // PSH | ACK
        b"hello",
        &[],
    );

    compressor.push(&data_pkt, |p| emitted.push(p.to_vec()));
    // Data packet flushes p1 and then emits data_pkt
    assert_eq!(emitted.len(), 2);
    assert_eq!(compressor.len(), 0);
}

#[test]
fn test_ack_compressor_ipv6_flow_coalescing() {
    let mut compressor = AckCompressor::new();
    let mut emitted: Vec<Vec<u8>> = Vec::new();

    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    let p1 = make_ipv6_tcp_packet(src, dst, 54321, 443, 10, 5000, 64240, 0x10, &[], &[]);
    let p2 = make_ipv6_tcp_packet(src, dst, 54321, 443, 10, 6000, 64240, 0x10, &[], &[]);

    compressor.push(&p1, |p| emitted.push(p.to_vec()));
    compressor.push(&p2, |p| emitted.push(p.to_vec()));

    assert_eq!(emitted.len(), 0);
    assert_eq!(compressor.len(), 1);

    compressor.flush(|p| emitted.push(p.to_vec()));
    assert_eq!(emitted.len(), 1);
    let ack_num = u32::from_be_bytes([
        emitted[0][48],
        emitted[0][49],
        emitted[0][50],
        emitted[0][51],
    ]);
    assert_eq!(ack_num, 6000);
}
