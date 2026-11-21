use std::net::UdpSocket;
use yip_io::batch::{send_gso_superpacket, set_udp_gso_segment, BatchUdpSocket, BATCH_SIZE};

#[test]
fn test_set_udp_gso_segment_probe() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
    // Probe GSO segment setting - should succeed or cleanly report unsupported without error
    let res = set_udp_gso_segment(&sock, 1280);
    assert!(res.is_ok(), "GSO probe should succeed or return Ok(false)");
}

#[test]
fn test_send_gso_superpacket_or_unsupported() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let payload = vec![0x42u8; 1280 * 2]; // 2 segments

    match send_gso_superpacket(&s1, &payload, 1280, addr2) {
        Ok(sent) => {
            // Kernel accepted GSO send or transient full buffer
            assert!(sent == 0 || sent == payload.len());
        }
        Err(e) => {
            // Kernel lacks UDP_SEGMENT or unsupported on this device loopback
            let raw = e.raw_os_error().unwrap_or(0);
            assert!(
                raw == libc::EINVAL || raw == libc::EOPNOTSUPP || raw == libc::EIO,
                "unexpected GSO error: {e}"
            );
        }
    }
}

#[test]
fn test_gso_super_packet_slicing() {
    let payload = vec![0x42u8; 64000];
    let mss = 1420;
    let segments = yip_io::tun_offload::slice_gso_payload(&payload, mss);
    assert_eq!(segments.len(), 46);
    assert_eq!(segments[0].len(), 1420);
    assert_eq!(segments.last().unwrap().len(), 64000 - 45 * 1420);
}

#[test]
fn test_batch_udp_socket_gso_probe_and_config() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
    let mut batch = BatchUdpSocket::new(&sock);

    // Initial probe
    let probed = batch.probe_gso();
    assert_eq!(probed, batch.is_gso_enabled());

    // Configure segment size
    let configured = batch
        .set_socket_gso_segment(1420)
        .expect("configure GSO segment");
    if configured {
        assert!(batch.is_gso_enabled());
        assert_eq!(batch.gso_segment_size(), Some(1420));

        // Reset segment size
        let reset = batch.set_socket_gso_segment(0).expect("reset GSO segment");
        assert!(reset);
        assert_eq!(batch.gso_segment_size(), None);
    }
}

#[test]
fn test_batch_udp_socket_send_gso_batch_roundtrip() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    let payloads: Vec<Vec<u8>> = (0..8)
        .map(|i| format!("gso-segment-packet-index-{i:04}").into_bytes())
        .collect();
    let pkts: Vec<(&[u8], std::net::SocketAddr)> =
        payloads.iter().map(|p| (p.as_slice(), addr2)).collect();

    let sent = b1.send_gso_batch(&pkts).expect("send_gso_batch");
    assert_eq!(sent, 8);

    std::thread::sleep(std::time::Duration::from_millis(25));

    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];

    let recvd = b2
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("recvmmsg_batch");
    assert_eq!(recvd, 8);
    for i in 0..8 {
        assert_eq!(out[i].len, payloads[i].len());
        assert_eq!(&buffers[i][..out[i].len], payloads[i].as_slice());
    }
}

#[test]
fn test_batch_udp_socket_send_gso_datagrams_roundtrip_and_fate_safety() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    // 4 datagrams with pairwise-distinct fate + 2 with duplicate fate
    let fates = [1u16, 2, 3, 4, 5, 5];
    let dgs: Vec<yip_io::poll::EgressDatagram> = fates
        .iter()
        .enumerate()
        .map(|(i, &f)| yip_io::poll::EgressDatagram {
            fate: f,
            dst: addr2,
            bytes: format!("egress-dg-idx-{i:03}-fate-{f}").into_bytes(),
        })
        .collect();

    let sent = b1.send_gso_datagrams(&dgs).expect("send_gso_datagrams");
    assert_eq!(sent, 6);

    std::thread::sleep(std::time::Duration::from_millis(25));

    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];

    let recvd = b2
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("recvmmsg_batch");
    assert_eq!(recvd, 6);
    for i in 0..6 {
        assert_eq!(out[i].len, dgs[i].bytes.len());
        assert_eq!(&buffers[i][..out[i].len], dgs[i].bytes.as_slice());
    }
}

#[test]
fn test_batch_udp_socket_gso_fallback_when_disabled() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    // Explicitly disable GSO to verify fallback path to sendmmsg
    b1.set_gso_enabled(false);
    assert!(!b1.is_gso_enabled());

    let payload = b"fallback-sendmmsg-datagram";
    let pkts: Vec<(&[u8], std::net::SocketAddr)> = (0..6).map(|_| (&payload[..], addr2)).collect();

    let sent = b1.send_gso_batch(&pkts).expect("send_gso_batch fallback");
    assert_eq!(sent, 6);

    std::thread::sleep(std::time::Duration::from_millis(25));

    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];

    let recvd = b2
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("recvmmsg_batch");
    assert_eq!(recvd, 6);
    for i in 0..6 {
        assert_eq!(&buffers[i][..out[i].len], payload);
    }
}

#[test]
fn test_batch_udp_socket_mixed_runs_and_singletons() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    let s3 = UdpSocket::bind("127.0.0.1:0").expect("bind s3");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();
    s3.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let addr3 = s3.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);
    let mut b3 = BatchUdpSocket::new(&s3);

    // 4 to addr2, 1 to addr3, 3 to addr2
    let mut pkts: Vec<(&[u8], std::net::SocketAddr)> = Vec::new();
    let p_a2 = b"packet-for-addr2";
    let p_a3 = b"packet-for-addr3-singleton";

    for _ in 0..4 {
        pkts.push((p_a2, addr2));
    }
    pkts.push((p_a3, addr3));
    for _ in 0..3 {
        pkts.push((p_a2, addr2));
    }

    let sent = b1.sendmmsg_or_gso(&pkts).expect("sendmmsg_or_gso mixed");
    assert_eq!(sent, 8);

    std::thread::sleep(std::time::Duration::from_millis(25));

    // Receiver 2 should receive 7 packets
    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];
    let recvd2 = b2
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("recvmmsg_batch s2");
    assert_eq!(recvd2, 7);

    // Receiver 3 should receive 1 packet
    let recvd3 = b3
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("recvmmsg_batch s3");
    assert_eq!(recvd3, 1);
    assert_eq!(&buffers[0][..out[0].len], p_a3);
}
