use std::net::UdpSocket;
use yip_io::batch::{BatchUdpSocket, BATCH_SIZE};

#[test]
fn test_recvmmsg_and_sendmmsg_burst() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    let mut to_send = Vec::new();
    let payload = b"vectorized batch test packet";
    for _ in 0..16 {
        to_send.push((&payload[..], addr2));
    }

    let sent = b1.sendmmsg_batch(&to_send).expect("sendmmsg");
    assert_eq!(sent, 16);

    std::thread::sleep(std::time::Duration::from_millis(10));

    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];

    let recvd = b2.recvmmsg_batch(&mut buffers, &mut out).expect("recvmmsg");
    assert_eq!(recvd, 16);
    for i in 0..16 {
        assert_eq!(&buffers[i][..out[i].len], payload);
    }
}

#[test]
fn test_full_batch_size_burst() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr1 = s1.local_addr().unwrap();
    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    // Send exactly BATCH_SIZE packets with distinct payloads
    let mut payloads = Vec::with_capacity(BATCH_SIZE);
    let mut to_send = Vec::with_capacity(BATCH_SIZE);
    for i in 0..BATCH_SIZE {
        payloads.push(format!("payload-packet-index-{i}").into_bytes());
    }
    for p in &payloads {
        to_send.push((p.as_slice(), addr2));
    }

    let sent = b1.sendmmsg_batch(&to_send).expect("sendmmsg batch 32");
    assert_eq!(sent, BATCH_SIZE);

    std::thread::sleep(std::time::Duration::from_millis(15));

    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];

    let recvd = b2
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("recvmmsg batch 32");
    assert_eq!(recvd, BATCH_SIZE);

    for i in 0..BATCH_SIZE {
        assert_eq!(out[i].len, payloads[i].len());
        assert_eq!(&buffers[i][..out[i].len], payloads[i].as_slice());
        assert_eq!(out[i].src, addr1);
    }
}

#[test]
fn test_empty_and_overflow_batches() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    // Empty send
    let sent = b1.sendmmsg_batch(&[]).expect("empty sendmmsg");
    assert_eq!(sent, 0);

    // Empty recv on non-blocking socket
    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];
    let recvd = b2
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("empty recvmmsg");
    assert_eq!(recvd, 0);

    // Overflow send: 40 packets provided, sendmmsg_batch should send BATCH_SIZE (32)
    let payload = b"overflow test";
    let to_send: Vec<(&[u8], std::net::SocketAddr)> =
        (0..40).map(|_| (&payload[..], addr2)).collect();
    let sent = b1.sendmmsg_batch(&to_send).expect("overflow sendmmsg");
    assert_eq!(sent, BATCH_SIZE);
}

#[test]
fn test_ipv6_batch_roundtrip() {
    let Ok(s1) = UdpSocket::bind("[::1]:0") else {
        // Skip test if IPv6 loopback is not available
        return;
    };
    let Ok(s2) = UdpSocket::bind("[::1]:0") else {
        return;
    };
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr1 = s1.local_addr().unwrap();
    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    let payload = b"ipv6 batch test";
    let to_send: Vec<(&[u8], std::net::SocketAddr)> =
        (0..8).map(|_| (&payload[..], addr2)).collect();

    let sent = b1.sendmmsg_batch(&to_send).expect("sendmmsg ipv6");
    assert_eq!(sent, 8);

    std::thread::sleep(std::time::Duration::from_millis(10));

    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];

    let recvd = b2
        .recvmmsg_batch(&mut buffers, &mut out)
        .expect("recvmmsg ipv6");
    assert_eq!(recvd, 8);
    for i in 0..8 {
        assert_eq!(&buffers[i][..out[i].len], payload);
        assert_eq!(out[i].src, addr1);
    }
}

#[test]
fn test_udp_gso_segment_and_superpacket() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    let addr2 = s2.local_addr().unwrap();

    // Probe set_udp_gso_segment
    let _ = yip_io::batch::set_udp_gso_segment(&s1, 1420);

    // Test send_gso_superpacket
    let payload = vec![0x5a; 2840];
    let res = yip_io::batch::send_gso_superpacket(&s1, &payload, 1420, addr2);
    let _ = res;
}
