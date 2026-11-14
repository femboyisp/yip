#![cfg(not(miri))]

use std::alloc::System;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;

use yip_io::poll::{drain_tun, recv_mmsg, send_mmsg, EgressDatagram, GsoScratch, MmsgBatchArena};
use yip_io::tun_offload::{write_vnet_hdr, VirtioNetHdr, GSO_TCPV6, VNET_HDR_LEN};
use yip_io::{MAX_DATAGRAM_BATCH, MAX_WIRE_DATAGRAM};
use yip_verify::{assert_no_alloc, TrackingAllocator};
use yipd::dataplane::test_dataplane_pair;
use yipd::mode::TunnelMode;

#[global_allocator]
static GLOBAL: TrackingAllocator<System> = TrackingAllocator(System);

fn dummy_ipv4_packet(payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + payload_len];
    pkt[0] = 0x45; // IPv4, header len 5 (20 bytes)
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    for (i, b) in pkt[20..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    pkt
}

fn dummy_ipv6_tcp_packet(payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![0u8; 40 + 20 + payload_len];
    pkt[0] = 0x60; // IPv6, tc=0, flow=0
    let total_payload = (20 + payload_len) as u16;
    pkt[4..6].copy_from_slice(&total_payload.to_be_bytes());
    pkt[6] = 6; // Next header = TCP
    pkt[7] = 64; // Hop limit
    pkt[8..24].copy_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pkt[24..40].copy_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // TCP header at byte 40
    pkt[40..42].copy_from_slice(&12345u16.to_be_bytes()); // sport
    pkt[42..44].copy_from_slice(&80u16.to_be_bytes()); // dport
    pkt[44..48].copy_from_slice(&1000u32.to_be_bytes()); // seq
    pkt[52] = 0x50; // data offset 5 words = 20 bytes
    pkt[53] = 0x10; // ACK flag
    pkt[54..56].copy_from_slice(&65535u16.to_be_bytes()); // window size
    for (i, b) in pkt[60..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    pkt
}

#[test]
fn test_dataplane_on_tun_into_steady_state_zero_alloc() {
    let (mut dp, _) = test_dataplane_pair(TunnelMode::L3Tun, false);
    let pkt = dummy_ipv4_packet(120);
    let mut batch: Vec<EgressDatagram> = Vec::with_capacity(MAX_DATAGRAM_BATCH);

    // Warm-up phase: allocate internal pools and scratch buffers
    for i in 0..10 {
        dp.on_tun_into(&pkt, 100 + i, &mut batch);
        assert!(!batch.is_empty(), "warm-up batch must produce datagrams");
        dp.recycle(&mut batch);
        assert!(batch.is_empty(), "recycle must drain batch");
    }

    // Steady-state phase: assert strictly zero heap allocations
    for i in 0..100 {
        assert_no_alloc!({
            dp.on_tun_into(&pkt, 1000 + i, &mut batch);
            assert!(!batch.is_empty());
            dp.recycle(&mut batch);
        });
    }
}

#[test]
fn test_drain_tun_steady_state_zero_alloc() {
    let (mut dp, _) = test_dataplane_pair(TunnelMode::L3Tun, false);
    let pkt = dummy_ipv4_packet(150);

    let (tun_tx, tun_rx) = UnixDatagram::pair().expect("create unix datagram pair for TUN mock");
    tun_rx
        .set_nonblocking(true)
        .expect("set non-blocking tun_rx");

    let udp_peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer socket");
    let udp_peer_addr = udp_peer.local_addr().expect("local addr");
    dp.set_peer_addr(udp_peer_addr);

    let udp_sock = UdpSocket::bind("127.0.0.1:0").expect("bind driver udp socket");
    udp_sock
        .set_nonblocking(true)
        .expect("set non-blocking udp");

    let mut tx_batch: Vec<EgressDatagram> = Vec::with_capacity(MAX_DATAGRAM_BATCH);
    let mut gso = GsoScratch::new();
    let mut read_buf = vec![0u8; MAX_WIRE_DATAGRAM];
    let mut split_out: Vec<u8> = Vec::with_capacity(MAX_WIRE_DATAGRAM);
    let mut split_offs: Vec<(usize, usize)> = Vec::with_capacity(16);

    // Warm-up phase: run through drain_tun and flush_tx
    for i in 0..10 {
        tun_tx.send(&pkt).expect("send packet to mock tun");
        drain_tun(
            tun_rx.as_raw_fd(),
            udp_sock.as_raw_fd(),
            &mut dp,
            100 + i,
            &mut tx_batch,
            &mut gso,
            false,
            &mut read_buf,
            &mut split_out,
            &mut split_offs,
        )
        .expect("drain_tun warm-up");
    }

    // Steady-state phase: assert strictly zero heap allocations during drain_tun
    for i in 0..50 {
        tun_tx.send(&pkt).expect("send packet to mock tun");
        assert_no_alloc!({
            drain_tun(
                tun_rx.as_raw_fd(),
                udp_sock.as_raw_fd(),
                &mut dp,
                2000 + i,
                &mut tx_batch,
                &mut gso,
                false,
                &mut read_buf,
                &mut split_out,
                &mut split_offs,
            )
            .expect("drain_tun steady-state");
        });
    }
}

#[test]
fn test_drain_tun_vnet_hdr_ipv6_gso_steady_state_zero_alloc() {
    let (mut dp, _) = test_dataplane_pair(TunnelMode::L3Tun, false);
    let pkt = dummy_ipv6_tcp_packet(2500); // 2500 bytes payload > MTU
    let mut framed_pkt = vec![0u8; VNET_HDR_LEN + pkt.len()];
    let hdr = VirtioNetHdr {
        flags: 0,
        gso_type: GSO_TCPV6,
        hdr_len: 60,
        gso_size: 1000,
        csum_start: 40,
        csum_offset: 16,
    };
    write_vnet_hdr(&hdr, &mut framed_pkt[..VNET_HDR_LEN]);
    framed_pkt[VNET_HDR_LEN..].copy_from_slice(&pkt);

    let (tun_tx, tun_rx) = UnixDatagram::pair().expect("create unix datagram pair for TUN mock");
    tun_rx
        .set_nonblocking(true)
        .expect("set non-blocking tun_rx");

    let udp_peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer socket");
    let udp_peer_addr = udp_peer.local_addr().expect("local addr");
    dp.set_peer_addr(udp_peer_addr);

    let udp_sock = UdpSocket::bind("127.0.0.1:0").expect("bind driver udp socket");
    udp_sock
        .set_nonblocking(true)
        .expect("set non-blocking udp");

    let mut tx_batch: Vec<EgressDatagram> = Vec::with_capacity(MAX_DATAGRAM_BATCH);
    let mut gso = GsoScratch::new();
    let mut read_buf = vec![0u8; VNET_HDR_LEN + 65535];
    let mut split_out: Vec<u8> = Vec::with_capacity(65535);
    let mut split_offs: Vec<(usize, usize)> = Vec::with_capacity(64);

    // Warm-up phase
    for i in 0..10 {
        tun_tx.send(&framed_pkt).expect("send packet to mock tun");
        drain_tun(
            tun_rx.as_raw_fd(),
            udp_sock.as_raw_fd(),
            &mut dp,
            100 + i,
            &mut tx_batch,
            &mut gso,
            true,
            &mut read_buf,
            &mut split_out,
            &mut split_offs,
        )
        .expect("drain_tun vnet warm-up");
    }

    // Steady-state phase: assert strictly zero heap allocations during GSO splitting
    for i in 0..50 {
        tun_tx.send(&framed_pkt).expect("send packet to mock tun");
        assert_no_alloc!({
            drain_tun(
                tun_rx.as_raw_fd(),
                udp_sock.as_raw_fd(),
                &mut dp,
                2000 + i,
                &mut tx_batch,
                &mut gso,
                true,
                &mut read_buf,
                &mut split_out,
                &mut split_offs,
            )
            .expect("drain_tun vnet steady-state");
        });
    }
}

#[test]
fn test_mmsg_batch_arena_steady_state_zero_alloc() {
    let mut arena = MmsgBatchArena::new_boxed();
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind tx socket");
    let rx = UdpSocket::bind("127.0.0.1:0").expect("bind rx socket");
    rx.set_nonblocking(true).expect("set non-blocking rx");
    let rx_addr = rx.local_addr().expect("local addr");

    let batch = vec![
        EgressDatagram {
            fate: 0,
            dst: rx_addr,
            bytes: vec![1, 2, 3, 4, 5],
        },
        EgressDatagram {
            fate: 1,
            dst: rx_addr,
            bytes: vec![6, 7, 8, 9, 10],
        },
    ];

    let mut bufs = Box::new([[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]);
    let mut lens = [0usize; MAX_DATAGRAM_BATCH];
    let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAM_BATCH];

    // Warm-up phase
    for _ in 0..5 {
        send_mmsg(tx.as_raw_fd(), &batch, &mut arena).expect("send_mmsg warm-up");
        let _ = recv_mmsg(
            rx.as_raw_fd(),
            &mut bufs[..],
            &mut lens,
            &mut srcs,
            &mut arena,
        );
    }

    // Steady-state phase: assert zero heap allocations across send_mmsg and recv_mmsg
    for _ in 0..50 {
        assert_no_alloc!({
            let sent = send_mmsg(tx.as_raw_fd(), &batch, &mut arena).expect("send_mmsg");
            assert_eq!(sent, 2);
        });

        assert_no_alloc!({
            let recvd = recv_mmsg(
                rx.as_raw_fd(),
                &mut bufs[..],
                &mut lens,
                &mut srcs,
                &mut arena,
            )
            .expect("recv_mmsg");
            assert_eq!(recvd, 2);
        });
    }
}
