#![cfg(not(miri))]

use std::alloc::System;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;

use yip_io::poll::{drain_tun, EgressDatagram, GsoScratch};
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
