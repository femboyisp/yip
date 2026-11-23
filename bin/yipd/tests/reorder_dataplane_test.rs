#![forbid(unsafe_code)]

use std::alloc::System;
use std::net::SocketAddr;
use yip_crypto::{generate_keypair, Handshake};
use yip_io::poll::DispatchOut;
use yip_verify::{assert_no_alloc, TrackingAllocator};
use yipd::config::PeerConfig;
use yipd::dataplane::{conn_tag_from_keys, DataPlane, Outcome};
use yipd::handshake::Established;
use yipd::mode::TunnelMode;
use yipd::peer_manager::PeerManager;
use yipd::wire_glue::derive_wire_keys;

#[global_allocator]
static ALLOC: TrackingAllocator<System> = TrackingAllocator(System);

fn make_ipv4_tcp_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
    let total_len = (40 + payload.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    // IPv4 header (20 bytes)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0x4000u16.to_be_bytes());
    pkt.push(64);
    pkt.push(6); // Protocol: TCP
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);

    // TCP header (20 bytes)
    pkt.extend_from_slice(&1234u16.to_be_bytes());
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.push(0x50); // Data offset: 5 * 4 = 20 bytes
    pkt.push(0x10); // Flags: ACK
    pkt.extend_from_slice(&65535u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());

    pkt.extend_from_slice(payload);
    pkt
}

fn test_dataplane_pair() -> (DataPlane, DataPlane) {
    let resp_kp = generate_keypair();
    let init_kp = generate_keypair();

    let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
    let mut res = Handshake::responder(&resp_kp.private).unwrap();

    let m1 = ini.write_message(&[]).unwrap();
    let _ = res.read_message(&m1).unwrap();
    let m2 = res.write_message(&[]).unwrap();
    let _ = ini.read_message(&m2).unwrap();

    let cb_i = ini.channel_binding();
    let (auth_key, hp_key) = derive_wire_keys(&cb_i);
    let (ini_send_k, ini_recv_k) = ini.raw_split_keys();
    let (res_send_k, res_recv_k) = res.raw_split_keys();

    let est_i = Established {
        session: ini.into_session().unwrap(),
        auth_key,
        hp_key,
        raw_send_key: ini_send_k,
        raw_recv_key: ini_recv_k,
    };
    let est_r = Established {
        session: res.into_session().unwrap(),
        auth_key,
        hp_key,
        raw_send_key: res_send_k,
        raw_recv_key: res_recv_k,
    };

    let conn_tag = conn_tag_from_keys(&auth_key, &hp_key);
    let addr_a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:10002".parse().unwrap();

    (
        DataPlane::new(est_i, conn_tag, TunnelMode::L3Tun, addr_b, false, 1200),
        DataPlane::new(est_r, conn_tag, TunnelMode::L3Tun, addr_a, false, 1200),
    )
}

fn setup_peer_manager_pair() -> (PeerManager, PeerManager, SocketAddr, SocketAddr) {
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();

    let ep_a: SocketAddr = "127.0.0.1:21001".parse().unwrap();
    let ep_b: SocketAddr = "127.0.0.1:21002".parse().unwrap();

    let peer_b_cfg = PeerConfig {
        public_key: kp_b.public,
        endpoint: Some(ep_b),
        alias: None,
    };
    let peer_a_cfg = PeerConfig {
        public_key: kp_a.public,
        endpoint: Some(ep_a),
        alias: None,
    };

    let mut pm_a = PeerManager::new(
        kp_a.private,
        kp_a.public,
        &[peer_b_cfg],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    let mut pm_b = PeerManager::new(
        kp_b.private,
        kp_b.public,
        &[peer_a_cfg],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );

    // Initial dummy TUN packet initiates handshake from A to B
    let dummy_ip = vec![0x45u8; 40];
    let dgs_init = pm_a.on_tun(&dummy_ip, 0);
    let init_dg = dgs_init
        .last()
        .expect("handshake init emitted")
        .bytes
        .clone();

    // B processes HandshakeInit and emits HandshakeResp
    let out_b = pm_b.on_udp(ep_a, &init_dg, 0);
    let resp_dg = match out_b {
        DispatchOut::Udp(e) | DispatchOut::Both(_, e) => {
            assert_eq!(e.len(), 1, "expected exactly 1 response datagram");
            e[0].bytes.clone()
        }
        _ => panic!("expected UDP egress for handshake response"),
    };

    // A processes HandshakeResp -> both are now Established!
    let _ = pm_a.on_udp(ep_b, &resp_dg, 0);

    assert!(pm_a.is_peer_established(&kp_b.public));
    assert!(pm_b.is_peer_established(&kp_a.public));

    (pm_a, pm_b, ep_a, ep_b)
}

#[test]
fn test_dataplane_tcp_packet_reordering_and_timeout() {
    let (mut sender, mut receiver) = test_dataplane_pair();

    let pkt1 = make_ipv4_tcp_packet(1000, &[1u8; 100]);
    let pkt2 = make_ipv4_tcp_packet(1100, &[2u8; 100]);
    let pkt3 = make_ipv4_tcp_packet(1200, &[3u8; 100]);
    let pkt5 = make_ipv4_tcp_packet(1400, &[5u8; 100]);

    // Encode packets on sender DataPlane
    let egress1 = sender.on_tun_packet(&pkt1, 100)[0].bytes.clone();
    let egress2 = sender.on_tun_packet(&pkt2, 100)[0].bytes.clone();
    let egress3 = sender.on_tun_packet(&pkt3, 100)[0].bytes.clone();
    let egress5 = sender.on_tun_packet(&pkt5, 100)[0].bytes.clone();

    // 1. Deliver Packet 1 (in-order) -> TunWrite
    let out1 = receiver.on_udp_datagram(&egress1, 100);
    match out1 {
        Outcome::TunWrite(data) => assert_eq!(data, &pkt1[..]),
        other => panic!(
            "expected Outcome::TunWrite for packet 1, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    // 2. Deliver Packet 3 (gap, expected 1100 but got 1200) -> None
    let out3 = receiver.on_udp_datagram(&egress3, 100);
    match out3 {
        Outcome::None => {}
        other => panic!(
            "expected Outcome::None for packet 3 (gap), got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    // 3. Deliver Packet 2 (hole fill) -> TunWriteBatch([pkt2, pkt3])
    let out2 = receiver.on_udp_datagram(&egress2, 100);
    match out2 {
        Outcome::TunWriteBatch(batch) => {
            assert_eq!(batch.len(), 2);
            assert_eq!(&batch[0][..], &pkt2[..]);
            assert_eq!(&batch[1][..], &pkt3[..]);
        }
        other => panic!(
            "expected Outcome::TunWriteBatch for hole fill, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    // 4. Deliver Packet 5 (gap, expected 1300 but got 1400) -> None
    let out5 = receiver.on_udp_datagram(&egress5, 100);
    match out5 {
        Outcome::None => {}
        other => panic!(
            "expected Outcome::None for packet 5 (gap), got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    // Advance time past micro-deadline (100 + DEFAULT_REORDER_DEADLINE_MS = 125ms deadline; advance past deadline)
    let _ = receiver.tick(100 + yip_transport::reorder::DEFAULT_REORDER_DEADLINE_MS + 1);
    let mut drained = Vec::new();
    receiver.drain_tun(&mut drained);
    assert_eq!(drained.len(), 1);
    assert_eq!(&drained[0][..], &pkt5[..]);

    // Subsequent drain should be empty
    drained.clear();
    receiver.drain_tun(&mut drained);
    assert!(drained.is_empty());
}

#[test]
fn test_peermanager_tcp_packet_reordering_and_drain() {
    let (mut pm_a, mut pm_b, ep_a, _ep_b) = setup_peer_manager_pair();

    let pkt1 = make_ipv4_tcp_packet(2000, &[1u8; 120]);
    let pkt2 = make_ipv4_tcp_packet(2120, &[2u8; 120]);
    let pkt3 = make_ipv4_tcp_packet(2240, &[3u8; 120]);
    let pkt5 = make_ipv4_tcp_packet(2480, &[5u8; 120]);

    let mut egress_a = Vec::new();
    pm_a.on_tun_into(&pkt1, 100, &mut egress_a);
    let dg1 = egress_a.pop().unwrap().bytes;
    pm_a.on_tun_into(&pkt2, 100, &mut egress_a);
    let dg2 = egress_a.pop().unwrap().bytes;
    pm_a.on_tun_into(&pkt3, 100, &mut egress_a);
    let dg3 = egress_a.pop().unwrap().bytes;
    pm_a.on_tun_into(&pkt5, 100, &mut egress_a);
    let dg5 = egress_a.pop().unwrap().bytes;

    // 1. Deliver Packet 1 -> Tun
    let out1 = pm_b.on_udp(ep_a, &dg1, 100);
    match out1 {
        DispatchOut::Tun(inner) => assert_eq!(inner, &pkt1[..]),
        other => panic!(
            "expected DispatchOut::Tun for packet 1, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    // 2. Deliver Packet 3 (gap) -> None
    let out3 = pm_b.on_udp(ep_a, &dg3, 100);
    assert!(matches!(out3, DispatchOut::None));

    // 3. Deliver Packet 2 (hole fill) -> TunBatch([pkt2, pkt3])
    let out2 = pm_b.on_udp(ep_a, &dg2, 100);
    match out2 {
        DispatchOut::TunBatch(batch) => {
            assert_eq!(batch.len(), 2);
            assert_eq!(&batch[0][..], &pkt2[..]);
            assert_eq!(&batch[1][..], &pkt3[..]);
        }
        other => panic!(
            "expected DispatchOut::TunBatch for hole fill, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    // 4. Deliver Packet 5 (gap) -> None
    let out5 = pm_b.on_udp(ep_a, &dg5, 100);
    assert!(matches!(out5, DispatchOut::None));

    // Advance time past micro-deadline (100 + DEFAULT_REORDER_DEADLINE_MS = 125ms; advance past deadline)
    let _ = pm_b.tick(100 + yip_transport::reorder::DEFAULT_REORDER_DEADLINE_MS + 1);
    let mut drained = Vec::new();
    pm_b.drain_tun(&mut drained);
    assert_eq!(drained.len(), 1);
    assert_eq!(&drained[0][..], &pkt5[..]);

    // Subsequent drain should be empty
    drained.clear();
    pm_b.drain_tun(&mut drained);
    assert!(drained.is_empty());
}

#[test]
fn test_reorder_buffer_zero_allocation_hotpath() {
    let mut buffer = yip_transport::reorder::ReorderBuffer::default();
    let mut drained_slots: Vec<Vec<u8>> = (0..32).map(|_| Vec::with_capacity(2048)).collect();
    let mut drained_count: usize;

    // Warm-up initial flow tracking slot
    let warmup_pkt = make_ipv4_tcp_packet(100, &[0xAA; 60]);
    buffer.process(&warmup_pkt, false, 10, |_pkt| {});

    // In-order packets must perform zero allocations
    let mut seq = 160u32;
    for i in 0..10 {
        let pkt = make_ipv4_tcp_packet(seq, &[i as u8; 60]);
        drained_count = 0;

        assert_no_alloc!({
            let outcome = buffer.process(&pkt, false, 20 + i, |p| {
                if drained_count < drained_slots.len() {
                    drained_slots[drained_count].clear();
                    drained_slots[drained_count].extend_from_slice(p);
                    drained_count += 1;
                }
            });
            assert!(matches!(
                outcome,
                yip_transport::reorder::ReorderOutcome::InOrder
            ));
            assert_eq!(drained_count, 1);
        });

        seq = seq.wrapping_add(60);
    }

    // Gap packet buffering must perform zero allocations
    let gap_pkt = make_ipv4_tcp_packet(seq.wrapping_add(60), &[0x33; 60]);
    assert_no_alloc!({
        let outcome = buffer.process(&gap_pkt, false, 50, |_| panic!("gap should not emit"));
        assert!(matches!(
            outcome,
            yip_transport::reorder::ReorderOutcome::Buffered
        ));
    });

    // Hole fill contiguous batch drain must perform zero allocations
    let hole_pkt = make_ipv4_tcp_packet(seq, &[0x22; 60]);
    drained_count = 0;
    assert_no_alloc!({
        let outcome = buffer.process(&hole_pkt, false, 50, |p| {
            if drained_count < drained_slots.len() {
                drained_slots[drained_count].clear();
                drained_slots[drained_count].extend_from_slice(p);
                drained_count += 1;
            }
        });
        assert!(matches!(
            outcome,
            yip_transport::reorder::ReorderOutcome::InOrder
        ));
        assert_eq!(drained_count, 2);
    });
}
