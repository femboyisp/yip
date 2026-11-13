use std::alloc::System;
use std::net::SocketAddr;
use yip_crypto::{generate_keypair, Handshake};
use yip_transport::ControlFrame;
use yip_verify::{assert_no_alloc, TrackingAllocator};
use yipd::dataplane::{conn_tag_from_keys, DataPlane, Outcome};
use yipd::handshake::{Established, PacketType};
use yipd::mode::TunnelMode;
use yipd::wire_glue::derive_wire_keys;

#[global_allocator]
static ALLOC: TrackingAllocator<System> = TrackingAllocator(System);

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

#[test]
fn test_dataplane_ingress_performs_zero_allocations_on_hotpath() {
    let (mut a, mut b) = test_dataplane_pair();

    // 1. Warm-up scratch buffers with initial control and data packets
    let ctrl = ControlFrame::MtuProbeAck {
        probe_id: 1,
        accepted_symbol_size: 1200,
    };
    let plain = ctrl.encode();
    let sealed = a.session_mut().seal(&plain).unwrap();
    let mut ctrl_dg = Vec::with_capacity(9 + sealed.ciphertext.len());
    ctrl_dg.push(PacketType::Control as u8);
    ctrl_dg.extend_from_slice(&sealed.counter.to_be_bytes());
    ctrl_dg.extend_from_slice(&sealed.ciphertext);

    // Warm-up control scratch
    let _ = b.on_udp_datagram(&ctrl_dg, 100);

    // Assert zero allocations on subsequent control ingress hotpath
    let sealed2 = a.session_mut().seal(&plain).unwrap();
    let mut ctrl_dg2 = Vec::with_capacity(9 + sealed2.ciphertext.len());
    ctrl_dg2.push(PacketType::Control as u8);
    ctrl_dg2.extend_from_slice(&sealed2.counter.to_be_bytes());
    ctrl_dg2.extend_from_slice(&sealed2.ciphertext);

    assert_no_alloc!({
        let outcome = b.on_udp_datagram(&ctrl_dg2, 101);
        assert!(matches!(outcome, Outcome::None));
    });

    // Test loop of subsequent control packets under assert_no_alloc!
    for i in 2..20 {
        let sealed = a.session_mut().seal(&plain).unwrap();
        let mut dg = Vec::with_capacity(9 + sealed.ciphertext.len());
        dg.push(PacketType::Control as u8);
        dg.extend_from_slice(&sealed.counter.to_be_bytes());
        dg.extend_from_slice(&sealed.ciphertext);

        assert_no_alloc!({
            let outcome = b.on_udp_datagram(&dg, 100 + i);
            assert!(matches!(outcome, Outcome::None));
        });
    }

    // Corrupted data wire packet deframes with zero allocations
    let mut bad_data_dg = vec![PacketType::Data as u8; 64];
    bad_data_dg[0] = PacketType::Data as u8;
    assert_no_alloc!({
        let outcome = b.on_udp_datagram(&bad_data_dg, 200);
        assert!(matches!(outcome, Outcome::None));
    });
}
