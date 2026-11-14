//! Integration tests for DAITA probabilistic state machines in yipd.
//!
//! Verifies:
//! 1. End-to-end traffic between two peers with DAITA enabled.
//! 2. Verification that padding/junk datagrams are emitted during bursts.
//! 3. Verification that receiver silently drops junk datagrams while normal data frames
//!    are decrypted and delivered intact.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use yip_crypto::generate_keypair;
use yip_io::poll::DispatchOut;
use yip_obf::{DaitaAction, DaitaProfile, JUNK_TYPE};
use yipd::config::{PeerConfig, TrafficDefenseConfig};
use yipd::mode::TunnelMode;
use yipd::peer_manager::PeerManager;

fn setup_established_daita_pair(
    profile: DaitaProfile,
) -> (PeerManager, PeerManager, SocketAddr, SocketAddr) {
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();
    let ep_a: SocketAddr = "10.10.1.1:10001".parse().unwrap();
    let ep_b: SocketAddr = "10.10.1.2:10002".parse().unwrap();

    let cfg_b = PeerConfig {
        public_key: kp_b.public,
        endpoint: Some(ep_b),
    };
    let cfg_a = PeerConfig {
        public_key: kp_a.public,
        endpoint: Some(ep_a),
    };

    let mut pm_a = PeerManager::new(
        kp_a.private,
        kp_a.public,
        &[cfg_b],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    let mut pm_b = PeerManager::new(
        kp_b.private,
        kp_b.public,
        &[cfg_a],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );

    let psk = [0x55u8; 32];
    pm_a.set_obf_psk(Some(psk));
    pm_b.set_obf_psk(Some(psk));

    let defense_cfg = TrafficDefenseConfig {
        preset: yip_obf::TrafficDefensePreset::Balanced,
        buckets: vec![256, 512, 1024, 1420],
        cover_interval_ms: Some(100),
        cover_burst_max: 2,
        jitter_max_ms: 0,
        daita_profile: profile,
    };
    pm_a.set_traffic_defense(defense_cfg.clone());
    pm_b.set_traffic_defense(defense_cfg);

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
fn test_daita_end_to_end_traffic_and_decoy_dropping() {
    let (mut pm_a, mut pm_b, ep_a, _ep_b) = setup_established_daita_pair(DaitaProfile::Front);

    assert!(pm_a.peer_daita_engine(0).is_some());
    assert!(pm_b.peer_daita_engine(0).is_some());

    // Send multiple real data packets from A to B to trigger bursts
    let payload = vec![0x45u8; 60]; // IPv4 dummy packet
    let mut all_received_tun = Vec::new();
    let mut junk_count = 0;
    let mut data_count = 0;

    for i in 1..=10 {
        let now_ms = (i * 50) as u64;
        let mut egress = Vec::new();
        pm_a.on_tun_into(&payload, now_ms, &mut egress);

        for dg in egress {
            // Deliver each datagram from A to B
            let out = pm_b.on_udp(ep_a, &dg.bytes, now_ms);
            match out {
                DispatchOut::Tun(tun_pkt) => {
                    data_count += 1;
                    all_received_tun.push(tun_pkt.to_vec());
                }
                DispatchOut::Both(tun_pkt, _) => {
                    data_count += 1;
                    all_received_tun.push(tun_pkt.to_vec());
                }
                DispatchOut::None => {
                    // Receiver silently dropped junk/decoy datagrams
                    junk_count += 1;
                }
                DispatchOut::Udp(_) => {
                    // Feedback / control packets
                }
            }
        }
    }

    // Verify all original data packets were decrypted and delivered intact
    assert!(
        data_count >= 10,
        "expected at least 10 data packets received, got {data_count}"
    );
    for pkt in &all_received_tun {
        assert_eq!(pkt, &payload, "decrypted TUN packet must match payload");
    }

    // Advance ticks to fire DAITA timers and check for padding emissions
    let mut tick_junk = 0;
    for tick_ms in [600u64, 1200u64, 1800u64, 2500u64] {
        if let Some(dgs) = pm_a.tick(tick_ms) {
            for dg in dgs {
                let out = pm_b.on_udp(ep_a, &dg.bytes, tick_ms);
                if matches!(out, DispatchOut::None) {
                    tick_junk += 1;
                }
            }
        }
    }

    assert!(
        junk_count + tick_junk > 0,
        "DAITA should emit padding/decoy datagrams that are dropped silently"
    );
}

#[test]
fn test_daita_receiver_drops_injected_junk_datagram() {
    let (mut pm_a, mut pm_b, ep_a, ep_b) = setup_established_daita_pair(DaitaProfile::Balanced);

    let key = pm_a
        .obf_key_for_egress(ep_b, JUNK_TYPE)
        .expect("must have established session key");

    // Manually forge an obfuscated JUNK_TYPE datagram
    let junk_body = vec![0x99u8; 128];
    let obf_junk = yip_obf::obfuscate(&key, JUNK_TYPE, &junk_body, 16).expect("obfuscate succeeds");

    // Feed forged junk to receiver B
    let out = pm_b.on_udp(ep_a, &obf_junk, 500);
    assert!(
        matches!(out, DispatchOut::None),
        "receiver must drop JUNK_TYPE datagram silently without yielding TUN or UDP"
    );

    // Ensure normal data still works after junk was processed
    let payload = vec![0x45u8; 50];
    let egress = pm_a.on_tun(&payload, 600);
    assert!(!egress.is_empty());
    let mut delivered = false;
    for dg in egress {
        let out = pm_b.on_udp(ep_a, &dg.bytes, 600);
        if let DispatchOut::Tun(p) | DispatchOut::Both(p, _) = out {
            assert_eq!(p, &payload[..]);
            delivered = true;
        }
    }
    assert!(
        delivered,
        "normal data frame delivered intact after junk packet"
    );
}

#[test]
fn test_daita_dataplane_integration() {
    let resp_kp = generate_keypair();
    let init_kp = generate_keypair();

    let mut ini = yip_crypto::Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
    let mut res = yip_crypto::Handshake::responder(&resp_kp.private).unwrap();

    let m1 = ini.write_message(&[]).unwrap();
    let _ = res.read_message(&m1).unwrap();
    let m2 = res.write_message(&[]).unwrap();
    let _ = ini.read_message(&m2).unwrap();

    let cb = ini.channel_binding();
    let (auth_key, hp_key) = yipd::wire_glue::derive_wire_keys(&cb);
    let (ini_send_k, ini_recv_k) = ini.raw_split_keys();

    let est = yipd::handshake::Established {
        session: ini.into_session().unwrap(),
        auth_key,
        hp_key,
        raw_send_key: ini_send_k,
        raw_recv_key: ini_recv_k,
    };

    let conn_tag = yipd::dataplane::conn_tag_from_keys(&auth_key, &hp_key);
    let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let mut dp =
        yipd::dataplane::DataPlane::new(est, conn_tag, TunnelMode::L3Tun, peer_addr, true, 1200);

    assert!(dp.daita_engine().is_none());
    let now = Instant::now();
    dp.set_daita_profile(DaitaProfile::Front, now).unwrap();
    assert!(dp.daita_engine().is_some());
    assert!(dp.daita_engine().unwrap().is_active());

    // Trigger normal sent event
    let actions = dp.on_daita_normal_sent(now);
    assert!(
        !actions.is_empty(),
        "Front defense emits actions on normal packet"
    );
    assert!(matches!(actions[0], DaitaAction::SendPadding { .. }));

    // Advance timer
    let future = now + Duration::from_millis(500);
    let _ = dp.on_daita_timer(future);
    let _ = dp.on_daita_tunnel_sent(future);
    let _ = dp.on_daita_tunnel_recv(future);
    let _ = dp.on_daita_normal_recv(future);
}
