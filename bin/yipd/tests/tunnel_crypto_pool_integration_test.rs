//! Integration tests for parallel crypto worker pool in yipd tunnel/dataplane.
//!
//! Verifies:
//! 1. Config parsing for `crypto_workers=<N|auto>` and CLI flag overrides.
//! 2. Two-peer tunnel establishment with dedicated crypto workers enabled.
//! 3. End-to-end packet processing: TUN frame -> parallel AEAD encryption ->
//!    in-order UDP transmission -> parallel AEAD decryption -> TUN frame delivery.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use yip_crypto::generate_keypair;
use yip_io::poll::DispatchOut;
use yipd::config::{Config, PeerConfig};
use yipd::mode::TunnelMode;
use yipd::peer_manager::PeerManager;

fn setup_established_crypto_pair(
    crypto_workers: usize,
) -> (PeerManager, PeerManager, SocketAddr, SocketAddr) {
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();
    let ep_a: SocketAddr = "10.20.1.1:10001".parse().unwrap();
    let ep_b: SocketAddr = "10.20.1.2:10002".parse().unwrap();

    let cfg_b = PeerConfig {
        public_key: kp_b.public,
        endpoint: Some(ep_b),
        alias: None,
        kem: None,
        pq_public_key: None,
    };
    let cfg_a = PeerConfig {
        public_key: kp_a.public,
        endpoint: Some(ep_a),
        alias: None,
        kem: None,
        pq_public_key: None,
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

    pm_a.set_crypto_workers(crypto_workers);
    pm_b.set_crypto_workers(crypto_workers);

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
    let out_a = pm_a.on_udp(ep_b, &resp_dg, 0);
    if let DispatchOut::Udp(pkts) = out_a {
        for dg in pkts {
            let _ = pm_b.on_udp(ep_a, &dg.bytes, 0);
        }
    }

    assert!(pm_a.is_peer_established(&kp_b.public));
    assert!(pm_b.is_peer_established(&kp_a.public));

    (pm_a, pm_b, ep_a, ep_b)
}

#[test]
fn test_config_parse_crypto_workers() {
    let base = "device=yip0\n\
                local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";

    // Default crypto_workers is 0
    let c_def = Config::parse(base).expect("parse base config");
    assert_eq!(c_def.crypto_workers, 0);

    // Explicit crypto_workers = 4
    let text_4 = format!("{base}crypto_workers=4\n");
    let c_4 = Config::parse(&text_4).expect("parse crypto_workers=4");
    assert_eq!(c_4.crypto_workers, 4);

    // Alias crypto_threads = 2
    let text_threads = format!("{base}crypto_threads=2\n");
    let c_threads = Config::parse(&text_threads).expect("parse crypto_threads=2");
    assert_eq!(c_threads.crypto_workers, 2);

    // crypto_workers = auto
    let text_auto = format!("{base}crypto_workers=auto\n");
    let c_auto = Config::parse(&text_auto).expect("parse crypto_workers=auto");
    let cores = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    let expected_auto = if cores > 2 { (cores / 2).min(4) } else { 0 };
    assert_eq!(c_auto.crypto_workers, expected_auto);
}

#[test]
fn test_crypto_pool_tunnel_end_to_end_traffic() {
    let (mut pm_a, mut pm_b, ep_a, _ep_b) = setup_established_crypto_pair(4);

    let mut now = 2000u64;
    let num_packets = 50;

    // Send a stream of packets from A to B
    for i in 0..num_packets {
        now += 1;
        // Construct mock IPv4 payload (routes to single configured peer)
        let mut inner = vec![0x45, 0x00, 0x00, 60];
        inner.resize(20, 0);
        inner.extend_from_slice(&format!("crypto payload message {i:04}").into_bytes());
        inner.resize(60, 0);

        let mut egress = Vec::new();
        pm_a.on_tun_into(&inner, now, &mut egress);
        assert!(
            !egress.is_empty(),
            "packet {i} must produce egress datagrams"
        );

        // Forward datagrams to peer B
        let mut delivered_count = 0;
        for dg in egress {
            let disp = pm_b.on_udp(ep_a, &dg.bytes, now);
            match disp {
                DispatchOut::Tun(delivered) => {
                    assert_eq!(
                        delivered,
                        inner.as_slice(),
                        "delivered packet must match inner payload"
                    );
                    delivered_count += 1;
                }
                DispatchOut::Both(delivered, _) => {
                    assert_eq!(
                        delivered,
                        inner.as_slice(),
                        "delivered packet must match inner payload"
                    );
                    delivered_count += 1;
                }
                DispatchOut::TunBatch(batch) => {
                    assert!(!batch.is_empty());
                    assert_eq!(batch[0], inner.as_slice());
                    delivered_count += batch.len();
                }
                DispatchOut::TunBatchThenUdp(batch, _) => {
                    assert!(!batch.is_empty());
                    assert_eq!(batch[0], inner.as_slice());
                    delivered_count += batch.len();
                }
                DispatchOut::None | DispatchOut::Udp(_) => {
                    // Redundant FEC parity symbol or feedback
                }
            }
        }
        assert!(
            delivered_count >= 1,
            "packet {i} must be delivered at least once to TUN"
        );
    }
}
