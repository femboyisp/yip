use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use yip_proto::control::{
    extract_ip_dst, ip_matches_cidr, parse_cidr, ControlCmd, ControlResponse, DaemonConfig,
    DaitaConfig, DaitaPreset, FecConfig, FecPreset, HopTrace, LatencyCategory, MeshTopologyGraph,
    PeerConfigEntry, PeerCryptoStatus, PingPeerResult, RouteEntry, SplitMode, SplitTunnelConfig,
    SplitTunnelTelemetry, TopologyLink, TopologyNode, XdpMode,
};
use yip_proto::metrics::{
    CryptoTelemetry, DaitaTelemetry, FecTelemetry, PeerTelemetryItem, PeersTelemetry,
    TelemetrySnapshot, TrafficTelemetry,
};
use yip_proto::peer::{PeerState, PeerStats};
use yip_proto::ticket::NetworkTicket;

#[test]
fn test_control_cmd_reload_and_get_config_serde() {
    let cmd_reload_default = ControlCmd::Reload { path: None };
    let json = serde_json::to_string(&cmd_reload_default).unwrap();
    assert_eq!(json, r#"{"cmd":"reload","path":null}"#);
    let deserialized: ControlCmd = serde_json::from_str(r#"{"cmd":"reload"}"#).unwrap();
    assert_eq!(deserialized, cmd_reload_default);

    let cmd_reload_custom = ControlCmd::Reload {
        path: Some("/etc/yip/test.conf".to_string()),
    };
    let json = serde_json::to_string(&cmd_reload_custom).unwrap();
    let deserialized: ControlCmd = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, cmd_reload_custom);

    let cmd_get_config = ControlCmd::GetConfig;
    let json = serde_json::to_string(&cmd_get_config).unwrap();
    assert_eq!(json, r#"{"cmd":"get_config"}"#);
    let deserialized: ControlCmd = serde_json::from_str(r#"{"cmd":"get_config"}"#).unwrap();
    assert_eq!(deserialized, cmd_get_config);
}

#[test]
fn test_control_response_config_and_reload_serde() {
    let daemon_cfg = DaemonConfig {
        device: "yip0".to_string(),
        listen: Some("127.0.0.1:51820".to_string()),
        public_key: Some(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        ),
        rendezvous: Some("198.51.100.1:51820".to_string()),
        network_id: Some("00112233445566778899aabbccddeeff".to_string()),
        peers: vec![PeerConfigEntry {
            public_key: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                .to_string(),
            endpoint: Some("198.51.100.2:51820".to_string()),
            alias: Some("peer-b".to_string()),
            transport: Some("raw_udp".to_string()),
            kem: None,
        }],
        fec: Some(FecPreset::Adaptive.default_config()),
        daita: Some(DaitaPreset::Balanced.default_config()),
        split_tunnel: Some(SplitTunnelConfig {
            enabled: true,
            mode: SplitMode::Exclude,
            cidrs: vec!["10.0.0.0/8".to_string()],
            domains: vec!["internal.corp".to_string()],
            apps: vec!["curl".to_string()],
        }),
        kem: None,
    };

    let resp_config = ControlResponse::Config {
        ok: true,
        config: daemon_cfg,
    };
    let json = serde_json::to_string(&resp_config).unwrap();
    let deserialized: ControlResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, resp_config);

    let resp_reload = ControlResponse::Reload {
        ok: true,
        message: "configuration reloaded successfully".to_string(),
        reloaded: true,
    };
    let json = serde_json::to_string(&resp_reload).unwrap();
    let deserialized: ControlResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, resp_reload);
}

#[test]
fn test_all_existing_control_cmd_variants_round_trip() {
    let variants = vec![
        ControlCmd::Status,
        ControlCmd::ListPeers,
        ControlCmd::AddPeer {
            public_key: "abc".to_string(),
            endpoint: Some("1.2.3.4:51820".to_string()),
            transport: Some("raw".to_string()),
            alias: Some("alpha".to_string()),
        },
        ControlCmd::RemovePeer {
            public_key: "abc".to_string(),
        },
        ControlCmd::SetTransport {
            public_key: "abc".to_string(),
            transport: "quic".to_string(),
        },
        ControlCmd::CertStatus,
        ControlCmd::CertRenew,
        ControlCmd::GetFecStatus,
        ControlCmd::SetFecConfig {
            preset: Some("hostile".to_string()),
            redundancy_pct: Some(25),
            data_shards: Some(10),
            parity_shards: Some(3),
        },
        ControlCmd::GetDaitaStatus,
        ControlCmd::SetDaitaConfig {
            preset: Some("balanced".to_string()),
            buckets: Some(vec![256, 512, 1024]),
            cover_interval_ms: Some(200),
            cover_burst_max: Some(3),
            jitter_max_ms: Some(5),
        },
        ControlCmd::GetRoutes,
        ControlCmd::GetTopology,
        ControlCmd::GetSplitTunnelStatus,
        ControlCmd::SetSplitTunnelConfig {
            enabled: Some(true),
            mode: Some("include".to_string()),
            cidrs: Some(vec!["192.168.1.0/24".to_string()]),
            domains: Some(vec!["example.com".to_string()]),
            apps: Some(vec!["firefox".to_string()]),
        },
        ControlCmd::TracePath {
            peer_node_id: "node123".to_string(),
        },
        ControlCmd::PingPeer {
            peer_node_id: "node123".to_string(),
            count: 5,
            timeout_ms: 3000,
        },
        ControlCmd::GetMetrics {
            peer: Some("node123".to_string()),
        },
        ControlCmd::GetCryptoStatus {
            peer: Some("node123".to_string()),
        },
        ControlCmd::TriggerRekey {
            peer: "node123".to_string(),
        },
        ControlCmd::GetXdpStatus,
        ControlCmd::SetXdpMode {
            mode: "native".to_string(),
        },
        ControlCmd::CreateTicket {
            name: Some("test-ticket".to_string()),
            route_mode: Some("direct".to_string()),
            endpoint: Some("1.2.3.4:443".to_string()),
        },
    ];

    for cmd in variants {
        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: ControlCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, cmd);
    }
}

#[test]
fn test_all_existing_control_response_variants_round_trip() {
    let mock_ticket = NetworkTicket {
        v: 1,
        name: "test-net".to_string(),
        network_id: "00112233445566778899aabbccddeeff".to_string(),
        route_mode: "MeshOnly".to_string(),
        endpoint: Some("1.2.3.4:443".to_string()),
        seeds: Some(vec!["seed1.example.com:443".to_string()]),
        created_at: Some("2026-11-17T00:00:00Z".to_string()),
    };

    let variants = vec![
        ControlResponse::Status {
            ok: true,
            version: "0.1.0".to_string(),
            node_addr: "fd00::1".to_string(),
            device: "yip0".to_string(),
            public_key: "abc".to_string(),
            listen_port: 443,
            network_id: "net1".to_string(),
            peers_count: 3,
            uptime_secs: 100,
            ca_status: Some("valid".to_string()),
            spsc_queue_drops: 0,
        },
        ControlResponse::ListPeers {
            ok: true,
            peers: vec![PeerStats {
                public_key: [3u8; 32],
                alias: Some("peer-3".to_string()),
                endpoint: Some("1.2.3.4:51820".parse().unwrap()),
                node_addr: "fd00::3".parse().unwrap(),
                state: "established".to_string(),
                last_activity_ms: 1234,
                tx_bytes: 1000,
                rx_bytes: 2000,
                tx_packets: 10,
                rx_packets: 20,
                fec_recovered: 1,
                transport: "raw_udp".to_string(),
                rtt_ms: Some(15),
                fec_ratio_pct: 12,
                cert_status: "CA Valid".to_string(),
            }],
        },
        ControlResponse::CertStatus {
            ok: true,
            not_before: 100,
            not_after: 200,
            ttl_remaining_secs: 100,
            renewal_threshold_secs: 30,
            is_threshold_ca: true,
        },
        ControlResponse::CertRenew {
            ok: true,
            renewed: true,
            message: "certificate renewed".to_string(),
            new_not_after: Some(300),
        },
        ControlResponse::FecStatus {
            ok: true,
            preset: "adaptive".to_string(),
            redundancy_pct: 12,
            data_shards: 10,
            parity_shards: 2,
            total_symbols_tx: 500,
            recovered_symbols_rx: 20,
            unrecoverable_burst_drops: 0,
            loss_recovery_rate_pct: 99.5,
        },
        ControlResponse::DaitaStatus {
            ok: true,
            preset: "balanced".to_string(),
            buckets: vec![256, 512, 1024, 1420],
            cover_interval_ms: Some(500),
            cover_burst_max: 2,
            jitter_max_ms: 2,
            authentic_bytes_tx: 1000,
            padding_bytes_tx: 200,
            decoy_packets_tx: 5,
            decoy_bytes_tx: 300,
            padding_ratio_pct: 16.6,
        },
        ControlResponse::Routes {
            ok: true,
            routes: vec![RouteEntry {
                prefix: "fd00::/64".to_string(),
                next_hop: "fd00::2".to_string(),
                peer_name: "peer2".to_string(),
                direct: true,
                mtu: 1420,
                margin: 0,
                metric: 10,
            }],
        },
        ControlResponse::Topology {
            ok: true,
            topology: MeshTopologyGraph {
                nodes: vec![TopologyNode {
                    id: "n1".to_string(),
                    label: "node-1".to_string(),
                    ip: "fd00::1".to_string(),
                    is_self: true,
                    is_relay: false,
                    rtt_ms: 0.0,
                    kem_algo: "ml-kem-768".to_string(),
                    rx_bytes: 100,
                    tx_bytes: 200,
                }],
                links: vec![TopologyLink {
                    source: "n1".to_string(),
                    target: "n2".to_string(),
                    direct: true,
                    rtt_ms: 12.5,
                    metric: 10,
                    latency_category: LatencyCategory::Optimal,
                }],
                total_peers: 1,
                direct_peers: 1,
                relay_peers: 0,
                avg_rtt_ms: 12.5,
            },
        },
        ControlResponse::SplitTunnelStatus {
            ok: true,
            enabled: true,
            mode: "exclude".to_string(),
            cidrs: vec!["10.0.0.0/8".to_string()],
            domains: vec!["corp.internal".to_string()],
            apps: vec!["slack".to_string()],
            bypassed_packets: 50,
            bypassed_bytes: 5000,
            overlay_packets: 100,
            overlay_bytes: 15000,
        },
        ControlResponse::TracePath {
            ok: true,
            target: "node-target".to_string(),
            reachable: true,
            hops: vec![HopTrace {
                hop_index: 1,
                node_id: "node-hop-1".to_string(),
                endpoint: Some("1.2.3.4:443".to_string()),
                rtt_ms: 5.2,
                is_direct: true,
                transport: "raw_udp".to_string(),
            }],
            total_rtt_ms: 5.2,
        },
        ControlResponse::PingPeer {
            ok: true,
            target: "peer-target".to_string(),
            endpoint: Some("1.2.3.4:443".to_string()),
            sent: 4,
            received: 4,
            packet_loss_pct: 0.0,
            min_rtt_ms: Some(10.0),
            avg_rtt_ms: Some(11.0),
            max_rtt_ms: Some(12.0),
            stddev_rtt_ms: Some(0.8),
            samples: vec![10.0, 11.0, 11.0, 12.0],
        },
        ControlResponse::CryptoStatus {
            ok: true,
            sessions: vec![PeerCryptoStatus {
                peer: "node-peer".to_string(),
                node_addr: "fd00::10".to_string(),
                endpoint: Some("1.2.3.4:443".to_string()),
                session_state: "active".to_string(),
                cipher_suite: "ChaCha20-Poly1305".to_string(),
                current_epoch: Some(1),
                current_epoch_age_secs: Some(120),
                next_epoch: Some(2),
                previous_epoch: None,
                rekey_in_flight: false,
                send_counter: Some(42),
                replay_floor: Some(1),
                replay_latest: Some(40),
                last_accepted_init_tai64n: None,
            }],
        },
        ControlResponse::XdpStatus {
            ok: true,
            interface: Some("eth0".to_string()),
            mode: "generic".to_string(),
            bound_mode: "generic".to_string(),
            attached_mode: "generic".to_string(),
            zero_copy_supported: false,
            prog_id: Some(123),
            queues_count: 2,
            hardware_offload_queues: vec![],
            umem_slabs: 1,
            umem_chunk_size: 2048,
            umem_total_chunks: 1024,
            umem_free_chunks: 512,
            fill_ring_drops: 0,
            rx_ring_drops: 0,
            tx_ring_drops: 0,
            completion_ring_drops: 0,
            rx_packets: 100,
            tx_packets: 200,
            rx_bytes: 1024,
            tx_bytes: 2048,
        },
        ControlResponse::Metrics {
            ok: true,
            metrics: TelemetrySnapshot {
                uptime_seconds: 500,
                traffic: TrafficTelemetry::default(),
                fec: FecTelemetry::default(),
                daita: DaitaTelemetry::default(),
                crypto: CryptoTelemetry::default(),
                split_tunnel: SplitTunnelTelemetry::default(),
                peers: PeersTelemetry::default(),
            },
            prometheus: "# HELP test\n".to_string(),
        },
        ControlResponse::Ticket {
            ok: true,
            ticket: mock_ticket,
            uri: "yip://ticket-xyz".to_string(),
            qr_terminal: "████".to_string(),
        },
        ControlResponse::Ack {
            ok: true,
            message: "peer added".to_string(),
        },
        ControlResponse::Err {
            ok: false,
            error: "bad request".to_string(),
        },
    ];

    for resp in variants {
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: ControlResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, resp);
    }
}

#[test]
fn test_control_response_reload_and_ack_no_collision() {
    let resp_reload = ControlResponse::Reload {
        ok: true,
        message: "configuration reloaded".to_string(),
        reloaded: true,
    };
    let resp_ack = ControlResponse::Ack {
        ok: true,
        message: "peer added".to_string(),
    };

    let reload_json = serde_json::to_string(&resp_reload).unwrap();
    let ack_json = serde_json::to_string(&resp_ack).unwrap();

    let deserialized_reload: ControlResponse = serde_json::from_str(&reload_json).unwrap();
    let deserialized_ack: ControlResponse = serde_json::from_str(&ack_json).unwrap();

    assert_eq!(deserialized_reload, resp_reload);
    assert_eq!(deserialized_ack, resp_ack);

    assert!(matches!(
        deserialized_reload,
        ControlResponse::Reload {
            ok: true,
            reloaded: true,
            ..
        }
    ));
    assert!(matches!(
        deserialized_ack,
        ControlResponse::Ack {
            ok: true,
            ref message
        } if message == "peer added"
    ));
}

#[test]
fn test_cidr_helpers() {
    let (ip4, prefix4) = parse_cidr("192.168.1.50/24").unwrap();
    assert_eq!(ip4, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
    assert_eq!(prefix4, 24);

    let (ip6, prefix6) = parse_cidr("fd00::1/64").unwrap();
    assert_eq!(ip6, IpAddr::V6(Ipv6Addr::from_str("fd00::1").unwrap()));
    assert_eq!(prefix6, 64);

    let (host_ip4, host_p4) = parse_cidr("10.0.0.1").unwrap();
    assert_eq!(host_p4, 32);
    assert_eq!(host_ip4, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    let (host_ip6, host_p6) = parse_cidr("::1").unwrap();
    assert_eq!(host_p6, 128);
    assert_eq!(host_ip6, IpAddr::V6(Ipv6Addr::LOCALHOST));

    assert!(parse_cidr("invalid_cidr").is_err());
    assert!(parse_cidr("1.2.3.4/33").is_err());
    assert!(parse_cidr("::1/129").is_err());

    let net4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
    assert!(ip_matches_cidr(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
        net4,
        24
    ));
    assert!(!ip_matches_cidr(
        IpAddr::V4(Ipv4Addr::new(192, 168, 2, 42)),
        net4,
        24
    ));

    let net6 = IpAddr::V6(Ipv6Addr::from_str("fd00::").unwrap());
    assert!(ip_matches_cidr(
        IpAddr::V6(Ipv6Addr::from_str("fd00::abcd").unwrap()),
        net6,
        64
    ));
    assert!(!ip_matches_cidr(
        IpAddr::V6(Ipv6Addr::from_str("fd01::abcd").unwrap()),
        net6,
        64
    ));

    // Mismatched IP families
    assert!(!ip_matches_cidr(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        net6,
        64
    ));

    // IPv4 packet extraction
    let mut ipv4_pkt = vec![0u8; 20];
    ipv4_pkt[0] = 0x45;
    ipv4_pkt[16..20].copy_from_slice(&[10, 1, 2, 3]);
    assert_eq!(
        extract_ip_dst(&ipv4_pkt),
        Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
    );

    // IPv6 packet extraction
    let mut ipv6_pkt = vec![0u8; 40];
    ipv6_pkt[0] = 0x60;
    let target_v6 = Ipv6Addr::from_str("fd00::cafe").unwrap();
    ipv6_pkt[24..40].copy_from_slice(&target_v6.octets());
    assert_eq!(extract_ip_dst(&ipv6_pkt), Some(IpAddr::V6(target_v6)));

    // Too short or invalid
    assert_eq!(extract_ip_dst(&[0x45, 0x00]), None);
    assert_eq!(extract_ip_dst(&[0x50; 25]), None);
}

#[test]
fn test_enum_parsing_and_serialization() {
    for (s, preset) in [
        ("off", FecPreset::Off),
        ("low", FecPreset::Low),
        ("adaptive", FecPreset::Adaptive),
        ("hostile", FecPreset::Hostile),
        ("custom", FecPreset::Custom),
    ] {
        assert_eq!(FecPreset::from_str(s).unwrap(), preset);
        assert_eq!(preset.to_string(), s);
        assert_eq!(serde_json::to_string(&preset).unwrap(), format!("\"{s}\""));
        assert_eq!(
            serde_json::from_str::<FecPreset>(&format!("\"{s}\"")).unwrap(),
            preset
        );
        let cfg: FecConfig = preset.default_config();
        let cfg_json = serde_json::to_string(&cfg).unwrap();
        let cfg_dec: FecConfig = serde_json::from_str(&cfg_json).unwrap();
        assert_eq!(cfg_dec, cfg);
    }
    assert!(FecPreset::from_str("nonexistent").is_err());

    for (s, preset) in [
        ("off", DaitaPreset::Off),
        ("low", DaitaPreset::Low),
        ("balanced", DaitaPreset::Balanced),
        ("max", DaitaPreset::Max),
        ("paranoid", DaitaPreset::Paranoid),
        ("custom", DaitaPreset::Custom),
    ] {
        assert_eq!(DaitaPreset::from_str(s).unwrap(), preset);
        assert_eq!(preset.to_string(), s);
        assert_eq!(serde_json::to_string(&preset).unwrap(), format!("\"{s}\""));
        assert_eq!(
            serde_json::from_str::<DaitaPreset>(&format!("\"{s}\"")).unwrap(),
            preset
        );
        let cfg: DaitaConfig = preset.default_config();
        let cfg_json = serde_json::to_string(&cfg).unwrap();
        let cfg_dec: DaitaConfig = serde_json::from_str(&cfg_json).unwrap();
        assert_eq!(cfg_dec, cfg);
    }
    assert!(DaitaPreset::from_str("nonexistent").is_err());

    for (s, mode) in [
        ("exclude", SplitMode::Exclude),
        ("include", SplitMode::Include),
    ] {
        assert_eq!(SplitMode::from_str(s).unwrap(), mode);
        assert_eq!(mode.to_string(), s);
        assert_eq!(serde_json::to_string(&mode).unwrap(), format!("\"{s}\""));
        assert_eq!(
            serde_json::from_str::<SplitMode>(&format!("\"{s}\"")).unwrap(),
            mode
        );
    }
    assert!(SplitMode::from_str("nonexistent").is_err());

    for (s, mode) in [
        ("auto", XdpMode::Auto),
        ("generic", XdpMode::Generic),
        ("native", XdpMode::Native),
        ("offload", XdpMode::Offload),
    ] {
        assert_eq!(XdpMode::from_str(s).unwrap(), mode);
        assert_eq!(mode.to_string(), s);
        assert_eq!(serde_json::to_string(&mode).unwrap(), format!("\"{s}\""));
        assert_eq!(
            serde_json::from_str::<XdpMode>(&format!("\"{s}\"")).unwrap(),
            mode
        );
    }
    assert_eq!(XdpMode::from_str("skb").unwrap(), XdpMode::Generic);
    assert_eq!(XdpMode::from_str("driver").unwrap(), XdpMode::Native);
    assert_eq!(XdpMode::from_str("drv").unwrap(), XdpMode::Native);
    assert_eq!(XdpMode::from_str("hardware").unwrap(), XdpMode::Offload);
    assert_eq!(XdpMode::from_str("hw").unwrap(), XdpMode::Offload);
    assert!(XdpMode::from_str("nonexistent").is_err());
}

#[test]
fn test_peer_state_and_peer_stats_serde() {
    for (s, state) in [
        ("idle", PeerState::Idle),
        ("handshaking", PeerState::Handshaking),
        ("established", PeerState::Established),
    ] {
        assert_eq!(PeerState::from_str(s).unwrap(), state);
        assert_eq!(state.to_string(), s);
        assert_eq!(state.as_str(), s);
        assert_eq!(serde_json::to_string(&state).unwrap(), format!("\"{s}\""));
        assert_eq!(
            serde_json::from_str::<PeerState>(&format!("\"{s}\"")).unwrap(),
            state
        );
    }
    assert!(PeerState::from_str("unknown").is_err());

    let stats = PeerStats {
        public_key: [7u8; 32],
        alias: Some("gateway".to_string()),
        endpoint: Some(SocketAddr::from(([192, 0, 2, 1], 51820))),
        node_addr: Ipv6Addr::from_str("fd00::7").unwrap(),
        state: "established".to_string(),
        last_activity_ms: 500,
        tx_bytes: 4096,
        rx_bytes: 8192,
        tx_packets: 4,
        rx_packets: 8,
        fec_recovered: 2,
        transport: "raw_udp".to_string(),
        rtt_ms: Some(25),
        fec_ratio_pct: 10,
        cert_status: "CA Valid".to_string(),
    };

    let json = serde_json::to_string(&stats).unwrap();
    let deserialized: PeerStats = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, stats);

    // Verify default cert_status when missing in JSON
    let min_json = r#"{
        "public_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "endpoint": null,
        "node_addr": "fd00::1",
        "state": "idle",
        "last_activity_ms": 0,
        "tx_bytes": 0,
        "rx_bytes": 0,
        "tx_packets": 0,
        "rx_packets": 0,
        "fec_recovered": 0,
        "transport": "raw_udp",
        "rtt_ms": null,
        "fec_ratio_pct": 0
    }"#;
    let min_stats: PeerStats = serde_json::from_str(min_json).unwrap();
    assert_eq!(min_stats.cert_status, "CA Valid");
}

#[test]
fn test_telemetry_item_and_ping_result_serde() {
    let ping = PingPeerResult {
        target: "node1".to_string(),
        endpoint: Some("1.2.3.4:51820".to_string()),
        sent: 4,
        received: 4,
        packet_loss_pct: 0.0,
        min_rtt_ms: Some(1.2),
        avg_rtt_ms: Some(1.5),
        max_rtt_ms: Some(2.0),
        stddev_rtt_ms: Some(0.3),
        samples: vec![1.2, 1.4, 1.6, 2.0],
    };
    let json = serde_json::to_string(&ping).unwrap();
    let dec: PingPeerResult = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, ping);

    let item = PeerTelemetryItem {
        public_key: "010203".to_string(),
        node_addr: "fd00::1".to_string(),
        endpoint: Some("127.0.0.1:443".to_string()),
        state: "established".to_string(),
        transport: "raw_udp".to_string(),
        tx_bytes: 100,
        rx_bytes: 200,
        tx_packets: 1,
        rx_packets: 2,
        fec_recovered: 0,
        rtt_ms: Some(10),
        fec_ratio_pct: 0,
        cert_status: "CA Valid".to_string(),
    };
    let json = serde_json::to_string(&item).unwrap();
    let dec: PeerTelemetryItem = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, item);
}

#[test]
fn test_default_ping_and_xdp_flags_and_cidr_boundary_mutants() {
    // Ping defaults
    let ping_cmd_json = r#"{"cmd":"ping_peer","peer_node_id":"peer123"}"#;
    let parsed: ControlCmd = serde_json::from_str(ping_cmd_json).unwrap();
    if let ControlCmd::PingPeer {
        count, timeout_ms, ..
    } = parsed
    {
        assert_eq!(count, 4);
        assert_eq!(timeout_ms, 2000);
    } else {
        panic!("expected PingPeer");
    }

    // XdpMode::to_flags
    assert_eq!(XdpMode::Auto.to_flags(), 0);
    assert_eq!(XdpMode::Generic.to_flags(), 2);
    assert_eq!(XdpMode::Native.to_flags(), 4);
    assert_eq!(XdpMode::Offload.to_flags(), 8);

    // parse_cidr prefix bounds
    assert!(parse_cidr("10.0.0.1/32").is_ok());
    assert!(parse_cidr("10.0.0.1/33").is_err());
    assert!(parse_cidr("10.0.0.1/24/extra").is_err());
    assert!(parse_cidr("fd00::1/128").is_ok());
    assert!(parse_cidr("fd00::1/129").is_err());

    // ip_matches_cidr prefix boundary / mask
    let v4_target: std::net::IpAddr = "192.168.1.100".parse().unwrap();
    let v4_net: std::net::IpAddr = "192.168.1.100".parse().unwrap();
    assert!(ip_matches_cidr(v4_target, v4_net, 32));
    assert!(!ip_matches_cidr(
        "192.168.1.101".parse().unwrap(),
        v4_net,
        32
    ));
    assert!(!ip_matches_cidr(v4_target, v4_net, 33));

    let v6_target: std::net::IpAddr = "fd00::1234".parse().unwrap();
    let v6_net: std::net::IpAddr = "fd00::1234".parse().unwrap();
    assert!(ip_matches_cidr(v6_target, v6_net, 128));
    assert!(!ip_matches_cidr("fd00::1235".parse().unwrap(), v6_net, 128));
    assert!(!ip_matches_cidr(v6_target, v6_net, 129));

    // extract_ip_dst short or malformed packets
    assert_eq!(extract_ip_dst(&[]), None);
    let mut short_v4 = [0u8; 19];
    short_v4[0] = 0x45;
    assert_eq!(extract_ip_dst(&short_v4), None);
    let mut bad_ver_v4 = [0u8; 20];
    bad_ver_v4[0] = 0x55;
    assert_eq!(extract_ip_dst(&bad_ver_v4), None);
    let mut short_v6 = [0u8; 39];
    short_v6[0] = 0x60;
    assert_eq!(extract_ip_dst(&short_v6), None);
}
