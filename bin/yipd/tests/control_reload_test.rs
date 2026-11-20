//! Integration tests for dynamic daemon configuration reload and GetConfig (#196).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use yip_proto::control::{ControlCmd, ControlResponse, DaitaPreset, FecPreset};
use yipd::config::Config;
use yipd::control::{run_cli_config, run_cli_reload, ControlHandle};
use yipd::handshake::Established;
use yipd::mode::TunnelMode;
use yipd::peer_manager::PeerManager;

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

fn fake_established(
    daemon_priv: &[u8; 32],
    peer_priv: &[u8; 32],
    peer_pub: &[u8; 32],
) -> Established {
    let mut ini = yip_crypto::Handshake::initiator(daemon_priv, peer_pub).unwrap();
    let mut res = yip_crypto::Handshake::responder(peer_priv).unwrap();
    let m1 = ini.write_message(&[]).unwrap();
    let _ = res.read_message(&m1).unwrap();
    let m2 = res.write_message(&[]).unwrap();
    let _ = ini.read_message(&m2).unwrap();
    let cb = ini.channel_binding();
    let (auth_key, hp_key) = yipd::wire_glue::derive_wire_keys(&cb);
    let (ini_send_k, ini_recv_k) = ini.raw_split_keys();
    Established {
        session: ini.into_session().unwrap(),
        auth_key,
        hp_key,
        raw_send_key: ini_send_k,
        raw_recv_key: ini_recv_k,
    }
}

#[test]
fn test_control_get_config_and_reload() {
    let test_id = format!("reload_{}", std::process::id());
    let socket_path = format!("/tmp/test_control_{test_id}.sock");
    let config_path = format!("/tmp/test_config_{test_id}.conf");

    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&config_path);

    let kp_daemon = yip_crypto::generate_keypair();
    let kp_peer1 = yip_crypto::generate_keypair();
    let kp_peer2 = yip_crypto::generate_keypair();
    let kp_peer3 = yip_crypto::generate_keypair();

    let hex_daemon_priv = hex_encode(&kp_daemon.private);
    let hex_daemon_pub = hex_encode(&kp_daemon.public);
    let hex_peer1_pub = hex_encode(&kp_peer1.public);
    let hex_peer2_pub = hex_encode(&kp_peer2.public);
    let hex_peer3_pub = hex_encode(&kp_peer3.public);

    let obf_psk_hex = "11".repeat(32);

    // Initial config text
    let initial_config_text = format!(
        "local_private = {hex_daemon_priv}\n\
         local_public = {hex_daemon_pub}\n\
         device = yip-test0\n\
         listen = 127.0.0.1:51820\n\
         obf_psk = {obf_psk_hex}\n\
         fec = adaptive\n\
         traffic_defense = off\n\
         \n\
         [peer]\n\
         public_key = {hex_peer1_pub}\n\
         endpoint = 10.0.0.1:5001\n\
         alias = peer1\n\
         \n\
         [peer]\n\
         public_key = {hex_peer2_pub}\n\
         endpoint = 10.0.0.2:5002\n\
         alias = peer2\n"
    );

    std::fs::write(&config_path, &initial_config_text).expect("write initial config");

    let initial_config = Config::parse(&initial_config_text).expect("parse initial config");
    let mut pm = PeerManager::new(
        initial_config.local_private,
        initial_config.local_public,
        &initial_config.peers,
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    pm.set_config_path(Some(PathBuf::from(&config_path)));
    pm.set_listen_port(initial_config.listen.port());
    pm.set_obf_psk(initial_config.obf_psk);

    // Establish a crypto session for peer1
    let est1 = fake_established(&kp_daemon.private, &kp_peer1.private, &kp_peer1.public);
    pm.install_established_session(
        &kp_peer1.public,
        est1,
        Some("10.0.0.1:5001".parse().unwrap()),
    );
    assert!(pm.is_peer_established(&kp_peer1.public));

    let handle = ControlHandle::bind(&socket_path).expect("bind control socket");
    pm.set_control(
        Some(handle),
        initial_config.device.clone(),
        std::time::Instant::now(),
    );

    let stream = UnixStream::connect(&socket_path).expect("connect control socket");
    let mut writer = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(stream);

    // 1. Test GetConfig
    let get_config_cmd = serde_json::to_string(&ControlCmd::GetConfig).unwrap() + "\n";
    writer.write_all(get_config_cmd.as_bytes()).unwrap();
    writer.flush().unwrap();

    let mut line = String::new();
    for _ in 0..50 {
        let _ = pm.tick(1_000);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    reader.read_line(&mut line).unwrap();
    let resp: ControlResponse = serde_json::from_str(&line).expect("parse GetConfig response");

    match resp {
        ControlResponse::Config { ok, config } => {
            assert!(ok);
            assert_eq!(config.device, "yip-test0");
            assert_eq!(config.public_key.as_deref(), Some(hex_daemon_pub.as_str()));
            assert_eq!(config.peers.len(), 2);
            let p1 = config
                .peers
                .iter()
                .find(|p| p.public_key == hex_peer1_pub)
                .expect("peer1 present");
            assert_eq!(p1.alias.as_deref(), Some("peer1"));
            assert_eq!(p1.endpoint.as_deref(), Some("10.0.0.1:5001"));
            let p2 = config
                .peers
                .iter()
                .find(|p| p.public_key == hex_peer2_pub)
                .expect("peer2 present");
            assert_eq!(p2.alias.as_deref(), Some("peer2"));
            assert_eq!(p2.endpoint.as_deref(), Some("10.0.0.2:5002"));
            assert!(config.fec.is_some());
            assert_eq!(config.fec.unwrap().preset, FecPreset::Adaptive);
        }
        other => panic!("expected ControlResponse::Config, got {other:?}"),
    }

    // 2. Prepare updated config file:
    // - peer1: endpoint updated to 10.0.0.1:6001, alias updated to peer1-renamed
    // - peer2: removed
    // - peer3: added with endpoint 10.0.0.3:5003 and alias peer3
    // - fec: updated to hostile (30% redundancy)
    // - traffic_defense: updated to balanced
    let updated_config_text = format!(
        "local_private = {hex_daemon_priv}\n\
         local_public = {hex_daemon_pub}\n\
         device = yip-test0\n\
         listen = 127.0.0.1:51820\n\
         obf_psk = {obf_psk_hex}\n\
         fec = hostile\n\
         traffic_defense = balanced\n\
         \n\
         [peer]\n\
         public_key = {hex_peer1_pub}\n\
         endpoint = 10.0.0.1:6001\n\
         alias = peer1-renamed\n\
         \n\
         [peer]\n\
         public_key = {hex_peer3_pub}\n\
         endpoint = 10.0.0.3:5003\n\
         alias = peer3\n"
    );

    std::fs::write(&config_path, &updated_config_text).expect("write updated config");

    // 3. Issue Reload command over control socket
    let reload_cmd = serde_json::to_string(&ControlCmd::Reload { path: None }).unwrap() + "\n";
    writer.write_all(reload_cmd.as_bytes()).unwrap();
    writer.flush().unwrap();

    line.clear();
    for _ in 0..50 {
        let _ = pm.tick(1_010);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    reader.read_line(&mut line).unwrap();
    let resp: ControlResponse = serde_json::from_str(&line).expect("parse Reload response");

    match resp {
        ControlResponse::Reload {
            ok,
            reloaded,
            message,
        } => {
            assert!(ok, "reload failed: {message}");
            assert!(reloaded);
            assert!(
                message.contains("reloaded"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected ControlResponse::Reload, got {other:?}"),
    }

    // 4. Verify post-reload state
    // Established session on peer1 MUST be preserved!
    assert!(
        pm.is_peer_established(&kp_peer1.public),
        "peer1 session state was dropped during reload"
    );
    // Peer2 was removed
    assert!(
        !pm.is_peer_established(&kp_peer2.public),
        "peer2 should be removed"
    );
    // Peer3 was added
    assert!(
        !pm.is_peer_established(&kp_peer3.public),
        "peer3 should be idle/unestablished"
    );

    // Verify active config reflects changes
    let active_config = pm.get_active_config();
    assert_eq!(active_config.peers.len(), 2);
    let p1_after = active_config
        .peers
        .iter()
        .find(|p| p.public_key == hex_peer1_pub)
        .expect("peer1 present after reload");
    assert_eq!(p1_after.alias.as_deref(), Some("peer1-renamed"));
    assert_eq!(p1_after.endpoint.as_deref(), Some("10.0.0.1:6001"));
    assert!(active_config
        .peers
        .iter()
        .all(|p| p.public_key != hex_peer2_pub));
    let p3_after = active_config
        .peers
        .iter()
        .find(|p| p.public_key == hex_peer3_pub)
        .expect("peer3 present after reload");
    assert_eq!(p3_after.alias.as_deref(), Some("peer3"));
    assert_eq!(p3_after.endpoint.as_deref(), Some("10.0.0.3:5003"));

    // Verify FEC and DAITA were updated
    assert_eq!(active_config.fec.unwrap().preset, FecPreset::Hostile);
    assert_eq!(active_config.daita.unwrap().preset, DaitaPreset::Balanced);

    // 5. Test CLI functions run_cli_config and run_cli_reload
    let sock = socket_path.clone();
    let cfg = config_path.clone();
    let client_thread = std::thread::spawn(move || {
        let res_cfg = run_cli_config(std::path::Path::new(&sock), true);
        assert!(
            res_cfg.is_ok(),
            "run_cli_config failed: {:?}",
            res_cfg.err()
        );

        let res_reload = run_cli_reload(std::path::Path::new(&sock), Some(&cfg), true);
        assert!(
            res_reload.is_ok(),
            "run_cli_reload failed: {:?}",
            res_reload.err()
        );
    });

    let mut now = 2_000;
    while !client_thread.is_finished() {
        let _ = pm.tick(now);
        now += 10;
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    client_thread.join().unwrap();

    // 6. Test rejecting reload when local_public identity mismatches
    let kp_foreign = yip_crypto::generate_keypair();
    let hex_foreign_pub = hex_encode(&kp_foreign.public);
    let mismatch_config_text = format!(
        "local_private = {hex_daemon_priv}\n\
         local_public = {hex_foreign_pub}\n\
         device = yip-test0\n\
         listen = 127.0.0.1:51820\n\
         \n\
         [peer]\n\
         public_key = {hex_peer1_pub}\n"
    );
    let mismatch_path = format!("/tmp/test_mismatch_{test_id}.conf");
    std::fs::write(&mismatch_path, &mismatch_config_text).expect("write mismatch config");

    let reload_mismatch_cmd = serde_json::to_string(&ControlCmd::Reload {
        path: Some(mismatch_path.clone()),
    })
    .unwrap()
        + "\n";
    writer.write_all(reload_mismatch_cmd.as_bytes()).unwrap();
    writer.flush().unwrap();

    line.clear();
    for _ in 0..50 {
        let _ = pm.tick(1_020);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    reader.read_line(&mut line).unwrap();
    let resp: ControlResponse =
        serde_json::from_str(&line).expect("parse Reload mismatch response");
    match resp {
        ControlResponse::Reload {
            ok,
            reloaded,
            message,
        } => {
            assert!(!ok, "reload should fail on local_public mismatch");
            assert!(!reloaded);
            assert!(
                message.contains("local_public") || message.contains("identity"),
                "expected identity error message, got: {message}"
            );
        }
        ControlResponse::Err { ok, error } => {
            assert!(!ok);
            assert!(
                error.contains("local_public") || error.contains("identity"),
                "expected identity error message, got: {error}"
            );
        }
        other => panic!("expected failure response for mismatch, got {other:?}"),
    }

    // Cleanup
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&mismatch_path);
}

#[test]
fn test_reload_preserves_dynamic_peers_and_rejects_device_or_port_change() {
    let tmp = std::env::temp_dir();
    let nonce: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let cfg_path = tmp.join(format!("test_dyn_peers_{nonce}.conf"));

    let local_priv = [10u8; 32];
    let local_pub = [20u8; 32];
    let static_peer_pk = [30u8; 32];
    let dynamic_peer_pk = [40u8; 32];

    let initial_content = format!(
        "local_private={}\nlocal_public={}\nlisten=127.0.0.1:443\ndevice=yip0\n[peer]\npublic_key={}\n",
        hex_encode(&local_priv),
        hex_encode(&local_pub),
        hex_encode(&static_peer_pk),
    );
    std::fs::write(&cfg_path, &initial_content).unwrap();

    let initial_config = Config::parse(&initial_content).unwrap();
    let mut pm = PeerManager::new(
        local_priv,
        local_pub,
        &initial_config.peers,
        initial_config.device_kind,
        None,
        None,
        false,
    );
    pm.set_listen_port(443);
    pm.set_control(None, "yip0".to_string(), std::time::Instant::now());

    // Dynamically add a non-static peer (e.g. from gossip or RPC)
    assert!(pm
        .add_peer_with_transport(yipd::config::PeerConfig::new(dynamic_peer_pk, None), None)
        .is_ok());
    assert_eq!(pm.list_peers().len(), 2);

    // Reload with same file (which only lists static_peer_pk)
    let report = pm
        .reload_config(Some(cfg_path.to_str().unwrap()))
        .expect("reload succeeds");
    assert_eq!(report.preserved_peers, 1);
    assert_eq!(report.removed_peers, 0);

    // Both static peer and non-static dynamic peer must remain present!
    let peers = pm.list_peers();
    assert_eq!(peers.len(), 2);
    assert!(peers.iter().any(|p| p.public_key == static_peer_pk));
    assert!(peers.iter().any(|p| p.public_key == dynamic_peer_pk));

    // Test rejection on device change
    let changed_device_path = tmp.join(format!("test_dev_chg_{nonce}.conf"));
    let changed_device_content = format!(
        "local_private={}\nlocal_public={}\nlisten=127.0.0.1:443\ndevice=yip99\n[peer]\npublic_key={}\n",
        hex_encode(&local_priv),
        hex_encode(&local_pub),
        hex_encode(&static_peer_pk),
    );
    std::fs::write(&changed_device_path, &changed_device_content).unwrap();
    let res = pm.reload_config(Some(changed_device_path.to_str().unwrap()));
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("device interface"));

    // Test rejection on listen port change
    let changed_port_path = tmp.join(format!("test_port_chg_{nonce}.conf"));
    let changed_port_content = format!(
        "local_private={}\nlocal_public={}\nlisten=127.0.0.1:8443\ndevice=yip0\n[peer]\npublic_key={}\n",
        hex_encode(&local_priv),
        hex_encode(&local_pub),
        hex_encode(&static_peer_pk),
    );
    std::fs::write(&changed_port_path, &changed_port_content).unwrap();
    let res = pm.reload_config(Some(changed_port_path.to_str().unwrap()));
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("listen port"));

    // Cleanup
    let _ = std::fs::remove_file(&cfg_path);
    let _ = std::fs::remove_file(&changed_device_path);
    let _ = std::fs::remove_file(&changed_port_path);
}

#[test]
fn test_reload_config_propagates_endpoint_to_established_epochs() {
    let daemon_kp = yip_crypto::generate_keypair();
    let peer_kp = yip_crypto::generate_keypair();
    let old_ep: std::net::SocketAddr = "198.51.100.1:51820".parse().unwrap();
    let new_ep: std::net::SocketAddr = "198.51.100.2:51820".parse().unwrap();

    let initial_config_text = format!(
        "local_private = {}\n\
         local_public = {}\n\
         device = yip0\n\
         listen = 127.0.0.1:51820\n\
         \n\
         [peer]\n\
         public_key = {}\n\
         endpoint = {}\n",
        hex_encode(&daemon_kp.private),
        hex_encode(&daemon_kp.public),
        hex_encode(&peer_kp.public),
        old_ep,
    );
    let cfg_path = format!("/tmp/test_reload_ep_{}.conf", std::process::id());
    std::fs::write(&cfg_path, &initial_config_text).unwrap();

    let cfg = yipd::config::Config::parse(&initial_config_text).unwrap();
    let mut pm = yipd::peer_manager::PeerManager::new(
        daemon_kp.private,
        daemon_kp.public,
        &cfg.peers,
        cfg.device_kind,
        None,
        None,
        false,
    );
    pm.set_listen_port(51820);
    pm.set_config_path(Some(std::path::PathBuf::from(&cfg_path)));

    // Install established session for peer with old_ep
    let established = fake_established(&daemon_kp.private, &peer_kp.private, &peer_kp.public);
    pm.install_established_session(&peer_kp.public, established, Some(old_ep));

    // Verify initial peer is established
    assert!(pm.is_peer_established(&peer_kp.public));

    // Write updated config with new_ep
    let updated_config_text = format!(
        "local_private = {}\n\
         local_public = {}\n\
         device = yip0\n\
         listen = 127.0.0.1:51820\n\
         \n\
         [peer]\n\
         public_key = {}\n\
         endpoint = {}\n",
        hex_encode(&daemon_kp.private),
        hex_encode(&daemon_kp.public),
        hex_encode(&peer_kp.public),
        new_ep,
    );
    std::fs::write(&cfg_path, &updated_config_text).unwrap();

    // Reload config
    let report = pm.reload_config(Some(&cfg_path)).expect("reload succeeds");
    assert_eq!(report.preserved_peers, 1);
    assert_eq!(report.updated_peers, 1);

    // Verify endpoint was propagated to the peer's endpoint field
    let stats = pm.peer_stats();
    assert_eq!(stats[0].endpoint, Some(new_ep));

    // Verify on_tun egress uses new_ep!
    let peer_addr = yip_proto::addr::node_addr(&peer_kp.public);
    let mut pkt = vec![0x60, 0, 0, 0, 0, 8, 59, 64];
    pkt.extend_from_slice(&[0u8; 16]); // src
    pkt.extend_from_slice(&peer_addr.octets()); // dst
    pkt.extend_from_slice(&[0u8; 8]); // payload

    let egress = pm.on_tun(&pkt, 1000);
    assert!(!egress.is_empty(), "expected egress datagram");
    assert_eq!(egress[0].dst, new_ep, "egress destination should be new_ep");

    let _ = std::fs::remove_file(&cfg_path);
}

#[test]
fn test_peer_alias_uniqueness_enforced() {
    let kp = yip_crypto::generate_keypair();
    let kp_peer1 = yip_crypto::generate_keypair();
    let kp_peer2 = yip_crypto::generate_keypair();

    // 1. Config parsing rejects duplicate peer aliases (case-insensitive)
    let dup_alias_conf = format!(
        "local_private = {}\n\
         local_public = {}\n\
         device = yip0\n\
         listen = 127.0.0.1:51820\n\
         \n\
         [peer]\n\
         public_key = {}\n\
         alias = my-node\n\
         \n\
         [peer]\n\
         public_key = {}\n\
         alias = MY-NODE\n",
        hex_encode(&kp.private),
        hex_encode(&kp.public),
        hex_encode(&kp_peer1.public),
        hex_encode(&kp_peer2.public),
    );
    let err = yipd::config::Config::parse(&dup_alias_conf);
    assert!(err.is_err());
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("duplicate peer alias"));

    // 2. add_peer_with_transport rejects duplicate peer alias
    let mut pm = yipd::peer_manager::PeerManager::new(
        kp.private,
        kp.public,
        &[],
        yipd::mode::TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    let peer1 = yipd::config::PeerConfig::new(kp_peer1.public, None).with_alias("alice");
    assert!(pm.add_peer_with_transport(peer1, None).is_ok());

    let peer2 = yipd::config::PeerConfig::new(kp_peer2.public, None).with_alias("ALICE");
    let res = pm.add_peer_with_transport(peer2, None);
    assert_eq!(res, Err("duplicate peer alias"));
}
