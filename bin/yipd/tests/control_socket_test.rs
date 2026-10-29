//! Integration test for UNIX domain control socket and headless mode (#124).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use yip_io::poll::Dispatch;

#[test]
fn control_socket_tick_integration() {
    let socket_path = format!("/tmp/test_control_int_{}.sock", std::process::id());

    let kp = yip_crypto::generate_keypair();
    let peer = yipd::config::PeerConfig {
        public_key: [1u8; 32],
        endpoint: Some("10.0.0.1:1000".parse().unwrap()),
    };
    let mut pm = yipd::peer_manager::PeerManager::new(
        kp.private,
        kp.public,
        &[peer],
        yipd::mode::TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    let handle = yipd::control::ControlHandle::bind(&socket_path).unwrap();
    pm.set_control(Some(handle), "yip-test0".into(), std::time::Instant::now());

    // Connect client
    let stream = UnixStream::connect(&socket_path).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    // 1. Query status
    writer.write_all(b"{\"cmd\":\"status\"}\n").unwrap();
    writer.flush().unwrap();

    // Drive tick until request processed
    let mut line = String::new();
    for _ in 0..50 {
        let _ = pm.tick(1_000);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"device\":\"yip-test0\""));
    assert!(line.contains("\"peers_count\":1"));

    // 2. Add peer dynamically
    let new_pk_hex = "bb".repeat(32);
    let add_json = format!(
        "{{\"cmd\":\"add_peer\",\"public_key\":\"{}\",\"endpoint\":\"10.42.0.1:443\"}}\n",
        new_pk_hex
    );
    writer.write_all(add_json.as_bytes()).unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_010);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"message\":\"peer added\""));

    // 3. List peers
    writer.write_all(b"{\"cmd\":\"list_peers\"}\n").unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_020);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"peers\":"));
    assert!(line.contains("\"10.42.0.1:443\""));

    // 4. Remove peer dynamically
    let rem_json = format!(
        "{{\"cmd\":\"remove_peer\",\"public_key\":\"{}\"}}\n",
        new_pk_hex
    );
    writer.write_all(rem_json.as_bytes()).unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_030);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"message\":\"peer removed\""));

    // 5. Query FEC status over control socket
    writer.write_all(b"{\"cmd\":\"get_fec_status\"}\n").unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_040);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"preset\":\"adaptive\""));
    assert!(line.contains("\"redundancy_pct\":12"));

    // 6. Set FEC configuration to hostile preset with custom redundancy
    writer
        .write_all(b"{\"cmd\":\"set_fec_config\",\"preset\":\"hostile\",\"redundancy_pct\":35}\n")
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_050);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("FEC configuration updated"));

    // 7. Verify updated FEC status over control socket
    writer.write_all(b"{\"cmd\":\"get_fec_status\"}\n").unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_060);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"redundancy_pct\":35"));
    assert_eq!(pm.fec_config().redundancy_pct, 35);

    // 8. Query DAITA status over control socket
    writer
        .write_all(b"{\"cmd\":\"get_daita_status\"}\n")
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_070);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"preset\":\"off\""));

    // 9. Reconfigure DAITA defense via set_daita_config
    writer
        .write_all(
            b"{\"cmd\":\"set_daita_config\",\"preset\":\"balanced\",\"cover_interval_ms\":250}\n",
        )
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_080);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("DAITA traffic defense configuration updated"));

    // 10. Verify updated DAITA status
    writer
        .write_all(b"{\"cmd\":\"get_daita_status\"}\n")
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_090);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"preset\":\"balanced\""));
    assert!(line.contains("\"cover_interval_ms\":250"));
    assert_eq!(
        pm.traffic_defense.preset,
        yip_obf::TrafficDefensePreset::Balanced
    );
    assert_eq!(pm.traffic_defense.cover_interval_ms, Some(250));

    // 11. Query live routing table via get_routes (#183)
    writer.write_all(b"{\"cmd\":\"get_routes\"}\n").unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_100);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"prefix\":"));
    assert!(line.contains("\"mtu\":1420"));
    assert!(line.contains("\"margin\":80"));

    // 12. Query mesh topology graph via get_topology (#183)
    writer.write_all(b"{\"cmd\":\"get_topology\"}\n").unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_110);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"total_peers\":"));
    assert!(line.contains("\"is_self\":true"));
    assert!(line.contains("\"kem_algo\":\"ML-KEM-768\""));

    // 13. Query initial split-tunnel status via get_split_tunnel (#184)
    writer
        .write_all(b"{\"cmd\":\"get_split_tunnel\"}\n")
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_120);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"enabled\":false"));
    assert!(line.contains("\"mode\":\"exclude\""));

    // 14. Reconfigure split tunnel via set_split_tunnel (#184)
    writer
        .write_all(
            b"{\"cmd\":\"set_split_tunnel\",\"enabled\":true,\"mode\":\"exclude\",\"cidrs\":[\"10.0.0.0/8\",\"192.168.0.0/16\"],\"domains\":[\"local\",\"corp\"]}\n",
        )
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_130);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("split-tunnel configuration updated"));

    // 15. Verify updated split tunnel status (#184)
    writer
        .write_all(b"{\"cmd\":\"get_split_tunnel\"}\n")
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_140);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"enabled\":true"));
    assert!(line.contains("\"mode\":\"exclude\""));
    assert!(line.contains("\"cidrs\":[\"10.0.0.0/8\",\"192.168.0.0/16\"]"));
    assert!(line.contains("\"domains\":[\"local\",\"corp\"]"));
    assert!(pm.split_tunnel.enabled);
    assert_eq!(pm.split_tunnel.cidrs.len(), 2);

    // 16. Query trace_path to peer (#187)
    writer
        .write_all(b"{\"cmd\":\"trace_path\",\"peer_node_id\":\"0101010101010101\"}\n")
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_150);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"target\":\"0101010101010101\""));
    assert!(line.contains("\"reachable\":true"));
    assert!(line.contains("\"hops\":"));
    assert!(line.contains("\"is_direct\":true"));

    // 17. Query ping_peer to peer (#187)
    writer
        .write_all(
            b"{\"cmd\":\"ping_peer\",\"peer_node_id\":\"0101010101010101\",\"count\":3,\"timeout_ms\":2000}\n",
        )
        .unwrap();
    writer.flush().unwrap();

    for _ in 0..50 {
        let _ = pm.tick(1_160);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"target\":\"0101010101010101\""));
    assert!(line.contains("\"sent\":3"));
    assert!(line.contains("\"received\":3"));
    assert!(line.contains("\"packet_loss_pct\":0.0"));
    assert!(line.contains("\"samples\":"));
}
