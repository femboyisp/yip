//! End-to-end integration tests for Prometheus and OpenTelemetry telemetry
//! exposition over the UNIX control socket and embedded HTTP scraper.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use yip_io::poll::Dispatch;
use yipd::config::PeerConfig;
use yipd::control::{client_query, run_cli_metrics, ControlCmd, ControlHandle, ControlResponse};
use yipd::metrics::MetricsHttpServer;
use yipd::mode::TunnelMode;
use yipd::peer_manager::{PeerManager, PeerStats};

fn make_test_peer_manager() -> PeerManager {
    let kp = yip_crypto::generate_keypair();
    let peer = PeerConfig {
        public_key: [1u8; 32],
        endpoint: Some("10.0.0.1:1000".parse().unwrap()),
    };
    PeerManager::new(
        kp.private,
        kp.public,
        &[peer],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    )
}

struct Harness {
    socket_path: String,
    pm: PeerManager,
    cached_stats: Arc<Mutex<Vec<PeerStats>>>,
    now_ms: u64,
}

impl Harness {
    fn new(test_name: &str) -> Self {
        let socket_path = format!(
            "/tmp/yip_metrics_test_{}_{}_{}.sock",
            test_name,
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        );
        let _ = std::fs::remove_file(&socket_path);

        let mut pm = make_test_peer_manager();
        let handle = ControlHandle::bind(&socket_path)
            .unwrap_or_else(|e| panic!("failed to bind control socket {socket_path}: {e}"));
        pm.set_control(Some(handle), "yip-test-dev".into(), Instant::now());

        let cached_stats = Arc::new(Mutex::new(pm.peer_stats()));

        Self {
            socket_path,
            pm,
            cached_stats,
            now_ms: 1_000,
        }
    }

    fn socket_path(&self) -> &str {
        &self.socket_path
    }

    fn refresh_cached_stats(&mut self) {
        let stats = self.pm.peer_stats();
        let mut lock = self.cached_stats.lock().unwrap();
        *lock = stats;
    }

    fn drive_ticks(&mut self, iterations: usize) {
        for _ in 0..iterations {
            let _ = self.pm.tick(self.now_ms);
            self.now_ms = self.now_ms.saturating_add(5);
            std::thread::sleep(Duration::from_millis(2));
        }
        self.refresh_cached_stats();
    }

    fn query_cmd(&mut self, cmd: ControlCmd) -> Result<ControlResponse, String> {
        let path = self.socket_path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let client_thread = std::thread::spawn(move || {
            let res = client_query(Path::new(&path), cmd);
            let _ = tx.send(res);
        });

        let mut result = None;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match rx.try_recv() {
                Ok(res) => {
                    result = Some(res);
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    let _ = self.pm.tick(self.now_ms);
                    self.now_ms = self.now_ms.saturating_add(5);
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }

        client_thread.join().expect("client thread join failed");
        self.refresh_cached_stats();
        result.ok_or_else(|| "timed out waiting for response".to_string())?
    }

    fn query_cli_metrics(&mut self, json: bool) -> Result<(), String> {
        let path = self.socket_path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let client_thread = std::thread::spawn(move || {
            let res = run_cli_metrics(Path::new(&path), json);
            let _ = tx.send(res);
        });

        let mut result = None;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match rx.try_recv() {
                Ok(res) => {
                    result = Some(res);
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    let _ = self.pm.tick(self.now_ms);
                    self.now_ms = self.now_ms.saturating_add(5);
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }

        client_thread.join().expect("client thread join failed");
        self.refresh_cached_stats();
        result.ok_or_else(|| "timed out waiting for response".to_string())?
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
) -> (String, Vec<(String, String)>, String) {
    let mut stream = TcpStream::connect(addr)
        .unwrap_or_else(|e| panic!("failed to connect to HTTP scraper at {addr}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("set write timeout");

    let req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write request");
    stream.flush().expect("flush request");

    let mut response_str = String::new();
    stream
        .read_to_string(&mut response_str)
        .expect("read response");

    let mut parts = response_str.splitn(2, "\r\n\r\n");
    let header_part = parts.next().unwrap_or("");
    let body_part = parts.next().unwrap_or("").to_string();

    let mut lines = header_part.lines();
    let status_line = lines.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    (status_line, headers, body_part)
}

#[test]
fn test_live_unix_control_socket_get_metrics() {
    let mut harness = Harness::new("ctrl_metrics");
    let socket_path = harness.socket_path().to_string();

    // 1. Raw UNIX domain socket JSON query
    let stream = UnixStream::connect(&socket_path).expect("connect to control socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("set write timeout");

    let mut writer = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(stream);

    writer
        .write_all(b"{\"cmd\":\"get_metrics\"}\n")
        .expect("write cmd");
    writer.flush().expect("flush cmd");

    harness.drive_ticks(50);

    let mut raw_resp_line = String::new();
    reader
        .read_line(&mut raw_resp_line)
        .expect("read response line");
    assert!(
        raw_resp_line.contains("\"ok\":true"),
        "raw response missing ok:true: {raw_resp_line}"
    );
    assert!(
        raw_resp_line.contains("\"metrics\":"),
        "raw response missing metrics object: {raw_resp_line}"
    );
    assert!(
        raw_resp_line.contains("\"prometheus\":"),
        "raw response missing prometheus string: {raw_resp_line}"
    );

    let parsed: ControlResponse =
        serde_json::from_str(raw_resp_line.trim()).expect("deserialize raw control response");
    match parsed {
        ControlResponse::Metrics {
            ok,
            metrics,
            prometheus,
        } => {
            assert!(ok);
            assert_eq!(metrics.traffic.tx_bytes, 0);
            assert_eq!(metrics.traffic.rx_bytes, 0);
            assert_eq!(metrics.peers.total, 1);
            assert!(
                prometheus.contains("# HELP yip_traffic_tx_bytes_total Total bytes transmitted")
            );
            assert!(prometheus.contains("# TYPE yip_traffic_tx_bytes_total counter"));
            assert!(prometheus.contains("yip_traffic_tx_bytes_total 0"));
            assert!(prometheus.contains("yip_peers_total 1"));
        }
        other => panic!("expected ControlResponse::Metrics variant, got: {other:?}"),
    }

    // 2. Client query dispatch
    let resp = harness
        .query_cmd(ControlCmd::GetMetrics { peer: None })
        .expect("client_query GetMetrics failed");
    match resp {
        ControlResponse::Metrics {
            ok,
            metrics,
            prometheus,
        } => {
            assert!(ok);
            assert_eq!(metrics.peers.total, 1);
            assert!(prometheus.contains("yip_peers_total 1"));
        }
        other => panic!("expected ControlResponse::Metrics variant, got: {other:?}"),
    }

    // 3. CLI runner query dispatch
    assert!(
        harness.query_cli_metrics(false).is_ok(),
        "run_cli_metrics raw text failed"
    );
    assert!(
        harness.query_cli_metrics(true).is_ok(),
        "run_cli_metrics JSON failed"
    );

    // 4. Targeted peer query
    let resp_targeted = harness
        .query_cmd(ControlCmd::GetMetrics {
            peer: Some("10.0.0.1".into()),
        })
        .expect("targeted peer query failed");
    match resp_targeted {
        ControlResponse::Metrics { ok, metrics, .. } => {
            assert!(ok);
            assert!(metrics.peers.list.len() <= 1);
        }
        other => panic!("expected ControlResponse::Metrics variant, got: {other:?}"),
    }
}

#[test]
fn test_live_ephemeral_http_scraper_endpoints() {
    let harness = Harness::new("http_scraper");
    let registry = harness.pm.metrics();
    let cached_stats = Arc::clone(&harness.cached_stats);

    let server = MetricsHttpServer::start(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        Box::new(move || cached_stats.lock().unwrap().clone()),
    )
    .expect("start MetricsHttpServer");

    let addr = server.local_addr();
    assert_ne!(addr.port(), 0);

    // 1. GET /healthz
    let (status, headers, body) = http_request(addr, "GET", "/healthz");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(body, "ok");
    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str());
    assert_eq!(content_type, Some("text/plain; charset=utf-8"));
    let content_length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .map(|(_, v)| v.as_str());
    assert_eq!(content_length, Some("2"));

    // 2. HEAD /healthz
    let (head_status, head_headers, head_body) = http_request(addr, "HEAD", "/healthz");
    assert_eq!(head_status, "HTTP/1.1 200 OK");
    assert_eq!(head_body, "");
    let head_content_len = head_headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .map(|(_, v)| v.as_str());
    assert_eq!(head_content_len, Some("2"));

    // 3. GET /metrics
    let (m_status, m_headers, m_body) = http_request(addr, "GET", "/metrics");
    assert_eq!(m_status, "HTTP/1.1 200 OK");
    let m_content_type = m_headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .expect("missing content-type header");
    assert!(
        m_content_type.contains("text/plain; version=0.0.4"),
        "expected text/plain; version=0.0.4 in content-type, got: {m_content_type}"
    );

    // Verify Prometheus format compliance
    assert!(m_body.contains("# HELP yip_uptime_seconds Process runtime in seconds"));
    assert!(m_body.contains("# TYPE yip_uptime_seconds counter"));
    assert!(m_body.contains("# HELP yip_peers_active Count of actively handshaked mesh peers"));
    assert!(m_body.contains("# TYPE yip_peers_active gauge"));
    assert!(m_body.contains("# HELP yip_traffic_tx_bytes_total Total bytes transmitted"));
    assert!(m_body.contains("# TYPE yip_traffic_tx_bytes_total counter"));
    assert!(m_body
        .contains("# HELP yip_traffic_rx_bytes_total Total payload and control bytes received"));
    assert!(m_body.contains("# TYPE yip_traffic_rx_bytes_total counter"));
    assert!(m_body.contains("# HELP yip_traffic_tx_packets_total Total packets dispatched"));
    assert!(m_body.contains("# TYPE yip_traffic_tx_packets_total counter"));
    assert!(m_body.contains("# HELP yip_traffic_rx_packets_total Total packets received"));
    assert!(m_body.contains("# TYPE yip_traffic_rx_packets_total counter"));
    assert!(m_body.contains("# HELP yip_traffic_dropped_packets_total Packets dropped due to route errors or queue overflow"));
    assert!(m_body.contains("# TYPE yip_traffic_dropped_packets_total counter"));
    assert!(
        m_body.ends_with('\n'),
        "prometheus exposition must end with newline"
    );

    // 4. 404 Not Found on unknown path
    let (nf_status, _, nf_body) = http_request(addr, "GET", "/unknown_route");
    assert_eq!(nf_status, "HTTP/1.1 404 Not Found");
    assert_eq!(nf_body, "Not Found");

    // 5. 405 Method Not Allowed on invalid method
    let (na_status, _, na_body) = http_request(addr, "POST", "/metrics");
    assert_eq!(na_status, "HTTP/1.1 405 Method Not Allowed");
    assert_eq!(na_body, "Method Not Allowed");

    server.stop();
}

#[test]
fn test_monotonic_counter_progression_under_simulated_packet_traffic() {
    let mut harness = Harness::new("monotonic_traffic");
    let registry = harness.pm.metrics();
    let cached_stats = Arc::clone(&harness.cached_stats);

    let server = MetricsHttpServer::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::clone(&registry),
        Box::new(move || cached_stats.lock().unwrap().clone()),
    )
    .expect("start MetricsHttpServer");
    let http_addr = server.local_addr();

    // ── Phase 0: Baseline Verification ──────────────────────────────────
    let initial_resp = harness
        .query_cmd(ControlCmd::GetMetrics { peer: None })
        .expect("initial query");
    let initial_metrics = match initial_resp {
        ControlResponse::Metrics { metrics, .. } => metrics,
        other => panic!("expected ControlResponse::Metrics, got: {other:?}"),
    };
    assert_eq!(initial_metrics.traffic.tx_bytes, 0);
    assert_eq!(initial_metrics.traffic.tx_packets, 0);
    assert_eq!(initial_metrics.traffic.rx_bytes, 0);
    assert_eq!(initial_metrics.traffic.rx_packets, 0);
    assert_eq!(initial_metrics.traffic.dropped_packets, 0);

    let (_, _, initial_http_body) = http_request(http_addr, "GET", "/metrics");
    assert!(initial_http_body.contains("yip_traffic_tx_bytes_total 0"));
    assert!(initial_http_body.contains("yip_traffic_rx_bytes_total 0"));

    // ── Phase 1: Synthetic Traffic Burst 1 ──────────────────────────────
    {
        // Dispatched 3 test TX packets
        harness.pm.record_test_tx_packet(1420);
        harness.pm.record_test_tx_packet(1420);
        harness.pm.record_test_tx_packet(1420);

        // Ingress 2 test RX packets
        harness.pm.metrics().record_rx(2840, 2);

        // Ingress malformed/empty UDP packet to trigger data plane drop
        let dummy_addr: SocketAddr = "192.0.2.1:54321".parse().unwrap();
        let _ = harness.pm.on_udp(dummy_addr, &[], 0);

        // FEC and crypto events
        harness.pm.metrics().record_fec_tx(10);
        harness.pm.metrics().record_fec_recovered(8);
        harness.pm.metrics().record_daita_padding(256);
        harness.pm.metrics().record_handshake_success();
        harness.pm.metrics().record_rekey();
    }
    harness.refresh_cached_stats();

    // Verify over UNIX control socket
    let p1_resp = harness
        .query_cmd(ControlCmd::GetMetrics { peer: None })
        .expect("phase 1 query");
    let p1_metrics = match p1_resp {
        ControlResponse::Metrics {
            metrics,
            prometheus,
            ..
        } => {
            assert!(prometheus.contains("yip_traffic_tx_bytes_total 4260"));
            assert!(prometheus.contains("yip_traffic_tx_packets_total 3"));
            assert!(prometheus.contains("yip_traffic_rx_bytes_total 2840"));
            assert!(prometheus.contains("yip_traffic_rx_packets_total 2"));
            assert!(prometheus.contains("yip_traffic_dropped_packets_total 1"));
            assert!(prometheus.contains("yip_fec_symbols_tx_total 10"));
            assert!(prometheus.contains("yip_fec_recovered_symbols_total 8"));
            assert!(prometheus.contains("yip_daita_padding_bytes_total 256"));
            assert!(prometheus.contains("yip_crypto_handshakes_total 1"));
            assert!(prometheus.contains("yip_crypto_rekeys_total 1"));
            metrics
        }
        other => panic!("expected ControlResponse::Metrics, got: {other:?}"),
    };

    assert_eq!(p1_metrics.traffic.tx_bytes, 4260);
    assert_eq!(p1_metrics.traffic.tx_packets, 3);
    assert_eq!(p1_metrics.traffic.rx_bytes, 2840);
    assert_eq!(p1_metrics.traffic.rx_packets, 2);
    assert_eq!(p1_metrics.traffic.dropped_packets, 1);
    assert_eq!(p1_metrics.fec.symbols_tx, 10);
    assert_eq!(p1_metrics.fec.recovered_symbols, 8);
    assert_eq!(p1_metrics.daita.padding_bytes, 256);
    assert_eq!(p1_metrics.crypto.handshakes, 1);
    assert_eq!(p1_metrics.crypto.rekeys, 1);

    // Verify over HTTP endpoint
    let (_, _, p1_http_body) = http_request(http_addr, "GET", "/metrics");
    assert!(p1_http_body.contains("yip_traffic_tx_bytes_total 4260"));
    assert!(p1_http_body.contains("yip_traffic_tx_packets_total 3"));
    assert!(p1_http_body.contains("yip_traffic_rx_bytes_total 2840"));
    assert!(p1_http_body.contains("yip_traffic_rx_packets_total 2"));
    assert!(p1_http_body.contains("yip_traffic_dropped_packets_total 1"));
    assert!(p1_http_body.contains("yip_fec_symbols_tx_total 10"));
    assert!(p1_http_body.contains("yip_fec_recovered_symbols_total 8"));
    assert!(p1_http_body.contains("yip_crypto_rekeys_total 1"));

    // ── Phase 2: Synthetic Traffic Burst 2 (Monotonic Verification) ─────
    {
        // Additional 2 TX packets
        harness.pm.record_test_tx_packet(1000);
        harness.pm.record_test_tx_packet(1000);

        // Additional 1 RX packet
        harness.pm.metrics().record_rx(1500, 1);

        // Additional dropped packet
        harness.pm.metrics().record_drop(2);

        // Additional rekey
        harness.pm.metrics().record_rekey();
    }
    harness.refresh_cached_stats();

    let p2_resp = harness
        .query_cmd(ControlCmd::GetMetrics { peer: None })
        .expect("phase 2 query");
    let p2_metrics = match p2_resp {
        ControlResponse::Metrics { metrics, .. } => metrics,
        other => panic!("expected ControlResponse::Metrics, got: {other:?}"),
    };

    // Strict monotonic progression assertions
    assert!(
        p2_metrics.traffic.tx_bytes > p1_metrics.traffic.tx_bytes,
        "tx_bytes must strictly increase: {} <= {}",
        p2_metrics.traffic.tx_bytes,
        p1_metrics.traffic.tx_bytes
    );
    assert_eq!(p2_metrics.traffic.tx_bytes, 6260);

    assert!(
        p2_metrics.traffic.tx_packets > p1_metrics.traffic.tx_packets,
        "tx_packets must strictly increase: {} <= {}",
        p2_metrics.traffic.tx_packets,
        p1_metrics.traffic.tx_packets
    );
    assert_eq!(p2_metrics.traffic.tx_packets, 5);

    assert!(
        p2_metrics.traffic.rx_bytes > p1_metrics.traffic.rx_bytes,
        "rx_bytes must strictly increase: {} <= {}",
        p2_metrics.traffic.rx_bytes,
        p1_metrics.traffic.rx_bytes
    );
    assert_eq!(p2_metrics.traffic.rx_bytes, 4340);

    assert!(
        p2_metrics.traffic.rx_packets > p1_metrics.traffic.rx_packets,
        "rx_packets must strictly increase: {} <= {}",
        p2_metrics.traffic.rx_packets,
        p1_metrics.traffic.rx_packets
    );
    assert_eq!(p2_metrics.traffic.rx_packets, 3);

    assert!(
        p2_metrics.traffic.dropped_packets > p1_metrics.traffic.dropped_packets,
        "dropped_packets must strictly increase: {} <= {}",
        p2_metrics.traffic.dropped_packets,
        p1_metrics.traffic.dropped_packets
    );
    assert_eq!(p2_metrics.traffic.dropped_packets, 3);

    assert!(
        p2_metrics.crypto.rekeys > p1_metrics.crypto.rekeys,
        "rekeys must strictly increase: {} <= {}",
        p2_metrics.crypto.rekeys,
        p1_metrics.crypto.rekeys
    );
    assert_eq!(p2_metrics.crypto.rekeys, 2);

    // Verify over HTTP endpoint matches exact monotonically updated values
    let (_, _, p2_http_body) = http_request(http_addr, "GET", "/metrics");
    assert!(p2_http_body.contains("yip_traffic_tx_bytes_total 6260"));
    assert!(p2_http_body.contains("yip_traffic_tx_packets_total 5"));
    assert!(p2_http_body.contains("yip_traffic_rx_bytes_total 4340"));
    assert!(p2_http_body.contains("yip_traffic_rx_packets_total 3"));
    assert!(p2_http_body.contains("yip_traffic_dropped_packets_total 3"));
    assert!(p2_http_body.contains("yip_crypto_rekeys_total 2"));

    // ── Phase 3: Concurrent Multi-Threaded Progression ─────────────────
    let thread_count = 4;
    let ops_per_thread = 50;
    let bytes_per_op = 100u64;

    let mut handles = Vec::new();
    for _ in 0..thread_count {
        let reg = Arc::clone(&registry);
        handles.push(std::thread::spawn(move || {
            for _ in 0..ops_per_thread {
                reg.record_tx(bytes_per_op, 1);
                reg.record_rx(bytes_per_op, 1);
            }
        }));
    }

    for h in handles {
        h.join().expect("worker thread failed");
    }
    harness.refresh_cached_stats();

    let p3_resp = harness
        .query_cmd(ControlCmd::GetMetrics { peer: None })
        .expect("phase 3 query");
    let p3_metrics = match p3_resp {
        ControlResponse::Metrics { metrics, .. } => metrics,
        other => panic!("expected ControlResponse::Metrics, got: {other:?}"),
    };

    let expected_added_bytes = thread_count as u64 * ops_per_thread as u64 * bytes_per_op;
    let expected_added_packets = thread_count as u64 * ops_per_thread as u64;

    assert_eq!(
        p3_metrics.traffic.tx_bytes,
        p2_metrics.traffic.tx_bytes + expected_added_bytes
    );
    assert_eq!(
        p3_metrics.traffic.tx_packets,
        p2_metrics.traffic.tx_packets + expected_added_packets
    );
    assert_eq!(
        p3_metrics.traffic.rx_bytes,
        p2_metrics.traffic.rx_bytes + expected_added_bytes
    );
    assert_eq!(
        p3_metrics.traffic.rx_packets,
        p2_metrics.traffic.rx_packets + expected_added_packets
    );

    // Verify consistency between control query and HTTP scraper under final counts
    let (_, _, p3_http_body) = http_request(http_addr, "GET", "/metrics");
    let expected_tx_str = format!("yip_traffic_tx_bytes_total {}", p3_metrics.traffic.tx_bytes);
    let expected_rx_str = format!("yip_traffic_rx_bytes_total {}", p3_metrics.traffic.rx_bytes);
    assert!(
        p3_http_body.contains(&expected_tx_str),
        "HTTP body missing {expected_tx_str}"
    );
    assert!(
        p3_http_body.contains(&expected_rx_str),
        "HTTP body missing {expected_rx_str}"
    );

    server.stop();
}

#[test]
fn test_metrics_registry_cached_peer_stats_fallback_in_http_scraper() {
    let registry = Arc::new(yipd::metrics::MetricsRegistry::new());
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Start server with an empty stats closure (simulating production fallback)
    let server = MetricsHttpServer::start(listen_addr, Arc::clone(&registry), Box::new(Vec::new))
        .expect("failed to start metrics HTTP server");
    let http_addr = server.local_addr();

    // Initial scrape: no peers cached yet, active should be 0
    let (status, _, body) = http_request(http_addr, "GET", "/metrics");
    assert!(status.contains("200 OK"));
    assert!(body.contains("yip_peers_active 0"));
    assert!(body.contains("yip_peers_total 0"));

    // Update peer stats via MetricsRegistry::update_peer_stats
    let peer = PeerStats {
        public_key: [7u8; 32],
        endpoint: Some("192.168.1.100:51820".parse().unwrap()),
        node_addr: "fd00::7".parse().unwrap(),
        state: "established".to_string(),
        last_activity_ms: 12345,
        tx_bytes: 54321,
        rx_bytes: 12345,
        tx_packets: 42,
        rx_packets: 24,
        fec_recovered: 5,
        transport: "Direct UDP".to_string(),
        rtt_ms: Some(15),
        fec_ratio_pct: 3,
        cert_status: "CA Valid".to_string(),
    };
    registry.update_peer_stats(vec![peer]);

    // Scrape again: even though stats_fn returns empty, registry cached stats fallback must populate metrics
    let (status2, _, body2) = http_request(http_addr, "GET", "/metrics");
    assert!(status2.contains("200 OK"));
    assert!(body2.contains("yip_peers_active 1"));
    assert!(body2.contains("yip_peers_total 1"));
    assert!(
        body2.contains("yip_peer_tx_bytes_total{peer=\"fd00::7\",transport=\"Direct UDP\"} 54321")
    );
    assert!(
        body2.contains("yip_peer_rtt_milliseconds{peer=\"fd00::7\",transport=\"Direct UDP\"} 15")
    );

    // Also verify get_cached_peer_stats
    let cached = registry.get_cached_peer_stats();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].tx_bytes, 54321);

    server.stop();
}

#[test]
fn test_metrics_http_server_bounded_concurrency_and_healthz() {
    let registry = Arc::new(yipd::metrics::MetricsRegistry::new());
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = MetricsHttpServer::start(listen_addr, Arc::clone(&registry), Box::new(Vec::new))
        .expect("failed to start metrics HTTP server");
    let http_addr = server.local_addr();

    assert_eq!(yipd::metrics::MAX_CONCURRENT_HTTP_CLIENTS, 16);
    assert_eq!(server.active_connections(), 0);

    let (status, _, body) = http_request(http_addr, "GET", "/healthz");
    assert!(status.contains("200 OK"));
    assert_eq!(body, "ok");

    server.stop();
}
