//! UNIX domain control socket implementation for headless yipd management (#124).
//!
//! Provides a non-blocking UNIX domain socket server speaking newline-delimited JSON
//! for querying daemon status, listing peer telemetry, and dynamically adding/removing peers.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::config::PeerConfig;
use crate::peer_manager::{PeerManager, PeerStats};

/// Inbound control commands received over the UNIX socket.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd")]
pub enum ControlCmd {
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "list_peers")]
    ListPeers,
    #[serde(rename = "add_peer")]
    AddPeer {
        public_key: String,
        endpoint: Option<String>,
    },
    #[serde(rename = "remove_peer")]
    RemovePeer { public_key: String },
}

/// Outbound control command responses returned to clients.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ControlResponse {
    Status {
        ok: bool,
        version: String,
        node_addr: String,
        device: String,
        peers_count: usize,
        uptime_secs: u64,
    },
    ListPeers {
        ok: bool,
        peers: Vec<PeerStats>,
    },
    Ack {
        ok: bool,
        message: String,
    },
    Err {
        ok: bool,
        error: String,
    },
}

/// A request dispatched from a socket client to the main dataplane thread.
pub struct ControlRequest {
    pub cmd: ControlCmd,
    pub responder: Sender<ControlResponse>,
}

/// Controller handle maintained by the dataplane / tunnel event loop.
pub struct ControlHandle {
    rx: Receiver<ControlRequest>,
    _worker: JoinHandle<()>,
    socket_path: PathBuf,
}

impl ControlHandle {
    /// Bind a new UNIX domain socket listener at `path` and spawn the background listener thread.
    pub fn bind(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(false)?;

        let (tx, rx) = channel();
        let socket_path = path.clone();

        let worker = thread::Builder::new()
            .name("yipd-control".into())
            .spawn(move || {
                run_listener(listener, tx);
            })?;

        Ok(Self {
            rx,
            _worker: worker,
            socket_path,
        })
    }

    /// Try to receive the next pending control request without blocking.
    pub fn try_recv(&self) -> Result<ControlRequest, TryRecvError> {
        self.rx.try_recv()
    }

    /// Drain and execute all pending control requests against the provided `PeerManager`.
    pub fn drain_and_dispatch(&self, pm: &mut PeerManager, device_name: &str, start_time: Instant) {
        while let Ok(req) = self.try_recv() {
            let resp = dispatch_cmd(pm, req.cmd, device_name, start_time);
            let _ = req.responder.send(resp);
        }
    }
}

impl Drop for ControlHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Background thread loop accepting connections and servicing client requests.
fn run_listener(listener: UnixListener, req_tx: Sender<ControlRequest>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            break;
        };
        let tx = req_tx.clone();
        thread::spawn(move || {
            handle_client(stream, tx);
        });
    }
}

/// Read newline-delimited JSON commands from a client connection and write responses.
fn handle_client(stream: UnixStream, req_tx: Sender<ControlRequest>) {
    let Ok(mut reader) = stream.try_clone().map(BufReader::new) else {
        return;
    };
    let mut writer = stream;
    let mut line = String::new();

    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let parsed: Result<ControlCmd, _> = serde_json::from_str(trimmed);
        match parsed {
            Ok(cmd) => {
                let (resp_tx, resp_rx) = channel();
                let req = ControlRequest {
                    cmd,
                    responder: resp_tx,
                };
                if req_tx.send(req).is_err() {
                    let err_resp = ControlResponse::Err {
                        ok: false,
                        error: "server shutting down".into(),
                    };
                    let _ = send_response(&mut writer, &err_resp);
                    break;
                }
                match resp_rx.recv() {
                    Ok(resp) => {
                        if send_response(&mut writer, &resp).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let err_resp = ControlResponse::Err {
                            ok: false,
                            error: "request dropped by event loop".into(),
                        };
                        let _ = send_response(&mut writer, &err_resp);
                        break;
                    }
                }
            }
            Err(e) => {
                let err_resp = ControlResponse::Err {
                    ok: false,
                    error: format!("invalid JSON command: {e}"),
                };
                if send_response(&mut writer, &err_resp).is_err() {
                    break;
                }
            }
        }
        line.clear();
    }
}

fn send_response(writer: &mut UnixStream, resp: &ControlResponse) -> std::io::Result<()> {
    let mut json = serde_json::to_string(resp).map_err(|e| std::io::Error::other(e.to_string()))?;
    json.push('\n');
    writer.write_all(json.as_bytes())?;
    writer.flush()
}

/// Synchronously process a command against `PeerManager`.
pub fn dispatch_cmd(
    pm: &mut PeerManager,
    cmd: ControlCmd,
    device_name: &str,
    start_time: Instant,
) -> ControlResponse {
    match cmd {
        ControlCmd::Status => {
            let stats = pm.peer_stats();
            ControlResponse::Status {
                ok: true,
                version: env!("CARGO_PKG_VERSION").into(),
                node_addr: pm.local_addr().to_string(),
                device: device_name.into(),
                peers_count: stats.len(),
                uptime_secs: start_time.elapsed().as_secs(),
            }
        }
        ControlCmd::ListPeers => {
            let peers = pm.peer_stats();
            ControlResponse::ListPeers { ok: true, peers }
        }
        ControlCmd::AddPeer {
            public_key,
            endpoint,
        } => {
            let pk = match crate::config::hex_to_32(&public_key) {
                Ok(k) => k,
                Err(_) => {
                    return ControlResponse::Err {
                        ok: false,
                        error: "invalid public_key hex (must be 64 hex characters)".into(),
                    };
                }
            };
            let ep: Option<SocketAddr> = match endpoint {
                Some(s) => match s.parse() {
                    Ok(a) => Some(a),
                    Err(_) => {
                        return ControlResponse::Err {
                            ok: false,
                            error: "invalid endpoint socket address".into(),
                        };
                    }
                },
                None => None,
            };
            match pm.add_peer(PeerConfig {
                public_key: pk,
                endpoint: ep,
            }) {
                Ok(()) => ControlResponse::Ack {
                    ok: true,
                    message: "peer added".into(),
                },
                Err(e) => ControlResponse::Err {
                    ok: false,
                    error: e.into(),
                },
            }
        }
        ControlCmd::RemovePeer { public_key } => {
            let pk = match crate::config::hex_to_32(&public_key) {
                Ok(k) => k,
                Err(_) => {
                    return ControlResponse::Err {
                        ok: false,
                        error: "invalid public_key hex (must be 64 hex characters)".into(),
                    };
                }
            };
            match pm.remove_peer(&pk) {
                Ok(()) => ControlResponse::Ack {
                    ok: true,
                    message: "peer removed".into(),
                },
                Err(e) => ControlResponse::Err {
                    ok: false,
                    error: e.into(),
                },
            }
        }
    }
}

pub const DEFAULT_CONTROL_SOCKET: &str = "/run/yipd.sock";
pub const FALLBACK_CONTROL_SOCKET: &str = "/tmp/yipd.sock";

/// Resolve the control socket path from an optional override, falling back to
/// `/run/yipd.sock` if present, or `/tmp/yipd.sock`.
pub fn resolve_control_socket(override_path: Option<&Path>) -> PathBuf {
    if let Some(p) = override_path {
        return p.to_path_buf();
    }
    let run_path = Path::new(DEFAULT_CONTROL_SOCKET);
    if run_path.exists() {
        return run_path.to_path_buf();
    }
    let tmp_path = Path::new(FALLBACK_CONTROL_SOCKET);
    if tmp_path.exists() {
        return tmp_path.to_path_buf();
    }
    run_path.to_path_buf()
}

/// Connect to a running yipd daemon over UNIX domain socket and send a control command.
pub fn client_query(socket_path: &Path, cmd: ControlCmd) -> Result<ControlResponse, String> {
    let stream = UnixStream::connect(socket_path).map_err(|e| {
        format!(
            "failed to connect to yipd control socket at {}: {e}",
            socket_path.display()
        )
    })?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;

    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);

    let mut req_str = serde_json::to_string(&cmd).map_err(|e| e.to_string())?;
    req_str.push('\n');
    writer
        .write_all(req_str.as_bytes())
        .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    let mut line = String::new();
    let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if n == 0 || line.trim().is_empty() {
        return Err("empty response received from yipd daemon".into());
    }

    serde_json::from_str(line.trim()).map_err(|e| format!("failed to parse daemon response: {e}"))
}

/// Format bytes as human-readable unit (B, KiB, MiB, GiB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.2} MiB", b / MB)
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Format transfer rate in bits per second (bps, Kbps, Mbps, Gbps).
pub fn format_rate(bytes_per_sec: f64) -> String {
    let bits_per_sec = bytes_per_sec * 8.0;
    if bits_per_sec >= 1_000_000_000.0 {
        format!("{:.2} Gbps", bits_per_sec / 1_000_000_000.0)
    } else if bits_per_sec >= 1_000_000.0 {
        format!("{:.2} Mbps", bits_per_sec / 1_000_000.0)
    } else if bits_per_sec >= 1_000.0 {
        format!("{:.1} Kbps", bits_per_sec / 1_000.0)
    } else {
        format!("{:.0} bps", bits_per_sec)
    }
}

/// Format duration in seconds as human-readable time string.
pub fn format_duration(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Generate a Unicode block sparkline from a series of values.
pub fn sparkline(values: &[f64]) -> String {
    if values.is_empty() {
        return String::new();
    }
    const BARS: [char; 8] = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = values.iter().copied().fold(0.0, f64::max);
    if max <= 0.0 {
        return " ".repeat(values.len());
    }
    values
        .iter()
        .map(|&v| {
            let fraction = (v / max).clamp(0.0, 1.0);
            let idx = ((fraction * (BARS.len() - 1) as f64).round() as usize).min(BARS.len() - 1);
            BARS[idx]
        })
        .collect()
}

/// Query and display daemon status.
pub fn run_cli_status(socket_path: &Path, json: bool) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::Status)?;
    if json {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    match resp {
        ControlResponse::Status {
            ok,
            version,
            node_addr,
            device,
            peers_count,
            uptime_secs,
        } => {
            if !ok {
                return Err("daemon reported status error".into());
            }
            println!("\x1b[1;32m●\x1b[0m \x1b[1myipd\x1b[0m v{version}");
            println!("  Device:     \x1b[1m{device}\x1b[0m");
            println!("  Mesh IPv6:  \x1b[36m{node_addr}\x1b[0m");
            println!("  Uptime:     {}", format_duration(uptime_secs));
            println!("  Peers:      {peers_count} configured");
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

/// Query and display peer table.
pub fn run_cli_peers(socket_path: &Path, json: bool) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::ListPeers)?;
    if json {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    match resp {
        ControlResponse::ListPeers { ok, peers } => {
            if !ok {
                return Err("daemon reported error listing peers".into());
            }
            if peers.is_empty() {
                println!("No peers currently configured.");
                return Ok(());
            }
            println!(
                "\x1b[1;4m{:<24} {:<21} {:<12} {:<15} {:<18} {:<10} {:<12}\x1b[0m",
                "PEER", "ENDPOINT", "STATE", "TRANSPORT", "TX / RX", "FEC PARITY", "FEC RECOVERED"
            );
            for p in peers {
                let ep_str = p
                    .endpoint
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "none".into());
                let traffic = format!(
                    "{} / {}",
                    format_bytes(p.tx_bytes),
                    format_bytes(p.rx_bytes)
                );
                let parity = format!("{}%", p.fec_ratio_pct);
                let rec = format!("{} pkts", p.fec_recovered);
                let state_colored = match p.state.as_str() {
                    "established" => format!("\x1b[32m{}\x1b[0m", p.state),
                    "handshaking" => format!("\x1b[33m{}\x1b[0m", p.state),
                    _ => format!("\x1b[90m{}\x1b[0m", p.state),
                };
                let peer_short = p.node_addr.to_string();
                println!(
                    "{:<24} {:<21} {:<21} {:<15} {:<18} {:<10} {:<12}",
                    peer_short, ep_str, state_colored, p.transport, traffic, parity, rec
                );
            }
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

struct CursorGuard;
impl Drop for CursorGuard {
    fn drop(&mut self) {
        println!("\x1b[?25h\x1b[0m");
        let _ = std::io::stdout().flush();
    }
}

/// Run real-time ANSI terminal top dashboard.
pub fn run_cli_top(socket_path: &Path, interval_ms: u64) -> Result<(), String> {
    let _guard = CursorGuard;
    let mut rate_history: Vec<f64> = Vec::with_capacity(20);
    let mut last_tx = 0u64;
    let mut last_rx = 0u64;
    let mut last_time = Instant::now();
    let mut first_tick = true;

    print!("\x1b[?25l");
    let _ = std::io::stdout().flush();

    loop {
        let status_resp = client_query(socket_path, ControlCmd::Status);
        let peers_resp = client_query(socket_path, ControlCmd::ListPeers);

        let now = Instant::now();
        let elapsed_secs = last_time.elapsed().as_secs_f64().max(0.001);
        last_time = now;

        print!("\x1b[2J\x1b[H");

        match (status_resp, peers_resp) {
            (
                Ok(ControlResponse::Status {
                    version,
                    node_addr,
                    device,
                    peers_count,
                    uptime_secs,
                    ..
                }),
                Ok(ControlResponse::ListPeers { peers, .. }),
            ) => {
                let mut total_tx = 0u64;
                let mut total_rx = 0u64;
                let mut total_fec_rec = 0u64;
                for p in &peers {
                    total_tx += p.tx_bytes;
                    total_rx += p.rx_bytes;
                    total_fec_rec += p.fec_recovered;
                }

                let delta_tx = if first_tick {
                    0.0
                } else {
                    (total_tx.saturating_sub(last_tx)) as f64 / elapsed_secs
                };
                let delta_rx = if first_tick {
                    0.0
                } else {
                    (total_rx.saturating_sub(last_rx)) as f64 / elapsed_secs
                };
                first_tick = false;
                last_tx = total_tx;
                last_rx = total_rx;

                let combined_rate = delta_tx + delta_rx;
                if rate_history.len() >= 20 {
                    rate_history.remove(0);
                }
                rate_history.push(combined_rate);

                let spark = sparkline(&rate_history);

                println!(
                    "\x1b[1;36myipctl top\x1b[0m — \x1b[1myipd\x1b[0m v{version} (Uptime: {})",
                    format_duration(uptime_secs)
                );
                println!(
                    "Device: \x1b[1m{}\x1b[0m  Node: \x1b[32m{}\x1b[0m  Peers: \x1b[1m{}\x1b[0m  FEC Recoveries: \x1b[1;32m{}\x1b[0m",
                    device, node_addr, peers_count, total_fec_rec
                );
                println!(
                    "Traffic: \x1b[34m↑ {}\x1b[0m (Live: {}/s)  \x1b[35m↓ {}\x1b[0m (Live: {}/s)  Spark: [\x1b[33m{}\x1b[0m]",
                    format_bytes(total_tx),
                    format_rate(delta_tx),
                    format_bytes(total_rx),
                    format_rate(delta_rx),
                    spark
                );
                println!("{}", "─".repeat(80));

                println!(
                    "\x1b[1;4m{:<24} {:<21} {:<12} {:<15} {:<18} {:<10} {:<12}\x1b[0m",
                    "PEER",
                    "ENDPOINT",
                    "STATE",
                    "TRANSPORT",
                    "TX / RX",
                    "FEC PARITY",
                    "FEC RECOVERED"
                );
                for p in peers {
                    let ep_str = p
                        .endpoint
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "none".into());
                    let traffic = format!(
                        "{} / {}",
                        format_bytes(p.tx_bytes),
                        format_bytes(p.rx_bytes)
                    );
                    let parity = format!("{}%", p.fec_ratio_pct);
                    let rec = format!("{} pkts", p.fec_recovered);
                    let state_colored = match p.state.as_str() {
                        "established" => format!("\x1b[32m{}\x1b[0m", p.state),
                        "handshaking" => format!("\x1b[33m{}\x1b[0m", p.state),
                        _ => format!("\x1b[90m{}\x1b[0m", p.state),
                    };
                    println!(
                        "{:<24} {:<21} {:<21} {:<15} {:<18} {:<10} {:<12}",
                        p.node_addr.to_string(),
                        ep_str,
                        state_colored,
                        p.transport,
                        traffic,
                        parity,
                        rec
                    );
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                println!("\x1b[1;31mError connecting to yipd control socket:\x1b[0m {e}");
                println!("Retrying in {}ms... (press Ctrl+C to exit)", interval_ms);
            }
            _ => {
                println!("Waiting for daemon telemetry...");
            }
        }

        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_protocol_status_serialization() {
        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();
        let resp = dispatch_cmd(&mut pm, ControlCmd::Status, "yip0", start);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"device\":\"yip0\""));
        assert!(json.contains("\"peers_count\":1"));
    }

    #[test]
    fn control_protocol_add_and_list_peers() {
        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        let new_pk_hex = "02".repeat(32);
        let add_cmd = ControlCmd::AddPeer {
            public_key: new_pk_hex.clone(),
            endpoint: Some("198.51.100.2:51820".into()),
        };
        let resp = dispatch_cmd(&mut pm, add_cmd, "yip0", start);
        assert_eq!(
            resp,
            ControlResponse::Ack {
                ok: true,
                message: "peer added".into()
            }
        );

        let list_cmd = ControlCmd::ListPeers;
        let resp = dispatch_cmd(&mut pm, list_cmd, "yip0", start);
        if let ControlResponse::ListPeers { ok, peers } = resp {
            assert!(ok);
            assert_eq!(peers.len(), 2);
            assert_eq!(peers[1].public_key, [2u8; 32]);
        } else {
            panic!("expected ListPeers response");
        }

        let remove_cmd = ControlCmd::RemovePeer {
            public_key: new_pk_hex,
        };
        let resp = dispatch_cmd(&mut pm, remove_cmd, "yip0", start);
        assert_eq!(
            resp,
            ControlResponse::Ack {
                ok: true,
                message: "peer removed".into()
            }
        );
        assert_eq!(pm.peer_stats().len(), 1);
    }

    #[test]
    fn control_handle_socket_round_trip() {
        let socket_path = format!("/tmp/test_control_{}.sock", std::process::id());
        let handle = ControlHandle::bind(&socket_path).unwrap();

        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        let client = UnixStream::connect(&socket_path).unwrap();
        let mut writer = client.try_clone().unwrap();
        let mut reader = BufReader::new(client);

        // Send status request
        writer.write_all(b"{\"cmd\":\"status\"}\n").unwrap();
        writer.flush().unwrap();

        // Wait for request in main thread
        let mut req = None;
        for _ in 0..50 {
            if let Ok(r) = handle.try_recv() {
                req = Some(r);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let req = req.expect("request should arrive at handle within 500ms");
        let resp = dispatch_cmd(&mut pm, req.cmd, "yip0", start);
        req.responder.send(resp).unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("\"device\":\"yip0\""));
    }

    #[test]
    fn test_format_helpers_and_sparkline() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(1048576 * 5), "5.00 MiB");
        assert_eq!(format_bytes(1073741824 * 3), "3.00 GiB");

        assert_eq!(format_rate(100.0), "800 bps");
        assert_eq!(format_rate(12500.0), "100.0 Kbps");
        assert_eq!(format_rate(1250000.0), "10.00 Mbps");
        assert_eq!(format_rate(125000000.0), "1.00 Gbps");

        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(3665), "1h 1m 5s");
        assert_eq!(format_duration(86400 * 2 + 3600 * 3), "2d 3h 0m");

        let values = [0.0, 10.0, 50.0, 100.0];
        let spark = sparkline(&values);
        assert_eq!(spark.chars().count(), 4);
        assert_eq!(spark.chars().next().unwrap(), ' ');
        assert_eq!(spark.chars().last().unwrap(), '█');
    }
}
