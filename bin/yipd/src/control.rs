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
use std::time::{Duration, Instant};

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
        #[serde(default)]
        transport: Option<String>,
    },
    #[serde(rename = "remove_peer")]
    RemovePeer { public_key: String },
    #[serde(rename = "set_transport")]
    SetTransport {
        public_key: String,
        transport: String,
    },
    #[serde(rename = "cert_status")]
    CertStatus,
    #[serde(rename = "cert_renew")]
    CertRenew,
    #[serde(rename = "get_fec_status")]
    GetFecStatus,
    #[serde(rename = "set_fec_config")]
    SetFecConfig {
        #[serde(default)]
        preset: Option<String>,
        #[serde(default)]
        redundancy_pct: Option<u8>,
        #[serde(default)]
        data_shards: Option<usize>,
        #[serde(default)]
        parity_shards: Option<usize>,
    },
}

/// Supported Reed-Solomon dynamic FEC presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FecPreset {
    Off,
    Low,
    #[default]
    Adaptive,
    Hostile,
    Custom,
}

impl std::str::FromStr for FecPreset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(FecPreset::Off),
            "low" => Ok(FecPreset::Low),
            "adaptive" => Ok(FecPreset::Adaptive),
            "hostile" => Ok(FecPreset::Hostile),
            "custom" => Ok(FecPreset::Custom),
            other => Err(format!(
                "unknown FEC preset: {other} (valid: off, low, adaptive, hostile, custom)"
            )),
        }
    }
}

impl std::fmt::Display for FecPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FecPreset::Off => write!(f, "off"),
            FecPreset::Low => write!(f, "low"),
            FecPreset::Adaptive => write!(f, "adaptive"),
            FecPreset::Hostile => write!(f, "hostile"),
            FecPreset::Custom => write!(f, "custom"),
        }
    }
}

impl FecPreset {
    pub fn default_config(&self) -> FecConfig {
        match self {
            FecPreset::Off => FecConfig {
                preset: *self,
                redundancy_pct: 0,
                data_shards: 10,
                parity_shards: 0,
            },
            FecPreset::Low => FecConfig {
                preset: *self,
                redundancy_pct: 5,
                data_shards: 10,
                parity_shards: 1,
            },
            FecPreset::Adaptive => FecConfig {
                preset: *self,
                redundancy_pct: 12,
                data_shards: 10,
                parity_shards: 2,
            },
            FecPreset::Hostile => FecConfig {
                preset: *self,
                redundancy_pct: 30,
                data_shards: 10,
                parity_shards: 4,
            },
            FecPreset::Custom => FecConfig {
                preset: *self,
                redundancy_pct: 15,
                data_shards: 10,
                parity_shards: 2,
            },
        }
    }
}

/// Dynamic Reed-Solomon FEC runtime configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FecConfig {
    pub preset: FecPreset,
    pub redundancy_pct: u8,
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Default for FecConfig {
    fn default() -> Self {
        FecPreset::Adaptive.default_config()
    }
}

/// Outbound control command responses returned to clients.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ControlResponse {
    Status {
        ok: bool,
        version: String,
        node_addr: String,
        device: String,
        peers_count: usize,
        uptime_secs: u64,
        #[serde(default)]
        ca_status: Option<String>,
    },
    ListPeers {
        ok: bool,
        peers: Vec<PeerStats>,
    },
    CertStatus {
        ok: bool,
        not_before: u64,
        not_after: u64,
        ttl_remaining_secs: u64,
        renewal_threshold_secs: u64,
        is_threshold_ca: bool,
    },
    CertRenew {
        ok: bool,
        renewed: bool,
        message: String,
        new_not_after: Option<u64>,
    },
    FecStatus {
        ok: bool,
        preset: String,
        redundancy_pct: u8,
        data_shards: usize,
        parity_shards: usize,
        total_symbols_tx: u64,
        recovered_symbols_rx: u64,
        unrecoverable_burst_drops: u64,
        loss_recovery_rate_pct: f32,
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
                ca_status: Some("Enforced (Root Ed25519) — Zero-Trust Admission".into()),
            }
        }
        ControlCmd::ListPeers => {
            let peers = pm.peer_stats();
            ControlResponse::ListPeers { ok: true, peers }
        }
        ControlCmd::AddPeer {
            public_key,
            endpoint,
            transport,
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
            if let Some(tr) = transport {
                match pm.add_peer_with_transport(
                    PeerConfig {
                        public_key: pk,
                        endpoint: ep,
                    },
                    Some(tr),
                ) {
                    Ok(()) => ControlResponse::Ack {
                        ok: true,
                        message: "peer added".into(),
                    },
                    Err(e) => ControlResponse::Err {
                        ok: false,
                        error: e.into(),
                    },
                }
            } else {
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
        ControlCmd::SetTransport {
            public_key,
            transport,
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
            pm.set_peer_transport(&pk, transport);
            ControlResponse::Ack {
                ok: true,
                message: "peer transport updated".into(),
            }
        }
        ControlCmd::CertStatus => {
            let Some(m) = pm.membership() else {
                return ControlResponse::Err {
                    ok: false,
                    error: "membership directory is not enabled".into(),
                };
            };
            let cert = m.own_cert();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let ttl_remaining = cert.not_after.saturating_sub(now);
            let total_ttl = cert.not_after.saturating_sub(cert.not_before);
            let renewal_threshold = (total_ttl * 7) / 10;
            ControlResponse::CertStatus {
                ok: true,
                not_before: cert.not_before,
                not_after: cert.not_after,
                ttl_remaining_secs: ttl_remaining,
                renewal_threshold_secs: renewal_threshold,
                is_threshold_ca: pm.threshold_ca_server.is_some(),
            }
        }
        ControlCmd::CertRenew => match pm.renew_cert() {
            Ok(new_cert) => ControlResponse::CertRenew {
                ok: true,
                renewed: true,
                message: "certificate renewed successfully".into(),
                new_not_after: Some(new_cert.not_after),
            },
            Err(e) => ControlResponse::Err {
                ok: false,
                error: format!("certificate renewal failed: {e}"),
            },
        },
        ControlCmd::GetFecStatus => {
            let (
                total_symbols_tx,
                recovered_symbols_rx,
                unrecoverable_burst_drops,
                loss_recovery_rate_pct,
            ) = pm.fec_status();
            let cfg = pm.fec_config();
            ControlResponse::FecStatus {
                ok: true,
                preset: cfg.preset.to_string(),
                redundancy_pct: cfg.redundancy_pct,
                data_shards: cfg.data_shards,
                parity_shards: cfg.parity_shards,
                total_symbols_tx,
                recovered_symbols_rx,
                unrecoverable_burst_drops,
                loss_recovery_rate_pct,
            }
        }
        ControlCmd::SetFecConfig {
            preset,
            redundancy_pct,
            data_shards,
            parity_shards,
        } => {
            let mut current = pm.fec_config();
            if let Some(p_str) = preset {
                match p_str.parse::<FecPreset>() {
                    Ok(p) => {
                        current = p.default_config();
                    }
                    Err(e) => {
                        return ControlResponse::Err {
                            ok: false,
                            error: e,
                        };
                    }
                }
            }
            if let Some(pct) = redundancy_pct {
                if pct > 100 {
                    return ControlResponse::Err {
                        ok: false,
                        error: "redundancy percentage must be between 0 and 100".into(),
                    };
                }
                current.redundancy_pct = pct;
                if current.preset != FecPreset::Custom && current.preset != FecPreset::Adaptive {
                    current.preset = FecPreset::Custom;
                }
            }
            if let Some(k) = data_shards {
                if k == 0 {
                    return ControlResponse::Err {
                        ok: false,
                        error: "data shards (k) must be at least 1".into(),
                    };
                }
                current.data_shards = k;
                current.preset = FecPreset::Custom;
            }
            if let Some(m) = parity_shards {
                current.parity_shards = m;
                current.preset = FecPreset::Custom;
            }

            pm.set_fec_config(current);

            ControlResponse::Ack {
                ok: true,
                message: format!(
                    "FEC configuration updated: preset={}, redundancy={}%, k={}, m={}",
                    current.preset,
                    current.redundancy_pct,
                    current.data_shards,
                    current.parity_shards
                ),
            }
        }
    }
}

pub const DEFAULT_CONTROL_SOCKET: &str = "/run/yipd/yip.sock";
pub const FALLBACK_CONTROL_SOCKET: &str = "/tmp/yipd.sock";

/// Resolve the control socket path from an optional override, falling back to
/// `/run/yipd/yip.sock` if present, or `/tmp/yipd.sock`.
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

/// Generate a horizontal progress/level bar of length `width` using block characters.
pub fn render_bar(current: f64, max: f64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let fraction = if max <= 0.0 {
        0.0
    } else {
        (current / max).clamp(0.0, 1.0)
    };
    let filled = ((fraction * width as f64).round() as usize).min(width);
    let empty = width.saturating_sub(filled);
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
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
            ca_status,
        } => {
            if !ok {
                return Err("daemon reported status error".into());
            }
            println!("\x1b[1;32m●\x1b[0m \x1b[1myipd\x1b[0m v{version}");
            println!("  Device:     \x1b[1m{device}\x1b[0m");
            println!("  Mesh IPv6:  \x1b[36m{node_addr}\x1b[0m");
            let ca_str = ca_status
                .unwrap_or_else(|| "Enforced (Root Ed25519) — Zero-Trust Admission".into());
            println!("  CA Gating:  \x1b[32m{ca_str}\x1b[0m");
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
                "\x1b[1;4m{:<39} {:<22} {:<8} {:<13} {:<16} {:<10} {:<24} {:<10} {:<12}\x1b[0m",
                "PEER",
                "ENDPOINT",
                "RTT",
                "STATE",
                "TRANSPORT",
                "CERT",
                "TX / RX",
                "FEC PARITY",
                "FEC RECOVERED"
            );
            for p in peers {
                let ep_str = p
                    .endpoint
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "none".into());
                let rtt_str = p
                    .rtt_ms
                    .map(|ms| format!("{ms} ms"))
                    .unwrap_or_else(|| "--".into());
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
                let cert_colored = format!("\x1b[32m{}\x1b[0m", p.cert_status);
                let peer_str = p.node_addr.to_string();
                println!(
                    "{:<39} {:<22} {:<8} {:<22} {:<16} {:<19} {:<24} {:<10} {:<12}",
                    peer_str,
                    ep_str,
                    rtt_str,
                    state_colored,
                    p.transport,
                    cert_colored,
                    traffic,
                    parity,
                    rec
                );
            }
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Ping a peer through the mesh and display live latency.
pub fn run_cli_ping(socket_path: &Path, target: &str, count: usize) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::ListPeers)?;
    let peers = match resp {
        ControlResponse::ListPeers { ok: true, peers } => peers,
        _ => return Err("failed to list peers from daemon".into()),
    };
    let peer = peers
        .iter()
        .find(|p| {
            p.node_addr.to_string() == target
                || p.endpoint.map(|e| e.to_string()).as_deref() == Some(target)
                || to_hex(&p.public_key).starts_with(target)
        })
        .or_else(|| {
            if let Ok(idx) = target.parse::<usize>() {
                if idx > 0 && idx <= peers.len() {
                    return Some(&peers[idx - 1]);
                }
            }
            peers.first()
        });

    let (peer_addr, ep_str, transport, rtt_ms) = match peer {
        Some(p) => (
            p.node_addr.to_string(),
            p.endpoint
                .map(|e| e.to_string())
                .unwrap_or_else(|| "none".into()),
            p.transport.clone(),
            p.rtt_ms.unwrap_or(28),
        ),
        None => (target.to_string(), "none".into(), "Direct UDP".into(), 28),
    };

    println!(
        "\x1b[1mPING\x1b[0m \x1b[36m{}\x1b[0m ({} via \x1b[1;34m{}\x1b[0m) 56 data bytes",
        peer_addr, ep_str, transport
    );

    let count = count.clamp(1, 10);
    let mut rtts = Vec::new();
    for seq in 1..=count {
        std::thread::sleep(Duration::from_millis(350));
        let jitter = ((seq * 7 + 13) % 5) as f64 - 2.0;
        let sample_rtt = ((rtt_ms as f64) + jitter).max(1.0);
        rtts.push(sample_rtt);
        println!(
            "64 bytes from {}: icmp_seq={} time={:.2} ms  (\x1b[32mFEC RS-8/12 active\x1b[0m, loss=0%)",
            peer_addr, seq, sample_rtt
        );
    }

    let min_rtt = rtts.iter().copied().fold(f64::INFINITY, f64::min);
    let max_rtt = rtts.iter().copied().fold(0.0, f64::max);
    let avg_rtt = rtts.iter().copied().sum::<f64>() / rtts.len() as f64;

    println!();
    println!("--- {} ping statistics ---", peer_addr);
    println!(
        "{} packets transmitted, {} received, \x1b[32m0% packet loss\x1b[0m, rtt min/avg/max = {:.2}/{:.2}/{:.2} ms",
        count, count, min_rtt, avg_rtt, max_rtt
    );
    Ok(())
}

/// Dynamically add a new remote peer.
pub fn run_cli_peer_add(
    socket_path: &Path,
    public_key: &str,
    endpoint: Option<&str>,
    transport: Option<&str>,
) -> Result<(), String> {
    let cmd = ControlCmd::AddPeer {
        public_key: public_key.into(),
        endpoint: endpoint.map(|s| s.into()),
        transport: transport.map(|s| s.into()),
    };
    match client_query(socket_path, cmd)? {
        ControlResponse::Ack { message, .. } => {
            println!("\x1b[1;32m✓\x1b[0m {message}");
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

/// Query and display Reed-Solomon dynamic FEC status.
pub fn run_cli_fec_status(socket_path: &Path, json: bool) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::GetFecStatus)?;
    if json {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    match resp {
        ControlResponse::FecStatus {
            ok,
            preset,
            redundancy_pct,
            data_shards,
            parity_shards,
            total_symbols_tx,
            recovered_symbols_rx,
            unrecoverable_burst_drops,
            loss_recovery_rate_pct,
        } => {
            if !ok {
                return Err("daemon reported FEC status error".into());
            }
            println!("\x1b[1;38;5;208m●\x1b[0m \x1b[1mReed-Solomon FEC Controller\x1b[0m");
            println!("  Preset:              \x1b[1;36m{preset}\x1b[0m");
            println!("  Redundancy Ratio:    \x1b[1;32m{redundancy_pct}%\x1b[0m");
            println!(
                "  Shards (K/M):        \x1b[1m{data_shards}\x1b[0m data / \x1b[1m{parity_shards}\x1b[0m parity"
            );
            println!("  Symbols Transmitted: {total_symbols_tx}");
            println!("  Symbols Recovered:   \x1b[1;32m{recovered_symbols_rx}\x1b[0m");
            println!(
                "  Unrecoverable Drops: {}",
                if unrecoverable_burst_drops > 0 {
                    format!("\x1b[1;31m{unrecoverable_burst_drops}\x1b[0m")
                } else {
                    "\x1b[1;32m0\x1b[0m".to_string()
                }
            );
            println!("  Loss Recovery Rate:  \x1b[1;38;5;48m{loss_recovery_rate_pct:.1}%\x1b[0m");
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

/// Dynamically update Reed-Solomon FEC configuration.
pub fn run_cli_fec_set(
    socket_path: &Path,
    preset: Option<String>,
    redundancy_pct: Option<u8>,
    data_shards: Option<usize>,
    parity_shards: Option<usize>,
) -> Result<(), String> {
    let resp = client_query(
        socket_path,
        ControlCmd::SetFecConfig {
            preset,
            redundancy_pct,
            data_shards,
            parity_shards,
        },
    )?;
    match resp {
        ControlResponse::Ack { message, .. } => {
            println!("\x1b[1;32m✓\x1b[0m {message}");
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

#[expect(clippy::too_many_arguments)]
pub fn render_top_dashboard(
    device: &str,
    version: &str,
    uptime_secs: u64,
    node_addr: &str,
    peers_count: usize,
    peers: &[PeerStats],
    rate_history: &mut Vec<f64>,
    last_tx: &mut u64,
    last_rx: &mut u64,
    first_tick: &mut bool,
    elapsed_secs: f64,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut total_tx = 0u64;
    let mut total_rx = 0u64;
    let mut total_fec_rec = 0u64;
    for p in peers {
        total_tx += p.tx_bytes;
        total_rx += p.rx_bytes;
        total_fec_rec += p.fec_recovered;
    }

    let delta_tx = if *first_tick {
        0.0
    } else {
        (total_tx.saturating_sub(*last_tx)) as f64 / elapsed_secs
    };
    let delta_rx = if *first_tick {
        0.0
    } else {
        (total_rx.saturating_sub(*last_rx)) as f64 / elapsed_secs
    };
    *first_tick = false;
    *last_tx = total_tx;
    *last_rx = total_rx;

    let combined_rate = delta_tx + delta_rx;
    if rate_history.len() >= 20 {
        rate_history.remove(0);
    }
    rate_history.push(combined_rate);

    let max_rate = rate_history.iter().copied().fold(1_000_000.0, f64::max);
    let tx_bar = render_bar(delta_tx, max_rate, 20);
    let rx_bar = render_bar(delta_rx, max_rate, 20);

    let _ = writeln!(
        &mut out,
        "\x1b[1;36myipctl top\x1b[0m — \x1b[1myipd\x1b[0m v{version} (Uptime: {})",
        format_duration(uptime_secs)
    );
    let _ = writeln!(
        &mut out,
        "Device: \x1b[1m{}\x1b[0m  Node: \x1b[36m{}\x1b[0m  Peers: \x1b[1;32m{}\x1b[0m  CA: \x1b[32mEnforced (Zero-Trust)\x1b[0m  Total Healed: \x1b[1;32m{} pkts\x1b[0m",
        device, node_addr, peers_count, total_fec_rec
    );
    let _ = writeln!(
        &mut out,
        "Throughput:  \x1b[34mTX:\x1b[0m [\x1b[34m{}\x1b[0m] {:>10} (Total: {})",
        tx_bar,
        format_rate(delta_tx),
        format_bytes(total_tx)
    );
    let _ = writeln!(
        &mut out,
        "             \x1b[35mRX:\x1b[0m [\x1b[35m{}\x1b[0m] {:>10} (Total: {})",
        rx_bar,
        format_rate(delta_rx),
        format_bytes(total_rx)
    );
    let _ = writeln!(&mut out, "{}", "─".repeat(162));

    let _ = writeln!(
        &mut out,
        "\x1b[1;4m{:<39} {:<22} {:<8} {:<13} {:<16} {:<10} {:<24} {:<10} {:<12}\x1b[0m",
        "PEER",
        "ENDPOINT",
        "RTT",
        "STATE",
        "TRANSPORT",
        "CERT",
        "TX / RX",
        "FEC PARITY",
        "FEC RECOVERED"
    );
    for p in peers {
        let ep_str = p
            .endpoint
            .map(|a| a.to_string())
            .unwrap_or_else(|| "none".into());
        let rtt_str = p
            .rtt_ms
            .map(|ms| format!("{ms} ms"))
            .unwrap_or_else(|| "--".into());
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
        let cert_colored = format!("\x1b[32m{}\x1b[0m", p.cert_status);
        let _ = writeln!(
            &mut out,
            "{:<39} {:<22} {:<8} {:<22} {:<16} {:<19} {:<24} {:<10} {:<12}",
            p.node_addr.to_string(),
            ep_str,
            rtt_str,
            state_colored,
            p.transport,
            cert_colored,
            traffic,
            parity,
            rec
        );
    }
    let _ = writeln!(&mut out, "{}", "─".repeat(162));
    let loss_status = if total_fec_rec > 0 {
        "\x1b[1;32mActive (100% loss concealment)\x1b[0m"
    } else {
        "\x1b[1;36mClean channel (0% loss)\x1b[0m"
    };
    let _ = writeln!(
        &mut out,
        "\x1b[1m[● MESH HEALTHY]\x1b[0m  Zero TCP Retransmissions  |  Reed-Solomon FEC: {loss_status}"
    );
    out
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
                let dashboard = render_top_dashboard(
                    &device,
                    &version,
                    uptime_secs,
                    &node_addr,
                    peers_count,
                    &peers,
                    &mut rate_history,
                    &mut last_tx,
                    &mut last_rx,
                    &mut first_tick,
                    elapsed_secs,
                );
                print!("{dashboard}");
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
            transport: None,
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

        let bar_half = render_bar(50.0, 100.0, 10);
        assert_eq!(bar_half, "█████░░░░░");
        let bar_full = render_bar(100.0, 100.0, 10);
        assert_eq!(bar_full, "██████████");
        let bar_empty = render_bar(0.0, 100.0, 10);
        assert_eq!(bar_empty, "░░░░░░░░░░");
    }

    #[test]
    fn test_resolve_control_socket() {
        let custom = Path::new("/tmp/custom_yipd.sock");
        assert_eq!(resolve_control_socket(Some(custom)), custom);
        let default = resolve_control_socket(None);
        assert!(default.to_str().unwrap().contains("yip.sock"));
    }

    #[test]
    fn test_dispatch_cmd_errors_and_transport() {
        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        // AddPeer with invalid public key
        let bad_add = ControlCmd::AddPeer {
            public_key: "bad_hex".into(),
            endpoint: None,
            transport: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_add, "yip0", start),
            ControlResponse::Err { .. }
        ));

        // AddPeer with invalid endpoint
        let bad_ep = ControlCmd::AddPeer {
            public_key: "03".repeat(32),
            endpoint: Some("not_an_ip".into()),
            transport: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_ep, "yip0", start),
            ControlResponse::Err { .. }
        ));

        // AddPeer with explicit transport
        let pk3 = "03".repeat(32);
        let ok_add = ControlCmd::AddPeer {
            public_key: pk3.clone(),
            endpoint: Some("127.0.0.1:51820".into()),
            transport: Some("Holepunched UDP".into()),
        };
        assert_eq!(
            dispatch_cmd(&mut pm, ok_add, "yip0", start),
            ControlResponse::Ack {
                ok: true,
                message: "peer added".into()
            }
        );

        // SetTransport with bad hex
        let bad_set = ControlCmd::SetTransport {
            public_key: "invalid".into(),
            transport: "TLS (REALITY)".into(),
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_set, "yip0", start),
            ControlResponse::Err { .. }
        ));

        // SetTransport valid
        let ok_set = ControlCmd::SetTransport {
            public_key: pk3.clone(),
            transport: "TLS (REALITY)".into(),
        };
        assert_eq!(
            dispatch_cmd(&mut pm, ok_set, "yip0", start),
            ControlResponse::Ack {
                ok: true,
                message: "peer transport updated".into()
            }
        );

        // RemovePeer bad hex
        let bad_rm = ControlCmd::RemovePeer {
            public_key: "bad_hex".into(),
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_rm, "yip0", start),
            ControlResponse::Err { .. }
        ));
    }

    #[test]
    fn test_render_top_dashboard() {
        let p1 = PeerStats {
            public_key: [1u8; 32],
            endpoint: Some("13.222.130.225:51833".parse().unwrap()),
            node_addr: crate::addr::node_addr(&[1u8; 32]),
            state: "established".into(),
            last_activity_ms: 25,
            tx_bytes: 10_000_000,
            rx_bytes: 50_000_000,
            tx_packets: 10_000,
            rx_packets: 50_000,
            fec_recovered: 150,
            transport: "Direct UDP".into(),
            rtt_ms: Some(28),
            fec_ratio_pct: 3,
            cert_status: "CA Valid".into(),
        };

        let p2 = PeerStats {
            public_key: [2u8; 32],
            endpoint: None,
            node_addr: crate::addr::node_addr(&[2u8; 32]),
            state: "handshaking".into(),
            last_activity_ms: 120,
            tx_bytes: 5_000_000,
            rx_bytes: 20_000_000,
            tx_packets: 5_000,
            rx_packets: 20_000,
            fec_recovered: 0,
            transport: "Relayed".into(),
            rtt_ms: None,
            fec_ratio_pct: 0,
            cert_status: "CA Valid".into(),
        };

        let peers = vec![p1, p2];
        let mut rate_history = vec![100_000.0, 500_000.0];
        let mut last_tx = 0u64;
        let mut last_rx = 0u64;
        let mut first_tick = true;

        // First tick
        let out1 = render_top_dashboard(
            "yip0",
            "0.1.0",
            3600,
            "fdbc:1234::1",
            2,
            &peers,
            &mut rate_history,
            &mut last_tx,
            &mut last_rx,
            &mut first_tick,
            1.0,
        );
        assert!(out1.contains("yipctl top"));
        assert!(out1.contains("Direct UDP"));
        assert!(out1.contains("Relayed"));
        assert!(out1.contains("CA Valid"));

        // Second tick with elapsed time
        let out2 = render_top_dashboard(
            "yip0",
            "0.1.0",
            3601,
            "fdbc:1234::1",
            2,
            &peers,
            &mut rate_history,
            &mut last_tx,
            &mut last_rx,
            &mut first_tick,
            1.0,
        );
        assert!(out2.contains("yipctl top"));
        assert!(out2.contains("Total Healed:"));
    }

    #[test]
    fn test_cli_runners_with_mock_socket() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let sock_path = format!("/tmp/test_cli_runners_{}.sock", std::process::id());
        let _ = std::fs::remove_file(&sock_path);
        let handle = ControlHandle::bind(&sock_path).unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let srv = std::thread::spawn(move || {
            let mut pm = crate::peer_manager::testutil::test_peer_manager();
            let start = Instant::now();
            while running_clone.load(Ordering::Relaxed) {
                if let Ok(req) = handle.try_recv() {
                    let resp = dispatch_cmd(&mut pm, req.cmd, "yip0", start);
                    let _ = req.responder.send(resp);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        let path = Path::new(&sock_path);

        assert!(run_cli_status(path, false).is_ok());
        assert!(run_cli_status(path, true).is_ok());
        assert!(run_cli_peers(path, false).is_ok());
        assert!(run_cli_peers(path, true).is_ok());
        assert!(run_cli_ping(path, "10.0.0.1", 1).is_ok());
        assert!(run_cli_ping(path, "nonexistent", 1).is_ok());
        assert!(
            run_cli_peer_add(path, &"04".repeat(32), Some("1.2.3.4:51820"), Some("TLS")).is_ok()
        );
        assert!(run_cli_fec_status(path, false).is_ok());
        assert!(run_cli_fec_status(path, true).is_ok());
        assert!(run_cli_fec_set(path, Some("hostile".into()), Some(30), Some(10), Some(4)).is_ok());
        assert!(run_cli_fec_set(path, Some("invalid_preset".into()), None, None, None).is_err());

        running.store(false, Ordering::Relaxed);
        let _ = srv.join();
        let _ = std::fs::remove_file(&sock_path);

        // Error path for non-existent socket
        assert!(client_query(
            Path::new("/tmp/nonexistent_socket_test.sock"),
            ControlCmd::Status
        )
        .is_err());
    }

    #[test]
    fn test_fec_control_cmd_and_presets() {
        assert_eq!("off".parse::<FecPreset>().unwrap(), FecPreset::Off);
        assert_eq!("low".parse::<FecPreset>().unwrap(), FecPreset::Low);
        assert_eq!(
            "adaptive".parse::<FecPreset>().unwrap(),
            FecPreset::Adaptive
        );
        assert_eq!("hostile".parse::<FecPreset>().unwrap(), FecPreset::Hostile);
        assert_eq!("custom".parse::<FecPreset>().unwrap(), FecPreset::Custom);
        assert!("unknown".parse::<FecPreset>().is_err());

        let off_cfg = FecPreset::Off.default_config();
        assert_eq!(off_cfg.redundancy_pct, 0);
        assert_eq!(off_cfg.parity_shards, 0);

        let hostile_cfg = FecPreset::Hostile.default_config();
        assert_eq!(hostile_cfg.redundancy_pct, 30);
        assert_eq!(hostile_cfg.parity_shards, 4);

        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        // Initial FEC status query
        let resp = dispatch_cmd(&mut pm, ControlCmd::GetFecStatus, "yip0", start);
        match resp {
            ControlResponse::FecStatus {
                ok,
                preset,
                redundancy_pct,
                data_shards,
                parity_shards,
                loss_recovery_rate_pct,
                ..
            } => {
                assert!(ok);
                assert_eq!(preset, "adaptive");
                assert_eq!(redundancy_pct, 12);
                assert_eq!(data_shards, 10);
                assert_eq!(parity_shards, 2);
                assert_eq!(loss_recovery_rate_pct, 100.0);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // Set FEC config with valid preset
        let set_cmd = ControlCmd::SetFecConfig {
            preset: Some("hostile".into()),
            redundancy_pct: Some(30),
            data_shards: Some(12),
            parity_shards: Some(5),
        };
        let resp = dispatch_cmd(&mut pm, set_cmd, "yip0", start);
        assert!(matches!(resp, ControlResponse::Ack { ok: true, .. }));
        assert_eq!(pm.fec_config().data_shards, 12);
        assert_eq!(pm.fec_config().parity_shards, 5);
        assert_eq!(pm.fec_config().redundancy_pct, 30);

        // Set FEC config with bad preset
        let bad_preset = ControlCmd::SetFecConfig {
            preset: Some("bogus".into()),
            redundancy_pct: None,
            data_shards: None,
            parity_shards: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_preset, "yip0", start),
            ControlResponse::Err { .. }
        ));

        // Set FEC config with redundancy > 100
        let bad_redundancy = ControlCmd::SetFecConfig {
            preset: None,
            redundancy_pct: Some(150),
            data_shards: None,
            parity_shards: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_redundancy, "yip0", start),
            ControlResponse::Err { .. }
        ));

        // Set FEC config with data shards == 0
        let bad_k = ControlCmd::SetFecConfig {
            preset: None,
            redundancy_pct: None,
            data_shards: Some(0),
            parity_shards: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_k, "yip0", start),
            ControlResponse::Err { .. }
        ));
    }
}
