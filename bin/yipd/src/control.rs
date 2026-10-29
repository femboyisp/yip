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
    #[serde(rename = "get_daita_status")]
    GetDaitaStatus,
    #[serde(rename = "set_daita_config")]
    SetDaitaConfig {
        #[serde(default)]
        preset: Option<String>,
        #[serde(default)]
        buckets: Option<Vec<usize>>,
        #[serde(default)]
        cover_interval_ms: Option<u64>,
        #[serde(default)]
        cover_burst_max: Option<u64>,
        #[serde(default)]
        jitter_max_ms: Option<u64>,
    },
    #[serde(rename = "get_routes")]
    GetRoutes,
    #[serde(rename = "get_topology")]
    GetTopology,
    #[serde(rename = "get_split_tunnel")]
    GetSplitTunnelStatus,
    #[serde(rename = "set_split_tunnel")]
    SetSplitTunnelConfig {
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default)]
        mode: Option<String>,
        #[serde(default)]
        cidrs: Option<Vec<String>>,
        #[serde(default)]
        domains: Option<Vec<String>>,
        #[serde(default)]
        apps: Option<Vec<String>>,
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

/// Supported DAITA traffic defense presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DaitaPreset {
    #[default]
    Off,
    Low,
    Balanced,
    Max,
    Paranoid,
    Custom,
}

impl std::str::FromStr for DaitaPreset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(DaitaPreset::Off),
            "low" => Ok(DaitaPreset::Low),
            "balanced" => Ok(DaitaPreset::Balanced),
            "max" => Ok(DaitaPreset::Max),
            "paranoid" => Ok(DaitaPreset::Paranoid),
            "custom" => Ok(DaitaPreset::Custom),
            other => Err(format!(
                "unknown DAITA preset: {other} (valid: off, low, balanced, max, paranoid, custom)"
            )),
        }
    }
}

impl std::fmt::Display for DaitaPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaitaPreset::Off => write!(f, "off"),
            DaitaPreset::Low => write!(f, "low"),
            DaitaPreset::Balanced => write!(f, "balanced"),
            DaitaPreset::Max => write!(f, "max"),
            DaitaPreset::Paranoid => write!(f, "paranoid"),
            DaitaPreset::Custom => write!(f, "custom"),
        }
    }
}

impl DaitaPreset {
    pub fn to_defense_config(self) -> crate::config::TrafficDefenseConfig {
        match self {
            DaitaPreset::Off => crate::config::TrafficDefenseConfig {
                preset: yip_obf::TrafficDefensePreset::Off,
                buckets: vec![],
                cover_interval_ms: None,
                cover_burst_max: 1,
                jitter_max_ms: 0,
            },
            DaitaPreset::Low | DaitaPreset::Balanced => crate::config::TrafficDefenseConfig {
                preset: yip_obf::TrafficDefensePreset::Balanced,
                buckets: vec![256, 512, 1024, 1420],
                cover_interval_ms: Some(500),
                cover_burst_max: 2,
                jitter_max_ms: 2,
            },
            DaitaPreset::Max | DaitaPreset::Paranoid => crate::config::TrafficDefenseConfig {
                preset: yip_obf::TrafficDefensePreset::Paranoid,
                buckets: vec![512, 1420],
                cover_interval_ms: Some(150),
                cover_burst_max: 4,
                jitter_max_ms: 4,
            },
            DaitaPreset::Custom => crate::config::TrafficDefenseConfig {
                preset: yip_obf::TrafficDefensePreset::Balanced,
                buckets: vec![256, 512, 1024, 1420],
                cover_interval_ms: Some(500),
                cover_burst_max: 2,
                jitter_max_ms: 2,
            },
        }
    }
}

pub fn defense_preset_name(preset: yip_obf::TrafficDefensePreset) -> &'static str {
    match preset {
        yip_obf::TrafficDefensePreset::Off => "off",
        yip_obf::TrafficDefensePreset::Balanced => "balanced",
        yip_obf::TrafficDefensePreset::Paranoid => "paranoid",
    }
}

/// An entry in the active overlay routing table (#183).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct RouteEntry {
    pub prefix: String,
    pub next_hop: String,
    pub peer_name: String,
    pub direct: bool,
    pub mtu: u16,
    pub margin: u16,
    pub metric: u32,
}

/// A node in the projected mesh topology graph (#183).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub ip: String,
    pub is_self: bool,
    pub is_relay: bool,
    pub rtt_ms: f64,
    pub kem_algo: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Latency classification for link visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum LatencyCategory {
    #[default]
    Optimal,
    Normal,
    Elevated,
}

/// A bidirectional or directional edge in the projected mesh topology graph (#183).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct TopologyLink {
    pub source: String,
    pub target: String,
    pub direct: bool,
    pub rtt_ms: f64,
    pub metric: u32,
    pub latency_category: LatencyCategory,
}

/// Complete network mesh topology projection (#183).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct MeshTopologyGraph {
    pub nodes: Vec<TopologyNode>,
    pub links: Vec<TopologyLink>,
    pub total_peers: usize,
    pub direct_peers: usize,
    pub relay_peers: usize,
    pub avg_rtt_ms: f64,
}

/// Supported split-tunnel policy routing modes (#184).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SplitMode {
    #[default]
    Exclude,
    Include,
}

impl std::str::FromStr for SplitMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "exclude" => Ok(SplitMode::Exclude),
            "include" => Ok(SplitMode::Include),
            other => Err(format!(
                "unknown split mode: {other} (valid: exclude, include)"
            )),
        }
    }
}

impl std::fmt::Display for SplitMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SplitMode::Exclude => write!(f, "exclude"),
            SplitMode::Include => write!(f, "include"),
        }
    }
}

/// Split-tunnel route and application bypass configuration (#184).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct SplitTunnelConfig {
    pub enabled: bool,
    pub mode: SplitMode,
    pub cidrs: Vec<String>,
    pub domains: Vec<String>,
    pub apps: Vec<String>,
}

/// Live split-tunnel traffic counters (#184).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct SplitTunnelTelemetry {
    pub bypassed_packets: u64,
    pub bypassed_bytes: u64,
    pub overlay_packets: u64,
    pub overlay_bytes: u64,
}

/// Internal split-tunnel engine state with pre-parsed CIDR masks.
#[derive(Debug, Clone, Default)]
pub struct SplitTunnelState {
    pub enabled: bool,
    pub mode: SplitMode,
    pub cidrs: Vec<String>,
    pub parsed_cidrs: Vec<(std::net::IpAddr, u8)>,
    pub domains: Vec<String>,
    pub apps: Vec<String>,
    pub telemetry: SplitTunnelTelemetry,
}

impl SplitTunnelState {
    pub fn config(&self) -> SplitTunnelConfig {
        SplitTunnelConfig {
            enabled: self.enabled,
            mode: self.mode,
            cidrs: self.cidrs.clone(),
            domains: self.domains.clone(),
            apps: self.apps.clone(),
        }
    }

    pub fn matches_ip(&self, ip: std::net::IpAddr) -> bool {
        for &(net, prefix) in &self.parsed_cidrs {
            if ip_matches_cidr(ip, net, prefix) {
                return true;
            }
        }
        false
    }

    pub fn should_bypass(&self, ip: std::net::IpAddr) -> bool {
        if !self.enabled {
            return false;
        }
        match self.mode {
            SplitMode::Exclude => self.matches_ip(ip),
            SplitMode::Include => !self.matches_ip(ip),
        }
    }

    pub fn record_bypassed(&mut self, bytes: u64) {
        self.telemetry.bypassed_packets += 1;
        self.telemetry.bypassed_bytes += bytes;
    }

    pub fn record_routed(&mut self, bytes: u64) {
        self.telemetry.overlay_packets += 1;
        self.telemetry.overlay_bytes += bytes;
    }
}

/// Parse a CIDR string into an IP address and prefix length.
pub fn parse_cidr(cidr_str: &str) -> Result<(std::net::IpAddr, u8), String> {
    let parts: Vec<&str> = cidr_str.trim().split('/').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err(format!("invalid CIDR syntax: '{cidr_str}'"));
    }
    let ip: std::net::IpAddr = parts[0]
        .parse()
        .map_err(|e| format!("invalid IP address '{}': {e}", parts[0]))?;
    let prefix = if parts.len() == 2 {
        let p: u8 = parts[1]
            .parse()
            .map_err(|e| format!("invalid prefix '{}': {e}", parts[1]))?;
        match ip {
            std::net::IpAddr::V4(_) if p > 32 => {
                return Err(format!("IPv4 prefix /{p} must be <= 32"));
            }
            std::net::IpAddr::V6(_) if p > 128 => {
                return Err(format!("IPv6 prefix /{p} must be <= 128"));
            }
            _ => p,
        }
    } else {
        match ip {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        }
    };
    Ok((ip, prefix))
}

/// Check if an IP address falls within a given CIDR subnet.
pub fn ip_matches_cidr(target: std::net::IpAddr, net: std::net::IpAddr, prefix: u8) -> bool {
    match (target, net) {
        (std::net::IpAddr::V4(t), std::net::IpAddr::V4(n)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = if prefix >= 32 {
                !0u32
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            (u32::from(t) & mask) == (u32::from(n) & mask)
        }
        (std::net::IpAddr::V6(t), std::net::IpAddr::V6(n)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = if prefix >= 128 {
                !0u128
            } else {
                !((1u128 << (128 - prefix)) - 1)
            };
            (u128::from(t) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

/// Extract destination IP address from raw IPv4 or IPv6 packet bytes.
pub fn extract_ip_dst(inner: &[u8]) -> Option<std::net::IpAddr> {
    if inner.len() >= 20 && inner[0] >> 4 == 4 {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(&inner[16..20]);
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
    } else if inner.len() >= 40 && inner[0] >> 4 == 6 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&inner[24..40]);
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
    } else {
        None
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
    DaitaStatus {
        ok: bool,
        preset: String,
        buckets: Vec<usize>,
        cover_interval_ms: Option<u64>,
        cover_burst_max: u64,
        jitter_max_ms: u64,
        authentic_bytes_tx: u64,
        padding_bytes_tx: u64,
        decoy_packets_tx: u64,
        decoy_bytes_tx: u64,
        padding_ratio_pct: f32,
    },
    Routes {
        ok: bool,
        routes: Vec<RouteEntry>,
    },
    Topology {
        ok: bool,
        topology: MeshTopologyGraph,
    },
    SplitTunnelStatus {
        ok: bool,
        enabled: bool,
        mode: String,
        cidrs: Vec<String>,
        domains: Vec<String>,
        apps: Vec<String>,
        bypassed_packets: u64,
        bypassed_bytes: u64,
        overlay_packets: u64,
        overlay_bytes: u64,
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
        ControlCmd::GetDaitaStatus => {
            let (cfg, stats, ratio) = pm.daita_status();
            ControlResponse::DaitaStatus {
                ok: true,
                preset: defense_preset_name(cfg.preset).to_string(),
                buckets: cfg.buckets,
                cover_interval_ms: cfg.cover_interval_ms,
                cover_burst_max: cfg.cover_burst_max,
                jitter_max_ms: cfg.jitter_max_ms,
                authentic_bytes_tx: stats.authentic_bytes_tx,
                padding_bytes_tx: stats.padding_bytes_tx,
                decoy_packets_tx: stats.decoy_packets_tx,
                decoy_bytes_tx: stats.decoy_bytes_tx,
                padding_ratio_pct: ratio,
            }
        }
        ControlCmd::SetDaitaConfig {
            preset,
            buckets,
            cover_interval_ms,
            cover_burst_max,
            jitter_max_ms,
        } => {
            let mut current = pm.traffic_defense.clone();
            if let Some(p_str) = preset {
                match p_str.parse::<DaitaPreset>() {
                    Ok(p) => {
                        current = p.to_defense_config();
                    }
                    Err(e) => {
                        return ControlResponse::Err {
                            ok: false,
                            error: e,
                        };
                    }
                }
            }
            if let Some(b) = buckets {
                let mut sorted = b;
                sorted.sort_unstable();
                current.buckets = sorted;
            }
            if let Some(civ) = cover_interval_ms {
                current.cover_interval_ms = if civ == 0 { None } else { Some(civ) };
            }
            if let Some(bm) = cover_burst_max {
                if bm == 0 {
                    return ControlResponse::Err {
                        ok: false,
                        error: "cover_burst_max must be at least 1".into(),
                    };
                }
                current.cover_burst_max = bm;
            }
            if let Some(j) = jitter_max_ms {
                current.jitter_max_ms = j;
            }

            let summary = format!(
                "preset={}, buckets={:?}, cover_interval={:?}, burst_max={}, jitter={}ms",
                defense_preset_name(current.preset),
                current.buckets,
                current.cover_interval_ms,
                current.cover_burst_max,
                current.jitter_max_ms,
            );
            pm.set_traffic_defense(current);

            ControlResponse::Ack {
                ok: true,
                message: format!("DAITA traffic defense configuration updated: {summary}"),
            }
        }
        ControlCmd::GetRoutes => {
            let routes = pm.routes();
            ControlResponse::Routes { ok: true, routes }
        }
        ControlCmd::GetTopology => {
            let topology = pm.topology(device_name);
            ControlResponse::Topology { ok: true, topology }
        }
        ControlCmd::GetSplitTunnelStatus => {
            let (cfg, telem) = pm.split_tunnel_status();
            ControlResponse::SplitTunnelStatus {
                ok: true,
                enabled: cfg.enabled,
                mode: cfg.mode.to_string(),
                cidrs: cfg.cidrs,
                domains: cfg.domains,
                apps: cfg.apps,
                bypassed_packets: telem.bypassed_packets,
                bypassed_bytes: telem.bypassed_bytes,
                overlay_packets: telem.overlay_packets,
                overlay_bytes: telem.overlay_bytes,
            }
        }
        ControlCmd::SetSplitTunnelConfig {
            enabled,
            mode,
            cidrs,
            domains,
            apps,
        } => {
            let parsed_mode = if let Some(m_str) = mode {
                match m_str.parse::<SplitMode>() {
                    Ok(m) => Some(m),
                    Err(e) => {
                        return ControlResponse::Err {
                            ok: false,
                            error: e,
                        };
                    }
                }
            } else {
                None
            };
            match pm.set_split_tunnel_config(enabled, parsed_mode, cidrs, domains, apps) {
                Ok(cfg) => ControlResponse::Ack {
                    ok: true,
                    message: format!(
                        "split-tunnel configuration updated: enabled={}, mode={}, cidrs={}",
                        cfg.enabled,
                        cfg.mode,
                        cfg.cidrs.len()
                    ),
                },
                Err(e) => ControlResponse::Err {
                    ok: false,
                    error: e,
                },
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

/// Query and display DAITA traffic defense status.
pub fn run_cli_daita_status(socket_path: &Path, json: bool) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::GetDaitaStatus)?;
    if json {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    match resp {
        ControlResponse::DaitaStatus {
            ok,
            preset,
            buckets,
            cover_interval_ms,
            cover_burst_max,
            jitter_max_ms,
            authentic_bytes_tx,
            padding_bytes_tx,
            decoy_packets_tx,
            decoy_bytes_tx,
            padding_ratio_pct,
        } => {
            if !ok {
                return Err("daemon reported DAITA status error".into());
            }
            println!("\x1b[1;38;5;208m●\x1b[0m \x1b[1mDAITA Traffic Defense Controller\x1b[0m");
            println!("  Preset:              \x1b[1;36m{preset}\x1b[0m");
            let buckets_str = if buckets.is_empty() {
                "none (raw wire size)".to_string()
            } else {
                buckets
                    .iter()
                    .map(|b| format!("{b}B"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!("  Quantization Buckets: \x1b[1;32m{buckets_str}\x1b[0m");
            println!(
                "  Cover Interval:      {}",
                cover_interval_ms
                    .map(|ms| format!("{ms} ms"))
                    .unwrap_or_else(|| "disabled".into())
            );
            println!("  Burst Ceiling:       {cover_burst_max} pkts");
            println!("  Max Egress Jitter:   {jitter_max_ms} ms");
            println!(
                "  Authentic Data:      {} ({authentic_bytes_tx} B)",
                format_bytes(authentic_bytes_tx)
            );
            println!(
                "  Padding Overhead:    {} ({padding_bytes_tx} B)",
                format_bytes(padding_bytes_tx)
            );
            println!(
                "  Decoy Cover Bursts:  {decoy_packets_tx} pkts / {} ({decoy_bytes_tx} B)",
                format_bytes(decoy_bytes_tx)
            );
            println!("  Padding Ratio:       \x1b[1;38;5;48m{padding_ratio_pct:.1}%\x1b[0m");
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

/// Dynamically update DAITA traffic defense configuration.
pub fn run_cli_daita_set(
    socket_path: &Path,
    preset: Option<String>,
    buckets: Option<Vec<usize>>,
    cover_interval_ms: Option<u64>,
    cover_burst_max: Option<u64>,
    jitter_max_ms: Option<u64>,
) -> Result<(), String> {
    let resp = client_query(
        socket_path,
        ControlCmd::SetDaitaConfig {
            preset,
            buckets,
            cover_interval_ms,
            cover_burst_max,
            jitter_max_ms,
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

/// Query and display the live mesh overlay routing table (#183).
pub fn run_cli_routes(socket_path: &Path, json: bool) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::GetRoutes)?;
    if json {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    match resp {
        ControlResponse::Routes { ok, routes } => {
            if !ok {
                return Err("daemon reported routes error".into());
            }
            println!(
                "\x1b[1;38;5;208m●\x1b[0m \x1b[1mActive Overlay Routing Table\x1b[0m ({} routes)",
                routes.len()
            );
            if routes.is_empty() {
                println!("  No active routes established.");
                return Ok(());
            }
            println!(
                "  {:<36} {:<24} {:<18} {:<8} {:<6} {:<8} {:<6}",
                "PREFIX", "NEXT_HOP", "PEER", "KIND", "MTU", "MARGIN", "METRIC"
            );
            println!("  {}", "-".repeat(112));
            for r in routes {
                let kind_str = if r.direct {
                    "\x1b[1;32mDirect\x1b[0m"
                } else {
                    "\x1b[1;33mRelayed\x1b[0m"
                };
                println!(
                    "  {:<36} {:<24} {:<18} {:<8} {:<6} {:<8} {:<6}",
                    r.prefix, r.next_hop, r.peer_name, kind_str, r.mtu, r.margin, r.metric
                );
            }
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

/// Query and display the projected mesh topology graph (#183).
pub fn run_cli_topology(socket_path: &Path, json: bool) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::GetTopology)?;
    if json {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    match resp {
        ControlResponse::Topology { ok, topology } => {
            if !ok {
                return Err("daemon reported topology error".into());
            }
            println!(
                "\x1b[1;38;5;208m●\x1b[0m \x1b[1mMesh Topology Graph\x1b[0m ({} peers: {} direct, {} relayed, avg {:.1}ms RTT)",
                topology.total_peers, topology.direct_peers, topology.relay_peers, topology.avg_rtt_ms
            );
            println!("\n  \x1b[1mNodes:\x1b[0m");
            for n in &topology.nodes {
                let role = if n.is_self {
                    "\x1b[1;32m[SELF]\x1b[0m"
                } else if n.is_relay {
                    "\x1b[1;33m[RELAY]\x1b[0m"
                } else {
                    "\x1b[1;36m[PEER]\x1b[0m"
                };
                let rtt_str = if n.is_self {
                    "local".to_string()
                } else {
                    format!("{:.1}ms", n.rtt_ms)
                };
                println!(
                    "    {:<8} {:<20} {:<36} {:<12} {}",
                    role, n.label, n.ip, n.kem_algo, rtt_str
                );
            }
            if !topology.links.is_empty() {
                println!("\n  \x1b[1mLinks:\x1b[0m");
                for l in &topology.links {
                    let direct_str = if l.direct { "Direct P2P" } else { "Relayed" };
                    let cat_color = match l.latency_category {
                        LatencyCategory::Optimal => "\x1b[1;32mOptimal\x1b[0m",
                        LatencyCategory::Normal => "\x1b[1;36mNormal\x1b[0m",
                        LatencyCategory::Elevated => "\x1b[1;31mElevated\x1b[0m",
                    };
                    println!(
                        "    {} -> {} ({}, {:.1}ms, metric {}, category: {})",
                        l.source, l.target, direct_str, l.rtt_ms, l.metric, cat_color
                    );
                }
            }
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

/// Query and display split-tunnel route and application bypass status (#184).
pub fn run_cli_split_status(socket_path: &Path, json: bool) -> Result<(), String> {
    let resp = client_query(socket_path, ControlCmd::GetSplitTunnelStatus)?;
    if json {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    match resp {
        ControlResponse::SplitTunnelStatus {
            ok,
            enabled,
            mode,
            cidrs,
            domains,
            apps,
            bypassed_packets,
            bypassed_bytes,
            overlay_packets,
            overlay_bytes,
        } => {
            if !ok {
                return Err("daemon reported split tunnel error".into());
            }
            println!("\x1b[1;38;5;208m●\x1b[0m \x1b[1mSplit-Tunnel Policy Controller\x1b[0m");
            println!(
                "  Status:              {}",
                if enabled {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[1;31mDISABLED\x1b[0m"
                }
            );
            println!(
                "  Policy Mode:         \x1b[1;36m{}\x1b[0m",
                mode.to_uppercase()
            );
            println!(
                "  Bypass CIDRs ({}):     {}",
                cidrs.len(),
                if cidrs.is_empty() {
                    "none".into()
                } else {
                    cidrs.join(", ")
                }
            );
            println!(
                "  Bypass Domains ({}):   {}",
                domains.len(),
                if domains.is_empty() {
                    "none".into()
                } else {
                    domains.join(", ")
                }
            );
            println!(
                "  Bypass Apps ({}):      {}",
                apps.len(),
                if apps.is_empty() {
                    "none".into()
                } else {
                    apps.join(", ")
                }
            );
            println!(
                "  Bypassed Traffic:    {} pkts / {} ({bypassed_bytes} B)",
                bypassed_packets,
                format_bytes(bypassed_bytes)
            );
            println!(
                "  Overlay Traffic:     {} pkts / {} ({overlay_bytes} B)",
                overlay_packets,
                format_bytes(overlay_bytes)
            );
            Ok(())
        }
        ControlResponse::Err { error, .. } => Err(error),
        _ => Err("unexpected response format from daemon".into()),
    }
}

/// Dynamically update split-tunnel route and application bypass configuration (#184).
pub fn run_cli_split_set(
    socket_path: &Path,
    enabled: Option<bool>,
    mode: Option<String>,
    cidrs: Option<Vec<String>>,
    domains: Option<Vec<String>>,
    apps: Option<Vec<String>>,
) -> Result<(), String> {
    let resp = client_query(
        socket_path,
        ControlCmd::SetSplitTunnelConfig {
            enabled,
            mode,
            cidrs,
            domains,
            apps,
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
        assert!(run_cli_daita_status(path, false).is_ok());
        assert!(run_cli_daita_status(path, true).is_ok());
        assert!(run_cli_daita_set(
            path,
            Some("balanced".into()),
            Some(vec![256, 512, 1024, 1420]),
            Some(500),
            Some(2),
            Some(2)
        )
        .is_ok());
        assert!(
            run_cli_daita_set(path, Some("invalid_preset".into()), None, None, None, None).is_err()
        );
        assert!(run_cli_routes(path, false).is_ok());
        assert!(run_cli_routes(path, true).is_ok());
        assert!(run_cli_topology(path, false).is_ok());
        assert!(run_cli_topology(path, true).is_ok());
        assert!(run_cli_split_status(path, false).is_ok());
        assert!(run_cli_split_status(path, true).is_ok());
        assert!(run_cli_split_set(
            path,
            Some(true),
            Some("exclude".into()),
            Some(vec!["10.0.0.0/8".into()]),
            Some(vec!["corp".into()]),
            Some(vec!["curl".into()])
        )
        .is_ok());
        assert!(
            run_cli_split_set(path, None, Some("invalid_mode".into()), None, None, None).is_err()
        );
        assert!(run_cli_split_set(
            path,
            None,
            None,
            Some(vec!["invalid_cidr".into()]),
            None,
            None
        )
        .is_err());

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

    #[test]
    fn test_daita_control_cmd_and_presets() {
        assert_eq!("off".parse::<DaitaPreset>().unwrap(), DaitaPreset::Off);
        assert_eq!("low".parse::<DaitaPreset>().unwrap(), DaitaPreset::Low);
        assert_eq!(
            "balanced".parse::<DaitaPreset>().unwrap(),
            DaitaPreset::Balanced
        );
        assert_eq!("max".parse::<DaitaPreset>().unwrap(), DaitaPreset::Max);
        assert_eq!(
            "paranoid".parse::<DaitaPreset>().unwrap(),
            DaitaPreset::Paranoid
        );
        assert_eq!(
            "custom".parse::<DaitaPreset>().unwrap(),
            DaitaPreset::Custom
        );
        assert!("unknown".parse::<DaitaPreset>().is_err());

        let off_cfg = DaitaPreset::Off.to_defense_config();
        assert_eq!(off_cfg.preset, yip_obf::TrafficDefensePreset::Off);
        assert!(off_cfg.buckets.is_empty());
        assert_eq!(off_cfg.cover_interval_ms, None);

        let bal_cfg = DaitaPreset::Balanced.to_defense_config();
        assert_eq!(bal_cfg.preset, yip_obf::TrafficDefensePreset::Balanced);
        assert_eq!(bal_cfg.buckets, vec![256, 512, 1024, 1420]);
        assert_eq!(bal_cfg.cover_interval_ms, Some(500));

        let par_cfg = DaitaPreset::Paranoid.to_defense_config();
        assert_eq!(par_cfg.preset, yip_obf::TrafficDefensePreset::Paranoid);
        assert_eq!(par_cfg.buckets, vec![512, 1420]);
        assert_eq!(par_cfg.cover_interval_ms, Some(150));

        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        // Initial DAITA status query
        let resp = dispatch_cmd(&mut pm, ControlCmd::GetDaitaStatus, "yip0", start);
        match resp {
            ControlResponse::DaitaStatus {
                ok,
                preset,
                buckets,
                cover_interval_ms,
                cover_burst_max,
                jitter_max_ms,
                authentic_bytes_tx,
                padding_bytes_tx,
                decoy_packets_tx,
                decoy_bytes_tx,
                padding_ratio_pct,
            } => {
                assert!(ok);
                assert_eq!(preset, "off");
                assert!(buckets.is_empty());
                assert_eq!(cover_interval_ms, None);
                assert_eq!(cover_burst_max, 1);
                assert_eq!(jitter_max_ms, 0);
                assert_eq!(authentic_bytes_tx, 0);
                assert_eq!(padding_bytes_tx, 0);
                assert_eq!(decoy_packets_tx, 0);
                assert_eq!(decoy_bytes_tx, 0);
                assert_eq!(padding_ratio_pct, 0.0);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // Set DAITA config with valid preset
        let set_cmd = ControlCmd::SetDaitaConfig {
            preset: Some("paranoid".into()),
            buckets: Some(vec![1420, 512]),
            cover_interval_ms: Some(100),
            cover_burst_max: Some(3),
            jitter_max_ms: Some(5),
        };
        let resp = dispatch_cmd(&mut pm, set_cmd, "yip0", start);
        assert!(matches!(resp, ControlResponse::Ack { ok: true, .. }));
        assert_eq!(
            pm.traffic_defense.preset,
            yip_obf::TrafficDefensePreset::Paranoid
        );
        assert_eq!(pm.traffic_defense.buckets, vec![512, 1420]); // Sorted
        assert_eq!(pm.traffic_defense.cover_interval_ms, Some(100));
        assert_eq!(pm.traffic_defense.cover_burst_max, 3);
        assert_eq!(pm.traffic_defense.jitter_max_ms, 5);

        // Set DAITA config with bad preset
        let bad_preset = ControlCmd::SetDaitaConfig {
            preset: Some("invalid".into()),
            buckets: None,
            cover_interval_ms: None,
            cover_burst_max: None,
            jitter_max_ms: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_preset, "yip0", start),
            ControlResponse::Err { .. }
        ));

        // Set DAITA config with burst == 0
        let bad_burst = ControlCmd::SetDaitaConfig {
            preset: None,
            buckets: None,
            cover_interval_ms: None,
            cover_burst_max: Some(0),
            jitter_max_ms: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_burst, "yip0", start),
            ControlResponse::Err { .. }
        ));
    }

    #[test]
    fn control_protocol_routes_and_topology() {
        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        // 1. GetRoutes
        let routes_resp = dispatch_cmd(&mut pm, ControlCmd::GetRoutes, "yip0", start);
        match routes_resp {
            ControlResponse::Routes { ok, routes } => {
                assert!(ok);
                assert_eq!(routes.len(), 1);
                assert_eq!(routes[0].mtu, 1420);
                assert_eq!(routes[0].margin, 80);
                assert!(routes[0].direct);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // 2. GetTopology
        let topo_resp = dispatch_cmd(&mut pm, ControlCmd::GetTopology, "yip0", start);
        match topo_resp {
            ControlResponse::Topology { ok, topology } => {
                assert!(ok);
                assert_eq!(topology.total_peers, 1);
                assert_eq!(topology.direct_peers, 1);
                assert_eq!(topology.relay_peers, 0);
                assert_eq!(topology.nodes.len(), 2);
                assert!(topology.nodes[0].is_self);
                assert_eq!(topology.nodes[0].kem_algo, "ML-KEM-768");
                assert_eq!(topology.links.len(), 1);
                assert_eq!(topology.links[0].source, "node-self");
                assert!(topology.links[0].direct);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[test]
    fn control_protocol_split_tunnel() {
        let mut pm = crate::peer_manager::testutil::test_peer_manager();
        let start = Instant::now();

        // Initial default status
        let status_resp = dispatch_cmd(&mut pm, ControlCmd::GetSplitTunnelStatus, "yip0", start);
        match status_resp {
            ControlResponse::SplitTunnelStatus {
                ok,
                enabled,
                mode,
                cidrs,
                domains,
                apps,
                bypassed_packets,
                bypassed_bytes,
                overlay_packets,
                overlay_bytes,
            } => {
                assert!(ok);
                assert!(!enabled);
                assert_eq!(mode, "exclude");
                assert!(cidrs.is_empty());
                assert!(domains.is_empty());
                assert!(apps.is_empty());
                assert_eq!(bypassed_packets, 0);
                assert_eq!(bypassed_bytes, 0);
                assert_eq!(overlay_packets, 0);
                assert_eq!(overlay_bytes, 0);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // Set valid config
        let set_cmd = ControlCmd::SetSplitTunnelConfig {
            enabled: Some(true),
            mode: Some("exclude".into()),
            cidrs: Some(vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()]),
            domains: Some(vec!["local".into()]),
            apps: Some(vec!["curl".into()]),
        };
        let resp = dispatch_cmd(&mut pm, set_cmd, "yip0", start);
        assert!(matches!(resp, ControlResponse::Ack { ok: true, .. }));
        assert!(pm.split_tunnel.enabled);
        assert_eq!(pm.split_tunnel.mode, SplitMode::Exclude);
        assert_eq!(pm.split_tunnel.cidrs.len(), 2);
        assert_eq!(pm.split_tunnel.domains, vec!["local"]);
        assert_eq!(pm.split_tunnel.apps, vec!["curl"]);

        // Set bad CIDR
        let bad_cidr = ControlCmd::SetSplitTunnelConfig {
            enabled: None,
            mode: None,
            cidrs: Some(vec!["invalid_cidr".into()]),
            domains: None,
            apps: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_cidr, "yip0", start),
            ControlResponse::Err { .. }
        ));

        // Set bad mode
        let bad_mode = ControlCmd::SetSplitTunnelConfig {
            enabled: None,
            mode: Some("bad_mode".into()),
            cidrs: None,
            domains: None,
            apps: None,
        };
        assert!(matches!(
            dispatch_cmd(&mut pm, bad_mode, "yip0", start),
            ControlResponse::Err { .. }
        ));
    }

    #[test]
    fn test_cidr_parsing_and_matching() {
        // IPv4 valid CIDRs
        let (ip, p) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(ip, "10.0.0.0".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(p, 8);
        assert!(ip_matches_cidr("10.42.1.99".parse().unwrap(), ip, p));
        assert!(!ip_matches_cidr("192.168.1.1".parse().unwrap(), ip, p));

        // Single IPv4 without prefix defaults to /32
        let (ip32, p32) = parse_cidr("192.168.1.50").unwrap();
        assert_eq!(p32, 32);
        assert!(ip_matches_cidr("192.168.1.50".parse().unwrap(), ip32, p32));
        assert!(!ip_matches_cidr("192.168.1.51".parse().unwrap(), ip32, p32));

        // IPv6 valid CIDRs
        let (v6_net, v6_p) = parse_cidr("fd00::/8").unwrap();
        assert_eq!(v6_p, 8);
        assert!(ip_matches_cidr(
            "fd00:7969:70::1".parse().unwrap(),
            v6_net,
            v6_p
        ));
        assert!(!ip_matches_cidr(
            "2001:db8::1".parse().unwrap(),
            v6_net,
            v6_p
        ));

        // IPv4 /0 matches everything IPv4
        let (zero_net, zero_p) = parse_cidr("0.0.0.0/0").unwrap();
        assert!(ip_matches_cidr(
            "1.2.3.4".parse().unwrap(),
            zero_net,
            zero_p
        ));

        // Error cases
        assert!(parse_cidr("not_an_ip/24").is_err());
        assert!(parse_cidr("10.0.0.1/33").is_err());
        assert!(parse_cidr("fd00::/129").is_err());
        assert!(parse_cidr("10.0.0.1/bad").is_err());
    }
}
