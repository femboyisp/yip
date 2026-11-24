//! Control socket commands, responses, and wire configuration types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub use crate::metrics::SplitTunnelTelemetry;
use crate::peer::PeerStats;
use crate::ticket::NetworkTicket;

/// Inbound control commands received over the UNIX socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
        #[serde(default)]
        alias: Option<String>,
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
    #[serde(rename = "trace_path")]
    TracePath { peer_node_id: String },
    #[serde(rename = "ping_peer")]
    PingPeer {
        peer_node_id: String,
        #[serde(default = "default_ping_count")]
        count: u32,
        #[serde(default = "default_ping_timeout_ms")]
        timeout_ms: u64,
    },
    #[serde(rename = "get_metrics")]
    GetMetrics {
        #[serde(default)]
        peer: Option<String>,
    },
    #[serde(rename = "get_crypto_status")]
    GetCryptoStatus {
        #[serde(default)]
        peer: Option<String>,
    },
    #[serde(rename = "trigger_rekey")]
    TriggerRekey { peer: String },
    #[serde(rename = "get_xdp_status")]
    GetXdpStatus,
    #[serde(rename = "set_xdp_mode")]
    SetXdpMode { mode: String },
    #[serde(rename = "create_ticket")]
    CreateTicket {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        route_mode: Option<String>,
        #[serde(default)]
        endpoint: Option<String>,
    },
    #[serde(rename = "reload")]
    Reload {
        #[serde(default)]
        path: Option<String>,
    },
    #[serde(rename = "get_config")]
    GetConfig,
}

const fn default_ping_count() -> u32 {
    4
}

const fn default_ping_timeout_ms() -> u64 {
    2000
}

/// Outbound control command responses returned to clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ControlResponse {
    Status {
        ok: bool,
        version: String,
        node_addr: String,
        device: String,
        #[serde(default)]
        public_key: String,
        #[serde(default)]
        listen_port: u16,
        #[serde(default)]
        network_id: String,
        peers_count: usize,
        uptime_secs: u64,
        #[serde(default)]
        ca_status: Option<String>,
        #[serde(default)]
        spsc_queue_drops: u64,
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
    TracePath {
        ok: bool,
        target: String,
        reachable: bool,
        hops: Vec<HopTrace>,
        total_rtt_ms: f64,
    },
    PingPeer {
        ok: bool,
        target: String,
        endpoint: Option<String>,
        sent: u32,
        received: u32,
        packet_loss_pct: f64,
        min_rtt_ms: Option<f64>,
        avg_rtt_ms: Option<f64>,
        max_rtt_ms: Option<f64>,
        stddev_rtt_ms: Option<f64>,
        samples: Vec<f64>,
    },
    CryptoStatus {
        ok: bool,
        sessions: Vec<PeerCryptoStatus>,
    },
    XdpStatus {
        ok: bool,
        interface: Option<String>,
        mode: String,
        bound_mode: String,
        attached_mode: String,
        zero_copy_supported: bool,
        prog_id: Option<u32>,
        queues_count: usize,
        hardware_offload_queues: Vec<u32>,
        umem_slabs: usize,
        umem_chunk_size: usize,
        umem_total_chunks: usize,
        umem_free_chunks: usize,
        fill_ring_drops: u64,
        rx_ring_drops: u64,
        tx_ring_drops: u64,
        completion_ring_drops: u64,
        rx_packets: u64,
        tx_packets: u64,
        rx_bytes: u64,
        tx_bytes: u64,
    },
    Metrics {
        ok: bool,
        metrics: crate::metrics::TelemetrySnapshot,
        prometheus: String,
    },
    Ticket {
        ok: bool,
        ticket: NetworkTicket,
        uri: String,
        #[serde(default)]
        qr_terminal: String,
    },
    Config {
        ok: bool,
        config: DaemonConfig,
    },
    Reload {
        ok: bool,
        message: String,
        reloaded: bool,
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

/// Static daemon configuration inspectable via control socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DaemonConfig {
    #[serde(default)]
    pub device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerConfigEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fec: Option<FecConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daita: Option<DaitaConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_tunnel: Option<SplitTunnelConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem: Option<String>,
}

/// A single remote peer configuration entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PeerConfigEntry {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem: Option<String>,
}

/// Supported Reed-Solomon dynamic FEC presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FecPreset {
    Off,
    Low,
    #[default]
    Adaptive,
    Hostile,
    Custom,
}

impl FecPreset {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Adaptive => "adaptive",
            Self::Hostile => "hostile",
            Self::Custom => "custom",
        }
    }

    pub const fn default_config(&self) -> FecConfig {
        match self {
            Self::Off => FecConfig {
                preset: *self,
                redundancy_pct: 0,
                data_shards: 10,
                parity_shards: 0,
            },
            Self::Low => FecConfig {
                preset: *self,
                redundancy_pct: 5,
                data_shards: 10,
                parity_shards: 1,
            },
            Self::Adaptive => FecConfig {
                preset: *self,
                redundancy_pct: 12,
                data_shards: 10,
                parity_shards: 2,
            },
            Self::Hostile => FecConfig {
                preset: *self,
                redundancy_pct: 30,
                data_shards: 10,
                parity_shards: 4,
            },
            Self::Custom => FecConfig {
                preset: *self,
                redundancy_pct: 15,
                data_shards: 10,
                parity_shards: 2,
            },
        }
    }
}

impl FromStr for FecPreset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "low" => Ok(Self::Low),
            "adaptive" => Ok(Self::Adaptive),
            "hostile" => Ok(Self::Hostile),
            "custom" => Ok(Self::Custom),
            other => Err(format!(
                "unknown FEC preset: {other} (valid: off, low, adaptive, hostile, custom)"
            )),
        }
    }
}

impl fmt::Display for FecPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Dynamic Reed-Solomon FEC runtime configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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

impl DaitaPreset {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Balanced => "balanced",
            Self::Max => "max",
            Self::Paranoid => "paranoid",
            Self::Custom => "custom",
        }
    }

    pub fn default_config(&self) -> DaitaConfig {
        match self {
            Self::Off => DaitaConfig {
                preset: *self,
                buckets: vec![],
                cover_interval_ms: None,
                cover_burst_max: 1,
                jitter_max_ms: 0,
            },
            Self::Low | Self::Balanced => DaitaConfig {
                preset: *self,
                buckets: vec![256, 512, 1024, 1420],
                cover_interval_ms: Some(500),
                cover_burst_max: 2,
                jitter_max_ms: 2,
            },
            Self::Max | Self::Paranoid => DaitaConfig {
                preset: *self,
                buckets: vec![512, 1420],
                cover_interval_ms: Some(150),
                cover_burst_max: 4,
                jitter_max_ms: 4,
            },
            Self::Custom => DaitaConfig {
                preset: *self,
                buckets: vec![256, 512, 1024, 1420],
                cover_interval_ms: Some(500),
                cover_burst_max: 2,
                jitter_max_ms: 2,
            },
        }
    }
}

impl FromStr for DaitaPreset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "low" => Ok(Self::Low),
            "balanced" => Ok(Self::Balanced),
            "max" => Ok(Self::Max),
            "paranoid" => Ok(Self::Paranoid),
            "custom" => Ok(Self::Custom),
            other => Err(format!(
                "unknown DAITA preset: {other} (valid: off, low, balanced, max, paranoid, custom)"
            )),
        }
    }
}

impl fmt::Display for DaitaPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// DAITA traffic analysis defense runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaitaConfig {
    pub preset: DaitaPreset,
    #[serde(default)]
    pub buckets: Vec<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_interval_ms: Option<u64>,
    #[serde(default)]
    pub cover_burst_max: u64,
    #[serde(default)]
    pub jitter_max_ms: u64,
}

impl Default for DaitaConfig {
    fn default() -> Self {
        DaitaPreset::Off.default_config()
    }
}

/// An entry in the active overlay routing table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RouteEntry {
    pub prefix: String,
    pub next_hop: String,
    pub peer_name: String,
    pub direct: bool,
    pub mtu: u16,
    pub margin: u16,
    pub metric: u32,
}

/// A node in the projected mesh topology graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LatencyCategory {
    #[default]
    Optimal,
    Normal,
    Elevated,
}

/// A bidirectional or directional edge in the projected mesh topology graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TopologyLink {
    pub source: String,
    pub target: String,
    pub direct: bool,
    pub rtt_ms: f64,
    pub metric: u32,
    pub latency_category: LatencyCategory,
}

/// Complete network mesh topology projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MeshTopologyGraph {
    pub nodes: Vec<TopologyNode>,
    pub links: Vec<TopologyLink>,
    pub total_peers: usize,
    pub direct_peers: usize,
    pub relay_peers: usize,
    pub avg_rtt_ms: f64,
}

/// Supported split-tunnel policy routing modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SplitMode {
    #[default]
    Exclude,
    Include,
}

impl SplitMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Exclude => "exclude",
            Self::Include => "include",
        }
    }
}

impl FromStr for SplitMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "exclude" => Ok(Self::Exclude),
            "include" => Ok(Self::Include),
            other => Err(format!(
                "unknown split mode: {other} (valid: exclude, include)"
            )),
        }
    }
}

impl fmt::Display for SplitMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Split-tunnel route and application bypass configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SplitTunnelConfig {
    pub enabled: bool,
    pub mode: SplitMode,
    pub cidrs: Vec<String>,
    pub domains: Vec<String>,
    pub apps: Vec<String>,
}

/// A single segment or hop along a mesh circuit trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HopTrace {
    pub hop_index: u32,
    pub node_id: String,
    pub endpoint: Option<String>,
    pub rtt_ms: f64,
    pub is_direct: bool,
    pub transport: String,
}

/// Statistics and probe samples from pinging a mesh peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PingPeerResult {
    pub target: String,
    pub endpoint: Option<String>,
    pub sent: u32,
    pub received: u32,
    pub packet_loss_pct: f64,
    pub min_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub stddev_rtt_ms: Option<f64>,
    pub samples: Vec<f64>,
}

/// Active cryptographic session states and anti-replay floors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PeerCryptoStatus {
    pub peer: String,
    pub node_addr: String,
    pub endpoint: Option<String>,
    pub session_state: String,
    pub cipher_suite: String,
    pub current_epoch: Option<u64>,
    pub current_epoch_age_secs: Option<u64>,
    pub next_epoch: Option<u64>,
    pub previous_epoch: Option<u64>,
    pub rekey_in_flight: bool,
    pub send_counter: Option<u64>,
    pub replay_floor: Option<u64>,
    pub replay_latest: Option<u64>,
    pub last_accepted_init_tai64n: Option<String>,
}

/// eBPF XDP attachment and driver offload modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    #[default]
    Auto,
    Generic,
    Native,
    Offload,
}

impl XdpMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Generic => "generic",
            Self::Native => "native",
            Self::Offload => "offload",
        }
    }

    /// Convert mode into Linux kernel XDP attach flags.
    pub const fn to_flags(self) -> u32 {
        match self {
            Self::Auto => 0,
            Self::Generic => 2, // XDP_FLAGS_SKB_MODE
            Self::Native => 4,  // XDP_FLAGS_DRV_MODE
            Self::Offload => 8, // XDP_FLAGS_HW_MODE
        }
    }
}

impl FromStr for XdpMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "generic" | "skb" => Ok(Self::Generic),
            "native" | "drv" | "driver" => Ok(Self::Native),
            "offload" | "hw" | "hardware" => Ok(Self::Offload),
            other => Err(format!(
                "invalid xdp mode '{other}', expected one of: auto, generic, native, offload"
            )),
        }
    }
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Parse a CIDR string into an IP address and prefix length.
pub fn parse_cidr(cidr_str: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = cidr_str.trim().split('/').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err(format!("invalid CIDR syntax: '{cidr_str}'"));
    }
    let ip: IpAddr = parts[0]
        .parse()
        .map_err(|e| format!("invalid IP address '{}': {e}", parts[0]))?;
    let prefix = if parts.len() == 2 {
        let p: u8 = parts[1]
            .parse()
            .map_err(|e| format!("invalid prefix '{}': {e}", parts[1]))?;
        match ip {
            IpAddr::V4(_) if p > 32 => {
                return Err(format!("IPv4 prefix /{p} must be <= 32"));
            }
            IpAddr::V6(_) if p > 128 => {
                return Err(format!("IPv6 prefix /{p} must be <= 128"));
            }
            _ => p,
        }
    } else {
        match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    };
    Ok((ip, prefix))
}

/// Check if an IP address falls within a given CIDR subnet.
pub fn ip_matches_cidr(target: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (target, net) {
        (IpAddr::V4(t), IpAddr::V4(n)) => {
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
        (IpAddr::V6(t), IpAddr::V6(n)) => {
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
pub fn extract_ip_dst(inner: &[u8]) -> Option<IpAddr> {
    if inner.len() >= 20 && inner[0] >> 4 == 4 {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(&inner[16..20]);
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    } else if inner.len() >= 40 && inner[0] >> 4 == 6 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&inner[24..40]);
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_response_spsc_queue_drops_backward_compatibility() {
        // Payload from an older daemon lacking spsc_queue_drops
        let legacy_json = r#"{
            "ok": true,
            "version": "0.1.0",
            "node_addr": "fd00::1",
            "device": "yip0",
            "peers_count": 2,
            "uptime_secs": 120
        }"#;

        let resp: ControlResponse = serde_json::from_str(legacy_json)
            .expect("legacy status JSON must deserialize with default spsc_queue_drops");

        match resp {
            ControlResponse::Status {
                spsc_queue_drops,
                node_addr,
                ..
            } => {
                assert_eq!(node_addr, "fd00::1");
                assert_eq!(spsc_queue_drops, 0, "legacy status must default to 0 drops");
            }
            other => panic!("expected ControlResponse::Status, got {other:?}"),
        }

        // Payload with explicit non-zero spsc_queue_drops
        let modern_json = r#"{
            "ok": true,
            "version": "0.1.0",
            "node_addr": "fd00::2",
            "device": "yip0",
            "peers_count": 1,
            "uptime_secs": 60,
            "spsc_queue_drops": 42
        }"#;

        let resp_modern: ControlResponse =
            serde_json::from_str(modern_json).expect("modern status JSON must deserialize");

        match resp_modern {
            ControlResponse::Status {
                spsc_queue_drops, ..
            } => {
                assert_eq!(spsc_queue_drops, 42);
            }
            other => panic!("expected ControlResponse::Status, got {other:?}"),
        }
    }
}
