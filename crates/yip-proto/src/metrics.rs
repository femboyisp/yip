//! Structured telemetry snapshot types for monitoring and export.

use serde::{Deserialize, Serialize};

/// Structured telemetry snapshot suitable for JSON export and OpenTelemetry mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetrySnapshot {
    pub uptime_seconds: u64,
    pub traffic: TrafficTelemetry,
    pub fec: FecTelemetry,
    pub daita: DaitaTelemetry,
    pub crypto: CryptoTelemetry,
    pub split_tunnel: SplitTunnelTelemetry,
    pub peers: PeersTelemetry,
}

/// Data-plane traffic counters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TrafficTelemetry {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub dropped_packets: u64,
}

/// Reed-Solomon FEC telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FecTelemetry {
    pub symbols_tx: u64,
    pub recovered_symbols: u64,
    pub unrecoverable_bursts: u64,
    pub recovery_rate_ratio: f64,
}

/// DAITA traffic analysis defense telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DaitaTelemetry {
    pub padding_bytes: u64,
    pub decoy_packets: u64,
    pub decoy_bytes: u64,
    pub padding_ratio: f64,
}

/// Cryptographic session telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CryptoTelemetry {
    pub handshakes: u64,
    pub handshake_failures: u64,
    pub rekeys: u64,
    pub current_epoch: u64,
}

/// Live split-tunnel traffic counters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SplitTunnelTelemetry {
    pub bypassed_packets: u64,
    pub bypassed_bytes: u64,
    pub overlay_packets: u64,
    pub overlay_bytes: u64,
}

/// Aggregated peer telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PeersTelemetry {
    pub active: usize,
    pub total: usize,
    pub list: Vec<PeerTelemetryItem>,
}

/// Per-peer telemetry details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PeerTelemetryItem {
    pub public_key: String,
    pub node_addr: String,
    pub endpoint: Option<String>,
    pub state: String,
    pub transport: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub fec_recovered: u64,
    pub rtt_ms: Option<u32>,
    pub fec_ratio_pct: u8,
    pub cert_status: String,
}
