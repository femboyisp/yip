//! Peer state and telemetry representations.

use std::fmt;
use std::net::{Ipv6Addr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Connection lifecycle and session state for a remote peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    /// No handshake has been completed; waiting for initiation or packets.
    #[default]
    Idle,
    /// Handshake negotiation is in flight.
    Handshaking,
    /// Crypto session is active and verified; dataplane traffic allowed.
    Established,
}

impl PeerState {
    /// Return the canonical string identifier for this peer state.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Handshaking => "handshaking",
            Self::Established => "established",
        }
    }
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for PeerState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "idle" => Ok(Self::Idle),
            "handshaking" => Ok(Self::Handshaking),
            "established" => Ok(Self::Established),
            other => Err(format!(
                "unknown peer state: '{other}' (valid: idle, handshaking, established)"
            )),
        }
    }
}

/// Summary telemetry and status for an individual peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStats {
    pub public_key: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub endpoint: Option<SocketAddr>,
    pub node_addr: Ipv6Addr,
    pub state: String,
    pub last_activity_ms: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub fec_recovered: u64,
    pub transport: String,
    pub rtt_ms: Option<u32>,
    pub fec_ratio_pct: u8,
    #[serde(default = "default_cert_status")]
    pub cert_status: String,
}

fn default_cert_status() -> String {
    "CA Valid".to_string()
}
