#![forbid(unsafe_code)]

//! OS-agnostic wire, IPC, ticket, and overlay address protocol definitions for yip.

pub mod addr;
pub mod control;
pub mod metrics;
pub mod peer;
pub mod ticket;

// Re-exports
pub use addr::{
    derive_overlay_ipv6, node_addr, verify_addr, MESH_PREFIX_LEN, OVERLAY_ADDR_CONTEXT_V2,
};
pub use control::{
    extract_ip_dst, ip_matches_cidr, parse_cidr, ControlCmd, ControlResponse, DaemonConfig,
    DaitaConfig, DaitaPreset, FecConfig, FecPreset, HopTrace, LatencyCategory, MeshTopologyGraph,
    PeerConfigEntry, PeerCryptoStatus, PingPeerResult, RouteEntry, SplitMode, SplitTunnelConfig,
    SplitTunnelTelemetry, TopologyLink, TopologyNode, XdpMode,
};
pub use metrics::{
    CryptoTelemetry, DaitaTelemetry, FecTelemetry, PeerTelemetryItem, PeersTelemetry,
    TelemetrySnapshot, TrafficTelemetry,
};
pub use peer::{PeerState, PeerStats};
pub use ticket::{render_qr_terminal, NetworkTicket, TICKET_VERSION};
