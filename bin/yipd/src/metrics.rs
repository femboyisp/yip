//! Lock-free metrics registry and Prometheus 0.0.4 exposition formatter.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Lock-free metrics registry holding data-plane counters and gauges.
#[derive(Debug)]
pub struct MetricsRegistry {
    start_time: Instant,
    // Traffic
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    dropped_packets: AtomicU64,
    // FEC
    fec_tx_symbols: AtomicU64,
    fec_recovered_symbols: AtomicU64,
    fec_burst_drops: AtomicU64,
    // DAITA
    daita_padding_bytes: AtomicU64,
    daita_decoy_packets: AtomicU64,
    daita_decoy_bytes: AtomicU64,
    // Crypto
    handshakes_success: AtomicU64,
    handshakes_failure: AtomicU64,
    rekeys: AtomicU64,
    current_epoch: AtomicU64,
    // Split tunnel
    split_bypassed_packets: AtomicU64,
    split_bypassed_bytes: AtomicU64,
    split_overlay_packets: AtomicU64,
    split_overlay_bytes: AtomicU64,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    /// Create a new registry with counters initialized to zero.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            fec_tx_symbols: AtomicU64::new(0),
            fec_recovered_symbols: AtomicU64::new(0),
            fec_burst_drops: AtomicU64::new(0),
            daita_padding_bytes: AtomicU64::new(0),
            daita_decoy_packets: AtomicU64::new(0),
            daita_decoy_bytes: AtomicU64::new(0),
            handshakes_success: AtomicU64::new(0),
            handshakes_failure: AtomicU64::new(0),
            rekeys: AtomicU64::new(0),
            current_epoch: AtomicU64::new(1),
            split_bypassed_packets: AtomicU64::new(0),
            split_bypassed_bytes: AtomicU64::new(0),
            split_overlay_packets: AtomicU64::new(0),
            split_overlay_bytes: AtomicU64::new(0),
        }
    }

    /// Record transmitted payload and packets.
    pub fn record_tx(&self, bytes: u64, packets: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.tx_packets.fetch_add(packets, Ordering::Relaxed);
    }

    /// Record received payload and packets.
    pub fn record_rx(&self, bytes: u64, packets: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.rx_packets.fetch_add(packets, Ordering::Relaxed);
    }

    /// Record dropped packets.
    pub fn record_drop(&self, packets: u64) {
        self.dropped_packets.fetch_add(packets, Ordering::Relaxed);
    }

    /// Record transmitted Reed-Solomon parity symbols.
    pub fn record_fec_tx(&self, symbols: u64) {
        self.fec_tx_symbols.fetch_add(symbols, Ordering::Relaxed);
    }

    /// Record recovered Reed-Solomon data symbols.
    pub fn record_fec_recovered(&self, symbols: u64) {
        self.fec_recovered_symbols
            .fetch_add(symbols, Ordering::Relaxed);
    }

    /// Record unrecoverable FEC burst drops.
    pub fn record_fec_burst_drop(&self, bursts: u64) {
        self.fec_burst_drops.fetch_add(bursts, Ordering::Relaxed);
    }

    /// Record DAITA traffic padding bytes.
    pub fn record_daita_padding(&self, bytes: u64) {
        self.daita_padding_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record DAITA decoy cover packets and bytes.
    pub fn record_daita_decoy(&self, packets: u64, bytes: u64) {
        self.daita_decoy_packets
            .fetch_add(packets, Ordering::Relaxed);
        self.daita_decoy_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a successful Noise handshake completion.
    pub fn record_handshake_success(&self) {
        self.handshakes_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Alias for record_handshake_success.
    pub fn record_handshake(&self) {
        self.record_handshake_success();
    }

    /// Record a failed Noise handshake attempt.
    pub fn record_handshake_failure(&self) {
        self.handshakes_failure.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an epoch rekey event.
    pub fn record_rekey(&self) {
        self.rekeys.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the current active cryptographic epoch ID.
    pub fn set_current_epoch(&self, epoch: u64) {
        self.current_epoch.store(epoch, Ordering::Relaxed);
    }

    /// Record split-tunnel bypassed direct packets and bytes.
    pub fn record_split_tunnel_bypass(&self, bytes: u64, packets: u64) {
        self.split_bypassed_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.split_bypassed_packets
            .fetch_add(packets, Ordering::Relaxed);
    }

    /// Record split-tunnel mesh overlay routed packets and bytes.
    pub fn record_split_tunnel_overlay(&self, bytes: u64, packets: u64) {
        self.split_overlay_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.split_overlay_packets
            .fetch_add(packets, Ordering::Relaxed);
    }

    /// Take a structured snapshot of all telemetry metrics.
    pub fn snapshot(&self, peer_stats: &[crate::peer_manager::PeerStats]) -> TelemetrySnapshot {
        let uptime_seconds = self.start_time.elapsed().as_secs();
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tx_packets = self.tx_packets.load(Ordering::Relaxed);
        let rx_packets = self.rx_packets.load(Ordering::Relaxed);
        let dropped_packets = self.dropped_packets.load(Ordering::Relaxed);

        let fec_tx = self.fec_tx_symbols.load(Ordering::Relaxed);
        let fec_recovered = self.fec_recovered_symbols.load(Ordering::Relaxed);
        let fec_bursts = self.fec_burst_drops.load(Ordering::Relaxed);
        let fec_total = fec_recovered + fec_bursts;
        let recovery_rate_ratio = if fec_total > 0 {
            fec_recovered as f64 / fec_total as f64
        } else {
            1.0
        };

        let daita_pad = self.daita_padding_bytes.load(Ordering::Relaxed);
        let daita_decoy_pkts = self.daita_decoy_packets.load(Ordering::Relaxed);
        let daita_decoy_bytes = self.daita_decoy_bytes.load(Ordering::Relaxed);
        let daita_total = tx_bytes + daita_pad;
        let padding_ratio = if daita_total > 0 {
            daita_pad as f64 / daita_total as f64
        } else {
            0.0
        };

        let handshakes_success = self.handshakes_success.load(Ordering::Relaxed);
        let handshakes_failure = self.handshakes_failure.load(Ordering::Relaxed);
        let rekeys = self.rekeys.load(Ordering::Relaxed);
        let current_epoch = self.current_epoch.load(Ordering::Relaxed);

        let bypassed_packets = self.split_bypassed_packets.load(Ordering::Relaxed);
        let bypassed_bytes = self.split_bypassed_bytes.load(Ordering::Relaxed);
        let overlay_packets = self.split_overlay_packets.load(Ordering::Relaxed);
        let overlay_bytes = self.split_overlay_bytes.load(Ordering::Relaxed);

        let active_peers = peer_stats
            .iter()
            .filter(|p| p.state.eq_ignore_ascii_case("established"))
            .count();
        let total_peers = peer_stats.len();

        let peer_items = peer_stats
            .iter()
            .map(|p| PeerTelemetryItem {
                public_key: p.public_key.iter().map(|b| format!("{b:02x}")).collect(),
                node_addr: p.node_addr.to_string(),
                endpoint: p.endpoint.map(|e| e.to_string()),
                state: p.state.clone(),
                transport: p.transport.clone(),
                tx_bytes: p.tx_bytes,
                rx_bytes: p.rx_bytes,
                tx_packets: p.tx_packets,
                rx_packets: p.rx_packets,
                fec_recovered: p.fec_recovered,
                rtt_ms: p.rtt_ms,
                fec_ratio_pct: p.fec_ratio_pct,
                cert_status: p.cert_status.clone(),
            })
            .collect();

        TelemetrySnapshot {
            uptime_seconds,
            traffic: TrafficTelemetry {
                tx_bytes,
                rx_bytes,
                tx_packets,
                rx_packets,
                dropped_packets,
            },
            fec: FecTelemetry {
                symbols_tx: fec_tx,
                recovered_symbols: fec_recovered,
                unrecoverable_bursts: fec_bursts,
                recovery_rate_ratio,
            },
            daita: DaitaTelemetry {
                padding_bytes: daita_pad,
                decoy_packets: daita_decoy_pkts,
                decoy_bytes: daita_decoy_bytes,
                padding_ratio,
            },
            crypto: CryptoTelemetry {
                handshakes: handshakes_success,
                handshake_failures: handshakes_failure,
                rekeys,
                current_epoch,
            },
            split_tunnel: SplitTunnelTelemetry {
                bypassed_packets,
                bypassed_bytes,
                overlay_packets,
                overlay_bytes,
            },
            peers: PeersTelemetry {
                active: active_peers,
                total: total_peers,
                list: peer_items,
            },
        }
    }

    /// Render metrics in standard Prometheus 0.0.4 text format.
    pub fn render_prometheus(&self, peer_stats: &[crate::peer_manager::PeerStats]) -> String {
        let mut out = String::with_capacity(2048);

        let uptime_seconds = self.start_time.elapsed().as_secs();
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tx_packets = self.tx_packets.load(Ordering::Relaxed);
        let rx_packets = self.rx_packets.load(Ordering::Relaxed);
        let dropped_packets = self.dropped_packets.load(Ordering::Relaxed);

        let fec_tx = self.fec_tx_symbols.load(Ordering::Relaxed);
        let fec_recovered = self.fec_recovered_symbols.load(Ordering::Relaxed);
        let fec_bursts = self.fec_burst_drops.load(Ordering::Relaxed);
        let fec_total = fec_recovered + fec_bursts;
        let recovery_rate_ratio = if fec_total > 0 {
            fec_recovered as f64 / fec_total as f64
        } else {
            1.0
        };

        let daita_pad = self.daita_padding_bytes.load(Ordering::Relaxed);
        let daita_decoy_pkts = self.daita_decoy_packets.load(Ordering::Relaxed);
        let daita_decoy_bytes = self.daita_decoy_bytes.load(Ordering::Relaxed);
        let daita_total = tx_bytes + daita_pad;
        let padding_ratio = if daita_total > 0 {
            daita_pad as f64 / daita_total as f64
        } else {
            0.0
        };

        let handshakes_success = self.handshakes_success.load(Ordering::Relaxed);
        let handshakes_failure = self.handshakes_failure.load(Ordering::Relaxed);
        let rekeys = self.rekeys.load(Ordering::Relaxed);
        let current_epoch = self.current_epoch.load(Ordering::Relaxed);

        let bypassed_packets = self.split_bypassed_packets.load(Ordering::Relaxed);
        let bypassed_bytes = self.split_bypassed_bytes.load(Ordering::Relaxed);
        let overlay_packets = self.split_overlay_packets.load(Ordering::Relaxed);
        let overlay_bytes = self.split_overlay_bytes.load(Ordering::Relaxed);

        let active_peers = peer_stats
            .iter()
            .filter(|p| p.state.eq_ignore_ascii_case("established"))
            .count();
        let total_peers = peer_stats.len();

        // Uptime
        out.push_str("# HELP yip_uptime_seconds Process runtime in seconds\n");
        out.push_str("# TYPE yip_uptime_seconds counter\n");
        let _ = writeln!(out, "yip_uptime_seconds {uptime_seconds}");

        // Peers summary
        out.push_str("# HELP yip_peers_active Count of actively handshaked mesh peers\n");
        out.push_str("# TYPE yip_peers_active gauge\n");
        let _ = writeln!(out, "yip_peers_active {active_peers}");

        out.push_str("# HELP yip_peers_total Count of all configured mesh peers\n");
        out.push_str("# TYPE yip_peers_total gauge\n");
        let _ = writeln!(out, "yip_peers_total {total_peers}");

        // Traffic totals
        out.push_str("# HELP yip_traffic_tx_bytes_total Total bytes transmitted\n");
        out.push_str("# TYPE yip_traffic_tx_bytes_total counter\n");
        let _ = writeln!(out, "yip_traffic_tx_bytes_total {tx_bytes}");

        out.push_str(
            "# HELP yip_traffic_rx_bytes_total Total payload and control bytes received\n",
        );
        out.push_str("# TYPE yip_traffic_rx_bytes_total counter\n");
        let _ = writeln!(out, "yip_traffic_rx_bytes_total {rx_bytes}");

        out.push_str("# HELP yip_traffic_tx_packets_total Total packets dispatched\n");
        out.push_str("# TYPE yip_traffic_tx_packets_total counter\n");
        let _ = writeln!(out, "yip_traffic_tx_packets_total {tx_packets}");

        out.push_str("# HELP yip_traffic_rx_packets_total Total packets received\n");
        out.push_str("# TYPE yip_traffic_rx_packets_total counter\n");
        let _ = writeln!(out, "yip_traffic_rx_packets_total {rx_packets}");

        out.push_str("# HELP yip_traffic_dropped_packets_total Packets dropped due to route errors or queue overflow\n");
        out.push_str("# TYPE yip_traffic_dropped_packets_total counter\n");
        let _ = writeln!(out, "yip_traffic_dropped_packets_total {dropped_packets}");

        // Per-peer metrics
        if !peer_stats.is_empty() {
            out.push_str("# HELP yip_peer_tx_bytes_total Transmitted bytes per peer\n");
            out.push_str("# TYPE yip_peer_tx_bytes_total counter\n");
            for p in peer_stats {
                let _ = writeln!(
                    out,
                    "yip_peer_tx_bytes_total{{peer=\"{}\",transport=\"{}\"}} {}",
                    p.node_addr, p.transport, p.tx_bytes
                );
            }

            out.push_str("# HELP yip_peer_rx_bytes_total Received bytes per peer\n");
            out.push_str("# TYPE yip_peer_rx_bytes_total counter\n");
            for p in peer_stats {
                let _ = writeln!(
                    out,
                    "yip_peer_rx_bytes_total{{peer=\"{}\",transport=\"{}\"}} {}",
                    p.node_addr, p.transport, p.rx_bytes
                );
            }

            out.push_str(
                "# HELP yip_peer_rtt_milliseconds Smoothed RTT in milliseconds per peer\n",
            );
            out.push_str("# TYPE yip_peer_rtt_milliseconds gauge\n");
            for p in peer_stats {
                let rtt = p.rtt_ms.unwrap_or(0);
                let _ = writeln!(
                    out,
                    "yip_peer_rtt_milliseconds{{peer=\"{}\",transport=\"{}\"}} {}",
                    p.node_addr, p.transport, rtt
                );
            }

            out.push_str(
                "# HELP yip_peer_loss_ratio Moving packet loss ratio (0.0 to 1.0) per peer\n",
            );
            out.push_str("# TYPE yip_peer_loss_ratio gauge\n");
            for p in peer_stats {
                let loss = p.fec_ratio_pct as f64 / 100.0;
                let _ = writeln!(
                    out,
                    "yip_peer_loss_ratio{{peer=\"{}\",transport=\"{}\"}} {:.4}",
                    p.node_addr, p.transport, loss
                );
            }
        }

        // FEC metrics
        out.push_str("# HELP yip_fec_symbols_tx_total Total Reed-Solomon symbols transmitted\n");
        out.push_str("# TYPE yip_fec_symbols_tx_total counter\n");
        let _ = writeln!(out, "yip_fec_symbols_tx_total {fec_tx}");

        out.push_str(
            "# HELP yip_fec_recovered_symbols_total Total Reed-Solomon symbols reconstructed\n",
        );
        out.push_str("# TYPE yip_fec_recovered_symbols_total counter\n");
        let _ = writeln!(out, "yip_fec_recovered_symbols_total {fec_recovered}");

        out.push_str(
            "# HELP yip_fec_unrecoverable_bursts_total Block drops exceeding parity capacity\n",
        );
        out.push_str("# TYPE yip_fec_unrecoverable_bursts_total counter\n");
        let _ = writeln!(out, "yip_fec_unrecoverable_bursts_total {fec_bursts}");

        out.push_str("# HELP yip_fec_recovery_rate_ratio Ratio of recovered to missing symbols\n");
        out.push_str("# TYPE yip_fec_recovery_rate_ratio gauge\n");
        let _ = writeln!(out, "yip_fec_recovery_rate_ratio {recovery_rate_ratio:.4}");

        // DAITA metrics
        out.push_str(
            "# HELP yip_daita_padding_bytes_total Total DAITA dummy padding bytes transmitted\n",
        );
        out.push_str("# TYPE yip_daita_padding_bytes_total counter\n");
        let _ = writeln!(out, "yip_daita_padding_bytes_total {daita_pad}");

        out.push_str(
            "# HELP yip_daita_decoy_packets_total Total DAITA cover traffic decoy packets emitted\n",
        );
        out.push_str("# TYPE yip_daita_decoy_packets_total counter\n");
        let _ = writeln!(out, "yip_daita_decoy_packets_total {daita_decoy_pkts}");

        out.push_str("# HELP yip_daita_decoy_bytes_total Total bytes of cover traffic\n");
        out.push_str("# TYPE yip_daita_decoy_bytes_total counter\n");
        let _ = writeln!(out, "yip_daita_decoy_bytes_total {daita_decoy_bytes}");

        out.push_str(
            "# HELP yip_daita_padding_ratio Ratio of defense padding bytes to authentic bytes\n",
        );
        out.push_str("# TYPE yip_daita_padding_ratio gauge\n");
        let _ = writeln!(out, "yip_daita_padding_ratio {padding_ratio:.4}");

        // Crypto metrics
        out.push_str(
            "# HELP yip_crypto_handshakes_total Successful Noise IK handshakes completed\n",
        );
        out.push_str("# TYPE yip_crypto_handshakes_total counter\n");
        let _ = writeln!(out, "yip_crypto_handshakes_total {handshakes_success}");

        out.push_str("# HELP yip_crypto_handshake_failures_total Failed handshake attempts\n");
        out.push_str("# TYPE yip_crypto_handshake_failures_total counter\n");
        let _ = writeln!(
            out,
            "yip_crypto_handshake_failures_total {handshakes_failure}"
        );

        out.push_str(
            "# HELP yip_crypto_rekeys_total Epoch key ratchets and manual rekeys executed\n",
        );
        out.push_str("# TYPE yip_crypto_rekeys_total counter\n");
        let _ = writeln!(out, "yip_crypto_rekeys_total {rekeys}");

        out.push_str("# HELP yip_crypto_current_epoch Current active cryptographic epoch ID\n");
        out.push_str("# TYPE yip_crypto_current_epoch gauge\n");
        let _ = writeln!(out, "yip_crypto_current_epoch {current_epoch}");

        // Split tunnel metrics
        out.push_str("# HELP yip_split_tunnel_bypassed_packets_total Packets routed directly to physical interface\n");
        out.push_str("# TYPE yip_split_tunnel_bypassed_packets_total counter\n");
        let _ = writeln!(
            out,
            "yip_split_tunnel_bypassed_packets_total {bypassed_packets}"
        );

        out.push_str(
            "# HELP yip_split_tunnel_bypassed_bytes_total Bytes routed outside overlay mesh\n",
        );
        out.push_str("# TYPE yip_split_tunnel_bypassed_bytes_total counter\n");
        let _ = writeln!(
            out,
            "yip_split_tunnel_bypassed_bytes_total {bypassed_bytes}"
        );

        out.push_str("# HELP yip_split_tunnel_overlay_packets_total Packets matched and forwarded across mesh overlay\n");
        out.push_str("# TYPE yip_split_tunnel_overlay_packets_total counter\n");
        let _ = writeln!(
            out,
            "yip_split_tunnel_overlay_packets_total {overlay_packets}"
        );

        out.push_str(
            "# HELP yip_split_tunnel_overlay_bytes_total Bytes routed across mesh overlay\n",
        );
        out.push_str("# TYPE yip_split_tunnel_overlay_bytes_total counter\n");
        let _ = writeln!(out, "yip_split_tunnel_overlay_bytes_total {overlay_bytes}");

        out
    }
}

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CryptoTelemetry {
    pub handshakes: u64,
    pub handshake_failures: u64,
    pub rekeys: u64,
    pub current_epoch: u64,
}

/// Split-tunnel routing telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr};

    #[test]
    fn test_atomic_counters_monotonic() {
        let registry = MetricsRegistry::new();
        registry.record_tx(100, 1);
        registry.record_tx(50, 1);
        registry.record_rx(200, 2);

        let snap = registry.snapshot(&[]);
        assert_eq!(snap.traffic.tx_bytes, 150);
        assert_eq!(snap.traffic.tx_packets, 2);
        assert_eq!(snap.traffic.rx_bytes, 200);
        assert_eq!(snap.traffic.rx_packets, 2);
    }

    #[test]
    fn test_prometheus_rendering_format() {
        let registry = MetricsRegistry::new();
        registry.record_tx(1500, 3);
        registry.record_handshake_success();
        registry.record_rekey();

        let rendered = registry.render_prometheus(&[]);
        assert!(rendered.contains("# HELP yip_traffic_tx_bytes_total Total bytes transmitted"));
        assert!(rendered.contains("# TYPE yip_traffic_tx_bytes_total counter"));
        assert!(rendered.contains("yip_traffic_tx_bytes_total 1500"));
        assert!(rendered.contains("yip_crypto_handshakes_total 1"));
        assert!(rendered.contains("yip_crypto_rekeys_total 1"));
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn test_fec_and_daita_metrics() {
        let registry = MetricsRegistry::new();
        registry.record_fec_tx(64);
        registry.record_fec_recovered(16);
        registry.record_fec_burst_drop(4);

        registry.record_daita_padding(512);
        registry.record_daita_decoy(2, 256);

        let snap = registry.snapshot(&[]);
        assert_eq!(snap.fec.symbols_tx, 64);
        assert_eq!(snap.fec.recovered_symbols, 16);
        assert_eq!(snap.fec.unrecoverable_bursts, 4);
        assert!((snap.fec.recovery_rate_ratio - 0.8).abs() < 1e-6);

        assert_eq!(snap.daita.padding_bytes, 512);
        assert_eq!(snap.daita.decoy_packets, 2);
        assert_eq!(snap.daita.decoy_bytes, 256);

        let rendered = registry.render_prometheus(&[]);
        assert!(rendered.contains("yip_fec_symbols_tx_total 64"));
        assert!(rendered.contains("yip_fec_recovered_symbols_total 16"));
        assert!(rendered.contains("yip_fec_unrecoverable_bursts_total 4"));
        assert!(rendered.contains("yip_fec_recovery_rate_ratio 0.8000"));
        assert!(rendered.contains("yip_daita_padding_bytes_total 512"));
        assert!(rendered.contains("yip_daita_decoy_packets_total 2"));
        assert!(rendered.contains("yip_daita_decoy_bytes_total 256"));
    }

    #[test]
    fn test_split_tunnel_and_crypto_metrics() {
        let registry = MetricsRegistry::new();
        registry.record_split_tunnel_bypass(1024, 8);
        registry.record_split_tunnel_overlay(2048, 16);
        registry.record_handshake_failure();
        registry.set_current_epoch(42);

        let snap = registry.snapshot(&[]);
        assert_eq!(snap.split_tunnel.bypassed_bytes, 1024);
        assert_eq!(snap.split_tunnel.bypassed_packets, 8);
        assert_eq!(snap.split_tunnel.overlay_bytes, 2048);
        assert_eq!(snap.split_tunnel.overlay_packets, 16);
        assert_eq!(snap.crypto.handshake_failures, 1);
        assert_eq!(snap.crypto.current_epoch, 42);

        let rendered = registry.render_prometheus(&[]);
        assert!(rendered.contains("yip_split_tunnel_bypassed_packets_total 8"));
        assert!(rendered.contains("yip_split_tunnel_bypassed_bytes_total 1024"));
        assert!(rendered.contains("yip_split_tunnel_overlay_packets_total 16"));
        assert!(rendered.contains("yip_split_tunnel_overlay_bytes_total 2048"));
        assert!(rendered.contains("yip_crypto_handshake_failures_total 1"));
        assert!(rendered.contains("yip_crypto_current_epoch 42"));
    }

    #[test]
    fn test_peer_stats_rendering() {
        let registry = MetricsRegistry::new();
        let peer = crate::peer_manager::PeerStats {
            public_key: [0xab; 32],
            endpoint: Some("192.168.1.100:51820".parse::<SocketAddr>().unwrap()),
            node_addr: "fd00::1".parse::<Ipv6Addr>().unwrap(),
            state: "Established".into(),
            last_activity_ms: 12345,
            tx_bytes: 8192,
            rx_bytes: 4096,
            tx_packets: 10,
            rx_packets: 5,
            fec_recovered: 2,
            transport: "Direct UDP".into(),
            rtt_ms: Some(15),
            fec_ratio_pct: 5,
            cert_status: "CA Valid".into(),
        };

        let snap = registry.snapshot(std::slice::from_ref(&peer));
        assert_eq!(snap.peers.active, 1);
        assert_eq!(snap.peers.total, 1);
        assert_eq!(snap.peers.list.len(), 1);
        assert_eq!(snap.peers.list[0].node_addr, "fd00::1");

        let rendered = registry.render_prometheus(std::slice::from_ref(&peer));
        assert!(rendered.contains("yip_peers_active 1"));
        assert!(rendered.contains("yip_peers_total 1"));
        assert!(rendered
            .contains("yip_peer_tx_bytes_total{peer=\"fd00::1\",transport=\"Direct UDP\"} 8192"));
        assert!(rendered
            .contains("yip_peer_rx_bytes_total{peer=\"fd00::1\",transport=\"Direct UDP\"} 4096"));
        assert!(rendered
            .contains("yip_peer_rtt_milliseconds{peer=\"fd00::1\",transport=\"Direct UDP\"} 15"));
        assert!(rendered
            .contains("yip_peer_loss_ratio{peer=\"fd00::1\",transport=\"Direct UDP\"} 0.0500"));
    }

    #[test]
    fn test_concurrent_counter_increments() {
        use std::sync::Arc;
        let registry = Arc::new(MetricsRegistry::new());
        let mut handles = Vec::new();

        for _ in 0..10 {
            let reg = Arc::clone(&registry);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    reg.record_tx(10, 1);
                    reg.record_rx(20, 1);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let snap = registry.snapshot(&[]);
        assert_eq!(snap.traffic.tx_bytes, 10000);
        assert_eq!(snap.traffic.tx_packets, 1000);
        assert_eq!(snap.traffic.rx_bytes, 20000);
        assert_eq!(snap.traffic.rx_packets, 1000);
    }
}
