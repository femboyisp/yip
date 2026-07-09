//! QUIC-mimicry transport (3c.1): a `quinn-proto` (sans-IO) QUIC costume that
//! carries yip's UNCHANGED inner protocol (Noise-IK / FEC / AEAD, driven by
//! [`PeerManager`]) inside RFC 9221 unreliable DATAGRAM frames.
//!
//! # Two layers
//!
//! - **Outer QUIC (the costume, zero-auth by design):** a throwaway self-signed
//!   server cert, ALPN `h3`, client SNI `www.cloudflare.com`, and an
//!   accept-any-cert client verifier ([`SkipServerVerification`]). A QUIC MITM
//!   recovers only inner yip ciphertext — the QUIC layer authenticates nothing.
//! - **Inner yip (the real security), UNCHANGED:** every yip datagram that the
//!   raw-UDP path would put directly on the wire is instead handed to
//!   [`quinn_proto::Connection::datagrams`]`().send()` and rides one QUIC
//!   DATAGRAM frame. [`PeerManager`] still runs the Noise-IK handshake, FEC,
//!   AEAD, cert admission and anti-hijack exactly as on the raw path — this
//!   module is purely the transport.
//!
//! # Architecture: Option B (a dedicated `run_quic` loop)
//!
//! `quinn-proto`'s I/O is decoupled from received packets (it emits ACKs, PMTUD
//! probes, handshake and timeout-driven packets that are not tied to any single
//! `recv`), and it wants dynamic timers (`Connection::poll_timeout()`, often
//! well under 10 ms during the handshake). The existing [`yip_io::poll::run_poll`]
//! `Dispatch` shape returns at most one output per `on_udp` call against a fixed
//! 10 ms tick — a poor fit for that model. So [`run_quic`] is a dedicated pump
//! that drives the state machines directly, using a small SAFE epoll primitive
//! ([`yip_io::epoll::Epoll`]) so all `unsafe` stays in yip-io and `yipd` keeps
//! `#![forbid(unsafe_code)]`. The per-iteration timeout is
//! `min(Connection::poll_timeout(), 10 ms)`.
//!
//! # Connection-role policy (avoid QUIC glare)
//!
//! yip is peer-to-peer, so both ends could open a QUIC connection → two
//! connections. A deterministic role by static-key order (mirroring yip's own
//! handshake glare tiebreak) keeps it to one connection per pair: the peer with
//! the **smaller** `local_public` is the QUIC **client** (`Endpoint::connect`);
//! the **larger** is the **server** (accepts). One [`Endpoint`] does both.
//!
//! # The pump (per iteration)
//!
//! recv UDP → [`Endpoint::handle`] → drive each connection (endpoint events,
//! `poll` events, drain received DATAGRAM frames) → each received frame is a
//! plain yip datagram → [`PeerManager::on_udp`] → wrap the returned egress via
//! `datagrams().send()` → drain `poll_transmit` → `sendto`. TUN frames go
//! through [`PeerManager::on_tun`] the same way; [`PeerManager::tick`] fires on
//! cadence.

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Instant;
use std::{cmp::Ordering, io};

use bytes::{Bytes, BytesMut};
use quinn_proto::congestion;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, ConnectError, Connection, ConnectionHandle, DatagramEvent, Endpoint,
    EndpointConfig, Event, MtuDiscoveryConfig, RttEstimator, SendDatagramError, ServerConfig,
    TransportConfig,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use yip_io::epoll::{read_fd, write_fd, Epoll};
use yip_io::poll::{Dispatch, DispatchOut};
use yip_io::MAX_WIRE_DATAGRAM;

use crate::peer_manager::PeerManager;

// ── tunables shared with the Task-1 spike (proven; do NOT re-derive) ──────────

/// Per-packet QUIC framing budget subtracted from `max_datagram_size` when
/// picking the FEC symbol size: short header + connection id + packet number +
/// DATAGRAM frame type/length + AEAD tag. The Task-1 spike measured 38 bytes on
/// a settled path (`upper_bound 1452 − max_datagram_size 1414`); 28 is a
/// deliberately tighter *reserve* so the computed symbol size stays strictly
/// inside the datagram budget even as the packet-number length fluctuates.
const QUIC_YIP_OVERHEAD: usize = 28;

/// The raw-UDP-path symbol size (`1200`) is the ceiling; QUIC never uses a
/// larger FEC symbol than the plain path, only a smaller one on a constrained
/// path. See [`quic_symbol_size`].
const QUIC_SYMBOL_CAP: u16 = 1200;

/// Deliberately larger than `u32::MAX` (so quinn-proto's pacer early-returns
/// `None` and the `in_flight + to_send >= window()` gate never trips) but well
/// clear of `u64::MAX` to leave arithmetic headroom. See [`NoCcController`].
const NO_CC_WINDOW: u64 = u64::MAX / 2;

/// Outer-costume ALPN: HTTP/3, the protocol a real QUIC/H3 endpoint speaks.
const QUIC_ALPN: &[u8] = b"h3";

/// Outer-costume client SNI: a real, ubiquitous HTTP/3 domain, so the
/// ClientHello's server-name looks like ordinary web traffic. The inner yip
/// Noise-IK handshake is the real security; the accept-any-cert verifier means
/// this name is never actually checked.
const QUIC_SNI: &str = "www.cloudflare.com";

/// FEC-safe symbol size for a QUIC path whose current `max_datagram_size` is
/// `mds`: `min(1200, mds − QUIC_YIP_OVERHEAD)`. Computed via `try_from` (no
/// `as` truncation). With `mds` settling at 1414 on a normal Ethernet path this
/// stays exactly 1200 (unchanged from the raw path); on a constrained path it
/// shrinks so a yip datagram always fits one QUIC DATAGRAM frame.
fn quic_symbol_size(mds: usize) -> u16 {
    let avail = mds.saturating_sub(QUIC_YIP_OVERHEAD);
    let capped = avail.min(usize::from(QUIC_SYMBOL_CAP));
    u16::try_from(capped).expect("value <= QUIC_SYMBOL_CAP (1200) fits u16")
}

// ── NoCc congestion controller (MANDATORY — see task-1-report.md) ─────────────
//
// DATAGRAM frames are ack-eliciting, so quinn-proto gates the packets carrying
// them behind the same congestion-window/pacing checks as STREAM data. Under a
// realistic WAN RTT the default Cubic controller delays a majority of a datagram
// burst by 50–103 ms — a silent, severe regression against yip's low-latency
// north star. A controller with an always-huge window disables both the cwnd
// gate and the pacer, so datagrams go out promptly (spike: 0/40 over 1 ms).

/// A no-op congestion controller whose window is always [`NO_CC_WINDOW`].
#[derive(Debug)]
struct NoCcController;

impl congestion::Controller for NoCcController {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, _last_packet_number: u64) {}

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
    ) {
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        NO_CC_WINDOW
    }

    fn clone_box(&self) -> Box<dyn congestion::Controller> {
        Box::new(Self)
    }

    fn initial_window(&self) -> u64 {
        NO_CC_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// Factory for [`NoCcController`], installed via
/// [`TransportConfig::congestion_controller_factory`].
#[derive(Debug)]
struct NoCcFactory;

impl congestion::ControllerFactory for NoCcFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn congestion::Controller> {
        Box::new(NoCcController)
    }
}

// ── accept-any-cert client verifier (the costume authenticates nothing) ───────

/// A rustls [`ServerCertVerifier`] that accepts any certificate. The outer QUIC
/// layer is a throwaway costume; the inner yip Noise-IK handshake is the real
/// security (double encryption is intentional — a QUIC MITM recovers only inner
/// yip ciphertext).
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── config builders (the spike's exact knobs) ─────────────────────────────────

/// Install the ring crypto provider as the rustls process default, once. Makes
/// `rustls::{Client,Server}Config::builder()` work without relying on ambient
/// global state having been set elsewhere.
fn install_ring_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Ignore the error: `Err` only means a provider is already installed,
        // which is exactly the state we want.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The exact `TransportConfig` the Task-1 spike proved: generous datagram
/// buffers (FEC bursts must never be dropped for lack of space), PMTUD on with a
/// realistic Ethernet ceiling, RFC 9000's mandatory 1200-byte floor, and — the
/// critical knob — the [`NoCcFactory`] congestion controller.
fn transport_config() -> Arc<TransportConfig> {
    let mut cfg = TransportConfig::default();
    cfg.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    cfg.datagram_send_buffer_size(4 * 1024 * 1024);

    let mut mtud = MtuDiscoveryConfig::default();
    mtud.upper_bound(1452);
    cfg.mtu_discovery_config(Some(mtud));
    cfg.min_mtu(1200);
    cfg.initial_mtu(1200);

    cfg.congestion_controller_factory(Arc::new(NoCcFactory));
    Arc::new(cfg)
}

/// Generate a throwaway self-signed server certificate for the outer costume.
fn gen_cert() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("self-signed cert generation");
    let cert_der = cert.cert.into();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (cert_der, key_der)
}

/// Build the QUIC server config (throwaway cert + ALPN `h3` + the spike's
/// `TransportConfig`). One `Endpoint` carries this to *accept*.
fn server_config() -> ServerConfig {
    install_ring_provider();
    let (cert, key) = gen_cert();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("throwaway server cert");
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).expect("rustls ServerConfig -> QuicServerConfig");
    let mut cfg = ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport_config());
    cfg
}

/// Build the QUIC client config (accept-any-cert verifier + ALPN `h3` + the
/// spike's `TransportConfig`). The same `Endpoint` uses this to *connect*.
fn client_config() -> ClientConfig {
    install_ring_provider();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).expect("rustls ClientConfig -> QuicClientConfig");
    let mut cfg = ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport_config());
    cfg
}

/// The QUIC role this node takes toward a peer, decided by static-key order to
/// avoid glare (two connections for one pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnRole {
    /// Smaller `local_public` ⇒ we `connect()`.
    Client,
    /// Larger `local_public` ⇒ we accept.
    Server,
}

/// Decide our QUIC role toward `peer_pub`: the smaller static key is the client.
/// Equal keys can't occur (a node is never its own peer); treat the degenerate
/// tie as `Server` so neither side dials itself.
fn connection_role(local_pub: &[u8; 32], peer_pub: &[u8; 32]) -> ConnRole {
    match local_pub.cmp(peer_pub) {
        Ordering::Less => ConnRole::Client,
        Ordering::Greater | Ordering::Equal => ConnRole::Server,
    }
}

// ── the pump ──────────────────────────────────────────────────────────────────

/// One outgoing UDP packet: a fully-framed QUIC packet and where it goes.
struct OutPacket {
    dst: SocketAddr,
    bytes: Vec<u8>,
}

/// Why a yip egress datagram could not be handed to QUIC.
#[derive(Debug)]
enum QuicSendError {
    /// No live, 1-RTT connection to the datagram's destination.
    NoConnection,
    /// The QUIC layer rejected the datagram (e.g. oversized ⇒ `TooLarge`).
    /// Rejected, never truncated.
    Datagram(SendDatagramError),
}

/// One QUIC connection to a single peer endpoint.
struct ConnEntry {
    handle: ConnectionHandle,
    conn: Connection,
    /// The peer's UDP address — used both as the `Endpoint::handle` remote and
    /// as the `PeerManager::on_udp` source so the inner protocol demuxes by it.
    peer_addr: SocketAddr,
    /// Whether the connection has reached 1-RTT (`Event::Connected`).
    up: bool,
    /// Set on `Event::ConnectionLost`; the entry is reaped after the drive pass.
    dead: bool,
}

/// A single `quinn-proto` [`Endpoint`] multiplexing every peer connection. The
/// endpoint carries a `ServerConfig` (to accept) and also `connect()`s — one
/// endpoint does both, per the connection-role policy.
struct QuicEndpoint {
    endpoint: Endpoint,
    conns: Vec<ConnEntry>,
}

impl QuicEndpoint {
    /// Build an endpoint that can both accept and initiate.
    fn new() -> Self {
        let ep_cfg = Arc::new(EndpointConfig::default());
        let endpoint = Endpoint::new(ep_cfg, Some(Arc::new(server_config())), true, None);
        Self {
            endpoint,
            conns: Vec::new(),
        }
    }

    /// Open a QUIC connection to `peer_addr` (we are the client for this peer).
    fn connect(&mut self, now: Instant, peer_addr: SocketAddr) -> Result<(), ConnectError> {
        let (handle, conn) = self
            .endpoint
            .connect(now, client_config(), peer_addr, QUIC_SNI)?;
        self.conns.push(ConnEntry {
            handle,
            conn,
            peer_addr,
            up: false,
            dead: false,
        });
        Ok(())
    }

    /// Whether we already hold a live (non-dead) connection to `addr`.
    fn has_conn_to(&self, addr: SocketAddr) -> bool {
        self.conns.iter().any(|c| c.peer_addr == addr && !c.dead)
    }

    /// Feed one received UDP datagram into the endpoint, routing it to an
    /// existing connection, accepting a new one, or emitting a stateless
    /// response into `out`.
    fn handle_datagram(
        &mut self,
        now: Instant,
        from: SocketAddr,
        data: BytesMut,
        out: &mut Vec<OutPacket>,
    ) {
        let Self { endpoint, conns } = self;
        let mut resp = Vec::new();
        let Some(event) = endpoint.handle(now, from, None, None, data, &mut resp) else {
            return;
        };
        match event {
            DatagramEvent::ConnectionEvent(ch, ev) => {
                if let Some(entry) = conns.iter_mut().find(|c| c.handle == ch) {
                    entry.conn.handle_event(ev);
                }
            }
            DatagramEvent::Response(t) => {
                out.push(OutPacket {
                    dst: t.destination,
                    bytes: resp[..t.size].to_vec(),
                });
            }
            DatagramEvent::NewConnection(incoming) => {
                let mut buf = Vec::new();
                match endpoint.accept(incoming, now, &mut buf, None) {
                    Ok((handle, conn)) => conns.push(ConnEntry {
                        handle,
                        conn,
                        peer_addr: from,
                        up: false,
                        dead: false,
                    }),
                    Err(e) => {
                        if let Some(t) = e.response {
                            out.push(OutPacket {
                                dst: t.destination,
                                bytes: buf[..t.size].to_vec(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Drive every connection one step: timers, endpoint-event round trip,
    /// connection events (marking newly-established connections in `newly_up`
    /// with their `max_datagram_size`, draining received DATAGRAM frames into
    /// `recv`), then draining `poll_transmit` into `out` (one datagram per QUIC
    /// packet — `max_datagrams = 1`). Reaps lost connections.
    fn drive(
        &mut self,
        now: Instant,
        out: &mut Vec<OutPacket>,
        recv: &mut Vec<(SocketAddr, Bytes)>,
        newly_up: &mut Vec<usize>,
    ) {
        let Self { endpoint, conns } = self;
        for entry in conns.iter_mut() {
            entry.conn.handle_timeout(now);

            while let Some(ev) = entry.conn.poll_endpoint_events() {
                if let Some(cev) = endpoint.handle_event(entry.handle, ev) {
                    entry.conn.handle_event(cev);
                }
            }

            while let Some(event) = entry.conn.poll() {
                match event {
                    Event::Connected => {
                        if !entry.up {
                            entry.up = true;
                            if let Some(mds) = entry.conn.datagrams().max_size() {
                                newly_up.push(mds);
                            }
                        }
                    }
                    Event::DatagramReceived => {
                        while let Some(bytes) = entry.conn.datagrams().recv() {
                            recv.push((entry.peer_addr, bytes));
                        }
                    }
                    Event::ConnectionLost { .. } => entry.dead = true,
                    _ => {}
                }
            }

            drain_transmits(&mut entry.conn, now, out);
        }
        conns.retain(|c| !c.dead);
    }

    /// Hand one plain yip datagram to the QUIC connection for `dst` as a single
    /// DATAGRAM frame, then flush that connection's transmits into `out` so the
    /// datagram rides its own QUIC packet (1 yip datagram per QUIC packet — FEC
    /// loss independence). Oversized datagrams are rejected, never truncated.
    fn send_datagram(
        &mut self,
        dst: SocketAddr,
        payload: Bytes,
        now: Instant,
        out: &mut Vec<OutPacket>,
    ) -> Result<(), QuicSendError> {
        let entry = self
            .conns
            .iter_mut()
            .find(|c| c.peer_addr == dst && c.up && !c.dead)
            .ok_or(QuicSendError::NoConnection)?;
        entry
            .conn
            .datagrams()
            .send(payload, false)
            .map_err(QuicSendError::Datagram)?;
        drain_transmits(&mut entry.conn, now, out);
        Ok(())
    }

    /// Drain any pending transmits across all connections into `out` (used after
    /// a batch of sends to flush handshake/ACK progression).
    fn flush_transmits(&mut self, now: Instant, out: &mut Vec<OutPacket>) {
        for entry in &mut self.conns {
            drain_transmits(&mut entry.conn, now, out);
        }
    }

    /// The soonest `Connection::poll_timeout` across all connections, expressed
    /// as an epoll timeout in ms, clamped to `[0, 10]` so `PeerManager::tick`
    /// still fires at least every 10 ms and quinn timers are never overslept.
    fn next_timeout_ms(&mut self, now: Instant) -> i32 {
        let mut earliest: Option<Instant> = None;
        for entry in &mut self.conns {
            if let Some(t) = entry.conn.poll_timeout() {
                earliest = Some(earliest.map_or(t, |e| e.min(t)));
            }
        }
        match earliest {
            None => 10,
            Some(t) if t <= now => 0,
            Some(t) => {
                let ms = (t - now).as_millis();
                i32::try_from(ms.min(10)).unwrap_or(10)
            }
        }
    }
}

/// Drain one connection's `poll_transmit` queue into `out`, one UDP datagram per
/// entry (`max_datagrams = 1`: no GSO batching, one DATAGRAM frame per packet).
fn drain_transmits(conn: &mut Connection, now: Instant, out: &mut Vec<OutPacket>) {
    let mut buf = Vec::new();
    while let Some(t) = conn.poll_transmit(now, 1, &mut buf) {
        out.push(OutPacket {
            dst: t.destination,
            bytes: buf[..t.size].to_vec(),
        });
        buf.clear();
    }
}

/// Take a `PeerManager` UDP/TUN outcome as owned data, decoupling it from the
/// manager borrow so the caller can immediately drive QUIC sends.
fn owned_out(out: DispatchOut<'_>) -> (Option<Vec<u8>>, Vec<yip_io::poll::EgressDatagram>) {
    match out {
        DispatchOut::None => (None, Vec::new()),
        DispatchOut::Tun(inner) => (Some(inner.to_vec()), Vec::new()),
        DispatchOut::Udp(dgs) => (None, dgs.to_vec()),
        DispatchOut::Both(inner, dgs) => (Some(inner.to_vec()), dgs.to_vec()),
    }
}

/// Send each yip egress datagram over its QUIC connection, logging (and
/// dropping, never truncating) any that don't fit or have no live connection.
fn send_egress(
    qe: &mut QuicEndpoint,
    egress: &[yip_io::poll::EgressDatagram],
    now: Instant,
    out: &mut Vec<OutPacket>,
) {
    for d in egress {
        match qe.send_datagram(d.dst, Bytes::copy_from_slice(&d.bytes), now, out) {
            Ok(()) => {}
            Err(QuicSendError::NoConnection) => {
                eprintln!(
                    "quic: no live connection to {}; dropping egress datagram",
                    d.dst
                );
            }
            Err(QuicSendError::Datagram(cause)) => {
                eprintln!(
                    "quic: QUIC rejected egress datagram to {} ({cause}); dropped",
                    d.dst
                );
            }
        }
    }
}

/// Write a decoded inner frame to the TUN device (best-effort: a single failed
/// write is logged and swallowed rather than tearing down the tunnel).
fn write_tun(tun_fd: RawFd, inner: &[u8]) {
    if let Err(e) = write_fd(tun_fd, inner) {
        eprintln!("quic: tun write error: {e}");
    }
}

// ── public entry point ─────────────────────────────────────────────────────────

/// A client-role peer we must keep a QUIC connection open to.
struct ClientPeer {
    addr: SocketAddr,
    /// When we last called `connect` (debounces reconnect after loss).
    last_attempt: Option<Instant>,
}

/// Minimum spacing between `connect` attempts for a client-role peer whose
/// connection is missing or was lost.
const RECONNECT_DEBOUNCE_MS: u128 = 1_000;

/// Run the QUIC-mimicry data loop until a fatal I/O error.
///
/// `peers` is the list of `(peer_public_key, endpoint)` for every peer with a
/// known direct endpoint. This node opens a QUIC connection to each peer for
/// which it is the client by static-key order (see [`connection_role`]) and
/// accepts from the rest. `manager` is driven UNCHANGED — it runs the inner
/// yip Noise-IK/FEC/AEAD protocol inside the QUIC DATAGRAM frames.
pub fn run_quic(
    sock: UdpSocket,
    tun_fd: RawFd,
    manager: &mut PeerManager,
    local_pub: [u8; 32],
    peers: &[([u8; 32], SocketAddr)],
) -> io::Result<()> {
    let poller = Epoll::new(sock.as_raw_fd(), tun_fd)?;

    let mut qe = QuicEndpoint::new();
    let start = Instant::now();

    // Client-role peers we must dial; server-role peers are reached by accepting.
    let mut client_peers: Vec<ClientPeer> = peers
        .iter()
        .filter(|(pk, _)| connection_role(&local_pub, pk) == ConnRole::Client)
        .map(|(_, addr)| ClientPeer {
            addr: *addr,
            last_attempt: None,
        })
        .collect();

    // Symbol size is set once, when the first connection reaches 1-RTT, before
    // the inner yip handshake builds any DataPlane (received frames — which
    // trigger the inner handshake — are processed after this point each loop).
    let mut symbol_set = false;

    loop {
        let now = Instant::now();
        let mut out: Vec<OutPacket> = Vec::new();

        // (Re)dial any client-role peer whose connection is missing, debounced.
        for cp in &mut client_peers {
            if qe.has_conn_to(cp.addr) {
                continue;
            }
            let due = cp
                .last_attempt
                .is_none_or(|t| now.duration_since(t).as_millis() >= RECONNECT_DEBOUNCE_MS);
            if due {
                cp.last_attempt = Some(now);
                if let Err(e) = qe.connect(now, cp.addr) {
                    eprintln!("quic: connect to {} failed: {e:?}", cp.addr);
                }
            }
        }

        // Wait for I/O or the next quinn timer / 10 ms tick, whichever is sooner.
        let timeout_ms = qe.next_timeout_ms(now);
        let ready = poller.wait(timeout_ms)?;
        // Recompute the clock after the (up-to-10 ms) wait so the manager's
        // `now_ms` and quinn's `now` agree for this iteration's work.
        let now = Instant::now();
        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // 1. Ingest UDP → endpoint (routes to connections / accepts new ones).
        if ready.udp {
            recv_all_udp(&sock, &mut qe, now, &mut out)?;
        }

        // 2. Drive connections: events + received DATAGRAM frames + transmits.
        let mut recv: Vec<(SocketAddr, Bytes)> = Vec::new();
        let mut newly_up: Vec<usize> = Vec::new();
        qe.drive(now, &mut out, &mut recv, &mut newly_up);

        // 3. Symbol size: set once, from the first established connection's MDS.
        for mds in newly_up {
            if !symbol_set {
                manager.set_data_symbol_size(quic_symbol_size(mds));
                symbol_set = true;
            }
        }

        // 4. Each received DATAGRAM frame is a plain yip datagram → PeerManager.
        for (peer_addr, payload) in recv {
            let (tun, egress) = owned_out(manager.on_udp(peer_addr, &payload, now_ms));
            if let Some(inner) = tun {
                write_tun(tun_fd, &inner);
            }
            send_egress(&mut qe, &egress, now, &mut out);
        }

        // 5. TUN frames → PeerManager → QUIC egress.
        if ready.tun {
            drain_tun(tun_fd, manager, &mut qe, now, now_ms, &mut out);
        }

        // 6. Cadence tick (feedback / keepalive / handshake retry / cover).
        let ticked = manager.tick(now_ms).map(|dgs| dgs.to_vec());
        if let Some(egress) = ticked {
            send_egress(&mut qe, &egress, now, &mut out);
        }

        // 7. Flush any transmits the sends/handshake progression produced.
        qe.flush_transmits(now, &mut out);

        // 8. Put everything on the wire.
        for p in &out {
            let _ = sock.send_to(&p.bytes, p.dst);
        }
    }
}

/// Drain all pending datagrams from the UDP socket (non-blocking) into the
/// endpoint. Transient/would-block conditions end the drain; a fatal error
/// propagates.
fn recv_all_udp(
    sock: &UdpSocket,
    qe: &mut QuicEndpoint,
    now: Instant,
    out: &mut Vec<OutPacket>,
) -> io::Result<()> {
    let mut buf = [0u8; MAX_WIRE_DATAGRAM];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                qe.handle_datagram(now, from, BytesMut::from(&buf[..n]), out);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Drain all pending frames from the TUN device (non-blocking) through the
/// manager and out over QUIC. TUN read errors other than would-block are logged
/// and end the drain (a transient TUN read failure must not tear down the loop).
fn drain_tun(
    tun_fd: RawFd,
    manager: &mut PeerManager,
    qe: &mut QuicEndpoint,
    now: Instant,
    now_ms: u64,
    out: &mut Vec<OutPacket>,
) {
    let mut buf = [0u8; MAX_WIRE_DATAGRAM];
    loop {
        match read_fd(tun_fd, &mut buf) {
            Ok(0) => return,
            Ok(n) => {
                let egress = manager.on_tun(&buf[..n], now_ms).to_vec();
                send_egress(qe, &egress, now, out);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("quic: tun read error: {e}");
                return;
            }
        }
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// An in-process client+server pair driven synchronously (no real sockets,
    /// no netns): packets are shuttled by destination address, `now` advances
    /// monotonically in virtual time. This exercises exactly the pump surface
    /// `run_quic` uses (`handle_datagram` / `drive` / `send_datagram`).
    struct TestPair {
        client: QuicEndpoint,
        server: QuicEndpoint,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        now: Instant,
        pending: Vec<OutPacket>,
        recvd: Vec<(SocketAddr, Vec<u8>)>,
    }

    impl TestPair {
        fn new() -> Self {
            let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
            let server_addr: SocketAddr = "127.0.0.1:2".parse().unwrap();
            let mut client = QuicEndpoint::new();
            let server = QuicEndpoint::new();
            let now = Instant::now();
            client.connect(now, server_addr).expect("client connect");
            Self {
                client,
                server,
                client_addr,
                server_addr,
                now,
                pending: Vec::new(),
                recvd: Vec::new(),
            }
        }

        /// One round: drive both endpoints, then deliver every in-flight packet
        /// by destination address (which may enqueue stateless responses).
        fn round(&mut self) {
            let mut newly_up = Vec::new();
            let mut recv = Vec::new();
            self.client
                .drive(self.now, &mut self.pending, &mut recv, &mut newly_up);
            self.server
                .drive(self.now, &mut self.pending, &mut recv, &mut newly_up);
            for (addr, bytes) in recv {
                self.recvd.push((addr, bytes.to_vec()));
            }

            let batch = std::mem::take(&mut self.pending);
            for p in batch {
                if p.dst == self.server_addr {
                    self.server.handle_datagram(
                        self.now,
                        self.client_addr,
                        BytesMut::from(&p.bytes[..]),
                        &mut self.pending,
                    );
                } else if p.dst == self.client_addr {
                    self.client.handle_datagram(
                        self.now,
                        self.server_addr,
                        BytesMut::from(&p.bytes[..]),
                        &mut self.pending,
                    );
                }
            }
            self.now += Duration::from_millis(1);
        }

        fn run(&mut self, rounds: usize) {
            for _ in 0..rounds {
                self.round();
            }
        }

        fn established(&self) -> bool {
            self.client.conns.iter().any(|c| c.up) && self.server.conns.iter().any(|c| c.up)
        }

        fn client_max_datagram(&mut self) -> Option<usize> {
            self.client
                .conns
                .first_mut()
                .and_then(|c| c.conn.datagrams().max_size())
        }

        fn send_client(&mut self, payload: Bytes) -> Result<(), QuicSendError> {
            let mut out = Vec::new();
            let r = self
                .client
                .send_datagram(self.server_addr, payload, self.now, &mut out);
            self.pending.extend(out);
            r
        }
    }

    #[test]
    fn quic_symbol_size_matches_spec() {
        // Spike: mds 1414 ⇒ 1200 (unchanged from the raw path).
        assert_eq!(quic_symbol_size(1414), 1200);
        // Constrained path: 1000 − 28 = 972.
        assert_eq!(quic_symbol_size(1000), 972);
        // Exactly at the cap boundary: 1228 − 28 = 1200.
        assert_eq!(quic_symbol_size(1228), 1200);
        // Pathologically small: saturates to 0, never underflows/panics.
        assert_eq!(quic_symbol_size(10), 0);
    }

    #[test]
    fn connection_role_is_by_static_key_order() {
        let small = [0x01u8; 32];
        let large = [0x02u8; 32];
        assert_eq!(connection_role(&small, &large), ConnRole::Client);
        assert_eq!(connection_role(&large, &small), ConnRole::Server);
        // Degenerate tie (cannot happen in practice) resolves to Server.
        assert_eq!(connection_role(&small, &small), ConnRole::Server);
    }

    #[test]
    fn client_server_handshake_reaches_1rtt() {
        let mut pair = TestPair::new();
        pair.run(300);
        assert!(
            pair.established(),
            "both endpoints must reach 1-RTT via the sans-IO pump"
        );
    }

    #[test]
    fn yip_datagram_round_trips_through_a_datagram_frame() {
        let mut pair = TestPair::new();
        pair.run(300);
        assert!(pair.established(), "handshake must complete first");

        // A yip-datagram-sized blob (a plausible FEC symbol payload).
        let payload = Bytes::from(vec![0xABu8; 1000]);
        pair.send_client(payload.clone()).expect("send datagram");
        pair.run(30);

        // The server must have received exactly these bytes, tagged with the
        // client's address (the `on_udp` source the real PeerManager keys on).
        assert!(
            pair.recvd
                .iter()
                .any(|(addr, bytes)| *addr == pair.client_addr && bytes.as_slice() == payload),
            "server did not receive the datagram intact; got {:?}",
            pair.recvd
        );
    }

    #[test]
    fn oversized_datagram_is_rejected_not_truncated() {
        let mut pair = TestPair::new();
        pair.run(300);
        assert!(pair.established(), "handshake must complete first");

        let max = pair
            .client_max_datagram()
            .expect("established connection advertises a max datagram size");
        let oversized = Bytes::from(vec![0x5Au8; max + 1]);

        let err = pair
            .send_client(oversized)
            .expect_err("oversized datagram must be rejected");
        assert!(
            matches!(err, QuicSendError::Datagram(SendDatagramError::TooLarge)),
            "expected TooLarge, got {err:?}"
        );

        // And nothing of that size must reach the peer (no silent truncation).
        pair.run(20);
        assert!(
            !pair.recvd.iter().any(|(_, bytes)| bytes.len() > max),
            "an over-max datagram must never appear on the peer (would be truncation)"
        );
    }

    #[test]
    fn max_datagram_size_stays_within_symbol_budget() {
        // Sanity: a freshly-established connection's MDS yields a symbol size no
        // larger than the cap and strictly inside the datagram budget.
        let mut pair = TestPair::new();
        pair.run(300);
        assert!(pair.established());
        let mds = pair.client_max_datagram().expect("established MDS");
        let sym = quic_symbol_size(mds);
        assert!(sym <= QUIC_SYMBOL_CAP, "symbol size {sym} exceeds cap");
        assert!(
            usize::from(sym) + QUIC_YIP_OVERHEAD <= mds || sym == QUIC_SYMBOL_CAP,
            "symbol size {sym} + overhead must fit MDS {mds}"
        );
    }
}
