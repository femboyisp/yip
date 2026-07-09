#![forbid(unsafe_code)]

//! 3c.1 Task 1 de-risk spike: prove (with real `quinn-proto` code, not docs-reading) whether an
//! RFC 9221 unreliable DATAGRAM frame can be sent **promptly** through a `quinn-proto` QUIC
//! connection -- i.e. NOT queued behind congestion control / pacing -- and measure
//! `max_datagram_size()` (PMTUD) plus rough per-datagram overhead.
//!
//! This is throwaway/exploratory: it drives two `quinn-proto` `Endpoint`s (client + server) by
//! hand over real loopback `UdpSocket`s, with an artificial one-way delay layered on top so the
//! path behaves like a realistic ~50ms-RTT WAN link instead of a ~0ms loopback link (which would
//! hide congestion-control/pacing gating entirely). See
//! `.superpowers/sdd/task-1-report.md` for the full writeup of what this proves.
//!
//! Run: `cargo run --release -p yipd --example quic_spike`

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::congestion;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig,
    MtuDiscoveryConfig, RttEstimator, ServerConfig, Transmit, TransportConfig,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// One-way artificial link latency layered on top of real loopback UDP sends, so the spike
/// reflects a realistic WAN path (~50ms RTT) rather than loopback's ~0ms RTT, which would make
/// congestion-control/pacing gating invisible (the initial congestion window alone comfortably
/// covers a short burst at 0 RTT).
const ONE_WAY_LATENCY: Duration = Duration::from_millis(25);

// ---- No-op congestion controller: an always-huge window, which both (a) never trips the
// `in_flight.bytes + bytes_to_send >= window()` gate in `Connection::poll_transmit`, and
// (b) disables the pacer outright (quinn-proto's `Pacer::delay` early-returns `None` once
// `window > u32::MAX`). This is a first-class, documented extension point
// (`congestion::Controller` / `congestion::ControllerFactory`), not a hack. ----

/// Deliberately larger than `u32::MAX` (see module docs) but well clear of `u64::MAX` to leave
/// headroom in `in_flight.bytes + bytes_to_send` arithmetic.
const NO_CC_WINDOW: u64 = u64::MAX / 2;

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

#[derive(Debug)]
struct NoCcFactory;

impl congestion::ControllerFactory for NoCcFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn congestion::Controller> {
        Box::new(NoCcController)
    }
}

// ---- Accept-any-cert client verifier: the outer QUIC layer is a throwaway costume (zero auth
// by design). The inner yip Noise-IK handshake (unmodified by 3c.1) is the real security; a QUIC
// MITM recovers only inner yip ciphertext. See the 3c.1 spec's "double encryption is
// intentional" invariant. ----

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
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

/// The exact `TransportConfig` knobs this spike proves out. Task 4's `quic.rs` reuses these
/// verbatim (per the 3c.1 plan).
fn transport_config(no_cc: bool) -> Arc<TransportConfig> {
    let mut cfg = TransportConfig::default();
    // Generous datagram buffers: FEC bursts must never get silently dropped for lack of space.
    cfg.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    cfg.datagram_send_buffer_size(4 * 1024 * 1024);

    // PMTUD is on by default in quinn-proto, but set it explicitly: search up to a realistic
    // Ethernet/IPv4 ceiling.
    let mut mtud = MtuDiscoveryConfig::default();
    mtud.upper_bound(1452);
    cfg.mtu_discovery_config(Some(mtud));
    cfg.min_mtu(1200);
    cfg.initial_mtu(1200);

    if no_cc {
        cfg.congestion_controller_factory(Arc::new(NoCcFactory));
    }
    Arc::new(cfg)
}

fn gen_cert() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("self-signed cert generation");
    let cert_der = cert.cert.into();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (cert_der, key_der)
}

fn server_config(no_cc: bool) -> ServerConfig {
    let (cert, key) = gen_cert();
    let crypto = QuicServerConfig::try_from(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .expect("throwaway server cert"),
    )
    .expect("rustls ServerConfig -> QuicServerConfig");
    let mut cfg = ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport_config(no_cc));
    cfg
}

fn client_config(no_cc: bool) -> ClientConfig {
    let rustls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let crypto =
        QuicClientConfig::try_from(rustls_cfg).expect("rustls ClientConfig -> QuicClientConfig");
    let mut cfg = ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport_config(no_cc));
    cfg
}

fn send_transmit(sock: &UdpSocket, t: &Transmit, buf: &[u8]) {
    sock.send_to(&buf[..t.size], t.destination)
        .expect("loopback UDP send");
}

/// One QUIC endpoint + its (single) connection + an artificial-latency inbound queue, so a real
/// loopback UDP socket behaves like a ~50ms-RTT WAN path instead of a ~0ms loopback path.
struct Side {
    endpoint: Endpoint,
    sock: UdpSocket,
    addr: SocketAddr,
    conn: Option<(ConnectionHandle, Connection)>,
    /// Packets read off the socket but not yet delivered to `endpoint.handle`.
    delayed_inbound: VecDeque<(Instant, SocketAddr, BytesMut)>,
}

impl Side {
    fn new(endpoint: Endpoint, sock: UdpSocket) -> Self {
        let addr = sock.local_addr().expect("bound socket has a local addr");
        Self {
            endpoint,
            sock,
            addr,
            conn: None,
            delayed_inbound: VecDeque::new(),
        }
    }

    /// Read everything currently sitting in the OS socket buffer and queue it for delivery
    /// `ONE_WAY_LATENCY` from now (simulated network delay).
    fn pump_socket(&mut self) {
        let mut buf = [0u8; 65535];
        while let Ok((len, from)) = self.sock.recv_from(&mut buf) {
            self.delayed_inbound.push_back((
                Instant::now() + ONE_WAY_LATENCY,
                from,
                BytesMut::from(&buf[..len]),
            ));
        }
    }

    /// Deliver any queued inbound packets whose simulated arrival time has passed.
    fn process_due(&mut self, now: Instant) {
        while self
            .delayed_inbound
            .front()
            .is_some_and(|(due, _, _)| *due <= now)
        {
            let (_, from, data) = self
                .delayed_inbound
                .pop_front()
                .expect("front just checked");
            let mut resp_buf = Vec::with_capacity(2048);
            if let Some(event) = self
                .endpoint
                .handle(now, from, None, None, data, &mut resp_buf)
            {
                match event {
                    DatagramEvent::ConnectionEvent(ch, ev) => {
                        if let Some((cch, conn)) = self.conn.as_mut() {
                            if *cch == ch {
                                conn.handle_event(ev);
                            }
                        }
                    }
                    DatagramEvent::Response(t) => send_transmit(&self.sock, &t, &resp_buf),
                    DatagramEvent::NewConnection(incoming) => {
                        let mut buf = Vec::with_capacity(2048);
                        match self.endpoint.accept(incoming, now, &mut buf, None) {
                            Ok((ch, conn)) => self.conn = Some((ch, conn)),
                            Err(e) => {
                                if let Some(t) = e.response {
                                    send_transmit(&self.sock, &t, &buf);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Drive timers + drain events + drain transmits for this side's connection. Returns the
    /// number of UDP packets actually put on the wire.
    fn drive_conn(&mut self, now: Instant) -> usize {
        let mut sent = 0;
        if let Some((_, conn)) = self.conn.as_mut() {
            conn.handle_timeout(now);
            while conn.poll().is_some() {}
            let mut buf = Vec::with_capacity(2048);
            while let Some(t) = conn.poll_transmit(now, 1, &mut buf) {
                send_transmit(&self.sock, &t, &buf);
                sent += 1;
                buf.clear();
            }
        }
        sent
    }

    fn next_wakeup(&mut self, now: Instant) -> Instant {
        let timer = self
            .conn
            .as_mut()
            .and_then(|(_, c)| c.poll_timeout())
            .unwrap_or(now + Duration::from_millis(5));
        let inbound = self
            .delayed_inbound
            .front()
            .map(|(due, _, _)| *due)
            .unwrap_or(now + Duration::from_millis(5));
        timer.min(inbound).max(now)
    }
}

fn run_handshake(no_cc: bool) -> (Side, Side) {
    let ep_cfg = Arc::new(EndpointConfig::default());
    let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
    server_sock
        .set_nonblocking(true)
        .expect("nonblocking server socket");
    let client_sock = UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
    client_sock
        .set_nonblocking(true)
        .expect("nonblocking client socket");

    let server_ep = Endpoint::new(
        ep_cfg.clone(),
        Some(Arc::new(server_config(no_cc))),
        true,
        None,
    );
    let client_ep = Endpoint::new(ep_cfg, None, true, None);

    let mut server = Side::new(server_ep, server_sock);
    let mut client = Side::new(client_ep, client_sock);

    let now = Instant::now();
    let (client_ch, client_conn) = client
        .endpoint
        .connect(now, client_config(no_cc), server.addr, "localhost")
        .expect("client connect");
    client.conn = Some((client_ch, client_conn));
    client.drive_conn(now);

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut client_connected = false;
    let mut server_connected = false;

    loop {
        let now = Instant::now();
        assert!(now <= deadline, "handshake did not complete within 10s");

        client.pump_socket();
        server.pump_socket();
        client.process_due(now);
        server.process_due(now);
        client.drive_conn(now);
        server.drive_conn(now);

        if let Some((_, conn)) = client.conn.as_ref() {
            client_connected = client_connected || !conn.is_handshaking();
        }
        if let Some((_, conn)) = server.conn.as_ref() {
            server_connected = server_connected || !conn.is_handshaking();
        }

        if client_connected && server_connected {
            // A few more rounds so the final Handshake-space ACKs land and 1-RTT settles.
            for _ in 0..4 {
                std::thread::sleep(ONE_WAY_LATENCY);
                let now = Instant::now();
                client.pump_socket();
                server.pump_socket();
                client.process_due(now);
                server.process_due(now);
                client.drive_conn(now);
                server.drive_conn(now);
            }
            break;
        }

        let wake = client.next_wakeup(now).min(server.next_wakeup(now));
        if wake > now {
            std::thread::sleep((wake - now).min(Duration::from_millis(2)));
        }
    }

    (client, server)
}

/// Let PMTUD converge (it probes over several RTTs) before reading `max_datagram_size()`.
fn settle_mtu(client: &mut Side, server: &mut Side, budget: Duration) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let now = Instant::now();
        client.pump_socket();
        server.pump_socket();
        client.process_due(now);
        server.process_due(now);
        client.drive_conn(now);
        server.drive_conn(now);
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// After handshake: fire N datagrams back-to-back (a burst, as FEC bursts would), and record
/// wall-clock latency from each `datagrams().send()` call to the moment `poll_transmit` actually
/// emits that datagram's packet onto the wire. Meanwhile keep pumping both sides (with the
/// artificial ~50ms RTT) so ACKs can arrive and CC/pacing react realistically.
fn measure_burst_latency(client: &mut Side, server: &mut Side, n: usize) -> (Vec<Duration>, usize) {
    let payload_len = {
        let (_, conn) = client.conn.as_mut().expect("client connected");
        conn.datagrams().max_size().unwrap_or(1162).min(1200)
    };

    let mut send_times = Vec::with_capacity(n);
    {
        let (_, conn) = client.conn.as_mut().expect("client connected");
        for _ in 0..n {
            let payload = Bytes::from(vec![0xABu8; payload_len]);
            send_times.push(Instant::now());
            conn.datagrams().send(payload, true).expect("send datagram");
        }
    }

    let mut on_wire_times: Vec<Instant> = Vec::with_capacity(n);
    let deadline = Instant::now() + Duration::from_secs(3);
    while on_wire_times.len() < n && Instant::now() < deadline {
        let now = Instant::now();
        client.pump_socket();
        server.pump_socket();
        client.process_due(now);
        server.process_due(now);

        // Drain the client's transmit queue one packet at a time, timestamping each.
        if let Some((_, conn)) = client.conn.as_mut() {
            conn.handle_timeout(now);
            while conn.poll().is_some() {}
            let mut buf = Vec::with_capacity(2048);
            while let Some(t) = conn.poll_transmit(now, 1, &mut buf) {
                send_transmit(&client.sock, &t, &buf);
                on_wire_times.push(Instant::now());
                buf.clear();
            }
        }
        server.drive_conn(now);

        std::thread::sleep(Duration::from_micros(100));
    }

    let dropped = n - on_wire_times.len();
    let latencies = send_times
        .iter()
        .zip(on_wire_times.iter())
        .map(|(s, w)| *w - *s)
        .collect();
    (latencies, dropped)
}

fn summarize(label: &str, latencies: &[Duration], dropped: usize) {
    if latencies.is_empty() {
        println!("  {label}: no datagrams made it to the wire (dropped={dropped})");
        return;
    }
    let max = latencies.iter().max().expect("non-empty");
    let min = latencies.iter().min().expect("non-empty");
    let sum: Duration = latencies.iter().sum();
    let avg = sum / u32::try_from(latencies.len()).unwrap_or(1);
    let over_1ms = latencies
        .iter()
        .filter(|d| **d > Duration::from_millis(1))
        .count();
    println!(
        "  {label}: n={} dropped={} min={:?} avg={:?} max={:?} count>1ms={}",
        latencies.len(),
        dropped,
        min,
        avg,
        max,
        over_1ms
    );
    for (i, d) in latencies.iter().enumerate() {
        println!("    [{i:>3}] {d:?}");
    }
}

fn run_case(label: &str, no_cc: bool) {
    println!("\n=== {label} (no_cc={no_cc}, simulated one-way latency={ONE_WAY_LATENCY:?}) ===");
    let (mut client, mut server) = run_handshake(no_cc);
    println!("  handshake complete");

    settle_mtu(&mut client, &mut server, Duration::from_millis(800));
    let max_size = {
        let (_, conn) = client.conn.as_mut().expect("client connected");
        conn.datagrams().max_size()
    };
    println!("  client max_datagram_size() after PMTUD settle = {max_size:?}");

    let (latencies, dropped) = measure_burst_latency(&mut client, &mut server, 40);
    summarize("burst of 40 datagrams", &latencies, dropped);
}

/// Rough per-datagram CPU cost: a quinn-proto (NoCc) send+poll_transmit+recv+ack-drain loop vs a
/// bare `UdpSocket::send_to`/`recv_from` loop of the same size and count, same process.
fn bench_cpu_cost() {
    println!("\n=== rough per-datagram CPU cost (NoCc quinn-proto vs bare UDP) ===");
    const N: usize = 2000;

    // Bare UDP baseline.
    let a = UdpSocket::bind("127.0.0.1:0").expect("bind a");
    let b = UdpSocket::bind("127.0.0.1:0").expect("bind b");
    let b_addr = b.local_addr().expect("b has local addr");
    let payload = vec![0xABu8; 1200];
    let start = Instant::now();
    let mut recv_buf = [0u8; 2048];
    for _ in 0..N {
        a.send_to(&payload, b_addr).expect("bare send");
        b.recv_from(&mut recv_buf).expect("bare recv");
    }
    let bare_elapsed = start.elapsed();
    println!(
        "  bare UDP:            {N} datagrams in {bare_elapsed:?}  ({:?}/datagram)",
        bare_elapsed / u32::try_from(N).unwrap_or(1)
    );

    // quinn-proto with NoCcController, steady state (post-handshake, post-MTU-settle).
    let (mut client, mut server) = run_handshake(true);
    settle_mtu(&mut client, &mut server, Duration::from_millis(500));
    let payload_len = client
        .conn
        .as_mut()
        .expect("client connected")
        .1
        .datagrams()
        .max_size()
        .unwrap_or(1162)
        .min(1200);

    let start = Instant::now();
    let mut sent = 0usize;
    while sent < N {
        {
            let (_, conn) = client.conn.as_mut().expect("client connected");
            let payload = Bytes::from(vec![0xABu8; payload_len]);
            if conn.datagrams().send(payload, true).is_ok() {
                sent += 1;
            }
        }
        let now = Instant::now();
        client.pump_socket();
        server.pump_socket();
        client.process_due(now);
        server.process_due(now);
        client.drive_conn(now);
        server.drive_conn(now);
    }
    let quic_elapsed = start.elapsed();
    println!(
        "  quinn-proto (NoCc):  {N} datagrams in {quic_elapsed:?}  ({:?}/datagram)",
        quic_elapsed / u32::try_from(N).unwrap_or(1)
    );
    println!(
        "  overhead ratio: {:.2}x bare UDP",
        quic_elapsed.as_secs_f64() / bare_elapsed.as_secs_f64()
    );
}

fn main() {
    run_case("default Cubic CC (baseline / at-risk)", false);
    run_case("NoCcController (proposed fix)", true);
    bench_cpu_cost();
}
