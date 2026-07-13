//! TLS-mimicry transport (3c.2): a **BoringSSL** (`boring` crate) TLS-over-TCP
//! costume carrying yip's UNCHANGED inner protocol (Noise-IK / FEC / AEAD via
//! [`PeerManager`]), framed as length-prefixed datagrams over the TLS
//! byte-stream. Mirrors `quic.rs` (3c.1) — TCP+TLS in place of QUIC-over-UDP.
//!
//! # Why `boring`, not `rustls`
//!
//! The Task-0 spike (`crates/yip-bench/RESULTS.md` "3c.2 spike") found rustls
//! has no GREASE support, so its ClientHello has a distinctive "Rust TLS
//! client" JA3/JA4 no matter how its cipher/extension list is coaxed. BoringSSL
//! GREASEs by default and exposes the cipher/extension/curve control needed to
//! tune toward a real browser fingerprint (JA4 already browser-*shaped* out of
//! the box, tunable to an exact Chrome recipe). The tradeoff: `boring-sys`
//! vendors and compiles BoringSSL (needs `cmake` + a C/C++ toolchain), a new
//! hard build dependency for `yipd` + CI that plain rustls did not have.
//!
//! # Two layers
//!
//! - **Outer TLS (the costume, zero-auth by design):** a real BoringSSL TLS 1.3
//!   session. The client sends a GREASE-enabled ClientHello (the browser-parrot
//!   signal) with SNI = the configured `tls_sni`, ALPN `h2`/`http/1.1`, and an
//!   accept-any-cert verifier (`SslVerifyMode::NONE`); the server presents a
//!   throwaway self-signed cert for `tls_sni`. A TLS MITM recovers only inner
//!   yip ciphertext — the outer TLS authenticates nothing, exactly as 3c.1's
//!   QUIC costume.
//! - **Inner yip (the real security), UNCHANGED:** every yip datagram the
//!   raw-UDP path would put directly on the wire is instead length-prefixed
//!   (`frame_datagram`/[`FrameReader`], `[u16 BE length][datagram bytes]`) and
//!   written to the TLS byte-stream. [`PeerManager`] still runs the Noise-IK
//!   handshake, FEC, AEAD, cert admission and anti-hijack exactly as on the raw
//!   path — this module is purely the transport.
//!
//! # Architecture: single-connection `run_tls` pump
//!
//! Unlike `run_quic` (one `Endpoint` multiplexing many peer connections),
//! [`run_tls`] is scoped to a **single** active TCP+TLS connection: the small
//! safe [`Epoll`] primitive this pump uses (so all `unsafe` stays in `yip-io`
//! and `yipd` keeps `#![forbid(unsafe_code)]`) watches exactly two fds, and a
//! TCP socket's fd is not stable across reconnects the way a UDP socket's is.
//! yip is peer-to-peer, so a deterministic role-by-static-key-order tiebreak
//! (mirroring 3c.1) keeps it to one connection: the peer with the **smaller**
//! `local_public` is the TCP **client**; the **larger** is the **server**.
//! Multi-peer TLS mesh (more than one TLS-transport peer) is a documented
//! follow-up — see the `TODO(3c.2 follow-up)` in [`run_tls`].
//!
//! # Non-blocking BoringSSL (`WANT_READ`/`WANT_WRITE`)
//!
//! The TCP stream is set non-blocking (a side effect of [`Epoll::new`]).
//! BoringSSL's handshake/read/write calls on a non-blocking stream return
//! [`boring::ssl::ErrorCode::WANT_READ`]/`WANT_WRITE` instead of blocking; the
//! standard pattern — wait for the fd, then retry the same call — is
//! implemented by [`drive_handshake`] (handshake) and [`drain_tls_read`] /
//! [`write_all_tls`] (steady-state I/O). The [`Epoll`] primitive only watches
//! `EPOLLIN`, so `WANT_WRITE` is handled with a short bounded retry rather than
//! a true wait-for-writability — see [`WOULD_BLOCK_RETRY_MS`] for why that is
//! an acceptable tradeoff here.
//!
//! # Reconnect
//!
//! On any TLS/TCP/framing error the connection is torn down (fail-closed,
//! never touching `PeerManager` state). The **client** re-dials with backoff
//! (`INITIAL_BACKOFF_MS` doubling to `MAX_BACKOFF_MS`); the **server** goes
//! back to `accept()`. The inner Noise-IK session re-handshakes naturally once
//! datagrams flow again — this module never resets `PeerManager`.

use std::cmp::Ordering;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use boring::pkey::{PKey, Private};
use boring::ssl::{
    select_next_proto, AlpnError, ErrorCode, HandshakeError, SslAcceptor, SslConnector, SslMethod,
    SslStream, SslVerifyMode,
};
use boring::x509::X509;

use yip_io::epoll::{read_fd, write_fd, Epoll};
use yip_io::poll::{Dispatch, DispatchOut, EgressDatagram};

use crate::peer_manager::PeerManager;

pub(crate) const TLS_FRAME_MAX: usize = yip_io::MAX_WIRE_DATAGRAM;

/// Append `[u16 BE length][dg]` to `out`. Errors if `dg` exceeds `TLS_FRAME_MAX`.
pub(crate) fn frame_datagram(dg: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let len = u16::try_from(dg.len())
        .ok()
        .filter(|_| dg.len() <= TLS_FRAME_MAX)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram too large for TLS frame",
            )
        })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(dg);
    Ok(())
}

/// Reassembles length-prefixed datagrams from a TLS plaintext byte-stream.
#[derive(Default)]
pub(crate) struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// Append freshly-decrypted TLS plaintext.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pop one complete datagram; `Ok(None)` if incomplete. Fail-closed on a zero
    /// or `> TLS_FRAME_MAX` length prefix (a hostile/corrupt peer).
    pub(crate) fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let len = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
        if len == 0 || len > TLS_FRAME_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad TLS frame length",
            ));
        }
        if self.buf.len() < 2 + len {
            return Ok(None);
        }
        let dg = self.buf[2..2 + len].to_vec();
        self.buf.drain(..2 + len);
        Ok(Some(dg))
    }
}

// ── tunables ────────────────────────────────────────────────────────────────

/// Non-blocking `WANT_READ`/`WANT_WRITE` retry wait, in ms, used by
/// [`drive_handshake`] and [`write_all_tls`]. [`Epoll`] only watches `EPOLLIN`
/// on its two fds (no `EPOLLOUT`), so a `WANT_WRITE` cannot be waited on
/// precisely; instead this retries after a short bounded wait, giving the
/// kernel a chance to drain the TCP send buffer. In practice this is rare: TCP
/// send buffers are many KB and yip's frames are far smaller, so `WANT_WRITE`
/// on a fresh write essentially never happens. `WANT_READ` (the common case —
/// e.g. waiting for the rest of the peer's handshake flight) is exactly what
/// `Epoll::wait` blocks on.
const WOULD_BLOCK_RETRY_MS: i32 = 20;

/// Fixed per-iteration pump cadence: `PeerManager::tick` must fire at least
/// every 10 ms (mirrors `run_quic`/`run_poll`). TCP+TLS has no analogue to
/// QUIC's dynamic `poll_timeout`, so this is a plain constant.
const TICK_MS: i32 = 10;

/// Reconnect / re-accept backoff: starts at 100 ms, doubles, caps at ~5 s.
const INITIAL_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_MS: u64 = 5_000;

/// Maximum wall-clock a single TLS handshake may take before it is abandoned.
/// Without this bound a peer that opens a TCP connection and then stalls (never
/// sending its next handshake flight) would pin `run_tls`'s single connection
/// slot indefinitely — an off-path, zero-crypto DoS, since the outer TLS is
/// zero-auth and `run_tls` serves one connection at a time. On timeout the
/// connection is dropped and the server re-accepts (or the client re-dials).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// ALPN protocols offered (client) / accepted (server), RFC 7301 wire format
/// (one-byte length prefix per protocol name): `h2` then `http/1.1`, matching
/// a real browser's HTTP/2-preferred offer (the QUIC-costume sibling in
/// `quic.rs` uses ALPN `h3` for the same reason).
const TLS_ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";

// ── BoringSSL config builders ──────────────────────────────────────────────

/// Client-side BoringSSL config: GREASE-enabled (the browser-parrot signal —
/// `crates/yip-bench/RESULTS.md` "3c.2 spike" recorded boring's default
/// cipher/extension set as already browser-*shaped* with GREASE present;
/// exact current-Chrome tuning is deferred to the nDPI-oracle-driven Task 6,
/// not blocked on here) and zero-auth verify (the outer TLS authenticates
/// nothing — inner yip Noise-IK is the real security, exactly like `quic.rs`'s
/// `SkipServerVerification`).
fn build_client_connector() -> io::Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(io::Error::other)?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_grease_enabled(true);
    builder
        .set_alpn_protos(TLS_ALPN_WIRE)
        .map_err(io::Error::other)?;
    Ok(builder.build())
}

/// Server-side BoringSSL config: a throwaway self-signed cert for `tls_sni`
/// (mirrors `quic.rs`'s `gen_cert`) on a modern (TLS 1.2+, no legacy ciphers)
/// `mozilla_intermediate_v5` base configuration.
fn build_server_acceptor(tls_sni: &str) -> io::Result<SslAcceptor> {
    let (cert, key) = gen_cert(tls_sni)?;
    let mut builder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(io::Error::other)?;
    builder.set_certificate(&cert).map_err(io::Error::other)?;
    builder.set_private_key(&key).map_err(io::Error::other)?;
    builder.set_alpn_select_callback(|_ssl, client_protos| {
        select_next_proto(TLS_ALPN_WIRE, client_protos).ok_or(AlpnError::NOACK)
    });
    Ok(builder.build())
}

/// Generate a throwaway self-signed server certificate for `tls_sni` (the
/// outer TLS costume; zero-auth by design — see module docs).
fn gen_cert(tls_sni: &str) -> io::Result<(X509, PKey<Private>)> {
    let certified =
        rcgen::generate_simple_self_signed(vec![tls_sni.to_owned()]).map_err(io::Error::other)?;
    let cert = X509::from_der(certified.cert.der()).map_err(io::Error::other)?;
    let key = PKey::private_key_from_pkcs8(&certified.key_pair.serialize_der())
        .map_err(io::Error::other)?;
    Ok((cert, key))
}

/// Convert a BoringSSL error into an `io::Error` (`Other`, wrapping the cause).
fn ssl_error_to_io(e: boring::ssl::Error) -> io::Error {
    io::Error::other(e)
}

// ── non-blocking handshake / read / write helpers ──────────────────────────

/// Drive a BoringSSL handshake to completion on a non-blocking stream,
/// retrying on `WANT_READ`/`WANT_WRITE` by waiting on `poller` between
/// attempts (the standard non-blocking OpenSSL/BoringSSL pattern:
/// `MidHandshakeSslStream::handshake` is re-invoked on the *same* in-progress
/// handshake state after each wait, not restarted).
fn drive_handshake<S>(
    mut result: Result<SslStream<S>, HandshakeError<S>>,
    poller: &Epoll,
    deadline: Instant,
) -> io::Result<SslStream<S>>
where
    S: io::Read + io::Write,
{
    loop {
        result = match result {
            Ok(stream) => return Ok(stream),
            Err(HandshakeError::SetupFailure(e)) => return Err(io::Error::other(e)),
            Err(HandshakeError::Failure(mid)) => {
                return Err(io::Error::other(format!(
                    "tls handshake failed: {}",
                    mid.error()
                )));
            }
            Err(HandshakeError::WouldBlock(mid)) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tls handshake did not complete within HANDSHAKE_TIMEOUT",
                    ));
                }
                poller.wait(WOULD_BLOCK_RETRY_MS)?;
                mid.handshake()
            }
        };
    }
}

/// Drain all TLS plaintext currently available (non-blocking) into `reader`.
/// Returns once the stream would block (the normal "caught up" exit) or on a
/// genuine TLS/TCP error (peer close, malformed record, etc — connection-level,
/// the caller tears the connection down).
fn drain_tls_read(
    stream: &mut SslStream<TcpStream>,
    reader: &mut FrameReader,
    buf: &mut [u8],
) -> io::Result<()> {
    loop {
        match stream.ssl_read(buf) {
            Ok(0) => return Ok(()),
            Ok(n) => reader.push(&buf[..n]),
            Err(e) => match e.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => return Ok(()),
                ErrorCode::ZERO_RETURN => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls: peer sent close_notify",
                    ));
                }
                _ => return Err(ssl_error_to_io(e)),
            },
        }
    }
}

/// Write `buf` in full to the TLS stream, retrying `WANT_READ`/`WANT_WRITE` by
/// waiting on `poller` (see [`WOULD_BLOCK_RETRY_MS`]) and looping on partial
/// writes.
fn write_all_tls(
    stream: &mut SslStream<TcpStream>,
    poller: &Epoll,
    mut buf: &[u8],
) -> io::Result<()> {
    while !buf.is_empty() {
        match stream.ssl_write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tls: ssl_write wrote 0 bytes",
                ));
            }
            Ok(n) => buf = &buf[n..],
            Err(e) => match e.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                    poller.wait(WOULD_BLOCK_RETRY_MS)?;
                }
                _ => return Err(ssl_error_to_io(e)),
            },
        }
    }
    Ok(())
}

/// Frame each egress datagram and write the batch to the TLS stream. A no-op
/// (no write syscall) when `egress` is empty.
fn send_egress(
    stream: &mut SslStream<TcpStream>,
    poller: &Epoll,
    egress: &[EgressDatagram],
    write_buf: &mut Vec<u8>,
) -> io::Result<()> {
    if egress.is_empty() {
        return Ok(());
    }
    write_buf.clear();
    for d in egress {
        frame_datagram(&d.bytes, write_buf)?;
    }
    write_all_tls(stream, poller, write_buf)
}

/// Take a `PeerManager` UDP outcome as owned data, decoupling it from the
/// manager borrow (mirrors `quic.rs`'s `owned_out`).
fn owned_out(out: DispatchOut<'_>) -> (Option<Vec<u8>>, Vec<EgressDatagram>) {
    match out {
        DispatchOut::None => (None, Vec::new()),
        DispatchOut::Tun(inner) => (Some(inner.to_vec()), Vec::new()),
        DispatchOut::Udp(dgs) => (None, dgs.to_vec()),
        DispatchOut::Both(inner, dgs) => (Some(inner.to_vec()), dgs.to_vec()),
    }
}

/// Write a decoded inner frame to the TUN device (best-effort: a single failed
/// write is logged and swallowed rather than tearing down the tunnel).
fn write_tun(tun_fd: RawFd, inner: &[u8]) {
    if let Err(e) = write_fd(tun_fd, inner) {
        eprintln!("tls: tun write error: {e}");
    }
}

/// Drain all pending frames from the TUN device (non-blocking) through the
/// manager and out over the TLS stream. TUN read errors other than
/// would-block are logged and end the drain (a transient TUN read failure must
/// not tear down the connection); a TLS write error propagates so the caller
/// tears the connection down (fail-closed).
fn drain_tun_tls(
    tun_fd: RawFd,
    manager: &mut PeerManager,
    stream: &mut SslStream<TcpStream>,
    poller: &Epoll,
    buf: &mut [u8],
    write_buf: &mut Vec<u8>,
    now_ms: u64,
) -> io::Result<()> {
    loop {
        match read_fd(tun_fd, buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                let egress = manager.on_tun(&buf[..n], now_ms).to_vec();
                send_egress(stream, poller, &egress, write_buf)?;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("tls: tun read error: {e}");
                return Ok(());
            }
        }
    }
}

// ── role tiebreak (mirrors quic.rs's connection_role) ──────────────────────

/// The TCP+TLS role this node takes toward the (single, first-configured)
/// peer, decided by static-key order to avoid glare (two connections racing
/// for one pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Smaller `local_public` ⇒ we `TcpStream::connect` + TLS client handshake.
    Client,
    /// Larger `local_public` ⇒ we `TcpListener::accept` + TLS server handshake.
    Server,
}

/// Decide our TCP+TLS role toward `peer_pub`: the smaller static key is the
/// client. Equal keys cannot occur for a genuine distinct peer.
fn connection_role(local_pub: &[u8; 32], peer_pub: &[u8; 32]) -> io::Result<Role> {
    match local_pub.cmp(peer_pub) {
        Ordering::Less => Ok(Role::Client),
        Ordering::Greater => Ok(Role::Server),
        Ordering::Equal => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local_public == peer public key: impossible for a distinct peer",
        )),
    }
}

// ── connect / accept ────────────────────────────────────────────────────────

/// Dial `peer_endpoint`, set the stream non-blocking (via [`Epoll::new`]), and
/// drive the TLS client handshake (browser-parrot ClientHello, SNI =
/// `tls_sni`) to completion.
fn connect_and_handshake(
    peer_endpoint: SocketAddr,
    tls_sni: &str,
    tun_fd: RawFd,
) -> io::Result<(SslStream<TcpStream>, Epoll)> {
    let tcp = TcpStream::connect(peer_endpoint)?;
    // Disable Nagle: the pump issues many small ssl_writes (ticks, keepalives,
    // small inner datagrams); Nagle+delayed-ACK would add up to ~40 ms latency
    // per small write, gratuitously so on a latency-sensitive VPN.
    tcp.set_nodelay(true)?;
    let tcp_fd = tcp.as_raw_fd();
    let poller = Epoll::new(tcp_fd, tun_fd)?;
    let connector = build_client_connector()?;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let stream = drive_handshake(connector.connect(tls_sni, tcp), &poller, deadline)?;
    Ok((stream, poller))
}

/// Accept one connection on `listener`, set the stream non-blocking (via
/// [`Epoll::new`]), and drive the TLS server handshake (throwaway self-signed
/// cert for `tls_sni`) to completion. `expected_peer` is the configured peer
/// endpoint, logged (not enforced — the inner Noise-IK handshake is the real
/// authentication, exactly as `quic.rs` does not authenticate by UDP source)
/// if the actual TCP peer address differs.
fn accept_and_handshake(
    listener: &TcpListener,
    tls_sni: &str,
    tun_fd: RawFd,
    expected_peer: SocketAddr,
) -> io::Result<(SslStream<TcpStream>, Epoll)> {
    let (tcp, accepted_from) = listener.accept()?;
    if accepted_from.ip() != expected_peer.ip() {
        eprintln!(
            "tls: accepted TCP connection from {accepted_from} but the configured peer is \
             {expected_peer}; proceeding (inner Noise-IK is the real authentication)"
        );
    }
    // Disable Nagle (see connect_and_handshake) — same low-latency rationale.
    tcp.set_nodelay(true)?;
    let tcp_fd = tcp.as_raw_fd();
    let poller = Epoll::new(tcp_fd, tun_fd)?;
    let acceptor = build_server_acceptor(tls_sni)?;
    // Bound the handshake: a peer that connects then stalls must not pin this
    // (single) connection slot forever — on timeout we drop and re-accept.
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let stream = drive_handshake(acceptor.accept(tcp), &poller, deadline)?;
    Ok((stream, poller))
}

// ── the pump ─────────────────────────────────────────────────────────────────

/// Drive one live TLS connection until it is torn down (fail-closed on any
/// TLS/TCP/framing error) or a fatal I/O error occurs. Mirrors `run_quic`'s
/// per-iteration pump ordering: TLS-readable → de-frame → `PeerManager::on_udp`;
/// TUN-readable → `PeerManager::on_tun`; then the fixed 10 ms cadence tick.
///
/// Returns `Ok(())` when the connection was torn down for a connection-level
/// reason (logged; the caller reconnects). A fatal error (the epoll primitive
/// itself failing) propagates via `?` and ends [`run_tls`] entirely.
fn pump(
    mut stream: SslStream<TcpStream>,
    poller: &Epoll,
    tun_fd: RawFd,
    manager: &mut PeerManager,
    peer_addr: SocketAddr,
    start: Instant,
) -> io::Result<()> {
    let mut reader = FrameReader::default();
    let mut tls_read_buf = [0u8; TLS_FRAME_MAX];
    let mut tun_read_buf = [0u8; TLS_FRAME_MAX];
    let mut write_buf: Vec<u8> = Vec::new();

    loop {
        let ready = poller.wait(TICK_MS)?;
        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // 1. TLS-readable: drain plaintext, de-frame, feed PeerManager::on_udp.
        if ready.udp {
            if let Err(e) = drain_tls_read(&mut stream, &mut reader, &mut tls_read_buf) {
                eprintln!("tls: connection read error, tearing down: {e}");
                return Ok(());
            }
            loop {
                match reader.next() {
                    Ok(Some(dg)) => {
                        let (tun, egress) = owned_out(manager.on_udp(peer_addr, &dg, now_ms));
                        if let Some(inner) = tun {
                            write_tun(tun_fd, &inner);
                        }
                        if let Err(e) = send_egress(&mut stream, poller, &egress, &mut write_buf) {
                            eprintln!("tls: connection write error, tearing down: {e}");
                            return Ok(());
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("tls: malformed frame, tearing down: {e}");
                        return Ok(());
                    }
                }
            }
        }

        // 2. TUN-readable: PeerManager::on_tun → TLS egress.
        if ready.tun {
            if let Err(e) = drain_tun_tls(
                tun_fd,
                manager,
                &mut stream,
                poller,
                &mut tun_read_buf,
                &mut write_buf,
                now_ms,
            ) {
                eprintln!("tls: connection write error, tearing down: {e}");
                return Ok(());
            }
        }

        // 3. Cadence tick (feedback / keepalive / handshake retry / cover).
        if let Some(egress) = manager.tick(now_ms).map(|dgs| dgs.to_vec()) {
            if let Err(e) = send_egress(&mut stream, poller, &egress, &mut write_buf) {
                eprintln!("tls: connection write error, tearing down: {e}");
                return Ok(());
            }
        }
    }
}

// ── public entry point ─────────────────────────────────────────────────────

/// Run the TLS-mimicry data loop until a fatal I/O error.
///
/// `peers` is the list of `(peer_public_key, endpoint)` for every configured
/// peer; only the **first** is served (see the follow-up note below). `listen`
/// is the local TCP listen address used when this node is the TLS server role
/// (see [`connection_role`]) — **note:** this parameter is not present in the
/// 3c.2 task brief's `run_tls` signature; it was added here because the pump
/// structurally needs a bind address for the server role and no other
/// parameter supplies one (Task 6, which wires `tunnel.rs` to call this
/// function, is expected to pass `config.listen`, the same address already
/// used for the raw-UDP/QUIC sockets).
///
/// `manager` is driven UNCHANGED — it runs the inner yip Noise-IK/FEC/AEAD
/// protocol inside the TLS byte-stream.
pub(crate) fn run_tls(
    tun_fd: RawFd,
    manager: &mut PeerManager,
    local_public: [u8; 32],
    peers: &[([u8; 32], SocketAddr)],
    listen: SocketAddr,
    tls_sni: &str,
) -> io::Result<()> {
    // TODO(3c.2 follow-up): multi-peer TLS. `run_tls` is scoped to a single
    // active TCP+TLS connection (the safe `Epoll` primitive it uses watches
    // exactly two fds); only the first configured peer is served. A multi-peer
    // TLS mesh needs either one `run_tls` per peer on distinct threads/ports or
    // a dedicated multiplexing pump analogous to `quic.rs`'s `QuicEndpoint`.
    let (peer_public, peer_addr) = *peers.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport=tls requires at least one configured peer",
        )
    })?;

    let role = connection_role(&local_public, &peer_public)?;

    let listener = match role {
        Role::Server => Some(TcpListener::bind(listen)?),
        Role::Client => None,
    };

    let start = Instant::now();
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        let attempt = match role {
            Role::Client => connect_and_handshake(peer_addr, tls_sni, tun_fd),
            Role::Server => {
                // `listener` is `Some` for every iteration when `role == Server`
                // (set once, above, before this loop, and never cleared).
                let listener = listener.as_ref().expect("listener set for Server role");
                accept_and_handshake(listener, tls_sni, tun_fd, peer_addr)
            }
        };

        let (stream, poller) = match attempt {
            Ok(pair) => pair,
            Err(e) => {
                // Back off on failure for BOTH roles. The server previously
                // retried `accept()` with zero delay, so a peer that connects
                // and immediately RSTs / sends a bad ClientHello (or fails the
                // handshake deadline) could spin this loop at unbounded rate,
                // burning CPU and flooding stderr. Backoff resets on the next
                // successful connection, so a legitimate peer arriving after one
                // failed attempt waits at most INITIAL_BACKOFF_MS.
                eprintln!("tls: {role:?} connection setup failed: {e}");
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };
        backoff_ms = INITIAL_BACKOFF_MS;

        pump(stream, &poller, tun_fd, manager, peer_addr, start)?;
        // `pump` returns `Ok(())` only on a connection-level teardown (already
        // logged inside `pump`); loop back to reconnect/re-accept. A fatal
        // infra error (e.g. `Epoll`/`poller.wait` failing) propagates out of
        // `pump` via `?` and, via the `?` on this call, out of `run_tls`.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_single() {
        let dg = b"hello yip";
        let mut wire = Vec::new();
        frame_datagram(dg, &mut wire).unwrap();
        let mut r = FrameReader::default();
        r.push(&wire);
        assert_eq!(r.next().unwrap().unwrap(), dg);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn frame_reassembles_across_partial_reads() {
        let dg = vec![0xABu8; 1200];
        let mut wire = Vec::new();
        frame_datagram(&dg, &mut wire).unwrap();
        let mut r = FrameReader::default();
        // deliver the wire in three arbitrary chunks
        r.push(&wire[..1]);
        assert!(r.next().unwrap().is_none());
        r.push(&wire[1..700]);
        assert!(r.next().unwrap().is_none());
        r.push(&wire[700..]);
        assert_eq!(r.next().unwrap().unwrap(), dg);
    }

    #[test]
    fn frame_two_back_to_back() {
        let (a, b) = (b"aaa".as_slice(), b"bbbb".as_slice());
        let mut wire = Vec::new();
        frame_datagram(a, &mut wire).unwrap();
        frame_datagram(b, &mut wire).unwrap();
        let mut r = FrameReader::default();
        r.push(&wire);
        assert_eq!(r.next().unwrap().unwrap(), a);
        assert_eq!(r.next().unwrap().unwrap(), b);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn frame_oversize_body_errs_on_write() {
        let big = vec![0u8; TLS_FRAME_MAX + 1];
        assert!(frame_datagram(&big, &mut Vec::new()).is_err());
    }

    #[test]
    fn reader_rejects_zero_and_oversize_len() {
        let mut r = FrameReader::default();
        r.push(&[0u8, 0]); // len 0
        assert!(r.next().is_err());
        let mut r2 = FrameReader::default();
        let bad = u16::try_from(TLS_FRAME_MAX).unwrap().wrapping_add(1);
        // only valid if TLS_FRAME_MAX < u16::MAX; if TLS_FRAME_MAX >= 65535 this
        // arm is unreachable — assert the max instead. Guard accordingly.
        if usize::from(bad) > TLS_FRAME_MAX && bad != 0 {
            r2.push(&bad.to_be_bytes());
            assert!(r2.next().is_err());
        }
    }

    #[test]
    fn connection_role_is_by_static_key_order() {
        let small = [0x01u8; 32];
        let large = [0x02u8; 32];
        assert_eq!(connection_role(&small, &large).unwrap(), Role::Client);
        assert_eq!(connection_role(&large, &small).unwrap(), Role::Server);
        assert!(connection_role(&small, &small).is_err());
    }

    /// Write `buf` in full on a *blocking* stream (no `WANT_READ`/`WANT_WRITE`
    /// can occur, so no epoll/poller is needed — unlike [`super::write_all_tls`]
    /// which is for the non-blocking pump).
    fn blocking_write_all(stream: &mut SslStream<TcpStream>, mut buf: &[u8]) {
        while !buf.is_empty() {
            let n = stream.ssl_write(buf).expect("ssl_write");
            buf = &buf[n..];
        }
    }

    /// Read one complete framed datagram from a *blocking* stream.
    fn blocking_read_one(stream: &mut SslStream<TcpStream>, reader: &mut FrameReader) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        loop {
            if let Some(dg) = reader.next().expect("well-formed frame") {
                return dg;
            }
            let n = stream.ssl_read(&mut buf).expect("ssl_read");
            assert!(n > 0, "peer closed before a full datagram arrived");
            reader.push(&buf[..n]);
        }
    }

    /// Localhost integration smoke test (proves the boring config + framing
    /// compose end-to-end, ahead of the full netns handshake+ping in Task 6):
    /// a real loopback `TcpListener`/`TcpStream`, a real BoringSSL handshake
    /// (client = [`build_client_connector`], server = [`build_server_acceptor`]
    /// with a throwaway self-signed cert), then a framed datagram sent each
    /// way through the real TLS layer, asserted byte-exact.
    #[test]
    fn tls_costume_roundtrips_a_framed_datagram_both_ways_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let sni = "example.test";

        let server = std::thread::spawn(move || {
            let (tcp, _from) = listener.accept().expect("accept");
            let acceptor = build_server_acceptor(sni).expect("server acceptor");
            let mut stream = acceptor.accept(tcp).expect("server handshake");

            let mut reader = FrameReader::default();
            let got = blocking_read_one(&mut stream, &mut reader);
            assert_eq!(got, b"ping-from-client");

            let mut wire = Vec::new();
            frame_datagram(b"pong-from-server", &mut wire).unwrap();
            blocking_write_all(&mut stream, &wire);
            stream.shutdown().ok();
        });

        let connector = build_client_connector().expect("client connector");
        let tcp = TcpStream::connect(addr).expect("connect");
        let mut stream = connector.connect(sni, tcp).expect("client handshake");

        let mut wire = Vec::new();
        frame_datagram(b"ping-from-client", &mut wire).unwrap();
        blocking_write_all(&mut stream, &wire);

        let mut reader = FrameReader::default();
        let got = blocking_read_one(&mut stream, &mut reader);
        assert_eq!(got, b"pong-from-server");

        server.join().expect("server thread panicked");
    }

    /// A peer that accepts the TCP connection but never speaks TLS must not pin
    /// the handshake open forever: `drive_handshake` must abandon it at its
    /// deadline so `run_tls` can reconnect / re-accept. This is the regression
    /// guard for the single-connection accept-DoS — an idle connect cannot hold
    /// the one connection slot indefinitely.
    #[test]
    fn drive_handshake_times_out_against_a_silent_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        // Accept and then stay silent (never send a ServerHello) well past the
        // client's short test deadline.
        let server = std::thread::spawn(move || {
            let (_tcp, _from) = listener.accept().expect("accept");
            std::thread::sleep(Duration::from_secs(2));
        });

        let connector = build_client_connector().expect("client connector");
        let tcp = TcpStream::connect(addr).expect("connect");
        let tcp_fd = tcp.as_raw_fd();
        // Epoll::new needs a second fd (the pump watches TUN there); a bound
        // UdpSocket supplies a valid, never-ready fd without any `unsafe`.
        let dummy = std::net::UdpSocket::bind("127.0.0.1:0").expect("dummy socket");
        let poller = Epoll::new(tcp_fd, dummy.as_raw_fd()).expect("epoll");

        let deadline = Instant::now() + Duration::from_millis(300);
        let res = drive_handshake(connector.connect("example.test", tcp), &poller, deadline);

        assert!(
            res.is_err(),
            "handshake against a silent peer must fail, not hang"
        );
        let err = res.err().unwrap();
        assert_eq!(
            err.kind(),
            io::ErrorKind::TimedOut,
            "silent-peer handshake must fail with TimedOut, got: {err}"
        );
        assert!(
            Instant::now() >= deadline,
            "must have waited until the deadline before giving up"
        );

        server.join().expect("server thread panicked");
    }
}
