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
//! # Architecture: multi-peer `run_tls` pump
//!
//! [`run_tls`] multiplexes multiple active TCP+TLS peer connections alongside the
//! TUN device using dynamic epoll registration in `yip-io`.
//! yip is peer-to-peer, so a deterministic role-by-static-key-order tiebreak
//! (mirroring 3c.1) assigns roles: for each configured peer, the side with the
//! **smaller** `local_public` is the TCP **client**; the side with the **larger**
//! is the **server**.
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
    select_next_proto, AlpnError, ErrorCode, HandshakeError, Ssl, SslAcceptor, SslConnector,
    SslMethod, SslStream, SslVerifyMode,
};
use boring::x509::X509;

use yip_io::epoll::{read_fd, set_nonblocking, write_fd, Epoll};
use yip_io::poll::{Dispatch, DispatchOut, EgressDatagram};

use crate::peer_manager::PeerManager;

pub(crate) const TLS_FRAME_MAX: usize = yip_io::MAX_WIRE_DATAGRAM;

pub(crate) const TOKEN_TUN: u64 = 0;
pub(crate) const TOKEN_LISTENER: u64 = 1;
pub(crate) const TOKEN_PEER_BASE: u64 = 100;

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
#[derive(Debug, Default)]
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
/// `pub(crate)`: also the reconnect backoff for the 3c.4 relay-dial client
/// (`crate::relay_client`), which mirrors this exact policy.
pub(crate) const INITIAL_BACKOFF_MS: u64 = 100;
pub(crate) const MAX_BACKOFF_MS: u64 = 5_000;

/// Maximum wall-clock a single TLS handshake may take before it is abandoned.
/// Without this bound a peer that opens a TCP connection and then stalls (never
/// sending its next handshake flight) would pin a connection slot indefinitely —
/// an off-path, zero-crypto DoS, since the outer TLS is zero-auth. On timeout the
/// connection is dropped and the server re-accepts (or the client re-dials).
/// `pub(crate)`: also used by `crate::relay_client::spawn`'s connect path.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum wall-clock time allowed for the inner Noise-IK handshake to complete
/// after outer TLS connection establishment. If no established session is confirmed
/// within this deadline, the connection is torn down so the peer slot
/// can be restored / retried.
pub(crate) const INNER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// ALPN protocols offered (client) / accepted (server), RFC 7301 wire format
/// (one-byte length prefix per protocol name): `h2` then `http/1.1`, matching
/// a real browser's HTTP/2-preferred offer (the QUIC-costume sibling in
/// `quic.rs` uses ALPN `h3` for the same reason).
const TLS_ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";

/// `supported_groups` list for the client-side browser-parrot ClientHello,
/// in real-Chrome order: `X25519MLKEM768` (the PQ hybrid, real IANA
/// codepoint `0x11ec`/`4588`), then `X25519`, `P-256`, `P-384` — the same
/// set/order `yip_utls::hello`'s Chrome-150 fixture crafts (see that crate's
/// `supported_groups_body`: `GREASE,4588,29,23,24`), so both TLS surfaces
/// present one consistent browser profile. Boring 5's vendored BoringSSL
/// (`boring-sys` bundles a Cloudflare fork, `patches/boring-pq.patch`)
/// defaults `supported_groups` to
/// `X25519MLKEM768,P256Kyber768Draft00,X25519,P-256,P-384` — the second
/// entry, group id `0xfe32`, is explicitly NOT the IANA-assigned codepoint
/// for that exchange (the patch's own commit message says so) and no real
/// browser ever sends it, making it a novel distinguisher for a TLS-mimicry
/// costume. `set_curves_list` below REPLACES the context's group list
/// wholesale (`SSL_CTX_set1_curves_list` → `ssl_str_to_group_ids`, a copy,
/// not an append/merge — verified against boring-sys 5.1.0's patched
/// vendored source), so this drops `0xfe32` while keeping the real
/// `X25519MLKEM768` hybrid (it makes the costume MORE Chrome-like, since
/// modern Chrome sends it too). Names must match `boring-sys`'s
/// `kNamedGroups` table exactly (case-sensitive): `"X25519MLKEM768"`,
/// `"X25519"`, `"P-256"`, `"P-384"`.
const CLIENT_CURVES_LIST: &str = "X25519MLKEM768:X25519:P-256:P-384";

// ── BoringSSL config builders ──────────────────────────────────────────────

/// Client-side BoringSSL config: GREASE-enabled (the browser-parrot signal —
/// `crates/yip-bench/RESULTS.md` "3c.2 spike" recorded boring's default
/// cipher/extension set as already browser-*shaped* with GREASE present;
/// exact current-Chrome tuning is deferred to the nDPI-oracle-driven Task 6,
/// not blocked on here) and zero-auth verify (the outer TLS authenticates
/// nothing — inner yip Noise-IK is the real security, exactly like `quic.rs`'s
/// `SkipServerVerification`). [`CLIENT_CURVES_LIST`] pins `supported_groups`
/// to a real-browser set, dropping boring 5's non-standard `0xfe32` default
/// (see that constant's doc comment).
pub(crate) fn build_client_connector() -> io::Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(io::Error::other)?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_grease_enabled(true);
    builder
        .set_alpn_protos(TLS_ALPN_WIRE)
        .map_err(io::Error::other)?;
    builder
        .set_curves_list(CLIENT_CURVES_LIST)
        .map_err(io::Error::other)?;
    Ok(builder.build())
}

/// Server-side BoringSSL config: a throwaway self-signed cert for `tls_sni`
/// (mirrors `quic.rs`'s `gen_cert`) on a modern (TLS 1.2+, no legacy ciphers)
/// `mozilla_intermediate_v5` base configuration.
pub(crate) fn build_server_acceptor(tls_sni: &str) -> io::Result<SslAcceptor> {
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
    let key = PKey::private_key_from_pkcs8(&certified.signing_key.serialize_der())
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
pub(crate) fn drive_handshake<S>(
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
pub(crate) fn drain_tls_read(
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
pub(crate) fn write_all_tls(
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

// ── role tiebreak (mirrors quic.rs's connection_role) ──────────────────────

/// The TCP+TLS role this node takes toward a peer, decided by static-key order
/// to avoid glare (two connections racing for one pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Smaller `local_public` ⇒ we `TcpStream::connect` + TLS client handshake.
    Client,
    /// Larger `local_public` ⇒ we `TcpListener::accept` + TLS server handshake.
    Server,
}

/// Decide our TCP+TLS role toward `peer_pub`: the smaller static key is the
/// client. Equal keys cannot occur for a genuine distinct peer.
pub(crate) fn connection_role(local_pub: &[u8; 32], peer_pub: &[u8; 32]) -> io::Result<Role> {
    match local_pub.cmp(peer_pub) {
        Ordering::Less => Ok(Role::Client),
        Ordering::Greater => Ok(Role::Server),
        Ordering::Equal => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local_public == peer public key: impossible for a distinct peer",
        )),
    }
}

/// Assign pairwise connection roles for each peer relative to `local_pub`.
pub(crate) fn assign_peer_roles(
    local_pub: &[u8; 32],
    peers: &[([u8; 32], SocketAddr)],
) -> io::Result<Vec<([u8; 32], SocketAddr, Role)>> {
    peers
        .iter()
        .map(|&(peer_pub, addr)| {
            let role = connection_role(local_pub, &peer_pub)?;
            Ok((peer_pub, addr, role))
        })
        .collect()
}

// ── multi-peer connection state machine ────────────────────────────────────

/// Multi-peer connection state machine and lifecycle manager.
#[derive(Debug)]
pub(crate) enum PeerConn {
    Disconnected {
        backoff_ms: u64,
        next_dial: Instant,
    },
    Connecting {
        stream: SslStream<TcpStream>,
        start: Instant,
    },
    Connected {
        stream: SslStream<TcpStream>,
        reader: FrameReader,
        start: Instant,
        inner_confirmed: bool,
        was_established: bool,
    },
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "helper methods tested in unit tests")
)]
impl PeerConn {
    /// Create a new disconnected connection ready to dial immediately.
    pub(crate) fn new_disconnected(now: Instant) -> Self {
        Self::Disconnected {
            backoff_ms: INITIAL_BACKOFF_MS,
            next_dial: now,
        }
    }

    /// Record a failure / disconnect and advance exponential backoff.
    /// Caps backoff at [`MAX_BACKOFF_MS`].
    pub(crate) fn record_failure(&mut self, now: Instant) {
        let current_backoff = match self {
            Self::Disconnected { backoff_ms, .. } => *backoff_ms,
            _ => INITIAL_BACKOFF_MS,
        };
        let next_dial = now + Duration::from_millis(current_backoff);
        let next_backoff = (current_backoff * 2).min(MAX_BACKOFF_MS);
        *self = Self::Disconnected {
            backoff_ms: next_backoff,
            next_dial,
        };
    }

    /// Current backoff delay in ms if disconnected.
    pub(crate) fn backoff_ms(&self) -> Option<u64> {
        match self {
            Self::Disconnected { backoff_ms, .. } => Some(*backoff_ms),
            _ => None,
        }
    }

    /// Next dial instant if disconnected.
    pub(crate) fn next_dial(&self) -> Option<Instant> {
        match self {
            Self::Disconnected { next_dial, .. } => Some(*next_dial),
            _ => None,
        }
    }

    /// True if currently in `Disconnected` state.
    pub(crate) fn is_disconnected(&self) -> bool {
        matches!(self, Self::Disconnected { .. })
    }

    /// True if currently in `Connecting` state.
    pub(crate) fn is_connecting(&self) -> bool {
        matches!(self, Self::Connecting { .. })
    }

    /// True if currently in `Connected` state.
    pub(crate) fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    /// Whether this connection should attempt dialing now.
    pub(crate) fn should_dial(&self, now: Instant) -> bool {
        match self {
            Self::Disconnected { next_dial, .. } => now >= *next_dial,
            _ => false,
        }
    }

    /// Check if the inner Noise-IK handshake has timed out.
    pub(crate) fn is_inner_handshake_timeout(&self, now: Instant) -> bool {
        self.is_inner_expired(now, INNER_HANDSHAKE_TIMEOUT)
    }

    /// Check if the inner Noise-IK handshake has exceeded `timeout`.
    pub(crate) fn is_inner_expired(&self, now: Instant, timeout: Duration) -> bool {
        match self {
            Self::Connected {
                start,
                inner_confirmed,
                ..
            } => !inner_confirmed && now.duration_since(*start) >= timeout,
            _ => false,
        }
    }

    /// Mark the inner handshake as confirmed.
    pub(crate) fn mark_inner_confirmed(&mut self) {
        if let Self::Connected {
            inner_confirmed, ..
        } = self
        {
            *inner_confirmed = true;
        }
    }

    /// Reference to the underlying TLS stream, if connecting or connected.
    pub(crate) fn stream(&self) -> Option<&SslStream<TcpStream>> {
        match self {
            Self::Connecting { stream, .. } | Self::Connected { stream, .. } => Some(stream),
            Self::Disconnected { .. } => None,
        }
    }

    /// Mutable reference to the underlying TLS stream, if connecting or connected.
    pub(crate) fn stream_mut(&mut self) -> Option<&mut SslStream<TcpStream>> {
        match self {
            Self::Connecting { stream, .. } | Self::Connected { stream, .. } => Some(stream),
            Self::Disconnected { .. } => None,
        }
    }

    /// Raw file descriptor of the TCP socket, if connecting or connected.
    pub(crate) fn raw_fd(&self) -> Option<RawFd> {
        self.stream().map(|s| s.get_ref().as_raw_fd())
    }

    /// Connection start timestamp, if connecting or connected.
    pub(crate) fn start(&self) -> Option<Instant> {
        match self {
            Self::Connecting { start, .. } | Self::Connected { start, .. } => Some(*start),
            Self::Disconnected { .. } => None,
        }
    }

    /// Reference to the plaintext frame reader, if connected.
    pub(crate) fn reader(&self) -> Option<&FrameReader> {
        match self {
            Self::Connected { reader, .. } => Some(reader),
            _ => None,
        }
    }

    /// Mutable reference to the plaintext frame reader, if connected.
    pub(crate) fn reader_mut(&mut self) -> Option<&mut FrameReader> {
        match self {
            Self::Connected { reader, .. } => Some(reader),
            _ => None,
        }
    }

    /// Whether this peer was established prior to the current connection.
    pub(crate) fn was_established(&self) -> Option<bool> {
        match self {
            Self::Connected {
                was_established, ..
            } => Some(*was_established),
            _ => None,
        }
    }

    /// Check if the TLS handshake in `Connecting` state has exceeded `timeout`.
    pub(crate) fn is_handshake_expired(&self, now: Instant, timeout: Duration) -> bool {
        match self {
            Self::Connecting { start, .. } => now.duration_since(*start) >= timeout,
            _ => false,
        }
    }

    /// Check if the TLS handshake has timed out against [`HANDSHAKE_TIMEOUT`].
    pub(crate) fn is_handshake_timeout(&self, now: Instant) -> bool {
        self.is_handshake_expired(now, HANDSHAKE_TIMEOUT)
    }

    /// Advance the TLS handshake if this connection is in `Connecting` state.
    ///
    /// Returns `Ok(true)` if handshake just finished (transitioning `*self` to `Connected`),
    /// `Ok(false)` if still in progress,
    /// or `Err(e)` if handshake failed.
    pub(crate) fn drive_handshake(
        &mut self,
        now: Instant,
        is_peer_established: bool,
    ) -> io::Result<bool> {
        let (done, err) = match self {
            Self::Connecting { stream, .. } => match stream.do_handshake() {
                Ok(()) => (true, None),
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                    (false, None)
                }
                Err(e) => (false, Some(ssl_error_to_io(e))),
            },
            _ => (false, None),
        };

        if let Some(e) = err {
            return Err(e);
        }

        if done {
            let old = std::mem::replace(
                self,
                Self::Disconnected {
                    backoff_ms: INITIAL_BACKOFF_MS,
                    next_dial: now,
                },
            );
            if let Self::Connecting { stream, .. } = old {
                *self = Self::Connected {
                    stream,
                    reader: FrameReader::default(),
                    start: now,
                    inner_confirmed: false,
                    was_established: is_peer_established,
                };
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Initiate a non-blocking TCP connect and BoringSSL TLS client handshake.
///
/// Returns an [`SslStream`] whose handshake is in-flight (or completed).
/// The stream's socket is non-blocking with `TCP_NODELAY` set.
pub(crate) fn try_connect(
    peer_addr: SocketAddr,
    tls_sni: &str,
) -> io::Result<SslStream<TcpStream>> {
    let domain = if peer_addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    sock.set_nonblocking(true)?;
    sock.set_nodelay(true)?;

    match sock.connect(&peer_addr.into()) {
        Ok(()) => {}
        Err(e)
            if e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }

    let tcp: TcpStream = sock.into();
    let connector = build_client_connector()?;
    let ssl = connector
        .configure()
        .map_err(io::Error::other)?
        .into_ssl(tls_sni)
        .map_err(io::Error::other)?;
    let mut stream = SslStream::new(ssl, tcp).map_err(io::Error::other)?;

    match stream.connect() {
        Ok(()) => {}
        Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {}
        Err(e) => return Err(ssl_error_to_io(e)),
    }

    Ok(stream)
}

/// Accept a non-blocking TCP connection and initiate a BoringSSL TLS server handshake.
pub(crate) fn try_accept(
    acceptor: &SslAcceptor,
    tcp: TcpStream,
) -> io::Result<SslStream<TcpStream>> {
    let ssl = Ssl::new(acceptor.context()).map_err(io::Error::other)?;
    let mut stream = SslStream::new(ssl, tcp).map_err(io::Error::other)?;
    match stream.accept() {
        Ok(()) => {}
        Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {}
        Err(e) => return Err(ssl_error_to_io(e)),
    }
    Ok(stream)
}

/// A configured peer slot tracked in the multi-peer event loop.
#[derive(Debug)]
pub(crate) struct PeerSlot {
    pub(crate) public_key: [u8; 32],
    pub(crate) addr: SocketAddr,
    pub(crate) role: Role,
    pub(crate) conn: PeerConn,
}

/// Abstraction over the inner data plane for TLS transport event pumping.
pub(crate) trait TlsDispatch {
    fn on_udp(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> (Option<Vec<u8>>, Vec<EgressDatagram>);
    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> Vec<EgressDatagram>;
    fn tick(&mut self, now_ms: u64) -> Vec<EgressDatagram>;
    fn is_peer_established(&self, pubkey: &[u8; 32]) -> bool;
}

impl TlsDispatch for PeerManager {
    fn on_udp(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> (Option<Vec<u8>>, Vec<EgressDatagram>) {
        owned_out(Dispatch::on_udp(self, src, dg, now_ms))
    }

    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> Vec<EgressDatagram> {
        Dispatch::on_tun(self, inner, now_ms).to_vec()
    }

    fn tick(&mut self, now_ms: u64) -> Vec<EgressDatagram> {
        Dispatch::tick(self, now_ms)
            .map(|s| s.to_vec())
            .unwrap_or_default()
    }

    fn is_peer_established(&self, pubkey: &[u8; 32]) -> bool {
        self.is_peer_established(pubkey)
    }
}

// ── connect / accept ────────────────────────────────────────────────────────

/// Dial `peer_endpoint`, set the stream non-blocking (via [`Epoll::new`]), and
/// drive the TLS client handshake (browser-parrot ClientHello, SNI =
/// `tls_sni`) to completion.
/// `pub(crate)`: also the connect path used by `crate::relay_client::spawn`
/// (the TLS relay-dial client, 3c.4) — `tun_fd` there is actually the
/// socketpair fd to the data plane; `Epoll` only cares that it is a second
/// watchable fd (see `yip_io::epoll::Ready`'s doc comment on name reuse).
pub(crate) fn connect_and_handshake(
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

fn find_server_peer_idx(peers: &[PeerSlot], accepted_from: SocketAddr) -> Option<usize> {
    if let Some(idx) = peers
        .iter()
        .position(|p| p.role == Role::Server && p.addr == accepted_from && !p.conn.is_connected())
    {
        return Some(idx);
    }
    if let Some(idx) = peers.iter().position(|p| {
        p.role == Role::Server && p.addr.ip() == accepted_from.ip() && !p.conn.is_connected()
    }) {
        return Some(idx);
    }
    peers
        .iter()
        .position(|p| p.role == Role::Server && p.conn.is_disconnected())
}

fn teardown_peer(idx: usize, peers: &mut [PeerSlot], poller: &Epoll, now: Instant) {
    if let Some(fd) = peers[idx].conn.raw_fd() {
        let _ = poller.remove(fd);
    }
    if peers[idx].role == Role::Client {
        peers[idx].conn.record_failure(now);
    } else {
        peers[idx].conn = PeerConn::new_disconnected(now);
    }
}

fn route_egress_to_peers(
    egress: &[EgressDatagram],
    peers: &mut [PeerSlot],
    poller: &Epoll,
    now: Instant,
) -> io::Result<()> {
    if egress.is_empty() {
        return Ok(());
    }
    let mut write_buf = Vec::new();
    for d in egress {
        if let Some(idx) = peers.iter().position(|p| p.addr == d.dst) {
            if peers[idx].conn.is_connected() {
                if let Some(stream) = peers[idx].conn.stream_mut() {
                    write_buf.clear();
                    if let Err(e) = frame_datagram(&d.bytes, &mut write_buf) {
                        eprintln!("tls: framing error for peer {}: {e}", d.dst);
                        continue;
                    }
                    if let Err(e) = write_all_tls(stream, poller, &write_buf) {
                        eprintln!(
                            "tls: connection write error for peer {}, tearing down: {e}",
                            d.dst
                        );
                        teardown_peer(idx, peers, poller, now);
                    }
                }
            } else {
                eprintln!(
                    "tls: peer {} not connected; dropping egress datagram",
                    d.dst
                );
            }
        } else {
            eprintln!(
                "tls: no configured peer matches egress destination {}; dropped",
                d.dst
            );
        }
    }
    Ok(())
}

// ── the pump ─────────────────────────────────────────────────────────────────

/// Drive the multi-peer TLS event loop until a fatal epoll error or termination condition.
#[expect(
    clippy::too_many_arguments,
    reason = "pump requires epoll poller, tun fd, listener, acceptor, manager, peer slots, sni, timeout, and loop controls"
)]
pub(crate) fn pump<M: TlsDispatch>(
    poller: &Epoll,
    tun_fd: RawFd,
    listener: Option<&TcpListener>,
    acceptor: Option<&SslAcceptor>,
    manager: &mut M,
    peers: &mut [PeerSlot],
    tls_sni: &str,
    start: Instant,
    inner_timeout: Duration,
    stop_on_all_disconnected: bool,
    max_iterations: Option<usize>,
) -> io::Result<()> {
    let mut tls_read_buf = [0u8; TLS_FRAME_MAX];
    let mut tun_read_buf = [0u8; TLS_FRAME_MAX];
    let mut ready_tokens = Vec::new();
    let mut iters = 0;

    loop {
        if let Some(max) = max_iterations {
            if iters >= max {
                return Ok(());
            }
            iters += 1;
        }

        let now = Instant::now();

        // 1. Client reconnect: dial any client-role peer whose reconnect backoff expired.
        for (idx, peer) in peers.iter_mut().enumerate() {
            if peer.role == Role::Client
                && peer.conn.is_disconnected()
                && peer.conn.should_dial(now)
            {
                let peer_addr = peer.addr;
                match try_connect(peer_addr, tls_sni) {
                    Ok(mut stream) => {
                        let finished = match stream.do_handshake() {
                            Ok(()) => true,
                            Err(e)
                                if e.code() == ErrorCode::WANT_READ
                                    || e.code() == ErrorCode::WANT_WRITE =>
                            {
                                false
                            }
                            Err(e) => {
                                eprintln!("tls: handshake error for {peer_addr}: {e}");
                                peer.conn.record_failure(now);
                                continue;
                            }
                        };
                        let fd = stream.get_ref().as_raw_fd();
                        if let Err(e) = poller.add(fd, TOKEN_PEER_BASE + idx as u64) {
                            eprintln!("tls: failed to register epoll token for {peer_addr}: {e}");
                            peer.conn.record_failure(now);
                        } else if finished {
                            peer.conn = PeerConn::Connected {
                                stream,
                                reader: FrameReader::default(),
                                start: now,
                                inner_confirmed: false,
                                was_established: manager.is_peer_established(&peer.public_key),
                            };
                        } else {
                            peer.conn = PeerConn::Connecting { stream, start: now };
                        }
                    }
                    Err(e) => {
                        eprintln!("tls: connect to {peer_addr} failed: {e}");
                        peer.conn.record_failure(now);
                    }
                }
            }
        }

        // 2. Handshake timeout and inner handshake timeout checks.
        for idx in 0..peers.len() {
            if peers[idx].conn.is_handshake_timeout(now) {
                eprintln!(
                    "tls: outer TLS handshake timeout for peer {}, tearing down",
                    peers[idx].addr
                );
                teardown_peer(idx, peers, poller, now);
            } else if peers[idx].conn.is_inner_expired(now, inner_timeout) {
                eprintln!(
                    "tls: inner handshake did not complete within {inner_timeout:?}, tearing down {}",
                    peers[idx].addr
                );
                teardown_peer(idx, peers, poller, now);
            }
        }

        if stop_on_all_disconnected && peers.iter().all(|p| p.conn.is_disconnected()) {
            return Ok(());
        }

        // 3. Epoll wait up to TICK_MS (10ms).
        poller.wait_tokens(TICK_MS, &mut ready_tokens)?;
        let now = Instant::now();
        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // 4. Handle ready epoll events.
        for token in ready_tokens.drain(..) {
            if token == TOKEN_LISTENER {
                if let (Some(listener), Some(acceptor)) = (listener, acceptor) {
                    loop {
                        match listener.accept() {
                            Ok((tcp, accepted_from)) => {
                                let _ = tcp.set_nodelay(true);
                                let _ = set_nonblocking(tcp.as_raw_fd());
                                if let Some(idx) = find_server_peer_idx(peers, accepted_from) {
                                    if !peers[idx].conn.is_disconnected() {
                                        teardown_peer(idx, peers, poller, now);
                                    }
                                    match try_accept(acceptor, tcp) {
                                        Ok(mut stream) => {
                                            let finished = match stream.do_handshake() {
                                                Ok(()) => true,
                                                Err(e)
                                                    if e.code() == ErrorCode::WANT_READ
                                                        || e.code() == ErrorCode::WANT_WRITE =>
                                                {
                                                    false
                                                }
                                                Err(e) => {
                                                    eprintln!(
                                                        "tls: server handshake error from {accepted_from}: {e}"
                                                    );
                                                    continue;
                                                }
                                            };
                                            let fd = stream.get_ref().as_raw_fd();
                                            if let Err(e) =
                                                poller.add(fd, TOKEN_PEER_BASE + idx as u64)
                                            {
                                                eprintln!(
                                                    "tls: failed to register epoll token for server peer: {e}"
                                                );
                                            } else if finished {
                                                peers[idx].conn = PeerConn::Connected {
                                                    stream,
                                                    reader: FrameReader::default(),
                                                    start: now,
                                                    inner_confirmed: false,
                                                    was_established: manager.is_peer_established(
                                                        &peers[idx].public_key,
                                                    ),
                                                };
                                            } else {
                                                peers[idx].conn =
                                                    PeerConn::Connecting { stream, start: now };
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "tls: accept TLS init error from {accepted_from}: {e}"
                                            );
                                        }
                                    }
                                } else {
                                    eprintln!(
                                        "tls: incoming connection from {accepted_from} rejected (no available server peer slot)"
                                    );
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => {
                                eprintln!("tls: listener accept error: {e}");
                                break;
                            }
                        }
                    }
                }
            } else if token == TOKEN_TUN {
                loop {
                    match read_fd(tun_fd, &mut tun_read_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let egress = manager.on_tun(&tun_read_buf[..n], now_ms);
                            route_egress_to_peers(&egress, peers, poller, now)?;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            eprintln!("tls: tun read error: {e}");
                            break;
                        }
                    }
                }
            } else if token >= TOKEN_PEER_BASE {
                let idx = (token - TOKEN_PEER_BASE) as usize;
                if idx < peers.len() {
                    if peers[idx].conn.is_connecting() {
                        let is_est = manager.is_peer_established(&peers[idx].public_key);
                        match peers[idx].conn.drive_handshake(now, is_est) {
                            Ok(true) => {}
                            Ok(false) => {}
                            Err(e) => {
                                eprintln!(
                                    "tls: handshake drive error for {}: {e}",
                                    peers[idx].addr
                                );
                                teardown_peer(idx, peers, poller, now);
                            }
                        }
                    }

                    if peers[idx].conn.is_connected() {
                        let mut should_teardown = false;
                        let peer_addr = peers[idx].addr;
                        let peer_public = peers[idx].public_key;
                        let was_established = peers[idx].conn.was_established().unwrap_or(false);
                        let mut frames = Vec::new();

                        if let PeerConn::Connected { stream, reader, .. } = &mut peers[idx].conn {
                            if let Err(e) = drain_tls_read(stream, reader, &mut tls_read_buf) {
                                eprintln!("tls: connection read error, tearing down: {e}");
                                should_teardown = true;
                            } else {
                                loop {
                                    match reader.next() {
                                        Ok(Some(dg)) => frames.push(dg),
                                        Ok(None) => break,
                                        Err(e) => {
                                            eprintln!("tls: malformed frame, tearing down: {e}");
                                            should_teardown = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        if should_teardown {
                            teardown_peer(idx, peers, poller, now);
                        } else {
                            for dg in frames {
                                let (tun, egress) = manager.on_udp(peer_addr, &dg, now_ms);
                                if (!was_established && manager.is_peer_established(&peer_public))
                                    || tun.is_some()
                                    || !egress.is_empty()
                                {
                                    peers[idx].conn.mark_inner_confirmed();
                                }
                                if let Some(inner) = tun {
                                    write_tun(tun_fd, &inner);
                                }
                                route_egress_to_peers(&egress, peers, poller, now)?;
                            }
                        }
                    }
                }
            }
        }

        // 5. Advance in-flight handshakes for any connecting peers on tick.
        for idx in 0..peers.len() {
            if peers[idx].conn.is_connecting() {
                let is_est = manager.is_peer_established(&peers[idx].public_key);
                match peers[idx].conn.drive_handshake(now, is_est) {
                    Ok(true) => {}
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("tls: handshake drive error for {}: {e}", peers[idx].addr);
                        teardown_peer(idx, peers, poller, now);
                    }
                }
            }
        }

        // 6. Cadence tick (feedback / keepalive / handshake retry / cover).
        let ticked_egress = manager.tick(now_ms);
        route_egress_to_peers(&ticked_egress, peers, poller, now)?;
    }
}

// ── public entry point ─────────────────────────────────────────────────────

/// Run the TLS-mimicry data loop until a fatal I/O error.
pub(crate) fn run_tls(
    tun_fd: RawFd,
    manager: &mut PeerManager,
    local_public: [u8; 32],
    peers: &[([u8; 32], SocketAddr)],
    listen: SocketAddr,
    listen_port_auto: bool,
    tls_sni: &str,
) -> io::Result<()> {
    if peers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport=tls requires at least one configured peer",
        ));
    }

    let roles = assign_peer_roles(&local_public, peers)?;
    let poller = Epoll::create()?;
    poller.add(tun_fd, TOKEN_TUN)?;

    let has_server_peer = roles.iter().any(|(_, _, role)| *role == Role::Server);
    let listener = if has_server_peer {
        let listener = crate::port::bind_tcp(listen, listen_port_auto)?;
        poller.add(listener.as_raw_fd(), TOKEN_LISTENER)?;
        Some(listener)
    } else {
        None
    };

    let acceptor = if has_server_peer {
        Some(build_server_acceptor(tls_sni)?)
    } else {
        None
    };

    let now = Instant::now();
    let mut slots: Vec<PeerSlot> = roles
        .into_iter()
        .map(|(public_key, addr, role)| PeerSlot {
            public_key,
            addr,
            role,
            conn: PeerConn::new_disconnected(now),
        })
        .collect();

    let start = Instant::now();
    pump(
        &poller,
        tun_fd,
        listener.as_ref(),
        acceptor.as_ref(),
        manager,
        &mut slots,
        tls_sni,
        start,
        INNER_HANDSHAKE_TIMEOUT,
        false,
        None,
    )
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
    /// guard for the handshake accept-DoS — an idle connect cannot hold
    /// the connection slot indefinitely.
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

    /// A completed outer TLS connection where the peer sends no inner Noise-IK
    /// packets must tear down after `inner_timeout`, returning `Ok(())`
    /// so the connection slot can be recycled.
    #[test]
    fn drive_inner_handshake_timeout_on_idle_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        let sni = "example.test";
        let test_timeout = Duration::from_millis(150);

        let server = std::thread::spawn(move || {
            let (tcp, _from) = listener.accept().expect("accept");
            let acceptor = build_server_acceptor(sni).expect("acceptor");
            let mut stream = acceptor.accept(tcp).expect("server handshake");
            // Outer TLS completed; server stays idle (sends no inner frames)
            // for longer than test_timeout.
            std::thread::sleep(test_timeout + Duration::from_millis(100));
            stream.shutdown().ok();
        });

        let connector = build_client_connector().expect("connector");
        let tcp = TcpStream::connect(addr).expect("connect");
        let tcp_fd = tcp.as_raw_fd();
        let dummy = std::net::UdpSocket::bind("127.0.0.1:0").expect("dummy socket");
        let poller = Epoll::new(tcp_fd, dummy.as_raw_fd()).expect("epoll");
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let stream = drive_handshake(connector.connect(sni, tcp), &poller, deadline)
            .expect("client handshake");

        let peer_pub = [3u8; 32];
        let local_priv = [1u8; 32];
        let local_pub = [2u8; 32];
        let peer_cfg = crate::config::PeerConfig {
            public_key: peer_pub,
            endpoint: Some(addr),
        };
        let mut manager = PeerManager::new(
            local_priv,
            local_pub,
            &[peer_cfg],
            crate::mode::TunnelMode::L3Tun,
            None,
            None,
            false,
        );

        let t0 = Instant::now();
        poller.remove(tcp_fd).unwrap();
        poller.remove(dummy.as_raw_fd()).unwrap();
        poller.add(dummy.as_raw_fd(), TOKEN_TUN).unwrap();
        poller.add(tcp_fd, TOKEN_PEER_BASE).unwrap();

        let mut slots = vec![PeerSlot {
            public_key: peer_pub,
            addr,
            role: Role::Client,
            conn: PeerConn::Connected {
                stream,
                reader: FrameReader::default(),
                start: t0,
                inner_confirmed: false,
                was_established: false,
            },
        }];

        let res = pump(
            &poller,
            dummy.as_raw_fd(),
            None,
            None,
            &mut manager,
            &mut slots,
            sni,
            t0,
            test_timeout,
            true,
            None,
        );

        assert!(
            res.is_ok(),
            "pump should exit with Ok(()) on timeout teardown"
        );
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= test_timeout,
            "pump must have waited at least test_timeout ({test_timeout:?}), elapsed: {elapsed:?}"
        );

        server.join().expect("server thread panicked");
    }

    /// A completed outer TLS connection where the peer sends garbage datagrams
    /// (which fail inner decryption/handshake) must not confirm the session and
    /// must tear down after `inner_timeout`.
    #[test]
    fn drive_inner_handshake_timeout_on_garbage_ingress() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        let sni = "example.test";
        let test_timeout = Duration::from_millis(150);

        let server = std::thread::spawn(move || {
            let (tcp, _from) = listener.accept().expect("accept");
            let acceptor = build_server_acceptor(sni).expect("acceptor");
            let mut stream = acceptor.accept(tcp).expect("server handshake");
            // Send garbage frames to client
            let mut wire = Vec::new();
            frame_datagram(b"scanner-garbage-noise", &mut wire).unwrap();
            blocking_write_all(&mut stream, &wire);
            std::thread::sleep(test_timeout + Duration::from_millis(100));
            stream.shutdown().ok();
        });

        let connector = build_client_connector().expect("connector");
        let tcp = TcpStream::connect(addr).expect("connect");
        let tcp_fd = tcp.as_raw_fd();
        let dummy = std::net::UdpSocket::bind("127.0.0.1:0").expect("dummy socket");
        let poller = Epoll::new(tcp_fd, dummy.as_raw_fd()).expect("epoll");
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let stream = drive_handshake(connector.connect(sni, tcp), &poller, deadline)
            .expect("client handshake");

        let peer_pub = [3u8; 32];
        let local_priv = [1u8; 32];
        let local_pub = [2u8; 32];
        let peer_cfg = crate::config::PeerConfig {
            public_key: peer_pub,
            endpoint: Some(addr),
        };
        let mut manager = PeerManager::new(
            local_priv,
            local_pub,
            &[peer_cfg],
            crate::mode::TunnelMode::L3Tun,
            None,
            None,
            false,
        );

        let t0 = Instant::now();
        poller.remove(tcp_fd).unwrap();
        poller.remove(dummy.as_raw_fd()).unwrap();
        poller.add(dummy.as_raw_fd(), TOKEN_TUN).unwrap();
        poller.add(tcp_fd, TOKEN_PEER_BASE).unwrap();

        let mut slots = vec![PeerSlot {
            public_key: peer_pub,
            addr,
            role: Role::Client,
            conn: PeerConn::Connected {
                stream,
                reader: FrameReader::default(),
                start: t0,
                inner_confirmed: false,
                was_established: false,
            },
        }];

        let res = pump(
            &poller,
            dummy.as_raw_fd(),
            None,
            None,
            &mut manager,
            &mut slots,
            sni,
            t0,
            test_timeout,
            true,
            None,
        );

        assert!(
            res.is_ok(),
            "pump should exit with Ok(()) on timeout teardown"
        );
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= test_timeout,
            "pump must have waited at least test_timeout ({test_timeout:?}), elapsed: {elapsed:?}"
        );

        server.join().expect("server thread panicked");
    }

    // ── boring 5 curve-list regression guard ───────────────────────────────
    //
    // boring 5's vendored BoringSSL (a Cloudflare fork, `boring-sys`'s
    // `patches/boring-pq.patch`) defaults `supported_groups` to
    // `X25519MLKEM768,P256Kyber768Draft00,X25519,P-256,P-384` — the second
    // entry, group id `0xfe32`, is NOT the IANA-assigned codepoint for that
    // exchange (the patch says so itself) and no real browser sends it,
    // making it a novel distinguisher for this transport=tls browser-parrot
    // costume. `build_client_connector` pins `CLIENT_CURVES_LIST` to drop it
    // while keeping the real `X25519MLKEM768` hybrid. These two tests prove
    // that pin holds against the ACTUAL wire bytes (not just the source),
    // so a future `boring`/`boring-sys` bump can't silently reintroduce
    // `0xfe32` (or any other unreviewed codepoint) without failing CI.

    /// `SSL_GROUP_P256_KYBER768_DRAFT00` — boring-sys 5.1.0's non-standard,
    /// non-IANA experimental group id (see [`CLIENT_CURVES_LIST`]'s doc
    /// comment). Must never appear in `build_client_connector`'s
    /// `supported_groups`.
    const GROUP_P256_KYBER768_DRAFT00_NONSTANDARD: u16 = 0xfe32;

    /// A TLS extension's `(type, body)`, walked out of a ClientHello's
    /// `extensions` block.
    fn walk_extensions(mut ext_block: &[u8]) -> Vec<(u16, &[u8])> {
        let mut out = Vec::new();
        while ext_block.len() >= 4 {
            let etype = u16::from_be_bytes([ext_block[0], ext_block[1]]);
            let elen = usize::from(u16::from_be_bytes([ext_block[2], ext_block[3]]));
            let body = &ext_block[4..4 + elen];
            out.push((etype, body));
            ext_block = &ext_block[4 + elen..];
        }
        assert!(ext_block.is_empty(), "trailing bytes after last extension");
        out
    }

    /// Parse the `supported_groups` (extension `0x000a`) group-id list out
    /// of a captured, single-TLS-record ClientHello (record header +
    /// handshake header + body, exactly what a raw `TcpStream::read` off an
    /// accepted socket returns for boring's first flight — no fragmentation
    /// handling needed at this size).
    fn supported_groups_of_captured_client_hello(wire: &[u8]) -> Vec<u16> {
        assert_eq!(wire[0], 22, "must be a handshake record");
        let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let hs = &wire[5..5 + record_len];
        assert_eq!(hs[0], 0x01, "must be a ClientHello");
        let hs_len = usize::from(u16::from_be_bytes([hs[2], hs[3]])) | (usize::from(hs[1]) << 16);
        let body = &hs[4..4 + hs_len];

        let mut off = 2 + 32; // legacy_version, random
        let sid_len = usize::from(body[off]);
        off += 1 + sid_len;
        let cs_len = usize::from(u16::from_be_bytes([body[off], body[off + 1]]));
        off += 2 + cs_len;
        let cm_len = usize::from(body[off]);
        off += 1 + cm_len;
        let ext_total_len = usize::from(u16::from_be_bytes([body[off], body[off + 1]]));
        off += 2;
        let extensions = walk_extensions(&body[off..off + ext_total_len]);

        let (_etype, groups_body) = extensions
            .into_iter()
            .find(|(etype, _)| *etype == 0x000a)
            .expect("supported_groups extension must be present");
        let list_len = usize::from(u16::from_be_bytes([groups_body[0], groups_body[1]]));
        assert_eq!(2 + list_len, groups_body.len(), "supported_groups length");
        groups_body[2..2 + list_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    /// A GREASE value per RFC 8701 §3.1: bytes `0x?A?A` for the same nibble
    /// on both halves (`0x0A0A, 0x1A1A, ..., 0xFAFA`).
    fn is_grease(v: u16) -> bool {
        let [hi, lo] = v.to_be_bytes();
        hi & 0x0F == 0x0A && lo & 0x0F == 0x0A && hi >> 4 == lo >> 4
    }

    /// Capture the raw first-flight bytes `build_client_connector` sends
    /// against a bare accepting socket (server never speaks TLS back, so the
    /// client blocks on `WANT_READ`/a real blocking read after sending the
    /// ClientHello — irrelevant here, we only need the accepted side's
    /// bytes).
    fn capture_client_hello() -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = std::thread::spawn(move || {
            let connector = build_client_connector().expect("connector");
            let tcp = TcpStream::connect(addr).expect("connect");
            let _ = connector.connect("probe.test", tcp);
        });
        let (mut tcp, _from) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set_read_timeout");
        let mut buf = vec![0u8; 8192];
        let mut total = Vec::new();
        loop {
            match std::io::Read::read(&mut tcp, &mut buf) {
                Ok(0) => break,
                Ok(n) => total.extend_from_slice(&buf[..n]),
                Err(_) => break, // read timeout: first flight fully arrived
            }
        }
        drop(tcp);
        let _ = client.join();
        total
    }

    /// Regression guard (boring 5 migration): `build_client_connector`'s
    /// `supported_groups` must be EXACTLY GREASE followed by
    /// `[X25519MLKEM768, X25519, P-256, P-384]` — real IANA codepoints only,
    /// in real-Chrome order, matching `yip_utls::hello`'s Chrome-150 fixture
    /// (`GREASE,4588,29,23,24`). Fails loudly if a future `boring`/
    /// `boring-sys` bump reintroduces `0xfe32` (or anything else not on this
    /// exact list) into the default group set.
    #[test]
    fn client_connector_supported_groups_are_exactly_the_real_browser_set() {
        let wire = capture_client_hello();
        let groups = supported_groups_of_captured_client_hello(&wire);

        assert!(
            !groups.contains(&GROUP_P256_KYBER768_DRAFT00_NONSTANDARD),
            "supported_groups must never carry the non-standard, non-IANA \
             P256Kyber768Draft00 codepoint (0xfe32): {groups:04x?}"
        );

        assert_eq!(groups.len(), 5, "GREASE + 4 real groups: {groups:04x?}");
        assert!(
            is_grease(groups[0]),
            "first entry must be a GREASE value: {:#06x}",
            groups[0]
        );
        const GROUP_X25519MLKEM768: u16 = 0x11ec;
        const GROUP_X25519: u16 = 0x001d;
        const GROUP_SECP256R1: u16 = 0x0017;
        const GROUP_SECP384R1: u16 = 0x0018;
        assert_eq!(
            &groups[1..],
            &[
                GROUP_X25519MLKEM768,
                GROUP_X25519,
                GROUP_SECP256R1,
                GROUP_SECP384R1
            ],
            "supported_groups (after GREASE) must be exactly the pinned \
             real-browser list, in real-Chrome order: {groups:04x?}"
        );
    }

    /// Regression guard (boring 5 migration): pinning `CLIENT_CURVES_LIST`
    /// must not accidentally drop the real `X25519MLKEM768` hybrid — a live
    /// client<->server handshake (both `build_client_connector`/
    /// `build_server_acceptor`, both boring 5 defaults on the server side)
    /// must still negotiate it.
    #[test]
    fn client_server_handshake_still_negotiates_x25519_mlkem768() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let sni = "example.test";

        let server = std::thread::spawn(move || {
            let (tcp, _from) = listener.accept().expect("accept");
            let acceptor = build_server_acceptor(sni).expect("server acceptor");
            let stream = acceptor.accept(tcp).expect("server handshake");
            stream.ssl().curve_name().map(str::to_owned)
        });

        let connector = build_client_connector().expect("client connector");
        let tcp = TcpStream::connect(addr).expect("connect");
        let stream = connector.connect(sni, tcp).expect("client handshake");
        let client_curve = stream.ssl().curve_name().map(str::to_owned);

        let server_curve = server.join().expect("server thread panicked");

        assert_eq!(client_curve.as_deref(), Some("X25519MLKEM768"));
        assert_eq!(server_curve.as_deref(), Some("X25519MLKEM768"));
    }

    #[test]
    fn multi_peer_role_assignment() {
        let local_pub = [10u8; 32];
        let peer_smaller = ([5u8; 32], "127.0.0.1:8001".parse().unwrap());
        let peer_greater_1 = ([15u8; 32], "127.0.0.1:8002".parse().unwrap());
        let peer_greater_2 = ([20u8; 32], "127.0.0.1:8003".parse().unwrap());

        let peers = [peer_smaller, peer_greater_1, peer_greater_2];
        let roles = assign_peer_roles(&local_pub, &peers).expect("role assignment");

        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0].2, Role::Server);
        assert_eq!(roles[1].2, Role::Client);
        assert_eq!(roles[2].2, Role::Client);

        // Individual pairwise verification
        assert_eq!(
            connection_role(&local_pub, &peers[0].0).unwrap(),
            Role::Server
        );
        assert_eq!(
            connection_role(&local_pub, &peers[1].0).unwrap(),
            Role::Client
        );
        assert_eq!(
            connection_role(&local_pub, &peers[2].0).unwrap(),
            Role::Client
        );

        // Identity check: same key is an error
        let peer_equal = ([10u8; 32], "127.0.0.1:8004".parse().unwrap());
        assert!(assign_peer_roles(&local_pub, &[peer_equal]).is_err());
    }

    #[test]
    fn multi_peer_reconnect_backoff_timing() {
        let now = Instant::now();
        let mut conn = PeerConn::new_disconnected(now);

        // Initially at INITIAL_BACKOFF_MS (100ms), ready to dial immediately.
        assert_eq!(conn.backoff_ms(), Some(INITIAL_BACKOFF_MS));
        assert!(conn.should_dial(now));

        // Sequence of failures: backoff should double at each step:
        // 100 -> 200 -> 400 -> 800 -> 1600 -> 3200 -> 5000 (capped at MAX_BACKOFF_MS) -> 5000
        let expected_delays = [100, 200, 400, 800, 1600, 3200, 5000, 5000];
        let expected_next_backoff = [200, 400, 800, 1600, 3200, 5000, 5000, 5000];

        for (delay_ms, next_backoff) in expected_delays.into_iter().zip(expected_next_backoff) {
            conn.record_failure(now);
            assert_eq!(conn.backoff_ms(), Some(next_backoff));
            assert_eq!(
                conn.next_dial(),
                Some(now + Duration::from_millis(delay_ms))
            );
        }

        assert_eq!(conn.backoff_ms(), Some(MAX_BACKOFF_MS));
    }

    #[test]
    fn multi_peer_inner_handshake_timeout_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let sni = "example.test";

        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let acceptor = build_server_acceptor(sni).expect("acceptor");
            acceptor.accept(tcp).expect("handshake")
        });

        let connector = build_client_connector().expect("connector");
        let tcp = TcpStream::connect(addr).expect("connect");
        let stream = connector.connect(sni, tcp).expect("client handshake");
        let _server_stream = server.join().expect("server join");

        let t0 = Instant::now();
        let mut conn = PeerConn::Connected {
            stream,
            reader: FrameReader::default(),
            start: t0,
            inner_confirmed: false,
            was_established: false,
        };

        assert!(conn.is_connected());
        assert!(!conn.is_disconnected());
        assert!(!conn.is_connecting());
        assert!(conn.raw_fd().is_some());
        assert!(conn.stream().is_some());
        assert!(conn.stream_mut().is_some());
        assert_eq!(conn.start(), Some(t0));
        assert!(conn.reader().is_some());
        assert!(conn.reader_mut().is_some());
        assert_eq!(conn.was_established(), Some(false));

        // Before timeout: not expired
        assert!(!conn.is_inner_handshake_timeout(t0 + Duration::from_secs(5)));
        assert!(!conn.is_inner_expired(t0 + Duration::from_secs(5), Duration::from_secs(10)));

        // After timeout: expired
        assert!(conn.is_inner_handshake_timeout(t0 + Duration::from_secs(10)));
        assert!(conn.is_inner_expired(t0 + Duration::from_secs(10), Duration::from_secs(10)));

        // Once confirmed: no longer expired even after deadline
        conn.mark_inner_confirmed();
        assert!(!conn.is_inner_handshake_timeout(t0 + Duration::from_secs(15)));
    }

    #[test]
    fn multi_peer_try_connect_and_drive_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let sni = "example.test";

        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let acceptor = build_server_acceptor(sni).expect("acceptor");
            acceptor.accept(tcp).expect("handshake")
        });

        let start_time = Instant::now();
        let stream = try_connect(addr, sni).expect("try_connect");
        let mut conn = PeerConn::Connecting {
            stream,
            start: start_time,
        };
        assert!(conn.is_connecting());
        assert!(conn.raw_fd().is_some());
        assert_eq!(conn.start(), Some(start_time));
        assert!(!conn.is_handshake_timeout(start_time));
        assert!(conn.is_handshake_expired(
            start_time + Duration::from_secs(10),
            Duration::from_secs(10)
        ));

        let t0 = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(2);
        while conn.is_connecting() && Instant::now() < deadline {
            let _ = conn.drive_handshake(t0, true);
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            conn.is_connected(),
            "connection should transition to Connected"
        );
        assert_eq!(conn.was_established(), Some(true));
        let _server_stream = server.join().expect("server join");
    }

    fn loopback_tls_pair(
        sni: &'static str,
    ) -> (SslStream<TcpStream>, SslStream<TcpStream>, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            tcp.set_nodelay(true).expect("nodelay server");
            let acceptor = build_server_acceptor(sni).expect("acceptor");
            acceptor.accept(tcp).expect("server handshake")
        });
        let connector = build_client_connector().expect("connector");
        let tcp = TcpStream::connect(addr).expect("connect");
        tcp.set_nodelay(true).expect("nodelay client");
        let client = connector.connect(sni, tcp).expect("client handshake");
        let server = server.join().expect("server join");
        (client, server, addr)
    }

    #[test]
    fn drive_multi_peer_concurrent_pump() {
        let sni = "example.test";
        let (mut stream_remote_1, stream_local_1, addr_1) = loopback_tls_pair(sni);
        let (mut stream_remote_2, stream_local_2, addr_2) = loopback_tls_pair(sni);

        let poller = Epoll::create().expect("epoll create");
        let tun_rx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind tun_rx");
        let tun_tx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind tun_tx");
        tun_tx
            .connect(tun_rx.local_addr().unwrap())
            .expect("connect tun_tx");

        poller
            .add(tun_rx.as_raw_fd(), TOKEN_TUN)
            .expect("add tun_rx");
        poller
            .add(stream_local_1.get_ref().as_raw_fd(), TOKEN_PEER_BASE)
            .expect("add peer 1");
        poller
            .add(stream_local_2.get_ref().as_raw_fd(), TOKEN_PEER_BASE + 1)
            .expect("add peer 2");

        let t0 = Instant::now();
        let pub1 = [1u8; 32];
        let pub2 = [2u8; 32];
        let mut slots = vec![
            PeerSlot {
                public_key: pub1,
                addr: addr_1,
                role: Role::Server,
                conn: PeerConn::Connected {
                    stream: stream_local_1,
                    reader: FrameReader::default(),
                    start: t0,
                    inner_confirmed: true,
                    was_established: true,
                },
            },
            PeerSlot {
                public_key: pub2,
                addr: addr_2,
                role: Role::Server,
                conn: PeerConn::Connected {
                    stream: stream_local_2,
                    reader: FrameReader::default(),
                    start: t0,
                    inner_confirmed: true,
                    was_established: true,
                },
            },
        ];

        let mut wire1 = Vec::new();
        frame_datagram(b"inbound-from-peer-1", &mut wire1).unwrap();
        blocking_write_all(&mut stream_remote_1, &wire1);

        let mut wire2 = Vec::new();
        frame_datagram(b"inbound-from-peer-2", &mut wire2).unwrap();
        blocking_write_all(&mut stream_remote_2, &wire2);

        #[derive(Default)]
        struct MockDispatch {
            on_udp_calls: Vec<(SocketAddr, Vec<u8>)>,
            on_tun_calls: Vec<Vec<u8>>,
            tun_egress: Vec<EgressDatagram>,
        }

        impl TlsDispatch for MockDispatch {
            fn on_udp(
                &mut self,
                src: SocketAddr,
                dg: &[u8],
                _now_ms: u64,
            ) -> (Option<Vec<u8>>, Vec<EgressDatagram>) {
                self.on_udp_calls.push((src, dg.to_vec()));
                (None, Vec::new())
            }

            fn on_tun(&mut self, inner: &[u8], _now_ms: u64) -> Vec<EgressDatagram> {
                self.on_tun_calls.push(inner.to_vec());
                self.tun_egress.clone()
            }

            fn tick(&mut self, _now_ms: u64) -> Vec<EgressDatagram> {
                Vec::new()
            }

            fn is_peer_established(&self, _pubkey: &[u8; 32]) -> bool {
                true
            }
        }

        let mut mock = MockDispatch {
            tun_egress: vec![EgressDatagram {
                dst: addr_2,
                fate: 0,
                bytes: b"tun-egress-for-peer-2".to_vec(),
            }],
            ..Default::default()
        };

        tun_tx.send(b"tun-pkt").expect("send tun");

        pump(
            &poller,
            tun_rx.as_raw_fd(),
            None,
            None,
            &mut mock,
            &mut slots,
            sni,
            t0,
            INNER_HANDSHAKE_TIMEOUT,
            false,
            Some(10),
        )
        .expect("pump");

        assert_eq!(mock.on_udp_calls.len(), 2);
        assert_eq!(mock.on_udp_calls[0].0, addr_1);
        assert_eq!(mock.on_udp_calls[0].1, b"inbound-from-peer-1");
        assert_eq!(mock.on_udp_calls[1].0, addr_2);
        assert_eq!(mock.on_udp_calls[1].1, b"inbound-from-peer-2");

        let mut r2 = FrameReader::default();
        let got2 = blocking_read_one(&mut stream_remote_2, &mut r2);
        assert_eq!(got2, b"tun-egress-for-peer-2");

        stream_remote_1.get_ref().set_nonblocking(true).unwrap();
        let mut buf1 = [0u8; 128];
        let res1 = stream_remote_1.ssl_read(&mut buf1);
        assert!(res1.is_err(), "Peer 1 must receive no egress: {res1:?}");
    }

    #[test]
    fn find_server_peer_idx_never_stomps_connecting_handshake() {
        let now = Instant::now();
        let pub1 = [1u8; 32];
        let pub2 = [2u8; 32];
        let addr1: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        // Slot 0 is in Connecting state (TLS handshake in-flight)
        // Slot 1 is Disconnected
        let (stream1, _server, _addr) = loopback_tls_pair("example.test");
        let peers = vec![
            PeerSlot {
                public_key: pub1,
                addr: addr1,
                role: Role::Server,
                conn: PeerConn::Connecting {
                    stream: stream1,
                    start: now,
                },
            },
            PeerSlot {
                public_key: pub2,
                addr: addr2,
                role: Role::Server,
                conn: PeerConn::new_disconnected(now),
            },
        ];

        // An unknown IP arrives: Rule 3 must pick Slot 1 (Disconnected), NOT Slot 0 (Connecting)
        let unknown: SocketAddr = "10.0.0.99:9999".parse().unwrap();
        assert_eq!(find_server_peer_idx(&peers, unknown), Some(1));

        // If only Slot 0 exists and is Connecting, Rule 3 returns None (does not stomp)
        assert_eq!(find_server_peer_idx(&peers[..1], unknown), None);
    }

    #[test]
    fn route_egress_drops_if_peer_is_connecting() {
        let now = Instant::now();
        let poller = Epoll::create().expect("epoll create");
        let (mut stream_remote, stream_local, addr) = loopback_tls_pair("example.test");

        let mut slots = vec![PeerSlot {
            public_key: [1u8; 32],
            addr,
            role: Role::Client,
            conn: PeerConn::Connecting {
                stream: stream_local,
                start: now,
            },
        }];

        let egress = vec![EgressDatagram {
            dst: addr,
            fate: 0,
            bytes: b"should-be-dropped-while-connecting".to_vec(),
        }];

        // Must succeed without writing into connecting stream
        route_egress_to_peers(&egress, &mut slots, &poller, now).expect("route egress");

        // Remote stream must have nothing to read
        stream_remote.get_ref().set_nonblocking(true).unwrap();
        let mut buf = [0u8; 128];
        let res = stream_remote.ssl_read(&mut buf);
        assert!(res.is_err(), "remote must receive no data while connecting");
    }
}
