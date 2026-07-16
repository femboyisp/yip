//! The 3c.4 TLS relay-dial client: a dedicated thread holds one browser-parrot
//! TLS connection to the relay, sends the obfuscated monotonic `Register`
//! (first-on-connect + keepalive), and pipes obf-wrapped RelaySend/RelayDeliver
//! envelopes to/from the data plane over a `SOCK_DGRAM` `UnixDatagram`
//! socketpair. No tokio; all TLS via 3c.2's `crate::tls` client primitives.
//!
//! # Register-first invariant
//!
//! The relay classifies a connection on its **first** frame: `Register` vs.
//! anything else determines whether the connection is treated as a real relay
//! client or served the decoy. So on every (re)connect this module writes
//! `Register` — and only `Register` — before entering the steady-state pump,
//! never a `RelaySend` (even if one is already queued on the socketpair).
//!
//! # The pump
//!
//! One [`yip_io::epoll::Epoll`] watches two fds: the TLS/TCP socket (reused as
//! `Ready.udp`, mirroring `crate::tls`'s pump — the name is just "first
//! watched fd") and the socketpair end to the data plane (`Ready.tun`,
//! "second watched fd"). The socketpair is a `SOCK_DGRAM` `UnixDatagram`, not
//! a `UnixStream`: one `send` is one already-obfuscated envelope and one
//! `recv` reproduces it whole — datagram boundaries stand in for framing, so
//! there is no `[u16 len]` prefix on this side (unlike the TLS byte-stream
//! side, which still needs `crate::tls::frame_datagram`/`FrameReader` since
//! TLS has no message boundaries of its own). This is deliberate (3c.4 final
//! review FIX 1/FIX 3): a `SOCK_STREAM` socketpair cannot atomically drop a
//! message under backpressure (a short write desyncs the framing forever), so
//! the old stream socketpair either had to block the data-plane thread or
//! kill the whole process on a full buffer. `SOCK_DGRAM` `send` is atomic —
//! it either enqueues the whole envelope or fails with `WouldBlock`/an error,
//! never a partial write — so backpressure can be handled the same
//! best-effort way as a real dropped UDP packet: see [`send_socketpair`].
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boring::ssl::SslStream;

use yip_io::epoll::{read_fd, write_fd, Epoll};
use yip_io::poll::{Dispatch, DispatchOut, EgressDatagram};
use yip_rendezvous::{encode, Message, NodeId};

use crate::peer_manager::PeerManager;
use crate::tls::{
    connect_and_handshake, drain_tls_read, frame_datagram, write_all_tls, FrameReader,
    INITIAL_BACKOFF_MS, MAX_BACKOFF_MS, TLS_FRAME_MAX,
};

// REALITY.4a: the async relay-dial path. `yip_utls::connect`/`RealityStream`
// are re-exported at the crate root (see `crates/yip-utls/src/lib.rs`).

/// Register keepalive: re-send `Register` (counter bumped) at least this
/// often even with no data flowing, so the relay's freshness gate never
/// expires this connection out from under an idle tunnel.
const REG_KEEPALIVE_MS: u64 = 30_000;

/// Per-boot monotonic Register counter. The relay's freshness gate requires
/// each `Register` for a given node to carry a counter strictly greater than
/// the last one it saw, and it remembers that last-seen value for up to the
/// 60 s `tls_seen` TTL (see `crates/yip-relay`'s freshness gate).
///
/// A counter that always started at 0 (bumped to 1 on the first `Register`)
/// would lock a restarted node out for up to that whole 60 s window: the
/// relay's remembered `last_counter` from the previous boot is still fresh,
/// and a fresh process starting back at 1 is *not* strictly greater than
/// whatever the previous boot had already reached (3c.4 final review FIX 2).
/// [`Counter::seeded_now`] avoids that by seeding from wall-clock time
/// instead of 0: as long as real time has moved forward since the previous
/// boot (true for any restart that isn't instantaneous), the new seed is
/// already greater than any counter value the previous boot could have sent,
/// so the very first `Register` after a restart is accepted immediately.
///
/// Residual edge case: a backward wall-clock/NTP step between the previous
/// boot and this one, landing within the relay's 60 s freshness window,
/// could still produce a seed the relay rejects as stale — briefly
/// reproducing the old lockout. This is strictly better than before (where
/// *every* restart within 60 s hit it, not just ones coinciding with a
/// backward clock step) and is accepted as-is.
pub(crate) struct Counter(u64);
impl Counter {
    /// Seed from the current wall-clock time (whole seconds since the Unix
    /// epoch) rather than 0 — see the type doc for why. Falls back to a seed
    /// of 0 if the clock reads before the epoch (a broken/unset clock);
    /// `next()` still produces a valid, if not restart-safe, sequence in
    /// that degenerate case.
    pub(crate) fn seeded_now() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Counter(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

/// Build the framed `[u16 len][obf(RDV_TYPE, Register{node,counter})]` bytes.
pub(crate) fn build_register(obf_key: &[u8; 16], node: NodeId, counter: u64) -> Vec<u8> {
    let mut plain = Vec::new();
    encode(&Message::Register { node, counter }, &mut plain);
    let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0);
    let mut out = Vec::new();
    crate::tls::frame_datagram(&env, &mut out).expect("register envelope within frame cap");
    out
}

// ── public entry point ─────────────────────────────────────────────────────

/// Spawn the relay-dial client thread. It owns `sock` (one end of a
/// `UnixDatagram::pair()`, the other end wired to the data plane) and the TLS
/// connection to the relay at `host:port` (SNI = `sni`), and runs forever:
/// connect → handshake → **Register first** → pump → on any error, back off
/// and reconnect.
pub(crate) fn spawn(
    host: String,
    port: u16,
    sni: String,
    obf_key: [u8; 16],
    self_node: NodeId,
    sock: UnixDatagram,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || run(&host, port, &sni, &obf_key, self_node, sock))
}

/// The reconnect-with-backoff loop. Only returns if `sock` can no longer be
/// made non-blocking (an unrecoverable local setup failure) — otherwise runs
/// until the process exits.
fn run(
    host: &str,
    port: u16,
    sni: &str,
    obf_key: &[u8; 16],
    self_node: NodeId,
    sock: UnixDatagram,
) {
    if let Err(e) = sock.set_nonblocking(true) {
        eprintln!("relay_client: could not set socketpair non-blocking, thread exiting: {e}");
        return;
    }
    let sock_fd = sock.as_raw_fd();

    // Seeded from wall-clock time, not 0 — see `Counter::seeded_now`'s doc
    // (3c.4 final review FIX 2: avoids a restart lockout against the relay's
    // freshness gate).
    let mut counter = Counter::seeded_now();
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        let addr = match resolve(host, port) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("relay_client: resolving relay {host}:{port} failed: {e}");
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };

        let (mut stream, poller) = match connect_and_handshake(addr, sni, sock_fd) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("relay_client: connect/handshake to relay {addr} failed: {e}");
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };
        backoff_ms = INITIAL_BACKOFF_MS;

        // Register FIRST — the relay classifies the connection on the first
        // frame it reads; a `RelaySend` written before `Register` gets this
        // connection served the decoy instead of the real relay role.
        let reg = build_register(obf_key, self_node, counter.next());
        if let Err(e) = write_all_tls(&mut stream, &poller, &reg) {
            eprintln!("relay_client: failed to send initial Register, reconnecting: {e}");
            std::thread::sleep(Duration::from_millis(backoff_ms));
            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            continue;
        }

        if let Err(e) = pump(
            &mut stream,
            &poller,
            &sock,
            obf_key,
            self_node,
            &mut counter,
        ) {
            eprintln!("relay_client: connection error, reconnecting: {e}");
        }
        // Loop back and reconnect (fresh backoff since the last connection
        // did complete a handshake + Register).
    }
}

// ── REALITY relay-dial (async, confined tokio runtime) ─────────────────────

/// Spawn the REALITY relay-dial client thread (REALITY.4a). Mirrors [`spawn`]
/// but dials via `yip_utls::connect` (a Chrome-faithful REALITY ClientHello +
/// TLS 1.3 handshake) instead of boring, driven by a CONFINED current-thread
/// tokio runtime. The data-plane loop (`run_relay_tls` + `PeerManager`) is a
/// separate thread and stays sync/epoll/tokio-free.
///
/// The outer REALITY TLS is zero-cert-auth by design (the camouflage). The
/// tunnel's confidentiality/integrity come from the end-to-end peer Noise-IK,
/// so an outer MITM / malicious relay sees only inner peer ciphertext and can
/// at worst DoS. REALITY.4b adds explicit Xray-style relay verification on top.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the existing sync `spawn`; the dial parameters are all distinct config-derived values"
)]
pub(crate) fn spawn_reality(
    host: String,
    port: u16,
    pubkey: [u8; 32],
    short_id: [u8; 8],
    sni: String,
    obf_key: [u8; 16],
    self_node: NodeId,
    sock: UnixDatagram,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("relay_client(reality): failed to build tokio runtime: {e}");
                return;
            }
        };
        rt.block_on(run_reality(
            &host, port, &pubkey, short_id, &sni, &obf_key, self_node, sock,
        ));
    });
}

/// The async reconnect-with-backoff loop for the REALITY relay-dial thread.
#[expect(
    clippy::too_many_arguments,
    reason = "parameters mirror `spawn_reality`; threading them is clearer than a struct here"
)]
async fn run_reality(
    host: &str,
    port: u16,
    pubkey: &[u8; 32],
    short_id: [u8; 8],
    sni: &str,
    obf_key: &[u8; 16],
    self_node: NodeId,
    sock: UnixDatagram,
) {
    // Wrap the socketpair as tokio (datagram boundaries preserved by SOCK_DGRAM).
    if let Err(e) = sock.set_nonblocking(true) {
        eprintln!("relay_client(reality): set_nonblocking failed: {e}");
        return;
    }
    let sock = match tokio::net::UnixDatagram::from_std(sock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("relay_client(reality): tokio UnixDatagram wrap failed: {e}");
            return;
        }
    };
    let mut counter = Counter::seeded_now();
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        let tcp = match tokio::net::TcpStream::connect((host, port)).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("relay_client(reality): connect to {host}:{port} failed: {e}");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };
        // Disable Nagle: the pump issues many small writes; Nagle+delayed-ACK
        // would add ~40ms latency, gratuitous on a latency-sensitive VPN.
        let _ = tcp.set_nodelay(true);

        let handshake = tokio::time::timeout(
            crate::tls::HANDSHAKE_TIMEOUT,
            yip_utls::connect(tcp, sni, pubkey, short_id),
        )
        .await;
        let stream = match handshake {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!("relay_client(reality): REALITY handshake to {sni} failed: {e}");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
            Err(_elapsed) => {
                eprintln!("relay_client(reality): REALITY handshake to {sni} timed out");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };
        // Handshake done → reset backoff for the next disconnect.
        backoff_ms = INITIAL_BACKOFF_MS;

        if let Err(e) = pump_reality(stream, &sock, obf_key, self_node, &mut counter).await {
            eprintln!("relay_client(reality): connection error, reconnecting: {e}");
        }
        // Loop back and reconnect (fresh backoff since the last connection did
        // complete a handshake + Register).
    }
}

/// The steady-state async pump: Register-first, then `select!` between the
/// `RealityStream` (inbound relay frames → socketpair), the socketpair
/// (outbound datagrams → framed → RealityStream), and a keepalive timer
/// (re-`Register`). Returns on any stream error/EOF so the caller reconnects.
async fn pump_reality<S>(
    mut stream: yip_utls::RealityStream<S>,
    sock: &tokio::net::UnixDatagram,
    obf_key: &[u8; 16],
    self_node: NodeId,
    counter: &mut Counter,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Register FIRST — the relay classifies the connection on its first frame.
    let reg = build_register(obf_key, self_node, counter.next());
    stream.write_all(&reg).await?;

    let mut reader = crate::tls::FrameReader::default();
    let mut tls_read_buf = [0u8; TLS_FRAME_MAX];
    let mut sock_read_buf = [0u8; TLS_FRAME_MAX];
    let mut keepalive = tokio::time::interval(Duration::from_millis(REG_KEEPALIVE_MS));
    keepalive.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            r = stream.read(&mut tls_read_buf) => {
                let n = r?;
                if n == 0 {
                    return Ok(()); // relay closed → reconnect
                }
                reader.push(&tls_read_buf[..n]);
                while let Some(dg) = reader.next()? {
                    // Best-effort, non-blocking send: the socketpair is a
                    // UDP-equivalent, never-a-reliability-layer channel (see
                    // `send_socketpair`). A blocking `.await` here would stall
                    // this whole `select!` loop — including the REALITY
                    // stream read/keepalive arms — on a slow data-plane
                    // drain, so drop on backpressure instead of awaiting it.
                    match sock.try_send(&dg) {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            r = sock.recv(&mut sock_read_buf) => {
                let n = r?;
                if n == 0 {
                    // Fail closed on an empty datagram (see
                    // `drain_socketpair`'s same invariant): framing a
                    // zero-length payload would emit a `[0x00,0x00]` frame
                    // that the peer's `FrameReader::next` rejects as a
                    // bad-length self-inflicted protocol violation.
                    continue;
                }
                let mut framed = Vec::new();
                crate::tls::frame_datagram(&sock_read_buf[..n], &mut framed)?;
                stream.write_all(&framed).await?;
            }
            _ = keepalive.tick() => {
                let reg = build_register(obf_key, self_node, counter.next());
                stream.write_all(&reg).await?;
            }
        }
    }
}

// ── socketpair I/O (SOCK_DGRAM: atomic send, no framing) ───────────────────

/// Rate-limits the "socketpair backpressure, dropping a datagram" log so
/// sustained backpressure (e.g. a wedged/slow peer thread) cannot itself
/// become a performance problem by logging on every dropped envelope.
static LAST_DROP_LOG_MS: AtomicU64 = AtomicU64::new(0);

fn now_wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Log the "dropping a datagram" debug line at most once per second.
fn log_socketpair_drop_rate_limited() {
    let now_ms = now_wall_clock_ms();
    let last = LAST_DROP_LOG_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) >= 1_000
        && LAST_DROP_LOG_MS
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        eprintln!("relay_client: socketpair backpressure, dropping a datagram");
    }
}

/// Best-effort atomic send of one already-obfuscated envelope to the
/// socketpair (3c.4 final review FIX 1). `sock` is `SOCK_DGRAM`, so `send`
/// either enqueues the WHOLE datagram or fails — never a partial write —
/// which is what makes it safe to just drop on backpressure instead of
/// spinning or erroring out: this transport is already best-effort,
/// UDP-equivalent, never a reliability layer. `env` is always far under
/// `yip_io::MAX_WIRE_DATAGRAM` (this module's envelopes), well inside any
/// `SOCK_DGRAM` size limit, so size is never the reason a send fails.
///
/// - `WouldBlock` (the socketpair's own send buffer is full): the datagram is
///   dropped (rate-limited debug log) and this returns `Ok(())` — backpressure
///   must never block or kill the data-plane thread.
/// - Any other error (the peer end of the pair is gone — observed on this
///   platform as `ConnectionRefused`/`NotConnected`/`BrokenPipe` depending on
///   exactly how the peer went away) is NOT recoverable here and propagates,
///   so the caller (`pump` or `run_relay_tls`) tears its loop down
///   fail-closed rather than silently talking to nobody forever.
fn send_socketpair(sock: &UnixDatagram, env: &[u8]) -> io::Result<()> {
    match sock.send(env) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            log_socketpair_drop_rate_limited();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Drain every datagram currently available on `sock` (non-blocking),
/// calling `emit` on each one's bytes. One `recv` is exactly one envelope a
/// peer `send_socketpair`'d — `SOCK_DGRAM` datagram boundaries stand in for
/// the old `[u16 len]` stream framing, so there is no reassembly here.
///
/// 3c.4 final review FIX 3: `Ok(0)` (an empty datagram — this module never
/// sends one, so it can only mean something is wrong) and any error other
/// than `WouldBlock`/`Interrupted` are treated as "the peer end of this
/// socketpair is gone" and returned as `Err`, tearing the caller's loop down
/// fail-closed. This matters most on the data-plane side (`run_relay_tls`):
/// if the relay thread has died, this is how the data plane notices and
/// exits instead of carrying on as if the relay were still reachable.
fn drain_socketpair(
    sock: &UnixDatagram,
    buf: &mut [u8],
    mut emit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    loop {
        match sock.recv(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "socketpair: received a zero-length datagram (peer gone?)",
                ));
            }
            Ok(n) => emit(&buf[..n])?,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Resolve `host:port` to one `SocketAddr` (re-resolved on every connect
/// attempt so a relay IP change is picked up on the next reconnect).
fn resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host, port).to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "relay host resolved to no addresses",
        )
    })
}

/// Drive one live TLS connection: pipe obf-wrapped envelope bytes between the
/// TLS stream and the socketpair, and re-send `Register` every
/// [`REG_KEEPALIVE_MS`]. Returns on any TLS/TCP/framing error, or on a
/// socketpair send/recv error other than backpressure (fail-closed; the
/// caller reconnects), or propagates a fatal `Epoll` error via `?`.
fn pump(
    stream: &mut SslStream<TcpStream>,
    poller: &Epoll,
    sock: &UnixDatagram,
    obf_key: &[u8; 16],
    self_node: NodeId,
    counter: &mut Counter,
) -> io::Result<()> {
    let mut tls_reader = FrameReader::default();
    let mut tls_read_buf = [0u8; TLS_FRAME_MAX];
    let mut sock_read_buf = [0u8; TLS_FRAME_MAX];
    let mut reframe_buf: Vec<u8> = Vec::new();
    let mut last_reg = Instant::now();
    // The poller wait cap: bounded by the keepalive interval so a fully idle
    // connection still wakes up in time to re-Register (`i32` comfortably
    // holds REG_KEEPALIVE_MS; fall back to i32::MAX rather than panic if that
    // ever changes to something absurd).
    let wait_ms = i32::try_from(REG_KEEPALIVE_MS).unwrap_or(i32::MAX);

    loop {
        let ready = poller.wait(wait_ms)?;

        // TLS-readable: drain plaintext, de-frame (the TLS side is still a
        // byte stream, so it still needs `[u16 len]` framing), and hand each
        // de-framed obf'd RelayDeliver envelope to the data plane as ONE
        // datagram send — best-effort, see `send_socketpair`.
        if ready.udp {
            drain_tls_read(stream, &mut tls_reader, &mut tls_read_buf)?;
            loop {
                match tls_reader.next() {
                    Ok(Some(dg)) => send_socketpair(sock, &dg)?,
                    Ok(None) => break,
                    Err(e) => return Err(e),
                }
            }
        }

        // Socketpair-readable: each `recv` is one already-obf'd `RelaySend`
        // envelope from the data plane (no framing on this side — datagram
        // boundaries ARE the framing); re-frame it for the TLS byte stream
        // and write it out.
        if ready.tun {
            drain_socketpair(sock, &mut sock_read_buf, |dg| {
                reframe_buf.clear();
                frame_datagram(dg, &mut reframe_buf)?;
                write_all_tls(stream, poller, &reframe_buf)
            })?;
        }

        if last_reg.elapsed() >= Duration::from_millis(REG_KEEPALIVE_MS) {
            let reg = build_register(obf_key, self_node, counter.next());
            write_all_tls(stream, poller, &reg)?;
            last_reg = Instant::now();
        }
    }
}

// ── data-plane end (3c.4 Task 6) ────────────────────────────────────────────

/// Fixed per-iteration pump cadence for [`run_relay_tls`]: `PeerManager::tick`
/// must fire at least every 10 ms, mirroring `crate::tls::run_tls`'s `TICK_MS`
/// (private to that module, so duplicated here — the same small-constant
/// duplication `tls.rs`/`quic.rs` already use for their own per-module
/// helpers rather than growing `pub(crate)` surface for one constant).
const TICK_MS: i32 = 10;

/// Take a `PeerManager` UDP outcome as owned data, decoupling it from the
/// manager borrow. Duplicated from `crate::tls`'s private `owned_out` (same
/// per-module small-helper duplication as `TICK_MS` above).
fn owned_out(out: DispatchOut<'_>) -> (Option<Vec<u8>>, Vec<EgressDatagram>) {
    match out {
        DispatchOut::None => (None, Vec::new()),
        DispatchOut::Tun(inner) => (Some(inner.to_vec()), Vec::new()),
        DispatchOut::Udp(dgs) => (None, dgs.to_vec()),
        DispatchOut::Both(inner, dgs) => (Some(inner.to_vec()), dgs.to_vec()),
    }
}

/// Write a decoded inner frame to the TUN device (best-effort: a single failed
/// write is logged and swallowed rather than tearing down the loop).
/// Duplicated from `crate::tls`'s private `write_tun`.
fn write_tun(tun_fd: RawFd, inner: &[u8]) {
    if let Err(e) = write_fd(tun_fd, inner) {
        eprintln!("relay_tls: tun write error: {e}");
    }
}

/// Send each of `egress`'s datagrams to the socketpair via
/// [`send_socketpair`] — the SAME best-effort atomic send the relay thread's
/// own [`pump`] uses on its socketpair-write side, so ordinary backpressure
/// drops silently here too instead of blocking or killing this loop.
/// `e.dst` is ignored: every egress datagram on this path is relay-destined,
/// so there is exactly one place to send it — the relay thread on the other
/// end of the socketpair.
fn send_egress_to_relay_thread(sock: &UnixDatagram, egress: &[EgressDatagram]) -> io::Result<()> {
    for d in egress {
        send_socketpair(sock, &d.bytes)?;
    }
    Ok(())
}

/// The data-plane end of the 3c.4 TLS relay-dial path: drives [`PeerManager`]
/// over the socketpair to [`spawn`]'s relay thread instead of a UDP socket.
/// Mirrors `crate::tls::run_tls`'s pump ordering (readable-side → de-frame →
/// `PeerManager::on_udp`; TUN-readable → `PeerManager::on_tun`; fixed
/// [`TICK_MS`] cadence tick) with the two [`Epoll`]-watched fds being `sock`
/// (`Ready.udp`) and `tun_fd` (`Ready.tun`) rather than a UDP socket and TUN.
///
/// All egress `PeerManager` produces here is already an obf'd RelaySend
/// envelope addressed (by `EgressDatagram::dst`, ignored) at the relay — see
/// [`crate::rendezvous::TlsRelayRendezvous`], which builds every
/// rendezvous-facing datagram against `relay_addr`. Everything read off
/// `sock` is one obf'd `RelayDeliver` envelope per datagram (no framing — see
/// the module doc for why `sock` is `SOCK_DGRAM`) the relay thread already
/// validated on-wire (it terminates the real TLS connection).
///
/// Only returns on a fatal I/O error: an `Epoll`/TUN failure, or a socketpair
/// send/recv indicating the relay thread's end of the pair is gone (3c.4
/// final review FIX 3 — see [`drain_socketpair`]/[`send_socketpair`]). This
/// loop does not itself reconnect (the relay thread already owns
/// reconnect-with-backoff for the TLS leg), so there is nothing safe to do on
/// a fatal error but tear down and let the caller (`tunnel::run`) propagate
/// it — which, since `yipd` has no process supervisor of its own yet, means
/// the whole process exits. That is intentional here (fail-closed on the
/// relay thread dying) and distinct from ordinary per-datagram backpressure,
/// which never reaches this far — it is dropped silently inside
/// `send_socketpair`.
pub(crate) fn run_relay_tls(
    tun_fd: RawFd,
    manager: &mut PeerManager,
    relay_addr: SocketAddr,
    sock: UnixDatagram,
) -> io::Result<()> {
    sock.set_nonblocking(true)?;
    let sock_fd = sock.as_raw_fd();
    let poller = Epoll::new(sock_fd, tun_fd)?;

    let mut sock_read_buf = [0u8; TLS_FRAME_MAX];
    let mut tun_read_buf = [0u8; TLS_FRAME_MAX];
    let start = Instant::now();

    loop {
        let ready = poller.wait(TICK_MS)?;
        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // 1. Socketpair-readable: inbound obf'd RelayDeliver envelopes from
        //    the relay thread, one per datagram → `PeerManager::on_udp`.
        if ready.udp {
            drain_socketpair(&sock, &mut sock_read_buf, |env| {
                let (tun, egress) = owned_out(manager.on_udp(relay_addr, env, now_ms));
                if let Some(inner) = tun {
                    write_tun(tun_fd, &inner);
                }
                send_egress_to_relay_thread(&sock, &egress)
            })?;
        }

        // 2. TUN-readable: `PeerManager::on_tun` → relay-bound egress.
        if ready.tun {
            loop {
                match read_fd(tun_fd, &mut tun_read_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let egress = manager.on_tun(&tun_read_buf[..n], now_ms).to_vec();
                        send_egress_to_relay_thread(&sock, &egress)?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        eprintln!("relay_tls: tun read error: {e}");
                        break;
                    }
                }
            }
        }

        // 3. Cadence tick (feedback / keepalive / handshake retry / cover).
        if let Some(egress) = manager.tick(now_ms).map(<[EgressDatagram]>::to_vec) {
            send_egress_to_relay_thread(&sock, &egress)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn register_frame_deobfuscates_to_fresh_register() {
        let key = yip_obf::derive_key(&[9u8; 32]);
        let node = yip_rendezvous::node_id(&[1u8; 32]);
        let framed = build_register(&key, node, 1);
        // Strip the [u16 len] TLS frame, then deobf + decode.
        let mut r = crate::tls::FrameReader::default();
        r.push(&framed);
        let env = r.next().unwrap().unwrap();
        let (pt, body) = yip_obf::deobfuscate(&key, &env).unwrap();
        assert_eq!(pt, yip_obf::RDV_TYPE);
        assert_eq!(
            yip_rendezvous::decode(&body),
            Some(yip_rendezvous::Message::Register { node, counter: 1 })
        );
    }

    /// 3c.4 final review FIX 2: the counter must be seeded from wall-clock
    /// time (definitely > 0, since we are not testing this in 1970), and
    /// still increase by exactly 1 on every `next()` from wherever it was
    /// seeded — the "monotonic from 1" guarantee becomes "monotonic from the
    /// seed".
    #[test]
    fn counter_is_monotonic_from_seed() {
        let mut c = Counter::seeded_now();
        let first = c.next();
        assert!(
            first > 0,
            "a wall-clock-seeded counter's first value must be well past 0"
        );
        assert_eq!(c.next(), first + 1);
        assert_eq!(c.next(), first + 2);
    }

    /// 3c.4 final review FIX 1: on ordinary backpressure (the socketpair's
    /// send buffer is full) `send_socketpair` must drop the datagram and
    /// return `Ok(())` — never `Err`, since a `SOCK_STREAM` socketpair's
    /// inability to atomically drop a partial write was exactly what used to
    /// kill the whole `yipd` process here. `SOCK_DGRAM`'s `send` is atomic
    /// (whole datagram or nothing), which is what makes the silent-drop safe.
    #[test]
    fn send_socketpair_drops_silently_on_backpressure() {
        let (a, b) = UnixDatagram::pair().expect("socketpair");
        a.set_nonblocking(true).expect("nonblocking");
        // Fill the kernel send buffer until a send would block, without ever
        // draining `b` — this reproduces sustained backpressure.
        let mut filled = false;
        for _ in 0..200_000 {
            match a.send(&[0u8; 64]) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    filled = true;
                    break;
                }
                Err(e) => panic!("unexpected error while filling the socketpair buffer: {e}"),
            }
        }
        assert!(filled, "expected the socketpair's send buffer to fill");

        // The buffer is now full: `send_socketpair` must swallow the
        // WouldBlock and return Ok, not propagate an Err.
        send_socketpair(&a, b"one datagram too many")
            .expect("backpressure must be dropped silently, not returned as an error");
        drop(b);
    }

    /// 3c.4 final review FIX 1 (the other half): any socketpair send error
    /// that is NOT backpressure — observed here via the peer end being
    /// dropped, which this platform reports as a real error
    /// (`ConnectionRefused`/`NotConnected`/`BrokenPipe` depending on timing)
    /// rather than `WouldBlock` — must propagate as `Err` so the caller
    /// (`pump`/`run_relay_tls`) tears its loop down instead of silently
    /// talking to a socketpair nobody is listening on anymore.
    #[test]
    fn send_socketpair_propagates_a_real_error_when_the_peer_is_gone() {
        let (a, b) = UnixDatagram::pair().expect("socketpair");
        a.set_nonblocking(true).expect("nonblocking");
        drop(b);

        let err = send_socketpair(&a, b"nobody is listening")
            .expect_err("sending to a socketpair whose peer end was dropped must be an error");
        assert_ne!(
            err.kind(),
            io::ErrorKind::WouldBlock,
            "a peer-gone error must be distinguishable from ordinary backpressure \
             (backpressure is dropped silently; peer-gone must tear the loop down)"
        );
    }

    /// 3c.4 final review FIX 3: `drain_socketpair` must fail closed on a
    /// zero-length datagram (this module's envelopes are never empty, so one
    /// arriving can only mean something is wrong) rather than treat it as an
    /// ordinary empty read and keep polling — see the function's doc comment
    /// for why this matters most on the data-plane side (`run_relay_tls`
    /// noticing the relay thread died).
    #[test]
    fn drain_socketpair_fails_closed_on_empty_datagram() {
        let (a, b) = UnixDatagram::pair().expect("socketpair");
        b.set_nonblocking(true).expect("nonblocking");
        a.send(&[]).expect("send an empty datagram");

        let mut buf = [0u8; 64];
        let mut emitted = Vec::new();
        let result = drain_socketpair(&b, &mut buf, |dg| {
            emitted.push(dg.to_vec());
            Ok(())
        });

        assert!(
            result.is_err(),
            "a zero-length datagram must tear the loop down (Err), not be silently ignored"
        );
        assert!(
            emitted.is_empty(),
            "the empty datagram itself must never reach `emit`"
        );
    }

    /// `drain_socketpair`'s ordinary path: multiple real datagrams are each
    /// delivered to `emit` exactly once, in order, with no framing/buffering
    /// needed (datagram boundaries alone separate them).
    #[test]
    fn drain_socketpair_emits_each_real_datagram() {
        let (a, b) = UnixDatagram::pair().expect("socketpair");
        b.set_nonblocking(true).expect("nonblocking");
        a.send(b"first").expect("send first");
        a.send(b"second").expect("send second");

        let mut buf = [0u8; 64];
        let mut emitted = Vec::new();
        drain_socketpair(&b, &mut buf, |dg| {
            emitted.push(dg.to_vec());
            Ok(())
        })
        .expect("two well-formed datagrams must not error");

        assert_eq!(emitted, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    /// Read one complete `[u16 len]`-framed datagram from a *blocking* TLS
    /// stream. Mirrors `crate::tls::tests::blocking_read_one`, duplicated
    /// here since that helper is private to `tls`'s own test module.
    fn blocking_read_one_tls(
        stream: &mut SslStream<TcpStream>,
        reader: &mut FrameReader,
    ) -> Vec<u8> {
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

    /// Write `buf` in full on a *blocking* TLS stream. Mirrors
    /// `crate::tls::tests::blocking_write_all`.
    fn blocking_write_all_tls(stream: &mut SslStream<TcpStream>, mut buf: &[u8]) {
        while !buf.is_empty() {
            let n = stream.ssl_write(buf).expect("ssl_write");
            buf = &buf[n..];
        }
    }

    /// End-to-end proof that [`spawn`] does the three things that matter:
    /// (1) connects and completes the TLS handshake against a stub relay
    /// server, (2) sends `Register` as the very first frame (the relay
    /// classifies on-first-frame — a `RelaySend` written first would get
    /// this connection served the decoy), and (3) pipes an inbound
    /// obf'd `RelayDeliver` frame from the TLS stream through, as one
    /// datagram, to the data-plane side of the (now `SOCK_DGRAM`)
    /// socketpair.
    ///
    /// Bounded so a hang fails loudly rather than blocking `cargo test`
    /// forever: the socketpair recv on the data-plane end carries a 5 s
    /// `read_timeout`, so a stuck client thread surfaces as a panicking
    /// `expect`, not an indefinite wait.
    #[test]
    fn relay_client_registers_first_and_pipes_relay_deliver_to_data_plane() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let sni = "relay.example.test";

        let obf_key = yip_obf::derive_key(&[42u8; 32]);
        let self_node = yip_rendezvous::node_id(&[7u8; 32]);
        let relay_src = yip_rendezvous::node_id(&[9u8; 32]);

        let server = std::thread::spawn(move || {
            let (tcp, _from) = listener.accept().expect("accept");
            let acceptor = crate::tls::build_server_acceptor(sni).expect("server acceptor");
            let mut stream = acceptor.accept(tcp).expect("server handshake");

            // The FIRST frame this stub relay reads MUST be a fresh Register
            // — that is the whole point of the Register-first invariant. The
            // counter is now wall-clock-seeded (FIX 2), so only its shape
            // (a Register for the right node, with a positive counter) is
            // checked, not an exact value.
            let mut reader = FrameReader::default();
            let env = blocking_read_one_tls(&mut stream, &mut reader);
            let (ptype, body) =
                yip_obf::deobfuscate(&obf_key, &env).expect("deobfuscate register envelope");
            assert_eq!(ptype, yip_obf::RDV_TYPE);
            match yip_rendezvous::decode(&body) {
                Some(yip_rendezvous::Message::Register { node, counter }) => {
                    assert_eq!(node, self_node);
                    assert!(counter > 0, "seeded counter must be positive");
                }
                other => {
                    panic!("first frame from the client must be a fresh Register, got {other:?}")
                }
            }

            // Reply with an obf'd RelayDeliver carrying b"pong".
            let mut plain = Vec::new();
            yip_rendezvous::encode(
                &yip_rendezvous::Message::RelayDeliver {
                    src: relay_src,
                    payload: b"pong".to_vec(),
                },
                &mut plain,
            );
            let env = yip_obf::obfuscate(&obf_key, yip_obf::RDV_TYPE, &plain, 0);
            let mut wire = Vec::new();
            frame_datagram(&env, &mut wire).expect("frame relay-deliver envelope");
            blocking_write_all_tls(&mut stream, &wire);

            // Hold the connection open briefly so the client has time to
            // read the reply before this thread (and the TCP connection)
            // tears down.
            std::thread::sleep(Duration::from_millis(300));
        });

        let (test_end, client_sock) = UnixDatagram::pair().expect("socketpair");
        test_end
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout on test end");

        let _client = spawn(
            addr.ip().to_string(),
            addr.port(),
            sni.to_string(),
            obf_key,
            self_node,
            client_sock,
        );

        // Recv the RelayDeliver envelope piped through to the data-plane
        // side of the socketpair as ONE datagram (no framing on this side),
        // bounded by test_end's 5 s read_timeout.
        let mut buf = [0u8; 4096];
        let n = test_end
            .recv(&mut buf)
            .expect("recv from data-plane end of the socketpair");
        let dg = &buf[..n];

        let (ptype, body) =
            yip_obf::deobfuscate(&obf_key, dg).expect("deobfuscate relay-deliver envelope");
        assert_eq!(ptype, yip_obf::RDV_TYPE);
        assert_eq!(
            yip_rendezvous::decode(&body),
            Some(yip_rendezvous::Message::RelayDeliver {
                src: relay_src,
                payload: b"pong".to_vec(),
            })
        );

        server.join().expect("server thread panicked");
        // `_client` is an intentionally-never-joined background thread (by
        // design `spawn` runs forever); it is left to retry-with-backoff
        // against the now-closed listener for the remaining test-process
        // lifetime, harmless at ≤5 s/attempt.
    }

    /// Read exactly `buf.len()` bytes from a *blocking* TLS stream.
    fn read_exact_ssl(stream: &mut SslStream<TcpStream>, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let n = stream.ssl_read(buf).expect("ssl_read");
            buf = &mut buf[n..];
        }
    }

    /// REALITY.4a: `spawn_reality` completes a real `yip_utls` TLS 1.3
    /// handshake against a plain local boring server (zero-cert-auth, so any
    /// TLS 1.3 server works), sends `Register` as the first frame, and pipes
    /// an inbound obf'd frame through to the data-plane socketpair end —
    /// proving handshake + pump + framing independent of REALITY auth (which
    /// the netns test covers).
    #[test]
    fn spawn_reality_handshakes_registers_first_and_pipes_inbound() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let sni = "relay.example.test";
        let obf_key = yip_obf::derive_key(&[9u8; 32]);
        let self_node = yip_rendezvous::node_id(&[1u8; 32]);

        // Data-plane end of the socketpair, with a read timeout so a hang fails loudly.
        let (relay_sock, data_plane_sock) = UnixDatagram::pair().expect("socketpair");
        data_plane_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");

        // Stub relay: accept one TLS connection, read the first frame (Register),
        // then send one obf'd RelayDeliver frame back.
        let server_obf = obf_key;
        let server = std::thread::spawn(move || {
            let acceptor = crate::tls::build_server_acceptor(sni).expect("server acceptor");
            // `yip_utls`'s crafted ClientHello draws its leading and trailing
            // GREASE extension codepoints independently (RFC 8701 gives 16
            // possible values), so on a rare unlucky draw the two collide and
            // a strict TLS 1.3 server (boring's default duplicate-extension
            // check) rejects that one ClientHello. `spawn_reality`'s own
            // client already reconnects-with-backoff on any handshake
            // failure, so this stub server just keeps accepting new
            // connections until one handshake actually completes, mirroring
            // that real recovery path instead of failing the test on the
            // ~1-in-16 unlucky draw.
            let mut tls = {
                let mut accepted = None;
                for _ in 0..20 {
                    let (tcp, _peer) = listener.accept().expect("accept");
                    match acceptor.accept(tcp) {
                        Ok(tls) => {
                            accepted = Some(tls);
                            break;
                        }
                        Err(_) => continue, // rejected ClientHello: let the client's reconnect retry
                    }
                }
                accepted.expect("server tls accept within 20 attempts")
            };
            // Read the client's first framed message (the Register) so the pump
            // is past Register-first before we send anything back.
            let mut hdr = [0u8; 2];
            read_exact_ssl(&mut tls, &mut hdr);
            let len = usize::from(u16::from_be_bytes(hdr));
            let mut body = vec![0u8; len];
            read_exact_ssl(&mut tls, &mut body);
            // Send an inbound obf'd datagram, framed, and hold the conn open briefly.
            let deliver = yip_obf::obfuscate(&server_obf, yip_obf::RDV_TYPE, b"inbound-proof", 0);
            let mut framed = Vec::new();
            crate::tls::frame_datagram(&deliver, &mut framed).expect("frame");
            blocking_write_all_tls(&mut tls, &framed);
            std::thread::sleep(Duration::from_millis(300));
        });

        spawn_reality(
            "127.0.0.1".to_string(),
            addr.port(),
            [0u8; 32], // pbk: unused by a plain TLS server (zero-cert-auth handshake still completes)
            [0u8; 8],
            sni.to_string(),
            obf_key,
            self_node,
            relay_sock,
        );

        // The data-plane end must receive exactly the inbound datagram (deobf'd on
        // the data plane in production; here we just prove the framed bytes arrived
        // as one datagram).
        let mut buf = [0u8; TLS_FRAME_MAX];
        let n = data_plane_sock
            .recv(&mut buf)
            .expect("recv inbound within 5s");
        let got = yip_obf::deobfuscate(&obf_key, &buf[..n]);
        assert_eq!(got.map(|(_t, b)| b), Some(b"inbound-proof".to_vec()));
        server.join().expect("server thread");
    }
}
