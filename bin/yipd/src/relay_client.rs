//! The 3c.4 TLS relay-dial client: a dedicated thread holds one browser-parrot
//! TLS connection to the relay, sends the obfuscated monotonic `Register`
//! (first-on-connect + keepalive), and pipes obf-wrapped RelaySend/RelayDeliver
//! envelopes to/from the data plane over a UnixStream socketpair. No tokio; all
//! TLS via 3c.2's `crate::tls` client primitives.
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
//! "second watched fd"). Both directions carry already-obfuscated envelope
//! bytes verbatim — this module only re-frames them (`[u16 BE
//! len]`-prefixed, `crate::tls::frame_datagram`/`FrameReader`) between the
//! TLS byte-stream and the socketpair; it never touches obfuscation or the
//! rendezvous `Message` codec except to build `Register` itself.
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use boring::ssl::SslStream;

use yip_io::epoll::{read_fd, write_fd, Epoll};
use yip_io::poll::{Dispatch, DispatchOut, EgressDatagram};
use yip_rendezvous::{encode, Message, NodeId};

use crate::peer_manager::PeerManager;
use crate::tls::{
    connect_and_handshake, drain_tls_read, frame_datagram, write_all_tls, FrameReader,
    INITIAL_BACKOFF_MS, MAX_BACKOFF_MS, TLS_FRAME_MAX,
};

/// Register keepalive: re-send `Register` (counter bumped) at least this
/// often even with no data flowing, so the relay's freshness gate never
/// expires this connection out from under an idle tunnel.
const REG_KEEPALIVE_MS: u64 = 30_000;

/// Per-boot monotonic Register counter (starts at 1; the relay's freshness gate
/// requires strictly-greater).
#[derive(Default)]
pub(crate) struct Counter(u64);
impl Counter {
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
/// `UnixStream::pair()`, the other end wired to the data plane) and the TLS
/// connection to the relay at `host:port` (SNI = `sni`), and runs forever:
/// connect → handshake → **Register first** → pump → on any error, back off
/// and reconnect.
pub(crate) fn spawn(
    host: String,
    port: u16,
    sni: String,
    obf_key: [u8; 16],
    self_node: NodeId,
    sock: UnixStream,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || run(&host, port, &sni, &obf_key, self_node, sock))
}

/// The reconnect-with-backoff loop. Only returns if `sock` can no longer be
/// made non-blocking (an unrecoverable local setup failure) — otherwise runs
/// until the process exits.
fn run(host: &str, port: u16, sni: &str, obf_key: &[u8; 16], self_node: NodeId, sock: UnixStream) {
    if let Err(e) = sock.set_nonblocking(true) {
        eprintln!("relay_client: could not set socketpair non-blocking, thread exiting: {e}");
        return;
    }
    let sock_fd = sock.as_raw_fd();

    let mut counter = Counter::default();
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
            sock_fd,
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

/// Write a whole framed message to the socketpair, or fail. `sock` is a
/// `SOCK_STREAM` `UnixStream`, so a non-blocking `write()` can return a SHORT
/// COUNT (n < len) when the send buffer is partially full; silently
/// discarding the short count would truncate the `[u16 len]`-framed envelope
/// and permanently desync the receiver's `FrameReader`. A partial write
/// cannot be unwound, so on persistent backpressure this returns `Err` → the
/// caller tears the TLS connection down and reconnects (fresh `FrameReader`s
/// both sides).
fn write_all_socketpair(sock_fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut off = 0;
    let mut spins = 0u32;
    const MAX_SPINS: u32 = 10_000;
    while off < buf.len() {
        match write_fd(sock_fd, &buf[off..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socketpair write returned 0",
                ))
            }
            Ok(n) => {
                off += n;
                spins = 0;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                spins += 1;
                if spins > MAX_SPINS {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "socketpair backpressure: giving up frame",
                    ));
                }
                std::thread::yield_now();
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Drain every complete frame currently buffered in `sock_reader`, calling
/// `emit` on each datagram. Fails closed and symmetric with the TLS-read
/// side: `FrameReader::next` does NOT drain the bad bytes on a malformed
/// frame, so ignoring the error and continuing would leave the same error
/// recurring forever (a permanently wedged direction). Returning `Err`
/// instead propagates out of `pump`, tearing the connection down so the
/// caller reconnects with a fresh `FrameReader`.
///
/// Factored out of `pump`'s socketpair→TLS branch so the decode/fail-closed
/// logic is unit-testable without a live TLS connection.
fn drain_socketpair_frames(
    sock_reader: &mut FrameReader,
    mut emit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    loop {
        match sock_reader.next() {
            Ok(Some(dg)) => emit(&dg)?,
            Ok(None) => return Ok(()),
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

/// Drive one live TLS connection: pipe obf-wrapped envelope bytes verbatim
/// between the TLS stream and the socketpair, and re-send `Register` every
/// [`REG_KEEPALIVE_MS`]. Returns on any TLS/TCP/framing error (fail-closed;
/// the caller reconnects) or propagates a fatal `Epoll` error via `?`.
fn pump(
    stream: &mut SslStream<TcpStream>,
    poller: &Epoll,
    sock_fd: RawFd,
    obf_key: &[u8; 16],
    self_node: NodeId,
    counter: &mut Counter,
) -> io::Result<()> {
    let mut tls_reader = FrameReader::default();
    let mut sock_reader = FrameReader::default();
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

        // TLS-readable: drain plaintext, de-frame, pipe each frame — an obf'd
        // RelayDeliver envelope — to the socketpair, best-effort (a full
        // socketpair buffer just drops the frame; this transport is already
        // best-effort UDP-equivalent, never a reliability layer).
        if ready.udp {
            drain_tls_read(stream, &mut tls_reader, &mut tls_read_buf)?;
            loop {
                match tls_reader.next() {
                    Ok(Some(dg)) => {
                        reframe_buf.clear();
                        frame_datagram(&dg, &mut reframe_buf)?;
                        write_all_socketpair(sock_fd, &reframe_buf)?;
                    }
                    Ok(None) => break,
                    Err(e) => return Err(e),
                }
            }
        }

        // Socketpair-readable: read the data plane's already-obf'd
        // `RelaySend` envelopes (framed the same `[u16 len]` way) and write
        // each one, re-framed, to the TLS stream.
        if ready.tun {
            loop {
                match read_fd(sock_fd, &mut sock_read_buf) {
                    Ok(0) => break,
                    Ok(n) => sock_reader.push(&sock_read_buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        eprintln!("relay_client: socketpair read error: {e}");
                        break;
                    }
                }
            }
            drain_socketpair_frames(&mut sock_reader, |dg| {
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

/// Frame each of `egress`'s datagrams (`[u16 BE len]`-prefixed, mirroring the
/// TLS-side framing) and write it to the socketpair via
/// [`write_all_socketpair`] — the SAME fail-closed framed write the relay
/// thread's own [`pump`] uses on its socketpair-read side, so persistent
/// backpressure surfaces as an `Err` here too rather than silently wedging.
/// `e.dst` is ignored: every egress datagram on this path is relay-destined,
/// so there is exactly one place to send it — the relay thread on the other
/// end of the socketpair.
fn send_egress_to_relay_thread(
    sock_fd: RawFd,
    egress: &[EgressDatagram],
    frame_buf: &mut Vec<u8>,
) -> io::Result<()> {
    for d in egress {
        frame_buf.clear();
        frame_datagram(&d.bytes, frame_buf)?;
        write_all_socketpair(sock_fd, frame_buf)?;
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
/// rendezvous-facing datagram against `relay_addr`. Everything read off `sock`
/// is an obf'd `RelayDeliver` envelope the relay thread already validated
/// on-wire (it terminates the real TLS connection); a malformed *frame*
/// (bad `[u16 len]` prefix) at this layer is nonetheless treated as fatal —
/// this loop does not itself reconnect (the relay thread already owns
/// reconnect-with-backoff for the TLS leg), so there is nothing safe to do but
/// tear down and let the caller (`tunnel::run`) propagate the fatal error.
///
/// Only returns on a fatal I/O error (an `Epoll`/socketpair/TUN failure, or a
/// malformed inbound frame).
pub(crate) fn run_relay_tls(
    tun_fd: RawFd,
    manager: &mut PeerManager,
    relay_addr: SocketAddr,
    sock: UnixStream,
) -> io::Result<()> {
    sock.set_nonblocking(true)?;
    let sock_fd = sock.as_raw_fd();
    let poller = Epoll::new(sock_fd, tun_fd)?;

    let mut reader = FrameReader::default();
    let mut sock_read_buf = [0u8; TLS_FRAME_MAX];
    let mut tun_read_buf = [0u8; TLS_FRAME_MAX];
    let mut frame_buf: Vec<u8> = Vec::new();
    let start = Instant::now();

    loop {
        let ready = poller.wait(TICK_MS)?;
        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // 1. Socketpair-readable: inbound obf'd RelayDeliver envelopes from
        //    the relay thread → de-frame → `PeerManager::on_udp`.
        if ready.udp {
            loop {
                match read_fd(sock_fd, &mut sock_read_buf) {
                    Ok(0) => break,
                    Ok(n) => reader.push(&sock_read_buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            loop {
                match reader.next() {
                    Ok(Some(env)) => {
                        let (tun, egress) = owned_out(manager.on_udp(relay_addr, &env, now_ms));
                        if let Some(inner) = tun {
                            write_tun(tun_fd, &inner);
                        }
                        send_egress_to_relay_thread(sock_fd, &egress, &mut frame_buf)?;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("relay_tls: malformed inbound frame, tearing down: {e}");
                        return Err(e);
                    }
                }
            }
        }

        // 2. TUN-readable: `PeerManager::on_tun` → relay-bound egress.
        if ready.tun {
            loop {
                match read_fd(tun_fd, &mut tun_read_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let egress = manager.on_tun(&tun_read_buf[..n], now_ms).to_vec();
                        send_egress_to_relay_thread(sock_fd, &egress, &mut frame_buf)?;
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
            send_egress_to_relay_thread(sock_fd, &egress, &mut frame_buf)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
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

    #[test]
    fn counter_is_monotonic_from_one() {
        let mut c = Counter::default();
        assert_eq!(c.next(), 1);
        assert_eq!(c.next(), 2);
        assert_eq!(c.next(), 3);
    }

    /// `FrameReader::next` rejects a zero length prefix as a malformed frame,
    /// and — critically — does NOT drain the offending bytes, so the same
    /// error would recur forever if the caller just logged and kept polling.
    /// `drain_socketpair_frames` (factored out of `pump`'s socketpair→TLS
    /// branch) must fail closed here: return `Err` rather than swallow it, so
    /// `pump` tears the connection down and the caller reconnects with a
    /// fresh `FrameReader` on both sides. This is the socketpair-side
    /// sibling of the TLS-read side, which already failed closed on a
    /// malformed frame before this fix.
    #[test]
    fn malformed_socketpair_frame_tears_down() {
        let mut reader = FrameReader::default();
        // A `[u16 len]` header of 0 is rejected by `FrameReader::next` as a
        // bad frame length (zero-length frames are invalid).
        reader.push(&[0x00, 0x00]);

        let mut emitted = Vec::new();
        let result = drain_socketpair_frames(&mut reader, |dg| {
            emitted.push(dg.to_vec());
            Ok(())
        });

        assert!(
            result.is_err(),
            "a malformed frame must tear the pump down (Err), not be silently dropped"
        );
        assert!(
            emitted.is_empty(),
            "no frame should have been emitted before the malformed one was hit"
        );
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
    /// obf'd `RelayDeliver` frame from the TLS stream through, verbatim,
    /// to the data-plane side of the socketpair.
    ///
    /// Bounded so a hang fails loudly rather than blocking `cargo test`
    /// forever: the socketpair read on the data-plane end carries a 5 s
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
            // — that is the whole point of the Register-first invariant.
            let mut reader = FrameReader::default();
            let env = blocking_read_one_tls(&mut stream, &mut reader);
            let (ptype, body) =
                yip_obf::deobfuscate(&obf_key, &env).expect("deobfuscate register envelope");
            assert_eq!(ptype, yip_obf::RDV_TYPE);
            assert_eq!(
                yip_rendezvous::decode(&body),
                Some(yip_rendezvous::Message::Register {
                    node: self_node,
                    counter: 1,
                }),
                "first frame from the client must be a fresh Register(counter=1)"
            );

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

        let (test_end, client_sock) = UnixStream::pair().expect("socketpair");
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

        // Read the framed RelayDeliver piped through to the data-plane side
        // of the socketpair, bounded by test_end's 5 s read_timeout.
        let mut reader = FrameReader::default();
        let mut chunk = [0u8; 4096];
        let dg = loop {
            if let Some(dg) = reader.next().expect("well-formed frame from relay_client") {
                break dg;
            }
            let n = (&test_end)
                .read(&mut chunk)
                .expect("read from data-plane end of the socketpair");
            assert!(n > 0, "socketpair closed before a full frame arrived");
            reader.push(&chunk[..n]);
        };

        let (ptype, body) =
            yip_obf::deobfuscate(&obf_key, &dg).expect("deobfuscate relay-deliver envelope");
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
}
