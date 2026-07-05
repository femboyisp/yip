//! The yipd tunnel: binds a UDP socket, runs the Noise-IK handshake, creates
//! the TUN device, then drives the data loop via a single-threaded epoll
//! `PollDriver` backed by [`DataPlane`].
//!
//! # Architecture (Task 3)
//!
//! The two-thread `Arc<Mutex<...>>` model has been retired.  [`DataPlane`]
//! implements [`yip_io::poll::Dispatch`] and is driven by
//! [`yip_io::poll::run_poll`], which multiplexes UDP and TUN I/O via `epoll`
//! from a single OS thread.  There are no locks, no channels, and no heap
//! allocation per packet beyond what `DataPlane` already preallocates.
//!
//! # conn_tag
//!
//! Each wire frame carries an 8-byte `conn_tag` that the receiver uses to
//! select the right session / decoder. We derive it from `auth_key || hp_key`
//! (both computed identically by both peers from the Noise channel binding).
//! M7+ will rotate the tag every epoch for unlinkability.
//!
//! # Feedback loop
//!
//! The loss-feedback Control packet and ARQ retransmit logic live entirely
//! inside [`DataPlane::tick`] and [`DataPlane::on_udp_datagram`]; the epoll
//! loop calls `tick` at least every 10 ms, which is within the 30 ms feedback
//! interval.

use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use yip_device::{DeviceKind, TunTap};
use yip_io::set_socket_buffers;

use crate::config::Config;
use crate::dataplane::{conn_tag_from_keys, DataPlane};
use crate::handshake;
use crate::mode::TunnelMode;

// ── public entry point ────────────────────────────────────────────────────────

/// Run the tunnel: bind, handshake, create TUN, then loop forever via the
/// selected I/O driver.
///
/// Only returns on a fatal I/O error.
pub fn run(config: Config) -> io::Result<()> {
    // ── bind the UDP socket ───────────────────────────────────────────────────
    let sock = UdpSocket::bind(config.listen)?;

    // ── handshake ─────────────────────────────────────────────────────────────
    let (established, peer_addr) = if false {
        let est = handshake::run_initiator(
            &sock,
            config.peers[0].endpoint,
            &config.local_private,
            &config.peers[0].public_key,
        )?;
        (est, config.peers[0].endpoint)
    } else {
        let (est, addr) = handshake::run_responder(&sock, &config.local_private)?;
        (est, addr)
    };

    // Connect so plain send/recv work without carrying the peer address.
    sock.connect(peer_addr)?;

    // Raise kernel socket buffers to 4 MiB so bursts do not overflow the
    // OS receive ring.
    set_socket_buffers(&sock, 4 * 1024 * 1024)?;

    // ── derive conn_tag ───────────────────────────────────────────────────────
    // Both peers compute the same auth_key and hp_key from the Noise channel
    // binding, so they derive the same conn_tag without extra signaling.
    let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);

    // ── create the tunnel device (TUN or TAP) ────────────────────────────────
    let mode = config.device_kind;
    let device_kind = match mode {
        TunnelMode::L3Tun => DeviceKind::Tun,
        TunnelMode::L2Tap => DeviceKind::Tap,
    };
    let tun = TunTap::create(&config.device, device_kind).map_err(io::Error::other)?;

    // Set TUN non-blocking before entering the epoll loop.  run_poll also
    // calls fcntl internally (belt-and-suspenders; idempotent).
    tun.set_nonblocking().map_err(io::Error::other)?;
    let tun_fd = tun.as_raw_fd();

    // ── set UDP non-blocking ──────────────────────────────────────────────────
    sock.set_nonblocking(true)?;
    let udp_fd = sock.as_raw_fd();

    // ── build DataPlane ───────────────────────────────────────────────────────
    let mut dataplane = DataPlane::new(established, conn_tag, mode);

    // ── run the selected event loop ───────────────────────────────────────────
    // `tun` and `sock` are kept alive on the stack here, so `tun_fd` and
    // `udp_fd` remain valid for the duration of the selected driver loop.
    // Default to the epoll `PollDriver`: on measurement it is the faster path
    // (lower tunnel RTT — the north-star metric) and is safe Rust. The
    // `UringDriver` currently regresses RTT with no throughput upside and is the
    // workspace's only `unsafe`, so it is opt-in via `YIP_USE_URING=1` for A/B
    // work until it beats epoll (SQPOLL / working GSO batching) and re-benchmarks
    // favourably. See crates/yip-bench/README.md "io_uring Phase B — driver A/B".
    if std::env::var_os("YIP_USE_URING").is_some() && yip_io::uring::uring_available() {
        yip_io::uring::run_uring(udp_fd, tun_fd, &mut dataplane)
    } else {
        yip_io::poll::run_poll(udp_fd, tun_fd, &mut dataplane)
    }
}
