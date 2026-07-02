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

// ── public entry point ────────────────────────────────────────────────────────

/// Run the tunnel: bind, handshake, create TUN, then loop forever via the
/// selected I/O driver.
///
/// Only returns on a fatal I/O error.
pub fn run(config: Config) -> io::Result<()> {
    // ── bind the UDP socket ───────────────────────────────────────────────────
    let sock = UdpSocket::bind(config.listen)?;

    // ── handshake ─────────────────────────────────────────────────────────────
    let (established, peer_addr) = if config.initiate {
        let est = handshake::run_initiator(
            &sock,
            config.peer_endpoint,
            &config.local_private,
            &config.peer_public,
        )?;
        (est, config.peer_endpoint)
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

    // ── create the TUN device ─────────────────────────────────────────────────
    let tun = TunTap::create(&config.device, DeviceKind::Tun).map_err(io::Error::other)?;

    // Set TUN non-blocking before entering the epoll loop.  run_poll also
    // calls fcntl internally (belt-and-suspenders; idempotent).
    tun.set_nonblocking().map_err(io::Error::other)?;
    let tun_fd = tun.as_raw_fd();

    // ── set UDP non-blocking ──────────────────────────────────────────────────
    sock.set_nonblocking(true)?;
    let udp_fd = sock.as_raw_fd();

    // ── build DataPlane ───────────────────────────────────────────────────────
    let mut dataplane = DataPlane::new(established, conn_tag);

    // ── run the selected event loop ───────────────────────────────────────────
    // `tun` and `sock` are kept alive on the stack here, so `tun_fd` and
    // `udp_fd` remain valid for the duration of the selected driver loop.
    if std::env::var("YIP_FORCE_POLL").is_ok() {
        yip_io::poll::run_poll(udp_fd, tun_fd, &mut dataplane)
    } else if yip_io::uring_available() {
        yip_io::run_uring(udp_fd, tun_fd, &mut dataplane)
    } else {
        yip_io::poll::run_poll(udp_fd, tun_fd, &mut dataplane)
    }
}
