//! The yipd tunnel: binds a UDP socket, creates the TUN/TAP device, then
//! drives the data loop via a single-threaded epoll `PollDriver` (or
//! `UringDriver`) backed by [`PeerManager`].
//!
//! # Architecture (Task 5)
//!
//! There is no pre-loop blocking handshake and no `sock.connect` — every
//! peer starts `Idle` and [`PeerManager`] brings it up lazily, in-loop, the
//! first time a TUN packet needs to reach it (or an incoming
//! `HandshakeInit` arrives first). See `peer_manager.rs`'s module doc for
//! the full routing/handshake design. [`PeerManager`] implements
//! [`yip_io::poll::Dispatch`] and is driven by [`yip_io::poll::run_poll`],
//! which multiplexes UDP and TUN I/O via `epoll` from a single OS thread —
//! there are no locks, no channels, and no per-packet heap allocation beyond
//! what each peer's `DataPlane` already preallocates.
//!
//! # conn_tag
//!
//! Each wire frame carries an 8-byte `conn_tag` that the receiver uses to
//! select the right session / decoder. Both peers derive it identically
//! from `auth_key || hp_key` (computed from the Noise channel binding) once
//! their handshake completes — see `dataplane::conn_tag_from_keys`. M7+ will
//! rotate the tag every epoch for unlinkability.
//!
//! # Feedback loop
//!
//! The loss-feedback Control packet and ARQ retransmit logic live entirely
//! inside each peer's `DataPlane::tick` and `DataPlane::on_udp_datagram`;
//! the epoll loop calls `tick` at least every 10 ms, which is within the
//! 30 ms feedback interval.

use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::process::Command;

use yip_device::{DeviceKind, TunTap};
use yip_io::set_socket_buffers;

use crate::addr::MESH_PREFIX_LEN;
use crate::config::Config;
use crate::mode::TunnelMode;
use crate::peer_manager::PeerManager;

// ── public entry point ────────────────────────────────────────────────────────

/// Run the tunnel: bind, create TUN/TAP, then loop forever via the selected
/// I/O driver, handshaking lazily in-loop as [`PeerManager`] needs to.
///
/// Only returns on a fatal I/O error.
pub fn run(config: Config) -> io::Result<()> {
    // ── bind the UDP socket ───────────────────────────────────────────────────
    // Unconnected (the addressed socket seam, #33): drivers use
    // recvfrom/sendto (poll.rs) or recvmsg/sendmsg (uring.rs) and carry the
    // peer address on every datagram; `PeerManager` routes by that address
    // (and, once established, by the per-peer `DataPlane`'s own stamped
    // `dst`) instead of relying on a fixed connected peer.
    let sock = UdpSocket::bind(config.listen)?;

    // Raise kernel socket buffers to 4 MiB so bursts do not overflow the
    // OS receive ring.
    set_socket_buffers(&sock, 4 * 1024 * 1024)?;

    // ── build the peer manager ────────────────────────────────────────────────
    let mode = config.device_kind;
    // A configured rendezvous server enables lazy Direct→Punch→Relay peer
    // bring-up; with none, `PeerManager` is pure-2a (direct endpoints only).
    let rendezvous: Option<Box<dyn crate::rendezvous::Rendezvous>> =
        config.rendezvous.map(|addr| {
            Box::new(crate::rendezvous::ConfiguredServerRendezvous::new(addr))
                as Box<dyn crate::rendezvous::Rendezvous>
        });
    // Build the mesh membership directory (2c) only when the full mesh config is
    // present (a trusted CA set, our cert, the signed root set, our record-
    // signing key, and the network id). Absent any of these, membership is
    // `None` and `PeerManager` is pure-2a/2b. `own_endpoints` seeds our own
    // gossip record with our bind address.
    let membership = match (
        &config.cert,
        &config.roots,
        config.member_sign_private,
        config.network_id,
    ) {
        (Some(cert), Some(roots), Some(sign_priv), Some(network_id))
            if !config.ca_public.is_empty() =>
        {
            Some(crate::membership::Membership::new(
                config.ca_public.clone(),
                network_id,
                cert.clone(),
                sign_priv,
                roots.clone(),
                vec![config.listen],
            ))
        }
        _ => None,
    };
    let mut manager = PeerManager::new(
        config.local_private,
        config.local_public,
        &config.peers,
        mode,
        rendezvous,
        membership,
    );
    // Enable anti-DPI obfuscation (3a) when the network `obf_psk` is configured.
    // `None` leaves the manager on the byte-identical 2a/2b/2c plaintext path.
    manager.set_obf_psk(config.obf_psk);
    let local_addr = manager.local_addr();

    // ── create the tunnel device (TUN or TAP) ────────────────────────────────
    let device_kind = match mode {
        TunnelMode::L3Tun => DeviceKind::Tun,
        TunnelMode::L2Tap => DeviceKind::Tap,
    };
    let tun = TunTap::create(&config.device, device_kind).map_err(io::Error::other)?;

    // Assign this node's self-certifying mesh address and route the mesh
    // prefix over the device. Best-effort: shelling out to `ip` (no unsafe,
    // no netlink code in this `forbid(unsafe_code)` binary) keeps this
    // simple, and a failure here (e.g. the address already present from a
    // prior run, or `ip` unavailable in some minimal test environment) must
    // not take down the tunnel — existing single-peer netns tests assign
    // their own (plain IPv4) tunnel addresses independently of this and do
    // not depend on it succeeding.
    assign_mesh_address(&config.device, local_addr);

    // Set TUN non-blocking before entering the epoll loop.  run_poll also
    // calls fcntl internally (belt-and-suspenders; idempotent).
    tun.set_nonblocking().map_err(io::Error::other)?;
    let tun_fd = tun.as_raw_fd();

    // ── set UDP non-blocking ──────────────────────────────────────────────────
    sock.set_nonblocking(true)?;
    let udp_fd = sock.as_raw_fd();

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
        yip_io::uring::run_uring(udp_fd, tun_fd, &mut manager)
    } else {
        yip_io::poll::run_poll(udp_fd, tun_fd, &mut manager)
    }
}

/// Best-effort: assign `local_addr/128` to `device` and route the mesh
/// prefix (`fd00::/8`) over it, via the `ip` CLI. Errors (including `ip`
/// being absent) are logged and swallowed — this is additive to whatever
/// addressing a test harness assigns itself, never required for the tunnel
/// to function in single-peer 2a scope.
fn assign_mesh_address(device: &str, local_addr: std::net::Ipv6Addr) {
    let addr_arg = format!("{local_addr}/128");
    match Command::new("ip")
        .args(["-6", "addr", "add", &addr_arg, "dev", device])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("yipd: `ip -6 addr add {addr_arg} dev {device}` exited {s}"),
        Err(e) => eprintln!("yipd: could not run ip to assign mesh address {addr_arg}: {e}"),
    }
    let prefix_arg = format!("fd00::/{MESH_PREFIX_LEN}");
    match Command::new("ip")
        .args(["-6", "route", "add", &prefix_arg, "dev", device])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("yipd: `ip -6 route add {prefix_arg} dev {device}` exited {s}"),
        Err(e) => eprintln!("yipd: could not run ip to add mesh route {prefix_arg}: {e}"),
    }
}
