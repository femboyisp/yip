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
use std::net::{ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
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
    //
    // `Rendezvous::Tls { host, port }` (3c.4, rendezvous=tls://) resolves
    // `host:port` to a routing-key `SocketAddr` up front and builds
    // `TlsRelayRendezvous` against it; `relay_tls` carries `(host, port,
    // relay_addr)` forward to the transport dispatch below, which uses it to
    // spawn `relay_client::spawn` and enter `relay_client::run_relay_tls`
    // instead of a UDP-socket driver.
    let mut relay_tls: Option<(String, u16, std::net::SocketAddr)> = None;
    let rendezvous: Option<Box<dyn crate::rendezvous::Rendezvous>> = match &config.rendezvous {
        None => None,
        Some(crate::config::Rendezvous::Udp(addr)) => Some(Box::new(
            crate::rendezvous::ConfiguredServerRendezvous::new(*addr),
        )
            as Box<dyn crate::rendezvous::Rendezvous>),
        Some(crate::config::Rendezvous::Tls { host, port }) => {
            let relay_addr = (host.as_str(), *port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("rendezvous relay {host}:{port} resolved to no addresses"),
                    )
                })?;
            relay_tls = Some((host.clone(), *port, relay_addr));
            Some(
                Box::new(crate::rendezvous::TlsRelayRendezvous::new(relay_addr))
                    as Box<dyn crate::rendezvous::Rendezvous>,
            )
        }
    };
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
    // `relay_only` (rendezvous=tls://, 3c.4) starts every peer straight in
    // Relaying and skips Direct/UDP-punch, since UDP is blocked on that path.
    let relay_only = relay_tls.is_some();
    let mut manager = PeerManager::new(
        config.local_private,
        config.local_public,
        &config.peers,
        mode,
        rendezvous,
        membership,
        relay_only,
    );
    // Enable anti-DPI obfuscation (3a) when the network `obf_psk` is configured.
    // `None` leaves the manager on the byte-identical 2a/2b/2c plaintext path.
    manager.set_obf_psk(config.obf_psk);
    // Opt-in idle cover traffic (3b Task 4): a no-op unless obf is also on
    // (`PeerManager::tick_dispatch` gates cover emission on both).
    manager.set_cover_traffic_ms(config.cover_traffic_ms);
    let local_addr = manager.local_addr();

    // ── create the tunnel device (TUN or TAP) ────────────────────────────────
    // The driver decision is made *before* opening the device: the poll
    // driver wants IFF_VNET_HDR + kernel GSO/GRO offload on the TUN fd (Task
    // 5); the uring driver (and the poll fallback inside it), and QUIC-mimicry
    // mode (whose `run_quic` pump has no vnet_hdr framing support), always
    // want a plain fd. `TunTap::create` degrades `want_vnet_hdr` gracefully —
    // if the kernel/driver doesn't support it, `tun.vnet_hdr_len()` comes
    // back `None` and `run_poll` below runs the byte-identical plain path.
    let device_kind = match mode {
        TunnelMode::L3Tun => DeviceKind::Tun,
        TunnelMode::L2Tap => DeviceKind::Tap,
    };
    let use_uring = std::env::var_os("YIP_USE_URING").is_some() && yip_io::uring::uring_available();
    let want_vnet_hdr = !use_uring && config.transport != crate::config::TransportMode::Quic;
    let tun =
        TunTap::create(&config.device, device_kind, want_vnet_hdr).map_err(io::Error::other)?;

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
    //
    // QUIC-mimicry mode (`transport=quic`, 3c.1): drive the dedicated
    // `run_quic` pump, which carries yip's UNCHANGED inner protocol inside QUIC
    // DATAGRAM frames. It takes ownership of `sock` (recvfrom/sendto) and the
    // raw `tun_fd`; the connection role for each peer is decided by static-key
    // order inside `run_quic`. QUIC provides its own wire obfuscation, so
    // `obf_psk`/`cover_traffic_ms` are rejected alongside it at config-parse.
    if config.transport == crate::config::TransportMode::Quic {
        let quic_peers: Vec<([u8; 32], std::net::SocketAddr)> = config
            .peers
            .iter()
            .filter_map(|p| p.endpoint.map(|ep| (p.public_key, ep)))
            .collect();
        return crate::quic::run_quic(sock, tun_fd, &mut manager, config.local_public, &quic_peers);
    }

    // TLS-mimicry mode (`transport=tls`, 3c.2): drive the dedicated `run_tls`
    // pump, which carries yip's UNCHANGED inner protocol length-prefixed over
    // a BoringSSL TLS-over-TCP byte-stream. It opens its own TCP socket(s)
    // (client-dials or server-`accept`s per `connection_role`) and the raw
    // `tun_fd`; `sock` (the UDP socket bound above) goes unused on this path,
    // same as the QUIC path above.
    if config.transport == crate::config::TransportMode::Tls {
        let tls_peers: Vec<([u8; 32], std::net::SocketAddr)> = config
            .peers
            .iter()
            .filter_map(|p| p.endpoint.map(|ep| (p.public_key, ep)))
            .collect();
        return crate::tls::run_tls(
            tun_fd,
            &mut manager,
            config.local_public,
            &tls_peers,
            config.listen,
            &config.tls_sni,
        );
    }

    // TLS relay-dial (`rendezvous=tls://`, 3c.4): straight-to-relay, no
    // Direct/UDP-punch (`relay_only` above already put `manager` in that
    // mode). A dedicated thread (`relay_client::spawn`) owns the one
    // browser-parrot TLS connection to the relay and speaks obf'd
    // Register/RelaySend/RelayDeliver envelopes over it; this thread and
    // `run_relay_tls` communicate over a `SOCK_DGRAM` `UnixDatagram::pair()`
    // socketpair — one `send` is one already-obf'd envelope and one `recv`
    // reproduces it whole (datagram boundaries, not `crate::tls`'s `[u16 BE
    // len]` stream framing, which only the TLS byte-stream leg still needs).
    // This is deliberate (3c.4 final review): a `SOCK_STREAM` socketpair
    // cannot atomically drop a message under backpressure, so it either
    // blocked the data-plane thread or killed the whole process on a full
    // buffer; `SOCK_DGRAM`'s atomic `send` lets backpressure be handled the
    // same best-effort way as a dropped UDP packet — see
    // `relay_client::send_socketpair`. `sock` (the UDP socket bound above)
    // goes unused on this path, same as the QUIC/TLS paths above — UDP is
    // exactly what this path exists to avoid. The poll driver is forced (not
    // `YIP_USE_URING`-gated): `run_relay_tls` is a dedicated `Epoll`-based
    // pump, structurally the same class of loop as `run_quic`/`run_tls`, not
    // `yip_io::uring`/`yip_io::poll::run_poll`.
    if let Some((host, port, relay_addr)) = relay_tls {
        let obf_key = yip_obf::derive_key(
            config
                .obf_psk
                .as_ref()
                .expect("rendezvous=tls:// requires obf_psk (enforced at config load)"),
        );
        let self_node = yip_rendezvous::node_id(&config.local_public);
        let (relay_thread_sock, data_plane_sock) = UnixDatagram::pair()?;
        let sni = host.clone();
        crate::relay_client::spawn(host, port, sni, obf_key, self_node, relay_thread_sock);
        return crate::relay_client::run_relay_tls(
            tun_fd,
            &mut manager,
            relay_addr,
            data_plane_sock,
        );
    }

    // Raw-UDP mode. Default to the epoll `PollDriver`: on measurement it is the
    // faster path (lower tunnel RTT — the north-star metric) and is safe Rust.
    // The `UringDriver` currently regresses RTT with no throughput upside and is
    // the workspace's only `unsafe`, so it is opt-in via `YIP_USE_URING=1` for
    // A/B work until it beats epoll (SQPOLL / working GSO batching) and
    // re-benchmarks favourably. See crates/yip-bench/README.md "io_uring Phase B".
    if use_uring {
        yip_io::uring::run_uring(udp_fd, tun_fd, &mut manager)
    } else {
        yip_io::poll::run_poll(udp_fd, tun_fd, tun.vnet_hdr_len().is_some(), &mut manager)
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
