//! Deterministic peer-to-shard mapping and consistent address hashing.
//!
//! In multi-core throughput sharding (Way A), each peer session is pinned to an
//! exclusive worker shard. To avoid cross-shard hops on the outbound path
//! whenever possible, inner TUN packet destination IPv6 addresses are mapped to
//! shards using the exact same hash as peer public keys.
//!
//! Because yip node addresses in `fd00::/8` are self-certifying addresses
//! generated via `crate::addr::node_addr(pubkey)`, hashing address octets `[1..9]`
//! yields the exact same shard as the peer's public key.

use std::net::Ipv6Addr;

/// Map an IPv6 address to a shard index deterministically in `0..num_shards`.
///
/// For mesh addresses in `fd00::/8` (where octet 0 is `0xfd`), octets `[1..9]`
/// (the first 8 bytes of the BLAKE2s identity digest) are converted to a 64-bit integer
/// and modulo-divided by `num_shards`.
///
/// For non-mesh IPv6 addresses (e.g., link-local, loopback, or global unicast),
/// the remaining host octets `[8..16]` are hashed to avoid panics and distribute
/// non-mesh traffic across shards.
///
/// Returns `0` if `num_shards <= 1`.
pub fn shard_for_addr(addr: Ipv6Addr, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let octets = addr.octets();
    let hash = if octets[0] == 0xfd {
        u64::from_be_bytes(octets[1..9].try_into().expect("slice has length 8"))
    } else {
        u64::from_be_bytes(octets[8..16].try_into().expect("slice has length 8"))
    };
    (hash % num_shards as u64) as usize
}

/// Map a peer's X25519 public key to its home shard index in `0..num_shards`.
///
/// This evaluates to `shard_for_addr(crate::addr::node_addr(pubkey), num_shards)`,
/// guaranteeing that outbound packets routed by destination IP match the owning
/// peer's shard.
///
/// Returns `0` if `num_shards <= 1`.
pub fn shard_for_pubkey(pubkey: &[u8; 32], num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    shard_for_addr(crate::addr::node_addr(pubkey), num_shards)
}

use std::io;
use std::net::ToSocketAddrs;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use yip_io::poll::Dispatch;

use crate::config::Config;

/// An outbound inner packet transferred across worker shards via SPSC ring buffers.
#[derive(Debug, Clone)]
pub struct OutboundPacket {
    pub bytes: Vec<u8>,
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signal all worker shard loops to stop gracefully.
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Reset the shutdown state (for test cleanup).
pub fn reset_shutdown() {
    SHUTDOWN.store(false, Ordering::Relaxed);
}

fn owned_out(
    out: yip_io::poll::DispatchOut<'_>,
) -> (Option<Vec<u8>>, Vec<yip_io::poll::EgressDatagram>) {
    match out {
        yip_io::poll::DispatchOut::None => (None, Vec::new()),
        yip_io::poll::DispatchOut::Tun(inner) => (Some(inner.to_vec()), Vec::new()),
        yip_io::poll::DispatchOut::Udp(dgs) => (None, dgs.to_vec()),
        yip_io::poll::DispatchOut::Both(inner, dgs) => (Some(inner.to_vec()), dgs.to_vec()),
    }
}

fn write_tun(tun_fd: std::os::fd::RawFd, inner: &[u8], vnet_hdr: bool) {
    if vnet_hdr {
        if inner.len() <= yip_io::MAX_WIRE_DATAGRAM {
            let mut buf = [0u8; yip_device::VNET_HDR_LEN + yip_io::MAX_WIRE_DATAGRAM];
            let end = yip_device::VNET_HDR_LEN + inner.len();
            buf[yip_device::VNET_HDR_LEN..end].copy_from_slice(inner);
            if let Err(e) = yip_io::epoll::write_fd(tun_fd, &buf[..end]) {
                eprintln!("sharded: tun write error: {e}");
            }
        } else {
            let mut buf = Vec::with_capacity(yip_device::VNET_HDR_LEN + inner.len());
            buf.extend_from_slice(&[0u8; yip_device::VNET_HDR_LEN]);
            buf.extend_from_slice(inner);
            if let Err(e) = yip_io::epoll::write_fd(tun_fd, &buf) {
                eprintln!("sharded: tun write error: {e}");
            }
        }
    } else if let Err(e) = yip_io::epoll::write_fd(tun_fd, inner) {
        eprintln!("sharded: tun write error: {e}");
    }
}

fn dst_for_packet(pkt: &[u8], is_tap: bool) -> Option<Ipv6Addr> {
    let ip_data = if is_tap {
        if pkt.len() >= 14 && pkt[12] == 0x86 && pkt[13] == 0xdd {
            &pkt[14..]
        } else {
            return None;
        }
    } else {
        pkt
    };

    if ip_data.len() >= 40 && (ip_data[0] >> 4) == 6 {
        let octets: [u8; 16] = ip_data[24..40].try_into().ok()?;
        Some(Ipv6Addr::from(octets))
    } else if ip_data.len() >= 20 && (ip_data[0] >> 4) == 4 {
        let octets: [u8; 4] = ip_data[16..20].try_into().ok()?;
        Some(std::net::Ipv4Addr::from(octets).to_ipv6_mapped())
    } else {
        None
    }
}

fn create_peer_manager(
    config: &Config,
    peers: &[crate::config::PeerConfig],
) -> io::Result<crate::peer_manager::PeerManager> {
    let rendezvous: Option<Box<dyn crate::rendezvous::Rendezvous>> = match &config.rendezvous {
        None => None,
        Some(crate::config::Rendezvous::Udp(addr)) => Some(Box::new(
            crate::rendezvous::ConfiguredServerRendezvous::new(*addr),
        )),
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
            Some(Box::new(crate::rendezvous::TlsRelayRendezvous::new(
                relay_addr,
            )))
        }
        Some(crate::config::Rendezvous::Reality { host, port, .. }) => {
            let relay_addr = (host.as_str(), *port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("rendezvous relay {host}:{port} resolved to no addresses"),
                    )
                })?;
            Some(Box::new(crate::rendezvous::TlsRelayRendezvous::new(
                relay_addr,
            )))
        }
    };

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

    let relay_only = matches!(
        config.rendezvous,
        Some(crate::config::Rendezvous::Tls { .. } | crate::config::Rendezvous::Reality { .. })
    );

    let mut manager = crate::peer_manager::PeerManager::new(
        config.local_private,
        config.local_public,
        peers,
        config.device_kind,
        rendezvous,
        membership,
        relay_only,
    );
    manager.set_obf_psk(config.obf_psk);
    manager.set_cover_traffic_ms(config.cover_traffic_ms);
    Ok(manager)
}

/// Run the sharded multi-core tunnel event loop across `num_shards` worker threads.
///
/// Allocates a multi-queue TUN/TAP device, binds `num_shards` `SO_REUSEPORT` UDP sockets,
/// sets up an N x (N - 1) SPSC ring buffer matrix for lock-free cross-shard routing,
/// partitions configured peers across shards, and spawns `num_shards` core-pinned threads.
pub fn run_sharded(config: Config, num_shards: usize) -> io::Result<()> {
    if num_shards == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "num_shards must be at least 1",
        ));
    }

    if config.transport != crate::config::TransportMode::RawUdp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sharded multi-core mode currently only supports raw UDP transport",
        ));
    }

    let mode = config.device_kind;
    let device_kind = match mode {
        crate::mode::TunnelMode::L3Tun => yip_device::DeviceKind::Tun,
        crate::mode::TunnelMode::L2Tap => yip_device::DeviceKind::Tap,
    };
    let use_uring = std::env::var_os("YIP_USE_URING").is_some() && yip_io::uring::uring_available();
    let want_vnet_hdr = !use_uring;

    let mut tun_queues = yip_device::TunTap::create_multi_queue(
        &config.device,
        device_kind,
        num_shards,
        want_vnet_hdr,
    )
    .map_err(io::Error::other)?;

    let local_addr = crate::addr::node_addr(&config.local_public);
    crate::tunnel::assign_mesh_address(&config.device, local_addr);

    let mut sockets =
        crate::port::bind_udp_reuseport(config.listen, config.listen_port_auto, num_shards)?;

    // Set up N x (N - 1) SPSC ring buffer matrix
    let mut tx_matrix: Vec<Vec<Option<yip_io::spsc::SpscProducer<OutboundPacket, 2048>>>> = (0
        ..num_shards)
        .map(|_| (0..num_shards).map(|_| None).collect())
        .collect();
    let mut rx_matrix: Vec<Vec<yip_io::spsc::SpscConsumer<OutboundPacket, 2048>>> = (0..num_shards)
        .map(|_| Vec::with_capacity(num_shards.saturating_sub(1)))
        .collect();

    for (i, row) in tx_matrix.iter_mut().enumerate() {
        for k in 0..num_shards {
            if i != k {
                let (tx, rx) = yip_io::spsc::spsc_pair::<OutboundPacket, 2048>();
                row[k] = Some(tx);
                rx_matrix[k].push(rx);
            }
        }
    }

    // Partition peers across shards
    let mut shard_peers: Vec<Vec<crate::config::PeerConfig>> = vec![Vec::new(); num_shards];
    for peer in &config.peers {
        let shard_idx = shard_for_pubkey(&peer.public_key, num_shards);
        shard_peers[shard_idx].push(peer.clone());
    }

    struct ShutdownGuard;
    impl Drop for ShutdownGuard {
        fn drop(&mut self) {
            request_shutdown();
        }
    }

    let mut handles = Vec::with_capacity(num_shards);

    for shard_id in 0..num_shards {
        let sock = sockets.remove(0);
        let tun_dev = tun_queues.remove(0);
        let tx_channels = std::mem::take(&mut tx_matrix[shard_id]);
        let rx_channels = std::mem::take(&mut rx_matrix[shard_id]);
        let peers = std::mem::take(&mut shard_peers[shard_id]);
        let cfg = config.clone();

        let handle = std::thread::Builder::new()
            .name(format!("yipd-shard-{shard_id}"))
            .spawn(move || -> io::Result<()> {
                let _guard = ShutdownGuard;

                if let Err(e) = yip_io::pin_current_thread(shard_id) {
                    eprintln!(
                        "warning: sched_setaffinity(core={shard_id}) failed: {e} -- continuing unpinned"
                    );
                }

                let mut manager = create_peer_manager(&cfg, &peers)?;
                let tun_fd = tun_dev.as_raw_fd();
                let sock_fd = sock.as_raw_fd();
                let poller = yip_io::epoll::Epoll::new(sock_fd, tun_fd)?;
                let vnet_len = tun_dev.vnet_hdr_len().unwrap_or(0);
                let is_tap = cfg.device_kind == crate::mode::TunnelMode::L2Tap;

                let mut udp_buf = [0u8; yip_io::MAX_WIRE_DATAGRAM];
                let mut tun_buf = vec![0u8; vnet_len + yip_io::MAX_WIRE_DATAGRAM];
                let start = std::time::Instant::now();
                let mut spsc_batch = Vec::new();

                loop {
                    if SHUTDOWN.load(Ordering::Relaxed) {
                        break;
                    }

                    let ready = poller.wait(10)?;
                    if SHUTDOWN.load(Ordering::Relaxed) {
                        break;
                    }

                    let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

                    // 1. Drain local UDP socket via on_udp
                    if ready.udp {
                        loop {
                            match sock.recv_from(&mut udp_buf) {
                                Ok((n, src)) => {
                                    let (tun_out, egress) =
                                        owned_out(manager.on_udp(src, &udp_buf[..n], now_ms));
                                    if let Some(inner) = tun_out {
                                        write_tun(tun_fd, &inner, vnet_len > 0);
                                    }
                                    for dg in &egress {
                                        let _ = sock.send_to(&dg.bytes, dg.dst);
                                    }
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                                Err(e) => return Err(e),
                            }
                        }
                    }

                    // 2. Drain local TUN queue fd
                    if ready.tun {
                        loop {
                            match yip_io::epoll::read_fd(tun_fd, &mut tun_buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if n > vnet_len {
                                        let pkt = &tun_buf[vnet_len..n];
                                        let target_shard = match dst_for_packet(pkt, is_tap) {
                                            Some(dst) => shard_for_addr(dst, num_shards),
                                            None => shard_id,
                                        };

                                        if target_shard == shard_id {
                                            let egress = manager.on_tun(pkt, now_ms);
                                            for dg in egress {
                                                let _ = sock.send_to(&dg.bytes, dg.dst);
                                            }
                                        } else if let Some(Some(ref tx)) =
                                            tx_channels.get(target_shard)
                                        {
                                            let _ = tx.push(OutboundPacket {
                                                bytes: pkt.to_vec(),
                                            });
                                        }
                                    }
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                                Err(e) => {
                                    eprintln!("yipd-shard-{shard_id}: tun read error: {e}");
                                    break;
                                }
                            }
                        }
                    }

                    // 3. Drain incoming SPSC inboxes
                    for rx in &rx_channels {
                        spsc_batch.clear();
                        rx.drain_batch(&mut spsc_batch, 64);
                        for pkt in &spsc_batch {
                            let egress = manager.on_tun(&pkt.bytes, now_ms);
                            for dg in egress {
                                let _ = sock.send_to(&dg.bytes, dg.dst);
                            }
                        }
                    }

                    // 4. Cadence tick (feedback / keepalive / retransmit / cover)
                    if let Some(egress) = manager.tick(now_ms) {
                        for dg in egress {
                            let _ = sock.send_to(&dg.bytes, dg.dst);
                        }
                    }
                }

                Ok(())
            })?;
        handles.push(handle);
    }

    for handle in handles {
        match handle.join() {
            Ok(res) => res?,
            Err(_) => return Err(io::Error::other("shard worker panicked")),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn pseudo_key(seed: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut state = seed;
        for i in 0..4 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            key[i * 8..(i + 1) * 8].copy_from_slice(&state.to_le_bytes());
        }
        key
    }

    #[test]
    fn test_boundary_conditions() {
        let key = [42u8; 32];
        let mesh_addr = crate::addr::node_addr(&key);
        let non_mesh_addr = Ipv6Addr::from_str("2001:db8::1").unwrap();

        for shards in [0, 1] {
            assert_eq!(shard_for_pubkey(&key, shards), 0);
            assert_eq!(shard_for_addr(mesh_addr, shards), 0);
            assert_eq!(shard_for_addr(non_mesh_addr, shards), 0);
        }
    }

    #[test]
    fn test_pubkey_always_equals_node_addr() {
        let shard_counts = [2, 3, 4, 7, 8, 16, 32, 64];

        for i in 0..1000 {
            let key = pseudo_key(i);
            let addr = crate::addr::node_addr(&key);

            for &shards in &shard_counts {
                let pk_shard = shard_for_pubkey(&key, shards);
                let addr_shard = shard_for_addr(addr, shards);

                assert_eq!(
                    pk_shard, addr_shard,
                    "mismatch for seed {i} with {shards} shards"
                );
                assert!(
                    pk_shard < shards,
                    "shard index {pk_shard} out of bounds for {shards} shards"
                );
            }
        }
    }

    #[test]
    fn test_determinism() {
        let key = pseudo_key(999);
        let addr = crate::addr::node_addr(&key);

        for _ in 0..10 {
            assert_eq!(shard_for_pubkey(&key, 4), shard_for_pubkey(&key, 4));
            assert_eq!(shard_for_addr(addr, 4), shard_for_addr(addr, 4));
        }
    }

    #[test]
    fn test_uniformity_distribution() {
        let total = 10_000;
        let num_shards = 4;
        let mut counts = vec![0; num_shards];

        for i in 0..total {
            let key = pseudo_key(i as u64);
            let shard = shard_for_pubkey(&key, num_shards);
            counts[shard] += 1;
        }

        let expected = total / num_shards;
        for (shard, &count) in counts.iter().enumerate() {
            let diff = (count as isize - expected as isize).abs();
            // With 10,000 samples across 4 shards, expected is 2500 with std dev ~43.
            // 400 is ~9.3 std deviations, virtually impossible to fail randomly if uniform.
            assert!(
                diff < 400,
                "shard {shard} count {count} deviated too far from expected {expected}"
            );
        }

        // Test with 8 shards
        let num_shards = 8;
        let mut counts8 = vec![0; num_shards];
        for i in 0..total {
            let key = pseudo_key(i as u64);
            let shard = shard_for_pubkey(&key, num_shards);
            counts8[shard] += 1;
        }

        let expected8 = total / num_shards;
        for (shard, &count) in counts8.iter().enumerate() {
            let diff = (count as isize - expected8 as isize).abs();
            assert!(
                diff < 300,
                "shard {shard} count {count} deviated too far from expected {expected8}"
            );
        }
    }

    #[test]
    fn test_non_mesh_addresses_graceful_handling() {
        let non_mesh_addrs = [
            Ipv6Addr::from_str("::1").unwrap(),
            Ipv6Addr::from_str("::").unwrap(),
            Ipv6Addr::from_str("2001:db8::1").unwrap(),
            Ipv6Addr::from_str("fe80::1234:5678:9abc:def0").unwrap(),
            Ipv6Addr::from_str("ff02::1").unwrap(),
        ];

        for &addr in &non_mesh_addrs {
            assert_eq!(shard_for_addr(addr, 0), 0);
            assert_eq!(shard_for_addr(addr, 1), 0);

            for shards in [2, 4, 8, 16] {
                let shard = shard_for_addr(addr, shards);
                assert!(
                    shard < shards,
                    "shard index {shard} out of bounds for {shards} shards"
                );
            }
        }
    }

    #[test]
    fn test_dst_for_packet_parsing() {
        // Test IPv6 packet parsing
        let mut v6_pkt = vec![0u8; 40];
        v6_pkt[0] = 0x60; // IPv6 version
        let target_v6: [u8; 16] = [
            0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 1,
        ];
        v6_pkt[24..40].copy_from_slice(&target_v6);

        let parsed = dst_for_packet(&v6_pkt, false);
        assert_eq!(parsed, Some(Ipv6Addr::from(target_v6)));

        // Test IPv4 packet parsing
        let mut v4_pkt = vec![0u8; 20];
        v4_pkt[0] = 0x45; // IPv4 version
        let target_v4: [u8; 4] = [10, 0, 0, 2];
        v4_pkt[16..20].copy_from_slice(&target_v4);

        let parsed_v4 = dst_for_packet(&v4_pkt, false);
        assert_eq!(
            parsed_v4,
            Some(std::net::Ipv4Addr::from(target_v4).to_ipv6_mapped())
        );

        // Test TAP Ethernet framing with IPv6
        let mut tap_pkt = vec![0u8; 14 + 40];
        tap_pkt[12] = 0x86;
        tap_pkt[13] = 0xdd;
        tap_pkt[14] = 0x60;
        tap_pkt[14 + 24..14 + 40].copy_from_slice(&target_v6);

        let parsed_tap = dst_for_packet(&tap_pkt, true);
        assert_eq!(parsed_tap, Some(Ipv6Addr::from(target_v6)));
    }

    #[test]
    fn test_run_sharded_validation() {
        let text = "device=yip0\nlisten=127.0.0.1:0\n\
                    local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                    peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    peer_endpoint=127.0.0.1:51820\n";
        let config = Config::parse(text).unwrap();

        // 0 shards should fail
        assert!(run_sharded(config.clone(), 0).is_err());

        // Non-RawUdp transport should fail
        let quic_text = format!("{text}transport=quic\n");
        let quic_config = Config::parse(&quic_text).unwrap();
        assert!(run_sharded(quic_config, 2).is_err());
    }

    fn have_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    }

    #[test]
    fn test_run_sharded_smoke_launch() {
        if !have_root() {
            eprintln!("skipping root-gated test_run_sharded_smoke_launch");
            return;
        }

        reset_shutdown();

        let text = "device=yiptest_sh%d\nlisten=127.0.0.1:0\n\
                    local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                    peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    peer_endpoint=127.0.0.1:51820\n";
        let config = Config::parse(text).unwrap();

        let handle = std::thread::spawn(move || run_sharded(config, 2));

        std::thread::sleep(std::time::Duration::from_millis(150));
        request_shutdown();

        let res = handle.join().expect("thread join");
        assert!(res.is_ok(), "run_sharded should exit cleanly on shutdown");
        reset_shutdown();
    }
}
