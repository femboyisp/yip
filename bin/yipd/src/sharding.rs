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

/// Deterministically map an incoming TUN packet to a target shard index in `0..num_shards`.
///
/// Uses inner 5-tuple symmetric flow hashing (`FlowTuple::extract` + `symmetric_flow_hash`)
/// to pin both directions of each connection to a single worker shard in strict FIFO sequence,
/// preventing TCP reordering and cross-core cache invalidation on TCP ACKs (Regime B+).
/// For non-IP packets or packets where flow extraction fails, falls back to destination
/// address hashing (`dst_for_packet` + `shard_for_addr`), or shard 0.
pub fn shard_for_packet(packet: &[u8], is_tap: bool, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let ip_payload = if is_tap {
        if packet.len() < 14 {
            return 0;
        }
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype == 0x0800 || ethertype == 0x86dd {
            &packet[14..]
        } else {
            return 0;
        }
    } else {
        packet
    };

    if let Some(flow) = crate::flow::FlowTuple::extract(ip_payload) {
        (flow.symmetric_flow_hash() as usize) % num_shards
    } else if let Some(dst) = dst_for_packet(packet, is_tap) {
        shard_for_addr(dst, num_shards)
    } else {
        0
    }
}

/// Deterministically pin all source and repair symbols of an FEC object block
/// to a single worker shard to ensure Cauchy Reed-Solomon decoding remains hot in L1D cache (Regime B+).
///
/// Guarantees that 100% of source symbols ($0..K$) and repair symbols ($0..R$) for any given
/// `(conn_tag, object_id)` pair map to the identical worker core.
pub fn shard_for_fec_symbol(conn_tag: u64, object_id: u16, num_shards: usize) -> usize {
    yip_transport::fec::shard_for_fec_symbol(conn_tag, object_id, num_shards)
}

/// Demux an unmasked wire frame header by `(conn_tag, object_id)` to a target worker shard index in `0..num_shards`.
///
/// If `header` contains at least 10 bytes (8-byte `conn_tag` + 2-byte `object_id`),
/// demuxes via [`shard_for_fec_symbol`]. Returns `0` if `header.len() < 10` or `num_shards <= 1`.
pub fn shard_for_wire_header(header: &[u8], num_shards: usize) -> usize {
    if num_shards <= 1 || header.len() < 10 {
        return 0;
    }
    let conn_tag = u64::from_be_bytes(header[0..8].try_into().expect("slice has length 8"));
    let object_id = u16::from_be_bytes(header[8..10].try_into().expect("slice has length 2"));
    shard_for_fec_symbol(conn_tag, object_id, num_shards)
}

/// Demux an incoming wire frame to its target worker shard index in `0..num_shards`.
pub fn shard_for_wire_frame(frame: &yip_wire::Frame, num_shards: usize) -> usize {
    shard_for_fec_symbol(frame.conn_tag, frame.object_id, num_shards)
}

/// Map an outer UDP datagram carrying a wire frame to a target shard index in `0..num_shards`.
///
/// When an outer UDP frame carries a Data packet (`PacketType::Data` as u8), extracts
/// the wire header starting at byte 1 and demuxes by `shard_for_fec_symbol`.
/// Returns `None` if the datagram is not a Data packet, is shorter than 11 bytes,
/// or `num_shards <= 1`.
pub fn shard_for_outer_udp(datagram: &[u8], num_shards: usize) -> Option<usize> {
    if num_shards <= 1 || datagram.len() < 11 {
        return None;
    }
    if datagram[0] == crate::handshake::PacketType::Data as u8 {
        Some(shard_for_wire_header(&datagram[1..11], num_shards))
    } else {
        None
    }
}

use std::io;
use std::net::ToSocketAddrs;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use yip_io::af_xdp::{FillRing, UmemPool, XskBindMode, XskDesc, XskSocket, UMEM_RING_SIZE};
use yip_io::poll::Dispatch;

use crate::config::Config;

/// An outbound inner packet transferred across worker shards via SPSC ring buffers.
#[derive(Debug, Clone)]
pub struct OutboundPacket {
    pub bytes: Vec<u8>,
}

/// Coalesced timer for 20 Hz cadence ticks under multi-core packet traffic.
#[derive(Debug, Clone)]
pub struct CoalescedTimer {
    interval: std::time::Duration,
    packet_batch_mask: u64,
    last_tick: std::time::Instant,
    packet_count: u64,
    last_check_packets: u64,
}

impl CoalescedTimer {
    pub const DEFAULT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);
    pub const DEFAULT_BATCH_MASK: u64 = 2047; // 2048 packets

    pub fn new() -> Self {
        Self::with_interval_and_mask(Self::DEFAULT_INTERVAL, Self::DEFAULT_BATCH_MASK)
    }

    pub fn with_interval_and_mask(interval: std::time::Duration, packet_batch_mask: u64) -> Self {
        Self {
            interval,
            packet_batch_mask,
            last_tick: std::time::Instant::now(),
            packet_count: 0,
            last_check_packets: 0,
        }
    }

    /// Record `n` processed packets.
    #[inline]
    pub fn on_packets(&mut self, n: u64) {
        self.packet_count = self.packet_count.wrapping_add(n);
    }

    /// Current cumulative packet count.
    #[inline]
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }

    /// Batch mask for traffic accounting.
    #[inline]
    pub fn packet_batch_mask(&self) -> u64 {
        self.packet_batch_mask
    }

    /// Check whether a clock query (`Instant::now()`) should be performed.
    ///
    /// Throttles clock queries to eliminate per-batch vDSO invocations under high packet rates:
    /// returns `true` when idle (`packets_this_iter == 0`), OR when packet count has advanced
    /// past the batch mask threshold (e.g. `accumulated_packets >= 2048` or `total_packets & 2047 == 0`).
    #[inline]
    pub fn should_check_time(&self, packets_this_iter: u64) -> bool {
        packets_this_iter == 0
            || (self.packet_count & self.packet_batch_mask == 0)
            || self.packet_count.wrapping_sub(self.last_check_packets) > self.packet_batch_mask
    }

    /// Check whether a timer tick should fire given the current time and packets processed
    /// in this loop iteration. Updates the last check packet count.
    pub fn should_tick(&mut self, now: std::time::Instant, _packets_this_iter: u64) -> bool {
        self.last_check_packets = self.packet_count;
        if now.duration_since(self.last_tick) >= self.interval {
            self.last_tick = now;
            true
        } else {
            false
        }
    }
}

impl Default for CoalescedTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Adaptive dynamic busy-polling engine for sub-microsecond latency.
///
/// Under active traffic bursts, busy-polls descriptor and socket queues with zero
/// syscalls / zero sleep-wakeup overhead for a configured duration (`busy_poll_duration`,
/// default 50 µs), gracefully yielding to `epoll_wait(10)` when traffic subsides.
#[derive(Debug, Clone)]
pub struct AdaptivePoller {
    busy_poll_duration: std::time::Duration,
    last_active: std::time::Instant,
}

impl AdaptivePoller {
    /// Create a new `AdaptivePoller` with a busy-poll duration of `busy_poll_us` microseconds.
    ///
    /// Initializes `last_active` 1 second in the past so the poller does not busy-poll
    /// on initial startup before any packets arrive.
    pub fn new(busy_poll_us: u64) -> Self {
        Self {
            busy_poll_duration: std::time::Duration::from_micros(busy_poll_us),
            last_active: std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap_or_else(std::time::Instant::now),
        }
    }

    /// Check whether the worker should busy-poll (spin loop with non-blocking wait(0)).
    #[inline]
    pub fn should_busy_poll(&self, now: std::time::Instant) -> bool {
        now.saturating_duration_since(self.last_active) < self.busy_poll_duration
    }

    /// Record that packets were processed at `now`, resetting the busy-polling window.
    #[inline]
    pub fn record_active(&mut self, now: std::time::Instant) {
        self.last_active = now;
    }
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

pub(crate) fn select_egress_socket<'a>(
    default_sock: &'a std::net::UdpSocket,
    pool: &'a [std::net::UdpSocket],
    pkt: &[u8],
    is_tap: bool,
    dst: std::net::SocketAddr,
) -> &'a std::net::UdpSocket {
    if pool.is_empty() {
        return default_sock;
    }
    let ip_pkt = if is_tap {
        if pkt.len() >= 14
            && ((pkt[12] == 0x08 && pkt[13] == 0x00) || (pkt[12] == 0x86 && pkt[13] == 0xdd))
        {
            &pkt[14..]
        } else {
            &[]
        }
    } else {
        pkt
    };

    let flow_hash = crate::flow::FlowTuple::extract(ip_pkt)
        .map(|f| f.flow_hash())
        .unwrap_or(0);
    let chosen = &pool[(flow_hash as usize) % pool.len()];
    if let Ok(chosen_local) = chosen.local_addr() {
        if dst.is_ipv6() != chosen_local.is_ipv6() {
            return default_sock;
        }
    }
    chosen
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

                // Probe opportunistic AF_XDP socket with 3-tier fallback
                let mut umem_pool = UmemPool::new(2048, 4096).ok();
                let xsk_ifname =
                    std::env::var("YIP_XDP_IFNAME").unwrap_or_else(|_| "lo".to_string());
                let mut xsk_sock = if let Some(ref pool) = umem_pool {
                    XskSocket::bind_opportunistic(&xsk_ifname, shard_id as u32, pool)
                        .unwrap_or_else(|_| XskSocket::fallback())
                } else {
                    XskSocket::fallback()
                };

                let mut fill_ring = FillRing::new(UMEM_RING_SIZE);
                if let Some(ref mut pool) = umem_pool {
                    while !fill_ring.is_full() {
                        if let Some(addr) = pool.alloc_chunk() {
                            fill_ring.produce(addr);
                        } else {
                            break;
                        }
                    }
                }

                let sock_fd =
                    if xsk_sock.mode() != XskBindMode::FallbackRecvmmsg && xsk_sock.fd() >= 0 {
                        xsk_sock.fd()
                    } else {
                        sock.as_raw_fd()
                    };
                let poller = yip_io::epoll::Epoll::new(sock_fd, tun_fd)?;
                let vnet_len = tun_dev.vnet_hdr_len().unwrap_or(0);
                let is_tap = cfg.device_kind == crate::mode::TunnelMode::L2Tap;
                let egress_bind = if cfg.listen.is_ipv6() {
                    std::net::SocketAddr::from(([0u8; 16], 0))
                } else {
                    std::net::SocketAddr::from(([0u8; 4], 0))
                };
                let egress_pool =
                    crate::port::bind_udp_egress_pool(egress_bind, 64).unwrap_or_default();
                let mut coalesced_timer = CoalescedTimer::new();
                let busy_poll_us = std::env::var("YIP_BUSY_POLL_US")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(50);
                let mut adaptive_poller = AdaptivePoller::new(busy_poll_us);

                let mut batch_sock = yip_io::batch::BatchUdpSocket::new(&sock);
                let mut rx_buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; yip_io::batch::BATCH_SIZE];
                let mut rx_datagrams =
                    [const { yip_io::batch::ReceivedDatagram::empty() }; yip_io::batch::BATCH_SIZE];
                let mut tun_buf = vec![0u8; vnet_len + yip_io::MAX_WIRE_DATAGRAM];
                let start = std::time::Instant::now();
                let mut cached_now_ms: u64 = 0;
                let mut spsc_batch = Vec::new();

                loop {
                    if SHUTDOWN.load(Ordering::Relaxed) {
                        break;
                    }

                    let is_busy_polling =
                        adaptive_poller.should_busy_poll(std::time::Instant::now());
                    let ready = if is_busy_polling {
                        std::hint::spin_loop();
                        poller.wait(0)?
                    } else {
                        poller.wait(10)?
                    };

                    if SHUTDOWN.load(Ordering::Relaxed) {
                        break;
                    }

                    let xsk_rx_ready = xsk_sock.mode() != XskBindMode::FallbackRecvmmsg
                        && !xsk_sock.rx_ring().is_empty();
                    let ready_none = !ready.udp && !ready.tun && !xsk_rx_ready;
                    let mut packets_this_iter: u64 = 0;

                    // 1. Drain local UDP socket / AF_XDP RX ring via on_udp
                    if ready.udp || xsk_rx_ready {
                        if xsk_sock.mode() == XskBindMode::FallbackRecvmmsg {
                            loop {
                                match batch_sock.recvmmsg_batch(&mut rx_buffers, &mut rx_datagrams) {
                                    Ok(0) => break,
                                    Ok(count) => {
                                        packets_this_iter =
                                            packets_this_iter.wrapping_add(count as u64);
                                        for i in 0..count {
                                            let dg = &rx_datagrams[i];
                                            let payload = &rx_buffers[i][..dg.len];
                                            let (tun_out, egress) =
                                                owned_out(manager.on_udp(dg.src, payload, cached_now_ms));
                                            if let Some(inner) = tun_out {
                                                write_tun(tun_fd, &inner, vnet_len > 0);
                                            }
                                            if !egress.is_empty() {
                                                let egress_batch: Vec<(&[u8], std::net::SocketAddr)> =
                                                    egress.iter().map(|d| (&d.bytes[..], d.dst)).collect();
                                                let _ = batch_sock.sendmmsg_batch(&egress_batch);
                                            }
                                        }
                                    }
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                                    Err(e) => return Err(e),
                                }
                            }
                        } else if let Some(ref mut pool) = umem_pool {
                            let mut descs = [XskDesc::default(); 32];
                            loop {
                                let count = xsk_sock.rx_ring_mut().consume_batch(&mut descs);
                                if count == 0 {
                                    break;
                                }
                                packets_this_iter =
                                    packets_this_iter.wrapping_add(count as u64);
                                for desc in &descs[..count] {
                                    if (desc.len as usize) <= pool.chunk_size() {
                                        let payload =
                                            pool.chunk_slice(desc.addr, desc.len as usize);
                                        let (tun_out, egress) =
                                            owned_out(manager.on_udp(cfg.listen, payload, cached_now_ms));
                                        if let Some(inner) = tun_out {
                                            write_tun(tun_fd, &inner, vnet_len > 0);
                                        }
                                        if !egress.is_empty() {
                                            let egress_batch: Vec<(&[u8], std::net::SocketAddr)> =
                                                egress.iter().map(|d| (&d.bytes[..], d.dst)).collect();
                                            let _ = batch_sock.sendmmsg_batch(&egress_batch);
                                        }
                                    }
                                    if !fill_ring.produce(desc.addr) {
                                        pool.free_chunk(desc.addr);
                                    }
                                }
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
                                        packets_this_iter = packets_this_iter.wrapping_add(1);
                                        let pkt = &tun_buf[vnet_len..n];
                                        let target_shard = shard_for_packet(pkt, is_tap, num_shards);

                                        if target_shard == shard_id {
                                            let egress = manager.on_tun(pkt, cached_now_ms);
                                            for dg in egress {
                                                let send_sock = select_egress_socket(
                                                    &sock,
                                                    &egress_pool,
                                                    pkt,
                                                    is_tap,
                                                    dg.dst,
                                                );
                                                let _ = send_sock.send_to(&dg.bytes, dg.dst);
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
                        packets_this_iter = packets_this_iter.wrapping_add(spsc_batch.len() as u64);
                        for pkt in &spsc_batch {
                            let egress = manager.on_tun(&pkt.bytes, cached_now_ms);
                            for dg in egress {
                                let send_sock = select_egress_socket(
                                    &sock,
                                    &egress_pool,
                                    &pkt.bytes,
                                    is_tap,
                                    dg.dst,
                                );
                                let _ = send_sock.send_to(&dg.bytes, dg.dst);
                            }
                        }
                    }

                    if packets_this_iter > 0 {
                        adaptive_poller.record_active(std::time::Instant::now());
                    }

                    // 4. Cadence tick (feedback / keepalive / retransmit / cover)
                    // Coalesced to 20 Hz (50 ms interval) or every 2048 packets.
                    // Clock queries are throttled: only queried when idle (ready_none / packets_this_iter == 0)
                    // or when packet count advances past the batch mask threshold.
                    coalesced_timer.on_packets(packets_this_iter);
                    if (ready_none && packets_this_iter == 0)
                        || coalesced_timer.should_check_time(packets_this_iter)
                    {
                        let now = std::time::Instant::now();
                        cached_now_ms =
                            u64::try_from(now.duration_since(start).as_millis()).unwrap_or(u64::MAX);

                        if coalesced_timer.should_tick(now, packets_this_iter) {
                            if let Some(egress) = manager.tick(cached_now_ms) {
                                if !egress.is_empty() {
                                    let egress_batch: Vec<(&[u8], std::net::SocketAddr)> =
                                        egress.iter().map(|d| (&d.bytes[..], d.dst)).collect();
                                    let _ = batch_sock.sendmmsg_batch(&egress_batch);
                                }
                            }
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
    use std::net::SocketAddr;
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

    #[test]
    fn test_shard_for_packet_flow_pinning() {
        let mut pkt1 = vec![0u8; 40];
        pkt1[0] = 0x45; // IPv4
        pkt1[9] = 6; // TCP
        pkt1[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt1[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt1[20..22].copy_from_slice(&8080u16.to_be_bytes());
        pkt1[22..24].copy_from_slice(&443u16.to_be_bytes());

        let flow1 = crate::flow::FlowTuple::extract(&pkt1).unwrap();
        let expected_shard = (flow1.symmetric_flow_hash() as usize) % 4;

        assert_eq!(shard_for_packet(&pkt1, false, 4), expected_shard);
        assert_eq!(shard_for_packet(&pkt1, false, 1), 0);
        assert_eq!(shard_for_packet(&pkt1, false, 0), 0);

        // Different port pair -> different flow
        let mut pkt2 = pkt1.clone();
        pkt2[20..22].copy_from_slice(&9090u16.to_be_bytes());
        let flow2 = crate::flow::FlowTuple::extract(&pkt2).unwrap();
        assert_eq!(
            shard_for_packet(&pkt2, false, 4),
            (flow2.symmetric_flow_hash() as usize) % 4
        );
    }

    #[test]
    fn test_shard_for_packet_tap() {
        let mut tap_pkt = vec![0u8; 14 + 40];
        tap_pkt[12] = 0x08; // EtherType IPv4
        tap_pkt[13] = 0x00;
        tap_pkt[14] = 0x45; // IPv4
        tap_pkt[14 + 9] = 6; // TCP
        tap_pkt[14 + 12..14 + 16].copy_from_slice(&[192, 168, 1, 10]);
        tap_pkt[14 + 16..14 + 20].copy_from_slice(&[192, 168, 1, 20]);
        tap_pkt[14 + 20..14 + 22].copy_from_slice(&12345u16.to_be_bytes());
        tap_pkt[14 + 22..14 + 24].copy_from_slice(&80u16.to_be_bytes());

        let inner_flow = crate::flow::FlowTuple::extract(&tap_pkt[14..]).unwrap();
        let expected_shard = (inner_flow.symmetric_flow_hash() as usize) % 4;
        assert_eq!(shard_for_packet(&tap_pkt, true, 4), expected_shard);
    }

    #[test]
    fn test_shard_for_packet_bidirectional_symmetric() {
        let mut pkt_fwd = vec![0u8; 40];
        pkt_fwd[0] = 0x45;
        pkt_fwd[9] = 6; // TCP
        pkt_fwd[12..16].copy_from_slice(&[192, 168, 1, 10]);
        pkt_fwd[16..20].copy_from_slice(&[10, 0, 0, 1]);
        pkt_fwd[20..22].copy_from_slice(&54321u16.to_be_bytes());
        pkt_fwd[22..24].copy_from_slice(&443u16.to_be_bytes());

        let mut pkt_rev = vec![0u8; 40];
        pkt_rev[0] = 0x45;
        pkt_rev[9] = 6; // TCP
        pkt_rev[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt_rev[16..20].copy_from_slice(&[192, 168, 1, 10]);
        pkt_rev[20..22].copy_from_slice(&443u16.to_be_bytes());
        pkt_rev[22..24].copy_from_slice(&54321u16.to_be_bytes());

        for shards in [2, 3, 4, 7, 8, 16, 32] {
            assert_eq!(
                shard_for_packet(&pkt_fwd, false, shards),
                shard_for_packet(&pkt_rev, false, shards),
                "forward and reverse packets must route to identical shard for {shards} shards"
            );
        }
    }

    #[test]
    fn test_shard_for_packet_fallback() {
        // Non-IP packet (e.g. ARP or truncated)
        let arp_pkt = vec![0u8; 28];
        assert_eq!(shard_for_packet(&arp_pkt, false, 4), 0);

        // Fallback to destination IP if flow extraction fails (e.g. invalid IHL)
        let mut bad_v4 = vec![0u8; 20];
        bad_v4[0] = 0x44; // IPv4 with invalid IHL = 4 (16 bytes < 20)
        bad_v4[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let dst_mapped = std::net::Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped();
        let expected_shard = shard_for_addr(dst_mapped, 4);
        assert_eq!(shard_for_packet(&bad_v4, false, 4), expected_shard);
    }

    #[test]
    fn test_coalesced_timer_idle_and_traffic() {
        let mut timer =
            CoalescedTimer::with_interval_and_mask(std::time::Duration::from_millis(50), 2047);

        let t0 = std::time::Instant::now();
        // Initially at t0 with 0 packets -> 0 ms elapsed, should not tick
        assert!(!timer.should_tick(t0, 0));

        // Advance 40 ms while idle (< 50 ms) -> should not tick
        let t40 = t0 + std::time::Duration::from_millis(40);
        assert!(!timer.should_tick(t40, 0));

        // Advance 51 ms while idle (>= 50 ms) -> should tick at 20 Hz
        let t51 = t0 + std::time::Duration::from_millis(51);
        assert!(timer.should_tick(t51, 0));

        // Immediately after ticking, should not tick again
        assert!(!timer.should_tick(t51, 0));

        // Under traffic: packets arriving (unaligned count, e.g. 500 packets)
        let t_traffic_start = t51;
        timer.on_packets(500); // packet_count = 500 (not a multiple of 2048)
        let t_traffic_before_interval = t_traffic_start + std::time::Duration::from_millis(25);
        // < 50ms elapsed -> should not tick
        assert!(!timer.should_tick(t_traffic_before_interval, 500));

        // Advance past 50ms under active traffic (unaligned packet count)
        let t_traffic_after = t_traffic_start + std::time::Duration::from_millis(55);
        // Once >= 50ms elapsed, should tick reliably regardless of packet count or alignment
        assert!(timer.should_tick(t_traffic_after, 500));

        // Immediately after ticking, should not tick again
        assert!(!timer.should_tick(t_traffic_after, 500));

        // Additional traffic check: batch that skips multiple of 2048 (e.g. 2049 packets)
        timer.on_packets(2049);
        let t_traffic_next = t_traffic_after + std::time::Duration::from_millis(52);
        assert!(timer.should_tick(t_traffic_next, 2049));

        // Next check right after should not tick
        assert!(!timer.should_tick(t_traffic_next, 1));
    }

    #[test]
    fn test_coalesced_timer_should_check_time() {
        let mut timer =
            CoalescedTimer::with_interval_and_mask(std::time::Duration::from_millis(50), 2047);

        // When idle (0 packets in this iteration), should check time
        assert!(timer.should_check_time(0));

        // When traffic arrives in sub-batch amounts (< 2048), should NOT check time
        timer.on_packets(500);
        assert!(!timer.should_check_time(500));

        timer.on_packets(1547); // total 2047
        assert_eq!(timer.packet_count(), 2047);
        assert!(!timer.should_check_time(1547));

        // Exactly hits or crosses 2048 -> should check time
        timer.on_packets(1); // total 2048
        assert_eq!(timer.packet_count(), 2048);
        assert!(timer.should_check_time(1));

        // After should_tick updates last_check_packets, next packet should NOT check time
        let now = std::time::Instant::now();
        let _ = timer.should_tick(now, 1);
        timer.on_packets(1);
        assert!(!timer.should_check_time(1));

        // A large batch crossing 2048 threshold (e.g. 2049 packets)
        timer.on_packets(2049);
        assert!(timer.should_check_time(2049));
    }

    #[test]
    fn test_select_egress_socket_address_family_matching() {
        let v4_default = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind v4 default");
        let v4_pool = crate::port::bind_udp_egress_pool(SocketAddr::from(([127, 0, 0, 1], 0)), 2)
            .expect("bind v4 pool");

        let v6_dst: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let v4_dst: SocketAddr = "192.0.2.1:51820".parse().unwrap();

        // 1. When pool is IPv4 and peer destination is IPv6 -> safely falls back to default socket
        let selected = select_egress_socket(&v4_default, &v4_pool, &[], false, v6_dst);
        assert_eq!(
            selected.local_addr().unwrap().port(),
            v4_default.local_addr().unwrap().port(),
            "must fallback to default socket when destination is IPv6 but pool is IPv4"
        );

        // 2. When pool is IPv4 and peer destination is IPv4 -> selects socket from pool
        let selected = select_egress_socket(&v4_default, &v4_pool, &[], false, v4_dst);
        let selected_port = selected.local_addr().unwrap().port();
        assert!(
            selected_port == v4_pool[0].local_addr().unwrap().port()
                || selected_port == v4_pool[1].local_addr().unwrap().port(),
            "must select socket from pool when address families match"
        );

        // 3. When pool is IPv6 and peer destination is IPv6 -> selects socket from pool
        if let Ok(v6_default) = std::net::UdpSocket::bind("[::1]:0") {
            if let Ok(v6_pool) =
                crate::port::bind_udp_egress_pool(SocketAddr::from(([0u8; 16], 0)), 2)
            {
                let selected_v6 = select_egress_socket(&v6_default, &v6_pool, &[], false, v6_dst);
                assert!(selected_v6.local_addr().unwrap().is_ipv6());
                let selected_v6_port = selected_v6.local_addr().unwrap().port();
                assert!(
                    selected_v6_port == v6_pool[0].local_addr().unwrap().port()
                        || selected_v6_port == v6_pool[1].local_addr().unwrap().port()
                );

                // 4. When pool is IPv6 and destination is IPv4 -> safely falls back to default socket
                let fallback_v4 = select_egress_socket(&v6_default, &v6_pool, &[], false, v4_dst);
                assert_eq!(
                    fallback_v4.local_addr().unwrap().port(),
                    v6_default.local_addr().unwrap().port()
                );
            }
        }
    }

    #[test]
    fn test_10000_tcp_packets_monotonic_ordering() {
        let num_shards = 4;
        let mut queues: Vec<Vec<u32>> = vec![Vec::new(); num_shards];

        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());

        let target_shard = shard_for_packet(&pkt, false, num_shards);

        // Send 10,000 packets of this flow
        for seq in 0..10_000u32 {
            pkt[24..28].copy_from_slice(&seq.to_be_bytes());
            pkt[40..44].copy_from_slice(&seq.to_be_bytes());

            let shard = shard_for_packet(&pkt, false, num_shards);
            assert_eq!(shard, target_shard, "all packets must pin to target shard");
            queues[shard].push(seq);
        }

        // Verify target shard queue received all 10,000 packets in strict monotonic order
        assert_eq!(queues[target_shard].len(), 10_000);
        for (i, &seq) in queues[target_shard].iter().enumerate() {
            assert_eq!(seq, i as u32, "monotonic order preserved at index {i}");
        }

        // Verify all other shards received 0 packets
        for (idx, q) in queues.iter().enumerate() {
            if idx != target_shard {
                assert_eq!(q.len(), 0, "other shard {idx} must receive 0 packets");
            }
        }
    }

    #[test]
    fn test_shard_for_fec_symbol_boundary() {
        let conn_tag = 0xdead_beef_1234_5678;
        assert_eq!(shard_for_fec_symbol(conn_tag, 42, 0), 0);
        assert_eq!(shard_for_fec_symbol(conn_tag, 42, 1), 0);
        assert_eq!(shard_for_wire_header(&[], 4), 0);
        assert_eq!(shard_for_wire_header(&[0u8; 9], 4), 0); // too short (< 10)
    }

    #[test]
    fn test_shard_for_fec_symbol_affinity() {
        let conn_tag = 0xfeed_face_cafe_babe;
        let num_shards = 8;

        for object_id in 0..100u16 {
            let expected_shard = shard_for_fec_symbol(conn_tag, object_id, num_shards);
            assert!(expected_shard < num_shards);
            for _ in 0..5 {
                assert_eq!(
                    shard_for_fec_symbol(conn_tag, object_id, num_shards),
                    expected_shard,
                    "all symbols for object_id {object_id} must pin to shard {expected_shard}"
                );
            }
        }
    }

    #[test]
    fn test_shard_for_wire_header_and_frame() {
        let conn_tag = 0x1122_3344_5566_7788u64;
        let object_id = 99u16;
        let num_shards = 4;

        let frame = yip_wire::Frame {
            conn_tag,
            object_id,
            payload_id: [1, 0, 0, 0],
            flags: 0,
            payload: vec![1, 2, 3],
        };

        let expected_shard = shard_for_fec_symbol(conn_tag, object_id, num_shards);
        assert_eq!(shard_for_wire_frame(&frame, num_shards), expected_shard);

        let mut header = [0u8; 10];
        header[0..8].copy_from_slice(&conn_tag.to_be_bytes());
        header[8..10].copy_from_slice(&object_id.to_be_bytes());
        assert_eq!(shard_for_wire_header(&header, num_shards), expected_shard);
    }

    #[test]
    fn test_shard_for_outer_udp() {
        let conn_tag = 0x0102_0304_0506_0708u64;
        let object_id = 123u16;
        let num_shards = 8;
        let expected = shard_for_fec_symbol(conn_tag, object_id, num_shards);

        // Valid Data datagram: [PacketType::Data, conn_tag (8b), object_id (2b), ...]
        let mut data_dg = vec![crate::handshake::PacketType::Data as u8];
        data_dg.extend_from_slice(&conn_tag.to_be_bytes());
        data_dg.extend_from_slice(&object_id.to_be_bytes());
        data_dg.extend_from_slice(&[0u8; 20]); // payload
        assert_eq!(shard_for_outer_udp(&data_dg, num_shards), Some(expected));

        // Non-Data packet (e.g. HandshakeInit) -> None
        let mut hs_dg = data_dg.clone();
        hs_dg[0] = crate::handshake::PacketType::HandshakeInit as u8;
        assert_eq!(shard_for_outer_udp(&hs_dg, num_shards), None);

        // Short datagram (< 11 bytes) -> None
        assert_eq!(shard_for_outer_udp(&data_dg[..10], num_shards), None);

        // num_shards <= 1 -> None
        assert_eq!(shard_for_outer_udp(&data_dg, 1), None);
        assert_eq!(shard_for_outer_udp(&data_dg, 0), None);
    }

    #[test]
    fn test_adaptive_poller_initial_state_does_not_busy_poll() {
        let poller = AdaptivePoller::new(50);
        let now = std::time::Instant::now();
        assert!(
            !poller.should_busy_poll(now),
            "poller must not busy poll initially before traffic is recorded"
        );
    }

    #[test]
    fn test_adaptive_poller_record_active_and_window_expiry() {
        let mut poller = AdaptivePoller::new(100);
        let t0 = std::time::Instant::now();
        poller.record_active(t0);

        // Within busy-poll window (50 µs < 100 µs)
        let t1 = t0 + std::time::Duration::from_micros(50);
        assert!(poller.should_busy_poll(t1));

        // Exactly at window boundary (100 µs not < 100 µs)
        let t2 = t0 + std::time::Duration::from_micros(100);
        assert!(!poller.should_busy_poll(t2));

        // Past window boundary (150 µs > 100 µs)
        let t3 = t0 + std::time::Duration::from_micros(150);
        assert!(!poller.should_busy_poll(t3));

        // Re-activating traffic at t3 extends the window
        poller.record_active(t3);
        assert!(poller.should_busy_poll(t3));
        assert!(poller.should_busy_poll(t3 + std::time::Duration::from_micros(80)));
        assert!(!poller.should_busy_poll(t3 + std::time::Duration::from_micros(101)));
    }

    #[test]
    fn test_adaptive_poller_zero_duration() {
        let mut poller = AdaptivePoller::new(0);
        let now = std::time::Instant::now();
        poller.record_active(now);
        assert!(
            !poller.should_busy_poll(now),
            "0-microsecond poller should never busy poll"
        );
    }
}
