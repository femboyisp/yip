//! Integration test for monotonic TCP packet ordering in sharded worker queues.
//!
//! Verifies that 10,000 packets of a single TCP connection are pinned to the exact
//! same worker shard queue in monotonic order (Regime B: zero TCP reordering).

#[path = "../src/flow.rs"]
mod flow;

use flow::FlowTuple;
use yip_io::spsc::spsc_pair;

fn build_ipv4_tcp_packet(seq: u32, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 44];
    pkt[0] = 0x45; // IPv4, IHL = 5
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src IP
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst IP
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes()); // TCP sequence number
    pkt[40..44].copy_from_slice(&seq.to_be_bytes()); // Payload sequence number
    pkt
}

fn route_packet_to_shard(pkt: &[u8], num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    if let Some(flow) = FlowTuple::extract(pkt) {
        (flow.flow_hash() as usize) % num_shards
    } else {
        0
    }
}

#[test]
fn test_10000_tcp_packets_pin_to_same_shard_monotonically() {
    let num_shards = 4;
    const NUM_PACKETS: usize = 10_000;

    // Create SPSC ring buffer channels for each shard (capacity 2048 each)
    let mut producers = Vec::with_capacity(num_shards);
    let mut consumers = Vec::with_capacity(num_shards);

    for _ in 0..num_shards {
        let (tx, rx) = spsc_pair::<u32, 2048>();
        producers.push(tx);
        consumers.push(rx);
    }

    // Determine target shard for this TCP connection
    let sample_pkt = build_ipv4_tcp_packet(0, 12345, 80);
    let target_shard = route_packet_to_shard(&sample_pkt, num_shards);

    // Drain buffers to collect received packets per shard
    let mut received_per_shard: Vec<Vec<u32>> = (0..num_shards)
        .map(|_| Vec::with_capacity(NUM_PACKETS))
        .collect();

    // Push 10,000 packets into the sharded queue system, draining the ring buffers
    // periodically as they fill to model active worker thread consumption.
    let mut batch = Vec::new();
    for seq in 0..NUM_PACKETS as u32 {
        let pkt = build_ipv4_tcp_packet(seq, 12345, 80);
        let shard = route_packet_to_shard(&pkt, num_shards);
        assert_eq!(
            shard, target_shard,
            "packet {seq} routed to shard {shard}, expected target shard {target_shard}"
        );

        // If producer ring buffer is full, drain from consumer
        if producers[shard].push(seq).is_err() {
            batch.clear();
            consumers[shard].drain_batch(&mut batch, 2048);
            received_per_shard[shard].extend_from_slice(&batch);

            // Retry push now that ring buffer has space
            producers[shard]
                .push(seq)
                .expect("producer push must succeed after drain");
        }
    }

    // Drain any remaining packets from all consumers
    for s in 0..num_shards {
        loop {
            batch.clear();
            let count = consumers[s].drain_batch(&mut batch, 2048);
            if count == 0 {
                break;
            }
            received_per_shard[s].extend_from_slice(&batch);
        }
    }

    // Assert that target shard received all 10,000 packets in strict monotonic sequence
    assert_eq!(
        received_per_shard[target_shard].len(),
        NUM_PACKETS,
        "target shard must receive all 10,000 packets"
    );
    for (i, &seq) in received_per_shard[target_shard].iter().enumerate() {
        assert_eq!(
            seq, i as u32,
            "packet at index {i} had sequence number {seq}, violating monotonic FIFO ordering"
        );
    }

    // Assert that all other shards received 0 packets
    for (s, shard_vec) in received_per_shard.iter().enumerate() {
        if s != target_shard {
            assert_eq!(
                shard_vec.len(),
                0,
                "shard {s} should have received 0 packets for this TCP flow"
            );
        }
    }
}

#[test]
fn test_multiple_flows_independent_pinning() {
    let num_shards = 4;
    let flows = [
        (10001u16, 80u16),
        (10002u16, 443u16),
        (20001u16, 8080u16),
        (30001u16, 9000u16),
    ];

    for &(src_port, dst_port) in &flows {
        let first_pkt = build_ipv4_tcp_packet(0, src_port, dst_port);
        let expected_shard = route_packet_to_shard(&first_pkt, num_shards);

        for seq in 1..500u32 {
            let pkt = build_ipv4_tcp_packet(seq, src_port, dst_port);
            let shard = route_packet_to_shard(&pkt, num_shards);
            assert_eq!(
                shard, expected_shard,
                "flow ({src_port}->{dst_port}) packet {seq} pinned to {shard}, expected {expected_shard}"
            );
        }
    }
}

#[test]
fn test_af_xdp_worker_probe_and_fallback_mode_detection() {
    use yip_io::af_xdp::{UmemPool, XskBindMode, XskSocket};

    // Verify worker UMEM allocation: 2048 chunks of 4096 bytes
    let umem = UmemPool::new(2048, 4096).expect("worker UmemPool allocation must succeed");
    assert_eq!(umem.chunk_size(), 4096);
    assert_eq!(umem.free_chunk_count(), 2048);

    // Resolve interface name as done in worker initialization
    let ifname = std::env::var("YIP_XDP_IFNAME").unwrap_or_else(|_| "lo".to_string());

    // Probe opportunistic AF_XDP socket on shard 0
    let sock =
        XskSocket::bind_opportunistic(&ifname, 0, &umem).unwrap_or_else(|_| XskSocket::fallback());

    // In unprivileged test environments, bind should gracefully probe and fallback
    match sock.mode() {
        XskBindMode::FallbackRecvmmsg => {
            assert_eq!(sock.fd(), -1);
        }
        XskBindMode::ZeroCopy | XskBindMode::Copy => {
            assert!(sock.fd() >= 0);
        }
    }

    // Verify fallback socket fallback() behaves consistently
    let fb = XskSocket::fallback();
    assert_eq!(fb.mode(), XskBindMode::FallbackRecvmmsg);
    assert_eq!(fb.fd(), -1);
}

#[test]
fn test_af_xdp_zero_copy_rx_ring_processing_simulation() {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use yip_io::af_xdp::{FillRing, UmemPool, XskDesc, XskSocket, UMEM_RING_SIZE};
    use yip_io::poll::{Dispatch, DispatchOut, EgressDatagram};

    let mut umem = UmemPool::new(64, 4096).expect("allocate UMEM pool for simulation");
    let mut fill_ring = FillRing::new(UMEM_RING_SIZE);
    let mut xsk_sock = XskSocket::fallback();

    // Fill initial descriptors into fill ring
    for _ in 0..16 {
        if let Some(addr) = umem.alloc_chunk() {
            assert!(fill_ring.produce(addr));
        }
    }
    assert_eq!(fill_ring.len(), 16);

    // Simulate incoming packet delivered via RX ring in ZeroCopy/Copy mode
    let chunk_addr = fill_ring.consume().expect("get chunk address");
    let dummy_packet = b"YIP_ZERO_COPY_PAYLOAD_TEST";
    {
        let slice = umem.chunk_slice_mut(chunk_addr, dummy_packet.len());
        slice.copy_from_slice(dummy_packet);
    }

    let desc = XskDesc::new(chunk_addr, dummy_packet.len() as u32, 0);
    assert!(xsk_sock.rx_ring_mut().produce(desc));

    // Dummy dispatch mock implementing Dispatch trait
    struct MockDispatch {
        received_packets: Vec<Vec<u8>>,
    }
    impl Dispatch for MockDispatch {
        fn on_udp(&mut self, _src: SocketAddr, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.received_packets.push(dg.to_vec());
            DispatchOut::None
        }
        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            &[]
        }
        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            None
        }
    }

    let mut mock = MockDispatch {
        received_packets: Vec::new(),
    };
    let dummy_src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51820));

    // Drain descriptors from RX ring and verify chunk slicing and replenish logic
    let mut drained_descs = [XskDesc::default(); 32];
    let n = xsk_sock.rx_ring_mut().consume_batch(&mut drained_descs);
    assert_eq!(n, 1);

    for desc in &drained_descs[..n] {
        let payload = umem.chunk_slice(desc.addr, desc.len as usize);
        let _ = mock.on_udp(dummy_src, payload, 0);
        // Replenish chunk address back to fill ring
        assert!(fill_ring.produce(desc.addr));
    }

    assert_eq!(mock.received_packets.len(), 1);
    assert_eq!(&mock.received_packets[0], dummy_packet);
    assert_eq!(fill_ring.len(), 16);
}

#[test]
fn test_adaptive_poller_transitions_between_spin_and_sleep() {
    let mut poller = yipd::sharding::AdaptivePoller::new(50);
    let start = std::time::Instant::now();
    poller.record_active(start);
    assert!(poller.should_busy_poll(start));
    assert!(poller.should_busy_poll(start + std::time::Duration::from_micros(30)));
    assert!(!poller.should_busy_poll(start + std::time::Duration::from_micros(60)));
}

#[test]
fn test_adaptive_poller_active_after_simulated_sleep_wakeup() {
    let mut poller = yipd::sharding::AdaptivePoller::new(50);
    // Initially not busy polling
    let t0 = std::time::Instant::now();
    assert!(!poller.should_busy_poll(t0));

    // Simulate 10 ms sleep in epoll_wait
    let t_wakeup = t0 + std::time::Duration::from_millis(10);
    // After wakeup, packet arrived and drained, timestamp is recorded
    poller.record_active(t_wakeup);

    // Subsequent loop iteration (e.g. 5 micros later) MUST enter busy polling!
    let t_next = t_wakeup + std::time::Duration::from_micros(5);
    assert!(poller.should_busy_poll(t_next));
}
