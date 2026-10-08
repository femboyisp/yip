# Multi-Core Throughput Sharding Architecture Design

**Date:** 2026-10-07
**Status:** Approved
**Issue:** #10 (Multi-queue throughput sharding — scale past one core)
**Predecessor:** #143 (Scaling spike GO for Way A, `crates/yip-bench/sharding-scale.md`)

---

## 1. Executive Summary

This specification defines the multi-core scaling architecture for `yipd` (**Way A: Per-Peer Engine Sharding**). Building on the empirical findings of the scaling spike ([PR #143](https://github.com/femboyisp/yip/pull/143)), which demonstrated $\sim 90\%$ clock-normalized scaling efficiency across physical CPU cores, this architecture lifts `yip`'s aggregate throughput past the single-core $\sim 1.2\text{ Gbps}$ ceiling toward multi-gigabit speeds.

To preserve the zero-lock, single-threaded latency and state invariants of `DataPlane` (sequential AEAD counters, contiguous Reed-Solomon FEC objects, and unperturbed `LossDetector` state), the system shards execution across $N$ physical cores. Inbound traffic is spread via kernel `SO_REUSEPORT`, and outbound inner packets distributed across a multi-queue TUN device are routed to the owning shard via lock-free Single-Producer Single-Consumer (SPSC) ring buffers.

---

## 2. Architecture & Threading Model

### 2.1 Thread Topology
The daemon instantiates $N$ autonomous worker threads (**Shards**), indexed $0 \dots N-1$, where $N$ defaults to the detected number of physical CPU cores (configurable via `shards = N` or `threads = N` in config).

```
                      ┌──────────────────────────────────────────────┐
                      │          Multi-Queue TUN Interface           │
                      └───────┬──────────────────────┬───────────────┘
                       Queue 0│               Queue 1│        Queue 2│
                              ▼                      ▼               ▼
                       ┌──────────────┐       ┌──────────────┐┌──────────────┐
                       │   Shard 0    │◄─────►│   Shard 1    ││   Shard 2    │ ...
                       │ (Core 0 pin) │ SPSC  │ (Core 1 pin) ││ (Core 2 pin) │
                       └──────┬───────┘Queues └──────┬───────┘└──────┬───────┘
                              │                      │               │
                              ▼                      ▼               ▼
                       ┌──────────────┐       ┌──────────────┐┌──────────────┐
                       │ UDP Socket 0 │       │ UDP Socket 1 ││ UDP Socket 2 │
                       └──────────────┘       └──────────────┘└──────────────┘
                                    SO_REUSEPORT (Listen Port)
```

1. **Core Pinning**:
   - Each shard thread is pinned to a dedicated physical CPU core using `libc::sched_setaffinity`.
   - SMT siblings are skipped unless $N$ explicitly exceeds the physical core count.
   - Threads are named `yipd-shard-{i}` for observability.
2. **Shared-Nothing State Invariant**:
   - Fast-path structures contain zero `Arc<Mutex<_>>` or `RwLock<_>`.
   - Each peer $P$ is owned exclusively by one shard $K$.
   - Shard $K$ executes all state modifications (Noise-IK handshakes, session rekeys, epoch swaps, AEAD counter increments, and FEC retransmits) for its assigned peers.

---

## 3. Component Specifications

### 3.1 Multi-Queue TUN Support (`crates/yip-device`)
`TunTap` is extended to support Linux multiqueue TUN devices (`IFF_MULTI_QUEUE = 0x0100`).

```rust
impl TunTap {
    /// Create a multi-queue TUN/TAP device with `queue_count` independent queue fds.
    pub fn create_multi_queue(
        name: &str,
        kind: DeviceKind,
        queue_count: usize,
        want_vnet_hdr: bool,
    ) -> Result<Vec<TunTap>, DeviceError>;
}
```
- **Initialization**:
  - The master queue fd is created via `/dev/net/tun` with `flags = (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE)`.
  - Queues $1 \dots N-1$ open `/dev/net/tun` and issue the identical `TUNSETIFF` ioctl against the interface name.
  - All queue fds are placed in non-blocking mode.
  - If `want_vnet_hdr` is requested, `TUNSETOFFLOAD` is negotiated per queue.
  - Returns a vector of $N$ `TunTap` instances, transferred 1:1 to shard worker threads.

### 3.2 Lock-Free SPSC Inter-Shard Mailbox (`crates/yip-io` or `crates/yipd::shard_channel`)
Cross-shard communication uses a matrix of lock-free bounded SPSC ring buffers:
- **Topology**: For $N$ shards, a flat $N \times (N - 1)$ channel set is initialized before spawning worker threads.
- **Data Structure**:
  - Cache-line padded head and tail indices (`crossbeam_utils::CachePadded<AtomicUsize>`).
  - Ring buffer capacity is a power of two ($2048$ entries).
  - Memory footprint: $2048 \times 8\text{ bytes} \approx 16\text{ KB}$ per queue; total process queue overhead for 8 cores is $< 1\text{ MB}$.
- **Buffer Pool**:
  - Transfers ownership of pre-allocated `PacketBuf` instances between threads without heap reallocation or payload copying.

### 3.3 UDP `SO_REUSEPORT` Sockets
Each shard binds its own UDP socket to the node's configured listen address:
- `SO_REUSEPORT` enabled via `setsockopt`.
- Socket receive and send buffers raised to $4\text{ MiB}$ via `yip_io::set_socket_buffers`.
- Socket set to non-blocking.
- The Linux kernel automatically distributes incoming datagrams across the $N$ sockets via its 4-tuple hash.

---

## 4. Peer Assignment & Data Flow

### 4.1 Functional Peer-to-Shard Assignment
Peer assignment is deterministic and functional across all shards:
$$\text{shard\_index} = \text{jump\_consistent\_hash}(\text{blake2s}(K_{pub}), N)$$
- Evaluates in $\sim 5\text{ ns}$ with no cross-thread locks or coordination.
- Identical assignment outcome regardless of which shard calculates it.
- Dynamically discovered mesh peers (via gossip/rendezvous) map deterministically to their home shard.

### 4.2 Outbound Packet Flow (Host $\to$ Internet)
1. **TUN Read**: Shard $i$ reads an egress IP packet from its assigned TUN queue fd.
2. **Route Match**: Shard $i$ extracts the destination address (`fd00::...`) and calculates the home shard $k$ for the destination peer.
3. **Dispatch**:
   - **Local Path ($k == i$)**: Shard $i$ immediately processes the packet via `DataPlane::on_tun_packet` (Noise AEAD seal $\to$ Reed-Solomon FEC encode $\to$ framing $\to$ sendto via Shard $i$'s UDP socket).
   - **Cross-Shard Path ($k \neq i$)**: Shard $i$ deposits the `PacketBuf` into `SPSC[i -> k]`. If the queue is saturated, the packet is dropped (incrementing `stat_cross_shard_drops`).

### 4.3 Inbound Packet Flow (Internet $\to$ Host)
1. **UDP Ingest**: A datagram arrives on Shard $i$'s UDP socket via `SO_REUSEPORT`.
2. **Deframe**: Shard $i$ authenticates SipHash header protection and extracts the 8-byte `conn_tag` (or handshake header).
3. **Session Handling**:
   - **Home Shard Match**: Shard $i$ FEC-decodes, AEAD-decrypts, and writes the resulting plaintext directly to Shard $i$'s TUN queue fd.
   - **Mismatched Shard (e.g., roaming or rekey)**: If the `conn_tag` belongs to a peer registered on Shard $k$, Shard $i$ pushes the raw datagram to Shard $k$ via an inter-shard queue to ensure Shard $k$'s state machine stays coherent.

### 4.4 Shard Event Loop Structure
Each shard runs a non-blocking loop driving its local driver (`PollDriver` or `UringDriver`):
```rust
loop {
    // 1. Drain local UDP socket (batch up to 64 datagrams)
    drain_udp_socket(&mut udp_sock, &mut peer_manager);

    // 2. Drain local TUN queue (batch up to 64 packets)
    drain_tun_queue(&mut tun_queue, &mut outbox_channels, &mut peer_manager);

    // 3. Drain all incoming SPSC queues from sibling shards
    drain_spsc_inboxes(&mut spsc_rx_matrix, &mut peer_manager);

    // 4. Flush outgoing UDP datagrams & TUN writes
    flush_egress(&mut udp_sock, &mut tun_queue, &mut peer_manager);

    // 5. Periodic tick (timers, ARQ retransmission, rekey) every 10ms
    peer_manager.tick();
}
```

---

## 5. Resilience, Error Handling & Fallbacks

1. **Backpressure Policy**:
   - SPSC ring buffer overflows result in head/tail drops rather than blocking the sending shard.
   - Preserves low latency across all shards; TCP congestion control (BBR/Cubic) naturally responds to packet drops.
2. **Single-Queue / Single-Core Fallback**:
   - When configured with `shards = 1` or running on a single-vCPU instance, `yipd` falls back to the existing single-queue event loop.
3. **Kernel Capabilities**:
   - If `IFF_MULTI_QUEUE` is unsupported or fails (e.g. in certain restricted container runtimes), `yipd` logs a descriptive warning and falls back to single-queue mode.

---

## 6. Testing & Verification Plan

1. **Unit Tests**:
   - `crates/yip-device`: Verify `TunTap::create_multi_queue` opens $N$ valid fds, with bidirectional cross-queue write/read verification.
   - `crates/yip-io`: Verify SPSC ring buffer concurrent throughput, wraparound arithmetic, and overflow drop semantics.
2. **Integration Tests (Network Namespaces)**:
   - `tests/sharded_tunnel_test.rs`: Configure 2 nodes in netns with `shards = 4`.
   - Run multi-stream `iperf3` and verify even CPU core utilization across worker threads.
   - Verify lossless communication during live session rekeying under load.
3. **Performance Gate**:
   - Run `cargo run --release -p yip-bench --example sharding_scale` to confirm aggregate throughput scaling.
