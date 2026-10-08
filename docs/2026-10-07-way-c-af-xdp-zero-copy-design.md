# Way C: Kernel-Bypass Zero-Copy I/O Tier (AF_XDP) & WireGuard Parity Benchmarks Design Spec

**Date:** 2026-10-07
**Status:** Approved
**Tracking Issue:** [#127](https://github.com/femboyisp/yip/issues/127)
**Authors:** DeepMind Antigravity Pair Programmer & Zoa Hickenlooper

---

## 1. Overview & Objective

Building upon the successful completion of **Way A (Multi-Peer Engine Sharding)** and **Regime B / B+ (Single-Peer Multi-Core Pipeline & Vectorized I/O)**, `yip` scales across CPU cores up to 21.5 Gbps with 0 packet drops and 0 TCP reordering.

However, even with vectorized `recvmmsg`/`sendmmsg` batching, packets still transit through the Linux kernel's standard socket buffer subsystem (`sk_buff`), incurring kernel allocation overhead and memory copies between kernel and userspace memory spaces.

**Way C (AF_XDP Zero-Copy Driver)** introduces a high-performance kernel-bypass I/O tier for `yip`:
1. **Zero-Copy Memory Architecture**: Replaces kernel socket buffer allocations with pre-registered, page-aligned userspace memory rings (`UMEM`).
2. **Three-Tier Fallback Engine**: Probes for native hardware driver zero-copy (`XDP_ZERO_COPY`), falls back to kernel-managed copy mode (`XDP_COPY`) on virtual/cloud NICs, and cleanly drops back to vectorized `recvmmsg` batching if unprivileged or unsupported.
3. **In-Place Cryptography & Cauchy Reed–Solomon FEC**: Eliminates intermediate `Vec<u8>` copies by performing AEAD decryption and matrix Galois field decoding directly inside UMEM chunk boundaries.
4. **Live Kernel WireGuard Parity Benchmark**: Provides an end-to-end network namespace comparative benchmark suite measuring real Linux kernel WireGuard (`wg0`) vs `yipd` across throughput, packet rate, CPU context switches, and RTT latency percentiles (p50, p90, p99, p99.9) under variable loss conditions.

---

## 2. Global Constraints & Invariants

1. **Safety Isolation**:
   - `#![forbid(unsafe_code)]` remains strictly enforced across `bin/yipd`, `crates/yip-transport`, `crates/yip-crypto`, and `crates/yip-device`.
   - Low-level libc XSK/XDP structures (`sockaddr_xdp`, ring memory mapping, `mmap`) are quarantined strictly within `crates/yip-io/src/af_xdp.rs` with explicit `// SAFETY:` justifications on all unsafe blocks.
2. **Lock-Free Hot Path**:
   - Zero mutexes, spinlocks, or atomic bus locks on the packet processing fast path.
   - Nonces claimed in 64-unit blocks via `ChunkedNonceDispenser`.
3. **Zero TCP Packet Reordering**:
   - Monotonic FIFO delivery guaranteed for every inner 5-tuple flow using bidirectional symmetric flow pinning (`FlowTuple::symmetric_flow_hash`).
4. **Transparent Fallback**:
   - Absence of root privileges, BPF subsystem support, or AF_XDP drivers must never panic or crash `yipd`; fallback to standard vectorized socket I/O is automatic.

---

## 3. Architecture & Components

```
                      +---------------------------------------+
                      |       yip Worker Thread (Core N)      |
                      +---------------------------------------+
                           |                             ^
                [tx_ring]  | (zero-copy)      (zero-copy)|  [rx_ring]
                           v                             |
        +-------------------------------------------------------------+
        |                 UMEM Shared Memory Buffer                   |
        |  (Aligned 2048/4096-byte chunks: Frame Headers + Payload)    |
        +-------------------------------------------------------------+
              | [completion_ring]                     ^ [fill_ring]
              v                                       |
    +--------------------------------------------------------------------+
    |              Linux NIC Driver / XDP Hook (Queue N)                 |
    +--------------------------------------------------------------------+
```

### 3.1 `crates/yip-io/src/af_xdp.rs`: AF_XDP Driver Module

- **`UmemConfig` & `UmemPool`**:
  - Allocates anonymous, page-aligned memory via `libc::mmap(MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE)`.
  - Configures chunk size (default: 2048 bytes), chunk headroom (0 bytes), and ring sizes (default: 2048 descriptors).
  - Registers the memory region with `setsockopt(fd, SOL_XDP, XDP_UMEM_REG, ...)`.
  - Manages a pre-populated atomic or SPSC free-list of 64-bit UMEM chunk offsets.
- **Ring Buffer Descriptors (`XskRing`)**:
  - **`FillRing` (`XDP_UMEM_FILL_RING`)**: Producer ring where userspace places vacant chunk addresses for the NIC to deposit inbound packets.
  - **`RxRing` (`XDP_RX_RING`)**: Consumer ring where the kernel notifies userspace of received datagrams with descriptor `(addr, len, flags)`.
  - **`TxRing` (`XDP_TX_RING`)**: Producer ring where userspace enqueues sealed outbound wire frames for transmission.
  - **`CompletionRing` (`XDP_UMEM_COMPLETION_RING`)**: Consumer ring where the kernel returns transmitted chunk addresses for userspace buffer reclamation.
- **Socket Initialization (`XskSocket`)**:
  - Creates socket via `libc::socket(AF_XDP, SOCK_RAW, 0)`.
  - Binds to interface `ifindex` and queue `queue_id` with `XDP_ZERO_COPY` flags. If `ENOTSUPP` or `EINVAL` is returned, automatically retries with `XDP_COPY`.
  - Supports `XDP_USE_NEED_WAKEUP` flag to eliminate redundant kernel wakeups when driver rings are not starved.

### 3.2 In-Place Datapath Execution (`bin/yipd/src/sharding.rs`)

1. **Ingress Zero-Copy Path**:
   - Worker queries `rx_ring.poll_batch(batch_size)` without syscalls when rings are active.
   - Wire frame header (`conn_tag`, `object_id`) is decoded directly at `umem.chunk_slice(addr)`.
   - AEAD frame decryption reads ciphertext from UMEM chunk and writes plaintext into either the TUN write buffer or an adjacent UMEM chunk using `open_into_with_window`.
   - Free chunk address is pushed back to `fill_ring`.
2. **Egress Zero-Copy Path**:
   - Outbound packet arrives on multi-queue TUN.
   - Worker reserves chunk address from UMEM free pool.
   - Nonce dispensed with 0 atomics from local chunk window.
   - Packet sealed directly into UMEM chunk memory via `seal_into_with_counter`.
   - Descriptor appended to `tx_ring`. If `tx_ring.needs_wakeup()`, calls `libc::sendto(xsk_fd, ...)` to kick the NIC.

---

## 4. Live WireGuard Parity Benchmarking Suite

### 4.1 Topology & Setup (`bin/yipd/tests/run-netns-wireguard-comp.sh`)

Configures two network namespaces (`NS_A` and `NS_B`) connected by a pair of virtual ethernet interfaces (`veth_a` $\leftrightarrow$ `veth_b`):
- **Base Network**: `10.44.0.0/24`.
- **WireGuard Interface**: `wg0` (`10.88.0.1` and `10.88.0.2`), configured via `ip link add dev wg0 type wireguard`, standard WireGuard keypair, and `wg set wg0`.
- **`yip` Interface**: `yip0` (`10.99.0.1` and `10.99.0.2`), running release `yipd` with multi-core sharding and AF_XDP.

### 4.2 Benchmark Workloads & Metrics

1. **Multi-Stream TCP Throughput (`iperf3`)**:
   - Streams: 1, 4, 8, 16 concurrent TCP flows.
   - Duration: 10 seconds per run.
   - Comparison: Aggregate Gbit/s and CPU utilization.
2. **Loss Recovery & Jitter Injection (`tc qdisc add ... netem`)**:
   - Link configuration: 10 ms RTT baseline delay with 0%, 1%, and 5% simulated random loss.
   - Metric: TCP goodput retention and ICMP RTT latency percentiles (p50, p90, p99, p99.9).
   - Expected outcome: Under 5% loss, WireGuard TCP throughput collapses due to packet drops and congestion window reduction, while `yip`'s Cauchy Reed–Solomon FEC maintains flat p99 and sustained line rate.
3. **Packet Forwarding Rate (`sockperf` / `pktgen`)**:
   - Measures maximum packets per second (Mpps) for 64-byte small frames.

---

## 5. Non-Root Workspace Microbenchmark (`benches/af_xdp_scale.rs`)

For unprivileged CI and continuous regression testing:
- Implements a simulated UMEM ring memory pipeline without requiring `CAP_NET_ADMIN`.
- Exercises chunk allocation, in-place zero-copy AEAD seal/open, Cauchy Reed–Solomon matrix operations, and multi-threaded scaling across 1, 2, 4, 8 worker cores.
- Asserts strict monotonic sequence delivery and 0 drops.

---

## 6. Implementation Plan & Sequencing

1. **Task 1: UMEM Memory Allocator & Ring Descriptors (`crates/yip-io`)**:
   - Implement page-aligned `UmemPool` with `FillRing` and `CompletionRing`.
   - Unit tests for chunk free-list management and circular ring operations.
2. **Task 2: AF_XDP Socket & Three-Tier Fallback (`crates/yip-io`)**:
   - Implement `XskSocket` with `RxRing` and `TxRing`.
   - Probing and fallback logic (`XDP_ZERO_COPY` $\to$ `XDP_COPY` $\to$ `BatchUdpSocket`).
3. **Task 3: Worker Datapath Zero-Copy Wiring (`bin/yipd/src/sharding.rs`)**:
   - Integrate AF_XDP rings into worker event loop.
   - In-place AEAD seal and open directly in UMEM buffers.
4. **Task 4: Non-Root Scaling Benchmark (`crates/yip-bench/benches/af_xdp_scale.rs`)**:
   - Verify ring buffer processing latency and multi-core scaling.
5. **Task 5: End-to-End Live WireGuard Parity Netns Benchmark (`run-netns-wireguard-comp.sh`)**:
   - Comparative test harness comparing `yipd` vs kernel `wg0`.
6. **Task 6: Documentation & Issue Management**:
   - Update `README.md`, `CHANGELOG.md`, `RESULTS.md`.
