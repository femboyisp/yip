# Regime F Design Specification: Line-Rate Offload, Rateless RLNC & Kernel-Bypass Acceleration

**Status:** Approved
**Author:** AI Pair Programmer & zoa
**Date:** 2026-10-08
**Scope:** `crates/yip-transport`, `crates/yip-io`, `bin/yipd`, `crates/yip-bench`

---

## 1. Executive Summary & Goals

Regime E achieved 61x faster Galois Field vector math with Intel GFNI instructions (33.1 ns / 362 Gbps), scaled the multi-core UMEM pipeline to 29.2 Gbps across 8 cores, and introduced single-peer worker sharding with stride nonces. However, live network namespace testing identified two key throughput and resilience frontiers:

1. **Multi-Queue ARQ Feedback Disconnect**: Under channel packet loss (1% or 5%), incoming `Control::LossFeedback` packets were steered by outer UDP hashes to worker shards other than the one that originally encoded the FEC object. Because `RetxBuffer` was local to each worker shard, the receiving shard had no record of the missing object, preventing repair emissions and causing throughput to collapse under loss.
2. **Userspace TUN Context-Switch Bottleneck**: Reading and writing standard 1500-byte packets over `/dev/net/tun` required over 820,000 system calls per second at 10 Gbps, limiting live clean-channel TCP goodput to 0.57–1.05 Gbps compared to Linux kernel WireGuard's 2.76 Gbps.
3. **Fixed-Block Boundary Latency**: While Cauchy Reed–Solomon is fast (1.71 µs block encoding), fixed $(K, R)$ blocks require block-boundary synchronization, causing micro-jitter when packet losses exceed $R$ symbols.

**Regime F delivers four unified breakthroughs**:
- **Cross-Shard ARQ Feedback Routing**: Deterministic routing of `Control::LossFeedback` packets to the originating encoder shard (`shard_for_fec_symbol`) via high-priority lock-free SPSC channels, restoring full 5.3x loss recovery and 0% net TCP drops in multi-queue mode.
- **TUN Line-Rate Offload (GSO / GRO + `io_uring`)**: Configuring `virtio_net_hdr` (`TUNSETVNETHDR`) to pass 64 KB TCP super-packets between the Linux kernel and `yipd` (reducing syscalls by up to 40x), paired with batched `io_uring` submission/completion rings (32–64 packets per pass) to surpass kernel WireGuard's 2.76 Gbps baseline.
- **Poly-Vector Rateless RLNC Engine**: Streaming Random Linear Network Coding over $GF(2^8)$ in `crates/yip-transport` with SIMD-accelerated incremental Gaussian elimination, eliminating block-boundary synchronization stalls.
- **WASM SIMD128 & Dual-Stack Outer IPv6 eBPF**: 128-bit WASM SIMD (`v128`) nibble shuffle vectorization for web/edge targets, and expanded dual-stack (IPv4 + IPv6) eBPF XDP filter bytecode for hardware RSS steering on modern cloud backbones.

---

## 2. System Architecture & Component Interaction

```
                      Linux Kernel Network Stack
                     ┌──────────────────────────┐
                     │       /dev/net/tun       │
                     │  (GSO / IFF_VNET_HDR)    │
                     └─┬──────────┬──────────┬──┘
                       │          │          │
                 64 KB Super-Pkts │          │ (40x Fewer Syscalls)
                       │          │          │
              ┌────────▼──────────▼──────────▼────────┐
              │ Worker 0         Worker 1    Worker N │
              │ (Handshake)                           │
              │                                       │
              │ Stride Nonces    Stride Nonces        │
              │ Rateless RLNC / Cauchy RS Engine      │
              │ AutoTunedPoller (10..200 µs EWMA)     │
              │                                       │
              │ [Cross-Shard SPSC ARQ Routing Matrix] │
              └────────┬──────────┬──────────┬────────┘
                       │          │          │
                 Batch Ring       │          │
                       │          │          │
              ┌────────▼──────────▼──────────▼────────┐
              │ AF_XDP Rings / io_uring Batch Sockets │
              │ Dual-Stack IPv4 / IPv6 eBPF Filter    │
              │ Hardware NIC RSS Symmetric Steering   │
              └───────────────────────────────────────┘
```

---

## 3. Cross-Shard ARQ Routing & Unified Retransmit Coordination (`bin/yipd`)

### 3.1 Problem Analysis
In multi-queue operation, worker shard $i$ owns an independent `DataPlane` with its own `RetxBuffer` and `FecEncoder`. When worker $i$ transmits an FEC object $(conn\_tag, object\_id)$, the unsealed source packets are buffered in worker $i$'s `RetxBuffer`.
When the receiver observes lost symbols, it emits an unmasked `Control::LossFeedback` datagram. Under socket load-balancing or RSS steering, this datagram often arrives on worker $j \ne i$. Worker $j$ checks its own `RetxBuffer`, finds no entry for $(conn\_tag, object\_id)$, and drops the feedback, causing the connection to stall under packet loss.

### 3.2 Deterministic ARQ Demuxing & Dispatch
1. **Header Inspection on UDP Ingress**:
   When worker $k$ receives an unauthenticated UDP datagram with byte 0 matching `PacketType::Control as u8`:
   - It decodes the control frame header to extract the 8-byte `conn_tag` and 2-byte `object_id`.
   - It computes the target shard index:
     $$\text{target\_shard} = \text{shard\_for\_fec\_symbol}(\text{conn\_tag}, \text{object\_id}, \text{num\_shards})$$
2. **Local vs SPSC Matrix Routing**:
   - If $\text{target\_shard} == k$: worker $k$ immediately processes the feedback via `manager.on_udp_control(...)`, retrieving buffered symbols from its local `RetxBuffer` and emitting repair symbols.
   - If $\text{target\_shard} \ne k$: worker $k$ enqueues the datagram into the lock-free SPSC channel directed to $\text{target\_shard}$:
     ```rust
     pub enum ShardMsg {
         Packet(Vec<u8>),
         SessionEpoch(SessionEpochMsg),
         HandshakeForward(Vec<u8>, std::net::SocketAddr),
         ArqFeedback(Vec<u8>, std::net::SocketAddr),
     }
     ```
3. **Guaranteed Repair Emission**:
   Worker $\text{target\_shard}$ drains its SPSC inbox, executes `manager.on_udp_control(...)`, generates repair packets using GFNI/AVX-512 SIMD, and transmits them directly to the remote peer's endpoint.
   This guarantees that 100% of loss feedback requests reach the shard holding the original symbols.

---

## 4. TUN Line-Rate Offload: GSO / GRO & Batched `io_uring` (`crates/yip-io`, `bin/yipd`)

### 4.1 Generic Segmentation Offload (GSO / GRO)
To break the 1 Gbps barrier over `/dev/net/tun`, `yipd` enables Linux Generic Segmentation Offload via `IFF_VNET_HDR`:
- `ioctl(tun_fd, TUNSETVNETHDR, &12)` enables the 12-byte `struct virtio_net_hdr` prefix:
  ```rust
  #[repr(C)]
  #[derive(Debug, Clone, Copy, Default)]
  pub struct VirtioNetHdr {
      pub flags: u8,
      pub gso_type: u8,
      pub hdr_len: u16,
      pub gso_size: u16,
      pub csum_start: u16,
      pub csum_offset: u16,
  }
  ```
- **Egress Path (TUN $\to$ Wire)**:
  - The Linux kernel passes aggregated TCP super-packets up to 64 KB in a single read buffer.
  - `gso_size` indicates MSS (e.g. 1420 bytes).
  - Worker threads slice the 64 KB payload into MTU-sized segments, assign sequential stride nonces, apply Poly-Vector FEC, and burst packets via batch UDP sockets or AF_XDP.
  - Reduces read syscall frequency by **up to 40x**.
- **Ingress Path (Wire $\to$ TUN)**:
  - Ingress packets belonging to the same flow are coalesced into a GRO super-packet with `gso_type = VIRTIO_NET_HDR_GSO_TCPV4` (or `TCPV6`).
  - A single write syscall delivers up to 64 KB directly into the kernel TCP stack.

### 4.2 Batched `io_uring` Ring Driver
In `crates/yip-io/src/uring.rs`:
- Implements submission (SQ) and completion (CQ) rings with 64-entry power-of-two capacities.
- Workers batch up to 32 read/write operations per submission, calling `io_uring_enter` to submit and harvest completions in a single pass.
- **Fail-Soft Portability**: Probes `io_uring_setup`. If running in unprivileged containers or kernels without `io_uring`, degrades cleanly to non-blocking epoll.

---

## 5. Poly-Vector Rateless RLNC Engine & WASM SIMD128 (`crates/yip-transport`)

### 5.1 Streaming Random Linear Network Coding Architecture
In `crates/yip-transport/src/rlnc.rs`:
- **Sliding Source Window**:
  Maintains an active sliding window of $W$ source packets ($W \in \{8, 16, 32\}$).
- **Rateless Linear Combination Encoding**:
  When emitting repair symbols, the encoder draws pseudorandom coefficients $c_1, \dots, c_W \in GF(2^8)$ derived from a 32-bit PRNG seed transmitted in the symbol header:
  $$C = \bigoplus_{i=1}^W c_i \cdot S_i$$
  Computed via vectorized `mul_add_row` (33.1 ns with GFNI, 35.6 ns with AVX2).
- **Incremental Gaussian Elimination Decoding**:
  - The decoder maintains an upper-triangular echelon matrix of size $W \times (W + L)$ where $L$ is symbol payload length.
  - Upon receiving coded symbol $(\mathbf{c}, C)$, it eliminates pivot columns against existing rows:
    $$\text{Row}_j \longleftarrow \text{Row}_j \oplus (\lambda \cdot \text{Row}_i)$$
  - When the submatrix reaches full rank ($W$), all $W$ source packets are resolved simultaneously.
  - **Zero Block Boundaries**: Eliminates head-of-line blocking and block-boundary stalls under bursty channel loss.

### 5.2 WASM SIMD128 Vector Acceleration
In `crates/yip-transport/src/rs_simd.rs`:
- Supports `target_arch = "wasm32"` using 128-bit `v128` types and `i8x16_shuffle`:
  ```rust
  #[cfg(target_arch = "wasm32")]
  pub unsafe fn mul_add_wasm128(coeff: u8, src: &[u8], dst: &mut [u8]) {
      // 16 bytes per chunk using i8x16_shuffle nibble table lookups
  }
  ```
- Brings 30–40x vector speedup to browser and WebAssembly runtimes.

---

## 6. Outer IPv6 eBPF Hardware RSS Steering (`crates/yip-io`)

### 6.1 Dual-Stack XDP Redirect Bytecode
In `crates/yip-io/src/bpf.rs`:
The minimal 20-instruction eBPF XDP filter is expanded to 28 instructions to support dual-stack outer UDP packets:
```c
// Dual-stack packet inspection
if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if (udp->dest == htons(listen_port))
            return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
    }
} else if (eth->h_proto == htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip6 + 1);
        if (udp->dest == htons(listen_port))
            return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
    }
}
return XDP_PASS;
```
- Hardware NIC RSS automatically distributes incoming IPv6 UDP datagrams across hardware queues based on IPv6 5-tuple flow hashes.
- `bpf_redirect_map` routes directly into the worker shard pinned to `ctx->rx_queue_index`.

---

## 7. Verification, Benchmarking & Parity Suite

1. **Unit & Differential Tests**:
   - `crates/yip-transport/tests/rlnc_test.rs`: Exhaustive tests of RLNC encoding, incremental Gaussian elimination, and rank-deficiency recovery under loss.
   - `crates/yip-transport/tests/rs_simd_test.rs`: WASM SIMD128 parity tests against scalar reference.
   - `bin/yipd/tests/sharded_ordering_test.rs`: Multi-queue ARQ feedback routing test verifying `ShardMsg::ArqFeedback` delivery across worker threads.
   - `crates/yip-io/tests/bpf_test.rs`: Dual-stack IPv4 and IPv6 bytecode verifier tests.
2. **Microbenchmarks (`crates/yip-bench`)**:
   - `rlnc_bench.rs`: Measure RLNC encoding/decoding ns/packet and Gbps throughput across window sizes $W \in \{8, 16, 32\}$.
   - `single_flow_scale.rs` & `af_xdp_scale.rs`: Multi-core scaling benchmarks with GSO enabled.
3. **Live Netns Head-to-Head Parity Benchmark (`run-netns-wireguard-comp.sh`)**:
   - Multi-queue `shards = 4` evaluated across 0%, 1%, and 5% loss.
   - **Target 0% Loss**: Surpass Linux kernel WireGuard's 2.76 Gbps baseline using GSO super-packets (targeting 3–5+ Gbps).
   - **Target 5% Loss**: Sustain $\ge 0.80$ Gbps goodput (5.3x higher than WireGuard) with 0% net TCP drops via cross-shard ARQ routing.

---

## 8. Safety, Invariants & Constraints

- `#![forbid(unsafe_code)]` preserved strictly across `bin/yipd`, `crates/yip-crypto`, and `crates/yip-device`.
- All `unsafe` blocks strictly quarantined in `crates/yip-transport` and `crates/yip-io`, each with clear `// SAFETY:` justifications.
- Pure Rust zero-external-C dependency philosophy maintained.
- Fail-soft graceful degradation on unsupported hardware or unprivileged container environments.
