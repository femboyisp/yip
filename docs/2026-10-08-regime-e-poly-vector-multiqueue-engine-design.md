# Regime E Design Specification: Unified Poly-Vector Engine & Dynamic Multi-Queue Sharding

**Status:** Approved
**Author:** AI Pair Programmer & zoa
**Date:** 2026-10-08
**Scope:** `crates/yip-transport`, `crates/yip-io`, `bin/yipd`, `crates/yip-bench`

---

## 1. Executive Summary & Goals

Regime D achieved 40.27 Gbps in synthetic multi-core microbenchmarks and accelerated Cauchy Reed–Solomon operations by 51.28x using AVX2. However, two architectural bottlenecks constrain real-world throughput and platform reach:

1. **Platform-Restricted SIMD Acceleration**: FEC Galois field acceleration was restricted to x86_64 AVX2, leaving ARM64 (AWS Graviton, Apple Silicon, Raspberry Pi 5) on pure-Rust scalar, and leaving high-end x86_64 servers (with AVX-512BW and hardware GFNI silicon instructions) under-utilized.
2. **Single-Peer Multi-Queue Serialization**: `bin/yipd` partitioned peers strictly by `shard_for_pubkey`. For a single point-to-point peer connection carrying multi-stream traffic (e.g., 4 iperf3 TCP streams), only 1 worker shard held the peer session; the remaining shards had empty peer tables. Packets distributed across multi-queue TUN descriptors were forced through SPSC queues into the single owner shard, bottlenecking encryption, decryption, and socket I/O on a single CPU core.
3. **Fixed Busy-Poll Latency Penalties**: The static 50 µs spin window either wastes cycles during low-load periods or sleeps too quickly under high-jitter network arrivals (80–120 µs inter-arrival bursts), inducing 1.5–3.5 µs sleep/wakeup spikes.

**Regime E delivers three unified breakthroughs**:
- **Unified Poly-Vector Galois Field Engine**: Tiered runtime SIMD dispatch covering hardware GFNI silicon affine instructions (`_mm512_gf2p8affine_epi64_epi8` / `_mm256_gf2p8affine_epi64_epi8`), AVX-512BW (64 B/cycle), AVX2 (32 B/cycle), SSSE3 (16 B/cycle), ARM64 NEON (`vqtbl1q_u8`), and pure-Rust scalar fallback.
- **Multi-Queue Ingress/Egress eBPF Driver**: Fully populate `BPF_MAP_TYPE_XSKMAP` across hardware queues $0..N$, steering symmetric 5-tuple inner flows directly to core-pinned AF_XDP rings in hardware.
- **Single-Peer Multi-Queue TUN Worker Sharding & Dynamic Auto-Tuned Busy-Polling**: Anchor handshakes on Shard 0 with lock-free session epoch replication across worker shards, collision-free stride nonces, independent per-shard replay windows, and an auto-tuned busy-poller dynamically scaling the spin window between 10 µs and 200 µs based on observed packet arrival jitter.

---

## 2. Architecture & Component Interaction

```
                        Linux Kernel Network Stack
                       ┌─────────────────────────┐
                       │      /dev/net/tun       │
                       │    (IFF_MULTI_QUEUE)    │
                       └─┬─────────┬─────────┬───┘
                         │         │         │
                   Queue 0       Queue 1   Queue N
                         │         │         │
                ┌────────▼─────────▼─────────▼────────┐
                │ Worker 0        Worker 1   Worker N │
                │ (Anchor / Rekey)                    │
                │                                     │
                │ Nonce = 0,N..   Nonce=1,N+1 Nonce=2 │ (Stride N)
                │ Poly-Vector FEC Engine              │
                │ (GFNI / AVX-512 / AVX2 / NEON)      │
                │ AutoTunedPoller (10..200 µs EWMA)   │
                └────────┬─────────┬─────────┬────────┘
                         │         │         │
                   Queue 0       Queue 1   Queue N
                         │         │         │
                ┌────────▼─────────▼─────────▼────────┐
                │ AF_XDP UMEM Rings / Batch Sockets   │
                │ Multi-Queue BPF_MAP_TYPE_XSKMAP     │
                │ Hardware NIC RSS Symmetric Steering │
                └─────────────────────────────────────┘
```

---

## 3. Poly-Vector SIMD Core (`crates/yip-transport`)

### 3.1 Tiered SIMD Dispatch Hierarchy
At runtime, `crates/yip-transport/src/rs_simd.rs` detects available CPU vector instruction sets using cached atomic detection flags:

$$\text{GFNI} \longrightarrow \text{AVX-512BW} \longrightarrow \text{AVX2} \longrightarrow \text{SSSE3} \longrightarrow \text{ARM64 NEON} \longrightarrow \text{Pure-Rust Scalar}$$

```rust
pub fn mul_add_row(coeff: u8, src: &[u8], dst: &mut [u8]) {
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
        return;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if gfni_supported() {
            unsafe { mul_add_gfni(coeff, src, dst) };
            return;
        }
        if avx512bw_supported() {
            unsafe { mul_add_avx512(coeff, src, dst) };
            return;
        }
        if avx2_supported() {
            unsafe { mul_add_avx2(coeff, src, dst) };
            return;
        }
        if ssse3_supported() {
            unsafe { mul_add_ssse3(coeff, src, dst) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if neon_supported() {
            unsafe { mul_add_neon(coeff, src, dst) };
            return;
        }
    }

    crate::gf256::mul_slice_into(dst, src, coeff);
}
```

### 3.2 GFNI Hardware Silicon Acceleration
Processors supporting Intel GFNI (e.g., Ice Lake, Alder Lake, Sapphire Rapids, Tremont, Sierra Forest) contain dedicated execution units computing Galois Field affine transformations in $GF(2^8)$:
- `_mm512_gf2p8affine_epi64_epi8(x, A, 0)` computes $x \cdot A$ for eight 64-bit blocks simultaneously in a single clock cycle.
- The 8x8 bit-matrix $A$ represents multiplication by `coeff` over $GF(2^8)$ under polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (0x11d).
- Column $j$ of matrix $A$ is given by $\text{coeff} \cdot 2^j \pmod{P(x)}$.
- Processing executes at 64 bytes per cycle with zero memory table lookup overhead.

### 3.3 AVX-512BW 64-Byte Nibble-Shuffle
For systems with AVX-512BW but without GFNI:
- Precomputes 16-entry low and high nibble tables for `coeff`, broadcast across 512-bit ZMM registers (`_mm512_broadcast_i32x4` / `_mm512_set1_epi64`).
- Processes 64 bytes per iteration using `_mm512_shuffle_epi8`.
- Doubles the throughput of AVX2 from 32 bytes to 64 bytes per instruction cycle.

### 3.4 SSSE3 16-Byte Nibble-Shuffle
For older x86_64 hardware without AVX2:
- Utilizes `_mm_shuffle_epi8` with 128-bit XMM registers.
- Processes 16 bytes per cycle, accelerating older CPUs and hypervisors lacking AVX2 passthrough.

### 3.5 ARM64 NEON Table Lookup (`vqtbl1q_u8`)
For ARM64 platforms (AWS Graviton2/3/4, Apple Silicon M1-M4, Raspberry Pi 5):
- Precomputes 16-byte low and high lookup tables:
  $$T_{lo}[b] = \text{mul}(\text{coeff}, b), \quad T_{hi}[b] = \text{mul}(\text{coeff}, b \ll 4)$$
- Employs `vqtbl1q_u8` on 128-bit NEON registers (`uint8x16_t`):
  1. Mask lower nibbles: `vlandq_u8(chunk, vdupq_n_u8(0x0f))`
  2. Shift upper nibbles: `vshrq_n_u8(chunk, 4)`
  3. Parallel table lookups: `vqtbl1q_u8(t_lo, lo_idx)` and `vqtbl1q_u8(t_hi, hi_idx)`
  4. Bitwise XOR and accumulate: `veorq_u8` into destination.
- Brings 50x FEC performance to ARM cloud instances and edge nodes.

---

## 4. Multi-Queue Ingress/Egress eBPF Driver (`crates/yip-io`)

### 4.1 BPF_MAP_TYPE_XSKMAP Multi-Queue Topology
Currently, `XdpRedirectFilter` attaches to a single queue ID. In Regime E:
- The map is dimensioned for all active hardware RX/TX queues on the interface:
  $$\text{max\_entries} = \min(N_{\text{shards}}, N_{\text{hardware\_queues}})$$
- Method `set_socket_for_queue(queue_id: u32, xsk_fd: RawFd) -> io::Result<()>` populates all queue indices $0..N-1$.

### 4.2 Symmetric Flow Steering Bytecode
The in-kernel eBPF bytecode is enhanced to compute symmetric 5-tuple flow hashing:
```c
// Pseudo-eBPF packet inspection
if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *ip = data + sizeof(*eth);
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if (udp->dest == htons(listen_port)) {
            // Read inner flow hash or RSS queue index
            __u32 queue_index = ctx->rx_queue_index;
            return bpf_redirect_map(&xsk_map, queue_index, 0);
        }
    }
}
return XDP_PASS;
```
- Hardware RSS steers outer flows to queue index `ctx->rx_queue_index`.
- `bpf_redirect_map` routes directly into the worker shard pinned to that queue, eliminating cross-core migrations.
- If unprivileged, falls back cleanly to `BpfFilterStatus::FallbackUnprivileged`.

---

## 5. Single-Peer Multi-Queue TUN Worker Sharding (`bin/yipd`)

### 5.1 The Root Cause of Single-Peer Throughput Bottlenecks
In Regime D:
- Peers were partitioned across worker shards via `shard_for_pubkey`.
- In a point-to-point tunnel with 1 peer, Shard $K$ held the peer and Shards $0..N-1 \setminus \{K\}$ had empty peer tables.
- All packets across multi-queue TUN descriptors were pushed across SPSC channels to Shard $K$.
- Shard $K$ alone performed 100% of AEAD crypto and socket writes, capping throughput at a single core's CPU limit.

### 5.2 Lock-Free Symmetric Session Replication
1. **Shard 0 as Handshake / Control Anchor**:
   - Shard 0 handles all Noise protocol handshakes (`Initiation`, `Response`, `CookieReply`), rekeying timers, and rendezvous gossip.
   - Any worker receiving a handshake packet forwards it to Shard 0 via high-priority SPSC channel.
2. **Session Epoch Broadcast**:
   - Upon handshake completion or rekey, Shard 0 broadcasts the negotiated `SessionEpoch` (keys, local index, peer index) to all worker shards via lock-free SPSC channels.
   - All worker shards install the session in parallel with zero locks.
3. **Lock-Free Stride Nonce Allocation for Egress**:
   - For egress encryption, worker shard $i \in [0, N-1]$ increments its nonce counter by stride $N$:
     $$\text{worker\_nonce}_i \leftarrow \text{worker\_nonce}_i + N$$
   - Worker 0: $0, N, 2N, 3N\dots$
   - Worker 1: $1, N+1, 2N+1, 3N+1\dots$
   - Worker $i$: $i, N+i, 2N+i, 3N+i\dots$
   - **Guarantees**: Zero atomic instructions on fast path, zero cache-line bouncing across CPU cores, and mathematical impossibility of nonce collisions.
4. **Per-Shard Sliding Replay Window on Ingress**:
   - Ingress packets of a given TCP flow are steered to the same worker shard by symmetric flow hashing.
   - Each worker maintains an independent `SlidingReplayWindow`, processing packets and writing decrypted frames directly into its own `/dev/net/tun` queue descriptor (`tun_queues[shard_id]`).
   - The Linux kernel netstack handles out-of-order reassembly across queues seamlessly.

### 5.3 Dynamic Auto-Tuned Busy-Polling (`AutoTunedPoller`)
Eliminates latency jitter under varying arrival patterns by tracking packet inter-arrival statistics:
- **Inter-Arrival Jitter Tracking**:
  - For each packet batch, calculates $\Delta t = t_k - t_{k-1}$.
  - Computes EWMA and Mean Absolute Deviation (Jitter):
    $$\text{EWMA} \leftarrow (1 - \alpha) \cdot \text{EWMA} + \alpha \cdot \Delta t \quad (\alpha = 0.125)$$
    $$\text{Jitter} \leftarrow (1 - \beta) \cdot \text{Jitter} + \beta \cdot |\Delta t - \text{EWMA}| \quad (\beta = 0.25)$$
- **Adaptive Spin Window Clamping**:
  $$W_{\text{spin}} = \text{clamp}(\text{EWMA} + 2 \cdot \text{Jitter}, \; 10\,\mu\text{s}, \; 200\,\mu\text{s})$$
- **Hysteresis & Yield Transitions**:
  - While idle time $< W_{\text{spin}}$: busy-polls with `std::hint::spin_loop()` and `poll(0)`.
  - When idle time $> 2 \cdot W_{\text{spin}}$: yields to `epoll_wait(10)` to preserve CPU cycles and thermal budget.

---

## 6. Verification, Benchmarking & Parity Suite

### 6.1 Differential Test Suite
- `crates/yip-transport/tests/rs_simd_test.rs`: Exhaustive testing across all 256 Galois field coefficients ($c \in 0..255$) and varied buffer sizes ($0..65536$ bytes), asserting exact bit-for-bit parity across GFNI, AVX-512BW, AVX2, SSSE3, NEON, and Scalar.
- `crates/yip-io/tests/bpf_test.rs`: Multi-queue map insertion and fallback verification.
- `bin/yipd/tests/sharded_ordering_test.rs`: Stride nonce monotonicity, collision absence, and `AutoTunedPoller` jitter adaptation tests.

### 6.2 Performance Microbenchmarks (`crates/yip-bench`)
- `rs_simd_bench.rs`: Tiered SIMD comparison reporting ns/packet and Gbps across all available CPU architectures.
- `single_flow_scale.rs`: Multi-core scaling with stride nonces and multi-queue ring processing.

### 6.3 End-to-End Netns Parity Benchmark (`run-netns-wireguard-comp.sh`)
- Updated to run with `shards = 4` (or available host hardware cores).
- Multi-stream TCP (`iperf3 -P 4`) evaluated across:
  - 0% loss (baseline throughput)
  - 1% loss (moderate network impairment)
  - 5% loss (severe packet loss / wireless impairment)
- Verifies multi-gigabit line-rate goodput across multi-queue TUN interfaces.

---

## 7. Safety, Constraints & Compatibility

- **Unsafe Quarantining**: `#![forbid(unsafe_code)]` remains strictly enforced across `bin/yipd`, `crates/yip-crypto`, and `crates/yip-device`. All SIMD intrinsics and libc calls are strictly quarantined inside `crates/yip-transport` and `crates/yip-io`.
- **Explicit Safety Invariants**: Every `unsafe` block must carry a descriptive `// SAFETY:` comment verifying pointer validity, memory alignment, slice bounds, and CPU feature safety.
- **Graceful Degradation**: Zero hard panics on unsupported architectures or unprivileged user environments. System transparently falls back through vector tiers down to pure-Rust scalar and batch sockets.
