# Regime D: Zero-Overhead Ultra-Low Latency & Line-Rate Acceleration Design Spec

- **Author**: Antigravity & Pair Programming Engineer
- **Date**: 2026-10-08
- **Status**: Approved
- **Target Branch**: `feat/multicore-sharding`
- **Target Crates**: `crates/yip-transport`, `crates/yip-io`, `bin/yipd`, `crates/yip-bench`

---

## 1. Executive Summary & Goals

Following the delivery of **Regime B+** (vectorized batching, symmetric flow pinning, FEC affinity) and **Way C** (kernel-bypass AF_XDP zero-copy engine hitting 35.21 Gbps / 3.44 Mpps and outperforming kernel WireGuard by 4.1x under loss), **Regime D** tackles the remaining microsecond-level latency overheads and CPU cycles across three core architectural vectors:

1. **Vectorized SIMD Reed–Solomon Codec (`crates/yip-transport`)**:
   - Accelerates Cauchy Reed–Solomon matrix multiplications over $GF(2^8)$ using 256-bit AVX2 nibble shuffle lookup tables (`_mm256_shuffle_epi8` / `vpshufb`).
   - Slashes per-packet FEC encode/decode compute from **~1,300 ns to < 200 ns** with runtime CPU feature detection (`std::is_x86_feature_detected!("avx2")`) and pure-Rust scalar fallback.
2. **Native Kernel eBPF XDP Steering Program (`crates/yip-io`)**:
   - Implements a self-contained, minimal eBPF XDP filter loaded via direct `bpf(BPF_PROG_LOAD)` and attached to the network interface.
   - Filters tunnel UDP datagrams on the destination port and executes `XDP_REDIRECT` directly into `BPF_MAP_TYPE_XSKMAP` at the NIC driver layer, bypassing `sk_buff` allocation and the kernel network stack completely.
   - Clean, transparent fallback to generic driver socket paths when unprivileged or when `CAP_BPF` is unavailable.
3. **Adaptive Dynamic Busy-Polling Loop (`bin/yipd`)**:
   - Replaces static `epoll_wait` yielding on active flows with a hysteresis-based spin-polling window (`YIP_BUSY_POLL_US`, default 50 µs).
   - Eliminates kernel scheduler wakeup latency (~1.5–3.5 µs) under active traffic bursts while automatically falling back to low-power `epoll_wait` when the VPN connection is idle.

---

## 2. Architectural Invariants & Safety Model

1. **Language & Memory Safety**:
   - `#![forbid(unsafe_code)]` remains strictly enforced in `bin/yipd`, `crates/yip-crypto`, `crates/yip-device`, and `crates/yip-wire`.
   - All `unsafe` blocks are quarantined within `crates/yip-io` (for BPF syscalls and low-level socket FFI) and `crates/yip-transport` (for target-feature SIMD intrinsics).
   - Every single `unsafe` block must carry an explicit, descriptive `// SAFETY:` justification detailing pointer provenance, memory bounds, alignment, and CPU feature safety.
2. **Deterministic Monotonicity & Zero-Drop Guarantee**:
   - Bidirectional symmetric flow hashing guarantees that forward TCP data and reverse ACKs are pinned to the identical worker core, maintaining strict monotonic FIFO ordering (0 TCP reordering).
   - Ring descriptor capacities remain strictly power-of-two, using bitwise mask indexing (`& (capacity - 1)`) to handle monotonic counter wrap-around past `u32::MAX`.
3. **Pure-Rust Zero-C-Dependency Build**:
   - No external C dependencies (`libbpf`, `clang`, `llvm`, or `dpdk`) are required to build or run `yipd`. The eBPF program is assembled into pre-compiled bytecode instructions embedded directly in Rust source.

---

## 3. Component Architecture & Data Flow

```
                             [ Physical NIC DMA ]
                                      │
                                      ▼
                      ┌────────────────────────────────┐
                      │  Kernel eBPF XDP Driver Hook   │
                      │   (crates/yip-io/src/bpf.rs)   │
                      └───────────────┬────────────────┘
                                      │
                         Match port?  ├─── No ────► [ Linux Network Stack / sk_buff ]
                                      │
                                     Yes: XDP_REDIRECT
                                      ▼
                      ┌────────────────────────────────┐
                      │    AF_XDP UMEM Chunk Rings     │
                      │  (crates/yip-io/src/af_xdp.rs) │
                      └───────────────┬────────────────┘
                                      │
                                      ▼
                      ┌────────────────────────────────┐
                      │    Adaptive Hybrid Poller      │
                      │   (bin/yipd/src/sharding.rs)   │
                      │  • Zero-syscall spin-poll      │
                      │  • Hysteresis epoll fallback   │
                      └───────────────┬────────────────┘
                                      │
                                      ▼
                      ┌────────────────────────────────┐
                      │     SIMD RS Codec Engine       │
                      │ (crates/yip-transport/src/rs)  │
                      │  • AVX2 256-bit nibble shuffle │
                      │  • < 200 ns matrix solve       │
                      └────────────────────────────────┘
```

---

## 4. Detailed Component Design

### 4.1 SIMD Galois Field Acceleration (`crates/yip-transport`)

#### Mathematical Formulation
In Galois Field $GF(2^8)$ with field polynomial $P(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11d`):
For any constant coefficient $C \in GF(2^8)$ and data byte $B \in GF(2^8)$:
$$B = (hi \ll 4) \oplus lo, \quad \text{where } lo = B \ \& \ \text{0x0F}, \ hi = (B \gg 4) \ \& \ \text{0x0F}$$
By field linearity:
$$C \cdot B = (C \cdot (hi \ll 4)) \oplus (C \cdot lo)$$

#### AVX2 Vectorized Implementation
Precomputes two 16-byte lookup tables per coefficient $C$:
- `tbl_lo[i] = C * i` for $i \in [0..15]$
- `tbl_hi[i] = C * (i << 4)` for $i \in [0..15]$

Broadcasts `tbl_lo` and `tbl_hi` across 256-bit YMM registers (`_mm256_broadcastsi128_si256`).
Processing 32 data bytes per cycle:
1. `v_lo = _mm256_and_si256(data, _mm256_set1_epi8(0x0f))`
2. `v_hi = _mm256_and_si256(_mm256_srli_epi16(data, 4), _mm256_set1_epi8(0x0f))`
3. `p_lo = _mm256_shuffle_epi8(v_tbl_lo, v_lo)`
4. `p_hi = _mm256_shuffle_epi8(v_tbl_hi, v_hi)`
5. `prod = _mm256_xor_si256(p_lo, p_hi)`
6. `acc  = _mm256_xor_si256(dest, prod)`

#### Differential Testing & Verification
- Unit and property-based fuzz tests verifying that `rs_simd_mul_add` produces identical outputs to `rs_scalar_mul_add` across all 256 field coefficients and arbitrary slice lengths (aligned and unaligned).

---

### 4.2 Native Kernel eBPF XSK Driver (`crates/yip-io/src/bpf.rs`)

#### Direct Syscall Invocation
- Employs `libc::syscall(libc::SYS_bpf, cmd, &attr, size)`.
- Implements:
  1. `bpf_map_create_xsk(max_entries: u32) -> io::Result<RawFd>`
  2. `bpf_map_update_xsk(map_fd: RawFd, queue_id: u32, xsk_fd: RawFd) -> io::Result<()>`
  3. `bpf_prog_load_xdp(listen_port: u16, xsk_map_fd: RawFd) -> io::Result<RawFd>`
  4. `bpf_attach_xdp(ifindex: u32, prog_fd: RawFd) -> io::Result<()>`

#### Bytecode Logic
```
r1 = ctx (xdp_md: data, data_end)
r2 = *(r1 + data)
r3 = *(r1 + data_end)
if (r2 + sizeof(eth + ip + udp) > r3) return XDP_PASS;
if (eth->proto != ETH_P_IP) return XDP_PASS;
if (ip->proto != IPPROTO_UDP) return XDP_PASS;
if (udp->dest != htons(listen_port)) return XDP_PASS;
r2 = xsk_map
r3 = ctx->rx_queue_index
return bpf_redirect_map(r2, r3, 0);
```

#### Fail-Soft Degradation
If `BPF_PROG_LOAD` or map creation fails with `EPERM`, `EACCES`, or `ENOSYS`, `bpf.rs` records `XdpFilterMode::FallbackDriver` and returns cleanly without error.

---

### 4.3 Adaptive Dynamic Busy-Polling Engine (`bin/yipd/src/sharding.rs`)

#### State & Config
- `busy_poll_us: u64`: Controlled via config option `busy_poll_us` or environment variable `YIP_BUSY_POLL_US` (default 50 µs).
- `last_rx_instant: Instant`: Updated whenever a datagram or descriptor is consumed.

#### Event Loop Algorithm
```rust
loop {
    let mut packets_this_iter = 0;

    // 1. Non-blocking drain of XSK rings and UDP sockets
    packets_this_iter += drain_network_ingress();

    // 2. Non-blocking drain of TUN device
    packets_this_iter += drain_tun_ingress();

    // 3. Non-blocking drain of SPSC inter-core queues
    packets_this_iter += drain_spsc_channels();

    if packets_this_iter > 0 {
        last_rx_instant = Instant::now();
    }

    // 4. Adaptive Polling Decision
    if now.duration_since(last_rx_instant).as_micros() < busy_poll_us {
        std::hint::spin_loop(); // Stay in user-space spin-poll, 0 syscalls
    } else {
        poller.wait(10)?; // Yield CPU into epoll when idle
    }
}
```

---

## 5. Testing & Verification Plan

1. **Unit & Differential Tests**:
   - `crates/yip-transport/tests/rs_simd_test.rs`: 100,000 differential random vector tests verifying SIMD vs scalar equivalence.
   - `crates/yip-io/tests/bpf_test.rs`: Validates eBPF instruction generation, BPF map registration, and fallback behavior.
2. **Scaling & Latency Microbenchmarks**:
   - `crates/yip-bench/benches/rs_simd_bench.rs`: Benchmark comparing scalar RS vs AVX2 RS encoding/decoding.
   - `crates/yip-bench/benches/af_xdp_scale.rs`: Updated to exercise the SIMD RS engine and measure aggregate Gbps and Mpps.
3. **Live Network Namespace Head-to-Head Tests**:
   - `bin/yipd/tests/run-netns-wireguard-comp.sh`: Execute live under `sudo` to measure the new RTT latency percentiles (p50, p90, p99) and TCP throughput.

---

## 6. Implementation Task Breakdown

- **Task 1**: Vectorized AVX2 Cauchy Reed–Solomon Galois Field Engine in `crates/yip-transport`.
- **Task 2**: Self-Contained eBPF XSK Redirect Driver & Map Loader in `crates/yip-io`.
- **Task 3**: Adaptive Dynamic Busy-Polling Engine in `bin/yipd/src/sharding.rs`.
- **Task 4**: SIMD Differential Fuzz Tests & Microbenchmarks in `crates/yip-bench`.
- **Task 5**: Live WireGuard Parity Netns Benchmark Execution & Regression Run.
- **Task 6**: Documentation, Results Update & Tracking Wrap-up.
