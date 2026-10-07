# Regime B Design Specification: Single-Peer Multi-Core Throughput Scaling (40 Mpps Architecture)

- **Author**: Antigravity & User
- **Status**: Approved Design
- **Date**: 2026-10-07
- **Target Issues**: Issue #10, Issue #28
- **Inspiration**: Andree Toonk's *"WireGuard at 40 Mpps with DPDK, in Go"*

---

## 1. Executive Summary & Problem Context

In standard WireGuard implementations (both in-kernel and `wireguard-go`), a single peer tunnel presents a major multi-core scaling bottleneck:
1. **Single-Queue Remote RSS Trap**: A single WireGuard tunnel is encapsulated over a fixed outer UDP 4-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`). The receiving NIC's hardware Receive Side Scaling (RSS) places 100% of packets onto a single hardware receive queue, pegging one CPU core to 100% while all other cores remain idle.
2. **False-Positive Anti-Replay Drops**: Standard WireGuard uses a 64-bit anti-replay bitmap. At multi-gigabit rates or 10–40 Mpps, $\approx 1.6\ \mu\text{s}$ of scheduling jitter between worker cores causes packets to fall outside the 64-bit window and be discarded.
3. **Atomic Nonce Cache Contention**: Calling `AtomicU64::fetch_add(1)` across 16–24 cores causes severe cache-line bouncing on the MESI/MOESI bus, degrading scaling by 35–45%.
4. **Per-Packet Timer Overhead**: Calling `clock_gettime(CLOCK_MONOTONIC)` or `Instant::now()` per packet consumes tens of millions of vDSO invocations per second.
5. **TCP Reordering Risk**: Naive round-robin packet distribution across cores introduces out-of-order packet delivery, triggering TCP Fast Retransmit, TCP SACK overhead, and collapsing TCP throughput.

This specification defines **Regime B (Symmetric Flow Pinning & Scaled Userspace Pipeline)** for `yip`, scaling a single peer tunnel across all available CPU cores up to 40 Mpps with **0 TCP packet reordering**, **0 fast-path lock contention**, and strict safety preservation (`#![forbid(unsafe_code)]` in `bin/yipd`).

---

## 2. End-to-End Pipeline Architecture

```
                    Plaintext (TUN / Multi-Queue)
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │    Extract Inner 5-Tuple      │
                 │ (src_ip, dst_ip, proto, ports)│
                 └───────────────┬───────────────┘
                                 │
                    flow_hash = wyhash(5-tuple)
                                 │
           ┌─────────────────────┴─────────────────────┐
           ▼                                           ▼
 worker_id = flow_hash % N                  port_offset = flow_hash % 64
 (Local Worker Core Affinity)               (Outer UDP Egress Port Pool)
           │                                           │
           ▼                                           ▼
┌───────────────────────┐                   ┌───────────────────────┐
│ Worker Thread i (Core)│                   │ Local Nonce Window    │
│ (Zero Lock Contention)│                   │ ([base .. base + 64]) │
└──────────┬────────────┘                   └──────────┬────────────┘
           │                                           │
           ▼                                           ▼
┌───────────────────────────────────────────────────────────┐
│ ChaCha20-Poly1305 Encrypt (SIMD / Zero Copy)              │
└──────────────────────────┬────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────┐
│ UDP Encapsulation: outer_src_port = P_base + port_offset  │
└──────────────────────────┬────────────────────────────────┘
                           │
                           ▼
                    Egress to Wire
```

On the receive path:
```
                    Ingress from Wire
                           │
                           ▼
             Remote NIC RSS distributes across
             receive queues via rotating outer ports
                           │
                           ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 1: Pre-Filter Replay Check (131,072-bit window)     │
│ Read-only check(&counter) on incoming batch               │
└──────────────────────────┬────────────────────────────────┘
                           │ Valid packets
                           ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 2: ChaCha20-Poly1305 Decrypt                        │
└──────────────────────────┬────────────────────────────────┘
                           │ Authenticated packets
                           ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 3: Post-Auth Replay Commit                          │
│ commit(&counter) marks bits in 16 KB circular bitmap      │
└──────────────────────────┬────────────────────────────────┘
                           │
                           ▼
                    Plaintext to TUN
```

---

## 3. Detailed Component Designs

### 3.1 Inner-Flow Hashing & Symmetric Flow Pinning

To guarantee strict in-order packet delivery for TCP flows:
- **5-Tuple Extraction**:
  - IPv4: `(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, src_port: u16, dst_port: u16)`
  - IPv6: `(src_ip: [u8; 16], dst_ip: [u8; 16], next_hdr: u8, src_port: u16, dst_port: u16)`
  - Non-L4 / ICMP: `(src_ip, dst_ip, proto, 0, 0)`
- **Hash Function**: Fast non-cryptographic hasher (`wyhash` or CRC32) executing in $< 4\text{ ns}$ with no allocations.
- **Worker Core Affinity**: Packets with `flow_hash` are processed by worker core `flow_hash % N`. Since all packets of a TCP stream yield the exact same `flow_hash`, all packets of that stream are processed sequentially on the same worker core $\implies$ **0 TCP packet reordering**.

### 3.2 Outer UDP Source Port Pool ($K = 64$)

- A sender maintains a pool of $K$ outer UDP sockets or binds with offsets $[P_{\text{base}}, P_{\text{base}} + K - 1]$.
- For each encapsulated packet:
  $$\text{outer\_src\_port} = P_{\text{base}} + (\text{flow\_hash} \pmod K)$$
- **Remote NIC RSS Distribution**: The remote NIC computes its hardware RSS hash over the outer 4-tuple. Varying `outer_src_port` distributes different inner flows uniformly across all remote NIC hardware queues and remote CPU cores.
- **Endpoint Relearning Resolution**:
  - Handshake initiation, response, and cookie packets (`Type 1`, `Type 2`, `Type 3`) always use the primary base port ($P_{\text{base}}$).
  - Only Handshake and Cookie packets trigger `relearn_endpoint` to modify the peer's stored base destination port.
  - Data packets (`Type 4`) track roaming IP changes without modifying the target destination port.

### 3.3 Lock-Free Chunked Nonce Allocation

```rust
pub struct ChunkedNonceDispenser {
    next_nonce: CachePadded<AtomicU64>,
    chunk_size: u64, // Default: 64
}

pub struct LocalNonceWindow {
    current: u64,
    limit: u64,
}
```

- Each worker thread claims nonces in chunks of $C = 64$ via `next_nonce.fetch_add(64, Ordering::Relaxed)`.
- During the next 64 packets, the worker performs plain local register increments (`self.current += 1`) with **zero atomic bus instructions**.
- Contention on the shared atomic counter is reduced by $64\times$ (down to $< 625\text{ kops/s}$ at 40 Mpps).
- Inactive or abandoned chunks upon session rekey are discarded safely, adhering to WireGuard RFC Section 5.4.

### 3.4 131,072-Bit Replay Window (`yip-crypto`)

```rust
pub const REPLAY_WINDOW_BITS: u64 = 131_072;
pub const REPLAY_WORDS: usize = 2048; // 131_072 / 64

pub struct ReplayWindow {
    latest: u64,
    bitmap: Box<[u64; REPLAY_WORDS]>, // 16 KB bitmap
    started: bool,
}
```

- **Circular Ring Indexing**:
  $$\text{word\_idx} = \left(\frac{\text{counter}}{64}\right) \ \& \ (2048 - 1)$$
  $$\text{bit\_mask} = 1\text{u64} \ll (\text{counter} \pmod{64})$$
- **Jitter Tolerance**: Absorbs up to 131,072 counters ($\approx 3.28\text{ ms}$ of inter-core scheduling jitter at 40 Mpps, $\approx 13.1\text{ ms}$ at 10 Mpps).
- **Two-Phase Commit**:
  1. `check(&self, counter: u64) -> bool`: Read-only pre-filter before AEAD decryption.
  2. `commit(&mut self, counter: u64)`: Executed only after AEAD authentication succeeds. Clears lapped words in the ring and sets the bit mask.

### 3.5 Low-Frequency Timer Coalescing ($\le 20\text{ Hz}$)

- Fast packet loops never call `Instant::now()` or `clock_gettime` per packet.
- Timers for rekeying (120 s), keepalive (25 s), and handshake timeout (5 s) are driven at a coalesced cadence of **20 Hz (50 ms interval)** or every $2,048$ packet batches.
- Eliminates millions of vDSO invocations per second from the datapath.

---

## 4. Safety & Invariant Guarantees

1. **`#![forbid(unsafe_code)]`**: Strictly maintained in `bin/yipd`.
2. **Lock-Free Fast Path**: Zero mutexes, zero read-write locks, zero condition variables in packet processing loops.
3. **Strict In-Order TCP Delivery**: 0 reordered packets for any single 5-tuple flow.
4. **DoS Resistance**: Unauthenticated packets cannot advance the replay window or clear bitmap words.

---

## 5. Verification & Benchmarking Plan

1. **Unit & Property Tests**:
   - `crates/yip-crypto`: Replay window test with wrapping, out-of-order within 131,072 bits, and replay drop assertions.
   - `crates/yip-io`: Concurrency test with 16 threads for `ChunkedNonceDispenser`.
   - `bin/yipd`: Inner 5-tuple hash tests for IPv4/IPv6 uniformity and flow stability.
2. **Microbenchmarks**:
   - `benches/replay_window_bench`: 64-bit vs 131,072-bit window performance.
   - `benches/nonce_dispenser_bench`: Single atomic vs chunked dispenser scaling.
   - `benches/flow_hash_bench`: 5-tuple hash throughput ($< 5\text{ ns}$ target).
3. **Integration Benchmarks**:
   - Monotonic sequence test across 1,000,000 simulated packets verifying 0 TCP reorders.
   - Live multi-core throughput benchmarking via `sharding_scale`.
