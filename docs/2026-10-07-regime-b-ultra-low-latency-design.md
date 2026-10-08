# Regime B+: Ultra-Low Latency & Vectorized Multi-Core Pipeline Design

- **Author**: Antigravity & User
- **Status**: Approved Design
- **Date**: 2026-10-07
- **Target Subsystems**: `bin/yipd`, `crates/yip-io`, `crates/yip-transport`, `crates/yip-crypto`
- **Scope**: Stage 1 of Ultra-Low Latency & High-Throughput Roadmap (In-Process Cache & Protocol Locality + Vectorized I/O)

---

## 1. Executive Summary & Problem Statement

Building upon Regime B's initial single-peer multi-core scaling (which reached 21.5 Gbps across 8 threads), two major latency and throughput bottlenecks remain in userspace packet processing:
1. **Directional Flow Asymmetry & Cache Invalidation**: Forward flows ($A \to B$) and return flows ($B \to A$, e.g., TCP ACKs) currently hash to different worker cores. Processing return packets on a separate core invalidates CPU L1/L2 cache lines, adding $30\text{--}40\%$ unnecessary latency to TCP round-trip turnaround times.
2. **FEC Symbol Desynchronization Under Loss**: When packet loss occurs, Cauchy Reed–Solomon source and repair symbols for the same `object_id` can arrive on different worker cores, requiring inter-thread synchronization or buffer transfers to reassemble and decode blocks.
3. **Per-Packet Syscall Tax**: Invoking `recvfrom` and `sendto` per packet at 2–3 Mpps consumes $35\text{--}45\%$ of CPU cycles purely crossing the kernel boundary ($250\text{--}400\text{ ns}$ per transition).
4. **Static Cache Footprint**: Fixed 16 KB replay window allocations per peer waste L1D cache space for low-throughput peers.

This specification designs **Regime B+ (Ultra-Low Latency & Vectorized Pipeline)**, introducing **Bidirectional Symmetric Flow Pinning**, **FEC Object Affinity**, **Adaptive Vectorized I/O (`recvmmsg`/`sendmmsg` + Opportunistic `UDP_SEGMENT`)**, and **Adaptive Cache-Local Replay Sizing**.

---

## 2. Architecture & Vectorized Datapath Flow

```
                     Vectorized Ingestion (TUN / UDP)
                       recvmmsg() [32-64 packets]
                                    │
                                    ▼
       ┌──────────────────────────────────────────────────────────┐
       │ Multi-Packet Ingest Buffer (Contiguous Cache Lines)      │
       └────────────────────────────┬─────────────────────────────┘
                                    │
            ┌───────────────────────┴───────────────────────┐
            ▼                                               ▼
   Plaintext TUN Batch                             Encrypted UDP Batch
            │                                               │
            ▼                                               ▼
 ┌───────────────────────┐                       ┌───────────────────────┐
 │ Symmetric 5-Tuple     │                       │ FEC Object & Tag      │
 │ Canonical Sorting     │                       │ Demuxing              │
 │ min(ip)/max(ip)...    │                       │ object_id affinity    │
 └──────────┬────────────┘                       └──────────┬────────────┘
            │                                               │
            ▼                                               ▼
 ┌───────────────────────┐                       ┌───────────────────────┐
 │ Local Core Pinning    │                       │ Pre-Filter Replay     │
 │ (Both TCP Directions) │                       │ & In-Cache SIMD Open  │
 └──────────┬────────────┘                       └──────────┬────────────┘
            │                                               │
            ▼                                               ▼
 ┌───────────────────────┐                       ┌───────────────────────┐
 │ SIMD AEAD Seal +      │                       │ Plaintext Output to   │
 │ Outer Port Select     │                       │ Local TUN Queue       │
 └──────────┬────────────┘                       └───────────────────────┘
            │
            ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ Vectorized Egress Buffer (Flush via sendmmsg / UDP_SEGMENT)   │
 └───────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Component Designs

### 3.1 Bidirectional Symmetric Flow Pinning (`bin/yipd/src/flow.rs`)

To ensure that both data packets and reverse TCP ACKs are processed on the **exact same physical CPU core**:
- The flow tuple normalizes endpoints into a canonical representation by ordering `(ip, port)`:
  $$\text{endpoint}_1 = (\text{src\_ip}, \text{src\_port}), \quad \text{endpoint}_2 = (\text{dst\_ip}, \text{dst\_port})$$
  $$\text{low} = \min(\text{endpoint}_1, \text{endpoint}_2), \quad \text{high} = \max(\text{endpoint}_1, \text{endpoint}_2)$$
- The canonical hash is computed as:
  $$\text{symmetric\_flow\_hash} = \mathcal{H}(\text{low.ip}, \text{high.ip}, \text{proto}, \text{low.port}, \text{high.port})$$
- **Guarantees**:
  - `symmetric_flow_hash(A -> B) == symmetric_flow_hash(B -> A)`
  - Both directions of an inner TCP connection execute on the same worker core.
  - Zero cross-core cache-line bouncing during bidirectional transfers.
  - Strict FIFO order maintained within each direction.

### 3.2 FEC Block & Object Affinity (`crates/yip-transport` & `bin/yipd`)

In `yip`'s Encrypt-then-FEC transport (`fec.rs`), objects are split into $K$ source symbols and $R$ Cauchy Reed–Solomon repair symbols under a shared `object_id: u16`.
- **Pinning Rule**: Incoming wire frames containing FEC symbols are dispatched to worker cores based on:
  $$\text{target\_shard} = (\text{conn\_tag} \oplus (\text{object\_id} \text{ as } \text{u64})) \pmod N$$
- **Guarantees**:
  - 100% of source symbols ($0..K$) and repair symbols ($0..R$) for a specific transmission block are ingested and reassembled on the **same worker core**.
  - `FecReassembler` performs matrix inversion and erasure decoding entirely within local L1/L2 cache lines.
  - Zero inter-thread synchronization or buffer transfers under packet loss.

### 3.3 Adaptive Vectorized I/O (`crates/yip-io`)

To cut userspace-to-kernel context switch costs:
1. **`recvmmsg` Batching**:
   - `crates/yip-io` implements `BatchDatagramSocket` wrapping `libc::recvmmsg`.
   - Each syscall retrieves up to $B = 32$ datagrams into pre-allocated, cache-aligned stack/boxed buffers.
   - Syscall overhead drops from 35% of CPU time to $< 5\%$.
2. **`sendmmsg` Burst Flushing**:
   - Outbound datagrams generated by encryption are buffered in a per-worker egress batch.
   - Flushed to the wire in bursts of up to 32 datagrams via `libc::sendmmsg`.
3. **Opportunistic UDP GSO (`UDP_SEGMENT`)**:
   - On Linux 4.18+, setsockopt `SOL_UDP / UDP_SEGMENT` is opportunistically probed.
   - Large outbound batches to the same peer endpoint are submitted as single 64 KB superpackets with GSO cmsg headers.
   - Falls back transparently to `sendmmsg` if `UDP_SEGMENT` returns `ENOPROTOOPT` or `EINVAL`.

### 3.4 Adaptive Cache-Local Replay Window (`crates/yip-crypto`)

- **Profile Sizing**:
  - `Standard`: 8,192 bits (1 KB bitmap) — fits completely within a single L1D cache line cluster (32–48 KB L1D), ideal for mesh nodes and mobile peers.
  - `HighThroughput`: 131,072 bits (16 KB bitmap) — absorbs $3.28\text{ ms}$ jitter at 40 Mpps for data-center gateway links.
- **Dynamic Auto-Promotion**: Sessions initialize in `Standard` mode and promote to `HighThroughput` when packet arrival rates exceed $100\text{ kpps}$.

---

## 4. Safety & Invariant Guarantees

1. **`#![forbid(unsafe_code)]`**: Strictly maintained in `bin/yipd` and `crates/yip-transport`.
2. **Quarantined FFI**: Vectorized `libc::recvmmsg`/`libc::sendmmsg` calls are strictly encapsulated within safe wrappers in `crates/yip-io`.
3. **Strict In-Order TCP Delivery**: 0 reordered packets per TCP stream.
4. **DoS Resilience**: Two-phase replay verification (check before AEAD, commit after AEAD) preserved across all replay profiles.

---

## 5. Verification & Benchmark Targets

1. **Unit & Invariant Tests**:
   - `test_symmetric_flow_hash_bidirectional`: verifies hash symmetry on IPv4/IPv6 TCP/UDP.
   - `test_fec_object_affinity`: verifies single-core affinity for all symbols of an object.
   - `test_recvmmsg_sendmmsg_burst`: validates burst send/receive integrity.
2. **Integration Latency Tests**:
   - `test_bidirectional_tcp_ack_latency`: verifies $\ge 30\%$ reduction in round-trip ACK latency.
   - `test_fec_recovery_under_jitter`: verifies instant in-cache RS decoding under 10% packet loss.
3. **Throughput Benchmark**:
   - Target scaling from 21.5 Gbps towards 30+ Gbps on multicore.
