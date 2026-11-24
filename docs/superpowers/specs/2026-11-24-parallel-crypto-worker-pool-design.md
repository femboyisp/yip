# Parallel Crypto Worker Pool Design Document

**Issue Reference:** [#252](https://github.com/femboyisp/yip/issues/252)
**Date:** 2026-11-24
**Status:** Approved

---

## 1. Problem Statement & Motivation

In multi-core mode (`shards=auto`), traffic in `yipd` is partitioned across worker shards via `symmetric_flow_hash(&flow) % num_shards` in [bin/yipd/src/sharding.rs](file:///home/zoa/projects/femboy/yip/bin/yipd/src/sharding.rs#L52-L84). Consequently, all datagrams for any single 4-tuple TCP connection are processed sequentially by a single core-pinned worker thread.

A single CPU core executing TUN reads, AEAD seal/open framing, packet classification, and UDP socket dispatch tops out at approximately 2.35 Gbps (approx. 200k pps at 1400 B MTU). In contrast, WireGuard-Go achieves 7.3 - 8.2 Gbps on the identical single TCP stream by distributing packet encryption and decryption across a worker pool of goroutines across all host cores (`device.RoutineEncryption`). However, WireGuard-Go suffers from a ~2.8 GB memory footprint due to garbage-collected channel churn.

### Goals
1. Scale single-stream TCP throughput to match or exceed WireGuard-Go (7.3 - 8.2+ Gbps).
2. Maintain strict in-order packet delivery without spurious out-of-order retransmissions or TCP congestion window collapse.
3. Keep memory footprint strictly bounded (<50 MB RSS) with zero steady-state heap allocations on the packet processing hot path.
4. Strictly maintain `#![forbid(unsafe_code)]` across all crates outside `crates/yip-io`.

---

## 2. Architecture & Thread Topology

### 2.1 Thread Roles
1. **Worker Shards (`yipd-shard-0`, `yipd-shard-1`, ...)**:
   - Handle I/O event polling via `Epoll`, `io_uring`, or `AF_XDP`.
   - Maintain peer session states, FEC encoding/decoding metadata, and route lookup.
   - Serve as producers for outbound cryptographic tasks and consumers for inbound tasks.
2. **Crypto Worker Pool (`yipd-crypto-0`, `yipd-crypto-1`, ...)**:
   - Sized by default to $N_{crypto} = \max(1, \text{num\_cpus} - \text{num\_shards})$ when $\text{num\_cpus} > \text{num\_shards}$, or configurable via `crypto_workers` in `yipd.conf` / `--crypto-workers <N|auto>`.
   - Each worker runs a tight execution loop pinned to assigned CPU cores, draining jobs from lock-free bounded SPSC queues ([crates/yip-io/src/spsc.rs](file:///home/zoa/projects/femboy/yip/crates/yip-io/src/spsc.rs)), computing ChaCha20-Poly1305 sealing or opening in parallel, and committing completed results.

---

## 3. Detailed Data Pipelines

### 3.1 Transmit (TX) Pipeline (TUN -> AEAD -> UDP)
1. **Batch Drainage & Nonce Allocation**:
   - The worker shard drains up to $M$ packets from TUN (`readv` / recvmmsg / GSO split).
   - If $M < 4$, the shard executes ChaCha20-Poly1305 inline, bypassing inter-thread dispatch latency.
   - If $M \ge 4$, the shard reserves a contiguous block of $M$ sequential counters:
     $$\text{start\_counter} = \text{session.reserve\_counters}(M)$$
     Packet $j \in [0, M-1]$ is assigned counter $\text{start\_counter} + j$.
2. **Work Dispatch**:
   - The $M$ tasks are striped across the $N_{crypto}$ workers via SPSC ring buffers.
   - Workers execute ChaCha20-Poly1305 AEAD seal in parallel.
3. **In-Order Reassembly Buffer (ROB)**:
   - Completed encrypted blocks are received and inserted into a circular bounded Reorder Buffer (`ReorderBuffer<T, CAP>`).
   - The shard drains the reorder buffer in strict monotonic sequence ($0 \dots M-1$), generates wire headers, and submits framed datagrams to the batch UDP socket (`sendmmsg` / AF_XDP TX / io_uring).

### 3.2 Receive (RX) Pipeline (UDP -> AEAD -> TUN)
1. **Batch Ingestion**:
   - The shard ingests incoming UDP datagrams, extracts connection tags and sequence counters from valid wire headers.
2. **Parallel Open**:
   - Datagram ciphertexts are distributed to the crypto worker pool for ChaCha20-Poly1305 AEAD opening.
3. **Sequential Replay Verification & TUN Write**:
   - Completed plaintext buffers are collected in monotonic order through the RX Reorder Buffer.
   - Replay window checks are performed sequentially. Datagrams that fail Poly1305 verification or replay checks are discarded.
   - Valid plaintext IP packets are written in batch to the TUN device.

---

## 4. Memory Management & Zero-Allocation Invariant

1. **Preallocated Buffers**:
   - SPSC ring buffers are statically sized (`CAP = 8192` or `512` slots).
   - Packet buffers are drawn from the shard's local preallocated buffer pools (`egress_pool` and `retx_buf_pool`) and returned upon completion.
2. **RSS Footprint**:
   - Total memory consumed by the worker pool and ring buffers is $<10\text{ MB}$, keeping overall daemon RSS $<50\text{ MB}$.
3. **No-Allocation Guarantee**:
   - No `Vec::new()`, heap resizing, or dynamic task spawning occurs in the steady-state packet processing loops.

---

## 5. Configuration & CLI

```ini
# yipd.conf
# Number of dedicated crypto worker threads (auto, 0 to disable, or explicit integer)
crypto_workers = auto
```

CLI override:
```bash
yipd --crypto-workers auto /etc/yip/yipd.conf
yipd --crypto-workers 4 /etc/yip/yipd.conf
```

---

## 6. Verification & Quality Gates

1. **Unit Tests**:
   - `reorder_buffer_test`: In-order, out-of-order, wrapped, and duplicate sequence handling in `ReorderBuffer`.
   - `crypto_pool_test`: Parallel multi-threaded batch encryption/decryption round-trip and tamper detection.
2. **Integration Tests**:
   - Multi-shard and single-shard tunnel data path tests with `crypto_workers` enabled.
   - `tunnel_crypto_pool_integration_test`: Full end-to-end TUN-to-UDP loop.
3. **Benchmarks & Performance Targets**:
   - Single-stream TCP throughput benchmark using `./crates/yip-bench/tests/run-iperf-compare.sh`.
   - Target: $\ge 7.3\text{ Gbps}$ single-stream goodput.
4. **Safety & Code Quality**:
   - `#![forbid(unsafe_code)]` enforced in all touched crates outside `crates/yip-io`.
   - Zero compiler warnings, clippy clean, cargo deny passes, zero emojis across all artifacts.
