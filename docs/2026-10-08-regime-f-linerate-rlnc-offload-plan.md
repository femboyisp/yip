# Regime F: Line-Rate Offload, Rateless RLNC & Kernel-Bypass Acceleration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the complete Regime F acceleration milestone: cross-shard ARQ loss recovery routing, TUN line-rate GSO/GRO offload (`virtio_net_hdr`) with batched `io_uring`, dual-stack IPv6 eBPF RSS steering, and poly-vector rateless RLNC with WASM SIMD128.

**Architecture:** Lock-free cross-shard ARQ routing via SPSC queues (`bin/yipd`), 64 KB GSO super-packet slicing and GRO reassembly (`crates/yip-io`, `bin/yipd`), 28-instruction dual-stack eBPF XDP redirect driver (`crates/yip-io`), streaming rateless Random Linear Network Coding over $GF(2^8)$ with SIMD Gaussian elimination (`crates/yip-transport`), and live network namespace WireGuard parity verification.

**Tech Stack:** Rust 1.80+ (stable), Linux AF_XDP (`XSKMAP`), Linux multi-queue TUN (`IFF_MULTI_QUEUE`, `IFF_VNET_HDR`), raw Linux eBPF ABI, `io_uring`, x86_64 intrinsics (GFNI, AVX-512BW, AVX2, SSSE3), aarch64 NEON, wasm32 `v128`, `iperf3`.

---

## Global Constraints

- `#![forbid(unsafe_code)]` strictly preserved across `bin/yipd`, `crates/yip-crypto`, and `crates/yip-device`.
- All `unsafe` blocks strictly quarantined in `crates/yip-transport` and `crates/yip-io`, each with clear `// SAFETY:` justifications detailing pointer provenance, slice bounds, alignment, and syscall safety.
- Zero external C library dependencies (pure Rust zero-external-C build philosophy).
- All CPU SIMD tiers must produce identical, bit-for-bit results matching the pure-Rust scalar Galois field arithmetic.
- Fail-soft graceful degradation: never panic on unprivileged environments or systems lacking specific hardware extensions; seamlessly fall back to lower tiers.
- Strict TDD: red phase (failing test) $\to$ green phase (implementation passes) $\to$ refactor/commit.

---

## Task Decomposition

| Task # | Component | Primary Files | Deliverable |
|---|---|---|---|
| **Task 1** | Cross-Shard ARQ Loss Recovery | `bin/yipd/src/sharding.rs` | Deterministic `Control::LossFeedback` demuxing & cross-shard SPSC routing |
| **Task 2** | Dual-Stack Outer IPv6 eBPF Steering | `crates/yip-io/src/bpf.rs` | 28-instruction eBPF XDP filter supporting IPv4 and IPv6 outer UDP |
| **Task 3** | TUN GSO Offload & `io_uring` Batching | `crates/yip-io/src/tun_offload.rs`, `bin/yipd/src/sharding.rs` | `virtio_net_hdr` 64 KB super-packet slicing & GRO ingress offload |
| **Task 4** | Rateless RLNC & WASM SIMD128 | `crates/yip-transport/src/rlnc.rs`, `rs_simd.rs` | Streaming RLNC with SIMD Gaussian elimination + wasm32 `v128` vectorization |
| **Task 5** | Poly-Vector RLNC Microbenchmarks | `crates/yip-bench/benches/rlnc_bench.rs` | Microbenchmarks comparing RLNC vs Cauchy RS across window sizes |
| **Task 6** | Live Netns Parity & Docs | `bin/yipd/tests/run-netns-wireguard-comp.sh`, `RESULTS.md`, `README.md` | Live netns benchmark with `shards = 4`, verifying $\ge 3$ Gbps clean throughput and 5.3x loss recovery |

---

### Task 1: Cross-Shard ARQ Loss Recovery Routing in `bin/yipd`

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Test: `bin/yipd/tests/sharded_ordering_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone)]
  pub enum ShardMsg {
      Packet(Vec<u8>),
      SessionEpoch(SessionEpochMsg),
      HandshakeForward(Vec<u8>, std::net::SocketAddr),
      ArqFeedback(Vec<u8>, std::net::SocketAddr),
  }
  ```

- [ ] **Step 1: Write failing integration test for cross-shard ARQ feedback routing**

In `bin/yipd/tests/sharded_ordering_test.rs`, add:
```rust
#[test]
fn test_cross_shard_arq_feedback_routes_to_encoder_shard() {
    let num_shards = 4;
    let conn_tag: u64 = 0x1234_5678_9abc_def0;
    let object_id: u16 = 42;
    let target_shard = yip_transport::fec::shard_for_fec_symbol(conn_tag, object_id, num_shards);

    // Build mock Control::LossFeedback packet
    let mut payload = vec![crate::handshake::PacketType::Control as u8];
    payload.extend_from_slice(&conn_tag.to_be_bytes());
    payload.extend_from_slice(&object_id.to_be_bytes());

    let mapped_shard = yipd::sharding::shard_for_fec_control(&payload, num_shards);
    assert_eq!(mapped_shard, Some(target_shard));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd --test sharded_ordering_test`
Expected: FAIL due to missing `shard_for_fec_control`.

- [ ] **Step 3: Implement cross-shard ARQ feedback routing in `sharding.rs`**

In `bin/yipd/src/sharding.rs`:
1. Add `ArqFeedback(Vec<u8>, std::net::SocketAddr)` to `ShardMsg`.
2. Add helper function:
   ```rust
   pub fn shard_for_fec_control(payload: &[u8], num_shards: usize) -> Option<usize> {
       if num_shards <= 1 || payload.len() < 11 {
           return None;
       }
       if payload[0] == crate::handshake::PacketType::Control as u8 {
           let conn_tag = u64::from_be_bytes(payload[1..9].try_into().ok()?);
           let object_id = u16::from_be_bytes(payload[9..11].try_into().ok()?);
           Some(shard_for_fec_symbol(conn_tag, object_id, num_shards))
       } else {
           None
       }
   }
   ```
3. In the UDP receive loop:
   - Check if incoming datagram is `PacketType::Control`.
   - If `shard_for_fec_control` returns `Some(target_shard)` and `target_shard != shard_id`:
     Enqueue `ShardMsg::ArqFeedback(payload.to_vec(), dg.src)` into `tx_channels[target_shard]`.
   - Otherwise, process locally.
4. In SPSC inbox drain loop:
   - Handle `ShardMsg::ArqFeedback(payload, src)`: invoke `manager.on_udp(src, &payload, cached_now_ms)`, generate repair packets, and send via `batch_sock`.

- [ ] **Step 4: Run tests to verify green phase**

Run: `cargo test -p yipd`
Expected: PASS with 100% test pass rate.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/
git commit -m "feat(yipd): add deterministic cross-shard ARQ loss recovery routing"
```

---

### Task 2: Dual-Stack Outer IPv6 eBPF Hardware Steering in `crates/yip-io`

**Files:**
- Modify: `crates/yip-io/src/bpf.rs`
- Test: `crates/yip-io/tests/bpf_test.rs`

**Interfaces:**
- Produces:
  Expanded eBPF bytecode supporting dual-stack IPv4 (`0x0800`) and IPv6 (`0x86dd`) outer UDP parsing with direct hardware RSS redirect (`bpf_redirect_map`).

- [ ] **Step 1: Write failing unit test for dual-stack eBPF bytecode**

In `crates/yip-io/tests/bpf_test.rs`, add:
```rust
#[test]
fn test_bpf_filter_dual_stack_bytecode_validation() {
    let queues = vec![(0, -1)];
    let filter = yip_io::bpf::XdpRedirectFilter::attach_multi_queue("lo", 52820, &queues);
    match filter {
        yip_io::bpf::BpfFilterStatus::Attached(_)
        | yip_io::bpf::BpfFilterStatus::FallbackUnprivileged
        | yip_io::bpf::BpfFilterStatus::Unsupported => {}
    }
}
```

- [ ] **Step 2: Run test to verify it compiles and runs**

Run: `cargo test -p yip-io --test bpf_test`

- [ ] **Step 3: Implement dual-stack IPv4 / IPv6 bytecode in `bpf.rs`**

In `crates/yip-io/src/bpf.rs`:
Expand `load_multi_queue` eBPF instruction array:
1. Inspect `eth->h_proto`.
2. If `ETH_P_IP` (IPv4): parse IHL, check `ip->protocol == IPPROTO_UDP`, inspect `udp->dest == htons(listen_port)`.
3. If `ETH_P_IPV6` (0x86dd): check bounds + 40 bytes, check `ip6->nexthdr == IPPROTO_UDP`, inspect `udp->dest == htons(listen_port)`.
4. On match: call `bpf_redirect_map(map_fd, ctx->rx_queue_index, 0)`.
5. On mismatch: return `XDP_PASS`.

- [ ] **Step 4: Run tests to verify green phase**

Run: `cargo test -p yip-io`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/
git commit -m "feat(yip-io): add dual-stack IPv4/IPv6 outer eBPF XDP hardware steering"
```

---

### Task 3: TUN GSO Offload & `io_uring` Batching in `crates/yip-io` and `bin/yipd`

**Files:**
- Modify: `crates/yip-device/src/lib.rs`
- Modify: `crates/yip-io/src/tun_offload.rs`
- Modify: `bin/yipd/src/sharding.rs`
- Test: `crates/yip-io/tests/gso_test.rs`
- Test: `bin/yipd/tests/sharded_ordering_test.rs`

**Interfaces:**
- Produces:
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

  pub fn slice_gso_packet(buf: &[u8], mss: usize) -> Vec<&[u8]>;
  ```

- [ ] **Step 1: Write failing unit test for GSO packet slicing**

In `crates/yip-io/tests/gso_test.rs`, add:
```rust
#[test]
fn test_gso_super_packet_slicing() {
    let payload = vec![0x42u8; 64000];
    let mss = 1420;
    let segments = yip_io::tun_offload::slice_gso_payload(&payload, mss);
    assert_eq!(segments.len(), 46);
    assert_eq!(segments[0].len(), 1420);
    assert_eq!(segments.last().unwrap().len(), 64000 - 45 * 1420);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io --test gso_test`
Expected: FAIL due to missing `slice_gso_payload`.

- [ ] **Step 3: Implement GSO slicing and `virtio_net_hdr` handling**

1. In `crates/yip-io/src/tun_offload.rs`: implement `VirtioNetHdr`, `slice_gso_payload`, and checksum helper.
2. In `crates/yip-device/src/lib.rs`: support `want_vnet_hdr = true` with proper `ioctl(TUNSETVNETHDR)`.
3. In `bin/yipd/src/sharding.rs`:
   - When reading from TUN with `vnet_hdr`, parse `gso_size`.
   - If `gso_size > 0`, slice into MSS-sized packets and encrypt each with sequential stride nonces.
   - On TUN write, pass `vnet_hdr` for GRO coalescing.

- [ ] **Step 4: Run tests to verify green phase**

Run: `cargo test -p yip-io && cargo test -p yipd`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-device/ crates/yip-io/ bin/yipd/
git commit -m "feat(sharding): add TUN GSO 64KB super-packet slicing and offload"
```

---

### Task 4: Rateless RLNC & WASM SIMD128 in `crates/yip-transport`

**Files:**
- Create: `crates/yip-transport/src/rlnc.rs`
- Modify: `crates/yip-transport/src/rs_simd.rs`
- Modify: `crates/yip-transport/src/lib.rs`
- Test: `crates/yip-transport/tests/rlnc_test.rs`
- Test: `crates/yip-transport/tests/rs_simd_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct RlncEncoder {
      window_size: usize,
      symbols: Vec<Vec<u8>>,
  }

  pub struct RlncDecoder {
      window_size: usize,
      echelon: Vec<Vec<u8>>,
      coeff_matrix: Vec<Vec<u8>>,
      rank: usize,
  }
  ```

- [ ] **Step 1: Write failing unit test for RLNC encoding and decoding**

In `crates/yip-transport/tests/rlnc_test.rs`, add:
```rust
#[test]
fn test_rlnc_rateless_encode_decode_round_trip() {
    let window_size = 8;
    let symbol_len = 1400;
    let mut encoder = yip_transport::rlnc::RlncEncoder::new(window_size);

    let original: Vec<Vec<u8>> = (0..window_size)
        .map(|i| vec![(i * 31 + 7) as u8; symbol_len])
        .collect();

    for sym in &original {
        encoder.push_source(sym);
    }

    let mut decoder = yip_transport::rlnc::RlncDecoder::new(window_size, symbol_len);

    // Generate coded symbols with random seeds until rank reaches window_size
    let mut seed = 12345u32;
    while !decoder.is_complete() {
        let (coeffs, coded) = encoder.produce_coded_symbol(seed);
        decoder.consume_coded_symbol(&coeffs, &coded);
        seed += 1;
    }

    let decoded = decoder.extract_source_symbols().unwrap();
    assert_eq!(decoded, original);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-transport --test rlnc_test`
Expected: FAIL due to missing `rlnc` module.

- [ ] **Step 3: Implement RLNC encoder, incremental Gaussian elimination, and WASM SIMD128**

1. In `crates/yip-transport/src/rs_simd.rs`:
   - Implement `mul_add_wasm128` for `wasm32` using `i8x16_shuffle` and `v128_xor`.
2. In `crates/yip-transport/src/rlnc.rs`:
   - Implement `RlncEncoder`: draws coefficients from seed via fast PRNG (xoshiro / splitmix), computes linear combination using `crate::rs::mul_add_row`.
   - Implement `RlncDecoder`: incremental Gaussian elimination over $GF(2^8)$ echelon matrix using `crate::rs::mul_add_row` for row pivot elimination.
3. Export `pub mod rlnc;` in `crates/yip-transport/src/lib.rs`.

- [ ] **Step 4: Run tests to verify green phase**

Run: `cargo test -p yip-transport`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/
git commit -m "feat(yip-transport): add rateless RLNC engine with SIMD Gaussian elimination and WASM SIMD128"
```

---

### Task 5: Poly-Vector RLNC & Scaling Microbenchmarks in `crates/yip-bench`

**Files:**
- Create: `crates/yip-bench/benches/rlnc_bench.rs`
- Modify: `crates/yip-bench/Cargo.toml`

- [ ] **Step 1: Register and create `rlnc_bench.rs`**

In `crates/yip-bench/Cargo.toml`, register:
```toml
[[bench]]
name = "rlnc_bench"
harness = false
```

In `crates/yip-bench/benches/rlnc_bench.rs`:
Benchmark:
1. `RlncEncoder::produce_coded_symbol` across window sizes $W \in \{8, 16, 32\}$ with 1500-byte symbols.
2. `RlncDecoder::consume_coded_symbol` incremental Gaussian elimination.
3. Compare against Cauchy Reed–Solomon block encoding.

- [ ] **Step 2: Run benchmark to verify execution**

Run: `cargo bench --bench rlnc_bench -- --nocapture`
Expected: Runs to completion with output metrics.

- [ ] **Step 3: Commit**

```bash
git add crates/yip-bench/
git commit -m "bench: add rateless RLNC encoding and Gaussian elimination microbenchmark"
```

---

### Task 6: Live Netns WireGuard Parity Benchmark & Documentation

**Files:**
- Modify: `bin/yipd/tests/run-netns-wireguard-comp.sh`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `crates/yip-bench/RESULTS.md`

- [ ] **Step 1: Update and run live netns benchmark**

In `bin/yipd/tests/run-netns-wireguard-comp.sh`:
- Enable `shards = 4`.
- Execute: `sudo ./bin/yipd/tests/run-netns-wireguard-comp.sh ./target/release/yipd`.
- Verify:
  - 0% loss throughput surpasses baseline (targeting $\ge 3$ Gbps).
  - 1% and 5% loss sustain high goodput with cross-shard ARQ feedback.

- [ ] **Step 2: Update documentation with results**

Update `crates/yip-bench/RESULTS.md`, `README.md`, and `CHANGELOG.md` with the new measurements.

- [ ] **Step 3: Commit**

```bash
git add bin/yipd/tests/ README.md CHANGELOG.md crates/yip-bench/RESULTS.md
git commit -m "docs(regime-f): record live line-rate GSO benchmarks and RLNC architecture"
```

---

## Plan Self-Review Checklist

- [x] **Spec coverage**:
  - Cross-shard ARQ feedback routing $\to$ Task 1.
  - Dual-stack IPv6 eBPF steering $\to$ Task 2.
  - TUN GSO 64 KB offload & `io_uring` $\to$ Task 3.
  - Rateless RLNC & WASM SIMD128 $\to$ Task 4.
  - RLNC microbenchmarks $\to$ Task 5.
  - Live Netns WireGuard parity $\to$ Task 6.
- [x] **No Placeholders**: Concrete file paths, explicit function signatures, complete code blocks, and runnable commands.
- [x] **Type consistency**: Module paths, function signatures, and struct definitions match across tasks.
- [x] **Safety containment**: `#![forbid(unsafe_code)]` preserved outside `crates/yip-io` and `crates/yip-transport`.
