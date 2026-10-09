# Regime E: Unified Poly-Vector Engine & Dynamic Multi-Queue Sharding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the complete Regime E acceleration milestone: poly-vector SIMD Galois Field engine (GFNI, AVX-512BW, AVX2, SSSE3, ARM64 NEON, and Scalar), multi-queue eBPF driver with hardware RSS steering, single-peer multi-queue TUN worker sharding with lock-free stride nonces, and dynamic auto-tuned busy-polling.

**Architecture:** Poly-vector dynamic runtime dispatch across CPU vector extensions (`crates/yip-transport`), multi-queue `BPF_MAP_TYPE_XSKMAP` expansion with symmetric flow steering (`crates/yip-io`), single-peer session epoch replication from Shard 0 anchor with stride nonce allocation across multi-queue TUN descriptors (`bin/yipd`), and microbenchmarking plus live netns WireGuard parity verification (`crates/yip-bench` and `bin/yipd/tests`).

**Tech Stack:** Rust 1.80+ (stable), x86_64 intrinsics (GFNI, AVX-512BW, AVX2, SSSE3), aarch64 NEON intrinsics, Linux AF_XDP (`XSKMAP`), Linux multi-queue TUN (`IFF_MULTI_QUEUE`), raw Linux eBPF ABI, `iperf3`, `ip netns`.

---

## Global Constraints

- `#![forbid(unsafe_code)]` strictly preserved in `bin/yipd`, `crates/yip-crypto`, and `crates/yip-device`.
- Every `unsafe` block in `crates/yip-transport` and `crates/yip-io` must carry a clear `// SAFETY:` justification detailing pointer provenance, memory bounds, alignment, and CPU feature/syscall safety.
- Zero external C library dependencies (pure Rust zero-external-C-build philosophy).
- All CPU SIMD tiers must produce identical, bit-for-bit results matching the pure-Rust scalar Galois field arithmetic.
- Graceful degradation: never panic on unprivileged environments or systems lacking specific hardware extensions; seamlessly fall back to lower tiers.
- Strict TDD: red phase (failing test) $\to$ green phase (implementation passes) $\to$ refactor/commit.

---

## Task Decomposition

| Task # | Component | Primary Files | Deliverable |
|---|---|---|---|
| **Task 1** | Poly-Vector SIMD Core | `crates/yip-transport/src/rs_simd.rs`, `rs.rs` | GFNI, AVX-512BW, SSSE3, NEON, Scalar tiered dispatch + differential tests |
| **Task 2** | Multi-Queue eBPF Driver | `crates/yip-io/src/bpf.rs`, `af_xdp.rs` | `BPF_MAP_TYPE_XSKMAP` multi-queue expansion & symmetric flow steering |
| **Task 3** | Dynamic Auto-Tuned Poller | `bin/yipd/src/sharding.rs` | `AutoTunedPoller` tracking EWMA + jitter with 10–200 µs dynamic spin window |
| **Task 4** | Single-Peer Multi-Queue TUN Sharding | `bin/yipd/src/sharding.rs` | Shard 0 session broadcast, stride nonces, multi-queue TUN integration |
| **Task 5** | Microbenchmark Suite | `crates/yip-bench/benches/rs_simd_bench.rs`, `single_flow_scale.rs` | Tiered SIMD comparison and multi-core single-peer scaling benchmarks |
| **Task 6** | Live Netns Parity & Docs | `bin/yipd/tests/run-netns-wireguard-comp.sh`, `README.md`, `RESULTS.md` | Multi-queue live netns benchmark with `shards=4` and full docs update |

---

### Task 1: Poly-Vector SIMD Core in `crates/yip-transport`

**Files:**
- Modify: `crates/yip-transport/src/rs_simd.rs`
- Modify: `crates/yip-transport/src/rs.rs`
- Modify: `crates/yip-transport/src/lib.rs`
- Test: `crates/yip-transport/tests/rs_simd_test.rs`

**Interfaces:**
- Consumes: `crate::gf256::{mul, mul_slice_into}`
- Produces:
  ```rust
  pub fn ssse3_supported() -> bool;
  pub fn avx2_supported() -> bool;
  pub fn avx512bw_supported() -> bool;
  pub fn gfni_supported() -> bool;
  pub fn neon_supported() -> bool;
  pub unsafe fn mul_add_ssse3(coeff: u8, src: &[u8], dst: &mut [u8]);
  pub unsafe fn mul_add_avx2(coeff: u8, src: &[u8], dst: &mut [u8]);
  pub unsafe fn mul_add_avx512(coeff: u8, src: &[u8], dst: &mut [u8]);
  pub unsafe fn mul_add_gfni(coeff: u8, src: &[u8], dst: &mut [u8]);
  pub unsafe fn mul_add_neon(coeff: u8, src: &[u8], dst: &mut [u8]);
  pub fn mul_add_row(coeff: u8, src: &[u8], dst: &mut [u8]);
  ```

- [ ] **Step 1: Write failing differential tests for SSSE3, AVX-512, GFNI, and NEON**

In `crates/yip-transport/tests/rs_simd_test.rs`, add tests verifying multi-tier vector arithmetic against scalar reference across all coefficients $0..=255$ and lengths $0..=1500$:

```rust
#[test]
fn test_poly_vector_differential_all_coeffs_and_lengths() {
    let lengths = [0, 1, 7, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1024, 1500];
    for &len in &lengths {
        let src: Vec<u8> = (0..len).map(|i| (i * 37 + 13) as u8).collect();
        for coeff in 0..=255u8 {
            let mut dst_scalar = vec![0x5au8; len];
            yip_transport::gf256::mul_slice_into(&mut dst_scalar, &src, coeff);

            let mut dst_simd = vec![0x5au8; len];
            yip_transport::rs::mul_add_row(coeff, &src, &mut dst_simd);

            assert_eq!(
                dst_simd, dst_scalar,
                "Mismatch for coeff {coeff} at len {len}"
            );
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails on new features**

Run: `cargo test -p yip-transport --test rs_simd_test`
Expected: Red or missing functions.

- [ ] **Step 3: Implement SSSE3, AVX-512, GFNI, and NEON vectorization in `rs_simd.rs`**

In `crates/yip-transport/src/rs_simd.rs`:
1. Implement feature detectors: `ssse3_supported()`, `avx512bw_supported()`, `gfni_supported()`, `neon_supported()`.
2. Implement `mul_add_ssse3` using `_mm_shuffle_epi8` with 128-bit XMM registers (16 bytes/iter).
3. Implement `mul_add_avx512` using `_mm512_shuffle_epi8` with 512-bit ZMM registers (64 bytes/iter).
4. Implement `mul_add_gfni` computing the 8x8 Galois field bit-matrix $A$ for `coeff` and invoking `_mm512_gf2p8affine_epi64_epi8` (or 256-bit `_mm256_gf2p8affine_epi64_epi8`) at 64 bytes/iter.
5. On `target_arch = "aarch64"`, implement `mul_add_neon` using `vqtbl1q_u8` (16 bytes/iter).
6. In `mul_add_row` (`crates/yip-transport/src/rs.rs`), implement tiered dispatch:
   GFNI $\to$ AVX-512BW $\to$ AVX2 $\to$ SSSE3 $\to$ NEON $\to$ Pure-Rust Scalar.

- [ ] **Step 4: Run tests to verify all vector tiers pass**

Run: `cargo test -p yip-transport`
Expected: PASS with 100% test pass rate.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/
git commit -m "feat(yip-transport): add poly-vector SIMD Galois Field engine (GFNI, AVX-512, SSSE3, NEON)"
```

---

### Task 2: Multi-Queue Ingress/Egress eBPF Driver in `crates/yip-io`

**Files:**
- Modify: `crates/yip-io/src/bpf.rs`
- Modify: `crates/yip-io/src/af_xdp.rs`
- Modify: `crates/yip-io/src/lib.rs`
- Test: `crates/yip-io/tests/bpf_test.rs`

**Interfaces:**
- Produces:
  ```rust
  impl XdpRedirectFilter {
      pub fn attach_multi_queue(
          ifname: &str,
          listen_port: u16,
          queue_fds: &[(u32, std::os::fd::RawFd)],
      ) -> BpfFilterStatus;
      pub fn set_socket_for_queue(
          &mut self,
          queue_id: u32,
          xsk_fd: std::os::fd::RawFd,
      ) -> std::io::Result<()>;
  }
  ```

- [ ] **Step 1: Write failing unit test for multi-queue map insertion and fallback**

In `crates/yip-io/tests/bpf_test.rs`, add:
```rust
#[test]
fn test_bpf_multi_queue_attach_opportunistic() {
    let queues = vec![(0, -1), (1, -1), (2, -1), (3, -1)];
    let status = yip_io::bpf::XdpRedirectFilter::attach_multi_queue("lo", 52820, &queues);
    match status {
        yip_io::bpf::BpfFilterStatus::Attached(_) => {}
        yip_io::bpf::BpfFilterStatus::FallbackUnprivileged => {}
        yip_io::bpf::BpfFilterStatus::Unsupported => {}
    }
}
```

- [ ] **Step 2: Run test to verify red phase**

Run: `cargo test -p yip-io --test bpf_test`
Expected: FAIL due to missing `attach_multi_queue`.

- [ ] **Step 3: Implement multi-queue map sizing, population, and bytecode**

In `crates/yip-io/src/bpf.rs`:
1. Dimension `BPF_MAP_TYPE_XSKMAP` to `queue_fds.len().max(1)` entries.
2. In loop, call `bpf_update_elem(map_fd, &queue_id, &xsk_fd, BPF_ANY)`.
3. In eBPF bytecode:
   - Check Ethernet (IPv4) $\to$ UDP $\to$ destination port == `htons(listen_port)`.
   - On match, inspect `ctx->rx_queue_index` and invoke `bpf_redirect_map(map_fd, ctx->rx_queue_index, 0)`.
   - On mismatch, return `XDP_PASS`.
4. Implement `set_socket_for_queue` allowing dynamic worker socket insertion.
5. In `crates/yip-io/src/af_xdp.rs`, expose helper for multi-queue binding.

- [ ] **Step 4: Run tests to verify green phase**

Run: `cargo test -p yip-io`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/
git commit -m "feat(yip-io): add multi-queue eBPF XSK redirect map and RSS steering"
```

---

### Task 3: Dynamic Auto-Tuned Busy-Polling in `bin/yipd`

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Test: `bin/yipd/tests/sharded_ordering_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone)]
  pub struct AutoTunedPoller {
      min_spin: std::time::Duration,
      max_spin: std::time::Duration,
      ewma_us: f64,
      jitter_us: f64,
      current_window: std::time::Duration,
      last_active: std::time::Instant,
  }
  ```

- [ ] **Step 1: Write failing unit test for `AutoTunedPoller`**

In `bin/yipd/tests/sharded_ordering_test.rs`, add:
```rust
#[test]
fn test_auto_tuned_poller_dynamic_jitter_adaptation() {
    let mut poller = yipd::sharding::AutoTunedPoller::new(10, 200);
    assert_eq!(poller.current_spin_window_us(), 50); // initial default

    let now = std::time::Instant::now();
    // Simulate high jitter packet inter-arrivals: 120 µs intervals
    poller.record_packet_burst(now, 120);
    assert!(poller.current_spin_window_us() >= 50);

    // Verify clamping
    assert!(poller.current_spin_window_us() <= 200);
    assert!(poller.current_spin_window_us() >= 10);
}
```

- [ ] **Step 2: Run test to verify red phase**

Run: `cargo test -p yipd --test sharded_ordering_test`
Expected: FAIL due to missing `AutoTunedPoller`.

- [ ] **Step 3: Implement `AutoTunedPoller` and wire into `run_sharded`**

In `bin/yipd/src/sharding.rs`:
1. Implement `AutoTunedPoller`:
   - EWMA update: `ewma = 0.875 * ewma + 0.125 * delta_t`.
   - Jitter update: `jitter = 0.75 * jitter + 0.25 * (delta_t - ewma).abs()`.
   - Window: `clamp(ewma + 2.0 * jitter, min_spin, max_spin)`.
2. Wire `AutoTunedPoller` into worker loop:
   - When active packets received: `poller.record_packet_burst(now, delta_t)`.
   - When deciding wait timeout: if `poller.should_busy_poll(now)`, do non-blocking `wait(0)` + `std::hint::spin_loop()`.
   - If idle for $> 2 \cdot W_{\text{spin}}$, yield to `poller.wait(10)`.

- [ ] **Step 4: Run tests to verify green phase**

Run: `cargo test -p yipd`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/
git commit -m "feat(yipd): add dynamic auto-tuned busy-polling with inter-arrival jitter tracking"
```

---

### Task 4: Single-Peer Multi-Queue TUN Worker Sharding in `bin/yipd`

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Test: `bin/yipd/tests/sharded_ordering_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct SessionEpochMsg {
      pub peer_pk: [u8; 32],
      pub send_key: [u8; 32],
      pub recv_key: [u8; 32],
      pub local_index: u32,
      pub peer_index: u32,
  }
  ```

- [ ] **Step 1: Write failing test for single-peer multi-queue distribution and stride nonces**

In `bin/yipd/tests/sharded_ordering_test.rs`, add:
```rust
#[test]
fn test_stride_nonce_allocation_guarantees_uniqueness_across_shards() {
    let num_shards = 4;
    let mut shard_nonces: Vec<Vec<u64>> = vec![Vec::new(); num_shards];
    for shard in 0..num_shards {
        let mut n = shard as u64;
        for _ in 0..1000 {
            shard_nonces[shard].push(n);
            n += num_shards as u64;
        }
    }
    // Verify no collisions across shards
    let mut all_nonces: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for nonces in shard_nonces {
        for n in nonces {
            assert!(all_nonces.insert(n), "Collision detected for nonce {n}");
        }
    }
}
```

- [ ] **Step 2: Run test to verify red phase**

Run: `cargo test -p yipd --test sharded_ordering_test`
Expected: FAIL or passes test check.

- [ ] **Step 3: Implement flow-sharded single-peer replication & stride nonces**

In `bin/yipd/src/sharding.rs`:
1. Shard 0 designated as Anchor for Handshakes & Rekeying.
2. In `run_sharded`, pass all configured peers into all worker shards (or clone session states upon handshake).
3. In worker `shard_id`, assign base nonce `shard_id as u64` and increment by `num_shards as u64` for each outbound datagram.
4. Each worker shard holds its own `tun_dev` (`tun_queues.remove(0)`), reading and writing its own queue descriptor directly without forcing cross-shard SPSC bottleneck for single-peer traffic.
5. Ingress traffic for each flow processed directly on the receiving shard with per-shard `SlidingReplayWindow`.

- [ ] **Step 4: Run tests to verify green phase**

Run: `cargo test -p yipd`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/
git commit -m "feat(yipd): add single-peer multi-queue TUN worker sharding with stride nonces"
```

---

### Task 5: Poly-Vector & Multi-Queue Microbenchmarks in `crates/yip-bench`

**Files:**
- Modify: `crates/yip-bench/benches/rs_simd_bench.rs`
- Modify: `crates/yip-bench/benches/single_flow_scale.rs`
- Modify: `crates/yip-bench/benches/af_xdp_scale.rs`

- [ ] **Step 1: Update `rs_simd_bench.rs` to measure all detected SIMD tiers**

In `crates/yip-bench/benches/rs_simd_bench.rs`:
Measure Scalar vs SSSE3 vs AVX2 vs AVX-512 vs GFNI vs NEON for:
1. `mul_add_row` over 1500-byte packets.
2. Cauchy Reed–Solomon block encoding ($K=10, M=4$).
Print table with ns/packet, Gbps throughput, and speedup relative to Scalar.

- [ ] **Step 2: Update `single_flow_scale.rs` and `af_xdp_scale.rs`**

Verify multi-threaded scaling (1, 2, 4, 8 threads) using stride nonces and multi-queue ring processing with zero drops and zero reordering.

- [ ] **Step 3: Run microbenchmarks and verify execution**

Run: `cargo bench --bench rs_simd_bench -- --nocapture`
Run: `cargo bench --bench single_flow_scale -- --nocapture`
Run: `cargo bench --bench af_xdp_scale -- --nocapture`
Expected: Clean completion with logged metrics.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/
git commit -m "bench: expand poly-vector SIMD and multi-queue microbenchmark harnesses"
```

---

### Task 6: Live Netns WireGuard Parity Benchmark & Documentation

**Files:**
- Modify: `bin/yipd/tests/run-netns-wireguard-comp.sh`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `crates/yip-bench/RESULTS.md`

- [ ] **Step 1: Upgrade `run-netns-wireguard-comp.sh` with multi-queue sharding**

In `bin/yipd/tests/run-netns-wireguard-comp.sh`:
- Add `shards = 4` to both `yip_a.conf` and `yip_b.conf`.
- Verify `sudo ./bin/yipd/tests/run-netns-wireguard-comp.sh ./target/release/yipd` runs cleanly.
- Verify multi-stream TCP iperf3 throughput under 0%, 1%, and 5% loss.

- [ ] **Step 2: Update documentation**

Document Regime E features, benchmarks, and configuration in:
- `README.md`
- `CHANGELOG.md`
- `crates/yip-bench/RESULTS.md`

- [ ] **Step 3: Commit**

```bash
git add bin/yipd/tests/ README.md CHANGELOG.md crates/yip-bench/RESULTS.md
git commit -m "docs(regime-e): record live multi-queue parity benchmarks and architecture"
```

---

## Plan Self-Review Checklist

- [x] **Spec coverage**:
  - GFNI, AVX-512BW, AVX2, SSSE3, NEON, Scalar $\to$ Task 1.
  - Multi-queue eBPF driver & RSS steering $\to$ Task 2.
  - Dynamic auto-tuned busy-polling $\to$ Task 3.
  - Single-peer multi-queue TUN worker sharding $\to$ Task 4.
  - Microbenchmarks & parity suite $\to$ Tasks 5 & 6.
- [x] **No Placeholders**: Every task contains concrete files, explicit interfaces, code snippets, test commands, and commit messages.
- [x] **Type consistency**: All module paths, struct names (`AutoTunedPoller`, `XdpRedirectFilter`), and function signatures match across all tasks.
- [x] **Safety containment**: `#![forbid(unsafe_code)]` preserved outside `crates/yip-io` and `crates/yip-transport`.
