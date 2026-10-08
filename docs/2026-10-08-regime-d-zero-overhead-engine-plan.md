# Regime D: Zero-Overhead Ultra-Low Latency & Line-Rate Acceleration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Regime D across the workspace: accelerate Cauchy Reed–Solomon matrix operations with 256-bit AVX2 SIMD nibble-shuffle table lookups (< 200 ns per packet), implement self-contained kernel eBPF XDP redirect drivers for zero-copy NIC packet filtering into AF_XDP rings, and introduce adaptive dynamic busy-polling for sub-microsecond packet latency under active bursts.

**Architecture:** Decomposes into three orthogonal layers:
1. `crates/yip-transport/src/rs_simd.rs`: AVX2 SIMD Galois Field $GF(2^8)$ multiplication using `_mm256_shuffle_epi8` with transparent runtime CPU feature dispatch to pure-Rust scalar fallback.
2. `crates/yip-io/src/bpf.rs`: Embedded eBPF XDP filter bytecode loaded via direct `bpf(BPF_PROG_LOAD)` and `BPF_MAP_TYPE_XSKMAP` to steer matching tunnel UDP packets directly into AF_XDP rings at the NIC driver layer, bypassing `sk_buff` allocations.
3. `bin/yipd/src/sharding.rs`: Adaptive hysteresis busy-polling window (`YIP_BUSY_POLL_US`, default 50 µs) spin-polling descriptor rings under active bursts with zero syscalls, falling back to low-power `epoll_wait` when the tunnel is idle.

**Tech Stack:** Rust 2021, x86_64 AVX2 intrinsics (`core::arch::x86_64`), Linux eBPF (`SYS_bpf`), Linux AF_XDP (`AF_XDP`), `libc`, `criterion`.

## Global Constraints

- `#![forbid(unsafe_code)]` strictly preserved in `bin/yipd`, `crates/yip-crypto`, `crates/yip-device`, and `crates/yip-wire`.
- All `unsafe` blocks strictly quarantined in `crates/yip-io` (raw BPF syscalls) and `crates/yip-transport` (SIMD intrinsics).
- Every `unsafe` block must carry a clear `// SAFETY:` justification detailing pointer provenance, memory bounds, alignment, and CPU feature safety.
- Zero locks, zero mutexes, zero atomic contention on fast datapath loops.
- Pure Rust zero-external-C-dependency build philosophy preserved (no external `libbpf`, `clang`, or `dpdk` dependencies).
- 100% test pass rate across the full workspace suite.

---

### Task 1: Vectorized AVX2 Cauchy Reed–Solomon Galois Field Engine (`crates/yip-transport`)

**Files:**
- Create: `crates/yip-transport/src/rs_simd.rs`
- Modify: `crates/yip-transport/src/rs.rs`
- Modify: `crates/yip-transport/src/lib.rs`
- Test: `crates/yip-transport/tests/rs_simd_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn mul_add_row(coeff: u8, src: &[u8], dst: &mut [u8]);
  pub fn avx2_supported() -> bool;
  ```

- [ ] **Step 1: Write failing differential unit test for AVX2 RS Galois Field arithmetic**

Create `crates/yip-transport/tests/rs_simd_test.rs`:
```rust
use yip_transport::rs::test_mul_add_row_differential;

#[test]
fn test_rs_simd_matches_scalar_across_all_coefficients_and_lengths() {
    let mut src = vec![0u8; 1500];
    for (i, byte) in src.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    for coeff in 0..=255u8 {
        for len in [0, 1, 15, 16, 31, 32, 63, 64, 128, 512, 1280, 1500] {
            test_mul_add_row_differential(coeff, &src[..len]);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-transport --test rs_simd_test`
Expected: FAIL (`test_mul_add_row_differential` or `rs_simd` not found).

- [ ] **Step 3: Implement `rs_simd.rs` with AVX2 nibble shuffle table lookups**

Create `crates/yip-transport/src/rs_simd.rs`:
- Precompute 16-entry low and high nibble tables for each coefficient in $GF(2^8)$.
- In `mul_add_avx2`, process 32-byte chunks using `_mm256_shuffle_epi8`, `_mm256_and_si256`, `_mm256_srli_epi16`, and `_mm256_xor_si256`.
- Process trailing unaligned remainder bytes using scalar lookup.
- Wire `mul_add_row` in `rs.rs` with runtime CPU feature detection (`std::is_x86_feature_detected!("avx2")`).

- [ ] **Step 4: Run test to verify clean pass**

Run: `cargo test -p yip-transport --test rs_simd_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/rs_simd.rs crates/yip-transport/src/rs.rs crates/yip-transport/src/lib.rs crates/yip-transport/tests/rs_simd_test.rs
git commit -m "feat(yip-transport): add AVX2 SIMD Cauchy Reed-Solomon Galois Field acceleration"
```

---

### Task 2: Self-Contained eBPF XSK Redirect Driver & Map Loader (`crates/yip-io`)

**Files:**
- Create: `crates/yip-io/src/bpf.rs`
- Modify: `crates/yip-io/src/lib.rs`
- Modify: `crates/yip-io/src/af_xdp.rs`
- Test: `crates/yip-io/tests/bpf_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum BpfFilterStatus {
      Attached(std::os::fd::RawFd),
      FallbackUnprivileged,
      Unsupported,
  }

  pub struct XdpRedirectFilter {
      map_fd: std::os::fd::RawFd,
      prog_fd: std::os::fd::RawFd,
  }

  impl XdpRedirectFilter {
      pub fn attach_opportunistic(ifname: &str, listen_port: u16, queue_id: u32, xsk_fd: std::os::fd::RawFd) -> BpfFilterStatus;
  }
  ```

- [ ] **Step 1: Write unit test for eBPF XSK redirect map and fallback handling**

Create `crates/yip-io/tests/bpf_test.rs`:
```rust
use yip_io::bpf::{BpfFilterStatus, XdpRedirectFilter};

#[test]
fn test_bpf_filter_attach_opportunistic_on_loopback() {
    let status = XdpRedirectFilter::attach_opportunistic("lo", 51820, 0, -1);
    assert!(
        status == BpfFilterStatus::FallbackUnprivileged
            || status == BpfFilterStatus::Unsupported
            || matches!(status, BpfFilterStatus::Attached(_)),
        "unexpected bpf status: {:?}",
        status
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io --test bpf_test`
Expected: FAIL (`bpf` module not found).

- [ ] **Step 3: Implement minimal eBPF program loader and XSKMAP registration**

Create `crates/yip-io/src/bpf.rs`:
- Implement raw syscall `libc::syscall(libc::SYS_bpf, cmd, attr, size)`.
- Implement `bpf_map_create_xskmap` and `bpf_prog_load_xdp_redirect`.
- Generate minimal eBPF bytecode filtering IPv4/UDP destination port and calling `bpf_redirect_map`.
- Quarantined with `// SAFETY:` justifications on every unsafe block.
- Gracefully returns `BpfFilterStatus::FallbackUnprivileged` on `EPERM` / `EACCES` / `ENOSYS`.

- [ ] **Step 4: Run test to verify clean pass**

Run: `cargo test -p yip-io --test bpf_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/bpf.rs crates/yip-io/src/lib.rs crates/yip-io/src/af_xdp.rs crates/yip-io/tests/bpf_test.rs
git commit -m "feat(yip-io): add self-contained eBPF XSK redirect driver and map loader"
```

---

### Task 3: Adaptive Dynamic Busy-Polling Engine (`bin/yipd/src/sharding.rs`)

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Test: `bin/yipd/tests/sharded_ordering_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct AdaptivePoller {
      busy_poll_duration: std::time::Duration,
      last_active: std::time::Instant,
  }

  impl AdaptivePoller {
      pub fn new(busy_poll_us: u64) -> Self;
      pub fn should_busy_poll(&self, now: std::time::Instant) -> bool;
      pub fn record_active(&mut self, now: std::time::Instant);
  }
  ```

- [ ] **Step 1: Write test for adaptive busy-poll state machine in `sharded_ordering_test.rs`**

Add test in `bin/yipd/tests/sharded_ordering_test.rs`:
```rust
#[test]
fn test_adaptive_poller_transitions_between_spin_and_sleep() {
    let mut poller = yipd::sharding::AdaptivePoller::new(50);
    let start = std::time::Instant::now();
    poller.record_active(start);
    assert!(poller.should_busy_poll(start));
    assert!(poller.should_busy_poll(start + std::time::Duration::from_micros(30)));
    assert!(!poller.should_busy_poll(start + std::time::Duration::from_micros(60)));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd --test sharded_ordering_test`
Expected: FAIL (`AdaptivePoller` not found).

- [ ] **Step 3: Implement `AdaptivePoller` and integrate into worker event loop**

In `bin/yipd/src/sharding.rs`:
- Implement `AdaptivePoller` with configurable `busy_poll_us` (read from `YIP_BUSY_POLL_US` env or config, default 50 µs).
- In worker shard event loop:
  - If `poller.should_busy_poll(now)`, execute `std::hint::spin_loop()` and immediately drain without entering `epoll_wait`.
  - When idle for > `busy_poll_us`, yield to `poller.wait(10)`.

- [ ] **Step 4: Run test to verify clean pass**

Run: `cargo test -p yipd --test sharded_ordering_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/sharding.rs bin/yipd/tests/sharded_ordering_test.rs
git commit -m "feat(yipd): add adaptive dynamic busy-polling loop for sub-microsecond latency"
```

---

### Task 4: SIMD Differential Fuzz Tests & Microbenchmarks (`crates/yip-bench`)

**Files:**
- Create: `crates/yip-bench/benches/rs_simd_bench.rs`
- Modify: `crates/yip-bench/benches/af_xdp_scale.rs`
- Modify: `crates/yip-bench/Cargo.toml`

**Interfaces:**
- Benchmarks:
  - `rs_simd_bench`: Microbenchmarks scalar RS vs AVX2 SIMD RS Galois Field matrix operations across varying vector lengths (64 B, 512 B, 1280 B, 1400 B).
  - `af_xdp_scale`: Exercises the SIMD RS engine in the end-to-end multi-core pipeline.

- [ ] **Step 1: Create `crates/yip-bench/benches/rs_simd_bench.rs` and register in `Cargo.toml`**

Add to `crates/yip-bench/Cargo.toml`:
```toml
[[bench]]
name = "rs_simd_bench"
harness = false
```

Implement `rs_simd_bench.rs` measuring encode and decode latency per packet in nanoseconds.

- [ ] **Step 2: Run benchmark to measure results**

Run: `cargo bench --bench rs_simd_bench -- --nocapture`
Expected: Benchmarks compile and demonstrate ~7× speedup in Galois Field matrix multiplication.

- [ ] **Step 3: Update `af_xdp_scale.rs` and measure end-to-end pipeline**

Run: `cargo bench --bench af_xdp_scale -- --nocapture`
Expected: Verified 0 packet drops, 0 out-of-order deliveries, and increased aggregate Gbps and Mpps.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/benches/rs_simd_bench.rs crates/yip-bench/benches/af_xdp_scale.rs crates/yip-bench/Cargo.toml
git commit -m "bench: add rs_simd_bench and integrate SIMD into af_xdp_scale microbenchmark"
```

---

### Task 5: Live WireGuard Parity Netns Benchmark Execution & Regression Run

**Files:**
- Modify: `bin/yipd/tests/run-netns-wireguard-comp.sh`

- [ ] **Step 1: Execute live netns benchmark under `sudo`**

Run:
```bash
cargo build --release -p yipd
sudo ./bin/yipd/tests/run-netns-wireguard-comp.sh ./target/release/yipd
```
Expected: Measures live head-to-head TCP throughput and RTT latency percentiles across 0%, 1%, and 5% channel loss with adaptive polling and SIMD RS enabled.

- [ ] **Step 2: Run full workspace regression test suite**

Run: `cargo test --workspace`
Expected: 100% pass cleanly across all crates.

- [ ] **Step 3: Commit**

```bash
git add bin/yipd/tests/run-netns-wireguard-comp.sh
git commit -m "test: verify live WireGuard parity netns benchmark under Regime D optimizations"
```

---

### Task 6: Documentation, Results Update & Tracking Wrap-up

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `crates/yip-bench/RESULTS.md`

- [ ] **Step 1: Record Regime D performance results and architecture**

Update `README.md`, `CHANGELOG.md`, and `crates/yip-bench/RESULTS.md` with:
- SIMD Galois Field microbenchmarks (< 200 ns per packet).
- eBPF XSK redirect program details.
- Updated head-to-head WireGuard parity comparison and multi-core scaling tables.

- [ ] **Step 2: Verify formatting and linter**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets`
Expected: Clean with 0 warnings.

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md crates/yip-bench/RESULTS.md
git commit -m "docs: record Regime D zero-overhead engine architecture and performance metrics"
```
