# Way C: Kernel-Bypass Zero-Copy I/O Tier (AF_XDP) & WireGuard Parity Benchmarks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Way C AF_XDP kernel-bypass zero-copy driver in `crates/yip-io` and `bin/yipd` with a 3-tier fallback engine, and establish an authoritative live WireGuard comparison benchmark suite measuring throughput, packet rate, and latency under variable network loss.

**Architecture:** Binds `AF_XDP` sockets directly to network interface queues using pre-allocated page-aligned UMEM memory rings (`FillRing`, `RxRing`, `TxRing`, `CompletionRing`), eliminating kernel `sk_buff` allocations and copy overhead. Performs in-place AEAD cryptography and Cauchy Reed–Solomon decoding. Provides a live network-namespace benchmark comparing Linux kernel WireGuard (`wg0`) against `yipd` under `tc netem` loss (0%, 1%, 5%).

**Tech Stack:** Rust 2021, Linux `AF_XDP` (`libc::sockaddr_xdp`, `SOL_XDP`), `crates/yip-io`, `bin/yipd`, `crates/yip-bench`, `tc netem`, `wireguard-tools`.

## Global Constraints

- `#![forbid(unsafe_code)]` strictly enforced in `bin/yipd`, `crates/yip-transport`, `crates/yip-crypto`, and `crates/yip-device`.
- Low-level libc XSK/XDP structures (`sockaddr_xdp`, ring memory mapping, `mmap`) quarantined strictly within `crates/yip-io/src/af_xdp.rs` with explicit `// SAFETY:` justifications on all unsafe blocks.
- Zero mutexes or locks on the packet-processing fast path.
- Zero TCP packet reordering for any inner 5-tuple flow via bidirectional symmetric flow pinning.
- Graceful 3-tier fallback: `XDP_ZERO_COPY` $\to$ `XDP_COPY` $\to$ `BatchUdpSocket` (`recvmmsg`).

---

### Task 1: UMEM Memory Allocator & Ring Descriptors (`crates/yip-io`)

**Files:**
- Create: `crates/yip-io/src/af_xdp.rs`
- Modify: `crates/yip-io/src/lib.rs`
- Test: `crates/yip-io/tests/umem_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const UMEM_CHUNK_SIZE: usize = 2048;
  pub const UMEM_RING_SIZE: u32 = 2048;

  pub struct UmemPool {
      area: *mut libc::c_void,
      size: usize,
      chunk_size: usize,
      free_chunks: Vec<u64>,
  }

  impl UmemPool {
      pub fn new(num_chunks: usize, chunk_size: usize) -> std::io::Result<Self>;
      pub fn alloc_chunk(&mut self) -> Option<u64>;
      pub fn free_chunk(&mut self, addr: u64);
      pub fn chunk_slice(&self, addr: u64, len: usize) -> &[u8];
      pub fn chunk_slice_mut(&mut self, addr: u64, len: usize) -> &mut [u8];
  }
  ```

- [ ] **Step 1: Write failing test for UMEM pool allocation and chunk slicing**

Create `crates/yip-io/tests/umem_test.rs`:

```rust
use yip_io::af_xdp::{UmemPool, UMEM_CHUNK_SIZE};

#[test]
fn test_umem_pool_allocation_and_slicing() {
    let mut pool = UmemPool::new(64, UMEM_CHUNK_SIZE).expect("allocate UMEM pool");
    let c1 = pool.alloc_chunk().expect("alloc chunk 1");
    let c2 = pool.alloc_chunk().expect("alloc chunk 2");
    assert_ne!(c1, c2);

    {
        let slice = pool.chunk_slice_mut(c1, 100);
        slice[0] = 0x42;
        slice[99] = 0x99;
    }

    let read_slice = pool.chunk_slice(c1, 100);
    assert_eq!(read_slice[0], 0x42);
    assert_eq!(read_slice[99], 0x99);

    pool.free_chunk(c1);
    pool.free_chunk(c2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io --test umem_test`
Expected: FAIL (`af_xdp` module not found).

- [ ] **Step 3: Implement `UmemPool` with page-aligned memory allocation**

Create `crates/yip-io/src/af_xdp.rs` implementing `UmemPool` using `libc::mmap(MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE)`.
Export `pub mod af_xdp;` in `crates/yip-io/src/lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-io --test umem_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/af_xdp.rs crates/yip-io/src/lib.rs crates/yip-io/tests/umem_test.rs
git commit -m "feat(yip-io): add UMEM shared memory pool and chunk allocator"
```

---

### Task 2: AF_XDP Socket & Three-Tier Fallback Engine (`crates/yip-io`)

**Files:**
- Modify: `crates/yip-io/src/af_xdp.rs`
- Test: `crates/yip-io/tests/xsk_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum XskBindMode {
      ZeroCopy,
      Copy,
      FallbackRecvmmsg,
  }

  pub struct XskSocket {
      fd: std::os::fd::RawFd,
      mode: XskBindMode,
  }

  impl XskSocket {
      pub fn bind_opportunistic(ifname: &str, queue_id: u32, umem: &UmemPool) -> std::io::Result<Self>;
      pub fn mode(&self) -> XskBindMode;
  }
  ```

- [ ] **Step 1: Write test for opportunistic AF_XDP socket creation**

Create `crates/yip-io/tests/xsk_test.rs`:

```rust
use yip_io::af_xdp::{UmemPool, XskBindMode, XskSocket, UMEM_CHUNK_SIZE};

#[test]
fn test_xsk_socket_opportunistic_probe() {
    let pool = UmemPool::new(64, UMEM_CHUNK_SIZE).expect("allocate pool");
    let res = XskSocket::bind_opportunistic("lo", 0, &pool);
    match res {
        Ok(sock) => {
            assert!(
                sock.mode() == XskBindMode::ZeroCopy
                    || sock.mode() == XskBindMode::Copy
                    || sock.mode() == XskBindMode::FallbackRecvmmsg
            );
        }
        Err(e) => {
            let raw = e.raw_os_error().unwrap_or(0);
            assert!(
                raw == libc::EPERM || raw == libc::EACCES || raw == libc::EAFNOSUPPORT,
                "unexpected bind error: {e}"
            );
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io --test xsk_test`
Expected: FAIL (`XskSocket` not found).

- [ ] **Step 3: Implement `XskSocket` with 3-tier fallback binding**

Implement `XskSocket::bind_opportunistic` in `crates/yip-io/src/af_xdp.rs` using `libc::socket(AF_XDP, SOCK_RAW, 0)` with `XDP_ZERO_COPY` $\to$ `XDP_COPY` $\to$ `FallbackRecvmmsg`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-io --test xsk_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/af_xdp.rs crates/yip-io/tests/xsk_test.rs
git commit -m "feat(yip-io): add AF_XDP socket initialization with 3-tier fallback"
```

---

### Task 3: Worker Datapath Zero-Copy Wiring (`bin/yipd/src/sharding.rs`)

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Test: `bin/yipd/tests/sharded_ordering_test.rs`

- [ ] **Step 1: Write integration test for worker datapath with AF_XDP probe**

Add test in `bin/yipd/tests/sharded_ordering_test.rs` verifying worker initialization succeeds cleanly when AF_XDP is probed.

- [ ] **Step 2: Run test to verify it passes or fails**

Run: `cargo test -p yipd --test sharded_ordering_test`

- [ ] **Step 3: Wire `XskSocket` into worker loop**

In `bin/yipd/src/sharding.rs`, probe `XskSocket::bind_opportunistic`. If `XskBindMode::FallbackRecvmmsg`, execute existing vectorized `BatchUdpSocket` loop. If `ZeroCopy` or `Copy`, drain RX ring into in-place AEAD decrypt.

- [ ] **Step 4: Run test suite to verify clean pass**

Run: `cargo test -p yipd`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/sharding.rs bin/yipd/tests/sharded_ordering_test.rs
git commit -m "feat(yipd): wire AF_XDP zero-copy socket into worker event loop"
```

---

### Task 4: Non-Root Workspace Scaling Microbenchmark (`crates/yip-bench`)

**Files:**
- Create: `crates/yip-bench/benches/af_xdp_scale.rs`
- Modify: `crates/yip-bench/Cargo.toml`

- [ ] **Step 1: Write non-root benchmark simulating UMEM ring pipeline**

Create `crates/yip-bench/benches/af_xdp_scale.rs` benchmarking chunk allocations, in-place AEAD seal/open, and multi-core scaling across 1, 2, 4, 8 threads. Register bench in `crates/yip-bench/Cargo.toml`.

- [ ] **Step 2: Run benchmark to measure results**

Run: `cargo bench --bench af_xdp_scale -- --nocapture`
Expected: Benchmark compiles and outputs scaling metrics across worker threads.

- [ ] **Step 3: Commit**

```bash
git add crates/yip-bench/benches/af_xdp_scale.rs crates/yip-bench/Cargo.toml
git commit -m "bench: add af_xdp_scale zero-copy pipeline microbenchmark"
```

---

### Task 5: End-to-End Live WireGuard Parity Netns Benchmark

**Files:**
- Create: `bin/yipd/tests/run-netns-wireguard-comp.sh`

- [ ] **Step 1: Write comparative network namespace benchmark script**

Create `bin/yipd/tests/run-netns-wireguard-comp.sh` setting up `wg0` (Linux kernel WireGuard) and `yip0` side-by-side in `NS_A` and `NS_B` over `veth` interfaces with `tc netem` (0%, 1%, 5% loss). Measures throughput and RTT latency percentiles (p50, p90, p99, p99.9).

- [ ] **Step 2: Make executable and verify syntax**

Run: `chmod +x bin/yipd/tests/run-netns-wireguard-comp.sh && bash -n bin/yipd/tests/run-netns-wireguard-comp.sh`
Expected: Syntax clean.

- [ ] **Step 3: Commit**

```bash
git add bin/yipd/tests/run-netns-wireguard-comp.sh
git commit -m "test: add live netns comparative WireGuard vs yip benchmark harness"
```

---

### Task 6: Documentation, Parity Tables, and Issue Management

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `crates/yip-bench/RESULTS.md`

- [ ] **Step 1: Update documentation and benchmark results**

Update `README.md`, `CHANGELOG.md`, and `crates/yip-bench/RESULTS.md` with AF_XDP architecture details and WireGuard parity findings.

- [ ] **Step 2: Run full regression test suite**

Run: `cargo test --workspace`
Expected: 100% pass cleanly.

- [ ] **Step 3: Commit and update tracking issue**

```bash
git add README.md CHANGELOG.md crates/yip-bench/RESULTS.md
git commit -m "docs: record Way C AF_XDP architecture and WireGuard parity benchmarks"
```
Update GitHub Issue [#127](https://github.com/femboyisp/yip/issues/127) with progress and results.
