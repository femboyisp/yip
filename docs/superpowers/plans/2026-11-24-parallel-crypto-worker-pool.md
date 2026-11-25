# Parallel Worker Crypto Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a dedicated lock-free parallel crypto worker pool in `yipd` to parallelize ChaCha20-Poly1305 encryption and decryption across available CPU cores for single-stream line-rate scaling past 7.3 - 8.2+ Gbps while maintaining strict packet ordering and a bounded <50 MB RAM footprint.

**Architecture:** A lock-free `CryptoWorkerPool` module in `bin/yipd/src/crypto_pool` orchestrates dedicated worker threads using bounded lock-free SPSC channels (`yip_io::spsc`). Shards dispatch batches of contiguous block encryption/decryption jobs across worker threads, gathering results through a circular Reorder Buffer (ROB) before transmission or TUN delivery, guaranteeing zero packet reordering.

**Tech Stack:** Rust 2021 edition, `yip-io` (lock-free SPSC ring buffers, batch I/O), `yip-crypto` (`ChaCha20Poly1305Cipher`, `SessionPair`), Linux epoll/recvmmsg/sendmmsg/io_uring.

## Global Constraints

- STRICTLY ZERO EMOJIS across all code, tests, documentation, commit messages, PR descriptions, and assistant responses.
- `#![forbid(unsafe_code)]` / `#![deny(unsafe_code)]` must be strictly maintained outside `crates/yip-device` and `crates/yip-io`.
- Zero steady-state heap allocations on the packet processing hot path.
- Memory usage must remain strictly bounded (<50 MB RSS) under line rates.
- Strict in-order packet delivery guaranteed by sequence-stamped reorder buffers to prevent premature TCP out-of-order retransmissions.
- All file references must use `file://` markdown link syntax.
- DO NOT tag or release until explicit user confirmation.

---

### Task 1: Lock-Free Bounded Reorder Buffer (ROB)

**Files:**
- Create: `bin/yipd/src/crypto_pool/reorder.rs`
- Create: `bin/yipd/src/crypto_pool/mod.rs`
- Modify: `bin/yipd/src/lib.rs`
- Test: `bin/yipd/tests/reorder_buffer_test.rs`

**Interfaces:**
- Consumes: Standard library primitives (`Option`, `Box`).
- Produces: `ReorderBuffer<T, const CAP: usize>` providing:
  - `pub fn new(initial_seq: u64) -> Self`
  - `pub fn insert(&mut self, seq: u64, item: T) -> Result<(), ReorderError>`
  - `pub fn drain_contiguous<F: FnMut(u64, T)>(&mut self, f: F) -> usize`
  - `pub fn next_expected_seq(&self) -> u64`
  - `pub fn len(&self) -> usize`
  - `pub fn is_empty(&self) -> bool`

- [ ] **Step 1: Write the failing test**
  Create `bin/yipd/tests/reorder_buffer_test.rs` testing in-order insertions, out-of-order insertions, sequence wrap-around, and duplicate/stale sequence rejection.

- [ ] **Step 2: Run test to confirm failure**
  Run `cargo test -p yipd --test reorder_buffer_test` and verify compile/test failure.

- [ ] **Step 3: Implement `ReorderBuffer`**
  Implement `ReorderBuffer` in `bin/yipd/src/crypto_pool/reorder.rs` using pre-allocated circular ring storage `Box<[Option<(u64, T)>; CAP]>`.

- [ ] **Step 4: Run test to confirm pass**
  Run `cargo test -p yipd --test reorder_buffer_test` and confirm all tests pass cleanly.

- [ ] **Step 5: Commit changes**
  Commit with message `feat(crypto_pool): implement lock-free bounded reorder buffer for in-order completion`.

---

### Task 2: Parallel Outbound Crypto Worker Engine

**Files:**
- Create: `bin/yipd/src/crypto_pool/outbound.rs`
- Modify: `bin/yipd/src/crypto_pool/mod.rs`
- Test: `bin/yipd/tests/outbound_crypto_pool_test.rs`

**Interfaces:**
- Consumes: `yip_crypto::session::ChaCha20Poly1305Cipher`, `yip_io::spsc::spsc_pair`, `ReorderBuffer`.
- Produces: `OutboundCryptoPool` providing:
  - `pub fn new(num_workers: usize, rob_capacity: usize) -> Self`
  - `pub fn register_cipher(&mut self, peer_id: usize, cipher: std::sync::Arc<ChaCha20Poly1305Cipher>)`
  - `pub fn dispatch_encrypt(&mut self, task: EncryptTask) -> Result<(), EncryptTask>`
  - `pub fn drain_completed<F: FnMut(CompletedDatagram)>(&mut self, f: F) -> usize`
  - `pub fn shutdown(self)`

- [ ] **Step 1: Write the failing test**
  Create `bin/yipd/tests/outbound_crypto_pool_test.rs` testing multi-threaded encryption dispatch across workers, verifying parallel throughput and strict in-order sequence completion.

- [ ] **Step 2: Run test to confirm failure**
  Run `cargo test -p yipd --test outbound_crypto_pool_test`.

- [ ] **Step 3: Implement `OutboundCryptoPool`**
  Implement worker threads running lock-free SPSC rings, handling in-place ChaCha20-Poly1305 seal and feeding completed items into `ReorderBuffer`.

- [ ] **Step 4: Run test to confirm pass**
  Run `cargo test -p yipd --test outbound_crypto_pool_test`.

- [ ] **Step 5: Commit changes**
  Commit with message `feat(crypto_pool): implement parallel outbound crypto worker pool with in-order completion`.

---

### Task 3: Parallel Inbound Crypto Worker Engine

**Files:**
- Create: `bin/yipd/src/crypto_pool/inbound.rs`
- Modify: `bin/yipd/src/crypto_pool/mod.rs`
- Test: `bin/yipd/tests/inbound_crypto_pool_test.rs`

**Interfaces:**
- Consumes: `yip_crypto::session::ChaCha20Poly1305Cipher`, `yip_io::spsc::spsc_pair`, `ReorderBuffer`.
- Produces: `InboundCryptoPool` providing:
  - `pub fn new(num_workers: usize, rob_capacity: usize) -> Self`
  - `pub fn register_cipher(&mut self, peer_id: usize, cipher: std::sync::Arc<ChaCha20Poly1305Cipher>)`
  - `pub fn dispatch_decrypt(&mut self, task: DecryptTask) -> Result<(), DecryptTask>`
  - `pub fn drain_completed<F: FnMut(DecryptedPacket)>(&mut self, f: F) -> usize`
  - `pub fn shutdown(self)`

- [ ] **Step 1: Write the failing test**
  Create `bin/yipd/tests/inbound_crypto_pool_test.rs` verifying parallel decryption and in-order delivery of plaintext payloads.

- [ ] **Step 2: Run test to confirm failure**
  Run `cargo test -p yipd --test inbound_crypto_pool_test`.

- [ ] **Step 3: Implement `InboundCryptoPool`**
  Implement parallel decryption workers with in-place `open_in_place` and bounded reorder buffer reassembly.

- [ ] **Step 4: Run test to confirm pass**
  Run `cargo test -p yipd --test inbound_crypto_pool_test`.

- [ ] **Step 5: Commit changes**
  Commit with message `feat(crypto_pool): implement parallel inbound decryption worker pool`.

---

### Task 4: Integration into `yipd` Config, Tunnel, Dataplane & Sharding

**Files:**
- Modify: `bin/yipd/src/config.rs`
- Modify: `bin/yipd/src/tunnel.rs`
- Modify: `bin/yipd/src/sharding.rs`
- Modify: `bin/yipd/src/dataplane.rs`
- Test: `bin/yipd/tests/tunnel_crypto_pool_integration_test.rs`

**Interfaces:**
- Consumes: `OutboundCryptoPool`, `InboundCryptoPool`, `Config`.
- Produces: Integrated tunnel data path with configurable worker count (`crypto_workers`, defaults to `auto` or explicit count).

- [ ] **Step 1: Write the failing integration test**
  Add `bin/yipd/tests/tunnel_crypto_pool_integration_test.rs` simulating TUN read/write loop with crypto worker pool enabled.

- [ ] **Step 2: Run test to confirm failure**
  Run `cargo test -p yipd --test tunnel_crypto_pool_integration_test`.

- [ ] **Step 3: Wire `CryptoWorkerPool` into `dataplane.rs`, `tunnel.rs`, and `sharding.rs`**
  Add cipher registration hooks on session establishment/rekey, and route packet batches through the crypto pool when batch size $\ge 4$ or when throughput exceeds threshold.

- [ ] **Step 4: Run test to confirm pass**
  Run `cargo test -p yipd --test tunnel_crypto_pool_integration_test` and verify workspace compiles cleanly without warnings.

- [ ] **Step 5: Commit changes**
  Commit with message `feat(dataplane): integrate parallel worker crypto pool into tunnel reactor loops`.

---

### Task 5: End-to-End Verification & Benchmark Validation

**Files:**
- Test: `crates/yip-bench/tests/netem_bench.rs`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Run complete workspace test suite**
  Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.

- [ ] **Step 2: Run multi-core netem single-stream benchmark**
  Verify single-peer TCP goodput scaling and zero loss.

- [ ] **Step 3: Verify RSS memory and zero allocation**
  Confirm memory stays strictly below 50 MB and zero heap allocation occurs during steady-state processing.

- [ ] **Step 4: Update documentation and CHANGELOG.md**
  Update `CHANGELOG.md` documenting parallel crypto worker pool scaling under `#252`.

- [ ] **Step 5: Create Pull Request and verify CI**
  Create PR closing `#252` and confirm all 17 CI checks pass.
