# Regime B+ Implementation Plan: Ultra-Low Latency & Vectorized Multi-Core Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Regime B+ ultra-low latency and vectorized I/O optimizations in `yip`, eliminating cross-core cache invalidation on return TCP ACKs, ensuring zero-jitter local-cache FEC block decoding, slashing kernel syscall transitions by $32\times$ via `recvmmsg`/`sendmmsg` and opportunistic `UDP_SEGMENT`, and reducing memory footprint with adaptive cache-local replay window sizing.

**Architecture:** Canonical sorting of inner 5-tuples pins both forward data and reverse TCP ACKs to the identical physical CPU core, keeping TCP state warm in L1/L2 cache. FEC frames are demuxed by `conn_tag ^ object_id` to decode Reed–Solomon blocks entirely in-cache. Sockets use vectorized batch calls (`recvmmsg`/`sendmmsg`) and opportunistic UDP GSO. Replay windows adaptively scale from 1 KB to 16 KB based on peer throughput.

**Tech Stack:** Rust 2021, `crates/yip-io`, `crates/yip-transport`, `crates/yip-crypto`, `bin/yipd`, `libc`, Linux `recvmmsg`/`sendmmsg`, `UDP_SEGMENT`.

## Global Constraints
- `#![forbid(unsafe_code)]` strictly enforced in `bin/yipd` and `crates/yip-transport`.
- Low-level `libc` FFI quarantined safely within `crates/yip-io`.
- Zero lock contention on the packet-processing fast path.
- Zero TCP packet reordering for any inner 5-tuple flow.
- Exact type consistency and no placeholder steps.

---

### Task 1: Bidirectional Symmetric Flow Hashing in `bin/yipd/src/flow.rs`

**Files:**
- Modify: `bin/yipd/src/flow.rs`
- Modify: `bin/yipd/src/sharding.rs:70-95`
- Test: `bin/yipd/src/flow.rs` (inline unit tests)

**Interfaces:**
- Produces:
  ```rust
  impl FlowTuple {
      pub fn symmetric_flow_hash(&self) -> u64;
  }
  ```

- [ ] **Step 1: Write failing unit test for bidirectional hash equality**

In `bin/yipd/src/flow.rs`, add a test verifying that swapping `(src_ip, src_port)` and `(dst_ip, dst_port)` yields the exact same hash:

```rust
#[test]
fn test_symmetric_flow_hash_bidirectional_equality() {
    let mut pkt_fwd = vec![0u8; 40];
    pkt_fwd[0] = 0x45;
    pkt_fwd[9] = 6; // TCP
    pkt_fwd[12..16].copy_from_slice(&[192, 168, 1, 10]);
    pkt_fwd[16..20].copy_from_slice(&[10, 0, 0, 1]);
    pkt_fwd[20..22].copy_from_slice(&54321u16.to_be_bytes());
    pkt_fwd[22..24].copy_from_slice(&443u16.to_be_bytes());

    let mut pkt_rev = vec![0u8; 40];
    pkt_rev[0] = 0x45;
    pkt_rev[9] = 6; // TCP
    pkt_rev[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt_rev[16..20].copy_from_slice(&[192, 168, 1, 10]);
    pkt_rev[20..22].copy_from_slice(&443u16.to_be_bytes());
    pkt_rev[22..24].copy_from_slice(&54321u16.to_be_bytes());

    let fwd = FlowTuple::extract(&pkt_fwd).expect("extract fwd");
    let rev = FlowTuple::extract(&pkt_rev).expect("extract rev");

    assert_eq!(
        fwd.symmetric_flow_hash(),
        rev.symmetric_flow_hash(),
        "forward and reverse packets of a TCP connection must yield identical symmetric flow hashes"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd test_symmetric_flow_hash_bidirectional_equality`
Expected: FAIL (`symmetric_flow_hash` method not found).

- [ ] **Step 3: Implement `symmetric_flow_hash` with canonical endpoint sorting**

In `bin/yipd/src/flow.rs`, implement `symmetric_flow_hash`:

```rust
impl FlowTuple {
    /// Compute a canonical bidirectional flow hash.
    /// Guarantees that hash(A -> B) == hash(B -> A) for identical protocols and ports,
    /// pinning both directions of a TCP/UDP connection to the same physical CPU core.
    #[inline]
    pub fn symmetric_flow_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;

        let is_canonical = (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port);
        let (low_ip, low_port, high_ip, high_port) = if is_canonical {
            (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        } else {
            (self.dst_ip, self.dst_port, self.src_ip, self.src_port)
        };

        let mut hasher = DefaultHasher::new();
        low_ip.hash(&mut hasher);
        high_ip.hash(&mut hasher);
        self.proto.hash(&mut hasher);
        low_port.hash(&mut hasher);
        high_port.hash(&mut hasher);
        hasher.finish()
    }
}
```

In `bin/yipd/src/sharding.rs`, update `shard_for_packet`:
```rust
pub fn shard_for_packet(packet: &[u8], is_tap: bool, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let ip_payload = if is_tap {
        if packet.len() < 14 {
            return 0;
        }
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype == 0x0800 || ethertype == 0x86dd {
            &packet[14..]
        } else {
            return 0;
        }
    } else {
        packet
    };

    if let Some(flow) = FlowTuple::extract(ip_payload) {
        (flow.symmetric_flow_hash() as usize) % num_shards
    } else if let Some(dst) = dst_for_packet(packet, is_tap) {
        shard_for_addr(dst, num_shards)
    } else {
        0
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd test_symmetric_flow_hash_bidirectional_equality`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/flow.rs bin/yipd/src/sharding.rs
git commit -m "feat(yipd): add bidirectional symmetric flow hashing for cache locality"
```

---

### Task 2: FEC Object Affinity in `crates/yip-transport` and `bin/yipd`

**Files:**
- Modify: `crates/yip-transport/src/fec.rs`
- Modify: `bin/yipd/src/sharding.rs`
- Test: `crates/yip-transport/tests/fec_affinity_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn shard_for_fec_symbol(conn_tag: u64, object_id: u16, num_shards: usize) -> usize;
  ```

- [ ] **Step 1: Write test for FEC symbol affinity**

Create `crates/yip-transport/tests/fec_affinity_test.rs` ensuring that all symbols (source $0..K$ and repair $0..R$) for any given `object_id` map to the exact same shard index:

```rust
use yip_transport::fec::shard_for_fec_symbol;

#[test]
fn test_all_symbols_of_object_map_to_same_shard() {
    let conn_tag = 0x1234_5678_9abc_def0;
    let num_shards = 8;

    for object_id in 0..100u16 {
        let expected_shard = shard_for_fec_symbol(conn_tag, object_id, num_shards);
        for _symbol_idx in 0..10 {
            let s = shard_for_fec_symbol(conn_tag, object_id, num_shards);
            assert_eq!(s, expected_shard, "all symbols of object {object_id} must map to shard {expected_shard}");
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-transport --test fec_affinity_test`
Expected: FAIL (`shard_for_fec_symbol` not found).

- [ ] **Step 3: Implement `shard_for_fec_symbol` and wire into `sharding.rs`**

In `crates/yip-transport/src/fec.rs`:
```rust
/// Deterministically pin all source and repair symbols of an FEC object block
/// to a single worker shard to ensure Cauchy Reed-Solomon decoding remains hot in L1D cache.
pub fn shard_for_fec_symbol(conn_tag: u64, object_id: u16, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let mixed = conn_tag ^ ((object_id as u64).wrapping_mul(0x9e3779b97f4a7c15));
    (mixed as usize) % num_shards
}
```

In `bin/yipd/src/sharding.rs`, when handling outer UDP frames, demux by `shard_for_fec_symbol` when `object_id` is parsed from the wire frame header.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-transport --test fec_affinity_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/fec.rs crates/yip-transport/tests/fec_affinity_test.rs bin/yipd/src/sharding.rs
git commit -m "feat(yip-transport): add FEC object affinity for zero-jitter in-cache reassembly"
```

---

### Task 3: Vectorized `recvmmsg` and `sendmmsg` Socket Engine in `crates/yip-io`

**Files:**
- Create: `crates/yip-io/src/batch.rs`
- Modify: `crates/yip-io/src/lib.rs`
- Test: `crates/yip-io/tests/batch_io_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const BATCH_SIZE: usize = 32;

  pub struct BatchUdpSocket {
      fd: std::os::fd::RawFd,
  }

  pub struct ReceivedDatagram {
      pub len: usize,
      pub src: std::net::SocketAddr,
  }

  impl BatchUdpSocket {
      pub fn new(sock: &std::net::UdpSocket) -> Self;
      pub fn recvmmsg_batch(
          &mut self,
          buffers: &mut [[u8; crate::MAX_WIRE_DATAGRAM]; BATCH_SIZE],
          out: &mut [ReceivedDatagram; BATCH_SIZE],
      ) -> std::io::Result<usize>;
      pub fn sendmmsg_batch(
          &mut self,
          packets: &[(&[u8], std::net::SocketAddr)],
      ) -> std::io::Result<usize>;
  }
  ```

- [ ] **Step 1: Write failing test for batch send and receive**

Create `crates/yip-io/tests/batch_io_test.rs`:

```rust
use std::net::UdpSocket;
use yip_io::batch::{BatchUdpSocket, BATCH_SIZE};

#[test]
fn test_recvmmsg_and_sendmmsg_burst() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let mut b1 = BatchUdpSocket::new(&s1);
    let mut b2 = BatchUdpSocket::new(&s2);

    let mut to_send = Vec::new();
    let payload = b"vectorized batch test packet";
    for _ in 0..16 {
        to_send.push((&payload[..], addr2));
    }

    let sent = b1.sendmmsg_batch(&to_send).expect("sendmmsg");
    assert_eq!(sent, 16);

    std::thread::sleep(std::time::Duration::from_millis(10));

    let mut buffers = [[0u8; yip_io::MAX_WIRE_DATAGRAM]; BATCH_SIZE];
    let mut out = [const { yip_io::batch::ReceivedDatagram::empty() }; BATCH_SIZE];

    let recvd = b2.recvmmsg_batch(&mut buffers, &mut out).expect("recvmmsg");
    assert_eq!(recvd, 16);
    for i in 0..16 {
        assert_eq!(&buffers[i][..out[i].len], payload);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io --test batch_io_test`
Expected: FAIL (`batch` module not found).

- [ ] **Step 3: Implement `BatchUdpSocket` using `libc::recvmmsg` and `libc::sendmmsg`**

Create `crates/yip-io/src/batch.rs` implementing safe wrappers around `libc::recvmmsg` and `libc::sendmmsg`.
Export `pub mod batch;` in `crates/yip-io/src/lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-io --test batch_io_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/batch.rs crates/yip-io/src/lib.rs crates/yip-io/tests/batch_io_test.rs
git commit -m "feat(yip-io): add vectorized recvmmsg and sendmmsg batch I/O primitives"
```

---

### Task 4: Opportunistic UDP GSO (`UDP_SEGMENT`) Offload

**Files:**
- Modify: `crates/yip-io/src/batch.rs`
- Modify: `bin/yipd/src/port.rs`
- Test: `crates/yip-io/tests/gso_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn set_udp_gso_segment(sock: &std::net::UdpSocket, segment_size: u16) -> std::io::Result<bool>;
  pub fn send_gso_superpacket(
      sock: &std::net::UdpSocket,
      payload: &[u8],
      segment_size: u16,
      dst: std::net::SocketAddr,
  ) -> std::io::Result<usize>;
  ```

- [ ] **Step 1: Write test for opportunistic GSO configuration**

Add test in `crates/yip-io/tests/gso_test.rs` ensuring `set_udp_gso_segment` probes support cleanly without panicking.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io --test gso_test`
Expected: FAIL (`set_udp_gso_segment` not found).

- [ ] **Step 3: Implement opportunistic UDP GSO with fallback**

Implement `set_udp_gso_segment` using `libc::setsockopt` with `SOL_UDP` and `libc::UDP_SEGMENT`. If `EINVAL` or `ENOPROTOOPT` occurs, return `Ok(false)` for fallback.
Implement `send_gso_superpacket` using `libc::sendmsg` with `cmsg` header.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-io --test gso_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/batch.rs bin/yipd/src/port.rs crates/yip-io/tests/gso_test.rs
git commit -m "feat(yip-io): add opportunistic UDP GSO superpacket segmentation"
```

---

### Task 5: Adaptive Cache-Local Replay Window in `crates/yip-crypto`

**Files:**
- Modify: `crates/yip-crypto/src/lib.rs`
- Test: `crates/yip-crypto/tests/adaptive_replay_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum ReplayProfile {
      Standard,       // 1 KB (8,192 bits)
      HighThroughput, // 16 KB (131,072 bits)
  }

  impl ReplayWindow {
      pub fn new_with_profile(profile: ReplayProfile) -> Self;
      pub fn promote_to_high_throughput(&mut self);
  }
  ```

- [ ] **Step 1: Write test for adaptive profile promotion**

Add test in `crates/yip-crypto/tests/adaptive_replay_test.rs` verifying a window initialized in `Standard` mode fits 1 KB and promotes to `HighThroughput` mode without dropping past seen counters.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-crypto --test adaptive_replay_test`
Expected: FAIL (`ReplayProfile` not found).

- [ ] **Step 3: Implement `ReplayProfile` and dynamic promotion**

In `crates/yip-crypto/src/lib.rs`, generalize `ReplayWindow` to support 1 KB (128 words = 8,192 bits) for `Standard` peers and 16 KB (2048 words = 131,072 bits) for `HighThroughput` peers.
Implement `promote_to_high_throughput(&mut self)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-crypto --test adaptive_replay_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-crypto/src/lib.rs crates/yip-crypto/tests/adaptive_replay_test.rs
git commit -m "feat(yip-crypto): add adaptive cache-local replay window sizing"
```

---

### Task 6: Worker Datapath Integration & End-to-End Latency/Throughput Benchmarks

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Run: `benches/single_flow_scale.rs`
- Run full regression: `cargo test --workspace`

- [ ] **Step 1: Wire batch I/O and symmetric flow hashing in worker event loop**

In `bin/yipd/src/sharding.rs`, replace single-packet `recv_from` and `send_to` with `recvmmsg_batch` and `sendmmsg_batch`.
Ensure inner flow hash uses `flow.symmetric_flow_hash()`.

- [ ] **Step 2: Run scaling benchmark and measure latency improvements**

Run: `cargo bench --bench single_flow_scale -- --nocapture`
Expected: Throughput increases and ACK latency decreases.

- [ ] **Step 3: Run full workspace test suite**

Run: `cargo test --workspace`
Expected: 100% pass cleanly.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/sharding.rs
git commit -m "feat(yipd): integrate vectorized I/O and symmetric flow pinning into worker event loop"
```
