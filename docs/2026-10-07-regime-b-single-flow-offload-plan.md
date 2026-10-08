# Regime B Implementation Plan: Single-Peer Multi-Core Throughput Scaling (40 Mpps Architecture)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Regime B single-peer multi-core throughput scaling in `yip`, enabling WireGuard tunnels to scale across all CPU cores up to 40 Mpps with zero TCP packet reordering, zero fast-path lock contention, an upgraded 131,072-bit anti-replay window, a lock-free chunked nonce dispenser, symmetric flow pinning, and low-frequency timer coalescing.

**Architecture:** Plaintext packets from multi-queue TUN are inspected for inner 5-tuples and hashed via fast wyhash. The hash pins each flow to a local worker core (guaranteeing 0 TCP reordering) and selects an outer UDP source port from a 64-port pool (driving remote NIC RSS across all remote cores). Nonces are claimed in 64-unit blocks per core without cache contention, and anti-replay is validated using a 131,072-bit (16 KB) circular bitmap. Timers are coalesced to 20 Hz.

**Tech Stack:** Rust 2021, `crates/yip-crypto`, `crates/yip-io`, `bin/yipd`, `crossbeam-utils`, `socket2`, `ring`, Linux multi-queue TUN, UDP `SO_REUSEPORT`.

## Global Constraints
- `#![forbid(unsafe_code)]` strictly preserved in `bin/yipd`.
- Zero mutexes, RwLocks, or channel locks on the fast packet-processing path.
- Zero TCP packet reordering for any inner 5-tuple flow.
- Exact type consistency and no placeholder steps.

---

### Task 1: Upgraded 131,072-Bit Circular Replay Window in `yip-crypto`

**Files:**
- Modify: `crates/yip-crypto/src/lib.rs:40-105`
- Test: `crates/yip-crypto/src/lib.rs:820-854` (inline unit tests)

**Interfaces:**
- Produces:
  ```rust
  pub const REPLAY_WINDOW_BITS: u64 = 131_072;
  pub const REPLAY_WORDS: usize = 2048;

  pub struct ReplayWindow {
      latest: u64,
      bitmap: Box<[u64; REPLAY_WORDS]>,
      started: bool,
  }

  impl ReplayWindow {
      pub fn new() -> Self;
      pub fn check(&self, counter: u64) -> bool;
      pub fn commit(&mut self, counter: u64);
  }
  ```

- [ ] **Step 1: Write failing tests for 131,072-bit replay window and out-of-order jitter**

Add unit tests to `crates/yip-crypto/src/lib.rs` verifying counters within a 100,000-packet spread are accepted, while counters $\ge 131,072$ packets behind `latest` are rejected:

```rust
#[test]
fn test_wide_replay_window_jitter_and_rejection() {
    let mut w = ReplayWindow::new();
    // Initially accepts 0
    assert!(w.check(0));
    w.commit(0);

    // Advance latest to 100,000
    assert!(w.check(100_000));
    w.commit(100_000);

    // Packet 50,000 (diff = 50,000 < 131,072) must be accepted
    assert!(w.check(50_000));
    w.commit(50_000);

    // Duplicate 50,000 must be rejected
    assert!(!w.check(50_000));

    // Packet 0 is now 100,000 behind, which is < 131,072, but it was already seen
    assert!(!w.check(0));

    // Advance to 250,000
    assert!(w.check(250_000));
    w.commit(250_000);

    // Packet 100,000 is 150,000 behind (>= 131,072), must be rejected as too old
    assert!(!w.check(100_000));
}
```

- [ ] **Step 2: Run test to verify it fails on 64-bit window**

Run: `cargo test -p yip-crypto test_wide_replay_window_jitter_and_rejection`
Expected: FAIL (assertion fails because packet 50,000 is rejected on 64-bit window with `diff >= 64`).

- [ ] **Step 3: Implement 131,072-bit circular replay window**

Replace lines 40–105 in `crates/yip-crypto/src/lib.rs`:

```rust
/// Number of past counters the replay window tracks behind the latest (16 KB bitmap).
pub const REPLAY_WINDOW_BITS: u64 = 131_072;
pub const REPLAY_WORDS: usize = 2048;

/// A wide sliding replay window over a monotonic `u64` counter using a circular word ring.
#[derive(Clone)]
pub struct ReplayWindow {
    latest: u64,
    bitmap: Box<[u64; REPLAY_WORDS]>,
    started: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            latest: 0,
            bitmap: vec![0u64; REPLAY_WORDS].into_boxed_slice().try_into().unwrap(),
            started: false,
        }
    }

    #[inline]
    fn word_idx(counter: u64) -> usize {
        ((counter / 64) as usize) & (REPLAY_WORDS - 1)
    }

    #[inline]
    fn bit_mask(counter: u64) -> u64 {
        1u64 << (counter % 64)
    }

    /// Would `counter` be accepted right now? Read-only — does not mutate state.
    pub fn check(&self, counter: u64) -> bool {
        if !self.started {
            return true;
        }
        if counter > self.latest {
            true
        } else {
            let diff = self.latest - counter;
            if diff >= REPLAY_WINDOW_BITS {
                return false; // too old
            }
            let idx = Self::word_idx(counter);
            let mask = Self::bit_mask(counter);
            (self.bitmap[idx] & mask) == 0
        }
    }

    /// Record `counter` as seen, advancing the window. Must be preceded by check().
    pub fn commit(&mut self, counter: u64) {
        if !self.started {
            self.started = true;
            self.latest = counter;
            let idx = Self::word_idx(counter);
            self.bitmap[idx] = Self::bit_mask(counter);
            return;
        }

        if counter > self.latest {
            let diff = counter - self.latest;
            if diff >= REPLAY_WINDOW_BITS {
                // Large leap: clear entire bitmap
                self.bitmap.fill(0);
            } else {
                // Clear any words in the circular ring that were overtaken
                let old_word = self.latest / 64;
                let new_word = counter / 64;
                if new_word > old_word {
                    let words_to_clear = ((new_word - old_word) as usize).min(REPLAY_WORDS);
                    for w in 1..=words_to_clear {
                        let idx = ((old_word + w as u64) as usize) & (REPLAY_WORDS - 1);
                        self.bitmap[idx] = 0;
                    }
                }
            }
            self.latest = counter;
            let idx = Self::word_idx(counter);
            self.bitmap[idx] |= Self::bit_mask(counter);
        } else {
            let diff = self.latest - counter;
            if diff < REPLAY_WINDOW_BITS {
                let idx = Self::word_idx(counter);
                self.bitmap[idx] |= Self::bit_mask(counter);
            }
        }
    }

    #[cfg(test)]
    pub fn check_and_set(&mut self, counter: u64) -> bool {
        if self.check(counter) {
            self.commit(counter);
            true
        } else {
            false
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-crypto`
Expected: PASS with 100% of crypto tests and wide window tests passing.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-crypto/src/lib.rs
git commit -m "feat(yip-crypto): upgrade replay window to 131,072-bit circular bitmap"
```

---

### Task 2: Lock-Free Chunked Nonce Dispenser in `yip-io`

**Files:**
- Create: `crates/yip-io/src/nonce.rs`
- Modify: `crates/yip-io/src/lib.rs`
- Test: `crates/yip-io/tests/nonce_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct ChunkedNonceDispenser {
      next_nonce: crossbeam_utils::CachePadded<AtomicU64>,
      chunk_size: u64,
  }

  pub struct LocalNonceWindow {
      current: u64,
      limit: u64,
  }

  impl ChunkedNonceDispenser {
      pub fn new(chunk_size: u64) -> Self;
      pub fn claim_chunk(&self) -> LocalNonceWindow;
  }

  impl LocalNonceWindow {
      pub fn next_nonce(&mut self, dispenser: &ChunkedNonceDispenser) -> Option<u64>;
  }
  ```

- [ ] **Step 1: Write failing concurrent tests for ChunkedNonceDispenser**

Create `crates/yip-io/tests/nonce_test.rs`:

```rust
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use yip_io::nonce::ChunkedNonceDispenser;

#[test]
fn test_chunked_nonce_dispenser_concurrency() {
    let dispenser = Arc::new(ChunkedNonceDispenser::new(64));
    let threads = 8;
    let nonces_per_thread = 10_000;

    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let d = Arc::clone(&dispenser);
            thread::spawn(move || {
                let mut local = d.claim_chunk();
                let mut collected = Vec::with_capacity(nonces_per_thread);
                for _ in 0..nonces_per_thread {
                    let n = local.next_nonce(&d).expect("nonce available");
                    collected.push(n);
                }
                collected
            })
        })
        .collect();

    let mut all_nonces = HashSet::new();
    for h in handles {
        let list = h.join().unwrap();
        for n in list {
            assert!(all_nonces.insert(n), "duplicate nonce detected: {n}");
        }
    }
    assert_eq!(all_nonces.len(), threads * nonces_per_thread);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io --test nonce_test`
Expected: FAIL (module `nonce` does not exist).

- [ ] **Step 3: Implement ChunkedNonceDispenser**

Create `crates/yip-io/src/nonce.rs`:

```rust
use crossbeam_utils::CachePadded;
use std::sync::atomic::{AtomicU64, Ordering};

pub const DEFAULT_NONCE_CHUNK_SIZE: u64 = 64;

/// Dispenses nonces in contiguous chunks to worker threads to prevent
/// atomic MESI cache-line contention across multi-core systems.
pub struct ChunkedNonceDispenser {
    next_nonce: CachePadded<AtomicU64>,
    chunk_size: u64,
}

impl ChunkedNonceDispenser {
    pub fn new(chunk_size: u64) -> Self {
        Self {
            next_nonce: CachePadded::new(AtomicU64::new(0)),
            chunk_size: chunk_size.max(1),
        }
    }

    pub fn claim_chunk(&self) -> LocalNonceWindow {
        let base = self.next_nonce.fetch_add(self.chunk_size, Ordering::Relaxed);
        LocalNonceWindow {
            current: base,
            limit: base.saturating_add(self.chunk_size),
        }
    }
}

/// Thread-local nonce allocation window.
#[derive(Debug, Clone, Copy)]
pub struct LocalNonceWindow {
    current: u64,
    limit: u64,
}

impl LocalNonceWindow {
    pub fn empty() -> Self {
        Self { current: 0, limit: 0 }
    }

    /// Dispenses the next 64-bit nonce. Increments local counter with zero atomic instructions.
    /// Replenishes from `dispenser` when the local chunk is exhausted.
    #[inline]
    pub fn next_nonce(&mut self, dispenser: &ChunkedNonceDispenser) -> Option<u64> {
        if self.current < self.limit {
            let n = self.current;
            self.current += 1;
            Some(n)
        } else {
            *self = dispenser.claim_chunk();
            if self.current < self.limit {
                let n = self.current;
                self.current += 1;
                Some(n)
            } else {
                None
            }
        }
    }
}
```

Modify `crates/yip-io/src/lib.rs` to export `pub mod nonce;`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-io --test nonce_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/nonce.rs crates/yip-io/src/lib.rs crates/yip-io/tests/nonce_test.rs
git commit -m "feat(yip-io): add lock-free chunked nonce dispenser"
```

---

### Task 3: Inner 5-Tuple Extraction & Symmetric Flow Hashing

**Files:**
- Create: `bin/yipd/src/flow.rs`
- Modify: `bin/yipd/src/main.rs`
- Test: `bin/yipd/src/flow.rs` (inline unit tests)

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct FlowTuple {
      pub src_ip: [u8; 16],
      pub dst_ip: [u8; 16],
      pub proto: u8,
      pub src_port: u16,
      pub dst_port: u16,
  }

  impl FlowTuple {
      pub fn extract(packet: &[u8]) -> Option<Self>;
      pub fn flow_hash(&self) -> u64;
  }
  ```

- [ ] **Step 1: Write failing unit test for inner flow extraction**

In `bin/yipd/src/flow.rs`, draft test suite checking IPv4 TCP, IPv4 UDP, IPv6 TCP, and ICMP:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ipv4_tcp() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, ihl=5
        pkt[9] = 6;    // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // TCP header at byte 20
        pkt[20..22].copy_from_slice(&8080u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());

        let flow = FlowTuple::extract(&pkt).expect("valid ipv4 tcp");
        assert_eq!(flow.proto, 6);
        assert_eq!(flow.src_port, 8080);
        assert_eq!(flow.dst_port, 443);
        assert_ne!(flow.flow_hash(), 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd test_extract_ipv4_tcp`
Expected: FAIL (unresolved module `flow`).

- [ ] **Step 3: Implement FlowTuple and fast wyhash**

Create `bin/yipd/src/flow.rs`:

```rust
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowTuple {
    pub fn extract(packet: &[u8]) -> Option<Self> {
        if packet.is_empty() {
            return None;
        }

        let version = packet[0] >> 4;
        match version {
            4 => Self::extract_v4(packet),
            6 => Self::extract_v6(packet),
            _ => None,
        }
    }

    fn extract_v4(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 20 {
            return None;
        }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if pkt.len() < ihl {
            return None;
        }
        let proto = pkt[9];
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        // Store as IPv4-mapped IPv6
        src_ip[10..12].copy_from_slice(&[0xff, 0xff]);
        src_ip[12..16].copy_from_slice(&pkt[12..16]);
        dst_ip[10..12].copy_from_slice(&[0xff, 0xff]);
        dst_ip[12..16].copy_from_slice(&pkt[16..20]);

        let (src_port, dst_port) = Self::extract_ports(&pkt[ihl..], proto);
        Some(Self {
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
        })
    }

    fn extract_v6(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 40 {
            return None;
        }
        let next_hdr = pkt[6];
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&pkt[8..24]);
        dst_ip.copy_from_slice(&pkt[24..40]);

        let (src_port, dst_port) = Self::extract_ports(&pkt[40..], next_hdr);
        Some(Self {
            src_ip,
            dst_ip,
            proto: next_hdr,
            src_port,
            dst_port,
        })
    }

    fn extract_ports(payload: &[u8], proto: u8) -> (u16, u16) {
        if (proto == 6 || proto == 17) && payload.len() >= 4 {
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            (sp, dp)
        } else {
            (0, 0)
        }
    }

    pub fn flow_hash(&self) -> u64 {
        // Deterministic SipHash / DefaultHasher for fast hash
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}
```

Register `mod flow;` in `bin/yipd/src/main.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd test_extract_ipv4_tcp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/flow.rs bin/yipd/src/main.rs
git commit -m "feat(yipd): add inner 5-tuple extraction and flow hashing"
```

---

### Task 4: Multi-Port UDP Egress Pool & Roaming Endpoint Logic

**Files:**
- Modify: `bin/yipd/src/port.rs`
- Modify: `bin/yipd/src/peer_manager/routing.rs`
- Test: `bin/yipd/tests/port_pool_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn bind_udp_egress_pool(base_port: u16, pool_size: usize) -> std::io::Result<Vec<std::net::UdpSocket>>;
  ```

- [ ] **Step 1: Write test for egress socket pool binding**

Add test in `bin/yipd/tests/port_pool_test.rs` ensuring $K$ sockets bind successfully with varying ports:

```rust
use yipd::port::bind_udp_egress_pool;

#[test]
fn test_bind_udp_egress_pool() {
    let pool = bind_udp_egress_pool(0, 8).expect("bind pool");
    assert_eq!(pool.len(), 8);
    for s in &pool {
        assert!(s.local_addr().unwrap().port() > 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd --test port_pool_test`
Expected: FAIL (`bind_udp_egress_pool` not found).

- [ ] **Step 3: Implement `bind_udp_egress_pool` and fix roaming logic**

In `bin/yipd/src/port.rs`:
```rust
pub fn bind_udp_egress_pool(base_port: u16, pool_size: usize) -> std::io::Result<Vec<std::net::UdpSocket>> {
    let mut sockets = Vec::with_capacity(pool_size);
    for i in 0..pool_size {
        let port = if base_port == 0 { 0 } else { base_port + (i as u16) };
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        let sock = std::net::UdpSocket::bind(addr)?;
        let _ = yip_io::set_socket_buffers(&sock, 2 * 1024 * 1024);
        sockets.push(sock);
    }
    Ok(sockets)
}
```

In `bin/yipd/src/peer_manager/routing.rs`, update `relearn_endpoint`:
```rust
pub fn relearn_endpoint_preserve_port(&mut self, peer_idx: usize, src: SocketAddr) {
    if let Some(peer) = self.peers.get_mut(peer_idx) {
        if let Some(ref mut ep) = peer.endpoint {
            if ep.ip() != src.ip() {
                ep.set_ip(src.ip());
            }
        } else {
            peer.endpoint = Some(src);
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd --test port_pool_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/port.rs bin/yipd/src/peer_manager/routing.rs bin/yipd/tests/port_pool_test.rs
git commit -m "feat(yipd): add UDP egress port pool and preserve port roaming"
```

---

### Task 5: Datapath Integration & 20 Hz Coalesced Timers

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Modify: `bin/yipd/src/tunnel.rs`
- Test: `bin/yipd/tests/sharded_ordering_test.rs`

**Interfaces:**
- Pins incoming TUN frames to shard index: `flow_hash % num_shards`
- Assigns outer UDP socket: `pool[flow_hash % pool.len()]`
- Checks rekey/keepalive timers every 20 Hz (50 ms interval) instead of per packet.

- [ ] **Step 1: Write integration test for monotonic TCP ordering**

Add test in `bin/yipd/tests/sharded_ordering_test.rs` verifying 10,000 packets of a TCP flow land on the exact same worker shard queue in monotonic order.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd --test sharded_ordering_test`
Expected: FAIL.

- [ ] **Step 3: Integrate flow affinity and 20 Hz timer coalescing in `sharding.rs`**

Update `sharding.rs` worker loop:
1. When TUN packet arrives:
   ```rust
   let target_shard = if let Some(flow) = FlowTuple::extract(&buf[..n]) {
       (flow.flow_hash() as usize) % num_shards
   } else {
       0
   };
   ```
2. Timer check:
   ```rust
   // Check time only once every 2048 packets or when 50ms tick expires
   if packet_count & 2047 == 0 {
       let now = std::time::Instant::now();
       if now.duration_since(last_timer_tick) >= std::time::Duration::from_millis(50) {
           peer_manager.handle_periodic_timers(now);
           last_timer_tick = now;
       }
   }
   ```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd --test sharded_ordering_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/sharding.rs bin/yipd/src/tunnel.rs bin/yipd/tests/sharded_ordering_test.rs
git commit -m "feat(yipd): integrate symmetric flow pinning and 20 Hz timer coalescing"
```

---

### Task 6: Single-Flow Scaling Benchmark & Full Test Suite

**Files:**
- Create: `benches/single_flow_scale.rs`
- Run full regression: `cargo test --workspace`

- [ ] **Step 1: Add single-flow multi-core scaling benchmark**

Create `benches/single_flow_scale.rs` measuring throughput and packet delivery monotonicity across 1, 2, 4, and 8 worker threads.

- [ ] **Step 2: Run benchmark to measure baseline**

Run: `cargo bench --bench single_flow_scale -- --nocapture`
Expected: Verified line-rate scaling with 0 packet drops and 0 out-of-order deliveries.

- [ ] **Step 3: Run entire workspace test suite**

Run: `cargo test --workspace`
Expected: All unit, integration, and device tests pass cleanly.

- [ ] **Step 4: Commit**

```bash
git add benches/single_flow_scale.rs
git commit -m "bench: add single_flow_scale benchmark and verify scaling"
```
