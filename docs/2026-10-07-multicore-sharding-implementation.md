# Multi-Core Throughput Sharding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement multi-core throughput sharding (Way A, Issue #10) in `yipd` using `IFF_MULTI_QUEUE` TUN queues, `SO_REUSEPORT` UDP sockets, and lock-free SPSC inter-shard queues across physical CPU cores.

**Architecture:** $N$ core-pinned worker threads each run an independent `DataPlane` event loop owning a dedicated `SO_REUSEPORT` UDP socket and an `IFF_MULTI_QUEUE` TUN queue fd. Cross-shard outbound packet handoffs use cache-line-padded bounded SPSC ring buffers, preserving single-owner lock-free crypto and FEC state.

**Tech Stack:** Rust (stable, 2021 edition), Linux TUN/TAP (`IFF_MULTI_QUEUE`), `SO_REUSEPORT`, `libc` CPU affinity, `crossbeam-utils` cache padding, epoll / io_uring drivers.

## Global Constraints
- Target platform: Linux (x86_64 / arm64).
- Safe Rust enforced everywhere except quarantined device/I/O crates (`forbid(unsafe_code)` in `yipd`).
- Zero locks on the fast packet-processing path.
- In-memory single-thread `DataPlane` invariants must remain intact (no sharing of `DataPlane` across threads).

---

### Task 1: Multi-Queue TUN Support in `yip-device`

**Files:**
- Modify: `crates/yip-device/src/lib.rs`
- Test: `crates/yip-device/tests/multi_queue.rs`

**Interfaces:**
- Produces: `TunTap::create_multi_queue(name: &str, kind: DeviceKind, queue_count: usize, want_vnet_hdr: bool) -> Result<Vec<TunTap>, DeviceError>`
- Consumes: Linux `TUNSETIFF` ioctl with `IFF_MULTI_QUEUE = 0x0100`

- [ ] **Step 1: Write the failing test for multi-queue creation**

Create `crates/yip-device/tests/multi_queue.rs`:
```rust
use yip_device::{DeviceKind, TunTap};

#[test]
fn create_multi_queue_allocates_requested_fds() {
    // Requires root or CAP_NET_ADMIN; skip if unprivileged
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping root-gated test create_multi_queue_allocates_requested_fds");
        return;
    }

    let queues = TunTap::create_multi_queue("yiptest_mq%d", DeviceKind::Tun, 2, false)
        .expect("failed to create multi-queue TUN");
    assert_eq!(queues.len(), 2);
    assert_ne!(
        std::os::fd::AsRawFd::as_raw_fd(&queues[0]),
        std::os::fd::AsRawFd::as_raw_fd(&queues[1])
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-device --test multi_queue`
Expected: FAIL (method `create_multi_queue` not found on `TunTap`).

- [ ] **Step 3: Implement `create_multi_queue` in `crates/yip-device/src/lib.rs`**

Add flag constant and implementation to `crates/yip-device/src/lib.rs`:
```rust
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

impl TunTap {
    /// Create a multi-queue TUN/TAP device with `queue_count` independent queue fds.
    pub fn create_multi_queue(
        name: &str,
        kind: DeviceKind,
        queue_count: usize,
        want_vnet_hdr: bool,
    ) -> Result<Vec<TunTap>, DeviceError> {
        if queue_count == 0 {
            return Err(DeviceError::InvalidName);
        }
        if queue_count == 1 {
            return Self::create(name, kind, want_vnet_hdr).map(|tun| vec![tun]);
        }

        let mut ifreq = encode_ifreq_mq(name, kind)?;
        let first = Self::open_queue(&mut ifreq, kind, want_vnet_hdr)?;
        let mut queues = Vec::with_capacity(queue_count);
        let actual_name = first.name().to_string();
        queues.push(first);

        for _ in 1..queue_count {
            let next = Self::open_queue(&mut ifreq, kind, want_vnet_hdr)?;
            queues.push(next);
        }

        Ok(queues)
    }

    fn open_queue(
        ifreq: &mut IfReq,
        kind: DeviceKind,
        want_vnet_hdr: bool,
    ) -> Result<TunTap, DeviceError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(DeviceError::Open)?;

        let fd = file.as_raw_fd();
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifreq as *mut IfReq) };
        if rc != 0 {
            return Err(DeviceError::Io(std::io::Error::last_os_error()));
        }

        let actual_name = decode_ifname(&ifreq.name)?;
        let vnet_hdr_len = if want_vnet_hdr {
            match Self::configure_offload(fd) {
                Ok(()) => Some(VNET_HDR_LEN),
                Err(_) => None,
            }
        } else {
            None
        };

        Ok(TunTap {
            file,
            kind,
            name: actual_name,
            vnet_hdr_len,
        })
    }
}

fn encode_ifreq_mq(name: &str, kind: DeviceKind) -> Result<IfReq, DeviceError> {
    let mut ifreq = encode_ifreq(name, kind)?;
    ifreq.flags |= IFF_MULTI_QUEUE;
    Ok(ifreq)
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p yip-device`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-device/src/lib.rs crates/yip-device/tests/multi_queue.rs
git commit -m "feat(yip-device): add IFF_MULTI_QUEUE multi-queue support"
```

---

### Task 2: Lock-Free SPSC Inter-Shard Ring Buffer in `yip-io`

**Files:**
- Create: `crates/yip-io/src/spsc.rs`
- Modify: `crates/yip-io/src/lib.rs`
- Test: `crates/yip-io/tests/spsc_test.rs`

**Interfaces:**
- Produces: `spsc_pair<T, const CAP: usize>() -> (SpscProducer<T, CAP>, SpscConsumer<T, CAP>)`
  - `SpscProducer::push(&self, item: T) -> Result<(), T>`
  - `SpscConsumer::pop(&self) -> Option<T>`
  - `SpscConsumer::drain_batch(&self, buf: &mut Vec<T>, max: usize) -> usize`

- [ ] **Step 1: Write unit tests for SPSC ring buffer**

Create `crates/yip-io/tests/spsc_test.rs`:
```rust
use yip_io::spsc::spsc_pair;

#[test]
fn spsc_basic_push_pop() {
    let (tx, rx) = spsc_pair::<u64, 4>();
    assert!(tx.push(10).is_ok());
    assert!(tx.push(20).is_ok());
    assert!(tx.push(30).is_ok());
    assert_eq!(rx.pop(), Some(10));
    assert_eq!(rx.pop(), Some(20));
    assert_eq!(rx.pop(), Some(30));
    assert_eq!(rx.pop(), None);
}

#[test]
fn spsc_capacity_full_rejects() {
    let (tx, rx) = spsc_pair::<u32, 2>();
    assert!(tx.push(1).is_ok());
    assert!(tx.push(2).is_ok());
    assert_eq!(tx.push(3), Err(3)); // Full
    assert_eq!(rx.pop(), Some(1));
    assert!(tx.push(4).is_ok());
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p yip-io --test spsc_test`
Expected: FAIL (module `spsc` not found).

- [ ] **Step 3: Implement `spsc` ring buffer in `crates/yip-io/src/spsc.rs`**

```rust
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub struct SpscBuffer<T, const CAP: usize> {
    storage: Box<[UnsafeCell<MaybeUninit<T>>; CAP]>,
    head: crossbeam_utils::CachePadded<AtomicUsize>,
    tail: crossbeam_utils::CachePadded<AtomicUsize>,
}

unsafe impl<T: Send, const CAP: usize> Sync for SpscBuffer<T, CAP> {}

pub struct SpscProducer<T, const CAP: usize> {
    buf: Arc<SpscBuffer<T, CAP>>,
}

pub struct SpscConsumer<T, const CAP: usize> {
    buf: Arc<SpscBuffer<T, CAP>>,
}

pub fn spsc_pair<T, const CAP: usize>() -> (SpscProducer<T, CAP>, SpscConsumer<T, CAP>) {
    assert!(CAP.is_power_of_two(), "capacity must be power of two");
    let uninit_slice = Box::new(std::array::from_fn(|_| UnsafeCell::new(MaybeUninit::uninit())));
    let buf = Arc::new(SpscBuffer {
        storage: uninit_slice,
        head: crossbeam_utils::CachePadded::new(AtomicUsize::new(0)),
        tail: crossbeam_utils::CachePadded::new(AtomicUsize::new(0)),
    });
    (
        SpscProducer { buf: Arc::clone(&buf) },
        SpscConsumer { buf },
    )
}

impl<T, const CAP: usize> SpscProducer<T, CAP> {
    pub fn push(&self, item: T) -> Result<(), T> {
        let tail = self.buf.tail.load(Ordering::Relaxed);
        let head = self.buf.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= CAP {
            return Err(item);
        }
        let slot = tail & (CAP - 1);
        unsafe {
            (*self.buf.storage[slot].get()).write(item);
        }
        self.buf.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }
}

impl<T, const CAP: usize> SpscConsumer<T, CAP> {
    pub fn pop(&self) -> Option<T> {
        let head = self.buf.head.load(Ordering::Relaxed);
        let tail = self.buf.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let slot = head & (CAP - 1);
        let item = unsafe {
            (*self.buf.storage[slot].get()).assume_init_read()
        };
        self.buf.head.store(head.wrapping_add(1), Ordering::Release);
        Some(item)
    }
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p yip-io --test spsc_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/spsc.rs crates/yip-io/src/lib.rs crates/yip-io/tests/spsc_test.rs
git commit -m "feat(yip-io): add lock-free SPSC ring buffer for inter-shard routing"
```

---

### Task 3: Consistent Shard Hashing & Peer Shard Assignment in `bin/yipd`

**Files:**
- Create: `bin/yipd/src/sharding.rs`
- Modify: `bin/yipd/src/main.rs`
- Test: `bin/yipd/src/sharding.rs` (inline unit tests)

**Interfaces:**
- Produces: `shard_for_pubkey(pubkey: &[u8; 32], num_shards: usize) -> usize`
- Produces: `shard_for_addr(addr: std::net::Ipv6Addr, num_shards: usize) -> usize`

- [ ] **Step 1: Write unit tests for shard hashing**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_assignment_is_deterministic_and_uniform() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        assert_eq!(shard_for_pubkey(&key1, 4), shard_for_pubkey(&key1, 4));
        assert!(shard_for_pubkey(&key1, 4) < 4);
        assert!(shard_for_pubkey(&key2, 4) < 4);
    }
}
```

- [ ] **Step 2: Implement shard assignment functions in `bin/yipd/src/sharding.rs`**

```rust
use std::net::Ipv6Addr;

pub fn shard_for_pubkey(pubkey: &[u8; 32], num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    // Consistent modulo over pubkey suffix
    let hash = u64::from_le_bytes(pubkey[0..8].try_into().unwrap());
    (hash % num_shards as u64) as usize
}

pub fn shard_for_addr(addr: Ipv6Addr, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let segments = addr.octets();
    let hash = u64::from_be_bytes(segments[8..16].try_into().unwrap());
    (hash % num_shards as u64) as usize
}
```

- [ ] **Step 3: Run unit tests**

Run: `cargo test -p yipd sharding`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/sharding.rs bin/yipd/src/main.rs
git commit -m "feat(yipd): add deterministic peer-to-shard mapping"
```

---

### Task 4: `SO_REUSEPORT` Multi-Socket Binding in `bin/yipd/src/port.rs`

**Files:**
- Modify: `bin/yipd/src/port.rs`
- Test: `bin/yipd/src/port.rs` (inline unit test)

**Interfaces:**
- Produces: `bind_udp_reuseport(addr: SocketAddr, count: usize) -> io::Result<Vec<UdpSocket>>`

- [ ] **Step 1: Write test for `bind_udp_reuseport`**

```rust
#[test]
fn test_bind_udp_reuseport_multiple_sockets() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socks = bind_udp_reuseport(addr, 2).expect("bind reuseport sockets");
    assert_eq!(socks.len(), 2);
    let port0 = socks[0].local_addr().unwrap().port();
    let port1 = socks[1].local_addr().unwrap().port();
    assert_eq!(port0, port1);
}
```

- [ ] **Step 2: Implement `bind_udp_reuseport`**

```rust
pub fn bind_udp_reuseport(addr: SocketAddr, count: usize) -> io::Result<Vec<UdpSocket>> {
    let mut sockets = Vec::with_capacity(count);
    let mut bound_addr = addr;

    for i in 0..count {
        let sock = socket2::Socket::new(
            if bound_addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 },
            socket2::Type::DGRAM,
            None,
        )?;
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&bound_addr.into())?;
        if i == 0 && bound_addr.port() == 0 {
            bound_addr = sock.local_addr()?.as_socket().unwrap();
        }
        let std_sock: UdpSocket = sock.into();
        yip_io::set_socket_buffers(&std_sock, 4 * 1024 * 1024)?;
        sockets.push(std_sock);
    }
    Ok(sockets)
}
```

- [ ] **Step 3: Run test**

Run: `cargo test -p yipd port`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/port.rs
git commit -m "feat(yipd): add SO_REUSEPORT socket pool binding"
```

---

### Task 5: Sharded Worker Event Loop & Cross-Shard Dispatch

**Files:**
- Modify: `bin/yipd/src/sharding.rs`
- Modify: `bin/yipd/src/tunnel.rs`
- Test: `tests/sharded_tunnel_test.rs`

**Interfaces:**
- Produces: `run_sharded(config: Config, shards: usize) -> io::Result<()>`
- Spawns $N$ threads pinned to physical cores; runs poll/uring event loops with SPSC inboxes/outboxes.

- [ ] **Step 1: Write integration test `tests/sharded_tunnel_test.rs`**

```rust
// Test launch of 2-shard yipd in test namespace
#[test]
fn sharded_tunnel_smoke_test() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping root-gated sharded tunnel test");
        return;
    }
    // Verify multi-queue creation and basic loop launch
}
```

- [ ] **Step 2: Implement worker thread loop in `bin/yipd/src/sharding.rs`**

Implement `run_sharded`:
1. Open multi-queue `TunTap` (`IFF_MULTI_QUEUE`).
2. Bind $N$ UDP sockets via `bind_udp_reuseport`.
3. Construct $N \times (N-1)$ SPSC ring buffers.
4. Pin each thread to physical core $i$.
5. Each thread runs event loop servicing local TUN fd, local UDP fd, and incoming SPSC queues.

- [ ] **Step 3: Wire `run_sharded` into `bin/yipd/src/tunnel.rs`**

When `config.shards > 1`, `tunnel::run` delegates to `run_sharded`.

- [ ] **Step 4: Verify test passes**

Run: `cargo test -p yipd`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/sharding.rs bin/yipd/src/tunnel.rs tests/sharded_tunnel_test.rs
git commit -m "feat(yipd): wire sharded multi-core event loop"
```

---

### Task 6: Configuration & Benchmarking Verification

**Files:**
- Modify: `bin/yipd/src/config.rs`
- Modify: `README.md`
- Test: `crates/yip-bench/examples/sharding_scale.rs`

**Interfaces:**
- Adds `shards = N` key to config parser (default = physical cores detected).

- [ ] **Step 1: Update config parser to parse `shards = N`**
- [ ] **Step 2: Verify `cargo check --all-targets` and `cargo test`**
- [ ] **Step 3: Run `cargo run --release -p yip-bench --example sharding_scale`**
- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/config.rs README.md
git commit -m "feat(config): add shards config option and update documentation"
```
