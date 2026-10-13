# Multi-Peer TLS Transport Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement full multi-peer mesh support for `transport = tls` in `yipd` by introducing a safe dynamic multi-fd Epoll primitive in `yip-io` and a non-blocking multi-peer event pump in `tls.rs`.

**Architecture:** Extend `crates/yip-io/src/epoll.rs` with safe dynamic registration (`add`, `remove`, `wait_tokens`), preserving `#![forbid(unsafe_code)]` in `yipd`. In `bin/yipd/src/tls.rs`, maintain pairwise static-key roles (`Role::Client` dials, `Role::Server` listens), multiplexing $N$ peer TLS byte-streams alongside `tun_fd` and `listener_fd` on a single non-blocking event loop.

**Tech Stack:** Rust (BoringSSL/`boring` crate, `libc` epoll, `yip-io`, `PeerManager`).

## Global Constraints

- Zero wire format or protocol changes: length-prefixed framing `[u16 BE length][datagram]` and BoringSSL outer TLS 1.3 parameters remain identical.
- Strictly enforce `#![forbid(unsafe_code)]` in `bin/yipd`; all epoll syscalls remain encapsulated in `crates/yip-io`.
- Fail-closed security invariants: unconfirmed connections exceeding `INNER_HANDSHAKE_TIMEOUT` (10s) are cleanly torn down.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes.

---

### Task 1: Dynamic Multi-FD Epoll Primitive in `yip-io`

**Files:**
- Modify: `crates/yip-io/src/epoll.rs`
- Test: `crates/yip-io/src/epoll.rs` (`mod tests`)

**Interfaces:**
- Consumes: `libc` epoll bindings
- Produces:
  ```rust
  impl Epoll {
      pub fn create() -> io::Result<Self>;
      pub fn add(&self, fd: RawFd, token: u64) -> io::Result<()>;
      pub fn remove(&self, fd: RawFd) -> io::Result<()>;
      pub fn wait_tokens(&self, timeout_ms: i32, out: &mut Vec<u64>) -> io::Result<()>;
  }
  ```

- [ ] **Step 1: Write the failing tests in `crates/yip-io/src/epoll.rs`**

```rust
#[test]
fn epoll_dynamic_add_remove_and_wait_tokens() {
    let epoll = Epoll::create().expect("create epoll");
    let mut fds = [0; 2];
    unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
    }
    let (rx, tx) = (fds[0], fds[1]);

    epoll.add(rx, 42).expect("add rx fd");

    let mut ready = Vec::new();
    epoll.wait_tokens(0, &mut ready).expect("wait");
    assert!(ready.is_empty());

    // Write byte to pipe
    assert_eq!(unsafe { libc::write(tx, [1u8].as_ptr().cast(), 1) }, 1);

    epoll.wait_tokens(50, &mut ready).expect("wait");
    assert_eq!(ready, vec![42]);

    epoll.remove(rx).expect("remove rx fd");
    ready.clear();
    epoll.wait_tokens(0, &mut ready).expect("wait");
    assert!(ready.is_empty());

    unsafe {
        libc::close(rx);
        libc::close(tx);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-io epoll_dynamic`
Expected: FAIL (methods not yet defined)

- [ ] **Step 3: Implement dynamic multi-FD methods in `crates/yip-io/src/epoll.rs`**

Add `Epoll::create()`, `Epoll::add()`, `Epoll::remove()`, and `Epoll::wait_tokens()`. Refactor `Epoll::new(udp_fd, tun_fd)` to call `create()` and register the two fds, keeping existing `wait(&self, timeout_ms)` compatible for `quic.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-io`
Expected: PASS

- [ ] **Step 5: Verify clippy and formatting**

Run: `cargo clippy -p yip-io --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS with 0 warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-io/src/epoll.rs
git commit -m "feat(yip-io): add dynamic multi-fd registration and wait_tokens to Epoll (#136)"
```

---

### Task 2: Multi-Peer Connection Management & Lifecycle in `tls.rs`

**Files:**
- Modify: `bin/yipd/src/tls.rs`
- Test: `bin/yipd/src/tls.rs` (`mod tests`)

**Interfaces:**
- Consumes: `yip_io::epoll::Epoll` (`create`, `add`, `remove`, `wait_tokens`)
- Produces:
  ```rust
  enum PeerConn {
      Disconnected { backoff_ms: u64, next_dial: Instant },
      Connecting { stream: SslStream<TcpStream>, start: Instant },
      Connected {
          stream: SslStream<TcpStream>,
          reader: FrameReader,
          start: Instant,
          inner_confirmed: bool,
          was_established: bool,
      },
  }
  ```

- [ ] **Step 1: Write failing unit tests for multi-peer role classification and lifecycle in `bin/yipd/src/tls.rs`**

Add tests:
- `multi_peer_role_assignment`: Given local pubkey and 3 peers, correctly assigns `Role::Client` to peers with greater pubkeys and `Role::Server` to peers with smaller pubkeys.
- `multi_peer_reconnect_backoff_timing`: Verifies that failed client connections double backoff up to `MAX_BACKOFF_MS`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p yipd tls::tests::multi_peer`
Expected: FAIL

- [ ] **Step 3: Implement `PeerConn` state machine and lifecycle helpers in `bin/yipd/src/tls.rs`**

- Define `PeerConn` enum with `Disconnected`, `Connecting`, `Connected`.
- Implement non-blocking `try_connect(peer_addr, tls_sni)` which sets up non-blocking stream and initiates TLS handshake.
- Enforce `INNER_HANDSHAKE_TIMEOUT` per connected stream.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd tls::tests::multi_peer`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/tls.rs
git commit -m "feat(tls): implement multi-peer connection lifecycle and role assignment (#136)"
```

---

### Task 3: Multi-Peer Data Pump & Egress Demux in `tls.rs`

**Files:**
- Modify: `bin/yipd/src/tls.rs`
- Test: `bin/yipd/src/tls.rs` (`mod tests`)

**Interfaces:**
- Consumes: `PeerManager` (`on_udp`, `on_tun`, `tick`), `Epoll::wait_tokens`
- Produces:
  ```rust
  pub(crate) fn run_tls(
      tun_fd: RawFd,
      manager: &mut PeerManager,
      local_public: [u8; 32],
      peers: &[([u8; 32], SocketAddr)],
      listen: SocketAddr,
      listen_port_auto: bool,
      tls_sni: &str,
  ) -> io::Result<()>;
  ```

- [ ] **Step 1: Write failing mock test driving 2 concurrent TLS peers through `pump` in `bin/yipd/src/tls.rs`**

Add `drive_multi_peer_concurrent_pump`:
- Sets up mock loopback streams for 2 distinct peers.
- Feeds inbound frames from Peer 1 and Peer 2.
- Verifies that frames from both peers are successfully fed into `manager.on_udp` with correct addresses, and TUN egress for Peer 2 routes to Peer 2's stream without leaking to Peer 1.

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p yipd tls::tests::drive_multi_peer_concurrent_pump`
Expected: FAIL

- [ ] **Step 3: Refactor `pump` and `run_tls` to drive the multi-peer event loop**

- Replace single-stream epoll with dynamic multi-token epoll:
  - Register `tun_fd` under `TOKEN_TUN = 0`.
  - If any peer has `Role::Server`, bind `TcpListener` and register under `TOKEN_LISTENER = 1`.
  - For each connected peer stream, register under `TOKEN_PEER_BASE + idx`.
- On `TOKEN_LISTENER`: accept incoming TCP connections, complete server TLS handshake, associate with matching server peer.
- On `TOKEN_PEER_BASE + idx`: drain TLS read, deframe datagrams, feed `manager.on_udp(peer_addr, &dg, now_ms)`, forward TUN packets, send immediate replies.
- On `TOKEN_TUN`: read `tun_fd`, feed `manager.on_tun`, route egress to matching peer stream by `d.dst`.
- On tick ($\le 10$ ms): call `manager.tick(now_ms)`, route egress datagrams, check client reconnect deadlines, reap unconfirmed streams over 10s.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd tls::tests`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/tls.rs
git commit -m "feat(tls): multiplex multi-peer ingress, egress and tick in pump (#136)"
```

---

### Task 4: Config Updates, Warnings Cleanup & Workspace Verification

**Files:**
- Modify: `bin/yipd/src/config.rs`
- Modify: `bin/yipd/src/tls.rs`
- Test: All workspace tests

**Interfaces:**
- Remove the temporary single-peer warning in `bin/yipd/src/config.rs` and `bin/yipd/src/tls.rs`.

- [ ] **Step 1: Remove multi-peer TLS warnings and update config tests**

In `bin/yipd/src/config.rs`, remove the `eprintln!("config: warning: transport=tls currently supports only a single peer...")` and update config test expectations.
In `bin/yipd/src/tls.rs`, remove the single-peer warning in `run_tls`.

- [ ] **Step 2: Run workspace unit and integration tests**

Run: `cargo test --all`
Expected: All tests PASS.

- [ ] **Step 3: Run clippy and format check across workspace**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: 0 warnings, formatting clean.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/config.rs bin/yipd/src/tls.rs
git commit -m "chore(tls): remove single-peer TLS warnings and verify workspace (#136)"
```
