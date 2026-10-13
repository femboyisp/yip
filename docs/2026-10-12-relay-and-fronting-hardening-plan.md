# Relay & Fronting Hardening Suite (#65, #63, #49) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the rendezvous Trojan front against TLS frame flooding (#65) and silent-probe timing side-channels (#63), and bound QUIC mimicry inbound connection allocations against accept-flood memory exhaustion (#49).

**Architecture:**
1. Implement per-connection token bucket rate limiting (`FrameRateLimiter`) in `conn_tunnel.rs` to bound relayed frame rates.
2. Implement concurrent speculative pre-connect to the decoy backend in `conn.rs` so that silent probers experience the decoy's native idle timeout rather than an artificial +3s delay.
3. Implement a hard connection cap (`MAX_QUIC_CONNS`) and unauthenticated connection timeout pruning in `quic.rs`.

**Tech Stack:** Rust (Tokio async I/O, quinn-proto, yip-rendezvous, yipd).

## Global Constraints
- Zero wire format changes.
- All code must pass `cargo test --all`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check`.
- Fail-closed security principles: abuse or unauthenticated stalls are pruned/terminated without affecting established legitimate traffic.

---

### Task 1: Relay TLS-Front Rate Limiting (#65)

**Files:**
- Modify: `bin/yip-rendezvous/src/conn_tunnel.rs`
- Test: `bin/yip-rendezvous/src/conn_tunnel.rs` (unit tests)

**Interfaces:**
- `FrameRateLimiter`: Token bucket tracker with capacity (1,000.0) and replenish rate (250.0 frames/sec).
- `drain_frames(&mut Vec<u8>, &TlsFrontCfg, NodeId, &mut FrameRateLimiter) -> bool`: Checks tokens before `route()`, dropping frames on burst exhaustion and terminating connection if abuse is sustained.

- [ ] **Step 1: Write failing unit test in `bin/yip-rendezvous/src/conn_tunnel.rs`**
  Add unit tests in `mod tests`:
  - `rate_limiter_permits_burst_and_throttles_excess`: verifies `FrameRateLimiter` accepts bursts up to 1,000 frames and rejects subsequent frames once drained until replenished.
  - `drain_frames_throttles_excess_relay_sends`: feeds >1,000 framed `RelaySend` messages into a test buffer and verifies that only the allowed quota is forwarded to the destination channel.

- [ ] **Step 2: Run test to verify failure**
  Run: `cargo test -p yip-rendezvous-bin conn_tunnel::tests::rate_limiter_permits_burst_and_throttles_excess`
  Expected: FAIL (missing `FrameRateLimiter`)

- [ ] **Step 3: Implement `FrameRateLimiter` and integrate into `run_tunnel` / `drain_frames`**
  In `bin/yip-rendezvous/src/conn_tunnel.rs`:
  - Define `FrameRateLimiter`:
    ```rust
    pub(crate) struct FrameRateLimiter {
        capacity: f64,
        tokens: f64,
        replenish_rate: f64,
        last_update: std::time::Instant,
        violations: u32,
    }
    ```
  - Implement `acquire(&mut self, cost: f64, now: std::time::Instant) -> bool`.
  - In `run_tunnel`: instantiate `let mut limiter = FrameRateLimiter::default();`.
  - Pass `&mut limiter` to `drain_frames`.
  - In `drain_frames`: before `route(msg, cfg)`, check `limiter.acquire(1.0, std::time::Instant::now())`. If tokens are exhausted, increment `violations` and drop the frame (log warning). If consecutive violations exceed 2,000, return `false` to fail-closed terminate the connection.

- [ ] **Step 4: Run tests to verify they pass**
  Run: `cargo test -p yip-rendezvous-bin conn_tunnel::tests`
  Expected: PASS

- [ ] **Step 5: Run clippy, fmt, and commit**
  Run: `cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings && cargo fmt --check`
  Commit:
  ```bash
  git add bin/yip-rendezvous/src/conn_tunnel.rs
  git commit -m "fix(relay): add per-connection token bucket rate limiter on TLS front (#65)"
  ```

---

### Task 2: Relay Idle-Connection Timing Side-Channel Elimination (#63)

**Files:**
- Modify: `bin/yip-rendezvous/src/conn.rs`
- Test: `bin/yip-rendezvous/src/conn.rs` (unit tests)

**Interfaces:**
- `handle_connection`: Starts speculative pre-connect `TcpStream::connect(decoy_addr)` in parallel with `read_and_classify`.
- If `Classify::Upgrade`: aborts/cancels speculative decoy connect.
- If timeout / `Classify::Decoy`: immediately splices into the already-connecting/connected decoy stream.

- [ ] **Step 1: Write failing unit test in `bin/yip-rendezvous/src/conn.rs`**
  Add unit test in `mod tests`:
  - `silent_probe_initiates_decoy_connect_at_handshake_start`: launches a local decoy TCP listener, connects a client that stays silent, and verifies that the relay connects to the decoy listener immediately upon receiving the TLS connection, rather than waiting 3s after `CLASSIFY_TIMEOUT`.

- [ ] **Step 2: Run test to verify failure**
  Run: `cargo test -p yip-rendezvous-bin conn::tests::silent_probe_initiates_decoy_connect_at_handshake_start`
  Expected: FAIL

- [ ] **Step 3: Implement speculative decoy connection in `handle_connection`**
  In `bin/yip-rendezvous/src/conn.rs`:
  - In `handle_connection`:
    - If `cfg.decoy.is_some()` and `cfg.reality.is_none()`:
      Spawn speculative background connect future: `let decoy_fut = TcpStream::connect(decoy_addr); tokio::pin!(decoy_fut);`
    - Run `read_and_classify(&mut stream, &cfg, &mut buf, now_ms).await`.
    - If decision is `Upgrade`: cancel/drop `decoy_fut`.
    - If decision is `Decoy` or timeout (`None`):
      Wait on `decoy_fut` (or proceed to `into_decoy_with_stream(stream, &cfg, buf, backend_stream)`).

- [ ] **Step 4: Run tests to verify they pass**
  Run: `cargo test -p yip-rendezvous-bin conn::tests`
  Expected: PASS

- [ ] **Step 5: Run clippy, fmt, and commit**
  Run: `cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings && cargo fmt --check`
  Commit:
  ```bash
  git add bin/yip-rendezvous/src/conn.rs
  git commit -m "fix(relay): pre-connect decoy backend to eliminate silent-probe timing side-channel (#63)"
  ```

---

### Task 3: QUIC Inbound-Connection State Bounding (#49)

**Files:**
- Modify: `bin/yipd/src/quic.rs`
- Test: `bin/yipd/src/quic.rs` (unit tests)

**Interfaces:**
- `MAX_QUIC_CONNS: usize = 256`
- `QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10)`
- `ConnEntry.created_at: Instant`
- `handle_datagram`: Refuses incoming connections via `endpoint.accept()` when capacity is reached and no expired connections can be evicted.
- `drive`: Prunes connections where `now.duration_since(entry.created_at) > QUIC_HANDSHAKE_TIMEOUT && !entry.up`.

- [ ] **Step 1: Write failing unit test in `bin/yipd/src/quic.rs`**
  Add unit tests in `mod tests`:
  - `quic_endpoint_enforces_max_conns_cap`: generates 256 inbound connections, attempts 257th, asserts 257th is rejected/dropped.
  - `quic_endpoint_prunes_stalled_unauthenticated_connections`: creates an unestablished connection, advances virtual time by 11s, calls `drive()`, asserts the connection is reaped.

- [ ] **Step 2: Run tests to verify failure**
  Run: `cargo test -p yipd quic::tests::quic_endpoint_enforces_max_conns_cap`
  Expected: FAIL

- [ ] **Step 3: Implement connection cap and timeout pruning in `bin/yipd/src/quic.rs`**
  In `bin/yipd/src/quic.rs`:
  - Add `created_at: Instant` to `ConnEntry`.
  - In `handle_datagram`:
    ```rust
    if self.conns.len() >= MAX_QUIC_CONNS {
        // Prune any timed out connections immediately
        self.conns.retain(|c| !(now.duration_since(c.created_at) > QUIC_HANDSHAKE_TIMEOUT && !c.up));
    }
    if self.conns.len() >= MAX_QUIC_CONNS {
        // Capacity exhausted; drop new incoming connection
        return;
    }
    ```
  - In `drive`:
    ```rust
    for entry in conns.iter_mut() {
        if !entry.up && now.duration_since(entry.created_at) > QUIC_HANDSHAKE_TIMEOUT {
            entry.dead = true;
        }
        // ...
    }
    conns.retain(|c| !c.dead);
    ```

- [ ] **Step 4: Run tests to verify they pass**
  Run: `cargo test -p yipd quic::tests`
  Expected: PASS

- [ ] **Step 5: Run clippy, fmt, and commit**
  Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
  Commit:
  ```bash
  git add bin/yipd/src/quic.rs
  git commit -m "fix(quic): cap concurrent connections and prune stalled handshakes (#49)"
  ```

---

### Task 4: Integration & Full Suite Verification

**Files:**
- Test: `cargo test --all`
- Test: Netns integration test suite

- [ ] **Step 1: Run full workspace test suite**
  Run: `cargo test --all && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
  Expected: PASS with 0 warnings.

- [ ] **Step 2: Run netns integration tests**
  Run: `sudo -E target/debug/deps/tunnel_netns-* --nocapture --test-threads=1`
  Expected: PASS

- [ ] **Step 3: Whole-branch review and merge**
  - Run diff against base.
  - Merge into `main` and push to `origin/main`.
  - Update and close GitHub issues #65, #63, and #49.
