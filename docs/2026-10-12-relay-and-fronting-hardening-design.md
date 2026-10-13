# Design Specification: Relay & Fronting Hardening Suite (#65, #63, #49)

**Date:** 2026-10-12
**Status:** Approved
**Scope:** Hardening the rendezvous TLS Trojan front against frame-flooding DoS (#65) and silent-probe timing side-channels (#63), and bounding QUIC costume inbound connection allocations against accept-flood memory exhaustion (#49).

---

## 1. Problem Statement & Threat Model

1. **#65 (TLS-Front Rate Limiting):**
   The blind relay's TLS front (`bin/yip-rendezvous/src/conn_tunnel.rs`) forwards decoded `RelaySend` messages to destination channels with no per-connection rate limit. A single upgraded peer can pump unlimited frames per second, exhausting CPU, outbound bandwidth, and filling destination channels.
2. **#63 (Idle-Connection Timing Side-Channel):**
   In `bin/yip-rendezvous/src/conn.rs`, `read_and_classify` trial-reads the first frame with a 3-second timeout (`CLASSIFY_TIMEOUT`). If an active prober opens a TLS connection and sends nothing, the relay waits 3s before connecting to the backend decoy (`into_decoy`). The observable idle time-to-close is `3s + decoy_timeout` (~63s) rather than the decoy's native timeout (~60s), leaking a timing side-channel that reveals the presence of the Trojan front.
3. **#49 (QUIC Inbound-Connection State Bounding):**
   In `bin/yipd/src/quic.rs`, `handle_datagram` accepts any inbound QUIC Initial with a new DCID via `endpoint.accept()`, pushing a `ConnEntry` to `self.conns` with no upper bound or timeout on uncompleted handshakes. A flood of spoofed or varied DCIDs grows `self.conns` without limit, leading to memory exhaustion and $O(n^2)$ lookup degradation.

---

## 2. Architecture & Detailed Design

### 2.1 Subsystem 1: Relay TLS-Front Rate Limiter (#65)
- **Component:** `bin/yip-rendezvous/src/conn_tunnel.rs`
- **Mechanism:** Per-connection token bucket rate limiter.
  - Structure:
    ```rust
    pub struct FrameRateLimiter {
        capacity: f64,
        tokens: f64,
        replenish_rate: f64, // tokens per second
        last_update: std::time::Instant,
    }
    ```
  - Default parameters:
    - `capacity`: 1,000.0 frames (burst tolerance for bulk traffic).
    - `replenish_rate`: 250.0 frames/sec (sustainable baseline rate per TLS tunnel connection).
  - Enforcement in `drain_frames`:
    - Before calling `route()`, check `rate_limiter.acquire(1.0)`.
    - If tokens are available: route frame.
    - If rate exceeded: drop the frame and increment a connection-scoped violation counter. If sustained violations exceed a grace threshold (or sustained drain for >2s), terminate connection cleanly (fail-closed against DoS).
  - Integration: Zero global lock contention; each `run_tunnel` owns its `FrameRateLimiter` instance on its local stack/task.

### 2.2 Subsystem 2: Decoy Pre-Connect Timing Side-Channel Elimination (#63)
- **Component:** `bin/yip-rendezvous/src/conn.rs`
- **Mechanism:** Speculative parallel pre-connect to decoy backend.
  - When a connection arrives in `handle_connection`:
    - If a `decoy_addr` is configured: start `TcpStream::connect(decoy_addr)` speculatively in the background (or as an async future) concurrently with `read_and_classify`.
    - If `decision` is `Classify::Upgrade`: abort / drop the pending decoy connect future immediately. The client upgrades to `run_tunnel` with zero decoy overhead.
    - If `decision` is `None` (idle timeout) or `Classify::Decoy`: await the pending decoy connection (which has already been connecting or waiting in parallel since client connect time `t=0`). Splice the client stream to the decoy backend.
  - **Result:** The decoy's native idle timeout clock runs from the exact moment the client connected, eliminating the +3s differential. A silent prober observes identical time-to-close as direct access to the backend decoy.

### 2.3 Subsystem 3: QUIC Inbound-Connection State Bounding (#49)
- **Component:** `bin/yipd/src/quic.rs`
- **Mechanism:** Hard cap on concurrent connections + uncompleted handshake timeout pruning.
  - Constants:
    - `MAX_QUIC_CONNS: usize = 256` (maximum concurrent QUIC connections in `QuicEndpoint`).
    - `QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10)` (grace period to achieve `entry.up == true`).
  - State tracking in `ConnEntry`:
    ```rust
    struct ConnEntry {
        handle: ConnectionHandle,
        conn: Connection,
        peer_addr: SocketAddr,
        up: bool,
        dead: bool,
        created_at: Instant,
    }
    ```
  - Enforcement in `handle_datagram`:
    - On `DatagramEvent::NewConnection`:
      - If `self.conns.len() >= MAX_QUIC_CONNS`: reject or drop the incoming connection unless unestablished/expired connections can be pruned immediately. If capacity is exhausted, do not call `endpoint.accept()`.
  - Enforcement in `drive`:
    - Check `now.duration_since(entry.created_at) > QUIC_HANDSHAKE_TIMEOUT && !entry.up`.
    - If timed out: mark `entry.dead = true`.
    - `conns.retain(|c| !c.dead)` drops stale unestablished state, preserving bounded memory and fast lookups.

---

## 3. Testing & Verification Plan

1. **Unit Tests:**
   - `conn_tunnel::tests`: Test `FrameRateLimiter` allows bursts up to capacity and throttles/drops sustained rates beyond `replenish_rate`.
   - `conn::tests`: Test speculative decoy pre-connect forwards instantly upon timeout or early non-yip frame, while legitimate `Upgrade` drops the speculative connection.
   - `quic::tests`: Test `handle_datagram` enforces `MAX_QUIC_CONNS` and prunes stalled unauthenticated connections after `QUIC_HANDSHAKE_TIMEOUT`.
2. **Workspace Verification:**
   - `cargo test --all`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo fmt --check`
   - Netns tunnel tests.
