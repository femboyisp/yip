# Design Specification: TLS Transport Pump Hardening (#61)

- **Date:** 2026-10-13
- **Author:** Antigravity / Pair Programming
- **Target Issue:** [#61](https://github.com/femboyisp/yip/issues/61) — "transport=tls: single-connection pump — completed-idle slot hold + silent multi-peer drop"
- **Target Branch:** `feat/tls-pump-hardening`

---

## 1. Context & Motivation

The `transport=tls` mimicry transport in `bin/yipd/src/tls.rs` wraps yip's inner Noise-IK/FEC/AEAD protocol inside length-prefixed TLS datagrams. Under its single-connection design (`run_tls`), two operational limitations exist:

1. **Completed-Idle Slot Hold:**
   Outer TLS is zero-auth by design (using throwaway self-signed certificates and browser-mimicry ClientHellos; real authentication happens via inner Noise-IK). A port scanner or attacker can complete the outer TLS handshake and remain completely silent. Because `pump()` previously exited only on TLS/TCP I/O or framing errors, an idle zero-auth TLS connection pins the single transport slot indefinitely, locking out the legitimate peer.
2. **Silent Multi-Peer Drop:**
   `run_tls` silently serves only `peers.first()` and ignores any additional configured peers without warning, leading to silent packet loss in multi-peer deployments.

---

## 2. Invariants & Security Constraints

1. **Fail-Closed Availability Defense:**
   A connection that does not complete an inner Noise-IK handshake within `INNER_HANDSHAKE_TIMEOUT` (10s) must be cleanly torn down (`Ok(())`), returning `run_tls` to its `accept` / connect retry loop.
2. **Zero Wire Format Changes:**
   Outer TLS records and inner length-prefixed datagram framing remain identical.
3. **Transparent Operational Logging:**
   Multi-peer configurations under `transport=tls` must emit clear operational warnings at both configuration parsing time and runtime loop launch.
4. **Non-blocking & Safe Concurrency:**
   All operations remain non-blocking within the 2-fd `Epoll` model.

---

## 3. Architecture & Data Flow

```
run_tls
   │
   ├── Check peers.len() > 1 -> Warn if true
   │
   ├── accept_and_handshake / connect_and_handshake (outer TLS)
   │
   └── pump(stream, poller, tun_fd, manager, peer_addr, peer_public, start)
         │
         ├── conn_start = Instant::now()
         │
         ├── Poller loop:
         │     ├── TLS-readable -> drain -> de-frame -> manager.on_udp
         │     │     └── If manager.is_peer_established(peer_public) -> inner_confirmed = true
         │     │
         │     ├── TUN-readable -> drain -> manager.on_tun -> TLS egress
         │     │
         │     ├── Cadence tick (10ms) -> manager.tick -> TLS egress
         │     │
         │     └── Deadline check:
         │           if !inner_confirmed && conn_start.elapsed() >= INNER_HANDSHAKE_TIMEOUT:
         │               log teardown
         │               return Ok(())  --> triggers re-accept / reconnect in run_tls
```

---

## 4. Detailed Component Changes

### 1. `bin/yipd/src/peer_manager/mod.rs`
Add `is_peer_established`:
```rust
pub fn is_peer_established(&self, pubkey: &[u8; 32]) -> bool {
    self.peers
        .iter()
        .any(|p| p.pubkey == *pubkey && matches!(p.state, PeerState::Established(_)))
}
```

### 2. `bin/yipd/src/tls.rs`
- Define `pub(crate) const INNER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);`.
- Update `pump` to accept `peer_public: [u8; 32]`.
- Track `inner_confirmed` and evaluate `conn_start.elapsed() >= INNER_HANDSHAKE_TIMEOUT`.
- Update `run_tls` to log a warning when `peers.len() > 1`.

### 3. `bin/yipd/src/config.rs`
- In `Config::from_str`, log a warning when `transport == TransportMode::Tls && peers.len() > 1`.

---

## 5. Verification Plan

- Unit test `is_peer_established_reports_correct_state` in `peer_manager/tests.rs`.
- Unit test `pump_drops_completed_idle_connection_after_deadline` in `tls.rs`.
- Workspace test pass: `cargo test --all`.
- Workspace clippy & fmt: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`.
