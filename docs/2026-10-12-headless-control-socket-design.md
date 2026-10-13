# Design Specification: Headless Mode & Control Socket (#124)

**Date:** 2026-10-12
**Status:** Approved
**Scope:** Providing supervisor-friendly headless execution and a local UNIX domain control socket (JSON protocol) for dynamic peer management and transitd integration (`YipDriver`).

---

## 1. Problem Statement & Motivation

Currently, `yipd` requires a static configuration file at launch time (`yipd <config-file>`). Once running, peer additions, removals, and telemetry inspections require restarting the daemon, breaking continuous tunnels.

For automated orchestrators (such as `transitd` via `femboyisp/www#22`):
1. **Headless Execution:** The daemon must run unattended under supervisors (systemd, runit, docker), supporting configuration overrides via environment variables and CLI flags with well-defined exit codes.
2. **Local Control Socket:** A local UNIX domain socket accepting line-delimited JSON commands is required to:
   - Query daemon health, version, uptime, and local address.
   - List active/configured peers with statistics (rx/tx bytes, latency, status, endpoint).
   - Add peers dynamically (`add_peer`).
   - Remove peers dynamically (`remove_peer`).

---

## 2. Architecture & Design

### 2.1 Concurrency Architecture
To protect line-rate dataplane forwarding (e.g. 10G–35G scaling) from slow JSON serialization, parsing, and slow socket clients:
- **Background Control Thread:** A dedicated lightweight thread binds the UNIX domain socket (path configured via `--control <path>` or `control_socket=<path>` in config, defaulting to `/run/yipd/control.sock` or fallback `/tmp/yipd.sock`).
- **Channel Decoupling:** Communicates with the data-plane thread via an asynchronous cross-thread channel:
  - `ControlRequest` sent from the control listener to `PeerManager` / event loop.
  - `ControlResponse` returned via a oneshot channel.
- **Tick Drain:** The event loop drains pending control requests at each tick interval (or epoll wakeup) and executes them synchronously against `PeerManager` with zero lock contention.

### 2.2 Wire Protocol (Newline-Delimited JSON)
Requests and responses are UTF-8 encoded, newline-delimited (`\n`) JSON objects.

#### Supported Commands:
1. **`health` / `status`**:
   - Request: `{"cmd": "status"}`
   - Response:
     ```json
     {
       "ok": true,
       "version": "0.1.0",
       "node_addr": "fdda:...",
       "device": "yip0",
       "peers_count": 2,
       "uptime_secs": 1420
     }
     ```
2. **`list_peers`**:
   - Request: `{"cmd": "list_peers"}`
   - Response:
     ```json
     {
       "ok": true,
       "peers": [
         {
           "public_key": "0123...cdef",
           "endpoint": "198.51.100.1:443",
           "state": "Established",
           "node_addr": "fd...",
           "rx_bytes": 1048576,
           "tx_bytes": 2097152,
           "last_activity_ms": 120
         }
       ]
     }
     ```
3. **`add_peer`**:
   - Request:
     ```json
     {
       "cmd": "add_peer",
       "public_key": "64_hex_digits",
       "endpoint": "198.51.100.1:443"
     }
     ```
   - Response: `{"ok": true, "message": "peer added"}` or `{"ok": false, "error": "invalid pubkey / already exists"}`
4. **`remove_peer`**:
   - Request: `{"cmd": "remove_peer", "public_key": "64_hex_digits"}`
   - Response: `{"ok": true, "message": "peer removed"}` or `{"ok": false, "error": "peer not found"}`

### 2.3 PeerManager Extensions
- Add `PeerManager::add_peer(&mut self, cfg: PeerConfig) -> Result<(), &'static str>`.
- Add `PeerManager::remove_peer(&mut self, pubkey: &[u8; 32]) -> Result<(), &'static str>`.
- Add `PeerManager::peer_stats(&self) -> Vec<PeerStats>`.

---

## 3. Testing & Verification Plan

1. **Unit Tests:**
   - In `peer_manager`: dynamic addition and removal of peers updates `by_node`, `by_tag`, and `peers` cleanly without disrupting ongoing sessions.
   - In `control`: JSON serialization, parsing, error responses for malformed commands, and concurrent client connections.
2. **Integration Tests:**
   - Integration test connecting a UNIX socket client to a running daemon instance, querying status, adding a peer dynamically, verifying traffic routes, and removing the peer.
3. **CLI & Headless Verification:**
   - Verify non-interactive execution with `--control /tmp/test.sock` and environment variable overrides.
