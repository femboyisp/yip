# Headless Mode & Control Socket (#124) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable headless daemon execution and a local UNIX domain control socket (JSON protocol) for dynamic peer addition/removal, status inspection, and `transitd` integration.

**Architecture:**
1. Extend `PeerManager` with dynamic peer addition (`add_peer`), peer removal (`remove_peer`), and inspection methods (`peer_stats`).
2. Build `bin/yipd/src/control.rs` implementing a non-blocking UNIX domain socket server with a JSON protocol (`status`, `list_peers`, `add_peer`, `remove_peer`).
3. Integrate control channel draining into `tunnel.rs` / `PeerManager::tick` without locking or slowing the dataplane loop.
4. Support `--control <path>` CLI argument and `control_socket=<path>` in config.

**Tech Stack:** Rust (standard library `std::os::unix::net`, serde_json, epoll / crossbeam / std::sync::mpsc).

## Global Constraints
- Zero wire format changes.
- All code must pass `cargo test --all`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check`.
- Non-blocking design: control socket operations must never block the data-plane event loop.

---

### Task 1: Dynamic Peer Management in `PeerManager` (#124 Part 1)

**Files:**
- Modify: `bin/yipd/src/peer_manager/mod.rs`
- Test: `bin/yipd/src/peer_manager/mod.rs` (unit tests)

**Interfaces:**
- `PeerManager::add_peer(&mut self, cfg: PeerConfig) -> Result<(), &'static str>`: Adds a new `Idle` peer, updates `by_node`, `by_addr`.
- `PeerManager::remove_peer(&mut self, pubkey: &[u8; 32]) -> Result<(), &'static str>`: Teardown and evict a peer by public key, removing its mappings from `by_tag`, `by_node`, `by_addr`.
- `PeerManager::peer_stats(&self) -> Vec<PeerStats>`: Collects telemetry (node_addr, state, endpoint, last_activity_ms, rx/tx stats).

- [ ] **Step 1: Write failing unit tests in `bin/yipd/src/peer_manager/mod.rs`**
  Add unit tests in `mod tests`:
  - `dynamic_add_peer_updates_mappings_and_routes`: adds a peer dynamically to an existing `PeerManager`, sends a TUN packet, verifies handshake initiates to the new peer.
  - `dynamic_remove_peer_cleans_mappings_and_tears_down`: removes a peer, verifies subsequent packets to that node address or from that endpoint/tag are dropped.

- [ ] **Step 2: Run tests to verify failure**
  Run: `cargo test -p yipd peer_manager::tests::dynamic_add_peer_updates_mappings_and_routes`
  Expected: FAIL (missing methods)

- [ ] **Step 3: Implement `add_peer`, `remove_peer`, and `peer_stats` in `PeerManager`**
  In `bin/yipd/src/peer_manager/mod.rs`:
  - Implement:
    ```rust
    pub struct PeerStats {
        pub public_key: [u8; 32],
        pub endpoint: Option<SocketAddr>,
        pub node_addr: std::net::Ipv6Addr,
        pub state: &'static str,
        pub last_activity_ms: u64,
    }

    impl PeerManager {
        pub fn add_peer(&mut self, cfg: PeerConfig) -> Result<(), &'static str> {
            if self.by_node.contains_key(&cfg.public_key) {
                return Err("peer already exists");
            }
            let idx = self.peers.len();
            let node = cfg.public_key;
            let addr = crate::addr::node_addr(&node);
            let path = crate::path::PathStateMachine::new(cfg.endpoint);
            self.peers.push(Peer {
                pubkey: cfg.public_key,
                endpoint: cfg.endpoint,
                state: PeerState::Idle,
                admitted_cert_not_after: None,
                is_static: false,
                node,
                path,
                path_kind: None,
                relay: false,
                last_lookup_ms: None,
                session_obf_key: None,
                last_activity_ms: 0,
                last_cover_ms: 0,
            });
            self.by_node.insert(node, idx);
            self.by_addr.insert(addr, idx);
            Ok(())
        }

        pub fn remove_peer(&mut self, pubkey: &[u8; 32]) -> Result<(), &'static str> {
            let Some(&idx) = self.by_node.get(pubkey) else {
                return Err("peer not found");
            };
            // Clean up state and mappings
            // Note: to preserve indices without shifting, or swap-remove with index remapping:
            self.remove_peer_at(idx);
            Ok(())
        }
    }
    ```

- [ ] **Step 4: Run tests to verify they pass**
  Run: `cargo test -p yipd peer_manager::tests`
  Expected: PASS

- [ ] **Step 5: Run clippy and commit**
  Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
  Commit:
  ```bash
  git add bin/yipd/src/peer_manager/mod.rs
  git commit -m "feat(peer_manager): support dynamic add and remove peer with stats (#124)"
  ```

---

### Task 2: Control Server & Wire Protocol Implementation (#124 Part 2)

**Files:**
- Create: `bin/yipd/src/control.rs`
- Modify: `bin/yipd/src/main.rs`
- Test: `bin/yipd/src/control.rs` (unit tests)

**Interfaces:**
- `ControlServer`: UNIX domain socket listener that accepts client connections, parses newline-delimited JSON commands, dispatches to `PeerManager`, and returns JSON responses.
- `ControlRequest` & `ControlResponse` enums.

- [ ] **Step 1: Write failing unit tests in `bin/yipd/src/control.rs`**
  Add unit tests:
  - `control_protocol_status_serialization`: verifies `{"cmd":"status"}` parses and responds with node details.
  - `control_protocol_add_and_list_peers`: verifies `add_peer` and `list_peers` serialization and execution round-trip.

- [ ] **Step 2: Run tests to verify failure**
  Run: `cargo test -p yipd control::tests`
  Expected: FAIL

- [ ] **Step 3: Implement `bin/yipd/src/control.rs`**
  - Implement request types:
    ```rust
    #[derive(serde::Deserialize)]
    #[serde(tag = "cmd")]
    pub enum ControlCmd {
        #[serde(rename = "status")]
        Status,
        #[serde(rename = "list_peers")]
        ListPeers,
        #[serde(rename = "add_peer")]
        AddPeer { public_key: String, endpoint: Option<String> },
        #[serde(rename = "remove_peer")]
        RemovePeer { public_key: String },
    }
    ```
  - Implement server binding, client connection handling, non-blocking polling / channel passing.

- [ ] **Step 4: Run tests to verify they pass**
  Run: `cargo test -p yipd control::tests`
  Expected: PASS

- [ ] **Step 5: Run clippy and commit**
  Run: `cargo clippy -p yipd --all-targets -- -D warnings && cargo fmt --check`
  Commit:
  ```bash
  git add bin/yipd/src/control.rs bin/yipd/src/main.rs
  git commit -m "feat(control): implement UNIX domain control socket JSON server (#124)"
  ```

---

### Task 3: Tunnel Integration & CLI / Config Wiring (#124 Part 3)

**Files:**
- Modify: `bin/yipd/src/config.rs`
- Modify: `bin/yipd/src/tunnel.rs`
- Modify: `bin/yipd/src/main.rs`
- Test: `bin/yipd/tests/control_socket_test.rs`

**Interfaces:**
- Config: `control_socket: Option<PathBuf>`
- CLI: `--control <path>`
- `tunnel.rs`: Initializes control server and drains control requests in the poll loop.

- [ ] **Step 1: Write integration test**
  Add test in `bin/yipd/tests/control_socket_test.rs`:
  - Spins up `yipd` in headless mode with `--control /tmp/test_yipd.sock`.
  - Connects a `UnixStream`, sends `{"cmd":"status"}\n`, validates JSON response.
  - Sends `{"cmd":"add_peer", ...}\n`, validates response, queries `list_peers`.

- [ ] **Step 2: Implement integration in `config.rs`, `tunnel.rs`, and `main.rs`**
  - Parse `control_socket=` in `config.rs`.
  - Parse `--control <path>` in `main.rs`.
  - In `tunnel.rs`, initialize the control socket and hook command handling into the event loop.

- [ ] **Step 3: Run integration test and full workspace tests**
  Run: `cargo test -p yipd --test control_socket_test`
  Run: `cargo test --all`
  Expected: PASS

- [ ] **Step 4: Run clippy, fmt, and commit**
  Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
  Commit:
  ```bash
  git add bin/yipd/src/config.rs bin/yipd/src/tunnel.rs bin/yipd/src/main.rs bin/yipd/tests/control_socket_test.rs
  git commit -m "feat(tunnel): wire control socket into tunnel event loop and CLI (#124)"
  ```

---

### Task 4: Integration Verification, Review, and Issue Closure

- [ ] **Step 1: Run full workspace test suite and linter check**
  Run: `cargo test --all && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
- [ ] **Step 2: Run netns integration test suite**
  Run: `sudo -E target/debug/deps/tunnel_netns-* --nocapture --test-threads=1`
- [ ] **Step 3: Whole-branch review, merge into `main`, push to `origin/main`**
- [ ] **Step 4: Close GitHub issue #124**
