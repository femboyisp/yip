# Multi-peer data plane + self-certifying addresses (2a) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn yipd from a single connected peer into a static N-peer mesh with key-derived self-certifying addresses, lazy in-loop handshakes, and an addressed socket seam (which also unblocks multi-core #10).

**Architecture:** A thin `PeerManager` owns a `HashMap` of per-peer `DataPlane`s (the finished #1 data path, reused one-per-peer). The `Dispatch` seam gains addressing (`on_udp(src)`, `EgressDatagram.dst`); drivers move from connected `recv`/`send` to `recvfrom`/`sendto`. Packets self-describe via the existing `PacketType` leading byte: `2`=Data (then demux by `conn_tag`), `0`/`1`=Noise handshake (driven in-loop). Sessions form lazily on first traffic (WireGuard-style).

**Tech Stack:** Rust, `snow` (Noise-IK), `blake2` (address derivation), `libc` (socket syscalls in yip-io), `raptorq` (existing FEC), netns integration tests.

## Global Constraints

- `yipd`, `yip-wire`, `yip-crypto`, `yip-transport` stay `#![forbid(unsafe_code)]`. `unsafe` only in `yip-io` and `yip-device`.
- No `as` numeric casts anywhere (use `From`/`TryFrom`); the sole allowed exception is `PacketType::* as u8`.
- Every task ends green on: `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, and the existing `cargo test --workspace`.
- **No wire-format regression:** the single-peer `tunnel_netns` tests (`ping_across_yipd_tunnel`, `_under_loss`, `arq_recovers_bulk_loss`, `l2_tap_ping_or_arp_across_tunnel`) must stay green under **both** drivers (default poll + `YIP_USE_URING=1`) after every task that touches the wire or the drivers.
- Land incrementally. Task 3 (the socket seam) is the biggest single diff and is its own reviewable step with **no behavior change for one peer**.
- Non-goals (do NOT implement): discovery/DHT (2c), NAT traversal/hole-punching/relay (2b), per-peer subnets/AllowedIPs, dynamic admission hooks, multi-core sharding (#10), anti-DPI hardening (#3).

## File Structure

- `bin/yipd/src/addr.rs` (**new**) — `node_addr(&pubkey) -> Ipv6Addr`, `verify_addr`, `MESH_PREFIX`. Pure, no I/O.
- `bin/yipd/src/config.rs` (**modify**) — parse a `[peer]` list into `Vec<PeerConfig>`; drop `initiate`; keep 1-entry back-compat.
- `crates/yip-io/src/poll.rs` (**modify**) — `Dispatch::on_udp(src)`, `EgressDatagram { dst, .. }`, `DispatchOut` carries dests; `recvfrom`/`sendto`.
- `crates/yip-io/src/uring.rs` (**modify**) — `recvfrom`/`sendto` (RecvMsg/SendMsg with names), per-datagram `dst`.
- `bin/yipd/src/handshake.rs` (**modify**) — add step-function API (`HandshakeState`) alongside the existing blocking fns (which tests still use).
- `bin/yipd/src/peer_manager.rs` (**new**) — `PeerManager` + `Dispatch` impl + in-loop lazy handshake + routing/demux.
- `bin/yipd/src/dataplane.rs` (**modify**) — endpoint-agnostic egress (manager stamps `dst`); expose `conn_tag()`.
- `bin/yipd/src/tunnel.rs` (**modify**) — drop `sock.connect` + pre-loop handshake; build `PeerManager`, run driver on it.
- `bin/yipd/tests/run-netns-triangle.sh` (**new**) + `bin/yipd/tests/tunnel_netns.rs` (**modify**) — 3-peer test.
- `.github/workflows/integration.yml` (**modify**) — gate the triangle test under both drivers.

---

### Task 1: Self-certifying address helper (`addr.rs`)

**Files:**
- Create: `bin/yipd/src/addr.rs`
- Modify: `bin/yipd/src/main.rs` (add `mod addr;`)

**Interfaces:**
- Produces: `pub fn node_addr(pubkey: &[u8; 32]) -> std::net::Ipv6Addr`; `pub fn verify_addr(addr: std::net::Ipv6Addr, pubkey: &[u8; 32]) -> bool`; `pub const MESH_PREFIX_LEN: u8 = 8;` (the `fd00::/8` ULA prefix).

- [ ] **Step 1: Write the failing test**

```rust
// in bin/yipd/src/addr.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_is_ula_and_deterministic() {
        let pk = [7u8; 32];
        let a = node_addr(&pk);
        assert_eq!(a.octets()[0], 0xfd, "must be in fd00::/8 ULA space");
        assert_eq!(node_addr(&pk), a, "derivation is deterministic");
    }

    #[test]
    fn addr_verifies_only_its_own_key() {
        let pk = [7u8; 32];
        let other = [8u8; 32];
        assert!(verify_addr(node_addr(&pk), &pk));
        assert!(!verify_addr(node_addr(&pk), &other));
    }

    #[test]
    fn distinct_keys_give_distinct_addrs() {
        assert_ne!(node_addr(&[1u8; 32]), node_addr(&[2u8; 32]));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yipd addr:: 2>&1 | tail`
Expected: FAIL — `node_addr` not found.

- [ ] **Step 3: Implement**

```rust
//! Self-certifying, key-derived mesh addresses: a node's inner IPv6 is derived
//! from its X25519 public key, so the address IS the identity — no authority.
use std::net::Ipv6Addr;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;

/// Domain-separation context so the address derivation can't collide with any
/// other use of the key.
const DOMAIN: &[u8] = b"yip-addr-v1";
/// The mesh occupies fd00::/8 (IPv6 ULA); every node address begins with 0xfd.
pub const MESH_PREFIX_LEN: u8 = 8;

/// Derive a node's inner IPv6 address from its public key:
/// `0xfd || BLAKE2s(DOMAIN || pubkey)[0..15]`.
pub fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr {
    let mut h = Blake2sVar::new(15).expect("15 is a valid blake2s output len");
    h.update(DOMAIN);
    h.update(pubkey);
    let mut digest = [0u8; 15];
    h.finalize_variable(&mut digest)
        .expect("output len matches");
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..].copy_from_slice(&digest);
    Ipv6Addr::from(octets)
}

/// True iff `addr` is the address `pubkey` derives to (self-certification check).
pub fn verify_addr(addr: Ipv6Addr, pubkey: &[u8; 32]) -> bool {
    node_addr(pubkey) == addr
}
```

Add `blake2 = { workspace = true }` (or the pinned version already used by `yip-wire`/`yip-crypto`) to `bin/yipd/Cargo.toml` if not present, and `mod addr;` to `bin/yipd/src/main.rs`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p yipd addr:: 2>&1 | tail`
Expected: PASS (3 tests). Then `cargo clippy -p yipd --all-targets -- -D warnings`.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/addr.rs bin/yipd/src/main.rs bin/yipd/Cargo.toml
git commit -m "feat(yipd): self-certifying key-derived node addresses (2a)"
```

---

### Task 2: Peer-list config

**Files:**
- Modify: `bin/yipd/src/config.rs`
- Test: `bin/yipd/src/config.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `crate::addr` is not needed here.
- Produces: `pub struct PeerConfig { pub public_key: [u8; 32], pub endpoint: std::net::SocketAddr }`; `Config` gains `pub peers: Vec<PeerConfig>` and loses `peer_public`/`peer_endpoint`/`initiate`. A single legacy `peer_public`+`peer_endpoint` still parses into a 1-entry `peers`.

- [ ] **Step 1: Write the failing test** (add to config.rs tests)

```rust
#[test]
fn parses_multiple_peers_and_legacy_single() {
    // New [peer] block form:
    let text = "local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                local_public=000000000000000000000000000000000000000000000000000000000000aa01\n\
                listen=0.0.0.0:51820\ndevice=yip0\n\
                [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b1\nendpoint=10.0.0.2:51820\n\
                [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b2\nendpoint=10.0.0.3:51820\n";
    let cfg = Config::parse(text).expect("parses");
    assert_eq!(cfg.peers.len(), 2);
    assert_eq!(cfg.peers[0].endpoint, "10.0.0.2:51820".parse().unwrap());
    assert_eq!(cfg.peers[1].public_key[31], 0xb2);
}

#[test]
fn legacy_single_peer_becomes_one_entry() {
    let text = "device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\n\
                local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
    let cfg = Config::parse(text).expect("legacy parses");
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].public_key[31], 0xbb);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yipd config:: 2>&1 | tail`
Expected: FAIL — `cfg.peers` does not exist.

- [ ] **Step 3: Implement**

Add the struct and field; extend `parse` to accumulate a `[peer]` block (each `[peer]` header pushes a new in-progress entry; `public_key`/`endpoint` fill the current entry), and fold a legacy `peer_public`+`peer_endpoint` into a single entry when no `[peer]` block is present. Remove `peer_public`/`peer_endpoint`/`initiate` from `Config`. Concretely:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub endpoint: SocketAddr,
}
// in Config: replace peer_public/peer_endpoint/initiate with:
pub peers: Vec<PeerConfig>,
```

In `parse`, track `peers: Vec<PeerConfig>`, plus `cur_pk`/`cur_ep: Option<..>` for the block being built and legacy `peer_public`/`peer_endpoint`. On a line equal to `[peer]`, flush any complete `cur` into `peers` and reset. On `public_key`/`endpoint`, set `cur_*`. At the end: flush a trailing `cur`; if `peers` is empty and legacy fields are present, push one `PeerConfig`. Error if `peers` ends empty. A `[peer]` with only one of the two fields is a parse error (`"peer block missing public_key/endpoint"`).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p yipd config:: 2>&1 | tail` → PASS. Fix any other module that read `cfg.peer_public`/`peer_endpoint`/`initiate` (only `tunnel.rs`, changed in Task 5 — for now, make `tunnel.rs` read `cfg.peers[0]` so the workspace still builds). Then `cargo build --workspace`.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/config.rs bin/yipd/src/tunnel.rs
git commit -m "feat(yipd): peer-list config (multi-peer), drop initiate (2a)"
```

---

### Task 3: Addressed socket seam (no behavior change for 1 peer) — the big refactor

**Files:**
- Modify: `crates/yip-io/src/poll.rs`, `crates/yip-io/src/uring.rs`, `bin/yipd/src/dataplane.rs`, `bin/yipd/src/tunnel.rs`
- Test: the existing `tunnel_netns` suite (regression), under both drivers.

**Interfaces:**
- Produces: `Dispatch::on_udp(&mut self, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_>`; `EgressDatagram { pub fate: u16, pub dst: SocketAddr, pub bytes: Vec<u8> }`; `DispatchOut::Udp(&'a [EgressDatagram])` / `Both(&'a [u8], &'a [EgressDatagram])` (Udp now carries dests via `EgressDatagram`, replacing `&[Vec<u8>]`). `run_poll`/`run_uring` unchanged signatures.
- Consumes: nothing new.

Approach: this is mechanical breadth. Do it in one PR but as ordered edits, keeping single-peer behavior identical (the manager that actually uses `src`/`dst` arrives in Task 5; here `DataPlane` ignores `src` and the driver sends every datagram to the one connected-equivalent `dst`).

- [ ] **Step 1: Change the trait + `EgressDatagram`** (poll.rs)

`on_udp` gains `src: SocketAddr`. `EgressDatagram` gains `dst: SocketAddr`. `DispatchOut::Udp`/`Both` take `&[EgressDatagram]` (so ARQ retransmits also carry dests). Update `impl AsRef<[u8]> for EgressDatagram` (unchanged body). This breaks every `Dispatch` impl and driver match — fix them in the following steps.

- [ ] **Step 2: Drivers use `recvfrom`/`sendto`** (poll.rs, uring.rs)

- `poll.rs`: `drain_udp` uses `libc::recvfrom` (fill a `sockaddr_storage`, convert to `SocketAddr`) and passes `src` to `on_udp`; `send_to_udp(fd, buf, dst)` uses `libc::sendto` with the datagram's `dst` sockaddr. Remove reliance on `connect`.
- `uring.rs`: the UDP recv completion recovers the source (use `opcode::RecvMsg` with a `msghdr` name buffer, or keep `RecvMulti` for the datagram and a parallel `recvfrom` — simplest: switch the UDP recv to `RecvMsg`/`SendMsg` with `msg_name` so `src`/`dst` ride along). Each send SQE targets the datagram's `dst`. Keep the graceful-fallback + busy-poll + GSO fate-tag logic intact; GSO coalescing now also requires same `dst` (add `dst` equality to `can_coalesce_gso_tagged`).
- Provide a helper in yip-io: `sockaddr_to_std(&libc::sockaddr_storage, len) -> SocketAddr` and `std_to_sockaddr(SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t)` (the only new `unsafe`, confined to yip-io).

- [ ] **Step 3: `DataPlane` egress carries `dst`** (dataplane.rs)

`DataPlane::new` takes the peer's `SocketAddr` (its single peer's endpoint) OR — cleaner — `DataPlane` stays endpoint-agnostic and `tunnel.rs` wraps it in a one-peer manager that stamps `dst`. For Task 3 minimal change: give `DataPlane` a `peer_addr: SocketAddr` field set at construction and stamp it on every `EgressDatagram` it produces (egress + ARQ + tick). `on_udp` ignores `src`. Add `pub fn conn_tag(&self) -> u64`.

- [ ] **Step 4: `tunnel.rs` — drop `connect`, keep one peer**

Bind the socket (unconnected); still do the pre-loop blocking handshake (Task 4/5 replace it); build `DataPlane::new(established, conn_tag, mode, cfg.peers[0].endpoint)`; run the driver. Update the `Dispatch for DataPlane` `on_udp` signature and all its `DispatchOut` returns to the addressed forms.

- [ ] **Step 5: Update every test `Dispatch` impl + verify no regression**

Update the test dispatches in `poll.rs` and `uring.rs` (add `src` param, `dst` on returned `EgressDatagram`s). Run:

```bash
cargo build --workspace && cargo clippy --workspace --all-targets -- -D warnings
cargo test -p yip-io -p yipd
cargo build --release -p yipd
BIN=$(ls -t target/debug/deps/tunnel_netns-* | grep -v '\.d$' | head -1)
for env in "" "YIP_USE_URING=1"; do for t in ping_across_yipd_tunnel ping_across_yipd_tunnel_under_loss arq_recovers_bulk_loss; do sudo -E env $env "$BIN" "$t" --exact --test-threads=1 2>&1 | grep "test result"; done; done
```
Expected: all unit tests pass; all 6 netns runs `ok`. If a netns run regresses, the wire changed — fix before committing.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(yip-io): addressed on_udp(src)+EgressDatagram.dst, recvfrom/sendto (2a seam)"
```

---

### Task 4: Handshake step-functions

**Files:**
- Modify: `bin/yipd/src/handshake.rs`
- Test: `bin/yipd/src/handshake.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `yip_crypto::Handshake` (`initiator`/`responder`/`write_message`/`read_message`/finalize→`Established`); `Established`.
- Produces:
  ```rust
  pub struct HandshakeState { /* wraps yip_crypto::Handshake + role */ }
  pub enum HandshakeStep { SendThenWait(Vec<u8>), Done(Box<Established>, Vec<u8>), Fail }
  impl HandshakeState {
      pub fn start_initiator(local_priv: &[u8;32], peer_pub: &[u8;32]) -> io::Result<(Self, Vec<u8>)>; // returns [HandshakeInit]++msg1
      pub fn start_responder(local_priv: &[u8;32], init_pkt: &[u8]) -> io::Result<(Established_or_more)>; // reads [HandshakeInit]++msg1, returns [HandshakeResp]++msg2 + Established
      pub fn read_response(self, resp_pkt: &[u8]) -> io::Result<Established>; // initiator reads [HandshakeResp]++msg2
  }
  ```
  Exact enum/return shapes: initiator is 2-step (start → read_response→Established); responder is 1-step (start_responder returns both the reply bytes and the `Established`), because Noise-IK completes for the responder on msg1. Keep the existing blocking `run_initiator`/`run_responder` (tests use them) — the step-functions are additive, sharing the `crypto_err`/`PacketType` framing.

- [ ] **Step 1: Failing test**

```rust
#[test]
fn step_handshake_initiator_responder_agree() {
    let (a_priv, a_pub) = /* genkey */;
    let (b_priv, b_pub) = /* genkey */;
    let (mut a, init_pkt) = HandshakeState::start_initiator(&a_priv, &b_pub).unwrap();
    let (b_est, resp_pkt) = HandshakeState::start_responder(&b_priv, &init_pkt).unwrap();
    let a_est = a.read_response(&resp_pkt).unwrap();
    // Both derive the same channel binding (conn_tag inputs).
    assert_eq!(a_est.auth_key, b_est.auth_key);
    assert_eq!(a_est.hp_key, b_est.hp_key);
}
```

- [ ] **Step 2: Run → fails.** `cargo test -p yipd handshake:: 2>&1 | tail`.

- [ ] **Step 3: Implement** the step-functions by factoring the message read/write out of the existing blocking loops (which currently do socket I/O around `handshake.write_message()`/`read_message()`); the step-functions do the same crypto but return the framed bytes instead of writing to a socket, and return `Established` at the same points the blocking versions do (`handshake.into_transport()`-equivalent — mirror the finalize the blocking fns use).

- [ ] **Step 4: Run → passes.** Then clippy.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/handshake.rs
git commit -m "feat(yipd): handshake step-functions for in-loop handshakes (2a)"
```

---

### Task 5: `PeerManager` + tunnel wiring (multi-peer, lazy handshake)

**Files:**
- Create: `bin/yipd/src/peer_manager.rs`
- Modify: `bin/yipd/src/main.rs` (`mod peer_manager;`), `bin/yipd/src/tunnel.rs`
- Test: `bin/yipd/src/peer_manager.rs` (`#[cfg(test)]` for routing/demux) + the netns triangle (Task 6)

**Interfaces:**
- Consumes: `crate::addr::node_addr`, `crate::config::PeerConfig`, `crate::handshake::HandshakeState`, `crate::dataplane::DataPlane`, `yip_io::poll::{Dispatch, DispatchOut, EgressDatagram}`.
- Produces: `pub struct PeerManager` implementing `Dispatch`; `pub fn new(local_priv, local_pub, peers: &[PeerConfig], mode) -> Self`.

Structure and behavior (implement to this shape):

```rust
enum PeerState { Handshaking { hs: HandshakeState, started_ms: u64 }, Established(Box<DataPlane>) }
struct Peer { pubkey: [u8;32], addr: Ipv6Addr, endpoint: SocketAddr, state: PeerState, pending_tun: Vec<Vec<u8>> }
pub struct PeerManager {
    local_priv: [u8;32], local_pub: [u8;32], mode: TunnelMode,
    peers: Vec<Peer>,                 // small N; linear scan is fine for 2a
    by_tag: HashMap<u64, usize>,      // conn_tag -> peers index
    by_addr: HashMap<Ipv6Addr, usize>,// derived addr -> peers index (routing)
    egress: Vec<EgressDatagram>,      // reused return scratch
}
```

`Dispatch for PeerManager`:
- `on_udp(src, dg)`: match `dg[0]` (`PacketType`): `Data` → `by_tag[dg[1..9]]` → that peer's `DataPlane::on_udp(dg)` → map its `Outcome` to `DispatchOut` (Tun writes pass through; any DataPlane egress gets `dst = src`/`peer.endpoint`). `HandshakeInit` → `HandshakeState::start_responder`; admit iff the recovered static key ∈ configured peers; on admit, transition Established, register `by_tag`, learn `endpoint = src`, return the `[HandshakeResp]` datagram (`dst = src`). `HandshakeResp` → find the `Handshaking` peer whose `endpoint == src` → `read_response` → Established → register `by_tag` → drain `pending_tun` through the new `DataPlane` (collect into `egress`).
- `on_tun(inner)`: parse the inner dst IPv6 → `by_addr` longest-prefix (host `/128`) → peer. If `Established`, delegate to its `DataPlane::on_tun`, stamping `dst = peer.endpoint`. If none/`Handshaking`, buffer in `pending_tun`; if no handshake in flight, `HandshakeState::start_initiator`, mark Handshaking, return the `[HandshakeInit]` datagram (`dst = peer.endpoint`).
- `tick`: drive handshake retries/timeouts (re-send init past a retry interval, drop past a deadline); fan `tick` to all `Established` peers.
- `flush_egress`: fan out to `Established` peers.

`tunnel.rs`: bind unconnected socket; build `PeerManager::new(...)`; `run_poll`/`run_uring(udp_fd, tun_fd, &mut manager)`. Remove the pre-loop blocking handshake and `sock.connect`. Assign the TUN device the local node's `node_addr(&local_pub)/128` and add the mesh-prefix route (in the netns test script, via `ip`).

- [ ] **Step 1: Failing unit test** — routing + demux (no sockets):

```rust
#[test]
fn routes_inner_dst_to_owning_peer_and_demuxes_by_tag() {
    // Build a PeerManager with two configured peers; assert by_addr maps each
    // peer's node_addr to its index, and that a Data packet with a registered
    // conn_tag routes to the right peer (use a small test seam that inserts a
    // fake Established peer with a known conn_tag).
}
```

- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement `PeerManager`** per the shape above.
- [ ] **Step 4: Run unit test → passes; workspace builds; clippy clean.**
- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/peer_manager.rs bin/yipd/src/main.rs bin/yipd/src/tunnel.rs
git commit -m "feat(yipd): PeerManager — multi-peer routing/demux + lazy handshake (2a)"
```

---

### Task 6: 3-peer netns triangle test + CI

**Files:**
- Create: `bin/yipd/tests/run-netns-triangle.sh`
- Modify: `bin/yipd/tests/tunnel_netns.rs` (add `triangle_full_mesh_ping`), `.github/workflows/integration.yml`

**Interfaces:** none (integration).

- [ ] **Step 1: Write the triangle script + test.** Three netns (A/B/C) on a shared bridge (or a full mesh of veths), one yipd each with a 2-peer static config (each node lists the other two: `public_key` + `endpoint`). Assign each TUN the node's `node_addr` (compute via `yipd --genkey`-derived keys; print the derived addr with a new `yipd --addr <pubkey-hex>` helper, or compute in the script). Bring up, then from A `ping` B's and C's derived addresses; from B ping C. Assert 0% loss on all three legs. Cleanup trap. Root-gated with a `SKIP` line if not root (matching the existing scripts).

- [ ] **Step 2: Run locally under both drivers.**

```bash
cargo test -p yipd --test tunnel_netns --no-run
BIN=$(ls -t target/debug/deps/tunnel_netns-* | grep -v '\.d$' | head -1)
for env in "" "YIP_USE_URING=1"; do sudo -E env $env "$BIN" triangle_full_mesh_ping --exact --test-threads=1 2>&1 | grep -E "received|test result"; done
```
Expected: full-mesh ping succeeds under both.

- [ ] **Step 3: Add a `yipd --addr <hex>` subcommand** (prints `node_addr` for a pubkey) so the script and operators can compute addresses. Small addition to `main.rs`.

- [ ] **Step 4: Gate in CI.** Add `triangle_full_mesh_ping` to the `for t in ...` list in `integration.yml`'s netns loop (runs under both `poll` and `YIP_USE_URING=1`).

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/tests/run-netns-triangle.sh bin/yipd/tests/tunnel_netns.rs bin/yipd/src/main.rs .github/workflows/integration.yml
git commit -m "test(yipd): 3-peer netns triangle full-mesh ping, gated under both drivers (2a)"
```

---

## Self-Review

**Spec coverage:**
- Key-derived self-certifying addresses → Task 1. ✅
- Peer-list config, drop `initiate` → Task 2. ✅
- Addressed `Dispatch`/driver seam (recvfrom/sendto), no 1-peer regression, both drivers → Task 3. ✅
- In-loop lazy handshake (step-functions + PeerManager state machine) → Tasks 4 + 5. ✅
- `PeerManager` over per-peer `DataPlane`s, routing by inner dst, demux by PacketType/conn_tag → Task 5. ✅
- 3-peer netns triangle + CI, both drivers → Task 6. ✅
- Non-goals (discovery, NAT, subnets, admission, #10, anti-DPI) — none implemented. ✅

**Placeholder scan:** Tasks 4 and 5 describe the `Established`-finalize and `Outcome→DispatchOut` mapping by reference to existing code rather than reproducing every line — acceptable because those are large existing surfaces the implementer reads in-repo; the *interfaces* (names, signatures, return shapes) are fully specified. All other steps carry concrete code/commands.

**Type consistency:** `EgressDatagram { fate, dst, bytes }` and `on_udp(src, ..)` used consistently across Tasks 3/5; `PeerConfig { public_key, endpoint }` consistent Tasks 2/5; `HandshakeState`/`HandshakeStep` names consistent Tasks 4/5; `node_addr`/`verify_addr` consistent Tasks 1/5/6.

**Note for the implementer:** the FEC-batching foundation (branch `feat/fec-object-batching`, `bf8d5ab`) is shelved and unrelated; do not merge it into this line. Base 2a on `main`.
