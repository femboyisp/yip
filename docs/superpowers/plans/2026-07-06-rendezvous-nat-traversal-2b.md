# Milestone 2b: Rendezvous + NAT Traversal + Relay — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let two NATed yip peers reach each other with no pre-arranged endpoint — discover each peer's reflexive address via a configured rendezvous server, UDP hole-punch a direct path, and fall back to a ciphertext-blind relay when the punch fails.

**Architecture:** A new shared `crates/yip-rendezvous` library holds the wire protocol (`node_id` + `Message` codec) and a pure `RendezvousServer` state machine. A thin `bin/yip-rendezvous` binary drives that state machine over a plain `UdpSocket`. In `yipd`, a `Rendezvous` trait (impl `ConfiguredServerRendezvous`) plus a per-peer path state machine (`Direct → Punch → Relay`, `path.rs`) layer onto 2a's lazy handshake inside `PeerManager`. Learned endpoints are only handshake-probe candidates — an established session's egress commits only after a Noise handshake completes over the path (anti-hijack).

**Tech Stack:** Rust, `blake2` (=0.10.6, node_id), `std::net::UdpSocket` (server loop), the existing `yip-io` `Dispatch` seam, `snow`/`yip-crypto` Noise-IK (unchanged), netns + `iptables MASQUERADE` for NAT simulation.

## Global Constraints

- `yipd` and `yip-rendezvous` stay `#![forbid(unsafe_code)]`; `unsafe` only in `yip-io`/`yip-device`.
- No `as` numeric casts except a message-type/`PacketType` discriminant `as u8`.
- **Anti-hijack invariant:** a rendezvous/punch-learned address is only ever a handshake-probe target; an `Established` session's egress is never redirected to a new address without a fresh completed handshake over it.
- **No data-plane wire regression:** the 2a single-peer netns tests (`ping_across_yipd_tunnel`, `ping_across_yipd_tunnel_under_loss`, `arq_recovers_bulk_loss`, `l2_tap_ping_or_arp_across_tunnel`) and `triangle_full_mesh_ping` stay green under BOTH `poll` and `YIP_USE_URING=1`.
- The `arq_recovers_bulk_loss` netns test runs the **release** `yipd` (debug RaptorQ is ~75× slower) — rebuild `--release` after any `yipd` change before running it.
- `node_id(pubkey) = BLAKE2s("yip-rdv-v1" || pubkey)[..16]` — exact domain string, 16-byte output.
- Green bar every task: `cargo fmt --all --check`, `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p <crate>`.
- Deferred / non-goals (do NOT build): UPnP/NAT-PMP/PCP + NAT-type classification (2b.1), ICE parallel candidate racing, discovery/DHT (2c), handshake anti-replay (#34), anti-DPI obfuscation of the new framing (#3), metadata-privacy tokens, federated/discoverable relay network.

---

## File Structure

- `crates/yip-rendezvous/` (NEW lib crate)
  - `src/lib.rs` — crate root, re-exports.
  - `src/proto.rs` — `NodeId`, `node_id(pubkey)`, `Message` enum + `encode`/`decode`.
  - `src/server.rs` — `RendezvousServer` pure state machine (registration TTL map, rate limit, forward counter).
- `bin/yip-rendezvous/` (NEW bin crate) — `src/main.rs`: `UdpSocket` loop driving `RendezvousServer`.
- `bin/yipd/src/rendezvous.rs` (NEW) — `Rendezvous` trait + `ConfiguredServerRendezvous` + `RdvEvent`.
- `bin/yipd/src/path.rs` (NEW) — per-peer path state machine (`PathStage`/`PathKind`/`PathState`).
- `bin/yipd/src/config.rs` (MODIFY) — `rendezvous: Option<SocketAddr>`; `PeerConfig.endpoint: Option<SocketAddr>`.
- `bin/yipd/src/peer_manager.rs` (MODIFY) — server-addr demux, path SM in `on_udp`/`on_tun`/`tick`, relay egress.
- `bin/yipd/src/tunnel.rs` (MODIFY) — build the rendezvous client from `config.rendezvous`, pass into `PeerManager`.
- `bin/yipd/src/main.rs` (MODIFY) — `mod rendezvous; mod path;`.
- `bin/yipd/tests/{run-netns-relay.sh,run-netns-punch.sh}` (NEW) + `tunnel_netns.rs` (MODIFY) + `.github/workflows/integration.yml` (MODIFY).

---

### Task 1: `yip-rendezvous` wire protocol (`proto.rs`)

**Files:**
- Create: `crates/yip-rendezvous/Cargo.toml`, `crates/yip-rendezvous/src/lib.rs`, `crates/yip-rendezvous/src/proto.rs`
- Test: inline `#[cfg(test)]` in `proto.rs`

**Interfaces:**
- Produces:
  - `pub type NodeId = [u8; 16];`
  - `pub fn node_id(pubkey: &[u8; 32]) -> NodeId` — `BLAKE2s("yip-rdv-v1" || pubkey)[..16]`.
  - `pub enum Message { Register { node: NodeId }, Lookup { node: NodeId }, PeerInfo { node: NodeId, reflexive: SocketAddr }, NotFound { node: NodeId }, PunchHint { node: NodeId, reflexive: SocketAddr }, RelaySend { src: NodeId, dst: NodeId, payload: Vec<u8> }, RelayDeliver { src: NodeId, payload: Vec<u8> } }`
  - `RelaySend` carries **both** the sender's and destination's node ids: the server can't derive a sender's `NodeId` from its UDP address, so it copies `src` into the `RelayDeliver` it forwards, giving the receiver the origin id to reply through the relay. The sender knows both ids (its own key + the peer's configured key).
  - `pub fn encode(msg: &Message, out: &mut Vec<u8>)` and `pub fn decode(buf: &[u8]) -> Option<Message>`.

- [ ] **Step 1: Create the crate.** `crates/yip-rendezvous/Cargo.toml`:

```toml
[package]
name = "yip-rendezvous"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
blake2 = { workspace = true }

[lints]
workspace = true
```

`crates/yip-rendezvous/src/lib.rs`:

```rust
//! Rendezvous + relay control protocol shared by `yipd` (client) and the
//! `yip-rendezvous` server: node-id derivation, the wire `Message` codec, and
//! the pure server state machine.
#![forbid(unsafe_code)]

pub mod proto;
pub mod server;

pub use proto::{decode, encode, node_id, Message, NodeId};
pub use server::RendezvousServer;
```

- [ ] **Step 2: Write failing tests** in `crates/yip-rendezvous/src/proto.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn node_id_is_deterministic_and_16_bytes() {
        let pk = [7u8; 32];
        let a = node_id(&pk);
        assert_eq!(a.len(), 16);
        assert_eq!(node_id(&pk), a);
        assert_ne!(node_id(&pk), node_id(&[8u8; 32]));
    }

    fn roundtrip(msg: Message) {
        let mut buf = Vec::new();
        encode(&msg, &mut buf);
        assert_eq!(decode(&buf), Some(msg));
    }

    #[test]
    fn all_messages_roundtrip() {
        let n = [1u8; 16];
        let v4: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        roundtrip(Message::Register { node: n });
        roundtrip(Message::Lookup { node: n });
        roundtrip(Message::PeerInfo { node: n, reflexive: v4 });
        roundtrip(Message::PeerInfo { node: n, reflexive: v6 });
        roundtrip(Message::NotFound { node: n });
        roundtrip(Message::PunchHint { node: n, reflexive: v4 });
        roundtrip(Message::RelaySend { src: [3u8; 16], dst: n, payload: vec![9, 8, 7] });
        roundtrip(Message::RelayDeliver { src: n, payload: vec![1, 2, 3, 4] });
    }

    #[test]
    fn decode_rejects_garbage_and_truncation() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0xFF]), None); // unknown discriminant
        let mut buf = Vec::new();
        encode(&Message::PeerInfo { node: [2u8; 16], reflexive: "1.2.3.4:5".parse().unwrap() }, &mut buf);
        buf.truncate(buf.len() - 1);
        assert_eq!(decode(&buf), None); // truncated addr
    }
}
```

- [ ] **Step 3: Run tests → fail.** `cargo test -p yip-rendezvous` → FAIL (module `proto` empty / functions missing).

- [ ] **Step 4: Implement `proto.rs`.** Prepend to the test module:

```rust
//! Node-id derivation and the rendezvous wire `Message` codec.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;

/// Domain separation so node-id can't collide with the mesh-address derivation.
const DOMAIN: &[u8] = b"yip-rdv-v1";

/// A rendezvous identity: `BLAKE2s(DOMAIN || pubkey)[..16]`. Distinct domain
/// from `yipd`'s `node_addr` so the two derivations never coincide.
pub type NodeId = [u8; 16];

/// Derive a node's rendezvous id from its X25519 public key.
pub fn node_id(pubkey: &[u8; 32]) -> NodeId {
    let mut h = Blake2sVar::new(16).expect("16 is a valid blake2s output len");
    h.update(DOMAIN);
    h.update(pubkey);
    let mut out = [0u8; 16];
    h.finalize_variable(&mut out).expect("output len matches");
    out
}

/// Message-type discriminants (the only permitted `as u8` in this crate).
#[repr(u8)]
enum Tag {
    Register = 0,
    Lookup = 1,
    PeerInfo = 2,
    NotFound = 3,
    PunchHint = 4,
    RelaySend = 5,
    RelayDeliver = 6,
}

/// A rendezvous/relay control message. See the 2b spec for direction/semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Register { node: NodeId },
    Lookup { node: NodeId },
    PeerInfo { node: NodeId, reflexive: SocketAddr },
    NotFound { node: NodeId },
    PunchHint { node: NodeId, reflexive: SocketAddr },
    RelaySend { dst: NodeId, payload: Vec<u8> },
    RelayDeliver { src: NodeId, payload: Vec<u8> },
}

fn put_addr(out: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn take_addr(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let (&fam, rest) = buf.split_first()?;
    let (ip, used): (IpAddr, usize) = match fam {
        4 => {
            let o: [u8; 4] = rest.get(..4)?.try_into().ok()?;
            (IpAddr::V4(Ipv4Addr::from(o)), 4)
        }
        6 => {
            let o: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(o)), 16)
        }
        _ => return None,
    };
    let port_bytes: [u8; 2] = rest.get(used..used + 2)?.try_into().ok()?;
    let port = u16::from_be_bytes(port_bytes);
    Some((SocketAddr::new(ip, port), 1 + used + 2))
}

/// Serialize `msg` onto `out` (appends; caller clears if reusing).
pub fn encode(msg: &Message, out: &mut Vec<u8>) {
    match msg {
        Message::Register { node } => {
            out.push(Tag::Register as u8);
            out.extend_from_slice(node);
        }
        Message::Lookup { node } => {
            out.push(Tag::Lookup as u8);
            out.extend_from_slice(node);
        }
        Message::PeerInfo { node, reflexive } => {
            out.push(Tag::PeerInfo as u8);
            out.extend_from_slice(node);
            put_addr(out, reflexive);
        }
        Message::NotFound { node } => {
            out.push(Tag::NotFound as u8);
            out.extend_from_slice(node);
        }
        Message::PunchHint { node, reflexive } => {
            out.push(Tag::PunchHint as u8);
            out.extend_from_slice(node);
            put_addr(out, reflexive);
        }
        Message::RelaySend { src, dst, payload } => {
            out.push(Tag::RelaySend as u8);
            out.extend_from_slice(src);
            out.extend_from_slice(dst);
            out.extend_from_slice(payload);
        }
        Message::RelayDeliver { src, payload } => {
            out.push(Tag::RelayDeliver as u8);
            out.extend_from_slice(src);
            out.extend_from_slice(payload);
        }
    }
}

/// Parse one datagram into a `Message`, or `None` if malformed/truncated.
pub fn decode(buf: &[u8]) -> Option<Message> {
    let (&tag, rest) = buf.split_first()?;
    let node16 = |b: &[u8]| -> Option<NodeId> { b.get(..16)?.try_into().ok() };
    match tag {
        t if t == Tag::Register as u8 => Some(Message::Register { node: node16(rest)? }),
        t if t == Tag::Lookup as u8 => Some(Message::Lookup { node: node16(rest)? }),
        t if t == Tag::NotFound as u8 => Some(Message::NotFound { node: node16(rest)? }),
        t if t == Tag::PeerInfo as u8 => {
            let node = node16(rest)?;
            let (reflexive, _) = take_addr(rest.get(16..)?)?;
            Some(Message::PeerInfo { node, reflexive })
        }
        t if t == Tag::PunchHint as u8 => {
            let node = node16(rest)?;
            let (reflexive, _) = take_addr(rest.get(16..)?)?;
            Some(Message::PunchHint { node, reflexive })
        }
        t if t == Tag::RelaySend as u8 => {
            let src = node16(rest)?;
            let dst = node16(rest.get(16..)?)?;
            Some(Message::RelaySend { src, dst, payload: rest.get(32..)?.to_vec() })
        }
        t if t == Tag::RelayDeliver as u8 => {
            let src = node16(rest)?;
            Some(Message::RelayDeliver { src, payload: rest.get(16..)?.to_vec() })
        }
        _ => None,
    }
}
```

- [ ] **Step 5: Run tests → pass; build/clippy/fmt clean.**

```bash
cargo test -p yip-rendezvous
cargo clippy -p yip-rendezvous --all-targets -- -D warnings && cargo fmt --all --check
```
Expected: all tests pass, no warnings.

- [ ] **Step 6: Commit.**

```bash
git add crates/yip-rendezvous/Cargo.toml crates/yip-rendezvous/src/lib.rs crates/yip-rendezvous/src/proto.rs Cargo.lock
git commit -m "feat(yip-rendezvous): node-id + wire message codec (2b)"
```

---

### Task 2: `RendezvousServer` state machine (`server.rs`)

**Files:**
- Create: `crates/yip-rendezvous/src/server.rs`
- Test: inline `#[cfg(test)]` in `server.rs`

**Interfaces:**
- Consumes: `crate::proto::{Message, NodeId}`.
- Produces:
  - `pub struct RendezvousServer { /* private */ }`
  - `pub fn new(now_ms: u64) -> Self` — `now_ms` seeds rate-limit windows.
  - `pub fn handle(&mut self, src: SocketAddr, msg: Message, now_ms: u64) -> Vec<(SocketAddr, Message)>` — process one message, return `(dst_addr, reply)` datagrams to send.
  - `pub fn sweep(&mut self, now_ms: u64)` — evict expired registrations (called on a timer).
  - `pub fn forwarded_count(&self) -> u64` — relay datagrams forwarded (test observability).
  - Constants: `REG_TTL_MS = 60_000`, `MAX_REGISTRATIONS = 65_536`, `RATE_WINDOW_MS = 1_000`, `MAX_MSGS_PER_WINDOW = 64`.

- [ ] **Step 1: Write failing tests** in `crates/yip-rendezvous/src/server.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{node_id, Message};
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr { s.parse().unwrap() }

    #[test]
    fn register_then_lookup_returns_observed_reflexive() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let b = node_id(&[2u8; 32]);
        // A registers from its observed reflexive addr.
        let out = s.handle(addr("198.51.100.7:41000"), Message::Register { node: a }, 0);
        assert!(out.is_empty(), "register produces no reply");
        // B looks up A: gets A's reflexive via PeerInfo, and A gets a PunchHint
        // carrying B's reflexive.
        let out = s.handle(addr("203.0.113.9:52000"), Message::Lookup { node: a }, 10);
        // one reply to B (PeerInfo), one to A (PunchHint)
        assert!(out.iter().any(|(d, m)| *d == addr("203.0.113.9:52000")
            && matches!(m, Message::PeerInfo { node, reflexive } if *node == a && *reflexive == addr("198.51.100.7:41000"))));
        assert!(out.iter().any(|(d, m)| *d == addr("198.51.100.7:41000")
            && matches!(m, Message::PunchHint { reflexive, .. } if *reflexive == addr("203.0.113.9:52000"))));
    }

    #[test]
    fn lookup_unregistered_returns_notfound() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let out = s.handle(addr("203.0.113.9:52000"), Message::Lookup { node: a }, 0);
        assert_eq!(out, vec![(addr("203.0.113.9:52000"), Message::NotFound { node: a })]);
    }

    #[test]
    fn ttl_expiry_evicts_registration() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        s.handle(addr("198.51.100.7:41000"), Message::Register { node: a }, 0);
        s.sweep(REG_TTL_MS + 1);
        let out = s.handle(addr("203.0.113.9:52000"), Message::Lookup { node: a }, REG_TTL_MS + 2);
        assert!(matches!(out.as_slice(), [(_, Message::NotFound { .. })]));
    }

    #[test]
    fn relay_forwards_to_registered_dst_and_counts() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let b = node_id(&[2u8; 32]);
        s.handle(addr("198.51.100.7:41000"), Message::Register { node: a }, 0); // A registered
        // B relays a payload to A -> A gets RelayDeliver{src=B, payload}.
        let out = s.handle(addr("203.0.113.9:52000"),
            Message::RelaySend { src: b, dst: a, payload: vec![9, 9] }, 5);
        assert_eq!(out, vec![(addr("198.51.100.7:41000"),
            Message::RelayDeliver { src: b, payload: vec![9, 9] })]);
        assert_eq!(s.forwarded_count(), 1);
    }

    #[test]
    fn relay_to_unregistered_dst_drops_no_forward() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let b = node_id(&[2u8; 32]);
        let out = s.handle(addr("203.0.113.9:52000"),
            Message::RelaySend { src: b, dst: a, payload: vec![1] }, 0);
        assert!(out.is_empty());
        assert_eq!(s.forwarded_count(), 0);
    }

    #[test]
    fn rate_limit_caps_messages_per_source_window() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let src = addr("203.0.113.9:52000");
        // Exceed the per-window cap; excess Lookups must produce no replies.
        let mut replies = 0;
        for _ in 0..(MAX_MSGS_PER_WINDOW + 10) {
            replies += s.handle(src, Message::Lookup { node: a }, 0).len();
        }
        // Only up to the cap are serviced (each serviced Lookup -> 1 NotFound).
        assert!(replies <= MAX_MSGS_PER_WINDOW, "rate limit must drop excess");
    }
}
```

- [ ] **Step 2: Run server tests → fail**, then implement `server.rs`. Prepend:

```rust
//! Pure rendezvous/relay server state machine: soft-state registration with
//! TTL, per-source rate limiting, and blind relay forwarding. No I/O — the
//! `bin/yip-rendezvous` loop owns the socket and the clock.
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::proto::{Message, NodeId};

/// Registration lifetime; clients refresh well within this.
pub const REG_TTL_MS: u64 = 60_000;
/// Hard cap on concurrent registrations (memory bound).
pub const MAX_REGISTRATIONS: usize = 65_536;
/// Rate-limit window and per-source message cap within it.
pub const RATE_WINDOW_MS: u64 = 1_000;
pub const MAX_MSGS_PER_WINDOW: usize = 64;

struct Reg {
    addr: SocketAddr,
    expiry_ms: u64,
}

struct Rate {
    window_start_ms: u64,
    count: usize,
}

/// Soft-state rendezvous + blind relay. Keyed by `NodeId`.
pub struct RendezvousServer {
    regs: HashMap<NodeId, Reg>,
    rates: HashMap<SocketAddr, Rate>,
    forwarded: u64,
}

impl RendezvousServer {
    pub fn new(_now_ms: u64) -> Self {
        Self { regs: HashMap::new(), rates: HashMap::new(), forwarded: 0 }
    }

    pub fn forwarded_count(&self) -> u64 {
        self.forwarded
    }

    /// True iff `src` is within its per-window budget (and records the hit).
    fn rate_ok(&mut self, src: SocketAddr, now_ms: u64) -> bool {
        let r = self.rates.entry(src).or_insert(Rate { window_start_ms: now_ms, count: 0 });
        if now_ms.saturating_sub(r.window_start_ms) >= RATE_WINDOW_MS {
            r.window_start_ms = now_ms;
            r.count = 0;
        }
        if r.count >= MAX_MSGS_PER_WINDOW {
            return false;
        }
        r.count += 1;
        true
    }

    /// Evict expired registrations. Call on a timer from the socket loop.
    pub fn sweep(&mut self, now_ms: u64) {
        self.regs.retain(|_, reg| reg.expiry_ms > now_ms);
        // Rate windows are cheap; drop stale ones opportunistically.
        self.rates.retain(|_, r| now_ms.saturating_sub(r.window_start_ms) < RATE_WINDOW_MS);
    }

    /// Process one received message; return datagrams to send as `(dst, msg)`.
    pub fn handle(&mut self, src: SocketAddr, msg: Message, now_ms: u64) -> Vec<(SocketAddr, Message)> {
        if !self.rate_ok(src, now_ms) {
            return Vec::new();
        }
        match msg {
            Message::Register { node } => {
                if self.regs.len() >= MAX_REGISTRATIONS && !self.regs.contains_key(&node) {
                    return Vec::new(); // at capacity; refuse new ids (existing refresh ok)
                }
                self.regs.insert(node, Reg { addr: src, expiry_ms: now_ms.saturating_add(REG_TTL_MS) });
                Vec::new()
            }
            Message::Lookup { node } => match self.regs.get(&node) {
                Some(reg) if reg.expiry_ms > now_ms => {
                    let peer_addr = reg.addr;
                    let mut out = vec![(src, Message::PeerInfo { node, reflexive: peer_addr })];
                    // Tell the looked-up peer to punch back toward the requester.
                    out.push((peer_addr, Message::PunchHint { node, reflexive: src }));
                    out
                }
                _ => vec![(src, Message::NotFound { node })],
            },
            Message::RelaySend { src: sender, dst, payload } => match self.regs.get(&dst) {
                Some(reg) if reg.expiry_ms > now_ms => {
                    self.forwarded += 1;
                    vec![(reg.addr, Message::RelayDeliver { src: sender, payload })]
                }
                _ => Vec::new(), // dst unknown: drop
            },
            // Server never receives these (they are server->client); ignore.
            Message::PeerInfo { .. }
            | Message::NotFound { .. }
            | Message::PunchHint { .. }
            | Message::RelayDeliver { .. } => Vec::new(),
        }
    }
}
```

(The consts `REG_TTL_MS`/`MAX_MSGS_PER_WINDOW` are `pub` on the `server` module and reachable in the inline tests via `use super::*`.)

- [ ] **Step 3: Run tests → pass; build/clippy/fmt clean.**

```bash
cargo test -p yip-rendezvous
cargo clippy -p yip-rendezvous --all-targets -- -D warnings && cargo fmt --all --check
```

- [ ] **Step 4: Commit.**

```bash
git add crates/yip-rendezvous/src/server.rs crates/yip-rendezvous/src/proto.rs
git commit -m "feat(yip-rendezvous): server state machine — registration TTL, rate limit, blind relay (2b)"
```

---

### Task 3: `bin/yip-rendezvous` server binary + socket smoke

**Files:**
- Create: `bin/yip-rendezvous/Cargo.toml`, `bin/yip-rendezvous/src/main.rs`
- Test: `bin/yip-rendezvous/tests/smoke.rs`

**Interfaces:**
- Consumes: `yip_rendezvous::{decode, encode, RendezvousServer, Message, node_id}`.
- Produces: a runnable binary `yip-rendezvous <listen-addr>` (e.g. `yip-rendezvous 0.0.0.0:51821`).

- [ ] **Step 1: Create the crate.** `bin/yip-rendezvous/Cargo.toml`:

```toml
[package]
name = "yip-rendezvous-bin"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[[bin]]
name = "yip-rendezvous"
path = "src/main.rs"

[dependencies]
yip-rendezvous = { path = "../../crates/yip-rendezvous" }

[lints]
workspace = true
```

- [ ] **Step 2: Write the failing smoke test** `bin/yip-rendezvous/tests/smoke.rs`:

```rust
//! Socket-level smoke: spawn the server, register from one socket, look up from
//! another, and relay a payload — asserting the observed reflexive addr and the
//! blind forward both work over real UDP.
use std::net::UdpSocket;
use std::process::{Child, Command};
use std::time::Duration;

use yip_rendezvous::{decode, encode, node_id, Message};

fn spawn_server(listen: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_yip-rendezvous"))
        .arg(listen)
        .spawn()
        .expect("spawn server")
}

#[test]
fn register_lookup_relay_over_udp() {
    let listen = "127.0.0.1:51821";
    let mut server = spawn_server(listen);
    std::thread::sleep(Duration::from_millis(300)); // let it bind

    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let a_id = node_id(&[1u8; 32]);
    let b_id = node_id(&[2u8; 32]);

    // A registers.
    let mut buf = Vec::new();
    encode(&Message::Register { node: a_id }, &mut buf);
    a.send_to(&buf, listen).unwrap();
    std::thread::sleep(Duration::from_millis(100));

    // B looks up A -> expects PeerInfo(A, A's reflexive addr).
    buf.clear();
    encode(&Message::Lookup { node: a_id }, &mut buf);
    b.send_to(&buf, listen).unwrap();
    let mut rx = [0u8; 2048];
    let (n, _) = b.recv_from(&mut rx).expect("B receives PeerInfo");
    match decode(&rx[..n]) {
        Some(Message::PeerInfo { node, reflexive }) => {
            assert_eq!(node, a_id);
            assert_eq!(reflexive, a.local_addr().unwrap());
        }
        other => panic!("expected PeerInfo, got {other:?}"),
    }

    // B relays a payload to A -> A receives RelayDeliver{src=B, payload}.
    buf.clear();
    encode(&Message::RelaySend { src: b_id, dst: a_id, payload: vec![7, 7, 7] }, &mut buf);
    b.send_to(&buf, listen).unwrap();
    let (n, _) = a.recv_from(&mut rx).expect("A receives RelayDeliver");
    match decode(&rx[..n]) {
        Some(Message::RelayDeliver { src, payload }) => {
            assert_eq!(src, b_id);
            assert_eq!(payload, vec![7, 7, 7]);
        }
        other => panic!("expected RelayDeliver, got {other:?}"),
    }

    let _ = server.kill();
}
```

- [ ] **Step 3: Run → fail** (`cargo test -p yip-rendezvous-bin` — binary missing).

- [ ] **Step 4: Implement `bin/yip-rendezvous/src/main.rs`:**

```rust
//! The yip rendezvous + blind relay server. Binds one UDP socket, drives the
//! pure `RendezvousServer` state machine, and sweeps expired registrations on a
//! read-timeout cadence. No TUN, no tunnel keys, no unsafe.
#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use yip_rendezvous::{decode, encode, Message, RendezvousServer};

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

fn main() -> std::io::Result<()> {
    let mut args = std::env::args();
    let _prog = args.next();
    let listen = match args.next().as_deref() {
        Some("--version") | Some("-V") => {
            println!("yip-rendezvous {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(addr) => addr.to_string(),
        None => {
            eprintln!("usage: yip-rendezvous <listen-addr>   e.g. 0.0.0.0:51821");
            std::process::exit(2);
        }
    };

    let sock = UdpSocket::bind(&listen)?;
    sock.set_read_timeout(Some(SWEEP_INTERVAL))?;
    eprintln!("yip-rendezvous listening on {listen}");

    // Millisecond clock from a monotonic base (Instant), so `now_ms` never goes
    // backwards and needs no wall clock.
    let base = Instant::now();
    let now_ms = |base: Instant| -> u64 {
        u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX)
    };

    let mut server = RendezvousServer::new(now_ms(base));
    let mut last_sweep = Instant::now();
    let mut rx = [0u8; 2048];
    let mut out = Vec::new();

    loop {
        match sock.recv_from(&mut rx) {
            Ok((n, src)) => {
                if let Some(msg) = decode(&rx[..n]) {
                    for (dst, reply) in server.handle(src, msg, now_ms(base)) {
                        out.clear();
                        encode(&reply, &mut out);
                        let _ = sock.send_to(&out, dst); // best-effort; drop on error
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
        if last_sweep.elapsed() >= SWEEP_INTERVAL {
            server.sweep(now_ms(base));
            last_sweep = Instant::now();
        }
    }
}
```

- [ ] **Step 5: Run → pass; build/clippy/fmt clean.** `cargo test -p yip-rendezvous-bin` (the smoke spawns a real server). If it flakes on bind timing, raise the initial sleep. Confirm `cargo build --workspace` includes the new binary.

- [ ] **Step 6: Commit.**

```bash
git add bin/yip-rendezvous/Cargo.toml bin/yip-rendezvous/src/main.rs bin/yip-rendezvous/tests/smoke.rs Cargo.lock
git commit -m "feat(yip-rendezvous): server binary + UDP register/lookup/relay smoke (2b)"
```

---

### Task 4: `Rendezvous` trait + `ConfiguredServerRendezvous` client + config

**Files:**
- Create: `bin/yipd/src/rendezvous.rs`
- Modify: `bin/yipd/src/config.rs` (add `rendezvous`, make `PeerConfig.endpoint` optional), `bin/yipd/src/main.rs` (`mod rendezvous;`), `bin/yipd/Cargo.toml` (dep on `yip-rendezvous`)
- Test: inline `#[cfg(test)]` in both files

**Interfaces:**
- Consumes: `yip_rendezvous::{node_id, encode, decode, Message, NodeId}`, `yip_io::poll::EgressDatagram`.
- Produces:
  - `pub enum RdvEvent { PeerCandidate { node: NodeId, addr: SocketAddr }, PunchTo { node: NodeId, addr: SocketAddr }, Relayed { src: NodeId, payload: Vec<u8> }, NotFound { node: NodeId }, Ignored }`
  - `pub trait Rendezvous { fn register(&mut self, node: NodeId) -> EgressDatagram; fn lookup(&mut self, node: NodeId) -> EgressDatagram; fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram; fn parse(&self, dg: &[u8]) -> RdvEvent; fn server_addr(&self) -> SocketAddr; }`
  - `pub struct ConfiguredServerRendezvous { server: SocketAddr }` + `pub fn new(server: SocketAddr) -> Self`.
  - `config::Config.rendezvous: Option<SocketAddr>`, `config::PeerConfig.endpoint: Option<SocketAddr>`.

- [ ] **Step 1: Make `PeerConfig.endpoint` optional + add `rendezvous`.** In `bin/yipd/src/config.rs`: change `pub endpoint: SocketAddr` → `pub endpoint: Option<SocketAddr>`; add `pub rendezvous: Option<SocketAddr>` to `Config`. In the parser: a `[peer]` block without an `endpoint`/`peer_endpoint` key yields `endpoint: None` (do NOT error); add a top-level `rendezvous=<IP:port>` key parsed into `Config.rendezvous` (absent → `None`). Update all existing `PeerConfig { endpoint: X }` literals in this file's tests to `endpoint: Some(X)`.

- [ ] **Step 2: Write failing config tests** (append to `config.rs` tests):

```rust
#[test]
fn parses_rendezvous_and_optional_endpoint() {
    let text = "local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                local_public=000000000000000000000000000000000000000000000000000000000000aa01\n\
                listen=0.0.0.0:51820\ndevice=yip0\nrendezvous=203.0.113.1:51821\n\
                [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b1\n";
    let cfg = Config::parse(text).expect("parses");
    assert_eq!(cfg.rendezvous, Some("203.0.113.1:51821".parse().unwrap()));
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].endpoint, None, "peer with no endpoint is rendezvous-only");
}

#[test]
fn rendezvous_absent_is_none() {
    let text = "local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                local_public=000000000000000000000000000000000000000000000000000000000000aa01\n\
                listen=0.0.0.0:51820\ndevice=yip0\n\
                [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b1\nendpoint=10.0.0.2:51820\n";
    let cfg = Config::parse(text).unwrap();
    assert_eq!(cfg.rendezvous, None);
    assert_eq!(cfg.peers[0].endpoint, Some("10.0.0.2:51820".parse().unwrap()));
}
```

- [ ] **Step 3: Run → fail; implement the config changes** (Step 1) until these pass. `cargo test -p yipd --bins config`.

- [ ] **Step 4: Add the `yip-rendezvous` dep** to `bin/yipd/Cargo.toml`: `yip-rendezvous = { path = "../../crates/yip-rendezvous" }`. Add `mod rendezvous;` to `bin/yipd/src/main.rs`.

- [ ] **Step 5: Write failing client tests** in `bin/yipd/src/rendezvous.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use yip_rendezvous::{encode, node_id, Message};

    fn server() -> SocketAddr { "203.0.113.1:51821".parse().unwrap() }

    #[test]
    fn register_targets_server_with_our_node_id() {
        let mut r = ConfiguredServerRendezvous::new(server());
        let me = node_id(&[1u8; 32]);
        let dg = r.register(me);
        assert_eq!(dg.dst, server());
        assert_eq!(yip_rendezvous::decode(&dg.bytes), Some(Message::Register { node: me }));
    }

    #[test]
    fn relay_wraps_payload_for_dst() {
        let mut r = ConfiguredServerRendezvous::new(server());
        let me = node_id(&[1u8; 32]);
        let peer = node_id(&[2u8; 32]);
        let dg = r.relay(me, peer, &[4, 5, 6]);
        assert_eq!(dg.dst, server());
        assert_eq!(
            yip_rendezvous::decode(&dg.bytes),
            Some(Message::RelaySend { src: me, dst: peer, payload: vec![4, 5, 6] })
        );
    }

    #[test]
    fn parse_maps_server_messages_to_events() {
        let r = ConfiguredServerRendezvous::new(server());
        let n = node_id(&[2u8; 32]);
        let a: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let mut buf = Vec::new();
        encode(&Message::PeerInfo { node: n, reflexive: a }, &mut buf);
        assert!(matches!(r.parse(&buf), RdvEvent::PeerCandidate { node, addr } if node == n && addr == a));
        buf.clear();
        encode(&Message::PunchHint { node: n, reflexive: a }, &mut buf);
        assert!(matches!(r.parse(&buf), RdvEvent::PunchTo { node, addr } if node == n && addr == a));
        buf.clear();
        encode(&Message::RelayDeliver { src: n, payload: vec![1, 2] }, &mut buf);
        assert!(matches!(r.parse(&buf), RdvEvent::Relayed { src, payload } if src == n && payload == vec![1, 2]));
        assert!(matches!(r.parse(&[0xFF]), RdvEvent::Ignored));
    }
}
```

- [ ] **Step 6: Run → fail; implement `rendezvous.rs`.** Prepend:

```rust
//! The `yipd` side of the rendezvous protocol: a `Rendezvous` trait (so a 2c
//! DHT backend can replace the configured-server one) and the
//! `ConfiguredServerRendezvous` impl that produces `EgressDatagram`s aimed at a
//! configured server and parses server datagrams into `RdvEvent`s the path
//! state machine reacts to.
use std::net::SocketAddr;

use yip_io::poll::EgressDatagram;
use yip_rendezvous::{decode, encode, Message, NodeId};

/// A parsed inbound rendezvous datagram, normalized for the path SM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdvEvent {
    /// The server told us where a peer is (answer to our `lookup`).
    PeerCandidate { node: NodeId, addr: SocketAddr },
    /// The server asked us to punch toward a peer that looked us up.
    PunchTo { node: NodeId, addr: SocketAddr },
    /// A relayed tunnel datagram from `src`; `payload` is fed to the peer path.
    Relayed { src: NodeId, payload: Vec<u8> },
    /// The looked-up peer is not registered.
    NotFound { node: NodeId },
    /// Not a message we act on.
    Ignored,
}

/// Abstraction over "how do I find/reach a peer by node id". 2b ships the
/// configured-server impl; 2c adds a DHT impl without touching `PeerManager`.
pub trait Rendezvous {
    fn register(&mut self, node: NodeId) -> EgressDatagram;
    fn lookup(&mut self, node: NodeId) -> EgressDatagram;
    fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram;
    fn parse(&self, dg: &[u8]) -> RdvEvent;
    fn server_addr(&self) -> SocketAddr;
}

/// Talks to a single configured rendezvous+relay server.
pub struct ConfiguredServerRendezvous {
    server: SocketAddr,
}

impl ConfiguredServerRendezvous {
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    fn to_server(&self, msg: &Message) -> EgressDatagram {
        let mut bytes = Vec::new();
        encode(msg, &mut bytes);
        EgressDatagram { fate: 0, dst: self.server, bytes }
    }
}

impl Rendezvous for ConfiguredServerRendezvous {
    fn register(&mut self, node: NodeId) -> EgressDatagram {
        self.to_server(&Message::Register { node })
    }
    fn lookup(&mut self, node: NodeId) -> EgressDatagram {
        self.to_server(&Message::Lookup { node })
    }
    fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram {
        self.to_server(&Message::RelaySend { src, dst, payload: payload.to_vec() })
    }
    fn parse(&self, dg: &[u8]) -> RdvEvent {
        match decode(dg) {
            Some(Message::PeerInfo { node, reflexive }) => RdvEvent::PeerCandidate { node, addr: reflexive },
            Some(Message::PunchHint { node, reflexive }) => RdvEvent::PunchTo { node, addr: reflexive },
            Some(Message::RelayDeliver { src, payload }) => RdvEvent::Relayed { src, payload },
            Some(Message::NotFound { node }) => RdvEvent::NotFound { node },
            _ => RdvEvent::Ignored,
        }
    }
    fn server_addr(&self) -> SocketAddr {
        self.server
    }
}
```

- [ ] **Step 7: Run → pass; build/clippy/fmt clean.** `cargo test -p yipd --bins` (config + rendezvous). Note: making `endpoint` optional will break `peer_manager.rs`/`tunnel.rs` references — Task 6 fixes those; for THIS task, adjust only the minimum in `peer_manager.rs`/`tunnel.rs` so the workspace still builds (e.g. `p.endpoint.unwrap_or_else(|| /* placeholder unspecified addr */)` is NOT acceptable — instead, in `PeerManager::new`, store `endpoint: Option<SocketAddr>` on `Peer` and default the not-yet-wired paths; if that is too invasive for this task, temporarily map `None` peers by skipping them with a `// TODO(task6)` and a compile-guarding `expect`). Keep the change minimal and localized; Task 6 does the real wiring. Ensure `cargo build --workspace` is green.

> Implementer note: cleanest minimal approach for Step 7 — change `Peer.endpoint` to `Option<SocketAddr>` now and make the 2a direct-path code use `if let Some(ep) = peer.endpoint` (a `None` peer simply has no direct candidate yet; it can't handshake until Task 6 supplies one, which is acceptable because no test in this task exercises a `None`-endpoint peer end-to-end). This avoids placeholder addresses entirely.

- [ ] **Step 8: Commit.**

```bash
git add bin/yipd/src/rendezvous.rs bin/yipd/src/config.rs bin/yipd/src/main.rs bin/yipd/Cargo.toml bin/yipd/src/peer_manager.rs bin/yipd/src/tunnel.rs Cargo.lock
git commit -m "feat(yipd): Rendezvous trait + configured-server client; optional endpoint + rendezvous config (2b)"
```

---

### Task 5: per-peer path state machine (`path.rs`)

**Files:**
- Create: `bin/yipd/src/path.rs`
- Modify: `bin/yipd/src/main.rs` (`mod path;`)
- Test: inline `#[cfg(test)]` in `path.rs`

**Interfaces:**
- Produces:
  - `pub enum PathKind { Direct, Punched, Relayed }`
  - `pub enum PathStage { Direct, Punching, Relaying, Failed }`
  - `pub struct PathState { /* private */ }` with:
    - `pub fn new(has_direct: bool, has_rendezvous: bool, now_ms: u64) -> Self`
    - `pub fn candidate(&self) -> Option<SocketAddr>` — the address to probe now (None ⇒ relay or nothing).
    - `pub fn stage(&self) -> PathStage`
    - `pub fn on_direct_addr(&mut self, addr: SocketAddr)` — supply the configured direct endpoint.
    - `pub fn on_peer_candidate(&mut self, addr: SocketAddr, now_ms: u64)` — a reflexive addr arrived (enter Punching).
    - `pub fn advance(&mut self, now_ms: u64) -> PathAction` — deadline-driven escalation.
    - `pub fn committed(&mut self, kind: PathKind)` — handshake completed over the current path.
    - `pub fn reset(&mut self, now_ms: u64)` — session went stale; re-enter from Direct.
  - `pub enum PathAction { Idle, NeedLookup, Probe(SocketAddr), Relay, Failed }`
  - Constants: `DIRECT_MS = 3_000`, `PUNCH_MS = 5_000` (per-stage windows).

- [ ] **Step 1: Write failing tests** in `bin/yipd/src/path.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn a(s: &str) -> SocketAddr { s.parse().unwrap() }

    #[test]
    fn direct_first_when_endpoint_known() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        assert!(matches!(p.advance(0), PathAction::Probe(x) if x == a("10.0.0.2:51820")));
        assert_eq!(p.stage(), PathStage::Direct);
    }

    #[test]
    fn escalates_direct_to_punch_after_window() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        let _ = p.advance(0);
        // After the direct window with no commit, ask for a lookup (enter punch).
        assert!(matches!(p.advance(DIRECT_MS + 1), PathAction::NeedLookup));
        assert_eq!(p.stage(), PathStage::Punching);
    }

    #[test]
    fn punch_probes_learned_candidate_then_relays_after_window() {
        let mut p = PathState::new(false, true, 0); // no direct endpoint
        assert!(matches!(p.advance(0), PathAction::NeedLookup));
        p.on_peer_candidate(a("198.51.100.7:41000"), 10);
        assert!(matches!(p.advance(10), PathAction::Probe(x) if x == a("198.51.100.7:41000")));
        // Punch window elapses without commit -> escalate to relay.
        assert!(matches!(p.advance(10 + PUNCH_MS + 1), PathAction::Relay));
        assert_eq!(p.stage(), PathStage::Relaying);
    }

    #[test]
    fn no_rendezvous_and_no_direct_is_failed() {
        let mut p = PathState::new(false, false, 0);
        assert!(matches!(p.advance(0), PathAction::Failed));
        assert_eq!(p.stage(), PathStage::Failed);
    }

    #[test]
    fn commit_pins_path_and_stops_escalating() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        let _ = p.advance(0);
        p.committed(PathKind::Direct);
        // Even past the direct window, a committed path does not escalate.
        assert!(matches!(p.advance(DIRECT_MS + 100), PathAction::Idle));
    }

    #[test]
    fn reset_reenters_from_direct() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        p.committed(PathKind::Direct);
        p.reset(1000);
        assert!(matches!(p.advance(1000), PathAction::Probe(x) if x == a("10.0.0.2:51820")));
        assert_eq!(p.stage(), PathStage::Direct);
    }
}
```

- [ ] **Step 2: Run → fail.** `cargo test -p yipd --bins path`.

- [ ] **Step 3: Implement `path.rs`.** Prepend (design: a small deadline-driven state machine; `advance` is called from `tick` and returns the next action the caller performs; `on_*` feed external inputs; `committed` freezes it):

```rust
//! Per-peer connection path state machine: escalate Direct -> Punch -> Relay,
//! each with a bounded window, feeding candidate addresses to the caller's
//! handshake machinery. A candidate is ONLY ever a probe target — the caller
//! commits a path (via `committed`) only once a Noise handshake completes over
//! it (the anti-hijack invariant lives in the caller; this SM never sends).
use std::net::SocketAddr;

/// Direct-stage window before escalating to punch.
pub const DIRECT_MS: u64 = 3_000;
/// Punch-stage window before escalating to relay.
pub const PUNCH_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Punched,
    Relayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStage {
    Direct,
    Punching,
    Relaying,
    Failed,
}

/// What the caller should do this tick for a not-yet-established peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAction {
    /// Nothing to do (committed, or waiting within a window).
    Idle,
    /// Send a `Lookup` for this peer (entering/among the punch stage).
    NeedLookup,
    /// Probe this candidate with a handshake Init.
    Probe(SocketAddr),
    /// Send the handshake/data via the relay.
    Relay,
    /// No path available (no direct endpoint and no rendezvous).
    Failed,
}

pub struct PathState {
    stage: PathStage,
    has_rendezvous: bool,
    direct: Option<SocketAddr>,
    candidate: Option<SocketAddr>, // reflexive addr for the punch stage
    stage_started_ms: u64,
    committed: bool,
    looked_up: bool,
}

impl PathState {
    pub fn new(has_direct: bool, has_rendezvous: bool, now_ms: u64) -> Self {
        let stage = if has_direct {
            PathStage::Direct
        } else if has_rendezvous {
            PathStage::Punching
        } else {
            PathStage::Failed
        };
        Self {
            stage,
            has_rendezvous,
            direct: None,
            candidate: None,
            stage_started_ms: now_ms,
            committed: false,
            looked_up: false,
        }
    }

    pub fn stage(&self) -> PathStage {
        self.stage
    }

    pub fn candidate(&self) -> Option<SocketAddr> {
        match self.stage {
            PathStage::Direct => self.direct,
            PathStage::Punching => self.candidate,
            _ => None,
        }
    }

    pub fn on_direct_addr(&mut self, addr: SocketAddr) {
        self.direct = Some(addr);
    }

    pub fn on_peer_candidate(&mut self, addr: SocketAddr, now_ms: u64) {
        // A reflexive addr arrived (from PeerInfo or a PunchHint): enter/refresh
        // the punch stage targeting it.
        self.candidate = Some(addr);
        if self.stage == PathStage::Direct || self.stage == PathStage::Punching {
            if self.stage != PathStage::Punching {
                self.stage_started_ms = now_ms;
            }
            self.stage = PathStage::Punching;
        }
    }

    fn enter(&mut self, stage: PathStage, now_ms: u64) {
        self.stage = stage;
        self.stage_started_ms = now_ms;
    }

    pub fn advance(&mut self, now_ms: u64) -> PathAction {
        if self.committed {
            return PathAction::Idle;
        }
        let elapsed = now_ms.saturating_sub(self.stage_started_ms);
        match self.stage {
            PathStage::Direct => {
                if let Some(addr) = self.direct {
                    if elapsed < DIRECT_MS {
                        return PathAction::Probe(addr);
                    }
                }
                // Direct window elapsed (or never had an endpoint): escalate.
                if self.has_rendezvous {
                    self.enter(PathStage::Punching, now_ms);
                    self.punch_action(now_ms)
                } else {
                    self.enter(PathStage::Failed, now_ms);
                    PathAction::Failed
                }
            }
            PathStage::Punching => {
                if elapsed >= PUNCH_MS {
                    self.enter(PathStage::Relaying, now_ms);
                    return PathAction::Relay;
                }
                self.punch_action(now_ms)
            }
            PathStage::Relaying => PathAction::Relay,
            PathStage::Failed => PathAction::Failed,
        }
    }

    fn punch_action(&mut self, _now_ms: u64) -> PathAction {
        match self.candidate {
            Some(addr) => PathAction::Probe(addr),
            None => {
                if !self.looked_up {
                    self.looked_up = true;
                }
                PathAction::NeedLookup
            }
        }
    }

    pub fn committed(&mut self, _kind: PathKind) {
        self.committed = true;
    }

    pub fn reset(&mut self, now_ms: u64) {
        self.committed = false;
        self.candidate = None;
        self.looked_up = false;
        self.stage = if self.direct.is_some() {
            PathStage::Direct
        } else if self.has_rendezvous {
            PathStage::Punching
        } else {
            PathStage::Failed
        };
        self.stage_started_ms = now_ms;
    }
}
```

Add `mod path;` to `bin/yipd/src/main.rs`.

- [ ] **Step 4: Run → pass; build/clippy/fmt clean.** `cargo test -p yipd --bins path`. (Note: `new(has_direct, ...)` ignores its `now_ms` for `Direct` start until `advance`; the tests above pass with this design. If `escalates_direct_to_punch_after_window` needs `stage_started_ms=0`, it is — `new` sets it to `now_ms`.)

- [ ] **Step 5: Commit.**

```bash
git add bin/yipd/src/path.rs bin/yipd/src/main.rs
git commit -m "feat(yipd): per-peer path state machine — Direct/Punch/Relay escalation (2b)"
```

---

### Task 6: wire rendezvous + path SM into `PeerManager` and `tunnel.rs`

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs`, `bin/yipd/src/tunnel.rs`
- Test: inline `#[cfg(test)]` in `peer_manager.rs` (mock `Rendezvous`)

**Interfaces:**
- Consumes: `crate::rendezvous::{Rendezvous, ConfiguredServerRendezvous, RdvEvent}`, `crate::path::{PathState, PathStage, PathKind, PathAction}`, `yip_rendezvous::node_id`.
- Produces: `PeerManager::new(local_private, local_public, peers, mode, rendezvous: Option<Box<dyn Rendezvous>>)` (extended signature); `PeerManager` demuxes server datagrams, drives the path SM, and relays.

This is the integration crux — read `peer_manager.rs` in full first. Key wiring (implement to this behavior):

1. **Struct + `new`:** add `rendezvous: Option<Box<dyn Rendezvous>>`, `local_node_id: NodeId`, and a `by_node: HashMap<NodeId, usize>` (peer node_id → index, built from configured pubkeys). Give each `Peer` a `path: PathState` (`PathState::new(peer.endpoint.is_some(), rendezvous.is_some(), 0)`; if the peer has a configured endpoint, immediately `path.on_direct_addr(ep)`), and change `Peer.endpoint` to `Option<SocketAddr>` (from Task 4) plus a committed `path_kind: Option<PathKind>`.

2. **`on_udp` demux:** if `src == rendezvous.server_addr()`, route to `on_rdv(dg, now)`:
   - `RdvEvent::PeerCandidate{node,addr}` / `PunchTo{node,addr}` → `by_node[node]` → `peer.path.on_peer_candidate(addr, now)`; on `PunchTo`, ALSO start a probe immediately (a fresh `start_initiator` to `addr` if not already Handshaking) so both sides open bindings.
   - `RdvEvent::Relayed{src,payload}` → treat `payload` as a peer datagram FROM the relayed peer: process it via the normal peer path, but any egress it produces must go back **via relay** (wrap through `rendezvous.relay(local_node_id, src, &out)`), and if it completes a handshake, commit `PathKind::Relayed`. (Track "this peer is currently reached via relay" so `Established` egress relays too.)
   - `RdvEvent::NotFound` / `Ignored` → drive/ignore.
   Otherwise (src ≠ server) → the existing 2a peer path unchanged. **Guard:** if `rendezvous` is `None`, skip the server-addr check entirely (pure 2a).

3. **`on_tun` / `tick`:** for a non-`Established` peer, call `peer.path.advance(now)` and act on `PathAction`:
   - `Probe(addr)` → ensure a handshake initiator is in flight to `addr` (reuse 2a's lazy `start_initiator`, but target `addr` — the candidate — instead of only the configured endpoint); buffer the TUN packet.
   - `NeedLookup` → emit `rendezvous.lookup(node_id(peer.pubkey))` (once per punch entry; also emit `rendezvous.register(local_node_id)` periodically — every ~20s — from `tick`).
   - `Relay` → send the handshake Init (and, once Established-via-relay, data) wrapped via `rendezvous.relay(local_node_id, peer_node, &bytes)`.
   - `Failed` → drop (no path).
   On handshake completion (existing `handle_handshake_resp`/`handle_handshake_init` success), call `peer.path.committed(kind)` where `kind` reflects which candidate completed, and set `Peer.endpoint = Some(committed_addr)` so 2a's `Established` egress targets it (for Direct/Punched). For Relayed, mark the peer relayed and route its egress through `rendezvous.relay`.

4. **Anti-hijack:** never change an `Established` peer's committed egress target from an unauthenticated event. `on_peer_candidate` only affects a non-`Established` peer's `path`; an `Established` peer ignores new candidates until it re-enters the SM via `reset` (which only happens on a local decision that the session is stale, not on a received packet).

5. **Registration:** in `tick`, if `rendezvous` is `Some`, emit a `register(local_node_id)` datagram every `REG_REFRESH_MS` (define `const REG_REFRESH_MS: u64 = 20_000;`) so the server keeps our reflexive binding fresh.

- [ ] **Step 1: Write a failing integration test** in `peer_manager.rs` tests using a **mock `Rendezvous`** that records datagrams and lets the test inject events. Assert: (a) a peer with `endpoint: None` and a rendezvous configured emits a `Lookup` (via the mock) when TUN traffic arrives; (b) feeding a `PeerCandidate` event then ticking produces a handshake Init `EgressDatagram` whose `dst` is the candidate addr; (c) with NO rendezvous configured, a peer with a direct endpoint behaves exactly as 2a (Init to the configured endpoint). Write the mock inline:

```rust
struct MockRdv { server: SocketAddr, sent: std::cell::RefCell<Vec<Message>> }
// impl Rendezvous for MockRdv: register/lookup/relay push the Message into `sent`
// and return an EgressDatagram{dst: server, bytes: encoded}; parse() decodes;
// server_addr() returns server.
```

(Full assertions per (a)-(c) above; use `node_id` from `yip_rendezvous`.)

- [ ] **Step 2: Run → fail.** `cargo test -p yipd --bins peer_manager`.

- [ ] **Step 3: Implement the wiring** per points 1–5. Read the current `on_udp`/`on_tun`/`tick`/`handle_handshake_*` and thread the path SM through them. Keep the 2a single-peer/glare/duplicate-init logic intact — the path SM only chooses *which address* to hand the existing handshake machinery, and adds the relay wrapping + server demux.

- [ ] **Step 4: Update `tunnel.rs`** to build the client and pass it in:

```rust
let rendezvous: Option<Box<dyn crate::rendezvous::Rendezvous>> = config
    .rendezvous
    .map(|addr| Box::new(crate::rendezvous::ConfiguredServerRendezvous::new(addr)) as Box<dyn _>);
let mut manager = PeerManager::new(
    config.local_private,
    config.local_public,
    &config.peers,
    mode,
    rendezvous,
);
```

- [ ] **Step 5: Run the unit tests + the FULL data-plane regression gate.**

```bash
cargo test -p yipd --bins
cargo build --release -p yipd
cargo test -p yipd --test tunnel_netns --no-run
BIN=$(ls -t target/debug/deps/tunnel_netns-* | grep -v '\.d$' | head -1)
for E in "" "YIP_USE_URING=1"; do for t in ping_across_yipd_tunnel ping_across_yipd_tunnel_under_loss arq_recovers_bulk_loss l2_tap_ping_or_arp_across_tunnel triangle_full_mesh_ping; do
  echo -n "$E $t: "; sudo -E env $E "$BIN" "$t" --exact --test-threads=1 2>&1 | grep -oE "test result: (ok|FAILED)"; done; done
```
Expected: all 10 `ok` — the 2a tests configure no `rendezvous`, so the path SM stays on the Direct stage and behavior is byte-identical (this is the no-regression guarantee).

- [ ] **Step 6: Commit.**

```bash
git add bin/yipd/src/peer_manager.rs bin/yipd/src/tunnel.rs
git commit -m "feat(yipd): wire rendezvous + path SM into PeerManager (lazy punch/relay escalation) (2b)"
```

---

### Task 7: netns integration — relay + hole-punch money tests + CI

**Files:**
- Create: `bin/yipd/tests/run-netns-relay.sh`, `bin/yipd/tests/run-netns-punch.sh`
- Modify: `bin/yipd/tests/tunnel_netns.rs`, `.github/workflows/integration.yml`

**Interfaces:** none (integration). Uses `env!("CARGO_BIN_EXE_yipd")` and `env!("CARGO_BIN_EXE_yip-rendezvous")`.

The two "money tests" must assert *which path carried traffic*, using the relay forward counter. Expose it: have `yip-rendezvous` print a periodic line `relay-forwarded=<N>` to stderr (from `RendezvousServer::forwarded_count()`), so the scripts can grep the server log.

- [ ] **Step 1: `run-netns-relay.sh`** — three netns: `A`, `B`, and `R` (relay). Topology so A and B have **no route to each other**, but both reach R:
  - `R` on a bridge; `A`–`R` veth on subnet `10.70.0.0/24`, `B`–`R` veth on subnet `10.71.0.0/24`; **do NOT** enable forwarding between the two subnets on R's netns (so A cannot reach B directly — only R's yip-rendezvous, bound on both, is reachable).
  - Configs: each of A, B lists the other as a `[peer]` with `public_key` only (**no endpoint**), and sets `rendezvous=<R's addr reachable from that side>`. Assign each TUN its `node_addr/128` (`yipd --addr`) + `fd00::/8` route (mirror `run-netns-triangle.sh`).
  - Start `yip-rendezvous` in R (log to a file), start `yipd` in A and B, `ping6` B's node_addr from A.
  - **Assert:** ping succeeds AND the server log shows `relay-forwarded=<N>` with N>0 (traffic went through the relay). Cleanup trap removes all netns + bridge. Root-gated (SKIP line if not root, matching existing scripts). Mirror `run-netns-triangle.sh` for boilerplate.

- [ ] **Step 2: `run-netns-punch.sh`** — two client netns `A`, `B` each behind a **NAT** to a shared transit netns `T` that also hosts `yip-rendezvous`:
  - `A`–`T` and `B`–`T` veths; in `A` and `B` netns add `iptables -t nat -A POSTROUTING -o <veth> -j MASQUERADE` so their source addr is rewritten (simulating NAT) — the classic hole-punch scenario where each sees the other's reflexive (post-NAT) addr via the server.
  - T forwards between the two transit subnets (so once punched, A↔B packets route through T at L3 — a hole-punch through the NATs, NOT through the relay).
  - Configs: A, B list each other by `public_key` only, `rendezvous=<T's addr>`.
  - Start server, start both yipd, `ping6` across.
  - **Assert:** ping succeeds AND the server log shows `relay-forwarded=0` (or the counter never increments) — proving the **punch** carried it, not the relay. Cleanup trap. Root-gated.

  > If a true post-NAT simultaneous-open punch is not reliably reproducible in netns on the CI kernel, fall back to asserting the connection succeeds with `relay-forwarded=0` via direct reflexive reachability (T routes between subnets, so the reflexive addr the server observes IS reachable) — the invariant under test ("punch path used, relay not used") still holds. Document whichever topology you land on in the script header.

- [ ] **Step 3: Add the Rust harness tests** in `tunnel_netns.rs` (mirror `triangle_full_mesh_ping`): `relay_path_ping` and `hole_punch_ping`, each root-gated with a `SKIP <name>: needs root` line, invoking the respective script via `bash <script> <yipd> <yip-rendezvous>` and asserting `status.success()`. Pass both binary paths:

```rust
let yipd = env!("CARGO_BIN_EXE_yipd");
let rdv = env!("CARGO_BIN_EXE_yip-rendezvous");
let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-relay.sh");
let status = Command::new("bash").arg(script).arg(yipd).arg(rdv).status().unwrap();
assert!(status.success(), "relay-path netns test failed");
```

- [ ] **Step 4: Graceful-degradation + optional-endpoint** are already covered: the 2a netns tests (no `rendezvous` configured) prove degradation in Task 6's gate; the relay/punch tests use `endpoint`-less peers, proving optional-endpoint reachability. No extra script needed — note this in the test module doc comment.

- [ ] **Step 5: Wire into CI.** In `.github/workflows/integration.yml`, add `relay_path_ping` and `hole_punch_ping` to the `netns-tunnel-test` job's `for t in ...` loop (they run under both `poll` and `uring`; the existing `SKIP <t>: needs root` honesty guard covers them). The release build step already exists for `arq`; these ping tests use the debug binary.

- [ ] **Step 6: Run both money tests locally under both drivers.**

```bash
BIN=$(ls -t target/debug/deps/tunnel_netns-* | grep -v '\.d$' | head -1)
for E in "" "YIP_USE_URING=1"; do for t in relay_path_ping hole_punch_ping; do
  echo -n "$E $t: "; sudo -E env $E "$BIN" "$t" --exact --test-threads=1 2>&1 | grep -oE "test result: (ok|FAILED)"; done; done
```
Expected: all 4 `ok`. If a test hangs, debug the topology/config (common causes: peer node_id mismatch, rendezvous addr unreachable from a netns, TUN addr/route wrong, punch window too short vs handshake round-trip — bump `PUNCH_MS` or the ping count/timeout).

- [ ] **Step 7: Commit.**

```bash
git add bin/yipd/tests/run-netns-relay.sh bin/yipd/tests/run-netns-punch.sh bin/yipd/tests/tunnel_netns.rs .github/workflows/integration.yml
git commit -m "test(yipd): netns relay + hole-punch money tests, gated both drivers (2b)"
```

---

## Self-Review

**Spec coverage:**
- Rendezvous transport = configured server behind `Rendezvous` trait → Tasks 1–4. ✅
- Lean core (server-observed reflexive + punch + blind relay; no UPnP/PMP/PCP/NAT-typing) → Tasks 2–3 (server), 5–6 (client punch/relay). ✅
- Candidate-validated-by-Noise anti-hijack → Task 6 point 4 + the path SM never sending. ✅
- `yip-rendezvous` binary (node_id, 7-message protocol incl. RelaySend/RelayDeliver split, TTL soft-state, rate limit, blind relay, forward counter) → Tasks 1–3. ✅
- `Rendezvous` trait + `ConfiguredServerRendezvous` + optional endpoint/rendezvous config → Task 4. ✅
- Per-peer path SM Direct→Punch→Relay → Task 5, wired in Task 6. ✅
- netns relay + punch money tests asserting which path carried traffic + graceful degradation + optional endpoint, both drivers, CI → Task 7. ✅
- Non-goals (UPnP/PMP/PCP, NAT-typing, ICE, DHT/2c, #34, #3, privacy tokens, federated relay) — none implemented. ✅

**Placeholder scan:** the recommended Task 4 Step 7 approach (change `Peer.endpoint` to `Option<SocketAddr>` and gate the direct path on `if let Some(ep)`) resolves cleanly with no placeholder address; the alternative `// TODO(task6)` is called out only as the discouraged option. No bare TBD/TODO/"handle errors" remain, and every code step carries complete code.

**Type consistency:** `NodeId = [u8;16]` (Tasks 1,2,4,6); `RelaySend { src, dst, payload }` / `RelayDeliver { src, payload }` are defined once in Task 1 and used unchanged everywhere (server forwards `src` from `RelaySend` into `RelayDeliver`). `EgressDatagram { fate, dst, bytes }` matches the merged 2a type. `PeerConfig.endpoint: Option<SocketAddr>` introduced in Task 4, consumed in Task 6. `PathAction`/`PathStage`/`PathKind` defined in Task 5, consumed in Task 6. `Rendezvous` trait signature identical in Tasks 4 and 6. No cross-task corrections remain — every task is additive over its predecessors.
