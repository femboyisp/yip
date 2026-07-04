# Multi-peer data plane + self-certifying addresses (sub-project #2, milestone 2a)

**Status:** approved (design) — pending spec review, then writing-plans
**Scope:** the first milestone of sub-project #2 (control plane). Turns yipd from a
hand-configured single point-to-point tunnel into a static **multi-peer** mesh with
key-derived addresses. It is the foundation the later control-plane milestones
populate, and it unblocks multi-core throughput (#10).
**Predecessors:** sub-project #1 (data plane + FEC transport, complete). Research:
`docs/research/00-overview.md` §2 (control/data split, self-certifying key-derived
addresses).

## Goal

Run N peers over one yipd instance: each peer has its own Noise session and FEC
transport; inner packets route to the right peer by a **key-derived inner address**;
sessions are established **lazily** (WireGuard-style) over an **unconnected** UDP
socket. No discovery, NAT traversal, or relay yet — peers and their endpoints come
from static config, exactly the seam those later milestones replace.

## Non-goals (explicitly deferred)

- **Discovery / DHT / gossip** (milestone 2c) — the peer set is static config here.
- **NAT traversal / hole-punching / relay** (milestone 2b) — peers are assumed to
  have a reachable configured endpoint.
- **Per-peer subnets / AllowedIPs** — each peer is exactly one key-derived host
  address (a `/128`). Site-to-site subnets are a later feature.
- **Dynamic admission hooks** (fastd `on-verify`) — admission in 2a = "the peer's
  public key is in the configured list."
- **Multi-core sharding** (#10) — 2a stays single-threaded; #10 later shards the
  peer set across engines.
- **Anti-DPI hardening** (sub-project #3) — the data-vs-handshake demux here uses
  the simplest correct scheme; removing its distinguishable features is #3's job.

## Success criteria

- A **3-peer netns triangle** (static config, no network services): each pair
  handshakes lazily on first traffic and pings across their **derived** addresses;
  a full-mesh ping (each node pings the other two) succeeds.
- A **1-peer** config is byte-identical on the wire to today's single-peer tunnel
  (no regression; the existing `tunnel_netns` suite passes unchanged).
- Address derivation, routing longest-prefix match, and the conn_tag/handshake
  demux are unit-tested (pure functions, no sockets).
- yipd stays `#![forbid(unsafe_code)]`; no `as` numeric casts.

## Background (verified in code)

- `bin/yipd/src/tunnel.rs::run()` binds one `UdpSocket`, **`sock.connect(peer_addr)`**
  (single connected peer), runs the Noise handshake **synchronously before the data
  loop** (`run_initiator`/`run_responder`), derives `conn_tag`, creates the TUN, and
  runs the driver with one `DataPlane`.
- `bin/yipd/src/config.rs` parses exactly one peer (`peer_public`, `peer_endpoint`)
  plus `local_private/public`, `listen`, `device`, `device_kind`, `initiate`.
- `crates/yip-io/src/poll.rs`: the `Dispatch` trait is **address-free** —
  `on_udp(&[u8], now)`, `on_tun(&[u8], now) -> &[EgressDatagram]`, `tick`,
  `flush_egress`. `DispatchOut` = `None | Tun(&[u8]) | Udp(&[Vec<u8>]) | Both`. The
  drivers use **connected** `recv`/`send` (`send_to_udp`, `drain_udp`).
- `bin/yipd/src/dataplane.rs`: `DataPlane` is already **fully self-contained per
  peer** — its own `session`, `transport`, `codec`, `conn_tag`, `retx`, `detector`,
  `mac_table`, scratch. This is the enabling property: one `DataPlane` == one peer.
- `conn_tag` (8 bytes) is derived from the Noise **channel binding** (`auth_key`,
  `hp_key`) — a per-session value both peers compute identically, and every **data**
  frame carries it as its first 8 bytes (`yip-wire`). Handshake messages do **not**
  carry it (it does not exist until the handshake completes).

## Architecture

### 1. Self-certifying key-derived addresses

A node's inner address is derived from its X25519 **public key**:

```
addr(pubkey) := 0xfd ‖ BLAKE2s-256(DOMAIN ‖ pubkey)[0..15]      // 128-bit IPv6
```

- A `/128` in the IPv6 ULA space `fd00::/8`. `DOMAIN` is a fixed context string
  (e.g. `b"yip-addr-v1"`) so the derivation can't collide with other uses of the key.
- **Self-certifying:** given a claimed address and a public key, any node recomputes
  and compares — the address *is* the identity, no authority, no assignment. A peer
  that can't produce a key hashing to its claimed address is rejected.
- 120 bits of hash → collision-resistant for any realistic mesh; a future
  subnets-behind-a-node feature can widen to a derived `/64` per node.
- New crate function (pure, unit-tested), likely `yip-crypto` or a small
  `yip-addr`: `fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr` and
  `fn verify_addr(addr: Ipv6Addr, pubkey: &[u8; 32]) -> bool`.

The local TUN device is assigned the node's own derived `/128`, plus a route for the
mesh prefix (`fd00::/8`, or a narrower project prefix) pointing at the TUN, so all
mesh traffic enters yipd and is routed per-peer.

### 2. Config: a peer list

`config.rs` grows from one peer to a **list**. Each entry:

```
[peer]
public_key = <64 hex>
endpoint   = <IP:port>        # where to reach it (static now; discovery fills later)
```

`local_private/public`, `listen`, `device`, `device_kind` stay. `peer_endpoint`/
`peer_public`/`initiate` (single-peer keys) become the degenerate 1-entry list;
`initiate` is dropped (lazy handshake makes it unnecessary — see §5). The node's own
inner address is *derived* from `local_public`, never configured.

### 3. The `Dispatch` / driver seam: unconnected sockets

The single real refactor. Multi-peer needs `recvfrom`/`sendto`, so the seam gains
addressing:

- `Dispatch::on_udp(src: SocketAddr, dg: &[u8], now)` — the receiver learns the
  source (also the hook NAT-roaming endpoint updates use later).
- Egress datagrams carry a **destination** `SocketAddr`. `EgressDatagram` gains a
  `dst: SocketAddr`; `DispatchOut::Udp`/`Both` likewise carry per-datagram dests.
- `poll.rs` / `uring.rs` switch connected `recv`/`send` to `recvfrom`/`sendto`
  (`recvmmsg`/`sendmmsg` with addresses). The GSO fate-tag path and the busy-poll
  loop are unchanged except that a send now targets a datagram's `dst`.

This addressed seam is exactly what multi-core (#10) needs, so 2a delivers it.

### 4. `PeerManager` — thin routing/demux over per-peer `DataPlane`s

Rather than rewrite `DataPlane` into a multi-peer monster, add a thin owner:

```rust
struct PeerManager {
    local_priv: StaticSecret,
    local_pub:  [u8; 32],
    peers:    HashMap<PeerId, PeerEntry>,   // PeerId = derived addr (or pubkey)
    by_tag:   HashMap<u64, PeerId>,         // conn_tag -> peer (UDP ingress demux)
    route:    /* longest-prefix trie */,    // inner dst addr -> PeerId (TUN egress)
    tun_scratch, udp_scratch, ...           // reused egress buffers
}

struct PeerEntry {
    pubkey:   [u8; 32],
    endpoint: SocketAddr,                    // static now; updatable later
    state:    PeerState,                     // Handshaking(..) | Established(DataPlane)
    pending_tun: Vec<Vec<u8>>,               // inner packets buffered during handshake
}
```

`PeerManager` implements `Dispatch`:

- **`on_udp(src, dg)`:** if `dg[0..8]` matches a known `by_tag` entry → a data frame
  → delegate to that peer's `DataPlane::on_udp` (its existing decode/deliver path).
  Otherwise treat `dg` as a **handshake message** (§5).
- **`on_tun(pkt)`:** longest-prefix-match the inner destination → `PeerId`. If that
  peer is `Established`, delegate to its `DataPlane::on_tun` (seal+FEC+frame),
  stamping each egress datagram's `dst = peer.endpoint`. If it is `Handshaking`,
  buffer the packet in `pending_tun` and (if not already) start a handshake.
- **`tick(now)`:** fan out to every `Established` peer's `tick`; drive handshake
  retries/timeouts; return control datagrams stamped with their peer's endpoint.
- **`flush_egress(now)`:** fan out (Bulk-batch flushes etc., once #FEC-batching lands).

`DataPlane` needs a small change: its egress currently produces `EgressDatagram`
without a `dst` — it now takes/receives the peer endpoint so egress datagrams are
addressed. Cleanest: `PeerManager` stamps `dst` on the datagrams returned by the
per-peer `DataPlane` (keeps `DataPlane` endpoint-agnostic).

### 5. In-loop lazy handshake (the crux)

Today the handshake is a blocking pre-loop step. Multi-peer needs it **in-band**, per
peer, driven by the event loop — because there are N peers and sessions come and go.

- **Packet discrimination.** An inbound datagram is a **data frame** iff its first 8
  bytes match a live `conn_tag` (`by_tag`); otherwise it is a **handshake message**.
  (conn_tag is a 64-bit per-session value; a stray handshake colliding with a live
  tag is ~2⁻⁶⁴.) This is the simplest correct demux; sub-project #3 replaces its
  distinguishable shape.
- **Initiator flow.** First `on_tun` packet routed to a peer with no session →
  create a `snow` initiator, send Noise **msg 1** to `peer.endpoint`, buffer the
  inner packet in `pending_tun`, mark `Handshaking`. When Noise **msg 2** arrives
  from that peer's endpoint (matched by `src`), complete the handshake → derive
  `conn_tag`, build the `DataPlane`, register `by_tag`, transition `Established`, and
  drain `pending_tun` through the new `DataPlane`.
- **Responder flow.** An unmatched datagram parses as a Noise **msg 1**: run a
  `snow` responder, recovering the initiator's static public key (Noise IK). Admit
  iff that key is in the configured peer list (2a admission); on admit, send msg 2,
  complete → `Established`. The peer's endpoint is learned from `src` (so a peer
  whose configured endpoint is stale/absent can still be reached once it initiates).
- **State/retries.** `Handshaking` carries the `snow` state + a start time; retry
  msg 1 on a bounded schedule; give up after a deadline (drop buffered packets).
  `initiate` config flag is gone — either side initiates on first need; simultaneous
  initiation resolves to one session by a deterministic tie-break (lower pubkey
  initiates, or accept the first completed).

DoS note: responder handshake processing on every unmatched packet is a small
compute cost; the stateless-"biscuit" responder (Rosenpass) is a sub-project #3/PQ
hardening follow-up, out of scope here. Cap concurrent half-open handshakes.

## Component / file changes

- **new `yip-addr` (or `yip-crypto` addition):** `node_addr`, `verify_addr`,
  `MESH_PREFIX`; pure + unit-tested.
- **`crates/yip-io/src/poll.rs`:** `Dispatch::on_udp` gains `src: SocketAddr`;
  `EgressDatagram` gains `dst`; `DispatchOut::Udp/Both` carry dests; `drain_udp`/
  `send_to_udp` → `recvfrom`/`sendto`.
- **`crates/yip-io/src/uring.rs`:** `recvfrom`/`sendto` (or `RecvMsg`/`SendMsg` with
  names); the send SQE targets each datagram's `dst`. GSO/busy-poll otherwise intact.
- **`bin/yipd/src/config.rs`:** peer-list parsing; drop `initiate`; keep back-compat
  single-peer shape as a 1-entry list.
- **`bin/yipd/src/tunnel.rs`:** drop the pre-loop blocking handshake and
  `sock.connect`; build a `PeerManager` from the peer list and run the driver on it.
- **`bin/yipd/src/peer_manager.rs` (new):** the `PeerManager` above + the in-loop
  handshake state machine + routing/demux.
- **`bin/yipd/src/dataplane.rs`:** minor — endpoint-agnostic egress (dst stamped by
  the manager); expose what the manager needs (conn_tag, an `on_udp`/`on_tun` that
  the manager delegates to).
- **`bin/yipd/src/handshake.rs`:** refactor `run_initiator`/`run_responder` from
  blocking socket loops into **step functions** (`start_initiator() -> msg1`,
  `read_message(msg) -> Option<reply|Established>`) the manager drives in-band.

## Data flow (peer P → peer Q, both configured, no session yet)

1. TUN read at P → `PeerManager::on_tun` → route inner dst (Q's derived addr) → Q
   entry, no session → `snow` initiator, `sendto(Q.endpoint, msg1)`, buffer the inner
   packet, mark Handshaking.
2. At Q: `recvfrom` → `on_udp(P_src, msg1)` → not a known conn_tag → Noise responder
   reads msg1, recovers P's static key, admits (in config), `sendto(P_src, msg2)`,
   derives conn_tag, builds P's `DataPlane`, Established.
3. At P: `recvfrom` → `on_udp(Q_src, msg2)` → matches P's pending handshake by src →
   completes, derives conn_tag (== Q's), builds Q's `DataPlane`, Established, drains
   buffered inner packet through it → seal+FEC+frame → `sendto(Q.endpoint, data)`.
4. Steady state: data frames demux by conn_tag → the peer's `DataPlane`, exactly the
   sub-project #1 path, one per peer.

## Testing / validation plan

- **Unit:** `node_addr`/`verify_addr` (known-answer + round-trip + reject-wrong-key);
  routing longest-prefix match; conn_tag-vs-handshake discrimination; peer-list config
  parsing (incl. the 1-entry back-compat shape).
- **netns triangle:** three namespaces, three yipd, static 3-peer configs; assert
  lazy handshake (no traffic until first ping) then full-mesh ping across derived
  addresses. New `bin/yipd/tests/` script + a `tunnel_netns`-style test, gated in
  `integration.yml` under both drivers.
- **Regression:** the existing single-peer `tunnel_netns` tests pass unchanged with a
  1-entry peer list (byte-identical wire).
- **Both drivers:** poll + uring (the addressed-socket seam must work on both).

## Risks / open questions

| Risk / question | Notes |
|---|---|
| The `Dispatch::on_udp(src)` + `EgressDatagram.dst` change ripples through both drivers, the GSO path, and every test dispatch. | Mechanical but broad; the biggest single diff. Land the seam first (no behavior change for 1 peer), then the manager. |
| In-loop handshake replaces the blocking pre-loop handshake — a real control-flow change. | Refactor `handshake.rs` into step functions; the manager owns the state machine. Simultaneous-initiation tie-break needs care. |
| Data-vs-handshake demux by "matches a live conn_tag" is a distinguishable feature (anti-DPI). | Acceptable for 2a (functional); sub-project #3 removes it. Flagged so it isn't baked in as permanent. |
| Responder does Noise work on every unmatched packet → cheap DoS surface. | Cap half-open handshakes; stateless-biscuit responder deferred to #3/PQ. |
| Address space / prefix choice (`fd00::/8` vs a narrower project prefix) and `/128`-per-node vs `/64`-per-node. | Recommend `/128` per node now, `/64` reserved for future subnets. Confirm on review. |
| Sign-off requested on: the address derivation (`DOMAIN`, prefix, 120-bit truncation), dropping `initiate`, and the `PeerManager`-stamps-`dst` split vs `DataPlane` owning endpoints. | — |
