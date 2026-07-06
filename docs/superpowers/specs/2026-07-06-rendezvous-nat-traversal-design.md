# Milestone 2b: Rendezvous + NAT Traversal + Relay — Design

**Status:** approved (brainstorming complete), ready for implementation planning.
**Sub-project:** #2 (control plane), milestone 2b. Follows 2a (multi-peer data plane,
merged PR #35). Precedes 2c (decentralized discovery/DHT).

## Goal

Let two yip peers that both sit behind NAT reach each other without a manually
pre-arranged reachable endpoint: discover each peer's public (reflexive) address via a
configured rendezvous server, perform a UDP hole-punch for a direct path, and fall back
to a ciphertext-blind relay when the punch fails. 2b operates on the **static configured
peer list** — it only changes *how a reachable endpoint for an already-known peer is
found*, never *who* the peers are (dynamic membership/discovery is 2c).

## Scope decisions (locked during brainstorming)

1. **Rendezvous transport:** a configured rendezvous server for 2b, behind a `Rendezvous`
   trait so a 2c DHT backend drops in without touching `PeerManager`.
2. **NAT scope — lean core:** server-observed reflexive address (STUN-like, no RFC 5389)
   + simultaneous-open UDP hole-punch + ciphertext-blind relay fallback. **No** UPnP /
   NAT-PMP / PCP port mapping and **no** STUN NAT-type classification — deferred to a 2b.1
   follow-up.
3. **Endpoint trust — candidates validated by Noise:** a rendezvous/punch-learned address
   is only a *candidate*, a target for handshake probes; an established session's egress
   commits to a path only once a Noise-IK handshake completes over it, and is never
   redirected without a fresh completed handshake. The rendezvous/relay server is
   untrusted for address integrity (only for pairing/availability).
4. **Server packaging:** a new standalone binary `bin/yip-rendezvous`, sharing
   `yip-wire`/`yip-crypto`/`yip-io`; no TUN, no tunnel sessions, no mesh membership.

## Non-goals (explicitly out of scope for 2b)

- Decentralized discovery / DHT / gossip / dynamic peer-set membership → **2c**.
- UPnP-IGD / NAT-PMP / PCP port mapping; STUN NAT-type classification → **2b.1**.
- ICE-style parallel candidate racing (2b escalates sequentially) → future optimization.
- Handshake anti-replay / authenticated `endpoint = src` on the *responder* → tracked in
  **#34** (rides with session-rekey #9). 2b does not depend on #34 and does not fix it.
- Anti-DPI / obfuscation of the new rendezvous/relay wire formats → **#3**. Plain framing
  is acceptable in 2b.
- Metadata privacy of the rendezvous graph (rotating/pairwise tokens, onion rendezvous) →
  later anonymity dial. 2b's server sees stable node ids + reflexive addrs + who-talks-to-whom.
- Federated/discoverable relay *network* (multiple operators, relay selection) — 2b scopes
  to "relay through a configured/known relay works."
- Multi-core sharding (#10), per-peer subnets/AllowedIPs — unchanged, out of scope.
- PQ-hybrid handshake (#9) — 2b changes only how peers learn a `SocketAddr`, not the
  Noise-IK handshake body.

## Architecture: candidate paths resolved by the handshake

Today a `Peer` has one `endpoint`. 2b generalizes to a per-peer **path state machine**
that escalates through candidate paths; the *first path over which a Noise-IK handshake
completes* becomes the committed path:

```
Direct (configured endpoint)  →  Punched (rendezvous + hole-punch)  →  Relayed (blind relay)
      2a behavior                        new                                  new
```

- **Direct** — try the configured endpoint (exactly 2a), but with a *short* window
  (a few seconds) before escalating, not the full 90s `HANDSHAKE_TOTAL_MS`.
- **Punched** — register self with the rendezvous server (announce `node_id → reflexive
  addr`); look up peer B's reflexive addr; both sides fire Noise Init probes at each
  other's reflexive addrs simultaneously (opens the NAT bindings — Bryan Ford
  simultaneous-open); attempt the handshake over the punched candidate.
- **Relayed** — wrap Noise datagrams in a thin relay envelope to the (blind) relay server
  addressed to `node_id(B)`; the handshake completes over the relay path.

Escalation is **sequential** with bounded per-stage timeouts (not ICE parallel racing),
matching the lean-core scope. The per-peer state machine lives in `PeerManager.tick`,
mirroring 2a's `HandshakingState` retry/timeout patterns.

### The anti-hijack invariant

A candidate address is *only ever a target for handshake probes*. An `Established`
session's egress is bound to the path its handshake authenticated over and is **never
redirected to a new address without a fresh completed handshake** over that address. So a
lying/malicious rendezvous or relay server, or an on-path attacker, can waste probes or
drop packets, but can never hijack or read a session. This reuses 2a's existing
"handshake authoritative, endpoint is a hint" model rather than adding a trust dependency.

## Component: `bin/yip-rendezvous` (new binary)

A single-threaded `yip-io` UDP loop. No TUN, no tunnel keys. Keyed on a **node id**:

```
node_id = BLAKE2s("yip-rdv-v1" || pubkey)[..16]   // 16 bytes; parallels addr.rs node_addr
```

so a node's rendezvous identity falls out of its public key (no new identity system). Both
peers know each other's pubkey from config, so both derive the same peer `node_id`.

### Wire protocol (client ⇄ server)

New outer framing with its own discriminant byte (distinct from the tunnel `PacketType`
space; plain framing — obfuscation is #3):

| Message | Direction | Server action |
|---|---|---|
| `Register { node_id }` | client → server | Record `node_id → observed reflexive SocketAddr` (the src the server saw). Rate-limited, auto-expiring (60s TTL); client refreshes periodically to keep the entry and the NAT binding alive. |
| `Lookup { node_id }` | client → server | Reply `PeerInfo { node_id, reflexive_addr }` if registered, else `NotFound`. Also send a `PunchHint { requester_node_id, requester_reflexive_addr }` to the looked-up peer so it starts punching back (simultaneous open). |
| `PeerInfo { node_id, reflexive_addr }` | server → client | Answer to `Lookup`. |
| `PunchHint { peer_node_id, peer_reflexive_addr }` | server → client | Tells a peer to start a punch toward the requester. |
| `NotFound { node_id }` | server → client | Looked-up peer not registered. |
| `RelayEnvelope { dst_node_id, payload }` | client → server → peer | Server looks up `dst_node_id`'s registered addr and forwards `payload` verbatim, re-wrapped as `RelayEnvelope { src_node_id, payload }` so the receiver knows it arrived relayed **and from which origin node** — the receiver needs `src_node_id` to address its reply back through the relay. **Blind** — `payload` is an opaque Noise datagram the server never parses/decrypts. Rate-limited. |

### Server state & bounds

- Bounded `HashMap<node_id, (SocketAddr, expiry)>` with TTL eviction; a max registration
  count (reject/evict beyond it).
- Per-source rate limiting on all message types.
- Soft state only — no persistence; registrations are rebuilt by client refresh.
- Config: a single `listen` address.

### Trust boundary

The server sees stable per-node ids (= the public mesh identity, not secret), reflexive
addresses, and the who-talks-to-whom graph. It cannot read tunnel traffic (Noise) and
cannot hijack sessions (anti-hijack invariant). Metadata-privacy hardening is out of scope.

## Component: client integration in `yipd`

### `Rendezvous` trait (the 2c-ready seam)

```rust
trait Rendezvous {
    fn register(&mut self, node_id: NodeId);                       // announce self; refreshed on tick
    fn lookup(&mut self, peer_node_id: NodeId);                    // fire request; answer arrives via on_rdv_message
    fn relay_send(&mut self, dst_node_id: NodeId, payload: &[u8]) -> EgressDatagram;
    fn on_rdv_message(&mut self, dg: &[u8]) -> RdvEvent;           // parse a server datagram
}
```

2b ships `ConfiguredServerRendezvous` (talks to the configured server addr). 2c adds
`DhtRendezvous` without touching `PeerManager`. `RdvEvent` enumerates the outcomes the
path SM reacts to: `PeerInfo`, `PunchHint`, `Relayed(peer_datagram)`, `NotFound`, `None`.

### Per-peer path state machine

Extends 2a's `PeerState` (`Idle → Handshaking → Established`) with a **path attempt**
threaded alongside the handshake. Each `Peer` gains:

```rust
struct PathState { stage: PathStage, candidate: Option<SocketAddr>, deadline_ms: u64 }
enum PathStage { Direct, Punching, Relaying, Failed }
enum PathKind  { Direct, Punched, Relayed }   // recorded on the committed Peer
```

When the lazy handshake fires, the SM walks the stages; each stage supplies a candidate
address (or a relay-wrapped send) that feeds the *existing* `start_initiator`/retransmit
machinery. On handshake completion, the committed `PathKind` + address is recorded and
`Established` egress uses it. This layers on top of 2a's handshake code rather than
replacing it. NAT-binding keepalives (punch) and relay-session keepalives are driven from
`tick`.

### Demux in `on_udp`

One new discriminator: **is the datagram's source the configured rendezvous/relay server?**
- From the server → `on_rdv_message`: `PeerInfo`/`PunchHint`/`NotFound` drive the path SM;
  a `RelayEnvelope`'s inner payload is unwrapped and fed into the *normal* peer-datagram
  path — a relayed Init/Resp/Data is processed exactly as a direct one (the data plane is
  identical whether direct or relayed).
- From anyone else → the 2a peer path, unchanged.

### Config changes (`config.rs`)

- `rendezvous = IP:port` (optional) — the coordinator/relay server. Absent ⇒ 2b features
  off, pure 2a direct-only behavior (graceful, non-breaking).
- Per-peer `endpoint` becomes **optional** — a peer with only `public_key` and no
  `endpoint` is reachable purely via rendezvous/punch/relay. (The real payoff: peer with a
  node whose address you don't know in advance.)

### New files

- `bin/yipd/src/rendezvous.rs` — `Rendezvous` trait, `ConfiguredServerRendezvous`, wire
  messages, `node_id` derivation.
- `bin/yipd/src/path.rs` — the per-peer path state machine.
- `peer_manager.rs` wires the SM into `tick`/`on_udp`/`on_tun` (kept from ballooning by
  the split).
- `bin/yip-rendezvous/` — the server crate.

## Security invariants (enforced by mechanism)

1. **No egress redirect without a completed handshake** (anti-hijack; see Architecture).
2. **Relay is blind** — forwards opaque Noise datagrams; holds no tunnel keys.
   Confidentiality/integrity come entirely from the unchanged data-plane crypto.
3. **Punch probes are just handshakes** — a punch probe *is* a Noise Init to a candidate;
   no separate unauthenticated punch packet exists to abuse. A probe to a wrong/spoofed
   address simply never completes.
4. **Rendezvous doesn't weaken admission** — admission still requires a configured peer's
   static key (2a). Rendezvous supplies only *where* to reach a known peer, never *who* is
   admitted.
5. **Bounded server-driven work** — a `Lookup`/`PunchHint` triggers at most one bounded
   punch attempt per peer per window; a flood of hints cannot amplify into unbounded probing.

**Relationship to #34:** the candidate model sidesteps #34 for the 2b path. #34's residual
(a responder trusting `endpoint = src` on a replayed Init) is unchanged and stays tracked
there; 2b does not depend on it.

## Error handling (all non-fatal, bounded — mirrors 2a's give-up semantics)

- Rendezvous server unreachable → skip Punch/Relay, fall back to Direct-only; log; retry
  registration with backoff.
- `Lookup → NotFound` → escalate to Relay if the peer has no direct endpoint, else keep
  retrying Direct within the window.
- Punch fails (symmetric NAT, timing) → escalate to Relay.
- Relay unavailable/rate-limited → connection fails after the total window (peer
  unreachable) — identical outcome to 2a's 90s give-up.
- Committed path goes stale (handshake needed again) → re-enter the SM from Direct.

## Testing

### Unit
- `node_id` derivation; rendezvous wire-message round-trip (all message types).
- Path SM transitions against a **mock `Rendezvous`** (no sockets): Direct→Punch→Relay
  escalation, deadlines, commit-on-completion, re-enter on stale.
- `yip-rendezvous` server logic: registration + TTL eviction, lookup hit/miss, blind
  forward addressing, rate-limit / max-registration enforcement.

### netns integration (NAT simulated with netns + MASQUERADE)
1. **Relay path (money test):** two `yipd` in separate netns whose underlay subnets have
   **no route between them** except through a `yip-rendezvous` netns both can reach
   (un-punchable double-NAT). Assert: ping succeeds AND it flows through the relay
   (relay forward-counter > 0).
2. **Hole-punch path (money test):** two `yipd` behind simulated NATs (netns +
   `MASQUERADE`) + reachable `yip-rendezvous`. Assert: connection succeeds directly after
   punch AND the relay is **not** used (relay counter ≈ 0) — proving punch carried it.
3. **Graceful degradation:** no `rendezvous` configured → the 2a direct path stays green
   (no regression).
4. **Optional-endpoint:** a peer configured with only `public_key` (no `endpoint`) becomes
   reachable via rendezvous.

Tests 1–2 run under **both** poll and io_uring (matching 2a's bar) and are gated in CI.
`yip-rendezvous` gets its own netns smoke.

**Observability for tests:** the relay server exposes a forwarded-datagram counter
(log line or test accessor) so tests can *assert which path carried traffic* — otherwise
"it worked" can't distinguish punch from relay.

## Integration surface reused from 2a

- `Dispatch::on_udp(src, …)` — the addressed seam; `src` distinguishes server vs peer.
- `EgressDatagram.dst` — a relay/punched endpoint is just a different `dst`.
- `Peer.endpoint` mutation point (`handle_handshake_init`) — the path SM records the
  committed address here on completion.
- `tick` — home for registration refresh, punch retries, relay keepalives (mirrors
  `HANDSHAKE_RETRY_MS`/`HANDSHAKE_TOTAL_MS`).
- `addr.rs` BLAKE2s derivation — parallel `node_id`.
