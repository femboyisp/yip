# Milestone 2c: Decentralized Peer Discovery — Design

**Status:** approved (brainstorming complete), ready for implementation planning.
**Sub-project:** #2 (control plane), milestone 2c. Follows 2a (multi-peer data plane +
self-certifying addresses) and 2b (rendezvous + NAT traversal + relay). Completes
sub-project #2.

## Goal

Make the peer set **dynamic**: a node learns which other members exist and how to reach
them without static per-peer configuration. yip becomes a **private membership mesh** — a
node is a valid peer iff it holds a valid, unexpired membership certificate signed by the
network's certificate authority (CA). Discovery of *where* a member is uses a
gossip-replicated signed directory; reaching them reuses 2b's already-merged NAT-traversal
path machinery.

## Scope decisions (locked during brainstorming)

1. **Membership model — private mesh anchored by a signed root set** (not an open
   permissionless DHT, not reachability-only). "Who is a valid peer" is defined by CA-signed
   membership, not the local static config.
2. **Membership proof — per-member signed certificate** (ZeroTier-CoM style). Peers verify
   each other's cert against the configured CA public key during admission; roots/CA are
   needed only at join/renewal, not per connection.
3. **Directory — gossip-replicated full directory** (anti-entropy), not a Kademlia DHT and
   not a roots-as-directory model. Every node converges on the full member map (which a
   routing VPN wants); simplest for a closed, bounded mesh.
4. **CA — offline CA + gossip-seed roots.** The membership-signing key is an offline tool
   (`yip-ca`); it never sits on an internet-exposed node. The "signed root set" is a
   CA-signed list of always-up member nodes that act only as gossip seeds / bootstrap (and
   may co-run the 2b rendezvous/relay). Compromising an online node cannot forge membership.

## Non-goals (explicitly out of scope for 2c)

- **Threshold/decentralized CA** (t-of-n roots co-sign membership) → **research backlog**,
  no priority, revisit after the rest of the roadmap. Filed as a tracking issue.
- Signed revocation records (fast revocation) → enhancement; v1 revocation = cert expiry.
- LAN-multicast zero-config discovery (Yggdrasil `src/multicast` style) → deferred.
- Kademlia/structured DHT → not needed for a bounded closed mesh (gossip chosen); the
  open self-certifying DHT membership model was explicitly rejected in favor of the signed
  root set.
- Anti-DPI / obfuscation of the new gossip + cert wire formats → **#3** (plain framing OK).
- Metadata privacy of the gossip graph (who's a member / who gossips with whom) → later
  anonymity milestone / PSI private discovery (research). Same posture as 2b's rendezvous graph.
- PoW sybil-hardening of `node_addr` → unnecessary; the CA cert gates sybil.
- Yggdrasil-style spanning-tree routing → **rejected**: it would require changing 2a's
  already-merged `node_addr` derivation (a BLAKE2s hash, no prefix locality). Kept as-is.
- Everything already done/owned elsewhere: the data plane + FEC (sub-project #1), NAT
  traversal/relay (2b), rekey #9, handshake anti-replay #34, multi-core #10, per-peer
  subnets, PQ handshake.

## Trust model

Three CA-anchored artifacts:

- **CA keypair (Ed25519, offline).** Signs member certs and the root list. Its *public*
  key(s) ship in every node's config as the trust anchor (multiple allowed for rotation).
  The signing key is only ever used by the offline `yip-ca` tool.
- **Member certificate.** Binds a member's keys to CA-attested membership:
  ```
  Cert { version:u8, member_pubkey:[u8;32], member_sign_pubkey:[u8;32],
         network_id:[u8;16], not_before:u64, not_after:u64,
         tags:Vec<(u8,Vec<u8>)>, ca_sig:[u8;64] }
  ```
  `member_pubkey` is the node's X25519 static key (Noise identity; `node_addr`/`node_id`
  derive from it). `member_sign_pubkey` is an Ed25519 key the member uses to sign its
  gossip records. `ca_sig` is the CA's Ed25519 signature over the canonical body. Short-ish
  lifetime → **revocation = non-renewal** (bounded lag).
- **Signed root set.** `{ [{root_pubkey:[u8;32], endpoint:SocketAddr}], version:u64,
  ca_sig:[u8;64] }` — a handful of always-up member nodes acting as gossip seeds / bootstrap
  anchors, CA-signed so the bootstrap list itself is authenticated.

**Signature-chain:** CA (Ed25519) → cert (binds the member's X25519 identity + Ed25519
record key) → gossip record (signed by the cert's Ed25519 key). Every link independently
verifiable offline.

**Sybil resistance** is a free consequence: no CA-signed cert → no admission and no accepted
directory entry.

## Components

### `crates/yip-membership` (new shared lib)

The cert + record format and verification, used by `yipd`, the membership/gossip module,
and `yip-ca`. Reuses `blake2` (node_id); adds `ed25519-dalek`.

- `Cert` (above) with `encode`/`decode` and
  `verify(cert, ca_pubkey, now: u64) -> Result<(), CertError>` (Ed25519 sig over the
  canonical body + `not_before ≤ now < not_after` + `network_id` match).
- `Record { node_id, cert, endpoints:Vec<SocketAddr>, seq:u64, sig:[u8;64] }` with
  `encode`/`decode`, `sign(record_body, member_sign_priv)`, and
  `verify(record, ca_pubkey, now) -> Result` (verifies the embedded cert **and** the
  record `sig` against the cert's `member_sign_pubkey`).
- `RootSet { roots:Vec<(pubkey, SocketAddr)>, version, ca_sig }` with verify.
- Gossip wire messages (`Digest`, `PullRequest`, `Records`) — plain framing (obfuscation
  is #3).

### `bin/yip-ca` (new offline CA binary)

Never runs as a service; distinct from the daemon.
- `yip-ca genkey` → prints the CA Ed25519 private/public keypair.
- `yip-ca sign-cert --member <x25519-hex> --member-sign <ed25519-hex> --network <id>
  --days N` → emits a member cert (binary).
- `yip-ca sign-roots --roots roots.toml` → emits the CA-signed `RootSet`.

### `bin/yipd/src/membership.rs` (new)

Owns the **directory** (knowledge of all members) and cert verification; separate from
`PeerManager`'s peer table (active sessions). Runs the gossip protocol.
- Directory: bounded `HashMap<NodeId, Record>`. Higher `seq` supersedes; an expired-cert
  record is evicted.
- `resolve(node_addr) -> Option<MemberInfo{pubkey, cert, endpoints}>`.
- `verify_cert(cert, now) -> bool` — is this a valid, unexpired cert signed by a configured
  CA key, covering the presented static key? (Used to admit a peer that presents its cert in
  the handshake — see admission below. Self-contained; does **not** depend on the directory.)
- Gossip driving: an in-session `Gossip` message type handled via `on_udp`, digest exchange
  from `tick`, bootstrap from the roots.

### `bin/yipd` integration (config + `PeerManager` + `tunnel.rs`)

- `config.rs`: `ca_public = <ed25519-hex>` (≥1), `cert = <path>`, `roots = <path>`. The
  node's X25519 keypair config is unchanged. Mesh mode = all three present; absent → pure
  2a/2b static config (non-breaking).
- `PeerManager`: gains `admit_member(pubkey, endpoints)` — the **runtime peer-table
  mutation it lacks today** (insert a `Peer` in `Idle`, register `by_addr`/`by_node`, seed
  `PathState` from the endpoints). Consults `Membership` at two points (below).
- `tunnel.rs`: builds `Membership` from config and passes it into `PeerManager` (as it does
  `rendezvous`).

## Data flow

**Gossip / directory maintenance.** Each node holds a member-signed self-`Record`
(`{node_id, cert, endpoints, seq, sig}`). Gossip rides *inside* established Noise sessions
(authenticated + encrypted, no separate unauthenticated channel): periodically a node
exchanges a compact digest (`{node_id: seq}`) with the roots (liveness) + a random sample
of connected members, then pulls newer/missing records and pushes ones the partner lacks.
The set converges epidemically. As 2b learns a node's reflexive address, the node bumps
`seq` and re-gossips updated `endpoints`.

**Bootstrap.** On join, a node handshakes with a signed **root** (always-admit, pre-vetted),
announces its own record, and pulls the root's directory digest → within a round or two it
holds the whole member map. Records are independently verifiable, so learning about a member
you've never talked to is safe.

**Connecting to a discovered peer (the two PeerManager integration points):**

1. **On-demand resolution (`on_tun`).** A TUN packet whose inner dst `node_addr` matches no
   current peer → `membership.resolve(node_addr)`. If a valid member record exists →
   `admit_member(pubkey, record.endpoints)` → the existing **2b lazy handshake fires**
   (Direct to the record endpoint; escalate to Punch/Relay via the 2b rendezvous if it's
   stale/NATed). No record → buffer/drop (as the current unknown-peer path does).
2. **Cert-based admission (`handle_handshake_init`).** The initiator **presents its cert in
   the handshake** (carried as a Noise-IK handshake payload — see the handshake note below);
   the responder likewise presents its cert (mutual membership proof). The closed-allowlist
   check becomes: configured/root peer **or** `membership.verify_cert(presented_cert, now)`
   where the cert must cover `remote_static` (the Noise remote static key the responder
   recovers). This keeps admission **pre-session and self-contained** — no directory
   dependency and no bootstrap race: a brand-new member, or a joining node handshaking a
   root, is admitted purely on the cert it presents. Anti-hijack unchanged — admission gates
   *identity*, the Noise handshake still gates the *session*; a peer with no valid cert never
   gets a session (the check runs before the responder replies, exactly as 2a's allowlist
   check does today).

   **Handshake note (a real wire addition):** the membership cert rides as a Noise-IK
   *handshake message payload* (snow supports app payloads in handshake messages) — the
   initiator's cert in msg1, the responder's in msg2 — so both sides verify membership before
   the session is usable, with no extra round-trip and no probationary/unauthenticated
   session. In pure 2a/2b mode (no `cert` configured) the payload is empty and admission
   falls back to the static allowlist — non-breaking. The directory is then purely for
   **discovery** (learn a member exists + its pubkey/endpoints so you know whom to initiate
   to and where), not for admission.

**Composition with 2b:** 2c supplies identity + cert + initial endpoints; 2b's merged
`PathState`/rendezvous/relay handle reaching them. The `node_id` a 2b lookup needs now comes
from the directory instead of static config.

## Security invariants (mechanism, not policy)

1. **Membership is CA-gated** — no valid cert → no admission, no accepted directory entry.
2. **Anti-hijack unchanged (2b)** — discovery supplies a candidate identity+cert+address;
   the Noise handshake gates every session; egress is never redirected without a completed
   handshake over the new path.
3. **Record-authenticity chain CA → cert → record-sig** — a forged cert fails the CA check;
   a tampered record fails the member Ed25519 check. Worst in-gossip attack = replay a
   stale-but-valid record, bounded by `seq` supersession + cert expiry.
4. **Offline CA / root compromise ≠ membership forgery** — a root holds no CA key; it is
   only a gossip seed + always-admit peer. Root compromise degrades availability, never
   membership.
5. **Revocation = cert expiry** (bounded lag = cert lifetime); signed revocation record is a
   noted enhancement.
6. Gossip rides **authenticated Noise sessions** (no unauthenticated injection channel);
   digest exchange rate-limited; directory bounded by the member set.

**Residual/known (documented):** a *compromised member* (valid cert) is a full peer until
its cert expires — inherent; revocation lag = cert lifetime. Gossip metadata is visible to
members — metadata privacy is the later anonymity milestone.

**Clock note:** cert `not_before/not_after` are wall-clock, so cert verification needs
`SystemTime` (2b/2a used monotonic `now_ms`) with a small skew tolerance — a real design
point the plan must handle (pass a wall-clock `now` into `verify`; tolerate modest clock skew).

## Error handling (all non-fatal)

- No mesh config (`cert`/`ca_public`/`roots`) → pure 2a/2b static behavior.
- Root unreachable at bootstrap → retry with backoff; proceed once any root/member seeds the
  directory.
- Own cert expired → can't be admitted by others (record evicted on expiry); log + require
  renewal; daemon still serves static-config peers.
- Malformed / invalid-signature record → dropped before insert (never poisons the directory).
- `resolve` miss → buffer the TUN packet + trigger a gossip pull; drop after a bound.

## Testing

**Unit:** `yip-membership` — cert encode/decode/verify (valid / expired / wrong-CA /
wrong-network / tampered-body); record sign+verify (incl. tampered endpoints, wrong
member-sign-key); directory supersession + expiry eviction; anti-entropy convergence
(in-process, no sockets); `verify_cert`; `RootSet` verify. `yip-ca` — genkey, sign-cert,
sign-roots round-trips verify in `yip-membership`.

**netns money tests:**
1. **Dynamic discovery (headline):** A and B are **not** in each other's static config;
   both hold CA-signed certs + the signed root list; a root R runs as gossip seed. A and B
   bootstrap to R, gossip converges, then A pings B's mesh address → A resolves B via the
   directory, admits it, cert-verified handshake, traffic flows. Assert ping succeeds AND
   the connection used the discovered identity (B was never configured on A).
2. **Admission rejection (load-bearing gate):** a node with no cert / expired cert /
   wrong-CA cert attempts to join+handshake → refused (not admitted, not in directory).
   Assert the handshake is rejected and no session forms.
3. **Root-outage tolerance:** after A and B have gossiped (directory converged), kill R →
   A↔B still establish (directory already holds the records). Assert connectivity survives
   root loss.
4. **No 2a/2b regression:** no mesh config → all existing single-peer + triangle + 2b
   money tests green under both `poll` and `YIP_USE_URING=1`.

CI-gated under both drivers.

## Integration surface reused

- 2b `PathState`/`PathKind`/rendezvous/relay — reaching a discovered peer.
- 2a `node_addr(pubkey)` / `node_id` — directory keys and mesh addressing.
- `PeerManager` `on_tun`/`handle_handshake_init`/`on_udp`/`tick` — the wiring points; the new
  `admit_member` is the runtime peer-table mutation 2c adds.
- `config.rs` `[peer]`/parsing — extended with `ca_public`/`cert`/`roots`; roots become
  always-admit peers.
