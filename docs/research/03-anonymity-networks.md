# Anonymity-Network Reference Analysis

Research notes for designing a Rust P2P mesh VPN with privacy as a goal.
Analysis of six locally-cloned reference projects: Arti, Tor (C), I2P (Java),
i2pd (C++), i2pd-tools, and mkp224o.

Sources: local repo READMEs/docs/source, the Tor spec model (onion routing,
ntor/ntor v3, HS v3), and the I2P spec model (garlic routing, NTCP2/SSU2,
netDb). All file paths below are absolute.

---

## 1. Arti — `/home/zoa/projects/femboy/yip/refrences/arti`

**What it does:** A from-scratch, embeddable, production-quality reimplementation
of the Tor anonymity protocols in Rust. As of 1.x it can bootstrap the directory,
build circuits, run as a SOCKS proxy, and act as both onion-service client and
server (and an experimental relay).

**Language / license:** Rust. Dual-licensed **MIT OR Apache-2.0** (per-crate, e.g.
`crates/arti-client/Cargo.toml`). This is materially more permissive than C-tor's
license and is the single biggest reason Arti is attractive to reuse.

**Anonymity model:** Onion routing, circuit-based. A client builds telescoping
3-hop circuits (guard → middle → exit) over TLS "channels"; each circuit
multiplexes application "streams." It is latency-sensitive / interactive-traffic
oriented (low-latency anonymity, not a mixnet) — same threat model as Tor:
resistant to a non-global adversary, vulnerable to end-to-end traffic
confirmation by a global passive adversary.

**Protocols & crypto:**
- Layered crate stack (`doc/dev/Architecture.md`): `tor-proto` implements
  channels/circuits/streams; `tor-cell` codes the fixed-size cell + relay-message
  formats; `tor-llcrypto` centralizes primitives.
- Handshakes live in `crates/tor-proto/src/crypto/handshake/`: `ntor.rs`
  (classic ntor, Curve25519 + HMAC-SHA256 one-way-authenticated key agreement),
  `ntor_v3.rs` (**ntor v3** — extensible handshake carrying encrypted
  parameters, the basis for congestion-control negotiation and future PQ
  hybridization), `hs_ntor.rs` (the onion-service variant), and `fast.rs`.
- Circuit crypto is the classic Tor onion: AES-CTR layers + per-hop running
  SHA-based digests, with relay-cell `SENDME` authentication tags.
- **Congestion control** is implemented natively (`crates/tor-proto/src/congestion/`):
  `vegas.rs` (TCP-Vegas-style RTT-based window), `rtt.rs`, `sendme.rs`,
  `params.rs`. This is Tor Proposal 324 — the most relevant latency-reduction
  work in the codebase.
- Onion-service crypto in `crates/tor-hscrypto`: ed25519 identity key,
  **key-blinding** to derive per-time-period blinded keys, SHA3-based MAC,
  `.onion` v3 encode/decode, time-period math for the HsDir hash ring, and a
  proof-of-work scheme (`pow`, EquiX via the `equix`/`hashx` crates) for DoS
  resistance at introduction.

**Directory / peer discovery model:** Centralized-ish — a small hardcoded set of
**directory authorities** vote to produce a signed hourly **consensus**;
`tor-dirmgr` fetches/validates/stores it, `tor-netdir` is the client's view,
`tor-consdiff` applies compressed diffs. Clients pin long-lived **guards**
(`tor-guardmgr`) to resist guard-rotation attacks. This is robust and
Sybil-resistant by authority signing, but it is a real centralization and
blocking chokepoint.

**Anti-censorship / anti-DPI:** `tor-ptmgr` manages **pluggable transports** —
external SOCKS-speaking binaries (obfs4, snowflake, meek, etc.). Bridges
(`doc/bridges.md`) are unlisted entry relays. Note the README caveat: ptmgr is
currently Tor-channel-specific and only speaks the original PT protocol.

**Strengths:** Memory-safe rewrite (Tor estimates ~half its CVEs were memory
bugs); genuinely modular crate boundaries; permissive license; native modern
congestion control; clean async (`tor-rtcompat` abstracts the runtime).
**Weaknesses:** Anonymity costs 3 hops of latency (typically hundreds of ms);
directory authorities are centralized; relay support is newer/less battle-tested
than C-tor; PT integration is still narrow.

**What could be done better (for our project):**
- *Latency:* 3 hops is a fixed tax. For a mesh VPN we want a *tunable* hop count
  (1–3) per traffic class, and to adopt Vegas-style RTT congestion control from
  day one rather than bolting it on later.
- *Decentralization:* replace dir authorities with a gossip/DHT membership layer
  (I2P-style) — Arti's authority model is its weakest point for a P2P mesh.
- *Anti-DPI:* the PT model is process-out-of-band; we'd want obfuscation as a
  first-class in-process transport layer (see obfs4/Snowflake notes below).
- *PQ:* ntor v3's extension fields are the right hook for hybrid X25519+ML-KEM;
  Arti hasn't shipped it but i2pd already has ML-KEM in NTCP2.

**Reusable crates (most relevant first):**
- `tor-llcrypto` — vetted primitive wrappers (Curve25519, ed25519, AES, SHA).
- `tor-proto` — channel/circuit/stream state machines and the onion crypto.
- `tor-cell` — fixed-size cell framing (a model for traffic-shaping uniformity).
- `tor-proto/congestion` (Vegas/RTT/SENDME) — directly reusable latency control.
- `tor-hscrypto` + `tor-cert` + `tor-keymgr`/`tor-key-forge` — key blinding,
  cert handling, on-disk key management.
- `tor-ptmgr` — pluggable-transport manager if we adopt the PT ecosystem.
- `tor-guardmgr` — guard/entry-node pinning logic (anti-Sybil for entry).
- `tor-rtcompat` — async-runtime abstraction; `fs-mistrust` — strict file-perm
  checks; `safelog` — redaction of sensitive data from logs (great privacy
  hygiene primitive); `tor-bytes` — readers/writers for binary protocols.
- `equix`/`hashx` — asymmetric client-puzzle PoW for DoS resistance.

---

## 2. Tor — `/home/zoa/projects/femboy/yip/refrences/tor`

**What it does:** The original C reference implementation of the Tor onion-routing
network ("little-t tor") — client, relay, and onion-service daemon.

**Language / license:** C (with a small Rust shim, see `Cargo.toml`). 3-clause BSD
(`LICENSE`).

**Anonymity model:** Identical conceptual model to Arti (it *is* the reference):
low-latency onion routing, telescoping 3-hop circuits over TLS, stream
multiplexing. Source is organized under `src/core` (protocol),
`src/feature` (HS, dir, relay), `src/lib`, `src/trunnel` (generated binary
codecs).

**Protocols & crypto:** ntor / ntor v3 circuit handshakes; AES-CTR onion layers;
RSA (legacy) + Ed25519/Curve25519 identities; HS v3 (ed25519, blinded keys,
SHA3). Proposal 324 congestion control. Trunnel generates the wire codecs.

**Directory / peer discovery model:** Same dir-authority + signed consensus +
guard model as Arti. This codebase *is* the authority/consensus implementation
the whole network depends on.

**Anti-censorship / anti-DPI:** The home of pluggable transports — obfs4
(obfuscated handshake + traffic), meek (domain-fronted HTTPS), and
**snowflake** (WebRTC via ephemeral browser-based proxies). PTs run as separate
processes speaking an extended SOCKS protocol. Bridges + BridgeDB for
distribution.

**Strengths:** Most mature, most audited, largest real network, the spec's ground
truth. **Weaknesses:** C memory-safety risk; ~20 years of accreted "spaghetti"
(their own README's words); originally a SOCKS proxy with integration bolted on;
same latency/centralization caveats as Arti.

**What could be done better:** Everything Arti was created to fix — memory safety,
modularity, embeddability. For us, Tor is the *spec/behavior reference*; Arti is
the code reference. Useful to mine `src/feature/dir` for the consensus/voting
algorithm if we ever want a federated directory, and `doc/HACKING` /
`doc/man/torrc` for the full config surface and threat-model documentation.

**Reusable ideas:** Consensus-voting design; guard-selection rationale; PT/SOCKS
hand-off contract; the cell-padding / traffic-shaping defenses documentation.
(Code itself is GPL-incompatible to lift into Rust, but the *designs* are public
spec.)

---

## 3. I2P — `/home/zoa/projects/femboy/yip/refrences/i2p.i2p`

**What it does:** The reference Java implementation of I2P, a fully P2P anonymous
overlay network ("the invisible internet"). Unlike Tor it's designed as a
self-contained network (intra-network "eepsites," not an exit-to-clearnet proxy).

**Language / license:** Java (build via Ant/Gradle, JDK 17+). Mix of public-domain
+ BSD/MIT-style + some GPL components (`LICENSE.txt` is a per-component manifest).

**Anonymity model:** **Garlic routing** (a superset of onion routing) over
**unidirectional tunnels**. Key differences from Tor:
- Tunnels are *one-way*: each peer maintains separate **inbound** and **outbound**
  tunnel pools, so a request and its reply traverse four different sets of hops.
- "Garlic" messages bundle multiple **cloves** (independent messages, each with
  its own delivery instructions — local/destination/router/tunnel) into one
  encrypted unit, frustrating traffic analysis and enabling bundled ACKs.
- Packet/message-switched rather than a single persistent circuit; more like a
  message overlay than a stream tunnel. Still low-latency (interactive), not a
  mixnet, with comparable end-to-end-confirmation caveats.

**Protocols & crypto:** Per-hop layered encryption on tunnels; end-to-end garlic
encryption between destinations. Modern I2P uses **ECIES-X25519-AEAD-Ratchet**
(X25519 + ChaCha20-Poly1305 + a double-ratchet-style session) for end-to-end,
replacing legacy ElGamal+AES. Destinations are self-certifying long-term keypairs;
**LeaseSets** publish the current inbound-tunnel gateways for a destination.

**Directory / peer discovery model:** Fully decentralized **netDb** — a
Kademlia-style DHT (XOR metric) holding two record types: **RouterInfos** (how to
reach a router) and **LeaseSets** (how to reach a destination). A subset of
high-capacity routers volunteer as **floodfill** nodes that store and flood these
records. No directory authorities — this is the headline contrast with Tor and
the model most relevant to a P2P mesh.

**Anti-censorship / anti-DPI:** Transport obfuscation is built into the
*transports themselves* rather than separate PTs: **NTCP2** (Noise-based,
obfuscated TCP, looks like random bytes, ChaCha20/Poly1305) and **SSU2**
(obfuscated UDP). No obfs4/snowflake equivalent and weaker against active probing
than Tor's PT ecosystem; I2P is also easier to block by enumerating routers.

**Strengths:** No central authority (Sybil-resistant via Kademlia + floodfill
churn); unidirectional tunnels + garlic bundling give a different/arguably
stronger traffic-analysis posture; built-in obfuscated transports.
**Weaknesses:** Higher latency and tunnel-build cost (separate in/out tunnels,
frequent rebuilds every ~10 min); smaller network; Java footprint; netDb
bootstrap ("reseed") is a real chokepoint and DHT is itself an attack surface
(eclipse/Sybil on the hash ring).

**What could be done better:** Reduce tunnel-build latency (pre-build pools — they
do, but it's costly); harden netDb against eclipse attacks; add Tor-style
pluggable transports for censored regions.

**Reusable ideas:** Garlic clove bundling for batched/padded messages; **netDb /
Kademlia floodfill** as a decentralized membership/discovery layer (directly
applicable to our mesh, replacing dir authorities); unidirectional tunnels as a
traffic-analysis defense; ECIES-X25519-AEAD-Ratchet for forward-secret e2e
sessions.

---

## 4. i2pd — `/home/zoa/projects/femboy/yip/refrences/i2pd`

**What it does:** A full-featured, lightweight C++ implementation of an I2P
client/router — same protocol as i2p.i2p but far smaller footprint and faster.

**Language / license:** C++. **BSD 3-clause** (`LICENSE`) — permissive, so designs
*and* code are reference-able.

**Anonymity model:** Same as I2P: garlic routing, unidirectional inbound/outbound
tunnel pools, message-switched. Implementation in `libi2pd/`:
`Tunnel.cpp`/`TunnelPool.cpp`/`TransitTunnel.cpp` (tunnel lifecycle),
`Garlic.cpp` (garlic encryption + clove delivery types — see
`GarlicDeliveryType` enum: local/destination/router/tunnel).

**Protocols & crypto (`libi2pd/`):**
- `NTCP2.cpp/.h` — Noise-pattern obfuscated TCP transport. Notable: the header
  already references **`PostQuantum.h`** and `NTCP2_SESSION_HANDSHAKE_MAX_SIZE`
  vs a long variant for **ML-KEM** frames — i2pd ships a *post-quantum hybrid*
  handshake. Padding is randomized (`NTCP2_MAX_PADDING_RATIO`). Block types
  include an explicit `eNTCP2BlkPadding`.
- `SSU2.cpp/.h` + `SSU2Session.cpp` — obfuscated UDP transport (lower latency,
  NAT traversal).
- `ECIESX25519AEADRatchetSession.cpp` — the modern forward-secret e2e session.
- `Elligator.cpp` — Elligator2 encoding to make X25519 public keys look like
  uniform random bytes (key anti-DPI primitive — defeats "this is a 32-byte
  curve point" fingerprinting).
- `Crypto.cpp`, `CryptoKey.cpp` — primitive layer (OpenSSL-backed).
- `NetDb.cpp/.hpp` + `NetDbRequests.cpp` — Kademlia netDb with `XORMetric`,
  `GetClosestFloodfills`, flooding to closest floodfills.

**Directory / peer discovery model:** Decentralized netDb / Kademlia floodfill
(see `NetDb.cpp` `XORMetric`, `closestFloodfills`). Reseed for bootstrap.

**Anti-censorship / anti-DPI:** NTCP2 + SSU2 are obfuscated by design; Elligator2
hides curve points; randomized padding ratio. Strong *passive* DPI resistance,
weaker active-probing resistance than Tor PTs.

**Strengths:** BSD-licensed (legally reusable), small/fast, modern crypto
(X25519/ChaCha20/Poly1305, ratchet, **ML-KEM PQ hybrid already in NTCP2**),
clean transport abstraction (`Transports.cpp`, `TransportSession.h`).
**Weaknesses:** C++ memory-safety risk; I2P's inherent tunnel-build latency;
network size.

**What could be done better:** Same I2P-level items (eclipse hardening, lower
build latency). Implementation-wise it's a strong model to copy.

**Reusable ideas/components:** NTCP2 Noise handshake + ML-KEM hybrid pattern;
**Elligator2 point-hiding**; randomized padding scheme; SSU2 UDP design (very
relevant for a UDP-based mesh VPN with NAT traversal); the Kademlia/floodfill
netDb membership design; garlic clove bundling. Because it's BSD, its structure
is the cleanest legal blueprint among the I2P repos.

---

## 5. i2pd-tools — `/home/zoa/projects/femboy/yip/refrences/i2pd-tools`

**What it does:** A grab-bag of standalone CLI utilities supplementing i2pd:
key generation, address verification, RouterInfo inspection, address-book
registration, and an I2P **vanity address** generator.

**Language / license:** C++ (Boost + OpenSSL deps). BSD-style (`LICENSE`).

**Anonymity model:** N/A (tooling). Operates on I2P's self-certifying destinations,
LeaseSets, and RouterInfos.

**Protocols & crypto / tools:**
- `keygen.cpp`, `keyinfo.cpp`, `offlinekeys.cpp` — destination keypair gen and
  offline-signing-key support (cold-key / online-signing separation).
- `vain.cpp` + `vanity.hpp` — multithreaded I2P vanity-destination generator;
  matches a `std::regex` against the base32 address. Includes a hand-rolled
  SHA-256 (`CalculateW`/`TransformBlock`) for speed — the I2P analogue of
  mkp224o but regex-based and (per the source) less micro-optimized.
- `verifyhost.cpp` — validates address-book host=dest signatures.
- `routerinfo.cpp`, `b33address.cpp`, `i2pbase64.cpp`, `x25519.cpp`,
  `regaddr*.cpp`, `famtool.cpp` (router "family" signing).

**Directory / peer discovery model:** N/A; reads/writes netDb files (RouterInfo
`.dat`).

**Anti-censorship / anti-DPI:** N/A.

**Strengths:** Practical reference for I2P key formats, offline keys, and
address-book/registration plumbing. **Weaknesses:** Utility-grade code, not a
library.

**What could be done better / reusable ideas:** The **offline-signing-key**
pattern (`offlinekeys.cpp`) is worth adopting — keep the long-term identity key
offline and rotate short-lived online signing keys. The router **family** concept
(`famtool.cpp`) is a useful idea for declaring "these mesh nodes are operated by
one party" so clients can avoid using multiple same-operator hops in one path.

---

## 6. mkp224o — `/home/zoa/projects/femboy/yip/refrences/mkp224o`

**What it does:** A fast multithreaded **vanity .onion v3 (ed25519) address
generator** — brute-forces ed25519 keypairs until the base32 of the public key
starts with a desired prefix.

**Language / license:** C (C99). **CC0 / public domain** (`COPYING.txt`) — freely
usable.

**Anonymity model:** N/A — it generates the *identity* whose hash *is* the onion
address. Relevant because it reveals exactly how Tor v3 addresses are derived.

**Protocols & crypto — the actual derivation (`worker_batch.inc.h`):** A v3 onion
address is `base32(pubkey ‖ checksum ‖ version)` where
`checksum = SHA3-256(".onion checksum" ‖ pubkey ‖ 0x03)[:2]` and `version = 0x03`.
The code:
1. Expands a random seed → ed25519 scalar `sk`, computes base point
   `A = sk·B` (`ge_scalarmult_base`).
2. **The key trick:** instead of generating a fresh keypair each attempt, it
   *adds the precomputed point `8·B`* to the running public point and increments
   the scalar by 8 (`ge_add(&sum, &ge_public, &ge_eightpoint)` then
   `addsztoscalar32(sk, counter)`). One cheap curve **point addition** per
   candidate instead of a full scalar multiplication — orders of magnitude
   faster. (The +8 / cofactor-8 step keeps the scalar valid for ed25519's
   clamping.)
3. **Batches** the expensive final coordinate inversion across `BATCHNUM`
   candidates using Montgomery's batch-inversion
   (`ge_p3_batchtobytes_destructive_1`), amortizing the one modular inverse over
   the whole batch.
4. Filters via a bitwise prefix matcher (`DOFILTER`), only finishing the full
   point + checksum + base32 (`FIPS202_SHA3_256`, `base32_to`) on a hit.
5. Optional passphrase mode = deterministic reseeding for reproducible keys.
   Multiple optimized ed25519 backends (`ref10`, `amd64-51-30k`, `amd64-64-24k`,
   `donna`) selectable at configure time.

**Directory / peer discovery, anti-DPI:** N/A.

**Strengths:** Extremely fast (incremental point addition + batch inversion +
SIMD ed25519); clean, public-domain, easy to lift. **Weaknesses:** Vanity prefixes
cost exponential time per character; longer prefixes are infeasible; vanity keys
have no security downside but offer no anonymity benefit either.

**What could be done better / reusable ideas (address-generation tricks):**
- **Incremental point addition** (`P += 8B`, `scalar += 8`) to enumerate a keyspace
  cheaply — reusable any time we brute-force or scan structured ed25519/x25519
  keys.
- **Batched modular inversion** (Montgomery's trick) to convert N projective
  points to affine with one inverse — a general speedup for bulk key
  derivation/verification in our crypto layer.
- The exact **v3 onion derivation** (`SHA3-256` truncated checksum + version byte
  + base32) is the template if we want short, self-certifying,
  human-pasteable node/service addresses where the address *is* the public key.
  We could adopt the same `base32(pubkey ‖ checksum ‖ version)` scheme for mesh
  node IDs so addresses are self-authenticating with no PKI.

---

## Cross-cutting takeaways for our Rust P2P mesh VPN

| Axis | Tor / Arti | I2P / i2pd | Implication for us |
|---|---|---|---|
| Routing | Onion, bidirectional circuits | Garlic, unidirectional tunnels + cloves | Garlic bundling + one-way paths give better traffic-analysis resistance for a mesh |
| Discovery | Dir authorities + signed consensus (centralized) | Kademlia netDb + floodfill (decentralized) | Adopt netDb-style DHT for a P2P mesh; authorities are a non-starter |
| Transport obfuscation | External pluggable transports (obfs4, meek, snowflake) | Built-in obfuscated transports (NTCP2 Noise, SSU2, Elligator2) | Build obfuscation in-process *and* keep a PT hook |
| Crypto | ntor v3, X25519, no shipped PQ yet | ECIES-X25519-AEAD ratchet + **ML-KEM PQ hybrid** | Go PQ-hybrid from day one (i2pd proves it's practical) |
| Latency | 3 hops fixed | in+out tunnels, frequent rebuilds | Make hop count tunable per traffic class |
| License | Arti MIT/Apache, Tor BSD, i2pd BSD, mkp224o CC0 | — | Arti, i2pd, mkp224o are all legally reusable in Rust |

**Latency vs anonymity tension:** Every layer of onion/garlic encryption adds a
full round-trip through an extra geographically-arbitrary relay. Tor's typical
3 hops add hundreds of ms; I2P's separate inbound/outbound tunnels are worse.
For a *low-latency* mesh VPN this is the core conflict. Mitigations we should
design in: (1) tunable hop count (1 hop for trusted/LAN-mesh traffic, 2–3 for
high-anonymity); (2) Vegas/RTT congestion control (Arti `tor-proto/congestion`)
to keep queues short; (3) UDP transport (SSU2 model) to avoid TCP-over-TCP
head-of-line blocking; (4) pre-built tunnel/circuit pools to hide build latency.

**Anti-DPI transports worth adopting:** NTCP2's Noise-based obfuscation +
Elligator2 (make handshakes look like uniform random bytes) as the *default*
in-process transport; obfs4 for full traffic-shape obfuscation in hostile
networks; Snowflake (WebRTC, ephemeral volunteer proxies) for the hardest
censorship; meek/domain-fronting as a last resort. Randomized padding (i2pd's
ratio approach) on every transport.
