# 02 — Mesh Overlay & P2P VPN Reference Survey

Research notes for designing a new Rust P2P mesh VPN. Six reference projects analyzed from local clones: their READMEs, build files, and key source modules. Findings below are read from source, not guessed.

Repos analyzed:

- `refrences/n2n` — ntop n2n (C, light P2P VPN, supernode/edge)
- `refrences/n2n-go` — Go reimplementation of n2n
- `refrences/omniedge` — OmniEdge (Rust, zero-config mesh VPN, application/CLI layer over OmniNervous)
- `refrences/OmniNervous` — OmniNervous (Rust, control/data plane split, WireGuard data plane)
- `refrences/ZeroTierOne` — ZeroTier (C++, smart ethernet switch / global overlay)
- `refrences/yggdrasil-go` — Yggdrasil (Go, encrypted IPv6 overlay, scalable routing)

---

## n2n (ntop)

**What it does**
Light L2 VPN that lets edge nodes form virtual "community" networks bypassing firewalls/NAT, using a publicly reachable supernode for discovery and relay, with direct UDP P2P when possible.

**Language / license**
C. GPLv3 (`COPYING`/`LICENSE`).

**Topology model**
Supernode/coordinator model. A supernode is a rendezvous + relay server with a public port; edges register to it per-community. Discovery and relay are conflated into the supernode (it is both the control plane and the fallback data plane). Multiple supernodes can form a **federation** (`doc/Federation.md`) — a special hidden community where supernodes treat each other as edges, propagating knowledge for backup/failover/load-sharing. Not a true mesh: peers still bootstrap via supernodes.

**Protocols & crypto**
Custom UDP framing. Header carries community name, virtual MAC, source/dest. Payload ciphers are pluggable transforms (`src/transform_*.c`): Twofish-CTS (`-A2`), AES-CBC/CTS (`-A3`, default), ChaCha20-CTR (`-A4`), SPECK-CTR (`-A5`), plus null and LZO/zstd compression. Optional header encryption (`-H`) hides community name, virtual MAC, real hostname/IP metadata. Keying is a static pre-shared community key (`-k`), optionally via `N2N_KEY` env. Addressing: each edge gets a virtual IP/MAC inside the community subnet.

**NAT traversal / hole-punching**
Supernode observes each edge's public IP:port and shares it; edges attempt direct UDP. No formal STUN/NAT-type classification in core C; falls back to supernode relay when direct fails. UPnP/PMP is not a core feature.

**L2 vs L3**
L2 (TAP) is the primary model — edges exchange Ethernet frames, so ARP/DHCP/broadcast work. L3 routing is layered on top via the OS.

**Routing**
Flat per-community switching. Supernode keeps the edge registry (MAC/IP → public endpoint); unicast goes direct or via supernode, broadcast/multicast is flooded through the supernode. No DHT, no spanning tree.

**Strengths / Weaknesses**
Strengths: tiny, portable C; pluggable ciphers; true L2; battle-tested; simple mental model. Weaknesses: supernode is a single point of trust/failure (federation mitigates but doesn't eliminate); supernode sees who-talks-to-whom (traffic-analysis metadata) even with payload encryption; static PSK per community (no forward secrecy, no per-peer keys); weak/optional NAT traversal; broadcast flooding scales poorly.

**What could be done better**
- *Privacy:* supernode learns the full peer graph; PSK reuse leaks community membership. Use per-peer keys + onion/relay padding to hide the graph.
- *Performance:* CBC/CTS block ciphers slower than AEAD; per-packet relay through supernode doubles latency.
- *Latency:* relay fallback is hairpin; add proactive hole-punch + multi-path.
- *Decentralization:* eliminate the mandatory rendezvous via DHT or gossip discovery.
- *Anti-DPI:* fixed UDP header shape is fingerprintable; add obfuscation/padding.
- *Encryption:* move to AEAD (ChaCha20-Poly1305) with per-session ephemeral keys and rotation.
- *Security:* community PSK with no PFS is the weakest link; adopt Noise-style handshakes.

**Reusable ideas/components**
Community-as-isolation namespace; pluggable transform pipeline abstraction (`Apply`/`Reverse`); supernode federation for HA bootstrap; optional header encryption to reduce metadata leakage; clean separation of edge vs supernode roles in one binary.

---

## n2n-go

**What it does**
Modern Go reimplementation of n2n's L2 supernode/edge VPN, with cleaner protocol framing, a fast-path data header, web visualization, and built-in NAT traversal.

**Language / license**
Go. MIT.

**Topology model**
Same supernode/edge model as n2n. Supernode is rendezvous + relay + IP allocator (`NetworkAllocator`, `ippool`) per community. Edges attempt direct P2P after discovery; supernode relays otherwise. Control plane = registration/heartbeat/peer-list exchange; data plane = TAP frames over UDP.

**Protocols & crypto**
Custom protocol v5 (`pkg/protocol`): 30-byte `ProtoVHeader` with community hash, flags, timestamp (replay protection), checksum; plus a compact **7-byte `ProtoVFuze` fast-path header** for bulk data. Payload transforms (`pkg/transform`): AES-GCM (AEAD) and zstd compression, composable pipeline. Passphrase → AES key derivation. Supernode authenticates edges with **RSA** keypair (`SNSecrets`, `TypeSNPublicSecret`). Deterministic MAC from machine-ID + community (`pkg/machine`).

**NAT traversal / hole-punching**
Real effort here (`pkg/natclient`): UPnP (IGDv1/IGDv2) and NAT-PMP/PCP port mapping, plus `TypePing` packets for UDP hole punching. P2P state quality tracked (`P2PCapacity`, `UDPWriteStrategy`: relay / best-effort-P2P / enforce-P2P).

**L2 vs L3**
L2 (TAP), cross-platform abstraction (`pkg/tuntap`, Linux/Windows/Darwin), Ethernet frames + gratuitous ARP.

**Routing**
Same flat per-community switching as n2n; supernode peer registry + direct/relayed unicast and supernode-flooded broadcast. Web viz exports peer graph as DOT/SVG/JSON.

**Strengths / Weaknesses**
Strengths: AEAD by default; explicit fast-path header (good throughput idea); proper UPnP/PMP/PCP + hole-punch; nice observability (peer graph, SQLite logs); buffer pooling for GC pressure. Weaknesses: inherits supernode-centric topology and metadata exposure; RSA for SN auth is heavyweight vs modern curves; Gob encoding for control msgs is Go-specific (not cross-language friendly); still per-community PSK with no PFS.

**What could be done better**
- *Privacy/Decentralization:* same supernode-knows-all critique as n2n.
- *Encryption:* AES-GCM is good; replace RSA SN-auth with Ed25519/X25519, add session PFS.
- *Anti-DPI:* fixed headers + timestamp are fingerprintable.
- *Cross-language:* swap Gob for CBOR/protobuf if interop matters.

**Reusable ideas/components**
Two-tier header design (full control header vs ultra-compact data fast-path) — directly applicable. Composable transform pipeline (encrypt + compress). `UDPWriteStrategy` enum (relay / best-effort / enforce P2P) as an explicit connection-quality state machine. Deterministic addressing from machine-ID + namespace. Buffer pool (`sync.Pool` analog → Rust `bytes`/object pool). Built-in peer-graph visualization endpoint.

---

## OmniEdge

**What it does**
Zero-config Rust P2P mesh VPN aimed at AI/robotics/edge; a single binary that joins devices into a virtual /24 reachable by virtual IP. It is the application/CLI/UI layer (auth, networks, routing-table mgmt, SSH, WASM plugins) on top of the **OmniNervous** P2P daemon.

**Language / license**
Rust (workspace of crates: `omni-api`, `omni-cli`, `omni-core`, `omni-helper`, `omni-plugin`, `omni-proto`, `omni-ssh`, `omni-tun`). Dual Apache-2.0 / MIT.

**Topology model**
Mesh data plane with a coordinator for control: a cloud (or self-hosted) account/network API plus a **nucleus** signaling server (modes: `edge`, `nucleus`, `dual`). The nucleus is a VIP→endpoint registry; data flows P2P (WireGuard) once peers are discovered, with relay fallback. So control plane = coordinator/nucleus, data plane = direct WireGuard mesh.

**Protocols & crypto**
Delegates transport crypto to WireGuard (via OmniNervous). Signaling encryption is X25519 + XSalsa20-Poly1305 (nacl box). Addressing: virtual IPs from a managed subnet (e.g. `10.147.1.x`), dual-stack IPv4/IPv6 with Happy Eyeballs (RFC 8305). `omni-core/routing.rs` is OS-level routing-table/DNS management (adds routes, detects system DNS), not overlay routing — overlay routing lives in OmniNervous.

**NAT traversal / hole-punching**
STUN NAT-type detection → UDP hole punch → UPnP/NAT-PMP/PCP port mapping → zero-knowledge relay fallback for symmetric/symmetric. Claims 99%+ success. (Implemented in OmniNervous.)

**L2 vs L3**
L3 (TUN) default, all platforms. L2 (TAP) Linux-only preview via `--transport-mode l2` (`l2-vpn` feature), delegated to OmniNervous L2 module.

**Routing**
Flat VIP routing: nucleus maps VIP→endpoint, peers talk directly. No DHT/tree; coordinator-assisted full-mesh. Exit-node support (route all traffic through a chosen peer).

**Strengths / Weaknesses**
Strengths: genuinely zero-config UX; WireGuard data plane (audited crypto, kernel or BoringTun userspace); WASM plugin system with capability-based sandboxing; built-in mesh SSH/SFTP/SCP; broad platform/arch matrix incl. OpenWrt/RISC-V; self-hostable nucleus for air-gapped use. Weaknesses: still needs a coordinator/account for the smooth path (centralized identity/trust); mesh is coordinator-assisted, not self-organizing; relies on cloud API for default flow.

**What could be done better**
- *Privacy:* cloud account ties identity to network; nucleus sees the peer graph. Offer fully self-sovereign identity + optional gossip discovery.
- *Decentralization:* nucleus is a soft SPOF; add multi-nucleus gossip or DHT discovery so a dead coordinator doesn't break new joins.
- *Anti-DPI:* WireGuard's fixed handshake is DPI-detectable; add pluggable obfuscation transport.
- *Latency/perf:* already strong (zero-copy claims) — main win is avoiding relay via better hole-punch and path selection.

**Reusable ideas/components**
Single-binary multi-mode (`edge`/`nucleus`/`dual`) deployment model. WASM capability-sandboxed plugin host (`omni-plugin` + WIT) — excellent extensibility pattern for Rust. Built-in mesh SSH (`omni-ssh`) as a value-add over raw L3. Self-hosted-nucleus story for privacy/air-gapped. Clean crate split: API/auth, CLI, core/routing-OS, tun, proto.

---

## OmniNervous

**What it does**
High-performance Rust P2P VPN **daemon** providing the engine under OmniEdge: a signaling control plane (the "nucleus") plus a WireGuard data plane, with sub-ms overhead and full NAT-traversal stack.

**Language / license**
Rust (single `daemon` crate, ~20 focused modules). MIT / Apache-2.0.

**Topology model**
Explicit **control-plane / data-plane split** — the headline architecture for our purposes. Control plane = nucleus signaling server (`signaling.rs`): a VIP→endpoint registry acting "like DNS for VPN," with delta-update heartbeats (<1KB) scaling to 10k+ registered / 2k per cluster on a $5 VM. Data plane = WireGuard tunnels (`wg.rs`), kernel (via `wg`/`wg-quick`) or userspace BoringTun, O(1) VIP routing table (`peers.rs`). Peers form a direct mesh; nucleus only brokers.

**Protocols & crypto**
Signaling: custom UDP messages with type bytes `0x11-0x1F` chosen to avoid WireGuard collision on the same port (REGISTER, HEARTBEAT, QUERY_PEER, NAT_PUNCH, DISCO_PING/PONG, MSG_ENCRYPTED envelope). Auth: HMAC-SHA256 with cluster PSK (constant-time compare via `subtle`); rate-limited (`governor`), LRU caches, CBOR with size limits, DoS hardening. Optional signaling encryption: X25519 + XSalsa20-Poly1305 (`crypto_box`/SalsaBox). Identity: X25519 keys, files `0o600`, `ZeroizeOnDrop`. Data plane: WireGuard = Noise_IKpsk2, ChaCha20-Poly1305, per-session ephemeral keys (forward secrecy). Relay messages `0x20-0x24`.

**NAT traversal / hole-punching**
Full stack in dedicated modules: `stun.rs` + `netcheck.rs` (NAT-type classification: FullCone/RestrictedCone/PortRestricted/Symmetric), `portmap.rs` (UPnP/NAT-PMP/PCP), DISCO ping/pong probes + NAT_PUNCH coordination via nucleus, and `relay.rs` — a **zero-knowledge relay** that forwards encrypted WireGuard packets (never decrypts), session-based (`[u8;16]` SessionId), rate-limited, auto-expiring. `happy_eyeballs.rs` for dual-stack racing.

**L2 vs L3**
L3 (TUN) default, all platforms. L2 (TAP) Linux-only via `l2-vpn` feature (`l2.rs`): L2 frames encrypted and tunneled over the same UDP/WireGuard path, with fragmentation/reassembly (MTU 1400) and Prometheus L2 metrics.

**Routing**
Flat VIP→endpoint mesh. Nucleus is the directory; once resolved, packets go peer-to-peer (or via relay). O(1) hashmap dispatch, no DHT/tree. Dual-stack v4/v6 mapping table.

**Strengths / Weaknesses**
Strengths: clean control/data separation; reuses WireGuard's audited crypto + PFS instead of rolling its own data-plane cipher; serious NAT stack incl. zero-knowledge relay; sharing the WG UDP port for signaling (clever, single-port firewall story); strong DoS/input hardening; Prometheus observability; zero-copy data path. Weaknesses: nucleus is still a discovery SPOF (single registry, though lightweight/self-hostable); signaling protocol is bespoke (one implementation); cluster PSK is a coarse trust boundary; relay capacity bounded by operator.

**What could be done better**
- *Privacy:* nucleus sees VIP↔endpoint↔graph; add optional encrypted/blinded registration and multi-nucleus gossip.
- *Decentralization:* discovery is centralized; a DHT or gossip layer would remove the SPOF while keeping WG data plane.
- *Anti-DPI:* WireGuard packets are fingerprintable; add a pluggable obfuscation/transport-shaping layer over the UDP socket.
- *Security:* per-cluster PSK is broad; move toward per-peer authorization / capability tokens.

**Reusable ideas/components**
The whole **control/data split is the template**: a thin signaling registry + WireGuard (BoringTun) data plane. Co-locating signaling and WG on one UDP port via a type-byte demux (`0x11-0x1F` vs WG types). Delta-update heartbeat protocol for scalable, low-bandwidth registries. Zero-knowledge relay design (forward ciphertext, session IDs, rate limits). NAT-type classifier → strategy selection. BoringTun userspace WG so no kernel dependency. `ZeroizeOnDrop` identities, constant-time PSK compare, CBOR-with-size-limits hardening patterns.

---

## ZeroTier (ZeroTierOne)

**What it does**
"Smart programmable Ethernet switch for planet Earth" — a global cryptographically-addressed P2P overlay (VL1) carrying an Ethernet virtualization layer (VL2, VXLAN-like) with SDN access control, so devices anywhere behave like one LAN.

**Language / license**
C++ (core in `node/`). Business Source License / MPL-2.0 for core (`LICENSE-MPL.txt`); controller and some parts are "source-available" non-free (`nonfree/`).

**Topology model**
Two layers. **VL1** is a global peer-to-peer transport: every node has a cryptographic identity and most traffic flows directly P2P. Bootstrap/relay anchors are **roots**, organized into a signed **World** (the "planet"; user-defined "moons" add private roots — `node/World.hpp`). Roots are stable rendezvous + last-resort relay, not traffic hubs. **VL2** is the virtual Ethernet network defined by a **network controller** (which issues network configs, IP assignments, and capability/membership certificates). So: decentralized P2P data plane (VL1) + centralized-per-network policy control plane (VL2 controller) + global root anchors.

**Protocols & crypto**
Identity (`node/Identity.cpp`): keypair (Curve25519/Ed25519 via `ECC`) whose **40-bit ZeroTier address is derived through a memory-hard hashcash** (SHA-512 + Salsa20 composition) — making address-collision/spoofing computationally expensive (a proof-of-work identity, last 5 bytes of the hard digest). Transport crypto: Salsa20 + Poly1305 (`Salsa20.cpp`, `Poly1305.cpp`), AES (`AES.cpp`, AES-NI/ARM-crypto paths) for newer modes, SHA-512. Custom `Packet` framing with verb-based protocol. VL2 enforcement via signed `CertificateOfMembership`, `Capability`, `Tag`, `CertificateOfOwnership`, `Revocation`.

**NAT traversal / hole-punching**
Strong: `SelfAwareness.cpp` learns external surface, UDP hole punching coordinated through roots/peers, multipath/link aggregation (`Bond.cpp`, `Path.cpp`), then relay through roots only if direct fails.

**L2 vs L3**
L2-first (it's an Ethernet switch — full Ethernet emulation, multicast via `Multicaster.cpp`). L3 rides on top as normal IP over the virtual L2.

**Routing**
VL1 uses identity (40-bit address) → peer endpoint, with the global root mesh + `Topology.cpp` for path knowledge; not a DHT for routing but roots act as a known anchor set + relays. VL2 is learned Ethernet switching (MAC tables) with controller-pushed routes and managed IPs. Multicast/broadcast handled by a multicast subsystem rather than naive flooding.

**Strengths / Weaknesses**
Strengths: cryptographic self-certifying addresses with PoW anti-spoofing; mature global anchor model with private moons; rich SDN policy (capabilities, tags, micro-segmentation, flow rules); excellent NAT traversal + multipath bonding; real Ethernet semantics. Weaknesses: per-network controller is a centralized policy authority (and the high-value controller is source-available, not free); C++ complexity; Salsa20-era crypto in legacy paths; roots still operated by ZeroTier by default (privacy/centralization concern unless you run moons).

**What could be done better**
- *Privacy:* default roots + controller see membership/metadata; self-hosting (moons + own controller) is possible but not the default.
- *Decentralization:* controller-per-network is a SPOF for policy/join; a decentralized membership-certificate scheme would help.
- *Encryption:* migrate fully off Salsa20 to modern AEAD/Noise; add PFS (sessions historically long-lived).
- *Anti-DPI:* distinctive packet structure; add obfuscation.
- *Latency:* already good via multipath; PoW identity gen is a one-time cost.

**Reusable ideas/components**
**Self-certifying cryptographic addresses derived from the public key with a memory-hard PoW** — strong Sybil/spoofing resistance, directly portable to Rust. The **World/moon** model: signed, versioned set of root anchors that's user-extensible for private deployments. Clean **VL1 (transport) / VL2 (virtual ethernet + policy) layering**. Capability/membership **certificates** for decentralized-ish authorization (microsegmentation without a live policy call per packet). Multipath link bonding (`Bond`) for latency/throughput. Multicast subsystem instead of flooding. `SelfAwareness` for learning one's own external address set.

---

## Yggdrasil (yggdrasil-go)

**What it does**
Fully end-to-end encrypted IPv6 overlay network: a self-arranging, decentralized mesh where every node gets a stable IPv6 address derived from its public key, and any IPv6 app can talk to any node securely — no central servers.

**Language / license**
Go. LGPLv3 (with a linking exception).

**Topology model**
**Fully decentralized, self-arranging** — no supernode, no coordinator, no controller. Nodes peer with configured/discovered neighbors (over TCP/TLS/QUIC/WS/Unix or LAN multicast) and collectively form the overlay. Control and data planes are unified inside the routing library; there is no privileged node. Routing logic lives in the external **Arceliar/ironwood** library (the v0.4+ "greedy routing on a spanning tree + DHT" successor).

**Protocols & crypto**
Identity = Ed25519 keypair. **Address derived from public key** (`src/address/address.go`): the `0200::/7` prefix, then the address encodes the count of leading 1-bits of the inverted key followed by the truncated inverted key — so the IPv6 address *is* (a compression of) the public key, self-certifying, and closer keys share longer prefixes. `/64` subnets per node available. Link encryption via TLS/QUIC; session/E2E crypto handled by ironwood (Ed25519 + ECDH/box-style). Peering links: `link_tcp/tls/quic/ws/wss/unix/socks`.

**NAT traversal / hole-punching**
Minimal/none by design — Yggdrasil relies on at least one routable peering link (you peer with a public node or a LAN neighbor) rather than hole-punching; LAN peers auto-discovered via multicast (`src/multicast`). NAT is sidestepped, not punched.

**L2 vs L3**
L3 only — pure IPv6 (TUN, `src/tun`, `ipv6rwc`). No L2/Ethernet emulation. Non-IPv6 traffic isn't carried.

**Routing**
The interesting part. Routing is **structured by the keyspace**: a global spanning tree provides coordinates, greedy routing forwards toward the destination key, and a **DHT** resolves key→tree-coordinate lookups. Because addresses are keys and the tree gives a metric over keyspace, packets find peers without any central directory and without full routing tables — it scales by locality in keyspace, not by node count tables. `src/admin` exposes `gettree`/`getpaths`/`getsessions` to inspect this.

**Strengths / Weaknesses**
Strengths: genuinely serverless/self-arranging; self-certifying crypto IPv6 addresses (no address authority); scalable routing without global tables; transport-agnostic peering (TCP/TLS/QUIC/WS); E2E encrypted by construction. Weaknesses: requires at least one reachable peer (no built-in NAT punch — practical bootstrapping pain); L3-only (no L2, no broadcast/legacy protocols); routing stretch — greedy-on-tree paths aren't always shortest; throughput historically below raw WireGuard; the tree root can become a hot/sensitive point.

**What could be done better**
- *Latency:* greedy-tree routing causes path stretch; better tree maintenance / source-route hints would cut hops.
- *Performance:* userspace Go path < WireGuard; a Rust + kernel/BoringTun data plane would help.
- *NAT/usability:* add STUN/hole-punching + relay so it works without a pre-arranged public peer.
- *Anti-DPI:* TLS/QUIC links blend in well already, but add explicit obfuscation option.
- *Privacy:* spanning-tree coordinates leak some topology; mixing/padding could harden.

**Reusable ideas/components**
**Public-key-derived self-certifying addresses** (here IPv6, akin to ZeroTier/Yggdrasil/CGAs) — eliminates an address authority entirely. **Structured keyspace routing (greedy-on-tree + DHT)** as a path to *decentralized discovery without a coordinator* — the single biggest idea to steal if we want no nucleus. **Transport-agnostic pluggable links** (TCP/TLS/QUIC/WS/Unix/SOCKS) — great for anti-DPI and restrictive networks. LAN multicast auto-peering for zero-config local mesh. Treating the routing engine as a separable library (ironwood) so the data plane and routing math evolve independently.

---

## Cross-cutting synthesis for a Rust mesh VPN

| Project | Topology | Discovery/Routing | Data plane | Crypto/Addressing | NAT |
|---|---|---|---|---|---|
| n2n | Supernode (federated) | SN registry, flat L2 switch | UDP + pluggable cipher | PSK per community, virtual MAC/IP | weak |
| n2n-go | Supernode | SN registry + fast-path header | UDP + AES-GCM | PSK + RSA SN-auth | UPnP/PMP + punch |
| OmniEdge | Coordinator + nucleus, mesh | VIP registry | WireGuard | account identity, VIP | full stack |
| OmniNervous | Control/data split, mesh | nucleus VIP→endpoint registry | WireGuard (BoringTun) | X25519 + WG, cluster PSK | full + zero-knowledge relay |
| ZeroTier | Roots (VL1) + controller (VL2) | roots + topology + MAC switching | custom Salsa20/AES | PoW-derived 40-bit address | strong + multipath |
| Yggdrasil | Fully decentralized | spanning tree + DHT, greedy routing | Go userspace, TUN | Ed25519 key = IPv6 address | none (peer-based) |

**Recommended blend for a low-latency decentralized P2P mesh:**
- Take **OmniNervous's control/data split** as the skeleton, with a **WireGuard/BoringTun data plane** (audited AEAD + per-session PFS) so we don't roll our own packet crypto.
- Replace the single nucleus with **Yggdrasil-style structured-keyspace discovery (DHT + tree) or gossip** to remove the coordinator SPOF — keep an optional lightweight nucleus only as a bootstrap/relay anchor (ZeroTier "moon"-style signed root set for private/air-gapped deployments).
- Adopt **self-certifying public-key-derived addresses** (Yggdrasil/ZeroTier) — optionally with ZeroTier's **memory-hard PoW** for Sybil resistance — so there's no address authority.
- Reuse **n2n-go's two-tier header** (compact data fast-path vs control header) and **OmniNervous's single-UDP-port type-byte demux**.
- Keep **OmniNervous's NAT stack**: STUN NAT-typing → hole-punch → UPnP/PMP/PCP → **zero-knowledge relay** fallback.
- Add what none of them default to: a **pluggable obfuscation transport** (anti-DPI) and **transport-agnostic links** (Yggdrasil-style TCP/TLS/QUIC) for hostile networks.
