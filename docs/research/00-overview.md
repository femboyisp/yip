# Reference Research — Overview & Synthesis

This directory contains the analysis of every reference project listed in the original brief (`projectref.md`),
grouped by role. Each file covers, per repo: what it does, language/license, protocols & crypto,
architecture, strengths/weaknesses, what could be done better (privacy, performance, latency,
decentralization/mesh/p2p, anti-DPI, encryption, security), and reusable ideas for our project.

| File | Cluster | Repos |
|------|---------|-------|
| [01-wireguard-family.md](01-wireguard-family.md) | WireGuard data plane + PQ | boringtun, gotatun, rosenpass, fastd |
| [02-mesh-overlays.md](02-mesh-overlays.md) | Mesh / P2P VPN overlays | n2n, n2n-go, omniedge, OmniNervous, ZeroTierOne, yggdrasil-go |
| [03-anonymity-networks.md](03-anonymity-networks.md) | Tor / I2P anonymity | arti, tor, i2p.i2p, i2pd, i2pd-tools, mkp224o |
| [04-mixnet-proxies.md](04-mixnet-proxies.md) | Mixnet + anti-censorship proxies | nym, shadowsocks-rust, Xray-core, v2ray-core, gsocket, openvpn |
| [05-transport-fec.md](05-transport-fec.md) | Reliable-UDP / FEC / encapsulation | kcp, kcp2k-rust, UDPspeeder, udpfrag, udplistener, tcp-in-udp, icmptunnel, etherconn, norp, nyxpsi |
| [06-crypto-pq-he.md](06-crypto-pq-he.md) | Crypto: AEAD, PQ, homomorphic | chacha20-blake3, lattigo, rosenpass (crypto) |
| [07-dpi-detection.md](07-dpi-detection.md) | DPI engines (the adversary) | nDPI, nDPId, rustnet |

---

## The goal (from projectref.md)

A **low-latency, high-performance, P2P mesh-network VPN tunnel**, written in **Rust**, with:
NAT hole-punching · RaptorQ FEC · L2 (TAP) bridging + L3 (TUN) tunneling · post-quantum
encryption with key rotation ("preferably homomorphic") · and elimination of DPI-detectable
network signatures.

---

## Cross-cutting design conclusions

These are the synthesized takeaways that should drive our own design. Details and citations are in
each cluster file.

### 1. Data plane: start from a modern async userspace WireGuard
- **gotatun** (Mullvad's async/tokio fork of BoringTun) is the best baseline: same audited Noise-IK
  core (Curve25519, ChaCha20-Poly1305, BLAKE2s) but with GSO/GRO, `recvmmsg`/`sendmmsg`, a recycled
  packet-buffer pool, a pluggable `DeviceTransports` trait, and swappable AEAD. MPL-licensed.
- None of the WireGuard forks ship discovery, NAT traversal, or relay — **that control plane is ours
  to build** and is where most of the real work lives.

### 2. Topology: control/data split + decentralized discovery
- Best fit = a **hybrid**: OmniNervous-style control/data split with a WireGuard data plane,
  but replace the single coordinator ("nucleus") with **Yggdrasil-style DHT/tree (or gossip)
  discovery** to remove the single point of failure, keeping an optional **ZeroTier-moon-style
  signed root set** only for bootstrap/relay anchoring.
- Use **self-certifying, key-derived addresses** (à la Yggdrasil/ZeroTier/mkp224o) so there is no
  address authority. Optionally PoW-harden address generation against Sybil.
- Reuse **fastd's dynamic peer-admission model** (`on-verify` hooks + peer groups) for mesh joins.

### 3. NAT traversal & relay
- Implement full UDP hole-punching (STUN-like rendezvous; see Bryan Ford's paper cited in projectref.md).
- Provide a **zero-knowledge relay fallback** (gsocket GSRN model: peers find each other by
  `hash(shared_secret)`, relay only ever sees ciphertext) when direct connection fails.

### 4. Transport substrate: FEC-first, ARQ-thin, pluggable & obfuscated
- **RaptorQ (RFC 6330)** as primary FEC — rateless, adaptive redundancy with no round-trips, beats
  Reed-Solomon (UDPspeeder) and KCP's retransmit-based ARQ for high-RTT lossy links. Use the
  `raptorq` crate. Must carry/derive OTI (object + symbol size) on both ends.
- Thin ARQ only for control/residual loss (hybrid), borrowing KCP's nodelay tuning.
- Make the **link layer pluggable & transport-agnostic** (plain UDP, TCP-in-UDP mimicry, TLS-mimicry,
  relay) — none of the references ship this cleanly.

### 5. Crypto stack
- **Data plane:** fast 256-bit AEAD (ChaCha20-Poly1305 baseline via RustCrypto/libcrux; adopt
  ChaCha20-BLAKE3's per-message subkey derivation + key-commitment as patterns). 256-bit symmetric
  is already quantum-safe.
- **Handshake:** copy **Rosenpass** — hybrid PQ KEM (Classic McEliece static + Kyber/ML-KEM
  ephemeral) feeding a PSK into the Noise channel; "no worse than WireGuard" + PQ. Prefer pure-Rust
  verified `libcrux` ML-KEM.
- **Key rotation:** rekey ~every 120 s (Rosenpass constants); stateless "biscuit" responder for DoS.
- **Homomorphic encryption — blunt verdict: NOT for the data plane.** 10^6–10^9× slower, ~1000–10000×
  ciphertext expansion, and pointless (both endpoints own the plaintext). Reserve HE/MPC (Lattigo) as
  an *optional control-plane* feature only: private peer discovery (PSI) or private directory lookups
  (PIR) for metadata privacy.

### 6. Anti-DPI: this is a hard requirement, and nDPI is the test adversary
DPI fingerprints VPNs by (from nDPI source):
1. **Fixed header constants/magic** — WireGuard's byte-0 message type + 3 zero reserved bytes + exact
   handshake sizes (148/92/64); OpenVPN's opcode.
2. **"Fully encrypted" first-packet heuristic** — flags maximal-entropy openers (catches Shadowsocks/obfs).
3. **Entropy → `SUSPICIOUS_ENTROPY`** risk flag.
4. **Mahalanobis burst-size model** — detects TLS-in-TLS by first-flights byte distribution.
5. **JA3/JA4 + SNI/ALPN** TLS fingerprinting; default ports; flow timing & packet-size stats.

**Our requirements:** no fixed magic/opcodes/reserved fields (random from byte 0; derive type
discriminators from keyed/rolling values, not constants) · defeat the fully-encrypted heuristic
(mimic real framing or shape entropy) · randomized variable-length padding · timing jitter + junk
packets · plausible ports (443). The **AmneziaWG** recipe (Jc/Jmin/Jmax junk packets, S1/S2 junk
before handshake, H1–H4 magic-header randomization) maps 1:1 — bake it in. Best obfuscation to steal:
**Xray REALITY** (uTLS browser ClientHello mimicry, SNI to a real domain, auth tag hidden in TLS
SessionID, active probes reverse-proxied to the real site) and **Shadowsocks AEAD-2022**.
**Wire nDPI/nDPId into CI as the verification adversary.**

### 7. Anonymity vs latency is a dial, not a fixed point
- Onion (Tor) / garlic (I2P) / Sphinx-mixnet (Nym) routing buy traffic-analysis resistance at a cost
  of hundreds of ms to seconds per packet — incompatible with our low-latency goal as a default.
- Make privacy a **per-flow policy**: default = direct encrypted P2P (fast, no metadata privacy);
  optional = multi-hop onion routing for sensitive flows. Reuse **Arti crates** as building blocks
  (`tor-proto`, `tor-cell`, `tor-llcrypto`, `tor-ptmgr`, congestion control), and NTCP2-style
  Noise+Elligator2 uniform-random handshakes from I2P.

---

## Open design questions (to resolve during planning)

1. Primary use case priority: gaming/real-time low latency, censorship circumvention, or anonymity?
2. Default topology: coordinator-assisted bootstrap then P2P, or fully serverless from day one?
3. L2+L3 both at launch, or L3 (TUN) first?
4. How aggressive is the anti-DPI default (always-on obfuscation vs opt-in)?
5. PQ from day one, or classical first with a PQ-ready handshake?
6. Platform targets (Linux-first? Windows/macOS/mobile?).

These feed the design doc and implementation plan.
