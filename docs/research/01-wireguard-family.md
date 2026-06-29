# Research 01 — The WireGuard Family (BoringTun, gotatun, Rosenpass, fastd)

Reference analysis for the design of a new Rust P2P mesh VPN. Each section is based
on reading the repos' READMEs, build files, and key source modules (not guessed).
All paths below are absolute and point into `/home/zoa/projects/femboy/yip/refrences/`.

---

## 1. BoringTun (Cloudflare)

**What it does**
Userspace implementation of the WireGuard protocol, shipped as a library (`boringtun`)
plus a CLI daemon (`boringtun-cli`). Deployed on millions of iOS/Android devices (1.1.1.1
app) and thousands of Cloudflare Linux servers.

**Language / license**
Rust, edition 2018. 3-Clause BSD. Library crate type is `staticlib`/`cdylib`/`rlib`,
with C FFI (`wireguard_ffi.h`) and JNI bindings (`src/jni.rs`) for mobile.

**Protocols & crypto primitives**
Stock WireGuard / Noise IK handshake:
- Static + ephemeral DH over **Curve25519** (`x25519-dalek`).
- AEAD: **ChaCha20-Poly1305** (data; via `ring`) and **XChaCha20-Poly1305** (cookie reply; via `chacha20poly1305` crate).
- Hash/KDF: **BLAKE2s** + HMAC-BLAKE2s for the Noise chaining-key KDF (`b2s_hash`, `b2s_hmac`, `b2s_keyed_mac_16` in `noise/handshake.rs`).
- Message types: handshake init (148 B), response (92 B), cookie reply (64 B), data (32 B overhead). Cookie/`mac1`/`mac2` DoS mitigation with a rate limiter (`noise/rate_limiter.rs`).

**Architecture / how it works**
- The protocol core is a *sober, synchronous, sans-IO state machine*: `Tunn` in
  `boringtun/src/noise/mod.rs`. You feed it bytes and it returns a `TunnResult` enum
  (`Done`, `Err`, `WriteToNetwork`, `WriteToTunnelV4/V6`). It owns up to `N_SESSIONS = 8`
  ring-buffered sessions, a `Handshake`, a `Timers` struct, and a queue of blocked packets.
  This makes the crypto layer fully testable and platform-independent — the library does
  **not** touch sockets or TUN devices.
- The optional `device` feature (`boringtun/src/device/`) is the daemon: a `Device`
  guarded by a custom `Lock`/`dev_lock.rs` wrapper, with a **thread-per-core** model
  (default `n_threads = 4`), each running an `event_loop` over an `epoll` (Linux,
  `device/epoll.rs`) or `kqueue` (macOS, `device/kqueue.rs`) reactor. Handlers are
  registered per FD: UDP sockets, the TUN iface (`tun_linux.rs`/`tun_darwin.rs`), timers,
  and the `wg`-compatible UAPI socket (`device/api.rs`).
- Peer routing uses a longest-prefix-match allowed-IPs trie (`ip_network_table` crate,
  `device/allowed_ips.rs`). Each handler call processes up to `MAX_ITR = 100` packets.
- Drops privileges after setup (`device/drop_privileges.rs`); needs `CAP_NET_ADMIN`.

**Strengths**
- Clean sans-IO `Tunn` core — ideal to lift wholesale and drive from any IO model.
- Battle-tested at massive scale; the de-facto reference for "WireGuard in Rust."
- Portable: same core compiles to iOS/Android/desktop via FFI/JNI.
- Standards-compatible UAPI so `wg`/`wg-quick` tooling just works.

**Weaknesses / limitations**
- Synchronous blocking thread-per-core with a coarse `Lock<Device>` — contention and
  no async composition; awkward inside a larger tokio app.
- No GSO/GRO/`sendmmsg` batching → lower throughput than the kernel module or gotatun.
- Single AEAD backend hardwired (`ring`); no pluggable crypto.
- "Currently undergoing restructuring; don't rely on master" per its own README.
- No traffic-analysis defense, no PQ, no mesh/discovery — pure point-to-point WG.

**What could be done better (for our goals)**
- *Privacy / anti-DPI*: WG packets have fixed, fingerprintable sizes and a cleartext type
  byte; nothing here obfuscates them. Add padding/obfuscation/pluggable transports.
- *Performance / latency*: adopt UDP GSO/GRO and batched syscalls; replace the global lock
  with per-peer state and lock-free queues.
- *Decentralization / mesh*: no peer discovery, NAT traversal, or relay — all manual.
- *Encryption / security*: no post-quantum protection; harvest-now-decrypt-later exposure.

**Reusable ideas/components**
- The entire `noise/` module (`Tunn`, `handshake`, `session`, `timers`, `rate_limiter`)
  as a sans-IO crypto core to wrap in our own async runtime.
- `TunnResult` sans-IO pattern — make our protocol layer return actions, not do IO.
- `device/allowed_ips.rs` + `ip_network_table` for the cryptokey-routing table.
- UAPI compatibility layer (`device/api.rs`) for `wg`-tool interop during bootstrap.
- The session ring buffer (`N_SESSIONS`) for seamless key rotation without dropping packets.

---

## 2. gotatun (Mullvad)

**What it does**
A userspace WireGuard implementation that is a **modernized async fork of BoringTun**,
maintained by Mullvad, adding tokio, kernel UDP offload, swappable AEAD backends, and
**DAITA** traffic-analysis defense.

**Language / license**
Rust (workspace, edition from workspace). **MPL-2.0** (relicensed from BSD; contributions
before 2026-03-05 remain BSD, see `LICENSE-CLOUDFLARE`). Independent security audits in
`audits/`. Builds as `cdylib`/`rlib`/`staticlib`; Nix flake provided.

**Protocols & crypto primitives**
Same WireGuard / Noise IK protocol and message formats as BoringTun (it keeps `noise/`),
with notable upgrades:
- **Swappable AEAD backend** selected at compile time (`crypto.rs`): `aws-lc-rs` (default)
  or `ring`. Still ChaCha20-Poly1305 / XChaCha20-Poly1305, Curve25519, BLAKE2s KDF.
- Security hardening over upstream: cookie MAC now includes the **source port** (per the
  whitepaper), not just IP (see CHANGELOG `[0.6.0]` Security note).
- Optional **DAITA** (Defense Against AI-guided Traffic Analysis) padding/decoy/delay layer.

**Architecture / how it works**
- Fully **async on tokio** (`tokio` with `sync,rt,time,macros,net,io-util`). `device/mod.rs`
  spawns long-lived tasks via a `Task` abstraction (`task.rs`): `outgoing`, `timers`,
  `incoming_ipv4`, `incoming_ipv6`, coordinated with `RwLock`/`Mutex`/`watch` and per-peer
  `PeerState` (`device/peer_state.rs`).
- **Pluggable transports** via the `DeviceTransports` trait (`device/transports.rs`),
  implemented generically for tuples of `(UdpTransportFactory, IpSend, IpRecv)`. Default is
  `(UdpSocketFactory, TunDevice, TunDevice)`. This decouples the WG engine from *how* bytes
  move — you can swap UDP for any datagram transport, or the TUN device for an in-memory channel.
- **Kernel UDP offload**: `udp/socket/linux.rs` uses `recvmmsg`/`sendmmsg` plus **UDP GRO**
  (`UDP_GRO`, `UdpGroSegments` cmsg) and GSO segmentation, dividing coalesced datagrams into
  per-packet `Packet` buffers. Big throughput win over BoringTun.
- **Lock-free packet buffer pool** (`packet/pool.rs`): `PacketBufPool<const N=4096>` recycles
  `BytesMut` allocations via a `ReturnToPool` drop guard, avoiding per-packet allocation.
- Rich **typed packet parsing** (`packet/`): `Decoder`/`PoD` traits, zerocopy IPv4/IPv6/TCP/UDP
  types and internet-checksum helpers — much more than BoringTun's raw offset constants.
- **DAITA** (`device/daita/`): integrates the **`maybenot`** framework. `DaitaSettings`
  carries a set of `maybenot::Machine`s plus caps (`max_decoy_frac`, `max_delay_frac`,
  `max_delayed_packets`). Hooks (`hooks.rs`) translate maybenot actions into constant-size
  padding, decoy (dummy) packets, and packet delaying, with per-peer counters
  (`daita_tx_padding_bytes`, etc.) exposed over an extended UAPI (`UAPI.md`, `daita-uapi` feature).
- `pcap` feature for packet capture; optional `mimalloc`/`jemalloc` allocators.

**Strengths**
- Modern async core that drops straight into a tokio application.
- Real throughput engineering: GSO/GRO + `mmsg` + pooled buffers.
- The `DeviceTransports` trait is exactly the abstraction a mesh/obfuscation layer needs.
- DAITA gives a ready-made, research-backed anti-traffic-analysis layer.
- Audited, security-hardened relative to upstream, broad platform matrix incl. Windows.

**Weaknesses / limitations**
- Still the WG handshake — same fingerprintable on-wire framing (DAITA mitigates *timing/size*,
  not the protocol signature itself); no built-in protocol mimicry/obfuscation.
- No post-quantum security.
- No peer discovery / mesh / NAT traversal — still 1:1 WG semantics; you bring the control plane.
- tokio + GSO/GRO + maybenot is a heavier dependency surface than BoringTun.

**What could be done better (for our goals)**
- *Anti-DPI*: combine DAITA with an actual transport-obfuscation layer behind `DeviceTransports`
  (e.g. encode WG inside QUIC/HTTPS-looking framing) to defeat protocol-signature DPI.
- *Decentralization*: build the mesh control plane (discovery, NAT hole-punching, relay
  fallback) on top — gotatun gives you the data plane only.
- *Encryption*: layer Rosenpass-style PQ PSK injection (it already supports PSK).

**Reusable ideas/components**
- **Take gotatun as our data-plane baseline** rather than BoringTun — async, faster, audited.
- `device/transports.rs` `DeviceTransports`/`UdpTransportFactory`/`IpSend`/`IpRecv` traits:
  our seam for obfuscated transports and in-process testing.
- `packet/pool.rs` `PacketBufPool` + `ReturnToPool` recycling pattern.
- `udp/socket/linux.rs` GRO/GSO + `recvmmsg`/`sendmmsg` implementation — copy the cmsg handling.
- `device/daita/` + the **`maybenot`** crate for traffic-shaping defenses; the extended UAPI
  keys are a clean way to configure per-peer defenses.
- The pluggable-AEAD pattern in `crypto.rs` (cfg-gated `aws-lc-rs` vs `ring`).
- `packet/` typed decoders (`Decoder`/`PoD`, zerocopy) for safe packet introspection.

### BoringTun vs gotatun — the differences that matter
| Aspect | BoringTun | gotatun |
|---|---|---|
| IO model | sync, thread-per-core + epoll/kqueue, `Lock<Device>` | async tokio tasks, per-peer state |
| UDP path | one packet per syscall | `recvmmsg`/`sendmmsg` + UDP GRO/GSO |
| Allocation | per-packet `Vec` | pooled/recycled `BytesMut` (`PacketBufPool`) |
| AEAD backend | `ring` only | `aws-lc-rs` (default) or `ring`, compile-time |
| Transport | hardwired UDP + TUN | `DeviceTransports` trait (pluggable) |
| Anti-traffic-analysis | none | DAITA via `maybenot` (padding/decoy/delay) |
| License | BSD-3 | MPL-2.0 |
| Crypto core | shared `noise/` | same `noise/` lineage, hardened (cookie src-port) |

Net: gotatun is BoringTun's `noise/` brain on a faster, more flexible, defense-aware body.

---

## 3. Rosenpass

**What it does**
A **post-quantum-secure key-exchange daemon** that does *not* replace WireGuard — it
performs a PQ handshake out-of-band and feeds the resulting symmetric key into WireGuard
as its **pre-shared key (PSK)**, giving "hybrid" classical+PQ security. Refreshes the PSK
about every two minutes.

**Language / license**
Rust workspace (`rosenpass`, `ciphers`, `cipher-traits`, `oqs`, `secret-memory`,
`wireguard-broker`, `rp` frontend, etc.). **MIT OR Apache-2.0**. Uses `liboqs` via `oqs-sys`.
Ships a ProVerif symbolic security analysis (`analysis/`, `analyze.sh`) and a whitepaper.

**Protocols & crypto primitives**
A custom KEM-based handshake (a Noise-like construction designed for PQ), not Noise IK:
- **Static KEM**: **Classic McEliece 460896** (`rosenpass_oqs::ClassicMceliece460896`,
  conservative code-based KEM with huge public keys) — used for long-term peer identity.
- **Ephemeral KEM**: **Kyber-512 / ML-KEM** (`rosenpass_oqs::Kyber512`, or `libcrux-ml-kem`
  behind a feature flag) — used for forward secrecy each handshake.
  (Selection in `ciphers/src/lib.rs`.)
- **AEAD**: ChaCha20-Poly1305 (RustCrypto or libcrux); **XChaCha20-Poly1305** for biscuits.
- **Hash/KDF**: keyed BLAKE2b / SHAKE256 with a typed **hash-domain-separation** system
  (`ciphers/src/hash_domain.rs`, `rosenpass/src/hash_domains.rs`).
- **Biscuit** mechanism (`msgs.rs`, `protocol/cookies.rs`): an encrypted, stateless responder
  token (like WG's cookie) so the responder keeps no per-handshake state until validated —
  DoS resistance with PQ-sized messages.

**Architecture / how it works**
- Core protocol is a **sans-IO `CryptoServer` + `poll()` state machine** (`protocol/mod.rs`):
  you call `handle_msg`, then `poll` for a `PollResult` listing prescriptive actions; you read
  the established key via `CryptoServer::osk` (output shared key). Time-based events are driven
  through `poll`. Mirrors BoringTun's sans-IO philosophy.
- **Zerocopy "lens" wire format** (`msgs.rs`): messages are views over `&mut [u8]` via the
  `zerocopy` crate (`Envelope<M>` with `msg_type`, payload, `mac`, `cookie`) — no serde,
  no allocation.
- The runnable daemon `app_server.rs` uses **`mio`** (epoll) UDP sockets + `signal-hook-mio`.
- **WireGuard broker** (`wireguard-broker/`): a separate, privilege-separable component that
  actually installs the derived PSK into a WireGuard interface, with backends for native `wg`
  CLI, Linux **netlink**, and a custom Unix-socket protocol. Each peer maps to a broker peer;
  on each successful exchange the new PSK is pushed to the broker.
- **`secret-memory`** crate: secrets stored in `memfd_secret`/`mlock`'d memory with `zeroize`,
  guarded allocators (custom `memsec` fork) — strong secret-hygiene discipline.
- The `rp` frontend wires Rosenpass + WireGuard into a turnkey VPN (runs as root, one interface).

**Strengths**
- **Post-quantum, hybrid-secure** today, layered *on top of* unmodified WireGuard via PSK —
  zero changes to the proven WG data path, so PQ adds no data-plane risk.
- Formally analyzed (ProVerif) with a published whitepaper; conservative crypto choices
  (McEliece for identity, Kyber/ML-KEM for FS).
- Excellent secret-memory hygiene (`secret-memory`, `zeroize`, `memfd_secret`).
- Clean sans-IO `CryptoServer` and zerocopy lens message handling.
- Broker design cleanly separates "key exchange" from "privileged key installation."

**Weaknesses / limitations**
- Control-plane only — does not move data packets; needs WireGuard (or another consumer) underneath.
- Classic McEliece public keys are very large (hundreds of KB), inflating identity distribution.
- Two-daemon, two-UDP-port deployment (`rp` uses port N and N+1); `rp` runs as root and owns one interface.
- mio/blocking model; not a tokio-native library you can embed trivially.
- No mesh/discovery of its own; it inherits WG's manual peering.

**What could be done better (for our goals)**
- *Decentralization*: marry the PQ exchange with our mesh discovery so PQ identities are
  distributed automatically (McEliece key size makes this a real design constraint).
- *Performance*: the PQ handshake is heavier; cache/reuse sessions and keep the 2-minute
  rekey decoupled from the data path (as it already is).
- *Integration*: rather than a separate daemon, embed the `CryptoServer` and feed our own
  data plane's PSK directly (skip the WG broker hop) for a single-process design.

**Reusable ideas/components**
- The **whole "PQ exchange → PSK injection" architecture**: keep our (gotatun-derived) WG-style
  data plane and bolt PQ security on via the PSK slot. This is the single most important takeaway
  for PQ.
- `cipher-traits` (`Kem`, `Aead`, `KeyedHash` traits) + `ciphers`/`oqs` — a clean abstraction to
  swap KEMs (McEliece, Kyber/ML-KEM, libcrux) without touching the protocol.
- **`secret-memory`** crate (memfd_secret/mlock/zeroize) — adopt directly for all key material.
- The **biscuit** stateless-responder pattern for DoS resistance with large PQ messages.
- `hash_domain.rs` typed hash-domain-separation for KDF safety.
- The `wireguard-broker` privilege-separation model (and its netlink PSK-setting backend).
- The `zerocopy` lens message pattern (`Envelope<M>`) for allocation-free wire formats.
- The sans-IO `CryptoServer::poll`/`PollResult` driver shape.

---

## 4. fastd (neocturne)

**What it does**
A small, fast, very configurable C VPN daemon that tunnels IP packets (TUN) or Ethernet
frames (TAP) over UDP, with **pluggable cipher/MAC "methods"** and support for **1:1, 1:N,
and meshed** topologies. Widely used as the transport for the **Freifunk** community mesh networks.

**Language / license**
C (with x86 SIMD asm for ciphers), built with **Meson**. **BSD-2-Clause**. Runs on Linux,
FreeBSD, OpenBSD, macOS (Android code present but unmaintained). Bundles a vendored `libmnl`.

**Protocols & crypto primitives**
- **Handshake: FHMQV-C** (Fully Hashed Menezes–Qu–Vanstone, implicitly authenticated DH) over
  **Curve25519** (`libuecc`), giving mutual implicit auth + PFS in a 3-message exchange
  (`protocols/ec25519_fhmqvc/`, `doc/source/crypto/fhmqvc.rst`). Each side has a long-term and
  a per-handshake ephemeral keypair; `d|e = SHA256(Y|X|B|A)` split into two 128-bit halves.
- **KDF**: HKDF-SHA256 (`hkdf_sha256.c`); a TLV authentication tag (HMAC-SHA256 over the whole
  handshake TLV list) prevents downgrade/tampering of later handshake fields.
- **Data "methods"** (compile-time selectable, `methods/`): ciphers **Salsa20 / Salsa20-12**
  (NaCl + XMM asm) and **AES-128-CTR** (OpenSSL); MACs **UMAC (uhash)**, **GMAC (ghash**, with
  PCLMULQDQ asm), **Poly1305**. Recommended method is `salsa2012+umac`. Also `null` (auth-only,
  no encryption) and `null@l2tp`.
- Distinct **encrypt-only vs authenticate-only** ("composed") method providers — you can
  authenticate without encrypting (e.g. for public mesh backbones).

**Architecture / how it works**
- Single-process, **single-threaded event loop** over `epoll` (`polling.c`, with a portable
  fallback) plus an async/worker offload path (`async.c`) for blocking/slow work like
  resolution and `on-verify`.
- **Method abstraction** (`method.h`, `crypto.h`): ciphers, MACs and methods are registered as
  vtables (`fastd_cipher_t`, `fastd_mac_t`, `fastd_method_provider_t`) chosen at runtime by name,
  with multiple implementations per primitive (generic vs SIMD) negotiated at startup. This is a
  clean crypto-agility design in C.
- **Topology & dynamic peers**: `mode` can be TUN, TAP, or **MULTITAP**; supports static peers,
  **peer groups** (`peer_group.h`) with per-group limits, and **dynamic peers** authenticated by
  an external **`on-verify`** shell command (`fastd.h`) — i.e. accept any peer whose key passes a
  policy hook, then drop it into a configured group. There are also `on-connect`/`on-establish`
  hooks. This is fastd's mesh story: decentralized, policy-driven peer admission rather than a
  fixed peer list.
- Peers are looked up by a **hash table** (`peer_hashtable.c`) and timers via a priority queue
  (`pqueue.c`).
- **L2TP kernel offload** (`offload/l2tp/`): after the fastd handshake, the data path can be
  handed to the **kernel's L2TP** implementation (`null@l2tp` method) so bulk forwarding bypasses
  userspace entirely — handshake in userspace, data plane in kernel. Major throughput technique.
- Drops privileges / uses Linux capabilities (`capabilities.c`).

**Strengths**
- **Native mesh/multi-peer support** with dynamic peer admission via `on-verify` — closest of the
  four to our "P2P mesh" target.
- **Crypto agility done well**: runtime-selectable methods with SIMD-accelerated implementations.
- **Kernel offload (L2TP)** pattern: userspace control plane, kernel data plane for speed.
- Auth-only modes for trust-but-not-confidential mesh backbones; very small footprint, embedded-friendly.
- Flexible topology modes (TUN/TAP/multitap), peer groups with policy.

**Weaknesses / limitations**
- **Written in C with hand-asm** — memory-safety risk, exactly what we avoid by choosing Rust.
- FHMQV-C is less analyzed and less standard than Noise IK; the underlying proof was found faulty
  (though believed safe in practice); not a modern default.
- Ciphers (Salsa20/12, AES-CTR) and MACs are dated vs ChaCha20-Poly1305 AEAD; AES path warns of
  cache-timing side channels without AES-NI.
- No post-quantum security; no built-in anti-DPI/obfuscation.
- Single-threaded data plane (mitigated only by the L2TP offload).

**What could be done better (for our goals)**
- *Encryption*: replace FHMQV-C + Salsa/UMAC with a modern Noise-style AEAD handshake (and add PQ).
- *Performance*: the L2TP-offload idea is great, but in Rust we'd prefer GSO/GRO (gotatun-style)
  or a kernel-WG handoff rather than L2TP specifically.
- *Anti-DPI*: nothing here; the mesh exposure is large, so obfuscation matters.

**Reusable ideas/components**
- **The dynamic-peer / `on-verify` admission model** — the key mesh idea: don't hardcode peers,
  authenticate-then-admit via a policy hook, and bucket peers into **peer groups** with per-group
  limits. Reimplement this as a Rust trait/callback for our control plane.
- **Runtime crypto-agility via named "methods"** (cipher × MAC combinations) with multiple
  backend implementations — informs how we expose pluggable suites.
- **Kernel-offload-after-handshake** pattern: do the handshake/control in our process, then hand
  the bulk data plane to a faster path (kernel WireGuard, GSO/GRO, or XDP) — separation of
  control and data plane.
- **Auth-only / encrypt-only split** methods — useful for mesh backbone links where confidentiality
  isn't required but authenticity is.
- TUN/TAP/multitap mode abstraction and the peer hashtable + timer priority-queue structures.

---

## Cross-cutting design notes for our Rust mesh VPN

1. **Data plane**: start from **gotatun** (async tokio, GSO/GRO, pooled buffers, `DeviceTransports`
   trait, DAITA) rather than BoringTun, but keep BoringTun's sans-IO `Tunn`/`TunnResult` discipline.
2. **Post-quantum**: adopt **Rosenpass's "PQ exchange → PSK" architecture** and its `cipher-traits`/
   `secret-memory`/biscuit components; PQ rides in the PSK slot, leaving the WG data path untouched.
3. **Mesh/P2P**: take **fastd's dynamic-peer `on-verify` + peer-group admission** model as the
   control-plane pattern (we still must add discovery, NAT traversal, and relay fallback ourselves —
   none of the four ship that).
4. **Anti-DPI**: DAITA/`maybenot` (size/timing) **plus** a real transport-obfuscation layer behind
   gotatun's `DeviceTransports` trait (protocol mimicry), since all four leave WG/FHMQV framing
   fingerprintable.
5. **Secret hygiene & crypto agility**: Rosenpass's `secret-memory` + trait-based primitives and
   fastd's named-method runtime selection together inform a safe, swappable crypto suite.
