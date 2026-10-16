# Roadmap

Where yip is and where it's going. Honest about status — nothing here is checked off unless
it's merged with tests. Dates are deliberately absent; this is a pre-1.0 project with one
maintainer.

## Done (merged, with integration tests on both I/O drivers)

- **Data plane + FEC transport** — encrypted L2/L3 tunnel over systematic Reed–Solomon-FEC
  UDP transport, streaming rateless RLNC (fountain coding), poly-vector SIMD Galois Field engine
  (GFNI, AVX-512BW, AVX2, SSSE3, ARM NEON, Wasm SIMD128), batched `sendmmsg`/`recvmmsg`,
  `UDP_SEGMENT` GSO, and 64 KB TUN GSO/GRO superpacket offload.
- **Multi-core throughput & kernel-bypass** — multi-queue TUN worker sharding (`IFF_MULTI_QUEUE`),
  core-pinned flow hashing, lock-free chunked nonce dispensers, circular replay windows, and
  AF_XDP zero-copy driver (over 40 Gbps aggregate throughput, 5.3x higher goodput than kernel
  WireGuard under 5% packet loss).
- **Control plane & mesh routing** — multi-peer routing, self-certifying key-derived addresses
  (`fd00::/8`), rendezvous NAT hole-punching with blind relay, CA-gated gossip discovery with
  relayed convergence, dynamic peer management, and headless daemon operation via UNIX domain
  control socket (`yip-ctl`).
- **Anti-DPI transports & verification panel** — 4 transport modes (`raw/obf`, `quic`, `tls`,
  `relay` Trojan front), REALITY TLS 1.3 browser mimicry with ML-KEM-768 hybrid key exchange,
  authenticated relay discriminator (constant-time BLAKE2s-MAC), and an industry-standard
  4-engine DPI verification panel (nDPI, tshark, Suricata, Zeek) with CI gating.
- **Session security & anti-replay** — ~120 s rekey with epoch overlap; per-epoch data-plane
  obfuscation key rotation; handshake anti-replay (TAI64N freshness gating); signed rendezvous
  registration; authenticated endpoint roaming.
- **Quality gates & maintainability** — 90% control plane line-coverage floor in CI; widened
  mutation testing (`cargo mutants`) across logic crates; modularized `peer_manager` and
  `yip-utls/src/stream/`.

## Now

- **Mutation test hardening** — kill remaining surviving mutants across `yip-obf`, `yip-membership`,
  `yip-rendezvous`, `yip-crypto`, `yip-wire`, and `yip-transport` to reach zero missed mutants
  across the core logic crates.
- **Real WAN benchmark harness (#109)** — reproducible WAN benchmark testing under real-world
  internet topologies (loss, jitter, reordering, bandwidth throttling).

## Next

- **Throughput 4c: MTU-aware packetization (#59)** — dynamic MSS clamping and adaptive path
  MTU discovery.
- **SipHash header-auth optimization (#58)** — streaming and SIMD acceleration for wire header
  authentication.
- **REALITY P256/P384 server-side KEX + HTTP/2 decoy (#84)** — broadening cipher suites and
  HTTP/2 decoy multiplexing.
- **Traffic-analysis defense** — jittered cover traffic cadence and packet size shaping.

## Later

- **Post-quantum hybrid handshake** — Classic McEliece + ML-KEM hybrid exchange behind the
  direct UDP datapath.
- **Multi-platform native drivers** — macOS (NetworkExtension / utun) and Windows (Wintun).

## Not goals (for now)

- A hosted service, a GUI app, or mobile clients — yip is the protocol and daemon first.
- Always-on anonymity — traffic-analysis defense and onion routing are opt-in dials, not
  costs everyone pays.

The full backlog lives in the [issue tracker](https://github.com/femboyisp/yip/issues).
