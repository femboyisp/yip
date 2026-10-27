# Roadmap

Where yip is and where it's going. Honest about status — nothing here is checked off unless
it's merged with tests. Dates are deliberately absent; this is a pre-1.0 project with one
maintainer.

## Done (merged, with integration tests on both I/O drivers)

- **Data plane + FEC transport** — encrypted L2/L3 tunnel over systematic Reed–Solomon-FEC
  UDP transport, streaming rateless RLNC (fountain coding), poly-vector SIMD Galois Field engine
  (GFNI, AVX-512BW, AVX2, SSSE3, ARM NEON, Wasm SIMD128), batched `sendmmsg`/`recvmmsg`,
  `UDP_SEGMENT` GSO, 64 KB TUN GSO/GRO superpacket offload, deadline-based FEC reassembly eviction
  with trailing symbol tombstoning, zero-allocation egress buffer scavenging under obfuscation,
  wire-auth 64-bit counter-bound FEC reassembly with pre-AEAD anti-replay gating, and
  bidirectional flow accounting in the traffic classifier (#11).
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
- **Real WAN benchmark harness & ephemeral AWS multi-region testing (#109)** — automated, reproducible
  WAN benchmarking suite across cloud VPSes and ephemeral multi-region AWS EC2 instances, comparing
  baseline IP, yip (RS-FEC), WireGuard, and OpenVPN under real network conditions and injected packet
  loss, with scheduled GitHub Actions automation.
- **Post-quantum hybrid handshake (`Noise_IKpsk2` + ML-KEM-512) (#9b, PR #152)** — single-RTT
  quantum-resistant key exchange pairing FIPS 203 ML-KEM-512 with classical X25519 DH. Fits strictly
  under `OBF_MTU_BUDGET = 1200` bytes with deadlock-free outer framing, FIPS 203 Section 7.2 modulus
  validation, IND-CCA2 implicit rejection, zero allocations in the data plane, and ~120s ephemeral
  rotation.
- **Phase 3 rigor, benchmarks & wire format ceremony (#148)** — deterministic P99 tail latency
  and jitter chart (`assets/bench-latency-jitter.svg`) visualizing flat ~62ms latency under loss,
  deterministic wire format and cryptographic ceremony diagram generator (`crates/yip-bench/generate-wire-format.py` ->
  `assets/wire-format.svg`) with CI gating, 100.0% mutation test score across 1,020 mutants (0 missed
  across `yip-wire`, `yip-crypto`, `yip-transport`, `yip-obf`, `yip-membership`, `yip-rendezvous`),
  and academic literature review synthesized in `README.md`.
- **MTU-aware packetization & in-band PLPMTUD (#59)** — effective shard length wire-trimming ($L_{\text{eff}} = \min(\text{object\_size}, \text{symbol\_size})$)
  collapsing 1400–1500B packets into $k = 1$ single-symbol objects, TUN device `SIOCSIFMTU` configuration (`--mtu 1400`),
  and RFC 8899 PLPMTUD 4-tier probe ladder (`1120`, `1320`, `1400`, `1530`) with roaming and blackhole floor fallback.
- **SipHash-1-3 & zero-alloc wire header auth (#58)** — streaming multi-slice SipHash-1-3 coverage authentication
  and stack-allocated keystream generation (`header_mask`), slashing scalar MAC CPU by ~45% and eliminating
  intermediate heap allocations on data-plane framing.
- **Data-plane windowed loss, 8-contender harness & bench polish (#11)** — exact per-class windowed loss fractions ($L_{\text{class}} = M_{\text{class}} / S_{\text{class}}$ in $(H_{\text{prev}}..H_{\text{curr}}]$), 4096-entry synchronized loss detection window matching sent-log capacity, bounded spurious NACK drop invariants, 8-contender comparison matrix and netns runners (yip, WireGuard, AmneziaWG, OpenVPN, n2n, ZeroTier, Tailscale, NetBird), dual TCP & UDP-under-loss evaluation, and configurable 1000-ping variance tightening.
- **Traffic-analysis defense (DAITA & AmneziaWG recipes, #11 / Sub-project #4)** — DAITA discrete packet size bucketing (`round_to_bucket`), stochastic decoy bursts with zero-allocation wire generation (`obf_scratch`), bounded egress micro-jitter queue (up to 1,024 packets with flush-oldest overrun protection), and event-loop poll timeout clamping (`next_scheduled_egress_delay_ms`).
- **Zero-friction distribution & packaging (#147)** — standalone, statically linked musl binaries (`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`) with zero dynamic runtime dependencies, multi-arch GitHub Actions and Forgejo automated release pipelines generating tarballs with detached `SHA256SUMS`, production multi-stage Dockerfile (`ghcr.io/femboyisp/yipd` and `yip-rendezvous`), turnkey POSIX `install.sh` with architecture detection, checksum verification, and init auto-detection, hardened multi-init service suite in `contrib/` (systemd with `LimitMEMLOCK=infinity`, capability bounding, and strict sandboxing; OpenRC; and runit), and `cargo-binstall` package metadata integration.
- **Per-core UMEM slab allocation & AF_XDP multi-worker scaling (#172)** — isolated `UmemSlab` partitions eliminating centralized free-list contention, lock-free batch chunk recycling between Completion and Fill rings, vectorized ring slice copying (4,057 Mops/s), and linear multi-worker scaling reaching 19.60 Gbps on 8 cores.
- **Zero-allocation FEC reassembler hot path (#171, PR #176)** — eliminated per-packet heap allocations, `HashMap` lookups, and intermediate `Vec<Vec<u8>>` cloning in `FecReassembler::push()`. Pre-allocated contiguous object buffers with a 256-bit bitset (`seen_mask: [u64; 4]`), zero-alloc in-place systematic delivery via buffer slicing (`mem::take` & `truncate`), in-place Cauchy Reed-Solomon packet loss repair (`reconstruct_missing_sources` & `decode_source_into`) avoiding `Vec<Vec<u8>>` heap matrix allocations, and bounded flat open-addressing slot table (`ObjectTable`) with SplitMix64 fast hashing and backward-shift deletion with zero tombstones. Achieved 3.1x faster reassembly on clean $K=1$ (117 ns), 4.0x on clean $K=3$ (173 ns), and 1.65x on packet loss recovery (632 ns).
- **Comprehensive documentation overhaul & landing page architecture (#170, PR #175)** — transformed repository landing page into an accessible, structured guide with clear "What is yip?", "When to use / when not to use", simplified quickstart, audience-specific pathways, terminal telemetry demo GIF, sanitized production-grade zero-trust CA key management, standardized default port 443 (with 8443 unprivileged fallback), best-of-3 AWS WAN benchmark measurements, and 6 standalone guides in `docs/` (`01-getting-started.md`, `02-configuration.md`, `03-architecture.md`, `04-security-and-threat-model.md`, `05-benchmarking-and-performance.md`, `06-troubleshooting.md`, plus `motivation.md`).

## Now

- **Multi-platform native drivers** — macOS (NetworkExtension / utun) and Windows (Wintun).

## Next

- **REALITY P256/P384 server-side KEX + HTTP/2 decoy (#84)** — broadening cipher suites and HTTP/2 decoy multiplexing.

## Later

- **Onion routing / multi-hop mixnet extensions** — multi-hop anonymity overlays.

## Not goals (for now)

- A hosted service, a GUI app, or mobile clients — yip is the protocol and daemon first.
- Always-on anonymity — traffic-analysis defense and onion routing are opt-in dials, not
  costs everyone pays.

The full backlog lives in the [issue tracker](https://github.com/femboyisp/yip/issues).
