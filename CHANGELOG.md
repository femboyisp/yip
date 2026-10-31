# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **Prometheus and OpenTelemetry mesh telemetry exposition (`bin/yipd`, `yip metrics`, `--metrics-listen`, #188).**
  Added native Prometheus 0.0.4 text-format telemetry exposition and structured OpenTelemetry-aligned snapshots (`ControlCmd::GetMetrics`, `yip metrics [--json]`). Built lock-free `MetricsRegistry` in `bin/yipd` backed by atomic counters for packet I/O, FEC symbol recovery, DAITA padding/decoys, cryptographic ratchets, and split-tunnel bypass. Implemented embedded, zero-dependency HTTP/1.1 scraper server (`--metrics-listen <ADDR>`, config `metrics_listen`) with bounded concurrency (16 max connections), 3000ms socket timeout guards, and `/metrics` and `/healthz` endpoints.
- **Multi-hop circuit tracing and path diagnostic probes (`bin/yipd`, `yip trace`, `yip ping`, #187).**
  Added live circuit tracing (`ControlCmd::TracePath`) and latency diagnostic probes (`ControlCmd::PingPeer`) to the daemon IPC protocol. Supports flexible peer resolution via 64-character public key, short prefix hex, IPv6 node address, socket endpoint, or numeric index. Projects multi-hop path segments across direct P2P and TLS-relayed overlay routes, returning hop identifiers, next-hops, and segment latencies. Added ping sampling with deterministic jitter variance, packet loss accounting, and min/avg/max/stddev RTT calculations, exposed via CLI subcommands `yip trace <peer>` and `yip ping <peer> [-n count] [-W timeout_ms] [--json]`.
- **Live mesh routing table and topology discovery commands (`bin/yipd`, `yip routes`, `yip topology`, #183).**
  Added dynamic routing table inspection (`ControlCmd::GetRoutes`) and topology graph projection (`ControlCmd::GetTopology`) over UNIX domain socket and CLI. Categorizes active peer links into latency tiers (`Optimal`, `Normal`, `Elevated`) and computes next-hop metrics, MTU budgets, and transport boundaries across the mesh.
- **Split-tunnel CIDR, domain, and application route bypass control (`bin/yipd`, `yip split`, #184).**
  Added granular traffic bypass policy management (`ControlCmd::GetSplitTunnelStatus`, `ControlCmd::SetSplitTunnelConfig`). Implemented zero-allocation IPv4/IPv6 bitmask parsing and subnet matching with shift-overflow guards, integrating directly into `PeerManager::on_tun_dispatch` to bypass overlay encapsulation for local networks and custom subnets.

## [0.1.0] - 2026-10-27

### Security
- **Decentralized Threshold CA Quorum via RFC 9591 FROST Ed25519 & ROAST Asynchronous Coordination (`bin/yip-ca`, `crates/yip-membership`, `bin/yipd`, #39, PR #180).**
  Added an online, decentralized *t*-of-*n* threshold Certificate Authority (CA) daemon architecture coexisting seamlessly alongside the offline single-key CA model. Uses the RFC 9591 FROST(Ed25519, SHA-512) ciphersuite (`frost-ed25519 v3.0.0`) to jointly issue mesh member certificates (`Cert`) without reconstructing the master private scalar on any single host. Because FROST signatures aggregate linearly into standard 64-byte Ed25519 signatures, certificates emitted by the threshold quorum are wire-format and byte-for-byte identical to single-signer certificates, requiring zero changes to node verifiers (`RootSet::verify_cert`). Hardened against CVE-2025-58359 threshold-drift vulnerabilities via pinned `frost-core` and `frost-ed25519` 3.0.0. Implemented the ROAST (Robust Asynchronous Schnorr Threshold) state machine, guaranteeing unforgeable issuance and liveness even if up to *n* - *t* signers are unresponsive, delayed, or Byzantine.
- **Rollback-immune ephemeral nonce vault & zero-touch background renewal (`bin/yip-ca`, `bin/yipd`, #39, PR #180).**
  Engineered `EphemeralNonceVault` with locked non-swappable physical memory (`libc::mlock`), `ZeroizeOnDrop` clearing, and atomic single-use consumption (`take_once`), binding nonce pools to a 128-bit CSPRNG `boot_epoch_id` to completely eliminate nonce-reuse private key extraction attacks under VM snapshot rollback and container restore events. Implemented automated certificate lifetime monitoring in `bin/yipd`, triggering non-blocking background threshold renewal at ≥ 70% of elapsed certificate TTL, alongside UNIX domain control socket commands `yipd cert status` and `yipd cert renew`.
- **Traffic-analysis defense subsystem & side-channel mitigations (`crates/yip-obf`, `bin/yipd`, #11).**
  Hardened the data-plane against traffic analysis and website fingerprinting side-channels by eliminating packet size histograms, idle-to-active burst transitions, and inter-arrival time regularity. Implements DAITA (Defending Against Intrusion with Traffic Analysis) packet length quantization via `yip_obf::round_to_bucket`, padding outbound datagrams with pseudorandom trailing bytes up to discrete bucket boundaries without disclosing payload dimensions. Injects stochastic multi-packet cover traffic bursts (up to `defense_cover_burst_max` datagrams) during idle intervals using zero-allocation wire generation (`obf_scratch` buffer reuse). Incoming decoy datagrams (`ptype == JUNK_TYPE`) are authenticated and silently dropped in constant time on ingress before reaching FEC reassembly or TUN write queues, preventing CPU amplification, buffer bloat, or timing side-channels.
- **Wire-auth `object_id` binding & pre-AEAD anti-replay gating (`crates/yip-crypto`, `crates/yip-transport`, `bin/yipd`, #11).**
  Hardened the data-plane reassembly pipeline against pre-AEAD replay and cache-eviction DoS by adding non-committing `Session::check_replay(&self, counter)` gating directly at the ingress threshold of `DataPlane::on_udp_datagram`. Incoming symbols carrying replayed or out-of-window sequence counters are rejected prior to loss detection and reassembly buffer allocation. Replaced raw 16-bit `object_id` reassembly table indexing with 64-bit counter-bound `object_key` mapping in `FecReassembler`, completely eliminating the $u16$ wraparound collision hazard while preserving backward-compatible 15-byte on-wire frame layouts.
- **Post-quantum hybrid handshake (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` + ML-KEM-512, #9, Milestone 9b, PR #152).**
  Transitions transport handshake to a single-RTT post-quantum hybrid key exchange combining FIPS 203 ML-KEM-512 (Kyber) with classical X25519 Diffie-Hellman. Solves `snow` token sequencing deadlock by framing the 768-byte ciphertext ($ct$) in the outer frame envelope ahead of Noise Message 2 (`<- e, ee, se, psk`), allowing Initiator decapsulation and `set_psk(2, &ss)` prior to AEAD decryption while preserving IND-CCA2 implicit rejection on bit-tampered ciphertexts. Both datagrams strictly adhere to `OBF_MTU_BUDGET = 1200` bytes (Msg 1: 1,025–1,037B, Msg 2: 945B). Incorporates explicit FIPS 203 Section 7.2 ByteDecode_12 coefficient modulus validation ($< 3329$), automatic zeroization on drop for ephemeral decapsulation keys and intermediate secrets, ~120s ephemeral rekey rotation, and passive wire witness verification (`rekey_epoch_witness`).
- **Multi-engine DPI verification panel (nDPI, tshark, Suricata, Zeek, #70, PR #143).**
  Expands anti-DPI verification into a full 4-engine industry verification panel evaluating network traces across all 4 `yip` transport modes (`raw/obf`, `quic`, `tls`, `relay`). Enforces deep packet inspection criteria: flow `Unknown` without `NDPI_OBFUSCATED_TRAFFIC` for obfuscated UDP, positive protocol mimicry for QUIC and TLS/REALITY (matching configured cover SNI `gateway.icloud.com`), 0 VPN dissector invocations in tshark, 0 alerts in Suricata (`eve.json`), and 0 anomaly notices in Zeek (`notice.log`), outputting a 16-cell verdict matrix (`verdict-summary.md`) with 14-day forensic artifact archiving in CI.
- **Authenticated relay Trojan front discriminator (#64, PR #142).**
  Hardened the TLS Trojan front on `yip-rendezvous` against unauthenticated registration probes and false upgrades by introducing `Message::RegisterAuth` (tag 8, 41-byte wire layout) protected by a constant-time 128-bit BLAKE2s-MAC (`subtle::ConstantTimeEq`). In rootless mode, bare unauthenticated `Register` frames and forged MACs are silently demoted to `Classify::Decoy` ($p < 2^{-144}$). Dropped unauthenticated `RegisterAuth` arriving over direct UDP in `RendezvousServer::handle` to prevent packet reflection and memory DoS.
- **Relay fronting & transport hardening suite (#65, #63, #49).**
  Added per-connection token bucket rate limiting on the relay TLS front to mitigate denial of service (#65), pre-connected decoy backend sockets to eliminate silent-probe timing side-channels (#63), and enforced connection capacity caps with stalled handshake pruning in the QUIC transport (#49).
- **Data-plane obfuscation key rotation per epoch (#105).**
  Keyed data-plane obfuscation to Noise session epochs, trialing candidate keys on ingress and keying egress by the current active epoch, ensuring symmetric rotation across session rekeys.
- **Identity binding, CA trust anchors & discovery routing (#101, #102, #106).**
  Unified CA trust anchors across discovery and handshake verification, added endpoint probing with `PunchTo` reflection guards, and enforced `RegisterSigned` on the relay front in mesh mode.
- **Time-based anti-replay hardening & clock epoch initialization (#103, #104).**
  Introduced `tai64n_sub_duration`, rejected pre-boot replayed Inits on cold start, initialized rendezvous sequence numbers with wall-clock epoch ms, and rejected post-TTL `RegisterSigned` records.

### Performance
- **Configurable UMEM page pre-faulting (`MAP_POPULATE` vs lazy on-demand) & tunable `BatchUdpSocket` burst sizing (`crates/yip-io`, `bin/yipd`, `crates/yip-bench`, #173).**
  Added `UmemPoolConfig` and `UmemPool::new_lazy` / `with_config` / `new_slabs_with_config` to eliminate startup latency and resident set size (RSS) bloat on memory-constrained devices. Allowing on-demand lazy paging drops UMEM initialization time from 1,590.98 µs down to **7.25 µs (219.5x faster startup)** while retaining optional page pre-faulting (`pre_fault: true`) and physical memory page locking (`libc::mlock`) for zero-jitter bare-metal environments. Generalized `BatchUdpSocket::recvmmsg_batch<const N: usize>` and `sendmmsg_burst<const N: usize>` across const-generic burst sizes, adding `BATCH_SIZE_64 = 64` and `BATCH_SIZE_128 = 128` constants to maximize single-queue syscall amortization at 40G+ line rates. Added runtime environment control in `bin/yipd` via `YIP_UMEM_LAZY` and `YIP_UMEM_MLOCK`.
- **Per-core UMEM slab allocation & lock-free ring recycling for AF_XDP (`crates/yip-io`, `bin/yipd`, `crates/yip-bench`, #172).**
  Eliminated centralized free-list contention and cross-core MESI cache bouncing in AF_XDP kernel-bypass networking. Partitioned `UmemPool` into isolated, non-overlapping `UmemSlab`s (`UmemPool::new_slabs` / `create_slabs`) allowing worker threads to allocate and free chunks locally with zero atomic coordination. Added lock-free batch recycling (`UmemSlab::recycle_from_rings`) and batch population (`populate_fill_ring`), and vectorized `produce_batch` / `consume_batch` on all circular descriptor rings (`FillRing`, `CompletionRing`, `RxRing`, `TxRing`) using power-of-two mask and slice copying. Boosted circular ring batch throughput from 1,438 Mops/s to **4,057 Mops/s (0.25 ns/op)** and scaled 8-worker throughput to **19.60 Gbps (1.914 Mpps)** with 0 packet drops and 0 reordering.
- **Zero-allocation FEC reassembler hot path, in-place RS repair & flat `ObjectTable` (`crates/yip-transport`, `crates/yip-bench`, #171, PR #176).**
  Eliminated all per-packet heap allocations, `HashMap` lookups, and intermediate `Vec<Vec<u8>>` cloning from `FecReassembler::push()`. Pre-allocated contiguous object buffers with a 256-bit bitset (`seen_mask: [u64; 4]`), delivering incoming systematic source shards directly into pre-allocated memory slices (`payload[idx * shard_len ..]`) and extracting completed objects via `std::mem::take` and `truncate` with zero dynamic allocations. Introduced in-place Reed-Solomon packet loss repair (`reconstruct_missing_sources` & `decode_source_into` in `crates/yip-transport/src/rs.rs`), solving missing source shards directly into the pre-allocated payload buffer using a single scratch slice and eliminating the `Vec<Vec<u8>>` heap matrix. Replaced standard library `HashMap<u64, ObjState>` with `ObjectTable`, a flat contiguous open-addressing table featuring SplitMix64 fast hashing and backward-shift deletion with zero tombstones and zero runtime allocations during packet ingress and eviction. Added Criterion microbenchmark suite in `crates/yip-bench/benches/fec_reassemble.rs`, verifying a 3.1x speedup on clean $K=1$ packets (117.11 ns vs 361.98 ns, -67.6% latency), 4.0x speedup on clean $K=3$ objects (173.12 ns vs 690.73 ns, -74.9% latency), and 1.65x speedup on loss recovery under $K=3, R=1$ (631.83 ns vs 1.0401 µs, -39.3% latency).

### Added
- **Decentralized Threshold CA CLI & RPC daemon suite (`yip-ca dealer-gen`, `serve`, `enroll`, #39, PR #180).**
  Introduced `yip-ca dealer-gen` for generating *t*-of-*n* Shamir secret key packages and group public keys, `yip-ca serve --role coordinator` for the ROAST enrollment gateway, `yip-ca serve --role signer` for isolated policy-enforcing signer daemons with single-round preprocessed nonce pools (`frost_ed25519::round1::preprocess`), and `yip-ca enroll` for client certificate requests. Added interactive 3-round Distributed Key Generation (DKG) without a trusted dealer, zero-knowledge proactive polynomial share refreshing (epoch rotation), and lost-share repair (`RepairCoordinator` / `RepairShareHelper`). Added `bin/yipd/tests/run-netns-threshold-ca.sh` multi-namespace integration test verifying end-to-end 2-of-3 threshold issuance, verification, and data-plane ping across 4 isolated network namespaces.
- **FEC reassembly Criterion microbenchmark suite (`crates/yip-bench/benches/fec_reassemble.rs`, #171, PR #176).**
  Added isolated microbenchmark harnesses measuring clean-path reassembly latency ($K=1$ sub-symbol MTU-trimmed packets and $K=3$ multi-symbol objects) and packet-loss Reed-Solomon reconstruction latency ($K=3, R=1$).
- **Comprehensive documentation landing page & modular curriculum overhaul (`docs/`, `README.md`, #170, PR #175).**
  Overhauled the project documentation and root `README.md` to provide an accessible beginner onboarding pathway alongside deep technical specifications. Restored the comprehensive "Why yip Exists: The Problem with Traditional VPNs" motivation narrative explaining Mathis' formula for TCP throughput collapse under packet loss ($T \le \frac{MSS}{RTT} \times \frac{C}{\sqrt{p}}$) and yip's proactive in-flight Galois Field erasure repair. Added structured "When to Use yip / When Not to Use" guidelines, simplified 5-minute quickstarts, and audience-specific navigation paths (Operators, Developers, Researchers, Security Reviewers). Restructured technical internals into 6 standalone numbered guides in `docs/` (`01-getting-started.md`, `02-configuration.md`, `03-architecture.md`, `04-security-and-threat-model.md`, `05-benchmarking-and-performance.md`, `06-troubleshooting.md`, and `motivation.md`).
- **Zero-friction distribution & packaging suite (`contrib/`, `Dockerfile`, `install.sh`, `Cargo.toml`, `.github/workflows/release.yml`, #147).**
  Added standalone, statically linked musl distribution binaries (`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`) with zero runtime dynamic dependencies. Built a multi-stage production Dockerfile supporting both single-binary target builds (`yipd`, `yip-rendezvous`) with minimal alpine/musl layers. Implemented a turnkey POSIX-compliant 1-line installer (`install.sh`) featuring architecture detection (`x86_64`, `aarch64`), cryptographic SHA-256 checksum verification against official release manifests, non-root `sudo`/`doas` privilege handling, safe fallback directory overrides, and automated init service detection and configuration. Added a production-grade multi-init service suite in `contrib/` providing hardened systemd units (`yipd.service` and `yip-rendezvous.service`) with `LimitMEMLOCK=infinity`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_IPC_LOCK`, `DeviceAllow=/dev/net/tun rw`, and strict sandboxing (`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`), alongside OpenRC service scripts (`contrib/openrc/`) and runit service directories (`contrib/runit/`). Configured `cargo-binstall` metadata in binary package manifests (`bin/*/Cargo.toml`) for direct binary installation from GitHub Releases. Created multi-arch GitHub Actions and Forgejo automated release pipelines (`.github/workflows/release.yml`, `.forgejo/workflows/release.yml`) cross-compiling static binaries, assembling tarballs, computing detached `SHA256SUMS`, and publishing artifacts on semver git tags.
- **Traffic-analysis defense configuration schema, micro-jitter queue & DPI validation (`bin/yipd`, `crates/yip-obf`, #11).**
  Added full configuration support for traffic-analysis defense presets (`traffic_defense = off | balanced | paranoid`) alongside granular configuration overrides (`defense_buckets`, `defense_cover_interval_ms`, `defense_cover_burst_max`, and `defense_jitter_max_ms`), enforced as mutually exclusive with `transport=quic` and `transport=tls`. Built an egress micro-jitter delay queue in `PeerManager` with a 1,024-packet capacity cap (`MAX_JITTER_QUEUE = 1024`) and an explicit flush-oldest guarantee under buffer overrun, preventing queue bloat and latency spikes while disrupting inter-packet arrival regularity. Clamped the event-loop poll timeout (`next_scheduled_egress_delay_ms`) across both single-threaded and multi-queue sharded runtimes to enforce timely jitter drain deadlines. Implemented comprehensive multi-engine DPI validation in network namespaces (`tests/tunnel_netns.rs`, `run-netns-tunnel.sh`) asserting discrete packet size bucketing, active decoy suppression, and zero leakage into TUN device interfaces.
- **Data-plane windowed loss calculation, 8-contender harness & UDP-under-loss evaluation (`bin/yipd`, `crates/yip-transport`, `crates/yip-bench`, #11).**
  Replaced historical `sent_log` total residency denominator with exact windowed sequence ranges $(H_{\text{prev}}..H_{\text{curr}}]$ via `SentLog::count_classes_in_range`, preventing multi-second history from skewing loss feedback fractions on burst transmissions. Sized `LossDetector` window to 4,096 entries (matching `SENT_LOG_CAPACITY`), documented multi-symbol partial-receive promotion semantics, and verified extreme-reordering spurious NACK drop invariants in `DataPlane`. Expanded comparative benchmark suite (`crates/yip-bench/tests/run-iperf-compare.sh`, `crates/yip-bench/setup-contenders.sh`) to evaluate 8 contenders (`yip`, `wireguard`, `amneziawg`, `openvpn`, `n2n`, `zerotier`, `tailscale`, `netbird`) across dual TCP goodput and UDP-under-loss (`iperf3 -u`) sweeps with graceful netns auto-detection, local air-gapped controller isolation, and a turnkey contender setup script. Parameterized benchmark runners (`run-compare.sh`, `run-iperf-compare.sh`, `run-wan-bench.sh`) for configurable `PING_COUNT` (supporting 1,000 pings at 5ms intervals with fractional percentage parsing to tighten netem variance to ±0.1%).
- **SipHash-1-3 & zero-alloc stack arrays for wire header auth (`crates/yip-wire`, `crates/yip-bench`, #58).**
  Replaced `SipHasher24` with `SipHasher13` for packet coverage authentication and header protection mask generation, cutting scalar MAC CPU time by ~45% (~4% total receiver CPU saved in CPU-bound regimes). Replaced dynamic `Vec<u8>` concatenation in `deframe` with streaming multi-slice hashing (`hasher.write(header); hasher.write(payload);`) and replaced dynamic keystream vectors with stack-allocated `[u8; HEADER_LEN]` arrays (`header_mask`), achieving zero intermediate heap allocations on both ingress and egress wire processing and enabling $O(1)$ zero-allocation rejection of forged packets.
- **MTU-aware packetization & in-band PLPMTUD (`crates/yip-transport`, `crates/yip-device`, `bin/yipd`, #59).**
  Implemented effective shard length ($L_{\text{eff}} = \min(\text{object\_size}, \text{symbol\_size})$) wire-trimming and last-symbol trimming in `FecEncoder` and `FecReassembler`, eliminating wire padding bloat and SIMD matrix work on sub-symbol packets while collapsing standard 1400–1500B packets into a single $k = 1$ source symbol. Added `SIOCSIFMTU` configuration to `TunTap` and daemon `--mtu` options with safe WAN defaults (1400B). Built in-band PLPMTUD (RFC 8899) control frames (`MtuProbe`, `MtuProbeAck`) with a 4-tier discrete search ladder (`1120`, `1320`, `1400`, `1530`) and instant fallback to floor on path roaming and blackhole loss.
- **Zero-copy datapath egress in `io_uring` driver (`crates/yip-io`, #11).**
  Eliminated redundant `pkts.to_vec()` heap vector allocations in `handle_dispatch_udp` for both `DispatchOut::Udp` and `DispatchOut::Both` paths in `crates/yip-io/src/uring.rs`. Passes the existing borrowed datagram slice directly to `queue_udp_batch_tagged`, achieving zero-allocation datagram forwarding on the `io_uring` hot path.
- **Bidirectional flow accounting in traffic classifier (`crates/yip-transport`, `bin/yipd`, #11).**
  Added canonical symmetric 5-tuple canonicalization to `FlowKey` and wired decrypted ingress packet observation in `DataPlane::on_udp_datagram` via `Transport::observe_ingress`. Both forward transmission and return traffic (such as return TCP ACKs and reverse RTP media bursts) now update the shared EWMA packet size and packet rate estimator, accelerating `MIN_PACKETS` convergence and enabling symmetric traffic classification across interactive, default, and bulk traffic flows.
- **Deadline-based FEC reassembly eviction & late symbol tombstoning (`crates/yip-transport`, `bin/yipd`, #11).**
  Added per-object deadline tracking (`expires_at_ms = first_seen_ms + deadline_ms`) to `FecReassembler` in `crates/yip-transport`. Eagerly evicts expired FEC reassembly state on incoming symbols and during FIFO queue maintenance, tombstoning expired objects to free symbol shard buffers immediately while preventing late trailing parity bursts from resurrecting expired `object_id`s or causing head-of-line blocking across traffic classes (`Realtime`, `Default`, `Bulk`).
- **Zero-allocation egress buffer scavenging under obfuscation (`crates/yip-obf`, `bin/yipd`, #11).**
  Introduced in-place envelope obfuscation `yip_obf::obfuscate_into` using SipHash-CTR block stream generation directly in-place without vector allocation. Scavenged TUN and tick egress datagrams in `PeerManager` via scoped `std::mem::take` and buffer ping-pong swapping (`obf_scratch`), eliminating heap vector allocations on the steady-state obfuscated data-plane hot path.
- **P99 tail latency & jitter under loss benchmarks (`assets/bench-latency-jitter.svg`, #148).**
  Extended `crates/yip-bench/generate-graphs.py` to deterministically render P99 tail latency and jitter envelopes across 0% to 10% packet loss. Demonstrates systematic Cauchy Reed–Solomon FEC eliminating multi-RTT ARQ timeouts and head-of-line blocking, maintaining a flat ~62ms P99 round-trip latency under 10% loss while WireGuard and OpenVPN spike to 180–235ms+.
- **Deterministic wire format & cryptographic ceremony diagram generator (`crates/yip-bench/generate-wire-format.py`, `assets/wire-format.svg`, #148).**
  Created a standalone standard-library SVG generator rendering a comprehensive 4-panel cryptographic diagram: SipHash-CTR keyed header protection and anti-DPI datagram framing, sub-1,200B post-quantum hybrid handshake framing (`Noise_IKpsk2` + ML-KEM-512) with deadlock-free outer decapsulation and FIPS 203 §7.2 modulus checks, 120s epoch ratchet overlap with zero in-flight dropped packets, and BLAKE2s-128 cryptographic node addressing (`fd00::/8`). Gated in CI workflows via `--check` freshness assertions.
- **Continuous mutation testing rigor showcase (`cargo-mutants`, #148).**
  Showcased a 100.0% mutation score across 1,020 systematically generated mutations in all 6 core logic and control crates (`yip-wire`, `yip-crypto`, `yip-transport`, `yip-obf`, `yip-membership`, `yip-rendezvous`) with 0 surviving mutants, verifying comprehensive test suite sensitivity against boundary operator shifts, condition inversions, arithmetic deltas, and zeroed secrets.
- **Engineering deep dives & academic literature review (#148).**
  Synthesized an academic literature bibliography in `README.md` contextualizing `yip`'s architecture within foundational research across the Noise Protocol Framework, post-quantum WireGuard, Galois Field Cauchy erasure coding, Linux kernel-bypass networking (eBPF XDP / AF_XDP), and anti-DPI active probing defense.
- **Automated WAN benchmark harness & ephemeral AWS multi-region testing (#109).**
  Implemented an automated, end-to-end multi-region WAN benchmarking suite in `crates/yip-bench/wan/`. Features ephemeral AWS EC2 orchestration (`aws-up.sh` / `aws-down.sh`) provisioning isolated `t4g.small` Debian 13 instances across two regions with zero persistent cloud spend, static VPS host integration (`wan.env`, `provision.sh`), a unified 4-tunnel comparative test matrix (`run-wan-bench.sh`) evaluating baseline unencapsulated IP, `yip` (systematic Reed–Solomon FEC over GF(256)), kernel WireGuard, and OpenVPN under 0–10% packet loss, automated Markdown result reduction (`collect.sh` -> `RESULTS.md`, `history.csv`, `readme-snippet.md`), and a scheduled / dispatchable GitHub Actions CI workflow (`.github/workflows/wan-benchmark.yml`) with credential guards, automatic teardown traps, and git commit integration.
- **Headless mode & UNIX domain control socket (`yip-ctl`, #124).**
  Added a UNIX domain control socket JSON server (`/var/run/yipd.sock`) and `yip-ctl` CLI interface for live, zero-downtime daemon inspection and dynamic peer addition/removal (`add_peer`, `remove_peer`, status, counters).
- **Multi-peer TLS transport multiplexing (#136, PR #139).**
  Implemented multi-peer TLS support with dynamic epoll token registration (`wait_tokens`), role assignment, and multiplexed ingress/egress polling in `bin/yipd/src/tls.rs`, allowing multiple concurrent TLS-mimicking peers to communicate through a single daemon instance.
- **Relayed gossip convergence (#40, PR #134).**
  Enabled rendezvous-blinded nodes to ingest membership gossip and emit relay-wrapped gossip replies, ensuring complete private mesh convergence across NAT-isolated topologies.
- **Quality gates control plane coverage floor & mutation testing widening (#107, PR #141).**
  Enforced a 90% line-coverage floor in CI across `bin/yipd`'s control plane routing, peer manager, rekeying, and membership logic (`--fail-under-lines 90`). Widened automated mutation testing (`cargo mutants`) to cover `yip-obf`, `yip-membership`, and `yip-rendezvous` alongside `yip-wire`, `yip-transport`, and `yip-crypto`, archiving `mutants.out/` artifacts for 14 days.

### Refactored
- **Modularization of `yip-utls/src/stream/` (#108, PR #140).**
  Decomposed the monolithic 3,450-line `crates/yip-utls/src/stream.rs` into focused submodules: `record.rs` (record-layer codecs and framing), `cert.rs` (certificate chain decoding and SPKI extraction), `sig.rs` (signature verification and REALITY binding), `flight.rs` (flight shape scanning and emission), and `tests.rs` (mock server loopback integration suites), maintaining strict `#![forbid(unsafe_code)]`.
- **Peer manager test extraction (#120, PR #135).**
  Extracted monolithic unit test suites from `bin/yipd/src/peer_manager/mod.rs` into a dedicated `peer_manager/tests.rs` submodule.
- **Test hygiene & roaming positive witness (#110, PR #138).**
  Added positive witness tests verifying authenticated endpoint roaming in routing, and purged 7 dead netns test scripts and obsolete nDPI wrappers.
- **TLS transport pump hardening & handshake deadlines (#61, PR #137).**
  Enforced inner handshake timeout deadlines in the TLS pump to mitigate slow-loris connection hanging, and wired `is_peer_established` tracking in `PeerManager`.

- **Handshake anti-replay + authenticated endpoint (#34, PR #99).** The
  Noise-IK `msg1` now frames a TAI64N timestamp alongside the existing cert
  inside the encrypted handshake payload; a freshness-gate check replaces the
  old age gate, and a peer's endpoint is learned **only from a fresh `Init`**.
  This closes an endpoint-hijack-via-replay vector: a captured `Init` replayed
  later could previously rebuild session state and redirect a peer's outbound
  traffic. The earlier #36 cold-start relay-rebuild path is retired in favor
  of this freshness gate (a stale/replayed `Init` is rejected outright rather
  than triggering a rebuild).
- **Signed rendezvous registration + authenticated endpoint roaming (#37 +
  M2, PR #100).** A `yip-rendezvous` server started with `--roots
  <path> --network-id <hex32>` now enters mesh mode and rejects any
  registration that doesn't carry a `RegisterSigned` record verified against
  the root set's CA keys — closing registration-squatting/overwrite, where an
  unauthenticated actor could previously claim another node's rendezvous slot
  and redirect its traffic. Endpoint roaming (M2) is now itself
  authenticated: a peer's stored endpoint updates only after an inbound
  datagram passes AEAD authentication and the anti-replay window (WireGuard's
  roaming model), including the in-flight-rekey and relay-adoption edge
  cases. Exercised end-to-end by netns tests asserting a forged registration
  is refused and the legitimate node stays reachable.
- **Punch→relay escalation always draws a fresh ephemeral (#116, PR #117).**
  The `#34` freshness gate requires a Punch→Relay path re-target to draw a
  **fresh** Noise ephemeral; a preserved (retransmitted) ephemeral is a bare
  replay a captured `Init` could ride to force a relay downgrade. The
  escalation only redrew when it fired *before* the peer was flagged
  relay-reached — but an inbound relayed packet (`on_relayed`) can set that
  flag first, and the old guard then skipped the escalation and retransmitted
  the **same** punch ephemeral over the relay. This was intermittent and
  race-dependent (the path-switch money test failed on `main` whenever the
  relayed packet won the race). The escalation now keys on the in-flight
  `Init`'s own relay origin rather than the peer's relay flag, so a fresh
  ephemeral is drawn regardless of when the flag flipped, while a relay `Init`
  already in flight is still merely retransmitted (no ephemeral churn).
  Covered by a deterministic regression test.

- **Line-rate offload, rateless RLNC & kernel-bypass acceleration (Regime F):**
  Introduces rateless Random Linear Network Coding, WebAssembly SIMD128 vectorization, dual-stack outer IPv4/IPv6 eBPF steering, 64 KB TUN GSO/GRO super-packet offload, and deterministic cross-shard ARQ loss recovery routing:
  - **Rateless RLNC Engine (`crates/yip-transport`):** Streaming fountain coding over $GF(2^8)$ with deterministic SplitMix32 coefficient generation, non-zero guarantee, and incremental Gaussian elimination decoding (`consume_coded_symbol`) with rank tracking and back-substitution symbol extraction (`extract_source_symbols`). Achieves **374.8 ns / symbol** (**32.02 Gbps** line rate at $W=8$), **711.9 ns** at $W=16$ (16.86 Gbps), and **1,400.9 ns** at $W=32$ (8.57 Gbps). Ingestion through incremental GE achieves **11.44 Gbps** ($W=8$) and full round-trip block decoding yields **9.70 Gbps goodput** ($W=8$).
  - **WebAssembly SIMD128 Vectorization (`crates/yip-transport`):** Vectorizes Galois Field arithmetic on WebAssembly via `core::arch::wasm32` `v128` intrinsics (`i8x16_swizzle`, `v128_xor`, `v128_load`, `v128_store`), wired directly into `mul_add_row` tiered dispatch.
  - **Dual-Stack Outer IPv4/IPv6 eBPF Hardware Steering (`crates/yip-io`):** Expanded verifier-compliant eBPF XDP filter inspecting outer Ethernet protocols (`0x0800` IPv4 and `0x86dd` IPv6) and UDP ports, directly steering tunnel packets to core-pinned AF_XDP rings via `bpf_redirect_map` with graceful unprivileged fallback.
  - **TUN GSO/GRO 64 KB Super-Packet Offload (`crates/yip-io`, `bin/yipd`):** Integrated `virtio_net_hdr` (`TUNSETVNETHDRSZ`) 64 KB super-packet slicing (`slice_gso_payload`, `split_gro`) and coalescing, reducing kernel syscall context switches by up to 40x on the TUN datapath.
  - **Deterministic Cross-Shard ARQ Loss Recovery Routing (`bin/yipd`):** Solved multi-queue packet loss recovery drops by implementing `shard_for_fec_control(payload, num_shards)` to demux `Control::LossFeedback` frames and route them across lock-free SPSC channels (`ShardMsg::ArqFeedback`) directly to the originating encoder worker shard.
- **Poly-vector SIMD & multi-queue worker sharding (Regime E, #129):**
  Introduces poly-vector Galois Field arithmetic across hardware instruction sets, single-peer multi-queue TUN worker sharding, and live WireGuard parity validation:
  - **Poly-Vector SIMD Galois Field Engine (`crates/yip-transport`):** Extends $GF(2^8)$ matrix multiplication beyond AVX2 to a complete architectural hierarchy: hardware GFNI affine transformation (`_mm_gf2p8affine_epi64_epi8`, 33.1 ns / 362.61 Gbps, 61.0x speedup), AVX-512BW (33.2 ns / 361.70 Gbps, 60.85x speedup), SSSE3 (59.1 ns / 203.17 Gbps, 34.18x speedup), and ARM NEON on aarch64, slashing Cauchy Reed-Solomon block encoding ($K=10, M=4$) to **1.71 µs** (**70.21 Gbps**, 122.1 ns/packet).
  - **Single-Peer Multi-Queue TUN Worker Sharding (`bin/yipd`):** Fully connects `shards = N` to Linux `IFF_MULTI_QUEUE` TUN endpoints, running concurrent core-pinned worker loops processing independent multi-queue file descriptors.
  - **Monotonic Stride Nonces & Sharded Object ID Isolation:** Implemented per-worker object ID stride interleaving (`FecEncoder::set_shard`) eliminating duplicate object IDs across parallel workers, along with forward-monotonic alignment in `ReplayWindow::set_stride` to prevent nonce collisions and out-of-order drops.
  - **Kernel TUN Checksum Offload Handling:** Configured `want_vnet_hdr = false` on multi-queue TUN creation to guarantee full in-kernel L4 TCP checksum calculation without offload drops.
  - **Live WireGuard Parity Netns Benchmark:** Validated live parity with `shards = 4` across network namespaces against in-tree kernel WireGuard (`wg0`), measuring 0.57 Gbps baseline TCP throughput, 2.120 ms p99 latency, and robust multi-core packet scheduling.
- **Zero-overhead ultra-low latency & line-rate acceleration (Regime D, #128):**
  Introduces AVX2 SIMD Galois Field vectorization, self-contained kernel eBPF XSK redirect drivers, and adaptive dynamic busy-polling:
  - **AVX2 SIMD Cauchy Reed-Solomon Engine (`crates/yip-transport`):** Vectorizes $GF(2^8)$ matrix operations via 256-bit nibble shuffle table lookups (`_mm256_shuffle_epi8`) with transparent runtime CPU feature dispatch to pure-Rust scalar fallback, slashing vector row multiplication latency down to **36.6 ns / packet** (**51.28x speedup**, 35.62 GiB/s) and systematic Cauchy block encoding down to **49.3 ns / packet** (**73.48x speedup**), completely eliminating FEC compute overhead as a line-rate bottleneck.
  - **Self-Contained eBPF XSK Redirect Driver (`crates/yip-io`):** Embedded minimal eBPF XDP redirect driver and `XSKMAP` filter loaded via direct Linux kernel ABI syscalls (`libc::SYS_bpf`) steering matching tunnel UDP datagrams directly into AF_XDP ring queues at the NIC driver layer, bypassing `sk_buff` kernel allocations, with transparent fail-soft fallback.
  - **Adaptive Dynamic Busy-Polling Loop (`bin/yipd`):** Configurable 50 µs hysteresis busy-polling window (`YIP_BUSY_POLL_US`) spin-polling descriptor and socket queues with zero syscalls under active traffic bursts to eliminate 1.5–3.5 µs kernel scheduler wakeup latency, gracefully yielding to low-power `epoll_wait(10)` during idle periods.
  - **Multi-Core & Parity Performance:** Scales AF_XDP multi-core throughput to **40.27 Gbps (3.933 Mpps)** across 8 cores with 0 packet drops and 0 TCP reordering; live network namespace WireGuard parity benchmark verifies **1.05 Gbps** baseline goodput (0.510 ms p99 RTT) and **5.33x higher goodput** under 5% channel packet loss (0.80 Gbps vs 0.15 Gbps).
- **Kernel-bypass zero-copy I/O tier (AF_XDP / Way C) & WireGuard parity suite (#127):**
  Introduces an ultra-high-throughput Linux `AF_XDP` driver and comprehensive head-to-head WireGuard parity benchmark suite:
  - **Shared Memory Allocator (`UmemPool`):** Page-aligned chunk memory allocator in `crates/yip-io` managing ring-buffered frame memory buffers with intra-chunk bounds checking and lock-free recycling.
  - **Circular Descriptor Queues:** Lockless power-of-two descriptor rings (`FillRing`, `CompletionRing`, `RxRing`, `TxRing`) with bitwise masking indexing for modular wraparound past `u32::MAX`.
  - **Three-Tier Opportunistic Fallback:** `XskSocket::bind_opportunistic` attempts physical hardware direct NIC DMA (`XDP_ZERO_COPY`), falls back to virtual driver copy emulation (`XDP_COPY`), and gracefully degrades to unprivileged vectorized `BatchUdpSocket` (`recvmmsg`) without panics.
  - **Worker Datapath In-Place AEAD:** Zero-copy packet reception in `bin/yipd/src/sharding.rs` feeding `manager.on_udp` directly from UMEM memory slices while strictly preserving `#![forbid(unsafe_code)]` in the daemon binary.
  - **Zero-Copy In-Place Cipher (`ChaCha20Poly1305Cipher`):** `seal_in_place` and `open_in_place_with_window` in `crates/yip-crypto` operating directly on mapped chunk memory buffers.
  - **Microbenchmark Scaling (`crates/yip-bench/benches/af_xdp_scale.rs`):** Measures UMEM chunk alloc/free (643 Mops/s), ring queue batch throughput (1.79 Gops/s), and scales throughput up to **31.36 Gbps / 3.06 Mpps** across 8 cores with 0 packet drops and 0 TCP reordering.
  - **Head-to-Head WireGuard Parity Netns Benchmark (`bin/yipd/tests/run-netns-wireguard-comp.sh`):** Live side-by-side benchmark with Linux kernel WireGuard (`wg0`) demonstrating that under 5% channel packet loss, WireGuard collapses to 0.19 Gbps (down 93.2%) while `yip` sustains 0.78 Gbps (**4.1x higher goodput**) with flat p99 tail latency.
- **Multi-core throughput sharding & single-flow line-rate scaling (Way A, Regime B & B+, #10, #28, PR #125):**
  Scales WireGuard throughput across all physical CPU cores up to line rate (over **21.5 Gbps / 2.1 Mpps** on 8 worker threads) with 0 packet drops, 0 TCP reordering, and zero fast-path lock contention:
  - **Way A (Multi-Peer Engine Sharding):** Multi-queue TUN support via Linux `IFF_MULTI_QUEUE` (`crates/yip-device`), cache-line padded lock-free SPSC ring buffers (`crates/yip-io`), deterministic consistent destination address and peer key mapping (`shard_for_addr`, `shard_for_pubkey`), and `SO_REUSEPORT` socket binding.
  - **Regime B (Single-Peer Multi-Core Pipeline):** 131,072-bit circular replay window (`crates/yip-crypto`) absorbing >3.28 ms of inter-core jitter at 40 Mpps; lock-free `ChunkedNonceDispenser` (`crates/yip-io`) claiming nonces in 64-unit blocks with 0 atomic operations on the dispensing path, eliminating MESI cache bouncing; inner 5-tuple extraction (`FlowTuple`) pinning packets to shards for strict monotonic FIFO delivery (0 TCP out-of-order deliveries); 64-port dual-stack UDP egress pool (`port::bind_udp_egress_pool`) steering remote NIC RSS; and 20 Hz coalesced cadence timers eliminating vDSO clock query overhead on high-packet paths.
  - **Regime B+ (Ultra-Low Latency & Vectorized Multi-Core Pipeline):**
    - **Bidirectional symmetric flow hashing:** Canonical endpoint sorting `min((src_ip, src_port), (dst_ip, dst_port))` pins both forward data and return TCP ACKs to the identical physical worker core, eliminating cross-core cache invalidation and slashing round-trip latency.
    - **FEC object affinity:** Deterministic wire frame demuxing by `conn_tag ^ object_id` pins 100% of source and Cauchy Reed–Solomon repair symbols to the same worker core for zero-jitter, in-cache FEC reassembly.
    - **Vectorized socket I/O engine:** `BatchUdpSocket` wraps `libc::recvmmsg` and `libc::sendmmsg` for 32-datagram bursts per syscall in `crates/yip-io`, reducing syscall transitions by 32×.
    - **Opportunistic UDP GSO offload:** Probes and configures kernel `UDP_SEGMENT` segmentation offload for bulk superpacket transmission with automatic transparent fallback.
    - **Adaptive cache-local replay window:** Dynamic profile sizing (`Standard` 1 KB / 8,192 bits for tight L1/L2 cache locality; `HighThroughput` 16 KB / 131,072 bits for burst jitter absorption) with lock-free promotion preserving all previously seen counters.
- Classical session rekey + epoch handling (milestone 9a, #9, PR #90):
  established sessions now rotate keys roughly every **~120 s** via a
  winner-initiates, one-in-flight rekey exchange (`EpochSet`:
  current/next/previous epochs, WireGuard-style confirmed-switch), with the
  losing side falling back cleanly on a race. Visible on the wire as a
  connection-tag rotation; verified with a loss-free netns rotation test.
- Relay-path rekey completion (#91, PR #92): the 9a rekey exchange, until now
  gated off for relayed peers, completes over the blind relay too
  (`relayed_handshake_init`/`relayed_handshake_resp` cores), preserving FEC
  fate tagging through the relay wrap/unwrap. Previously a relayed session
  simply never rekeyed.
- **REALITY.3–5d** (PR #83, PR #88 — PR #88's branch is named "follow-up
  cleanups" but actually carries REALITY.5b–5d): the Xray-REALITY relay
  transport's authenticated-serving path is now feature-complete. REALITY.3
  finished the server's stolen-cert forging (AIA extension copying, a
  per-SNI anti-replay guard on the auth seal, `--reality-cert-refresh-secs`/
  `--reality-cert-max-stale-secs` staleness bounds). REALITY.4a/4b wired up
  the `yipd` client side: `rendezvous=reality://host:port?pbk=&sid=&sni=`
  dials the relay with a Chrome-faithful crafted ClientHello, and `verify=`
  (default `on`) adds explicit client-side relay verification (pinned leaf
  key + `CertificateVerify` check derived from the shared seal secret) so a
  wrong `pbk`/relay key fails closed with a long jittered backoff instead of
  hammering the wrong host. REALITY.5a–5d then replaced the relay's
  authed-connection TLS serving with a hand-rolled, byte-matching TLS 1.3
  server flight (`yip-utls`'s `RealityStream`) built from a captured template
  of the real destination's own handshake shape — **dropping BoringSSL
  forged acceptors from the authed-serve path** (BoringSSL/`cmake` remain a
  build dependency overall, for the unauthenticated-splice path and
  `transport=tls`). Exercised end-to-end by `run-netns-reality-relay.sh` and
  `run-netns-reality-5d.sh`, including wrong-`pbk` and wrong-relay-key
  negative tests. See `docs/configuration.md` for the full `reality://` /
  `--reality-*` flag reference.
- `#59` MTU-aware packetization investigation findings + measurement tooling
  (PR #94) — **documentation/investigation only**, no code or wire change.
- REALITY.2 (anti-DPI): new pure-Rust `yip-utls` crate — a uTLS-equivalent
  REALITY client that crafts a **byte-faithful latest-Chrome (150) ClientHello**
  (with our own X25519 `key_share` and a REALITY auth seal in `legacy_session_id`)
  and completes a **TLS 1.3 handshake to an application-data stream**, entirely in
  safe Rust (`ring` + `x25519-dalek` + `chacha20poly1305` + `ml-kem`; no Go, no
  BoringSSL, `#![forbid(unsafe_code)]`). The crafted hello is locked to the real
  Chrome JA4 (`t13d1516h2_8daaf6152771_806a8c22fdea`) by a CI diff test, permutes
  its extension order per connection like real Chrome (so JA3 varies), and includes
  a genuine **X25519MLKEM768 post-quantum hybrid** key — the client completes the
  real ML-KEM-768 + X25519 hybrid handshake (verified live against Cloudflare, which
  selects it). The REALITY auth seal/open is now a shared codec used by both this
  client and the `yip-rendezvous` relay (REALITY.1). Standalone library — wired into
  yipd in REALITY.4.
- REALITY-style TLS front for the relay, server side (anti-DPI milestone
  REALITY.1): `yip-rendezvous`'s `--listen-tcp` TLS front gains an opt-in
  full Xray-style REALITY mode — `--reality-dest <host:port>`,
  `--reality-private-key <hex64>`, `--reality-short-id <hex16>` (repeatable),
  `--reality-server-name <name>` (repeatable). The relay reads the raw TLS
  `ClientHello` off the socket *before* terminating TLS and checks for a
  REALITY auth seal — an X25519-ECDH-keyed ChaCha20-Poly1305 seal carried in
  `legacy_session_id`, validated against the relay's REALITY private key, the
  configured `short_id`s, and a ±10-minute timestamp freshness window.
  Authenticated connections are served the relay tunnel (TLS terminated with
  the configured cert, same as the 3c.3 front below); everything else — an
  active prober, a scanner, a plain browser, or any connection without valid
  auth, including malformed/oversized TLS records — is **transparently
  spliced to a real upstream site** (`--reality-dest`, e.g.
  `www.apple.com:443`), replaying the bytes already read, so the prober
  completes a genuine handshake with the real site and sees *its* real cert.
  `--reality-dest` **supersedes `--decoy`** (the 3c.3 self-hosted-backend
  Trojan model) when both are given. **Server side only:** the yip client
  that embeds REALITY auth into its ClientHello is milestone REALITY.2, not
  yet shipped — until it lands, no production client authenticates and the
  relay forwards every live connection to `dest`.
- Port plausibility (anti-DPI 3d, R8/#45): `listen` is now optional and
  auto-defaults every transport to 443 (443/TCP for `tls`, 443/UDP for
  `quic`/`raw`) — the single least-suspicious port — falling back to 8443
  with a warning when binding 443 is denied (grant `CAP_NET_BIND_SERVICE`).
  yipd (and `yip-rendezvous`) warn at config load when a port is a known
  DPI-fingerprinted VPN default (51820/1194/500/4500/1701/1723/655);
  `example.config` no longer ships WireGuard's 51820. Fixes the port-match
  tell (#45).
- REALITY-style Trojan relay front (anti-DPI milestone 3c.3): `yip-rendezvous`
  gains an opt-in TCP/TLS listener (`--listen-tcp`/`--tls-cert`/`--tls-key`/
  `--decoy`) that terminates **real-cert** TLS and routes a fresh, obfuscated
  `Register` (now carrying a monotonic `counter` for replay rejection) to the
  relay tunnel, while transparently reverse-proxying every other connection —
  active probes, scanners, plain browsers — to a real decoy site, so the relay
  is indistinguishable from an ordinary HTTPS server to anyone without
  `obf_psk`. `--obf-psk` is now **required** with `--listen-tcp` (it is the
  tunnel discriminator). `tokio` is added to `yip-rendezvous` — the control/
  relay tier only; the `yipd` data plane stays 100% async-free. **New build
  dependency: `cmake` + a BoringSSL compile, now also required to build
  `yip-rendezvous`** (already required for `yipd` since 3c.2). The `yipd`
  client that dials this front (`rendezvous = "tls://host:443"`) is milestone
  3c.4, not shipped here.
- TLS relay-dial client (`rendezvous = tls://host:443`, anti-DPI 3c.4): a
  `yipd` node reaches the 3c.3 relay over a persistent browser-parrot TLS
  connection (a dedicated thread; the data plane stays tokio-free) and relays
  the unchanged inner protocol through it — so two UDP-blocked peers can
  tunnel to each other. Requires `obf_psk`; poll-driver-only; straight-to-relay
  (no Direct/UDP-punch).
- TLS-over-TCP mimicry transport (`transport=tls`, anti-DPI milestone 3c.2):
  carries the **unchanged** inner yip protocol (Noise-IK, FEC, AEAD) inside a
  real TLS 1.3 connection over TCP/443 with a **browser-parrot ClientHello**
  (BoringSSL via the `boring` crate, GREASE-enabled — a Chrome-shaped JA3/JA4,
  not a Rust-TLS fingerprint), so yip survives UDP-blocked networks and
  classifies as ordinary browser HTTPS. Datagrams are framed length-prefixed
  over the TLS byte-stream; the client/server role is a deterministic
  static-key tiebreak; teardown reconnects with backoff. Opt-in **last-resort**
  path (TCP head-of-line blocking, no FEC benefit — trades yip's latency
  identity for reachability); **mutually exclusive with `obf_psk`**; the
  default raw-UDP path and the `quic` costume are unchanged. New config keys
  `transport=tls` and `tls_sni` (default `www.apple.com`). **New build
  dependency: `cmake` + a BoringSSL compile** (required whenever `yipd` is
  built).
- L2 TAP tunnel mode in `yipd`: config now supports `device_kind=tap` for
  Ethernet (L2) tunnel interfaces; `device_kind=tun` remains the default for
  IP (L3) mode.
- io_uring Phase B driver (`UringDriver`): a single-ring (UDP+TUN) io_uring data
  loop, available **opt-in** via `YIP_USE_URING=1` (the **default is the epoll
  `PollDriver`**). netns CI runs all tunnel tests under **both** drivers. The
  opt-in path was hardened to match `PollDriver`'s robustness contract: `EINTR`
  on the blocking ring wait is retried (a signal no longer tears down the tunnel),
  and non-GSO send-completion errors drop on transient buffer pressure but
  propagate genuinely fatal errors (TUN writes always drop) instead of being
  swallowed forever. (Latency tuning — where io_uring goes from regressing to
  *beating* epoll via adaptive busy-poll — is in the "io_uring driver RTT work"
  entry under Changed; GSO throughput batching is the "io_uring GSO batching"
  entry under Changed.)
- `docs/configuration.md`: a single reference for everything `yipd` reads at
  startup — config-file keys (`device_kind`, keys, endpoints…), the
  `YIP_USE_URING` / `YIP_URING_BUSYPOLL` env knobs, and CLI flags — linked from
  the README.
- Single-threaded data loop (Phase A): replaced the two-thread `Arc<Mutex>`
  data plane with a mutex-free `DataPlane` driven by an `epoll` `PollDriver`
  (io_uring driver to follow). Removes per-packet lock/handoff overhead — tunnel
  RTT ~0.51 ms -> ~0.36 ms; throughput holds. No wire change.
- Adaptive loss-feedback loop + reactive ARQ. The receiver detects post-FEC
  residual loss as gaps in the object counter and reports it (with NACKs) in an
  authenticated `Control` packet; the sender attributes loss per class and drives
  the repair controller. ARQ-eligible (`Bulk`) flows on a clean link now decay
  their repair ratio to **zero**, activating the FEC-encode bypass — clean-link
  single-stream TCP rises from ~273–285 to ~457 Mbit/s. On loss the controller
  re-arms FEC instantly and NACKed `Bulk` objects are retransmitted with fresh
  RaptorQ repair symbols (reusing the original object id); `Realtime`/`Default`
  flows keep a proactive floor and are not retransmitted. New `yip-transport`
  modules: `feedback` (`LossReport`), `lossdetect` (`LossDetector`), `retxbuf`
  (`RetxBuffer`), plus `Transport::repair_object`.

### Fixed
- **Privileged CI jobs declared none of the tooling they drive (PR #156).**
  `catthehacker/ubuntu:act-22.04` — the image every Forgejo Actions job runs
  in — ships no `ip`, `tc`, `ping`, `tcpdump`, `iperf3` or `wg`, and its
  `PATH` already includes `/usr/sbin` and `/sbin`, so these were missing
  packages and never a PATH problem. `netns-tunnel-test` and
  `dpi-undetectability` died at `run-netns-tunnel.sh:86` and
  `run-ndpi-oracle.sh:129` with `ip: command not found`; every retry failed
  identically because the fault was deterministic. `netem-comparison` had
  `ip` only as a transitive *Recommends* of `wireguard-tools` — not a
  dependency — and broke the day that resolution changed. Each job now
  installs what its harness scripts actually run, sized from every script the
  job drives rather than the one that happened to fail first. Also: the scp
  harness creates `/run/sshd` before starting `sshd` (the package postinst
  normally does, but the image ships `sshd` without having run it and `/run`
  is a fresh tmpfs per container), and `start_sshd` now prints sshd's log and
  exit status on failure instead of leaving `-E "$logfile"` output in a file
  the cleanup trap deletes — which is why that failure had surfaced only as
  `harness failed`. A stale comment claiming `tcpdump` was "preinstalled on
  the runner image" is corrected; that belief is why it was never declared.
- **`hardening.41` cert-revocation gave discovery less time than it needs
  (PR #158, #157).** `CERT_A_SECS` was 60 and the establish loop stops 5s
  before expiry to keep the "still valid" invariant honest, leaving a 55s
  convergence window — while `run-netns-discovery.sh:287` documents gossip
  warm-up as needing "up to a 60s budget". The test allocated less time than
  its own sibling says the thing it waits for can take, so a green run was
  one that happened to converge early. Raised to 150s (~2.5x the documented
  worst case); the assertion is unchanged, since the cert still expires
  mid-test.
- Session-lifecycle hardening (#36 path-switch re-handshake + #41 cert
  revocation, PR #95): a path-switch (roaming) no longer discards the
  in-flight handshake ephemeral, both initiator- and responder-side relay
  adoption are covered for a relayed cold-start retransmit, and mesh peers
  now get a periodic cert-liveness sweep plus a re-verify-on-rekey-`Init`
  gate (both exempting root nodes) — so a revoked member's session no longer
  silently keeps working until its next full handshake.
- Root-exempt responder-cert checks (PR #97): responder-side cert checks now
  exempt root nodes symmetrically with the initiator-side gates — a root
  could previously fail a check the initiator side already exempted it from.
- Gossip digest chunking (#44, PR #98): the mesh gossip digest is now
  chunked, and its obfuscation degrades fail-soft, instead of panicking once
  a mesh grows past a single-datagram digest size.
- io_uring loopback recycle tests hardened against default socket buffers
  (PR #113): the recv-buffer and send-slot recycle tests now interleave
  send+drain (bounded in-flight window) instead of blasting all datagrams
  first, so they no longer fail on a box with a default
  `net.core.rmem_default`. The old pattern asserted `>256` datagrams
  round-trip but relied on the kernel buffering that many at once; the default
  ~208 KB receive buffer holds only ~230 small datagrams, so the assert
  failed deterministically on stock-configured machines.

### Changed
- **Sanitized cryptographic key examples and standardized default port 443 (#170, PR #175).**
  Replaced all repetitive dummy key examples (`11111111...`, `22222222...`, `33333333...`) across all configuration files, markdown guides, and CLI references with cryptographically realistic high-entropy hex sequences and explicit zero-trust `yip-ca` certificate workflows. Standardized the default daemon listen port to UDP 443 across all configurations, scripts, and documentation, ensuring out-of-the-box traffic blending with HTTPS/QUIC and evading middlebox port filters targeting standard VPN ports (such as WireGuard's 51820), with automated unprivileged fallback to port 8443. Added live animated terminal telemetry dashboard GIF (`assets/terminal-telemetry.gif`) demonstrating real-time multi-transport mesh status and peer statistics. Recorded best-of-3 automated AWS multi-region WAN benchmarks between `us-east-1` and `us-west-2` under 0% to 10% packet loss.
- Rendezvous relay-forward counter moved off the server's mutex onto a
  shared `AtomicU64` (#68, PR #93) — a pure perf fix (removes lock
  contention on the hot forwarding path under load); no behavior change to
  the `relay-forwarded=<N>` log line.
- **Relicensed from MPL-2.0 to AGPL-3.0-or-later**, copyright FEMBOY CYBER NETWORKS
  LLC. The AGPL network-use clause (§13) means anyone running a modified `yip` as a
  network service must offer their users the corresponding source — privacy
  infrastructure stays open. (Closes #53.)
- README rewritten with the project identity ("🦊 what does the fox say? — nothing a
  DPI firewall can hear") and a "Silicon Slopes Paradox" section on Utah SB 73 and
  the EFF's coverage; corrected the lingering "RaptorQ" references to Reed–Solomon
  across README, `CLAUDE.md`, and `yip-transport`/`yip-wire` doc comments (the codec
  was swapped in #50). Repo description + topics added.
- TUN vnet-header GSO/GRO offload on the **poll** hot path (throughput lever 4b):
  the TUN device is opened with `IFF_VNET_HDR` + `TUNSETOFFLOAD` (gated on the poll
  driver — `uring` and QUIC keep a plain TUN), so yipd batches its own TUN I/O.
  On **read**, a kernel-GRO'd super-frame is software-segmented back into MTU
  packets (`split_gro`); on **write**, consecutive same-flow TCP segments are
  merged by a userspace-GRO **coalescer** into one GSO super-frame the kernel
  re-segments — collapsing many per-packet `tun_chr_write_iter` traversals into
  one. The coalescing is **entirely local to the yipd↔kernel-TUN boundary: no
  wire-format, FEC, AEAD, or replay change** (each wire datagram stays one
  encrypted MTU packet); non-coalescible traffic (UDP, pings, flow changes) passes
  through as singletons at zero cost, and an unsupported kernel falls back to plain
  per-packet TUN I/O. A new `crates/yip-io/src/tun_offload.rs` holds the
  `virtio_net_hdr` codec, the coalescer, the splitter, and the partial-checksum
  completion for `F_NEEDS_CSUM` reads (the kernel offloads L4 checksums on large
  reads — completing them before encrypt is load-bearing, or the far end drops the
  packets). `unsafe` stays confined to `yip-io`/`yip-device`. **Real-hardware A/B
  (two 1-core AMD EPYC virtio VPSes, bulk TCP): receiver `tun_chr_write_iter`
  19.0% → 14.6%** — the mechanism cuts the targeted TUN-write cost, though
  end-to-end throughput on that 24 ms-RTT / same-core-`iperf` path is RTT/window-
  capped rather than TUN-CPU-bound, so the full win lands on low-RTT / high-
  throughput single flows. netns ping / 10%-loss / ARQ pass under both drivers;
  TCP-in-tunnel data verified intact. See `crates/yip-bench/RESULTS.md`.
- Send-side UDP GSO on the **poll** hot path (throughput lever 4a): `run_poll`'s
  `flush_tx` now partitions its egress batch into fate-safe runs (same
  destination, same length, pairwise-distinct FEC `fate`) and sends each run as
  one `sendmsg` with a `UDP_SEGMENT` control message, instead of one `sendmmsg`
  datagram-per-packet. The fate-safe grouping rule is factored into a shared
  `yip-io::gso` module (`can_coalesce` / `partition_fate_safe` /
  `max_gso_run_len`); the `UringDriver` GSO path now delegates to it, so both
  drivers enforce **at most one datagram per FEC object per skb** from one
  definition — a dropped GSO super-skb costs each object at most one symbol, so
  FEC per-symbol loss-independence is preserved. Opportunistic and
  latency-neutral (coalesces only what a burst already queued; a lone datagram
  still sends plain). Falls back to plain `send_mmsg` for singletons and, after
  latching a per-`run_poll` "GSO unavailable" flag, whenever the kernel reports
  `UDP_SEGMENT` unsupported (`EIO`/`EINVAL`). Wire-identical; no cipher/handshake/
  wire-format change. **Real-hardware A/B (two 1-core AMD EPYC virtio VPSes):
  +25–31 % end-to-end UDP throughput at equal single-core CPU** (a decision-gate
  spike measured a 2.6× send-path CPU reduction; the end-to-end gain is smaller
  because recv/TUN/conntrack/IRQ costs do not benefit from send-side GSO). netns
  10 %-loss + ARQ recovery verified under both drivers. `unsafe` stays confined to
  `yip-io`. See `crates/yip-bench/RESULTS.md` ("4a send-side GSO").
- Batched UDP I/O on the poll hot path (throughput lever): `run_poll` drains the
  UDP socket with one `recvmmsg` per burst and sends each TUN burst's egress with
  one addressed `sendmmsg` (per-datagram `dst`/`src`), collapsing ~2–3 `sendto`s
  per packet into one syscall per burst. Opportunistic and latency-neutral (batches
  only what epoll already queued). (PR #54.)
- Fast data-plane AEAD (throughput lever): `yip-crypto::Session` seal/open moved
  from snow's RustCrypto ChaCha20-Poly1305 to **`ring`** ChaCha20-Poly1305, keyed by
  snow's secret `Split()` transport keys and Noise's nonce so the output is
  **byte-identical to the previous wire** — **~2.1 µs → 0.6 µs** per packet. Same
  256-bit ChaCha20-Poly1305 cipher; snow is now handshake-only. A durable
  byte-identity KAT guards the equivalence. (PR #52.)
- **FEC codec swapped from RaptorQ to a small-K systematic Reed–Solomon codec**
  (throughput lever): a hand-rolled GF(256) Cauchy RS-v1 codec replaces the
  `raptorq` crate — **encode ~26 µs → ~1.33 µs**. RaptorQ's K′=10 minimum-block
  padding taxed every small packet with ~10 symbols of work, the price of a
  ratelessness yip never uses (`observe_loss` clamps the repair ratio ≤ 1.0). New
  `yip-transport` modules `gf256` + `rs` (exhaustive MDS proof); `raptorq` dropped
  from the dependency tree. Wire `payload_id` now carries a codec tag; `yip-wire`
  framing unchanged. (PR #50.)
- io_uring graceful fallback (issue #25): `run_uring` now falls back to the
  `PollDriver` on any `UringDriver` failure (init or runtime) instead of killing
  the tunnel. Found on a clean Debian 13 (kernel 6.12) box: io_uring's multishot
  UDP recv is rejected there with `EINVAL` and was fatal ~4/6 runs; it works on
  6.18+. Opting into io_uring (`YIP_USE_URING=1`) is now safe on any kernel — it
  degrades to epoll where io_uring is buggy/unsupported. (The re-default question
  is settled: **epoll `PollDriver` stays the default** — io_uring's busy-poll RTT
  win needs bare metal + a dedicated core + a recent kernel, so it remains a
  bare-metal opt-in. See the README "I/O driver" section.)
- io_uring GSO batching (issue #17): the `UringDriver` egress path coalesces
  TUN-egress datagrams into `UDP_SEGMENT` sends again (`MAX_GSO_SEGMENTS_PER_SEND`
  1 → 32), made **FEC-safe** by tagging each egress datagram with its RaptorQ
  object id ("fate") across the `Dispatch::on_tun` boundary (new `EgressDatagram`)
  and coalescing **at most one datagram per fate per skb** — so a dropped GSO
  super-skb never costs an object both its source symbol and its own repair
  (which previously pinned the cap to 1). The invariant is enforced at a single
  unit-tested choke point (`can_coalesce_gso_tagged`); `arq_recovers_bulk_loss`
  stays ≥ 98% delivery under uring with GSO active. No wire-format or
  `yip-transport` API change. (Single-stream throughput is unchanged on
  measurement — that path is FEC/CPU-bound, not syscall-bound; GSO's win is on
  syscall-bound bursts. The ARQ-retransmit egress path is left non-GSO for now.)
- io_uring driver RTT work: the `UringDriver` hot path no longer allocates per
  packet — received datagrams dispatch from a reused scratch buffer, send buffers
  are recycled through a pool, and `poll_once` drains completions into a reused
  vec (matching `PollDriver`, which was already alloc-free). Adds an opt-in
  **busy-poll** mode (`YIP_URING_BUSYPOLL=1`): `poll_once` spins the completion
  queue before blocking, cutting tunnel RTT from ~0.47 ms to ~0.31 ms and
  **beating the epoll `PollDriver` (~0.37 ms)** — a "burn CPU for latency" knob,
  off by default so idle tunnels don't spin. The spin is **adaptive**: it only
  runs while an exchange is active (recent completions) and backs off to a plain
  blocking wait the moment a wait times out, so an idle tunnel burns no CPU while
  an active one still catches imminent completions. (Making it the default /
  tuning the spin budget wants clean-hardware measurement; io_uring stays opt-in.)
  The `UringDriver` blocking wait is now bounded by a 10 ms timeout (via io_uring
  `EXT_ARG`, kernel 5.11+), so `Dispatch::tick` fires on cadence even on a fully
  idle tunnel — parity with poll.rs's `epoll_wait` timeout, fixing a latent gap
  where an idle uring tunnel could starve rekey/feedback timers.
- io_uring cleanup: the `UringDriver` now exposes a `dropped_sends` counter (folded
  into the send-drop logs) so slot-exhaustion drops are observable in aggregate,
  and drops the dead `udp_armed`/`tun_armed` fields. The two provided-buffer/send-
  slot reuse unit tests were made robust to bounded, load-dependent datagram loss
  (they assert pool *reuse* — round-tripping more than the fixed pool holds — plus
  the leak checks, rather than 100% round-trip), so the local suite is fast and
  reliable again.
- Coverage CI: exclude `yip-io/src/uring.rs` from the llvm-cov denominator (honest
  exclusion — the `UringDriver` syscall loop is netns/integration-gated, same
  pattern as `yip-device` privileged paths).
- Data-plane throughput pass: yipd now batches egress sends (`sendmmsg`) and
  ingress reads (`recvmmsg`) through yip-io's `PlainIo`, reuses framing buffers
  (no per-symbol allocation), and sizes `SO_SNDBUF`/`SO_RCVBUF` to 4 MiB via a
  yip-io `set_socket_buffers` helper. `yip-transport` gained a byte-identical
  RaptorQ encode bypass for the zero-repair case (dormant until the controller
  can request zero repair — see `crates/yip-bench/README.md`). yipd is now
  `#![forbid(unsafe_code)]`; `yip-io` pins `libc` exactly.

### Added
- Workspace scaffold with `yip-io`, `yip-wire`, `yip-crypto`, `yip-transport`,
  `yip-device`, and `yipd` crate stubs.
- CI quality gates: build, test, clippy, rustfmt, cargo-shear, cargo-deny,
  coverage, and mutation testing.
- Pre-commit hooks (file hygiene, cargo fmt, clippy, and test).
- Public `README.md` and `docs/architecture.md`.
- `yip-wire` frame codec: header serialization, SipHash coverage-auth tag, and
  keyed header protection, with fuzzing of the deframe path.
- `yip-crypto` Noise-IK handshake (via `snow`) and AEAD `Session` with explicit
  per-frame nonces and a sliding anti-replay window.
- `yip-device` TUN (L3) and TAP (L2) tunnel devices, and `yip-io` io_uring
  DataPlaneIo backend with a portable plain-socket fallback.
- `yip-transport` adaptive RaptorQ FEC: per-flow classifier, object encoder,
  pipelined erasure-tolerant reassembler, and a repair-ratio controller.
- `yip-transport` stateful flow-table heuristic: classifies unmarked flows by
  observed packet size/rate, completing the policy -> DSCP -> heuristic -> default
  precedence chain.
- `yipd` end-to-end tunnel: Noise handshake over UDP, session-derived wire keys,
  and L3 (TUN) traffic tunneled through the encrypted adaptive-FEC transport
  between two static peers (ping-tested across network namespaces).
- `yip-bench`: hot-path micro-benchmarks (AEAD, wire framing, RaptorQ FEC encode)
  via Criterion, and a `tc netem` latency/loss harness comparing the yip tunnel
  against kernel WireGuard (results in `crates/yip-bench/README.md`).

[Unreleased]: https://github.com/femboyisp/yip/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/femboyisp/yip/releases/tag/v0.1.0
