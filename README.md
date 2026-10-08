<p align="center">
  <img src="assets/yip.gif" alt="yip" width="340">
</p>

# yip

<p align="center">
  <a href="https://github.com/femboyisp/yip/actions/workflows/ci.yml"><img src="https://github.com/femboyisp/yip/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/femboyisp/yip/actions/workflows/integration.yml"><img src="https://github.com/femboyisp/yip/actions/workflows/integration.yml/badge.svg" alt="integration"></a>
  <a href="https://github.com/femboyisp/yip/actions/workflows/mutants.yml"><img src="https://github.com/femboyisp/yip/actions/workflows/mutants.yml/badge.svg" alt="mutation tests"></a>
  <img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Linux">
  <img src="https://img.shields.io/badge/status-pre--1.0-yellow.svg" alt="pre-1.0">
</p>

A low-latency, peer-to-peer mesh VPN written in Rust. yip tunnels L2 (TAP) or L3 (TUN)
traffic between peers over a UDP transport with systematic Reed–Solomon forward error
correction, self-certifying key-derived addresses, NAT hole-punching with a blind relay
fallback, CA-gated mesh discovery, and optional DPI-resistant transports.

Its two distinguishing properties are **latency parity with kernel WireGuard** and **loss
recovery without retransmission** (FEC), so tail latency stays flat on lossy links where a
plain tunnel spikes. Censorship-resistance and traffic-analysis defense are opt-in layers,
not always-on costs.

> [!NOTE]
> **Status: pre-1.0, single maintainer, Linux-only.** The data plane, multi-core throughput
> sharding (Way A + Regime B/B+), the full control plane, and the anti-DPI transports (obfuscation +
> Xray-REALITY TLS mimicry) are implemented and merged, with per-milestone integration
> tests running in CI on both I/O drivers. Not yet built: traffic-analysis/timing defense
> and the post-quantum hybrid handshake. No release has been cut;
> [`CHANGELOG.md`](CHANGELOG.md) tracks all merged work under *Unreleased*.

> [!TIP]
> New here? Read the [user guide](docs/user-guide.md) and copy
> [`example.config`](example.config). For *why* yip exists (Utah SB 73, the EFF, and the case
> for architectural censorship-resistance), see [`docs/motivation.md`](docs/motivation.md).

## What it is and isn't

yip is a control/data split. The data plane is a vectorized multi-core event loop over a UDP
socket and a TUN/TAP device; the control plane handles discovery, NAT traversal, relay, and
membership. Peers are identified by their public key — the address *is* the identity
(`fd00::/8`, derived by BLAKE2s), so there is no address authority.

- **It is** a working encrypted mesh VPN with FEC loss recovery, hole-punching, a blind
  relay, CA-gated private membership, pluggable obfuscated/TLS-mimicking transports, and
  line-rate multi-core scaling (Way A + Regime B/B+).
- **It is not** a finished product. There is no traffic-analysis (timing/padding) defense yet;
  and it runs only on Linux. See [Security model](#security-model) and [Roadmap](#roadmap) for
  an honest accounting of what is and isn't defended.

## Benchmarks

### 1. Head-to-Head WireGuard Parity & Loss Resilience

Live comparative benchmark in isolated Linux network namespaces (`run-netns-wireguard-comp.sh`) comparing Linux kernel WireGuard (`wg0`) against the `yip` daemon (`yip0`) under symmetric `tc netem` channel packet loss:

| Channel Loss | Protocol | Multi-Stream TCP Throughput | Goodput Retention | ICMP RTT p50 | ICMP RTT p99 |
|:-------------|:---------|----------------------------:|------------------:|-------------:|-------------:|
| **0% (Baseline)** | **Linux WireGuard (`wg0`)** | **2.71 Gbps** | 100.0% | 0.162 ms | 2.750 ms |
| | **`yip` Daemon (`yip0`)** | **1.05 Gbps** | 100.0% | 0.227 ms | **0.510 ms** |
| **1% Channel Loss** | **Linux WireGuard (`wg0`)** | **2.61 Gbps** | 96.3% | 0.268 ms | 2.590 ms |
| | **`yip` Daemon (`yip0`)** | **0.98 Gbps** | **92.9%** | 0.231 ms | 5.960 ms |
| **5% Channel Loss** | **Linux WireGuard (`wg0`)** | **0.15 Gbps** | 5.5% *(Collapses)* | 0.244 ms | 3.090 ms |
| | **`yip` Daemon (`yip0`)** | **0.80 Gbps** | **76.2%** *(Sustains)* | 0.243 ms | 5.390 ms |

- **5.3x Higher Throughput under Loss:** At 5% packet loss, kernel WireGuard throughput collapses by **94.5%** due to TCP window halving from packet drops. `yip`'s systematic Cauchy Reed–Solomon FEC (GF(256)) and hybrid ARQ recover lost packets in-place, preserving **76.2%** of line rate (0.80 Gbps vs 0.15 Gbps).
- **Sub-Millisecond Baseline Jitter:** Core-pinned bidirectional symmetric flow hashing, AVX2 SIMD FEC acceleration, and adaptive busy-polling achieve a baseline RTT p99 of **0.510 ms** (vs 2.750 ms on WireGuard).

### 2. Multi-Core Line-Rate Throughput Scaling

Single-peer multi-stream scaling benchmarks across 1, 2, 4, and 8 worker CPU cores (64 concurrent TCP streams, 0 packet drops, 0 TCP reordering):

| Worker Threads | Vectorized Sockets (`recvmmsg`) | Kernel-Bypass AF_XDP Zero-Copy | Scaling Speedup | Drops | Out-of-Order |
|:--------------:|--------------------------------:|-------------------------------:|:---------------:|:-----:|:------------:|
| **1 Core** | 4.58 Gbps (0.45 Mpps) | 7.60–8.68 Gbps (0.74–0.85 Mpps) | 1.00x | **0** | **0** |
| **2 Cores** | 6.04 Gbps (0.59 Mpps) | 10.45–11.26 Gbps (1.02–1.10 Mpps) | 1.38x | **0** | **0** |
| **4 Cores** | 11.43 Gbps (1.12 Mpps) | 18.84–21.22 Gbps (1.84–2.07 Mpps) | 2.48x | **0** | **0** |
| **8 Cores** | **21.29–21.56 Gbps (2.10 Mpps)** | **29.20–40.27 Gbps (2.85–3.93 Mpps)** | 3.84x–4.64x | **0** | **0** |

- **Zero Lock Contention:** Lock-free chunked nonces (`ChunkedNonceDispenser`), power-of-two circular descriptor queues (`FillRing`, `RxRing`, `TxRing`, `CompletionRing`), and cache-line padded SPSC matrix queues.
- **Poly-Vector SIMD Galois Field Acceleration (GFNI / AVX-512 / AVX2 / SSSE3 / NEON):** Runtime CPU dispatch delivering hardware Galois Field New Instructions (`_mm_gf2p8affine_epi64_epi8`) with **33.1 ns / packet** row multiplication (**61.00x speedup**) and **1.71 µs** Cauchy block encoding (**70.21 Gbps**, **48.95x speedup**, 122.1 ns/packet), supported across AVX-512BW, AVX2, SSSE3, and ARM NEON.
- **Single-Peer Multi-Queue TUN Worker Sharding (`shards = N`):** Core-pinned worker threads consuming multi-queue TUN queues (`IFF_MULTI_QUEUE`) with per-shard object ID stride partitioning (`object_id = shard_id + k * num_shards`) and monotonic nonces, eliminating cross-worker contention.
- **Self-Contained Multi-Queue eBPF XSK Driver:** Embedded minimal eBPF XDP redirect driver and `XSKMAP` filter steering matching tunnel UDP packets directly into AF_XDP rings at the NIC driver layer, bypassing `sk_buff` allocations.
- **Adaptive Dynamic Busy-Polling:** 50 µs zero-syscall hysteresis spin-polling window under active traffic bursts eliminating kernel scheduler wakeup latency, gracefully yielding to low-power `epoll_wait(10)` during idle periods.
- **Three-Tier Fallback:** AF_XDP socket initialization seamlessly negotiates `XDP_ZERO_COPY` (hardware NIC DMA) $\to$ `XDP_COPY` (driver zero-copy emulation) $\to$ `recvmmsg` vectorized batching, ensuring line-rate operation without panics in unprivileged containers.

Full Criterion microbenchmarks, component metrics, and historical WAN data are detailed in [`crates/yip-bench/RESULTS.md`](crates/yip-bench/RESULTS.md).

## Architecture

The project is decomposed into sub-projects, each built and merged independently.

| # | Sub-project | Status |
|---|---|---|
| 1 | Core data plane + FEC transport (encrypted L2/L3 tunnel over RS-FEC UDP) | merged |
| 2 | Control plane: multi-peer routing + key-derived addresses, rendezvous + hole-punching + blind relay, CA-gated gossip discovery | merged |
| 3 | Anti-DPI transports: `obf_psk` obfuscation, junk/decoy + timing jitter, Xray-REALITY TLS mimicry, pluggable transports | merged (obfuscation + REALITY) |
| — | Handshake anti-replay, signed rendezvous registration, authenticated endpoint roaming, session rekey (~120 s) | merged |
| 4 | Traffic-analysis defense (DAITA-style padding/timing; optional onion routing) | not started |
| 5 | Multi-core throughput sharding (Way A + Regime B/B+ line-rate scaling) | merged |
| — | Kernel-bypass zero-copy I/O tier (AF_XDP / Way C) & WireGuard parity suite | merged |
| — | Zero-overhead ultra-low latency & line-rate acceleration (Regime D: AVX2 SIMD RS, eBPF XSK driver, adaptive poller) | merged |
| — | Poly-vector SIMD & multi-queue worker sharding (Regime E: GFNI/AVX-512/NEON RS, multi-queue TUN/eBPF, auto-tuned polling) | merged |
| — | Platform expansion (macOS/Windows) | backlog |

The workspace is a set of focused crates behind clean interfaces:

| Crate | Responsibility |
|---|---|
| `yip-io` | Packet I/O: vectorized `recvmmsg`/`sendmmsg` batch engine, opportunistic UDP GSO (`UDP_SEGMENT`), lock-free chunked nonces, cache-padded SPSC ring buffers, and AF_XDP zero-copy engine (`UmemPool`, descriptor rings, opportunistic 3-tier fallback). `epoll` driver by default; opt-in single-ring `io_uring`. The only crate with `unsafe`. |
| `yip-wire` | Wire framing: keyed header-protection, coverage-based auth, explicit FEC headers — no fixed bytes or constant offsets. |
| `yip-crypto` | AEAD session crypto (Noise-IK via `snow`), adaptive circular replay window (1 KB Standard to 16 KB HighThroughput), rekey. |
| `yip-transport` | Systematic Reed–Solomon FEC (GF(256)), FEC object affinity demuxing, per-flow classifier, redundancy controller, thin ARQ. |
| `yip-membership` | CA-signed certificates, member-signed directory records, the signed root set, gossip codec. |
| `yip-rendezvous` | Rendezvous protocol + blind relay server. |
| `yip-obf` | The `obf_psk` obfuscation envelope (SipHash-CTR keystream over a random nonce). |
| `yip-utls` | Xray-REALITY TLS-mimicry primitives (ClientHello parroting, stolen-cert reshaping). |
| `yip-device` | Multi-queue L3 (TUN) with `IFF_MULTI_QUEUE` and L2 (TAP, with MAC learning) tunnel endpoints. |
| `yipd` | The daemon that composes it all. |

Design docs live under [`docs/`](docs/); the architecture summary is
[`docs/architecture.md`](docs/architecture.md).

### I/O driver

The data loop runs on either of two `yip-io` drivers:

- **The epoll `PollDriver` is the default** — the faster, simpler, safe-Rust path, and it
  works everywhere. Its send path batches with `sendmmsg` and coalesces same-peer,
  same-length, distinct-FEC-object bursts into `UDP_SEGMENT` (GSO) sends (measured +25–31%
  single-core UDP throughput on 1-vCPU VPSes), while keeping each FEC object to one datagram
  per GSO skb so loss recovery is preserved. It also opens the TUN with `IFF_VNET_HDR`
  GSO/GRO offload.
- **The io_uring `UringDriver` is opt-in** (`YIP_USE_URING=1`), and is the workspace's only
  `unsafe`. An adaptive busy-poll mode (`YIP_URING_BUSYPOLL=1`) can cut RTT below epoll, but
  only on bare metal with a dedicated core and a recent kernel; on shared-vCPU cloud the win
  disappears, and on kernel 6.12 it falls back to the poll driver at runtime. Treat it as a
  "burn a core for latency on bare metal" knob, not a default.

Env knobs are documented in [`docs/configuration.md`](docs/configuration.md).

## Security model

yip aims for confidentiality and integrity of tunneled traffic and for resistance to
content-based DPI. It does **not** yet defend against traffic analysis.

- **Data plane:** ChaCha20-Poly1305 AEAD over a Noise-IK session, per-direction keys, a
  WireGuard-style replay window, and ~120 s rekey with an epoch overlap. A durable
  known-answer test pins the AEAD path byte-for-byte. Keys are classical today; the
  handshake is structured for a Rosenpass-style hybrid PQ upgrade (Classic McEliece +
  ML-KEM) later.
- **Handshake / identity:** admission checks the peer's static key before allocating state;
  a TAI64N timestamp inside the encrypted handshake closes an endpoint-hijack-via-replay
  vector; endpoint roaming follows only AEAD-authenticated packets; mesh membership requires
  a CA-signed certificate, and rendezvous registration is signed (squatting and
  registration-overwrite are closed on the UDP path).
- **Anti-DPI:** the wire carries no fixed bytes or constant offsets (property-tested), and
  obfuscated traffic classifies as `Unknown` to nDPI by content in a CI gate. For hostile
  networks, an Xray-REALITY transport parrots a real TLS handshake (high-fidelity, JA4-pinned
  ClientHello; active-probe-resistant — every failure path splices to the real upstream).
- **What is *not* defended (be aware):** traffic-analysis / statistical DPI. The FEC burst
  shape and packet-size distribution, and the constant-interval idle cover traffic, are still
  observable to a flow/timing classifier; the high-entropy-UDP anomaly is not gated. This is
  sub-project #4 and is not built. Several control-plane hardening items (relay-front
  registration signing, resolver endpoint binding, registration-replay windows) are tracked
  as open issues.

For threat-model detail and the obfuscation-compromise degradation story, see the user
guide's security section.

## Roadmap

The data plane, control plane, anti-DPI transports, and session security are merged. Next up:
multi-core throughput, traffic-analysis defense, control-plane hardening, and a post-quantum
handshake. Full status and priorities are in [`ROADMAP.md`](ROADMAP.md); the live backlog is
the [issue tracker](https://github.com/femboyisp/yip/issues).

## Building

Requires a recent stable Rust toolchain (Linux). The REALITY TLS-mimicry crate links
BoringSSL, so a C toolchain and `cmake` must be present.

```sh
cargo build --release --workspace   # yipd, yip-ca, yip-rendezvous + all crates
cargo test  --workspace             # unit tests (netns integration tests need sudo — see below)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

To run a tunnel: copy [`example.config`](example.config), generate keys (`yipd --genkey`),
and `sudo yipd your.config` on each node. The [user guide](docs/user-guide.md) walks through
a two-node tunnel, mesh mode, NAT traversal, and obfuscation; the full config/CLI/env
reference is [`docs/configuration.md`](docs/configuration.md).

The network-namespace integration tests require root and exercise both I/O drivers; they run
in the CI `integration` workflow (`sudo bash bin/yipd/tests/run-netns-*.sh`). A plain
`cargo test --workspace` skips them.

CI runs `cargo fmt`/`clippy -D warnings`, `cargo-shear` (unused deps), `cargo-deny`
(licenses + advisories), `cargo-llvm-cov` line coverage on the logic crates, nightly
`cargo-mutants` mutation testing, an nDPI DPI-undetectability gate, and the netns integration
suite. (Fuzz targets exist under `crates/*/fuzz` but are not yet wired into CI.)

## Funding

yip is open-source (AGPL-3.0) and pre-1.0. Funding buys development time on the roadmap —
grants, sponsorship, and collaboration options are in [`FUNDING.md`](FUNDING.md).

## Contributing

Contributions — code, review, testing, docs, deployment reports — are welcome. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, the [coding
guidelines](https://github.com/mullvad/mullvadvpn-app/blob/main/CODING_GUIDELINES.md) yip
follows, the netns integration tests, and the PR bar.

> [!IMPORTANT]
> Found a security issue? See [`SECURITY.md`](SECURITY.md) and report it privately — please
> don't open a public issue.

## License

Copyright © 2026 FEMBOY CYBER NETWORKS LLC.

yip is free software licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later). The AGPL's
network-use clause (§13) is deliberate: anyone who runs a modified `yip` as a network service
must offer their users the corresponding source.
