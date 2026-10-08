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

Measured 2026-07-25 between two 1-vCPU VPSes (Utah ↔ Las Vegas, ~23 ms RTT, real internet
path) running the current build. TCP, single stream, single core.

| Metric | Direct path | yip tunnel | WireGuard (same path) |
|---|---|---|---|
| Latency, idle | 23.2 ms | 23.7 ms (0% loss) | ~23.3 ms |
| Throughput, TCP 1-stream | 1.16 Gbit/s | 142 Mbit/s | ~438 Mbit/s |
| App-visible loss @ 5% underlay loss | 5.5% | **0.5%** | ~5% |

Read these honestly:

- **Latency is on par with WireGuard** — the tunnel adds ~0.3–0.5 ms over the raw path. This
  is the property yip optimizes for.
- **FEC is the differentiator.** At 5% underlay loss, yip's systematic Reed–Solomon codec
  cuts application-visible loss to ~0.5% (≈ the underlying rate squared) with zero extra
  round-trips, so p99 stays flat where a plain tunnel's TCP throughput collapses.
- **Multi-core scaling (Way A + Regime B/B+):** Single-peer multi-stream scaling benchmarks
  (`crates/yip-bench/benches/single_flow_scale.rs`) verify lock-free scaling across cores:
  **4.34 Gbps (1 core) → 10.72 Gbps (4 cores) → 19.05–21.56 Gbps (8 cores)** with 0 packet drops
  and 0 TCP reordering. Vectorized `recvmmsg`/`sendmmsg` socket engines, opportunistic UDP GSO
  (`UDP_SEGMENT`), lock-free chunked nonces, and bidirectional symmetric flow pinning eliminate
  cross-core cache invalidation.

Hot-path microbenchmarks (Criterion), single-flow multi-core scaling tables, the `tc netem`
WireGuard comparison, and the raw WAN data live in [`crates/yip-bench/RESULTS.md`](crates/yip-bench/RESULTS.md).

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
| — | Platform expansion (macOS/Windows) & AF_XDP zero-copy relay tier (Way C) | backlog |

The workspace is a set of focused crates behind clean interfaces:

| Crate | Responsibility |
|---|---|
| `yip-io` | Packet I/O: vectorized `recvmmsg`/`sendmmsg` batch engine, opportunistic UDP GSO (`UDP_SEGMENT`), lock-free chunked nonces, cache-padded SPSC ring buffers. `epoll` driver by default; opt-in single-ring `io_uring`; AF_XDP planned. The only crate with `unsafe`. |
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
