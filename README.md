# yip

**A low-latency, high-performance, P2P mesh-network VPN tunnel, written in Rust.**

yip is built for *insane* low latency on direct peer-to-peer links — fast enough for gaming and
streaming, and for L2 IXP-style offloading with forward-error-correction autocorrection — while
also serving as a general-purpose L2/L3 mesh VPN. Censorship-resistance, traffic-analysis defense,
and anonymity are opt-in dials layered on top, not always-on costs.

> **Status:** sub-project #1 (the core data plane + FEC transport) is **complete** — a working
> encrypted FEC VPN tunnel, ping-tested across network namespaces, with benchmarks showing its FEC
> recovers packet loss that plain WireGuard passes through. The control plane, anti-DPI, and
> hardening sub-projects are next. See [Roadmap](#roadmap).

## Goals

- **Insane low latency** on direct P2P paths — the north star. The latency lever is the I/O model
  (single `io_uring` ring over UDP + TUN/TAP, then AF_XDP zero-copy), not the crypto.
- **L2 (TAP) and L3 (TUN)** data planes — Ethernet bridging *and* IP tunneling.
- **Adaptive RaptorQ FEC** — rateless forward error correction that recovers packet loss with
  **zero extra round-trips**, tuned per-flow so realtime traffic pays no latency tax and lossy/bulk
  links spend redundancy where it helps. Loss recovery without retransmission keeps p99 latency flat
  under loss, where plain tunnels spike.
- **NAT hole-punching** — rendezvous + UDP hole-punching, with a zero-knowledge relay fallback.
- **Post-quantum-ready crypto** — classical Noise-IK now (reusing audited primitives), structured so
  a Rosenpass-style hybrid PQ handshake (Classic McEliece + ML-KEM) drops in later. ~120 s rekey.
- **No DPI-detectable signatures** — no fixed magic bytes or constant header offsets; keyed
  header-protection, randomized padding, timing jitter. nDPI/nDPId are the test adversary.

## Architecture

yip is a control/data split. The whole project is decomposed into five sub-projects, each built and
shipped independently:

| # | Sub-project | What it adds |
|---|---|---|
| **1** | **Core data plane + FEC transport** *(complete)* | Encrypted L2+L3 tunnel between peers over an adaptive RaptorQ-FEC UDP transport on a kernel-bypass-ready I/O layer. |
| 2 | Control plane | Decentralized discovery (DHT/gossip), self-certifying key-derived addresses, NAT traversal, relay fallback. |
| 3 | Anti-DPI / obfuscation | Pluggable obfuscating link layer (AmneziaWG recipe, optional REALITY TLS-mimicry); nDPI in CI. |
| 4 | Traffic-analysis defense | DAITA-style padding/timing; optional per-flow onion routing (Arti crates). |
| 5 | Hardening / multi-platform | macOS/Windows, optional AF_XDP/kernel-module relay tier, management UX. |

The data plane (sub-project #1) is a Cargo workspace of focused crates, each one trait behind a
clean interface:

| Crate | Responsibility |
|---|---|
| `yip-io` | Kernel-bypass-ready packet I/O (`io_uring` ring over UDP + TUN/TAP; AF_XDP backend). The latency core. |
| `yip-wire` | Lean, DPI-resistant wire framing: keyed header-protection, coverage-based auth, explicit FEC headers. |
| `yip-crypto` | AEAD session crypto (Noise-IK), anti-replay, rekey — PQ-ready. |
| `yip-transport` | Adaptive RaptorQ FEC, per-flow classifier, redundancy controller, thin ARQ. |
| `yip-device` | L3 (TUN) and L2 (TAP, with MAC learning) tunnel endpoints. |
| `yipd` | The daemon that wires it all together. |

Full design: [`docs/superpowers/specs/2026-06-28-data-plane-fec-transport-design.md`](docs/superpowers/specs/2026-06-28-data-plane-fec-transport-design.md).
Architecture summary: [`docs/architecture.md`](docs/architecture.md).

## Roadmap

Sub-project #1 (core data plane + FEC transport) is **complete** — a working encrypted FEC VPN
tunnel, proven by pinging across it between two daemons in separate network namespaces.

- [x] **M1** — Workspace scaffold + all quality gates (lints, CI, coverage, mutation, fuzz).
- [x] **M2** — `yip-wire`: framing, keyed header-protection, coverage-auth (fuzzed).
- [x] **M3** — `yip-crypto`: Noise-IK session (via `snow`) + explicit-nonce AEAD + replay window.
- [x] **M4** — `yip-io` (io_uring) + `yip-device`: TUN/TAP devices and packet I/O.
- [x] **M5** — `yip-transport`: adaptive RaptorQ FEC + per-flow classifier + stateful flow heuristic.
- [x] **M6** — `yipd` end-to-end 2-peer encrypted tunnel (ping-tested across network namespaces).
- [x] **M7** — benchmark harness: hot-path micro-benchmarks (AEAD ~2 µs/frame, wire framing
  ~512 ns/frame, RaptorQ encode ~24 µs/frame) and a `tc netem` yip-vs-WireGuard comparison (release
  build) — yip's FEC recovers loss WireGuard passes through (~1 % effective at 10 % injected vs ~17 %
  for WG) for a ~0.2 ms RTT premium, and under loss yip's scp throughput holds while WireGuard's TCP
  collapses (~6× yip at 5–10 % loss). See [`crates/yip-bench/README.md`](crates/yip-bench/README.md)
  for the full results.
- [ ] **Next** — control plane (decentralized discovery, NAT traversal, relay fallback); then
  anti-DPI / obfuscation, DAITA/anonymity, and hardening sub-projects.

## Building

Requires a recent stable Rust toolchain (Linux).

`yipd` tunnel mode is selected in config via `device_kind=tun|tap` (`tun` by
default).

```sh
cargo build --workspace      # build everything
cargo test  --workspace      # run the test suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI additionally runs `cargo-shear` (unused deps), `cargo-deny` (licenses + advisories),
`cargo-llvm-cov` (≥90 % line coverage on logic crates), `cargo-mutants`, and `cargo-fuzz`.

## Contributing

Code follows the [Mullvad coding guidelines](https://github.com/mullvad/mullvadvpn-app): the
workspace lint set with `-D warnings`, no `as` casts for numeric conversion (`From`/`TryFrom`),
`#![forbid(unsafe_code)]` on every crate except `yip-io`, pinned dependency versions, and a
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) `CHANGELOG.md`.

Install the pre-commit hooks so fmt, clippy, tests, and file hygiene run before every commit:

```sh
pre-commit install        # one-time, after cloning
pre-commit run --all-files  # optional: run against the whole tree
```

## License

[MPL-2.0](LICENSE).
