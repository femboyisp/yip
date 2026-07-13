# 🦊 yip

**An invisible, low-latency, high-performance P2P mesh-network VPN tunnel, written in Rust.**

```
       /\___/\
      /  o   o  \      "What does the fox say?"
     (    ="=    )     ...nothing a DPI firewall can hear.
      \  ~~~~~  /
       \_______/
```

`yip` is a stealthy, ultra-fast L2/L3 mesh VPN built for *insane* low latency on direct
peer-to-peer links — fast enough for gaming and streaming, and for L2 IXP-style offloading with
forward-error-correction autocorrection — while also serving as a general-purpose mesh VPN. It is
engineered to be **silent**: no fixed magic bytes, no constant header offsets, no data-center IP
blocks to ban. Censorship-resistance, DPI evasion, traffic-analysis defense, and anonymity are
**opt-in dials** layered on top — run wide open for raw performance, or go completely dark when the
network turns hostile. When the sensors ask what the fox says, they get exactly zero answers.

> **Status:** the data plane (#1), the full control plane (#2: multi-peer + self-certifying
> addresses, rendezvous/NAT-traversal/relay, decentralized CA-gated mesh discovery), and the first
> anti-DPI milestone (#3a: opt-in `obf_psk` obfuscation, proven undetectable to nDPI in CI) are
> **complete and merged** — a working, encrypted, loss-recovering, obfuscatable mesh VPN, all
> ping-tested across network namespaces on both I/O drivers. Throughput levers (batched I/O, GSO,
> TUN offload) and traffic-analysis defense are the current work. See [Roadmap](#roadmap).
>
> **New here?** Read the [user guide](docs/user-guide.md) and copy
> [`example.config`](example.config).

## 🏛️ The Silicon Slopes Paradox: why yip exists

`yip` is engineered by [**FEMBOY CYBER NETWORKS LLC**](#license), an independent entity registered
in the state of Utah.

On May 6, 2026, Utah enacted **Senate Bill 73 (SB 73)** — the *Online Age Verification Amendments*.
As covered by the [**Electronic Frontier Foundation**](https://www.eff.org/deeplinks/2026/04/utahs-new-law-regulating-vpns-goes-effect-next-week),
this made Utah the first state to explicitly target the use of VPNs to circumvent geofenced,
government-mandated online identity checks — holding a website operator legally liable when a user
reaches their platform from inside Utah's borders **even if that user is masking their location**.

The EFF calls out the **liability trap** this creates: a site that cannot reliably guess the physical
origin of a privacy-protected IP faces the choice of banning *every* known commercial VPN range or
forcing intrusive ID/biometric checks on *every visitor on earth* to screen out hidden Utah users.
SB 73 even reaches for a First Amendment overreach by targeting the act of *providing instructions*
on routing around local geofences.

> *"Blocking all known VPN and proxy IP addresses is a technical whack-a-mole that likely no company
> can win… The internet is built to, and will always, route around censorship."* — **EFF**

Our position as a Utah technology firm is simple: **attacks on VPNs are attacks on the tools that
enable fundamental digital privacy.** The state tried to make privacy tools a legal liability; our
response as engineers is to make them *mathematically unidentifiable*. `yip` is designed to break the
whack-a-mole game — a decentralized, CA-gated P2P mesh using opt-in NAT hole-punching and
zero-signature obfuscation, with **no centralized data-center IP blocks to ban**. We don't publish
instructions for breaking local laws; we build open systems architecture so that secure, private,
low-latency networking stays an unbroken human right, whatever state you live in.

## Goals

- **Insane low latency** on direct P2P paths — the north star. The latency lever is the I/O model
  — a single-threaded event loop over UDP + TUN/TAP — not the crypto. A lean `epoll` driver is the
  default; a single-ring `io_uring` driver is opt-in (see [I/O driver](#io-driver) below).
- **L2 (TAP) and L3 (TUN)** data planes — Ethernet bridging *and* IP tunneling.
- **Adaptive Reed–Solomon FEC** — systematic forward error correction that recovers packet loss with
  **zero extra round-trips**, tuned per-flow so realtime traffic pays no latency tax and lossy/bulk
  links spend redundancy where it helps. Loss recovery without retransmission keeps p99 latency flat
  under loss, where plain tunnels spike. *(Landing on its feet mid-stride, instead of stopping to ask
  for the packet again.)*
- **NAT hole-punching** — rendezvous + UDP hole-punching, with a zero-knowledge relay fallback.
- **Post-quantum-ready crypto** — classical Noise-IK now (reusing audited primitives), structured so
  a Rosenpass-style hybrid PQ handshake (Classic McEliece + ML-KEM) drops in later. ~120 s rekey.
- **No DPI-detectable signatures** — no fixed magic bytes or constant header offsets; keyed
  header-protection, randomized padding, timing jitter. nDPI/nDPId are the test adversary. *(Winter
  fur against the snow: look right at it and it's background noise.)*

## Architecture

yip is a control/data split. The whole project is decomposed into five sub-projects, each built and
shipped independently:

| # | Sub-project | What it adds |
|---|---|---|
| **1** | **Core data plane + FEC transport** *(complete)* | Encrypted L2+L3 tunnel between peers over an adaptive Reed–Solomon-FEC UDP transport on a kernel-bypass-ready I/O layer. |
| **2** | **Control plane** *(complete)* | Multi-peer routing + self-certifying key-derived addresses, rendezvous + UDP hole-punching + blind relay, and decentralized CA-gated gossip discovery (private membership mesh). |
| **3** | Anti-DPI / obfuscation *(3a done)* | Opt-in `obf_psk` obfuscation — no fixed bytes/sizes/type-discriminator, control-timer jitter, nDPI-proven Unknown *(done)*. Junk/decoy packets, REALITY TLS-mimicry, pluggable transports *(next)*. |
| 4 | Traffic-analysis defense | DAITA-style padding/timing; optional per-flow onion routing (Arti crates). |
| 5 | Hardening / multi-platform | macOS/Windows, optional AF_XDP/kernel-module relay tier, management UX. |

The data plane (sub-project #1) is a Cargo workspace of focused crates, each one a trait behind a
clean interface:

| Crate | Responsibility | Fox-lore |
|---|---|---|
| `yip-io` | Kernel-bypass-ready packet I/O: a single-threaded event loop over UDP + TUN/TAP (`epoll` driver by default; opt-in single-ring `io_uring`; AF_XDP backend planned). The latency core. | **The pounce** — high-efficiency, zero-waited motion. |
| `yip-wire` | Lean, DPI-resistant wire framing: keyed header-protection, coverage-based auth, explicit FEC headers. | **The camouflage** — no tracks, no signature. |
| `yip-crypto` | AEAD session crypto (Noise-IK), anti-replay, rekey — PQ-ready. | **The den** — the secret only the pack shares. |
| `yip-transport` | Adaptive Reed–Solomon FEC, per-flow classifier, redundancy controller, thin ARQ. | **The agility** — lands on its feet mid-stride. |
| `yip-device` | L3 (TUN) and L2 (TAP, with MAC learning) tunnel endpoints. | **The burrow** — where the tunnel meets the ground. |
| `yipd` | The daemon that wires it all together. | **The fox itself.** |

Full design: [`docs/superpowers/specs/2026-06-28-data-plane-fec-transport-design.md`](docs/superpowers/specs/2026-06-28-data-plane-fec-transport-design.md).
Architecture summary: [`docs/architecture.md`](docs/architecture.md).

### I/O driver

The data loop can run on either of two `yip-io` drivers. After benchmarking on bare metal and cloud
VMs across kernels, the conclusion is:

- **The epoll `PollDriver` is the default** — it is the faster, simpler, safe-Rust path and works
  everywhere. On measurement it has *lower* tunnel RTT than the io_uring driver's blocking wait. Its
  send path batches datagrams with `sendmmsg` and coalesces same-peer, same-length, distinct-FEC-object
  bursts into `UDP_SEGMENT` (GSO) sends — measured **+25–31 % single-core UDP throughput** on 1-core
  virtio VPSes — while keeping each FEC object to at most one datagram per GSO skb so loss-recovery is
  preserved. It also opens the TUN with `IFF_VNET_HDR` GSO/GRO offload, splitting kernel-GRO'd reads
  and coalescing same-flow TCP writes into super-frames to cut per-packet TUN-device cost (a purely
  local optimization — no wire/FEC change; it falls back to plain per-packet I/O where unsupported).
  See [`crates/yip-bench/RESULTS.md`](crates/yip-bench/RESULTS.md).
- **The io_uring `UringDriver` is opt-in** (`YIP_USE_URING=1`) and is the workspace's only `unsafe`.
  It carries an optional **adaptive busy-poll** mode (`YIP_URING_BUSYPOLL=1`) that spins the
  completion queue to cut RTT **below** epoll — but only on **bare metal with a dedicated core per
  peer** and a **recent kernel**. On shared-vCPU cloud instances the win disappears (hypervisor
  jitter, core oversubscription), and on Debian 13 stable's kernel 6.12 io_uring's multishot recv is
  rejected outright (issue #25); it now **falls back to the `PollDriver`** at runtime instead of
  crashing. So io_uring is a **"burn a core for latency on bare metal"** knob, not a general default.

Bottom line: use the default (epoll) everywhere; reach for `YIP_USE_URING=1 YIP_URING_BUSYPOLL=1`
only on a dedicated-core, recent-kernel host where sub-millisecond RTT is worth a spinning core.
Env knobs are documented in [`docs/configuration.md`](docs/configuration.md).

## Roadmap

Sub-project #1 (core data plane + FEC transport) is **complete** — a working encrypted FEC VPN
tunnel, proven by pinging across it between two daemons in separate network namespaces.

- [x] **M1** — Workspace scaffold + all quality gates (lints, CI, coverage, mutation, fuzz).
- [x] **M2** — `yip-wire`: framing, keyed header-protection, coverage-auth (fuzzed).
- [x] **M3** — `yip-crypto`: Noise-IK session (via `snow`) + explicit-nonce AEAD + replay window.
- [x] **M4** — `yip-io` (io_uring) + `yip-device`: TUN/TAP devices and packet I/O.
- [x] **M5** — `yip-transport`: adaptive FEC + per-flow classifier + stateful flow heuristic.
- [x] **M6** — `yipd` end-to-end 2-peer encrypted tunnel (ping-tested across network namespaces).
- [x] **M7** — benchmark harness: hot-path micro-benchmarks and a `tc netem` yip-vs-WireGuard
  comparison — yip's FEC recovers loss WireGuard passes through (~1 % effective at 10 % injected vs
  ~17 % for WG) for a ~0.2 ms RTT premium, and under loss yip's scp throughput holds while
  WireGuard's TCP collapses (~6× yip at 5–10 % loss). See
  [`crates/yip-bench/README.md`](crates/yip-bench/README.md).
- [x] **#2 Control plane** — multi-peer routing + self-certifying key-derived addresses (2a);
  rendezvous + UDP hole-punching + blind relay (2b); decentralized CA-gated gossip discovery /
  private membership mesh (2c). All merged, netns money-tests on both drivers.
- [x] **#3a Anti-DPI (kill fixed bytes)** — opt-in `obf_psk` obfuscation: a keyed envelope wraps
  every datagram (masked type + random padding, no fixed byte/size), control-timer jitter, and an
  nDPI CI oracle proving obfuscated traffic classifies as `Unknown`. Merged.
- [x] **#4 Throughput (single-core)** — the FEC codec swapped from RaptorQ to a small-K systematic
  **Reed–Solomon** codec (encode ~26 µs → ~1.3 µs); a fast `ring` ChaCha20-Poly1305 data path
  (~2.1 µs → 0.6 µs); batched `sendmmsg`/`recvmmsg`; send-side `UDP_SEGMENT` GSO (+25–31 %); and TUN
  vnet-header GSO/GRO offload. All merged.
- [ ] **Next** — #4c MTU-aware packetization; #3b junk/decoy packets + traffic-shaping, #3c TLS/QUIC
  mimicry (REALITY), #3d pluggable transports; then traffic-analysis defense (#4) and the PQ-hybrid
  handshake.

Guides: [user guide](docs/user-guide.md) · [configuration reference](docs/configuration.md) ·
[testing & benchmarking](docs/testing-and-benchmarking.md) · [`example.config`](example.config).

## Building

Requires a recent stable Rust toolchain (Linux).

```sh
cargo build --release --workspace   # yipd, yip-ca, yip-rendezvous + all crates
cargo test  --workspace             # run the test suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

To run a tunnel, copy [`example.config`](example.config), fill in keys
(`yipd --genkey`), and `sudo yipd your.config` — the [user guide](docs/user-guide.md) walks through
a two-node tunnel, mesh mode, NAT traversal, and enabling obfuscation. The full config/CLI/env
reference is [`docs/configuration.md`](docs/configuration.md); how to test and benchmark is
[`docs/testing-and-benchmarking.md`](docs/testing-and-benchmarking.md).

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

Copyright © 2026 **FEMBOY CYBER NETWORKS LLC**.

`yip` is free software licensed under the **[GNU Affero General Public License v3.0 or later](LICENSE)**
(AGPL-3.0-or-later). The AGPL's network-use clause (§13) is deliberate: anyone who runs a modified
`yip` as a network service must offer their users the corresponding source. Privacy infrastructure
should stay open — the fox's tricks belong to everyone.
