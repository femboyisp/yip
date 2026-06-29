# Architecture

This is a navigational summary. The authoritative design lives in the specs and plans under
`docs/superpowers/`; the cross-cutting research conclusions live in `docs/research/`.

## Map of the docs

- **`docs/research/00-overview.md`** — synthesis of ~35 reference projects and the cross-cutting
  design conclusions that drive yip. Start here for *why* the design is what it is.
- **`docs/research/01–07`** — per-cluster deep analysis (WireGuard family, mesh overlays, anonymity
  networks, mixnet/proxies, transport/FEC, crypto/PQ, DPI engines).
- **`docs/superpowers/specs/`** — approved design specs, one per sub-project.
- **`docs/superpowers/plans/`** — bite-sized implementation plans, one per milestone.

## Project shape

yip is decomposed into five sub-projects, built in order. Each is independently testable and ships
on its own; later sub-projects layer onto the data plane through stable trait interfaces.

```
                 ┌─────────────────────────────────────────────┐
 #4 DAITA /      │  per-flow anonymity dial (optional onion)    │
 anonymity       └─────────────────────────────────────────────┘
                 ┌─────────────────────────────────────────────┐
 #3 anti-DPI     │  obfuscating link layer (impl of `Link`)     │
                 └─────────────────────────────────────────────┘
                 ┌─────────────────────────────────────────────┐
 #2 control      │  discovery · NAT traversal · relay fallback  │
 plane           └─────────────────────────────────────────────┘
                 ┌─────────────────────────────────────────────┐
 #1 DATA PLANE   │  device ↔ transport ↔ crypto ↔ wire ↔ io     │  ← built first
 (this repo's    │  (TUN/TAP) (RaptorQ) (Noise) (frame) (uring) │
  current focus) └─────────────────────────────────────────────┘
```

## Data-plane pipeline (sub-project #1)

Encrypt-then-FEC. Each layer is one Rust trait, independently testable, with the I/O backend
swappable without touching the protocol.

**Egress** (host → wire):

```
TUN/TAP frame
  → classify (DSCP/5-tuple → FlowClass: policy → DSCP → heuristic → default)   [yip-transport]
  → seal     (AEAD-encrypt the inner frame end-to-end)                          [yip-crypto]
  → encode   (RaptorQ-encode the ciphertext → symbols)                          [yip-transport]
  → frame    (keyed header-protection + coverage-auth, one symbol per datagram) [yip-wire]
  → send     (io_uring ring / AF_XDP)                                           [yip-io]
```

**Ingress** reverses it: `recv → deframe (auth + deprotect) → decode (object complete?) → open →
write`.

### Why this is low-latency

Crypto is latency-irrelevant (~0.5–2 µs/packet). The real cost in a userspace tunnel is syscalls,
kernel/user copies, and async scheduling jitter. yip attacks that with a single `io_uring` ring
servicing both the UDP socket and the TUN/TAP fd (busy-polled), and an AF_XDP zero-copy backend for
bare metal — closing most of the gap to kernel WireGuard. RaptorQ recovers loss *proactively*, so
there is no retransmit round-trip and p99 latency stays flat under loss.

## Conventions

See `CLAUDE.md` and the [Mullvad coding guidelines](https://github.com/mullvad/mullvadvpn-app).
Highlights: workspace lint set with `-D warnings`; no `as` numeric casts; `#![forbid(unsafe_code)]`
everywhere except `yip-io`; ≥90 % coverage on logic crates; pinned dependency versions.
