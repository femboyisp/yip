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
on its own; later sub-projects layer onto the data plane through stable trait interfaces. #1–#3 are
merged (#3 partially — obfuscation and REALITY TLS-mimicry are in, DAITA-style padding is not); #4
and #5 have not started. See the sub-project table in `README.md` for the authoritative status.

```
                 ┌─────────────────────────────────────────────┐
 #5 multi-core / │  multi-queue sharding · macOS/Windows ·      │
 multi-platform  │  AF_XDP relay tier                           │
                 └─────────────────────────────────────────────┘
                 ┌─────────────────────────────────────────────┐
 #4 traffic-     │  DAITA-style padding/timing · optional onion │
 analysis        └─────────────────────────────────────────────┘
                 ┌─────────────────────────────────────────────┐
 #3 anti-DPI     │  obfuscating link layer (impl of `Link`)     │
                 └─────────────────────────────────────────────┘
                 ┌─────────────────────────────────────────────┐
 #2 control      │  discovery · NAT traversal · relay fallback  │
 plane           └─────────────────────────────────────────────┘
                 ┌─────────────────────────────────────────────┐
 #1 DATA PLANE   │  device ↔ transport ↔ crypto ↔ wire ↔ io     │  ← built first
                 │  (TUN/TAP) (RS-FEC)  (Noise) (frame) (epoll) │
                 └─────────────────────────────────────────────┘
```

## Data-plane pipeline (sub-project #1)

Encrypt-then-FEC. Each layer is one Rust trait, independently testable, with the I/O backend
swappable without touching the protocol.

**Egress** (host → wire):

```
TUN/TAP frame
  → classify (DSCP/5-tuple → FlowClass: policy → DSCP → heuristic → default)   [yip-transport]
  → seal     (AEAD-encrypt the inner frame end-to-end)                          [yip-crypto]
  → encode   (RS-encode the ciphertext → symbols, GF(256) Cauchy or P+Q)        [yip-transport]
  → frame    (keyed header-protection + coverage-auth, one symbol per datagram) [yip-wire]
  → send     (epoll `PollDriver`, batched `sendmmsg`/GSO; io_uring opt-in)      [yip-io]
```

**Ingress** reverses it: `recv → deframe (auth + deprotect) → decode (object complete?) → open →
write`.

### Why this is low-latency

Crypto is latency-irrelevant (~0.5–2 µs/packet after the `ring` ChaCha20-Poly1305 swap; see
`crates/yip-bench/RESULTS.md`). The real cost in a userspace tunnel is syscalls, kernel/user
copies, and scheduling jitter. yip attacks that with a single-threaded `epoll`-driven event loop
(the default `PollDriver`) that batches sends with `sendmmsg`/`UDP_SEGMENT` (GSO) and reads bursts
with `recvmmsg`; an opt-in `io_uring` driver (`YIP_USE_URING=1`) trades a core for lower RTT on
bare metal with adaptive busy-polling. AF_XDP zero-copy is sub-project #5 and has not started. The
Reed–Solomon FEC recovers loss *proactively* (no retransmit round-trip needed for the common case),
so p99 latency stays flat under loss; a thin reactive ARQ backstops residual loss on ARQ-eligible
flows.

## Conventions

See `CLAUDE.md` and the
[coding guidelines](https://github.com/mullvad/mullvadvpn-app/blob/main/CODING_GUIDELINES.md) yip
follows. Highlights: workspace lint set with `-D warnings`; no `as` numeric casts;
`#![forbid(unsafe_code)]` everywhere except `yip-io`; ≥90 % coverage on logic crates; pinned
dependency versions.
