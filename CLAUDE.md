# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This project builds **yip**, a **low-latency, high-performance, P2P mesh-network VPN tunnel written
in Rust**. The original full brief lives in `projectref.md` (local, git-ignored). Key required
properties:

- NAT hole-punching (rendezvous + UDP hole-punching; relay fallback)
- Forward error correction for lossy links (originally RaptorQ; **swapped in #50 for a small-K
  systematic Reed–Solomon codec** over GF(256) — ~20× cheaper encode, no ratelessness tax)
- L2 data plane (TAP-based bridging / L2 VPN) **and** L3 tunneling (TUN)
- Post-quantum encryption at high performance / low latency, with key rotation
- Elimination of DPI-detectable network signatures (anti-DPI / censorship resistance)

**Status:** past research; the design is approved and implementation has begun. Sub-project #1 (core
data plane + FEC transport) is specced, and milestone **M1 (workspace scaffold + quality gates) is
merged** — six crate stubs (`yip-io`, `yip-wire`, `yip-crypto`, `yip-transport`, `yip-device`) plus
the `yipd` binary, all gates green. See `README.md` for the public overview and `docs/` for design.

## Layout

- `README.md` — public repository overview: goals, status, architecture, build.
- `projectref.md` — the original vision brief + annotated list of ~35 reference projects
  (**local, git-ignored** — not committed).
- `refrences/` — local clones of those reference projects (note the spelling: `refrences`, not
  `references`; **local, git-ignored**). **Read-only reference material — do not modify these clones.**
- `docs/research/` — our analysis of every reference repo. **Start with
  [`docs/research/00-overview.md`](docs/research/00-overview.md)**, which synthesizes the
  cross-cutting design conclusions and indexes the seven per-cluster analysis files (01–07).
- `docs/superpowers/specs/` — design specs (created during brainstorming, once design is approved).

## How to work in this repo (for now)

- The research in `docs/research/` is the institutional memory — consult it before proposing
  architecture; it already records what each reference does well/badly and what is reusable.
- When analyzing a reference project, the clones in `refrences/` are authoritative — read the actual
  source rather than relying on the one-line descriptions in `projectref.md`.
- Design work follows the superpowers flow: **brainstorming → spec in `docs/superpowers/specs/`
  → writing-plans → implementation.** Do not jump to scaffolding code before a design is approved.
- Implementation milestones are tracked in `docs/superpowers/plans/`; M1 is complete and merged.

## Key architectural decisions reached during research

These are starting positions (see `docs/research/00-overview.md` for full reasoning), not final:

- **Data plane:** fork/adapt the modern async userspace WireGuard model (Mullvad **gotatun** is the
  best baseline) rather than writing Noise from scratch.
- **Control plane is the real work:** discovery, NAT traversal, and relay are *not* provided by any
  WireGuard fork and must be built. Lean toward a control/data split (OmniNervous) with decentralized
  discovery (Yggdrasil-style DHT/tree or gossip) and an optional signed root set for bootstrap.
- **Addresses:** self-certifying, derived from the public key (no address authority).
- **Transport:** small-K systematic **Reed–Solomon** FEC primary (`yip-transport::rs`, GF(256)
  Cauchy; RaptorQ was the original plan, dropped in #50 — its K′=10 min-block padding taxed every
  small packet for a ratelessness yip never uses), thin ARQ for residual loss; pluggable,
  obfuscatable link layer (plain UDP / TCP-in-UDP mimicry / TLS-mimicry / relay).
- **Crypto:** 256-bit AEAD data plane (ChaCha20-Poly1305 baseline) + **Rosenpass-style hybrid PQ
  handshake** (Classic McEliece + ML-KEM) feeding a PSK; ~120 s rekey.
  **Homomorphic encryption is NOT used in the data plane** (orders-of-magnitude overhead, no benefit);
  reserve HE/MPC only for optional metadata-privacy control-plane features (PSI/PIR).
- **Anti-DPI:** no fixed magic bytes / reserved fields; randomized padding, timing jitter, junk
  packets (AmneziaWG recipe); optional TLS-mimicry (Xray REALITY model). **nDPI/nDPId are the test
  adversary** and should be wired into CI to verify undetectability.
- **Anonymity is a per-flow dial** (default fast direct P2P; optional onion routing reusing Arti
  crates), not an always-on cost.
