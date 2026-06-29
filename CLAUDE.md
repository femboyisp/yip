# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is a **design/research-stage** project (not yet a codebase) to build a new networking application:
a **low-latency, high-performance, P2P mesh-network VPN tunnel written in Rust**. The full goal is in
the root `README.md`. Key required properties:

- NAT hole-punching (rendezvous + UDP hole-punching; relay fallback)
- RaptorQ forward error correction (rateless FEC) for lossy links
- L2 data plane (TAP-based bridging / L2 VPN) **and** L3 tunneling (TUN)
- Post-quantum encryption at high performance / low latency, with key rotation
- Elimination of DPI-detectable network signatures (anti-DPI / censorship resistance)

There is **no Rust code yet.** The current contents are research and (forthcoming) design docs.

## Layout

- `README.md` — the vision: goal + an annotated list of ~35 reference projects with links.
- `refrences/` — local clones of those reference projects (note the spelling: `refrences`, not
  `references`). **Read-only reference material — do not modify these clones.**
- `docs/research/` — our analysis of every reference repo. **Start with
  [`docs/research/00-overview.md`](docs/research/00-overview.md)**, which synthesizes the
  cross-cutting design conclusions and indexes the seven per-cluster analysis files (01–07).
- `docs/superpowers/specs/` — design specs (created during brainstorming, once design is approved).

## How to work in this repo (for now)

- The research in `docs/research/` is the institutional memory — consult it before proposing
  architecture; it already records what each reference does well/badly and what is reusable.
- When analyzing a reference project, the clones in `refrences/` are authoritative — read the actual
  source rather than relying on the README's one-line descriptions.
- Design work follows the superpowers flow: **brainstorming → spec in `docs/superpowers/specs/`
  → writing-plans → implementation.** Do not jump to scaffolding code before a design is approved.

## Key architectural decisions reached during research

These are starting positions (see `docs/research/00-overview.md` for full reasoning), not final:

- **Data plane:** fork/adapt the modern async userspace WireGuard model (Mullvad **gotatun** is the
  best baseline) rather than writing Noise from scratch.
- **Control plane is the real work:** discovery, NAT traversal, and relay are *not* provided by any
  WireGuard fork and must be built. Lean toward a control/data split (OmniNervous) with decentralized
  discovery (Yggdrasil-style DHT/tree or gossip) and an optional signed root set for bootstrap.
- **Addresses:** self-certifying, derived from the public key (no address authority).
- **Transport:** RaptorQ FEC primary (`raptorq` crate), thin ARQ for residual loss; pluggable,
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
