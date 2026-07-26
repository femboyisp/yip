# Security Policy

yip is a VPN — its whole job is security — but it is **pre-1.0 software with one maintainer
and no external audit**. Treat it accordingly. If you rely on it in a threat-model where
compromise is dangerous, read the honest accounting below first.

## Reporting a vulnerability

> [!CAUTION]
> Do not open a public issue for a security vulnerability.

Report privately via GitHub's [private vulnerability
reporting](https://github.com/femboyisp/yip/security/advisories/new), or email the maintainer
at the address in the repo profile. Include enough to reproduce (affected version/commit,
config, and a description or PoC). We'll acknowledge, work a fix, and credit you unless you'd
rather stay anonymous. There is no bounty program.

## Supported versions

There are no releases yet; `main` is the only supported branch. Fixes land there.

## What yip protects

- **Confidentiality + integrity** of tunneled traffic: ChaCha20-Poly1305 AEAD over a Noise-IK
  session, per-direction keys, a replay window, and ~120 s rekey. Keys are classical today.
- **Identity**: mesh membership requires a CA-signed certificate; handshake admission checks
  the peer's static key; a TAI64N timestamp closes an endpoint-hijack-via-replay vector;
  endpoint roaming follows only authenticated packets; rendezvous registration is signed on
  the UDP path.
- **Content-DPI resistance**: no fixed bytes or constant offsets (property-tested); nDPI
  classifies obfuscated traffic as `Unknown`; an Xray-REALITY transport parrots real TLS for
  hostile networks.

## What yip does *not* (yet) protect — read this

- **Traffic analysis.** There is no timing/padding (DAITA-style) defense yet. The FEC burst
  shape, packet-size distribution, and constant-interval idle cover traffic are observable to
  a statistical/flow classifier, and the high-entropy-UDP anomaly is not gated. Use the
  REALITY/TLS transport, not plain `obf_psk`, where the network is actively hostile.
- **The control plane has known hardening gaps** — the TLS relay-front registration is not yet
  signed, the resolver can be steered by an unauthenticated address, and a couple of
  registration/handshake replay windows exist. These are tracked openly in the
  [issue tracker](https://github.com/femboyisp/yip/issues) (search `security`).
- **No independent audit.** The crypto reuses audited primitives (`snow`, `ring`), but the
  protocol composition and the control plane have not been externally reviewed.

If a documented limitation above matters to your threat model, that's a reason to wait, not a
vulnerability to report — but a *new* way to break the stated guarantees is exactly what we
want to hear about privately.
