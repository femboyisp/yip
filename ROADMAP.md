# Roadmap

Where yip is and where it's going. Honest about status — nothing here is checked off unless
it's merged with tests. Dates are deliberately absent; this is a pre-1.0 project with one
maintainer.

## Done (merged, with integration tests on both I/O drivers)

- **Data plane + FEC transport** — encrypted L2/L3 tunnel over a systematic Reed–Solomon-FEC
  UDP transport; batched `sendmmsg`/`recvmmsg`, `UDP_SEGMENT` GSO, TUN vnet-header offload.
- **Control plane** — multi-peer routing, self-certifying key-derived addresses, rendezvous +
  UDP hole-punching + blind relay, CA-gated gossip discovery (private membership mesh).
- **Anti-DPI transports** — `obf_psk` obfuscation (no fixed bytes/offsets, nDPI-proven
  `Unknown`), junk/decoy + timing jitter, and an Xray-REALITY TLS-mimicry transport.
- **Session security** — ~120 s rekey with epoch overlap; handshake anti-replay (TAI64N);
  signed rendezvous registration; authenticated endpoint roaming.

## Now

- **Throughput / multi-core.** Single-core is today's ceiling (~142 Mbit/s single-stream on a
  1-vCPU box). Plan: profile the per-core budget → `SO_REUSEPORT` + per-core flow-hashed
  workers for gigabit+ aggregate → cut per-packet cost (header-auth, batched AEAD/FEC, wider
  GSO/GRO) → loss-gated adaptive FEC so clean paths run near line-rate without dropping
  resilience. Headline target: gigabit+ aggregate; single-flow approaching kernel WireGuard is
  the stretch.

## Next

- **Traffic-analysis defense** — jitter the cover-traffic cadence, shape the FEC burst/size
  distribution, and add a statistical/entropy DPI test gate (beyond the nDPI content gate).
  Pairs naturally with the packet-shaping half of the throughput work.
- **Control-plane hardening** — the open security issues: relay-front signed registration,
  resolver signed-endpoint binding, wall-clock registration/anti-replay floors, per-epoch
  obf-key rotation. See the [issue tracker](https://github.com/femboyisp/yip/issues).
- **Quality-gate expansion** — bring `yipd` under coverage; widen mutation testing past the
  logic crates; add a perf-regression gate; commit a reproducible WAN benchmark harness.

## Later

- **Post-quantum handshake** — a Rosenpass-style hybrid (Classic McEliece + ML-KEM) path
  behind the existing rekey machinery.
- **Multi-platform** — macOS/Windows backends; an AF_XDP kernel-bypass relay tier.
- **Maintainability** — split the large `peer_manager.rs`/`stream.rs` into module directories.

## Not goals (for now)

- A hosted service, a GUI app, or mobile clients — yip is the protocol and daemon first.
- Always-on anonymity — traffic-analysis defense and onion routing are opt-in dials, not
  costs everyone pays.

The full backlog lives in the [issue tracker](https://github.com/femboyisp/yip/issues).
