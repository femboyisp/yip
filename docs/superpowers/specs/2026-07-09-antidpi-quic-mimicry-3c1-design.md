# Sub-project #3 Milestone 3c.1: QUIC Mimicry (the QUIC costume) — Design

**Status:** approved (brainstorming complete), ready for implementation planning.
**Sub-project:** #3 (anti-DPI / censorship resistance), milestone 3c.1. 3a
(obf_psk obfuscation) merged; 3b (junk/traffic-shaping) in review (PR #47).

## Goal

Make yip traffic **classified as QUIC (HTTP-3) by DPI** so it defeats what 3a/3b
cannot: (a) the `NDPI_SUSPICIOUS_ENTROPY` heuristic (nDPI suppresses entropy risk
for flows it classifies as QUIC/TLS/DTLS), (b) protocol-allowlist censorship
("only 443/HTTPS allowed" — QUIC on 443/UDP *is* mainstream HTTPS), while
**preserving yip's low-latency UDP+FEC north star**. Opt-in; the default raw-UDP
path is byte-identical.

## Approach in one line

Run yip's **unchanged** inner protocol (Noise-IK handshake, cert admission, FEC,
AEAD) inside a **real QUIC connection** (`quinn-proto`) as **RFC 9221 unreliable
DATAGRAM frames** — a genuine QUIC stack (not a hand-rolled fake), so the wire is
real QUIC (nDPI classifies it, active probes see a valid QUIC server) and FEC's
zero-retransmit independence is preserved (DATAGRAM frames are exempt from QUIC's
stream ordering/retransmission).

## Decomposition of sub-project 3c

- **3c.1 (this spec) — the QUIC costume.** A real `quinn-proto` QUIC transport
  carrying yip's inner protocol in DATAGRAM frames; classified as QUIC; entropy
  defeated; FEC preserved. Generic-but-real QUIC handshake (rustls fingerprint).
  Direct-endpoint peers only.
- **3c.2 — REALITY-grade hardening.** Byte-exact browser ClientHello (uTLS-style
  parroting → JA3/JA4 match), genuine-site reverse-proxy fronting for
  unauthenticated probes, burst-size/timing match (R4 Mahalanobis). The
  active-probe + fingerprint layer.
- **3c.3 — compose QUIC with rendezvous/hole-punch/relay (2b) + mesh (2c).**
  QUIC to/through the rendezvous, relay of QUIC packets, NAT traversal under QUIC.

## Scope decisions (locked during brainstorming)

1. **Real `quinn-proto`, not a fake QUIC costume.** Pure-Rust, `#![forbid(unsafe_code)]`-friendly,
   rustls-based. A real handshake is inherently probe-robust and avoids fragile
   hand-rolled emulation. Use `quinn-proto` (the sans-IO state machine), **not**
   the high-level `quinn` crate (which pulls tokio) — we drive it from yipd's
   existing single-threaded epoll loop.
2. **FEC symbols ride as RFC 9221 DATAGRAM frames** — unreliable, unordered, so
   FEC's no-HoL-blocking / zero-retransmit property is fully preserved. FEC
   recovers datagrams dropped under a full congestion window (same as UDP loss).
3. **QUIC replaces the obf/junk wire layer.** In `transport=quic` mode the 3a
   `obf_psk` envelope and 3b junk/cover are OFF (QUIC's encryption is the wire
   costume). `transport=quic` and `obf_psk` are **mutually exclusive** (validated
   at config load).
4. **Inner yip protocol unchanged.** Noise-IK, cert admission (2c), FEC, AEAD —
   the real security — run untouched inside QUIC DATAGRAM frames. `PeerManager`
   routing/demux/handshake logic is not modified.
5. **Two-layer security.** Outer QUIC TLS-1.3 uses a **throwaway self-signed
   cert** + client **accept-any-cert** verifier — QUIC provides zero auth, only
   the costume + transport encryption. yip's Noise-IK is the real auth; a MITM of
   the outer QUIC recovers only inner yip ciphertext.
6. **Direct-endpoint peers only** for 3c.1 (the 2a case). Rendezvous/relay/mesh
   composition → 3c.3.
7. **Generic fingerprint is the 3c.1 bar.** quinn's real-but-rustls QUIC
   handshake gets classified as QUIC (the goal); byte-exact browser JA3/JA4
   parroting → 3c.2 (no mature Rust uTLS crate exists; it's the largest cost
   item, deferred).

## Non-goals (out of scope for 3c.1)

- Byte-exact uTLS-style browser ClientHello / JA3/JA4 match → **3c.2**.
- Genuine-site reverse-proxy fronting for probes → **3c.2**.
- Burst-size/timing distribution matching (R4 Mahalanobis) → **3c.2**.
- QUIC composed with rendezvous / hole-punch / relay / mesh → **3c.3**.
- io_uring driver in QUIC mode (poll-only for 3c.1).
- Plausible-port defaults / listening on 443 (R8) → **3d**.
- General N-transport pluggable abstraction → **3d** (3c.1 is one hardcoded
  second transport, selected by config).
- TLS-over-TCP fallback transport (for UDP-blocked networks) → a separate later
  cut; never the FEC data plane (TCP HoL destroys FEC).

## Architecture

### The transport seam

No pluggable-transport trait exists today; the obf layer (`obf_egress`/`deobf_ingress`)
is a byte-envelope on the raw-UDP hot path. QUIC-mimicry is heavier — `quinn-proto`
owns connection state and drives its own packet I/O — so 3c.1 adds a **second,
parallel data-plane driving path** selected once at startup by config
(`transport=quic`), alongside `run_poll`/`run_uring`. Absent the flag ⇒ today's
path byte-identical.

New module `bin/yipd/src/quic.rs`: owns a `quinn-proto::Endpoint` bound to the
existing UDP socket, plus a `run_quic` epoll loop (the "pump"). `PeerManager` is
threaded through unchanged.

### The pump (per epoll wakeup)

1. **UDP readable** → `recvfrom` → `Endpoint::handle(bytes)` → routes to the
   right `Connection` (or accepts a new one).
2. **Drain connection events** → a `Datagram` event carries a **plain yip
   datagram** → `PeerManager::on_udp(quic_peer, bytes)`.
3. **PeerManager egress** (`EgressDatagram`s — plain yip bytes, no obf) →
   `Connection::datagram_send(bytes)` (one QUIC DATAGRAM frame each).
4. **Drain `quinn-proto` transmits** (`poll_transmit`) → `sendto`.
5. **Timers** — epoll timeout = `min(Connection::poll_timeout, yip tick
   interval)`; `PeerManager::tick` runs yip's cadences; QUIC's own loss/idle
   timers driven from `poll_timeout`.

`PeerManager` sees plain yip datagrams over QUIC instead of obf'd ones over raw
UDP — routing/demux/Noise/FEC/cert-admission untouched.

### Two-layer handshake

- **Outer (QUIC, `quinn-proto`):** real QUIC/TLS-1.3 — Initial → ClientHello (in
  CRYPTO frames, carrying a plausible **SNI** + ALPN **`h3`**) → 1-RTT. Server:
  throwaway self-signed cert. Client: accept-any-cert rustls verifier. Zero auth;
  pure costume + transport encryption.
- **Inner (yip, unchanged):** once QUIC is up, `HandshakeInit`/`HandshakeResp`
  Noise-IK + cert admission + Data/Control/FEC flow as DATAGRAM frames. yip's
  static keys + CA cert are the real identity/auth.

A probe that completes the QUIC handshake but can't do yip's inner Noise never
becomes a yip session — yet it saw a valid QUIC server (inherent 3c.1
probe-robustness; 3c.2 adds fronting).

### Data-plane framing & MTU

- **1:1 FEC-symbol ↔ DATAGRAM-frame**, one yip datagram per QUIC packet (avoid
  coalescing → keeps FEC's loss independence).
- **Dynamic symbol size:** QUIC adds ~28 B/packet (short header + conn-id +
  packet-number + AEAD tag). With **PMTUD** enabled, `Connection::max_datagram_size()`
  reaches ~1420 B on a 1500 path, so yip keeps `symbol_size = min(1200,
  max_datagram_size − overhead)` — **1200 in steady state** (a 1200-symbol packet
  is ~1280 B on the wire, well under 1500), dropping below 1200 only in the brief
  pre-PMTUD phase or on a smaller path. Oversized inner datagram = a
  config/telemetry error, never silent truncation.
- **`symbol_size` must be parameterized.** It is currently **hardcoded `1200`**
  in `crates/yip-transport/src/lib.rs` for all flow classes. The plan must
  thread it through `Transport`/`FlowParams` construction so `yipd` passes the
  QUIC-mode value; raw/obf mode passes exactly 1200 (byte-identical).

### Latency tuning

`quinn-proto` `TransportConfig` tuned for latency, not throughput: generous
datagram receive buffer, **congestion-control/pacing bypassed for DATAGRAM
frames** so a datagram is sent immediately (validated in the task-1 spike below —
this is the #1 risk). DATAGRAM frames dropped under a full congestion window are
**recovered by FEC** (same as UDP loss today). Mirrors Hysteria's "real QUIC wire
format, bypass QUIC's conservative loss/CC semantics."

## Performance (flag + measure — QUIC mode is an opt-in premium)

QUIC mode is the first thing in the project to add cost to the packet hot path.
It is **opt-in**; the raw-UDP + FEC (+uring) default is untouched and remains the
low-latency north-star path. Known costs + one hard risk:

1. **Double encryption (throughput tax, ~zero latency):** every datagram is
   sealed twice — yip's inner Noise AEAD *and* QUIC's outer AEAD + header
   protection (~+2–4 µs/packet on top of ~2 µs AEAD + ~24 µs FEC ⇒ ~10–15%
   throughput). Unavoidable: yip's inner AEAD is the real security (QUIC's cert
   is throwaway), and a plaintext QUIC packet isn't QUIC. Accept.
2. **Poll-only** → QUIC mode's latency floor is epoll (~0.37 ms), not
   uring+busypoll (~0.30 ms). The lowest-latency mode stays non-QUIC.
3. **Correlated loss** if datagrams coalesce into one QUIC packet → send one
   datagram/packet (above).
4. **THE RISK — `quinn-proto` datagram send latency.** The design assumes a
   DATAGRAM frame can be sent *immediately*, bypassing CC/pacing. This is an
   assumption about `quinn-proto`'s knobs and **must be validated with real code
   before building the full transport** (task 1 spike). If it can't, the approach
   needs a contingency.
5. **Throughput opportunity — GSO/`sendmmsg`.** Production QUIC batches sends via
   UDP GSO; yip-io has a `send_batch`/mmsg seam. Research whether QUIC-mode sends
   can batch to claw back the double-encryption tax (opportunity, not a
   requirement for 3c.1).

The plan extends `yip-bench` with a **QUIC-vs-raw benchmark** (latency +
throughput, `transport=quic` vs raw+obf) so the premium is measured, not guessed.

## Security

- Two independent layers; the outer QUIC (throwaway cert, accept-any-cert) is
  MITM-able **by design** and provides no auth — a MITM recovers only inner yip
  ciphertext, still protected by Noise-IK + 2c cert admission. QUIC breaking ≠
  yip breaking.
- Anti-hijack / admission (2a/2b/2c) unchanged — the inner protocol is untouched.
- `quinn-proto` is `#![forbid(unsafe_code)]`-friendly; QUIC mode adds no `unsafe`
  to yipd. New dependency `quinn-proto` (+ its rustls/ring transitive deps) is
  scoped to the `yipd` crate only.

## Testing

**The headline money test — the oracle flips from 3a.** A new
`bin/yipd/tests/run-quic-mimicry-oracle.sh` + `quic_classified_as_quic` netns
test captures a yip-over-QUIC exchange and asserts, via `ndpiReader`:
- **(a) the flow is positively classified as `QUIC`** (not `Unknown`) — a real
  quinn QUIC Initial is what nDPI's QUIC dissector keys on.
- **(b) `NDPI_SUSPICIOUS_ENTROPY` is NOT raised** — the concrete, testable proof
  3c defeats the entropy heuristic 3a/3b could only report. (3a asserted
  Unknown + entropy-fired-report-only; 3c asserts QUIC + entropy-suppressed.)

**netns connectivity + no-regression (poll driver):**
- `transport=quic`: two `yipd` complete the two-layer bring-up (QUIC handshake →
  inner yip Noise-IK → cert admission → ping) + a loss variant proving **FEC
  recovers dropped DATAGRAM frames** over QUIC.
- **No-regression:** `transport` unset ⇒ raw-UDP path (incl. 3a/3b) byte-identical
  — existing netns suite green, both drivers. Config validation:
  `transport=quic` ⊕ `obf_psk` (mutually exclusive, error at load).

**Unit:** the `quic.rs` pump (endpoint setup, client+server QUIC handshake
completes, a yip datagram round-trips a DATAGRAM frame, oversized-datagram
rejected); the `symbol_size` parameterization (QUIC value vs exactly-1200 raw);
config parse/validation.

**Light probe check:** an off-the-shelf QUIC client (`curl --http3` / a bare
quinn client) gets a valid QUIC handshake but never a yip session — documents the
3c.1 probe posture (3c.2 hardens with fronting).

**Honest scope in the tests:** 3c.1 proves "classified as QUIC, entropy defeated,
FEC-preserved connectivity" — NOT JA3/JA4-browser-exactness or probe-fronting
(3c.2). Framed like 3b's flow-shape check, not overclaiming "indistinguishable
from Chrome."

## Task-1 spike (de-risk before building)

The plan's first task is a **`quinn-proto` datagram spike**: a minimal
client/server echoing DATAGRAM frames, measuring (a) datagram send latency with
CC/pacing configured off (the #1 risk), (b) per-packet CPU overhead vs raw UDP,
(c) that PMTUD yields the ~1200 datagram budget. A failing spike (datagrams not
sent promptly) surfaces the contingency in task 1 — cheap — before the full
transport is built.

## Integration surface

- New: `crates`-external dependency `quinn-proto` (yipd only); `bin/yipd/src/quic.rs`
  (endpoint + pump); `run_quic` epoll variant; `config.rs` `transport` field +
  mutual-exclusion validation; `tunnel.rs` transport selection.
- Modified: `crates/yip-transport` — parameterize `symbol_size` through
  `Transport`/`FlowParams` (was hardcoded 1200 in `lib.rs`).
- Unchanged: `PeerManager` (routing/demux/Noise/FEC/cert-admission), yip-crypto,
  yip-wire, the raw-UDP + obf_psk + junk paths.
