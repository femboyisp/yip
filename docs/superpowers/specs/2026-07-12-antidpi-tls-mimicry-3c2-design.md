# Sub-project #3 Milestone 3c.2: TLS Mimicry (the TLS costume) — Design

**Status:** draft (under review)
**Sub-project:** #3 (anti-DPI / censorship resistance), milestone 3c.2. 3a
(`obf_psk`) #43, 3b (junk/traffic-shaping) #47, and 3c.1 (QUIC mimicry) #48 are
merged. On main after the docs/license pass (#57).

---

## 1. Goal

Give yip a **TLS-over-TCP-443 costume** so it survives networks that block UDP
(and therefore both raw-UDP and the 3c.1 QUIC path) entirely — the "only 443/TCP
HTTPS is allowed" regime. yip traffic on this path must **classify as ordinary
browser HTTPS** to DPI: a real TLS 1.3 handshake with a **JA3/JA4 fingerprint that
matches a current mainstream browser**, a plausible SNI, and nothing that flags as
a VPN or as an unusual TLS client.

This is the **QUIC costume's TCP sibling**, built the same way 3c.1 was: a *real*
TLS stack carrying yip's **unchanged** inner protocol. It is explicitly a
**last-resort fallback path**, not the low-latency north-star path (see §2).

## 2. What this is NOT (honest scope + tradeoffs)

- **Not the low-latency path.** TLS is over TCP: head-of-line blocking, and yip's
  FEC gives no benefit over an already-reliable, in-order stream. This path trades
  yip's latency/loss-recovery identity for reachability. It is **opt-in and
  last-resort** — used only where UDP (raw + QUIC) is blocked. The default
  raw-UDP path and the 3c.1 QUIC path are unchanged and preferred.
- **Not active-probe defense.** Like 3c.1's QUIC costume, the outer TLS is
  **zero-auth**: it makes traffic *look* like browser HTTPS, defeating content
  classification, entropy heuristics, JA3/JA4 fingerprinting, and port-allowlist
  censorship. It does **not** make the endpoint survive an *active probe* (a
  scanner connecting and checking whether a real website answers). Full REALITY
  active-probe defense requires a server hiding behind a real site, which fits
  yip's **relay/rendezvous tier**, not symmetric P2P peers — that is a separate
  milestone **3c.3 (REALITY on the relay)**, explicitly out of scope here.
- **Not TCP hole-punching.** TCP NAT traversal for double-NAT'd peers is
  unreliable and **deferred**. 3c.2 carries TLS-TCP to **directly-reachable peers
  and the relay/rendezvous**. In a UDP-blocked hostile network the relay (over
  TLS-TCP-443) is the realistic path anyway.
- **Not a new discovery path.** The UDP-based rendezvous / NAT-hole-punch control
  plane (2b) does not run over TLS-TCP (and would be blocked in a UDP-blocked
  network anyway). 3c.2 connects to the **configured** `peer_endpoint` / relay
  endpoint — same as the 3c.1 QUIC path, which also dials the configured endpoint
  with a role tiebreak rather than discovering it. Dynamic discovery over TCP is
  future work.

## 3. Approach (in one line)

Run yip's **unchanged** inner protocol (Noise-IK handshake, cert admission, FEC,
AEAD, driven by `PeerManager`) inside a **real rustls TLS 1.3 connection over
TCP**, with a **browser-parrot ClientHello**, framed as length-prefixed messages
over the TLS byte-stream. A dedicated `run_tls` pump mirrors 3c.1's `run_quic`.

## 4. The unknown, and why Task 0 is a spike

The one genuinely risky piece is the **browser-parrot ClientHello**. rustls does
**not** parrot browsers — its default ClientHello has a distinctive "Rust TLS
client" JA3/JA4. Producing a *current Chrome/Firefox* JA3/JA4 in Rust, within
yip's constraints (`forbid(unsafe)` outside yip-io/yip-device, pinned deps,
workspace lints), is unproven and may require either coaxing rustls
(cipher/extension/order customization) or a BoringSSL-backed path (`boring`).

**Task 0 (throwaway spike, hard gate):** stand up a minimal TLS-over-TCP tunnel
and verify its ClientHello produces a **JA3/JA4 that matches a real browser**,
checked against the existing nDPI oracle (`bin/yipd/tests/run-ndpi-oracle.sh`,
which builds JA3/JA4 + extracts SNI). Try rustls-coaxing first; if it cannot reach
a clean browser fingerprint, evaluate `boring`. **Gate:** if neither yields a
JA3/JA4-clean browser parrot within the constraints, STOP and report before
building §5 — do not ship a costume that fingerprints as a non-browser TLS client.
The spike records the chosen mechanism + the exact parrot target (e.g. Chrome
current-stable).

## 5. Architecture

Mirrors 3c.1 (`bin/yipd/src/quic.rs`) — TLS-over-TCP in place of QUIC-over-UDP.

### 5.1 Two layers
- **Outer TLS (the costume, zero-auth by design):** a real rustls TLS 1.3
  session. Client side sends the **browser-parrot ClientHello** (Task 0's
  mechanism) with SNI = a configurable real domain (`tls_sni`, e.g.
  `www.apple.com`); server side presents a throwaway self-signed cert for that
  name; the client uses an accept-any-cert verifier (the outer TLS authenticates
  nothing — a TLS MITM recovers only inner yip ciphertext, exactly as 3c.1's QUIC
  MITM does).
- **Inner yip (the real security), UNCHANGED:** every datagram the raw-UDP path
  would put on the wire is instead written to the TLS stream. `PeerManager` runs
  Noise-IK, FEC, AEAD, cert admission, and anti-hijack exactly as on raw/QUIC.
  This module is purely transport.

### 5.2 Datagram framing over the TLS byte-stream
Unlike QUIC (RFC 9221 DATAGRAM frames carry message boundaries), TLS is a
**byte-stream**. yip's datagram protocol is recovered with a minimal length
prefix: each yip datagram is written as `[u16 length big-endian][datagram
bytes]`; the reader accumulates TLS plaintext and emits a datagram once a full
`length`-body has arrived. `length ≤ MAX_WIRE_DATAGRAM`; a malformed/oversized
length tears down the connection (fail-closed). This 2-byte prefix rides *inside*
the TLS record layer — invisible on the wire (the wire shows only TLS records).

### 5.3 The `run_tls` pump (`bin/yipd/src/tls.rs`)
A dedicated loop like `run_quic`, selected when `transport=tls`:
- **Role (avoid glare, mirror 3c.1):** the peer with the **smaller**
  `local_public` is the TCP **client** (`TcpStream::connect` + TLS client
  handshake); the **larger** is the TCP **server** (`TcpListener::accept` + TLS
  server handshake). One deterministic connection per pair.
- **Pump:** drive the TCP socket + rustls state machine with the same SAFE epoll
  primitive 3c.1 uses (`yip_io::epoll::Epoll`), so all `unsafe` stays in yip-io
  and `yipd` keeps `#![forbid(unsafe_code)]`. Per iteration: read TCP → feed
  rustls → drain decrypted plaintext → de-frame (§5.2) → `PeerManager::on_udp` →
  frame the returned egress → write to rustls → flush TCP. TUN frames go through
  `PeerManager::on_tun`; `PeerManager::tick` fires on cadence.
- **Reconnect:** on TCP/TLS teardown, the client re-dials with backoff (the inner
  Noise session re-handshakes as it would after any transport blip). The data
  hot path is never blocked on reconnect logic.

### 5.4 Config surface
`transport=tls` joins the existing `TransportMode` enum (`raw`/`udp`/`quic`,
default `RawUdp`). New optional keys, only meaningful when `transport=tls`:

| Key | Value | Default | Notes |
|---|---|---|---|
| `transport` | `tls` | (absent ⇒ `RawUdp`) | Selects the TLS costume. Mutually exclusive with `obf_psk` (like `quic`). |
| `tls_sni` | domain string | a sane default (e.g. `www.apple.com`) | SNI + self-signed cert name for the costume. |

`transport=tls` is **mutually exclusive with `obf_psk`** (the TLS layer *is* the
obfuscation on this path; double-wrapping is pointless), consistent with 3c.1.

## 6. Security & correctness invariants

1. **Inner protocol unchanged.** Noise-IK, cert admission, FEC, AEAD, anti-hijack,
   rekey are byte-for-byte the raw-path logic. 3c.2 is transport only; a compromise
   of the outer TLS (zero-auth) yields only inner yip ciphertext.
2. **Opt-in, default byte-identical.** With `transport` absent (or `raw`/`udp`),
   there is no TLS, no TCP listener, no new bytes — the merged raw-UDP / 3a / 3b /
   3c.1 behavior is untouched.
3. **Fail-closed framing.** A malformed length prefix, an oversized frame, or a
   TLS error tears the connection down without touching session/admission state or
   panicking; the inner Noise session simply re-handshakes on reconnect.
4. **No weakening of 3a/3b/3c.1.** `transport=tls` is a distinct path; the obf_psk,
   junk, and QUIC paths are unchanged. Mutual exclusion with `obf_psk` is enforced
   at config load (clear error), same as `quic`.
5. **`unsafe` contained.** rustls, the TCP sockets, and the epoll primitive keep
   `unsafe` inside `yip-io` / dependencies; `yipd` stays `#![forbid(unsafe_code)]`.
   No `as` numeric casts except discriminants/libc-ABI.
6. **The costume is a real handshake.** A *real* rustls TLS 1.3 handshake with a
   browser-parrot ClientHello — never a hand-rolled fake TLS record layer (which
   subtle deviations would betray). This is the whole point of using rustls/boring.

## 7. Testing

- **Task 0 spike report:** the chosen ClientHello mechanism (rustls-coaxed vs
  `boring`), the parrot target, and the nDPI JA3/JA4 + SNI result. Decision gate
  recorded.
- **Unit (`tls.rs` framing):** `[u16 len][body]` frame/de-frame round-trip;
  partial-record accumulation (a datagram split across two TLS reads reassembles);
  an oversized/zero length is rejected to the fail-closed path.
- **Config:** `transport=tls` parses; `transport=tls` + `obf_psk` set together is
  a load-time error (mirrors the `quic` mutual-exclusion test).
- **netns integration (the money test):** two `yipd` with `transport=tls` complete
  the Noise handshake + ping across the TLS-TCP tunnel (direct-reachable, no NAT);
  a bulk transfer arrives intact; teardown/reconnect recovers. `transport` absent
  stays byte-identical (existing suite green).
- **nDPI oracle (hard gate):** run the TLS path through `run-ndpi-oracle.sh` →
  classifies as **TLS/HTTPS** (not VPN, not `NDPI_OBFUSCATED_TRAFFIC`), with a
  browser JA3/JA4 and the configured SNI. Add a `transport=tls` arm alongside the
  existing raw/obf/QUIC arms.
- **No-regression:** full workspace + the existing netns suite on both drivers
  (the raw/obf/QUIC paths unchanged); `transport=tls` is additive.

## 8. Scope & files

- **Create:** `bin/yipd/src/tls.rs` (the `run_tls` pump + framing + role/reconnect
  + the browser-parrot rustls config from Task 0), unit tests inline.
- **Modify:** `bin/yipd/src/config.rs` (add `Tls` to `TransportMode`, `tls_sni`
  key, the `obf_psk` mutual-exclusion check), `bin/yipd/src/tunnel.rs` (dispatch
  `transport=tls` → `run_tls`, next to the existing `quic` branch),
  `bin/yipd/Cargo.toml` (add `rustls` — or `boring`, per Task 0 — pinned),
  `docs/configuration.md` + `example.config` (document `transport=tls` / `tls_sni`),
  `bin/yipd/tests/run-ndpi-oracle.sh` (add the TLS arm), `CHANGELOG.md`.
- **Untouched:** `PeerManager` inner logic (Noise/FEC/AEAD/admission), `yip-wire`,
  `yip-crypto`, `yip-transport`, the raw-UDP and QUIC paths, 3a/3b obfuscation.

**Out of scope (later):** REALITY active-probe defense on the relay/rendezvous
tier (**3c.3**); TCP hole-punching for double-NAT'd P2P; disabling FEC repair on
the TLS transport (a bandwidth optimization — `repair-ratio → 0` when
`transport=tls`); port plausibility defaults (**3d**, issue #45).
