# 07 — DPI Detection Engines: How VPNs Get Fingerprinted (and How to Evade)

Research notes for the Rust P2P mesh VPN. We study three Deep Packet Inspection (DPI)
engines to understand exactly what gives VPN/proxy traffic away, then translate that
into hard requirements for our wire protocol. Goal: **defeat nDPI-class engines.**

Repos analyzed (local clones):

- `refrences/nDPI` — ntop nDPI, the reference open-source DPI library (C, LGPLv3)
- `refrences/nDPId` — nDPId, a lightweight daemon built on libnDPI (C, GPLv3)
- `refrences/rustnet` — rustnet, a per-process network monitor with a small DPI engine (Rust, Apache-2.0)

---

## nDPI (ntop)

### What it does
nDPI is the de-facto open-source DPI library. It classifies network flows into ~300+
application/L7 protocols by combining port heuristics, payload signatures, statistical
heuristics, TLS/QUIC fingerprinting (JA3/JA4), and a per-flow risk-scoring system. It is
embedded in ntopng, nProbe, many commercial middleboxes, and is the engine censorship/
monitoring research is benchmarked against. It is the engine we most need to beat.

### Language / license
C. **LGPLv3** (`COPYING`). ~260 protocol dissectors under `src/lib/protocols/`.

### Detection techniques
nDPI runs a layered pipeline (see Architecture). Concretely it uses:

- **Port-based defaults** — every protocol registers default ports in
  `ndpi_init_protocol_defaults` (`src/lib/ndpi_main.c`). WireGuard → UDP 51820,
  OpenVPN → TCP/UDP 1194, tinc → TCP/UDP 655. Used as a hint and as a fallback "guessed"
  classification when DPI fails.
- **Payload signatures / first-N-bytes matching** — each dissector inspects the first
  bytes of the flow payload for opcodes, magic constants, fixed header layouts, fixed
  packet lengths (e.g. WireGuard's reserved-zero bytes; BitTorrent's `\x13BitTorrent
  protocol`).
- **TLS/QUIC fingerprinting** — `tls.c` parses ClientHello/ServerHello and builds
  **JA3** and **JA4** fingerprints (`tls_match_ja4`, `JA_STR_LEN`), extracts SNI, ALPN,
  supported-versions, cipher list, extension ordering. Hashes are matched against
  malicious-fingerprint hashmaps (`malicious_ja4_hashmap`).
- **Statistical / entropy analysis** — per-flow Shannon entropy
  (`flow->entropy = ndpi_entropy(...)`) mapped to a risk via `ndpi_entropy2risk`
  (`ndpi_utils.c`). High, uniform entropy on traffic that *isn't* already a known
  encrypted protocol (TLS/QUIC/DTLS) raises `NDPI_SUSPICIOUS_ENTROPY`.
- **"Fully encrypted" first-packet heuristic** — `fully_enc_heuristic()` in
  `ndpi_main.c` is a direct implementation of the Wu et al. USENIX'23 algorithm for
  detecting fully-encrypted proxies (Shadowsocks/VMess/obfs). For the first TCP payload
  it computes: (1) popcount bit-ratio must sit in `(3.4, 4.6)` per byte — i.e. ~50% set
  bits, the signature of random ciphertext; (2) first 6 bytes not all printable;
  (3) <50% printable bytes overall; (4) no run of ≥20 printable bytes. A packet that
  looks "too random and has no plaintext structure" is flagged
  `NDPI_OBFUSCATED_TRAFFIC` ("Fully Encrypted"). **This is the headline anti-proxy
  detector — random-looking bytes are themselves a signal.**
- **Flow timing / packet-size distributions (Mahalanobis)** — `tls.c`'s
  `tls_obfuscated_heur_search` / `check_set` model the byte-volume distribution of the
  first 4 client↔server *bursts* (flights) of a flow and compare against precomputed
  multivariate Gaussian models for Firefox TLS 1.2, TLS 1.3, and Chrome
  (mean vectors + inverse covariance matrices, `ndpi_mahalanobis_distance`). This detects
  **obfuscated-TLS and TLS-in-TLS tunnels** (obfs4 with iat-mode, Shadowsocks-over-TLS,
  meek) by their burst-size statistics even when bytes are opaque.
- **DGA / numeric-SNI heuristics** — Tor is identified in TLS partly via DGA-style
  SNI (`www.<random>.com/.net` patterns, numeric-IP SNI, padding-extension anomalies).

### How it fingerprints VPN/proxy protocols (be concrete)

- **WireGuard** (`wireguard.c`): keys entirely off the fixed header. Byte 0 is the
  message type (1=handshake-init, 2=handshake-response, 3=cookie-reply,
  4=transport-data); **bytes 1–3 are reserved and MUST be zero** — if any is nonzero
  the dissector excludes immediately. It then matches **fixed handshake lengths**:
  init = 148 bytes, response = 92, cookie = 64 (148/92 are constant because the
  Noise_IK handshake fields are fixed-size). It cross-checks `sender_index`/
  `receiver_index` consistency across the first packets in each direction. So WireGuard
  is given away by: (a) the 3 zero reserved bytes, (b) the exact 148/92/64-byte
  handshake sizes, (c) the index correlation. (Note: TunnelBear's 204/100-byte variant
  is explicitly handled — nDPI already knows about size-tweak "obfuscation".)
- **OpenVPN** (`openvpn.c`): the first byte's top 5 bits are the **opcode**
  (`P_OPCODE_MASK 0xF8`): HARD_RESET_CLIENT/SERVER V1/V2/V3, CONTROL_V1, ACK_V1, etc.
  It validates the opcode, requires the first packet to be a HARD_RESET, matches the
  8-byte **session-id** across consecutive packets and between client/server resets,
  and (for TCP) checks the 2-byte length prefix equals the payload length. A second
  **opcode-distribution heuristic** (`search_heur_opcode`, from Xue et al. USENIX'22)
  defeats *XOR/obfuscated* OpenVPN: even encrypted, the distribution of the first byte
  (the opcode) over the handshake is distinctive (≥2 distinct non-reset opcodes,
  symmetric traffic) → flagged `NDPI_OBFUSCATED_TRAFFIC` "Obfuscated OpenVPN" at
  AGGRESSIVE confidence. Also explicitly de-collides against STUN's magic cookie
  `0x2112A442`.
- **Tor** (`tls.c`): via TLS fingerprint + self-signed-cert / DGA SNI patterns
  (`www.<random-with-digits>.com|.net`, no ALPN, Encrypt-then-MAC ext present) →
  `NDPI_PROTOCOL_TOR`. Bridges/pluggable transports fall to the obfuscation heuristics.
- **obfs4 / meek / Shadowsocks / VMess**: no per-protocol byte signature (there is none
  — that's the point of these transports). They are caught by the **fully-encrypted
  first-packet heuristic** and/or the **Mahalanobis burst-size heuristic**, both of
  which classify *the absence of structure plus statistical shape* rather than content.
- **Others present**: `tinc.c`, `softether.c`, `ciscovpn.c`, `pptp.c`, `ipsec.c`,
  `wireguard`/`tailscale.c`, `cloudflare_warp.c`, `hamachi.c` — most rely on fixed
  header bytes / handshake constants, same weakness as WireGuard.

### Architecture (flow tracking, classification pipeline)
- **Flow tracking**: 5-tuple flow hash table; per-flow state struct
  (`ndpi_flow_struct`) holds per-protocol scratch (e.g. `l4.udp.wireguard_stage`,
  `ovpn_session_id`, `tls_quic.obfuscated_heur_state`).
- **Pipeline**: on each packet, candidate dissectors are selected by a bitmask
  (proto/L4/IP-version, e.g. `NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD`).
  Each dissector either matches, asks for more packets, or calls
  `NDPI_EXCLUDE_DISSECTOR` to drop out. Detection usually completes within the first
  few packets; if nothing matches, nDPI **guesses by IP/port** (`guessed` event) and may
  run **extra-dissection / heuristic** passes (entropy, fully-encrypted, obfuscated-TLS
  burst stats) over subsequent packets.
- **Output**: a `(master_protocol, app_protocol)` pair, a **confidence** level
  (DPI > DPI_AGGRESSIVE > by-port > by-IP), a **category**, and a set of **risk flags**
  — crucially `NDPI_OBFUSCATED_TRAFFIC` and `NDPI_SUSPICIOUS_ENTROPY`, which a censor
  can act on even without a positive protocol ID.

### Strengths / Weaknesses / evasion gaps
- **Strengths**: very broad protocol coverage; doesn't depend solely on ports;
  statistical heuristics catch "structureless" tunnels; JA3/JA4 catches mimicry that
  reuses a recognizable client fingerprint; emits a "looks obfuscated" verdict even
  when it can't name the protocol.
- **Weaknesses / gaps we can exploit**:
  - Most VPN dissectors hinge on **fixed magic/constants** (WireGuard reserved zeros +
    exact handshake sizes; OpenVPN opcode in the first byte). Remove those → that
    dissector excludes itself.
  - The fully-encrypted heuristic **only runs on TCP flow beginnings** and keys on a
    `(3.4, 4.6)` bit-ratio window plus printable-byte rules — it can be dodged by
    *not* presenting maximal-entropy bytes (deliberate low-entropy framing / mimicry)
    or by avoiding the "first TCP payload" trigger.
  - The obfuscated-TLS heuristic is fitted to **specific browser models** (Firefox/
    Chrome, TLS 1.2/1.3, no resumption/0-RTT) and explicit burst counts/sizes; traffic
    whose burst-size distribution doesn't match the modeled handshake shape, or that
    varies, is not flagged.
  - Heuristics carry false-positive cost, so several are **off by default / aggressive-
    confidence only** and gated to "uninformative" (non-CDN/unknown) destinations.

---

## nDPId

### What it does
nDPId is a small multi-threaded daemon that wraps libnDPI to capture live traffic,
run nDPI classification per flow, and emit **JSON events** (new/end/idle/update/guessed/
analyse/detection-update) over a UNIX socket. `nDPIsrvd` then fans those events out to
consumers (TCP/UNIX). It is essentially "nDPI as a streaming sensor" — the productized
deployment shape of what a monitoring/censorship operator would actually run.

### Language / license
C. **GPLv3** (`COPYING`). Bundles libnDPI (`libnDPI/`).

### Detection techniques
**All L7 detection is delegated to libnDPI** — so every nDPI technique above applies
(port, signatures, JA3/JA4, entropy, fully-encrypted + obfuscated-TLS heuristics). nDPId
adds the *operational* layer:

- **Flow distribution without locks**: a flow's worker thread is chosen by a hash of the
  3-tuple (src/dst IP, L4 proto, src/dst port) so each flow is single-threaded.
- **Flow lifecycle + feature extraction**: the experimental `analyse` event (`-A`)
  exports flow-level features nDPI computes — packet-length and inter-arrival-time
  statistics (min/max/avg/stddev), entropy, direction counters — i.e. the
  **packet-size-distribution and flow-timing** signals, served up for downstream ML.
- **base64 packet events**: can ship raw payloads to consumers for deeper analysis.
- **`guessed` event**: explicitly surfaces when nDPI fell back to IP/port guessing —
  useful to a censor as "unknown encrypted thing on a weird port."

### How it fingerprints VPN/proxy protocols
Same as nDPI (it *is* nDPI). The relevant addition: nDPId makes the **risk flags and the
`analyse` feature stream** first-class outputs, so an operator can build policy on
"`NDPI_OBFUSCATED_TRAFFIC` OR high entropy OR guessed-only on non-standard port" without
writing a single byte-signature.

### Architecture
Microservice: `nDPId` (producer, per-interface, N worker threads) → UNIX socket →
`nDPIsrvd` (collector + distributor, buffering) → consumers (TCP/UNIX). Length-prefixed
JSON stream (`[5-digit-len][json]`). No encryption/auth on the relay yet.

### Strengths / Weaknesses / evasion gaps
- **Strengths**: real-time, scalable, lockless; turns nDPI verdicts + flow stats into an
  actionable event stream; the `analyse` features are exactly what an ML classifier
  would train on.
- **Weaknesses / gaps**: inherits *all* of nDPI's blind spots; adds nothing that sees
  through a tunnel nDPI itself can't. Our evasion target is therefore entirely "beat
  libnDPI's dissectors + heuristics."

---

## rustnet

### What it does
rustnet is a terminal (TUI) per-process network monitor: it maps every TCP/UDP/QUIC
connection to its owning process (eBPF/PKTAP/native APIs) and runs a **lightweight DPI
engine** to label the application protocol. It is a monitoring/observability tool, not a
censorship engine — but it shows the "minimum viable DPI" an endpoint agent ships, and
it's the Rust-ecosystem reference for how to parse these protocols.

### Language / license
Rust. **Apache-2.0** (`LICENSE`). DPI lives in `src/network/dpi/`.

### Detection techniques
- **Port-based dispatch + first-bytes signatures**: `analyze_tcp_packet` /
  `analyze_udp_packet` (`dpi/mod.rs`) try protocols in order, gated by well-known ports
  (22 SSH, 443 HTTPS, 53 DNS, 1883 MQTT, …) **and/or** content signatures
  (`https::is_tls_handshake`, `bittorrent::is_bittorrent_handshake`, `mqtt::is_mqtt_packet`,
  `stun::is_likely_stun`). Signature-based protocols (BitTorrent, STUN magic cookie) work
  on non-standard ports too.
- **TLS parsing (no JA3/JA4)**: `dpi/https.rs` parses ClientHello/ServerHello to extract
  **SNI, ALPN, cipher suite, TLS version** (incl. resilient/partial-record parsing for
  reassembled QUIC). It does **not** compute JA3/JA4 hashes and does not fingerprint the
  client beyond these fields.
- **QUIC**: `dpi/quic.rs` (largest dissector, ~2.5k LOC) detects QUIC, reassembles
  CRYPTO frames, and pulls SNI out of the QUIC ClientHello; detects CONNECTION_CLOSE.
- **No entropy / no fully-encrypted / no obfuscation / no statistical heuristics**:
  there is no popcount/Mahalanobis/timing analysis. If a flow matches no signature and
  no port, it is simply `None` (unknown).
- **TCP analytics**: retransmission / out-of-order / fast-retransmit counters (for health,
  not classification).

### How it fingerprints VPN/proxy protocols
It largely **doesn't**. There is **no WireGuard, OpenVPN, Tor, obfs4, or Shadowsocks
dissector**. A WireGuard or fully-encrypted flow simply shows as unknown UDP/TCP with the
owning process. The one strong signal rustnet *does* have that nDPI lacks: **per-process
attribution** — it knows which binary opened the socket. (For us this is mostly an
endpoint-side concern, not on-path DPI, but worth noting: a VPN client process is itself
identifying.)

### Architecture
Capture (libpcap, privilege-dropped) → worker threads parse L2/L3/L4 + run DPI →
connections keyed by 5-tuple in a `DashMap` → periodic snapshot → TUI. DPI is per-packet,
stateless-ish per call (with QUIC reassembly state), protocol-aware connection timeouts
(SSH 30 min, HTTP 10 min, etc.). DPI can be disabled with `--no-dpi`.

### Strengths / Weaknesses / evasion gaps
- **Strengths**: clean, fast, accurate L7 labels for *plaintext-ish* protocols; SNI/ALPN
  extraction; unique per-process mapping.
- **Weaknesses / gaps**: no statistical, entropy, or obfuscation detection; no VPN
  dissectors; trivially evaded by any encrypted tunnel that doesn't hit a known port
  signature. **Not a threat to a competent VPN — but it confirms the easy wins
  (ports, first-byte magic, TLS SNI) every engine reaches for first.**

---

## Anti-DPI design implications for our protocol

These are concrete, testable requirements for our wire format, derived directly from the
detectors above. The north star: **a passive observer (nDPI/nDPId-class) must not be able
to (a) name our protocol, (b) flag it as `OBFUSCATED_TRAFFIC`/`SUSPICIOUS_ENTROPY`, or
(c) reliably distinguish it from benign traffic by statistics.**

### R1 — No fixed magic bytes, opcodes, or reserved-zero fields
This is the single biggest lesson. WireGuard dies on **3 reserved zero bytes + a
1-byte type field + fixed 148/92/64 handshake sizes**; OpenVPN dies on its **5-bit opcode
in byte 0 + 8-byte session id**. Requirements:
- No constant bytes at fixed offsets, ever. No version/type/reserved field in cleartext.
- Every byte an on-path observer sees, including the *first* byte of the *first* packet,
  must be indistinguishable from random (or from the cover protocol — see R4).
- Message-type discrimination must be done **inside** the encrypted envelope (or via an
  obfuscation key, AmneziaWG-style, see R7), never via a plaintext tag.

### R2 — Defeat the "fully encrypted" first-packet heuristic
nDPI's `fully_enc_heuristic` flags TCP flows whose first payload is maximal-entropy with
no printable structure (bit-ratio ∈ `(3.4,4.6)`, <50% printable, no 20-byte printable
run). Pure random handshakes (Noise, Shadowsocks-style) trip this. Options:
- **Either** mimic a real protocol's plaintext framing so the first bytes *do* contain
  legitimate-looking structure (TLS record header `0x16 03 0x..`, HTTP, etc.) — see R4;
- **Or** shape the first packet to sit *outside* the detector's window: e.g. lower
  measured entropy via structured/typed framing, ensure it isn't the first TCP payload
  in isolation, or pad with low-entropy filler. Note the heuristic is **TCP-only and
  first-packet-only** — a UDP transport that doesn't present a lone high-entropy TCP
  opener avoids it, but UDP draws its own scrutiny, so prefer a deliberate design rather
  than relying on the gap.
- **Test gate**: run our handshake packets through nDPI with `fully_encrypted_heuristic`
  enabled and assert no `NDPI_OBFUSCATED_TRAFFIC "Fully Encrypted"`.

### R3 — Control entropy and avoid `SUSPICIOUS_ENTROPY`
`ndpi_entropy2risk` only suppresses the entropy risk when the flow is *already* a known
encrypted protocol (TLS/QUIC/DTLS). An unclassified high-entropy flow gets flagged.
Therefore: do not be an unclassified high-entropy flow. Either be (convincingly) TLS/QUIC
(R4), or modulate entropy so it doesn't read as "uniform random ciphertext" on the wire.

### R4 — TLS/QUIC mimicry with a *real* fingerprint, not a custom one
nDPI computes JA3/JA4 and matches malicious hashmaps; the obfuscated-TLS heuristic models
**Firefox/Chrome handshake burst sizes** via Mahalanobis distance. Implications if we
mimic TLS:
- Use a **mainstream, current** TLS ClientHello (utls-style "parrot" of Chrome/Firefox):
  correct cipher list, extension *ordering*, supported-versions, ALPN, GREASE, ECH-grease.
  A bespoke handshake yields a unique JA3/JA4 that itself becomes our signature.
- Critically, mimicry must extend **past the handshake into burst sizes/timing** — the
  Mahalanobis model checks the first 4 client↔server flights' byte volumes. If we wrap a
  tunnel inside TLS but our flights don't match a browser's, we get
  `OBFUSCATED_TLS / TLS-in-TLS` flagged. So either match the modeled distribution or
  randomize flights enough to fall outside the (browser-fitted, fixed-distance) models.

### R5 — Randomize packet sizes (kill fixed-length fingerprints)
Fixed handshake/record sizes are a fingerprint (WireGuard 148/92/64; even TunnelBear's
204/100 is already catalogued). Requirements:
- **Randomized, variable-length padding** on every packet, especially handshake packets,
  so no message type maps to a constant length.
- Avoid characteristic length *sequences*. Add jitter to record/datagram sizes so the
  per-flight byte totals don't cluster (defeats Mahalanobis / packet-size-distribution
  ML in nDPId's `analyse` features).

### R6 — Randomize timing / inter-arrival (kill flow-timing fingerprints)
nDPId's `analyse` exports IAT and packet-length stats (min/max/avg/stddev) per flow — the
training signal for statistical/ML classifiers. Requirements:
- Optional **timing jitter** and **decoy/junk packets** during handshake and idle to
  break burst structure and IAT regularity.
- Avoid lockstep request/response cadence that produces a clean 4-flight handshake shape.

### R7 — Adopt the AmneziaWG model (proof this works against nDPI)
AmneziaWG is the canonical example of defeating nDPI's WireGuard dissector, and its
parameter set maps 1:1 onto the requirements above. We should support equivalents:
- **Junk packets — Jc / Jmin / Jmax**: send `Jc` (≈4–12) junk packets of random size
  (`Jmin`..`Jmax` bytes) before the real handshake. Breaks first-packet heuristics
  (R2), entropy timing, and the "first payload" trigger — the observer sees random-length
  noise first, not a 148-byte handshake.
- **Junk before init/response — S1 / S2**: prepend `S1` random bytes to the handshake-
  init and `S2` to the handshake-response (`S1≤1132`, `S2≤1188`). This changes the
  handshake **lengths** away from the fixed 148/92 → the size match in `wireguard.c`
  fails (R5).
- **Magic header randomization — H1/H2/H3/H4**: replace WireGuard's fixed message-type
  values (1/2/3/4) and the implicit zero reserved bytes with per-deployment random 32-bit
  constants `H1..H4`, unique per message type. This directly kills the byte-0 type +
  reserved-zero check (R1). For us, go further than AmneziaWG: don't even use static
  per-deployment constants — **derive the type discriminator from a keyed/rolling value**
  so it isn't a constant an observer can learn across flows.
- Lesson: AmneziaWG defeats nDPI's WireGuard detector purely by (a) removing the fixed
  header constants, (b) varying handshake sizes, and (c) injecting random junk. Our
  protocol should bake these in from day one rather than bolt them on.

### R8 — Don't look like "an unknown thing on a weird port"
Port 51820/1194/655 etc. are instant hints; an unclassified encrypted flow on a random
high port is itself suspicious to operators reading nDPId's `guessed` events. Prefer
plausible ports (443/UDP for QUIC-mimicry, 443/TCP for TLS-mimicry) consistent with the
cover protocol chosen in R4. Combined with R1–R7, the flow should classify *as* the cover
protocol (TLS/QUIC) at normal confidence, with no risk flags.

### R9 — Verification harness (make evasion testable)
Build the actual adversary into CI: run captured handshakes/data flows of our protocol
through **nDPI / nDPId** (both ship here) with all heuristics enabled
(`fully_encrypted_heuristic`, `tls_heuristics` incl. obfuscated/TLS-in-TLS, openvpn opcode
heuristic, entropy). **Pass criteria**: (a) not classified as WireGuard/OpenVPN/Tor/VPN/
proxy; (b) no `NDPI_OBFUSCATED_TRAFFIC` or `NDPI_SUSPICIOUS_ENTROPY` risk; (c) ideally
classified as the intended benign cover protocol at DPI (not AGGRESSIVE/guessed)
confidence. Re-run on every nDPI version bump, since heuristics and models evolve.
