# 04 — Mixnet & Censorship-Circumvention Proxy Research

Reference analysis for a Rust P2P mesh VPN. Six local reference repos studied:
Nym (mixnet), Shadowsocks-rust (AEAD proxy), Xray-core (XTLS/REALITY), V2Ray-core
(VMess/VLESS), gsocket (relay rendezvous), OpenVPN (classic TLS VPN).

The recurring tension across all of them: **privacy/unobservability vs. latency/throughput**.
Mixnets (Nym) buy strong traffic-analysis resistance with seconds of added latency; transport
obfuscators (Shadowsocks, REALITY, XHTTP) buy DPI resistance at near-zero latency cost but
provide no metadata anonymity. A mesh VPN should treat these as *pluggable transport layers*
and let policy choose the trade-off per-flow.

---

## Nym

- **What it does**: Decentralized, incentivized **mixnet** (Loopix design) that anonymizes
  packet metadata by routing fixed-size Sphinx packets through 5 hops with random per-hop
  delays, reordering, and constant cover traffic. Also offers a faster WireGuard-based dVPN
  mode and anonymous (zk-nym / Coconut) credentials decoupling payment from usage.
- **Language / license**: Rust. Apache-2.0 (`license = "Apache-2.0"` in workspace `Cargo.toml`;
  `LICENSES/` also vendors Apache-2.0 / BSL-1.0).
- **Protocols & crypto**:
  - **Sphinx packets** (`common/nymsphinx`, external `sphinx-packet` crate): fixed **2048-byte**
    payload, layered onion encryption, per-hop ECDH + HKDF key derivation, **ephemeral key
    blinding** so successive nodes can't correlate by key value, per-layer HMAC integrity, and
    **Lioness wide-block** payload encryption (any bit-flip invalidates the whole payload).
  - **SURBs** (single-use reply blocks) for anonymous replies without revealing sender.
  - **zk-nym / Coconut** re-randomizable anonymous credentials (`common/nym_offline_compact_ecash`,
    `dkg`) — pay once, spend unlinkably.
  - **Lewes Protocol (LP)** (`docs/LP_*.md`): a *fast* direct-TCP gateway registration path using
    **Noise XKpsk3** (mutual auth + forward secrecy) over **KCP** (ordered, fast-retransmit). An
    explicit latency/anonymity escape hatch — registration without the multi-hop cost.
  - **nymnoise** Noise-based transport between nodes; dVPN mode uses WireGuard.
- **Architecture / how it works**: `User → Entry Gateway → Mix L1 → Mix L2 → Mix L3 → Exit
  Gateway → Internet`. Each mix node strips one Sphinx layer, holds the packet a **random
  (Poisson/exponential) delay**, then forwards — destroying the timing correlation an observer
  needs. Topology + node bonding/rewards live in CosmWasm smart contracts (`contracts/mixnet`);
  a `nym-api` publishes the network topology. Large messages are **fragmented** and chunks travel
  independently. Clients emit **loop cover packets** (`common/nymsphinx/cover`) that are
  cryptographically indistinguishable from real traffic.
- **Anti-DPI / traffic-shaping**: This is the strongest in the set for *metadata*: uniform packet
  size (no size fingerprint), constant cover-traffic rate (unobservability — adversary can't tell
  if you're active), per-hop random delay + reorder (unlinkability), no long-lived circuits
  (resists end-to-end correlation). It does **not** disguise the fact that you're talking to a Nym
  gateway, so it pairs DPI-resistance poorly with mimicry — entry is recognizable.
- **Strengths**: Best-in-class traffic-analysis resistance; decentralized + economically
  incentivized; clean Rust crate separation; anonymous payment story.
- **Weaknesses**: High latency (seconds) from mixing delays — unusable for real-time; cover traffic
  burns bandwidth/battery; entry gateways are fingerprintable; complexity and on-chain dependency.
- **Could be done better**: Adaptive cover-traffic (scale rate to threat level/battery); make mix
  delay tunable per-flow; combine with a mimicry transport at the entry hop so the gateway
  connection itself looks like HTTPS; PQ-harden the Sphinx ECDH.
- **Reusable ideas**: (1) **Fixed-size packet discipline + cover traffic** as an optional
  "paranoid mode" layer. (2) **SURBs** for anonymous bidirectional replies in a mesh. (3) The
  **two-mode design** (slow-anonymous Sphinx vs. fast-Noise/KCP "LP") is exactly the
  privacy-vs-latency dial we want. (4) Noise XKpsk3 + KCP as a reliable, FS-protected control
  channel. (5) `nonexhaustive-delayqueue` / Poisson delay queue crate for timing obfuscation.

---

## Shadowsocks (shadowsocks-rust)

- **What it does**: Fast, minimal **AEAD tunnel proxy** ("SOCKS over an encrypted stream") to
  bypass firewalls. Encrypts so the stream looks like random bytes; relies on the
  unrecognizability of high-entropy traffic rather than mimicry.
- **Language / license**: Rust. MIT.
- **Protocols & crypto**:
  - **AEAD v1**: AES-128/256-GCM, ChaCha20-Poly1305. Per-connection random **salt** → HKDF-SHA1
    subkey from the pre-shared key; payload framed as `[encrypted length][len tag][encrypted
    payload][payload tag]` chunks (`relay/tcprelay/aead.rs`).
  - **AEAD-2022 (SIP022)** (`aead_2022.rs`): modern redesign — `2022-blake3-aes-256-gcm`,
    `2022-blake3-chacha20-poly1305`. Adds **timestamped headers** (replay protection,
    `get_now_timestamp`), **request/response salt binding** (ties response to request salt to
    stop probing/replay), **Extended Identity Headers (EIH)** for multi-user key derivation
    (BLAKE3 "identity subkey" context), and explicit padding fields.
  - Crypto via the `shadowsocks-crypto` crate (aws-lc / ring backends).
  - **SIP003 plugins** (`plugin/`): spawn external transports — `v2ray-plugin`,
    `simple-obfs`, `obfs_proxy` — to add HTTP/TLS/WebSocket obfuscation Shadowsocks itself lacks.
- **Architecture**: `sslocal` (client SOCKS5/HTTP/redir/tun/fakedns inbound) ↔ `ssserver` (remote).
  TCP and UDP relays, ACL rules, SIP008 online config delivery, TUN mode for full device routing.
- **Anti-DPI / traffic-shaping**: Core technique is **"look like nothing"** — the entire stream
  (after the salt) is AEAD ciphertext with no plaintext handshake, no recognizable header, no TLS.
  AEAD-2022 specifically hardens against **active probing** (timestamp + salt binding so a censor
  replaying captured bytes gets no distinguishable response). It has **no traffic mimicry or
  padding by default**; obfuscation (TLS/WebSocket cover) is delegated to SIP003 plugins. Packet
  length leakage is its main DPI weakness, addressed only partially via plugin padding.
- **Strengths**: Tiny, extremely fast, low latency, battle-tested AEAD; clean Rust crates
  (`shadowsocks` core vs `shadowsocks-service`); multi-user EIH; TUN support.
- **Weaknesses**: Random-looking traffic is itself a fingerprint to entropy-based DPI; vulnerable
  to active probing in v1 (fixed in 2022); no built-in metadata anonymity (1-hop only).
- **Could be done better**: Native padding/length obfuscation instead of relying on plugins;
  built-in pluggable mimicry; PQ key exchange (it's PSK-only today).
- **Reusable ideas**: (1) The **AEAD-2022 framing** (`[len][len-tag][payload][payload-tag]` chunks
  with BLAKE3-derived subkeys) is a clean, audited record layer to copy directly. (2) **Timestamp +
  request/response salt binding** for anti-replay/anti-probe — cheap and effective. (3) **EIH**
  multi-user keying for a shared mesh relay. (4) The `shadowsocks` vs `shadowsocks-service` crate
  split is a good architecture template for a Rust core lib + binaries.

---

## Xray-core (XTLS / REALITY)

- **What it does**: Advanced anti-censorship proxy platform; superset of V2Ray adding **XTLS**,
  **REALITY**, **VLESS Vision/Encryption**, and **XHTTP** — the current state of the art for
  surviving sophisticated DPI + active probing.
- **Language / license**: Go. Mozilla Public License 2.0.
- **Protocols & crypto**:
  - **VLESS** (`proxy/vless`): stateless, lightweight protocol (UUID auth, no per-packet crypto of
    its own — relies on the transport TLS/REALITY for confidentiality). Flow `xtls-rprx-vision`
    (`XRV`).
  - **VLESS Encryption** (`proxy/vless/encryption`): **post-quantum** hybrid handshake —
    **ML-KEM-768 + X25519** (`crypto/mlkem`, `ecdh.X25519`), with a CTR-based XOR layer to make the
    public-key/ciphertext bytes **indistinguishable from random** (`client.go`: comments note
    making "X25519 public key / ML-KEM-768 ciphertext distinguishable from random bytes").
  - **VMess** (`proxy/vmess`): older AEAD protocol with **AEAD AuthID** headers (HMAC-SHA256 +
    CRC64 behavior seed) replacing the legacy MD5 time-based auth that was probe-vulnerable.
  - **Trojan**, **Shadowsocks**, **Shadowsocks-2022**, Hysteria, WireGuard all bundled.
- **Architecture**: Modular inbound→router→outbound pipeline. Inbounds (SOCKS, VLESS, etc.) feed a
  routing engine that selects outbounds; transports are layered independently (TCP/WS/gRPC/
  HTTPUpgrade/**XHTTP(splithttp)**/KCP) under a security layer (TLS/REALITY/none).
- **Anti-DPI / traffic-shaping** — the key repo:
  - **REALITY** (`transport/internet/reality/reality.go`): the headline technique. The client uses
    **uTLS** to emit a real browser's ClientHello fingerprint (Chrome/Firefox/Safari/iOS), with
    `ServerName` set to a **real, popular third-party site** (e.g. a CDN). It embeds an
    authentication tag in the TLS **SessionID** field: X25519 ECDH with the server's public key →
    HKDF → AES-GCM seal over the ClientHello. A legit REALITY server recognizes the tag and serves
    proxy traffic; **anyone else (a censor's active probe) is transparently reverse-proxied to the
    genuine target site**, so probing yields a real TLS cert and real content from the real domain.
    `SpiderX`/`ShortId`/`SpiderY` drive a crawler that mimics human browsing (random padding
    cookies, referer chains, link following) when verification fails. No fake cert, no domain
    fronting needed — it borrows a real domain's TLS identity.
  - **XTLS Vision** (`proxy/vless/encoding`, `XtlsRead can switch to splice copy`): avoids the
    "TLS-in-TLS" double-encryption fingerprint and CPU cost by **splicing** the inner TLS stream
    directly once the handshake is done — payload length patterns then match real TLS.
  - **XHTTP / splithttp** (`transport/internet/splithttp`, `xpadding.go`): tunnels over HTTP/1.1,
    HTTP/2, HTTP/3 with separate **stream-up / packet-up / one** upload modes and **`x_padding`**
    headers to defeat length analysis; can ride real CDNs.
  - **uTLS fingerprint mimicry** is the common thread — defeat JA3/JA4 TLS fingerprinting.
- **Strengths**: Strongest practical anti-DPI; REALITY eliminates the need to own/forge a cert or
  fronting domain; PQ-ready VLESS encryption; huge transport flexibility; active ecosystem.
- **Weaknesses**: Go (GC pauses, larger binary); uses `unsafe`/reflection to reach into Go's TLS
  internals (`reflect`, `unsafe.Pointer` in reality.go) — fragile across Go versions; complex
  config; centralized client→server (no mesh, no metadata anonymity).
- **Could be done better**: Mesh/multi-path routing; metadata anonymity (it's 1-hop); the
  reflection hacks would be a clean rewrite in Rust with a proper uTLS-equivalent.
- **Reusable ideas** (highest priority to steal): (1) **REALITY's "borrow a real domain's TLS
  identity + reverse-proxy probes to the genuine site"** — the single most valuable anti-probing
  idea here; implementable in Rust over rustls + a uTLS-style fingerprint shim. (2) **uTLS browser
  ClientHello mimicry** against JA3/JA4. (3) **XTLS Vision splicing** to avoid TLS-in-TLS
  fingerprints. (4) **XHTTP padding + multi-mode HTTP transport** for CDN-frontable fallback.
  (5) **VLESS PQ hybrid (ML-KEM-768 + X25519) with random-looking handshake bytes** for our key
  exchange.

---

## V2Ray-core

- **What it does**: The original modular proxy platform Xray forked from; "build your own network"
  toolkit implementing **VMess** and **VLESS** with pluggable transports. Now largely superseded
  by Xray for cutting-edge anti-DPI (this repo's README even points to the v2fly fork).
- **Language / license**: Go. MIT.
- **Protocols & crypto**:
  - **VMess**: AEAD-based (AES-128-GCM / ChaCha20-Poly1305), UUID identity, time-based AuthID. The
    legacy MD5/alterID scheme was probe-vulnerable; AEAD header auth (HMAC-SHA256) replaced it.
  - **VLESS**: lightweight, crypto delegated to the transport TLS layer.
  - Transports: TCP, mKCP, WebSocket, HTTP/2, QUIC, gRPC, plus TLS security and pluggable header
    obfuscation (e.g. mKCP `header` masquerading as wireguard/dtls/wechat-video/utp/srtp).
- **Architecture**: Same inbound→router→outbound design as Xray (Xray inherited it). Dispatcher +
  routing rules + DNS + policy modules; transports decoupled from proxy protocols.
- **Anti-DPI / traffic-shaping**: TLS wrapping, WebSocket-over-TLS (CDN-frontable),
  **mKCP packet-header masquerading** (disguise UDP as common protocols), HTTP/2 multiplexing.
  Lacks REALITY/XTLS Vision/XHTTP — so its TLS-in-TLS and fingerprint resistance is weaker than
  Xray's. Domain fronting via WebSocket+CDN was its main fronting technique.
- **Strengths**: Clean, well-factored modular architecture (the reference for pluggable transports);
  mature; MIT-licensed.
- **Weaknesses**: Behind Xray on anti-DPI; VMess has historical probing weaknesses; Go runtime;
  no anonymity layer.
- **Could be done better**: Everything Xray already did (REALITY, Vision, XHTTP); a Rust rewrite of
  its transport abstraction.
- **Reusable ideas**: (1) The **inbound/router/outbound + pluggable transport** architecture is the
  cleanest template for our proxy layering — adopt the abstraction, not the code. (2) **mKCP
  header masquerading** (cheap UDP disguise) is a low-cost obfuscation idea for our UDP/mesh data
  plane. (3) WebSocket/gRPC-over-TLS as CDN-frontable fallback transports.

---

## gsocket (Global Socket)

- **What it does**: Lets two hosts **behind NAT/firewall connect by shared secret instead of
  IP:port**, by rendezvousing through a public **Global Socket Relay Network (GSRN)**. "Connect
  like there is no firewall." Powers reverse shells, SFTP, mounts, port-forwards, WireGuard tunnels.
- **Language / license**: C. BSD-2-Clause.
- **Protocols & crypto**:
  - **Secret → address derivation**: a shared secret is hashed (SHA-256, `gsocket-engine.c`
    ~line 2314) into a 128-bit **GS-Address** used as the rendezvous token at the relay; the
    secret itself never leaves the host. The relay only ever sees the derived address + ciphertext.
  - **End-to-end encryption**: **OpenSSL SRP** (RFC 5054) password-authenticated key exchange —
    **AES-256** with a **4096-bit prime**, **no PKI**, **Perfect Forward Secrecy**. SRP password
    is also derived from the secret (`GS_srp_setpassword`).
  - Optional **Tor** transport to the relay for IP hiding.
  - Internal multiplexing protocol (`include/gsocket/packet.h`): 2048-byte max packets, message vs.
    channel types, `0xFB` escape byte, in-band control.
- **Architecture / how it works**: Both peers connect *out* to the GSRN (port 443-friendly) and
  present the same derived GS-Address; the relay **pairs** a listener and a connector with matching
  addresses and then becomes a **blind TCP pipe**. Because the relay only sees SRP-encrypted bytes,
  it learns nothing. All connections are **outbound**, so they traverse NAT/firewalls trivially.
- **Anti-DPI / traffic-shaping**: Its censorship story is **NAT/firewall traversal + a neutral
  relay that sees only ciphertext**, optionally over Tor. It is *not* a traffic-mimicry tool — no
  TLS fingerprint shaping or padding — so the GSRN connection itself is fingerprintable. Strength
  is the **rendezvous-by-secret** model and outbound-only connectivity.
- **Strengths**: Brilliantly simple rendezvous UX (secret = identity = address); no PKI; PFS; works
  through any NAT; tiny C, static binaries everywhere; Tor option.
- **Weaknesses**: Relies on a (free but) semi-central relay network; SRP is unusual/dated vs Noise;
  no transport obfuscation; C memory-safety risk.
- **Could be done better**: Replace SRP with Noise (IK/XK); add TLS-mimicry to the relay leg;
  decentralize/federate the relay set; add padding.
- **Reusable ideas** (very relevant to a P2P mesh): (1) **Derive a rendezvous ID from a shared
  secret via hash** so peers find each other without knowing IP:port — exactly the mesh
  bootstrapping/discovery primitive we need. (2) **Outbound-only, relay-paired NAT traversal** with
  a **blind relay that only sees ciphertext** — a clean fallback when hole-punching fails.
  (3) **PAKE-from-shared-secret** for zero-PKI mutual auth (use Noise/SPAKE2 instead of SRP).
  (4) The in-band multiplexing/channel framing for many logical streams over one pipe.

---

## OpenVPN

- **What it does**: Classic, mature **SSL/TLS VPN daemon** — a TUN/TAP tunnel with a TLS-negotiated
  control channel and a symmetric-keyed data channel. The baseline "real VPN" to compare against.
- **Language / license**: C. GPLv2.
- **Protocols & crypto**:
  - **Control channel**: full TLS (OpenSSL / mbedTLS / wolfSSL / AWS-LC backends) for mutual cert
    auth + key negotiation.
  - **Data channel**: negotiated cipher (AES-256-GCM, ChaCha20-Poly1305) via **NCP** (cipher
    negotiation, `ssl_ncp.c`); **crypto epochs** (`crypto_epoch.c`) for key rotation/ratcheting.
  - **tls-auth / tls-crypt / tls-crypt-v2** (`tls_crypt.c/.h`): a **pre-shared static key wraps the
    control-channel packets** using an **SIV (nonce-misuse-resistant AEAD)** construction —
    `auth_tag = HMAC-SHA256(Ka, header||msg)`, encrypt with Ke. Purpose: DoS/scan resistance and
    **hiding the TLS handshake** from passive observers (no plaintext TLS ClientHello on the wire
    unless you hold the group key). **tls-crypt-v2** adds per-client keys (client sends its
    wrapped key on connect).
- **Architecture**: Client↔server (or p2p) daemon; TUN/TAP virtual interface; control channel
  (TLS) negotiates data-channel keys; supports UDP and TCP transport. **DCO** (Data Channel
  Offload, kernel module) for performance.
- **Anti-DPI / traffic-shaping**: Weakest of the set. Default OpenVPN has a **recognizable
  handshake fingerprint** and is widely blocked by DPI. `tls-crypt` hides/authenticates the control
  channel (so the handshake isn't plaintext and unsolicited scans are dropped), which is partial
  obfuscation, but the traffic is still identifiable as OpenVPN-shaped. No mimicry, padding, or
  domain fronting natively — usually wrapped in stunnel/obfs/websocket externally.
- **Strengths**: Extremely mature, audited, multi-backend crypto; flexible; SIV control-channel
  wrapping; DCO performance; epoch-based key rotation is a solid design.
- **Weaknesses**: Easily DPI-fingerprinted and blocked; heavyweight config; C; client-server, not
  mesh; no metadata privacy.
- **Could be done better**: Pluggable obfuscation transports built-in; Noise instead of full TLS
  for a smaller handshake; native mesh.
- **Reusable ideas**: (1) **tls-crypt's SIV-wrapped control channel** (pre-shared key hides +
  authenticates handshake, drops unsolicited probes) — a cheap anti-scan/anti-probe layer for our
  control plane. (2) **NCP cipher negotiation** + **crypto-epoch key ratcheting** for forward
  secrecy with rekeying. (3) **Multi-backend crypto abstraction** (swap OpenSSL/ring/aws-lc) as an
  architecture pattern.

---

## Cross-cutting takeaways for our Rust P2P mesh VPN

**Anti-DPI techniques worth stealing, ranked:**

1. **REALITY (Xray)** — borrow a real popular domain's TLS identity via uTLS fingerprint mimicry;
   auth tag hidden in TLS SessionID; reverse-proxy any unauthenticated probe to the *genuine* site
   so active probing is indistinguishable from visiting that site. No fronting domain, no forged
   cert. Highest-value technique.
2. **uTLS / JA3-JA4 ClientHello mimicry** + **XTLS Vision splicing** to avoid the TLS-in-TLS
   fingerprint.
3. **Shadowsocks AEAD-2022 framing** with **timestamp + request/response salt binding** for a
   probe-resistant, low-latency "looks like random" record layer.
4. **XHTTP `x_padding` + multi-mode HTTP** and **mKCP header masquerading** as CDN-frontable /
   UDP-disguise fallbacks.
5. **OpenVPN tls-crypt SIV wrapping** for a cheap anti-scan control channel.

**Privacy/anonymity layer (opt-in, high-latency):** Nym's **Sphinx fixed-size packets + Poisson
delays + cover traffic + SURBs** for a "paranoid mode," plus Nym's **two-tier model** (slow-anon
mixnet vs. fast Noise/KCP) as the explicit privacy↔latency dial.

**Mesh primitives:** gsocket's **hash(secret)→rendezvous-ID discovery** and **blind ciphertext-only
relay fallback** for NAT traversal; replace SRP with **Noise (IK/XK) + ML-KEM-768/X25519 hybrid**
(per VLESS Encryption) for PQ-safe, PKI-free mutual auth with random-looking handshake bytes.

**Engineering:** copy the **V2Ray/Xray inbound→router→outbound + pluggable-transport** abstraction
and the **shadowsocks core-lib/service-binary crate split**; use a **multi-backend crypto** layer
and **epoch key ratcheting** (OpenVPN) for forward secrecy.
