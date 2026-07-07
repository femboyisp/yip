# Sub-project #3 Milestone 3a: Anti-DPI Obfuscation (kill fixed bytes) — Design

**Status:** approved (brainstorming complete), ready for implementation planning.
**Sub-project:** #3 (anti-DPI / censorship resistance), milestone 3a. Sub-projects #1
(data plane + FEC) and #2 (control plane: 2a/2b/2c) are complete/merged.

## Goal

Make yip traffic **indistinguishable from random UDP** to a passive DPI observer:
eliminate every fixed byte, fixed offset, fixed size, and fixed timing signature so an
engine like nDPI/nDPId cannot fingerprint or classify it. This is the "no fixed magic
bytes / reserved fields" core (research `docs/research/07-dpi-detection.md`, requirements
R1/R5/R6/R7) — the foundation the rest of #3 builds on.

## Decomposition of sub-project #3 (settled during brainstorming; per the authoritative research)

- **3a (this spec)** — kill fixed magic bytes: remove the `PacketType`/rendezvous/gossip
  discriminant bytes, extend the keyed masking to cover the whole datagram *including the
  type discriminator*, randomize handshake/packet sizes, jitter the control timers. No new
  transport — all inside `yip-wire`/`yipd`/`yip-rendezvous`.
- **3b** — junk/decoy packets (AmneziaWG `Jc/Jmin/Jmax`) + heavier traffic-shaping (R2/R3/R6).
- **3c** — TLS/QUIC mimicry (Xray REALITY model): uTLS ClientHello parroting, real-domain
  SNI, probe-reverse-proxying, burst-shape matching (R4). New transport; separate spec.
- **3d** — pluggable-transport abstraction + plausible ports (R8).
- **3e** — the nDPI/nDPId CI undetectability oracle (R9). **Stood up with 3a** (it is how 3a
  is proven), then tightened as 3b/3c land.

## Scope decisions (locked during brainstorming)

1. **Opt-in, gated by a configured `obf_psk`.** With `obf_psk` set, the full obfuscation
   applies; absent, the current wire format is unchanged (no regression). Obfuscation is a
   censorship-circumvention feature enabled where needed.
2. **Handshake obfuscation is keyed by a network-wide `obf_psk`** (AmneziaWG / WireGuard-PSK
   / REALITY model), not by static per-deployment constants and not derived from the (non-
   secret) responder static key. A censor without `obf_psk` sees uniform-random bytes.
3. **The type discriminator moves inside the keyed envelope** — never a plaintext byte at a
   fixed offset. Demux is by source-address + trial-unmask (extending the pattern
   `PeerManager` already uses for Data/Control).
4. **Padding on handshakes (generous), modest on data frames; junk/decoy packets → 3b.**
5. **Timing jitter on control cadences only** (handshake retries, gossip, keepalives), NOT
   the latency-critical data path.

## Non-goals (out of scope for 3a)

- Junk/decoy packets + heavier traffic-shaping → **3b**.
- TLS/QUIC mimicry, uTLS, REALITY → **3c**.
- Pluggable-transport abstraction, plausible ports (443) → **3d**.
- Data-plane timing obfuscation (would add latency; only ever an explicit opt-in in 3b).
- Entropy-shaping / TCP first-payload heuristics (R2/R3) — mainly bite TCP transports;
  deferred with the TLS-mimicry transport (3c). 3a is UDP.
- Handshake anti-replay (#34), rekey/PQ (#9), metadata/gossip-graph privacy (anonymity
  milestone), onion routing — orthogonal to DPI-signature elimination.

## The current detectable signatures (what 3a removes)

- **`PacketType` prefix** (`bin/yipd/src/handshake.rs`): a 1-byte `{HandshakeInit=0,
  HandshakeResp=1, Data=2, Control=3, Gossip=4}` at offset 0 of every datagram, matched at
  `peer_manager.rs on_udp` before any decryption — a constant value at a fixed offset (R1).
- **Rendezvous** (`crates/yip-rendezvous/src/proto.rs`): a plaintext `Tag` byte (0–6) +
  plaintext `NodeId`(16) + plaintext address family/IP/port at fixed offsets.
- **Gossip** (`crates/yip-membership/src/gossip.rs`): plaintext `{Digest=0, PullRequest=1,
  Records=2}` discriminant + raw record bytes, sent as plaintext `PacketType::Gossip`
  datagrams (2c does not seal gossip).
- **Control counter:** the `Control` frame's raw AEAD counter is sent *unmasked* at a fixed
  offset — a sequential-value correlation handle.
- **Fixed handshake sizes:** Noise-IK msg1/msg2 are constant-length for a fixed cert size
  (the WireGuard 148/92-byte fingerprint, R5).
- **Fixed control timing:** the 1 s handshake retry (`HANDSHAKE_RETRY_MS`), gossip digest,
  and keepalive cadences produce a regular inter-arrival signature (R6).

`yip-wire` already masks its 15-byte frame header with a SipHash-CTR keystream (keyed by
`hp_key`, seeded by the trailing tag) — 3a extends that proven primitive; it does **not**
introduce new crypto.

## Architecture

**Two keying regimes** (the handshake has no session key yet):

- **Established-session frames** (Data / Control / Gossip-in-session): masked by the
  session's existing `hp_key`. 3a extends that mask to carry the **type** and **pad-length**
  as keyed fields, and adds padding — no new key.
- **Pre-session datagrams** (`HandshakeInit`/`HandshakeResp`, rendezvous messages): masked by
  a keystream keyed on `obf_psk`.

**Demux without `dg[0]`** (the plaintext `PacketType` byte is deleted): the receiver
dispatches by **source address + trial-unmask**, in order:
1. If the source is a known Established peer, try that session's `hp_key` codec (type read
   from the masked header) — the hot path for Data/Control/Gossip.
2. If that fails **or** the source is a non-session source, trial-`deobfuscate` with
   `obf_psk` and process the inner Noise handshake — this covers both a brand-new peer's
   `HandshakeInit` and a **re-handshake/rekey from an already-known source** (its session
   codec fails, so it falls through here).
The inner Noise message self-authenticates on `read_message` (wrong PSK → garbage → Noise
fails → dropped); MAC/auth failure at every step is free and safe, so trial-unmask never
mis-dispatches. When `obf_psk` is unset, the current `dg[0]` path is retained unchanged.

## The obfuscation transform

Reuse `yip-wire`'s SipHash-CTR keystream construction in two places.

**Session frames (`yip-wire::Codec`, extend):** widen the masked `flags` byte into a masked
**type field** (Data/Control/Gossip) + a masked **pad-length field**; append random padding
on `frame`, strip on `deframe`. Because the whole header is already `hp_key`-masked and
per-datagram-seeded by the tag, the type + pad-length are keyed, per-packet-varying fields
— no fixed plaintext byte. This deletes the outer `PacketType` prefix for sessions and folds
the previously-unmasked Control counter under the same masked header.

**Pre-session (`yip-obf`, new shared component — a small crate or `yip-wire` submodule):**
```
obf_key = BLAKE2s("yip-obf-v1" || obf_psk)
datagram = obf_nonce (random, per-packet)
         ‖ [ SipHash-CTR(obf_key, obf_nonce) ⊕ (type ‖ body ‖ padding) ]
```
`obfuscate(obf_key, type, body) -> Vec<u8>` and `deobfuscate(obf_key, dg) -> Option<(type,
body)>`. The nonce is random (indistinguishable from random); the masked region is
keystream-XORed (uniform-random without `obf_key`). The type is a keyed masked field here
too. Used by `yipd` (handshake send/recv) **and** `yip-rendezvous`.

**Why a keystream (not AEAD) suffices:** the goal is hiding *structure/fingerprint*, not
content — Noise/AEAD already protect content. This is AmneziaWG's model, keyed and
per-packet-seeded per R7.

**On the wire:** every datagram is `[random nonce/tag] ‖ [uniform-random-looking bytes]`
with no fixed value, no fixed type byte, and (with padding) no fixed size.

## Size & timing

- **Padding (R5):** each obfuscated datagram appends random-length padding (the real length
  is the masked pad-length field). **Handshakes** are padded to a random length from a wide
  range (up to ~1200 B) so their size distribution carries no signal (kills the fixed
  148/92-byte shape). **Data frames** already vary (FEC symbols) and ride near the MTU, so
  they get modest random padding where room permits. Padding costs bandwidth, not latency.
- **Timing jitter (R6):** jitter the **control cadences** — handshake retry
  (`HANDSHAKE_RETRY_MS`), gossip digest interval, keepalives — by ±a fraction so they emit no
  lockstep inter-arrival signature. **Not** the data-plane egress (that would add latency,
  violating the low-latency north star); data timing obfuscation is a 3b opt-in.

## Config, components & coverage

**Config:** `obf_psk=<hex>` (optional) on both `yipd` and `yip-rendezvous` — a network-wide
shared secret distributed with the network's other config (in 2c mesh mode, alongside the CA
pubkey/roots). Absent → plain mode. The rendezvous server holds it to unmask client traffic.

**Components:**
- `yip-wire::Codec` (extend) — masked type + pad-length + padding for session frames.
- `yip-obf` (new small shared component) — the `obf_psk`-keyed nonce+mask+padding envelope
  for pre-session datagrams; reused by `yipd` and `yip-rendezvous`.
- `bin/yipd/src/peer_manager.rs on_udp` (rewire) — replace the `dg[0]` match with
  source-then-trial-unmask when `obf_psk` is set; keep `dg[0]` when unset. Handshake send
  sites stop pushing the `PacketType` byte and wrap via `yip-obf`.
- `bin/yipd/src/config.rs` + `bin/yip-rendezvous` — parse `obf_psk`.

**Coverage of the 2b/2c plaintext formats:**
- **Rendezvous:** wrapped by `yip-obf`, killing the plaintext `Tag`/node-id/addr fields. The
  blind relay forwards already-obfuscated bytes end-to-end (never unmasks).
- **Gossip:** routed through the session `hp_key` mask (peers are Established), so the outer
  `PacketType` byte + inner `GossipMsg` discriminant + record bytes become uniform-random to
  an observer (also closes 2c's passive gossip-metadata leak).
- **Cert `version` byte / handshake cert payload:** rides inside the AEAD-encrypted +
  `obf_psk`-masked Noise handshake — already hidden.

## Security invariants

- Obfuscation is a layer **over** Noise/AEAD — it never weakens them. The mask hides only the
  fingerprint; content secrecy remains Noise's.
- **`obf_psk` compromise degrades to "detectable but still secure":** a censor who learns
  `obf_psk` can recognize/block yip handshakes but **cannot decrypt** anything. The PSK gates
  unblockability, not confidentiality.
- **Fail-closed:** wrong/absent `obf_psk` → `deobfuscate` garbage → inner Noise `read_message`
  fails → drop. Trial-unmask is free and never mis-dispatches.
- **Anti-hijack / admission (2a/2b/2c) unchanged** — obfuscation wraps the same datagrams; the
  Noise handshake and cert admission still gate every session.

## Error handling

- `obf_psk` absent → plain mode (byte-identical 2a/2b/2c).
- `obf_psk` mismatch between peers → handshakes never deobfuscate → no connection; surface a
  "handshakes failing — check obf_psk" log heuristic.
- Malformed datagram → `deobfuscate` returns `None` / Noise fails → dropped, no panic reachable
  from wire input.

## Testing

**Unit:**
- `yip-obf`: obfuscate/deobfuscate round-trip; wrong-PSK fails; **whole-datagram no-constant-
  byte** test (across many packets, no byte position is ever constant — generalize
  `yip-wire`'s existing `codec_has_no_constant_header_bytes`); pad-length varies; type recovered.
- `yip-wire`: masked type + pad-length round-trip; no constant byte across the whole frame.

**netns integration:**
- Two `yipd` with `obf_psk` set complete a handshake + ping (obfuscation doesn't break
  connectivity), under both drivers.
- `obf_psk` mismatch → no connection.
- The 2b/2c money tests (relay, hole-punch, discovery) still pass with `obf_psk` on
  (obfuscation composes with the control plane), both drivers.
- **No-regression:** `obf_psk` absent → all existing netns tests byte-identical green, both
  drivers.

**The nDPI undetectability oracle (3e, stood up with 3a) — the money test:** a new
`dpi-undetectability` CI job builds `ndpiReader` from `refrences/nDPI`, runs a full
obfuscated yip exchange (handshake + data + control + gossip + rendezvous) in netns under
`tcpdump` capture, feeds the pcap to `ndpiReader` with flow-risk/entropy/obfuscation
heuristics enabled, and asserts: **(a)** no flow classified as WireGuard/OpenVPN/any
VPN/proxy master protocol, **(b)** no `NDPI_OBFUSCATED_TRAFFIC` and no
`NDPI_SUSPICIOUS_ENTROPY` risk flag. A merge gate that fails the build if a wire change
reintroduces a signature. Pin the `refrences/nDPI` clone; refresh on version bumps.

## Integration surface reused

- `yip-wire`'s SipHash-CTR mask + tag construction (the obfuscation primitive).
- The `PeerManager` "demux by source + trial-decrypt, fail-closed" pattern (already used for
  Data/Control) — generalized to handshake/gossip.
- 2a/2b/2c wire formats — `PacketType`, rendezvous `Tag`, gossip `GossipMsg` (all the
  plaintext discriminants this milestone folds into keyed envelopes).
