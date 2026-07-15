# REALITY TLS milestone — design spec

**Date:** 2026-07-15
**Status:** design (pending user approval)
**Depends on:** [`2026-07-15-reality-tls-clienthello-control-research.md`](2026-07-15-reality-tls-clienthello-control-research.md)
**Approach:** Option 3 (pure-Rust uTLS-equivalent client) — chosen. No Go/cgo, no
BoringSSL fork; `forbid(unsafe_code)` preserved outside `yip-io`/`yip-device`.

## Goal

Give the yip **relay path** true Xray-style REALITY: an active prober who connects
to the relay's TCP/443 and does not hold the REALITY key is **transparently spliced
to a real upstream site** (`dest`, e.g. `www.apple.com:443`) and sees that site's
genuine cert and behavior — indistinguishable from connecting to the real site —
while an authenticated yip client is served the relay tunnel. This replaces the
3c.3 Trojan front (own-cert + self-hosted decoy), whose active-probe story is
weaker (self-signed cert on the P2P costume; operator must own a domain/cert on the
relay).

Out of scope: the P2P `transport=tls` costume (3c.2) stays the honest passive
Chrome parrot, documented as probe-visible; REALITY layers only on the relay path.

## Auth protocol (Xray-REALITY-compatible)

Per connection:

1. Client generates an ephemeral X25519 keypair `(c_priv, c_pub)`. `c_pub` is the
   TLS 1.3 `key_share` (so it is a genuine, load-bearing handshake key — not an
   extra field a censor could strip).
2. `shared = X25519(c_priv, server_reality_pub)`; `key = HKDF(shared)`.
3. `auth = AEAD_seal(key, nonce=client_random[..12], plaintext = short_id ‖
   unix_minutes_le)`; the 32-byte `legacy_session_id` carries `auth` (truncated/
   tagged to 32 B per Xray's scheme).
4. Server, on the raw ClientHello: reads `c_pub` from `key_share`, `client_random`,
   and `legacy_session_id`; computes the same `shared`/`key`; `AEAD_open`. Success +
   fresh timestamp (±N minutes) + known `short_id` ⇒ **authed**; anything else ⇒
   **forward to `dest`**. No timing oracle: the forward path and the auth-fail path
   are byte- and latency-indistinguishable (decide, then act).

`server_reality_pub` / `short_id`(s) are config; the client is provisioned with the
public key out of band (like a WireGuard peer key).

## Architecture & decomposition

Each sub-milestone is its own spec → plan → PR (per the never-merge / review-each rule).

### REALITY.1 — server-side raw ClientHello parse + transparent `dest` forwarding
**(build first; biggest anti-probe win; no client changes)**
- New module in `yip-rendezvous`: read the TLS record + ClientHello off the socket
  *before* any TLS termination; extract SNI, `key_share`(X25519), `client_random`,
  `legacy_session_id`.
- Auth check (§ above). On fail/absent ⇒ open TCP to `dest`, **replay the buffered
  ClientHello**, splice bidirectionally to EOF. On success ⇒ hand the (buffered +
  live) stream to the existing `boring` acceptor branch.
- Reuses the current front's slowloris caps (`HANDSHAKE_TIMEOUT`, `MAX_TLS_CONNS`).
- Interim: until REALITY.2 ships a client that embeds auth, no real client authenticates,
  so **every** connection forwards to `dest` — which is itself a correct, safe, fully
  probe-faithful relay-front-that-looks-like-a-website. The tunnel path stays on the
  existing obf/Trojan branch behind a config flag until REALITY.2 lands.

### REALITY.2 — pure-Rust REALITY ClientHello crafter + TLS 1.3 client (the crux)
- New crate `yip-utls` (pure Rust, `forbid(unsafe)`): a **single pinned Chrome**
  ClientHello template (JA3/JA4-faithful) where we own `key_share` + `legacy_session_id`.
- Minimal **TLS 1.3-only** client handshake (one cipher suite the pinned Chrome
  offers, X25519 group) driving the rest of the handshake, reusing `yip-crypto`
  primitives (X25519, HKDF, ChaCha20-Poly1305/AES-GCM) — **no new crypto**.
- **CI JA3/JA4 diff test**: assert our ClientHello matches a checked-in capture of
  the pinned real Chrome hello, byte-for-byte modulo GREASE/random — a mismatch is a
  build failure. (Mitigates "hand-rolled hello is *more* fingerprintable" risk.)
- This is the largest sub-part; it may itself split (2a: JA3-faithful hello + crafter;
  2b: TLS 1.3 handshake/key-schedule to Finished).

### REALITY.3 — on-the-fly stolen-cert for the authed branch
- On an authed connection, fetch the real `dest` cert chain once (cache it), generate
  an ephemeral leaf copying its subject/SAN/validity signed by an ephemeral key; serve
  it via the `boring` acceptor's cert callback. The authed client trusts the REALITY
  key (skips CA validation), so this is accepted; probers never reach this branch.

### REALITY.4 — yipd wiring & config
- Config: `reality_dest`, `reality_server_names`, `reality_public_key`,
  `reality_private_key` (relay), `reality_short_id`. Replace the 3c.4 relay-dial TLS
  handshake with the REALITY.2 crafter. Document in `example.config` + `configuration.md`.

## Testing / adversary
- Unit: auth seal/open round-trip; timestamp-freshness reject; unknown-`short_id` reject.
- netns: authed client tunnels; un-authed connection reaches a stand-in `dest` and gets
  its cert (prove the splice).
- **Active-probe oracle in CI**: `curl`/`openssl s_client` the relay with no auth ⇒ must
  receive `dest`'s real cert (or the stand-in's), never a self-signed/relay cert;
  add to the DPI-undetectability job. Extends the nDPI adversary with an *active* prober.
- JA3/JA4 diff test (REALITY.2) as above.

## Risks
- **Fingerprint drift:** a hand-rolled hello that lags Chrome is a tell. Mitigation:
  pin one version, CI-diff against a real capture, and treat the template as
  maintenance (bump on Chrome releases).
- **Hand-rolled TLS 1.3 crypto:** security-sensitive. Mitigation: TLS 1.3-only, one
  suite, reuse audited `yip-crypto` primitives, KATs against a reference (openssl).
- **Scope:** REALITY.2 is genuinely large; keep it isolated and reviewable, never
  merged without the JA3 diff test green.

## Open questions (defaults chosen; correct me)
- Pinned Chrome version for the template + CI capture: **current stable** (default).
- "signal-tlsd" concrete reference: **standard REALITY semantics** assumed pending detail.
- P2P `transport=tls`: **left as-is** (default).
