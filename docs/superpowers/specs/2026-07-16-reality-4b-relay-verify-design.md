# REALITY.4b — client-side Xray-style relay verification (default ON) — design spec

**Date:** 2026-07-16
**Status:** design — pressure-tested by an adversarial advisor pass + a cross-model pass (`agy`/GPT-OSS-120B); pending user review.
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md)
**Depends on:** REALITY.4a (merged, the `reality://` client loop) + REALITY.3 (merged, the server stolen-cert authed path + anti-replay) + REALITY.2 (merged, `yip-utls`).
**Scope:** `yip-utls` (client verify) + `yip-rendezvous` (server binding) + `yipd` (config/fallback). PR 2 of the REALITY.4 pair.

## Goal

Let a yip client **cryptographically verify it is talking to the genuine relay** (the holder of
`relay_reality_priv`), not a MITM/impostor — without weakening the un-authenticated-prober
camouflage. On verification failure the client behaves like a plain browser (does not reveal it is a
REALITY client, does not retry-storm). Toggled by `verify=on|off` on the `reality://` URL,
**default ON**; a client-local policy, never negotiated on the wire (4a hard-rejected `verify=` as
4b-only).

REALITY.4a rested the tunnel's security on the inner peer Noise-IK (the outer TLS is zero-cert-auth;
a MITM sees only inner ciphertext, at worst DoS). 4b adds explicit **relay authentication** on top:
the relay proves possession of `relay_reality_priv` via the TLS `CertificateVerify`, giving
**client-side active-probe resistance** (a censor that MITMs/redirects the client's dial gets a
browser-like give-up rather than a fingerprintable REALITY retry loop).

## Why this mechanism (and why it is safe) — from the review

The only value tied to `relay_reality_priv` is the seal's ECDH shared secret
`shared = X25519(client_eph, relay_reality_priv)` (which the client also computes as
`X25519(client_eph_priv, relay_reality_pub)`). A MITM holds neither private key, so it cannot compute
`shared`. So the relay proves possession by signing the standard TLS 1.3 `CertificateVerify` with a
key **derived from `shared`**, and the client verifies it. Two independent reviews confirmed:

- **Transcript binding resists MITM/relay/reflection.** `CertificateVerify` signs the handshake
  transcript hash, which includes the server's *own* TLS ECDHE key_share. A MITM must terminate TLS
  with the client using its own key_share (to read plaintext), so the client-side transcript differs
  from the genuine relay's; the MITM cannot reuse the relay's signature, cannot read the relay's
  *encrypted* Certificate flight to extract/re-sign the leaf, and cannot itself produce a valid
  signature (needs the `shared`-derived key). Cross-relay redirection fails closed (wrong static key
  ⇒ seal AEAD-open fails ⇒ spliced to `dest`).
- **Key domain-separation is safe.** The same `shared` derives the seal AEAD key
  (`info="yip-reality-v1"`) and the cert key (`info="yip-reality-cert-v1"`); distinct HKDF `info`
  strings give independent outputs. Knowing one does not yield the other.

**The one design-breaker the review caught:** an earlier draft used **Ed25519**, which Chrome does
**not** advertise in its cleartext `signature_algorithms` — signing `CertificateVerify` with it
would force either a non-Chrome ClientHello (a passive, key-less JA3/JA4 distinguisher — defeats
REALITY) or an RFC-8446 violation. **Xray REALITY deliberately uses ECDSA-P256** for exactly this
reason. This spec uses **ECDSA-P256** (`ecdsa_secp256r1_sha256`, `0x0403` — already in yip-utls's
Chrome-faithful sig-algs list).

## Design

### 1. Derived cert key (`yip_utls::auth` — shared, both sides identical)

`derive_cert_key(shared: &[u8;32]) -> p256::SecretKey` — deterministic, both sides derive the
identical key:

- `okm = HKDF-SHA256-Expand(prk=Extract(salt="", ikm=shared), info="yip-reality-cert-v1", L=48)` —
  **48 bytes** (wide-reduction, RFC 9380 §5 hash-to-field style), not 32, so the mod-`n` reduction
  bias is negligible (< 2⁻¹²⁸) and both sides land on the same scalar (advisor/cross-model C1).
- Reduce the 48 bytes to a P-256 scalar **in constant time** via RustCrypto (`p256::Scalar` /
  `NonZeroScalar::from_repr` over the wide input, or `p256::FieldBytes` + `Scalar::reduce_bytes`) —
  no data-dependent branch on the value (cross-model C8). The ~2⁻²⁵⁶ zero case maps deterministically
  to `1` (documented) rather than branching to reject, so client and server never diverge.
- The public key is `SecretKey::public_key()`. A self-test asserts the derived point is on-curve and
  non-zero (defense-in-depth).

Both the client (`connect`) and the server (`run_reality_conn`) call this with their computed
`shared`. Reuse `yip-utls`'s existing `ring::hkdf` (as in `auth.rs`) or RustCrypto `hkdf`.

### 2. Server binding (`yip-rendezvous`) — always bind on authed connections

- **Expose `shared`.** `reality_auth_open`/`reality_auth_recover` already compute
  `shared = X25519(relay_priv, client_eph)` internally; return it (alongside `ts_min`) so
  `run_reality_conn` has it after the auth decision.
- **Per-connection re-forge (user decision — the cached-key model changes).** On an authed
  connection, derive the ECDSA-P256 keypair from `shared`, and **re-forge the borrowed-identity leaf
  per connection**: reuse the cached `StolenFields` for the SNI (REALITY.3 already caches these; the
  cache is refactored to expose `StolenFields`, not just the acceptor, so no `dest` re-fetch), sign
  the leaf with the derived key. Terminate the TLS 1.3 handshake with a **per-connection acceptor/Ssl
  carrying that cert+key**; BoringSSL signs the standard `CertificateVerify` over the transcript with
  the derived P-256 key, selecting `ecdsa_secp256r1_sha256` (the client advertises it). Cost: one
  keygen + one leaf-sign + per-connection cert setup — sub-millisecond vs. the TLS handshake.
- **Always bind** — the server produces the `shared`-derived cert on **every** authed connection,
  independent of whether the client verifies (the client's `verify` is a local policy the server
  never learns). `verify=off` clients simply ignore it.
- **Anti-replay stays in force (advisor C3 / cross-model C4 — already handled).** REALITY.3's
  `ReplayGuard` + the `ts_min` skew gate splice a replayed authed ClientHello to `dest` *before* any
  re-forge, so a censor cannot replay a captured ClientHello to force the authed path (and thus the
  shorter cert-flight oracle). No new work; the spec records the dependency.

### 3. Client verification (`yip_utls`) — `connect(..., verify: bool)`

`yip_utls` is hand-rolled (it already parses the server Certificate/CertificateVerify for the
transcript but validates nothing). When `verify=true`, after the server's flight:

- **Pin the leaf key.** Parse the leaf's SPKI; **reject** unless it is a P-256 key **byte-equal** to
  `derive_cert_key(shared).public_key()`. Do **not** trust the cert-declared algorithm/key type
  (algorithm-confusion, advisor C4 / cross-model): the comparison is against a specific expected
  P-256 point, not cert metadata.
- **Verify `CertificateVerify`.** Reconstruct the RFC 8446 §4.4.3 signed content
  (`0x20 × 64 ‖ "TLS 1.3, server CertificateVerify" ‖ 0x00 ‖ Transcript-Hash(ClientHello…Certificate)`)
  and verify the signature with **`ecdsa_secp256r1_sha256` hard-pinned** (ignore the
  `SignatureScheme` the message announces), using a **vetted verifier** (`p256::ecdsa::VerifyingKey`
  + `Signature::from_der`) — its range checks come free; ECDSA malleability is **not** exploitable
  here (no state is keyed on signature bytes — cross-model C2 downgraded).
- **Fail-closed on every edge** (advisor C4 / cross-model C6): missing/garbage `CertificateVerify`,
  absent/truncated leaf, wrong key type, any signature scheme other than the pinned one, any parse
  error ⇒ `Error::RealityVerify`. Cert parsing is bounded/no-panic (reuse REALITY.2's fail-closed
  reader discipline — cross-model C9).
- **KAT tests (cross-model C5).** The transcript-hash boundary is fail-closed-fragile in a
  hand-rolled stack — a boundary error rejects *genuine* relays (availability). Mandate a
  **known-answer test**: a recorded genuine `CertificateVerify` + transcript (from a local
  REALITY-server binder), asserting our reconstruction verifies. Mirrors REALITY.2's RFC 8448 KATs.
- `verify=false` ⇒ today's zero-cert-auth, byte-unchanged.

### 4. Config + fallback (`yipd`)

- **Config.** `Rendezvous::Reality` gains `verify: bool`; parse `verify=on|off` on `reality://`
  (**default ON** when absent — 4a's hard-reject is replaced with real parsing); client-local, never
  on the wire. `relay_client::spawn_reality` threads it into `yip_utls::connect`. Emit a **warn log
  when `verify=off`** (cross-model C10 — the downgrade is a policy risk).
- **Browser-faithful fallback** (advisor C5 / cross-model C6). Verification runs inside `connect`,
  **before** any inner yip Register frame, so a failure never emits yip-specific bytes. On
  `Error::RealityVerify` the client: (a) sends the **same TLS alert a mainstream browser sends on a
  certificate failure** (pin the exact alert against a real browser capture — candidate
  `bad_certificate(42)`; verify empirically), not a bare TCP RST; and (b) the relay-dial reconnect
  loop applies a **jittered** long backoff (randomized, not a fixed fleet-wide constant) or stops
  dialing that relay — so the failure timing/manner is not a fleet-wide tell distinguishable from a
  browser giving up.

## Config surface / docs

- `reality://host:port?pbk=&sid=&sni=&verify=on|off` (default ON). Update `example.config` +
  `docs/configuration.md` (the flag, default-ON, the client-local/non-negotiated note, browser-
  fallback behavior, and the `verify=off` downgrade caveat).

## Testing / adversary

- **Unit (derivation):** client and server `derive_cert_key(shared)` agree byte-for-byte on random
  `shared`; derived point on-curve/non-zero; the degenerate-zero mapping is deterministic.
- **Unit (client verify):** passes against a correctly-bound handshake; **fails** (⇒ `RealityVerify`)
  against a wrong leaf key, a wrong-key `CertificateVerify` signature, a non-pinned signature scheme,
  a missing/truncated `CertificateVerify`, and a garbage cert (no panic).
- **KAT:** a recorded genuine binder handshake — our transcript reconstruction verifies (guards the
  §4.4.3 boundary).
- **netns:** a `verify=on` client tunnels through a real REALITY relay (relay binds; verify passes;
  relay-forwarded > 0). A **wrong-relay-key** (or a stand-in MITM) ⇒ verify fails ⇒ **no tunnel, no
  Register sent, jittered give-up** (assert the client does not retry-storm and sends the browser
  alert). Extend REALITY.4a's netns harness.
- **Camouflage unchanged:** an un-authed prober is still spliced to `dest` (REALITY.1/.3) — no new
  server behavior on the un-authed path.
- JA3/JA4 fidelity (REALITY.2) unchanged — ECDSA-P256 keeps the ClientHello Chrome-faithful.

## Risks / accepted limits (documented)

- **Cert-flight size distinguisher (advisor C2 / cross-model C7) — deferred to REALITY.5.** The
  re-forged leaf is a single self-signed cert, so its *encrypted* Certificate-message length is
  smaller than `dest`'s real leaf+intermediate chain; a censor comparing the authed flight size
  against a genuine `dest` visit could distinguish. ECDSA-P256 (vs the earlier Ed25519) narrows but
  does not close it. **Full server-flight size-padding is REALITY.5 (#76)** — noted as an explicit
  overlap; 4b does not claim to close it.
- **Fail-closed = blockable (advisor C6 / cross-model C10).** An active MITM cannot get *accepted*,
  but can force `verify=on` clients to give up (a censor "win" via blocking). Operators may set
  `verify=off` to regain reachability, downgrading authentication — inherent to authenticated
  connections; `verify` stays client-local and defaults ON with a warn on off.
- **Static relay key, no REALITY-layer forward secrecy (advisor C7).** `shared` is
  static-ephemeral; `relay_reality_priv` compromise retroactively forges cert-auth for all sessions
  (and opens all seals). Inner Noise-IK still preserves tunnel-*content* secrecy. Inherent to
  REALITY; the widened blast radius is documented.

## Non-goals

- Server-flight/ServerHello + cert-flight size fidelity (REALITY.5, #76).
- Negotiating `verify` on the wire (deliberately client-local).
- Changing the un-authed splice, the anti-replay, or the inner Noise-IK.

## Success criteria

1. `derive_cert_key` is deterministic, uniform (48-byte wide reduction), constant-time, and agrees
   client↔server; ECDSA-P256 keeps the ClientHello Chrome-faithful (JA4 diff stays green).
2. A `verify=on` client tunnels through the genuine relay; a MITM/wrong-key relay is rejected
   (`RealityVerify`) with no tunnel, no Register, a browser-faithful alert, and jittered give-up —
   proven by unit + KAT + netns tests, all fail-closed.
3. The un-authed-prober camouflage is unchanged (spliced to `dest`); anti-replay (REALITY.3) stays
   in force so replays cannot force the authed cert-flight.
4. `verify=on|off` parses (default ON), is client-local, warns on off. `forbid-unsafe` outside
   yip-io/yip-device; no `as` casts; clippy clean. Cert-flight size-padding is explicitly deferred
   to REALITY.5.
