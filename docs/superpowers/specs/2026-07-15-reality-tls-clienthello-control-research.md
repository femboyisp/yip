# REALITY TLS — client ClientHello-control research & recommendation

**Date:** 2026-07-15
**Status:** research (pre-spec) — feeds the REALITY milestone design
**Question:** To build true Xray-style REALITY, the yipd *client* must embed an
X25519 auth signal into its TLS ClientHello so the server can decide auth
**before terminating TLS** (and forward un-authed probes to the real upstream).
Can we do that with our current `boring` stack, and if not, what should we do?

---

## Why this is the crux

REALITY's three mechanisms are **coupled** — none works without ClientHello-level auth:

1. **Pre-termination auth.** The server must tell a real client from an active
   prober *from the ClientHello itself*. If it has to terminate TLS first (to read
   a framed message, as our current Trojan front does), the prober already saw our
   cert — game over.
2. **Un-authed → real upstream.** Only once auth is decided pre-termination can the
   server splice an un-authed connection straight to the genuine `dest`
   (`www.apple.com:443`), so the prober gets that site's *real* CA cert and behavior.
3. **Authed → stolen cert.** The real client skips CA validation (it trusts the
   REALITY public key), so the server can serve an on-the-fly cert copying the real
   site's chain. A prober that *did* validate would reject it — which is exactly why
   probers must be forwarded upstream instead.

Xray embeds the auth in the ClientHello's **`legacy_session_id`** (32 bytes,
otherwise a random "compat mode" value in TLS 1.3) and reuses the TLS 1.3
**`key_share`** X25519 ephemeral as the ECDH key against the server's REALITY
public key. Both require the client to *control* those ClientHello fields.

## What `boring` 4.22 actually gives us (measured)

A throwaway probe captured the real ClientHello our 3c.2 config emits and grepped
the crate's API surface:

- ClientHello is a genuine **Chrome-shaped 517-byte** hello with GREASE and a
  **32-byte `legacy_session_id`** that is **random per connection**
  (`5a512999…` then `a1022fc4…`). This is precisely the field REALITY overwrites.
- **No setter for `legacy_session_id`.** The only related API is
  `set_session_id_context` — a *server-side* session-resumption concept, not the
  client's hello field.
- **No export of the `key_share` X25519 private.** `SSL_get_client_random` can
  *read* the client random, but there is no way to learn (or set) the ephemeral
  key_share scalar, so we cannot compute `ECDH(client_ephemeral, server_reality_pub)`.
- **No `SSL_CTX_add_custom_ext` binding** in the crate (BoringSSL has it in C, but
  it is not surfaced, and a novel extension is itself a JA3 tell anyway).
- **What *is* exposed** — `set_grease_enabled`, `set_permute_extensions`, ECH
  grease, cert-compression — is great for *passive* fingerprint mimicry (already
  used in 3c.2) and **useless for REALITY auth**.

**Conclusion:** stock `boring` produces an excellent passive Chrome parrot but
gives the client zero control over the fields REALITY needs. The *server* side is
fine (we can raw-parse the incoming ClientHello ourselves); the **client** side is
the blocker.

---

## Options for client ClientHello control

### Option 1 — `boring-sys` FFI to BoringSSL's C API
Drop to the raw C API to set `legacy_session_id` / export the key_share.

- **Reality:** BoringSSL's public C API deliberately **does not** expose either.
  You would be calling functions that don't exist.
- **Pros:** keeps the genuine Chrome hello.
- **Cons:** not actually possible without patching BoringSSL; `unsafe` (violates
  yip's `forbid(unsafe_code)` outside `yip-io`/`yip-device`).
- **Verdict:** ❌ not viable.

### Option 2 — Fork/patch BoringSSL (+ custom `boring-sys`)
Add C shims (`SSL_set_client_session_id`, `SSL_export_key_share`) to a BoringSSL fork.

```c
// boringssl patch (illustrative)
int SSL_set1_client_session_id(SSL *ssl, const uint8_t *id, size_t len);
int SSL_get1_key_share_private(SSL *ssl, uint8_t out[32]);
```

- **Pros:** minimal *Rust*; keeps the exact Chrome fingerprint.
- **Cons:** you now maintain a BoringSSL fork and a patched `boring-sys` build
  (already a `cmake` + BoringSSL compile — see 3c.2); brittle across upstream bumps;
  the auth crypto lives in `unsafe` C; painful to cross-compile (we ship yipd by
  cross-compile). High long-term cost.
- **Verdict:** ⚠️ works, poor fit.

### Option 3 — Pure-Rust uTLS-equivalent (hand-rolled ClientHello + TLS 1.3 client) ★ recommended
Craft the ClientHello ourselves (mimicking one pinned Chrome JA3/JA4), generating
our own X25519 `key_share` (so we hold the private), setting `legacy_session_id` to
the REALITY auth ciphertext, then drive the TLS 1.3 handshake.

```rust
// sketch — we own every byte, so REALITY auth drops in naturally
let (eph_priv, eph_pub) = x25519_keygen();                 // we keep eph_priv
let shared  = x25519(eph_priv, server_reality_pub);        // ECDH for auth
let auth_ct = aead_seal(hkdf(shared), reality_payload());  // 32 bytes
let hello = ChromeHelloTemplate::v131()
    .key_share(X25519, eph_pub)     // our ephemeral
    .legacy_session_id(auth_ct)     // <- the REALITY channel
    .sni(dest).grease().build();    // JA3-faithful
// then: TLS 1.3 key schedule over `hello` ... (the large part)
```

- **Pros:** pure Rust; full control; aligns with yip's from-scratch, `forbid(unsafe)`
  ethos; auditable; no Go, no cgo; auth crypto stays in safe Rust reusing
  `yip-crypto` primitives.
- **Cons:** **large** — a real uTLS is thousands of lines. Two hard sub-parts: (a) a
  ClientHello template that *exactly* matches a shipping Chrome (a mismatch makes us
  **more** fingerprintable than today's `boring` parrot, not less), and (b) a correct
  TLS 1.3 handshake/key-schedule (security-sensitive). Ongoing upkeep to track
  Chrome's evolving fingerprint.
- **Scope note:** this is its own milestone; it should not be smuggled into a
  "polish" PR. Mitigate the fingerprint risk by pinning **one** Chrome version and
  wiring a JA3/JA4 diff test against a captured real Chrome hello into CI.
- **Verdict:** ✅ correct long-term path; largest up-front cost.

### Option 4 — FFI to Go uTLS / Xray-core
Build uTLS+REALITY as a C-ABI shared library (cgo) and call it from yipd.

- **Pros:** reuses the **battle-tested, actively-maintained** REALITY and the
  correct, always-current Chrome fingerprint; fastest route to something that works.
- **Cons:** adds a **Go toolchain + cgo** to the build; `unsafe` FFI boundary
  (violates the unsafe policy); a second language in a pure-Rust project; a much
  larger static binary; breaks our clean cross-compile-and-ship pipeline (cgo cross
  builds are painful); the data plane would call into Go on the hot path.
- **Verdict:** ⚠️ pragmatic bridge, architecturally at odds with yip.

### Option 5 — rustls + a fingerprint fork
- **Reality:** rustls also exposes neither `legacy_session_id` nor the key_share
  private, and its default JA3 is a **distinctive non-Chrome** shape. Forking it to
  *both* match Chrome *and* expose the REALITY fields is roughly Option 3's effort
  with someone else's codebase.
- **Verdict:** ❌ no advantage over Option 3.

### Option 6 (rejected) — a `boring`-compatible "REALITY-lite" without ClientHello auth
Could we key auth on something a `boring` client *can* vary that the server reads
pre-termination? Measured answer: **no** — session_id, client_random, and the ext
list are all uncontrollable, so a `boring` client can carry **no** pre-termination
secret. Any workaround (source-IP allowlist, TCP-timing, TFO cookie) is weaker and
not true REALITY. **Verdict:** ❌ does not meet the goal.

---

## Feasibility spike (2026-07-15) — PROVEN

A throwaway pure-Rust spike (`ring` only, no Go, no BoringSSL fork, no `unsafe`)
built a TLS 1.3 ClientHello with a **caller-chosen `legacy_session_id`** and **our
own X25519 `key_share`** (we hold the private), sent it to the real
`cloudflare.com:443`, ran the RFC 8446 key schedule against the server's key_share,
and **decrypted the server's first encrypted record — `inner_type=0x16`, first byte
`0x08` = EncryptedExtensions.** i.e. both REALITY prerequisites hold in safe Rust:
we control the exact ClientHello fields REALITY needs, *and* our TLS 1.3 key schedule
is correct against real internet infrastructure.

Remaining REALITY.2 work is therefore known-tractable byte-work, not open research:
(a) expand the minimal spike hello into a **byte-exact Chrome template** with the
JA3/JA4 CI diff test, and (b) finish the handshake past EncryptedExtensions
(client Finished + app data). No uncertainty remains in the approach.

## Recommendation

**Client side: Option 3 (pure-Rust uTLS-equivalent), delivered as its own
milestone** — spike-confirmed viable (above). — it is the only path that gives real REALITY auth *and* honors yip's
pure-Rust / `forbid(unsafe)` / from-scratch constraints. Reject the Go-FFI shortcut
(Option 4): it would be the only Go+cgo+unsafe surface in the project and would
wreck the cross-compile pipeline the WAN bench just validated.

**Server side is not blocked by any of this** and should go first: raw-parse the
inbound ClientHello off the socket (no TLS lib needed to read `legacy_session_id` +
`key_share` + SNI), do the ECDH/decrypt auth check, and either (a) splice un-authed
connections to the real `dest` (the headline anti-probe win, deliverable *now* and
independently valuable), or (b) hand authed connections to `boring` as the acceptor
with an on-the-fly stolen cert.

### Proposed decomposition (each its own spec → plan → PR)

- **REALITY.1 — server-side raw ClientHello parse + transparent `dest` forwarding.**
  Upgrades the relay front from self-hosted decoy (Trojan) to real-upstream borrow.
  No client changes; auth can stay the current obf discriminator *terminated after*
  a boring handshake **only for the authed branch** — but the un-authed branch now
  splices to the real site. Biggest anti-probe gain per unit effort.
- **REALITY.2 — the pure-Rust REALITY ClientHello crafter (Option 3), client side.**
  The uTLS-equivalent + X25519-in-`legacy_session_id` auth + JA3/JA4 CI diff test.
- **REALITY.3 — on-the-fly stolen-cert generation** for the authed branch (fetch the
  real chain, re-sign an ephemeral leaf; client trusts the REALITY key, not CA).
- **REALITY.4 — yipd wiring:** `reality_dest`, `reality_server_names`,
  `reality_public_key`/`short_id` config; replace the 3c.4 relay-dial handshake with
  the REALITY.2 crafter.

### Open questions for the design session
- Which Chrome version to pin for the JA3/JA4 template (and the CI diff source)?
- What "signal-tlsd" behavior specifically should we match? (Named in the brief; I
  need the concrete reference to fold in its SNI/fronting/probe-response choices.)
- Do we keep the existing 3c.2 P2P `transport=tls` costume as-is (passive parrot,
  honestly documented as probe-visible) and layer REALITY only on the relay path?
