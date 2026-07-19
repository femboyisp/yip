# REALITY.5b — byte-matching ServerHello emission + server key schedule — design spec

**Date:** 2026-07-17
**Status:** design (pending user review)
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md) — REALITY.5 (#76).
**Depends on:** REALITY.5a (`ServerFlightTemplate` capture + cache — **stacks on 5a / #83**), REALITY.2 (`yip-utls` key schedule / ML-KEM / combiner / `HelloWriter`).
**Scope:** `yip-utls` (server KEX + ServerHello emission + key derivation) + `yip-rendezvous` (extract the client's ML-KEM ek from the ClientHello). PR 2 of REALITY.5 (5a/5b/5c/5d).

## Goal

Emit a **byte-matching ServerHello** for an authed connection — structurally identical to the borrowed `dest`'s (captured in 5a) but keyed on the **relay's own** ephemeral (so the relay holds the session keys) — and derive the server-side TLS 1.3 handshake keys. This is the server-side counterpart to REALITY.2's client: 5b builds the ServerHello + key schedule; 5c emits the encrypted flight; 5d wires it into `tls_front`.

## Why the relay's own key_share (not dest's)

A passive DPI byte-matches the cleartext ServerHello structure. The relay CANNOT relay dest's ServerHello verbatim — dest's `key_share` value is dest's ephemeral, whose private key only dest holds, so the relay couldn't derive the session keys. So the relay emits dest's **structure** (cipher, ordered extensions incl. GREASE, chosen group) with **its own** `key_share` value and a fresh random — indistinguishable to a DPI (dest's `key_share`/random are per-connection random too), while the relay holds the keys.

## Scope: key_share groups 4588 + X25519 only

The relay keys the group `dest` selected. Our Chrome-faithful client sends `key_share`s only for **X25519MLKEM768 (4588)** + **X25519 (29)** (offering P256/P384 without key_shares), so a dest selecting 4588 or X25519 replies in 1-RTT. A dest selecting **P256/P384** would require a **HelloRetryRequest** (client sent no key_share for them) — **deferred to #84** (evaluate whether any real dest needs it). 5b supports 4588 + X25519; an SNI whose `dest` selects any other group degrades to splice-only (5d — fail-safe, no fidelity claim).

## Design

### 1. `yip-utls` — server KEX (`server.rs`, new module)

```rust
/// The relay's server-side key exchange for a REALITY authed connection: given
/// the group `dest` selected and the client's key_share(s), generate the relay's
/// own ephemeral, and return the relay's `key_share` bytes (for the ServerHello)
/// + the ECDHE shared secret (for `derive_handshake_keys`).
pub fn server_key_share(
    group: u16,
    client_x25519: &[u8; 32],
    client_mlkem_ek: Option<&[u8]>, // required for group 4588
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, Vec<u8>), Error> // (server_key_share_bytes, shared_secret)
```

- **Group 4588 (X25519MLKEM768):** generate an X25519 ephemeral; **ML-KEM Encapsulate** against `client_mlkem_ek` (`ml_kem::kem::Encapsulate` — the mirror of REALITY.2's client `Decapsulate`) → `(ct(1088), mlkem_ss)`; `x25519_ss = X25519(server_eph_priv, client_x25519)`. `server_key_share = ct ‖ x25519_pub(32)`; `shared = mlkem_ss ‖ x25519_ss` (the **same combiner order** REALITY.2's client uses — `combined = mlkem_ss ‖ x25519_ss`). Fail-closed on a wrong-length/undecodable `client_mlkem_ek`.
- **Group 29 (X25519):** generate an X25519 ephemeral; `server_key_share = x25519_pub(32)`; `shared = X25519(server_eph_priv, client_x25519)`.
- **Any other group:** `Err(Error::UnsupportedGroup)` (5d → splice-only).

### 2. `yip-utls` — ServerHello emission

```rust
/// Emit a byte-matching ServerHello handshake message from the captured
/// `ServerHelloShape`, substituting the per-connection values, and derive the
/// server-side handshake keys. Returns the ServerHello wire bytes (handshake
/// message: `0x02 ‖ u24 len ‖ body`) + the `HandshakeKeys`.
pub fn emit_server_hello(
    shape: &ServerHelloShape,
    client_hello_msg: &[u8],      // the raw ClientHello handshake message (for the transcript)
    client_legacy_session_id: &[u8], // echoed into the ServerHello
    client_x25519: &[u8; 32],
    client_mlkem_ek: Option<&[u8]>,
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, HandshakeKeys), Error>
```

- Compute the server key_share via `server_key_share(shape.key_share_group, …)`.
- Rebuild the ServerHello body via `HelloWriter`, **verbatim from `shape`** except:
  - **`random`**: a fresh 32 bytes from `rng`.
  - **`legacy_session_id_echo`**: `client_legacy_session_id` (per-connection, from *this* ClientHello — NOT the template's).
  - **`cipher_suite`** = `shape.cipher_suite`; **compression** = `shape.legacy_compression_method`.
  - **extensions**: emit `shape.extensions` in order, verbatim, EXCEPT the `key_share` extension (id 0x0033) — replace its body with the relay's `server_key_share` bytes (`group(2) ‖ len(2) ‖ key_share_bytes`). All other extensions (supported_versions, GREASE, etc.) are copied byte-for-byte.
  - Wrap as a handshake message (`0x02 ‖ u24 len ‖ body`).
- Derive keys: `transcript_ch_sh = transcript_hash(client_hello_msg ‖ server_hello_msg, shape.cipher_suite)`; `derive_handshake_keys(&shared, &transcript_ch_sh, shape.cipher_suite)` (reused as-is). The server seals its flight with `server_key/server_iv` and opens the client's records with `client_key/client_iv`.
- Return `(server_hello_msg, handshake_keys)`.

### 3. `yip-rendezvous` — extract the client's ML-KEM ek

`bin/yip-rendezvous/src/reality.rs`'s `ClientHelloInfo` has `key_share_x25519` but not the ML-KEM ek (needed for group-4588 encapsulation). Add `pub key_share_mlkem_ek: Option<Vec<u8>>` and extract it in `parse_client_hello` (the group-4588 `key_share` entry is `mlkem_ek(1184) ‖ x25519(32)` — REALITY.2's `hello::key_share_body` documents this layout). Fail-closed on wrong length (→ `None`). This is what 5d feeds to `emit_server_hello`; 5b adds the field + a parse test.

## Testing / adversary

- **Unit (KEX):** `server_key_share` for 4588 returns a `ct(1088)‖x25519(32)` key_share + a 64-byte combined secret; for 29 a 32-byte key_share + 32-byte secret; an unsupported group → `Err`.
- **Round-trip (the key proof):** the relay `emit_server_hello`s from a fixture `ServerHelloShape` (both a 4588 and a 29 fixture); a test **client** — REALITY.2's own `parse_server_hello` + the client KEX (decapsulate/DH) + `derive_handshake_keys` — parses the emitted ServerHello and derives the **same** `HandshakeKeys` (`server_key`/`client_key` byte-equal both sides). This proves the ServerHello is well-formed AND both sides agree on the handshake keys (the actual goal).
- **Byte-match:** the emitted ServerHello's cipher/compression/extension-order (incl. GREASE) equal the `shape`'s; only `random`, `legacy_session_id_echo`, and the `key_share` value differ. Assert by re-parsing with `parse_server_hello_shape` and diffing against the source shape (modulo the substituted fields).
- **Unit (parse):** `parse_client_hello` extracts `key_share_mlkem_ek` from a fixture group-4588 ClientHello; wrong length → `None`.
- Existing REALITY.2 client tests + JA4 diff unchanged (5b is server-side, additive).

## Risks
- **New server-side crypto** (ML-KEM Encapsulate, server key schedule) — security-sensitive. Mitigation: reuse REALITY.2's audited key schedule + combiner unchanged; the round-trip test against REALITY.2's own client is the correctness gate (both sides must agree or no test passes). `forbid-unsafe`, no new crypto primitives.
- **Template drift:** if `dest`'s ServerHello structure changes between capture and emit, the emitted ServerHello matches the last captured template, not dest's live one (accepted; refresh mitigates — 5a).
- **Group mismatch:** dest selected a group outside {4588, 29} → `Err(UnsupportedGroup)` → 5d degrades to splice (fail-safe; tracked by #84).

## Non-goals (later REALITY.5 sub-milestones)
- Emitting the encrypted flight (EncryptedExtensions/Certificate[padded]/CertificateVerify/Finished) + the server stream (5c); the middlebox-compat CCS emission (5c, per the 5a hand-off note); wiring into `tls_front` (5d).
- P256/P384 server KEX + HelloRetryRequest (#84).

## Success criteria
1. `yip_utls::server_key_share` keys groups 4588 + X25519 (ML-KEM Encapsulate + X25519), producing the relay's key_share + the ECDHE shared secret with the same combiner as REALITY.2's client; unsupported group → `Err`.
2. `yip_utls::emit_server_hello` emits a ServerHello byte-matching the captured `ServerHelloShape` (verbatim cipher/extensions/GREASE; only random/session_id-echo/key_share substituted) and derives `HandshakeKeys`; a REALITY.2 client parsing it derives the **identical** keys (round-trip proven).
3. `yip-rendezvous`'s `ClientHelloInfo` extracts the client's ML-KEM ek (for 5d's group-4588 wiring); fail-closed on malformed.
4. `forbid-unsafe` (outside yip-io/yip-device); no `as` casts; clippy clean. No emission of the encrypted flight (5c) and no `tls_front` wiring (5d) here.
