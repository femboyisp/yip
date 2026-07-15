# REALITY.2 — pure-Rust uTLS client crafter (`yip-utls`) — design spec

**Date:** 2026-07-15
**Status:** design (pending user review)
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md)
**Depends on:** REALITY.1 (merged) — the relay that authenticates these clients.
**Approach:** Option 3 (pure-Rust). Spike-proven against real `cloudflare.com:443`.

## Goal

A new crate **`yip-utls`** (`#![forbid(unsafe_code)]`, pure Rust) that connects to a
REALITY relay by (a) emitting a **byte-faithful latest-stable-Chrome ClientHello**
whose `key_share` (X25519) and `legacy_session_id` (the REALITY auth seal) we control,
and (b) driving a **minimal TLS 1.3 handshake to completion**, yielding an
`AsyncRead + AsyncWrite` application-data stream. Delivered as a **standalone,
tested library — NOT wired into yipd** (that is REALITY.4, gated behind REALITY.3 +
server anti-replay). Merging REALITY.2 creates no deployable/unsafe state.

## Ground-truth fingerprint (captured 2026-07-15, real Chrome 150 via tls.peet.ws)

The crafter reproduces this exactly (structure), locked by a CI diff test:

- **JA3:** `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-17613-10-11-45-0-65037-35-13-16-27-43-65281-23-5-51,4588-29-23-24,0` → hash `e229e1bc25321cbef7268568d386cf86`
- **JA4:** `t13d1516h2_8daaf6152771_806a8c22fdea`; **JA4_r** (un-hashed, the authoritative field list) recorded in the fixture.
- **Extension wire order:** GREASE, sct(18), ALPS(17613), supported_groups(10), ec_point_formats(11), psk_key_exchange_modes(45), server_name(0), ECH(65037), session_ticket(35), signature_algorithms(13), ALPN(16, `h2`/`http/1.1`), compress_certificate(27, brotli), supported_versions(43, GREASE/1.3/1.2), renegotiation_info(65281), extended_master_secret(23), status_request(5, OCSP), key_share(51), GREASE.
- **supported_groups:** GREASE, X25519MLKEM768(4588), X25519(29), P-256(23), P-384(24).
- **key_share entries:** GREASE(1 byte), **X25519MLKEM768(4588) — 1216 bytes**, **X25519(29) — 32 bytes**.
- **legacy_session_id:** 32 random bytes.

The raw capture is committed as the test fixture (`yip-utls/tests/fixtures/chrome150.json` +
`.bin` of a captured hello), cross-checked against the curl-impersonate Chrome recipe.

## Why modern Chrome is tractable without Kyber/ECH crypto

JA3 and JA4 hash only the **structure** (cipher IDs, extension IDs + order, group IDs,
sig-alg IDs) — **not** the `key_share` or ECH *data*. Therefore:
- The **X25519MLKEM768 key_share is 1216 bytes of OS-random** — a real ML-KEM
  encapsulation key is pseudorandom, so this is indistinguishable to passive inspection
  and JA3/JA4-identical. **We do not implement ML-KEM/Kyber.** It is decorative.
- The **ECH extension** is emitted with correctly-shaped random data (GREASE-ECH), same
  reasoning.
- **REALITY auth rides the X25519 key_share entry** (Chrome's *second* one); we hold that
  private key. Our own relay (REALITY.1) always selects the X25519 group, so **the
  handshake completes over plain X25519 + a SHA-256 suite (AES-128-GCM / ChaCha20-Poly1305)
  — identical to the spike.** The 1216-byte MLKEM entry is never exercised in the key schedule.
- REALITY.1's `parse_client_hello` already walks past GREASE/MLKEM768 to the X25519 entry
  (tested), so the two are wire-compatible.

## Architecture — `yip-utls`

**Crypto crates — interop constraint.** REALITY.1's `reality.rs` seal/open uses
`x25519-dalek` + `chacha20poly1305` (+ HKDF-SHA256). The shared auth codec (`auth.rs`)
**must reuse those exact primitives** so a `yip-utls` seal is byte-identical to what
`reality_auth_open` expects — this is a correctness (interop) requirement, verified by the
interop test. The separate TLS 1.3 handshake (`handshake.rs`) may use `ring` (as the spike
did) or the RustCrypto stack; KAT its key schedule against openssl either way.

```
crates/yip-utls/
  Cargo.toml            # forbid-unsafe; auth: x25519-dalek + chacha20poly1305 + hkdf/sha2
                        #   (match REALITY.1 for interop); handshake: ring OR RustCrypto; getrandom
  src/lib.rs            # pub connect(...) entry + re-exports
  src/hello.rs          # Chrome-150 ClientHello crafter (2a)
  src/auth.rs           # SHARED REALITY auth seal/open codec (client seals, server opens)
  src/handshake.rs      # TLS 1.3 client key schedule + record layer to app-data (2b)
  src/stream.rs         # the returned AsyncRead+AsyncWrite app-data stream
  src/ja.rs             # JA3/JA4 computation over a ClientHello (for the diff test)
  tests/fixtures/       # chrome150.json + captured hello bytes
  tests/ja_diff.rs      # crafted hello == fixture (GREASE/random-normalized) — build fails on drift
  tests/handshake_live.rs  # (ignored-by-default) handshake vs a real TLS 1.3 site, like the spike
```

### Public interface (what REALITY.4 will consume later)
```rust
/// Connect to a REALITY relay: craft a Chrome-faithful ClientHello carrying the
/// REALITY auth seal, complete a TLS 1.3 handshake over the caller's TCP stream,
/// and return the application-data stream.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    sni: &str,
    server_reality_pub: &[u8; 32],
    short_id: [u8; 8],
) -> Result<RealityStream<S>, Error>;
```
(Sync/`std::net` variant too if the eventual yipd caller needs it — the 3c.4 relay-dial
thread is `std::thread`-based; decide at REALITY.4. REALITY.2 targets an async stream so
the live-handshake test is simple; keep the core sans-IO where practical.)

### Shared auth codec (`auth.rs`)
The seal the client writes into `legacy_session_id` must be exactly what REALITY.1's
`reality_auth_open` accepts. Extract the seal/open pair into `yip-utls::auth` (promoting
REALITY.1's `#[cfg(test)] reality_seal` to a real shared primitive), and have
`yip-rendezvous` depend on `yip-utls` for the `open` side. Scheme (unchanged from
REALITY.1): `shared = X25519(eph_priv, server_reality_pub)`; `key = HKDF-SHA256(salt="",
ikm=shared, info="yip-reality-v1", 32)`; `legacy_session_id = ChaCha20-Poly1305-seal(key,
nonce=client_random[..12], pt = short_id(8) ‖ unix_minutes_le(8))`. An **interop test**
proves crafter-seal ↔ `reality_auth_open` round-trips.

## Decomposition

- **REALITY.2a — the crafter + JA3/JA4 diff.** `hello.rs` + `ja.rs` + the fixture +
  `tests/ja_diff.rs`. Self-contained: assert the crafted hello's JA3/JA4 equals the
  captured Chrome-150 values, and that the emitted bytes match the fixture field-by-field
  after normalizing the 5 GREASE slots + `client_random` + `key_share`/ECH random data +
  the `legacy_session_id`. **A drift is a build failure.**
- **REALITY.2b — the TLS 1.3 client + shared auth codec.** `handshake.rs` + `stream.rs` +
  `auth.rs`, `connect()`, the interop test, and a live-server handshake test (spike-shaped,
  `#[ignore]` in CI unless network is allowed). Yields a working app-data stream over
  X25519 + AES-128-GCM/ChaCha20-Poly1305, zero-auth on the server cert (REALITY key, not CA).

## Testing / adversary
- **JA3/JA4 diff (the anti-fingerprint guard):** crafted hello == `e229e1bc…` /
  `t13d1516h2_8daaf6152771_…`, byte-diff vs fixture modulo GREASE/randoms. Fails the build
  on any drift — this is what prevents "hand-rolled hello is *more* fingerprintable."
- **Auth interop:** `yip-utls` seal opened by `yip-rendezvous::reality_auth_open` → authed;
  wrong key/short_id/stale → rejected.
- **Live handshake:** craft → connect a real TLS 1.3 endpoint → decrypt its EncryptedExtensions
  (spike's proof), plus a full round to app-data against `openssl s_server`.
- **Fail-closed:** malformed ServerHello / unexpected group / alert → `Error`, never panic.

## Risks & mitigations
- **Fingerprint drift** (Chrome bumps): the pinned fixture + CI diff *flags* it; bumping is
  routine maintenance (re-capture, update fixture). We pin Chrome 150 (captured today).
- **Hand-rolled TLS 1.3 crypto:** security-sensitive. Mitigation: TLS 1.3-only, X25519 +
  two SHA-256 suites, reuse `ring` primitives (no new crypto), KAT the key schedule against
  the spike/openssl, and keep `handshake.rs` small and single-purpose.
- **MLKEM/ECH realism:** random-of-right-length is JA3/JA4-faithful and passively
  indistinguishable (both fields are pseudorandom in real Chrome); documented as a known,
  deliberate boundary (a censor completing an MLKEM handshake would need our relay to *offer*
  it, which it never does).

## Non-goals (REALITY.2)
- Wiring into yipd (REALITY.4). On-the-fly stolen dest cert (REALITY.3). Server anti-replay
  (lands with REALITY.3/.4). ML-KEM/Kyber or ECH *crypto* (decorative bytes only). TLS 1.2.

## Success criteria
1. `yip-utls` builds `forbid(unsafe)`, `clippy -D warnings` clean.
2. `tests/ja_diff.rs`: crafted hello JA3==`e229e1bc25321cbef7268568d386cf86`,
   JA4==`t13d1516h2_8daaf6152771_806a8c22fdea`, byte-match vs fixture modulo the normalized fields.
3. `connect()` completes a real TLS 1.3 handshake and returns a usable app-data stream (live + openssl tests).
4. `yip-utls::auth` seal is accepted by `yip-rendezvous::reality_auth_open` (interop test); tamper/stale/wrong-key rejected.
