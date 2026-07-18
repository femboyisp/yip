# REALITY.5c — encrypted server-flight emission + server-side stream — design spec

**Date:** 2026-07-17
**Status:** design (pending user review)
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md) — REALITY.5 (#76).
**Depends on:** REALITY.5b (`emit_server_hello` + `HandshakeKeys`), REALITY.5a (`EncryptedFlightShape` + `CertChainShape` + `capture_dest_flight`), REALITY.4b (`auth::derive_cert_key`, the client `verify_certificate_verify`), REALITY.2 (`record_seal`, `record_open`, `finished_verify_data`, `derive_application_keys`, `RealityStream`).
**Scope:** `yip-utls` only (server-side flight assembly + sealing + record framing + server stream). PR 3 of REALITY.5 (5a/5b/5c/5d).

## Goal

Complete the server side of the hand-rolled TLS 1.3 handshake begun in 5b: emit the **encrypted server flight** (`EncryptedExtensions` / `Certificate` / `CertificateVerify` / `Finished`) sealed under the 5b handshake keys and **framed to byte-match the borrowed `dest`'s record lengths** (captured in 5a), then provide the server-side data-phase stream. Together with 5b's cleartext ServerHello, this makes the relay's entire authed server flight — cleartext ServerHello **and** encrypted records — indistinguishable to a passive DPI from a genuine Chrome↔`dest` session. This replaces the BoringSSL `SslAcceptor` currently used on the authed REALITY path (`reality_cert::build_forged_acceptor*`), whose flight is BoringSSL's, not `dest`'s.

## Threat model / fidelity strategy (the load-bearing decision)

The in-scope adversary is a **passive DPI**, which sees only the **encrypted record framing** — the outer record lengths (`EncryptedFlightShape::record_lengths`). The per-message lengths (`encrypted_extensions_len`, `certificate_verify_len`, …) live **inside** the AEAD, visible only to a party holding the session keys — the benign client, or nobody (the outer TLS is zero-CA-auth; a MITM cannot derive the keys). Moreover most handshake messages **cannot** be padded to an arbitrary target: `EncryptedExtensions` has no padding slot, and 5c's `CertificateVerify` is ECDSA-P256 (the 4b binding key), so its size cannot match a `dest` that signed with RSA.

**Decision (user-approved):** 5c matches **`record_lengths` exactly** (full passive-DPI fidelity) and relies on the forged **leaf** being sized to `dest`'s `leaf_der_len` (5d's forging job). `EE` / `CertificateVerify` / `Finished` are emitted at their natural sizes and the difference is absorbed by **TLS 1.3 record padding**. The captured per-message lengths (`ee_len`, `cert_verify_len`, `finished_len`) become validation guides, **not** hard emission targets. If the natural flight content cannot fit `dest`'s record framing, 5c returns `Err` and 5d degrades that connection to splice-only (fail-safe).

## What `record_lengths` covers (scope-fixing fact)

`capture_dest_flight` (5a, `stream.rs`) reads the server flight **under the handshake keys** and **breaks the instant it sees the server `Finished`** (`find_finished_end`), pushing `record_lengths.push(payload.len())` for each record along the way. Therefore `record_lengths` covers **only the `{EE, Certificate, CertificateVerify, Finished}` handshake-key records** — it never includes post-`Finished` `NewSessionTicket` records (those are sealed under the *application* keys and are never captured). Any surplus (`sum(record_lengths[i] - 17)` exceeding the four messages' bytes) is `dest`'s **TLS record padding** inside those handshake records, not NST.

Consequence: **5c seals the entire flight under the 5b handshake keys** (`HandshakeKeys::server_key`/`server_iv`) — no application-key derivation for the flight, no fake NST emission. (`17` = 1 inner content-type byte + 16-byte AEAD tag; identical across all three TLS 1.3 suites `yip-utls` supports.)

## The 5c / 5d boundary

5c stays pure `yip-utls` (no networking beyond the generic `AsyncRead + AsyncWrite` stream, fully testable in-process):

- **5c (`yip-utls`, this PR):** given the 5b `HandshakeKeys`, the 5a `EncryptedFlightShape` + `CertChainShape`, a caller-supplied **forged leaf DER** and **ECDSA-P256 signing key**, and the raw `ClientHello ‖ ServerHello` transcript bytes, assemble + seal the flight (CCS ‖ handshake-key records matching `record_lengths`), drain the client's CCS + `Finished`, derive application keys, and return the server-side `RealityStream`. All wire assembly, sealing, and framing live here.
- **5d (`yip-rendezvous`, next PR):** forge the leaf (rcgen — mimic `dest`'s fields, SPKI = `derive_cert_key(shared)` public key, **pad to `leaf_der_len`**), derive the signing key, and drive the epoll pump — replacing `build_forged_acceptor*`.

## Design

### 1. `HandshakeKeys` — expose `server_hs_traffic`

The server `Finished`'s `verify_data` needs the server handshake-traffic secret as its base. `derive_handshake_keys` already computes it internally (`s_hs`) but `HandshakeKeys` stores only `client_hs_traffic`. Add:

```rust
pub struct HandshakeKeys {
    // ... existing fields ...
    pub client_hs_traffic: Vec<u8>,
    pub server_hs_traffic: Vec<u8>, // NEW — base secret for the server Finished
}
```

Populate it from the existing `s_hs` local in `derive_handshake_keys`. Additive; 5b's `emit_server_hello` and the client `connect` are unaffected (they don't read it).

### 2. `sign_certificate_verify` — the signing mirror of 4b's verifier

```rust
/// Sign the TLS 1.3 server `CertificateVerify` (RFC 8446 §4.4.3) with the
/// derived ECDSA-P256 key, over the same signed content the client's
/// `verify_certificate_verify` reconstructs. Returns the DER ECDSA signature.
pub fn sign_certificate_verify(
    signing_key: &p256::ecdsa::SigningKey,
    transcript_hash_through_certificate: &[u8],
) -> Result<Vec<u8>, Error>
```

- Reconstruct the §4.4.3 signed content **identically** to `verify_certificate_verify`: `0x20 × 64 ‖ "TLS 1.3, server CertificateVerify" ‖ 0x00 ‖ transcript_hash_through_certificate`.
- Sign with `ecdsa_secp256r1_sha256` (scheme `0x0403`) — the hard-pinned scheme the client verifies. No `suite` argument: 4b hard-pins the scheme, and `p256::ecdsa::SigningKey` signs with SHA-256 internally, so the signer needs no suite (the caller uses `suite` only to compute `transcript_hash_through_certificate`).
- The signing key is `derive_cert_key(shared)` (4b) — the client pins the leaf's SPKI to this key and verifies this signature, so this **is** the 4b relay-verification binding. `DerivedCertKey` exposes `pkcs8_der` (not a `SigningKey`), so the caller reconstructs `p256::ecdsa::SigningKey::from_pkcs8_der(&derived.pkcs8_der)` — a one-liner that keeps this primitive decoupled from the 4b type and testable with any P-256 key.
- Fail-closed: propagate any signing error as `Err` (no `unwrap`).

### 3. `emit_server_flight` — assemble + seal + frame

```rust
/// Assemble the encrypted server flight (EE/Certificate/CertificateVerify/
/// Finished), sealed under `keys` handshake keys and framed to byte-match
/// `flight_shape.record_lengths`, prefixed with the middlebox-compat CCS.
/// Returns the full wire bytes (CCS ‖ sealed records) plus the derived
/// application keys for the data phase.
pub fn emit_server_flight(
    keys: &HandshakeKeys,
    flight_shape: &EncryptedFlightShape,
    cert_chain: &CertChainShape,
    forged_leaf_der: &[u8],
    cert_signing_key: &p256::ecdsa::SigningKey,
    transcript_ch_sh: &[u8], // raw ClientHello ‖ ServerHello bytes (from 5b)
) -> Result<ServerFlight, Error>

pub struct ServerFlight {
    /// CCS ‖ sealed handshake-key records — write these to the client.
    pub wire: Vec<u8>,
    /// Application traffic keys for the data phase (both directions).
    pub app_keys: ApplicationKeys,
}
```

**Step 1 — build the four handshake messages** into a contiguous plaintext `hs_stream`:
- **EncryptedExtensions** (`0x08`): minimal valid message — empty extensions list. Wire: `08 00 00 02 00 00` (u24 body-len = 2, u16 ext-list-len = 0).
- **Certificate** (`0x0b`, RFC 8446 §4.4.2): `certificate_request_context = empty (00)` ‖ `certificate_list` (u24 len) where the first entry is `u24 cert_data_len ‖ forged_leaf_der ‖ u16 ext_len(00 00)` and each `cert_chain.intermediates_der` entry follows verbatim as `u24 len ‖ der ‖ 00 00`. Leaf sizing to `leaf_der_len` is 5d's forging responsibility; 5c uses `forged_leaf_der` as given.
- **CertificateVerify** (`0x0f`): `algorithm(0x0403) ‖ u16 sig_len ‖ sig`, `sig = sign_certificate_verify(cert_signing_key, transcript_hash(transcript_ch_sh ‖ EE ‖ Certificate, suite))`.
- **Finished** (`0x14`): body = `finished_verify_data(keys.server_hs_traffic, transcript_hash(transcript_ch_sh ‖ EE ‖ Certificate ‖ CertificateVerify, suite), suite)`.

**Step 2 — record framing** to match `record_lengths` exactly. Greedily chunk `hs_stream` across the records:
```
seq = 0; off = 0; wire = CHANGE_CIPHER_SPEC_RECORD.to_vec()
for len in record_lengths:
    cap = len - 17                        // Err if len < 17
    chunk = hs_stream[off .. off + min(remaining, cap)]
    pad  = cap - chunk.len()
    wire ||= record_seal_padded(server_key, server_iv, seq, suite,
                                CONTENT_TYPE_HANDSHAKE, chunk, pad)   // inner = chunk ‖ 0x16 ‖ 0×pad
    off += chunk.len(); seq = seq.checked_add(1)?
Err(FlightTooLarge) if off < hs_stream.len()   // content didn't fit
```
Records past the handshake bytes are pure padding (`0x16 ‖ zeros`); the client's `RealityStream::poll_fill_read_buf` already skips post-handshake handshake-typed records. Because our `Certificate ≈ dest`'s (leaf sized to `leaf_der_len` + `intermediates_der` verbatim) and our `EE`/`CertVerify`/`Finished` are each `≤ dest`'s, `hs_stream.len() ≤ sum(cap)` holds and the greedy fill reproduces `dest`'s exact record count and lengths.

**Step 3 — application keys.** Derive `app_keys = derive_application_keys(keys.handshake_secret, transcript_hash(transcript_ch_sh ‖ EE ‖ Certificate ‖ CertificateVerify ‖ Finished, suite), suite)`. Both sides hash the same wire bytes through the server `Finished`, so the client (which does not validate the server `Finished` contents) derives identical application keys.

### 4. `record_seal_padded` — padding-aware seal (new primitive in `handshake.rs`)

The shipped `record_seal` builds `inner = plaintext ‖ content_type` (no padding). Add a sibling that appends TLS 1.3 record padding:

```rust
/// Like `record_seal`, but appends `pad_len` zero bytes of TLS 1.3 record
/// padding after the inner content-type, so the sealed record's ciphertext-
/// payload length is exactly `content.len() + 1 + pad_len + TAG_LEN`.
pub fn record_seal_padded(
    key: &[u8], iv: &[u8; 12], seq: u64, suite: u16,
    content_type: u8, content: &[u8], pad_len: usize,
) -> Result<Vec<u8>, Error>
```

Refactor `record_seal` to delegate (`record_seal(..) = record_seal_padded(.., 0)`) so the two share one implementation and the existing `record_seal` KATs continue to cover the `pad_len = 0` path.

### 5. Role-agnostic `RealityStream` — add a server constructor

The client `RealityStream` seals egress with `client_key`/`client_iv` and opens ingress with `server_key`/`server_iv`. The server needs the exact mirror (seal with `server_*`, open with `client_*`). The record machinery (`poll_read`/`poll_write`, CCS-skip, NewSessionTicket-skip) is identical.

- **Rename** the struct's internal `client_key`/`client_iv`/`client_seq` → `egress_key`/`egress_iv`/`egress_seq` and `server_key`/`server_iv`/`server_seq` → `ingress_key`/`ingress_iv`/`ingress_seq` (semantic, role-neutral). Pure field renames — behavior-identical.
- The existing `connect` builds the **client** variant (egress = client keys, ingress = server keys) — unchanged behavior.
- Add a **server** constructor used by 5c's data phase (egress = server-app keys, ingress = client-app keys), consuming the `ApplicationKeys` from `emit_server_flight` and the already-connected stream (after the flight is written and the client's CCS + `Finished` drained).

The shipped client tests + round-trip tests are the regression net for the rename.

### 6. Server data-phase entry (drain client Finished, then stream)

A server-side counterpart to the tail of `connect`: after `emit_server_flight`'s `wire` is written to the client, **drain the client's CCS + `Finished`** (open under `keys.client_key`/`client_iv` handshake keys; **contents unchecked** — REALITY is zero client-auth, exactly symmetric with how the client drains the server's `Finished`), then build and return the server `RealityStream` on the application keys. This may be a `pub async fn serve(stream, keys, flight_shape, cert_chain, forged_leaf_der, cert_signing_key, transcript_ch_sh) -> Result<RealityStream<S>, Error>` that composes `emit_server_flight` + write + drain + stream construction, mirroring `connect`'s shape so 5d has a single entry point.

## Error handling (fail-closed)

- `record_lengths` empty, or any `record_lengths[i] < 17` → `Err` (malformed template) → 5d splices.
- `hs_stream.len() > sum(record_lengths[i] - 17)` → `Err(Error::FlightTooLarge)` → 5d splices.
- `sign_certificate_verify` error → `Err` (no `unwrap` on the key).
- Per-record `seq` via `checked_add` (matches `capture_dest_flight`); overflow → `Err`, not panic.
- Draining the client `Finished`: bounded read (reuse the `MAX_SERVER_FLIGHT_LEN`-style cap), fail-closed on malformed/oversized.
- Crate-wide `forbid-unsafe`; no `as` casts; no bare `#[allow]` (use `#[expect(reason=)]`). Length math via `usize`/`u16::try_from`/the existing u24 helpers, fail-closed on overflow.

## Testing / adversary

1. **Round-trip gate (the correctness proof):** in-process `tokio::io::duplex` — the shipped client `connect(verify = on)` on one end; 5c's `serve` (`emit_server_flight` + write + drain + server stream) on the other; both keyed by one shared REALITY seal (so `derive_cert_key(shared)` agrees). Assert: the client completes the handshake, **verifies the 4b binding** (CertVerify by `derive_cert_key(shared)`, leaf pinned), and application data flows **both** directions over the two `RealityStream`s (application keys agree). This subsumes/productionizes the existing `run_mock_tls13_server_with_cert` test mock.
2. **Byte-framing test:** emit from a fixture `EncryptedFlightShape` whose `record_lengths` includes an inflated final record **and** a trailing pure-padding record; assert the emitted records' outer lengths **equal `record_lengths` exactly**, the CCS is present and first, and re-opening under the handshake keys recovers `EE ‖ Cert ‖ CertVerify ‖ Finished` (padding stripped).
3. **CertVerify sign↔verify KAT:** `sign_certificate_verify` output is accepted by the shipped `verify_certificate_verify` for the same transcript + key; rejected for a wrong key and for a tampered transcript.
4. **`record_seal_padded` KAT:** `record_seal_padded(.., pad_len)` output opens under `record_open` to the original content (padding stripped) and its ciphertext-payload length is exactly `content.len() + 1 + pad_len + 16`; `pad_len = 0` equals the shipped `record_seal`.
5. **Fail-safe tests:** capacity overflow, `record_lengths[i] < 17`, empty `record_lengths` → `Err` (not panic).
6. **No regression:** the full existing `yip-utls` suite (client `connect`, JA4-diff, 5a/5b) stays green after the role-agnostic rename and the `record_seal` refactor.

## Risks

- **Server-side handshake correctness** (the server key schedule + CertVerify signing) is security-sensitive. Mitigation: reuse REALITY.2's audited `record_seal`/`finished_verify_data`/`derive_application_keys` and 4b's §4.4.3 construction unchanged; the round-trip test against the shipped client (which must complete + verify or no test passes) is the correctness gate.
- **The role-agnostic rename** touches shipped client code. Mitigation: pure mechanical field renames, behavior-identical; existing client + round-trip tests are the net.
- **Template capacity edge:** a `dest` whose flight is unusually tightly framed (little/no padding) combined with a forged leaf near `leaf_der_len` could leave `hs_stream` marginally over capacity. Mitigation: `FlightTooLarge` → splice (fail-safe, no broken handshake); 5d can log the SNI for template review.

## Non-goals (later REALITY.5 sub-milestones / deferred)

- No `yip-rendezvous` wiring, no leaf forging (rcgen), no epoll pump, no BoringSSL-acceptor removal — all **5d**.
- No post-`Finished` `NewSessionTicket` emission (never captured; outside `record_lengths`).
- No P256/P384 server KEX + HelloRetryRequest (#84).
- `close_notify` on teardown (REALITY.2 M3) is out of scope unless trivially shared with the client fix.

## Success criteria

1. `sign_certificate_verify` produces a signature the shipped `verify_certificate_verify` accepts (and rejects for a wrong key / tampered transcript) — the 4b binding, server side.
2. `emit_server_flight` emits `CCS ‖ records` whose outer lengths **equal** `EncryptedFlightShape::record_lengths` exactly, carrying a well-formed `EE ‖ Certificate ‖ CertificateVerify ‖ Finished` sealed under the 5b handshake keys; over-capacity/malformed templates → `Err` (fail-safe).
3. A shipped client `connect(verify = on)` completes the full handshake against 5c's server flight in-process, **verifies the 4b binding**, and exchanges application data both directions (application keys agree).
4. `record_seal_padded` + the role-agnostic `RealityStream` rename land with the existing `yip-utls` suite green (no client regression).
5. `forbid-unsafe`; no `as` casts; no bare `#[allow]`; clippy clean. No `yip-rendezvous` wiring (5d) and no leaf forging here.
