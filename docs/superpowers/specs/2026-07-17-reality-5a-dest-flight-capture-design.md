# REALITY.5a — dest server-flight template capture — design spec

**Date:** 2026-07-17
**Status:** design (pending user review)
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md) — REALITY.5 (#76).
**Depends on:** REALITY.2 (`yip-utls`), REALITY.3 (dest cert fetch + `RealityCertCache`), REALITY.4b (per-connection binding + `StolenFields` cache — **stacks on 4b / #82**).
**Scope:** `yip-utls` (the Chrome-faithful capture) + `yip-rendezvous` (caching). Read-only. PR 1 of the REALITY.5 milestone (5a/5b/5c/5d).

## Goal

Capture, per configured `server_name`, the **structure** of the real `dest`'s TLS 1.3 server flight, so later sub-milestones can emit an authed-path server flight indistinguishable from a genuine Chrome↔`dest` session. 5a is the **foundation**: it probes `dest` with a Chrome-faithful ClientHello, parses the full server flight, and caches a `ServerFlightTemplate`. No emission or matching yet (5b emits the ServerHello, 5c the encrypted flight, 5d wires it in).

## Why this is tractable — only the ServerHello is cleartext

In TLS 1.3 the server flight after `ServerHello` (EncryptedExtensions, Certificate, CertificateVerify, Finished) is **encrypted**. A passive DPI therefore observes only:

- **the `ServerHello` structurally** (cleartext) — later sub-milestones must **byte-match** it;
- **the encrypted records' lengths + framing** — later sub-milestones must **length/framing-match**, not content-match.

So the template captures the ServerHello *structure* and the *shape* (lengths/framing) of the encrypted flight — not the encrypted plaintext contents (which stay our own forged cert + 4b's derived-key CertVerify, later padded to size). `yip-utls` is uniquely placed to capture this: it reads the cleartext ServerHello raw **and** derives the handshake keys to decrypt the flight, so it sees both the ServerHello structure and every message's plaintext length + the enclosing encrypted-record lengths.

## Design

### 1. `yip-utls` — `ServerFlightTemplate` + `capture_dest_flight`

New public types (a new `template.rs`, or in `handshake.rs`):

```rust
/// The structural fingerprint of a real dest's TLS 1.3 server flight, captured
/// by a Chrome-faithful probe. Later REALITY.5 sub-milestones reproduce it.
pub struct ServerFlightTemplate {
    pub server_hello: ServerHelloShape,
    pub encrypted_flight: EncryptedFlightShape,
    pub cert_chain: CertChainShape,
}

/// The cleartext ServerHello structure to byte-match (5b), EXCLUDING the two
/// per-connection values (the 32-byte `random` and the `key_share` value),
/// which 5b substitutes with the relay's own.
pub struct ServerHelloShape {
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    /// Extensions in wire order, each `(id, body_bytes)` — INCLUDING any GREASE
    /// extension and its exact placement (order is a fingerprint). The
    /// `key_share` extension's body records the group; its 1-per-connection
    /// public-key VALUE is present here as captured but is substituted by 5b.
    pub extensions: Vec<(u16, Vec<u8>)>,
    /// The negotiated `key_share` group (echoed for convenience; also derivable
    /// from `extensions`).
    pub key_share_group: u16,
}

/// The observable shape of the encrypted flight to length/framing-match (5c).
pub struct EncryptedFlightShape {
    /// The **ciphertext-payload length** of each TLS record carrying the
    /// encrypted flight, in order — i.e. the value of each record's length
    /// field (bytes 3–4 of the 5-byte record header), which is what a passive
    /// DPI reads; it EXCLUDES the 5-byte outer header. This is how dest split
    /// EE‖Cert‖CertVerify‖Finished into records (a fingerprint). AEAD overhead:
    /// all three TLS 1.3 suites `yip_utls` supports use a 16-byte tag, and TLS
    /// 1.3 appends a 1-byte inner content-type before sealing, so for record
    /// `i` the plaintext(+any TLS-record padding) chunk 5c must seal to hit
    /// this length is exactly `record_lengths[i] - 17` (1 content-type + 16
    /// tag). Stating this fixes the framing math in 5c and avoids off-by-17.
    pub record_lengths: Vec<usize>,
    /// Per-message plaintext lengths (handshake-message length incl. the 4-byte
    /// header), so 5c can pad each forged message to match.
    pub encrypted_extensions_len: usize,
    pub certificate_len: usize,
    pub certificate_verify_len: usize,
    pub finished_len: usize,
}

/// The Certificate message's chain shape. 5c forges + pads ONLY the leaf and
/// appends dest's real intermediates verbatim — intermediates are public,
/// CA-signed, and carry no connection-specific data, so copying their exact
/// DER (rather than a size-only pad) gives full structural AND content chain
/// parity even to an adversary who decrypts the flight, at zero extra forging
/// (the outer TLS is zero-CA-auth, so the chain need not validate).
pub struct CertChainShape {
    /// dest's leaf-cert DER length — 5c pads the forged leaf's DER to this.
    pub leaf_der_len: usize,
    /// dest's intermediate certificates' raw DER bytes, in chain order
    /// (verbatim; 5c appends these after the forged leaf). Empty if dest sent a
    /// leaf-only chain.
    pub intermediates_der: Vec<Vec<u8>>,
}

/// What `capture_dest_flight` returns: the leaf DER (for the caller to parse
/// into its own cert fields) + the structural template.
pub struct CapturedFlight {
    pub leaf_der: Vec<u8>,
    pub template: ServerFlightTemplate,
}
```

- `pub async fn capture_dest_flight<S: AsyncRead + AsyncWrite + Unpin>(stream: S, sni: &str) -> Result<CapturedFlight, Error>` — a **focused sibling of `connect`** (not `connect` with a flag — keeps `connect`'s hot path clean; shares the parse/key-schedule helpers). It:
  1. Sends the same Chrome-faithful ClientHello `connect` sends (reuse `hello::craft` + the ephemeral/ML-KEM setup). A REALITY seal is irrelevant here (probing the real `dest`, which ignores `legacy_session_id`); pass a zero/throwaway seal, exactly as REALITY.2's live tests do against Cloudflare.
  2. Reads + parses the raw `ServerHello` into `ServerHelloShape` (extend the parser — today `parse_server_hello` extracts only `suite`/`group`/`server_key_share`; 5a additionally records the ordered extension list and compression).
  3. Derives the handshake keys and **decrypts** the flight (reuse `derive_handshake_keys` + the record layer), walking EE/Certificate/CertificateVerify/Finished — recording `EncryptedFlightShape` (each record's ciphertext-payload length from the record layer; per-message lengths from the flight walk) and `CertChainShape` (the leaf DER's length as `leaf_der_len`, and every subsequent chain cert's DER verbatim into `intermediates_der`) + the leaf DER itself into `CapturedFlight` (from the Certificate message's first entry).
  4. Returns after the server `Finished` — it does **not** send a client `Finished` or enter the app phase (it is a probe; no data is tunneled). Bounded by the crate's existing flight/OOM caps; fail-closed on malformed input (reuse the `Reader` discipline).

### 2. `yip-rendezvous` — capture via yip_utls + cache the template

- **Unify the dest probe on `yip-utls`.** Rewrite `fetch_dest_leaf` (today `tokio_boring::connect`) to call `yip_utls::capture_dest_flight`: connect TCP to `dest`, `capture_dest_flight(tcp, sni)`, then extract `StolenFields` from `captured.leaf_der` (parse the DER via `boring::x509::X509::from_der` + the existing `extract_fields` logic — adapt `extract_fields` to take a `&X509Ref` built from the DER, or a `&[u8]` DER) and return `(StolenFields, ServerFlightTemplate)`. One Chrome-faithful connection yields both; `dest` now responds to the exact hello our clients send.
- **Cache the template.** `RealityCertCache::CacheEntry` gains `template: Arc<ServerFlightTemplate>`; `fields_for`/`acceptor_for` unchanged; add `pub fn template_for(&self, sni: &str) -> Option<Arc<ServerFlightTemplate>>`. `prewarm` + `apply_refresh` capture and store the template alongside the fields. `template_for` is defined here but not consumed until 5b — gate it `#[cfg_attr(not(test), expect(dead_code, reason = "consumed by REALITY.5b"))]`, matching the codebase precedent.
- The `--reality-server-name` allowlist, staleness bound, degrade-to-splice, and TLS-1.3-only forged acceptor (REALITY.3/4b) are all unchanged — 5a only swaps the probe transport and adds the cached template.

## Config surface / docs
No new config. Note in `docs/configuration.md` that the dest probe is now Chrome-faithful (a fidelity improvement) and captures a server-flight template for REALITY.5's authed-path mimicry.

## Testing / adversary
- **Unit (parse):** feed a constructed/fixture server flight (a ServerHello with a known ordered extension list incl. a GREASE ext + an encrypted flight of known record/message lengths + a 2-cert chain: 1 leaf + 1 intermediate) → assert `ServerFlightTemplate` fields (cipher, extension order+GREASE, `record_lengths` = each record's ciphertext-payload length, per-message lengths, `cert_chain.leaf_der_len`, and `cert_chain.intermediates_der` = the intermediate's verbatim DER).
- **Unit (fail-closed):** malformed/truncated ServerHello or flight → `Err`, no panic.
- **Live (`#[ignore]`, network):** `capture_dest_flight` against `cloudflare.com:443` → template has a plausible `cipher_suite`, a non-empty ordered `extensions` (incl. `key_share`/`supported_versions`), a non-zero `cert_chain.leaf_der_len` (Cloudflare typically also yields ≥1 verbatim intermediate in `intermediates_der`), and a non-empty `record_lengths`. Mirrors REALITY.2's `handshake_live` gating.
- **Migration:** the rewritten `fetch_dest_leaf` yields a `StolenFields` equivalent to the old boring path for a local stand-in `dest` (adapt REALITY.3's cert-cache tests to the new probe; they stay green). Anti-replay / forged-acceptor tests untouched.

## Risks
- **Probe brittleness:** `capture_dest_flight` is a second full hand-rolled TLS 1.3 handshake path in `yip-utls`; a parser bug fails the probe (→ that SNI degrades to splice-only via REALITY.3's existing per-SNI degrade, fail-safe) rather than mis-serving. Mitigation: it shares `connect`'s vetted parse/key-schedule helpers; the live test guards real-world shape.
- **Template staleness / dest variation:** `dest` may vary its flight (load-balancer TLS termination differences, cert rotation). Captured at prewarm + refreshed like the cert; a per-connection exact match isn't promised (5b/5c match the last captured template). Documented; acceptable for a structural template.
- **Group the relay can key:** the captured `key_share_group` might be one the relay cannot complete server-side (exotic group). 5a only RECORDS it; 5b handles keyable-group selection. Out of scope here.

## Non-goals (later REALITY.5 sub-milestones)
- Emitting the ServerHello (5b) / the encrypted flight + cert-size padding (5c) / wiring the hand-rolled server into `tls_front` (5d) + the 4b fidelity follow-ups (alert/CCS live-capture, hermetic CertVerify KAT).
- Byte-matching the encrypted *plaintext* contents (only lengths/framing are observable).

## Success criteria
1. `yip_utls::capture_dest_flight` completes a Chrome-faithful handshake to a real dest and returns a `ServerFlightTemplate` capturing the ServerHello structure (ordered extensions incl. GREASE, cipher, key_share group), the encrypted-flight shape (ciphertext-payload record lengths + per-message lengths), the leaf size, and the verbatim intermediate-cert DERs — fail-closed on malformed input, no panic.
2. `yip-rendezvous`'s dest probe is unified on this Chrome-faithful capture; the `ServerFlightTemplate` is cached per SNI (`template_for`) alongside `StolenFields`, captured at prewarm + refresh; REALITY.3/4b cert/anti-replay behavior unchanged and tests green.
3. `forbid-unsafe` (outside yip-io/yip-device); no `as` casts; clippy clean. No authed-path emission changes (that's 5b+).
