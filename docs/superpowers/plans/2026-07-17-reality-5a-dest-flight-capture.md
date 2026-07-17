# REALITY.5a — Dest Server-Flight Template Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture, per configured `server_name`, the structural template of the real `dest`'s TLS 1.3 server flight (ServerHello structure + encrypted-flight record/message lengths + cert-chain leaf size & verbatim intermediates) via a Chrome-faithful `yip_utls` probe, and cache it in `yip-rendezvous` — the read-only foundation for REALITY.5b/c/d.

**Architecture:** A new `yip_utls::capture_dest_flight` (a focused sibling of `connect`) sends the Chrome-faithful ClientHello, reads + parses the raw ServerHello structure, derives handshake keys, decrypts the flight, and records a `ServerFlightTemplate` + leaf DER — returning after the server Finished (no client Finished / no app phase). `yip-rendezvous` unifies its dest probe on this (replacing the boring cert fetch) and caches the template per SNI.

**Tech Stack:** Rust; `yip_utls` hand-rolled TLS 1.3 (reuses `hello::craft`, `parse_server_hello`, `derive_handshake_keys`, `record_open`, the flight scan); `yip-rendezvous` (boring X509 leaf parse, `RealityCertCache`).

## Global Constraints

- `#![forbid(unsafe_code)]` everywhere except `yip-io`/`yip-device` — NO `unsafe`.
- NO `as` numeric casts — use `try_from`/`from_be_bytes`/`usize::from`.
- NO bare `#[allow(...)]` — use `#[expect(reason = "...")]`.
- **Read-only** — 5a captures + caches; NO authed-path emission changes (that's 5b+). `connect`'s hot path stays byte-unchanged (JA3/JA4 diff green).
- `record_lengths[i]` = the TLS record's ciphertext-payload length (the length-field value, excluding the 5-byte header). Per-record plaintext(+padding) 5c must reproduce = `record_lengths[i] - 17` (1 content-type + 16 AEAD tag; all three TLS 1.3 suites use a 16-byte tag).
- `CertChainShape` = `{ leaf_der_len, intermediates_der: Vec<Vec<u8>> }` — intermediates captured VERBATIM (public CA certs; 5c appends them after the forged leaf).
- Fail-closed on malformed/hostile dest bytes — no panic (reuse the crate's `Reader` discipline + the existing `MAX_SERVER_FLIGHT_LEN`/`MAX_HANDSHAKE_MSG_LEN` caps).
- Every task ends green: relevant `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt`.
- Stacked on merged 4b. **Never merge the PR** — open it, leave it for the user.

**Spec:** `docs/superpowers/specs/2026-07-17-reality-5a-dest-flight-capture-design.md`. Read it (esp. "Why this is tractable" + §1) before starting.

---

### Task 1: Template types + ServerHello-shape parse (`yip-utls`)

Define the `ServerFlightTemplate` types and extend the ServerHello parser to capture the full structure (ordered extensions incl. GREASE + compression), not just suite/group/key_share.

**Files:**
- Create: `crates/yip-utls/src/template.rs` (the types)
- Modify: `crates/yip-utls/src/handshake.rs` (add `parse_server_hello_shape`)
- Modify: `crates/yip-utls/src/lib.rs` (`pub mod template;` + re-exports)

**Interfaces:**
- Produces: `ServerFlightTemplate`, `ServerHelloShape`, `EncryptedFlightShape`, `CertChainShape`, `CapturedFlight` (exact fields per the spec §1).
- Produces: `pub fn parse_server_hello_shape(record_payload: &[u8]) -> Result<ServerHelloShape, Error>` — like `parse_server_hello` but returns the ordered extension list + compression + cipher + key_share group.

- [ ] **Step 1: Write the failing ServerHello-shape test**

Add to `handshake.rs` tests. Build a minimal ServerHello handshake-message payload with a known cipher (`0x1301`), null compression, and an ordered extension list `[supported_versions(43), key_share(51) with group X25519(29), a GREASE ext (0x?a?a)]`, then assert the parse:

```rust
    #[test]
    fn parse_server_hello_shape_captures_ordered_extensions() {
        // handshake msg: type(0x02) ‖ u24 len ‖ { legacy_version(0x0303) ‖ random(32)
        //   ‖ session_id(u8 len + bytes) ‖ cipher_suite(2) ‖ compression(1) ‖ ext(u16 len + list) }
        let sh = build_test_server_hello(
            0x1301, // cipher
            0x00,   // compression
            &[
                (0x002b_u16, vec![0x03, 0x04]),            // supported_versions -> TLS 1.3
                (0x0033_u16, key_share_ext_body(0x001d)),  // key_share, group X25519(29)
                (0x2a2a_u16, vec![]),                      // a GREASE extension, empty
            ],
        );
        let shape = parse_server_hello_shape(&sh).expect("parse");
        assert_eq!(shape.cipher_suite, 0x1301);
        assert_eq!(shape.legacy_compression_method, 0x00);
        assert_eq!(shape.key_share_group, 0x001d);
        // Order + ids preserved (incl. the GREASE ext at its position).
        let ids: Vec<u16> = shape.extensions.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0x002b, 0x0033, 0x2a2a]);
    }
```

Add the `build_test_server_hello` / `key_share_ext_body` test helpers (compose the bytes per the comment). If similar helpers already exist for the `parse_server_hello` tests, reuse them.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yip-utls handshake::tests::parse_server_hello_shape`
Expected: FAIL — `cannot find function parse_server_hello_shape` / `ServerHelloShape`.

- [ ] **Step 3: Define the template types**

Create `crates/yip-utls/src/template.rs` with the five structs exactly as in the spec §1 (`ServerHelloShape`, `EncryptedFlightShape`, `CertChainShape`, `ServerFlightTemplate`, `CapturedFlight`) with their doc comments (copy the spec's field docs — esp. the `record_lengths` `-17` note and the `CertChainShape` verbatim-intermediates rationale). Add `pub mod template;` to `lib.rs` and re-export the types (`pub use template::{ServerFlightTemplate, CapturedFlight};` etc.).

- [ ] **Step 4: Implement `parse_server_hello_shape`**

In `handshake.rs`, add it next to `parse_server_hello`. Reuse the same `Reader`/cursor discipline `parse_server_hello` uses (it already walks legacy_version/random/session_id/cipher/compression/extensions to pull suite+group+key_share). The shape variant additionally accumulates every extension as `(id, body.to_vec())` in wire order and records the compression byte:

```rust
/// Like [`parse_server_hello`] but captures the FULL ServerHello structure
/// (ordered extensions incl. GREASE, compression) for REALITY.5 mimicry. The
/// per-connection `random` and `key_share` VALUE are not returned here (5b
/// substitutes the relay's own); the `key_share` group IS (`key_share_group`).
pub fn parse_server_hello_shape(record_payload: &[u8]) -> Result<crate::template::ServerHelloShape, Error> {
    // ... same bounded walk as parse_server_hello, but:
    //   - record `compression` byte,
    //   - for each extension, push (ext_id, ext_body.to_vec()) in order,
    //   - when ext_id == key_share (0x0033), read the group (first u16 of the body)
    //     into key_share_group.
    // Fail-closed via `.get()`/Reader on every field; reuse parse_server_hello's guards.
}
```

If `parse_server_hello` has an internal helper that walks to the extension list, factor it so both share the walk (DRY) — otherwise mirror its exact bounded logic. Keep `parse_server_hello` byte-behavior-unchanged (its callers in `connect` must not shift).

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p yip-utls handshake::tests::parse_server_hello_shape` → PASS. Then `cargo test -p yip-utls handshake` (existing parse tests still green).

- [ ] **Step 6: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt -p yip-utls
git add crates/yip-utls/src/template.rs crates/yip-utls/src/handshake.rs crates/yip-utls/src/lib.rs
git commit -m "feat(reality.5a): ServerFlightTemplate types + parse_server_hello_shape (ordered exts + GREASE)"
```

---

### Task 2: Flight-shape capture — message lengths + verbatim intermediates (`yip-utls`)

A function that walks the *decrypted* server flight recording per-message lengths (`EncryptedFlightShape`'s message fields) + the cert chain (`leaf_der_len` + verbatim `intermediates_der`) + the leaf DER. Reuse/extend the existing `scan_cert_flight` (4b already walks the flight to pull the leaf + CertVerify).

**Files:**
- Modify: `crates/yip-utls/src/stream.rs` (add `scan_flight_shape`)

**Interfaces:**
- Consumes: the template types (Task 1); the existing flight-walk pattern (`scan_cert_flight`, stream.rs:50+).
- Produces: `fn scan_flight_shape(hs_flight: &[u8]) -> Result<FlightShapeScan, Error>` where `FlightShapeScan { leaf_der: Vec<u8>, cert_chain: CertChainShape, ee_len: usize, cert_len: usize, cert_verify_len: usize, finished_len: usize }`.

- [ ] **Step 1: Write the failing flight-shape test**

Add to `stream.rs` tests. Build a decrypted flight = `EncryptedExtensions(0x08) ‖ Certificate(0x0b, 2 certs: leaf + intermediate) ‖ CertificateVerify(0x0f) ‖ Finished(0x14)` with known message lengths, and assert:

```rust
    #[test]
    fn scan_flight_shape_records_lengths_and_verbatim_intermediates() {
        let leaf = vec![0xAA; 40];
        let inter = vec![0xBB; 30];
        let flight = build_test_server_flight(
            /*ee_body=*/ &[0x00, 0x00],                 // empty EE
            /*certs=*/ &[leaf.clone(), inter.clone()],  // leaf + 1 intermediate
            /*cert_verify_sig_len=*/ 70,
            /*finished_len=*/ 32,
        );
        let s = scan_flight_shape(&flight).expect("scan");
        assert_eq!(s.leaf_der, leaf);
        assert_eq!(s.cert_chain.leaf_der_len, 40);
        assert_eq!(s.cert_chain.intermediates_der, vec![inter]); // verbatim
        // Per-message lengths include the 4-byte handshake header.
        assert_eq!(s.ee_len, 4 + 2);
        assert!(s.cert_len > 0 && s.cert_verify_len > 0 && s.finished_len > 0);
    }
```

Add `build_test_server_flight` (compose per-message: `type ‖ u24 len ‖ body`; the Certificate body = `cert_request_context(u8=0) ‖ u24 cert_list_len ‖ [ u24 cert_len ‖ cert_der ‖ u16 ext_len ‖ exts ]*`). Mirror TLS 1.3 Certificate wire format.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yip-utls stream::tests::scan_flight_shape`
Expected: FAIL — `cannot find function scan_flight_shape`.

- [ ] **Step 3: Implement `scan_flight_shape`**

Model it on the existing `scan_cert_flight` (stream.rs:50) — same bounded `while hs_flight.len() >= pos + 4` walk reading `msg_type` + u24 len. For each message record its total length (`4 + len`) into the right `*_len` field (EE=0x08, Cert=0x0b, CertVerify=0x0f, Finished=0x14). For the Certificate message, parse the cert_list (bounded): the FIRST cert → `leaf_der` + `leaf_der_len`; each SUBSEQUENT cert's DER → push verbatim into `intermediates_der`. Fail-closed on any truncation/overflow (reuse `.get()`/the existing bounds; respect `MAX_HANDSHAKE_MSG_LEN`). Add `HS_TYPE_ENCRYPTED_EXTENSIONS = 0x08` if not already present.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p yip-utls stream::tests::scan_flight_shape` → PASS. Then `cargo test -p yip-utls stream` (existing scan_cert_flight / verify tests green — do not alter them).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt -p yip-utls
git add crates/yip-utls/src/stream.rs
git commit -m "feat(reality.5a): scan_flight_shape — per-message lengths + verbatim intermediate DERs"
```

---

### Task 3: `capture_dest_flight` — the Chrome-faithful probe (`yip-utls`)

Tie it together: craft the hello, handshake through the server flight, capture the template (record lengths from the record read + Tasks 1/2), return after the server Finished.

**Files:**
- Modify: `crates/yip-utls/src/stream.rs` (`capture_dest_flight`)
- Modify: `crates/yip-utls/src/lib.rs` (`pub use stream::capture_dest_flight;`)

**Interfaces:**
- Consumes: `hello::craft` + the ephemeral/ML-KEM setup (as in `connect`), `parse_server_hello_shape` (Task 1), `derive_handshake_keys` + `record_open` (existing), `scan_flight_shape` (Task 2).
- Produces: `pub async fn capture_dest_flight<S: AsyncRead + AsyncWrite + Unpin>(stream: S, sni: &str) -> Result<CapturedFlight, Error>`.

- [ ] **Step 1: Write the failing capture tests**

Extend REALITY.2/4b's in-process mock-TLS-server harness in `stream.rs` (the mock that a `connect` test drives). Have the mock present a known flight (a ServerHello with a fixed extension order + a 2-cert chain + known record framing), then:

```rust
    #[tokio::test]
    async fn capture_dest_flight_records_template_from_mock() {
        // Drive capture_dest_flight against the mock; assert the returned
        // ServerFlightTemplate matches what the mock sent: cipher, ordered
        // extensions, key_share_group, record_lengths (ciphertext-payload
        // lengths), per-message lengths, leaf_der_len + verbatim intermediates.
    }
```

Plus a live gate:

```rust
    #[tokio::test]
    #[ignore] // network; run with `cargo test -p yip-utls -- --ignored`
    async fn capture_dest_flight_cloudflare() {
        let tcp = tokio::net::TcpStream::connect("cloudflare.com:443").await.unwrap();
        let cap = capture_dest_flight(tcp, "cloudflare.com").await.expect("capture");
        assert!(cap.template.server_hello.cipher_suite != 0);
        assert!(!cap.template.server_hello.extensions.is_empty());
        assert!(cap.template.cert_chain.leaf_der_len > 0);
        assert!(!cap.template.encrypted_flight.record_lengths.is_empty());
        assert!(!cap.leaf_der.is_empty());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yip-utls stream::tests::capture_dest_flight_records_template`
Expected: FAIL — `cannot find function capture_dest_flight`.

- [ ] **Step 3: Implement `capture_dest_flight`**

A focused sibling of `connect` — share the sub-helpers, do NOT touch `connect`'s body. Sequence:
1. Craft the Chrome hello with a random `legacy_session_id` (no REALITY seal — probing the real `dest`, which ignores it) and a fresh X25519 ephemeral + ML-KEM key (reuse `connect`'s exact setup; the seal/`server_reality_pub` args are simply omitted). Write it.
2. Read the server's ServerHello record; `parse_server_hello_shape` → `ServerHelloShape`; also pull the `suite` + server key_share to derive keys (reuse `parse_server_hello` for the values, or read them from the shape's `key_share` ext body).
3. Complete the ECDHE (+ ML-KEM if group 4588, exactly as `connect`) and `derive_handshake_keys`.
4. Read the encrypted records of the server flight, recording **each record's ciphertext-payload length** into `record_lengths` as you read (the length field of each record header, before `record_open`), and `record_open` each into the running `hs_flight` — until the server `Finished` (reuse `connect`'s flight-read loop / `find_finished_end`; respect `MAX_SERVER_FLIGHT_LEN`).
5. `scan_flight_shape(&hs_flight)` (Task 2) → the `EncryptedFlightShape` message lengths + `CertChainShape` + `leaf_der`.
6. Assemble `EncryptedFlightShape { record_lengths, ee_len, cert_len→certificate_len, cert_verify_len→certificate_verify_len, finished_len }` + `ServerFlightTemplate` + `CapturedFlight { leaf_der, template }`. Return. Do NOT send a client Finished or read app data.

If `connect`'s record-read loop is inline and hard to reuse without touching it, duplicate the ~15-line read loop here (this is a probe, not the hot path — a small, clearly-commented duplication is acceptable and safer than refactoring the crux `connect`). Bounded + fail-closed throughout.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p yip-utls stream::tests::capture_dest_flight_records_template` → PASS. Then `cargo test -p yip-utls` (all offline incl. JA4 diff + 4b verify tests green — `connect` untouched).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-utls --all-targets -- -D warnings
cargo fmt -p yip-utls
git add crates/yip-utls/src/stream.rs crates/yip-utls/src/lib.rs
git commit -m "feat(reality.5a): capture_dest_flight — Chrome-faithful dest server-flight probe"
```

---

### Task 4: Unify the dest probe + cache the template (`yip-rendezvous`)

Rewrite `fetch_dest_leaf` to use `capture_dest_flight`, extract `StolenFields` from the returned leaf DER, and cache the `ServerFlightTemplate` per SNI.

**Files:**
- Modify: `bin/yip-rendezvous/src/reality_cert.rs` (`fetch_dest_leaf` rewrite; `extract_fields` adapt to DER; `CacheEntry.template` + `template_for`; prewarm/refresh store it)
- Modify: `docs/configuration.md` (one line: dest probe is now Chrome-faithful + captures a flight template)

**Interfaces:**
- Consumes: `yip_utls::capture_dest_flight`, `yip_utls::ServerFlightTemplate`, `yip_utls::CapturedFlight`.
- Produces: `fetch_dest_leaf(...) -> Result<(StolenFields, ServerFlightTemplate), String>`; `RealityCertCache::template_for(sni) -> Option<Arc<ServerFlightTemplate>>`.

- [ ] **Step 1: Write the failing test**

Adapt REALITY.3's `fetch_dest_leaf` test (the one that spins a local TLS `dest` and asserts `StolenFields`) to the new signature + assert a template comes back and is cached. Add a `template_for` cache test: after `prewarm` against a local dest, `template_for(sni)` is `Some` with a non-empty `server_hello.extensions` and a `leaf_der_len > 0`.

```rust
    #[tokio::test]
    async fn prewarm_caches_server_flight_template() {
        let dest = spawn_local_dest().await; // existing REALITY.3 test helper
        let cache = RealityCertCache::prewarm(&["good.test".to_owned()], dest, /*…*/).await.unwrap();
        let t = cache.template_for("good.test").expect("template cached");
        assert!(!t.server_hello.extensions.is_empty());
        assert!(t.cert_chain.leaf_der_len > 0);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yip-rendezvous-bin reality_cert::tests::prewarm_caches_server_flight_template`
Expected: FAIL — `no method template_for` / `fetch_dest_leaf` signature mismatch.

- [ ] **Step 3: Rewrite `fetch_dest_leaf` + adapt `extract_fields` + cache the template**

- `fetch_dest_leaf`: replace the `tokio_boring::connect` body with: `TcpStream::connect(dest)` → `yip_utls::capture_dest_flight(tcp, sni)` (bounded by the existing `timeout`) → parse `captured.leaf_der` into a `boring::x509::X509` (`X509::from_der(&captured.leaf_der)`) → `extract_fields(&x509)` → return `(fields, captured.template)`.
- `extract_fields`: it takes `&X509Ref` today; keep that (build the `X509` from DER in `fetch_dest_leaf` and pass `&x509`), so `extract_fields` itself is unchanged (the AIA/DER-parse from #75 still works on the same `X509`).
- `CacheEntry`: add `template: Arc<ServerFlightTemplate>`; `prewarm`/`apply_refresh` store `Arc::new(template)` alongside `fields`. Add `pub fn template_for(&self, sni) -> Option<Arc<ServerFlightTemplate>>`, gated `#[cfg_attr(not(test), expect(dead_code, reason = "consumed by REALITY.5b"))]`. The TLS-1.3-only forged acceptor, per-SNI degrade, staleness, and 4b binding are all unchanged.

- [ ] **Step 4: Run to verify it passes + full suite**

Run: `cargo test -p yip-rendezvous-bin reality_cert` → PASS (new template test + adapted cert tests). Then full `cargo test -p yip-rendezvous-bin` (anti-replay / 4b binding / forged-acceptor tests green). The `#[ignore]`d live `fetch_real_leaf_from_cloudflare` test (REALITY.3) — update it to the new signature; it stays `#[ignore]`.

- [ ] **Step 5: Docs, clippy, fmt, commit**

Add one line to `docs/configuration.md` (the dest probe is now a Chrome-faithful yip_utls handshake that also captures a server-flight template for REALITY.5 mimicry).

```bash
cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings
cargo fmt
git add bin/yip-rendezvous/src/reality_cert.rs docs/configuration.md
git commit -m "feat(reality.5a): unify dest probe on capture_dest_flight + cache ServerFlightTemplate per SNI"
```

---

## Self-Review

**1. Spec coverage:**
- §1 template types (ServerHello structure / encrypted-flight shape incl. `record_lengths`=ciphertext / cert chain leaf-size + verbatim intermediates) → Tasks 1+2. ✓
- §1 `capture_dest_flight` (Chrome hello, parse shape, decrypt flight, record lengths, return after server Finished, no app phase) → Task 3. ✓
- §2 unify dest probe on yip_utls + cache `template_for` per SNI at prewarm/refresh; REALITY.3/4b unchanged → Task 4. ✓
- Testing (parse unit, flight-shape unit, mock capture, live cloudflare, fetch migration) → Tasks 1–4. ✓
- Read-only / `connect` untouched / JA4 green → constraint honored (Task 3 duplicates the read loop rather than refactor `connect`). ✓
- Non-goals (5b/c/d emission) — no task emits. ✓

**2. Placeholder scan:** Test helpers (`build_test_server_hello`, `key_share_ext_body`, `build_test_server_flight`) are described with their exact wire composition, not left vague; reuse existing helpers where present. No `unimplemented!`/TODO in shipped code. `template_for`'s dead-code gate is intentional (documented, consumed by 5b).

**3. Type consistency:** `ServerFlightTemplate`/`ServerHelloShape`/`EncryptedFlightShape`/`CertChainShape { leaf_der_len, intermediates_der }`/`CapturedFlight { leaf_der, template }` (Task 1) are consumed with those exact fields in `scan_flight_shape`→`FlightShapeScan` (Task 2), `capture_dest_flight` (Task 3), and `fetch_dest_leaf`/`template_for` (Task 4). `parse_server_hello_shape`/`scan_flight_shape`/`capture_dest_flight` names consistent across tasks.

**Flags for the user at handoff:**
1. **`capture_dest_flight` may duplicate `connect`'s ~15-line record-read loop** rather than refactor the crux `connect` — safer, small duplication. OK, or prefer a shared helper (touches `connect`)?
2. **`template_for` ships dead-code-gated** (consumed by 5b) — standard pattern here.
