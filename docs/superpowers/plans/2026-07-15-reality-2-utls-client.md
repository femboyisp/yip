# REALITY.2 — `yip-utls` pure-Rust uTLS client — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes.

**Goal:** A new `yip-utls` crate that crafts a byte-faithful Chrome-150 ClientHello (with our X25519 key_share + a REALITY auth seal in `legacy_session_id`) and completes a TLS 1.3 handshake to an application-data stream — a standalone, tested library, not wired into yipd.

**Architecture:** Two halves. 2a = deterministic ClientHello crafter (`hello.rs`) + JA3/JA4 computation (`ja.rs`) locked by a fixture diff test. 2b = TLS 1.3 client key schedule/record layer (`handshake.rs`, `ring`) yielding a stream (`stream.rs`), plus a shared REALITY auth codec (`auth.rs`) that interops with REALITY.1's `reality_auth_open`.

**Tech Stack:** Rust, `ring` (X25519/HKDF/AEAD/SHA-256 for the TLS handshake), `x25519-dalek` + `chacha20poly1305` + `hkdf`/`sha2` (for the REALITY auth seal — must match `yip-rendezvous`), `getrandom`, `tokio` (async stream + live test).

## Global Constraints
- `#![forbid(unsafe_code)]` on the whole crate. No bare `#[allow]` (use `#[expect(reason=)]`). No `as` numeric casts — use `to_be_bytes`/`from_be_bytes`/`try_from`.
- **Not wired into yipd** — `yip-utls` is a standalone library (REALITY.4 wires it). Never add a yipd dependency on it in this milestone.
- Auth-seal primitives MUST byte-match REALITY.1's (`x25519-dalek` + `chacha20poly1305` + HKDF-SHA256, info `b"yip-reality-v1"`, nonce `client_random[..12]`, plaintext `short_id(8) ‖ unix_minutes_le(8)`).
- Ground truth: `docs/superpowers/specs/reality-2-chrome150-fingerprint.txt` — the exact cipher/extension/group/sig-alg lists. The fidelity lock is the **JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`** (STABLE across Chrome's per-connection extension permutation). JA3 is order-sensitive and **varies per connection** in real Chrome (captures show `e229e1bc…`, `f2caf6de…`, …) — the crafter must reproduce that variation, so DO NOT pin a single JA3 hash.
- Live-network tests are `#[ignore]` so default CI stays offline.
- Wire assembly uses the `HelloWriter` helper (below), never magic slice offsets.

---

### Task 1: Crate scaffold + fixture + `HelloWriter`

**Files:**
- Create: `crates/yip-utls/Cargo.toml`, `crates/yip-utls/src/lib.rs`, `crates/yip-utls/src/wire.rs`
- Create: `crates/yip-utls/tests/fixtures/chrome150.txt` (copy of the fingerprint reference)
- Modify: root `Cargo.toml` workspace `members` (add `crates/yip-utls`)

**Interfaces (Produces):**
- `wire::HelloWriter { fn new()->Self; fn u8(&mut self,u8); fn u16(&mut self,u16); fn bytes(&mut self,&[u8]); fn u8_prefixed(&mut self, impl FnOnce(&mut Self)); fn u16_prefixed(&mut self, impl FnOnce(&mut Self)); fn into_bytes(self)->Vec<u8> }`

- [ ] **Step 1: Create the crate.** `Cargo.toml`:
```toml
[package]
name = "yip-utls"
version = "0.1.0"
edition = "2021"

[dependencies]
ring = "0.17"
x25519-dalek = "2"
chacha20poly1305 = "0.10"
hkdf = "0.12"
sha2 = "0.10"
getrandom = "0.2"
tokio = { version = "1", features = ["io-util", "net", "macros", "rt"] }

[dev-dependencies]
tokio = { version = "1", features = ["io-util", "net", "macros", "rt-multi-thread", "time"] }
```
`src/lib.rs`:
```rust
//! Pure-Rust uTLS-equivalent REALITY client (REALITY.2). Crafts a byte-faithful
//! Chrome-150 ClientHello carrying a REALITY auth seal and completes a TLS 1.3
//! handshake to an application-data stream. Standalone — not wired into yipd.
#![forbid(unsafe_code)]

pub mod wire;
```
Add `"crates/yip-utls"` to the workspace `members` in the root `Cargo.toml`.

- [ ] **Step 2: Copy the fixture.** `cp docs/superpowers/specs/reality-2-chrome150-fingerprint.txt crates/yip-utls/tests/fixtures/chrome150.txt`

- [ ] **Step 3: Write the failing `HelloWriter` test** — `src/wire.rs` `#[cfg(test)]`:
```rust
#[test]
fn u16_prefixed_backfills_length() {
    let mut w = HelloWriter::new();
    w.u16_prefixed(|w| { w.bytes(&[0xAA, 0xBB, 0xCC]); });
    assert_eq!(w.into_bytes(), vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]);
}
#[test]
fn u8_prefixed_backfills_length() {
    let mut w = HelloWriter::new();
    w.u8_prefixed(|w| { w.bytes(&[0x01, 0x02]); });
    assert_eq!(w.into_bytes(), vec![0x02, 0x01, 0x02]);
}
```

- [ ] **Step 4: Run — expect FAIL** (`HelloWriter` undefined). `cargo test -p yip-utls wire`

- [ ] **Step 5: Implement `HelloWriter`** in `src/wire.rs`:
```rust
/// A length-prefix-aware byte writer for TLS wire structures. `*_prefixed`
/// reserves the length, runs the closure, then backfills the exact body length
/// — so a length can never desync from its body.
pub struct HelloWriter { buf: Vec<u8> }
impl HelloWriter {
    pub fn new() -> Self { Self { buf: Vec::new() } }
    pub fn u8(&mut self, v: u8) { self.buf.push(v); }
    pub fn u16(&mut self, v: u16) { self.buf.extend_from_slice(&v.to_be_bytes()); }
    pub fn bytes(&mut self, b: &[u8]) { self.buf.extend_from_slice(b); }
    pub fn u16_prefixed(&mut self, f: impl FnOnce(&mut Self)) {
        let at = self.buf.len();
        self.u16(0);
        f(self);
        let len = u16::try_from(self.buf.len() - at - 2).expect("section fits u16");
        self.buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
    }
    pub fn u8_prefixed(&mut self, f: impl FnOnce(&mut Self)) {
        let at = self.buf.len();
        self.u8(0);
        f(self);
        let len = u8::try_from(self.buf.len() - at - 1).expect("section fits u8");
        self.buf[at] = len;
    }
    pub fn into_bytes(self) -> Vec<u8> { self.buf }
}
impl Default for HelloWriter { fn default() -> Self { Self::new() } }
```

- [ ] **Step 6: Run — expect PASS.** `cargo test -p yip-utls wire` + `cargo clippy -p yip-utls --all-targets -- -D warnings`

- [ ] **Step 7: Commit.** `git add crates/yip-utls Cargo.toml && git commit -m "feat(yip-utls): crate scaffold + HelloWriter + Chrome-150 fixture (REALITY.2 Task 1)"`

---

### Task 2: `ja.rs` — JA3/JA4 from a ClientHello

**Files:** Create `crates/yip-utls/src/ja.rs`; add `pub mod ja;` to `lib.rs`.

**Interfaces (Produces):**
- `ja::ja3(hello_msg: &[u8]) -> Option<String>` — the JA3 decimal string (not hashed): `version,ciphers,extensions,groups,ecpfmts`, GREASE values FILTERED OUT (JA3 excludes GREASE).
- `ja::ja3_hash(hello_msg: &[u8]) -> Option<String>` — MD5 hex of the JA3 string. (Add `md-5 = "0.10"` to deps.)
- `ja::ja4(hello_msg: &[u8]) -> Option<String>` — the JA4 `t13d<nn><ee>h2_<sha>_<sha>` string (TLS1.3, cipher count, ext count, ALPN, sorted-cipher sha256[..12], sorted-ext+sigalg sha256[..12]).

**Interfaces (Consumes):** parses the ClientHello handshake message (same layout REALITY.1's `parse_client_hello` walks).

- [ ] **Step 1: Failing test** — `ja.rs` `#[cfg(test)]`. Build a small synthetic ClientHello (reuse a helper you write, or a hard-coded byte const) with a KNOWN cipher/ext/group set and assert `ja3(...)` equals the hand-computed decimal string and `ja3_hash` its md5. (Full Chrome-150 match is Task 4; here prove the algorithm on a tiny known input.)
```rust
#[test]
fn ja3_of_known_hello_matches() {
    // hello with version 0x0303, ciphers [0x1301], exts [0,43], groups [29], ecpf [0]
    let hello = tiny_hello();               // helper builds the bytes
    assert_eq!(ja::ja3(&hello).unwrap(), "771,4865,0-43,29,0");
}
```

- [ ] **Step 2: Run — expect FAIL.** `cargo test -p yip-utls ja`

- [ ] **Step 3: Implement `ja3`/`ja3_hash`/`ja4`.** Parse the ClientHello (version, cipher list, extension type list in wire order, supported_groups from ext 10, ec_point_formats from ext 11). **Filter GREASE** (values where `(v & 0x0f0f) == 0x0a0a`) from every list. JA3 = `format!("{ver},{ciphers-},{exts-},{groups-},{ecpf-}")` joining with `-`. `ja3_hash` = md5 hex. JA4: `t` + `13` (TLS1.3 from supported_versions) + `d` (SNI present) + 2-digit cipher count + 2-digit ext count + first-ALPN 2 chars; then `_` + hex(sha256(sorted-comma-joined-ciphers))[..12] + `_` + hex(sha256(sorted-exts (excluding SNI+ALPN) then sig-algs))[..12]. Follow the JA4 spec exactly; the fixture's `ja4_r` is the authoritative field list to match against in Task 4.

- [ ] **Step 4: Run — expect PASS.** `cargo test -p yip-utls ja` + clippy.

- [ ] **Step 5: Commit.** `git commit -m "feat(yip-utls): JA3/JA4 computation over a ClientHello (REALITY.2 Task 2)"`

---

### Task 3: `hello.rs` — deterministic Chrome-150 crafter

**Files:** Create `crates/yip-utls/src/hello.rs`; `pub mod hello;` in `lib.rs`.

**Interfaces (Consumes):** `wire::HelloWriter`.
**Interfaces (Produces):**
- `hello::Rng` = `trait RandomSource { fn fill(&mut self, buf: &mut [u8]); }` (a seeded impl for tests; an OS impl for prod).
- `hello::ClientHelloParams { pub sni: String, pub key_share_x25519_pub: [u8;32], pub legacy_session_id: [u8;32] }`
- `hello::craft(params: &ClientHelloParams, rng: &mut dyn RandomSource) -> Vec<u8>` — returns the **handshake message** bytes (`0x01 ‖ u24 len ‖ body`) of a byte-faithful Chrome-150 ClientHello. GREASE values, MLKEM768(1216B) + ECH data, are drawn from `rng`.

- [ ] **Step 1: Failing test** — `hello.rs`: craft with a fixed-seed rng + fixed params, assert the result parses and has: version `0x0303`, a 32-byte `legacy_session_id` == params, cipher list == the fixture's 16 (with GREASE), extension types in the fixture's exact order, supported_groups == `[GREASE,4588,29,23,24]`, three key_share entries (GREASE 1B, 4588 1216B, 29 = our 32B pub). Write assertions that walk the bytes.

- [ ] **Step 2: Run — expect FAIL.** `cargo test -p yip-utls hello`

- [ ] **Step 3: Implement `craft`.** Using `HelloWriter`, emit: `legacy_version 0x0303`; `random(32)` from rng; `session_id` = params.legacy_session_id (u8_prefixed, 32); cipher_suites (u16_prefixed: GREASE(drawn), then FIXED `1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035`); compression `01 00`; then the extensions block (u16_prefixed).
  **EXTENSION ORDER — PERMUTE PER CONNECTION (critical; see the fingerprint reference "SECOND/THIRD CAPTURE" notes):** modern Chrome/BoringSSL shuffles its extension order every connection, keeping ONE GREASE first and ONE GREASE last; a *fixed* order would make us MORE fingerprintable than real Chrome (its JA3 varies each connection; ours must too). So: emit **GREASE first**, then these **16 real extensions in a per-connection order produced by a Fisher–Yates shuffle seeded from `rng`**, then **GREASE last**. Each extension's own content is FIXED; only their relative order varies. The 16 real extensions (build each as an `(id, body)` then shuffle the list):
  sct(18, empty), ALPS(17613, `h2`), supported_groups(10: GREASE,4588,29,23,24), ec_point_formats(11: `00`), psk_key_exchange_modes(45: `01 01`), server_name(0, params.sni), ECH(65037: right-shaped random from rng), session_ticket(35, empty), signature_algorithms(13: `0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601` — the Chrome-150 list, 11 entries incl. the 3 PQ ML-DSA algs), ALPN(16: `h2`,`http/1.1`), compress_certificate(27: brotli `0002`), supported_versions(43: GREASE,`0304`,`0303`), renegotiation_info(65281: `00`), extended_master_secret(23, empty), status_request(5: `01 0000 0000`), key_share(51: GREASE(1B rng), 4588 = 1216B rng, 29 = params.key_share_x25519_pub).
  Draw the GREASE 16-bit values from rng and build them as `0x?a?a` with equal bytes (one random nibble `n` → byte `(n<<4)|0x0a`, used for both bytes). Wrap the body as the handshake message (`0x01 ‖ u24 ‖ body`). **NOTE:** shuffle is deterministic given the seed (so Task 4's byte-exact assertions hold), but produces a DIFFERENT order for different seeds.
   - GREASE construction detail: a GREASE value is `0x?a?a` where both nibble-pairs equal (e.g. `0x1a1a`, `0xdada`). Generate one random nibble `n`, value = `((n<<4)|0x0a)` repeated in both bytes.

- [ ] **Step 4: Run — expect PASS.** `cargo test -p yip-utls hello` + clippy.

- [ ] **Step 5: Commit.** `git commit -m "feat(yip-utls): deterministic Chrome-150 ClientHello crafter (REALITY.2 Task 3, 2a)"`

---

### Task 4: JA3/JA4 fixture diff test (the anti-fingerprint guard)

**Files:** Create `crates/yip-utls/tests/ja_diff.rs`.

**Interfaces (Consumes):** `hello::craft`, `ja::{ja3_hash, ja4}`.

- [ ] **Step 1: Write the test.**
```rust
// tests/ja_diff.rs
use yip_utls::{hello, ja};
struct Seed(u64);
impl hello::RandomSource for Seed {
    fn fill(&mut self, b: &mut [u8]) { for x in b { self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1); *x = (self.0 >> 33) as u8; } }
}
#[test]
fn crafted_hello_matches_chrome150_ja4_and_permutes_ja3() {
    let params = hello::ClientHelloParams {
        sni: "www.apple.com".into(),
        key_share_x25519_pub: [0x11; 32],
        legacy_session_id: [0x22; 32],
    };
    // JA4 is STABLE across Chrome's per-connection extension permutation — lock it.
    let m1 = hello::craft(&params, &mut Seed(1));
    let m2 = hello::craft(&params, &mut Seed(2));
    assert_eq!(ja::ja4(&m1).unwrap(), "t13d1516h2_8daaf6152771_806a8c22fdea");
    assert_eq!(ja::ja4(&m2).unwrap(), "t13d1516h2_8daaf6152771_806a8c22fdea");
    // JA3 is order-sensitive; real Chrome's varies every connection, so ours MUST too
    // (a fixed JA3 is MORE fingerprintable than real Chrome — defeats the purpose).
    assert_ne!(
        ja::ja3_hash(&m1).unwrap(),
        ja::ja3_hash(&m2).unwrap(),
        "extension order must permute per connection like real Chrome"
    );
    // Same seed is reproducible (deterministic shuffle) — for byte-exact debugging.
    let m1b = hello::craft(&params, &mut Seed(1));
    assert_eq!(m1, m1b);
}
```
(The `as u8` in the test PRNG is acceptable in test-only code; if clippy objects, use `u8::try_from(self.0 & 0xff).unwrap()`. Note: the assertion is on **JA4** (stable) + **JA3 varies** — NOT a fixed JA3 hash, per the fingerprint reference's permutation finding.)

- [ ] **Step 2: Run — expect FAIL** (JA3/JA4 mismatch → iterate `hello.rs` field order/ID lists against the fixture until it matches). This is the fidelity-proving loop.

- [ ] **Step 3: Iterate `hello.rs` to green.** Any mismatch means a cipher/extension/group/order drift vs the fixture — fix it. Do NOT change the assertion.

- [ ] **Step 4: Run — expect PASS.** `cargo test -p yip-utls --test ja_diff`

- [ ] **Step 5: Commit.** `git commit -m "test(yip-utls): JA3/JA4 diff lock crafted hello == real Chrome 150 (REALITY.2 Task 4, 2a)"`

---

### Task 5: `auth.rs` — shared REALITY auth codec (client seal + server open)

**Files:** Create `crates/yip-utls/src/auth.rs`; `pub mod auth;` in `lib.rs`. Modify `bin/yip-rendezvous/Cargo.toml` (add `yip-utls = { path = "../../crates/yip-utls" }`), `bin/yip-rendezvous/src/reality.rs` (replace its local seal/open bodies with calls to `yip_utls::auth`).

**Interfaces (Produces):**
- `auth::seal(server_reality_pub: &[u8;32], eph_priv: &[u8;32], client_random: &[u8;32], short_id: [u8;8], ts_min: u64) -> [u8;32]`
- `auth::open(reality_priv: &[u8;32], eph_pub: &[u8;32], client_random: &[u8;32], session_id: &[u8], short_ids: &[[u8;8]], now_min: u64, skew_min: u64) -> bool`

- [ ] **Step 1: Failing test** — `auth.rs`: `seal` then `open` round-trips (matching keys/short_id/fresh ts → true); wrong key/unknown short_id/stale/tampered → false. Port the exact scheme from `bin/yip-rendezvous/src/reality.rs` (x25519-dalek `StaticSecret`/`PublicKey`, HKDF-SHA256 salt `b""` info `b"yip-reality-v1"` len 32, ChaCha20-Poly1305 nonce `client_random[..12]`, plaintext `short_id ‖ ts_min.to_le_bytes()`, `abs_diff` skew).

- [ ] **Step 2: Run — expect FAIL.** `cargo test -p yip-utls auth`

- [ ] **Step 3: Implement `seal`/`open`** by moving the logic out of `reality.rs`.

- [ ] **Step 4: Repoint `yip-rendezvous`.** In `reality.rs`, make `reality_auth_open` call `yip_utls::auth::open(...)` (extracting `eph_pub` from `info.key_share_x25519`), and delete the `#[cfg(test)] reality_seal` in favor of `yip_utls::auth::seal`. Keep `parse_client_hello` as-is.

- [ ] **Step 5: Run — both crates green.** `cargo test -p yip-utls auth && cargo test -p yip-rendezvous-bin reality` + clippy both. Add an **interop test** in `yip-utls/tests/interop.rs`: a `seal` → hand-build a ClientHello via `hello::craft` with that seal as `legacy_session_id` and the matching eph pub → `yip_rendezvous`? (yip-utls can't dep on the bin). Instead assert `auth::open` accepts `auth::seal` output (same crate) AND add the reciprocal assertion inside `yip-rendezvous`'s reality tests (seal via `yip_utls::auth::seal`, open via `reality_auth_open`).

- [ ] **Step 6: Commit.** `git commit -m "feat(yip-utls): shared REALITY auth codec; yip-rendezvous consumes it (REALITY.2 Task 5, 2b)"`

---

### Task 6: `handshake.rs` — TLS 1.3 client key schedule + record layer

**Files:** Create `crates/yip-utls/src/handshake.rs`; `mod handshake;` in `lib.rs`.

**Interfaces (Produces):**
- `handshake::ServerHelloInfo { suite: u16, server_key_share: [u8;32] }`
- `handshake::parse_server_hello(record_payload: &[u8]) -> Result<ServerHelloInfo, Error>`
- `handshake::KeySchedule` with `derive(ecdhe: &[u8], transcript_hash: &[u8], suite: u16) -> HandshakeKeys` and record seal/open (nonce = iv XOR seq, AAD = record header) — reuse the spike's exact RFC 8446 logic (`hkdf_extract`/`hkdf_expand_label`/`derive_secret`, `ring::hkdf`/`hmac`, `ring::aead::{AES_128_GCM, CHACHA20_POLY1305}`, `ring::digest::SHA256`, `ring::agreement::X25519`).

- [ ] **Step 1: Failing test** — offline KAT: feed a captured ServerHello + known ECDHE and assert the derived server-handshake key/iv match precomputed values (compute the expected via a tiny openssl-derived vector, or assert the key schedule against RFC 8446 test vectors from Appendix — use the published RFC 8446 traffic-secret test vector). At minimum: `parse_server_hello` extracts suite + x25519 share from a hand-built ServerHello.

- [ ] **Step 2: Run — expect FAIL.** `cargo test -p yip-utls handshake`

- [ ] **Step 3: Implement** the ServerHello parser + key schedule + record open/seal, lifting the spike's verified code (which decrypted real Cloudflare EncryptedExtensions). TLS 1.3 only; X25519; suites `0x1301`(AES-128-GCM) + `0x1303`(ChaCha20). Fail-closed on any parse error.

- [ ] **Step 4: Run — expect PASS.** `cargo test -p yip-utls handshake` + clippy.

- [ ] **Step 5: Commit.** `git commit -m "feat(yip-utls): TLS 1.3 client key schedule + record layer (REALITY.2 Task 6, 2b)"`

---

### Task 7: `stream.rs` + `connect()` — app-data stream + public entry

**Files:** Create `crates/yip-utls/src/stream.rs`; `pub use` the entry in `lib.rs`. Create `crates/yip-utls/src/error.rs` (`pub enum Error`).

**Interfaces (Consumes):** `hello`, `handshake`, `auth`. **Produces:**
- `pub async fn connect<S: AsyncRead+AsyncWrite+Unpin>(stream: S, sni: &str, server_reality_pub: &[u8;32], short_id: [u8;8]) -> Result<RealityStream<S>, Error>`
- `RealityStream<S>` impl `AsyncRead + AsyncWrite` over the negotiated application-data keys (record framing, seq counters both directions, key update NOT required for MVP).

- [ ] **Step 1: Failing test** — an in-process test using `tokio::io::duplex` with a *mock* server that: reads the ClientHello, replies a canned ServerHello + encrypted flight computed with the same key schedule (or simpler: a loopback test that just drives `connect` far enough to send the ClientHello and assert its bytes match `hello::craft`). The full round is covered by the live test (Task 8); here assert `connect` emits the crafted hello and reaches the ServerHello-parse step.

- [ ] **Step 2: Run — expect FAIL.** `cargo test -p yip-utls stream`

- [ ] **Step 3: Implement** `connect` (generate eph X25519 via `ring::agreement`, but ALSO need the raw pub for the hello + the ECDHE — use `ring::agreement::EphemeralPrivateKey` + `compute_public_key`; seal via `auth::seal(server_reality_pub, ...)` — NOTE the auth ECDH is `x25519-dalek` on the SAME eph key, so generate the eph key as raw 32 bytes with `getrandom`, derive the x25519 pub with `x25519-dalek` for BOTH the key_share and the handshake ECDHE to keep one key; then do the TLS ECDHE with `x25519-dalek` too rather than ring::agreement, so the private is reusable). Assemble hello → send → read ServerHello → key schedule → read/decrypt server flight → send client Finished → build `RealityStream`.

- [ ] **Step 4: Run — expect PASS.** `cargo test -p yip-utls stream` + clippy.

- [ ] **Step 5: Commit.** `git commit -m "feat(yip-utls): connect() + RealityStream app-data stream (REALITY.2 Task 7, 2b)"`

---

### Task 8: live handshake test — full HTTP GET

**Files:** Create `crates/yip-utls/tests/handshake_live.rs`.

- [ ] **Step 1: Write the `#[ignore]` test.**
```rust
#[tokio::test]
#[ignore] // network; run with `cargo test -p yip-utls -- --ignored`
async fn handshake_and_http_get_cloudflare() {
    let tcp = tokio::net::TcpStream::connect("cloudflare.com:443").await.unwrap();
    // a random reality pub/short_id — the auth just won't validate at a real site,
    // but the TLS handshake (zero-cert-auth) completes; we only prove RFC 8446 compliance.
    let mut s = yip_utls::connect(tcp, "cloudflare.com", &[0u8;32], [0u8;8]).await.unwrap();
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    s.write_all(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = s.read(&mut buf).await.unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 "), "expected HTTP response, got {:?}", &buf[..n.min(64)]);
}
```

- [ ] **Step 2: Run it locally** (network): `cargo test -p yip-utls -- --ignored`. Expect an HTTP status line. (If a real site rejects the hello, iterate; `openssl s_server` is the fallback controlled endpoint — add a second test spawning `openssl s_server -tls1_3` and GETting it.)

- [ ] **Step 3: Commit.** `git commit -m "test(yip-utls): live TLS 1.3 handshake + HTTP GET (REALITY.2 Task 8, 2b)"`

---

### Task 9: no-regression + docs + CHANGELOG

**Files:** Modify `CHANGELOG.md`; verify workspace.

- [ ] **Step 1: Full workspace green.** `cargo test --workspace` (yip-rendezvous still passes with the extracted auth codec), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`.
- [ ] **Step 2: Coverage sanity.** yip-utls is a new logic crate — confirm it isn't accidentally excluded, and its unit tests give it ≥90% (the CI coverage cmd excludes only `yipd`/`yip-device`). Add unit tests for any uncovered `Error`/parse arms.
- [ ] **Step 3: CHANGELOG** `### Added`: "REALITY.2 (anti-DPI): new `yip-utls` crate — pure-Rust Chrome-150-faithful ClientHello crafter + TLS 1.3 client + shared REALITY auth codec, JA3/JA4-locked to real Chrome. Standalone; wired into yipd in REALITY.4."
- [ ] **Step 4: Commit.** `git commit -m "docs(yip-utls): CHANGELOG + no-regression (REALITY.2 Task 9)"`

## Self-Review
- **Spec coverage:** crate scaffold (T1) ✓, JA3/JA4 (T2) ✓, crafter (T3) ✓, diff guard (T4) ✓, shared auth codec + interop (T5) ✓, TLS 1.3 handshake (T6) ✓, connect/stream (T7) ✓, live HTTP GET (T8) ✓, no-regression/docs (T9) ✓. Deterministic crafter (T3 `RandomSource`) ✓. Not-wired-into-yipd honored ✓.
- **Key sequencing risk:** T7 needs ONE ephemeral key used for BOTH the auth seal (`x25519-dalek`) and the TLS ECDHE — the plan pins generating it as raw 32 bytes and using `x25519-dalek` for both to avoid a ring/dalek key mismatch. Flagged in T7 Step 3.
- **Type consistency:** `craft`→`Vec<u8>` (handshake msg) consumed by `ja::*` and `connect`; `auth::seal`→`[u8;32]` used as `legacy_session_id`. Consistent.
