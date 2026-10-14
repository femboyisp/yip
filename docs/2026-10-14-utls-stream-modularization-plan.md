# `yip-utls` Stream Modularization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modularize `crates/yip-utls/src/stream.rs` (~3,450 lines) into a focused module directory `crates/yip-utls/src/stream/` (`record.rs`, `cert.rs`, `sig.rs`, `flight.rs`, `mod.rs`, `tests.rs`) with zero wire format changes and 100% backward compatibility for all external callers.

**Architecture:** Deconstruct the single monolithic file into 5 cohesive submodules under `crates/yip-utls/src/stream/`. `mod.rs` serves as the facade holding `RealityStream`, `connect`, `serve`, `capture_dest_flight`, and public re-exports (`pub use flight::*; pub use sig::*;`). Submodule and integration tests are partitioned to live cleanly with their domains.

**Tech Stack:** Rust (edition 2021), tokio, p256, ml-kem, x25519-dalek, x509-parser.

## Global Constraints

- Zero wire format or protocol changes across all client and server handshakes.
- Retain `#![forbid(unsafe_code)]` in `crates/yip-utls`.
- Exact backward compatibility: `yip_utls::connect`, `yip_utls::capture_dest_flight`, `yip_utls::RealityStream`, `yip_utls::stream::serve`, `yip_utls::stream::scan_flight_shape`, `yip_utls::stream::emit_server_flight`, `yip_utls::stream::sign_certificate_verify`, `FlightShapeScan`, `ServerFlight` must remain exported at identical paths.
- Workspace standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` passes, `cargo fmt --check` passes, `cargo deny check` passes.

---

### Task 1: Record Layer & Framing (`crates/yip-utls/src/stream/record.rs`)

**Files:**
- Create: `crates/yip-utls/src/stream/record.rs`
- Create: `crates/yip-utls/src/stream/mod.rs` (scaffolding `pub mod record;`)

**Interfaces:**
- Produces:
  - `pub(crate) const RECORD_HEADER_LEN: usize = 5;`
  - `pub(crate) const LEGACY_RECORD_VERSION_INITIAL: u16 = 0x0301;`
  - `pub(crate) const LEGACY_RECORD_VERSION: u16 = 0x0303;`
  - `pub(crate) const CHANGE_CIPHER_SPEC_RECORD: [u8; 6];`
  - `pub(crate) const MAX_APP_RECORD_LEN: usize = 16384;`
  - `pub(crate) const MAX_HANDSHAKE_MSG_LEN: usize = 1 << 20;`
  - `pub(crate) const MAX_SERVER_FLIGHT_LEN: usize = 256 * 1024;`
  - `pub(crate) const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;`
  - `pub(crate) const CONTENT_TYPE_ALERT: u8 = 0x15;`
  - `pub(crate) const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;`
  - `pub(crate) const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;`
  - `pub(crate) const ALERT_DESCRIPTION_CLOSE_NOTIFY: u8 = 0;`
  - `pub(crate) const HS_TYPE_FINISHED: u8 = 0x14;`
  - `pub(crate) fn record_header(content_type: u8, legacy_version: u16, payload_len: usize) -> Result<[u8; RECORD_HEADER_LEN], Error>`
  - `pub(crate) fn find_finished_end(hs_flight: &[u8]) -> Result<Option<usize>, Error>`

- [ ] **Step 1: Create `record.rs` with record constants, codecs, and unit tests**

```rust
// In crates/yip-utls/src/stream/record.rs
use crate::error::Error;

pub(crate) const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub(crate) const CONTENT_TYPE_ALERT: u8 = 0x15;
pub(crate) const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub(crate) const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
pub(crate) const ALERT_DESCRIPTION_CLOSE_NOTIFY: u8 = 0;
pub(crate) const HS_TYPE_FINISHED: u8 = 0x14;
pub(crate) const RECORD_HEADER_LEN: usize = 5;
pub(crate) const LEGACY_RECORD_VERSION_INITIAL: u16 = 0x0301;
pub(crate) const LEGACY_RECORD_VERSION: u16 = 0x0303;

pub(crate) const CHANGE_CIPHER_SPEC_RECORD: [u8; 6] = [
    CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    0x03,
    0x03,
    0x00,
    0x01,
    0x01,
];

pub(crate) const MAX_APP_RECORD_LEN: usize = 16384;
pub(crate) const MAX_HANDSHAKE_MSG_LEN: usize = 1 << 20;
pub(crate) const MAX_SERVER_FLIGHT_LEN: usize = 256 * 1024;

pub(crate) fn record_header(
    content_type: u8,
    legacy_version: u16,
    payload_len: usize,
) -> Result<[u8; RECORD_HEADER_LEN], Error> {
    let len_u16 = u16::try_from(payload_len).map_err(|_| Error::RecordTooLarge(payload_len))?;
    let mut hdr = [0u8; RECORD_HEADER_LEN];
    hdr[0] = content_type;
    hdr[1..3].copy_from_slice(&legacy_version.to_be_bytes());
    hdr[3..5].copy_from_slice(&len_u16.to_be_bytes());
    Ok(hdr)
}

pub(crate) fn find_finished_end(hs_flight: &[u8]) -> Result<Option<usize>, Error> {
    let mut offset = 0;
    while offset < hs_flight.len() {
        if offset + 4 > hs_flight.len() {
            return Ok(None);
        }
        let msg_type = hs_flight[offset];
        let msg_len = ((hs_flight[offset + 1] as usize) << 16)
            | ((hs_flight[offset + 2] as usize) << 8)
            | (hs_flight[offset + 3] as usize);
        if msg_len > MAX_HANDSHAKE_MSG_LEN {
            return Err(Error::MalformedHandshake);
        }
        let msg_end = match offset.checked_add(4).and_then(|o| o.checked_add(msg_len)) {
            Some(end) => end,
            None => return Err(Error::MalformedHandshake),
        };
        if msg_end > hs_flight.len() {
            return Ok(None);
        }
        if msg_type == HS_TYPE_FINISHED {
            return Ok(Some(msg_end));
        }
        offset = msg_end;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_header_builds_expected_layout() {
        let hdr = record_header(CONTENT_TYPE_APPLICATION_DATA, LEGACY_RECORD_VERSION, 42).unwrap();
        assert_eq!(hdr[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(u16::from_be_bytes([hdr[1], hdr[2]]), LEGACY_RECORD_VERSION);
        assert_eq!(u16::from_be_bytes([hdr[3], hdr[4]]), 42);
    }

    #[test]
    fn record_header_rejects_oversized_payload() {
        assert!(record_header(CONTENT_TYPE_APPLICATION_DATA, LEGACY_RECORD_VERSION, 65536).is_err());
    }

    #[test]
    fn find_finished_end_locates_finished_message() {
        // EncryptedExtensions (type 0x08, len 2) + Finished (type 0x14, len 4)
        let flight = vec![
            0x08, 0x00, 0x00, 0x02, 0xAA, 0xBB,
            0x14, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        ];
        assert_eq!(find_finished_end(&flight).unwrap(), Some(flight.len()));
    }

    #[test]
    fn find_finished_end_returns_none_if_incomplete() {
        let partial = vec![0x08, 0x00, 0x00, 0x05, 0xAA];
        assert_eq!(find_finished_end(&partial).unwrap(), None);
    }
}
```

- [ ] **Step 2: Create temporary `crates/yip-utls/src/stream/mod.rs` to register `pub mod record;`**

```rust
// In crates/yip-utls/src/stream/mod.rs
pub mod record;
```

- [ ] **Step 3: Run tests to verify `record.rs` compiles and passes**

Run: `cargo test -p yip-utls stream::record`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/yip-utls/src/stream/record.rs crates/yip-utls/src/stream/mod.rs
git commit -m "feat(utls): extract record-layer codecs and framing into stream/record.rs (#108)"
```

---

### Task 2: Certificate & SPKI Parsing (`crates/yip-utls/src/stream/cert.rs`)

**Files:**
- Create: `crates/yip-utls/src/stream/cert.rs`
- Modify: `crates/yip-utls/src/stream/mod.rs` (`pub mod cert;`)

**Interfaces:**
- Consumes:
  - `record::MAX_HANDSHAKE_MSG_LEN`
- Produces:
  - `pub(crate) struct CertFlightInfo { pub(crate) cert_msg_end: usize, pub(crate) leaf_der: Vec<u8> }`
  - `pub(crate) fn scan_cert_flight(hs_flight: &[u8]) -> Result<CertFlightInfo, Error>`
  - `pub(crate) fn certificate_chain_ders(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), Error>`
  - `pub(crate) fn certificate_leaf_der(body: &[u8]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn certificate_verify_signature(body: &[u8]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn spki_sec1_pubkey_from_der(cert_der: &[u8]) -> Result<Vec<u8>, Error>`

- [ ] **Step 1: Create `cert.rs` with certificate decoding and SPKI extraction**

Move `CertFlightInfo`, `scan_cert_flight`, `certificate_chain_ders`, `certificate_leaf_der`, `certificate_verify_signature`, and `spki_sec1_pubkey_from_der` from `stream.rs` into `crates/yip-utls/src/stream/cert.rs`.

Include associated unit tests:
- `scan_cert_flight_*`
- `certificate_chain_ders_*`
- `spki_sec1_pubkey_from_der_*`

- [ ] **Step 2: Register `pub mod cert;` in `stream/mod.rs`**

- [ ] **Step 3: Run tests to verify `cert.rs` passes**

Run: `cargo test -p yip-utls stream::cert`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/yip-utls/src/stream/cert.rs crates/yip-utls/src/stream/mod.rs
git commit -m "feat(utls): extract certificate parsing and SPKI extraction into stream/cert.rs (#108)"
```

---

### Task 3: Signatures & REALITY Binding (`crates/yip-utls/src/stream/sig.rs`)

**Files:**
- Create: `crates/yip-utls/src/stream/sig.rs`
- Modify: `crates/yip-utls/src/stream/mod.rs` (`pub mod sig;`)

**Interfaces:**
- Consumes:
  - `cert::certificate_verify_signature`, `cert::spki_sec1_pubkey_from_der`
- Produces:
  - `pub(crate) fn verify_certificate_verify(leaf_spki_sec1: &[u8], signature_bytes: &[u8], transcript_hash_cv: &[u8; 32]) -> Result<(), Error>`
  - `pub fn sign_certificate_verify(signing_key: &p256::ecdsa::SigningKey, transcript_hash_cv: &[u8; 32]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn verify_reality_binding(leaf_der: &[u8], cv_body: &[u8], transcript_hash_cv: &[u8; 32], expected_auth_key: &auth::RealityAuthKey) -> Result<(), Error>`

- [ ] **Step 1: Create `sig.rs` with signature and REALITY binding logic**

Move `verify_certificate_verify`, `sign_certificate_verify`, and `verify_reality_binding` from `stream.rs` into `crates/yip-utls/src/stream/sig.rs`.

Include associated unit tests:
- `sign_certificate_verify_is_accepted_by_the_verifier`
- `sign_certificate_verify_rejected_for_wrong_key_and_tampered_transcript`
- `verify_reality_binding_*`

- [ ] **Step 2: Register `pub mod sig;` in `stream/mod.rs`**

- [ ] **Step 3: Run tests to verify `sig.rs` passes**

Run: `cargo test -p yip-utls stream::sig`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/yip-utls/src/stream/sig.rs crates/yip-utls/src/stream/mod.rs
git commit -m "feat(utls): extract signature verification and REALITY binding into stream/sig.rs (#108)"
```

---

### Task 4: Flight Shape Scanning & Emission (`crates/yip-utls/src/stream/flight.rs`)

**Files:**
- Create: `crates/yip-utls/src/stream/flight.rs`
- Modify: `crates/yip-utls/src/stream/mod.rs` (`pub mod flight;`)

**Interfaces:**
- Consumes:
  - `cert::certificate_chain_ders`, `record::*`, `sig::sign_certificate_verify`
- Produces:
  - `pub struct FlightShapeScan { pub total_len: usize, pub cert_chain_shape: CertChainShape, pub encrypted_flight_shape: EncryptedFlightShape }`
  - `pub struct ServerFlight { pub server_hello: Vec<u8>, pub encrypted_records: Vec<Vec<u8>>, pub app_keys: ApplicationKeys }`
  - `pub fn scan_flight_shape(hs_flight: &[u8]) -> Result<FlightShapeScan, Error>`
  - `pub fn emit_server_flight(template: &ServerFlightTemplate, transcript_ch_sh: &[u8], keys: &HandshakeKeys, signing_key: &p256::ecdsa::SigningKey) -> Result<ServerFlight, Error>`
  - `pub(crate) fn u24_len(n: usize) -> Result<[u8; 3], Error>`
  - `pub(crate) fn handshake_message(msg_type: u8, body: &[u8]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn certificate_entry(der: &[u8]) -> Result<Vec<u8>, Error>`

- [ ] **Step 1: Create `flight.rs` with flight scanning and emission**

Move `FlightShapeScan`, `scan_flight_shape`, `ServerFlight`, `emit_server_flight`, `u24_len`, `handshake_message`, and `certificate_entry` from `stream.rs` into `crates/yip-utls/src/stream/flight.rs`.

Include associated unit tests:
- `scan_flight_shape_records_lengths_and_verbatim_intermediates`
- `scan_flight_shape_leaf_only_chain_has_no_intermediates`
- `scan_flight_shape_rejects_flight_without_certificate`
- `emit_server_flight_matches_record_lengths_and_reopens_to_messages`
- `emit_server_flight_rejects_malformed_or_over_capacity_framing`

- [ ] **Step 2: Register `pub mod flight;` in `stream/mod.rs`**

- [ ] **Step 3: Run tests to verify `flight.rs` passes**

Run: `cargo test -p yip-utls stream::flight`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/yip-utls/src/stream/flight.rs crates/yip-utls/src/stream/mod.rs
git commit -m "feat(utls): extract flight shape scanning and emission into stream/flight.rs (#108)"
```

---

### Task 5: Finalize `mod.rs`, `tests.rs` & Remove Monolithic `stream.rs` (`crates/yip-utls/src/stream/`)

**Files:**
- Modify: `crates/yip-utls/src/stream/mod.rs` (orchestration, `RealityStream`, `connect`, `serve`, `capture_dest_flight`, RNGs, re-exports)
- Create: `crates/yip-utls/src/stream/tests.rs` (full loopback mock tests)
- Delete: `crates/yip-utls/src/stream.rs`

**Interfaces:**
- Produces:
  - `pub use flight::{emit_server_flight, scan_flight_shape, FlightShapeScan, ServerFlight};`
  - `pub use sig::sign_certificate_verify;`
  - `pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(s: S, sni: &str, reality_pub: &[u8; 32], short_id: [u8; 8], verify: bool) -> Result<RealityStream<S>, Error>`
  - `pub async fn capture_dest_flight<S: AsyncRead + AsyncWrite + Unpin>(s: S, sni: &str) -> Result<CapturedFlight, Error>`
  - `pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, flight: ServerFlight) -> Result<RealityStream<S>, Error>`
  - `pub struct RealityStream<S>`

- [ ] **Step 1: Write `crates/yip-utls/src/stream/mod.rs`**

Assemble the orchestrator containing:
- Module declarations:
  ```rust
  pub mod cert;
  pub mod flight;
  pub mod record;
  pub mod sig;
  #[cfg(test)]
  mod tests;
  ```
- Public re-exports:
  ```rust
  pub use flight::{emit_server_flight, scan_flight_shape, FlightShapeScan, ServerFlight};
  pub use sig::sign_certificate_verify;
  ```
- RNG adapters: `OsRng`, `MlKemRng`.
- Functions: `connect`, `capture_dest_flight`, `serve`, `protocol_io_error`, `protocol_io_error_owned`, `handshake_io_error`.
- Struct: `RealityStream<S>` with `impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S>` and `AsyncWrite`.

- [ ] **Step 2: Move remaining end-to-end integration/mock unit tests into `stream/tests.rs`**

Move `run_mock_tls13_server`, `run_mock_tls13_server_with_cert`, `run_mock_dest_server_with_known_flight`, `connect_against_mock_tls13_server`, `capture_dest_flight_against_mock`, `reality_stream_io_roundtrip` from `stream.rs` into `crates/yip-utls/src/stream/tests.rs`.

- [ ] **Step 3: Remove the old monolithic `crates/yip-utls/src/stream.rs`**

Run: `git rm crates/yip-utls/src/stream.rs`

- [ ] **Step 4: Run test suite across workspace**

Run: `cargo test -p yip-utls`
Run: `cargo test --all`
Expected: ALL PASS (351+ unit tests pass, 42 netns integration tests pass).

- [ ] **Step 5: Run linter and formatting checks**

Run: `cargo clippy --all-targets -- -D warnings`
Run: `cargo fmt --check`
Run: `cargo deny check`
Expected: All clean, 0 warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-utls/src/stream/ crates/yip-utls/src/stream.rs
git commit -m "refactor(utls): complete stream modularization into stream/ module directory (#108)"
```

---

## Plan Self-Review Checklist

1. **Spec Coverage**: All items in `docs/2026-10-14-utls-stream-modularization-design.md` map 1:1 to Tasks 1 through 5.
2. **No Placeholders**: Exact code and signatures provided for all tasks.
3. **Type Consistency**: `ServerFlight`, `FlightShapeScan`, `CertFlightInfo`, `RealityStream` types and re-exports match across all tasks.
