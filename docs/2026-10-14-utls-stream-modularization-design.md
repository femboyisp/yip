# Modularization of `yip-utls/src/stream.rs` (Issue #108 Part 2) Design Spec

## 1. Context & Motivation

In Issue #108 ("refactor(yipd): split peer_manager.rs into a module directory"), Part 1 addressed `bin/yipd/src/peer_manager` by splitting the monolithic `peer_manager.rs` into a module directory (`mod.rs`, `handshake.rs`, `rekey.rs`, `relay.rs`, `routing.rs`, `obf.rs`, `gossip.rs`, `tests.rs`, `testutil.rs`).

Part 2 calls for applying the exact same treatment to `crates/yip-utls/src/stream.rs`. The file has grown to ~3,450 lines (with ~1,770 lines of implementation and ~1,680 lines of unit tests), encompassing:
- TLS 1.3 record-layer framing and finished scanning.
- Certificate chain parsing, DER parsing, and SPKI extraction.
- Signature verification (`CertificateVerify`) and REALITY binding verification.
- Flight shape scanning and server flight emission.
- Async I/O stream orchestration (`connect`, `serve`, `capture_dest_flight`, `RealityStream`).

## 2. Goals & Non-Goals

### Goals
- **Maintainability & Modularity**: Group cohesive concerns into focused files under `crates/yip-utls/src/stream/`.
- **Zero Wire Format / Protocol Changes**: Exact byte-for-byte behavior preservation across all client and server TLS handshakes.
- **Zero API Breakage**: Retain all public symbols, function signatures, and import paths exposed by `yip-utls` and `yip-utls::stream`.
- **Test Integrity**: Preserve all 351 unit tests and 42 integration/netns tests across the workspace.
- **Safety**: Retain `#![forbid(unsafe_code)]`.

### Non-Goals
- Changing any cryptographic algorithms, ciphersuites, or handshake logic.
- Refactoring `RealityStream` state machine or public methods.
- Modifying other modules in `yip-utls` (`auth.rs`, `hello.rs`, `handshake.rs`, etc.).

## 3. Directory Layout

We convert `crates/yip-utls/src/stream.rs` into a module directory `crates/yip-utls/src/stream/`:

```
crates/yip-utls/src/stream/
├── mod.rs        # Stream orchestration (connect, serve, capture_dest_flight, RealityStream, RNGs, re-exports)
├── record.rs     # Record-layer framing, record header codecs, find_finished_end, record constants
├── cert.rs       # Certificate chain parsing, leaf extraction, SPKI public key extraction
├── sig.rs        # CertificateVerify signature verification & creation, verify_reality_binding
├── flight.rs     # Flight shape scanning, template inspection, ServerFlight emission
└── tests.rs      # Unit test suites covering stream lifecycle, mocking, and end-to-end handshakes
```

## 4. Module Specifications

### 4.1. `record.rs`
- **Constants**:
  - `RECORD_HEADER_LEN: usize = 5`
  - `LEGACY_RECORD_VERSION_INITIAL: u16 = 0x0301`
  - `LEGACY_RECORD_VERSION: u16 = 0x0303`
  - `CHANGE_CIPHER_SPEC_RECORD: [u8; 6]`
  - `MAX_APP_RECORD_LEN: usize = 16384`
  - `MAX_HANDSHAKE_MSG_LEN: usize = 1 << 20`
  - `MAX_SERVER_FLIGHT_LEN: usize = 256 * 1024`
  - `CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14`
  - `CONTENT_TYPE_ALERT: u8 = 0x15`
  - `CONTENT_TYPE_HANDSHAKE: u8 = 0x16`
  - `CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17`
  - `ALERT_DESCRIPTION_CLOSE_NOTIFY: u8 = 0`
  - `HS_TYPE_FINISHED: u8 = 0x14`
- **Functions**:
  - `pub(crate) fn record_header(content_type: u8, legacy_version: u16, payload_len: usize) -> Result<[u8; RECORD_HEADER_LEN], Error>`
  - `pub(crate) fn find_finished_end(hs_flight: &[u8]) -> Result<Option<usize>, Error>`

### 4.2. `cert.rs`
- **Types**:
  - `pub(crate) struct CertFlightInfo { pub(crate) cert_msg_end: usize, pub(crate) leaf_der: Vec<u8> }`
- **Functions**:
  - `pub(crate) fn scan_cert_flight(hs_flight: &[u8]) -> Result<CertFlightInfo, Error>`
  - `pub(crate) fn certificate_chain_ders(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), Error>`
  - `pub(crate) fn certificate_leaf_der(body: &[u8]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn certificate_verify_signature(body: &[u8]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn spki_sec1_pubkey_from_der(cert_der: &[u8]) -> Result<Vec<u8>, Error>`

### 4.3. `sig.rs`
- **Functions**:
  - `pub(crate) fn verify_certificate_verify(leaf_spki_sec1: &[u8], signature_bytes: &[u8], transcript_hash_cv: &[u8; 32]) -> Result<(), Error>`
  - `pub fn sign_certificate_verify(signing_key: &p256::ecdsa::SigningKey, transcript_hash_cv: &[u8; 32]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn verify_reality_binding(leaf_der: &[u8], cv_body: &[u8], transcript_hash_cv: &[u8; 32], expected_auth_key: &auth::RealityAuthKey) -> Result<(), Error>`

### 4.4. `flight.rs`
- **Types**:
  - `pub struct FlightShapeScan { pub total_len: usize, pub cert_chain_shape: CertChainShape, pub encrypted_flight_shape: EncryptedFlightShape }`
  - `pub struct ServerFlight { pub server_hello: Vec<u8>, pub encrypted_records: Vec<Vec<u8>>, pub app_keys: ApplicationKeys }`
- **Functions**:
  - `pub fn scan_flight_shape(hs_flight: &[u8]) -> Result<FlightShapeScan, Error>`
  - `pub fn emit_server_flight(template: &ServerFlightTemplate, transcript_ch_sh: &[u8], keys: &HandshakeKeys, signing_key: &p256::ecdsa::SigningKey) -> Result<ServerFlight, Error>`
  - `pub(crate) fn u24_len(n: usize) -> Result<[u8; 3], Error>`
  - `pub(crate) fn handshake_message(msg_type: u8, body: &[u8]) -> Result<Vec<u8>, Error>`
  - `pub(crate) fn certificate_entry(der: &[u8]) -> Result<Vec<u8>, Error>`

### 4.5. `mod.rs`
- **Types**:
  - `struct OsRng`
  - `struct MlKemRng`
  - `pub struct RealityStream<S>`
- **Functions**:
  - `pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(s: S, sni: &str, reality_pub: &[u8; 32], short_id: [u8; 8], verify: bool) -> Result<RealityStream<S>, Error>`
  - `pub async fn capture_dest_flight<S: AsyncRead + AsyncWrite + Unpin>(s: S, sni: &str) -> Result<CapturedFlight, Error>`
  - `pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, flight: ServerFlight) -> Result<RealityStream<S>, Error>`
  - `fn protocol_io_error(msg: &'static str) -> io::Error`
  - `fn protocol_io_error_owned(msg: String) -> io::Error`
  - `fn handshake_io_error(e: handshake::Error) -> io::Error`
- **Re-exports**:
  - `pub use flight::{emit_server_flight, scan_flight_shape, FlightShapeScan, ServerFlight};`
  - `pub use sig::sign_certificate_verify;`

### 4.6. `tests.rs`
- Unit tests covering `record.rs`, `cert.rs`, `sig.rs`, `flight.rs`, and `stream` handshakes:
  - `record_header_*`, `find_finished_end_*`
  - `scan_cert_flight_*`, `certificate_*`, `spki_*`
  - `verify_*`, `sign_certificate_verify_*`
  - `scan_flight_shape_*`, `emit_server_flight_*`
  - Full loopback handshake mocks (`run_mock_tls13_server`, `run_mock_dest_server_with_known_flight`, `connect_against_mock_tls13_server`, `capture_dest_flight_against_mock`).

## 5. Verification Plan
- Unit tests: `cargo test -p yip-utls` passes cleanly.
- Integration netns tests: `cargo test --all` passes cleanly.
- Linter & Formatting: `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` pass with 0 warnings.
- Dependency audit: `cargo deny check` passes.
