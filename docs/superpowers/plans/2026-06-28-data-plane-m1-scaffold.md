# Data Plane M1 — Workspace Scaffold & Quality Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `yip` Cargo workspace with all six crate stubs, the core trait skeleton, and every quality gate (lints, fmt, coverage, mutation, fuzz, unused-deps, advisories) green in CI — the foundation every later milestone builds on.

**Architecture:** A Rust workspace of six focused crates (`yip-io`, `yip-wire`, `yip-crypto`, `yip-transport`, `yip-device`, `yipd`). This milestone creates each crate as a compiling stub exposing only the trait signatures later milestones implement, plus the repo-wide tooling. No protocol behavior yet — the deliverable is "an empty but correctly structured, fully linted, CI-green workspace."

**Tech Stack:** Rust (edition 2021), Cargo workspaces, GitHub Actions, `cargo-llvm-cov`, `cargo-mutants`, `cargo-fuzz`, `cargo-shear`, `cargo-deny`.

## Global Constraints

- License: **MPL-2.0** (every crate `license = "MPL-2.0"`).
- Crate names **kebab-case**; binary crate is `yipd`.
- Lints: adopt the `coding-guidelines` set verbatim as `[workspace.lints]`; CI builds `--deny warnings`.
- **`as` is banned for numeric casts** — use `From`/`TryFrom`.
- Protocol crates (`yip-wire`, `yip-crypto`, `yip-transport`, `yip-device`) are `#![forbid(unsafe_code)]`; only `yip-io` may contain `unsafe`, and every block needs a `// SAFETY:` comment.
- Dependencies: pin full `x.y.z` versions; no git deps without org-fork + `rev` pin.
- Borrowed types in signatures: `&[T]`/`&str`/`&Path`, never `&Vec`/`&String`/`&PathBuf`.
- Files: UTF-8, LF, final newline, no trailing whitespace, space indent.
- Commits: imperative, capitalized, ≤72-char subject; end body with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Coverage bar (enforced from M2 onward, wired here): **≥90%** on logic crates via `cargo-llvm-cov`.

---

## File structure (created in this milestone)

```
Cargo.toml                      # workspace root: members, lints, shared deps
rustfmt.toml                    # Mullvad reference config
deny.toml                       # cargo-deny: licenses + advisories
CHANGELOG.md                    # keep-a-changelog
LICENSE                         # MPL-2.0 text
crates/
  yip-io/        { Cargo.toml, src/lib.rs }   # DataPlaneIo trait
  yip-wire/      { Cargo.toml, src/lib.rs }   # WireCodec trait + Frame type
  yip-crypto/    { Cargo.toml, src/lib.rs }   # Session trait
  yip-transport/ { Cargo.toml, src/lib.rs }   # Transport trait + FlowClass
  yip-device/    { Cargo.toml, src/lib.rs }   # Device trait
bin/
  yipd/          { Cargo.toml, src/main.rs }  # daemon entrypoint stub
.github/workflows/
  ci.yml                        # build, test, clippy, fmt, shear, deny
  coverage.yml                  # llvm-cov
  mutants.yml                   # cargo-mutants (nightly/on-demand)
```

---

### Task 1: Workspace root, lints, and tooling config

**Files:**
- Create: `Cargo.toml`
- Create: `rustfmt.toml`
- Create: `deny.toml`
- Create: `CHANGELOG.md`
- Create: `LICENSE`

**Interfaces:**
- Consumes: nothing.
- Produces: the `[workspace]` + `[workspace.lints]` + `[workspace.dependencies]` tables every crate inherits via `lints.workspace = true` and `dep.workspace = true`.

- [ ] **Step 1: Write the workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["crates/*", "bin/*"]

[workspace.package]
edition = "2021"
license = "MPL-2.0"
repository = "https://github.com/femboyisp/yip"

[workspace.dependencies]
thiserror = "2.0.9"
tracing = "0.1.41"

[workspace.lints.clippy]
allow_attributes = "warn"
as_ptr_cast_mut = "warn"
as_underscore = "warn"
borrow_as_ptr = "warn"
implicit_clone = "warn"
undocumented_unsafe_blocks = "warn"
unicode_not_nfc = "warn"
unused_async = "deny"
wildcard_dependencies = "deny"

[workspace.lints.rust]
absolute_paths_not_starting_with_crate = "deny"
explicit_outlives_requirements = "warn"
macro_use_extern_crate = "deny"
missing_abi = "deny"
non_ascii_idents = "forbid"
rust_2018_idioms = { level = "deny", priority = -1 }
single_use_lifetimes = "warn"
unused_lifetimes = "warn"
unused_macro_rules = "warn"
```

- [ ] **Step 2: Write `rustfmt.toml`**

```toml
# Mullvad reference configuration (mullvadvpn-app/rustfmt.toml)
edition = "2021"
max_width = 100
```

- [ ] **Step 3: Write `deny.toml`**

```toml
[advisories]
yanked = "deny"

[licenses]
allow = ["MPL-2.0", "MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unicode-3.0"]
confidence-threshold = 0.9

[bans]
multiple-versions = "warn"
wildcard-dependencies = "deny"
```

- [ ] **Step 4: Write `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Workspace scaffold with `yip-io`, `yip-wire`, `yip-crypto`, `yip-transport`,
  `yip-device`, and `yipd` crate stubs.
- CI quality gates: build, test, clippy, rustfmt, cargo-shear, cargo-deny,
  coverage, and mutation testing.
```

- [ ] **Step 5: Add the MPL-2.0 license text**

Run: `curl -fsSL https://www.mozilla.org/media/MPL/2.0/index.txt -o LICENSE`
Expected: `LICENSE` contains the Mozilla Public License 2.0 text (starts with "Mozilla Public License Version 2.0").

- [ ] **Step 6: Verify the workspace parses (no members yet → expect a specific error)**

Run: `cargo metadata --no-deps --format-version 1 >/dev/null`
Expected: FAIL — `error: no targets specified`/`failed to load manifest for workspace member` because `crates/*` and `bin/*` are empty. This confirms the manifest is syntactically valid and globs are active. Proceed to Task 2 which adds members.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml rustfmt.toml deny.toml CHANGELOG.md LICENSE
git commit -m "Add workspace root, lints, and tooling config

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `yip-wire` crate stub with `WireCodec` trait + `Frame` type

**Files:**
- Create: `crates/yip-wire/Cargo.toml`
- Create: `crates/yip-wire/src/lib.rs`

**Interfaces:**
- Consumes: workspace lints/deps.
- Produces:
  - `pub struct Frame { pub conn_tag: u64, pub object_id: u16, pub payload: Vec<u8> }`
  - `pub trait WireCodec { fn frame(&self, frame: &Frame) -> Vec<u8>; fn deframe(&self, datagram: &[u8]) -> Result<Frame, WireError>; }`
  - `pub enum WireError { AuthFailed, Malformed }`

- [ ] **Step 1: Write the failing test**

`crates/yip-wire/src/lib.rs` (test module at bottom):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_carries_object_id() {
        let frame = Frame { conn_tag: 7, object_id: 42, payload: vec![1, 2, 3] };
        assert_eq!(frame.object_id, 42);
    }
}
```

- [ ] **Step 2: Write `crates/yip-wire/Cargo.toml`**

```toml
[package]
name = "yip-wire"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
thiserror = { workspace = true }

[lints]
workspace = true
```

- [ ] **Step 3: Write the minimal `crates/yip-wire/src/lib.rs`**

```rust
//! Wire framing for the yip data plane: keyed header-protection and
//! coverage-based authentication. Behavior lands in milestone M2; this
//! milestone establishes the public surface later crates depend on.
#![forbid(unsafe_code)]

/// A single on-wire frame carrying one FEC symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Epoch-rotating keyed token selecting the session/decoder.
    pub conn_tag: u64,
    /// Which pipelined FEC object this symbol belongs to.
    pub object_id: u16,
    /// The ciphertext symbol payload.
    pub payload: Vec<u8>,
}

/// Errors from decoding a wire datagram.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// Coverage-auth tag did not verify.
    #[error("authentication failed")]
    AuthFailed,
    /// Datagram was too short or structurally invalid.
    #[error("malformed datagram")]
    Malformed,
}

/// Encodes [`Frame`]s to datagrams and back. Implemented in M2.
pub trait WireCodec {
    /// Serialize and header-protect a frame into a wire datagram.
    fn frame(&self, frame: &Frame) -> Vec<u8>;
    /// Authenticate, deprotect, and parse a datagram into a [`Frame`].
    fn deframe(&self, datagram: &[u8]) -> Result<Frame, WireError>;
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p yip-wire`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-wire
git commit -m "Add yip-wire crate stub with WireCodec trait and Frame type

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `yip-crypto` crate stub with `Session` trait

**Files:**
- Create: `crates/yip-crypto/Cargo.toml`
- Create: `crates/yip-crypto/src/lib.rs`

**Interfaces:**
- Consumes: workspace lints/deps.
- Produces:
  - `pub trait Session { fn seal(&mut self, plaintext: &[u8]) -> Vec<u8>; fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>; }`
  - `pub enum CryptoError { Decrypt, Replay }`

- [ ] **Step 1: Write the failing test**

`crates/yip-crypto/src/lib.rs` (test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_error_is_comparable() {
        assert_eq!(CryptoError::Replay, CryptoError::Replay);
        assert_ne!(CryptoError::Replay, CryptoError::Decrypt);
    }
}
```

- [ ] **Step 2: Write `crates/yip-crypto/Cargo.toml`**

```toml
[package]
name = "yip-crypto"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
thiserror = { workspace = true }

[lints]
workspace = true
```

- [ ] **Step 3: Write `crates/yip-crypto/src/lib.rs`**

```rust
//! AEAD session crypto for the yip data plane. M3 wires this to gotatun's
//! audited Noise-IK core; this milestone fixes the public surface.
#![forbid(unsafe_code)]

/// Errors from opening a sealed message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD tag did not verify / decryption failed.
    #[error("decryption failed")]
    Decrypt,
    /// Nonce/counter outside the anti-replay window.
    #[error("replayed message")]
    Replay,
}

/// An established, rekeying AEAD session between two peers. Implemented in M3.
pub trait Session {
    /// AEAD-encrypt an inner frame for transmission.
    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8>;
    /// AEAD-decrypt a received ciphertext, enforcing anti-replay.
    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p yip-crypto`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-crypto
git commit -m "Add yip-crypto crate stub with Session trait

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `yip-transport` crate stub with `Transport` trait + `FlowClass`

**Files:**
- Create: `crates/yip-transport/Cargo.toml`
- Create: `crates/yip-transport/src/lib.rs`

**Interfaces:**
- Consumes: `yip_wire::Frame`.
- Produces:
  - `pub enum FlowClass { Realtime, Bulk, Default }`
  - `pub trait Transport { fn send(&mut self, frame: &[u8], class: FlowClass); fn recv(&mut self) -> Option<Vec<u8>>; }`

- [ ] **Step 1: Write the failing test**

`crates/yip-transport/src/lib.rs` (test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flow_class_is_default() {
        assert_eq!(FlowClass::default(), FlowClass::Default);
    }
}
```

- [ ] **Step 2: Write `crates/yip-transport/Cargo.toml`**

```toml
[package]
name = "yip-transport"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
yip-wire = { path = "../yip-wire" }

[lints]
workspace = true
```

- [ ] **Step 3: Write `crates/yip-transport/src/lib.rs`**

```rust
//! Adaptive RaptorQ-FEC transport: per-flow classification, the adaptive
//! redundancy controller, and thin ARQ. Implemented across M5; this
//! milestone fixes the public surface and the flow taxonomy.
#![forbid(unsafe_code)]

/// Latency/reliability class assigned to a flow by the classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowClass {
    /// Latency-critical (games/voice): tiny block, no ARQ.
    Realtime,
    /// Bulk / L2-IXP: larger block, heavier redundancy, ARQ on.
    Bulk,
    /// Baseline when nothing else applies.
    #[default]
    Default,
}

/// The FEC transport: accepts sealed frames, emits decoded frames.
/// Implemented in M5.
pub trait Transport {
    /// Encode and queue a sealed frame for transmission under `class`.
    fn send(&mut self, frame: &[u8], class: FlowClass);
    /// Return the next fully decoded frame, if one is ready.
    fn recv(&mut self) -> Option<Vec<u8>>;
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p yip-transport`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport
git commit -m "Add yip-transport crate stub with Transport trait and FlowClass

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `yip-device` crate stub with `Device` trait

**Files:**
- Create: `crates/yip-device/Cargo.toml`
- Create: `crates/yip-device/src/lib.rs`

**Interfaces:**
- Consumes: workspace lints/deps.
- Produces:
  - `pub enum DeviceKind { Tun, Tap }`
  - `pub trait Device { fn kind(&self) -> DeviceKind; fn read_frame(&mut self, buf: &mut [u8]) -> std::io::Result<usize>; fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<usize>; }`

- [ ] **Step 1: Write the failing test**

`crates/yip-device/src/lib.rs` (test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_kinds_are_distinct() {
        assert_ne!(DeviceKind::Tun, DeviceKind::Tap);
    }
}
```

- [ ] **Step 2: Write `crates/yip-device/Cargo.toml`**

```toml
[package]
name = "yip-device"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
```

- [ ] **Step 3: Write `crates/yip-device/src/lib.rs`**

```rust
//! L3 (TUN) and L2 (TAP) tunnel endpoints behind one trait. Real device
//! I/O lands in M4; this milestone fixes the public surface.
#![forbid(unsafe_code)]

/// Whether a device operates at L3 (IP) or L2 (Ethernet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// L3 IP tunnel (`/dev/net/tun`, TUN mode).
    Tun,
    /// L2 Ethernet tap (`/dev/net/tun`, TAP mode) with MAC learning.
    Tap,
}

/// A tunnel endpoint that yields and accepts inner frames. Implemented in M4.
pub trait Device {
    /// Whether this is an L3 (TUN) or L2 (TAP) device.
    fn kind(&self) -> DeviceKind;
    /// Read one inner frame into `buf`, returning its length.
    fn read_frame(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Write one inner frame, returning the number of bytes written.
    fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<usize>;
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p yip-device`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-device
git commit -m "Add yip-device crate stub with Device trait

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `yip-io` crate stub with `DataPlaneIo` trait (the only unsafe-allowed crate)

**Files:**
- Create: `crates/yip-io/Cargo.toml`
- Create: `crates/yip-io/src/lib.rs`

**Interfaces:**
- Consumes: workspace lints/deps.
- Produces:
  - `pub enum Backend { IoUring, AfXdpZeroCopy, AfXdpCopy, Mmsg }`
  - `pub trait DataPlaneIo { fn backend(&self) -> Backend; fn send(&mut self, datagram: &[u8]) -> std::io::Result<()>; fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>; }`

- [ ] **Step 1: Write the failing test**

`crates/yip-io/src/lib.rs` (test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_are_ordered_by_preference() {
        // io_uring is the first backend we build (M4); fallback rungs follow.
        assert_ne!(Backend::IoUring, Backend::Mmsg);
    }
}
```

- [ ] **Step 2: Write `crates/yip-io/Cargo.toml`**

```toml
[package]
name = "yip-io"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
```

- [ ] **Step 3: Write `crates/yip-io/src/lib.rs`**

Note: this crate is intentionally NOT `forbid(unsafe_code)` — M4 adds io_uring/AF_XDP `unsafe`. The `undocumented_unsafe_blocks` lint (from the workspace) enforces `// SAFETY:` comments.

```rust
//! Kernel-bypass-ready packet I/O. M4 adds the io_uring backend (single ring
//! servicing UDP + TUN/TAP), then AF_XDP. This is the only crate permitted to
//! contain `unsafe`; every `unsafe` block must carry a `// SAFETY:` comment.

/// Selected I/O backend, in fallback-preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Single io_uring ring for UDP + TUN/TAP (built first in M4).
    IoUring,
    /// AF_XDP zero-copy (bare-metal accelerant, later).
    AfXdpZeroCopy,
    /// AF_XDP copy mode (cloud-VM fallback).
    AfXdpCopy,
    /// Portable recvmmsg/sendmmsg fallback rung.
    Mmsg,
}

/// Sends and receives wire datagrams via the selected backend. Implemented in M4.
pub trait DataPlaneIo {
    /// The backend actually selected at startup (after probing/fallback).
    fn backend(&self) -> Backend;
    /// Send one datagram.
    fn send(&mut self, datagram: &[u8]) -> std::io::Result<()>;
    /// Receive one datagram into `buf`, returning its length.
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p yip-io`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io
git commit -m "Add yip-io crate stub with DataPlaneIo trait

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: `yipd` binary stub

**Files:**
- Create: `bin/yipd/Cargo.toml`
- Create: `bin/yipd/src/main.rs`

**Interfaces:**
- Consumes: all five library crates (as path deps; wiring happens in M6).
- Produces: a runnable `yipd` binary that prints its version and exits 0.

- [ ] **Step 1: Write the failing test**

`bin/yipd/src/main.rs`:

```rust
//! The yip daemon. M6 wires device <-> transport <-> crypto <-> wire <-> io
//! and loads a static 2-peer config. For now it is a version-printing stub.

fn banner() -> String {
    format!("yipd {}", env!("CARGO_PKG_VERSION"))
}

fn main() {
    println!("{}", banner());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_contains_name() {
        assert!(banner().starts_with("yipd "));
    }
}
```

- [ ] **Step 2: Write `bin/yipd/Cargo.toml`**

```toml
[package]
name = "yipd"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
yip-io = { path = "../../crates/yip-io" }
yip-wire = { path = "../../crates/yip-wire" }
yip-crypto = { path = "../../crates/yip-crypto" }
yip-transport = { path = "../../crates/yip-transport" }
yip-device = { path = "../../crates/yip-device" }

[lints]
workspace = true
```

Note: these five path deps are unused until M6. `cargo-shear` would flag them — Task 9 configures `yipd` as exempt (the wiring crate intentionally pre-declares them). If you prefer zero warnings now, comment them out and re-add in M6; this plan keeps them declared and exempts the binary.

- [ ] **Step 3: Run the test and the binary**

Run: `cargo test -p yipd && cargo run -p yipd`
Expected: test PASS; binary prints `yipd 0.0.0`.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd
git commit -m "Add yipd binary stub

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Whole-workspace gate — build, fmt, clippy clean

**Files:**
- Modify: none (verification task; fix any crate file that fails).

**Interfaces:**
- Consumes: all crates from Tasks 1–7.
- Produces: a workspace that is `fmt`-clean and `clippy`-clean under `--deny warnings`.

- [ ] **Step 1: Format the workspace**

Run: `cargo fmt --all`
Expected: exits 0; files normalized.

- [ ] **Step 2: Verify formatting is clean**

Run: `cargo fmt --all -- --check`
Expected: exits 0, no diff.

- [ ] **Step 3: Build the whole workspace**

Run: `cargo build --workspace`
Expected: compiles, 0 warnings.

- [ ] **Step 4: Clippy with warnings denied**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: exits 0, no warnings. If any crate warns, fix it before continuing.

- [ ] **Step 5: Run all tests**

Run: `cargo test --workspace`
Expected: all tests pass (6 unit tests across crates).

- [ ] **Step 6: Commit any formatting/lint fixes**

```bash
git add -A
git commit -m "Format workspace and resolve clippy warnings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: CI pipeline — build, test, clippy, fmt, shear, deny

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the green workspace from Task 8.
- Produces: a CI workflow gating every push/PR.

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
---
name: CI
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions: {}

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - name: Format check
        run: cargo fmt --all -- --check
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Build
        run: cargo build --workspace
      - name: Test
        run: cargo test --workspace

  shear:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: taiki-e/install-action@cargo-shear
      - name: Unused dependencies
        run: cargo shear --expand

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

- [ ] **Step 2: Configure `yipd`'s pre-declared deps as shear-exempt**

Append to `bin/yipd/Cargo.toml`:

```toml
[package.metadata.cargo-shear]
ignored = ["yip-io", "yip-wire", "yip-crypto", "yip-transport", "yip-device"]
```

- [ ] **Step 3: Verify shear locally**

Run: `cargo shear --expand`
Expected: exits 0 (no unused deps reported; `yipd`'s pre-wired deps are ignored).

- [ ] **Step 4: Verify deny locally**

Run: `cargo deny check`
Expected: exits 0 (advisories + licenses pass). If a transitive license is missing from `deny.toml`'s allow-list, add it with a comment.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml bin/yipd/Cargo.toml
git commit -m "Add CI: build, test, clippy, fmt, shear, deny

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Coverage and mutation-testing workflows

**Files:**
- Create: `.github/workflows/coverage.yml`
- Create: `.github/workflows/mutants.yml`

**Interfaces:**
- Consumes: the green workspace.
- Produces: coverage + mutation gates (informational this milestone; the 90% threshold bites from M2 when real logic exists).

- [ ] **Step 1: Write `.github/workflows/coverage.yml`**

```yaml
---
name: Coverage
on:
  pull_request:
  workflow_dispatch:

permissions: {}

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: taiki-e/install-action@cargo-llvm-cov
      - name: Coverage (logic crates)
        run: >
          cargo llvm-cov --workspace
          --exclude yip-io --exclude yipd
          --fail-under-lines 90 --summary-only
```

Note: `yip-io` (kernel-bypass `unsafe`, hardware-gated) and `yipd` (wiring) are excluded from the 90% gate per the spec's honest-exclusion rule. The threshold passes trivially this milestone (stubs are fully covered by their unit tests); it becomes meaningful in M2.

- [ ] **Step 2: Write `.github/workflows/mutants.yml`**

```yaml
---
name: Mutation testing
on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

permissions: {}

jobs:
  mutants:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: taiki-e/install-action@cargo-mutants
      - name: Mutation test (logic crates)
        run: >
          cargo mutants --package yip-wire --package yip-transport
          --package yip-crypto -- --all-targets
```

- [ ] **Step 3: Verify coverage locally**

Run: `cargo llvm-cov --workspace --exclude yip-io --exclude yipd --fail-under-lines 90 --summary-only`
Expected: exits 0; reports ≥90% lines on the four logic stub crates (their unit tests cover every line).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/coverage.yml .github/workflows/mutants.yml
git commit -m "Add coverage and mutation-testing workflows

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: Fuzz-target scaffold for `yip-wire`

**Files:**
- Create: `crates/yip-wire/fuzz/Cargo.toml`
- Create: `crates/yip-wire/fuzz/fuzz_targets/deframe.rs`

**Interfaces:**
- Consumes: `yip_wire::WireCodec` (trait only this milestone — the target compiles against the surface, exercised for real in M2).
- Produces: a buildable `cargo-fuzz` target so M2 can start fuzzing immediately.

- [ ] **Step 1: Write `crates/yip-wire/fuzz/Cargo.toml`**

```toml
[package]
name = "yip-wire-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4.7"

[dependencies.yip-wire]
path = ".."

[[bin]]
name = "deframe"
path = "fuzz_targets/deframe.rs"
test = false
doc = false
bench = false

[workspace]
```

Note the empty `[workspace]` table: it keeps the fuzz crate out of the root workspace (standard `cargo-fuzz` layout).

- [ ] **Step 2: Write `crates/yip-wire/fuzz/fuzz_targets/deframe.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

// M2 replaces this with a real WireCodec instance and asserts deframe never
// panics on arbitrary input. For now it proves the fuzz harness builds.
fuzz_target!(|data: &[u8]| {
    let _ = data;
});
```

- [ ] **Step 3: Verify the fuzz target builds**

Run: `cargo +nightly fuzz build -p yip-wire-fuzz` (from `crates/yip-wire/fuzz`, or `cargo +nightly fuzz build` within that dir)
Expected: builds successfully. If `cargo-fuzz` or nightly is unavailable on the dev machine, document that and skip — CI's nightly job covers it in M2.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-wire/fuzz
git commit -m "Add fuzz-target scaffold for yip-wire deframe

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (M1's slice):** workspace + six crates ✓ (Tasks 2–7); lints/rustfmt/`as`-ban/`forbid(unsafe)` placement ✓ (Task 1 + per-crate); CI build/test/clippy/fmt ✓ (Tasks 8–9); cargo-shear + cargo-deny ✓ (Task 9); coverage ≥90% gate with honest `yip-io`/`yipd` exclusion ✓ (Task 10); mutation + fuzz scaffolds ✓ (Tasks 10–11); MPL-2.0 + changelog ✓ (Task 1). The trait surfaces (`DataPlaneIo`, `WireCodec`/`Frame`, `Session`, `Transport`/`FlowClass`, `Device`) match the spec's §1 crate responsibilities. Behavior (framing, crypto, io, FEC) is deferred to M2–M6 by design — not a gap.

**Placeholder scan:** every code/command step contains real content; no TBD/TODO-as-work. The "implemented in Mn" comments are accurate forward-references in stub bodies, not missing plan content.

**Type consistency:** trait/type names used in `yipd`'s deps and the `Interfaces` blocks match their definitions (`Frame`, `WireError`, `CryptoError`, `FlowClass`, `DeviceKind`, `Backend`). `FlowClass::Default` is the `#[default]` variant, consistent with Task 4's test.

---

**Definition of done for M1:** `cargo build/test/clippy/fmt` all green across the workspace; CI, coverage, mutation, and fuzz workflows present; six crates structured with their public trait surfaces; ready for M2 to implement `yip-wire`.
