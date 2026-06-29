# Data Plane M2 — `yip-wire` Framing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the `yip-wire` stub into a working wire codec: serialize/parse frames, append a SipHash coverage-auth tag, and keyed-header-protect the header so no constant bytes appear on the wire — fully unit-tested and fuzzed.

**Architecture:** `yip-wire` exposes a concrete `Codec` (holding two injectable 16-byte keys) implementing the existing `WireCodec` trait. On-wire layout is `[protected header][payload][8-byte tag]`. The tag is `SipHash-2-4(auth_key, header‖payload)`; the header is XORed with a keyed mask derived from the tag (a `SipHash`-CTR keystream under `hp_key`). Constant-time tag comparison via `subtle`. Pure logic, no I/O, no async.

**Tech Stack:** Rust, `siphasher` (SipHash-2-4), `subtle` (constant-time compare), `libfuzzer-sys`.

## Global Constraints

- License MPL-2.0; `#![forbid(unsafe_code)]` stays on `yip-wire`.
- Lints: workspace set, CI `--deny warnings`. **No `as` numeric casts** — use `From`/`TryFrom`/`to_be_bytes`/`from_be_bytes`.
- Deps pinned full `x.y.z`: `siphasher = "1.0.3"`, `subtle = "2.6.1"`.
- Borrowed types in signatures (`&[u8]`, not `&Vec<u8>`).
- Files UTF-8/LF/final-newline/no-trailing-ws; commits imperative+capitalized ≤72-char subject, body ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Coverage: `yip-wire` is a logic crate held to ≥90% line coverage.
- **Crypto scope note (put in code docs):** the SipHash-based header protection is the *framing/obfuscation mechanism* with injectable keys. Its cryptographic binding to the session (and any replacement of the SipHash-CTR mask with a stream cipher) is revisited in M3 when real handshake keys exist. Do not advertise it as the final security boundary — the AEAD in `yip-crypto` is.

## Wire format (fixed in M2)

```
offset 0                15            15+N          15+N+8
       ┌────────────────┬─────────────┬─────────────┐
       │ protected hdr  │  payload N  │  tag (8 B)   │
       │   (15 bytes)   │ (ciphertext)│ SipHash-2-4  │
       └────────────────┴─────────────┴─────────────┘
header (logical, before protection):
  conn_tag : u64 BE   (8)
  object_id: u16 BE   (2)
  payload_id: [u8;4]  (4)   # raptorq SBN+ESI, opaque here
  flags    : u8       (1)
```
Constants: `HEADER_LEN = 15`, `TAG_LEN = 8`, `MIN_FRAME = 23`.
(The spec's optional per-object `object_size` descriptor and transport-context coverage are deferred to a later milestone; M2 authenticates `header‖payload` only and carries a fixed header.)

---

### Task 1: Extend `Frame`, add deps, header (de)serialization + constants

**Files:**
- Modify: `crates/yip-wire/Cargo.toml`
- Modify: `crates/yip-wire/src/lib.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `pub struct Frame { pub conn_tag: u64, pub object_id: u16, pub payload_id: [u8; 4], pub flags: u8, pub payload: Vec<u8> }`
  - `pub const HEADER_LEN: usize = 15; pub const TAG_LEN: usize = 8; pub const MIN_FRAME: usize = HEADER_LEN + TAG_LEN;`
  - private `fn write_header(frame: &Frame) -> [u8; HEADER_LEN]`
  - private `fn read_header(bytes: &[u8; HEADER_LEN]) -> (u64, u16, [u8; 4], u8)`

- [ ] **Step 1: Write the failing test**

Add to `crates/yip-wire/src/lib.rs` test module:

```rust
#[test]
fn header_roundtrips() {
    let frame = Frame {
        conn_tag: 0x0102_0304_0506_0708,
        object_id: 0xABCD,
        payload_id: [9, 8, 7, 6],
        flags: 0x5A,
        payload: vec![],
    };
    let bytes = write_header(&frame);
    assert_eq!(bytes.len(), HEADER_LEN);
    let (conn_tag, object_id, payload_id, flags) = read_header(&bytes);
    assert_eq!(conn_tag, frame.conn_tag);
    assert_eq!(object_id, frame.object_id);
    assert_eq!(payload_id, frame.payload_id);
    assert_eq!(flags, frame.flags);
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-wire header_roundtrips`
Expected: FAIL to compile (`Frame` has no `payload_id`/`flags`; `write_header`/`read_header`/consts undefined).

- [ ] **Step 3: Add the deps**

In `crates/yip-wire/Cargo.toml`, set the `[dependencies]` section to:

```toml
[dependencies]
thiserror = { workspace = true }
siphasher = "1.0.3"
subtle = "2.6.1"
```

- [ ] **Step 4: Implement the struct, constants, and helpers**

Replace the `Frame` struct in `crates/yip-wire/src/lib.rs` with the extended version, and add the constants + helpers above the `WireCodec` trait:

```rust
/// A single on-wire frame carrying one FEC symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Epoch-rotating keyed token selecting the session/decoder.
    pub conn_tag: u64,
    /// Which pipelined FEC object this symbol belongs to.
    pub object_id: u16,
    /// RaptorQ payload identifier (SBN + ESI), opaque to the wire layer.
    pub payload_id: [u8; 4],
    /// Symbol kind / control bits (source/repair, feedback, ARQ).
    pub flags: u8,
    /// The ciphertext symbol payload.
    pub payload: Vec<u8>,
}

/// Length of the logical (and protected) frame header in bytes.
pub const HEADER_LEN: usize = 15;
/// Length of the trailing coverage-auth tag in bytes.
pub const TAG_LEN: usize = 8;
/// Smallest valid frame: header + tag, empty payload.
pub const MIN_FRAME: usize = HEADER_LEN + TAG_LEN;

/// Serialize the logical header (big-endian, fixed layout).
fn write_header(frame: &Frame) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..8].copy_from_slice(&frame.conn_tag.to_be_bytes());
    out[8..10].copy_from_slice(&frame.object_id.to_be_bytes());
    out[10..14].copy_from_slice(&frame.payload_id);
    out[14] = frame.flags;
    out
}

/// Parse the logical header fields back out.
fn read_header(bytes: &[u8; HEADER_LEN]) -> (u64, u16, [u8; 4], u8) {
    let conn_tag = u64::from_be_bytes(bytes[0..8].try_into().expect("8 bytes"));
    let object_id = u16::from_be_bytes(bytes[8..10].try_into().expect("2 bytes"));
    let payload_id: [u8; 4] = bytes[10..14].try_into().expect("4 bytes");
    let flags = bytes[14];
    (conn_tag, object_id, payload_id, flags)
}
```

- [ ] **Step 5: Run the test — expect pass**

Run: `cargo test -p yip-wire header_roundtrips`
Expected: PASS. Also run `cargo test -p yip-wire` — the M1 `frame_carries_object_id` test still passes (update it if it constructed `Frame` without the new fields).

Note: if `frame_carries_object_id` fails to compile because it builds `Frame` without `payload_id`/`flags`, add `payload_id: [0; 4], flags: 0,` to that literal.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-wire/Cargo.toml crates/yip-wire/src/lib.rs
git commit -m "Extend Frame and add header serialization to yip-wire

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Coverage-auth tag (SipHash-2-4)

**Files:**
- Modify: `crates/yip-wire/src/lib.rs`

**Interfaces:**
- Consumes: `siphasher`.
- Produces: private `fn auth_tag(auth_key: &[u8; 16], covered: &[u8]) -> [u8; TAG_LEN]`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn auth_tag_is_keyed_and_covers_input() {
    let k1 = [1u8; 16];
    let k2 = [2u8; 16];
    let a = auth_tag(&k1, b"hello");
    let b = auth_tag(&k1, b"hello");
    let c = auth_tag(&k1, b"hellp"); // one byte different
    let d = auth_tag(&k2, b"hello"); // different key
    assert_eq!(a, b, "deterministic for same key+input");
    assert_ne!(a, c, "changes when covered bytes change");
    assert_ne!(a, d, "changes when key changes");
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-wire auth_tag_is_keyed`
Expected: FAIL (`auth_tag` undefined).

- [ ] **Step 3: Implement `auth_tag`**

Add to `crates/yip-wire/src/lib.rs` (and the imports at the top of the file):

```rust
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// Compute the 8-byte coverage-auth tag over `covered` under `auth_key`.
fn auth_tag(auth_key: &[u8; 16], covered: &[u8]) -> [u8; TAG_LEN] {
    let mut hasher = SipHasher24::new_with_key(auth_key);
    hasher.write(covered);
    hasher.finish().to_be_bytes()
}
```

- [ ] **Step 4: Run the test — expect pass**

Run: `cargo test -p yip-wire auth_tag_is_keyed`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-wire/src/lib.rs
git commit -m "Add SipHash coverage-auth tag to yip-wire

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Keyed header-protection mask

**Files:**
- Modify: `crates/yip-wire/src/lib.rs`

**Interfaces:**
- Consumes: `siphasher`.
- Produces:
  - private `fn keystream(hp_key: &[u8; 16], sample: &[u8], n: usize) -> Vec<u8>`
  - private `fn xor_in_place(buf: &mut [u8], mask: &[u8])`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn keystream_masks_reversibly_and_hides_constants() {
    let hp = [3u8; 16];
    let sample = [0xAAu8; TAG_LEN];
    let mut header = [0u8; HEADER_LEN]; // all-zero "constant" header
    let mask = keystream(&hp, &sample, HEADER_LEN);
    assert_eq!(mask.len(), HEADER_LEN);
    xor_in_place(&mut header, &mask);
    assert_ne!(header, [0u8; HEADER_LEN], "constant header is hidden after masking");
    // XOR again with the same mask restores the original
    xor_in_place(&mut header, &mask);
    assert_eq!(header, [0u8; HEADER_LEN], "masking is reversible");
    // a different sample yields a different stream
    let mask2 = keystream(&hp, &[0xBBu8; TAG_LEN], HEADER_LEN);
    assert_ne!(mask, mask2);
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-wire keystream_masks`
Expected: FAIL (`keystream`/`xor_in_place` undefined).

- [ ] **Step 3: Implement the keystream + xor**

```rust
/// Generate `n` mask bytes as a SipHash-CTR keystream under `hp_key`,
/// seeded by `sample`. Block i = SipHash24(hp_key, sample ‖ i_be_u32).
fn keystream(hp_key: &[u8; 16], sample: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut counter: u32 = 0;
    while out.len() < n {
        let mut hasher = SipHasher24::new_with_key(hp_key);
        hasher.write(sample);
        hasher.write(&counter.to_be_bytes());
        out.extend_from_slice(&hasher.finish().to_be_bytes());
        counter += 1;
    }
    out.truncate(n);
    out
}

/// XOR `mask` into `buf` byte-for-byte (`buf.len()` must be `<= mask.len()`).
fn xor_in_place(buf: &mut [u8], mask: &[u8]) {
    for (b, m) in buf.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
}
```

- [ ] **Step 4: Run the test — expect pass**

Run: `cargo test -p yip-wire keystream_masks`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-wire/src/lib.rs
git commit -m "Add keyed header-protection keystream to yip-wire

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `Codec` implementing `WireCodec` (frame + deframe)

**Files:**
- Modify: `crates/yip-wire/src/lib.rs`

**Interfaces:**
- Consumes: `auth_tag`, `keystream`, `xor_in_place`, `write_header`, `read_header`, `subtle`.
- Produces:
  - `pub struct Codec { auth_key: [u8; 16], hp_key: [u8; 16] }`
  - `impl Codec { pub fn new(auth_key: [u8; 16], hp_key: [u8; 16]) -> Self }`
  - `impl WireCodec for Codec` with `frame`/`deframe` per the trait.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn codec_roundtrips_a_frame() {
    let codec = Codec::new([4u8; 16], [5u8; 16]);
    let frame = Frame {
        conn_tag: 0xDEAD_BEEF_0000_0001,
        object_id: 7,
        payload_id: [1, 2, 3, 4],
        flags: 0b0000_0011,
        payload: b"the quick brown fox".to_vec(),
    };
    let wire = codec.frame(&frame);
    assert!(wire.len() >= MIN_FRAME);
    assert_eq!(codec.deframe(&wire).unwrap(), frame);
}

#[test]
fn codec_rejects_tampered_frame() {
    let codec = Codec::new([4u8; 16], [5u8; 16]);
    let frame = Frame {
        conn_tag: 1, object_id: 1, payload_id: [0; 4], flags: 0,
        payload: b"payload".to_vec(),
    };
    let mut wire = codec.frame(&frame);
    let last = wire.len() - 1;
    wire[last] ^= 0x01; // flip a payload/tag bit
    assert_eq!(codec.deframe(&wire), Err(WireError::AuthFailed));
}

#[test]
fn codec_rejects_short_datagram() {
    let codec = Codec::new([4u8; 16], [5u8; 16]);
    assert_eq!(codec.deframe(&[0u8; MIN_FRAME - 1]), Err(WireError::Malformed));
}

#[test]
fn codec_has_no_constant_header_bytes() {
    // Two frames identical except conn_tag must not share a plaintext-looking
    // header prefix on the wire (header is protected).
    let codec = Codec::new([4u8; 16], [5u8; 16]);
    let base = Frame { conn_tag: 0, object_id: 0, payload_id: [0; 4], flags: 0, payload: vec![] };
    let wire = codec.frame(&base);
    // The first 15 wire bytes are the protected all-zero header; they must not be all zero.
    assert_ne!(&wire[..HEADER_LEN], &[0u8; HEADER_LEN]);
}
```

- [ ] **Step 2: Run them — expect failure**

Run: `cargo test -p yip-wire codec_`
Expected: FAIL (`Codec` undefined).

- [ ] **Step 3: Implement `Codec`**

Add the `subtle` import at the top (`use subtle::ConstantTimeEq;`) and append:

```rust
/// Wire codec: frames `Frame`s with a SipHash coverage-auth tag and keyed
/// header protection. Keys are injected (real session keys arrive in M3).
pub struct Codec {
    auth_key: [u8; 16],
    hp_key: [u8; 16],
}

impl Codec {
    /// Construct a codec from a 16-byte auth key and a 16-byte header-protection key.
    pub fn new(auth_key: [u8; 16], hp_key: [u8; 16]) -> Self {
        Self { auth_key, hp_key }
    }
}

impl WireCodec for Codec {
    fn frame(&self, frame: &Frame) -> Vec<u8> {
        let header = write_header(frame);
        let mut out = Vec::with_capacity(HEADER_LEN + frame.payload.len() + TAG_LEN);
        out.extend_from_slice(&header);
        out.extend_from_slice(&frame.payload);
        // Authenticate header‖payload, then append the tag.
        let tag = auth_tag(&self.auth_key, &out);
        out.extend_from_slice(&tag);
        // Header-protect: XOR a keyed mask (seeded by the tag) over the header.
        let mask = keystream(&self.hp_key, &tag, HEADER_LEN);
        xor_in_place(&mut out[..HEADER_LEN], &mask);
        out
    }

    fn deframe(&self, datagram: &[u8]) -> Result<Frame, WireError> {
        if datagram.len() < MIN_FRAME {
            return Err(WireError::Malformed);
        }
        let tag = &datagram[datagram.len() - TAG_LEN..];
        // Recover the header by removing the keyed mask (seeded by the tag).
        let mask = keystream(&self.hp_key, tag, HEADER_LEN);
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&datagram[..HEADER_LEN]);
        xor_in_place(&mut header, &mask);
        let payload = &datagram[HEADER_LEN..datagram.len() - TAG_LEN];
        // Recompute the tag over recovered-header‖payload and compare in constant time.
        let mut authed = Vec::with_capacity(HEADER_LEN + payload.len());
        authed.extend_from_slice(&header);
        authed.extend_from_slice(payload);
        let expected = auth_tag(&self.auth_key, &authed);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(WireError::AuthFailed);
        }
        let (conn_tag, object_id, payload_id, flags) = read_header(&header);
        Ok(Frame { conn_tag, object_id, payload_id, flags, payload: payload.to_vec() })
    }
}
```

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yip-wire`
Expected: all tests pass. Then `cargo clippy -p yip-wire --all-targets -- -D warnings` — clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-wire/src/lib.rs
git commit -m "Implement WireCodec frame and deframe in yip-wire

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Wire the fuzz target to real `deframe`

**Files:**
- Modify: `crates/yip-wire/fuzz/fuzz_targets/deframe.rs`

**Interfaces:**
- Consumes: `yip_wire::{Codec, WireCodec}`.
- Produces: a fuzz target that constructs a fixed-key `Codec` and asserts `deframe` never panics on arbitrary input; and that any datagram it *accepts* re-frames to a datagram that deframes equal (round-trip on accepted inputs).

- [ ] **Step 1: Replace the no-op fuzz target**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use yip_wire::{Codec, WireCodec};

// deframe must never panic on arbitrary bytes. For inputs it accepts, the
// parsed frame must re-frame and deframe back to an equal frame.
fuzz_target!(|data: &[u8]| {
    let codec = Codec::new([0x11; 16], [0x22; 16]);
    if let Ok(frame) = codec.deframe(data) {
        let reframed = codec.frame(&frame);
        let again = codec.deframe(&reframed).expect("re-framed frame must deframe");
        assert_eq!(frame, again);
    }
});
```

- [ ] **Step 2: Build the fuzz target**

Run (from `crates/yip-wire/fuzz`): `cargo +nightly fuzz build`
Expected: builds successfully.

- [ ] **Step 3: Smoke-run the fuzzer briefly**

Run (from `crates/yip-wire/fuzz`): `cargo +nightly fuzz run deframe -- -runs=200000 -max_total_time=30`
Expected: completes with no crash (`Done ... runs`). If `cargo-fuzz`/nightly is unavailable in the environment, record that and rely on the CI fuzz job; the target must at least `fuzz build`.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-wire/fuzz/fuzz_targets/deframe.rs
git commit -m "Fuzz yip-wire deframe against the real codec

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Coverage gate + changelog

**Files:**
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: the full `yip-wire` test suite.
- Produces: confirmed ≥90% line coverage on `yip-wire`; a changelog entry.

- [ ] **Step 1: Verify coverage meets the bar**

Run: `cargo llvm-cov --package yip-wire --fail-under-lines 90 --summary-only`
Expected: exits 0. If any function is under-covered (e.g. an error branch), add a focused unit test for it and re-run until ≥90%.

- [ ] **Step 2: Add the changelog entry**

Under `## [Unreleased]` → `### Added` in `CHANGELOG.md`, append:

```markdown
- `yip-wire` frame codec: header serialization, SipHash coverage-auth tag, and
  keyed header protection, with fuzzing of the deframe path.
```

- [ ] **Step 3: Run the full local gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo shear`
Expected: all clean.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "Record yip-wire codec in changelog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (M2 slice):** frame serialization ✓ (T1); coverage-auth tag ✓ (T2); keyed header-protection / no-constant-bytes ✓ (T3, T4 `codec_has_no_constant_header_bytes`); `WireCodec::frame`/`deframe` with auth-fail + malformed handling ✓ (T4); fuzzing of deframe ✓ (T5); ≥90% coverage ✓ (T6). Deferred-by-design (noted in the plan, not gaps): the optional `object_size` descriptor, transport-context (NAT) coverage selection, and binding header protection to session keys — all land with `yip-crypto`/`yip-io` in later milestones.

**Placeholder scan:** every code/command step is concrete; the "deferred to M3/later" notes are accurate forward-references, not missing plan content.

**Type consistency:** `Frame` fields (`conn_tag: u64`, `object_id: u16`, `payload_id: [u8;4]`, `flags: u8`, `payload: Vec<u8>`) are used identically across `write_header`, `read_header`, `Codec::frame`, `Codec::deframe`, and every test. `auth_tag` returns `[u8; TAG_LEN]`; `keystream` returns `Vec<u8>` of length `n`; `WireError::{AuthFailed, Malformed}` match the M1 enum.

**Definition of done for M2:** `cargo test --workspace` green; `yip-wire` ≥90% covered; fuzz target builds and runs clean; whole-workspace fmt/clippy/shear green; CI passes on push.
