# Zero-Allocation PQNoise State Machine and BLAKE3 Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `snow`, `blake2` v0.10.6, `hkdf`, and `hmac` with a bespoke, zero-allocation `PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3` state machine in `crates/yip-crypto`, and migrate overlay addressing and rendezvous identity derivation to BLAKE3.

**Architecture:** Implement a stack-allocated `SymmetricState` and `HandshakeState` directly in `crates/yip-crypto` utilizing BLAKE3's native keyed mode and XOF stream with 1-byte domain tags (`0x01` MixKey, `0x02` MixKeyAndHash, `0x03` Split, `0x04` Rekey). Flight 1 transmits an unencrypted 768-byte ML-KEM-512 ciphertext bound by a mandatory Step 6 AEAD tag under `k_3`, while Responder decapsulation key material is referenced on the stack. Overlay addresses and rendezvous tokens migrate to `blake3::derive_key` context separation, while `crates/yip-wire` and `crates/yip-obf` retain `SipHash-1-3`.

**Tech Stack:** Rust 2021 edition, `blake3 = { version = "1.8", default-features = false, features = ["zeroize"] }`, `ring = "0.17"`, `ml-kem = "0.3"`, `zeroize = "1.8"`, `subtle = "2.6"`.

## Global Constraints

- Strictly ZERO emojis in any commit message, code comment, test description, or documentation.
- Preserve `#![forbid(unsafe_code)]` across all `yip` workspace crates.
- No dynamic heap allocations (`Box<dyn ...>`, `Vec<u8>`) on the handshake execution path.
- Keep `SipHash-1-3` in `crates/yip-wire` and `crates/yip-obf` (do not replace with BLAKE3).
- Disable `rayon` and `traits-preview` features on `blake3`.
- All tests must pass `-D warnings`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`, and `cargo deny check`.

---

### Task 1: Workspace Dependency Purge and BLAKE3 Configuration

**Files:**
- Modify: `Cargo.toml:1-120`
- Modify: `crates/yip-crypto/Cargo.toml:1-35`
- Modify: `crates/yip-rendezvous/Cargo.toml:1-35`
- Modify: `bin/yipd/Cargo.toml:1-60`

**Interfaces:**
- Consumes: `blake3` crate on `crates.io`.
- Produces: Workspace-wide `blake3` dependency with `features = ["zeroize"]`; removal of `snow`, `blake2`, `hkdf`, and `hmac`.

- [ ] **Step 1: Write Cargo.toml dependency declarations**
  Update root `Cargo.toml` `[workspace.dependencies]`:
  - Add `blake3 = { version = "1.8", default-features = false, features = ["zeroize"] }`
  - Remove `blake2 = "=0.10.6"`
  - Remove `snow = "0.10.0"`
  Update `crates/yip-crypto/Cargo.toml`:
  - Remove `snow`
  - Add `blake3 = { workspace = true }`
  - Add `subtle = "2.6"` (for constant-time all-zero point checks)
  Update `crates/yip-rendezvous/Cargo.toml`:
  - Replace `blake2 = { workspace = true }` with `blake3 = { workspace = true }`
  Update `bin/yipd/Cargo.toml`:
  - Replace `blake2 = { workspace = true }` with `blake3 = { workspace = true }`

- [ ] **Step 2: Run cargo check to inspect initial dependency resolution**
  Run: `cargo check -p yip-crypto`
  Confirm `snow` and `blake2` are unlinked in `yip-crypto`.

- [ ] **Step 3: Commit dependency changes**
  Commit: `build: replace snow and blake2 with blake3 in workspace dependencies`

---

### Task 2: Core SymmetricState and Domain-Separated BLAKE3 XOF Ratchet

**Files:**
- Create: `crates/yip-crypto/src/symmetric.rs`
- Modify: `crates/yip-crypto/src/lib.rs:1-60`
- Test: `crates/yip-crypto/tests/symmetric_tests.rs`

**Interfaces:**
- Consumes: `blake3::Hasher`, `zeroize::{Zeroize, ZeroizeOnDrop}`.
- Produces: `pub struct SymmetricState`, `mix_hash`, `mix_key`, `mix_key_and_hash`, `split`, `rekey`.

- [ ] **Step 1: Write unit tests for SymmetricState**
  Create `crates/yip-crypto/tests/symmetric_tests.rs`:
  - Test protocol name initialization matches expected BLAKE3 hash.
  - Test `mix_hash` updates `h` deterministically.
  - Test `mix_key` (tag `0x01`) ratchets `ck` and emits 32-byte key `k`.
  - Test `mix_key_and_hash` (tag `0x02`) updates `ck`, mixes `temp_h` into `h`, and emits `k`.
  - Test `split` (tag `0x03`) derives two distinct directional transport keys.
  - Test `rekey` (tag `0x04`) derives deterministic forward-secrecy transport keys.
  - Test domain separation: verify that tag `0x01` output differs from tag `0x02` and `0x03` on identical input.

- [ ] **Step 2: Run tests to confirm failure**
  Run: `cargo test -p yip-crypto --test symmetric_tests` (fails because `symmetric.rs` does not exist yet).

- [ ] **Step 3: Implement SymmetricState in `crates/yip-crypto/src/symmetric.rs`**
  Implement:
  - `SymmetricState` with `ck: [u8; 32]`, `h: [u8; 32]`, deriving `Clone, Zeroize, ZeroizeOnDrop`.
  - `mix_hash(&mut self, data: &[u8])`: one-shot BLAKE3 compression.
  - `mix_key(&mut self, ikm: &[u8; 32]) -> [u8; 32]`: keyed hasher with `0x01` tag, 64-byte XOF fill, zeroizing scratch buffer before returning.
  - `mix_key_and_hash(&mut self, psk: &[u8; 32]) -> [u8; 32]`: keyed hasher with `0x02` tag, 96-byte XOF fill, zeroizing scratch buffer before returning.
  - `split(&self) -> ([u8; 32], [u8; 32])`: keyed hasher with `0x03` tag, 64-byte XOF fill, zeroizing scratch buffer.
  - `rekey(current_key: &[u8; 32]) -> [u8; 32]`: keyed hasher with `0x04` tag, 32-byte XOF fill.

- [ ] **Step 4: Run tests to confirm success**
  Run: `cargo test -p yip-crypto --test symmetric_tests`
  Confirm all tests pass cleanly.

- [ ] **Step 5: Commit SymmetricState implementation**
  Commit: `feat(crypto): implement zero-allocation SymmetricState with BLAKE3 XOF ratchet`

---

### Task 3: Native Zero-Allocation HandshakeState (`PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3`)

**Files:**
- Create: `crates/yip-crypto/src/handshake.rs`
- Modify: `crates/yip-crypto/src/lib.rs:1-120`
- Test: `crates/yip-crypto/tests/handshake_tests.rs`

**Interfaces:**
- Consumes: `SymmetricState`, `ring::agreement::X25519`, `ml_kem::kem::{Encapsulate, Decapsulate}`, `chacha20poly1305`, `subtle::ConstantTimeEq`.
- Produces: `InitiatorHandshake`, `ResponderHandshake`, `write_message_1`, `read_message_1`, `write_message_2`, `read_message_2`.

- [ ] **Step 1: Write integration tests for Flight 1 and Flight 2 handshake**
  Create `crates/yip-crypto/tests/handshake_tests.rs`:
  - Generate initiator static keypair and responder static keypairs (X25519 + ML-KEM-512).
  - Initiator executes `write_message_1` into fixed stack buffer (assert exact length: 864 bytes + payload).
  - Responder executes `read_message_1` with `dk: &[u8; 1632]`.
  - Responder executes `write_message_2` into fixed stack buffer (assert exact length: 48 bytes + payload).
  - Initiator executes `read_message_2`.
  - Both sides verify identical transport keys from `Split()`.
  - Test corruption: corrupting 1 byte in KEM ciphertext or static key tag causes immediate error and drops state.
  - Test low-order X25519 point: inject all-zero DH shared secret, assert `Error::InvalidKey`.

- [ ] **Step 2: Run tests to confirm failure**
  Run: `cargo test -p yip-crypto --test handshake_tests`

- [ ] **Step 3: Implement `HandshakeState` in `crates/yip-crypto/src/handshake.rs`**
  Implement:
  - Protocol constant: `b"PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3"`.
  - Prologue mixing: `MixHash(prologue)`, `MixHash(rs_x25519)`, `MixHash(rs_mlkem512_ek)`.
  - Flight 1:
    - Initiator generates ephemeral X25519 $e_i$, computes `es` (with `ConstantTimeEq` non-zero check), encrypts static key $s_i$ under $k_1$ with Poly1305 tag, computes `ss`, encapsulates ML-KEM-512 producing $(ct, ss_{\text{kem}})$, writes $ct$ in plaintext, mixes $ct$ into $h$, mixes $ss_{\text{kem}}$ into $ck$ emitting $k_3$, and encrypts payload with mandatory 16-byte Poly1305 tag under $k_3$.
  - Responder `read_message_1`:
    - Takes `dk: &[u8; 1632]` directly. Parses $e_i$, executes `es`, decrypts $s_i$, executes `ss`, decapsulates $ct$ using $dk$, ratchets $ss_{\text{kem}}$, and decrypts payload. Atomic validation: on any MAC failure, intermediate state is wiped and error returned.
  - Flight 2:
    - Responder generates $e_r$, executes `ee`, `se`, `psk` (`MixKeyAndHash`), encrypts payload, and calls `split()`.
  - Initiator `read_message_2`:
    - Parses $e_r$, executes `ee`, `se`, `psk`, verifies payload MAC, and calls `split()`.

- [ ] **Step 4: Run tests and verify zero allocations**
  Run: `cargo test -p yip-crypto --test handshake_tests`
  Confirm all tests pass cleanly.

- [ ] **Step 5: Commit HandshakeState implementation**
  Commit: `feat(crypto): implement native zero-alloc PQNoise handshake state machine`

---

### Task 4: Transport Session, Rekeying, and `crates/yip-crypto` Public API

**Files:**
- Modify: `crates/yip-crypto/src/session.rs:1-150`
- Modify: `crates/yip-crypto/src/lib.rs:1-120`
- Test: `crates/yip-crypto/tests/pqnoise_vectors.rs`

**Interfaces:**
- Consumes: `InitiatorHandshake`, `ResponderHandshake`, `SymmetricState::rekey`.
- Produces: Updated `Session`, `SessionPair`, `ChaCha20Poly1305Cipher`, `rekey_transport_key`.

- [ ] **Step 1: Write deterministic golden vector tests**
  Create `crates/yip-crypto/tests/pqnoise_vectors.rs`:
  - Run handshake with deterministic mock seeds for $s_i, rs_i, e_i, e_r, \text{PSK}$.
  - Record and assert intermediate hex values of $ck, h, k_1, k_2, k_3, k_{\text{send}}, k_{\text{recv}}$.
  - Test 120-second epoch rekeying: assert deterministic next key from `rekey(key)`.

- [ ] **Step 2: Update `crates/yip-crypto/src/session.rs` and `lib.rs`**
  - Wire native `split()` output into `SessionPair` containing directional `ChaCha20Poly1305Cipher` engines.
  - Implement 120s epoch rekeying using `SymmetricState::rekey` (`0x04` tag).
  - Remove all remaining `snow` references and exports from `crates/yip-crypto/src/lib.rs`.

- [ ] **Step 3: Run all crypto crate tests**
  Run: `cargo test -p yip-crypto`
  Verify all unit and integration tests in `yip-crypto` pass.

- [ ] **Step 4: Commit transport session and rekeying updates**
  Commit: `refactor(crypto): wire native PQNoise transport session and 120s BLAKE3 rekey`

---

### Task 5: Overlay Address & Rendezvous Identity Migration

**Files:**
- Modify: `bin/yipd/src/addr.rs:1-80`
- Modify: `crates/yip-rendezvous/src/proto.rs:1-150`
- Modify: `bin/yipd/tests/run-netns-registration-hijack.sh:1-120`
- Test: `bin/yipd/src/addr.rs` tests
- Test: `crates/yip-rendezvous/src/proto.rs` tests

**Interfaces:**
- Consumes: `blake3::derive_key`, `blake3::keyed_hash`.
- Produces:
  - `pub fn derive_overlay_ipv6(public_key: &[u8; 32]) -> std::net::Ipv6Addr`
  - `pub fn derive_node_id(public_key: &[u8; 32]) -> [u8; 16]`
  - `pub fn compute_register_mac(key: &[u8; 32], payload: &[u8]) -> [u8; 16]`

- [ ] **Step 1: Write failing tests for BLAKE3 addressing and rendezvous**
  - In `bin/yipd/src/addr.rs`: add test verifying address derived with `OVERLAY_ADDR_CONTEXT_V2` (`"yip-v2-overlay-ipv6-addr"`).
  - In `crates/yip-rendezvous/src/proto.rs`: add test verifying `node_id` derived with `RENDEZVOUS_NODE_ID_CONTEXT_V2` (`"yip-v2-rendezvous-node-id"`) and 128-bit BLAKE3 registration MAC.

- [ ] **Step 2: Implement BLAKE3 address derivation in `bin/yipd/src/addr.rs`**
  - Replace `blake2::Blake2sVar` with `blake3::derive_key(OVERLAY_ADDR_CONTEXT_V2, public_key)`.
  - Set octet 0 to `0xfd`, octets 1..16 from `digest[0..15]`.

- [ ] **Step 3: Implement BLAKE3 rendezvous tokens in `crates/yip-rendezvous/src/proto.rs`**
  - Replace `blake2::Blake2sVar` with `blake3::derive_key(RENDEZVOUS_NODE_ID_CONTEXT_V2, public_key)`.
  - Replace BLAKE2s-MAC with `blake3::keyed_hash(key, payload)` truncated to 16 bytes.
  - Verify constant-time comparison via `subtle::ConstantTimeEq`.

- [ ] **Step 4: Update integration shell scripts**
  - Update `bin/yipd/tests/run-netns-registration-hijack.sh` to use Python `blake3` (or CLI/test utility) for mock token calculation.

- [ ] **Step 5: Run address and rendezvous tests**
  Run: `cargo test -p yip-rendezvous`
  Run: `cargo test -p yipd --bin yipd addr`
  Verify all tests pass.

- [ ] **Step 6: Commit addressing and rendezvous migration**
  Commit: `feat(addr, rendezvous): migrate overlay IPv6 and rendezvous identity to BLAKE3`

---

### Task 6: Full Workspace Integration, Cleanups, and CI Gates

**Files:**
- Modify: `bin/yipd/src/peer_manager/mod.rs:1-300`
- Modify: `bin/yipd/src/control.rs:1-300`
- Modify: `crates/yip-mesh/src/lib.rs:1-60`
- Modify: `docs/01-getting-started.md`
- Modify: `docs/03-architecture.md`
- Modify: `docs/04-security-and-threat-model.md`

**Interfaces:**
- Consumes: All updated crates.
- Produces: Fully unified, clean workspace passing all lints and tests.

- [ ] **Step 1: Update peer manager and control RPC cipher suite strings**
  - In `bin/yipd/src/control.rs` and `bin/yipd/src/peer_manager/mod.rs`: update cipher suite status string to `"PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3"`.

- [ ] **Step 2: Update documentation and SVG references**
  - Update `docs/01-getting-started.md`, `docs/03-architecture.md`, and `docs/04-security-and-threat-model.md` to document the v2 BLAKE3 overlay derivation and native PQNoise protocol.

- [ ] **Step 3: Run comprehensive workspace verification**
  Run: `cargo fmt -- --check`
  Run: `cargo clippy --workspace --all-targets -- -D warnings`
  Run: `cargo test --workspace`
  Run: `cargo deny check`
  Run: `cargo shear`

- [ ] **Step 4: Commit full workspace integration**
  Commit: `refactor(mesh): complete workspace cutover to native PQNoise and BLAKE3`
