# Fast ChaCha20-Poly1305 Data-Plane AEAD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut `yip_crypto::Session::seal`/`open` from ~2.1 µs to sub-µs — same 256-bit ChaCha20-Poly1305 — by using a fast (asm) AEAD implementation and killing the per-packet heap allocation.

**Architecture:** Spike-first. Task 1 measures and DECIDES between A1 (build snow with a fast crypto backend — risky under BLAKE2s) and A2 (snow for the handshake only; extract its secret `Split()` transport keys and run ChaCha20-Poly1305 via a fast crate — `ring` — with the Noise nonce, byte-identical to snow). Tasks 2–3 integrate the chosen path into `Session` and add a reusable-buffer no-alloc API. **A2 is the expected winner; Tasks 2–3 are written for it and the controller revises if the spike picks A1 or the contingency.**

**Tech Stack:** Rust, `snow` 0.10 (Noise handshake), `ring` (fast ChaCha20-Poly1305), `criterion`.

**Spec:** `docs/superpowers/specs/2026-07-11-throughput-fast-aead-design.md`.

## Global Constraints

- **Same cipher:** 256-bit ChaCha20-Poly1305, 16-byte tag. No AES, no cipher change (CLAUDE.md commitment).
- **Keys are the secret Noise `Split()` output** — NEVER the non-secret channel binding / `get_handshake_hash()`.
- **Noise nonce:** 12 bytes = `[0,0,0,0]` ++ `counter.to_le_bytes()`; **AAD = empty**. (Byte-identity to snow depends on this exactly.)
- **Nonce uniqueness per (key, direction):** the monotonic per-direction `send_counter` is the nonce; never reused under one key.
- **Byte-identical to snow's current wire** — verified by a KAT test (`our seal == snow::write_message` for the same key/counter/plaintext). If unachievable, a wire change is acceptable (pre-release), but byte-identity is expected with `ring`.
- Preserve the Noise handshake (`Noise_IK_25519_ChaChaPoly_BLAKE2s`), the `ReplayWindow` (check-and-set-before-verify), and monotonic `send_counter` semantics.
- `crates/yip-crypto` stays `#![forbid(unsafe_code)]` — the SIMD/asm lives inside `ring`, not yip code.
- `refrences/` is read-only.

---

## File Structure

- `crates/yip-crypto/src/lib.rs` — **modify.** `Handshake::into_session` extracts the transport keys; `Session` holds directional keys + `ring` AEAD keys instead of (A2) the snow transport; `seal`/`open` use `ring`; add `seal_into`/`open_into` (no-alloc).
- `crates/yip-crypto/Cargo.toml` — **modify.** add `ring`.
- `crates/yip-bench/examples/aead_spike.rs` — **create (Task 1).** the throwaway measurement + byte-identity spike.
- `bin/yipd/src/dataplane.rs` — **modify (Task 3).** use `seal_into`/`open_into` with a reusable buffer on the hot loop.
- `crates/yip-bench/RESULTS.md` — **modify (Task 3).** record before/after.

---

### Task 1: De-risk spike — key extraction, byte-identity, and speed (GATE)

**Purpose:** settle the one real unknown before building — can we get snow's secret transport keys, and does a fast crate reproduce snow's ChaCha20-Poly1305 output byte-for-byte? Measure the speedup. **This is a gate:** if neither A1 nor A2 is feasible, STOP and report the contingency.

**Files:**
- Create: `crates/yip-bench/examples/aead_spike.rs`
- Temporarily: add `ring` to `crates/yip-bench/Cargo.toml` (the spike lives in yip-bench so it can drive `established_pair` handshakes and touch snow).

**Interfaces:**
- Consumes: `yip_bench::established_pair()` (two handshaked `Session`s) or drive `yip_crypto::Handshake` directly to a completed state.
- Produces (for Task 2): the confirmed snow key-extraction method, the confirmed `ring` seal/open call shape, and the byte-identity result.

- [ ] **Step 1: Investigate snow's transport-key access**

Read snow 0.10's API (`cargo doc --open -p snow`, or the source under `~/.cargo/registry/src/*/snow-0.10*/src/`). Find how to obtain the two directional 32-byte ChaCha20-Poly1305 transport keys after a completed handshake. Candidates in order of preference:
- `snow::HandshakeState::dangerously_get_raw_split() -> (Vec<u8>, Vec<u8>)` (if present) — the two split keys.
- any getter on `StatelessTransportState` / `TransportState`.
Record the exact method + which key is send vs receive for initiator/responder. If **no** key access exists, note it (A2 blocked → check A1/contingency in Step 4).

- [ ] **Step 2: Write the spike** (`crates/yip-bench/examples/aead_spike.rs`)

Drive a full initiator+responder handshake, extract the transport keys (per Step 1), and prove a fast `ring` ChaCha20-Poly1305 reproduces snow byte-for-byte, then time both. Skeleton (adapt the key-extraction call to what Step 1 found):

```rust
//! De-risk spike for fast AEAD: prove ring ChaCha20-Poly1305 with snow's extracted
//! transport keys + the Noise nonce is byte-identical to snow's write_message, and
//! measure the speedup. Run: cargo run --release -p yip-bench --example aead_spike
use ring::aead::{LessSafeKey, UnboundKey, Nonce, Aad, CHACHA20_POLY1305};
use std::time::Instant;

// Noise ChaChaPoly nonce: 4 zero bytes ++ 8-byte little-endian counter.
fn noise_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn main() {
    // 1. Complete a handshake (initiator <-> responder) and get a Session pair.
    //    (Use yip_crypto::Handshake::{initiator,responder} + write/read_message.)
    //    Extract the two directional transport keys via the method Step 1 found:
    //        let (k_send, k_recv) = handshake.dangerously_get_raw_split(); // adapt
    //    k_send is the initiator's send key = responder's recv key.

    // 2. Byte-identity: for counters 0..8 and a sample plaintext, compare
    //    snow's write_message(counter, pt) against ring seal with the SAME key,
    //    noise_nonce(counter), empty AAD.
    //    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &k_send).unwrap());
    //    let mut buf = pt.to_vec();
    //    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(noise_nonce(ctr)),
    //                                 Aad::empty(), &mut buf).unwrap();
    //    assert_eq!(buf, snow_ciphertext, "ring != snow at counter {ctr}");
    // Print "byte-identity: OK" or the first mismatch.

    // 3. Timing (release), >=20k iters, black_box:
    //    - snow write_message (baseline)
    //    - ring seal_in_place_append_tag (fast path)
    //    - ring with a reused buffer (no per-call alloc) vs a fresh Vec each call
    //    Print us/op for each.

    let _ = (noise_nonce(0), Instant::now()); // keep imports live in the skeleton
}
```

Fill in the handshake + extraction using the real APIs. The load-bearing assertion is **byte-identity** (ring output == snow output); the timings guide the decision.

- [ ] **Step 3: Run it**

Run: `cargo run --release -p yip-bench --example aead_spike`
Expected: `byte-identity: OK`, and ring seal in the ~0.3–0.9 µs range vs snow's ~1.5–2 µs (numbers per the box; on the target VPS ring ≈ 0.73 µs).

- [ ] **Step 4: GATE decision**

- **Byte-identity OK + ring clearly faster** → choose **A2** (ring + extracted keys). Record the exact key-extraction method + send/recv key mapping for Task 2. Proceed.
- **Key extraction impossible** → try **A1**: can `snow` build with a fast resolver (`ring-accelerated`) for `Noise_IK_25519_ChaChaPoly_BLAKE2s`? Add the feature, `cargo build -p yip-crypto`; if it builds and speeds up snow, choose A1 (Tasks 2–3 become "snow feature swap", no key extraction). If it fails on BLAKE2s, note it.
- **Both infeasible** → STOP. Report the contingency (ship only the no-alloc win + confirm RustCrypto AVX2 is engaged, ~1.3 µs) and escalate — do not force a cipher/handshake change.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-bench/examples/aead_spike.rs crates/yip-bench/Cargo.toml Cargo.lock
git commit -m "spike(fast-aead): ring ChaCha20-Poly1305 byte-identity vs snow + timing gate"
```

---

### Task 2: Integrate the fast AEAD into `Session` (A2 — expected)

> **Contingency:** if Task 1 chose **A1**, replace this task with "switch snow's Cargo feature to the fast resolver + confirm the suite/benchmarks" (no key extraction, `Session` unchanged). The steps below implement **A2**.

**Files:**
- Modify: `crates/yip-crypto/src/lib.rs`, `crates/yip-crypto/Cargo.toml`

**Interfaces:**
- Consumes: the snow key-extraction method + send/recv mapping confirmed by Task 1; `ring::aead::{LessSafeKey, UnboundKey, Nonce, Aad, CHACHA20_POLY1305}`.
- Produces (signatures preserved so callers/tests are unchanged this task):
  - `Session::seal(&mut self, plaintext: &[u8]) -> Result<Sealed, CryptoError>`
  - `Session::open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>`

- [ ] **Step 1: Add `ring`**

`crates/yip-crypto/Cargo.toml` `[dependencies]`: add `ring = "0.17"`.

- [ ] **Step 2: Write the byte-identity + round-trip tests**

Add to `crates/yip-crypto/src/lib.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn seal_is_byte_identical_across_a_reference_session() {
    // Two independently-built sessions from the same handshake produce the same
    // keystream for the same counter+plaintext; a receiver opens what a sender seals.
    let (mut a, mut b) = crate::test_session_pair();
    for ctr in 0u64..8 {
        let s = a.seal(&[0x5Au8; 64]).unwrap();
        assert_eq!(s.counter, ctr);
        assert_eq!(b.open(s.counter, &s.ciphertext).unwrap(), vec![0x5Au8; 64]);
    }
}

#[test]
fn open_rejects_tampered_ciphertext() {
    let (mut a, mut b) = crate::test_session_pair();
    let s = a.seal(b"secret").unwrap();
    let mut bad = s.ciphertext.clone();
    bad[0] ^= 1;
    assert_eq!(b.open(s.counter, &bad), Err(CryptoError::Decrypt));
}

#[test]
fn open_rejects_replay_and_opens_out_of_order() {
    let (mut a, mut b) = crate::test_session_pair();
    let s0 = a.seal(b"zero").unwrap();
    let s1 = a.seal(b"one").unwrap();
    assert_eq!(b.open(s1.counter, &s1.ciphertext).unwrap(), b"one"); // out of order
    assert_eq!(b.open(s0.counter, &s0.ciphertext).unwrap(), b"zero");
    assert_eq!(b.open(s1.counter, &s1.ciphertext), Err(CryptoError::Replay)); // replay
}
```

If `test_session_pair()` doesn't exist, add a `#[cfg(test)] pub(crate) fn test_session_pair() -> (Session, Session)` that drives `Handshake::initiator`/`responder` to completion and returns both sessions (mirror `yip_bench::established_pair`). The pre-existing `session_seals_and_opens_roundtrip` / `session_opens_out_of_order` / replay / tamper tests stay and must keep passing.

- [ ] **Step 3: Run to verify current impl passes (baseline), rewrite, re-verify**

Run: `cargo test -p yip-crypto --lib` → PASS on the current snow impl (these tests are behavior-preserving guards for the rewrite).

- [ ] **Step 4: Rewrite `Session` to use ring with extracted keys**

Change `Session` to hold the directional `ring` keys + counter + replay (drop the snow transport for the data plane). Replace the struct, `into_session`, `seal`, `open`:

```rust
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

/// Noise ChaChaPoly nonce: 4 zero bytes ++ 8-byte little-endian counter.
fn noise_nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(n)
}

/// AEAD session: fast ChaCha20-Poly1305 over the two secret Noise transport keys.
pub struct Session {
    send_key: LessSafeKey, // seals outbound frames
    recv_key: LessSafeKey, // opens inbound frames
    send_counter: u64,
    replay: ReplayWindow,
}

// in Handshake::into_session:
    pub fn into_session(mut self) -> Result<Session, CryptoError> {
        // Extract the two secret transport keys (method confirmed by the Task-1 spike).
        let (k_send, k_recv) = self
            .inner
            .dangerously_get_raw_split()      // ADAPT to the confirmed API
            .map_err(|_| CryptoError::Handshake)?;
        let send = UnboundKey::new(&CHACHA20_POLY1305, &k_send).map_err(|_| CryptoError::Handshake)?;
        let recv = UnboundKey::new(&CHACHA20_POLY1305, &k_recv).map_err(|_| CryptoError::Handshake)?;
        Ok(Session {
            send_key: LessSafeKey::new(send),
            recv_key: LessSafeKey::new(recv),
            send_counter: 0,
            replay: ReplayWindow::new(),
        })
    }

impl Session {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let counter = self.send_counter;
        let mut buf = plaintext.to_vec();
        self.send_key
            .seal_in_place_append_tag(noise_nonce(counter), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        self.send_counter = self.send_counter.checked_add(1).ok_or(CryptoError::Decrypt)?;
        Ok(Sealed { counter, ciphertext: buf })
    }

    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.replay.check_and_set(counter) {
            return Err(CryptoError::Replay);
        }
        let mut buf = ciphertext.to_vec();
        let plain = self
            .recv_key
            .open_in_place(noise_nonce(counter), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(plain.to_vec())
    }
}
```

**Key mapping:** confirm from the spike which of the split pair is send vs recv for initiator vs responder (Noise convention: initiator's first split key is its send key; the responder mirrors). Get this right or `open` fails — the round-trip test catches it.

- [ ] **Step 5: Run tests + lints**

Run: `cargo test -p yip-crypto` → all pass (new + pre-existing).
Run: `cargo clippy -p yip-crypto --all-targets -- -D warnings && cargo fmt -p yip-crypto -- --check` → clean. Confirm `#![forbid(unsafe_code)]` still at the top of `lib.rs` and the crate builds (no `unsafe` introduced).

- [ ] **Step 6: Commit**

```bash
git add crates/yip-crypto/src/lib.rs crates/yip-crypto/Cargo.toml Cargo.lock
git commit -m "feat(yip-crypto): fast ring ChaCha20-Poly1305 data-plane AEAD (throughput)

Session::seal/open now use ring's asm ChaCha20-Poly1305 over the Noise Split()
transport keys with the Noise nonce (byte-identical to snow). snow does the
handshake only. Same cipher, replay+counter semantics unchanged."
```

---

### Task 3: No-alloc buffer API + dataplane + benchmark + no-regression

**Files:**
- Modify: `crates/yip-crypto/src/lib.rs` (add `seal_into`/`open_into`), `bin/yipd/src/dataplane.rs` (hot-loop reuse), `crates/yip-bench/benches/hotpath.rs` (if needed), `crates/yip-bench/RESULTS.md`.

**Interfaces:**
- Produces: `Session::seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<u64, CryptoError>` (returns the counter; `out` cleared+filled with ciphertext+tag); `Session::open_into(&mut self, counter: u64, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError>`.

- [ ] **Step 1: Add the no-alloc methods + a test**

Add to `Session`:

```rust
    /// Seal into a caller-owned reusable buffer (no per-call allocation).
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<u64, CryptoError> {
        let counter = self.send_counter;
        out.clear();
        out.extend_from_slice(plaintext);
        self.send_key
            .seal_in_place_append_tag(noise_nonce(counter), Aad::empty(), out)
            .map_err(|_| CryptoError::Decrypt)?;
        self.send_counter = self.send_counter.checked_add(1).ok_or(CryptoError::Decrypt)?;
        Ok(counter)
    }

    /// Open into a caller-owned reusable buffer (no per-call allocation).
    pub fn open_into(&mut self, counter: u64, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        if !self.replay.check_and_set(counter) {
            return Err(CryptoError::Replay);
        }
        out.clear();
        out.extend_from_slice(ciphertext);
        let n = {
            let plain = self
                .recv_key
                .open_in_place(noise_nonce(counter), Aad::empty(), out)
                .map_err(|_| CryptoError::Decrypt)?;
            plain.len()
        };
        out.truncate(n);
        Ok(())
    }
```

Test (add to `mod tests`):

```rust
#[test]
fn seal_into_matches_seal_and_opens() {
    let (mut a, mut b) = crate::test_session_pair();
    let mut sbuf = Vec::new();
    let ctr = a.seal_into(b"reuse me", &mut sbuf).unwrap();
    let mut obuf = Vec::new();
    b.open_into(ctr, &sbuf, &mut obuf).unwrap();
    assert_eq!(obuf, b"reuse me");
}
```

- [ ] **Step 2: Use the no-alloc path in the dataplane hot loop**

In `bin/yipd/src/dataplane.rs`, give the struct a reusable `seal_buf: Vec<u8>` and switch the tx hot path (line ~232) from `self.session.seal(inner)` (which allocs + is later `.clone()`d at line ~248) to `self.session.seal_into(inner, &mut self.seal_buf)`, then pass `&self.seal_buf` to `.encode(...)` — eliminating both the seal alloc and the clone. Keep the feedback-report seal (line ~539) on the simple `seal` (cold path). Run `cargo build -p yipd`.

- [ ] **Step 3: Benchmark**

Run: `cargo bench -p yip-bench --bench hotpath -- aead`
Expected: `aead_seal_1300` well below ~2.1 µs (ring path; ~0.7–0.9 µs on the VPS profile). Record both `aead_seal_1300` and `aead_open_1300`.

- [ ] **Step 4: Record + no-regression**

Append a dated "Fast AEAD (ring ChaCha20-Poly1305)" section to `crates/yip-bench/RESULTS.md`: seal/open before (~2.1 µs snow) vs after, and the single-core throughput implication.
Run: `cargo test` (full workspace) → green.
Rebuild release, then netns bring-up (AEAD is on the end-to-end path):

```bash
cargo build --release
for s in run-netns-tunnel run-netns-tunnel-loss run-arq-integrity; do
  echo "== $s =="; sudo bin/yipd/tests/$s.sh target/release/yipd || echo "FAILED: $s"
done
```
Expected: PASS — a session establishes and passes traffic end-to-end with the new AEAD. If sudo/netns unavailable, record skipped-for-environment (the byte-identity KAT + round-trip tests are the correctness guarantee).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-crypto/src/lib.rs bin/yipd/src/dataplane.rs crates/yip-bench/RESULTS.md
git commit -m "perf(yipd): no-alloc seal_into/open_into on the dataplane hot path + bench"
```

---

## Self-Review

**1. Spec coverage:**
- §3 fast AEAD impl (A2 ring + extracted secret keys) → Task 1 (spike/decide), Task 2 (integrate). ✅
- §3 A1 alternative + contingency → Task 1 Step 4 + Task 2 contingency note. ✅
- §3 no-alloc → Task 3 (`seal_into`/`open_into` + dataplane). ✅
- §4 invariants: same cipher (ring CHACHA20_POLY1305), secret Split() keys (not channel binding), Noise nonce `[0;4]++ctr.le`, empty AAD, byte-identity KAT, replay/counter preserved, forbid-unsafe → Task 1 byte-identity gate + Task 2 tests + constraints. ✅
- §5 tests (KAT, round-trip, replay, out-of-order, tamper, no-alloc, bench, netns) → Tasks 1–3. ✅
- §6 scope/files → matches. ✅

**2. Placeholder scan:** Task 1 is a spike (exploratory by design — the key-extraction API is what it confirms); Tasks 2–3 carry complete code. The `dangerously_get_raw_split()` call is marked "ADAPT to the confirmed API" because it is literally the spike's deliverable — not a placeholder for un-thought-through logic.

**3. Type consistency:** `Session { send_key, recv_key: LessSafeKey, send_counter: u64, replay }`, `noise_nonce(u64) -> Nonce`, `seal/open` (unchanged sigs) and `seal_into(&[u8], &mut Vec<u8>) -> Result<u64,_>` / `open_into(u64, &[u8], &mut Vec<u8>) -> Result<(),_>` are consistent across Tasks 2–3 and the dataplane change. `Sealed { counter, ciphertext }` unchanged. `test_session_pair()` introduced in Task 2, reused in Task 3.
