# Throughput — Fast ChaCha20-Poly1305 Data-Plane AEAD — Design Spec

**Status:** draft (under review)
**Sub-project:** #4 (Throughput & Scalability). Lever 2 of the single-core-10-Gbit set
(cheap FEC ✓ → **fast AEAD** → AF_XDP/batched I/O). On main after P+Q FEC (70d8c8d).

---

## 1. Goal

Cut the data-plane AEAD (`yip_crypto::Session::seal`/`open`) from **~2.1 µs to sub-µs**
(~0.8 µs on the target VPS) — **same 256-bit ChaCha20-Poly1305 cipher**, a faster
implementation. No cipher change, no security-model change, Noise handshake untouched.

## 2. Why

Profiling puts AEAD seal at ~2.1 µs/packet — the dominant single-core cost now that P+Q FEC
made encode ~0.32 µs. Two causes, both fixable:

1. **Slow AEAD backend.** `Session::seal`/`open` (`crates/yip-crypto/src/lib.rs:209-244`) wrap
   `snow::StatelessTransportState::write_message`/`read_message`, which uses snow's default
   RustCrypto ChaCha20-Poly1305. On the target VPS (AMD Ryzen 9 3900X, 1 core, AVX2 + AES-NI,
   no AVX-512), `openssl speed` measures **asm ChaCha20-Poly1305 at 0.73 µs/1400 B** vs yip's
   ~2.1 µs — a ~3× implementation gap, entirely within the same cipher.
2. **Per-packet heap allocation.** `seal` and `open` each do `vec![0u8; …]` per call
   (lib.rs:211, 237) — ~0.2 µs/packet of allocator traffic, independent of the cipher.

Bandwidth is free and the box is 1-core, so single-core CPU is the throughput ceiling; AEAD
is the biggest remaining slice. This milestone is **CLAUDE.md-conformant**: "256-bit AEAD
data plane (ChaCha20-Poly1305 baseline)" is preserved verbatim — only the implementation gets
faster. **Post-quantum is a separate handshake-layer concern** (Rosenpass-style hybrid KEM);
symmetric 256-bit ChaCha20-Poly1305 is already quantum-resistant and untouched here.

## 3. Approach — spike-first, two candidates + one unconditional win

There is a real unknown (below), so **Task 1 is a measurement spike** that decides between
two candidates on the real VPS profile before we build the integration. Both keep
ChaCha20-Poly1305.

### A1 — faster snow crypto backend (minimal, byte-compatible)
Build snow with an asm/accelerated resolver (e.g. `ring-accelerated`) so snow's own
`write_message`/`read_message` use fast ChaCha20-Poly1305. Tiny diff, wire byte-identical.
**Risk:** yip's Noise params are `Noise_IK_25519_ChaChaPoly_BLAKE2s`, and `ring` provides no
**BLAKE2s** — snow's ring resolver may refuse to build/run for this pattern. The spike tries
it and measures; if it can't do BLAKE2s, A1 is out.

### A2 — own the data-plane AEAD with snow's *secret* transport keys (robust, byte-identical)
Use snow for the handshake **only**. After the handshake completes, **extract snow's raw
`Split()` transport keys** (the two directional 32-byte ChaCha20-Poly1305 keys — the actual
secret key material, via snow's raw-split API; the spike confirms the exact method) and run
`seal`/`open` with a fast ChaCha20-Poly1305 crate (`ring` or `aws-lc-rs`) directly.

- **Keys come from the secret `Split()` output — NOT from the channel binding / handshake
  hash.** The handshake hash (`get_handshake_hash()`) is *not secret* (a passive observer
  reconstructs it from the transcript ciphertexts), so it must never be used to derive
  encryption keys. Only the DH-derived `Split()` keys are secret.
- **Nonce = Noise's construction:** 12 bytes = `[0,0,0,0]` ++ `counter.to_le_bytes()`
  (Noise spec §11.4 for ChaChaPoly). **AAD = empty** (Noise transport messages carry no AD).
- With the *same* keys, *same* nonce, *same* cipher, and empty AAD, A2's output is
  **byte-identical** to snow's `write_message` — so it is wire-compatible AND cross-checkable
  against snow in tests (a byte-identity KAT gate).

### Unconditional: eliminate the per-packet allocation
Regardless of A1/A2, `seal`/`open` write into **caller-provided reusable buffers** instead of
`vec![0u8; …]`. New buffer-taking methods (e.g. `seal_into(&mut self, plaintext, out: &mut Vec<u8>)`)
or an internal scratch buffer owned by `Session`. ~0.2 µs/packet, always valid.

**Expected landing:** given BLAKE2s, **A2** is the likely winner (byte-identical, guaranteed
fast, snow limited to the handshake). The spike proves feasibility + speed rather than
guessing; if A1 unexpectedly works and is fast enough, its smaller diff wins.

**Contingency:** if the spike finds *both* A1 (snow can't use a fast backend for BLAKE2s) and
A2 (snow won't expose raw `Split()` keys) infeasible, it reports that and we ship the
unconditional no-alloc win plus confirming RustCrypto's AVX2 ChaCha20 backend is engaged
(a partial improvement, ~1.3 µs), then reassess — do not force a cipher/handshake change to
hit the number.

## 4. Security invariants (load-bearing — this is crypto)

1. **Same cipher:** 256-bit ChaCha20-Poly1305, 16-byte tag. No AES, no cipher downgrade.
2. **Keys are the secret Noise `Split()` output** (or snow's own, in A1) — never derived from
   the non-secret channel binding / handshake hash.
3. **Nonce uniqueness per (key, direction):** the monotonic per-direction `send_counter`
   drives the nonce; a counter is never reused under one key. Counter is u64 (never wraps in
   practice; ~120 s rekey bounds it further). Directional keys keep tx/rx nonces independent.
4. **Byte-identical to the current wire** (A1 by construction; A2 by matching Noise's
   nonce/AAD) — verified by a KAT test comparing against snow's output. If the chosen fast
   crate cannot match Noise framing exactly, a wire change is acceptable (pre-release "peers
   rebuild together" posture), but byte-identity is preferred and expected.
5. **Replay + ordering semantics preserved:** the existing `ReplayWindow` (`check_and_set`
   before AEAD verify, WireGuard-style) and monotonic `send_counter` are unchanged.
6. **Handshake unchanged:** `Noise_IK_25519_ChaChaPoly_BLAKE2s` via snow, including
   `get_handshake_hash()` channel binding used elsewhere. (X25519 stays; PQ is a separate
   future milestone.)
7. **`#![forbid(unsafe_code)]` holds in `yip-crypto`** — the SIMD/asm lives inside the AEAD
   dependency (`ring`/`aws-lc-rs`), not in yip code.

## 5. Testing

- **Spike (Task 1) report:** measured seal/open µs for (a) snow default baseline, (b) A1
  snow-ring (or "cannot build with BLAKE2s"), (c) A2 fast-crate with extracted keys, (d) the
  no-alloc delta — on `--release`. Decision recorded.
- **Byte-identity KAT:** for a fixed key + counter + plaintext, the chosen fast path produces
  **exactly** snow's `write_message` ciphertext+tag (proves wire-compat + correctness).
- **Round-trip:** `seal` → `open` recovers the plaintext; across many counters.
- **Replay:** a replayed counter is rejected (`CryptoError::Replay`); the window still slides.
- **Out-of-order open:** counters delivered out of order all open (existing test preserved).
- **Tamper:** a flipped ciphertext/tag byte fails `open` (`CryptoError::Decrypt`).
- **No-alloc:** the buffer-reuse path produces identical output to the allocating path.
- **Benchmark:** `hotpath::aead_seal_1300` / `aead_open_1300` drop from ~2.1 µs to sub-µs;
  record before/after (VPS profile) in `crates/yip-bench/RESULTS.md`.
- **No-regression:** full `yip-crypto` + workspace suite; the netns tunnel tests still bring up
  a session and pass traffic (the AEAD is on the hot path end-to-end).

## 6. Scope & files

- **Modify:** `crates/yip-crypto/src/lib.rs` (`Session::seal`/`open` — fast AEAD + reusable
  buffers; A2 also: extract transport keys at handshake→transport transition, hold the
  directional keys + a fast AEAD context in `Session`), `crates/yip-crypto/Cargo.toml`
  (add `ring` or `aws-lc-rs`; snow feature change if A1), `crates/yip-bench` (bench + RESULTS).
- **Possibly create:** `crates/yip-crypto/src/aead.rs` if the fast-AEAD path is cleaner split
  out of `lib.rs`.
- **Callers:** `bin/yipd/src/dataplane.rs` uses `seal`/`open`; if the no-alloc API changes the
  signature (buffer-taking), thread the reusable buffer through the dataplane hot loop.
- **Untouched:** the Noise handshake, `ReplayWindow`, counter semantics, `yip-wire`,
  `wire_glue`, FEC, the QUIC path.

**Out of scope (later levers / milestones):** AF_XDP / `sendmmsg` / GSO batched I/O (lever 3);
AES-256-GCM (deferred — would need a CLAUDE.md security-model decision); the PQ handshake
(separate sub-project); wire-framing trims.
