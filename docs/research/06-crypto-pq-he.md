# 06 — Cryptography & Post-Quantum Research

Research notes for the Rust P2P mesh VPN. Goals: post-quantum encryption at
high performance / low latency, "preferably homomorphic", and key rotation.

Three local repos analyzed:

- `refrences/chacha20-blake3` — Rust AEAD cipher with SIMD
- `refrences/lattigo` — Go, lattice-based multiparty homomorphic encryption
- `refrences/rosenpass` — Rust post-quantum key exchange (PQ aspects only)

---

## ChaCha20-BLAKE3

### What it does
A from-scratch Authenticated Encryption with Associated Data (AEAD) construction
combining the ChaCha20 stream cipher with BLAKE3 used both as a key-derivation
function and as a keyed MAC. Designed to be a single general-purpose AEAD that
runs fast on any CPU without dedicated crypto instructions (unlike AES, which
wants AES-NI). Author: Sylvain Kerkour. Spec at kerkour.com/chacha20-blake3.

### Language / license
Rust, `#![no_std]` core (optional `alloc`/`std`). MIT license. Workspace splits
into a standalone `chacha` stream-cipher crate and the `chacha20-blake3` AEAD
crate. Dependencies are minimal: `blake3`, `constant_time_eq`, `zeroize`.

### Crypto scheme
Encrypt-then-MAC with per-message subkey derivation (verified from
`chacha20_blake3.rs`):

1. `kdf_out = BLAKE3.keyed(key, nonce)` expanded to 72 bytes via the XOF.
2. Split: `encryption_key = kdf_out[0..32]`, `authentication_key = kdf_out[32..64]`,
   `encryption_nonce = kdf_out[64..72]` (8-byte ChaCha nonce).
3. Ciphertext = `ChaCha20(encryption_key, encryption_nonce)` XOR keystream over plaintext.
4. `tag = BLAKE3.keyed(authentication_key, aad || len(aad) || ciphertext || len(ciphertext))`,
   a 32-byte tag. Length fields are appended as little-endian u64 to prevent
   canonicalization/length-extension ambiguity.
5. Decrypt recomputes the tag and compares in constant time (`constant_time_eq_32`)
   before decrypting.

Sizes: 32-byte key, **24-byte nonce**, **32-byte tag** (double the 16-byte
Poly1305 tag). The long random nonce plus deriving a fresh ChaCha key+nonce per
message is what makes random nonces safe and gives the design margin.

Key property the README emphasizes: **full context commitment / key commitment.**
Because the 32-byte BLAKE3 tag commits to the key, nonce, AAD and ciphertext, a
ciphertext cannot be made to decrypt validly under two different keys. Classic
AES-GCM and ChaCha20-Poly1305 are *not* key-committing — a real concern in
multi-key / multi-recipient settings.

### Performance characteristics
Pure-Rust SIMD with runtime feature detection (verified in `chacha/src/lib.rs`):

- x86_64: AVX-512 (16 ChaCha blocks in parallel, `SIMD_LANES = 16`) and AVX2
  (8 blocks, `SIMD_LANES = 8`), selected at runtime via `is_x86_feature_detected!`.
- aarch64: NEON (always assumed present).
- wasm32: simd128 (compile-time).
- Scalar fallback otherwise. SIMD only kicks in for inputs ≥ 128 bytes.

Author's single-core benchmarks (AMD EPYC 9R45, pure-Rust non-optimized):

| Message Size | ChaCha20-BLAKE3 | XChaCha20-Poly1305 | AES-256-GCM |
| ----- | ----- | ----- | ----- |
| 64 B  | 103 MB/s | 116 MB/s | **540 MB/s** (AES-NI) |
| 1 KB  | 523 MB/s | 767 MB/s | **1,287 MB/s** |
| 64 KB | **2,153 MB/s** | 1,636 MB/s | 1,475 MB/s |
| 1 MB  | **3,297 MB/s** | 1,654 MB/s | 1,476 MB/s |
| 10 MB | **3,353 MB/s** | 1,664 MB/s | 1,477 MB/s |

Takeaway: it loses on tiny messages (KDF + larger tag is fixed overhead, and
AES-NI dominates small blocks) but wins decisively on bulk throughput, and beats
AES-256-GCM without needing AES-NI. The keystream supports streaming/partial
calls (it buffers the last block), useful for chunked I/O.

### PQ security level
None as a primitive — this is symmetric crypto. However, symmetric ciphers with
256-bit keys are considered **quantum-resistant**: Grover's algorithm only halves
the effective key strength, leaving ~128-bit post-quantum security. So a 256-bit
AEAD is fine for the *data plane* against quantum adversaries; the quantum risk in
a VPN is entirely in the *key exchange* (which is where Rosenpass comes in).

### Strengths / Weaknesses
**Strengths:** no_std, no special hardware required, strong bulk throughput,
key-committing AEAD, 24-byte nonce safe for random generation, clean minimal Rust,
zeroize support, MIT-licensed and easy to vendor.

**Weaknesses:** Non-standard construction (not RFC'd, no formal proof published
beyond the blog spec, single author) — adopting it is a trust decision. Slower on
small packets, which matters for a VPN moving lots of ~1.3 KB frames. 32-byte tag
is 2× the per-packet overhead of Poly1305 (16 B). Not yet on crates.io as a
stable release (README installs from git).

### Reusable ideas / components
- The **per-message subkey-derivation pattern** (KDF the long-term key + nonce into
  fresh cipher key/nonce/MAC key) is exactly what you want layered over a session
  key from the handshake — it neutralizes nonce-reuse risk.
- The standalone `chacha` crate with runtime SIMD dispatch is reusable on its own.
- **Key commitment** is worth keeping as a design requirement for the data plane.
- For our VPN, the realistic choice is between this and the battle-tested
  RustCrypto/libcrux `ChaCha20-Poly1305` — see recommendation.

---

## Lattigo

### What it does
A Go library implementing full-RNS, Ring-Learning-With-Errors (RLWE) based
**homomorphic encryption (HE)** and **multiparty / threshold HE** protocols.
HE lets you compute on ciphertexts without decrypting them. Originally EPFL-LDS,
now maintained by Tune Insight SA. Current major version v6.

### Language / license
Pure Go (cross-platform, compiles to WASM), Apache 2.0. Claims performance
"comparable to state-of-the-art C++ libraries." Strictly hierarchical packages:
`ring` (modular poly arithmetic, NTT, sampling) → `core` (`rlwe`, `rgsw`) →
`schemes` (`bfv`, `bgv`, `ckks`) → `circuits` → `multiparty`.

### Crypto scheme
Three RLWE schemes (verified in `schemes/`):

- **BFV** (Brakerski-Fan-Vercauteren), scale-invariant, exact **integer** modular
  arithmetic. Here implemented as a wrapper over BGV.
- **BGV** (Brakerski-Gentry-Vaikuntanathan), exact modular **integer** arithmetic;
  Lattigo's BGV is a full-RNS generalization covering both BGV and BFV.
- **CKKS** (a.k.a. HEAAN), **approximate fixed-point** arithmetic over real/complex
  numbers — the scheme for ML / statistics on encrypted data. Includes bootstrapping,
  DFT, comparison (`sign`/`max`/`step`), inverse, polynomial and minimax evaluators.

Also: **RGSW** ciphertexts + external product and **LMKCDEY blind rotations**
(building blocks for programmable bootstrapping). The `multiparty` package adds
threshold key-gen and interactive bootstrapping with secret-shared keys (`mpckks`,
`mpbgv`) — N parties jointly hold the secret key so no single party can decrypt.

### Performance characteristics
HE is **orders of magnitude slower** than symmetric crypto and that is intrinsic,
not an implementation flaw:

- Ciphertexts are large polynomials over power-of-two cyclotomic rings (ring degree
  N typically 2^13–2^16). A single ciphertext is on the order of **tens of KB to
  several MB**, encrypting at most a few thousand "slots."
- **Ciphertext expansion** of roughly 1,000×–10,000× plaintext size is normal.
- A homomorphic multiplication costs many polynomial NTTs plus a relinearization
  key-switch; **bootstrapping** (noise refresh, needed for deep circuits) takes
  on the order of **seconds** per operation.
- Latency is milliseconds-to-seconds per *homomorphic operation*, vs nanoseconds
  per byte for AEAD. This is a 10^6–10^9 gap.

It is well-optimized *for HE* (full-RNS, NTT, concurrency-friendly Go), but "fast HE"
is still glacial next to a stream cipher.

### PQ security level
**Post-quantum by construction.** RLWE/LWE lattice problems are the basis of
NIST's PQ standards (ML-KEM/Kyber, ML-DSA/Dilithium). Parameter sets are chosen for
128-bit (or higher) security against known classical and quantum attacks; the
`ring`/`rlwe` parameters encode this. So Lattigo is genuinely PQ — it just solves a
completely different problem than transport encryption.

### Strengths / Weaknesses
**Strengths:** Mature, actively maintained, broad scheme coverage, true multiparty/
threshold HE, pure Go, permissive license, has worked PIR and PSI examples.

**Weaknesses:** It's **Go**, not Rust (FFI/process boundary or a rewrite to use it
in our stack). Massive computational and bandwidth overhead. Steep parameter-tuning
learning curve (noise budget, scale, leveled vs bootstrapped). Completely unsuited
to per-packet bulk encryption. Backward-incompatible churn within v6.

### Reusable ideas / components
- **Not** for the data plane. See the reality-check section.
- The `examples/multiparty/int_psi` (private set intersection) and `int_pir`
  (private information retrieval) examples map directly onto *plausible* control-plane
  privacy features: private peer discovery and metadata-minimizing lookups.
- Threshold key-gen ideas (`multiparty`) are conceptually interesting for a mesh where
  no single coordinator should hold a master secret — but MPC, not HE, is usually the
  right tool there.

---

## Rosenpass (post-quantum aspects only)

### What it does
A post-quantum **key-exchange** daemon that establishes a symmetric key and hands it
to WireGuard via WireGuard's pre-shared-key (PSK) slot. WireGuard keeps doing the
actual packet encryption (its Noise IK with X25519/ChaCha20-Poly1305); Rosenpass
adds a PQ-secure shared secret on top so the link is secure even against a
"harvest-now-decrypt-later" quantum adversary. This is exactly the architectural
pattern a PQ VPN should copy.

### Language / license
Rust, dual MIT / Apache-2.0. Uses `liboqs` (Open Quantum Safe) via the in-tree
`rosenpass-oqs` bindings crate, with experimental `libcrux` (formally-verified)
backends behind feature flags. Funded via NLnet / NGI Assure.

### Crypto scheme — the KEM choice (the important part)
Rosenpass uses **two distinct KEMs** in a hybrid construction (verified in
`ciphers/src/lib.rs`):

- **Static KEM = Classic McEliece 460896** (`rosenpass_oqs::ClassicMceliece460896`).
  Code-based, NIST level 3-ish, extremely conservative / oldest-studied PQ assumption.
  Trade-off: **enormous public keys (~half a megabyte)** but small ciphertexts and
  very fast encaps/decaps. Used for the long-term peer identity, which is exchanged/
  configured rarely, so the giant key is acceptable there.
- **Ephemeral KEM = Kyber-512** (`rosenpass_oqs::Kyber512`, i.e. ML-KEM-512).
  Lattice-based, small keys and ciphertexts (~800 B / ~768 B), fast. Used fresh per
  handshake for forward secrecy.

So Rosenpass deliberately answers "McEliece *or* Kyber?" with **both** — different
KEMs for different roles. The rationale is defense-in-diversity: even if lattice
assumptions (Kyber) were broken, the code-based static KEM (McEliece) still
authenticates the peer, and vice-versa. McEliece's huge key is tolerable because it's
the static identity; Kyber's compactness is used for the per-session ephemeral.

The AEAD inside the handshake messages is ChaCha20-Poly1305 / XChaCha20-Poly1305
(RustCrypto or libcrux), and keyed-hashing/KDF is BLAKE2b / Keyed-SHAKE256. Note this
is **classical** symmetric crypto with 256-bit keys (PQ-safe via large keys), the
same reasoning as the ChaCha20-BLAKE3 section.

Handshake messages (from `msgs.rs`): `InitHello` → `RespHello` → `InitConf` →
`EmptyData` (a 4-message pattern). `InitHello` carries the ephemeral Kyber public key
(`epki`) and a McEliece ciphertext (`sctr`); secrets are mixed into a running key via
keyed hashing, McEliece-then-Kyber, with explicit domain separation.

### Composition with WireGuard's Noise
Rosenpass runs *beside* WireGuard, not inside it. It periodically computes a fresh
PQ shared secret and injects it as WireGuard's PSK. Because WireGuard already mixes
the PSK into its Noise handshake, the combined channel is **"hybrid": no less secure
than WireGuard alone**, plus PQ confidentiality. WireGuard still does X25519, so an
attacker must break *both* X25519 and the PQ KEMs — that's the point of a hybrid.
Rosenpass itself is stateless on the responder side via a "biscuit" mechanism
(encrypted server-side state echoed by the client, like a TLS cookie), giving DoS
resistance.

### Key rotation
This is a first-class feature (verified in `protocol/constants.rs`):

- `REKEY_AFTER_TIME_RESPONDER = 120.0` s and `REKEY_AFTER_TIME_INITIATOR = 130.0` s
  (initiator rekeys 10 s later to avoid both sides racing) — i.e. **rekey every ~2
  minutes**, matching the WireGuard paper (rekey every 2 min, discard after 3).
- `BISCUIT_EPOCH = 300.0` s — responder rotates its biscuit (stateless-cookie) key.
- Cookie secret / cookie value epochs of 120 s for the WireGuard-style DoS-mitigation
  cookie.
- Initiator retransmission uses exponential backoff (0.5 s → 10 s, growth 2×, with
  jitter).

So the design rekeys the whole PQ exchange every two minutes and continuously feeds
fresh PSKs to the data plane — exactly the key-rotation behavior our VPN wants.

### Performance characteristics
The cost is paid only at handshake / rekey time (every ~2 min), never per packet.
McEliece keygen is slow and its public key is ~half a MB, but encaps/decaps are fast;
Kyber is fast and compact across the board. Per-packet cost is unchanged — it's just
WireGuard. Net data-plane latency impact ≈ zero.

### PQ security level
Hybrid: classical X25519 (from WireGuard) **+** PQ Classic-McEliece-460896 (≈ NIST
L3, code-based) **+** PQ Kyber-512 (NIST L1, lattice). The two-KEM design hedges the
PQ assumption itself. Symmetric layer is 256-bit (PQ-adequate).

### Strengths / Weaknesses
**Strengths:** Rust, formally-analyzed protocol (ProVerif symbolic proofs in-tree),
clean separation of long-term vs ephemeral KEM, built-in rekey, stateless responder,
"can't make it worse than WireGuard" composition, real-world deployed. Directly
reusable architecture.

**Weaknesses:** `liboqs` is a C dependency (the libcrux backends are the path to a
pure-Rust/verified build, still experimental). McEliece's ~0.5 MB public keys bloat
peer config/identity exchange. It assumes a WireGuard-style point-to-point model; a
*mesh* needs orchestration on top. Kyber-512 is the lowest NIST level (L1) — you may
prefer Kyber-768/ML-KEM-768 for more margin.

### Reusable ideas / components
- **Copy the whole architecture:** PQ KEM handshake that outputs a symmetric key,
  rotated every ~2 minutes, feeding a fast symmetric AEAD data plane. This is the
  blueprint for our VPN.
- **Hybrid, two-KEM design:** static code-based KEM for identity + ephemeral lattice
  KEM for forward secrecy, mixed with domain-separated keyed hashing.
- **Stateless responder via encrypted biscuits** for DoS resistance in a mesh where
  any node may be flooded.
- The `cipher-traits` / pluggable-backend pattern (RustCrypto vs libcrux behind
  features) is a good way to keep our crypto swappable.
- Consider `libcrux-ml-kem` directly (pure Rust, formally verified) rather than the
  `liboqs` C path.

---

## Reality check: homomorphic encryption for a VPN data plane

**Short version: do not use homomorphic encryption (Lattigo) to encrypt VPN packets.
It is the wrong tool by 6–9 orders of magnitude. "Preferably homomorphic" and
"low-latency VPN data plane" are mutually exclusive goals.**

### Why HE cannot carry the data plane
A VPN data plane encrypts a stream of ~1.3 KB frames and must add at most microseconds
of latency and gigabits/sec of throughput. HE optimizes for *computing on* ciphertexts,
and pays for that with:

- **Throughput / latency gap of 10^6–10^9.** ChaCha20-BLAKE3 does ~3 GB/s/core and
  encrypts a packet in well under a microsecond. An HE encryption + any homomorphic op
  is milliseconds-to-seconds. You would turn a 10 Gbit link into a trickle and add
  seconds of latency.
- **Ciphertext expansion ~1,000×–10,000×.** An RLWE ciphertext is a big polynomial
  (ring degree 2^13–2^16) measured in tens of KB to MB regardless of payload. A 1.3 KB
  packet would become megabytes on the wire — catastrophic for a VPN, which is
  bandwidth-sensitive by definition.
- **No reason to do it.** HE's value is computing on data you can't see. A VPN tunnel
  has no party that needs to compute on the plaintext while blind to it — both endpoints
  *are* the data owner. There is simply no homomorphic computation to perform on packet
  payloads. You'd pay the entire HE tax for zero functional benefit.
- **PQ is already solved cheaply.** The quantum threat to a VPN is the key exchange,
  not the bulk cipher (256-bit symmetric is already PQ-safe). A PQ KEM hybrid handshake
  (Rosenpass-style) closes that gap at ~zero per-packet cost. HE adds nothing here.

### Where HE / MPC might *legitimately* fit (control plane only, optional)
These are rare-event, small-data, latency-tolerant operations — the opposite of the
data plane — and even here MPC/PSI is often lighter than full HE:

- **Private peer / service discovery via PSI.** "Which peers do we both know / which
  services do we both offer?" without revealing full membership lists. Lattigo ships an
  `int_psi` example. A dedicated PSI protocol (OPRF/Diffie-Hellman-based) is usually far
  cheaper than HE, though.
- **Private routing / private information retrieval.** Looking up a peer's address or a
  route from a directory without revealing *which* entry you wanted — Lattigo's `int_pir`
  example. Useful for metadata privacy in a directory/coordination server.
- **Metadata-privacy aggregation.** Privately aggregating mesh telemetry/usage stats
  across nodes so the coordinator learns only the sum, not per-node values (threshold HE
  or secret-sharing/MPC).
- **Threshold key custody.** Splitting a coordination secret across nodes so no single
  node can decrypt — but this is MPC/threshold cryptography, typically not HE.

All of these are **off the packet path**, run seconds-or-minutes apart, and operate on
kilobytes. That's the only regime where the HE/MPC tax is affordable.

### Recommended split
| Concern | Use | Don't use |
| --- | --- | --- |
| Bulk packet encryption (data plane) | Fast symmetric AEAD (ChaCha20-Poly1305 / ChaCha20-BLAKE3), 256-bit keys | HE, AES without AES-NI |
| Post-quantum security | PQ KEM **hybrid** handshake (X25519 + ML-KEM, optional McEliece static) | HE for transport |
| Key rotation | Rekey every ~2 min, fresh session key per epoch (Rosenpass model) | Long-lived static keys |
| Private peer discovery / directory lookups (optional, control plane) | PSI / PIR (MPC first; Lattigo only if needed) | HE on the data plane |

The user's "preferably homomorphic" instinct is best satisfied by reserving HE/MPC for
a *future, optional control-plane privacy feature*, and explicitly **not** the data plane.
