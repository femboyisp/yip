# Milestone 4a: Throughput — Small-K Reed–Solomon Codec — Design Spec

**Status:** draft (under review)
**Sub-project:** #4 (Throughput & Scalability), milestone 4a.
**Supersedes:** `2026-07-09-throughput-plan-cached-fec-4a-design.md` (plan-cached RaptorQ — abandoned; see §2).

---

## 1. Goal

Replace RaptorQ with a hand-rolled small-K **systematic Reed–Solomon** codec in yip's
per-packet FEC (`crates/yip-transport/src/fec.rs`), eliminating RaptorQ's fixed
per-object cost and unlocking **multi-gigabit single-core throughput while keeping
proactive FEC** (zero-RTT loss recovery). In the same milestone, build the reusable
**GF(256) arithmetic core** that the whole FEC-codec campaign (RS → sliding-window RLC →
RLNC recoding) rides on.

## 2. Why — the investigation that led here

A profiling spike and a four-track investigation established the following ground truth
(all measured, release builds, symbol_size 1200):

- yip FEC-encodes **per packet**: objects are 1–3 source symbols (K≈2), repair R≈1.
- RaptorQ encode is ~26 µs/packet → the ~355 Mbit/s single-core ceiling.
- **Caching RaptorQ's `SourceBlockEncodingPlan` only reaches ~12 µs** (2.1×), and 96% of
  that residual is the irreducible GF(256) intermediate-symbol solve over RaptorQ's
  **K′=10 minimum block** (RFC 6330 systematic table). A 2-symbol object does ~10
  symbols of work — a ~5× padding tax that no implementation avoids.
- The K′=10 tax exists because RaptorQ is a **rateless fountain code**. yip **never uses
  ratelessness**: `AdaptiveController::observe_loss` clamps `ratio ≤ 1.0`, so
  `repair_count(source) ≤ source` always — never near a fountain code's unbounded repair.
  yip pays RaptorQ's biggest cost for a capability it does not use.
- **Small-K systematic Reed–Solomon**, measured: **0.77 µs encode / 0.89 µs decode** at
  K=2/R=1 (`reed-solomon-erasure`), and **0.06 µs** for the R=1 XOR-parity case — ~15×
  faster than plan-cached RaptorQ, same byte overhead (R/K), no `unsafe`, and its 255−K
  on-demand repair ceiling is never binding for yip's R values.

RS keeps per-packet framing (no batching latency) and proactive repair (zero-RTT
recovery), so it gives up nothing yip actually uses. The RaptorQ dependency is dropped.

> **Campaign context.** 4a is **Stage 1** of a staged FEC-codec campaign toward the
> north-star of **sliding-window RLNC**: Stage 2 (RLC, RFC 8681) kills the residual
> bandwidth overhead and adds streaming recovery; Stage 3 adds relay recoding for the
> mesh. All three are GF(256) linear codes — 4a builds the GF(256) core and the erasure
> Gaussian-elimination solver that Stage 2 reuses verbatim, and 4a's wire framing
> pre-slots the later codecs via a codec tag (§6).

## 3. Architecture

### 3.1 The GF(256) core (`crates/yip-transport/src/gf256.rs`, new)

A small, safe, table-based GF(256) engine — the reusable foundation:

- Field: GF(2⁸) with reducing polynomial `0x11D` (`x⁸+x⁴+x³+x²+1`).
- Precomputed `LOG`/`EXP` tables (512-entry EXP to avoid modular reduction on multiply).
- Public ops: `add(a,b) = a ^ b`; `mul(a,b)` via log/antilog; `mul_slice_into(dst, src, c)`
  = multiply-accumulate `dst[i] ^= mul(src[i], c)` (the symbol-wise MAC used by both
  RS repair generation and the decoder).
- `#![forbid(unsafe_code)]`-clean (no SIMD in 4a; a future SIMD path can live in a leaf
  crate if profiling ever demands it — not needed to hit multi-gigabit, per the model).

Tables are built once at first use (`std::sync::OnceLock`), not per encode.

### 3.2 Encoder (`FecEncoder`, rewritten)

Systematic RS over the GF(256) core. For an object of `object_size` bytes:

1. `K = ceil(object_size / symbol_size)` source symbols of `symbol_size` bytes (final
   symbol zero-padded to the boundary).
2. `R = min(repair_count, 255 − K)` repair symbols (the clamp is the GF(256) codeword
   bound; never binding at yip's per-packet K, documented for the future coalesced case).
3. Generate repair with **one consistent generator** for all R: repair symbol at
   `symbol_index = K + m` (`m = 0..R−1`) is `repair_m[b] = Σ_i C[m][i] · source_i[b]` over
   GF(256), where `C` is the `R×K` **Cauchy** matrix. Repair row `m` depends only on
   `(K, m)` — never on R — so a given repair index always means the same linear
   combination regardless of how many repair symbols were emitted. **This consistency is
   load-bearing:** the decoder derives K from `object_size` and reconstructs the row for
   each *received* repair index directly, without needing to know R (R is not on the wire).
4. Emit `K + R` `Symbol`s: source symbols at `symbol_index` `0..K−1` (raw data —
   **systematic**, so a no-loss receiver does zero decode work), repair symbols at
   `K..K+R−1`.

> **On the XOR micro-opt (deferred).** For R=1 a plain XOR parity encodes in ~0.06 µs vs
> ~0.77 µs for the general Cauchy path — but XOR is the *all-ones* row, which is **not**
> Cauchy row 0, so using it for R=1 while using Cauchy for R≥2 would make repair index K
> ambiguous to the decoder. Since FEC at 0.77 µs is already far below the AEAD floor
> (~2 µs) — i.e. no longer the bottleneck — 4a uses the single consistent Cauchy generator
> and does **not** special-case R=1. A future micro-opt could adopt a RAID-6-style
> all-ones-P + Vandermonde-Q generator (MDS for R≤2, XOR-fast for the P symbol) if ever
> warranted; out of scope for 4a.

`repair_with_id(object_id, extra_repair)` (the ARQ retransmit path) generates *additional*
repair symbols at higher `symbol_index` values for a previously-sent object, capped so
total shards ≤ 255.

**Generator = Cauchy, not Vandermonde.** The load-bearing property is **MDS**: any K of the
K+R shards must decode. A Cauchy matrix over GF(256) guarantees every K×K submatrix is
invertible by construction (Vandermonde can be singular for some K/index combinations).
The systematic generator is conceptually `[ I_K ; C ]` (identity rows = source, Cauchy
rows = repair). The `R×K` Cauchy matrix is cached per `K` (working set is K=1–3; bounded
at 64 entries like the prior plan cache, cleared on overflow).

### 3.3 Reassembler (`FecReassembler`, rewritten)

- Group received symbols by `object_id`; record each arrived `symbol_index` and its bytes.
- `K = ceil(object_size / symbol_size)` (from `object_size`, as today).
- **All K source indices (`0..K−1`) present →** concatenate source symbols, trim to
  `object_size`. No decode (systematic passthrough — the no-loss common case).
- **Else, once ≥ K distinct shards arrived →** erasure-decode: form the K×K submatrix of
  `[ I_K ; C ]` for the K received indices, invert it via Gaussian elimination over
  GF(256), multiply by the received shards to recover the missing source symbols, trim to
  `object_size`.
- Return the reconstructed object exactly once; later/duplicate symbols for a completed
  object return `None`.

**DoS guards (preserved from the RaptorQ reassembler):**
- reject `object_size == 0` or `object_size > MAX_OBJECT_SIZE` (256 KiB);
- reject `symbol_index ≥ 255` (out of the GF(256) codeword range — the analogue of the
  current SBN-bounds guard);
- bound objects-in-flight with oldest-object eviction (`max_objects`);
- never panic on any attacker-supplied field — return `None`.

## 4. Public API (unchanged shape — callers in `lib.rs` untouched)

- `FecEncoder::encode(&mut self, ciphertext: &[u8], params: FlowParams, repair: u32) -> Vec<Symbol>`
- `FecEncoder::repair_with_id(&mut self, ciphertext: &[u8], params: FlowParams, object_id: u16, extra_repair: u32) -> Vec<Symbol>`
- `FecReassembler::new(symbol_size: u16, max_objects: usize)` / `push(&mut self, &Symbol) -> Option<Vec<u8>>`
- `Symbol { object_id: u16, object_size: u32, payload_id: [u8;4], data: Vec<u8> }` — struct
  shape unchanged; `payload_id` semantics change (§6).

`Transport::encode`/`decode`/`repair_object` and `AdaptiveController` are unchanged: the
`repair_count → R` derivation is identical; only the encoder clamps `R ≤ 255 − K`.

## 5. Invariants

1. **MDS correctness:** any K of the K+R emitted shards reconstruct the object
   byte-for-byte, for every K∈{1,2,3,8} and R∈{1,2,4} exercised by tests.
2. **Systematic:** with no loss, the decoder does zero field arithmetic (source symbols
   are the raw data); output equals the original ciphertext exactly.
3. **No behavior/policy change:** all flow-class repair ratios (Realtime 0.15, Default
   0.10, Bulk 0.05) and the adaptive controller are unchanged; byte overhead stays R/K.
4. **Codeword bound:** `K + R ≤ 255` always (encoder clamp).
5. **No panics on malformed input;** all existing DoS guards hold.
6. **`#![forbid(unsafe_code)]`** holds across `yip-transport`.

## 6. Wire framing

The `yip-wire::Frame` structure is **unchanged**. Only the meaning of the opaque
`payload_id: [u8;4]` changes, plus a codec tag:

- `payload_id[0] = codec_tag` — `0x01` = "RS v1". Turns the RaptorQ→RS interop break into
  an explicit, detectable mismatch, and pre-slots RLC as `0x02`.
- `payload_id[1..3] = symbol_index: u16` (big-endian) — the shard position: `0..K−1`
  source, `K..K+R−1` repair.
- `payload_id[3]` = reserved (0) — headroom for RLC window metadata later.
- `object_size` continues to ride in the frame payload prefix (`wire_glue.rs`) and yields
  `K = ceil(object_size / symbol_size)`; `object_id`, `flags`, `counter` unchanged.

`wire_glue.rs::symbol_to_frame`/`frame_to_symbol` change only to pack/parse the codec tag
and `symbol_index` in `payload_id` (the `Symbol` fields they read are otherwise the same).

**Interop:** wire-incompatible with RaptorQ peers. Fails **safe** — an RS decoder rejects a
non-`0x01` codec tag rather than misdecoding. Acceptable under yip's pre-release
"both peers rebuild together" posture; the codec tag makes the change (and the future RLC
change) detectable rather than silent. FEC framing rides *inside* the encrypted/obfuscated
envelope (3a `obf_psk` / 3c.1 QUIC), so the change creates **no new DPI signature**.

## 7. Testing & verification

- **GF(256) unit tests:** field axioms (commutativity, associativity, distributivity,
  `a·a⁻¹ = 1` for all a≠0) against a brute-force carryless-multiply reference.
- **RS round-trip property test (the correctness gate):** for K∈{1,2,3,8}, R∈{1,2,4},
  encode a known payload, then for **every** K-of-(K+R) subset of shards, assert the
  reassembler reconstructs the original byte-for-byte. Exhaustive over erasure patterns —
  this *is* the MDS proof for yip's K/R range.
- **Systematic no-loss test:** all K source shards → reconstruct with zero decode path taken.
- **Independent cross-check:** `reed-solomon-erasure` as a **dev-dependency** — for the
  same erasure scenarios, confirm an independent RS implementation also recovers (a
  property-level agreement check on our understanding; byte-level identity is not expected,
  as the generator matrices differ).
- **DoS/malformed tests:** port the existing guard tests (zero/oversized `object_size`,
  out-of-range `symbol_index`, late/duplicate symbol, eviction-at-capacity) to the RS
  reassembler.
- **`wire_glue` round-trip:** `symbol_to_frame`→`frame_to_symbol` preserves codec tag,
  `symbol_index`, `object_size`, class, counter.
- **Benchmarks:** `hotpath::transport_encode_1300` and `pipeline_profile` → encode <1 µs;
  record before/after + single-core multi-gigabit projection in `crates/yip-bench/RESULTS.md`.
- **No-regression (end-to-end gate):** netns loss paths `run-netns-tunnel-loss.sh` (FEC
  recovers dropped packets across a real tunnel) and `run-arq-integrity.sh` (retransmit via
  `repair_with_id`), plus the clean `run-netns-tunnel.sh` / `-l2` tests. Green here proves
  the swap end-to-end. If the environment cannot run netns/sudo, the exhaustive round-trip
  property test is the correctness guarantee.

## 8. Scope & files

- **Create:** `crates/yip-transport/src/gf256.rs` (GF(256) core), `rs.rs` *optional* if the
  RS matrix/codec logic is cleaner split from `fec.rs` — otherwise keep it in `fec.rs`.
- **Rewrite:** `crates/yip-transport/src/fec.rs` (`FecEncoder`, `FecReassembler`, `Symbol`
  framing; RaptorQ-specific code removed; new unit tests replacing the RaptorQ ones).
- **Modify:** `crates/yip-transport/src/lib.rs` (register `gf256` module; `pub mod`);
  `bin/yipd/src/wire_glue.rs` (codec tag + `symbol_index` in `payload_id`);
  `crates/yip-transport/Cargo.toml` (drop `raptorq` runtime dep; add `reed-solomon-erasure`
  dev-dep); `crates/yip-bench` benches/examples that reference RaptorQ; `RESULTS.md`.
- **Untouched:** `yip-wire::Frame` structure, `control.rs` logic, the QUIC path,
  `AdaptiveController`.
- **Housekeeping:** the superseded plan-cache spec/plan get a "superseded" banner; the
  `plan_cache_spike.rs` throwaway example is removed.

**Out of scope (later milestones):** sliding-window RLC (Stage 2), RLNC recoding (Stage 3),
I/O batching (4b), multi-core sharding (4c), AEAD acceleration.
