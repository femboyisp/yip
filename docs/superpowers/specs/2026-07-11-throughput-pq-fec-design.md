# Throughput — P+Q Fast-Path FEC — Design Spec

**Status:** draft (under review)
**Sub-project:** #4 (Throughput & Scalability). Lever 1 of the single-core-10-Gbit set
(cheap FEC → fast AEAD → AF_XDP/batched I/O). Builds on 4a (RS codec, merged 9fb194d).

---

## 1. Goal

Make **proactive FEC repair cheap for the common low-redundancy cases (R=1 and R=2)** so
yip can keep zero-RTT loss recovery *on* over lossy links without the general Cauchy solve
eating the per-packet CPU budget. 4a's Cauchy repair costs ~1.3 µs/packet; a RAID-6-style
**P+Q** generator computes R=1/R=2 repair in ~0.4–0.5 µs (R=1 is a pure XOR), keeping
protection near-free at any throughput. This is a contained change to `rs.rs` + `fec.rs` on
the shipped GF(256) core.

## 2. Why

On a 1-core target the throughput ceiling is single-core CPU. Post-4a the per-packet budget
for ~10 Gbit is ~1.2 µs; the general RS repair (~1.3 µs) alone busts it, so keeping
proactive repair on a lossy link forces throughput down. But repair does **not** have to
use the general solve: for R≤2 there are classic MDS constructions that are far cheaper.
This is exactly the "XOR fast path" 4a deferred — deferred because mixing XOR-for-R=1 with
Cauchy-for-R≥2 makes a repair symbol at index K **ambiguous** to a decoder that doesn't know
which generator produced it. This milestone resolves that by **signaling the generator
scheme on the wire** (in the reserved `payload_id[3]` byte 4a set aside for it).

Bandwidth is free on the target servers, so running generous cheap repair (R=1/R=2) is
costless in bytes — the only cost that mattered was CPU, which P+Q removes.

## 3. The P+Q scheme (normative)

Two generator **schemes**, selected by R, both systematic (`[ I_K ; generator ]`) over
GF(256) (poly 0x11D, generator element 2 — the shipped `gf256`):

- **`SCHEME_PQ` (id `1`), used for non-ARQ classes at R ∈ {1,2}** (see §4 for why ARQ
  classes stay on Cauchy):
  - Repair row `m = 0` (symbol_index `K`) — **P**: `coef_i = 1` for all `i` (the XOR of all
    K sources). Pure XORs, no GF multiplies.
  - Repair row `m = 1` (symbol_index `K+1`) — **Q**: `coef_i = 2^i` (the RAID-6 syndrome;
    `2^i` = generator^i over GF(256), computed incrementally). One GF-mul per source.
  - **MDS:** R=1 (P alone) recovers any 1 erasure; R=2 (P+Q) is the classic RAID-6
    construction — recovers any 2 erasures, because for two missing sources `i≠j` the 2×2
    system `[1, 1; 2^i, 2^j]` is invertible (`2^i ≠ 2^j` for `i≠j < K ≤ 255`).
  - `SCHEME_PQ` is defined **only for m ∈ {0,1}**; a repair symbol claiming this scheme with
    `symbol_index ≥ K+2` is invalid and MUST be rejected by the decoder.
- **`SCHEME_CAUCHY` (id `0`), used when R ≥ 3:** the existing 4a Cauchy generator
  `C[m][i] = inv((K+m) ^ i)` — MDS for all R. Unchanged.

The generator row is a pure function of `(scheme, K, m)`, so a repair symbol's coefficients
are fully determined once the decoder knows the scheme (from `payload_id[3]`) and K (from
`object_size`). Repair row `m` never depends on R.

**Shared row primitive.** Both encode and decode compute a repair row via one function:

```
rs::repair_row(scheme, k, m) -> Vec<u8>   // K coefficients for repair row m
  SCHEME_CAUCHY: [ cauchy_coef(k, m, 0..k) ]
  SCHEME_PQ, m==0: [ 1; k ]                       // P
  SCHEME_PQ, m==1: [ 1, 2, 4, ... 2^(k-1) ]       // Q, incremental *2
  SCHEME_PQ, m>=2: invalid (caller guards)
```

`gf256` is **unchanged** — `2^i` is built incrementally (`p *= 2`) inside `repair_row`.

## 4. Scheme selection & wire framing

- **Encoder** chooses the scheme per block: **`SCHEME_PQ` when the flow class is non-ARQ
  (`params.arq == false`) and R ∈ {1,2}; `SCHEME_CAUCHY` otherwise** (any ARQ class, R=0, or
  R ≥ 3). yip's per-packet R on the non-ARQ classes (Realtime 0.15, Default 0.10) is almost
  always 1, so P+Q is the common path exactly where proactive repair is always on.
- **ARQ cross-call invariant (why scheme keys on `params.arq`, not just R):** the ARQ
  retransmit path (`repair_with_id` / `Transport::repair_object`) re-encodes the *same*
  `object_id` in a **separate** `build()` call with a *different* repair count
  (`RETX_EXTRA_REPAIR = 4`). All symbols of one `object_id` — original send **and** every
  retransmit — MUST use the same generator, or the reassembler (which locks a block to the
  scheme of its first-received symbol) rejects the mismatched batch and the object never
  decodes. Choosing the scheme from the per-call R would make an original R=1 send (`Pq`) and
  its R=4 retransmit (`Cauchy`) disagree — silently defeating ARQ. Keying on the **stable**
  `params.arq` flag fixes this: **every ARQ-eligible class always uses Cauchy** (so original
  and retransmit agree), and non-ARQ classes (which are encoded exactly once per `object_id`,
  never retransmitted) get the P+Q fast path. `Pq` is capped at R≤2 by construction (only P,Q
  rows exist), so an ARQ object that could grow past R=2 must be Cauchy anyway.
- The scheme id is packed into **`payload_id[3]`** (the byte 4a reserved) on **every** symbol
  of the block — source and repair — so the decoder can read it from any received symbol.
  `payload_id` layout becomes `[codec_tag=0x01][symbol_index:u16 BE][scheme:u8]`.
- `yip-wire::Frame`, `wire_glue.rs`, and the `Symbol` struct are **unchanged** (`payload_id`
  is still an opaque `[u8;4]`; only its 4th byte gains meaning).
- **Interop:** old 4a peers pack `payload_id[3]=0` and only ever produce Cauchy repair, so a
  4a sender ↔ P+Q receiver still interops for R≥3/Cauchy and for source symbols; a P+Q
  sender's R≤2 repair is only decodable by a P+Q-aware receiver. Under the pre-release
  "peers rebuild together" posture this is fine; the scheme byte makes the difference
  explicit, not silent.

## 5. API changes

- `rs::Scheme` enum (`Cauchy`, `Pq`) with `to_u8()`/`from_u8(u8) -> Option<Scheme>`
  (constants `SCHEME_CAUCHY=0`, `SCHEME_PQ=1`).
- `rs::encode_repair(source: &[Vec<u8>], r: usize, scheme: Scheme) -> Vec<Vec<u8>>` — adds
  the `scheme` arg; generates each repair row via `repair_row(scheme, k, m)`.
- `rs::decode_source(k, shard_len, received, scheme: Scheme) -> Option<Vec<Vec<u8>>>` — adds
  `scheme`; builds each repair row of the submatrix via `repair_row(scheme, k, m)`; rejects
  (returns `None`) a `SCHEME_PQ` repair index with `m ≥ 2`.
- `fec.rs`: `pack_payload_id(symbol_index, scheme_u8)`; `parse_payload_id -> Option<(u16, u8)>`
  (rejects a non-`0x01` codec tag **and** an unknown scheme id); `FecEncoder::build` selects
  the scheme and packs it; `FecReassembler` stores the block's scheme (from the first symbol)
  and passes it to `decode_source`.
- **Ingest guard (DoS-robustness):** `FecReassembler::push` rejects — before storing — a
  repair symbol whose `(scheme, symbol_index)` is invalid, i.e. a `SCHEME_PQ` symbol with
  `symbol_index ≥ K+2` (only `K`,`K+1` are valid P/Q rows). This mirrors the existing
  `symbol_index ≥ 255` guard, so a single forged symbol cannot block a legitimate block's
  decode. `decode_source` keeps the same check defensively (returns `None`).
- `Transport`/`AdaptiveController`/`lib.rs` public API unchanged (the `repair_count → R`
  derivation is identical; scheme selection is internal to `fec.rs`).

## 6. Invariants

1. **MDS for both schemes:** any K of K+R shards reconstruct the object byte-for-byte —
   P+Q for R∈{1,2}, Cauchy for R∈{3,4}, over K∈{1,2,3,8}.
2. **R=1 repair is a pure XOR** (no GF multiply on the encode hot path).
3. **Scheme is a pure function of `(scheme_id, K, m)`** and never depends on R.
4. **No behavior/policy change:** flow-class ratios and the controller are unchanged; the
   scheme is chosen from `(params.arq, R)` — ARQ classes always Cauchy, non-ARQ classes P+Q
   at R∈{1,2} (§4). **ARQ recovery must still work end-to-end** (a partial original send +
   an `RETX_EXTRA_REPAIR` retransmit reconstructs the object).
5. **No panics on malformed input;** a `SCHEME_PQ` repair with `m ≥ 2`, a wrong codec tag, or
   an unknown scheme id is rejected (`None`). All existing DoS guards hold.
6. **`#![forbid(unsafe_code)]`** holds; `gf256` untouched.

## 7. Testing

- **`repair_row` unit tests:** P row is all-ones; Q row is `[1,2,4,...,2^(k-1)]`; Cauchy row
  matches `cauchy_coef`.
- **MDS property test (the gate):** extend the exhaustive K-of-(K+R) round-trip to run for
  **both** schemes — `SCHEME_PQ` at R∈{1,2}, `SCHEME_CAUCHY` at R∈{3,4}, K∈{1,2,3,8}; every
  erasure pattern reconstructs byte-for-byte.
- **RAID-6 2-erasure test:** an explicit K=4, R=2 P+Q block, drop every pair of shards,
  assert recovery.
- **Malformed:** a `SCHEME_PQ` symbol with `symbol_index ≥ K+2`, and an unknown scheme id,
  return `None` (no panic).
- **`payload_id` round-trip:** encoder packs `[0x01, idx_hi, idx_lo, scheme]`; reassembler
  recovers `(symbol_index, scheme)` and rejects a non-`0x01` tag.
- **fec round-trip:** an R=1 and an R=2 block decode through the reassembler under erasure
  and reordering; an R=3 block still decodes (Cauchy path).
- **Benchmark:** `hotpath::transport_encode_1300` at R=1 and R=2 — confirm the P+Q path is
  sub-µs vs 4a's ~1.3 µs Cauchy baseline; record in `crates/yip-bench/RESULTS.md`.
- **No-regression:** full `yip-transport` suite + the netns loss/ARQ tests (`run-netns-tunnel-loss.sh`,
  `run-arq-integrity.sh`) green — FEC still recovers end-to-end.

## 8. Scope & files

- **Modify:** `crates/yip-transport/src/rs.rs` (`Scheme`, `repair_row`, scheme args on
  `encode_repair`/`decode_source`), `crates/yip-transport/src/fec.rs` (scheme selection,
  `payload_id[3]` pack/parse, reassembler scheme handling), `crates/yip-bench` bench/RESULTS.
- **Untouched:** `gf256.rs`, `yip-wire`, `wire_glue.rs`, the QUIC path, `control.rs`, `lib.rs`
  public API.

**Out of scope (later 10-Gbit levers):** fast AEAD (SIMD ChaCha20 / AES-NI, needs a
CLAUDE.md security-model decision), AF_XDP / `sendmmsg` / GSO batched I/O.
