# Throughput 4a — Small-K Reed–Solomon Codec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace RaptorQ with a hand-rolled small-K systematic Reed–Solomon codec (over a new GF(256) core) in yip's per-packet FEC, reaching multi-gigabit single-core throughput while keeping proactive, zero-RTT loss recovery.

**Architecture:** Three layers, bottom-up. `gf256.rs` — safe table-based GF(256) field arithmetic. `rs.rs` — the normative RS-v1 Cauchy generator + systematic encode/erasure-decode over equal-length shards, with the exhaustive MDS proof. `fec.rs` (rewritten) — thin `FecEncoder`/`FecReassembler` that split a sealed ciphertext into shards, wrap them as `Symbol`s with a codec-tagged `payload_id`, and reassemble/decode with all DoS guards. `Transport`, `wire_glue`, and `yip-wire::Frame` are unchanged.

**Tech Stack:** Rust, no runtime FEC dependency (`raptorq` dropped); `reed-solomon-erasure` as a test-only dev-dependency oracle.

**Spec:** `docs/superpowers/specs/2026-07-09-throughput-rs-codec-4a-design.md` (§3.2.1 is the normative Cauchy definition — implement it exactly).

## Global Constraints

- `crates/yip-transport` (and the new `gf256.rs`, `rs.rs`) are `#![forbid(unsafe_code)]` — no `unsafe`.
- No `as` numeric casts except enum discriminants — use `u8::try_from`/`u16::try_from`/`u32::try_from`/`usize::from`/`u64::from`.
- **Normative RS-v1 codec (codec_tag `0x01`), from spec §3.2.1**, over GF(256) with reducing polynomial `0x11D`: source-column elements `y_i = i` (`i ∈ 0..K`), repair-row elements `x_m = K+m` (`m ∈ 0..R`), Cauchy entry `C[m][i] = inv(x_m ⊕ y_i)`, `repair_m[b] = Σ_i C[m][i]·source_i[b]`. Source rows are identity (systematic). Repair row `m` depends only on `(K, m)`, never on R.
- `K + R ≤ 255` always (encoder clamp `R = min(repair, 255 − K)`). Reject `K == 0` or `K ≥ 255`.
- `symbol_index` on the wire: `0..K−1` = source, `K..K+R−1` = repair.
- `payload_id` layout = `[tag:u8][index:u16 big-endian][reserved:u8]`; `FecEncoder` packs it, `FecReassembler` validates the tag and parses the index. `wire_glue.rs` and `yip-wire::Frame` are **unchanged**.
- Byte overhead stays R/K; all `FlowClass` repair ratios and `AdaptiveController` unchanged; `Transport` API-preserving.
- All existing DoS guards preserved (`object_size == 0`/`> MAX_OBJECT_SIZE`, out-of-range index, late/dup symbol, oldest-object eviction) + new guards (`K==0`/`K≥255`, wrong codec tag, dedupe-by-index, decode-and-free).
- `refrences/` is read-only.

---

## File Structure

- `crates/yip-transport/src/gf256.rs` — **create.** GF(256) field: `add`, `mul`, `inv`, `mul_slice_into`; `LOG`/`EXP` tables via `OnceLock`.
- `crates/yip-transport/src/rs.rs` — **create.** `cauchy_coef`, `encode_repair`, `decode_source`; the exhaustive MDS property test + `reed-solomon-erasure` cross-check live here.
- `crates/yip-transport/src/fec.rs` — **rewrite.** `Symbol` (shape unchanged), `FecEncoder`, `FecReassembler` over `rs`/`gf256`; RaptorQ removed.
- `crates/yip-transport/src/lib.rs` — **modify.** `pub mod gf256; pub mod rs;`; update `Transport::repair_object` doc comment ("RaptorQ" → "FEC repair symbols").
- `crates/yip-transport/Cargo.toml` — **modify.** drop `raptorq`; add `reed-solomon-erasure` under `[dev-dependencies]`.
- `crates/yip-bench/Cargo.toml` — **modify.** drop `raptorq` (line 14; only referenced there).
- `crates/yip-bench/RESULTS.md` — **modify.** record before/after.

---

### Task 1: GF(256) field core

**Files:**
- Create: `crates/yip-transport/src/gf256.rs`
- Modify: `crates/yip-transport/src/lib.rs` (add `pub mod gf256;`)

**Interfaces — Produces:**
- `gf256::add(a: u8, b: u8) -> u8`
- `gf256::mul(a: u8, b: u8) -> u8`
- `gf256::inv(a: u8) -> u8`  (panics only on `a == 0`, which callers never do)
- `gf256::mul_slice_into(dst: &mut [u8], src: &[u8], c: u8)`  — `dst[i] ^= mul(src[i], c)`

- [ ] **Step 1: Write the failing tests**

Create `crates/yip-transport/src/gf256.rs` with a test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Brute-force reference multiply over GF(2^8) with reducing poly 0x11D.
    fn ref_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1d; // 0x11D truncated to 8 bits
            }
            b >>= 1;
        }
        p
    }

    #[test]
    fn mul_matches_reference() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), ref_mul(a, b), "mul({a},{b})");
            }
        }
    }

    #[test]
    fn exp_table_is_primitive() {
        // A primitive generator visits all 255 nonzero elements before repeating.
        let mut seen = [false; 256];
        let mut x = 1u8;
        for _ in 0..255 {
            assert!(!seen[usize::from(x)], "generator not primitive: repeat at {x}");
            seen[usize::from(x)] = true;
            x = mul(x, 2);
        }
        assert_eq!(x, 1, "order of 2 must be 255");
    }

    #[test]
    fn inverse_is_correct() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a*inv(a) for {a}");
        }
    }

    #[test]
    fn mul_slice_into_accumulates() {
        let src = [1u8, 2, 3, 4];
        let mut dst = [10u8, 20, 30, 40];
        mul_slice_into(&mut dst, &src, 5);
        for i in 0..4 {
            assert_eq!(dst[i], 10 * (i as u8 + 1) ^ mul(src[i], 5));
        }
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p yip-transport --lib gf256`
Expected: FAIL to compile (`mul`/`inv`/`mul_slice_into` not defined).

- [ ] **Step 3: Implement the field**

Prepend to `crates/yip-transport/src/gf256.rs`:

```rust
//! GF(2^8) arithmetic (reducing polynomial 0x11D, primitive element 2) — the
//! reusable field core for yip's Reed–Solomon FEC (and the future RLC codec).
#![forbid(unsafe_code)]

use std::sync::OnceLock;

/// Reducing polynomial x^8 + x^4 + x^3 + x^2 + 1, low 8 bits (0x11D & 0xFF).
const POLY: u8 = 0x1d;

struct Tables {
    /// EXP[i] = 2^i in GF(256); doubled to 512 so `mul` needs no modular reduction.
    exp: [u8; 512],
    /// LOG[v] = discrete log of v base 2 (LOG[0] unused).
    log: [u8; 256],
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u8 = 1;
        for i in 0..255usize {
            exp[i] = x;
            log[usize::from(x)] = u8::try_from(i).expect("i < 255");
            // x *= 2  (i.e. multiply by the primitive element)
            let hi = x & 0x80;
            x <<= 1;
            if hi != 0 {
                x ^= POLY;
            }
        }
        for i in 255..512usize {
            exp[i] = exp[i - 255];
        }
        Tables { exp, log }
    })
}

/// Field addition (and subtraction) — XOR.
#[inline]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Field multiplication.
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let idx = usize::from(t.log[usize::from(a)]) + usize::from(t.log[usize::from(b)]);
    t.exp[idx] // idx <= 254+254 = 508 < 512
}

/// Multiplicative inverse. Precondition: `a != 0`.
#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "gf256::inv(0) is undefined");
    let t = tables();
    // 2^(255 - log a)
    t.exp[255 - usize::from(t.log[usize::from(a)])]
}

/// Accumulate `c * src` into `dst` (`dst[i] ^= mul(src[i], c)`). Lengths must match.
#[inline]
pub fn mul_slice_into(dst: &mut [u8], src: &[u8], c: u8) {
    debug_assert_eq!(dst.len(), src.len());
    if c == 0 {
        return;
    }
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= mul(s, c);
    }
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p yip-transport --lib gf256`
Expected: PASS (4 tests). Then `cargo clippy -p yip-transport --all-targets -- -D warnings` clean.

- [ ] **Step 5: Register the module + commit**

Add to `crates/yip-transport/src/lib.rs` after `pub mod fec;`:

```rust
pub mod gf256;
```

Run: `cargo build -p yip-transport`
Then:

```bash
git add crates/yip-transport/src/gf256.rs crates/yip-transport/src/lib.rs
git commit -m "feat(yip-transport): GF(256) field core for RS FEC (throughput 4a)"
```

---

### Task 2: RS-v1 Cauchy codec core

**Files:**
- Create: `crates/yip-transport/src/rs.rs`
- Modify: `crates/yip-transport/src/lib.rs` (add `pub mod rs;`), `crates/yip-transport/Cargo.toml` (add `reed-solomon-erasure` dev-dep)

**Interfaces:**
- Consumes: `crate::gf256::{mul, inv, mul_slice_into}`.
- Produces:
  - `rs::cauchy_coef(k: usize, m: usize, i: usize) -> u8` — `C[m][i] = inv((k+m) ^ i)`.
  - `rs::encode_repair(source: &[Vec<u8>], r: usize) -> Vec<Vec<u8>>` — `r` repair shards, each the length of a source shard. `source.len() = K`; all shards equal length. Requires `K + r ≤ 255`.
  - `rs::decode_source(k: usize, shard_len: usize, received: &[(u16, &[u8])]) -> Option<Vec<Vec<u8>>>` — recover the K source shards from ≥K distinct received `(symbol_index, bytes)` pairs; `None` if fewer than K usable or (defensively) singular.

- [ ] **Step 1: Write the failing tests**

Create `crates/yip-transport/src/rs.rs` with the test module (the MDS gate + oracle):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn shard(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap())).collect()
    }

    /// Every k-subset of the k+r shards must reconstruct the source (MDS).
    #[test]
    fn exhaustive_k_of_k_plus_r_decodes() {
        let len = 64usize;
        for k in 1..=8usize {
            for r in 1..=4usize {
                let source: Vec<Vec<u8>> = (0..k).map(|s| shard(u8::try_from(s).unwrap() * 7 + 1, len)).collect();
                let repair = encode_repair(&source, r);
                // all shards indexed 0..k (source) then k..k+r (repair)
                let mut all: Vec<(u16, Vec<u8>)> = Vec::new();
                for (i, s) in source.iter().enumerate() {
                    all.push((u16::try_from(i).unwrap(), s.clone()));
                }
                for (m, s) in repair.iter().enumerate() {
                    all.push((u16::try_from(k + m).unwrap(), s.clone()));
                }
                // every combination of exactly k of the k+r shards
                let n = all.len();
                for mask in 0u32..(1 << n) {
                    if mask.count_ones() as usize != k {
                        continue;
                    }
                    let recv: Vec<(u16, &[u8])> = (0..n)
                        .filter(|b| mask & (1 << b) != 0)
                        .map(|b| (all[b].0, all[b].1.as_slice()))
                        .collect();
                    let got = decode_source(k, len, &recv)
                        .unwrap_or_else(|| panic!("decode failed k={k} r={r} mask={mask:b}"));
                    assert_eq!(got, source, "k={k} r={r} mask={mask:b}");
                }
            }
        }
    }

    /// Independent-implementation agreement: reed-solomon-erasure recovers the
    /// same erasure scenarios (recovery success, not byte-identity — matrices differ).
    #[test]
    fn reed_solomon_erasure_oracle_agrees() {
        use reed_solomon_erasure::galois_8::ReedSolomon;
        let len = 32usize;
        for (k, r) in [(2usize, 2usize), (3, 2), (4, 1)] {
            let source: Vec<Vec<u8>> = (0..k).map(|s| shard(u8::try_from(s).unwrap() + 3, len)).collect();
            let rse = ReedSolomon::new(k, r).unwrap();
            let mut shards: Vec<Vec<u8>> = source.clone();
            shards.extend(std::iter::repeat(vec![0u8; len]).take(r));
            rse.encode(&mut shards).unwrap();
            // erase the first source shard; reed-solomon-erasure must recover it
            let mut opt: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            opt[0] = None;
            rse.reconstruct(&mut opt).unwrap();
            assert_eq!(opt[0].as_ref().unwrap(), &source[0], "oracle recovers k={k} r={r}");
        }
    }
}
```

- [ ] **Step 2: Add the dev-dependency, run to verify failure**

Add to `crates/yip-transport/Cargo.toml`:

```toml
[dev-dependencies]
reed-solomon-erasure = "6.0.0"
```

Run: `cargo test -p yip-transport --lib rs`
Expected: FAIL to compile (`encode_repair`/`decode_source` undefined).

- [ ] **Step 3: Implement the codec core**

Prepend to `crates/yip-transport/src/rs.rs`:

```rust
//! Normative RS-v1 systematic Reed–Solomon over GF(256) (spec §3.2.1): a Cauchy
//! generator `[ I_K ; C ]` with `C[m][i] = inv((K+m) ^ i)`, giving MDS (any K of
//! K+R shards decode). Source rows are identity, so no-loss decode is a copy.
#![forbid(unsafe_code)]

use crate::gf256;

/// Cauchy generator entry for repair row `m`, source column `i`, with `k` sources.
/// `C[m][i] = inv(x_m ^ y_i)` where `x_m = k + m`, `y_i = i`.
pub fn cauchy_coef(k: usize, m: usize, i: usize) -> u8 {
    let x = u8::try_from(k + m).expect("k+m < 256 (K+R <= 255)");
    let y = u8::try_from(i).expect("i < 256");
    gf256::inv(gf256::add(x, y)) // x ^ y != 0 since {y_i} and {x_m} are disjoint
}

/// Generate `r` repair shards from the `source` shards (all equal length).
pub fn encode_repair(source: &[Vec<u8>], r: usize) -> Vec<Vec<u8>> {
    let k = source.len();
    let len = source.first().map_or(0, Vec::len);
    let mut repair = vec![vec![0u8; len]; r];
    for (m, rep) in repair.iter_mut().enumerate() {
        for (i, src) in source.iter().enumerate() {
            gf256::mul_slice_into(rep, src, cauchy_coef(k, m, i));
        }
    }
    repair
}

/// Recover the K source shards from ≥K distinct received `(symbol_index, bytes)`.
/// Returns `None` if fewer than K distinct usable shards, or (defensively) if the
/// K×K matrix is singular (never happens for valid distinct indices — MDS).
pub fn decode_source(k: usize, shard_len: usize, received: &[(u16, &[u8])]) -> Option<Vec<Vec<u8>>> {
    // Deduplicate by index, keep the first K distinct.
    let mut seen = [false; 256];
    let mut rows: Vec<(usize, &[u8])> = Vec::with_capacity(k);
    for &(idx, bytes) in received {
        let idx = usize::from(idx);
        if idx >= 255 || bytes.len() != shard_len || seen[idx] {
            continue;
        }
        seen[idx] = true;
        rows.push((idx, bytes));
        if rows.len() == k {
            break;
        }
    }
    if rows.len() < k {
        return None;
    }

    // Fast path: all K source shards present (indices 0..k) → systematic copy.
    if rows.iter().all(|&(idx, _)| idx < k) {
        let mut out = vec![vec![0u8; shard_len]; k];
        for &(idx, bytes) in &rows {
            out[idx].copy_from_slice(bytes);
        }
        return Some(out);
    }

    // General path: build the K×K generator submatrix M for the received rows,
    // invert it (Gauss–Jordan over GF(256)), and apply to the received shards.
    // Row for source index i (< k): unit vector e_i. Row for repair index j (>= k):
    // Cauchy row (j - k), i.e. M[row][i] = cauchy_coef(k, j-k, i).
    let mut m = vec![vec![0u8; k]; k];
    for (row, &(idx, _)) in rows.iter().enumerate() {
        if idx < k {
            m[row][idx] = 1;
        } else {
            for i in 0..k {
                m[row][i] = cauchy_coef(k, idx - k, i);
            }
        }
    }
    let minv = invert(&mut m)?;

    // source_i = Σ_row minv[i][row] * received_shard[row]
    let mut out = vec![vec![0u8; shard_len]; k];
    for i in 0..k {
        for (row, &(_, bytes)) in rows.iter().enumerate() {
            gf256::mul_slice_into(&mut out[i], bytes, minv[i][row]);
        }
    }
    Some(out)
}

/// Gauss–Jordan inverse of a K×K GF(256) matrix; `None` if singular.
fn invert(a: &mut [Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = a.len();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| (0..n).map(|j| u8::from(i == j)).collect())
        .collect();
    for col in 0..n {
        // find a pivot row at/below `col` with a nonzero entry in `col`
        let piv = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, piv);
        inv.swap(col, piv);
        // normalize pivot row so a[col][col] == 1
        let d = gf256::inv(a[col][col]);
        for j in 0..n {
            a[col][j] = gf256::mul(a[col][j], d);
            inv[col][j] = gf256::mul(inv[col][j], d);
        }
        // eliminate `col` from every other row
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = a[r][col];
            if f == 0 {
                continue;
            }
            for j in 0..n {
                a[r][j] ^= gf256::mul(f, a[col][j]);
                inv[r][j] ^= gf256::mul(f, inv[col][j]);
            }
        }
    }
    Some(inv)
}
```

- [ ] **Step 4: Run to verify tests pass**

Run: `cargo test -p yip-transport --lib rs`
Expected: PASS (`exhaustive_k_of_k_plus_r_decodes`, `reed_solomon_erasure_oracle_agrees`).
Run: `cargo clippy -p yip-transport --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Register module + commit**

Add to `crates/yip-transport/src/lib.rs` after `pub mod gf256;`:

```rust
pub mod rs;
```

```bash
git add crates/yip-transport/src/rs.rs crates/yip-transport/src/lib.rs crates/yip-transport/Cargo.toml
git commit -m "feat(yip-transport): normative RS-v1 Cauchy codec core + MDS proof (throughput 4a)"
```

---

### Task 3: `fec.rs` rewrite — RS `FecEncoder`/`FecReassembler`, drop RaptorQ

**Files:**
- Rewrite: `crates/yip-transport/src/fec.rs`
- Modify: `crates/yip-transport/Cargo.toml` (drop `raptorq`), `crates/yip-bench/Cargo.toml` (drop `raptorq`), `crates/yip-transport/src/lib.rs` (`Transport::repair_object` doc comment "RaptorQ" → "FEC repair symbols")

**Interfaces:**
- Consumes: `crate::rs::{encode_repair, decode_source}`, `crate::gf256` (indirectly), `crate::FlowParams`.
- Produces (API shape unchanged — `lib.rs`/`Transport` callers untouched):
  - `Symbol { object_id: u16, object_size: u32, payload_id: [u8;4], data: Vec<u8> }`
  - `FecEncoder::new() -> Self`; `FecEncoder::encode(&mut self, ciphertext: &[u8], params: FlowParams, repair: u32) -> Vec<Symbol>`; `FecEncoder::repair_with_id(&mut self, ciphertext: &[u8], params: FlowParams, object_id: u16, extra_repair: u32) -> Vec<Symbol>`
  - `FecReassembler::new(symbol_size: u16, max_objects: usize) -> Self`; `in_flight(&self) -> usize`; `push(&mut self, &Symbol) -> Option<Vec<u8>>`

**Constants:** keep `const MAX_OBJECT_SIZE: u32 = 262_144;`. Add `const CODEC_RS_V1: u8 = 0x01;`.

- [ ] **Step 1: Write the new `fec.rs` with its tests**

Replace the entire contents of `crates/yip-transport/src/fec.rs` with:

```rust
//! Systematic Reed–Solomon FEC (RS-v1, spec §3.2.1) for the transport. Encrypt-
//! then-FEC: one sealed ciphertext frame is the object, split into K source
//! symbols of `symbol_size` (last zero-padded) plus R Cauchy repair symbols.
//! Each `Symbol` carries a codec-tagged `payload_id = [0x01, idx_hi, idx_lo, 0]`.
#![forbid(unsafe_code)]

use crate::rs;
use std::collections::{HashMap, VecDeque};

/// Maximum permitted object size for a single FEC-coded frame (256 KiB): bounds
/// the memory a forged symbol can cause the decoder to allocate.
const MAX_OBJECT_SIZE: u32 = 262_144;

/// Codec tag for RS-v1 in `payload_id[0]` (pre-slots RLC as 0x02).
const CODEC_RS_V1: u8 = 0x01;

/// One wire-bound RS symbol plus the metadata the receiver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Which pipelined object this symbol belongs to.
    pub object_id: u16,
    /// The object's original ciphertext byte count (yields K = ceil(size/symbol_size)).
    pub object_size: u32,
    /// `[codec_tag, symbol_index_hi, symbol_index_lo, reserved]`.
    pub payload_id: [u8; 4],
    /// The symbol bytes (exactly `symbol_size`).
    pub data: Vec<u8>,
}

/// Pack `[0x01, idx_be_hi, idx_be_lo, 0]`.
fn pack_payload_id(symbol_index: u16) -> [u8; 4] {
    let idx = symbol_index.to_be_bytes();
    [CODEC_RS_V1, idx[0], idx[1], 0]
}

/// Return `symbol_index` if the codec tag is RS-v1, else `None`.
fn parse_payload_id(payload_id: &[u8; 4]) -> Option<u16> {
    if payload_id[0] != CODEC_RS_V1 {
        return None;
    }
    Some(u16::from_be_bytes([payload_id[1], payload_id[2]]))
}

/// Number of source symbols for an object of `object_size` at `symbol_size`.
fn source_count(object_size: u32, symbol_size: u16) -> usize {
    let size = usize::try_from(object_size).expect("object_size fits usize");
    size.div_ceil(usize::from(symbol_size))
}

/// Split `ciphertext` into `k` source shards of `sym` bytes each (last zero-padded).
fn split_source(ciphertext: &[u8], k: usize, sym: usize) -> Vec<Vec<u8>> {
    let mut shards = vec![vec![0u8; sym]; k];
    for (i, shard) in shards.iter_mut().enumerate() {
        let start = i * sym;
        let end = (start + sym).min(ciphertext.len());
        if start < ciphertext.len() {
            shard[..end - start].copy_from_slice(&ciphertext[start..end]);
        }
    }
    shards
}

/// Encodes ciphertext frames into RS symbols, assigning monotonic object ids.
#[derive(Debug, Default)]
pub struct FecEncoder {
    next_object_id: u16,
}

impl FecEncoder {
    /// Create an encoder starting at object id 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode one ciphertext frame into K source + `repair` repair symbols.
    pub fn encode(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        repair: u32,
    ) -> Vec<Symbol> {
        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        self.build(ciphertext, params, object_id, repair)
    }

    /// Re-encode `ciphertext` under an EXPLICIT `object_id` (ARQ retransmit),
    /// returning all K source symbols + `extra_repair` repair symbols at indices
    /// K..K+extra_repair-1 — the same Cauchy rows as `encode`, so a receiver that
    /// got zero original symbols can reconstruct from this batch alone.
    pub fn repair_with_id(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        object_id: u16,
        extra_repair: u32,
    ) -> Vec<Symbol> {
        self.build(ciphertext, params, object_id, extra_repair)
    }

    /// Shared encode: K source + R repair (R clamped to 255-K), K bounds enforced.
    fn build(
        &self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        object_id: u16,
        repair: u32,
    ) -> Vec<Symbol> {
        let object_size = u32::try_from(ciphertext.len()).expect("frame fits u32");
        let sym = usize::from(params.symbol_size);
        let k = source_count(object_size, params.symbol_size);
        // Guard: K==0 (empty frame) or K>=255 (no GF(256) codeword room) → no symbols.
        if k == 0 || k >= 255 {
            return Vec::new();
        }
        let max_repair = 255 - k;
        let r = usize::try_from(repair).unwrap_or(max_repair).min(max_repair);

        let source = split_source(ciphertext, k, sym);
        let mut out = Vec::with_capacity(k + r);
        for (i, shard) in source.iter().enumerate() {
            out.push(Symbol {
                object_id,
                object_size,
                payload_id: pack_payload_id(u16::try_from(i).expect("i < 255")),
                data: shard.clone(),
            });
        }
        if r > 0 {
            for (m, rep) in rs::encode_repair(&source, r).into_iter().enumerate() {
                let idx = u16::try_from(k + m).expect("k+m < 255");
                out.push(Symbol {
                    object_id,
                    object_size,
                    payload_id: pack_payload_id(idx),
                    data: rep,
                });
            }
        }
        out
    }
}

struct ObjState {
    /// Received shards keyed by symbol_index (deduped).
    shards: HashMap<u16, Vec<u8>>,
    k: usize,
    done: bool,
}

/// Reassembles RS symbols into objects, keeping multiple objects in flight
/// (keyed by `object_id`), tolerating loss/reordering, evicting oldest at cap.
pub struct FecReassembler {
    symbol_size: u16,
    objects: HashMap<u16, ObjState>,
    order: VecDeque<u16>,
    max_objects: usize,
}

impl FecReassembler {
    /// Create a reassembler for a class's `symbol_size`, keeping at most
    /// `max_objects` partially-received objects.
    pub fn new(symbol_size: u16, max_objects: usize) -> Self {
        Self {
            symbol_size,
            objects: HashMap::new(),
            order: VecDeque::new(),
            max_objects: max_objects.max(1),
        }
    }

    /// Number of objects currently being reassembled.
    pub fn in_flight(&self) -> usize {
        self.objects.len()
    }

    /// Feed one received symbol. Returns the decoded object when it completes.
    /// Returns `None` (never panics) for any malformed/attacker field.
    pub fn push(&mut self, symbol: &Symbol) -> Option<Vec<u8>> {
        // --- Guards: object_size, codec tag, symbol_index, K bounds ---
        if symbol.object_size == 0 || symbol.object_size > MAX_OBJECT_SIZE {
            return None;
        }
        let symbol_index = parse_payload_id(&symbol.payload_id)?; // wrong codec tag → None
        if usize::from(symbol_index) >= 255 {
            return None;
        }
        if symbol.data.len() != usize::from(self.symbol_size) {
            return None;
        }
        let k = source_count(symbol.object_size, self.symbol_size);
        if k == 0 || k >= 255 {
            return None;
        }

        if !self.objects.contains_key(&symbol.object_id) {
            if self.objects.len() >= self.max_objects {
                if let Some(oldest) = self.order.pop_front() {
                    self.objects.remove(&oldest);
                }
            }
            self.objects.insert(
                symbol.object_id,
                ObjState { shards: HashMap::new(), k, done: false },
            );
            self.order.push_back(symbol.object_id);
        }
        let state = self.objects.get_mut(&symbol.object_id)?;
        if state.done {
            return None; // late/duplicate for an already-decoded object
        }
        // Dedupe by index; only store what we don't have.
        state.shards.entry(symbol_index).or_insert_with(|| symbol.data.clone());

        if state.shards.len() < state.k {
            return None;
        }

        // Decode once we hold K distinct shards.
        let received: Vec<(u16, &[u8])> =
            state.shards.iter().map(|(&idx, d)| (idx, d.as_slice())).collect();
        let sources = rs::decode_source(state.k, usize::from(self.symbol_size), &received)?;
        state.done = true;

        // Concatenate source shards and trim to the original object_size.
        let size = usize::try_from(symbol.object_size).expect("size fits usize");
        let mut object = Vec::with_capacity(state.k * usize::from(self.symbol_size));
        for shard in &sources {
            object.extend_from_slice(shard);
        }
        object.truncate(size);
        Some(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    #[test]
    fn source_symbols_are_systematic_raw_data() {
        let params = FlowClass::Default.params();
        let ct = vec![0x5Au8; 1200];
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 0);
        assert_eq!(syms.len(), 1); // K=1, R=0
        assert_eq!(syms[0].payload_id, [CODEC_RS_V1, 0, 0, 0]);
        assert_eq!(syms[0].data, ct); // systematic: symbol == data
    }

    #[test]
    fn encode_indices_and_tags_are_correct() {
        let params = FlowClass::Bulk.params();
        let ct = vec![0x11u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 3); // R=3
        assert_eq!(syms.len(), 5);
        let idx: Vec<u16> = syms.iter().map(|s| parse_payload_id(&s.payload_id).unwrap()).collect();
        assert_eq!(idx, vec![0, 1, 2, 3, 4]);
        assert!(syms.iter().all(|s| s.object_size == 2400 && s.object_id == 0));
    }

    #[test]
    fn roundtrips_through_erasure_and_reordering() {
        let params = FlowClass::Bulk.params();
        let ct: Vec<u8> = (0..5000u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let mut enc = FecEncoder::new();
        let mut syms = enc.encode(&ct, params, 4);
        syms.reverse();
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for (i, s) in syms.iter().enumerate() {
            if i % 4 == 0 {
                continue; // drop every 4th
            }
            if let Some(frame) = re.push(s) {
                out = Some(frame);
                break;
            }
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn no_loss_decodes_from_source_only() {
        let params = FlowClass::Default.params();
        let ct: Vec<u8> = (0..3600u32).map(|i| u8::try_from(i % 251).unwrap()).collect(); // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for s in syms.iter().take(3) {
            // only the 3 source symbols
            out = out.or(re.push(s));
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn repair_with_id_reencodes_full_object_for_zero_shard_receiver() {
        let params = FlowClass::Default.params();
        let ct = vec![0x33u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let first = enc.encode(&ct, params, 1);
        let oid = first[0].object_id;
        // Receiver got NOTHING from the first batch. ARQ re-encode with extra=4.
        let batch = enc.repair_with_id(&ct, params, oid, 4);
        assert!(batch.iter().all(|s| s.object_id == oid));
        assert_eq!(batch.len(), 6); // 2 source + 4 repair
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for s in &batch {
            out = out.or(re.push(s));
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()), "ARQ batch alone reconstructs");
    }

    // --- Guard / DoS tests ---

    fn sym(object_size: u32, index: u16, sym_size: usize) -> Symbol {
        Symbol { object_id: 0, object_size, payload_id: pack_payload_id(index), data: vec![0u8; sym_size] }
    }

    #[test]
    fn rejects_zero_and_oversized_object_size() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(&sym(0, 0, 1200)), None);
        assert_eq!(re.push(&sym(MAX_OBJECT_SIZE + 1, 0, 1200)), None);
    }

    #[test]
    fn rejects_wrong_codec_tag() {
        let mut re = FecReassembler::new(1200, 64);
        let mut s = sym(1200, 0, 1200);
        s.payload_id[0] = 0x02; // not RS-v1
        assert_eq!(re.push(&s), None);
    }

    #[test]
    fn rejects_out_of_range_symbol_index() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(&sym(1200, 255, 1200)), None);
        assert_eq!(re.push(&sym(1200, 60000, 1200)), None);
    }

    #[test]
    fn rejects_wrong_symbol_length() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(&sym(1200, 0, 999)), None); // not symbol_size
    }

    #[test]
    fn duplicate_index_is_deduped_not_double_counted() {
        let params = FlowClass::Bulk.params();
        let ct = vec![0x42u8; 3600]; // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        // Push symbol 0 three times, then 1, 2 → only 3 distinct → decodes exactly once.
        assert_eq!(re.push(&syms[0]), None);
        assert_eq!(re.push(&syms[0]), None);
        assert_eq!(re.push(&syms[0]), None);
        assert_eq!(re.push(&syms[1]), None);
        let out = re.push(&syms[2]);
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn late_symbol_after_decode_returns_none() {
        let params = FlowClass::Default.params();
        let ct = vec![0xABu8; 1200];
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut decoded = false;
        for s in &syms {
            if re.push(s).is_some() {
                decoded = true;
                break;
            }
        }
        assert!(decoded);
        assert_eq!(re.push(&syms[0]), None); // late/dup after completion
    }

    #[test]
    fn evicts_oldest_when_full() {
        let params = FlowClass::Default.params();
        let mut enc = FecEncoder::new();
        let a = enc.encode(b"first object payload contents here!!", params, 4);
        let b = enc.encode(b"second object payload contents here!", params, 4);
        let mut re = FecReassembler::new(params.symbol_size, 1); // cap 1
        re.push(&a[0]); // partial a
        assert_eq!(re.in_flight(), 1);
        let mut got_b = None;
        for s in &b {
            got_b = got_b.or(re.push(s));
        }
        assert_eq!(got_b.as_deref(), Some(&b"second object payload contents here!"[..]));
    }
}
```

- [ ] **Step 2: Run to verify tests fail (RaptorQ still referenced by Cargo)**

Run: `cargo test -p yip-transport --lib fec`
Expected: the new `fec.rs` compiles against `rs`/`gf256` and tests PASS. (If `raptorq` is now an unused dependency, `cargo` still builds; the shear/lint cleanup is Step 3.)

- [ ] **Step 3: Drop RaptorQ from both crates + fix doc comment**

Edit `crates/yip-transport/Cargo.toml` — remove the line `raptorq = "2.0.0"` (the `[package.metadata.cargo-shear] ignored = ["yip-wire"]` line stays).
Edit `crates/yip-bench/Cargo.toml` — remove the line `raptorq = "2.0.0"` (line 14).
Edit `crates/yip-transport/src/lib.rs` — in `Transport::repair_object`'s doc comment, replace "RaptorQ repair symbols" wording with "FEC repair symbols" (search the doc block above `pub fn repair_object`).

- [ ] **Step 4: Full crate build + tests + lints**

Run: `cargo build -p yip-transport -p yip-bench`
Expected: compiles with no `raptorq` dependency.
Run: `cargo test -p yip-transport`
Expected: all lib + integration tests pass (the pre-existing `lib.rs` transport tests — `transport_encodes_classifies_and_decodes_through_loss`, `retransmitted_repair_completes_a_missing_object`, etc. — exercise the new codec end-to-end and must stay green).
Run: `cargo clippy -p yip-transport -p yip-bench --all-targets -- -D warnings && cargo fmt -p yip-transport -- --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/fec.rs crates/yip-transport/src/lib.rs \
        crates/yip-transport/Cargo.toml crates/yip-bench/Cargo.toml Cargo.lock
git commit -m "feat(yip-transport): swap RaptorQ for systematic RS FEC codec (throughput 4a)

Rewrite FecEncoder/FecReassembler over the gf256+rs core: K source + Cauchy
repair symbols, codec-tagged payload_id, systematic no-loss decode, erasure
recovery via GF(256) Gauss-Jordan. repair_with_id re-encodes the whole object
(ARQ contract preserved). All DoS guards + new K/tag/dedupe guards. raptorq
dependency removed from yip-transport and yip-bench."
```

---

### Task 4: Benchmarks + no-regression

**Files:**
- Modify/append: `crates/yip-bench/RESULTS.md`
- Run-only: `crates/yip-bench/benches/hotpath.rs` (`transport_encode_1300`), `crates/yip-bench/examples/pipeline_profile.rs`, `bin/yipd/tests/run-netns-*.sh`

**Interfaces:** Consumes the Task 3 codec via `Transport` (benches/netns use `Transport`, unchanged API).

- [ ] **Step 1: Encode benchmark (after)**

Run: `cargo bench -p yip-bench --bench hotpath -- transport_encode_1300`
Expected: median well under 1 µs (vs the ~26 µs RaptorQ baseline). Record the value.

- [ ] **Step 2: Pipeline profile (after)**

Run: `cargo run --release -p yip-bench --example pipeline_profile`
Expected: `encode` line ≪ 1 µs; `symbols/packet` ~2.00; `decoded ok : 5000/5000`. Record.

- [ ] **Step 3: Record results**

Append a dated "Throughput 4a — RS codec" section to `crates/yip-bench/RESULTS.md`: `transport_encode_1300` before (~26 µs) / after; `pipeline_profile` encode before/after; and the single-core throughput implication (FEC term now ≪ AEAD 2 µs → AEAD-bound → multi-gigabit single core per the model).

- [ ] **Step 4: No-regression — full workspace tests**

Run: `cargo test`
Expected: all workspace tests pass.

- [ ] **Step 5: No-regression — netns loss + ARQ (end-to-end gate)**

Rebuild release first, then the FEC-exercising netns paths (need `sudo`/network namespaces):

```bash
cargo build --release
for s in run-netns-tunnel run-netns-tunnel-loss run-netns-tunnel-l2 run-arq-integrity; do
  echo "== $s =="; sudo bin/yipd/tests/$s.sh || echo "FAILED: $s"
done
```
Expected: each reports success — clean tunnel + ping; the loss variant proves RS recovers dropped symbols end-to-end; ARQ integrity proves `repair_with_id` tops up a stalled object. If the environment cannot run netns/sudo, record that these were skipped and note the exhaustive MDS property test (Task 2) + `fec` round-trip tests (Task 3) are the correctness guarantee.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-bench/RESULTS.md
git commit -m "bench(throughput-4a): record RS codec encode speedup + no-regression"
```

---

## Self-Review

**1. Spec coverage:**
- §3.1 GF(256) core → Task 1. ✅
- §3.2 + §3.2.1 normative Cauchy encoder, R clamp, K bounds → Task 2 (`rs`), Task 3 (`FecEncoder`). ✅
- §3.2 `repair_with_id` full re-encode → Task 3 (`repair_with_id`/`build`) + `repair_with_id_reencodes_full_object_for_zero_shard_receiver`. ✅
- §3.3 reassembler (systematic passthrough, erasure decode, DoS guards, dedupe/free) → Task 3 (`FecReassembler`) + guard tests. ✅
- §5 invariants → MDS property (Task 2), systematic (`no_loss_decodes_from_source_only`), K+R≤255 clamp (Task 3 `build`), no-panic guards (Task 3). ✅
- §6 wire framing (`payload_id` pack/parse, tag, wire_glue unchanged) → Task 3 `pack_payload_id`/`parse_payload_id`; wire_glue untouched. ✅
- §7 tests (field axioms, exhaustive MDS, oracle, DoS, pack/parse, benches, netns) → Tasks 1–4. ✅
- §8 scope (drop raptorq both crates, doc comments, gf256/rs new modules) → Task 3. ✅

**2. Placeholder scan:** No TBD/TODO; every code step carries complete code. ✅

**3. Type consistency:** `rs::encode_repair(&[Vec<u8>], usize) -> Vec<Vec<u8>>` and `rs::decode_source(usize, usize, &[(u16, &[u8])]) -> Option<Vec<Vec<u8>>>` are used consistently by `FecEncoder::build` and `FecReassembler::push`. `Symbol` fields, `pack_payload_id`/`parse_payload_id` (`[u8;4]` ↔ `u16`), `source_count`, `MAX_OBJECT_SIZE`, `CODEC_RS_V1` are consistent across the rewrite. `FecEncoder`/`FecReassembler` public signatures match the pre-existing `lib.rs` callers (`Transport::encode`/`decode`/`repair_object`). ✅
