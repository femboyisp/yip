# P+Q Fast-Path FEC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make proactive FEC repair cheap for R≤2 (P+Q / RAID-6) so loss protection stays on without the general Cauchy solve, keeping per-packet CPU low.

**Architecture:** Add a generator **scheme** to the RS codec: `SCHEME_PQ` (P = XOR all-ones, Q = 2^i syndrome; MDS for R≤2) for R≤2, and the existing `SCHEME_CAUCHY` for R≥3. Both encode and decode compute a repair row via one `rs::repair_row(scheme, k, m)` primitive. The scheme rides in the reserved `payload_id[3]` byte so the decoder is unambiguous. `gf256`, `yip-wire`, and `wire_glue` are untouched.

**Tech Stack:** Rust, the shipped `gf256`/`rs`/`fec` in `crates/yip-transport`.

**Spec:** `docs/superpowers/specs/2026-07-11-throughput-pq-fec-design.md`.

## Global Constraints

- `crates/yip-transport` is `#![forbid(unsafe_code)]` — no `unsafe`.
- No `as` numeric casts except enum discriminants — use `try_from`/`from`.
- **Normative P+Q (spec §3):** `SCHEME_PQ` (id `1`) for R≤2 — repair row `m=0` = **P** (`coef_i = 1` ∀i, the XOR), row `m=1` = **Q** (`coef_i = 2^i`, generator^i over GF(256)). `SCHEME_CAUCHY` (id `0`) for R≥3 — `cauchy_coef(k,m,i) = inv((k+m)^i)`. Repair row depends only on `(scheme, K, m)`, never on R.
- **R=1 repair is a pure XOR** on the encode hot path (no GF multiply) — realize it in `rs.rs` (do NOT modify `gf256`).
- Scheme selection: `R ≤ 2 → SCHEME_PQ`, `R ≥ 3 → SCHEME_CAUCHY`.
- `payload_id` layout = `[codec_tag=0x01][symbol_index:u16 BE][scheme:u8]`, on **every** symbol of a block (source and repair).
- **MDS invariant:** any K of K+R shards reconstruct byte-for-byte — P+Q at R∈{1,2}, Cauchy at R∈{3,4}, K∈{1,2,3,8}.
- DoS guards preserved + **ingest guard:** `FecReassembler::push` rejects (before storing) a `SCHEME_PQ` symbol with `symbol_index ≥ K+2`, an unknown scheme id, and (existing) wrong codec tag / `symbol_index ≥ 255` / zero-or-oversized `object_size` / `K==0`/`K≥255`. Never panics.
- Untouched: `gf256.rs`, `yip-wire`, `wire_glue.rs`, `control.rs`, `lib.rs` public API, the QUIC path.
- `refrences/` is read-only.

---

## File Structure

- `crates/yip-transport/src/rs.rs` — **modify.** Add `Scheme` enum + `SCHEME_CAUCHY`/`SCHEME_PQ` consts, `repair_row(scheme,k,m)`, `scheme` arg on `encode_repair`/`decode_source` (with the PQ `m≥2` reject), the R=1 XOR fast path.
- `crates/yip-transport/src/fec.rs` — **modify.** `pack_payload_id(idx, scheme_u8)`, `parse_payload_id -> Option<(u16, Scheme)>`, scheme selection in `build`, `ObjState.scheme`, `push` ingest guard + scheme threading to `decode_source`.
- `crates/yip-bench/benches/hotpath.rs` + `crates/yip-bench/RESULTS.md` — **modify (Task 2).** R=1/R=2 encode benchmark + record.

Tasks 1 (rs.rs + fec.rs) are one unit because the signature change ripples between them; splitting would leave the crate non-compiling mid-task.

---

### Task 1: P+Q scheme in `rs.rs` + `fec.rs`

**Files:**
- Modify: `crates/yip-transport/src/rs.rs`, `crates/yip-transport/src/fec.rs`

**Interfaces:**
- Consumes: `gf256::{mul, mul_slice_into, add}` (unchanged), existing `rs::cauchy_coef`, `rs::invert`.
- Produces:
  - `rs::Scheme { Cauchy, Pq }`; `rs::SCHEME_CAUCHY=0u8`, `rs::SCHEME_PQ=1u8`; `Scheme::to_u8()`, `Scheme::from_u8(u8)->Option<Scheme>`, `Scheme::for_repair(r: usize)->Scheme`.
  - `rs::repair_row(scheme: Scheme, k: usize, m: usize) -> Vec<u8>`.
  - `rs::encode_repair(source: &[Vec<u8>], r: usize, scheme: Scheme) -> Vec<Vec<u8>>`.
  - `rs::decode_source(k: usize, shard_len: usize, received: &[(u16, &[u8])], scheme: Scheme) -> Option<Vec<Vec<u8>>>`.
  - `fec.rs` internal: `pack_payload_id(u16, u8)`, `parse_payload_id(&[u8;4]) -> Option<(u16, rs::Scheme)>`; `ObjState.scheme: rs::Scheme`.

- [ ] **Step 1: Write the failing `rs.rs` tests (schemes + MDS for both)**

In `crates/yip-transport/src/rs.rs`, replace the existing `#[cfg(test)] mod tests` block's contents so it exercises both schemes. Add these tests (keep the existing `shard` helper):

```rust
#[test]
fn repair_row_p_is_all_ones_q_is_powers_of_two() {
    assert_eq!(repair_row(Scheme::Pq, 4, 0), vec![1, 1, 1, 1]);
    // Q: 2^0,2^1,2^2,2^3 over GF(256) = 1,2,4,8
    assert_eq!(repair_row(Scheme::Pq, 4, 1), vec![1, 2, 4, 8]);
    // Cauchy row matches cauchy_coef
    let cr = repair_row(Scheme::Cauchy, 3, 0);
    assert_eq!(cr, vec![cauchy_coef(3, 0, 0), cauchy_coef(3, 0, 1), cauchy_coef(3, 0, 2)]);
}

#[test]
fn scheme_u8_roundtrip_and_selection() {
    assert_eq!(Scheme::from_u8(SCHEME_CAUCHY), Some(Scheme::Cauchy));
    assert_eq!(Scheme::from_u8(SCHEME_PQ), Some(Scheme::Pq));
    assert_eq!(Scheme::from_u8(9), None);
    assert_eq!(Scheme::Pq.to_u8(), SCHEME_PQ);
    assert_eq!(Scheme::for_repair(1), Scheme::Pq);
    assert_eq!(Scheme::for_repair(2), Scheme::Pq);
    assert_eq!(Scheme::for_repair(3), Scheme::Cauchy);
}

/// Every k-subset of the k+r shards must reconstruct, for the scheme yip uses at that R.
#[test]
fn exhaustive_k_of_k_plus_r_decodes_both_schemes() {
    let len = 64usize;
    let cases = [
        (Scheme::Pq, 1usize),
        (Scheme::Pq, 2usize),
        (Scheme::Cauchy, 3usize),
        (Scheme::Cauchy, 4usize),
    ];
    for (scheme, r) in cases {
        for k in 1..=8usize {
            let source: Vec<Vec<u8>> =
                (0..k).map(|s| shard(u8::try_from(s).unwrap() * 7 + 1, len)).collect();
            let repair = encode_repair(&source, r, scheme);
            let mut all: Vec<(u16, Vec<u8>)> = Vec::new();
            for (i, s) in source.iter().enumerate() {
                all.push((u16::try_from(i).unwrap(), s.clone()));
            }
            for (m, s) in repair.iter().enumerate() {
                all.push((u16::try_from(k + m).unwrap(), s.clone()));
            }
            let n = all.len();
            for mask in 0u32..(1 << n) {
                if usize::try_from(mask.count_ones()).unwrap() != k {
                    continue;
                }
                let recv: Vec<(u16, &[u8])> = (0..n)
                    .filter(|b| mask & (1 << b) != 0)
                    .map(|b| (all[b].0, all[b].1.as_slice()))
                    .collect();
                let got = decode_source(k, len, &recv, scheme)
                    .unwrap_or_else(|| panic!("decode failed scheme={scheme:?} k={k} r={r} mask={mask:b}"));
                assert_eq!(got, source, "scheme={scheme:?} k={k} r={r} mask={mask:b}");
            }
        }
    }
}

/// P+Q must recover ANY two erasures at k=4,r=2 (the RAID-6 property).
#[test]
fn pq_recovers_every_two_erasures() {
    let len = 48usize;
    let k = 4usize;
    let source: Vec<Vec<u8>> = (0..k).map(|s| shard(u8::try_from(s).unwrap() + 9, len)).collect();
    let repair = encode_repair(&source, 2, Scheme::Pq);
    let mut all: Vec<(u16, Vec<u8>)> = Vec::new();
    for (i, s) in source.iter().enumerate() {
        all.push((u16::try_from(i).unwrap(), s.clone()));
    }
    for (m, s) in repair.iter().enumerate() {
        all.push((u16::try_from(k + m).unwrap(), s.clone()));
    }
    let n = all.len(); // k+2 = 6
    for a in 0..n {
        for b in (a + 1)..n {
            let recv: Vec<(u16, &[u8])> = (0..n)
                .filter(|&x| x != a && x != b)
                .map(|x| (all[x].0, all[x].1.as_slice()))
                .collect();
            let got = decode_source(k, len, &recv, Scheme::Pq).expect("k of k+2 decodes");
            assert_eq!(got, source, "erased {a},{b}");
        }
    }
}

/// A SCHEME_PQ repair index with m>=2 is invalid → decode returns None (no panic).
#[test]
fn pq_rejects_repair_row_ge_2() {
    let len = 16usize;
    let k = 2usize;
    let source: Vec<Vec<u8>> = (0..k).map(|s| shard(u8::try_from(s).unwrap() + 1, len)).collect();
    // Fabricate: 1 real source (idx 0) + a bogus repair at index k+2 (m=2), scheme Pq.
    let bogus = vec![0u8; len];
    let recv: Vec<(u16, &[u8])> = vec![
        (0u16, source[0].as_slice()),
        (u16::try_from(k + 2).unwrap(), bogus.as_slice()),
    ];
    assert_eq!(decode_source(k, len, &recv, Scheme::Pq), None);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-transport --lib rs`
Expected: FAIL to compile (`Scheme`, `repair_row`, the new `encode_repair`/`decode_source` arity undefined).

- [ ] **Step 3: Implement the scheme in `rs.rs`**

Update `crates/yip-transport/src/rs.rs`. Add after the `use crate::gf256;` line:

```rust
/// Generator scheme for the repair rows (packed into `payload_id[3]` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Cauchy generator (MDS for all R). Used for R >= 3.
    Cauchy,
    /// RAID-6-style P+Q (MDS for R <= 2). P = XOR all-ones, Q = 2^i syndrome.
    Pq,
}

/// Wire id for `Scheme::Cauchy`.
pub const SCHEME_CAUCHY: u8 = 0;
/// Wire id for `Scheme::Pq`.
pub const SCHEME_PQ: u8 = 1;

impl Scheme {
    /// Wire id for `payload_id[3]`.
    pub fn to_u8(self) -> u8 {
        match self {
            Scheme::Cauchy => SCHEME_CAUCHY,
            Scheme::Pq => SCHEME_PQ,
        }
    }

    /// Parse a wire id; `None` for an unknown scheme.
    pub fn from_u8(v: u8) -> Option<Scheme> {
        match v {
            SCHEME_CAUCHY => Some(Scheme::Cauchy),
            SCHEME_PQ => Some(Scheme::Pq),
            _ => None,
        }
    }

    /// The scheme the encoder uses for `r` repair symbols: P+Q for r<=2, Cauchy for r>=3.
    pub fn for_repair(r: usize) -> Scheme {
        if r <= 2 {
            Scheme::Pq
        } else {
            Scheme::Cauchy
        }
    }
}

/// The K generator coefficients for repair row `m` under `scheme`.
/// For `Scheme::Pq`, only `m ∈ {0,1}` is valid (P, Q); callers guard higher `m`
/// (an out-of-range PQ row here yields an all-zero row, never reached in practice).
pub fn repair_row(scheme: Scheme, k: usize, m: usize) -> Vec<u8> {
    match scheme {
        Scheme::Cauchy => (0..k).map(|i| cauchy_coef(k, m, i)).collect(),
        Scheme::Pq => match m {
            0 => vec![1u8; k], // P: all ones (XOR)
            1 => {
                // Q: [2^0, 2^1, ..., 2^(k-1)] over GF(256), built incrementally.
                let mut p = 1u8;
                (0..k)
                    .map(|_| {
                        let c = p;
                        p = gf256::mul(p, 2);
                        c
                    })
                    .collect()
            }
            _ => vec![0u8; k],
        },
    }
}
```

Replace `encode_repair` with the scheme-aware version (with the pure-XOR fast path for `coef == 1`, which makes the P row — and Q's first term — plain XOR, no GF multiply):

```rust
/// Generate `r` repair shards from the `source` shards (all equal length) under `scheme`.
pub fn encode_repair(source: &[Vec<u8>], r: usize, scheme: Scheme) -> Vec<Vec<u8>> {
    let k = source.len();
    let len = source.first().map_or(0, Vec::len);
    let mut repair = vec![vec![0u8; len]; r];
    for (m, rep) in repair.iter_mut().enumerate() {
        let coefs = repair_row(scheme, k, m);
        for (src, &c) in source.iter().zip(coefs.iter()) {
            if c == 1 {
                // Pure-XOR fast path (the entire P row; Q's i=0 term).
                for (d, &s) in rep.iter_mut().zip(src.iter()) {
                    *d ^= s;
                }
            } else if c != 0 {
                gf256::mul_slice_into(rep, src, c);
            }
        }
    }
    repair
}
```

In `decode_source`, add the `scheme: Scheme` parameter and build each repair submatrix row via `repair_row`, rejecting an invalid PQ row. Change the signature and the general-path row build:

```rust
pub fn decode_source(
    k: usize,
    shard_len: usize,
    received: &[(u16, &[u8])],
    scheme: Scheme,
) -> Option<Vec<Vec<u8>>> {
```

and replace the general-path submatrix construction (the `else { for (i, cell) ... cauchy_coef ... }` block) with:

```rust
        if idx < k {
            m[row][idx] = 1;
        } else {
            let rm = idx - k; // repair row index (0-based)
            if scheme == Scheme::Pq && rm >= 2 {
                return None; // invalid P+Q repair row
            }
            m[row].copy_from_slice(&repair_row(scheme, k, rm));
        }
```

- [ ] **Step 4: Run the `rs.rs` tests**

Run: `cargo test -p yip-transport --lib rs`
Expected: PASS — all five new tests. (`fec.rs` won't compile yet because it calls the old signatures; that's Step 5.)

- [ ] **Step 5: Write the failing `fec.rs` tests**

Add to `crates/yip-transport/src/fec.rs` `#[cfg(test)] mod tests` (the existing tests that call `parse_payload_id(...).unwrap()` for an index must become `.unwrap().0` — update those call sites):

```rust
#[test]
fn r1_uses_pq_scheme_in_payload_id() {
    let params = FlowClass::Default.params(); // ratio 0.10 → R=1 at K=2
    let ct = vec![0x11u8; 2400]; // K=2
    let mut enc = FecEncoder::new();
    let syms = enc.encode(&ct, params, 1);
    // scheme byte (payload_id[3]) is SCHEME_PQ on every symbol
    assert!(syms.iter().all(|s| s.payload_id[3] == crate::rs::SCHEME_PQ));
}

#[test]
fn r3_uses_cauchy_scheme() {
    let params = FlowClass::Bulk.params();
    let ct = vec![0x22u8; 3600]; // K=3
    let mut enc = FecEncoder::new();
    let syms = enc.encode(&ct, params, 3);
    assert!(syms.iter().all(|s| s.payload_id[3] == crate::rs::SCHEME_CAUCHY));
}

#[test]
fn r1_pq_block_roundtrips_through_erasure() {
    let params = FlowClass::Default.params();
    let ct: Vec<u8> = (0..3600u32).map(|i| u8::try_from(i % 251).unwrap()).collect(); // K=3
    let mut enc = FecEncoder::new();
    let syms = enc.encode(&ct, params, 1); // K=3, R=1 (P), 4 symbols
    let mut re = FecReassembler::new(params.symbol_size, 64);
    let mut out = None;
    // drop one source symbol; the P repair recovers it
    for (i, s) in syms.iter().enumerate() {
        if i == 1 {
            continue;
        }
        out = out.or(re.push(s));
    }
    assert_eq!(out.as_deref(), Some(ct.as_slice()));
}

#[test]
fn r2_pq_block_recovers_two_losses() {
    let params = FlowClass::Realtime.params();
    let ct: Vec<u8> = (0..4800u32).map(|i| u8::try_from(i % 251).unwrap()).collect(); // K=4
    let mut enc = FecEncoder::new();
    let syms = enc.encode(&ct, params, 2); // K=4, R=2 (P+Q), 6 symbols
    let mut re = FecReassembler::new(params.symbol_size, 64);
    let mut out = None;
    for (i, s) in syms.iter().enumerate() {
        if i == 0 || i == 2 {
            continue; // drop two sources
        }
        out = out.or(re.push(s));
    }
    assert_eq!(out.as_deref(), Some(ct.as_slice()));
}

#[test]
fn reassembler_rejects_pq_repair_index_out_of_range() {
    let params = FlowClass::Default.params();
    let ct = vec![0x33u8; 2400]; // K=2
    let mut enc = FecEncoder::new();
    let syms = enc.encode(&ct, params, 1); // K=2, R=1, PQ
    let mut re = FecReassembler::new(params.symbol_size, 64);
    // Craft a PQ symbol at index K+2 (=4) — an invalid P/Q row — must be rejected.
    let mut bad = syms[0].clone();
    bad.payload_id = pack_payload_id(4, crate::rs::SCHEME_PQ);
    assert_eq!(re.push(&bad), None);
}

#[test]
fn reassembler_rejects_unknown_scheme() {
    let mut re = FecReassembler::new(1200, 64);
    let mut s = sym(2400, 0, 1200);
    s.payload_id[3] = 9; // unknown scheme id
    assert_eq!(re.push(&s), None);
}
```

- [ ] **Step 6: Run to verify failure**

Run: `cargo test -p yip-transport --lib fec`
Expected: FAIL to compile (`pack_payload_id`/`parse_payload_id` arity, `payload_id[3]` scheme not set).

- [ ] **Step 7: Implement the scheme in `fec.rs`**

Update `crates/yip-transport/src/fec.rs`.

Replace `pack_payload_id`/`parse_payload_id`:

```rust
/// Pack `[0x01, idx_be_hi, idx_be_lo, scheme]`.
fn pack_payload_id(symbol_index: u16, scheme: u8) -> [u8; 4] {
    let idx = symbol_index.to_be_bytes();
    [CODEC_RS_V1, idx[0], idx[1], scheme]
}

/// Return `(symbol_index, scheme)` if the codec tag is RS-v1 and the scheme id is
/// known, else `None`.
fn parse_payload_id(payload_id: &[u8; 4]) -> Option<(u16, rs::Scheme)> {
    if payload_id[0] != CODEC_RS_V1 {
        return None;
    }
    let scheme = rs::Scheme::from_u8(payload_id[3])?;
    Some((u16::from_be_bytes([payload_id[1], payload_id[2]]), scheme))
}
```

In `FecEncoder::build`, choose the scheme and pack it on every symbol. Replace the body from the `let source = split_source(...)` line through the repair loop:

```rust
        let source = split_source(ciphertext, k, sym);
        let scheme = rs::Scheme::for_repair(r);
        let scheme_u8 = scheme.to_u8();
        let mut out = Vec::with_capacity(k + r);
        for (i, shard) in source.iter().enumerate() {
            out.push(Symbol {
                object_id,
                object_size,
                payload_id: pack_payload_id(u16::try_from(i).expect("i < 255"), scheme_u8),
                data: shard.clone(),
            });
        }
        if r > 0 {
            for (m, rep) in rs::encode_repair(&source, r, scheme).into_iter().enumerate() {
                let idx = u16::try_from(k + m).expect("k+m < 255");
                out.push(Symbol {
                    object_id,
                    object_size,
                    payload_id: pack_payload_id(idx, scheme_u8),
                    data: rep,
                });
            }
        }
        out
```

Add `scheme` to `ObjState` (find its `struct ObjState { ... }` definition and add the field):

```rust
struct ObjState {
    shards: HashMap<u16, Vec<u8>>,
    k: usize,
    scheme: rs::Scheme,
    done: bool,
}
```

In `FecReassembler::push`, thread the scheme through. Replace from the `let symbol_index = parse_payload_id(...)?;` line down to the `decode_source` call:

```rust
        let (symbol_index, scheme) = parse_payload_id(&symbol.payload_id)?; // bad tag/scheme → None
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
        // Ingest guard: a P+Q repair row m>=2 (index >= K+2) is invalid.
        if scheme == rs::Scheme::Pq && usize::from(symbol_index) >= k + 2 {
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
                ObjState {
                    shards: HashMap::new(),
                    k,
                    scheme,
                    done: false,
                },
            );
            self.order.push_back(symbol.object_id);
        }
        let state = self.objects.get_mut(&symbol.object_id)?;
        if state.done {
            return None; // late/duplicate for an already-decoded object
        }
        // Reject a symbol whose scheme disagrees with the block's (confusion guard).
        if state.scheme != scheme {
            return None;
        }
        // Dedupe by index; only store what we don't have.
        state
            .shards
            .entry(symbol_index)
            .or_insert_with(|| symbol.data.clone());

        if state.shards.len() < state.k {
            return None;
        }

        // Decode once we hold K distinct shards.
        let received: Vec<(u16, &[u8])> = state
            .shards
            .iter()
            .map(|(&idx, d)| (idx, d.as_slice()))
            .collect();
        let sources =
            rs::decode_source(state.k, usize::from(self.symbol_size), &received, state.scheme)?;
```

- [ ] **Step 8: Run the full `yip-transport` suite**

Run: `cargo test -p yip-transport`
Expected: PASS — the new `rs`/`fec` tests plus all pre-existing tests (the `lib.rs` `Transport` integration tests exercise the new scheme selection end-to-end; `retransmitted_repair_completes_a_missing_object` etc. must stay green).
Run: `cargo clippy -p yip-transport --all-targets -- -D warnings && cargo fmt -p yip-transport -- --check`
Expected: clean. (Run `cargo fmt -p yip-transport` yourself first — the pre-commit fmt hook only checks.)

- [ ] **Step 9: Commit**

```bash
git add crates/yip-transport/src/rs.rs crates/yip-transport/src/fec.rs
git commit -m "feat(yip-transport): P+Q fast-path FEC for R<=2 (throughput)

Add a generator Scheme (Cauchy | Pq) signaled in payload_id[3]. R<=2 uses
RAID-6 P+Q (P=XOR all-ones, Q=2^i syndrome, MDS for R<=2) with a pure-XOR
fast path for the P row; R>=3 keeps Cauchy. Reassembler threads the block
scheme and rejects out-of-range P+Q rows / unknown schemes. gf256/yip-wire
untouched."
```

---

### Task 2: Benchmark + no-regression

**Files:**
- Modify: `crates/yip-bench/benches/hotpath.rs` (add an R=2 encode bench alongside the existing R-driven `transport_encode_1300`), `crates/yip-bench/RESULTS.md`.
- Run-only: `bin/yipd/tests/run-netns-tunnel-loss.sh`, `run-arq-integrity.sh`, `run-netns-tunnel.sh`.

**Interfaces:** Consumes the Task 1 codec via `Transport` (unchanged API).

- [ ] **Step 1: Add R=1 and R=2 codec benchmarks**

After Task 1, the existing `transport_encode_1300` bench already measures the **R=1 P/XOR path** (unmarked → Default class, ratio 0.10, K=2 → R=1 → `SCHEME_PQ`), so it needs no change — it becomes the R=1 measurement. To also measure the **R=2 P+Q (Q-row)** path we call `FecEncoder` directly, because forcing R=2 through `Transport` would need a ~17 KB object (`ceil(0.15·K) ≥ 2` ⇒ K ≥ 14). In `crates/yip-bench/benches/hotpath.rs`, ensure the imports include `FecEncoder`, `FlowClass` (from `yip_transport`), and inside `bench_fec_and_classify` add after the existing `transport_encode_1300` bench:

```rust
    // Isolate the P+Q codec cost directly (Transport can't force R=2 on a packet-sized
    // object). K=3 object; repair=1 = P (pure XOR), repair=2 = P+Q.
    use yip_transport::{FecEncoder, FlowClass};
    let fec_params = FlowClass::Default.params();
    let fec_ct = vec![0xCDu8; 3600]; // K = 3
    c.bench_function("fec_encode_r1_p", |bn| {
        let mut enc = FecEncoder::new();
        bn.iter(|| black_box(enc.encode(black_box(&fec_ct), black_box(fec_params), 1)))
    });
    c.bench_function("fec_encode_r2_pq", |bn| {
        let mut enc = FecEncoder::new();
        bn.iter(|| black_box(enc.encode(black_box(&fec_ct), black_box(fec_params), 2)))
    });
```

- [ ] **Step 2: Capture the encode benchmarks**

Run: `cargo bench -p yip-bench --bench hotpath -- encode`
Expected: `transport_encode_1300` and `fec_encode_r1_p` (R=1, P/XOR path) medians **below** 4a's ~1.3 µs — ideally sub-µs; `fec_encode_r2_pq` (P+Q) also below the general-Cauchy baseline. Record the three medians.

- [ ] **Step 3: Record results**

Append a dated "P+Q fast-path FEC" section to `crates/yip-bench/RESULTS.md`: the R=1 encode median before (4a ~1.3 µs) vs after (P/XOR), the R=2 median, and the takeaway (proactive R≤2 repair now sub-µs → protection stays on within the per-packet budget).

- [ ] **Step 4: No-regression — transport suite + netns**

Run: `cargo test -p yip-transport && cargo test`
Expected: all green.
Rebuild release, then the FEC-exercising netns tests (need sudo/netns):

```bash
cargo build --release
for s in run-netns-tunnel run-netns-tunnel-loss run-arq-integrity; do
  echo "== $s =="; sudo bin/yipd/tests/$s.sh target/release/yipd || echo "FAILED: $s"
done
```
Expected: each PASS — FEC still recovers over a real tunnel under loss, and ARQ retransmit still works. If netns/sudo is unavailable, record skipped-for-environment and note the exhaustive MDS property test (Task 1) is the correctness guarantee.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-bench/benches/hotpath.rs crates/yip-bench/RESULTS.md
git commit -m "bench(throughput): record P+Q fast-path FEC encode speedup + no-regression"
```

---

## Self-Review

**1. Spec coverage:**
- §3 normative P+Q + Cauchy + `repair_row` → Task 1 Step 3 (`repair_row`, `encode_repair`, `Scheme`). ✅
- §3 R=1 pure XOR → Task 1 Step 3 `encode_repair` `c==1` fast path; asserted indirectly by the round-trip + bench. ✅
- §4 scheme selection (R≤2→PQ) + `payload_id[3]` on all symbols → Task 1 Step 7 `build`. ✅
- §5 API (`Scheme`, `for_repair`, scheme args, `pack`/`parse`) → Task 1 Steps 3, 7. ✅
- §5 ingest guard (PQ index ≥ K+2, unknown scheme) → Task 1 Step 7 `push` + tests `reassembler_rejects_*`. ✅
- §6 MDS both schemes → Task 1 Step 1 `exhaustive_..._both_schemes` + `pq_recovers_every_two_erasures`. ✅
- §6 no-panic / DoS → `pq_rejects_repair_row_ge_2`, `reassembler_rejects_*`. ✅
- §7 benchmark + netns no-regression → Task 2. ✅
- §8 gf256/yip-wire/wire_glue untouched → not in any task's file list. ✅

**2. Placeholder scan:** No TBD/TODO; every code step carries complete code. ✅

**3. Type consistency:** `rs::Scheme`, `repair_row(Scheme,usize,usize)->Vec<u8>`, `encode_repair(&[Vec<u8>],usize,Scheme)`, `decode_source(usize,usize,&[(u16,&[u8])],Scheme)`, `pack_payload_id(u16,u8)`, `parse_payload_id->Option<(u16,rs::Scheme)>`, `ObjState.scheme: rs::Scheme` are used consistently across Steps 3/7 and the tests. The `parse_payload_id` return type changes from `Option<u16>` to `Option<(u16, Scheme)>` — Step 5 notes existing test call sites must switch to `.unwrap().0`. ✅
