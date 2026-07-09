# Throughput 4a — Plan-Cached FEC Encoder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the ~26 µs-per-packet RaptorQ plan regeneration by caching `SourceBlockEncodingPlan` per `symbol_count` in `FecEncoder`, unlocking multi-gigabit single-core throughput while keeping every flow class's proactive repair ratio unchanged.

**Architecture:** `FecEncoder` (in `crates/yip-transport/src/fec.rs`) currently builds a fresh `raptorq::Encoder` for every `repair >= 1` object, which reruns the data-independent constraint-matrix solve (`SourceBlockEncodingPlan::generate`) each time. We add an instance-owned `HashMap<u16, SourceBlockEncodingPlan>` cache and encode via `raptorq::SourceBlockEncoder::with_encoding_plan`, which reuses a cached plan. Output stays byte-identical to `Encoder::new(..).get_encoded_packets(repair)`. No wire-format, no public-API, no flow-class-policy change.

**Tech Stack:** Rust, `raptorq` 2.0.1 (`SourceBlockEncoder`, `SourceBlockEncodingPlan`), `criterion` (yip-bench).

## Global Constraints

- `crates/yip-transport` is `#![forbid(unsafe_code)]` — introduce NO `unsafe`.
- No `as` numeric casts except enum discriminants — use `u16::try_from` / `u32::try_from` / `usize::from` / `u64::from`.
- **Byte-identity invariant:** for any single-source-block object, the cached-plan symbols MUST equal `Encoder::new(ciphertext, oti).get_encoded_packets(repair)` mapped through `split_packet` — same `payload_id`, `data`, `object_size`, and `object_id`.
- No wire-format change; all flow-class repair ratios stay exactly as `FlowClass::params()` defines them (Realtime 0.15, Default 0.10, Bulk 0.05).
- Plan cache is bounded at 64 entries (`PLAN_CACHE_CAP`).
- Touch ONLY `crates/yip-transport/src/fec.rs` (+ its `#[cfg(test)]` module) and the `crates/yip-bench` harness. Do not modify `crates/yip-transport/src/lib.rs` (its `Transport::encode` path already passes the right `repair` count).
- `refrences/` is read-only reference material — never modify it.
- The real `raptorq` 2.0.1 signature is `SourceBlockEncoder::with_encoding_plan(source_block_id: u8, config: &ObjectTransmissionInformation, data: &[u8], plan: &SourceBlockEncodingPlan)`. `data` must already be zero-padded to `symbol_count * symbol_size`; `with_encoding_plan` internally asserts `create_symbols(config, data).len() == plan.source_symbol_count`.

---

## File Structure

- `crates/yip-transport/src/fec.rs` — **modify.** `FecEncoder` gains `plan_cache` field, a `plan()` accessor, and a `encode_with_cached_plan()` helper; `encode()` and `repair_with_id()` route `repair >= 1` single-block objects through it. All new unit tests live in the existing `#[cfg(test)] mod tests`.
- `crates/yip-bench/examples/plan_cache_spike.rs` — **create (Task 1).** Standalone de-risk spike: proves byte-identity and measures cached-vs-fresh encode µs against the real raptorq API before we touch `FecEncoder`. Kept as a permanent profiling example.
- `crates/yip-bench/RESULTS.md` — **modify/append (Task 3).** Record before/after `transport_encode_1300` and `pipeline_profile` numbers.

---

### Task 1: De-risk spike — cached-plan byte-identity + residual timing (GATE)

**Purpose:** Before modifying `FecEncoder`, prove against the real `raptorq` 2.0.1 API that (a) a cached `SourceBlockEncodingPlan` reused via `SourceBlockEncoder::with_encoding_plan` produces byte-identical packets to `Encoder::new(..).get_encoded_packets(repair)`, and (b) the per-encode cost with a cached plan collapses to low-single-digit µs. **This is a gate:** if (b) fails, STOP and report — do not proceed to Task 2.

**Files:**
- Create: `crates/yip-bench/examples/plan_cache_spike.rs`

**Interfaces:**
- Consumes: `raptorq::{Encoder, SourceBlockEncoder, SourceBlockEncodingPlan, ObjectTransmissionInformation, EncodingPacket, calculate_block_offsets}`.
- Produces: nothing consumed by later tasks (throwaway-but-kept profiling example). Establishes the exact block-padding + `symbol_count` derivation that Task 2 mirrors.

- [ ] **Step 1: Write the spike example**

Create `crates/yip-bench/examples/plan_cache_spike.rs`:

```rust
//! De-risk spike for throughput 4a (plan-cached FEC). Proves a cached
//! SourceBlockEncodingPlan reused via SourceBlockEncoder::with_encoding_plan is
//! byte-identical to Encoder::new(..).get_encoded_packets(repair), and measures
//! the per-encode cost with a cached plan vs a freshly-built Encoder.
//!
//! Run: cargo run --release -p yip-bench --example plan_cache_spike
use std::collections::HashMap;
use std::time::Instant;

use raptorq::{
    calculate_block_offsets, Encoder, EncodingPacket, ObjectTransmissionInformation,
    SourceBlockEncoder, SourceBlockEncodingPlan,
};

const SYMBOL_SIZE: u16 = 1200;

/// Mirror of raptorq's Encoder::new single-source-block construction: returns the
/// zero-padded block bytes and its source `symbol_count`. Returns None if the OTI
/// implies more than one source block (the cached path does not apply).
fn single_block(ciphertext: &[u8], oti: &ObjectTransmissionInformation) -> Option<(Vec<u8>, u16)> {
    let offsets = calculate_block_offsets(ciphertext, oti);
    if oti.sub_blocks() != 1 || offsets.len() != 1 {
        return None;
    }
    let (start, end) = offsets[0];
    let block: Vec<u8> = if end > ciphertext.len() {
        let mut v = Vec::from(&ciphertext[start..]);
        v.resize(end - start, 0);
        v
    } else {
        ciphertext[start..end].to_vec()
    };
    let sym = usize::from(oti.symbol_size());
    let symbol_count = u16::try_from(block.len() / sym).expect("symbol_count fits u16");
    Some((block, symbol_count))
}

fn cached_encode(
    cache: &mut HashMap<u16, SourceBlockEncodingPlan>,
    ciphertext: &[u8],
    oti: &ObjectTransmissionInformation,
    repair: u32,
) -> Vec<EncodingPacket> {
    let (block, symbol_count) = single_block(ciphertext, oti).expect("single source block");
    let plan = cache
        .entry(symbol_count)
        .or_insert_with(|| SourceBlockEncodingPlan::generate(symbol_count));
    let sbe = SourceBlockEncoder::with_encoding_plan(0, oti, &block, plan);
    sbe.source_packets()
        .into_iter()
        .chain(sbe.repair_packets(0, repair))
        .collect()
}

fn fresh_encode(
    ciphertext: &[u8],
    oti: &ObjectTransmissionInformation,
    repair: u32,
) -> Vec<EncodingPacket> {
    Encoder::new(ciphertext, *oti).get_encoded_packets(repair)
}

fn main() {
    // (a) Byte-identity across sizes (symbol_count 1..3) and repair 1..=8.
    let mut cache = HashMap::new();
    for &len in &[600usize, 1200, 1201, 2400, 3000] {
        let ct: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let oti = ObjectTransmissionInformation::with_defaults(
            u64::try_from(len).unwrap(),
            SYMBOL_SIZE,
        );
        for repair in 1u32..=8 {
            let a = cached_encode(&mut cache, &ct, &oti, repair);
            let b = fresh_encode(&ct, &oti, repair);
            assert_eq!(a.len(), b.len(), "len differs len={len} repair={repair}");
            for (x, y) in a.iter().zip(b.iter()) {
                assert_eq!(x.serialize(), y.serialize(), "bytes differ len={len} repair={repair}");
            }
        }
    }
    println!("byte-identity: OK (sizes 600..3000, repair 1..=8)");

    // (b) Residual timing: fresh Encoder per call vs cached plan per call.
    // Use the Default-class hot case: ~1300-byte object, repair = 1.
    let ct = vec![0xCDu8; 1300];
    let oti = ObjectTransmissionInformation::with_defaults(1300, SYMBOL_SIZE);
    let iters = 20_000u32;

    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(fresh_encode(&ct, &oti, 1));
    }
    let fresh_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    let mut cache2 = HashMap::new();
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(cached_encode(&mut cache2, &ct, &oti, 1));
    }
    let cached_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    println!("fresh  encode : {fresh_us:.2} us/packet");
    println!("cached encode : {cached_us:.2} us/packet");
    println!("speedup       : {:.1}x", fresh_us / cached_us);
}
```

- [ ] **Step 2: Run the spike (release)**

Run: `cargo run --release -p yip-bench --example plan_cache_spike`
Expected: prints `byte-identity: OK ...`, then a `fresh encode` around 20–30 µs and a `cached encode` in the low-single-digit µs (roughly ≤ 5 µs), with a speedup well above 1.

- [ ] **Step 3: GATE decision**

If `cached encode` is low-single-digit µs (a large speedup): the approach is validated — proceed to Task 2.
If `cached encode` did NOT collapse (still ≳ 10 µs, small speedup): **STOP.** Report the numbers; the residual (`with_encoding_plan` apply-ops + repair generation) is the bottleneck and 4a's premise fails — escalate to reconsider sliding-window FEC (spec §6, deferred 4d). Do not start Task 2.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/examples/plan_cache_spike.rs
git commit -m "spike(throughput-4a): cached RaptorQ plan byte-identity + residual timing gate"
```

---

### Task 2: Plan cache in `FecEncoder` (the real change)

**Files:**
- Modify: `crates/yip-transport/src/fec.rs` (imports ~line 6-9; `FecEncoder` struct ~line 34-37; `encode` ~line 46-78; `repair_with_id` ~line 82-100; new helpers; new tests in `mod tests`).

**Interfaces:**
- Consumes: from Task 1, the validated single-source-block construction (`single_block` logic) and `SourceBlockEncoder::with_encoding_plan(0, oti, &block, plan)` + `source_packets()`.chain(`repair_packets(0, repair)`).
- Produces (unchanged public API — callers in `lib.rs` are untouched):
  - `FecEncoder::encode(&mut self, ciphertext: &[u8], params: crate::FlowParams, repair: u32) -> Vec<Symbol>`
  - `FecEncoder::repair_with_id(&mut self, ciphertext: &[u8], params: crate::FlowParams, object_id: u16, extra_repair: u32) -> Vec<Symbol>` (note: signature changes from `&self` to `&mut self` — the only caller, `Transport::repair_object` in `lib.rs:150`, already holds `&mut self`).

- [ ] **Step 1: Write the failing byte-identity test (repair ≥ 1)**

Add to `crates/yip-transport/src/fec.rs` `#[cfg(test)] mod tests` (place near the existing `encode_via_real_encoder` helper). This generalizes the existing repair=0 byte-identity test to repair 1..=8 and multiple sizes:

```rust
/// Reference: the real raptorq Encoder with an explicit repair count, mapped
/// through split_packet with object_id 0 (matching a fresh FecEncoder's first
/// object). This is the byte-identity oracle for the cached-plan path.
fn encode_via_real_encoder_repair(
    ciphertext: &[u8],
    params: crate::FlowParams,
    repair: u32,
) -> Vec<Symbol> {
    let object_size = u32::try_from(ciphertext.len()).unwrap();
    let oti = ObjectTransmissionInformation::with_defaults(
        u64::from(object_size),
        params.symbol_size,
    );
    let encoder = Encoder::new(ciphertext, oti);
    encoder
        .get_encoded_packets(repair)
        .iter()
        .map(|p| split_packet(0, object_size, p))
        .collect()
}

#[test]
fn cached_plan_repair_is_byte_identical_to_encoder() {
    let params = FlowClass::Default.params();
    for &len in &[600usize, 1200, 1201, 2400, 3000] {
        let ct: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        for repair in 1u32..=8 {
            // Fresh encoder so object_id starts at 0, matching the oracle.
            let mut enc = FecEncoder::new();
            let produced = enc.encode(&ct, params, repair);
            let reference = encode_via_real_encoder_repair(&ct, params, repair);
            assert_eq!(
                produced.len(),
                reference.len(),
                "symbol count differs len={len} repair={repair}"
            );
            for (p, r) in produced.iter().zip(reference.iter()) {
                assert_eq!(p.object_id, r.object_id, "object_id len={len} repair={repair}");
                assert_eq!(p.object_size, r.object_size, "object_size len={len} repair={repair}");
                assert_eq!(p.payload_id, r.payload_id, "payload_id len={len} repair={repair}");
                assert_eq!(p.data, r.data, "data len={len} repair={repair}");
            }
        }
    }
}
```

- [ ] **Step 2: Run it to verify it PASSES already (baseline), then confirm it still guards after refactor**

Run: `cargo test -p yip-transport --lib fec::tests::cached_plan_repair_is_byte_identical_to_encoder`
Expected: PASS — the current `encode` (via `Encoder::new`) is already byte-identical to the oracle. This test is the guardrail: it must STAY green after the cached-plan refactor in Step 3. (This is a refactor-under-test, not classic red-green: the invariant is "output unchanged".)

- [ ] **Step 3: Add the plan cache, accessor, and cached-plan helper; route `encode`/`repair_with_id` through it**

In `crates/yip-transport/src/fec.rs`:

(a) Extend the imports (line ~6-9) to add the two plan types:

```rust
use raptorq::{
    calculate_block_offsets, Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation,
    PayloadId, SourceBlockEncoder, SourceBlockEncodingPlan,
};
use std::collections::{HashMap, VecDeque};
```

(b) Add the cache bound constant near `MAX_OBJECT_SIZE` (line ~18):

```rust
/// Maximum distinct `symbol_count` plans cached at once. yip's packet-sized
/// objects produce only a handful of symbol counts (typically 1–3), so this
/// bound is never reached in practice; it caps memory if pathological object
/// sizes are ever encoded. On overflow the cache is cleared (simple bound —
/// no LRU needed given the tiny working set).
const PLAN_CACHE_CAP: usize = 64;
```

(c) Add the field to `FecEncoder` (line ~34-37):

```rust
/// Encodes ciphertext frames into RaptorQ symbols, assigning monotonic object ids.
#[derive(Debug, Default)]
pub struct FecEncoder {
    next_object_id: u16,
    /// Cache of RaptorQ encoding plans keyed by source `symbol_count`. Reusing a
    /// plan skips the ~26 µs constraint-matrix solve that `Encoder::new` performs
    /// per object. A plan is valid for any object with the same `symbol_count`.
    plan_cache: HashMap<u16, SourceBlockEncodingPlan>,
}
```

(d) Add the accessor and helper as `impl FecEncoder` methods (after `new()`):

```rust
    /// Get (or generate and cache) the encoding plan for `symbol_count`.
    fn plan(&mut self, symbol_count: u16) -> &SourceBlockEncodingPlan {
        if !self.plan_cache.contains_key(&symbol_count) {
            if self.plan_cache.len() >= PLAN_CACHE_CAP {
                self.plan_cache.clear();
            }
            self.plan_cache
                .insert(symbol_count, SourceBlockEncodingPlan::generate(symbol_count));
        }
        self.plan_cache
            .get(&symbol_count)
            .expect("plan present after insert")
    }

    /// Encode a single-source-block object into source + `repair` symbols using a
    /// cached plan. Returns `None` when the object is not a single source block
    /// (caller must fall back to the full `Encoder`). Byte-identical to
    /// `Encoder::new(ciphertext, oti).get_encoded_packets(repair)`.
    fn encode_with_cached_plan(
        &mut self,
        object_id: u16,
        object_size: u32,
        ciphertext: &[u8],
        oti: &ObjectTransmissionInformation,
        repair: u32,
    ) -> Option<Vec<Symbol>> {
        let offsets = calculate_block_offsets(ciphertext, oti);
        if offsets.len() != 1 {
            return None;
        }
        let (start, end) = offsets[0];
        // Mirror Encoder::new's zero-padding of the (single) source block up to a
        // symbol-size multiple.
        let block: Vec<u8> = if end > ciphertext.len() {
            let mut v = Vec::from(&ciphertext[start..]);
            v.resize(end - start, 0);
            v
        } else {
            ciphertext[start..end].to_vec()
        };
        let sym_size = usize::from(oti.symbol_size());
        let symbol_count = u16::try_from(block.len() / sym_size).expect("symbol_count fits u16");
        let plan = self.plan(symbol_count);
        let sbe = SourceBlockEncoder::with_encoding_plan(0, oti, &block, plan);
        Some(
            sbe.source_packets()
                .into_iter()
                .chain(sbe.repair_packets(0, repair))
                .map(|p| split_packet(object_id, object_size, &p))
                .collect(),
        )
    }
```

(e) Rewrite `encode` (line ~46-78) to route `repair >= 1` single-block objects through the cache, keeping the existing `repair == 0` fast path and the full-`Encoder` fallback:

```rust
    pub fn encode(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        repair: u32,
    ) -> Vec<Symbol> {
        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        let object_size = u32::try_from(ciphertext.len()).expect("frame fits u32");

        let oti = ObjectTransmissionInformation::with_defaults(
            u64::from(object_size),
            params.symbol_size,
        );

        if oti.sub_blocks() == 1 {
            if repair == 0 {
                // Fast path: systematic source symbols are the data itself.
                return source_symbols(object_id, object_size, ciphertext, &oti);
            }
            // repair >= 1: cached-plan path (skips the per-object solve).
            if let Some(syms) =
                self.encode_with_cached_plan(object_id, object_size, ciphertext, &oti, repair)
            {
                return syms;
            }
        }

        // Fallback: multi-sub-block or multi-source-block object (never produced
        // by yip's packet-sized frames) uses the full encoder.
        let encoder = Encoder::new(ciphertext, oti);
        encoder
            .get_encoded_packets(repair)
            .into_iter()
            .map(|p| split_packet(object_id, object_size, &p))
            .collect()
    }
```

(f) Rewrite `repair_with_id` (line ~82-100) to `&mut self` and use the cache:

```rust
    pub fn repair_with_id(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        object_id: u16,
        extra_repair: u32,
    ) -> Vec<Symbol> {
        let object_size = u32::try_from(ciphertext.len()).expect("frame fits u32");
        let oti = ObjectTransmissionInformation::with_defaults(
            u64::from(object_size),
            params.symbol_size,
        );
        if oti.sub_blocks() == 1 {
            if let Some(syms) =
                self.encode_with_cached_plan(object_id, object_size, ciphertext, &oti, extra_repair)
            {
                return syms;
            }
        }
        let encoder = Encoder::new(ciphertext, oti);
        encoder
            .get_encoded_packets(extra_repair)
            .into_iter()
            .map(|p| split_packet(object_id, object_size, &p))
            .collect()
    }
```

- [ ] **Step 4: Run the byte-identity test + the full fec suite**

Run: `cargo test -p yip-transport --lib fec::`
Expected: PASS — `cached_plan_repair_is_byte_identical_to_encoder` still green, plus all pre-existing fec tests (`zero_repair_bypass_*`, `encode_produces_source_plus_repair_with_explicit_oti`, `reassembles_through_erasure_and_reordering`, `repair_with_id_produces_decodable_symbols`, `encode_with_repair_uses_full_encoder_and_decodes`, the malformed-input/DoS tests, etc.) still green.

- [ ] **Step 5: Add a cache-liveness test**

Add to `mod tests`:

```rust
#[test]
fn plan_cache_populates_and_is_bounded() {
    let params = FlowClass::Default.params();
    let mut enc = FecEncoder::new();
    // Two distinct object sizes -> distinct symbol_counts (1 and 2 symbols).
    let small = vec![0x11u8; 1000]; // 1 source symbol at symbol_size 1200
    let big = vec![0x22u8; 2000]; // 2 source symbols
    let _ = enc.encode(&small, params, 2);
    let _ = enc.encode(&big, params, 2);
    // Re-encode the same sizes: must reuse cached plans (no new entries).
    let _ = enc.encode(&small, params, 3);
    let _ = enc.encode(&big, params, 3);
    assert_eq!(enc.plan_cache.len(), 2, "exactly two symbol_counts cached");
    assert!(
        enc.plan_cache.len() <= PLAN_CACHE_CAP,
        "cache stays within bound"
    );
}
```

- [ ] **Step 6: Run the new test + full transport suite + lints**

Run: `cargo test -p yip-transport`
Expected: PASS (all lib + integration tests).
Run: `cargo clippy -p yip-transport --all-targets -- -D warnings && cargo fmt -p yip-transport -- --check`
Expected: no warnings, formatting clean.

- [ ] **Step 7: Commit**

```bash
git add crates/yip-transport/src/fec.rs
git commit -m "feat(yip-transport): cache RaptorQ encoding plan per symbol_count (throughput 4a)

Route repair>=1 single-source-block objects through
SourceBlockEncoder::with_encoding_plan with an instance-owned plan cache,
skipping the ~26us Encoder::new solve on every packet. Byte-identical output;
all flow-class repair ratios unchanged."
```

---

### Task 3: Benchmark + profile + no-regression verification

**Purpose:** Prove the encode-path speedup with real numbers and confirm the full suite (unit + netns) stays green. Byte-identity (Task 2) is the correctness guarantee; this task is the measured payoff + end-to-end confirmation.

**Files:**
- Modify/append: `crates/yip-bench/RESULTS.md`
- Run-only (no edits): `crates/yip-bench/benches/hotpath.rs` (`transport_encode_1300`), `crates/yip-bench/examples/pipeline_profile.rs`, `bin/yipd/tests/run-*.sh` (non-QUIC netns suite).

**Interfaces:**
- Consumes: the Task 2 `FecEncoder` change (linked into `Transport::encode`, which `hotpath.rs` and `pipeline_profile.rs` exercise via `Transport::new(vec![])`).
- Produces: recorded before/after numbers in `RESULTS.md`.

- [ ] **Step 1: Capture the encode benchmark (after)**

Run: `cargo bench -p yip-bench --bench hotpath -- transport_encode_1300`
Expected: median well below the ~26 µs pre-4a baseline — low-single-digit µs (the Default class emits repair=1 on the ~1300-byte object, which previously hit the solve).

- [ ] **Step 2: Capture the pipeline profile (after)**

Run: `cargo run --release -p yip-bench --example pipeline_profile`
Expected: the `encode` line drops from the pre-4a ~26 µs to low-single-digit µs; `symbols/packet` unchanged (~2.00), `decoded ok : 5000/5000`.

- [ ] **Step 3: Record results**

Append a dated "Throughput 4a — plan-cached FEC" section to `crates/yip-bench/RESULTS.md` with: the `transport_encode_1300` median before (~26 µs, from the 4a spike findings) and after (this run), the `pipeline_profile` encode line before/after, and the `plan_cache_spike` fresh-vs-cached speedup from Task 1. State the single-core throughput implication (encode no longer the bottleneck; AEAD ~2 µs becomes the ceiling → multi-gigabit).

- [ ] **Step 4: No-regression — transport unit suite**

Run: `cargo test -p yip-transport && cargo test -p yip-bench`
Expected: all green.

- [ ] **Step 5: No-regression — netns integration suite (non-QUIC)**

Rebuild release first (the netns scripts run the release binary), then run the non-QUIC netns tests. These need `sudo` / network namespaces.

Run:
```bash
cargo build --release
for s in run-netns-tunnel run-netns-tunnel-loss run-netns-tunnel-l2 run-arq-integrity; do
  echo "== $s =="; sudo bin/yipd/tests/$s.sh || echo "FAILED: $s"
done
```
Expected: each script reports success (tunnel bring-up + ping across; loss variant proves FEC still recovers dropped symbols; ARQ integrity intact). If the environment cannot run netns/sudo, record that these were skipped and note that byte-identity (Task 2) is the correctness guarantee per spec §5 — do NOT mark the task blocked solely on netns availability.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-bench/RESULTS.md
git commit -m "bench(throughput-4a): record plan-cached FEC encode speedup + no-regression"
```

---

## Self-Review

**1. Spec coverage:**
- Spec §3 plan cache + `with_encoding_plan` transform → Task 2 (steps 3a–3f). ✅
- Spec §4 Invariant 1 (byte-identity) → Task 1 spike + Task 2 `cached_plan_repair_is_byte_identical_to_encoder`. ✅
- Spec §4 Invariant 2 (bounded 64) → Task 2 `PLAN_CACHE_CAP` + `plan_cache_populates_and_is_bounded`. ✅
- Spec §4 Invariant 3 (no policy change) → guaranteed by not touching `lib.rs`/`control.rs`; `repair` count derivation unchanged. ✅
- Spec §5 unit tests (byte-identity, cache liveness) → Task 2 steps 1, 5. ✅
- Spec §5 benchmark (`transport_encode_1300`, `pipeline_profile`) → Task 3 steps 1–2. ✅
- Spec §5 netns no-regression → Task 3 step 5. ✅
- Spec §2 gate (residual must collapse) → Task 1 step 3. ✅

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"/uncoded steps — every code step carries full code. ✅

**3. Type consistency:** `encode_with_cached_plan(&mut self, object_id: u16, object_size: u32, ciphertext: &[u8], oti: &ObjectTransmissionInformation, repair: u32) -> Option<Vec<Symbol>>` and `plan(&mut self, symbol_count: u16) -> &SourceBlockEncodingPlan` are used consistently in `encode`/`repair_with_id`. `repair_with_id` `&self`→`&mut self` change is noted with its sole caller. `split_packet(object_id, object_size, &p)` matches the existing signature (`fec.rs:164`). `with_encoding_plan(0, oti, &block, plan)` matches the verified raptorq 2.0.1 signature. ✅
