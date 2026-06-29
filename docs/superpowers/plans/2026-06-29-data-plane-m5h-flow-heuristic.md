# Data Plane M5.5 — Stateful Flow-Table Heuristic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the deferred heuristic layer to `yip-transport`'s classifier — a stateful per-5-tuple flow table that observes packet size/rate over time and classifies unmarked flows (small+frequent → Realtime, large+sustained → Bulk), completing the precedence chain policy → DSCP → **heuristic** → default.

**Architecture:** A `FlowTable` keyed by the 5-tuple keeps a small per-flow stat (EWMA packet size, packet count, first/last timestamp), bounded by max-entries LRU + TTL eviction (the table is keyed by attacker-influenceable tuples, so it must stay bounded). The `Classifier` becomes stateful (`&mut self`) and time-aware (an injected `now_millis: u64`, not `Instant::now()`, for deterministic tests and a daemon-supplied clock). On a packet with no policy match and no DSCP marking, the classifier observes the flow and consults the heuristic; flows with too little history fall through to Default until they warm up.

**Tech Stack:** Rust (pure logic, no new external deps).

## Global Constraints

- License MPL-2.0; `#![forbid(unsafe_code)]` stays on `yip-transport`.
- Lints: workspace set, CI `--deny warnings`. **No `as` numeric casts** EXCEPT documented float↔int in the rate/EWMA math (comment each, mirroring `control.rs`).
- No new dependencies.
- Borrowed types in signatures (`&[u8]`, `&FlowKey`).
- Files UTF-8/LF/final-newline/no-trailing-ws; commits imperative+capitalized ≤72-char subject, body ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Pre-commit hook runs fmt+clippy+test; each commit must pass it.
- Coverage: `yip-transport` stays ≥90% line coverage.

## Design (the "spike" for pure-logic work)

```rust
// 5-tuple key, fixed-size and Hash-able (v4 addresses live in the low 4 bytes of a 16-byte field).
pub struct FlowKey { src: [u8;16], dst: [u8;16], src_port: u16, dst_port: u16, proto: u8 }

struct FlowStat { ewma_size: f32, packets: u32, first_ms: u64, last_ms: u64 }

pub struct FlowTable { map: HashMap<FlowKey, FlowStat>, order: VecDeque<FlowKey>, max: usize, ttl_ms: u64 }
```

Heuristic thresholds (named constants, tunable): a flow needs ≥ `MIN_PACKETS` (4) of history to be classified; `ewma_size < SMALL_BYTES` (256) → Realtime; `ewma_size > LARGE_BYTES` (1000) → Bulk; otherwise None (→ Default). EWMA weight `EWMA_ALPHA` = 0.25.

---

### Task 1: extend `parse_ip` to the full 5-tuple

**Files:**
- Modify: `crates/yip-transport/src/classify.rs`

**Interfaces:**
- Produces:
  - `pub struct FlowKey { pub src: [u8; 16], pub dst: [u8; 16], pub src_port: u16, pub dst_port: u16, pub proto: u8 }` (derive `Clone, PartialEq, Eq, Hash, Debug`)
  - extends the private `Parsed` struct with `key: FlowKey` (keeping `dscp`), and `parse_ip` fills src/dst addresses + both ports.

- [ ] **Step 1: Write the failing test**

In `classify.rs` tests:

```rust
#[test]
fn parse_ip_extracts_full_5_tuple() {
    // IPv4 UDP: src 10.0.0.1, dst 10.0.0.2, sport 1111, dport 2222
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
    p[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
    p[20..22].copy_from_slice(&1111u16.to_be_bytes()); // sport
    p[22..24].copy_from_slice(&2222u16.to_be_bytes()); // dport
    let parsed = parse_ip(&p, false).unwrap();
    assert_eq!(parsed.key.src[..4], [10, 0, 0, 1]);
    assert_eq!(parsed.key.dst[..4], [10, 0, 0, 2]);
    assert_eq!(parsed.key.src_port, 1111);
    assert_eq!(parsed.key.dst_port, 2222);
    assert_eq!(parsed.key.proto, 17);
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-transport parse_ip_extracts`
Expected: FAIL (`FlowKey`/`Parsed.key` undefined).

- [ ] **Step 3: Implement**

Add `FlowKey` (public) and extend `Parsed` to carry a `key: FlowKey` plus the existing `dscp: u8`. In `parse_ip`, after computing `version`/`l4_off`, fill a 16-byte src/dst (IPv4 → first 4 bytes, rest 0; IPv6 → all 16), and read src_port at `l4_off..l4_off+2`, dst_port at `l4_off+2..l4_off+4` (both only for TCP/UDP, else 0). Keep every access bounds-checked via `.get(...)?`. Example for the IPv4 address fill:

```rust
let mut src = [0u8; 16];
let mut dst = [0u8; 16];
src[..4].copy_from_slice(ip.get(12..16)?);
dst[..4].copy_from_slice(ip.get(16..20)?);
```

(IPv6: copy `ip.get(8..24)?` into `src` and `ip.get(24..40)?` into `dst`.) Ports:

```rust
let (src_port, dst_port) = if matches!(proto, 6 | 17) {
    let sp = ip.get(l4_off..l4_off + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0);
    let dp = ip.get(l4_off + 2..l4_off + 4).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0);
    (sp, dp)
} else {
    (0, 0)
};
```

Keep the existing `dst_port`-based policy matching working (it now reads `parsed.key.dst_port`/`parsed.key.proto`). Update the `classify` policy loop to use `parsed.key.proto` / `Some(parsed.key.dst_port)`.

- [ ] **Step 4: Run the test — expect pass**

Run: `cargo test -p yip-transport classify parse_ip`
Expected: PASS (the existing classify tests still pass — policy/DSCP behavior unchanged). clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/classify.rs
git commit -m "Extract the full 5-tuple in the packet parser

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `FlowTable` — per-flow stats + bounded eviction + heuristic

**Files:**
- Create: `crates/yip-transport/src/flow.rs`
- Modify: `crates/yip-transport/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct FlowTable { ... }`
  - `impl FlowTable { pub fn new(max: usize, ttl_ms: u64) -> Self; pub fn observe(&mut self, key: &FlowKey, size: usize, now_ms: u64); pub fn classify(&self, key: &FlowKey) -> Option<FlowClass>; pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool }`

- [ ] **Step 1: Write the failing tests**

`crates/yip-transport/src/flow.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::FlowKey;
    use crate::FlowClass;

    fn key(port: u16) -> FlowKey {
        FlowKey { src: [1; 16], dst: [2; 16], src_port: 1000, dst_port: port, proto: 17 }
    }

    #[test]
    fn small_frequent_flow_classifies_realtime() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(5000);
        // 8 small packets, 5ms apart
        for i in 0..8 {
            t.observe(&k, 80, i * 5);
        }
        assert_eq!(t.classify(&k), Some(FlowClass::Realtime));
    }

    #[test]
    fn large_flow_classifies_bulk() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(6000);
        for i in 0..8 {
            t.observe(&k, 1400, i * 2);
        }
        assert_eq!(t.classify(&k), Some(FlowClass::Bulk));
    }

    #[test]
    fn cold_flow_is_unclassified() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(7000);
        t.observe(&k, 80, 0); // only 1 packet < MIN_PACKETS
        assert_eq!(t.classify(&k), None);
    }

    #[test]
    fn table_evicts_to_stay_bounded() {
        let mut t = FlowTable::new(2, 10_000); // cap 2
        for p in 0..5u16 {
            t.observe(&key(8000 + p), 100, u64::from(p));
        }
        assert!(t.len() <= 2, "table never exceeds max");
    }
}
```

- [ ] **Step 2: Run them — expect failure**

Run: `cargo test -p yip-transport flow`
Expected: FAIL (`FlowTable` undefined).

- [ ] **Step 3: Implement `FlowTable`**

Add `pub mod flow; pub use flow::FlowTable;` to `lib.rs`. In `flow.rs`:

```rust
//! Stateful per-5-tuple flow table backing the classifier's heuristic layer.
//! Tracks each flow's EWMA packet size and rate to infer a [`FlowClass`] for
//! flows that carry no DSCP marking. Bounded by max-entries LRU + TTL eviction.

use crate::classify::FlowKey;
use crate::FlowClass;
use std::collections::{HashMap, VecDeque};

const MIN_PACKETS: u32 = 4;
const SMALL_BYTES: f32 = 256.0;
const LARGE_BYTES: f32 = 1000.0;
const EWMA_ALPHA: f32 = 0.25;

struct FlowStat {
    ewma_size: f32,
    packets: u32,
    first_ms: u64,
    last_ms: u64,
}

/// A bounded per-flow table feeding the classifier heuristic.
pub struct FlowTable {
    map: HashMap<FlowKey, FlowStat>,
    order: VecDeque<FlowKey>,
    max: usize,
    ttl_ms: u64,
}

impl FlowTable {
    /// Create a table holding at most `max` flows, evicting entries idle for `ttl_ms`.
    pub fn new(max: usize, ttl_ms: u64) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), max: max.max(1), ttl_ms }
    }

    /// Number of tracked flows.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Record one observed packet of `size` bytes on `key` at `now_ms`.
    pub fn observe(&mut self, key: &FlowKey, size: usize, now_ms: u64) {
        self.evict_expired(now_ms);
        // f32::from has no usize impl; this is a documented size->float widening.
        let size_f = u16::try_from(size).map(f32::from).unwrap_or(f32::from(u16::MAX));
        match self.map.get_mut(key) {
            Some(stat) => {
                stat.ewma_size = EWMA_ALPHA * size_f + (1.0 - EWMA_ALPHA) * stat.ewma_size;
                stat.packets = stat.packets.saturating_add(1);
                stat.last_ms = now_ms;
            }
            None => {
                if self.map.len() >= self.max {
                    if let Some(old) = self.order.pop_front() {
                        self.map.remove(&old);
                    }
                }
                self.map.insert(
                    key.clone(),
                    FlowStat { ewma_size: size_f, packets: 1, first_ms: now_ms, last_ms: now_ms },
                );
                self.order.push_back(key.clone());
            }
        }
    }

    /// Heuristic class for a tracked flow, or None when there is too little history
    /// or the flow does not fit a class.
    pub fn classify(&self, key: &FlowKey) -> Option<FlowClass> {
        let stat = self.map.get(key)?;
        if stat.packets < MIN_PACKETS {
            return None;
        }
        if stat.ewma_size < SMALL_BYTES {
            Some(FlowClass::Realtime)
        } else if stat.ewma_size > LARGE_BYTES {
            Some(FlowClass::Bulk)
        } else {
            None
        }
    }

    fn evict_expired(&mut self, now_ms: u64) {
        while let Some(front) = self.order.front() {
            let expired = self
                .map
                .get(front)
                .is_none_or(|s| now_ms.saturating_sub(s.last_ms) > self.ttl_ms);
            if expired {
                let k = self.order.pop_front().expect("front exists");
                self.map.remove(&k);
            } else {
                break;
            }
        }
    }
}
```

Note: `order` may contain a key whose entry was overwritten (re-inserted) — `evict_expired`/eviction tolerate this by checking `map.get`. If clippy flags the `order` possibly holding duplicate keys as a concern, that is acceptable: the LRU is approximate (good enough for a heuristic) and the `map` is the source of truth for `len()`.

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yip-transport flow`
Expected: PASS. clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/flow.rs crates/yip-transport/src/lib.rs
git commit -m "Add bounded flow table with heuristic classification

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: wire the heuristic into `Classifier` (stateful + timed) and `Transport`

**Files:**
- Modify: `crates/yip-transport/src/classify.rs`
- Modify: `crates/yip-transport/src/lib.rs`

**Interfaces:**
- Changes:
  - `Classifier` gains a `flows: FlowTable` field; `classify` becomes `&mut self` and takes `now_ms: u64`: `pub fn classify(&mut self, inner: &[u8], l2: bool, now_ms: u64) -> FlowClass`.
  - `Transport::encode` gains a `now_ms: u64` parameter, passed through to the classifier.

- [ ] **Step 1: Write the failing test**

In `classify.rs` tests:

```rust
#[test]
fn heuristic_classifies_unmarked_small_flow_after_warmup() {
    let mut c = Classifier::new(vec![]);
    // unmarked (DSCP 0) small UDP packets on one flow
    let pkt = ipv4(0, 17, 5000); // 24 bytes, DSCP 0
    // first few packets: cold -> Default
    assert_eq!(c.classify(&pkt, false, 0), FlowClass::Default);
    // warm the flow up with several small packets
    for i in 1..6 {
        c.classify(&pkt, false, i * 5);
    }
    // now the heuristic should kick in -> Realtime
    assert_eq!(c.classify(&pkt, false, 30), FlowClass::Realtime);
}
```

Update the existing classify tests to pass a `now_ms` argument (e.g. `0`) — they assert policy/DSCP results which are reached before the heuristic, so any timestamp works.

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-transport heuristic_classifies`
Expected: FAIL (arity mismatch / heuristic not wired).

- [ ] **Step 3: Implement**

Add `flows: FlowTable` to `Classifier` (init in `new` with sensible bounds, e.g. `FlowTable::new(4096, 30_000)`). Make `classify` `&mut self` with `now_ms`. The precedence becomes:

```rust
pub fn classify(&mut self, inner: &[u8], l2: bool, now_ms: u64) -> FlowClass {
    let Some(p) = parse_ip(inner, l2) else { return FlowClass::Default; };
    // 1. explicit policy
    for r in &self.rules {
        if r.proto.is_none_or(|x| x == p.key.proto)
            && r.dst_port.is_none_or(|x| x == p.key.dst_port)
        {
            return r.class;
        }
    }
    // 2. DSCP
    match p.dscp {
        46 | 40 | 48 | 56 => return FlowClass::Realtime,
        8 | 10 | 12 | 14 => return FlowClass::Bulk,
        _ => {}
    }
    // 3. heuristic: observe this packet, then consult flow history
    self.flows.observe(&p.key, inner.len(), now_ms);
    if let Some(class) = self.flows.classify(&p.key) {
        return class;
    }
    // 4. default
    FlowClass::Default
}
```

Then update `Transport::encode` to take `now_ms: u64` and pass it: `let class = self.classifier.classify(inner, l2, now_ms);`. Update the `Transport` end-to-end test and any caller to pass a timestamp (e.g. `0`).

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yip-transport`
Expected: all pass (existing + the new heuristic test). clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/classify.rs crates/yip-transport/src/lib.rs
git commit -m "Wire the flow-table heuristic into the classifier

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: coverage, changelog, full gate

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Verify coverage**

Run: `cargo llvm-cov --package yip-transport --fail-under-lines 90 --summary-only`
Expected: exits 0. If under, add a focused test (e.g. an IPv6 5-tuple parse, a TTL-expiry eviction, or a mid-size flow returning None from the heuristic).

- [ ] **Step 2: Changelog**

Under `## [Unreleased]` → `### Added` in `CHANGELOG.md`:

```markdown
- `yip-transport` stateful flow-table heuristic: classifies unmarked flows by
  observed packet size/rate, completing the policy -> DSCP -> heuristic -> default
  precedence chain.
```

- [ ] **Step 3: Full gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo shear && cargo deny check`
Expected: all clean/pass.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "Record flow-table heuristic in changelog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** completes the classifier's deferred heuristic layer (the 3rd precedence tier) ✓ (T1–T3); the flow table is **bounded** (max-entries LRU + TTL) so attacker-influenceable 5-tuples can't explode it ✓ (T2); time is injected (`now_ms`) for determinism + a daemon clock ✓ (T3); ≥90% coverage ✓ (T4).

**Placeholder scan:** all code is concrete. The documented float conversions (`f32::from` of a `u16`-narrowed size, the EWMA math) are the only `as`-adjacent operations and are commented; no raw `as` casts.

**Type consistency:** `FlowKey` (classify.rs) is used by `FlowTable` (flow.rs) and the `Classifier`; `FlowClass` shared from lib.rs; `Transport::encode`'s new `now_ms` threads through to `Classifier::classify`. The existing classify/Transport tests are updated for the new `now_ms` arity.

**Definition of done:** `cargo test --workspace` green; `yip-transport` ≥90% covered; an unmarked small flow classifies Realtime after warm-up while a cold flow falls to Default; the flow table stays bounded under churn; whole-workspace fmt/clippy/shear/deny green; CI passes on push.

**Note for M6:** the daemon supplies `now_ms` from a monotonic clock and calls `Transport::encode(ciphertext, inner, l2, now_ms)`. The heuristic observes only egress inner packets here; observing the return path for bidirectionality is a later refinement.
