# Adaptive loss-feedback loop + reactive ARQ Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the data-plane control loop — the receiver reports loss, the sender adapts the repair ratio (down to zero on clean ARQ-backed flows, firing the dormant FEC bypass) and retransmits NACKed objects for eligible flows.

**Architecture:** A single authenticated receiver→sender `Control` packet carries `{ delivered_count, high_counter, missing[] }`. The receiver detects loss as gaps in the monotonic per-direction sealed counter. The sender owns all class attribution (it knows each counter's class from its sent log): it feeds per-class residual loss to the controller and retransmits eligible NACKed objects with fresh RaptorQ repair symbols. Built in two phases: (A) control channel + feedback + class-aware zero-repair (the throughput win), then (B) reactive ARQ.

**Tech Stack:** Rust, `raptorq` 2.0, `snow`/ChaCha20-Poly1305 (existing `Session`), the existing `yip-transport` controller/FEC, `bin/yipd` tunnel loops.

## Global Constraints

- **Counter is one unified monotonic per-direction sequence over ALL sealed packets** (data objects AND control packets). Data objects stay uniquely identified; control packets consume sequence numbers too. The receiver reports raw gaps; the **sender** disambiguates every gap via its sent log (data-object-of-class-X vs control) — so a lost control packet yields a NACK the sender safely ignores, and per-class loss attribution is exact.
- **ARQ-eligibility AND zero-repair-eligibility are both gated on `FlowParams.arq`** (currently `Bulk=true`, `Realtime=false`, `Default=false`). ARQ-classes can earn ratio 0; non-ARQ classes keep a `> 0` floor. (To later let `Default` reach zero, flip its `arq` flag — one line; out of scope here.)
- **Control packets are authenticated** via the existing `Session` AEAD (seal/open) — a forged/replayed report is rejected by the AEAD + replay window. No new key material.
- **Everything bounded:** retransmit buffer (LRU + TTL), receiver pending-loss set, `missing` per packet (`MAX_NACK`).
- **Additive wire change only:** the data-plane *symbol* frame is unchanged; only `PacketType::Control = 3` is added. The `tunnel_netns` ping test is the regression gate.
- Mullvad lints, `-D warnings`; no `as` numeric casts except the existing `PacketType::* as u8` idiom; `#![forbid(unsafe_code)]` on every crate except `yip-io`; exact dependency pins; ≥90 % coverage on `yip-transport`; `CHANGELOG.md` per Keep a Changelog.
- Indicative constants (tune against the bench): `FEEDBACK_INTERVAL_MS = 30`, `GRACE_MS = 5`, `MAX_NACK = 64`, realtime/default floor = each class's `initial_repair_ratio`, retransmit buffer = 1024 objects / 2 s TTL.

---

## Phase A — control channel + feedback + class-aware zero-repair

### Task 1: `Control` report type + (de)serialization

A plain serializable report, independent of crypto/wire — pure data + bytes.

**Files:**
- Create: `crates/yip-transport/src/feedback.rs`
- Modify: `crates/yip-transport/src/lib.rs` (add `pub mod feedback;` and re-export)
- Test: in `feedback.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `pub struct LossReport { pub delivered_count: u32, pub high_counter: u64, pub missing: Vec<u64> }` with `pub fn encode(&self) -> Vec<u8>` and `pub fn decode(bytes: &[u8]) -> Option<LossReport>`. Wire layout: `[delivered_count:4 BE][high_counter:8 BE][n_missing:2 BE][missing: n×8 BE]`. `decode` returns `None` on short/inconsistent input (untrusted bytes). `encode` caps `missing` at `MAX_NACK` (defined `pub const MAX_NACK: usize = 64;`).

- [ ] **Step 1: Write the round-trip + bounds tests**

```rust
#[test]
fn loss_report_roundtrips() {
    let r = LossReport { delivered_count: 1000, high_counter: 5_000, missing: vec![10, 42, 4_999] };
    let bytes = r.encode();
    let got = LossReport::decode(&bytes).expect("decodes");
    assert_eq!(got.delivered_count, 1000);
    assert_eq!(got.high_counter, 5_000);
    assert_eq!(got.missing, vec![10, 42, 4_999]);
}

#[test]
fn loss_report_decode_rejects_short_input() {
    assert!(LossReport::decode(&[]).is_none());
    assert!(LossReport::decode(&[0u8; 5]).is_none()); // shorter than the 14-byte header
}

#[test]
fn loss_report_encode_caps_missing_at_max_nack() {
    let r = LossReport { delivered_count: 0, high_counter: 0, missing: (0..1000).collect() };
    let got = LossReport::decode(&r.encode()).expect("decodes");
    assert_eq!(got.missing.len(), MAX_NACK);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p yip-transport loss_report -v`
Expected: FAIL — `LossReport` not defined.

- [ ] **Step 3: Implement `LossReport`, `encode`, `decode`, `MAX_NACK`**

Big-endian throughout; `decode` validates `bytes.len() >= 14` and `bytes.len() == 14 + n_missing*8`. No `as` casts (use `u32::from_be_bytes`, `usize::from`, `u16::try_from`).

- [ ] **Step 4: Run tests** — `cargo test -p yip-transport loss_report -v` → PASS.

- [ ] **Step 5: Commit** — `git commit -m "Add LossReport control-packet (de)serialization"`

---

### Task 2: Receiver-side gap loss detector

Consumes the stream of delivered/seen counters; emits a `LossReport`. Pure logic, no I/O.

**Files:**
- Create: `crates/yip-transport/src/lossdetect.rs`
- Modify: `crates/yip-transport/src/lib.rs` (`pub mod lossdetect;`)
- Test: in `lossdetect.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `LossReport`, `MAX_NACK` (Task 1).
- Produces: `pub struct LossDetector { .. }` with:
  - `pub fn new(grace_ms: u64, window: usize) -> Self`
  - `pub fn on_seen(&mut self, counter: u64, now_ms: u64)` — call for every received sealed packet's counter (data or control), before knowing if its object decodes.
  - `pub fn on_delivered(&mut self, counter: u64)` — call when an object for `counter` fully decodes (so it is never reported missing).
  - `pub fn report(&mut self, now_ms: u64) -> LossReport` — declares as missing any counter `< high_counter` first-seen-or-implied older than `grace_ms` and not delivered; advances internal watermark; returns the report and clears reported counters. `delivered_count` = objects delivered since the last `report`. Bounds the pending set to `window` (drops oldest).

Gap model: track `high_counter` (max seen). `on_seen(c)` records `c` and, if `c > high_counter + 1`, marks the skipped range `(prev_high, c)` as *implied-pending* with timestamp `now_ms`. `on_delivered(c)` removes `c` from pending and counts a delivery. `report` promotes implied-pending entries older than `grace_ms` (still not delivered) to `missing`.

- [ ] **Step 1: Write the detector tests**

```rust
#[test]
fn contiguous_no_loss() {
    let mut d = LossDetector::new(5, 1024);
    for c in 0..100u64 { d.on_seen(c, 0); d.on_delivered(c); }
    let r = d.report(100);
    assert!(r.missing.is_empty());
    assert_eq!(r.delivered_count, 100);
}

#[test]
fn gap_reported_after_grace() {
    let mut d = LossDetector::new(5, 1024);
    // see 0,1,3 (2 is a gap); deliver the ones we saw
    for c in [0u64, 1, 3] { d.on_seen(c, 0); d.on_delivered(c); }
    // before grace elapses, 2 is not yet declared
    assert!(d.report(3).missing.is_empty());
    // after grace, 2 is missing
    let r = d.report(10);
    assert_eq!(r.missing, vec![2]);
}

#[test]
fn reorder_within_grace_not_reported() {
    let mut d = LossDetector::new(5, 1024);
    d.on_seen(0, 0); d.on_delivered(0);
    d.on_seen(2, 0); d.on_delivered(2);   // 1 appears skipped...
    d.on_seen(1, 2); d.on_delivered(1);   // ...but arrives within grace
    let r = d.report(10);
    assert!(r.missing.is_empty(), "in-grace reorder must not be reported lost");
}

#[test]
fn missing_set_is_bounded() {
    let mut d = LossDetector::new(0, 8);   // grace 0 → immediate; window 8
    d.on_seen(0, 0);
    d.on_seen(1000, 1);                    // implies a huge gap
    let r = d.report(5);
    assert!(r.missing.len() <= 8 + 64);    // bounded by window and MAX_NACK at encode
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p yip-transport -- lossdetect` → FAIL (undefined).

- [ ] **Step 3: Implement `LossDetector`** per the gap model. Use a `BTreeMap<u64, u64>` (counter → first-implied ms) for pending, a `delivered: u32` counter reset each `report`, and bound the pending map to `window` (evict smallest keys). No `as` casts.

- [ ] **Step 4: Run tests** — all PASS.

- [ ] **Step 5: Commit** — `git commit -m "Add gap-based receiver loss detector"`

---

### Task 3: Class-aware controller — let ARQ classes earn ratio 0

**Files:**
- Modify: `crates/yip-transport/src/control.rs` (`AdaptiveController`)
- Modify: `crates/yip-transport/src/lib.rs` (`Transport::observe_loss` already exists; confirm it forwards per-class)
- Test: `control.rs` `#[cfg(test)]`

**Interfaces:**
- Changes `AdaptiveController::new` to take the class's `arq` flag (or a `floor: f32`): for ARQ classes `min_ratio = 0.0`; for non-ARQ classes `min_ratio = initial_repair_ratio` (unchanged). `repair_count` returns `0` when the ratio rounds to 0 (drop the unconditional `.max(1)`; instead `max(1)` only when `ratio > 0.0`). Keep `observe_loss`'s snap-up (`loss+0.05`) and 10 % clean decay.
- Produces: `repair_count(source) == 0` iff the class is ARQ-eligible and has decayed clean to ratio 0; `>= 1` otherwise.

- [ ] **Step 1: Write the tests**

```rust
#[test]
fn arq_class_decays_to_zero_when_clean() {
    let mut c = AdaptiveController::new_for(FlowClass::Bulk.params()); // arq=true
    for _ in 0..200 { c.observe_loss(0.0); }
    assert_eq!(c.ratio(), 0.0, "bulk earns zero repair on a clean link");
    assert_eq!(c.repair_count(1), 0, "zero ratio -> zero repair -> bypass fires");
    assert_eq!(c.repair_count(10), 0);
}

#[test]
fn non_arq_class_keeps_floor() {
    let mut c = AdaptiveController::new_for(FlowClass::Realtime.params()); // arq=false
    for _ in 0..200 { c.observe_loss(0.0); }
    assert!(c.ratio() >= FlowClass::Realtime.params().initial_repair_ratio - 1e-6);
    assert!(c.repair_count(1) >= 1, "realtime keeps proactive repair");
}

#[test]
fn snaps_up_on_loss_even_from_zero() {
    let mut c = AdaptiveController::new_for(FlowClass::Bulk.params());
    for _ in 0..200 { c.observe_loss(0.0); }
    assert_eq!(c.ratio(), 0.0);
    c.observe_loss(0.10);
    assert!(c.ratio() >= 0.10, "any loss re-arms FEC immediately");
    assert!(c.repair_count(10) >= 1);
}
```

- [ ] **Step 2: Run to verify it fails** — FAIL (`new_for` undefined / floor not applied).

- [ ] **Step 3: Implement.** Add `pub fn new_for(params: FlowParams) -> Self` setting `min_ratio = if params.arq { 0.0 } else { params.initial_repair_ratio }`. Update `repair_count`: compute `n`; `if self.ratio <= f32::EPSILON { 0 } else { n.max(1) }`. Keep the existing `new` (or route it through `new_for`). Update `Transport::new` to build controllers via `new_for`.

- [ ] **Step 4: Run tests** — `cargo test -p yip-transport` all PASS (existing controller tests included; adjust any that assumed `max(1)` for a clean bulk flow).

- [ ] **Step 5: Commit** — `git commit -m "Let ARQ-class repair ratio decay to zero; keep floor for non-ARQ"`

---

### Task 4: Daemon control channel + feedback wiring (Phase A)

Wire the pieces into yipd: send/receive `Control` packets, run the detector, feed `observe_loss`. Establishes the sent log (counter→class) reused by ARQ.

**Files:**
- Modify: `bin/yipd/src/handshake.rs` (`PacketType::Control = 3`)
- Modify: `bin/yipd/src/tunnel.rs` (egress sent-log; ingress detector + control emit; control handler)
- Reference: egress seals per object (`session.seal` → `sealed.counter`), then `transport.encode`; ingress `recv_batch` → `frame_to_symbol` (yields counter+class) → `transport.decode` → on `Some` the object delivered.

**Interfaces:**
- Consumes: `LossReport`/`encode`/`decode` (T1), `LossDetector` (T2), `Transport::observe_loss` (T3), `Session::seal/open`.
- Produces: yipd sends a sealed `Control` packet (`[PacketType::Control][counter:8][ciphertext]`) every `FEEDBACK_INTERVAL_MS` and on new loss; on receiving one, decrypts, and for each `missing` counter looks up its class in the **sent log** (`HashMap<u64, FlowClass>` or the retransmit buffer) to call `observe_loss(class, per_class_fraction)`. A `missing` counter not in the sent log (or a control counter) is ignored for attribution.

- [ ] **Step 1: Baseline gate** — `sudo -E cargo test -p yipd --test tunnel_netns ping_across_yipd_tunnel -- --nocapture --test-threads=1` → PASS.

- [ ] **Step 2: Add `PacketType::Control = 3`** in handshake.rs (mirror the existing enum + `as u8` usage).

- [ ] **Step 3: Implement the wiring.** Egress: record `sent_log.insert(counter, class)` per object (bounded — evict with the retransmit buffer in Phase B; for now a bounded `HashMap`/ring). A periodic timer (or a counter of elapsed `now_ms`) builds a `LossReport` from the ingress detector, seals it, sends it with the `Control` prefix. Ingress: call `detector.on_seen(counter)` for every datagram and `detector.on_delivered(counter)` when `decode` returns `Some`; branch on `PacketType::Control` to decrypt + attribute loss. Keep the two-thread model; the detector and sent-log are shared (`Arc<Mutex>`), like Session/Transport. Per-class fraction = (class missing in this report) / (class sent in the window) — compute from the sent log.

- [ ] **Step 4: Netns regression + activation check.** Run the netns ping test → PASS (wire unchanged for data). Then a new netns check (extend `tunnel_netns` or add a test): on a CLEAN link, after a few seconds of bulk traffic, assert the bulk controller reached ratio 0 (expose via a log line or a test hook) and the FEC bypass is firing (≈1 symbol/packet). If a full assertion is impractical in the test harness, log the ratio and verify manually + leave a smoke assertion that the tunnel still pings.

- [ ] **Step 5: Commit** — `git commit -m "Wire the control channel: feedback packets drive observe_loss"`

---

### Task 5: Phase-A end-to-end throughput check

Confirm the throughput win actually lands now that bulk can reach zero repair.

**Files:**
- Modify: `crates/yip-bench/README.md` (Phase-A throughput delta)
- Run: `crates/yip-bench/tests/run-iperf-compare.sh`

- [ ] **Step 1: Build release + measure**

```bash
cargo build --release -p yipd
sudo -E bash crates/yip-bench/tests/run-iperf-compare.sh target/release/yipd
```
Expected: yip clean-link (0 % loss) single-stream TCP **rises** vs the throughput-pass baseline (~220–285 Mbit/s) once the bulk flow drives repair to 0 (the bypass fires + datagram count halves). Record the before/after.

- [ ] **Step 2: Record** in the bench README (a "Feedback loop — Phase A" delta). If throughput did NOT rise, STOP and investigate whether the bulk flow actually reached ratio 0 (the feedback round-trip + classification) before proceeding to ARQ.

- [ ] **Step 3: Commit** — `git commit -m "Measure the Phase-A clean-link throughput win"`

---

## Phase B — reactive ARQ

### Task 6: Bounded sender retransmit buffer

**Files:**
- Create: `crates/yip-transport/src/retxbuf.rs`
- Modify: `crates/yip-transport/src/lib.rs` (`pub mod retxbuf;`)
- Test: `retxbuf.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `pub struct RetxBuffer { .. }` with `pub fn new(max: usize, ttl_ms: u64) -> Self`, `pub fn put(&mut self, counter: u64, ciphertext: Vec<u8>, class: FlowClass, object_id: u16, now_ms: u64)`, `pub fn get(&self, counter: u64, now_ms: u64) -> Option<(&[u8], FlowClass, u16)>` (returns `None` if absent or older than `ttl`; the `u16` is the original `object_id` — retransmits MUST reuse it so the receiver's existing decoder for that object is topped up rather than a new one started), and internal LRU+TTL eviction keeping `<= max` entries. Mirrors the existing bounded `FlowTable` pattern in `flow.rs` (order `VecDeque` + map, evict oldest past cap/ttl).

- [ ] **Step 1: Write tests** (put/get round-trip; eviction past `max`; `get` returns `None` past `ttl`; bounded size under churn — mirror `flow.rs::flow_table_is_bounded`).

```rust
#[test]
fn retx_put_get_roundtrip() {
    let mut b = RetxBuffer::new(1024, 2000);
    b.put(7, vec![1,2,3], FlowClass::Bulk, 99, 0);
    let (ct, class, oid) = b.get(7, 100).expect("present");
    assert_eq!(ct, &[1,2,3]); assert_eq!(class, FlowClass::Bulk); assert_eq!(oid, 99);
}
#[test]
fn retx_evicts_past_ttl() {
    let mut b = RetxBuffer::new(1024, 2000);
    b.put(7, vec![1], FlowClass::Bulk, 0, 0);
    assert!(b.get(7, 3000).is_none(), "expired past ttl");
}
#[test]
fn retx_is_bounded_under_churn() {
    let mut b = RetxBuffer::new(16, 1_000_000);
    for c in 0..10_000u64 { b.put(c, vec![0u8; 4], FlowClass::Bulk, 0, c); }
    assert!(b.len() <= 16);
}
```

- [ ] **Step 2: Run to verify fail.** **Step 3: Implement** (add `len()` for the test). **Step 4: Run PASS.** **Step 5: Commit** — `git commit -m "Add bounded sender retransmit buffer"`

---

### Task 7: Retransmit on NACK (fresh repair symbols, class/deadline-aware) + dedup

**Files:**
- Modify: `crates/yip-transport/src/lib.rs` (a `Transport::repair_object` API)
- Modify: `bin/yipd/src/tunnel.rs` (egress fills `RetxBuffer`; control handler retransmits eligible NACKs)
- Test: `lib.rs` `#[cfg(test)]` (repair round-trip) + the netns ARQ test

**Interfaces:**
- Consumes: `RetxBuffer` (T6), `FecEncoder` (existing), `FlowParams.arq`/`deadline`.
- Produces: `pub fn repair_object(&mut self, ciphertext: &[u8], class: FlowClass, object_id: u16, extra_repair: u32) -> Vec<Symbol>` on `Transport` — generates fresh RaptorQ repair symbols (ESI beyond the source range) for the object, **carrying the original `object_id`** so the receiver tops up its existing decoder for that object. (Implementation: a `FecEncoder::repair_with_id(ciphertext, params, object_id, extra_repair)` that builds the encoder and emits the repair-only `EncodingPacket`s through `split_packet(object_id, …)`; verify identity + completion via the decode round-trip below.)

- [ ] **Step 1: Repair round-trip unit test**

```rust
#[test]
fn retransmitted_repair_completes_a_missing_object() {
    let mut tx = Transport::new(vec![]);
    let ct = vec![0x33u8; 2400]; // 2 source symbols
    let (cls, syms) = tx.encode(&ct, &ct, false, 0);
    let oid = syms[0].object_id; // the original object's identity
    // Drop one source symbol; decode stalls.
    let mut rx = Transport::new(vec![]);
    let mut out = None;
    for s in syms.iter().skip(1) { out = out.or(rx.decode(s, cls)); }
    assert!(out.is_none(), "one symbol short -> not yet decoded");
    // Retransmit: fresh repair symbols carrying the SAME object_id top up the decoder.
    let repair = tx.repair_object(&ct, cls, oid, 2);
    assert!(repair.iter().all(|s| s.object_id == oid), "repair reuses object identity");
    for s in &repair { out = out.or(rx.decode(s, cls)); }
    assert_eq!(out.as_deref(), Some(ct.as_slice()));
}
```

- [ ] **Step 2: Run fail → Step 3: implement `repair_object`** (and have egress capture `object_id = syms[0].object_id` from its `encode` result and `retx.put(counter, sealed.ciphertext.clone(), class, object_id, now)`). The control handler, per `missing` counter: `if let Some((ct, class, oid)) = retx.get(counter, now)` (which already drops entries past the buffer TTL) and `class.params().arq` (excludes realtime — its objects are never retransmitted) → `let syms = transport.repair_object(ct, class, oid, K)` → frame each under that `counter` + class (reuse `wire_glue::symbol_to_frame`) → `send_batch`. Else ignore. Dedup is automatic: a retransmit for an already-delivered object returns `None` from `decode` (the existing "late symbol after completion" path — covered by `decode_late_symbol_returns_none_after_completion`).

- [ ] **Step 4: Netns ARQ test under loss.** Add/extend a root-gated test: two yipd over netem with ~5–10 % loss carrying a **bulk** flow; assert payload integrity is maintained (ARQ recovers what FEC misses). A **realtime**-classed flow under loss: assert no retransmit traffic for it (e.g., via a counter/log). At minimum, assert the bulk transfer completes intact under loss where it would otherwise drop.

- [ ] **Step 5: Commit** — `git commit -m "Reactive ARQ: retransmit fresh repair symbols for eligible NACKs"`

---

### Task 8: End-to-end measurement + docs (the verdict)

**Files:**
- Modify: `crates/yip-bench/README.md`, `CHANGELOG.md`
- Run: `run-iperf-compare.sh`, `run-fec-compare.sh`, the netns ARQ test

- [ ] **Step 1: Measure** clean-link throughput (should hold the Phase-A gain) and loss-recovery (FEC + ARQ): `run-fec-compare.sh` should still show yip ~full delivery; add an ARQ-under-loss data point.

- [ ] **Step 2: Record** before/after + the ARQ result in the bench README; add a `CHANGELOG.md` entry. Revert any sub-change that showed no value.

- [ ] **Step 3: Full gate** — `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` → green; plus the root-gated netns tests under sudo.

- [ ] **Step 4: Commit** — `git commit -m "Measure and record the feedback loop + ARQ"`

---

## Self-review notes

- **Spec coverage:** Control packet → T1; gap detector → T2; class-aware zero-repair → T3; control wiring/attribution → T4; Phase-A throughput verdict → T5; retransmit buffer → T6; ARQ retransmit + dedup + deadline/class gating → T7; final measurement → T8. Security (sealed control) is in T4; bounded buffers in T2/T6. Out-of-scope items untasked.
- **Phase boundary:** T1–T5 deliver a working, independently-valuable system (the throughput win) before any ARQ code — the spec's required sequencing.
- **Type consistency:** `LossReport{delivered_count,high_counter,missing}`, `MAX_NACK`, `LossDetector::{new,on_seen,on_delivered,report}`, `AdaptiveController::new_for`, `RetxBuffer::{new,put,get,len}`, `Transport::repair_object` are used consistently across tasks.
- **Wire-compat gate:** T4 and T7 are guarded by the `tunnel_netns` ping test; data-symbol frame unchanged.
- **Known soft spot:** T4's "assert the controller reached ratio 0" may need a small test hook (a log line or a debug accessor) since it's daemon-internal — the plan allows logging + a ping smoke assertion if a hard assertion is impractical; the real proof is T5's throughput rise.
