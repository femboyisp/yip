# Data-plane correctness follow-ups (#11b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the bounded correctness gaps called out in issue #11 for the post-#7 data plane: bind wire `object_id` to authenticated context, honor per-class FEC deadlines for reassembly and ARQ eligibility, and make the flow classifier observe ingress as well as egress.

**Architecture:** All changes stay inside existing crates (`yip-transport`, `yipd`) with no wire-format break. `object_id` binding is a receiver-side namespace scoped to the authenticated session/epoch. Deadline eviction extends `FecReassembler` with timestamped objects and a periodic sweep driven from `Transport::decode` / `DataPlane::tick`. Bidirectional flow accounting adds an ingress observe hook after successful decode. The loss-detector partial-receive limitation is documentation-only in this wave.

**Tech Stack:** Rust, existing `yip-transport` FEC/ARQ stack, `bin/yipd` `DataPlane`.

## Global Constraints

- **No wire-format change.** Symbol layout (`object_id`, `object_size`, payload) is unchanged; binding is local namespacing + validation.
- **No control-plane / rekey work.** Epoch-aware binding must compile against today's single-session model and remain compatible with the #9 epoch table (separate `Transport` or scoped context per epoch when #9 lands).
- **Netns gate unchanged.** `cargo test -p yipd tunnel_netns` (default + `YIP_FORCE_POLL=1`) must stay green after every task.
- **Independent PRs OK.** Tasks 1–3 can land as separate commits/PRs; Task 0 (docs) is standalone.
- Mullvad lints, `-D warnings`; no `as` numeric casts except sanctioned `PacketType::* as u8`; `#![forbid(unsafe_code)]` outside `yip-io`; ≥90 % aggregate coverage (excluding `yip-device`, `yipd` per existing gate); `CHANGELOG.md` entry per shipped task.

## Non-goals

- Exact per-class loss denominator (issue #11 performance item; conservative over-repair is safe).
- Loss-detector algorithm changes beyond documentation (revisit only if heavy-loss multi-symbol accuracy becomes measured).
- Anti-DPI header protection (#11c) or rekey epoch machinery (#9 implementation).
- `drain_tun` clone elimination, AF_XDP, bench polish.

## Risk Controls

| Risk | Mitigation |
|------|------------|
| Forged `object_id` evicts live decoder | Scope ids to authenticated context; reject symbols for unknown scoped ids |
| Deadline sweep stalls hot path | O(in_flight) sweep only on `tick` / decode entry, bounded `max_objects` |
| Ingress observe skews egress classification | Observe on both paths with same `FlowKey` derivation; unit + netns tests |
| #9 epoch overlap conflicts | Design binding key as `(epoch_id, wire_object_id)` seam; default `epoch_id = 0` until #9 |

---

## Task 0: Document loss-detector partial-receive limitation

**Files:**
- Modify: `crates/yip-transport/src/lossdetect.rs` (module docs only)

**Scope:** Expand the existing module-level docs to state explicitly:
- `resolved_set` eviction under extreme reordering can yield a benign spurious NACK (sender drops).
- Exact for single-symbol / zero-repair objects; multi-symbol heavy-loss accuracy is best-effort.
- No behavior change in this task.

- [ ] **Step 1:** Add a `## Limitations` subsection to the module docs covering the three bullets above.
- [ ] **Step 2:** `cargo test -p yip-transport lossdetect -v` → PASS (docs only).
- [ ] **Step 3:** Commit — `git commit -m "Docs: loss-detector partial-receive limitation (#11b)"`

---

## Task 1: Wire-auth `object_id` binding

Bind attacker-supplied `object_id` / `object_size` to authenticated peer context so a forged id cannot LRU-evict a live in-flight object.

**Files:**
- Modify: `crates/yip-transport/src/fec.rs` (`FecReassembler`, `Symbol` handling)
- Modify: `crates/yip-transport/src/lib.rs` (`Transport::decode`, encoder id allocation)
- Modify: `bin/yipd/src/dataplane.rs` (pass binding context into decode)
- Test: `crates/yip-transport/src/fec.rs` `#[cfg(test)]`, `bin/yipd/src/dataplane.rs` `#[cfg(test)]`

**Design:**
- Introduce `ObjectScope { epoch_id: u64, local_id: u16 }` (or equivalent) as the reassembler map key. Phase 1 uses `epoch_id = 0`.
- Sender: `FecEncoder` continues emitting monotonic `local_id`; scope is implicit on the authenticated egress path.
- Receiver: on first symbol for a scope, verify `object_size` against decrypted inner length bounds (existing C1/C2 guards stay). Reject symbols whose `(epoch_id, local_id)` was never opened by a symbol authenticated under the current session (no "create decoder" solely from wire id).
- Optional hardening: cap distinct scopes per class to `max_objects` (existing bound).

**Interfaces:**
- `pub struct ObjectScope { pub epoch_id: u64, pub local_id: u16 }`
- `FecReassembler::push(&mut self, scope: ObjectScope, symbol: &Symbol) -> Option<Vec<u8>>`
- `Transport::decode(&mut self, symbol: &Symbol, class: FlowClass, scope: ObjectScope) -> Option<Vec<u8>>`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn forged_object_id_cannot_evict_live_object() {
    // Start decoding object A under scope (0, 1); inject forged symbol for scope (0, 9999)
    // with attacker object_size; assert A's decoder remains intact and forged scope rejected.
}

#[test]
fn decode_roundtrip_preserves_scope_binding() {
    // encode → decode with matching scope succeeds; mismatched scope returns None.
}
```

- [ ] **Step 2:** Run `cargo test -p yip-transport forged_object` → FAIL.

- [ ] **Step 3:** Implement `ObjectScope`, rewire `FecReassembler` keys, plumb scope from `DataPlane::on_udp_datagram` (derive `epoch_id = 0` for now).

- [ ] **Step 4:** Run `cargo test -p yip-transport fec` and `cargo test -p yipd dataplane` → PASS.

- [ ] **Step 5:** Gate — `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`

- [ ] **Step 6:** Commit — `git commit -m "Bind FEC object_id to authenticated scope (#11b)"`

---

## Task 2: Deadline-based FEC eviction

Honor `FlowParams.deadline` for reassembler eviction and ARQ eligibility instead of LRU-count alone.

**Files:**
- Modify: `crates/yip-transport/src/fec.rs` (`ObjState`, `FecReassembler`)
- Modify: `crates/yip-transport/src/lib.rs` (`Transport` — expose sweep hook)
- Modify: `crates/yip-transport/src/retxbuf.rs` (TTL alignment with class deadline)
- Modify: `bin/yipd/src/dataplane.rs` (`tick` calls sweep; ARQ skips expired objects)
- Test: `crates/yip-transport/src/fec.rs`, `crates/yip-transport/src/retxbuf.rs`

**Design:**
- Store `first_seen_ms` per object in `ObjState`.
- `FecReassembler::sweep(now_ms, deadline: Duration)` drops objects where `now_ms - first_seen_ms > deadline`.
- On `push`, if at `max_objects`, evict expired-first, then oldest (current LRU) as fallback.
- `RetxBuffer::get` returns `None` when entry age exceeds `min(ttl_ms, class.deadline)`.
- `DataPlane::tick` invokes per-class sweep using `FlowClass::params().deadline`.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn reassembler_evicts_past_deadline() {
    let mut r = FecReassembler::new(512, 256);
    // insert partial object at t=0; sweep at t=deadline+1 removes it without completing.
}

#[test]
fn retx_get_respects_class_deadline() {
    // put entry; advance clock past Bulk deadline; get returns None.
}
```

- [ ] **Step 2:** Run `cargo test -p yip-transport deadline` → FAIL.

- [ ] **Step 3:** Implement `first_seen_ms`, `sweep`, wire into `Transport` and `DataPlane::tick`.

- [ ] **Step 4:** Run unit tests → PASS; run netns tunnel suite (both drivers) → PASS.

- [ ] **Step 5:** Commit — `git commit -m "Honor FlowParams.deadline for FEC and ARQ (#11b)"`

---

## Task 3: Bidirectional flow accounting

Let the classifier heuristic observe ingress-decoded packets, not only egress `encode` calls.

**Files:**
- Modify: `crates/yip-transport/src/classify.rs` (`Classifier::observe` or split internal helper)
- Modify: `crates/yip-transport/src/lib.rs` (`Transport::observe_ingress`)
- Modify: `bin/yipd/src/dataplane.rs` (call after successful `decode` + `open`)
- Test: `crates/yip-transport/src/classify.rs`, `crates/yip-transport/src/lib.rs`

**Design:**
- Add `pub fn observe_ingress(&mut self, inner: &[u8], l2: bool, now_ms: u64)` on `Transport` that updates `FlowTable` without returning a class (or returns `Option<FlowClass>` for diagnostics only).
- `DataPlane::on_udp_datagram` data path: after `transport.decode` yields ciphertext and `session.open` succeeds, call `observe_ingress` with the decrypted inner frame.
- Egress `encode` continues to call `classify` (which also observes). Duplicate observe on reflected traffic is acceptable; keys are symmetric 5-tuple from packet headers.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn ingress_observe_populates_flow_table_without_egress() {
    let mut t = Transport::new(vec![]);
    let inner = ipv4_udp_small_packet();
    t.observe_ingress(&inner, false, 100);
    // Next classify for same 5-tuple should hit heuristic (Realtime/Bulk) without prior encode.
}
```

- [ ] **Step 2:** Run `cargo test -p yip-transport ingress_observe` → FAIL.

- [ ] **Step 3:** Implement `observe_ingress` + dataplane hook.

- [ ] **Step 4:** Run `cargo test -p yip-transport classify` and netns suite → PASS.

- [ ] **Step 5:** Commit — `git commit -m "Observe ingress packets in flow classifier (#11b)"`

---

## Task 4: Integration gate + changelog

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1:** Add Keep a Changelog entries under `Unreleased` summarizing Tasks 0–3 (or per-task entries if landed separately).
- [ ] **Step 2:** Full gate:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo llvm-cov --workspace --exclude yip-device --exclude yipd --fail-under-lines 90 --summary-only
# netns: default driver + YIP_FORCE_POLL=1 (all three tunnel tests)
```

- [ ] **Step 3:** Commit — `git commit -m "CHANGELOG: data-plane correctness follow-ups (#11b)"`

---

## Definition of done (#11b)

- [ ] Loss-detector limitation documented (Task 0).
- [ ] Forged `object_id` cannot evict unrelated live objects (Task 1).
- [ ] Reassembler + ARQ respect `FlowParams.deadline` (Task 2).
- [ ] Classifier flow table learns from ingress and egress (Task 3).
- [ ] All gates green; changelog updated (Task 4).
