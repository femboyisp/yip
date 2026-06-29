# Data Plane M5 — `yip-transport` Adaptive RaptorQ FEC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `yip-transport`'s proactive adaptive FEC: classify each flow, RaptorQ-encode a sealed ciphertext frame into wire symbols with explicit OTI, reassemble symbols back into the frame across packet loss and reordering, and adapt the repair ratio to measured loss.

**Architecture:** Encrypt-then-FEC: the transport operates on already-sealed ciphertext (from `yip-crypto`). A `Classifier` maps an inner packet to a `FlowClass` (policy → DSCP → heuristic → default), each class carrying `FlowParams` (symbol size, repair ratio, deadline). A `FecEncoder` turns one ciphertext frame + a repair count into a `Vec<Symbol>` (source + repair, each with the RaptorQ payload-id and the object's OTI size). A `FecReassembler` keeps a per-`object_id` RaptorQ decoder (pipelined, LRU-evicted, deadline-bounded) and yields the ciphertext when an object decodes. An `AdaptiveController` adjusts each class's repair ratio toward a target residual loss. The reactive ARQ round-trip is deferred to M6 (needs the daemon feedback channel); M5 exposes the hook (`FecReassembler::expired` reports undecodable objects).

**Tech Stack:** Rust, `raptorq` (RFC 6330 fountain code).

## Global Constraints

- License MPL-2.0; `#![forbid(unsafe_code)]` stays on `yip-transport`.
- Lints: workspace set, CI `--deny warnings`. **No `as` numeric casts** — use `From`/`TryFrom`/`try_into`. (RaptorQ APIs take `u64`/`u16`; convert lengths with `u64::try_from`/`u16::try_from`.)
- Dep pinned full `x.y.z`: `raptorq = "2.0.0"`.
- Borrowed types in signatures (`&[u8]`).
- Files UTF-8/LF/final-newline/no-trailing-ws; commits imperative+capitalized ≤72-char subject, body ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- A pre-commit hook runs fmt+clippy+test on commit; each task's commit must pass it.
- Coverage: `yip-transport` is a pure-logic crate held to ≥90% line coverage.

## Verified `raptorq` 2.0.0 API (spiked)

```rust
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
let oti = ObjectTransmissionInformation::with_defaults(object_len_u64, symbol_size_u16);
// oti.transfer_length() -> u64 ; oti.symbol_size() -> u16 ; oti.serialize() -> Vec<u8> (12 bytes)
let enc = Encoder::new(&ciphertext, oti);
let packets: Vec<EncodingPacket> = enc.get_encoded_packets(repair_count_u32); // source + `repair_count` repair
let wire: Vec<u8> = packets[i].serialize();        // 4-byte payload-id (SBN+ESI) + symbol bytes
let pkt = EncodingPacket::deserialize(&wire);      // parse back
let mut dec = Decoder::new(ObjectTransmissionInformation::with_defaults(object_len_u64, symbol_size_u16));
let done: Option<Vec<u8>> = dec.decode(pkt);       // Some(object) once enough symbols arrive; idempotent after
```

Key facts the design relies on: the decoder needs the **same OTI** (object length + symbol size) as the encoder — `symbol_size` is fixed per `FlowClass`, `object_len` (= ciphertext length) varies per object and is carried explicitly as `Symbol.object_size` (nyxpsi rule 1: never infer OTI from packet length). `get_encoded_packets(n)` is rateless and deterministic — requesting more repair later returns the same prefix plus new repair (used by M6's ARQ).

## Symbol — the transport's wire-bound unit

```rust
pub struct Symbol {
    pub object_id: u16,      // which pipelined object (assigned by the encoder, monotonic)
    pub object_size: u32,    // OTI transfer_length for this object (the ciphertext length)
    pub payload_id: [u8; 4], // RaptorQ SBN+ESI, from EncodingPacket::serialize()'s first 4 bytes
    pub data: Vec<u8>,       // the symbol bytes (serialized EncodingPacket minus the 4-byte id)
}
```

M6 maps `Symbol` ↔ `yip_wire::Frame` (`object_id`/`payload_id` map directly; `object_size` rides the frame's object-descriptor). For M5, `Symbol` is the self-contained unit the transport produces and consumes.

---

### Task 1: `FlowClass` params + `Classifier`

**Files:**
- Modify: `crates/yip-transport/Cargo.toml`
- Modify: `crates/yip-transport/src/lib.rs`
- Create: `crates/yip-transport/src/classify.rs`

**Interfaces:**
- Produces:
  - `pub struct FlowParams { pub symbol_size: u16, pub initial_repair_ratio: f32, pub deadline: std::time::Duration, pub arq: bool }`
  - `impl FlowClass { pub fn params(self) -> FlowParams }` (defaults per class)
  - `pub struct PolicyRule { pub proto: Option<u8>, pub dst_port: Option<u16>, pub class: FlowClass }`
  - `pub struct Classifier { rules: Vec<PolicyRule> }` with `new(rules)`, and `pub fn classify(&self, inner: &[u8], l2: bool) -> FlowClass`
  - private `fn parse_ip(inner: &[u8], l2: bool) -> Option<Parsed>` extracting `{ dscp: u8, proto: u8, dst_port: Option<u16> }`

- [ ] **Step 1: Write the failing tests**

Create `crates/yip-transport/src/classify.rs` with a test module (and `mod classify;` in lib.rs):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    fn ipv4(dscp: u8, proto: u8, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45; // v4, IHL 5
        p[1] = dscp << 2; // DSCP in top 6 bits of ToS
        p[9] = proto;
        // dst port at IP payload offset 20 (UDP/TCP dst is bytes 2..4 of L4)
        p[22] = (dst_port >> 8) as u8; // NOTE: replace `as` with to_be_bytes in impl; test buffer only
        p[23] = (dst_port & 0xff) as u8;
        p
    }

    #[test]
    fn dscp_ef_maps_to_realtime() {
        let c = Classifier::new(vec![]);
        // DSCP 46 (EF) -> Realtime
        assert_eq!(c.classify(&ipv4(46, 17, 5000), false), FlowClass::Realtime);
        // DSCP 0 default -> Default
        assert_eq!(c.classify(&ipv4(0, 17, 5000), false), FlowClass::Default);
    }

    #[test]
    fn policy_rule_overrides_dscp() {
        let c = Classifier::new(vec![PolicyRule { proto: Some(17), dst_port: Some(5000), class: FlowClass::Bulk }]);
        // policy wins even though DSCP says realtime
        assert_eq!(c.classify(&ipv4(46, 17, 5000), false), FlowClass::Bulk);
    }

    #[test]
    fn malformed_packet_is_default() {
        let c = Classifier::new(vec![]);
        assert_eq!(c.classify(&[0u8; 3], false), FlowClass::Default);
    }
}
```

(The test buffer uses `as` only to build fixtures; the PRODUCTION code must use `to_be_bytes`/`from_be_bytes` — no `as`.)

- [ ] **Step 2: Run them — expect failure**

Run: `cargo test -p yip-transport classify`
Expected: FAIL (module/types undefined).

- [ ] **Step 3: Implement `classify.rs`**

Add `pub mod classify;` near the top of `lib.rs` and `pub use classify::{Classifier, PolicyRule};`. Extend `FlowClass` with a `params` method (in `lib.rs`):

```rust
// in lib.rs, alongside FlowClass:
use std::time::Duration;

/// Per-class FEC parameters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlowParams {
    /// RaptorQ symbol size for this class (fixed, so it need not be signaled per packet).
    pub symbol_size: u16,
    /// Initial proactive repair fraction (the controller adjusts from here).
    pub initial_repair_ratio: f32,
    /// How long to keep a partially-received object before evicting it.
    pub deadline: Duration,
    /// Whether this class uses reactive ARQ (wired in M6).
    pub arq: bool,
}

impl FlowClass {
    /// Default FEC parameters for this class.
    pub fn params(self) -> FlowParams {
        match self {
            FlowClass::Realtime => FlowParams {
                symbol_size: 1200, initial_repair_ratio: 0.15,
                deadline: Duration::from_millis(20), arq: false,
            },
            FlowClass::Bulk => FlowParams {
                symbol_size: 1200, initial_repair_ratio: 0.05,
                deadline: Duration::from_millis(500), arq: true,
            },
            FlowClass::Default => FlowParams {
                symbol_size: 1200, initial_repair_ratio: 0.10,
                deadline: Duration::from_millis(100), arq: false,
            },
        }
    }
}
```

`classify.rs`:

```rust
//! Per-flow classification: map an inner packet to a [`FlowClass`] via the
//! precedence policy rule -> DSCP/ToS -> heuristic -> default.

use crate::FlowClass;

/// A user policy rule pinning matching flows to a class (highest precedence).
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// IP protocol number to match (None = any).
    pub proto: Option<u8>,
    /// Destination L4 port to match (None = any).
    pub dst_port: Option<u16>,
    /// Class assigned to matching flows.
    pub class: FlowClass,
}

/// Classifies inner packets into flow classes.
#[derive(Debug, Clone)]
pub struct Classifier {
    rules: Vec<PolicyRule>,
}

struct Parsed {
    dscp: u8,
    proto: u8,
    dst_port: Option<u16>,
}

impl Classifier {
    /// Build a classifier from an ordered list of policy rules.
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// Classify an inner frame. `l2` = true when the frame is an Ethernet (TAP)
    /// frame (skip the 14-byte Ethernet header), false for an L3 (TUN) IP packet.
    pub fn classify(&self, inner: &[u8], l2: bool) -> FlowClass {
        let Some(p) = parse_ip(inner, l2) else {
            return FlowClass::Default;
        };
        // 1. explicit policy
        for r in &self.rules {
            if r.proto.is_none_or(|x| x == p.proto)
                && r.dst_port.is_none_or(|x| Some(x) == p.dst_port)
            {
                return r.class;
            }
        }
        // 2. DSCP
        match p.dscp {
            46 | 40 | 48 | 56 => return FlowClass::Realtime, // EF, CS5, CS6, CS7
            8 | 10 | 12 | 14 => return FlowClass::Bulk,      // CS1, AF11..AF13 (bulk-ish)
            _ => {}
        }
        // 3. heuristic: small datagrams look interactive
        if inner.len() < 256 {
            return FlowClass::Realtime;
        }
        // 4. default
        FlowClass::Default
    }
}

/// Extract DSCP/proto/dst-port from an IPv4/IPv6 inner packet (None if malformed).
fn parse_ip(inner: &[u8], l2: bool) -> Option<Parsed> {
    let ip = if l2 {
        // Ethernet header is 14 bytes; only handle plain (non-VLAN) IPv4/IPv6.
        let ethertype = u16::from_be_bytes([*inner.get(12)?, *inner.get(13)?]);
        match ethertype {
            0x0800 | 0x86DD => inner.get(14..)?,
            _ => return None,
        }
    } else {
        inner
    };
    let version = ip.first()? >> 4;
    let (dscp, proto, l4_off) = match version {
        4 => {
            let ihl = usize::from(ip[0] & 0x0F) * 4;
            let dscp = ip.get(1)? >> 2;
            let proto = *ip.get(9)?;
            (dscp, proto, ihl)
        }
        6 => {
            let tc = (u16::from(*ip.first()? & 0x0F) << 4) | u16::from(ip.get(1)? >> 4);
            let dscp = u8::try_from(tc >> 2).ok()?;
            let proto = *ip.get(6)?; // next-header
            (dscp, proto, 40)
        }
        _ => return None,
    };
    // dst port = bytes 2..4 of the L4 header, for TCP(6)/UDP(17)
    let dst_port = if matches!(proto, 6 | 17) {
        ip.get(l4_off + 2..l4_off + 4)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    } else {
        None
    };
    Some(Parsed { dscp, proto, dst_port })
}
```

Note: `is_none_or` requires a recent stable Rust (1.82+); our toolchain is 1.96. If clippy/build complains, use `r.proto.map_or(true, |x| x == p.proto)`.

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yip-transport classify`
Expected: PASS. `cargo clippy -p yip-transport --all-targets -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/Cargo.toml crates/yip-transport/src/lib.rs crates/yip-transport/src/classify.rs
git commit -m "Add flow params and packet classifier to yip-transport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `FecEncoder` — object → symbols

**Files:**
- Create: `crates/yip-transport/src/fec.rs`
- Modify: `crates/yip-transport/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct Symbol { pub object_id: u16, pub object_size: u32, pub payload_id: [u8; 4], pub data: Vec<u8> }`
  - `pub struct FecEncoder { next_object_id: u16 }`
  - `impl FecEncoder { pub fn new() -> Self; pub fn encode(&mut self, ciphertext: &[u8], params: FlowParams, repair: u32) -> Vec<Symbol> }`

- [ ] **Step 1: Write the failing test**

In `crates/yip-transport/src/fec.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    #[test]
    fn encode_produces_source_plus_repair_with_explicit_oti() {
        let mut enc = FecEncoder::new();
        let ct: Vec<u8> = (0..3000u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let params = FlowClass::Bulk.params();
        let syms = enc.encode(&ct, params, 8);
        // object_size carried explicitly on every symbol
        assert!(syms.iter().all(|s| s.object_size == 3000));
        // distinct object_ids increment
        let syms2 = enc.encode(&ct, params, 8);
        assert_eq!(syms[0].object_id, 0);
        assert_eq!(syms2[0].object_id, 1);
        // payload_id is 4 bytes; data non-empty
        assert_eq!(syms[0].payload_id.len(), 4);
        assert!(!syms[0].data.is_empty());
        // at least source symbols (ceil(3000/1200)=3) plus 8 repair
        assert!(syms.len() >= 3 + 8);
    }
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-transport encode_produces`
Expected: FAIL (`FecEncoder`/`Symbol` undefined).

- [ ] **Step 3: Implement the encoder**

Add `pub mod fec;` and `pub use fec::{FecEncoder, FecReassembler, Symbol};` to `lib.rs` (FecReassembler arrives in Task 3 — add it to the `pub use` then). In `fec.rs`:

```rust
//! RaptorQ object encoding/decoding for the FEC transport. Encrypt-then-FEC:
//! the unit of coding is one sealed ciphertext frame ("object"), split into
//! source + repair symbols carrying an explicit OTI (object size) so the
//! decoder never has to infer it.

use raptorq::{Encoder, EncodingPacket, ObjectTransmissionInformation};

/// One wire-bound RaptorQ symbol plus the metadata the receiver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Which pipelined object this symbol belongs to.
    pub object_id: u16,
    /// The object's RaptorQ transfer length (ciphertext byte count).
    pub object_size: u32,
    /// RaptorQ payload identifier (SBN + ESI).
    pub payload_id: [u8; 4],
    /// The symbol bytes.
    pub data: Vec<u8>,
}

/// Encodes ciphertext frames into RaptorQ symbols, assigning monotonic object ids.
#[derive(Debug, Default)]
pub struct FecEncoder {
    next_object_id: u16,
}

impl FecEncoder {
    /// Create an encoder starting at object id 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode one ciphertext frame into source + `repair` symbols under `params`.
    pub fn encode(&mut self, ciphertext: &[u8], params: crate::FlowParams, repair: u32) -> Vec<Symbol> {
        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        let object_size = u32::try_from(ciphertext.len()).expect("frame fits u32");
        let oti = ObjectTransmissionInformation::with_defaults(
            u64::from(object_size),
            params.symbol_size,
        );
        let encoder = Encoder::new(ciphertext, oti);
        encoder
            .get_encoded_packets(repair)
            .into_iter()
            .map(|p| split_packet(object_id, object_size, &p))
            .collect()
    }
}

/// Split a serialized EncodingPacket into the 4-byte payload-id and the symbol bytes.
fn split_packet(object_id: u16, object_size: u32, packet: &EncodingPacket) -> Symbol {
    let bytes = packet.serialize();
    let mut payload_id = [0u8; 4];
    payload_id.copy_from_slice(&bytes[..4]);
    Symbol { object_id, object_size, payload_id, data: bytes[4..].to_vec() }
}
```

- [ ] **Step 4: Run the test — expect pass**

Run: `cargo test -p yip-transport encode_produces`
Expected: PASS. `cargo clippy -p yip-transport --all-targets -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/fec.rs crates/yip-transport/src/lib.rs
git commit -m "Add RaptorQ FEC encoder to yip-transport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `FecReassembler` — symbols → object (pipelined, erasure-tolerant, evicting)

**Files:**
- Modify: `crates/yip-transport/src/fec.rs`

**Interfaces:**
- Produces:
  - `pub struct FecReassembler { symbol_size: u16, objects: std::collections::HashMap<u16, ObjState>, order: std::collections::VecDeque<u16>, max_objects: usize }`
  - `impl FecReassembler { pub fn new(symbol_size: u16, max_objects: usize) -> Self; pub fn push(&mut self, symbol: &Symbol) -> Option<Vec<u8>>; pub fn in_flight(&self) -> usize }`

- [ ] **Step 1: Write the failing tests**

Add to `fec.rs` tests:

```rust
#[test]
fn reassembles_through_erasure_and_reordering() {
    let mut enc = FecEncoder::new();
    let ct: Vec<u8> = (0..5000u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let params = crate::FlowClass::Bulk.params();
    let mut syms = enc.encode(&ct, params, 12);
    // reorder + drop every 4th
    syms.reverse();
    let mut re = FecReassembler::new(params.symbol_size, 64);
    let mut out = None;
    for (i, s) in syms.iter().enumerate() {
        if i % 4 == 0 { continue; } // erasure
        if let Some(frame) = re.push(s) { out = Some(frame); break; }
    }
    assert_eq!(out.as_deref(), Some(ct.as_slice()));
}

#[test]
fn pipelines_two_objects_and_evicts_when_full() {
    let mut enc = FecEncoder::new();
    let params = crate::FlowClass::Default.params();
    let a = enc.encode(b"first object payload contents here", params, 4);
    let b = enc.encode(b"second object payload contents here", params, 4);
    let mut re = FecReassembler::new(params.symbol_size, 1); // cap 1 -> pushing b evicts a
    // feed only the first symbol of `a` (incomplete), then all of `b`
    re.push(&a[0]);
    assert_eq!(re.in_flight(), 1);
    let mut got_b = None;
    for s in &b {
        if let Some(f) = re.push(s) { got_b = Some(f); }
    }
    assert_eq!(got_b.as_deref(), Some(&b"second object payload contents here"[..]));
}
```

- [ ] **Step 2: Run them — expect failure**

Run: `cargo test -p yip-transport reassembl pipelines`
Expected: FAIL (`FecReassembler` undefined).

- [ ] **Step 3: Implement the reassembler**

```rust
use raptorq::Decoder;
use std::collections::{HashMap, VecDeque};

struct ObjState {
    decoder: Decoder,
    done: bool,
}

/// Reassembles RaptorQ symbols into objects, keeping multiple objects in flight
/// (keyed by `object_id`), tolerating loss and reordering, and evicting the
/// oldest object once `max_objects` is exceeded.
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
    pub fn push(&mut self, symbol: &Symbol) -> Option<Vec<u8>> {
        if !self.objects.contains_key(&symbol.object_id) {
            self.admit(symbol.object_id);
        }
        let state = self.objects.get_mut(&symbol.object_id)?;
        if state.done {
            return None; // late/duplicate symbol for an already-decoded object
        }
        let oti = raptorq::ObjectTransmissionInformation::with_defaults(
            u64::from(symbol.object_size),
            self.symbol_size,
        );
        // ensure the decoder is keyed to this object's OTI on first symbol
        // (decoder was created in `admit` without size; recreate if needed)
        let _ = oti; // OTI is set when the decoder is created in `admit_with`
        let mut wire = Vec::with_capacity(4 + symbol.data.len());
        wire.extend_from_slice(&symbol.payload_id);
        wire.extend_from_slice(&symbol.data);
        let packet = raptorq::EncodingPacket::deserialize(&wire);
        if let Some(object) = state.decoder.decode(packet) {
            state.done = true;
            return Some(object);
        }
        None
    }

    fn admit(&mut self, object_id: u16) {
        // We do not yet know object_size until the first symbol; create a
        // placeholder decoder lazily in `push` instead. To keep OTI correct,
        // store the decoder built from the first symbol's size.
        // (Implemented via admit_with below.)
        let _ = object_id;
        unreachable!("admit is replaced by admit_with in push");
    }
}
```

IMPORTANT implementation note for the engineer: the placeholder `admit`/OTI handling above is deliberately sketched — the decoder must be constructed with the object's OTI, which is only known from the first symbol's `object_size`. Implement it cleanly as follows instead of the sketch: in `push`, when the object is unknown, build the `Decoder` from `ObjectTransmissionInformation::with_defaults(u64::from(symbol.object_size), self.symbol_size)`, evict the oldest (`order.pop_front()` → `objects.remove`) if `objects.len() >= max_objects`, insert the new `ObjState { decoder, done: false }`, and push the id onto `order`. Then proceed to deserialize+decode. Remove the unused `admit`/`unreachable!` sketch. The two tests pin the required behavior (erasure+reorder decode; cap-1 eviction); make them pass with a clean implementation.

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yip-transport`
Expected: all pass. `cargo clippy -p yip-transport --all-targets -- -D warnings` clean (no `unreachable!`/dead code left).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/fec.rs
git commit -m "Add pipelined RaptorQ reassembler to yip-transport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `AdaptiveController` — repair ratio from measured loss

**Files:**
- Create: `crates/yip-transport/src/control.rs`
- Modify: `crates/yip-transport/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct AdaptiveController { ratio: f32, target_residual: f32, symbol_size: u16 }`
  - `impl AdaptiveController { pub fn new(params: FlowParams) -> Self; pub fn observe_loss(&mut self, loss_fraction: f32); pub fn repair_count(&self, source_symbols: u32) -> u32; pub fn ratio(&self) -> f32 }`

- [ ] **Step 1: Write the failing tests**

`crates/yip-transport/src/control.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    #[test]
    fn ratio_rises_under_loss_and_decays_when_clean() {
        let mut c = AdaptiveController::new(FlowClass::Default.params());
        let start = c.ratio();
        for _ in 0..10 { c.observe_loss(0.20); } // heavy loss
        assert!(c.ratio() > start, "repair ratio increases under loss");
        let high = c.ratio();
        for _ in 0..50 { c.observe_loss(0.0); } // clean link
        assert!(c.ratio() < high, "repair ratio decays toward minimum when clean");
    }

    #[test]
    fn repair_count_scales_with_source_symbols() {
        let c = AdaptiveController::new(FlowClass::Bulk.params());
        // at the initial 5% ratio, 100 source symbols -> at least a few repair
        assert!(c.repair_count(100) >= 1);
        assert!(c.repair_count(0) == 0 || c.repair_count(0) >= 1); // never panics on zero
    }
}
```

- [ ] **Step 2: Run them — expect failure**

Run: `cargo test -p yip-transport control`
Expected: FAIL.

- [ ] **Step 3: Implement the controller**

Add `pub mod control;` + `pub use control::AdaptiveController;` to `lib.rs`. In `control.rs`:

```rust
//! Adaptive redundancy controller: nudges a class's repair ratio toward the
//! level that keeps post-FEC residual loss under target, AIMD-style.

use crate::FlowParams;

/// Tracks and adjusts the proactive repair ratio for one flow class.
#[derive(Debug, Clone)]
pub struct AdaptiveController {
    ratio: f32,
    min_ratio: f32,
    target_residual: f32,
}

impl AdaptiveController {
    /// Start from a class's initial repair ratio.
    pub fn new(params: FlowParams) -> Self {
        Self {
            ratio: params.initial_repair_ratio,
            min_ratio: params.initial_repair_ratio,
            target_residual: 0.001, // aim for <0.1% post-FEC loss
        }
    }

    /// The current repair ratio (repair symbols per source symbol).
    pub fn ratio(&self) -> f32 {
        self.ratio
    }

    /// Update from an observed loss fraction (0.0..=1.0). Additive increase when
    /// loss exceeds what the current redundancy can mask; multiplicative decrease
    /// toward the class minimum when the link is clean.
    pub fn observe_loss(&mut self, loss_fraction: f32) {
        let loss = loss_fraction.clamp(0.0, 1.0);
        if loss > self.target_residual + self.ratio {
            // losing more than we can repair: add headroom above the loss rate
            self.ratio = (loss + 0.05).min(1.0);
        } else if loss <= self.target_residual {
            // clean: decay 10% toward the floor
            self.ratio = (self.ratio * 0.9).max(self.min_ratio);
        }
    }

    /// How many repair symbols to emit for an object with `source_symbols` source symbols.
    pub fn repair_count(&self, source_symbols: u32) -> u32 {
        let raw = (f64::from(source_symbols) * f64::from(self.ratio)).ceil();
        let n = u32::try_from(raw as i64).unwrap_or(u32::MAX); // ceil of non-negative; clamp
        n.max(1)
    }
}
```

Note: the single `raw as i64` is a float→int conversion with no `From`; `u32::try_from` of the `i64` provides the checked narrowing. If clippy's `cast` lints object, use `raw.clamp(1.0, f64::from(u32::MAX))` then `raw as u32` is still a cast — prefer: compute with integers where possible, or accept this one documented float→int conversion with a `// f64::ceil of a non-negative product; clamped` comment (FFI-free numeric conversion from float is the one place `as` is unavoidable; document it).

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yip-transport control`
Expected: PASS. clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-transport/src/control.rs crates/yip-transport/src/lib.rs
git commit -m "Add adaptive repair-ratio controller to yip-transport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `Transport` assembly + coverage + changelog

**Files:**
- Modify: `crates/yip-transport/src/lib.rs`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Replaces the M1 `Transport` trait with a concrete `Transport` struct tying the classifier, encoder, controller, and reassembler together:
  - `pub struct Transport { classifier: Classifier, encoder: FecEncoder, controllers: [AdaptiveController; 3], reassemblers: std::collections::HashMap<u16, FecReassembler> }`
  - `impl Transport { pub fn new(rules: Vec<PolicyRule>) -> Self; pub fn encode(&mut self, ciphertext: &[u8], inner: &[u8], l2: bool) -> (FlowClass, Vec<Symbol>); pub fn decode(&mut self, symbol: &Symbol, class: FlowClass) -> Option<Vec<u8>>; pub fn observe_loss(&mut self, class: FlowClass, loss: f32) }`

- [ ] **Step 1: Write the failing test (end-to-end within the crate)**

In `lib.rs` tests:

```rust
#[test]
fn transport_encodes_classifies_and_decodes_through_loss() {
    let mut tx = Transport::new(vec![]);
    let mut rx = Transport::new(vec![]);
    // a "sealed ciphertext" blob + the inner packet used only for classification
    let ciphertext: Vec<u8> = (0..4000u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let mut inner = vec![0u8; 64];
    inner[0] = 0x45;
    inner[1] = 46 << 2; // DSCP EF -> Realtime
    let (class, mut syms) = tx.encode(&ciphertext, &inner, false);
    assert_eq!(class, FlowClass::Realtime);
    // drop every 6th symbol; decode the rest
    let mut out = None;
    for (i, s) in syms.drain(..).enumerate() {
        if i % 6 == 0 { continue; }
        if let Some(frame) = rx.decode(&s, class) { out = Some(frame); break; }
    }
    assert_eq!(out.as_deref(), Some(ciphertext.as_slice()));
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-transport transport_encodes`
Expected: FAIL (concrete `Transport` not yet defined — the M1 stub is a trait).

- [ ] **Step 3: Implement `Transport`**

Remove the M1 `Transport` trait and its stub test. Add the concrete struct. `decode` routes a symbol to the per-class reassembler (keyed by a small class index), creating it lazily from the class's `symbol_size`. `encode` classifies, picks the class controller's repair count from the source-symbol estimate (`ceil(object_size / symbol_size)`), and encodes.

```rust
use std::collections::HashMap;

/// The FEC transport: classifies, encodes sealed frames into symbols, and
/// reassembles received symbols back into frames.
pub struct Transport {
    classifier: Classifier,
    encoder: FecEncoder,
    controllers: [AdaptiveController; 3],
    reassemblers: HashMap<u8, FecReassembler>,
}

fn class_index(c: FlowClass) -> usize {
    match c {
        FlowClass::Realtime => 0,
        FlowClass::Bulk => 1,
        FlowClass::Default => 2,
    }
}

impl Transport {
    /// Build a transport with the given classifier policy rules.
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self {
            classifier: Classifier::new(rules),
            encoder: FecEncoder::new(),
            controllers: [
                AdaptiveController::new(FlowClass::Realtime.params()),
                AdaptiveController::new(FlowClass::Bulk.params()),
                AdaptiveController::new(FlowClass::Default.params()),
            ],
            reassemblers: HashMap::new(),
        }
    }

    /// Classify `inner`, then FEC-encode the sealed `ciphertext` for that class.
    pub fn encode(&mut self, ciphertext: &[u8], inner: &[u8], l2: bool) -> (FlowClass, Vec<Symbol>) {
        let class = self.classifier.classify(inner, l2);
        let params = class.params();
        let source = u32::try_from(ciphertext.len().div_ceil(usize::from(params.symbol_size)))
            .unwrap_or(u32::MAX)
            .max(1);
        let repair = self.controllers[class_index(class)].repair_count(source);
        let syms = self.encoder.encode(ciphertext, params, repair);
        (class, syms)
    }

    /// Feed a received symbol for `class`; returns the frame when its object decodes.
    pub fn decode(&mut self, symbol: &Symbol, class: FlowClass) -> Option<Vec<u8>> {
        let params = class.params();
        let idx = u8::try_from(class_index(class)).expect("3 classes");
        self.reassemblers
            .entry(idx)
            .or_insert_with(|| FecReassembler::new(params.symbol_size, 256))
            .push(symbol)
    }

    /// Feed an observed loss fraction into `class`'s controller.
    pub fn observe_loss(&mut self, class: FlowClass, loss: f32) {
        self.controllers[class_index(class)].observe_loss(loss);
    }
}
```

- [ ] **Step 4: Run the test + coverage**

Run: `cargo test -p yip-transport`
Expected: all pass. Then `cargo llvm-cov --package yip-transport --fail-under-lines 90 --summary-only` — must exit 0. If under, add a focused test (e.g. an IPv6 classify path, or `decode` of a late/duplicate symbol returning None).

- [ ] **Step 5: Changelog + full gate**

Add under `## [Unreleased]` → `### Added` in `CHANGELOG.md`:

```markdown
- `yip-transport` adaptive RaptorQ FEC: per-flow classifier, object encoder,
  pipelined erasure-tolerant reassembler, and a repair-ratio controller.
```

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo shear && cargo deny check`
Expected: all clean. (`raptorq` is a real used dep.)

- [ ] **Step 6: Commit**

```bash
git add crates/yip-transport/src/lib.rs CHANGELOG.md
git commit -m "Assemble yip-transport FEC transport and record in changelog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (M5 slice):** per-flow classifier with precedence policy→DSCP→heuristic→default ✓ (T1); RaptorQ object encode with explicit OTI ✓ (T2); pipelined, erasure- and reorder-tolerant reassembly with eviction ✓ (T3); adaptive repair-ratio controller ✓ (T4); the four nyxpsi rules — explicit OTI (T2/T3), pipelined objects (T3), no UDP-Lite (N/A here, plain bytes), real measurement (controller takes a real loss fraction) ✓; assembled `Transport` + ≥90% coverage ✓ (T5). **Deferred-by-design (noted, not gaps):** the reactive ARQ NACK round-trip and the feedback-report wire packet need the daemon control channel → M6 (the controller's `observe_loss` and the reassembler's eviction are the hooks). Per-flow GSO/GRO coalescing and the `Symbol`↔`yip_wire::Frame` mapping (object_size onto the frame descriptor) are M6 integration. Bulk-class frame *coalescing* into larger objects is a later refinement (M5 encodes one frame per object).

**Placeholder scan:** Task 3 deliberately sketches `admit` then instructs the engineer to implement the decoder-from-first-symbol-OTI cleanly (the tests pin the contract) — this is explicit guidance, not a shipped placeholder; the `unreachable!` sketch must be removed. All other steps use the spiked-verified `raptorq` API. The one float→int `as` in the controller is called out with the required justification.

**Type consistency:** `FlowClass`/`FlowParams` (lib.rs), `Symbol{object_id:u16,object_size:u32,payload_id:[u8;4],data:Vec<u8>}`, `Classifier`/`PolicyRule` (classify.rs), `FecEncoder`/`FecReassembler` (fec.rs), `AdaptiveController` (control.rs) are used identically across tasks and re-exported from `lib.rs`. `class_index` maps the 3 classes consistently in Task 5.

**Definition of done for M5:** `cargo test --workspace` green; `yip-transport` ≥90% covered; a sealed frame survives classification → encode → symbol loss/reorder → reassembly back to the identical bytes; whole-workspace fmt/clippy/shear/deny green; CI passes on push.
