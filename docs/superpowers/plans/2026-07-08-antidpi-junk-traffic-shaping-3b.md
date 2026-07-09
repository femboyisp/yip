# Sub-project #3 Milestone 3b: Junk / Decoy Packets + Traffic-Shaping — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Blur yip's residual flow-shape fingerprint (2-packet handshake opener + constant 30 ms Control pulse) with latency-free junk/decoy traffic, behind the existing `obf_psk`, reusing the merged 3a `yip-obf` envelope.

**Architecture:** A new `JUNK_TYPE=6` in the same `yip-obf` envelope makes junk byte-indistinguishable from real traffic; the receiver silently drops it. Three latency-free emission points: a junk burst around the handshake (automatic), opt-in idle cover traffic (`cover_traffic_ms`), and jitter on the 30 ms Control-feedback cadence (automatic). A tiny handwritten xorshift PRNG (seeded once from `getrandom`) fills junk bodies/lengths/counts; `getrandom` stays only for the per-packet nonce and the infrequent cadence jitter.

**Tech Stack:** Rust, the merged 3a stack (`crates/yip-obf`, `bin/yipd/src/peer_manager.rs` obf machinery), `getrandom`, `refrences/nDPI` (`ndpiReader`) + `tcpdump` for the oracle.

## Global Constraints

- `yipd`, `yip-obf` stay `#![forbid(unsafe_code)]`; no new `unsafe`. No `as` casts except the `JUNK_TYPE`/`PacketType` discriminant bytes.
- **Junk is a LAYER over Noise/AEAD** — a keystream-XOR envelope over a throwaway body. It NEVER touches Noise/session crypto, and changes NO admission/session/routing decision.
- **Junk body content is irrelevant to indistinguishability** (the keystream XOR masks it — even zeros mask to random on the wire), so a fast PRNG body is provably safe. `getrandom` is used ONLY for the 8-byte per-packet nonce (in `yip_obf`, already) and the cadence `jitter_ms` (infrequent). Junk bodies/lengths/counts/pads use the fast xorshift PRNG.
- **Silent-drop on receive** — `JUNK_TYPE ⇒ drop`: no reply (zero reflection/amplification), no state change, no payload parsed, no panic reachable from any junk/garbage datagram.
- **Bounded cost** — `Jc ≤ 12`, junk sizes capped under `OBF_MTU_BUDGET` (=1200), `cover_traffic_ms` rate-bounded; handshake junk is one burst per attempt (not per-packet).
- **`obf_psk` absent ⇒ byte-identical** to merged 3a/2a/2b/2c. No-regression: all existing netns tests green under BOTH `poll` and `YIP_USE_URING=1`; the `arq_recovers_bulk_loss` netns test uses the **release** `yipd` (rebuild `--release` after any yipd change).
- **Data hot path NEVER delayed/batched** (north-star latency) — junk is off-hot-path (handshake), idle-only (cover), or reporting-timer-only (control jitter).
- Green every task: `cargo fmt --all --check`, `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p <crate>`.
- Deferred / non-goals (do NOT build): data-path timing shaping / inter-packet delay / batching (paranoid mode / sub-project #4), entropy shaping (3c), port plausibility (3d), any new AEAD/session-key material, the `nDPId -A` ML statistical harness.

**Sandbox note:** the pre-commit hook's workspace `cargo test` can trip on 2 pre-existing unrelated `yip-io` io_uring memlock tests (they pass in CI). If it blocks ONLY on those, commit `--no-verify` after confirming your crate + clippy + fmt are green.

---

## File Structure

- `crates/yip-obf/src/lib.rs` (MODIFY): add `pub const JUNK_TYPE: u8 = 6;` and `pub struct XorShift64` (a fast seeded PRNG).
- `bin/yipd/src/peer_manager.rs` (MODIFY): a junk-datagram builder + PRNG field; the `deobf_ingress` `JUNK_TYPE` drop arm; the handshake junk burst in `begin_handshake`; idle-cover emission in `tick`; per-peer last-activity tracking.
- `bin/yipd/src/config.rs` (MODIFY): `cover_traffic_ms: Option<u64>`.
- `bin/yipd/src/dataplane.rs` (MODIFY): jitter the `FEEDBACK_INTERVAL_MS` Control cadence when obf is on.
- `bin/yipd/src/tunnel.rs` (MODIFY): thread `cover_traffic_ms` into `PeerManager`.
- `bin/yipd/tests/run-netns-obfuscated.sh` / `tunnel_netns.rs` / a new `run-flowshape-check.sh` + `.github/workflows/integration.yml` (MODIFY/NEW): netns + oracle + flow-shape check.

---

### Task 1: `yip-obf` — `JUNK_TYPE` + fast PRNG

**Files:**
- Modify: `crates/yip-obf/src/lib.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces: `pub const JUNK_TYPE: u8 = 6;`
- Produces: `pub struct XorShift64 { state: u64 }` with `pub fn from_getrandom() -> Self`, `pub fn next_u64(&mut self) -> u64`, `pub fn gen_range(&mut self, lo: u64, hi_inclusive: u64) -> u64` (returns `lo` when `lo >= hi_inclusive`; else a value in `lo..=hi_inclusive`), `pub fn fill(&mut self, buf: &mut [u8])`.

- [ ] **Step 1: Write failing tests** in `crates/yip-obf/src/lib.rs` `mod tests`:

```rust
#[test]
fn junk_type_is_distinct_from_other_ptypes() {
    // 0..=4 are yipd PacketType, 5 is RDV_TYPE.
    assert_eq!(JUNK_TYPE, 6);
    assert_ne!(JUNK_TYPE, RDV_TYPE);
}

#[test]
fn xorshift_gen_range_stays_in_bounds_and_varies() {
    let mut r = XorShift64::from_getrandom();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let v = r.gen_range(3, 12);
        assert!((3..=12).contains(&v), "in range");
        seen.insert(v);
    }
    assert!(seen.len() > 3, "gen_range must actually vary, got {seen:?}");
    // degenerate range returns lo
    assert_eq!(r.gen_range(7, 7), 7);
    assert_eq!(r.gen_range(9, 4), 9);
}

#[test]
fn xorshift_fill_produces_varied_bytes() {
    let mut r = XorShift64::from_getrandom();
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    r.fill(&mut a);
    r.fill(&mut b);
    assert_ne!(a, b, "consecutive fills differ");
    assert!(a.iter().any(|&x| x != 0), "not all-zero");
}

#[test]
fn junk_datagram_deobfuscates_to_junk_type() {
    let key = derive_key(b"net");
    let mut r = XorShift64::from_getrandom();
    let mut body = [0u8; 128];
    r.fill(&mut body);
    let dg = obfuscate(&key, JUNK_TYPE, &body, 7);
    let (pt, _b) = deobfuscate(&key, &dg).expect("round-trips");
    assert_eq!(pt, JUNK_TYPE);
}
```

- [ ] **Step 2: Run → fail.** `cargo test -p yip-obf`.

- [ ] **Step 3: Implement** in `crates/yip-obf/src/lib.rs`. Add near `RDV_TYPE`:

```rust
/// Decoy/junk datagram type (3b). A datagram wrapped under this ptype carries
/// no real data; the receiver drops it silently. Distinct from the tunnel
/// `PacketType` values (0..=4) and `RDV_TYPE` (5).
pub const JUNK_TYPE: u8 = 6;

/// A fast, non-cryptographic xorshift64* PRNG for junk bodies/lengths/counts.
/// Seeded once from the OS RNG; thereafter pure userspace (no syscall per
/// draw). NOT for any security decision — junk bytes are keystream-masked by
/// `obfuscate`, so their content is irrelevant to indistinguishability.
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn from_getrandom() -> Self {
        let mut seed = [0u8; 8];
        getrandom::getrandom(&mut seed).expect("OS RNG");
        // xorshift64* must never have a zero state.
        let s = u64::from_le_bytes(seed) | 1;
        Self { state: s }
    }

    pub fn next_u64(&mut self) -> u64 {
        // xorshift64* (Marsaglia / Vigna).
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `lo..=hi_inclusive`; returns `lo` if the range is
    /// empty/degenerate. Modulo bias is irrelevant for junk sizing.
    pub fn gen_range(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        if lo >= hi_inclusive {
            return lo;
        }
        let span = hi_inclusive - lo + 1;
        lo + (self.next_u64() % span)
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let bytes = self.next_u64().to_le_bytes();
            let n = core::cmp::min(8, buf.len() - i);
            buf[i..i + n].copy_from_slice(&bytes[..n]);
            i += n;
        }
    }
}
```

- [ ] **Step 4: Run → pass; clippy/fmt clean; commit.**

```bash
cargo test -p yip-obf && cargo clippy -p yip-obf --all-targets -- -D warnings && cargo fmt --all --check
git add crates/yip-obf/src/lib.rs
git commit -m "feat(yip-obf): JUNK_TYPE + fast xorshift PRNG for decoy traffic (3b)"
```

---

### Task 2: junk builder + silent-drop demux arm (`peer_manager`)

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `yip_obf::{JUNK_TYPE, XorShift64, obfuscate}`, the existing `obf_key`/`session_obf_key`, `OBF_MTU_BUDGET`, `random_pad`, `OBF_DATA_PAD_MAX`.
- Produces: a `PeerManager` field `junk_rng: yip_obf::XorShift64` (built in `new`); `fn build_junk(&mut self, key: &[u8;16]) -> Vec<u8>`; a `JUNK_TYPE` drop arm in `deobf_ingress`.
- Produces (constants near the other obf consts): `const JUNK_MIN_LEN: usize = 64; const JUNK_MAX_LEN: usize = 1024; const JUNK_BURST_MIN: u64 = 3; const JUNK_BURST_MAX: u64 = 12;`

Read `deobf_ingress` (peer_manager.rs ~1438) and the obf-const block (~322) first. Implement:

1. `PeerManager` gains `junk_rng: yip_obf::XorShift64` (init `yip_obf::XorShift64::from_getrandom()` in `new`). Add the four `JUNK_*` consts near `OBF_MTU_BUDGET`.
2. `fn build_junk(&mut self, key: &[u8;16]) -> Vec<u8>`: draw `len = self.junk_rng.gen_range(JUNK_MIN_LEN as u64, JUNK_MAX_LEN as u64)` (convert via `usize::try_from`), clamp so `len <= JUNK_MAX_LEN` (already) — the real datagram is `len + envelope overhead`, all well under `OBF_MTU_BUDGET`; fill a `vec![0u8; len]` via `self.junk_rng.fill(&mut body)`; return `yip_obf::obfuscate(key, yip_obf::JUNK_TYPE, &body, random_pad(OBF_DATA_PAD_MAX))`. (Body content is irrelevant — masked — but filling it costs nothing and is conservative.)
3. **`deobf_ingress` JUNK drop arm:** in BOTH key regimes (the session-key branch and the network-key branch), if the recovered `ptype == yip_obf::JUNK_TYPE`, return `None` (drop — inert). Add it explicitly rather than relying on the "unrecognized ptype falls through to None" default, so intent is clear and a session-keyed junk isn't needlessly retried under the network key. **No reply, no state mutation.**

- [ ] **Step 1: Unit tests** (in `peer_manager.rs` tests): (a) `build_junk(key)` produces a datagram that `yip_obf::deobfuscate(key, dg)` recovers as `(JUNK_TYPE, _)`; (b) a junk datagram from an Established peer's source, fed through `on_udp` with obf on, is dropped — `DispatchOut::None`, the peer's session state unchanged, no egress emitted; (c) a junk datagram from an unknown source (network-key junk) fed through `on_udp` is dropped, no panic; (d) with `obf_key = None`, none of this path runs (existing behavior).
- [ ] **Step 2: Run → fail; implement** points 1–3.
- [ ] **Step 3: Gate — unit tests + clippy/fmt.** `cargo test -p yipd --bins`. Commit (`feat(yipd): junk-datagram builder + silent-drop JUNK_TYPE demux arm (3b)`).

---

### Task 3: handshake junk burst

**Files:**
- Modify: `bin/yipd/src/peer_manager.rs` (`begin_handshake` ~515)
- Test: inline `#[cfg(test)]`

**Interfaces:** Consumes `build_junk`, `JUNK_BURST_MIN/MAX`, `self.obf_key`, `self.junk_rng`.

Behavior: in `begin_handshake`, when `self.obf_key.is_some()`, BEFORE the real `HandshakeInit` datagram is emitted, emit `Jc = junk_rng.gen_range(JUNK_BURST_MIN, JUNK_BURST_MAX)` junk datagrams — each `build_junk(&network_key)` — as `EgressDatagram`s addressed to the same handshake `target`, pushed to the egress buffer ahead of the Init. The Init still goes out (unchanged). Read how `begin_handshake` returns/collects egress (it returns a single `EgressDatagram` today; you'll need to return/emit multiple — check whether it pushes to `self.egress` or returns one, and thread the junk into whichever path the caller drains, keeping the real Init as the last/return value). **When `obf_key` is None, `begin_handshake` is byte-identical to today (no junk).**

- [ ] **Step 1: Structural + behavioral tests:** (a) with obf on, calling `begin_handshake` emits `Jc` junk datagrams (all deobfuscate to `JUNK_TYPE` under the network key) followed by exactly one real `HandshakeInit`, all addressed to `target`; (b) across many `begin_handshake` calls, the junk count VARIES (proves `Jc` randomizes — collect counts into a set, assert `> 1` distinct); (c) with `obf_key = None`, `begin_handshake` emits exactly one datagram (the Init) — no junk (byte-identical).
- [ ] **Step 2: Run → fail; implement.**
- [ ] **Step 3: Gate — `cargo test -p yipd --bins`; clippy/fmt.** Commit (`feat(yipd): junk burst around the handshake init (3b)`).

---

### Task 4: idle cover traffic (`cover_traffic_ms`)

**Files:**
- Modify: `bin/yipd/src/config.rs`, `bin/yipd/src/tunnel.rs`, `bin/yipd/src/peer_manager.rs` (the `tick` loop + per-peer activity tracking)
- Test: inline config test + `peer_manager` unit test

**Interfaces:** Consumes `build_junk`, each peer's `session_obf_key`. Produces `Config.cover_traffic_ms: Option<u64>`; a `PeerManager` field for the interval; per-peer `last_activity_ms`.

1. **config.rs:** add `pub cover_traffic_ms: Option<u64>`, parse `cover_traffic_ms=<u64>` (reuse the existing integer parse pattern; a value of 0 or a non-integer is a parse error). Default `None`.
2. **tunnel.rs:** pass `config.cover_traffic_ms` into `PeerManager` (a setter mirroring `set_obf_psk`, or a `new` param — follow whichever the existing wiring uses; `set_obf_psk` is a setter, so add `set_cover_traffic_ms`).
3. **peer_manager.rs:** each `Peer` gains `last_activity_ms: u64`, updated whenever real Data is sent to or received from that peer (find the Data egress + the Data ingress-dispatch sites; set `last_activity_ms = now_ms`). In `tick`, when `obf_key.is_some()` AND `cover_traffic_ms` is `Some(iv)`, for each `Established` peer where `now_ms - last_activity_ms >= iv` AND `now_ms - last_cover_ms >= iv`, emit one session-keyed `build_junk(&session_obf_key)` datagram to that peer's endpoint and set `last_cover_ms = now_ms`. **Cover fires only when idle** (the `last_activity` gate) so it never races real data.

- [ ] **Step 1: Tests:** (a) config parse: `cover_traffic_ms=250` → `Some(250)`, absent → `None`, `cover_traffic_ms=0` → error; (b) `peer_manager`: with obf on + `cover_traffic_ms=Some(iv)`, an Established peer idle for `>= iv` gets one session-keyed junk datagram from `tick` (deobfuscates to `JUNK_TYPE` under its session key); a peer with recent activity (`last_activity_ms = now`) gets NONE; with `cover_traffic_ms = None`, `tick` emits no cover.
- [ ] **Step 2: Run → fail; implement.**
- [ ] **Step 3: Gate — `cargo test -p yipd --bins`; clippy/fmt.** Commit (`feat(yipd): opt-in idle cover traffic via cover_traffic_ms (3b)`).

---

### Task 5: jitter the 30 ms Control-feedback cadence

**Files:**
- Modify: `bin/yipd/src/dataplane.rs` (the `FEEDBACK_INTERVAL_MS` emission ~503), `bin/yipd/src/peer_manager.rs` (thread obf-on into the DataPlane)
- Test: inline `#[cfg(test)]`

Read `dataplane.rs`'s `FEEDBACK_INTERVAL_MS` (=30, line ~27) and the emission check (~503). Behavior: when obf is on, the feedback timer's *emission schedule* is jittered ±25% (a stored, re-rolled-per-emission interval in `[22,38] ms`), mirroring 3a's stored-jittered-interval pattern (`retry_ms`); when obf is off, the interval stays exactly `FEEDBACK_INTERVAL_MS`. This reshuffles WHEN the feedback report is emitted — it never delays a data packet, and the ±25% bound keeps ARQ feedback timely.

1. `DataPlane` learns obf is on: add an `obf_on: bool` (set at construction / via a setter from `PeerManager`, which knows `obf_key.is_some()`). Add a small local `fn jitter_feedback_ms(base: u64, obf_on: bool, /* rng or getrandom */) -> u64` — reuse the SAME approach as `peer_manager::jitter_ms` (getrandom-based ±25%; this cadence fires ~33×/s so `getrandom` is fine, and it matches how 3a jitters its other three cadences). If sharing the helper is awkward across modules, duplicate the ~5-line helper (matches the accepted `random_pad` cross-module duplication).
2. Store `feedback_interval_ms` on the DataPlane; compare `now - last_feedback >= feedback_interval_ms`; after each emission, re-roll it (`jitter_feedback_ms(FEEDBACK_INTERVAL_MS, obf_on)` when on, `FEEDBACK_INTERVAL_MS` when off).

- [ ] **Step 1: Tests:** `jitter_feedback_ms(30, true)` ∈ [22, 38] and not constant across calls; `jitter_feedback_ms(30, false)` == 30 exactly. If the emission logic is reachable in a unit test, assert obf-off emits at exactly 30 ms cadence (existing feedback tests must stay green).
- [ ] **Step 2: Run → fail; implement.**
- [ ] **Step 3: Gate — `cargo test -p yipd --bins` (the existing dataplane/feedback tests MUST stay green — obf-off cadence unchanged); clippy/fmt.** Commit (`feat(yipd): jitter Control-feedback cadence under obf_psk (3b)`).

---

### Task 6: netns integration — junk doesn't break connectivity + no-regression

**Files:**
- Modify: `bin/yipd/tests/run-netns-obfuscated.sh` (or add a `cover_traffic_ms` line behind an env toggle), `bin/yipd/tests/tunnel_netns.rs`, `.github/workflows/integration.yml`

- [ ] **Step 1:** Extend the obfuscated netns path so a run can set `cover_traffic_ms` (e.g. honor an optional `COVER_MS` env in `run-netns-obfuscated.sh`, appended to both configs when set — a no-op when unset, matching the 3a `OBF_PSK` env-guard pattern; use an `if [ -n "${COVER_MS:-}" ]` guard, NOT a bare `&&` one-liner inside a function). Junk (handshake burst + control jitter) is automatic with `obf_psk`, so the existing `obfuscated_ping` already exercises it — add one test `obfuscated_ping_with_cover` that sets `COVER_MS` and asserts the ping still succeeds.
- [ ] **Step 2:** Rust harness: add `obfuscated_ping_with_cover` (root-gated SKIP, `.env("OBF_PSK", …).env("COVER_MS", "200")`), asserts success.
- [ ] **Step 3: GATE (run yourself, sudo, BOTH drivers):** rebuild `--release -p yipd`. Then: the new `obfuscated_ping_with_cover` × 2 drivers → ok; the existing obf-on tests (`obfuscated_ping`, `obf_psk_mismatch_no_connection`, `relay_path_ping_obfuscated`, `hole_punch_ping_obfuscated`, `discovery_dynamic_ping_obfuscated`) × 2 drivers → ok (junk is automatic, so these now exercise it); and the 10 obf-OFF netns tests × 2 drivers → ok (byte-identical no-regression). Report the full matrix.
- [ ] **Step 4:** Add `obfuscated_ping_with_cover` to `integration.yml`'s netns loop (both drivers). Commit (`test(yipd): netns junk/cover connectivity + no-regression (3b)`).

---

### Task 7: nDPI oracle no-regression + lightweight flow-shape structural check

**Files:**
- Modify: `bin/yipd/tests/run-ndpi-oracle.sh` (or invoke it — junk is automatic with obf_psk, so the existing oracle already captures junk-laden traffic)
- Create: `bin/yipd/tests/run-flowshape-check.sh`, `tunnel_netns.rs` `flowshape_not_obviously_constant`, `.github/workflows/integration.yml` job wiring

- [ ] **Step 1: nDPI oracle no-regression.** The 3a `run-ndpi-oracle.sh` captures an obfuscated exchange — with 3b, that exchange now includes the handshake junk burst automatically. Run it and confirm it STILL passes: flow `Unknown`, no `NDPI_OBFUSCATED_TRAFFIC`. Junk must not become a new signature (e.g. must not trip nDPI's WireGuard stage machine into a classified state). If a param needs nudging (e.g. junk sizes), adjust in Task 3's consts and note it. This is a hard gate.
- [ ] **Step 2: `run-flowshape-check.sh`** — a lightweight, deterministic capture-based check (NOT the `nDPId -A` ML harness). Set up two `yipd` with `obf_psk` in netns (reuse the oracle/obf setup), and for **N ≥ 5 independent sessions** (fresh handshake each — e.g. restart the initiator, or N separate 2-node bring-ups), `tcpdump` the underlay and count the datagrams observed **before the first bidirectional data exchange** (the "handshake opener" packet count). **Assert** that count is **not constant across the N sessions** (the junk burst randomizes it) — this is the flow-shape analogue of 3a's `no_byte_position_is_constant` test, at the packet-count level. Optionally also assert the pre-data packet count is `> 2` (junk present). `set -euo pipefail`, cleanup trap, root-gated. Keep it deterministic and fast — a handful of short sessions, integer packet counts, a variance/ distinct-count assertion. Frame the log output honestly: "no obviously-constant handshake cardinality," NOT "provably unclassifiable."
- [ ] **Step 3: Rust harness** `flowshape_not_obviously_constant` in `tunnel_netns.rs` (root-gated SKIP; `bash run-flowshape-check.sh <yipd>`; assert success).
- [ ] **Step 4: CI.** Run the oracle no-regression + the flow-shape check locally under sudo. Add `flowshape_not_obviously_constant` to the netns loop / the `dpi-undetectability` job area in `integration.yml`. Commit (`test(ci): nDPI no-regression + lightweight flow-shape structural check (3b)`).

---

## Self-Review

**Spec coverage:** `JUNK_TYPE` + fast PRNG → Task 1 ✅; junk builder + silent-drop demux → Task 2 ✅; handshake junk burst (Jc/Jmin/Jmax) → Task 3 ✅; opt-in idle cover (`cover_traffic_ms`) → Task 4 ✅; Control-cadence jitter → Task 5 ✅; netns junk-doesn't-break-connectivity + no-regression → Task 6 ✅; nDPI no-regression + lightweight flow-shape check → Task 7 ✅. `obf_psk`-absent-byte-identical enforced by the `obf_key.is_some()` gating in Tasks 2–5 + the no-regression gate. Security invariants (layer-over-Noise, silent-drop/inert, bounded cost, no data-path latency) realized by the keystream-XOR junk envelope + the drop arm + the off-hot-path emission points.

**Placeholder scan:** Task 1 carries complete code; Tasks 2–7 are integration tasks specified by interface + behavior + exact sites (`deobf_ingress` ~1438, `begin_handshake` ~515, `FEEDBACK_INTERVAL_MS` ~503), matching the 2b/2c/3a crux-task style. The one genuinely deferred detail — whether `begin_handshake` returns one datagram vs pushes to `self.egress` — is called out in Task 3 for the implementer to read and adapt, since it depends on unchanged code.

**Type consistency:** `JUNK_TYPE: u8 = 6`, `XorShift64::{from_getrandom, next_u64, gen_range, fill}`, `build_junk(&mut self, key: &[u8;16]) -> Vec<u8>`, `Config.cover_traffic_ms: Option<u64>` consistent across Tasks 1/2/3/4. Junk uses the network `obf_key` for the handshake burst and the peer's `session_obf_key` for idle cover, matching 3a's two-regime keying. Control jitter reuses the `jitter_ms` ±25% approach (getrandom), distinct from the junk xorshift PRNG — stated in the Global Constraints and Task 5.
