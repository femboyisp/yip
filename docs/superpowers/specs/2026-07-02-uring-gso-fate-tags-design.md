# io_uring GSO batching without breaking FEC — fate-tagged egress design

**Status:** implemented (signed off and landed; this file remains the design record)
**Scope:** issue #17, sub-project #1 (core data plane), `UringDriver` GSO egress path
**Predecessors:** issue #7 / `docs/superpowers/specs/2026-06-30-io-uring-busy-poll-design.md`
(introduced `UringDriver` + GSO), the follow-up hardening pass that pinned
`MAX_GSO_SEGMENTS_PER_SEND = 1` after `tc netem` testing showed GSO coalescing
silently defeats FEC recovery.

## Goal

Re-enable UDP GSO batching in `UringDriver` egress (`crates/yip-io/src/uring.rs`)
without reintroducing the correctness regression that got it pinned to
`MAX_GSO_SEGMENTS_PER_SEND = 1`. The fix must guarantee: **no single GSO
`SendMsg` (one `UDP_SEGMENT` super-skb) ever carries two datagrams that are
symbols of the same RaptorQ FEC object.**

## Background (verified in code)

- `MAX_GSO_SEGMENTS_PER_SEND: usize = 1` (`crates/yip-io/src/uring.rs`) — the
  only thing keeping `max_gso_datagrams_for_segment` from letting
  `queue_udp_batch` actually coalesce anything. Today this silently disables
  GSO: `can_coalesce_gso` still finds same-length runs, but `max_chunk` clamps
  to 1, so every "batch" is chunked back down to individual `queue_udp_send`
  calls.
- `handle_dispatch_tun` calls `d.on_tun(frame, now_ms)` once per TUN-read
  completion and passes the **entire returned batch** straight to
  `queue_udp_batch(pkts, allow_gso=true)`.
- `DataPlane::on_tun_packet` (`bin/yipd/src/dataplane.rs`) seals one inner
  packet, then calls `Transport::encode` (`crates/yip-transport/src/lib.rs`),
  which assigns **one `object_id`** (`FecEncoder::next_object_id`,
  `crates/yip-transport/src/fec.rs`) to **all** symbols — source and repair —
  produced for that call. `on_tun_packet` frames every symbol into
  `egress_scratch` and returns them together. So today's single `on_tun`
  batch = exactly one FEC object's full symbol set (its source symbol(s) + its
  own proactive-repair symbols), all the same wire length (RaptorQ pads every
  symbol, including the truncated tail, to a fixed `symbol_size`; the frame
  header/tag overhead is also fixed — so `can_coalesce_gso`'s equal-length
  check always passes within one object).
- Consequence: raising `MAX_GSO_SEGMENTS_PER_SEND` above 1 coalesces a source
  symbol and its own repair symbol(s) into the same skb. Under `tc netem` loss
  on veth, GSO segmentation is deferred to the receiving side, so a dropped skb
  is dropped **as a unit** — the object loses source and repair together, which
  is worse than losing either alone, and defeats FEC's whole purpose. This was
  empirically confirmed: `MAX_GSO_SEGMENTS_PER_SEND = 8` dropped
  `arq_recovers_bulk_loss` (5% loss, `MIN_DELIVERY_PCT=98`) delivery to ~95% —
  a hard FAIL — which is why the cap is pinned at 1.
- The driver cannot see this today because `Dispatch::on_tun`
  (`crates/yip-io/src/poll.rs`) returns opaque `&[Vec<u8>]` — no signal of
  which FEC object a datagram belongs to reaches `UringDriver`.
- `arq_recovers_bulk_loss` already runs in CI under **both** drivers
  (`.github/workflows/integration.yml`, `for mode in poll uring`), so this is
  the standing regression gate for the fix.

## Non-goals

- No wire-format change. `object_id` is already on the wire
  (`yip_wire::Frame::object_id`); this design only threads the *already-known*
  `Symbol.object_id` through the `Dispatch` trait boundary so the driver can
  see it before framing leaves the process. Nothing new is transmitted.
- No change to `yip-transport`'s public API. `Symbol.object_id` is already
  `pub`; this is purely a yip-io ⇄ yipd wiring change.
- GSO for the ARQ retransmit path (`DispatchOut::Udp`, `handle_dispatch_udp`,
  always called with `allow_gso=false`) is explicitly out of scope — see Risks.
- No change to `PollDriver`'s behavior (it never did GSO); only its
  `Dispatch::on_tun` call site needs a mechanical signature update.

## Success criteria

- `MAX_GSO_SEGMENTS_PER_SEND` restored to > 1 (proposed: 32) with GSO genuinely
  exercised (`gso_submission_count() > 0` in tests, and observable in bench
  throughput) — not silently defeated as it is today.
- `arq_recovers_bulk_loss` (5% `tc netem` loss) stays ≥ 98% delivery under
  `YIP_USE_URING=1`, matching the `poll` driver's existing pass.
- Structural invariant — *no coalesced skb contains two datagrams from the same
  FEC object* — is enforced at a single, directly unit-testable choke point,
  not merely "by construction" of an accumulator that could regress silently.
- `uring_gso_large_batch_chunks_payload_to_udp_limits`'s tautology (its expected
  value currently calls `UringDriver::max_gso_datagrams_for_segment`, the
  function under test) is fixed.

## Architecture

### 1. The transport → driver API change: a per-datagram fate tag

Add a small public type in `crates/yip-io/src/poll.rs`, next to `Dispatch`/
`DispatchOut` (the existing trait boundary):

```rust
/// One egress datagram plus the FEC "fate group" it belongs to.
///
/// GSO coalesces same-length UDP datagrams into one `UDP_SEGMENT` super-skb;
/// under loss the whole skb is dropped/delayed as a unit (segmentation is
/// deferred to the receiver). Two datagrams that are symbols of the same
/// RaptorQ object must never share a skb — losing them together can defeat
/// FEC recovery for that object. `fate` is the RaptorQ `Symbol::object_id`
/// (source symbols and this object's repair symbols share it; a different
/// object gets a different value). A GSO-capable driver must guarantee at
/// most one datagram per distinct `fate` in any single coalesced send.
#[derive(Debug, Clone)]
pub struct EgressDatagram {
    pub fate: u16,
    pub bytes: Vec<u8>,
}

impl AsRef<[u8]> for EgressDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
```

**Design decision: tag by `object_id` alone, not `object_id + is_repair`.** The
failure mode is "the object loses enough symbols that RaptorQ can't decode it" —
that's just as true for two *source* symbols of the same object sharing a skb as
for a source+repair pair. Object-granularity tagging is both necessary and
sufficient; a source/repair sub-tag would add complexity (the encoder path would
need to expose per-symbol role, which today it doesn't cheaply — the full-
`Encoder` path doesn't guarantee source-before-repair ordering in its output)
for zero additional safety margin.

**Why a struct wrapping `Vec<u8>` (not a parallel `&[u16]` slice or
`(u16, Vec<u8>)` tuple):** `Dispatch::on_tun` returns a borrow of a reused
scratch buffer (`DataPlane::egress_scratch`) — the existing pattern is
`Vec<Vec<u8>>`; a struct-of-two-fields Vec (`Vec<EgressDatagram>`) is a minimal,
ergonomic change to that same shape (`resize_with`/index/clear in place, no
separate buffer to keep in sync). A parallel `&[u16]` slice would require the
caller to zip two borrows with independent lifetimes for no benefit.
`#![forbid(unsafe_code)]` and no-`as`-casts are unaffected either way — nothing
here needs unsafe or numeric casts beyond what already exists.

**Trait change** (`crates/yip-io/src/poll.rs`):

```rust
pub trait Dispatch {
    fn on_udp(&mut self, dg: &[u8], now_ms: u64) -> DispatchOut<'_>;
    // was: fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[Vec<u8>];
    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram];
    fn tick(&mut self, now_ms: u64) -> Option<&[u8]>;
}
```

`DispatchOut::Udp`/`Both` (the `on_udp` return path, used for ARQ retransmits)
are **unchanged** — `allow_gso` is always `false` there today
(`handle_dispatch_udp`), so no tagging is needed on that path (see Risks for the
latent issue this leaves).

**`bin/yipd/src/dataplane.rs` changes** (the only place that constructs
`EgressDatagram`, since it already knows `sym.object_id` at encode time — no
`yip-transport` API change needed):

```rust
egress_scratch: Vec<EgressDatagram>,   // was Vec<Vec<u8>>

pub fn on_tun_packet(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram] {
    ...
    if self.egress_scratch.len() < n_syms {
        self.egress_scratch.resize_with(n_syms, || EgressDatagram { fate: 0, bytes: Vec::new() });
    }
    for (slot, sym) in self.egress_scratch[..n_syms].iter_mut().zip(symbols.iter()) {
        let frame = wire_glue::symbol_to_frame(self.conn_tag, sym, sealed.counter, class);
        let dg = self.codec.frame(&frame);
        slot.fate = sym.object_id;
        slot.bytes.clear();
        slot.bytes.push(PacketType::Data as u8);
        slot.bytes.extend_from_slice(&dg);
    }
    &self.egress_scratch[..n_syms]
}
```

`impl yip_io::poll::Dispatch for DataPlane`'s `on_tun` return type updates to
`&[yip_io::poll::EgressDatagram]` to match.

**`crates/yip-io/src/poll.rs` (`PollDriver`, `drain_tun`)** — mechanical:

```rust
let pkts_owned: Vec<EgressDatagram> = d.on_tun(inner, now_ms).to_vec();
for pkt in &pkts_owned {
    send_to_udp(udp_fd, &pkt.bytes)?;
}
```

No GSO in `PollDriver`; `.fate` is simply unused there.

### 2. The driver-side accumulator (`UringDriver`)

**Key insight:** within a single `on_tun` call, every returned datagram already
shares one `fate` (one `Transport::encode` call = one object) — so there is
nothing to coalesce *within* one dispatch call. Batching must happen **across**
multiple TUN-read completions handled inside the same `poll_once` (i.e., across
several different objects that happened to arrive in the same completion-queue
drain). This is exactly the bursty-egress case where GSO's syscall-amortization
matters most, and it requires zero added latency: at low load (one TUN frame per
`poll_once`), the accumulator has only one fate group buffered and naturally
falls back to per-datagram sends — today's degenerate (safe) behavior, unchanged.

**New `UringDriver` field:**

```rust
/// Egress datagrams staged this poll_once, tagged with their FEC fate group.
/// Flushed (and the invariant enforced) by `flush_pending_gso` before
/// `poll_once` returns, so no cross-call buffering/latency is added.
pending_gso: Vec<EgressDatagram>,
```

`MAX_PENDING_GSO_DATAGRAMS: usize = 512` (bounds worst-case memory/CPU for the
dedup pass below to the CQE-drain size, `RING_ENTRIES`) — `handle_dispatch_tun`
flushes early if this is exceeded mid-loop, in addition to the mandatory
end-of-`poll_once` flush.

**`handle_dispatch_tun`** stages instead of sending immediately:

```rust
fn handle_dispatch_tun(&mut self, d: &mut impl Dispatch, frame: &[u8], now_ms: u64) {
    let pkts = d.on_tun(frame, now_ms);
    self.pending_gso.extend_from_slice(pkts);
    if self.pending_gso.len() >= MAX_PENDING_GSO_DATAGRAMS {
        self.flush_pending_gso();
    }
}
```

**`poll_once`** calls `self.flush_pending_gso();` once, right after the per-CQE
`for` loop (same place sends used to happen inline), before the `tick` handling.
All TUN-egress sends for this `poll_once` still leave within the same call — no
cross-`poll_once` deferral, no new latency vs. today beyond microseconds of
intra-call reordering.

**`flush_pending_gso`** — greedy "at most one datagram per fate per pass":

```rust
fn flush_pending_gso(&mut self) {
    while !self.pending_gso.is_empty() {
        let mut chunk: Vec<EgressDatagram> = Vec::with_capacity(self.pending_gso.len());
        let mut deferred: Vec<EgressDatagram> = Vec::with_capacity(self.pending_gso.len());
        for dg in self.pending_gso.drain(..) {
            if chunk.iter().any(|c| c.fate == dg.fate) {
                deferred.push(dg);   // this fate already claimed this pass
            } else {
                chunk.push(dg);
            }
        }
        self.pending_gso = deferred;
        if let Err(e) = self.queue_udp_batch_tagged(&chunk, true) {
            eprintln!("uring: drop udp send batch from tun: {e}");
        }
    }
}
```

Each pass takes at most one symbol per object present in `pending_gso` (in
arrival order) — e.g. pass 1 = "first symbol of every currently-pending object"
(matches "skb A = one source per N objects"), pass 2 = "second symbol of each
remaining object" ("skb B = the matching repairs"), etc., until every buffered
symbol has been placed in some pass. Bounded by `MAX_PENDING_GSO_DATAGRAMS`, so
worst case is a deterministic, small `O(n²)` (≤ 512² ≈ 262k cheap `u16`
compares — sub-100µs, and only reached in the rare max-burst case; typical
bursts are far smaller). A `HashSet`-based `O(n)` version is a documented future
micro-opt if profiling ever shows this matters — not adopted now to keep the
correctness-critical path a small, obviously-correct pure loop.

**`queue_udp_batch_tagged`** — the enforcement choke point (defense in depth:
correctness does not depend on `flush_pending_gso`'s dedup pass being bug-free; a
duplicate fate reaching here safely degrades to non-GSO sends rather than
corrupting the invariant):

```rust
fn queue_udp_batch_tagged(&mut self, datagrams: &[EgressDatagram], allow_gso: bool) -> io::Result<()> {
    if datagrams.is_empty() {
        return Ok(());
    }
    if allow_gso && self.gso_enabled {
        if let Some(segment_size) = Self::can_coalesce_gso_tagged(datagrams) {
            let max_chunk = Self::max_gso_datagrams_for_segment(segment_size);
            for chunk in datagrams.chunks(max_chunk) {
                if self.queue_udp_gso(chunk, segment_size)? {
                    continue;
                }
                eprintln!("uring: GSO submit failed, trying per-datagram sends");
                for dg in chunk {
                    self.queue_udp_send(&dg.bytes)?;
                }
            }
            return Ok(());
        }
    }
    for dg in datagrams {
        self.queue_udp_send(&dg.bytes)?;
    }
    Ok(())
}

fn can_coalesce_gso_tagged(datagrams: &[EgressDatagram]) -> Option<u16> {
    if datagrams.len() < 2 {
        return None;
    }
    let first_len = datagrams.first()?.bytes.len();
    if first_len == 0 {
        return None;
    }
    let segment_size = u16::try_from(first_len).ok()?;
    for (i, dg) in datagrams.iter().enumerate() {
        if dg.bytes.len() != first_len {
            return None;
        }
        if datagrams[..i].iter().any(|prior| prior.fate == dg.fate) {
            return None; // duplicate fate anywhere in the candidate batch -> unsafe to coalesce
        }
    }
    Some(segment_size)
}
```

`can_coalesce_gso_tagged` mirrors `can_coalesce_gso` but adds the fate-uniqueness
check; it's a pure associated function (no `&self`), so it's directly
unit-testable without building a ring.

**`queue_udp_gso` becomes generic** so both the untagged (`queue_udp_batch`,
ARQ/on_udp path) and tagged (`queue_udp_batch_tagged`, TUN-egress path) callers
share one implementation with no extra clone:

```rust
fn queue_udp_gso<T: AsRef<[u8]>>(&mut self, datagrams: &[T], segment_size: u16) -> io::Result<bool> {
    ...
    for datagram in datagrams {
        coalesced.extend_from_slice(datagram.as_ref());
    }
    ...
}
```

`Vec<u8>: AsRef<[u8]>` already holds (existing call site unaffected);
`EgressDatagram: AsRef<[u8]>` is added above.

**`max_gso_datagrams_for_segment`, `queue_udp_send`,
`recover_gso_fallback_datagrams`, `recover_gso_unsent_datagrams`,
`is_gso_unsupported_errno` are all unchanged** — they operate on raw bytes only,
after the fate-safety decision has already been made.

**`MAX_GSO_SEGMENTS_PER_SEND`: 1 → 32.** It is no longer a correctness guard
(that's `can_coalesce_gso_tagged` now) — purely a throughput/blast-radius knob
bounding skb size and the amount of per-datagram retry work on a partial
`SendMsg` completion (`recover_gso_unsent_datagrams`). 32 is a starting point
pending the bench re-run called for in Rollout; combined with
`MAX_UDP_PAYLOAD / segment_len` (≈ 65507/1235 ≈ 53 for the current 1200-byte
symbol size + framing overhead) and `MAX_GSO_DATAGRAMS` (64), the effective cap
is `min(53, 32, 64) = 32`.

### 3. Simpler alternative considered: gate GSO on zero repair

Instead of fate tags, `Transport::encode`'s controller-derived repair count
could be surfaced per `on_tun` call as a single bool (`allow_gso_this_batch =
repair_count == 0`), threaded through the *existing* untagged `Vec<u8>` path with
no new type, no accumulator, no cross-call buffering — a much smaller diff.

**Why this is correct when it applies:** at `repair==0`, an object's decode has
zero slack — losing *any* one of its symbols already dooms the object regardless
of whether the loss was correlated (GSO) or independent (no GSO). Coalescing
source symbols of a zero-repair object doesn't change that object's
recoverability, so the correctness hazard this issue is about (source and repair
sharing fate) simply doesn't arise.

**Why it's rejected as the primary fix:** the adaptive controller raises `repair`
precisely when it observes loss — i.e., `repair > 0` is exactly the regime
`arq_recovers_bulk_loss` exercises (5% `tc netem` loss drives the controller up
from its `initial_repair_ratio`). A zero-repair gate would leave GSO **off** for
the whole lossy-link test and, more importantly, off for every real-world lossy
link — the case GSO's CPU/syscall savings matter most for, since redundancy
inflates per-packet count. It only pays off on already-clean links, which don't
need this issue's fix to begin with. Documented here per the design brief's
request to compare, not adopted.

## Component / file changes

- `crates/yip-io/src/poll.rs`
  - Add `EgressDatagram` (+ `impl AsRef<[u8]>`).
  - `Dispatch::on_tun` return type: `&[Vec<u8>]` -> `&[EgressDatagram]`.
  - `drain_tun`: iterate `.bytes`.
- `crates/yip-io/src/uring.rs`
  - `MAX_GSO_SEGMENTS_PER_SEND`: `1` -> `32` (+ updated rationale comment).
  - New field `pending_gso: Vec<EgressDatagram>` + `MAX_PENDING_GSO_DATAGRAMS` const.
  - `queue_udp_gso` generic-ized over `T: AsRef<[u8]>`.
  - New `can_coalesce_gso_tagged`, `queue_udp_batch_tagged`, `flush_pending_gso`.
  - `handle_dispatch_tun`: stage into `pending_gso` instead of sending immediately.
  - `poll_once`: call `flush_pending_gso()` after the CQE-processing loop.
  - Test module: update `EchoDispatch`/`TickCountDispatch`/`GsoLargeBatchDispatch`
    `on_tun` signatures; add/rewrite tests (see Testing below).
- `bin/yipd/src/dataplane.rs`
  - `egress_scratch: Vec<Vec<u8>>` -> `Vec<EgressDatagram>`.
  - `on_tun_packet` return type + fill logic (`fate: sym.object_id`).
  - `impl Dispatch for DataPlane`'s `on_tun` return type.
  - Unit tests that index egress datagrams -> index `.bytes`/`.fate`.
- No changes to `crates/yip-transport/` (`Symbol.object_id` already public) or
  `crates/yip-wire/` (no wire format change).

## Data flow

1. TUN frame arrives -> `Dispatch::on_tun` -> `DataPlane::on_tun_packet`: seal
   (AEAD) -> `Transport::encode` (classify + FEC-encode; all symbols from this
   call share one `object_id`) -> frame each symbol -> build
   `EgressDatagram { fate: symbol.object_id, bytes: framed }` into
   `egress_scratch` -> returned as `&[EgressDatagram]`.
2. `PollDriver::drain_tun`: sends each `.bytes` individually — unaffected by
   `fate`, no GSO, no behavior change.
3. `UringDriver::handle_dispatch_tun`: extends `pending_gso` with the returned
   slice (cloned, same as today's `.to_vec()`); flushes early if over
   `MAX_PENDING_GSO_DATAGRAMS`.
4. At the end of each `poll_once`'s CQE-drain pass, `flush_pending_gso`
   repeatedly extracts an at-most-one-per-fate chunk (arrival order) and hands it
   to `queue_udp_batch_tagged(chunk, allow_gso=true)`.
5. `queue_udp_batch_tagged` re-validates via `can_coalesce_gso_tagged` (equal
   length **and** all-distinct fate), MTU/cap-chunks via the existing
   `max_gso_datagrams_for_segment`, and issues `SendMsg` with the `UDP_SEGMENT`
   cmsg (`queue_udp_gso`) — or falls back to per-datagram `Send` on any
   rejection (mismatched length, duplicate fate caught defensively, submission
   failure, or GSO-unsupported kernel via the existing `gso_enabled` circuit
   breaker).
6. On the wire: **unchanged**. The kernel resegments the coalesced skb before
   delivery to the peer's socket; the receiver's reassembly path never observes
   GSO — this is a purely sender-local optimization.

## Testing / validation plan

**Unit tests, pure functions (no ring needed):**
- `can_coalesce_gso_tagged_rejects_duplicate_fate` — two equal-length datagrams,
  same `fate` -> `None`.
- `can_coalesce_gso_tagged_accepts_distinct_fates_same_length` — two equal-length
  datagrams, different `fate` -> `Some(segment_size)`.
- `can_coalesce_gso_tagged_rejects_mismatched_length` — mirrors the existing
  length-mismatch case for the tagged variant.

**`UringDriver` integration tests (loopback, existing `URING_SERIAL`-guarded style):**
- `uring_gso_same_object_datagrams_are_never_coalesced` (rewrite of
  `uring_gso_loopback_preserves_multi_datagram_payloads`): `GsoDispatch` returns
  5 datagrams from **one** `on_tun` call, all tagged with the same `fate`.
  Assert `gso_submission_count() == 0` (the accumulator can never form a ≥2 chunk
  from a single fate) **and** all 5 still round-trip via per-datagram sends. The
  direct regression test for the bug this issue is about.
- `uring_gso_distinct_objects_coalesce_across_tun_reads` (new; the required
  "N-object coalescing" test, replaces
  `uring_gso_large_batch_chunks_payload_to_udp_limits`'s premise, which is
  invalidated by the new invariant): a `Dispatch` double whose `on_tun` returns
  one datagram per call tagged with a **fresh, incrementing `fate`** each time,
  driven by writing several trigger frames to the TUN pipe before draining so
  multiple TUN-read completions land in the same `poll_once` CQE batch. Assert
  `gso_submission_count() > 1`, all datagrams round-trip, and — the
  de-tautologized check — an **independently computed** expected minimum using
  hardcoded literals for `MAX_UDP_PAYLOAD` (65 507) and the chosen
  `MAX_GSO_SEGMENTS_PER_SEND` (32) (`div_ceil`), with a comment noting these
  literals must be kept in sync with the module constants by hand — not by
  calling `max_gso_datagrams_for_segment`, the function under test.
- `uring_gso_submit_fallback_uses_per_datagram_send` — rewrite to use the same
  multi-object burst setup (today's version uses `GsoDispatch`'s single-object
  batch, which — post-fix — never attempts GSO at all).

**Regression gate (already CI-wired, run manually before merge and then in CI):**
- `arq_recovers_bulk_loss` under `YIP_USE_URING=1` — must stay ≥ 98% delivery
  (previously failed at ~95% with `MAX_GSO_SEGMENTS_PER_SEND=8` and no fate
  tagging) and confirm the "ARQ retransmits: N" (N>0) log line still appears.
- `ping_across_yipd_tunnel`, `ping_across_yipd_tunnel_under_loss`,
  `l2_tap_ping_or_arp_across_tunnel` under both `poll` and `uring` — no
  regression expected (already in the CI matrix).
- Recommended (not a hard gate): re-run the `yip-bench` clean-link throughput
  comparison to confirm GSO now shows a measurable throughput win over the
  `MAX_GSO_SEGMENTS_PER_SEND=1` baseline — the actual point of re-enabling it.

## Fallback & rollout

- **GSO-unsupported kernels:** unchanged. `gso_enabled` is still flipped off by
  `is_gso_unsupported_errno` on the first `UDP_SEGMENT`-rejecting completion,
  after which `queue_udp_batch_tagged`'s `allow_gso && self.gso_enabled` gate
  degrades every subsequent call to per-datagram sends for the life of the
  driver.
- **Feature flag:** `UringDriver` itself is already opt-in behind
  `YIP_USE_URING=1` (currently opt-in pending it beating `PollDriver`'s RTT).
  This fix lands directly behind that existing gate — no new flag is required
  for correctness, since the fate-tag invariant is enforced structurally and
  unit-tested. Optionally add a `YIP_URING_GSO_MAX` env override (mirroring the
  existing `YIP_URING_BUSYPOLL` pattern) as an ops escape hatch — nice-to-have.
- **Rollout sequence:** (1) land the `Dispatch` API change + `PollDriver`
  mechanical update (no behavior change, signature churn only); (2) land the
  `UringDriver` accumulator + `MAX_GSO_SEGMENTS_PER_SEND` bump behind the
  existing `YIP_USE_URING` gate; (3) run the full validation plan above,
  including the manual `arq_recovers_bulk_loss` + bench re-run; (4) if
  `UringDriver` later graduates from opt-in to default, this fix is a
  prerequisite — GSO was the main throughput lever `UringDriver` was supposed to
  bring.

## Open questions / risks

| Risk / question | Notes |
|---|---|
| ARQ retransmit path already mixes symbols from **multiple different missing objects** into one `DispatchOut::Udp` batch, harmless today only because `allow_gso=false` there. | Explicitly out of scope. If GSO is ever wanted for retransmits, the same `EgressDatagram`/fate-tag approach must be applied there too — flagging so it isn't silently forgotten. |
| `flush_pending_gso`'s `O(n²)` dedup-pass scan, bounded by `MAX_PENDING_GSO_DATAGRAMS = 512`. | Chosen for a small, obviously-correct pure loop over a stateful `HashSet`; revisit only if profiling shows it matters (typical bursts far smaller than 512). |
| `MAX_GSO_SEGMENTS_PER_SEND = 32` and `MAX_PENDING_GSO_DATAGRAMS = 512` are first-guess constants. | Need the bench re-run to tune; not blocking correctness. |
| Column-based (transpose) send ordering interleaves different objects' symbols on the wire, rather than each object's symbols going out back-to-back as today. | RaptorQ decode is symbol-driven, not order-sensitive, so expected to be a non-issue, but worth confirming no latency regression in the bench re-run. |
| `object_id: u16` wraparound — two *different* objects could theoretically share a wrapped `object_id` ~65 536 objects apart. | Not a practical risk: a GSO batch only spans datagrams staged within one `poll_once` (microseconds, far fewer than 65 536 objects), but flagging the assumption for reviewer sign-off. |
| Human sign-off requested on: the `flush_pending_gso` design (flat-list + greedy dedup passes) vs. a per-row transpose; the chosen constant values; and whether the optional `YIP_URING_GSO_MAX` escape hatch is wanted. | — |
