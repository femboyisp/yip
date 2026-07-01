# Adaptive loss-feedback loop + reactive ARQ — design

**Status:** approved (brainstorming, 2026-06-30)
**Scope:** sub-project #1 (core data plane), adaptive-control milestone
**Predecessors:** M1–M6 + M5.5, the benchmark harness (PR #1), and the throughput
pass (PR #2, `c492b5d`) which shipped a *dormant* zero-repair FEC bypass.

## Goal

Close the data-plane control loop so the receiver tells the sender what it
actually lost, and the sender adapts. This (a) **activates the throughput win**
the throughput pass set up — clean bulk flows drive the repair ratio to zero,
firing the merged FEC-encode bypass and halving per-packet datagram count — and
(b) adds **reactive ARQ** so the rare loss that escapes proactive FEC is
retransmitted for flows that can still use it.

## Success criteria

- On a clean link, a bulk/default flow's repair ratio reaches **zero** (verified:
  the FEC bypass fires, ~1 symbol/packet instead of ~2), and **clean-link
  throughput measurably rises** vs the post-throughput-pass baseline
  (~220–285 Mbit/s single-stream).
- Under `tc netem` loss, a bulk flow's **post-FEC residual loss stays low** and
  objects FEC cannot recover are **retransmitted and delivered** (ARQ works).
- A **realtime** flow keeps a small proactive repair floor (never zero) and is
  **never** retransmitted (deadline-aware) — its latency profile is unchanged.
- Forged feedback/NACK packets are **rejected** (control packets authenticated).
- All new state is **bounded** (retransmit buffer, pending-loss set, NACK list).
- All existing netns ping/tunnel tests stay green; the data-plane *symbol* wire
  frame is unchanged (only an additive new control packet type is introduced).

## Background — current state

- `yip_transport::AdaptiveController::observe_loss(loss)` exists and is sensible
  (AIMD: jumps ratio to `loss+0.05` on loss, decays 10%/observation when clean)
  but **the daemon never calls it** — so the ratio is static at
  `initial_repair_ratio`. `repair_count` floors at `max(1)` and `min_ratio =
  initial_repair_ratio`, so repair never reaches zero. Hence the throughput
  pass's zero-repair bypass is dormant.
- The wire symbol payload carries a monotonic per-object `counter` (one
  `Session::seal` per TUN packet → +1 per object, contiguous). The object's
  `FlowClass` rides in the authenticated `Frame.flags`.
- `PacketType` in `bin/yipd/src/handshake.rs`: `HandshakeInit=0`,
  `HandshakeResp=1`, `Data=2`. The 1-byte prefix is temporary anti-DPI debt
  (folds into keyed header-protection in sub-project #3); a new control type
  rides the same scheme.
- `Transport::decode` already keys reassembly per object and tolerates
  reorder/loss; `FlowParams` carries a per-class `deadline` (currently only
  partially honored).

## Design

### 1. Shared authenticated control packet (`PacketType::Control = 3`)

A single receiver→sender packet, **sealed with the session AEAD** (same channel
as data — a forged report otherwise lets an attacker force max redundancy or
strip FEC). It is the only new wire object. Payload (pre-seal):

- `delivered_count: u32` — objects delivered in the reporting window (for rate).
- `high_counter: u64` — highest object counter the receiver has observed.
- `missing: Vec<u64>` — object counters seen-as-gaps and declared lost
  (bounded, ≤ `MAX_NACK` per packet; if more are pending, send the oldest and
  set a `truncated` flag so the sender treats it as high-loss).

One packet feeds **both** consumers (controller tuning + ARQ); the receiver does
**no** per-class attribution (it cannot know the class of a fully-lost object).
Sent on a periodic heartbeat (`FEEDBACK_INTERVAL_MS`) **and** opportunistically
the moment new losses are detected.

Indicative constants (pinned in the plan, tuned against the bench): `FEEDBACK_
INTERVAL_MS ≈ 20–50`, `GRACE_MS ≈ 5` (≈2×RTT on the target paths), `MAX_NACK ≈
64` counters/packet, `realtime_floor ≈ 0.05`, retransmit buffer ≈ 1024 objects /
2 s TTL. These are starting points, not load-bearing invariants.

### 2. Receiver-side loss detection (gap-based)

Per direction the receiver keeps a bounded structure:

- `delivered`: advances as objects decode; tracks the contiguous-delivered
  watermark and a bounded set of counters seen-but-not-complete (with first-seen
  time).
- When object `C` decodes → mark delivered; drop from pending; advance watermark.
- A counter `C < high_counter` that has not completed within `GRACE_MS` (a few ms
  / ~2×RTT) is **declared lost**: added to `missing` and counted toward
  `delivered_count`'s denominator.
- Gap discovery: when symbols for counter `N` arrive and `N > high_counter+1`,
  the skipped counters `(high_counter, N)` are *candidates* — confirmed lost only
  after `GRACE_MS` without completion (handles reorder). With the zero-repair
  bypass a lost single-symbol object appears **only** as such a gap, so gap
  detection (not partial-object state) is the load-bearing signal.

The receiver clears a `missing` entry once it has been reported (tracking
reported counters to avoid re-NACKing), and re-reports only if still unfilled
after a retransmit window (bounded retries).

### 3. Sender-side attribution + class-aware controller

On receiving a (decrypted, authenticated) control packet, the sender — which
holds each sent object's class in its retransmit buffer (§4) — does **all**
attribution:

- For each `missing` counter, look up its `FlowClass` in the sent buffer and
  tally per-class residual loss. Per-class loss fraction =
  `class_missing / class_sent` over the window → `Transport::observe_loss(class,
  frac)` for each active class (zero for classes with no reported loss → decay).
- **Class-aware zero floor.** Relax the controller so the ratio can decay to
  **zero for `Bulk`/`Default`** (they have the ARQ backstop) but only to a small
  **`realtime_floor` (> 0) for `Realtime`** (no ARQ; needs latency-free masking).
  Concretely: make `min_ratio` class-derived (0 for bulk/default, a small floor
  for realtime) and drop `repair_count`'s unconditional `max(1)` — it returns 0
  only when the (class-aware) ratio is 0, else ≥1. `observe_loss` already snaps
  the ratio up to `loss+0.05` on any loss, so zero-repair is *earned* by clean
  feedback and *abandoned instantly* on loss. This is what fires the dormant
  bypass and halves clean bulk datagrams.

### 4. Reactive ARQ — deadline/class-aware retransmit

- **Sender retransmit buffer:** bounded (LRU + TTL), keyed by object `counter`,
  holding `{ sealed_ciphertext, class, sent_at }`. Populated as the egress loop
  sends each object.
- **On NACK (a `missing` counter):** retransmit **iff** the object is still
  buffered **and** its class is retransmit-eligible (`Bulk`/`Default`, not
  `Realtime`) **and** it is within its deadline (`sent_at + FlowParams.deadline >
  now`). Otherwise ignore the NACK. The realtime/deadline filtering lives here,
  on the sender (which knows the class), not on the receiver.
- **Retransmit mechanism:** generate **fresh RaptorQ repair symbols** for the
  buffered object (rateless — idiomatic; not a blind resend) and send them under
  the original `counter`. They top up the receiver's existing decoder for that
  object. If the receiver already evicted that object's decode state, the
  retransmit must carry enough symbols to complete from scratch (send source +
  repair on retransmit).
- **Receiver dedup:** a retransmit that arrives after the object already
  completed (counter ≤ watermark / already delivered) is dropped — the existing
  `decode` "late symbol returns None after completion" path already covers this;
  verify it holds for retransmitted symbols.

### 5. Security & anti-DPI

Control packets are sealed/authenticated exactly like data (a forged or replayed
report is rejected by the AEAD + replay window). Every new structure is bounded:
retransmit buffer (LRU+TTL), receiver pending-loss set, per-packet `missing` cap.
The new `Control=3` rides the existing temporary `PacketType` prefix; removing
that prefix (keyed header-protection) remains sub-project #3 and is unaffected.

### 6. Testing

- **Controller (unit):** decays to 0 for bulk/default under sustained clean
  feedback; decays only to the floor for realtime; snaps to `loss+0.05` on a loss
  report; `repair_count` returns 0 iff the class-aware ratio is 0.
- **Loss detector (unit):** from a scripted gappy counter stream (with reorder
  inside `GRACE_MS`), computes the correct `missing` set and `delivered_count`;
  reorder within grace is **not** falsely reported; bounded pending set.
- **Retransmit buffer (unit):** bounded LRU+TTL; lookup-by-counter; eviction.
- **ARQ round-trip (unit/integration):** a NACK for a buffered bulk object →
  fresh repair symbols → receiver completes; a NACK for a realtime object or an
  expired-deadline object → no retransmit; duplicate/late retransmit deduped.
- **End-to-end (netns + netem):** (a) clean link → bulk flow ratio reaches 0,
  bypass fires (assert ~1 symbol/packet), **clean-link iperf throughput rises**
  vs the throughput-pass baseline; (b) under 5–10% netem loss → bulk residual
  stays low, ARQ-recovered objects delivered, realtime flow keeps its floor and
  is not retransmitted. Wire-compat: existing `tunnel_netns` ping stays green.

## Components touched

- `crates/yip-transport`: `control.rs` (class-aware floor, `repair_count` 0-path);
  `lib.rs` (`observe_loss` plumbing, retransmit-symbol generation API); a new
  loss-detector module (receiver) and retransmit-buffer module (sender), or
  folded into existing files if small.
- `crates/yip-wire` or `bin/yipd`: the `Control` packet (de)serialization of
  `{ delivered_count, high_counter, missing[] }`.
- `bin/yipd/src/`: `handshake.rs` (`PacketType::Control = 3`); `tunnel.rs`
  (egress populates the retransmit buffer; ingress runs the loss detector + emits
  control packets; a control-packet handler that decrypts, attributes loss to
  `observe_loss`, and retransmits eligible NACKs); a periodic feedback timer.
- `crates/yip-bench`: an end-to-end test asserting clean-link ratio→0 + throughput
  rise, and ARQ recovery under loss.

## Wire compatibility

Additive: the data-plane *symbol* frame is unchanged; only a new `Control=3`
packet type is added. yip has no deployed third-party peers (pre-release, both
ends are this codebase), so the protocol extension is safe; a peer that did not
understand `Control` would simply drop it (graceful degradation of feedback/ARQ,
data still flows). The anti-DPI prefix story is unchanged (sub-project #3).

## Implementation sequencing

Though one cohesive system, the plan should build it in two ordered phases with a
working checkpoint between them: **(A) control channel + loss feedback +
class-aware zero-repair** — this alone activates the throughput win and is
independently testable; then **(B) reactive ARQ** on the same control packet
(retransmit buffer + NACK handling + dedup). The control packet is designed once
(carrying `missing[]` from the start) so phase B adds no wire change.

## Out of scope (deferred)

- The unified io_uring busy-poll rewrite (separate; throughput-pass deferred it).
- Removing the `PacketType` prefix / keyed header-protection (sub-project #3).
- Full deadline-based FEC *eviction* beyond what ARQ eligibility needs.
- Multipath / FEC across objects / congestion control.
- L2/TAP path; rekey; PQ handshake.

## Risks

- **Re-arm window exposure.** A bulk flow at zero repair loses the ~1 RTT of
  packets sent before feedback re-arms FEC. Mitigated by ARQ (those losses are
  retransmitted) and the instant `loss+0.05` snap-up. Realtime never goes to zero,
  so it is never exposed.
- **Gap mis-detection under reorder.** Mitigated by the `GRACE_MS` confirmation
  window before declaring a counter lost.
- **Retransmit storms / amplification.** Bounded `missing` per packet, bounded
  retransmit buffer, bounded re-NACK retries; a NACK for an evicted/expired object
  is ignored.
- **Forged reports.** Mitigated by sealing control packets (AEAD + replay window).
- **Counter attribution after buffer eviction.** A `missing` counter no longer in
  the sender's buffer is treated as loss-for-stats but not retransmitted (it is
  too old to matter) — bounded behavior, no error.
