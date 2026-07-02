# Issues #7–#11 orchestration — design

**Status:** approved (brainstorming, 2026-07-01)
**Scope:** program-level execution plan for GitHub issues #7–#11 using batched
subagents; not a feature spec for any single milestone.
**Predecessors:** io_uring Phase A merged (#6); sub-project #1 data plane complete.

## Goal

Land the remaining sub-project #1 milestones and follow-ups in dependency order,
using parallel subagents where work is independent, without merge conflicts or
regressions on the netns gate.

## Issues covered

| Issue | Title | Wave | Agent model |
|-------|-------|------|-------------|
| #7 | io_uring Phase B: `UringDriver` | 1 | Single agent, sequential (plan tasks 5–8) |
| #11a | Test/coverage polish | Optional | Not gate-blocking (see coverage note); may run parallel to #7 |
| #8 | L2 (TAP) + MAC learning | 2 | Brainstorm → spec → plan, then impl |
| #9 | Session rekey + PQ-hybrid | 2 | Brainstorm → spec; classical rekey first |
| #11b | Correctness follow-ups | 2 | Parallel after #7 merges |
| #11c | Anti-DPI hooks | 3 | After #9 (`conn_tag` rotation) |
| #10 | Multi-queue throughput sharding | 3+ | Deferred until throughput bottleneck proven |
| #11d | Bench polish | Any | Optional parallel when tools available |
| #11e | Sub-projects #2–#5 roadmap | 4 | Spec/research only |

## Success criteria

- **Wave 1:** `UringDriver` ships (tasks 5–8 of
  `docs/superpowers/plans/2026-06-30-io-uring-busy-poll.md`); all three netns
  tests pass on both `UringDriver` and `PollDriver` (`YIP_FORCE_POLL=1`); bench
  RTT/throughput deltas recorded; **the workspace-aggregate coverage gate stays
  green** — `cargo llvm-cov --workspace --exclude yip-device --exclude yipd
  --fail-under-lines 90` (the actual CI gate). Because `uring.rs` is in `yip-io`
  (included) and is hard-to-test `unsafe`, Wave 1 must add enough `uring.rs`
  loopback/helper tests (or rely on its skip-on-Err keeping counted lines low) to
  keep the aggregate ≥90%. This — not per-module targets — is the coverage bar.
- **Wave 2:** Approved specs for #8 and #9; #11b correctness items scoped and
  tasked.
- **No wire-format change** across Wave 1 (netns suite is the gate throughout).
- **`unsafe` only in `yip-io`**; yipd stays `#![forbid(unsafe_code)]`.

> **Coverage-gate reality (drives the #11a scoping below):** the CI gate is a
> **workspace *aggregate*** line-coverage check at 90%, **excluding `yipd` and
> `yip-device`**. So (a) `dataplane.rs` lives in `yipd` and is **not gated at all**;
> (b) `poll.rs` (in `yip-io`) contributes to the aggregate but is **not** gated
> per-module — it currently sits well below 90% and CI is green because the
> aggregate holds. Raising `poll.rs`/`dataplane.rs` is therefore **optional polish**,
> not a Wave-1 requirement. The only coverage work Wave 1 *must* do is keep the
> aggregate ≥90% once the gated, hard-to-test `uring.rs` lands (folded into #7).

## Dependency graph

```
#7 Phase B ──┬──► #8 L2/TAP
             ├──► #9 Rekey
             └──► #10 Multi-queue (deferred)

#9 Rekey ──► #11c conn_tag rotation / anti-DPI

#11a Tests ── optional, may run parallel with #7 (separate branch)
              CAVEAT: the `Dispatch` trait lives in poll.rs (Agent 2's file) and
              is consumed by uring.rs (Agent 1). FREEZE the Dispatch trait
              signature; Agent 2 is additive-tests + private-helper extraction
              ONLY (no trait/`run_poll`-signature change) so it can't ripple
              into the merged uring.rs at rebase.

#11b Correctness ── after #7 merges (may touch dataplane)

#11e Roadmap ── spec-only, no implementation
```

## Wave 1 — parallel execution (immediate)

### Agent 1: #7 Phase B (`UringDriver`)

- **Branch:** `feat/uring-phase-b`
- **Skill:** `subagent-driven-development` on existing plan
- **Spec/plan:** `docs/superpowers/specs/2026-06-30-io-uring-busy-poll-design.md`,
  `docs/superpowers/plans/2026-06-30-io-uring-busy-poll.md` tasks 5–8
- **Progress ledger:** `.superpowers/sdd/progress.md`

**Task sequence (serial within agent):**

1. **Task 5:** `crates/yip-io/src/uring.rs` — one ring over UDP+TUN; provided-buffer
   ring `256 × MAX_WIRE_DATAGRAM` (512 KiB, < 1 MiB memlock); multishot `RECV` on
   UDP, pooled `READ` on TUN; `user_data` demux; loopback unit test (skip-on-Err
   under memlock).
2. **Task 6:** GSO egress (`UDP_SEGMENT` cmsg) + bounded in-flight send table;
   sendmmsg fallback on GSO rejection.
3. **Task 7:** `tunnel.rs` driver selection — `YIP_FORCE_POLL=1` → `run_poll`;
   else `uring_available()` → `run_uring`; else `run_poll`. Netns gate: 3 tests ×
   2 drivers = 6 runs, all PASS.
4. **Task 8:** Bench RTT/throughput (poll vs uring); CI adds `YIP_FORCE_POLL=1`
   netns run; `CHANGELOG.md` + bench README updated.

**Constraints:**

- No wire change; byte-identical framing.
- Buffer-lifetime `unsafe` confined to `uring.rs` with `// SAFETY:` per block.
- Single-core by design (throughput scaling is #10, out of scope).
- **Freeze the `Dispatch` trait** (defined in `poll.rs`) before Agent 2 runs in
  parallel — `uring.rs` builds against it.

**Gate:** `cargo test --workspace`, clippy `-D warnings`, six netns runs green,
bench deltas committed, **and the aggregate coverage gate stays ≥90%** (`cargo
llvm-cov --workspace --exclude yip-device --exclude yipd --fail-under-lines 90`) —
`uring.rs` is gated (`yip-io`), so add loopback/helper tests for it (skip-on-Err
under memlock) sufficient to hold the aggregate. This is #7's job, not #11a's.

### Agent 2: #11a test/coverage — OPTIONAL polish (not gate-blocking)

Per the coverage-gate reality note above, this is **not a Wave-1 requirement**:
`dataplane.rs` (in `yipd`) is excluded from the gate entirely, and `poll.rs` is
only an aggregate contributor, not a per-module gate. Run this only if higher
module coverage is independently wanted; it does **not** block #7 or the CI gate.

- **Branch:** `feat/coverage-11a` (separate branch; only merge-time conflicts).
- **Files:** `crates/yip-io/src/poll.rs` (aggregate contributor) and
  `bin/yipd/src/dataplane.rs` (ungated — polish only).
- **Hard constraint:** tests + private-helper extraction ONLY. Do **not** change
  the `Dispatch` trait or `run_poll`'s public signature — `uring.rs` (#7) builds
  against them, and a change would ripple into the merged `uring.rs` at rebase.

**Baselines (⚠️ unverified — measure with `cargo llvm-cov` before targeting):**
approx `poll.rs` ~48%, `dataplane.rs` ~76%, `yip-io/lib.rs` ~87%. These are the
spec author's estimates; confirm before acting, and remember only the *workspace
aggregate* (excl. `yipd`/`yip-device`) is gated.

**Approach:**

- Factor testable helpers from `run_poll` where the epoll loop is hard to drive
  end-to-end (readable-handling, send-output paths) — additive, no signature change.
- Extend `dataplane` unit tests for branches not hit by existing round-trip /
  control / forged-packet tests (polish; `yipd` is ungated).

**Gate:** `cargo test --workspace` green; the workspace aggregate coverage stays
≥90% (it already is). No per-module gate applies.

### Wave 1 merge order

1. Merge **#7** first (the functional milestone; carries the `uring.rs` coverage
   needed to hold the aggregate).
2. If run, rebase and merge **#11a** onto #7 (tests only; trivial conflicts in
   shared imports / the frozen `Dispatch` trait only).

## Wave 2 — after #7 merges

Three parallel tracks, but note the split: #8 and #9 here are **design only**
(brainstorm → spec; no code), which is safe to run in parallel; their
**implementations run sequentially in Wave 3** (#8 then #9) because both touch
`tunnel.rs`/`DataPlane`. #11b is the one track that writes code in Wave 2 — it may
run alongside the #8/#9 *design* work since those aren't editing files yet.

### Agent 3: #8 L2/TAP

- Brainstorm → spec → plan (new doc under `docs/superpowers/specs/`).
- **Scope:** `yipd` config flag `device_kind=tun|tap`; create `DeviceKind::Tap`;
  wire `l2: true` into `Transport::encode`; 2-peer case sends all Ethernet frames
  to the single peer (MAC learning table deferred for multi-peer).
- **Gate:** netns L2 bridged flow test; classifier sees L2 frames correctly.

### Agent 4: #9 rekey

- Brainstorm → spec (classical rekey first).
- **Scope:** ~120 s handshake reschedule; epoch in wire/auth context; overlap
  window for in-flight old-epoch packets; `conn_tag` rotation per epoch.
- **PQ-hybrid:** separate sub-task after classical rekey works (`psk` modifier on
  `NOISE_PARAMS`).
- **Gate:** unit tests for epoch swap; netns tunnel stays up across rekey.

### Agent 5: #11b correctness

- **Items (independent, can be separate PRs):**
  - Wire-auth `object_id` binding to authenticated peer/epoch context.
  - Deadline-based FEC eviction (`FlowParams.deadline` honored for reassembler +
    ARQ eligibility).
  - Bidirectional flow accounting (classifier observes ingress, not egress only).
- Loss-detector partial-receive limitation: document in `lossdetect.rs` (no code
  change unless heavy-loss accuracy becomes a measured problem).

## Wave 3 — sequential milestones

1. **#8 implementation** after spec approval.
2. **#9 implementation** (classical rekey) after spec approval.
3. **#11c anti-DPI** — static `PacketType` prefix → keyed header-protection;
   `conn_tag` rotation (requires #9).
4. **#10 multi-queue sharding** — only when single-ring throughput is a
   demonstrated bottleneck; reuses per-shard `UringDriver` machinery from #7.

## Wave 4 — roadmap (spec only)

#11e items are research/spec deliverables, not implementation:

- Sub-project #2: control plane (discovery, NAT, relay).
- Sub-project #3: anti-DPI/obfuscation (AmneziaWG, REALITY, nDPI CI).
- Sub-project #4: DAITA/anonymity (Arti).
- Sub-project #5: hardening/multi-platform.

## Optional parallel: #11d bench polish

Can run anytime tools are available on a runner:

- 1000-ping samples for tighter netem variance.
- Extra contenders (ZeroTier, AmneziaWG) when installed.
- UDP-under-loss columns for WG/OpenVPN/n2n.

Does not block Wave 1.

## Subagent dispatch template

```text
Agent 1 (general-purpose):
  Branch: feat/uring-phase-b
  Read: docs/superpowers/plans/2026-06-30-io-uring-busy-poll.md (tasks 5–8)
  Skill: subagent-driven-development
  Gate: 6 netns runs, bench README, CHANGELOG, AND workspace-aggregate
        llvm-cov ≥90% (uring.rs is gated — add its loopback/helper tests)

Agent 2 (general-purpose) — OPTIONAL, not gate-blocking:
  Branch: feat/coverage-11a
  Targets: poll.rs (aggregate contributor), dataplane.rs (ungated polish)
  Constraint: additive tests only; DO NOT touch the Dispatch trait / run_poll sig
  Gate: cargo test green; aggregate coverage stays ≥90% (already does)
```

Do **not** dispatch Agents 3–5 until Agent 1 merges (avoids `tunnel.rs` /
`dataplane` conflicts).

## Risks

| Risk | Mitigation |
|------|------------|
| `UringDriver` buffer-lifetime bugs | Phase A (`PollDriver`) already ships; `YIP_FORCE_POLL=1` fallback |
| Merge conflict #7 vs #11a | Separate branches; merge #7 first; **freeze the `Dispatch` trait** so Agent 2's poll.rs work can't ripple into the merged uring.rs |
| `uring.rs` drags workspace-aggregate coverage < 90% (gated crate, hard-to-test unsafe) | #7 adds uring.rs loopback/helper tests (skip-on-Err under memlock) to hold the aggregate — this is #7's gate, not #11a's |
| #8/#9 both touch `DataPlane` | Spec in Wave 2, implement sequentially (#8 then #9) |
| Coverage drive changes behavior | Agent 2 constrained to tests + testability refactors only |

## Out of scope for this orchestration

- Control plane (sub-project #2) implementation.
- AF_XDP backend (stub remains; after io_uring stable).
- Multi-queue (#10) until benchmark proves need.
- PQ-hybrid before classical rekey (#9 sub-task).

## Next step after this spec

Wave 1's implementation plan **already exists** — `docs/superpowers/plans/2026-06-30-io-uring-busy-poll.md`
tasks 5–8 are #7. So the next step is simply to **dispatch Agent 1** via
`subagent-driven-development` on those tasks (adding the `uring.rs` coverage tests
to hold the aggregate gate). Agent 2 (#11a) is optional and needs no plan — it's
additive tests only. No new Wave-1 plan doc is required.
