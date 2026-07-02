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
| #11a | Test/coverage gaps | 1 | Single agent, parallel to #7 |
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
  RTT/throughput deltas recorded; `yip-io/poll.rs` and `bin/yipd/dataplane.rs`
  reach ≥90% line coverage.
- **Wave 2:** Approved specs for #8 and #9; #11b correctness items scoped and
  tasked.
- **No wire-format change** across Wave 1 (netns suite is the gate throughout).
- **`unsafe` only in `yip-io`**; yipd stays `#![forbid(unsafe_code)]`.

## Dependency graph

```
#7 Phase B ──┬──► #8 L2/TAP
             ├──► #9 Rekey
             └──► #10 Multi-queue (deferred)

#9 Rekey ──► #11c conn_tag rotation / anti-DPI

#11a Tests ── parallel with #7 (no file overlap on uring.rs)

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

**Gate:** `cargo test --workspace`, clippy `-D warnings`, six netns runs green,
bench deltas committed.

### Agent 2: #11a test/coverage (parallel)

- **Branch:** `feat/coverage-11a`
- **Files:** `crates/yip-io/src/poll.rs`, `bin/yipd/src/dataplane.rs` (and helpers
  only as needed for coverage)
- **No behavior changes** — tests only unless a trivial refactor improves
  testability without semantic change.

**Targets (baseline 2026-07-01):**

| Module | Current line coverage | Target |
|--------|----------------------|--------|
| `yip-io/poll.rs` | 48% | ≥90% |
| `yipd/dataplane.rs` | 76% | ≥90% |
| `yip-io/lib.rs` | 87% | ≥90% if touched |

**Approach:**

- Factor testable helpers from `run_poll` where the epoll loop is hard to drive
  end-to-end (readable-handling, send-output paths).
- Extend `dataplane` unit tests for branches not hit by existing round-trip /
  control / forged-packet tests.
- `tunnel.rs` and `main.rs` remain integration-covered (excluded from hermetic
  90% gate by design).

**Gate:** `cargo llvm-cov` ≥90% on touched modules; `cargo test --workspace` green.

### Wave 1 merge order

1. Merge **#7** first (functional milestone).
2. Rebase and merge **#11a** (tests only; resolve any trivial conflicts in
   shared imports only).

## Wave 2 — after #7 merges

Three parallel tracks:

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
Agent 1 (generalPurpose):
  Branch: feat/uring-phase-b
  Read: docs/superpowers/plans/2026-06-30-io-uring-busy-poll.md (tasks 5–8)
  Skill: subagent-driven-development
  Gate: 6 netns runs, bench README, CHANGELOG

Agent 2 (generalPurpose):
  Branch: feat/coverage-11a
  Targets: poll.rs, dataplane.rs
  Gate: llvm-cov ≥90% on touched modules
```

Do **not** dispatch Agents 3–5 until Agent 1 merges (avoids `tunnel.rs` /
`dataplane` conflicts).

## Risks

| Risk | Mitigation |
|------|------------|
| `UringDriver` buffer-lifetime bugs | Phase A (`PollDriver`) already ships; `YIP_FORCE_POLL=1` fallback |
| Merge conflict #7 vs #11a | Separate branches; merge #7 first |
| #8/#9 both touch `DataPlane` | Spec in Wave 2, implement sequentially (#8 then #9) |
| Coverage drive changes behavior | Agent 2 constrained to tests + testability refactors only |

## Out of scope for this orchestration

- Control plane (sub-project #2) implementation.
- AF_XDP backend (stub remains; after io_uring stable).
- Multi-queue (#10) until benchmark proves need.
- PQ-hybrid before classical rekey (#9 sub-task).

## Next step after this spec

Invoke **writing-plans** to produce a Wave 1 implementation plan (Agent 1 + Agent 2
task breakdown with checkboxes), then dispatch subagents.
