# Multi-core sharding — scaling spike + benchmark runner (design)

**Date:** 2026-07-26
**Issues:** #10 (Way A per-peer sharding), #28 (regime B). Sub-project 2, **part 1** (de-risk) of the multi-core effort. Follows the `peer_manager.rs` split (#11, PR #119) which was part 1's prerequisite.
**Status:** approved, pre-implementation.

## Purpose

The cpu-regime spike (`crates/yip-bench/cpu-bound-regime.md`) established that the yip receiver has a hard **~1.2 Gbps single-core ceiling** and that a CPU-bound regime is real. Way A (per-peer engine sharding, #10) proposes to lift that ceiling by running N core-pinned data planes. Before committing to that architecture — which reintroduces cross-core coordination the single-thread design deliberately removed — we must **measure whether the receive path actually scales across cores**. If it plateaus early (shared memory bandwidth, L3 contention, kernel recv path), sharding buys far less than N× and the whole sub-project needs rethinking.

This part delivers: (1) a standalone scaling spike that answers the question with real numbers on the 12-core dev box, and (2) a Forgejo benchmark workflow on the **existing** runner so the bench suite runs automatically going forward.

## Non-goals

- **No production `yipd` change.** The spike is a standalone bench binary reusing the real `yip-crypto`/`yip-wire`/`yip-transport` code. No sharding is added to `yipd` here.
- **No full sharding architecture.** Peer→core ownership, the outbound TUN-steering solution, and the relay-from-one-IP hotspot are **part 2**, specced only if this spike shows scaling worth building.
- **No runner provisioning.** A Forgejo runner already exists on the instance (label `ubuntu-latest`); we target it, we do not install one.

## Part 1a — the scaling spike (`sharding_scale`)

**Question:** does the yip receive path scale ~linearly with core count, or does something shared cap aggregate throughput below N × 1.2 Gbps?

**Location:** a new binary under `crates/yip-bench` (an `examples/` or `src/bin` target — NOT a criterion bench; this is a throughput/scaling measurement, not a micro-bench). Runs on the 12-core dev box (AMD Ryzen 5 7640U).

**Fixture (built once):** an established session pair (reuse `yip_bench::established_pair`) and a batch of representative **received** datagrams — i.e. the wire bytes a receiver actually processes: `Codec::frame`'d + FEC-encoded + AEAD-sealed 1300-byte inner packets. Build a few thousand distinct datagrams so workers aren't all hammering one cache line.

**Level 1 — compute scaling (no network; THE gate):**
- Spawn N worker threads, each pinned to a distinct core via `libc::sched_setaffinity` (libc is already a dependency; no new crate).
- Each worker runs the **real receive chain** on datagrams from the batch in a tight loop for a fixed wall-clock window (e.g. 5 s): `Codec::deframe` (SipHash verify + header-deprotect) → FEC decode → AEAD `open`. Each worker owns its own decoder/session-open state (no shared mutable state between workers — this models per-core `DataPlane`s).
- Sweep **N = 1, 2, 4, 8, 12**. For each N, sum bytes processed across workers over the window.
- **Metrics:** aggregate Gbps(N); **scaling efficiency = Gbps(N) / (N × Gbps(1))**. Efficiency ≈ 1.0 = linear scaling; a collapse at N=4–8 exposes the shared-resource ceiling.

**Level 2 — SO_REUSEPORT delivery (real UDP loopback; confirmation):**
- N receiver threads, each pinned to a core, each with its own `SO_REUSEPORT` UDP socket bound to the same port; each runs the same per-packet receive work.
- A blaster (on a disjoint set of cores) sends the datagram batch from **many source ports** so the kernel's 4-tuple hash spreads load across the N sockets.
- Measure aggregate received-and-processed Gbps vs N; also record per-socket packet distribution (confirm the kernel spreads evenly) and drop rate.
- Level 1 is the gate: if compute doesn't scale, level 2 cannot. Level 2 confirms the kernel steering + recv-syscall path scales too.

**Caveats to state in results:** loopback has no real NIC (absolute Gbps optimistic — but that makes a *negative* scaling result strong); the dev box is a laptop Ryzen, not target-class server silicon, so the *shape* of the scaling curve travels better than the absolute ceiling. Report both levels with the efficiency table.

**Findings doc:** write results to `crates/yip-bench/sharding-scale.md` (like the prior spikes), with the N-sweep table, efficiency column, and a go/no-go read for part 2.

## Part 1b — Forgejo benchmark workflow (`.github/workflows/benchmarks.yml`)

Forgejo Actions reads `.github/workflows/` (where the existing `ci.yml`/`coverage.yml`/`integration.yml`/`mutants.yml` already live) and the existing runner advertises `ubuntu-latest`.

- New workflow `benchmarks.yml`, `runs-on: ubuntu-latest`, triggered on push to `main` and manual `workflow_dispatch`.
- Steps: build release, run the **non-root** bench suite — `cargo bench -p yip-bench --bench hotpath`, `--bench mac_candidates`, and the `sharding_scale` binary — capturing stdout to files and uploading them as a workflow artifact.
- The root-gated benches (`cpu-regime`, netem) are **out of scope** here (they need sudo+netns; the existing runner's privileges are unknown) — a follow-up can add them behind a capability check.
- Purpose is **regression tracking + on-demand measurement**, not to be the authoritative scaling number (that comes from the dev-box run in the findings doc; the runner's core count may differ).

## Verdict logic (what the spike decides)

- **Efficiency stays high (≳0.8) through N=8–12** → the receive path scales; Way A is worth building. Proceed to part 2 (the sharded-`yipd` architecture spec).
- **Efficiency collapses early** (e.g. ≤0.5 by N=4) → aggregate throughput is bounded by a shared resource, not per-core CPU. Sharding buys little; part 2 is re-scoped or shelved, and the finding is documented as the real ceiling.

## Verification

1. `sharding_scale` builds and runs on the 12-core box; produces the N-sweep table for both levels; `crates/yip-bench/sharding-scale.md` written.
2. `cargo fmt`/`clippy` clean on the new bench code; workspace tests unaffected (no production code touched).
3. `benchmarks.yml` is valid workflow YAML and runs green on the existing runner (the `sharding_scale` invocation completes and uploads its artifact).

## Sequencing

Land part 1 (spike + workflow) as one PR. Read the efficiency table. If go, spec part 2 (sharded-`yipd`: peer→core ownership, outbound TUN steering, relay hotspot) as its own brainstorm → spec → plan.
