# Multi-core sharding scaling spike (Way A go/no-go)

Bench: `crates/yip-bench/examples/sharding_scale.rs`
Run:   `cargo run --release -p yip-bench --example sharding_scale`

**Question:** does the yip receive path scale ~linearly across cores, or does a
shared resource cap aggregate throughput below N × the ~1.2 Gbps single-core
ceiling (see `cpu-bound-regime.md`)? This is the go/no-go for Way A (per-peer
engine sharding, #10) before building the sharded `yipd`.

**Method:** N core-pinned worker threads, each running the real receive chain
from the library crates — `Codec::deframe` (SipHash + header-deprotect) → FEC
decode → AEAD decrypt-attempt — with **topology-aware pinning** (physical cores
first, SMT siblings last), a **start barrier**, and a **per-worker owned,
distinct, L3-exceeding fixture** (46.8 MB total > 16 MB L3) so memory-bandwidth
contention actually manifests. Level 2 additionally delivers datagrams over real
`SO_REUSEPORT` UDP sockets to confirm the kernel distribution mechanism.

Box: AMD Ryzen 5 7640U, **6 physical cores / 12 SMT threads**, 16 MiB L3.

## Level 1 — compute scaling (the gate)

| N  | aggregate Gbps | per-core | efficiency | avg MHz |
|---:|---------------:|---------:|-----------:|--------:|
| 1  | 1.80           | 1.80     | 1.00       | 4620    |
| 2  | 3.46           | 1.73     | 0.96       | 4605    |
| 4  | 6.50           | 1.62     | 0.90       | 4428    |
| 6  | 8.99           | 1.50     | **0.83**   | 4262    |
| 8  | 9.64           | 1.20     | 0.67       | 4084    |
| 12 | 10.55          | 0.88     | 0.49       | 3989    |

**Reading it (physical vs SMT vs DVFS):**
- **Across the 6 physical cores (N ≤ 6) it scales near-linearly.** Raw
  efficiency at N=6 is 0.83, but the all-core clock also droops 4620 → 4262 MHz
  (−7.7%) under the laptop package power limit. **Clock-normalized**, N=6 is
  `0.83 / (4262/4620) ≈ 0.90` — i.e. ~90% of ideal per-core work is retained at
  6 physical cores; most of the raw loss is DVFS, not a scaling wall.
- **N=8 and N=12 add SMT threads** (there are only 6 physical cores). The extra
  throughput (8.99 → 10.55 Gbps) is real but sub-linear — the expected ~40% SMT
  uplift for compute-bound AEAD/FEC work sharing an execution unit, compounded
  by further clock droop. This is **not** a memory-bandwidth ceiling.

## Level 2 — SO_REUSEPORT delivery (mechanism confirmation)

| N | recv Gbps | imbalance | offered | drop% |
|--:|----------:|----------:|--------:|------:|
| 1 | 0.82      | 1.00      | 6.6M    | 76.4  |
| 2 | 1.48      | 1.08      | 6.0M    | 53.6  |
| 4 | 2.32      | 1.65      | 5.3M    | 16.3  |
| 6 | 2.33      | 1.55      | 4.5M    | 2.0   |

- **SO_REUSEPORT distributes fairly** — per-socket datagram counts are roughly
  even (imbalance 1.0–1.65), confirming the kernel 4-tuple hash spreads load
  across the N sockets. This is the delivery mechanism Way A depends on.
- **Absolute level-2 throughput is blaster-/SMT-/loopback-bound, NOT a receiver
  ceiling** and is not magnitude-comparable to level 1: the blaster shares the
  box (its cores land on the receivers' SMT siblings), and `offered` falls as N
  grows because the blaster's core budget shrinks. By construction the receiver
  `open()` always fails the tag check (independent blaster/receiver sessions),
  so each packet still pays the full deframe + FEC-decode + decrypt-attempt cost
  — honest per-packet work, just no committed plaintext. Level 1 is the
  authoritative compute-scaling number.

## Verdict: **GO** for Way A

The receive path scales near-linearly across physical cores (~0.90
clock-normalized efficiency at 6 cores; no memory-bandwidth wall through the
L3-exceeding, distinct-payload fixture). The ~1.2 Gbps single-core ceiling
genuinely multiplies with physical cores. On target-class server silicon —
fixed all-core clock (no laptop DVFS droop) and more physical cores — Way A
should deliver roughly `physical_cores × ~1.2 Gbps` aggregate. Building the
sharded `yipd` (part 2) is justified.

**Design implications for part 2:**
- Size one shard per **physical** core, not per SMT thread (SMT adds ~40%, not
  100%, for this compute-bound path).
- `SO_REUSEPORT` is a sound inbound steering mechanism (kernel distributes
  evenly). The unproven-here hard part remains the **outbound TUN path** (routing
  each inner packet to the core owning its destination peer) — that is part 2's
  central design problem, to be specced next.

## Caveats
- **Laptop, not server silicon:** absolute Gbps is optimistic (loopback, no NIC)
  and the DVFS droop is a mobile-APU artifact; a fixed-clock server scales
  *better* than this curve, so the GO is conservative.
- Re-run on multi-core target hardware (via the `benchmarks.yml` workflow /
  a real POP-class box) before finalizing part 2's shard-count defaults.
