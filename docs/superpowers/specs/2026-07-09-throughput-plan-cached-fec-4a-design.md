# Milestone 4a: Throughput — Plan-Cached FEC — Design Spec

**Status:** draft (under review)
**Sub-project:** #4 (Throughput & Scalability), milestone 4a.

---

## 1. Goal

Optimize the RaptorQ FEC encoding hot path in [`crates/yip-transport`](file:///home/zoa/projects/femboy/yip/crates/yip-transport/src/lib.rs) to unlock multi-gigabit throughput on a single CPU core.

Currently, yip's single-core throughput is capped at ~355 Mbps because the daemon generates a fresh [`raptorq::Encoder`](file:///home/zoa/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/raptorq-2.0.1/src/encoder.rs) for every packet. This triggers a full constraint matrix Gaussian elimination solve ([`SourceBlockEncodingPlan::generate`](file:///home/zoa/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/raptorq-2.0.1/src/encoder.rs#L128)) costing ~26 µs per packet.

We will eliminate this bottleneck by caching the `SourceBlockEncodingPlan` for each unique `symbol_count` at runtime, bypassing the 26 µs plan generation step. This avoids micro-batching latency or compromising proactive loss recovery, preserving yip's zero-RTT recovery thesis.

---

## 2. Bottleneck Analysis

Profiling under saturation shows the following cost breakdown per packet:
* **AEAD Seal (ChaCha20-Poly1305)**: ~2.1 µs
* **AEAD Open (ChaCha20-Poly1305)**: ~2.0 µs
* **Wire Frame/Deframe (SipHash/CTR)**: ~0.5 µs
* **RaptorQ FEC Encode (proactive repair $\ge 1$)**: **~26.3 µs** (Dominant bottleneck)

### The Root Cause
RaptorQ's intermediate symbol plan generation is computationally expensive, but it is **entirely independent of packet payload data**. It depends only on the `symbol_count` (ceil of payload length / symbol size). Because yip operates on per-packet objects, the payload size is capped by the MTU, resulting in a tiny, predictable set of symbol counts (typically 1, 2, or 3 symbols).

By constructing a new `Encoder` per packet, yip regenerates the identical encoding plan on every packet transmission, discarding it immediately after.

### Caching Fast Path vs. Baseline
Our benchmarks reveal the following cost step function:
* **`repair == 0` (Fast path bypass)**: **~0.27 µs** (~3.8 Gbps equivalent)
* **`repair >= 1` (Gaussian solve + encoding)**: **~26.0–28.0 µs** (~370 Mbps equivalent)

With plan caching, generating $R \ge 1$ repair packets drops from 26 µs to the cost of the fast path plus simple matrix-vector XOR multiplication operations, pushing active FEC encoding performance into the low-single-digit microsecond range.

---

## 3. Architecture & Implementation

### The Plan Cache
[`FecEncoder`](file:///home/zoa/projects/femboy/yip/crates/yip-transport/src/fec.rs) will gain a bounded, instance-owned cache mapping `symbol_count` to pre-calculated plans (`FecEncoder` is already `&mut self` on the encode path and lives inside a single-threaded `Transport`, so no cross-thread synchronization is required):

```rust
use raptorq::{SourceBlockEncoder, SourceBlockEncodingPlan};
use std::collections::HashMap;

pub struct FecEncoder {
    next_object_id: u16,
    // Bounded cache to prevent memory leaks from corrupted sizes
    plan_cache: HashMap<u16, SourceBlockEncodingPlan>,
}
```

### The Encoding Transform
In `FecEncoder::encode` and `FecEncoder::repair_with_id`:
1. Calculate the target `symbol_count` from `ciphertext.len()` and `params.symbol_size`.
2. Check if the object conforms to a single source block (`oti.sub_blocks() == 1`). This is always true for yip's packet-sized objects.
3. If true, retrieve the plan from the cache:
   ```rust
   let plan = self.plan_cache
       .entry(symbol_count)
       .or_insert_with(|| SourceBlockEncodingPlan::generate(symbol_count));
   ```
4. Construct the source-block encoder using the pre-computed plan and emit
   source **and** repair packets. Note the real `raptorq` 2.0.1 signature is
   `with_encoding_plan(source_block_id, config, data, plan)` — the first arg is
   the RaptorQ source-block number (`0` for yip's single-block objects), **not**
   yip's wrapper `object_id`, which is applied later in `split_packet`. The
   `data` slice must be zero-padded to `symbol_count * symbol_size` exactly as
   `Encoder::new` pads before `create_symbols` (an internal
   `assert_eq!(source_symbols.len(), plan.source_symbol_count)` enforces this):
   ```rust
   let block = pad_to(ciphertext, symbol_count, params.symbol_size);
   let sbe = SourceBlockEncoder::with_encoding_plan(0, &oti, &block, plan);
   // Full packet set = systematic source symbols ++ repair symbols,
   // matching Encoder::get_encoded_packets(repair) exactly.
   let packets: Vec<EncodingPacket> = sbe
       .source_packets()
       .into_iter()
       .chain(sbe.repair_packets(0, repair))
       .collect();
   // then map each packet through split_packet(object_id, object_size, &p)
   ```
5. If `oti.sub_blocks() != 1` (safety fallback for multi-source-block objects,
   which yip's packet-sized frames never produce), fall back to the standard
   `raptorq::Encoder::new(...).get_encoded_packets(repair)` path.

---

## 4. Invariants

1. **Byte-Identical Outputs**: The symbols generated via `SourceBlockEncoder::with_encoding_plan` must be byte-identical to those generated by the standard `raptorq::Encoder` for any given payload, repair count, and object ID.
2. **Memory Bounding**: The plan cache size is capped at 64 entries (matching `raptorq`'s internal LRU cache limit) to prevent memory expansion if malformed sizes are processed.
3. **No Timing/Behavior Changes**: All flow classes keep their configured proactive repair ratios (`Realtime` at 15%, `Default` at 10%). Tunnels benefit from immediate, latency-free throughput upgrades without changes to recovery behavior.

---

## 5. Verification & Testing

### Unit Tests
* **Byte-Identity Verification**: Compare the byte outputs of the plan-cached encoder against the standard encoder across a matrix of payload sizes (1 to 1500 bytes) and repair counts (1 to 8).
* **Cache Liveness**: Verify that the cache hit rate is 100% after the first packet for a static stream size.

### Benchmark Verification
* **Criterion Hotpath**: Re-run the `transport_encode_1300` benchmark. The median execution time must drop from ~26 µs to $<3$ µs.
* **Pipeline Profile**: Re-run `pipeline_profile` example. The `encode` line must show low-single-digit microseconds.

### Integration Tests
* **netns Throughput Gates**: Re-run `run-compare.sh` and `run-iperf-compare.sh`. Verify that clean-link TCP/iperf3 throughput on a single core increases from the 355 Mbps baseline toward the AEAD/syscall bottleneck (~1.5–2 Gbps+).
* **No-Regression Gate**: Verify that every existing `netns` integration test on this base remains green, confirming that plan caching does not break standard packet recovery or path negotiation. Because the wire format is unchanged, byte-identity (Invariant 1) is what actually guarantees no regression; the netns suite is the end-to-end confirmation.

---

## 6. Scope & Base Branch

4a branches off `main` and touches **only** `crates/yip-transport/src/fec.rs` (plus its unit tests) and the `yip-bench` harness — a pure encode-path speedup with no wire-format or public-API change. `fec.rs` is byte-identical on `main` and the unmerged `feat/antidpi-3c1` (3c.1/QUIC) branch, so the two are independent: 4a does not depend on 3c.1, and 3c.1's `Transport::new(rules, symbol_size)` signature change does not affect this work. The QUIC netns scripts (`run-netns-quic*.sh`, `run-quic-vs-raw.sh`) live on the 3c.1 branch; QUIC no-regression is covered automatically once both land, since plan-caching is invisible below the FEC symbol boundary that QUIC's DATAGRAM frames carry. **Out of scope (later 4x milestones):** I/O batching (4b), multi-core sharding #10 (4c), header-compression / L4S / sliding-window FEC (4d).
