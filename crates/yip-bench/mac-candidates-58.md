# #58 SipHash MAC-candidate spike (measure-only)

Bench: `crates/yip-bench/benches/mac_candidates.rs`
Run:   `cargo bench -p yip-bench --bench mac_candidates`

Isolated keyed-MAC over header‖symbol, 8-byte tag.

Ran two boxes. Ratio is stable across both, so the lever is confirmed:
- Dev box: Ryzen 5 7640U (Zen4, AVX2+AVX512), 12 core.
- Target box: VPS-A "Las Vegas" AMD EPYC, 1 core, Debian 13 (the 4b profile box).
  blake3 SIMD dispatch active on both (EPYC advertises avx2). Native x86_64-gnu
  bench binary built on the dev box, glibc 2.41 == 2.41, run on the EPYC then
  deleted -- no toolchain/repo installed on the VPS.

| covered | candidate         | EPYC ns | dev ns | vs SipHash-2-4 (EPYC) |
|--------:|-------------------|--------:|-------:|----------------------:|
| 1415 B  | siphash13         |     420 |    241 | 0.55x  (-45%)         |
| 1415 B  | siphash24 (today) |     758 |    433 | 1.00x                 |
| 1415 B  | blake3_keyed      |    1888 |   1223 | 2.49x (slower)        |
|   63 B  | siphash13         |    31.8 |   16.7 | 0.63x                 |
|   63 B  | siphash24         |    50.5 |   25.1 | 1.00x                 |
|   63 B  | blake3_keyed      |     104 |   65.5 | 2.06x (slower)        |

## Findings
1. SipHash-1-3 is the only cheaper option: ~44% off the MAC at packet size ->
   ~9% * 0.44 ~= ~4% of receiver CPU saved. Confirms the parked ~4.5% estimate.
2. BLAKE3 rejected on data (not just principle): ~2.8x slower here. Its SIMD win
   needs KB-MB inputs; at a 1.4 KB symbol key-schedule + finalize overhead wins.

## Open question (out of scope for this spike -> the parked "swap" decision)
Is a reduced-round SipHash-1-3 acceptable for a 64-bit per-symbol pre-decoder
filter, given AEAD still carries end-to-end auth? If yes, ~4% receiver CPU is the
prize -- but it did NOT move end-to-end throughput on RTT/window-capped boxes (4b
lesson). Revisit only if a box is genuinely MAC-bound.
