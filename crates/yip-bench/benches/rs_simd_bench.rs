//! Poly-Vector SIMD Galois Field Microbenchmark (Regime E).
//!
//! Microbenchmarks Galois Field GF(2^8) arithmetic and Cauchy Reed–Solomon
//! block encoding across all detected SIMD tiers:
//! - Pure-Rust Scalar baseline (`gf256::mul_slice_into`)
//! - SSSE3 128-bit nibble shuffle (`mul_add_ssse3`)
//! - AVX2 256-bit nibble shuffle (`mul_add_avx2`)
//! - AVX-512BW 512-bit nibble shuffle (`mul_add_avx512`)
//! - GFNI bit-matrix affine transformation (`mul_add_gfni`)
//! - ARM64 NEON table lookup (`mul_add_neon`)
//! - Tiered production datapath dispatch (`mul_add_row`)

use std::hint::black_box;
use std::time::Instant;

use yip_transport::gf256;
use yip_transport::rs::{self, Scheme};
use yip_transport::rs_simd;

fn scalar_mul_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    gf256::mul_slice_into(dst, src, coeff);
}

fn ssse3_mul_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if rs_simd::ssse3_supported() {
        // SAFETY: ssse3_supported() confirmed CPU supports SSSE3, slice lengths match.
        unsafe { rs_simd::mul_add_ssse3(coeff, src, dst) };
        return;
    }
    scalar_mul_add(coeff, src, dst);
}

fn avx2_mul_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if rs_simd::avx2_supported() {
        // SAFETY: avx2_supported() confirmed CPU supports AVX2, slice lengths match.
        unsafe { rs_simd::mul_add_avx2(coeff, src, dst) };
        return;
    }
    scalar_mul_add(coeff, src, dst);
}

fn avx512_mul_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if rs_simd::avx512bw_supported() {
        // SAFETY: avx512bw_supported() confirmed CPU supports AVX-512BW, slice lengths match.
        unsafe { rs_simd::mul_add_avx512(coeff, src, dst) };
        return;
    }
    scalar_mul_add(coeff, src, dst);
}

fn gfni_mul_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if rs_simd::gfni_supported() {
        // SAFETY: gfni_supported() confirmed CPU supports GFNI, slice lengths match.
        unsafe { rs_simd::mul_add_gfni(coeff, src, dst) };
        return;
    }
    scalar_mul_add(coeff, src, dst);
}

fn neon_mul_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "aarch64")]
    if rs_simd::neon_supported() {
        // SAFETY: neon_supported() confirmed CPU supports ARM64 NEON, slice lengths match.
        unsafe { rs_simd::mul_add_neon(coeff, src, dst) };
        return;
    }
    scalar_mul_add(coeff, src, dst);
}

fn tiered_mul_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    rs::mul_add_row(coeff, src, dst);
}

struct SimdTier {
    name: &'static str,
    supported: bool,
    mul_add: fn(u8, &[u8], &mut [u8]),
}

fn encode_block_cauchy(
    source: &[Vec<u8>],
    m: usize,
    mul_add: fn(u8, &[u8], &mut [u8]),
) -> Vec<Vec<u8>> {
    let k = source.len();
    let len = source[0].len();
    let mut repair = vec![vec![0u8; len]; m];
    for (row_idx, rep) in repair.iter_mut().enumerate() {
        let coefs = rs::repair_row(Scheme::Cauchy, k, row_idx);
        for (src, &c) in source.iter().zip(coefs.iter()) {
            if c == 1 {
                for (d, &s) in rep.iter_mut().zip(src.iter()) {
                    *d ^= s;
                }
            } else if c != 0 {
                mul_add(c, src, rep);
            }
        }
    }
    repair
}

fn main() {
    println!("================================================================================");
    println!("  YIP Regime E: Cauchy Reed-Solomon Poly-Vector SIMD Galois Field Microbenchmark");
    println!("================================================================================");
    println!("CPU Feature Detection:");
    println!("  SSSE3:     {}", rs_simd::ssse3_supported());
    println!("  AVX2:      {}", rs_simd::avx2_supported());
    println!("  AVX-512BW: {}", rs_simd::avx512bw_supported());
    println!("  GFNI:      {}", rs_simd::gfni_supported());
    println!("  NEON:      {}", rs_simd::neon_supported());
    println!("--------------------------------------------------------------------------------\n");

    let tiers = [
        SimdTier {
            name: "Scalar (Pure-Rust)",
            supported: true,
            mul_add: scalar_mul_add,
        },
        SimdTier {
            name: "SSSE3 (128-bit)",
            supported: rs_simd::ssse3_supported(),
            mul_add: ssse3_mul_add,
        },
        SimdTier {
            name: "AVX2 (256-bit)",
            supported: rs_simd::avx2_supported(),
            mul_add: avx2_mul_add,
        },
        SimdTier {
            name: "AVX-512BW (512-bit)",
            supported: rs_simd::avx512bw_supported(),
            mul_add: avx512_mul_add,
        },
        SimdTier {
            name: "GFNI (Bit-Matrix)",
            supported: rs_simd::gfni_supported(),
            mul_add: gfni_mul_add,
        },
        SimdTier {
            name: "NEON (ARM64)",
            supported: rs_simd::neon_supported(),
            mul_add: neon_mul_add,
        },
        SimdTier {
            name: "Tiered (mul_add_row)",
            supported: true,
            mul_add: tiered_mul_add,
        },
    ];

    // Verification of bit-exactness across all supported tiers
    for tier in &tiers {
        if !tier.supported {
            continue;
        }
        let size = 1500;
        let mut dst_scalar = vec![0x33u8; size];
        let mut dst_tier = vec![0x33u8; size];
        let src: Vec<u8> = (0..size)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        let coeff = 0x57;

        scalar_mul_add(coeff, &src, &mut dst_scalar);
        (tier.mul_add)(coeff, &src, &mut dst_tier);
        assert_eq!(
            dst_tier, dst_scalar,
            "Tier {} failed bit-exactness verification!",
            tier.name
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Part 1: 1500-byte Row Multiplication Across 50,000 Iterations
    // ─────────────────────────────────────────────────────────────────────────
    let row_size = 1500;
    let row_iters = 50_000;
    let coeff = 0x57;
    let mut src = vec![0u8; row_size];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }

    println!("### 1. Vector Row Multiplication (Payload: 1500 B, Iterations: 50,000)");
    println!(
        "| {:<22} | {:<9} | {:>14} | {:>17} | {:>14} |",
        "SIMD Tier", "Supported", "Latency (ns)", "Throughput (Gbps)", "Speedup Factor"
    );
    println!(
        "|------------------------|-----------|----------------|-------------------|----------------|"
    );

    // Warm-up scalar baseline
    let mut dst = vec![0u8; row_size];
    for _ in 0..10_000 {
        scalar_mul_add(black_box(coeff), black_box(&src), black_box(&mut dst));
    }
    let t0 = Instant::now();
    for _ in 0..row_iters {
        scalar_mul_add(black_box(coeff), black_box(&src), black_box(&mut dst));
    }
    let scalar_row_elapsed = t0.elapsed();
    let mut scalar_row_ns = scalar_row_elapsed.as_nanos() as f64 / row_iters as f64;

    for tier in &tiers {
        if !tier.supported {
            println!(
                "| {:<22} | {:<9} | {:>14} | {:>17} | {:>14} |",
                tier.name, "No", "-", "-", "-"
            );
            continue;
        }

        let mut dst_tier = vec![0u8; row_size];
        // Warm up
        for _ in 0..10_000 {
            (tier.mul_add)(black_box(coeff), black_box(&src), black_box(&mut dst_tier));
        }

        let t = Instant::now();
        for _ in 0..row_iters {
            (tier.mul_add)(black_box(coeff), black_box(&src), black_box(&mut dst_tier));
        }
        let elapsed = t.elapsed();
        let tier_ns = elapsed.as_nanos() as f64 / row_iters as f64;
        let gbps = (row_size as f64 * 8.0) / tier_ns;
        let speedup = if tier.name.starts_with("Scalar") {
            scalar_row_ns = tier_ns;
            1.00
        } else {
            scalar_row_ns / tier_ns.max(0.001)
        };

        println!(
            "| {:<22} | {:<9} | {:>11.1} ns | {:>12.2} Gbps | {:>13.2}x |",
            tier.name, "Yes", tier_ns, gbps, speedup
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // Part 2: Systematic Cauchy Reed-Solomon (K=10, M=4) Block Encoding
    // ─────────────────────────────────────────────────────────────────────────
    let k = 10;
    let m = 4;
    let block_size = 1500;
    let block_iters = 10_000;

    let mut source = vec![vec![0u8; block_size]; k];
    for (i, row) in source.iter_mut().enumerate() {
        for (j, b) in row.iter_mut().enumerate() {
            *b = ((i * 17) ^ (j * 31) ^ 0x5a) as u8;
        }
    }

    println!(
        "### 2. Systematic Cauchy Reed-Solomon (K={}, M={}) Block Encoding (Payload: {} B)",
        k, m, block_size
    );
    println!(
        "| {:<22} | {:<9} | {:>14} | {:>16} | {:>17} | {:>14} |",
        "SIMD Tier",
        "Supported",
        "Block Time (µs)",
        "Per-Pkt FEC (ns)",
        "Throughput (Gbps)",
        "Speedup Factor"
    );
    println!(
        "|------------------------|-----------|----------------|------------------|-------------------|----------------|"
    );

    // Warm-up scalar baseline
    for _ in 0..1000 {
        let _ = black_box(encode_block_cauchy(black_box(&source), m, scalar_mul_add));
    }
    let t0 = Instant::now();
    for _ in 0..block_iters {
        let rep = encode_block_cauchy(black_box(&source), m, scalar_mul_add);
        black_box(rep);
    }
    let scalar_block_elapsed = t0.elapsed();
    let mut scalar_block_ns = scalar_block_elapsed.as_nanos() as f64 / block_iters as f64;

    for tier in &tiers {
        if !tier.supported {
            println!(
                "| {:<22} | {:<9} | {:>14} | {:>16} | {:>17} | {:>14} |",
                tier.name, "No", "-", "-", "-", "-"
            );
            continue;
        }

        // Warm up
        for _ in 0..1000 {
            let _ = black_box(encode_block_cauchy(black_box(&source), m, tier.mul_add));
        }

        let t = Instant::now();
        for _ in 0..block_iters {
            let rep = encode_block_cauchy(black_box(&source), m, tier.mul_add);
            black_box(rep);
        }
        let elapsed = t.elapsed();
        let block_ns = elapsed.as_nanos() as f64 / block_iters as f64;
        let block_us = block_ns / 1000.0;
        let per_packet_ns = block_ns / (k + m) as f64;
        let goodput_gbps = (k as f64 * block_size as f64 * 8.0) / block_ns;
        let speedup = if tier.name.starts_with("Scalar") {
            scalar_block_ns = block_ns;
            1.00
        } else {
            scalar_block_ns / block_ns.max(0.001)
        };

        println!(
            "| {:<22} | {:<9} | {:>11.2} µs | {:>13.1} ns | {:>12.2} Gbps | {:>13.2}x |",
            tier.name, "Yes", block_us, per_packet_ns, goodput_gbps, speedup
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // Part 3: Production Datapath Packet Size Scaling
    // ─────────────────────────────────────────────────────────────────────────
    println!("### 3. Production Datapath Multi-Size Scaling (mul_add_row)");
    println!(
        "| Packet Size (B) | Scalar (ns/pkt) | SIMD Datapath (ns) | Speedup Ratio | Datapath Throughput |"
    );
    println!(
        "|-----------------|-----------------|--------------------|---------------|---------------------|"
    );

    let test_sizes = [64, 512, 1280, 1400, 1500];
    for &size in &test_sizes {
        let mut s = vec![0u8; size];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let mut d_scalar = vec![0u8; size];
        let mut d_simd = vec![0u8; size];

        // Warm up
        for _ in 0..5_000 {
            gf256::mul_slice_into(&mut d_scalar, &s, coeff);
            rs::mul_add_row(coeff, &s, &mut d_simd);
        }

        let iters = 50_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            gf256::mul_slice_into(black_box(&mut d_scalar), black_box(&s), black_box(coeff));
        }
        let sc_ns = t0.elapsed().as_nanos() as f64 / iters as f64;

        let t1 = Instant::now();
        for _ in 0..iters {
            rs::mul_add_row(black_box(coeff), black_box(&s), black_box(&mut d_simd));
        }
        let sm_ns = t1.elapsed().as_nanos() as f64 / iters as f64;
        let speedup = sc_ns / sm_ns.max(0.001);
        let gbps = (size as f64 * 8.0) / sm_ns;

        println!(
            "| {:15} | {:12.1} ns | {:15.1} ns | {:12.2}x | {:14.2} Gbps |",
            size, sc_ns, sm_ns, speedup, gbps
        );
    }
    println!("================================================================================");
}
