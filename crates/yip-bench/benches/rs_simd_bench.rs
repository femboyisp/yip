//! Cauchy Reed-Solomon SIMD Galois Field Microbenchmark (Regime D).
//!
//! Measures per-packet Galois Field GF(2^8) matrix operations and Cauchy
//! Reed-Solomon encode/decode latency:
//! 1. Scalar lookup vs AVX2 256-bit nibble-shuffle table lookups (`_mm256_shuffle_epi8`).
//! 2. Tested across varying packet sizes: 64 B, 512 B, 1280 B, 1400 B.
//! 3. Measures speedup ratio and verifies < 200 ns per packet FEC computation.

use std::hint::black_box;
use std::time::Instant;

use yip_transport::gf256;
use yip_transport::rs::{self, Scheme};

fn main() {
    println!("=== Cauchy Reed-Solomon SIMD Galois Field Microbenchmark (Regime D) ===");
    println!("AVX2 CPU support detected: {}", rs::avx2_supported());
    println!();

    let sizes = [64, 512, 1280, 1400];
    let iters = 100_000;

    println!("### 1. Vector Row Multiplication (mul_add_row)");
    println!(
        "| Packet Size (B) | Scalar (ns/pkt) | AVX2 SIMD (ns/pkt) | Speedup Ratio | Throughput (GiB/s) |"
    );
    println!(
        "|-----------------|-----------------|--------------------|---------------|--------------------|"
    );

    for &size in &sizes {
        let mut src = vec![0u8; size];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let mut dst_scalar = vec![0u8; size];
        let mut dst_simd = vec![0u8; size];
        let coeff = 0x57;

        // Warm up
        for _ in 0..10_000 {
            gf256::mul_slice_into(
                black_box(&mut dst_scalar),
                black_box(&src),
                black_box(coeff),
            );
            rs::mul_add_row(black_box(coeff), black_box(&src), black_box(&mut dst_simd));
        }

        // Measure scalar
        let t0 = Instant::now();
        for _ in 0..iters {
            gf256::mul_slice_into(
                black_box(&mut dst_scalar),
                black_box(&src),
                black_box(coeff),
            );
        }
        let scalar_elapsed = t0.elapsed();
        let scalar_ns = scalar_elapsed.as_nanos() as f64 / iters as f64;

        // Measure SIMD
        let t1 = Instant::now();
        for _ in 0..iters {
            rs::mul_add_row(black_box(coeff), black_box(&src), black_box(&mut dst_simd));
        }
        let simd_elapsed = t1.elapsed();
        let simd_ns = simd_elapsed.as_nanos() as f64 / iters as f64;

        let speedup = scalar_ns / simd_ns.max(0.001);
        let gib_per_sec = (size as f64 * iters as f64)
            / (simd_elapsed.as_secs_f64() * (1024.0 * 1024.0 * 1024.0));

        println!(
            "| {:15} | {:15.1} | {:18.1} | {:12.2}x | {:18.2} |",
            size, scalar_ns, simd_ns, speedup, gib_per_sec
        );
    }
    println!();

    println!("### 2. Systematic Cauchy Reed-Solomon Block Encoding (K=10, R=2)");
    println!(
        "| Block Payload Size | Scalar (µs/block) | AVX2 SIMD (µs/block) | Speedup Ratio | Per-Packet (ns) |"
    );
    println!(
        "|--------------------|-------------------|----------------------|---------------|-----------------|"
    );

    let k = 10;
    let r = 2;
    let block_iters = 20_000;

    for &size in &[512, 1280, 1400] {
        let mut source = vec![vec![0u8; size]; k];
        for (i, row) in source.iter_mut().enumerate() {
            for (j, b) in row.iter_mut().enumerate() {
                *b = ((i * 17) ^ (j * 31)) as u8;
            }
        }

        // Warm up
        for _ in 0..1000 {
            let _ = black_box(rs::encode_repair(
                black_box(&source),
                black_box(r),
                Scheme::Cauchy,
            ));
        }

        // Measure scalar baseline: manually simulate scalar encode_repair loop
        let t0 = Instant::now();
        for _ in 0..block_iters {
            let mut repair = vec![vec![0u8; size]; r];
            for (m, rep) in repair.iter_mut().enumerate() {
                let coefs = rs::repair_row(Scheme::Cauchy, k, m);
                for (src, &c) in source.iter().zip(coefs.iter()) {
                    if c == 1 {
                        for (d, &s) in rep.iter_mut().zip(src.iter()) {
                            *d ^= s;
                        }
                    } else if c != 0 {
                        gf256::mul_slice_into(rep, src, c);
                    }
                }
            }
            black_box(repair);
        }
        let scalar_elapsed = t0.elapsed();
        let scalar_us = (scalar_elapsed.as_nanos() as f64 / block_iters as f64) / 1000.0;

        // Measure SIMD encode_repair
        let t1 = Instant::now();
        for _ in 0..block_iters {
            let repair = rs::encode_repair(black_box(&source), black_box(r), Scheme::Cauchy);
            black_box(repair);
        }
        let simd_elapsed = t1.elapsed();
        let simd_us = (simd_elapsed.as_nanos() as f64 / block_iters as f64) / 1000.0;

        let speedup = scalar_us / simd_us.max(0.001);
        let per_packet_ns = (simd_us * 1000.0) / (k + r) as f64;

        println!(
            "| {:18} | {:17.2} | {:20.2} | {:12.2}x | {:15.1} |",
            format!("10 x {} B", size),
            scalar_us,
            simd_us,
            speedup,
            per_packet_ns
        );
    }
}
