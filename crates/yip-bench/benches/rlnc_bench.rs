//! Poly-Vector RLNC & Scaling Microbenchmark (Regime F).
//!
//! Microbenchmarks rateless Random Linear Network Coding (RLNC) over GF(2^8):
//! 1. `RlncEncoder::produce_coded_symbol` across window sizes W in {8, 16, 32} with 1500-byte symbols.
//! 2. `RlncDecoder::consume_coded_symbol` incremental Gaussian elimination across W in {8, 16, 32}.
//! 3. Full block round-trip decode (incremental GE rank 0->W + back-substitution) across W in {8, 16, 32}.
//! 4. Direct comparison against Cauchy Reed–Solomon block encoding (K=W, 1500-byte symbols).

use std::hint::black_box;
use std::time::Instant;

use yip_transport::rlnc::{RlncDecoder, RlncEncoder};
use yip_transport::rs::{self, Scheme};
use yip_transport::rs_simd;

const SYMBOL_SIZE: usize = 1500;
const WINDOW_SIZES: [usize; 3] = [8, 16, 32];

/// Generates deterministic source symbols for a given window size and symbol length.
fn generate_source_symbols(window_size: usize, symbol_len: usize) -> Vec<Vec<u8>> {
    (0..window_size)
        .map(|i| {
            (0..symbol_len)
                .map(|j| ((i * 37 + j * 13 + 7) & 0xff) as u8)
                .collect()
        })
        .collect()
}

/// Pre-generates a sequence of linearly independent coded symbols that bring a decoder to full rank.
fn pregenerate_full_rank_coded_symbols(
    encoder: &RlncEncoder,
    window_size: usize,
    symbol_len: usize,
    base_seed: u32,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut decoder = RlncDecoder::new(window_size, symbol_len);
    let mut coded_symbols = Vec::with_capacity(window_size);
    let mut seed = base_seed;

    while !decoder.is_complete() {
        let (coeffs, coded) = encoder.produce_coded_symbol(seed);
        if decoder.consume_coded_symbol(&coeffs, &coded) {
            coded_symbols.push((coeffs, coded));
        }
        seed = seed.wrapping_add(1);
    }

    assert_eq!(coded_symbols.len(), window_size);
    coded_symbols
}

/// Encodes a single Cauchy Reed–Solomon repair symbol for comparison.
fn encode_single_cauchy_repair_symbol(source: &[Vec<u8>], row_idx: usize, dst: &mut [u8]) {
    dst.fill(0);
    let k = source.len();
    let coefs = rs::repair_row(Scheme::Cauchy, k, row_idx);
    for (src, &c) in source.iter().zip(coefs.iter()) {
        if c == 1 {
            for (d, &s) in dst.iter_mut().zip(src.iter()) {
                *d ^= s;
            }
        } else if c != 0 {
            rs::mul_add_row(c, src, dst);
        }
    }
}

/// Encodes M Cauchy Reed–Solomon repair symbols for comparison.
fn encode_cauchy_block(source: &[Vec<u8>], m: usize) -> Vec<Vec<u8>> {
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
                rs::mul_add_row(c, src, rep);
            }
        }
    }
    repair
}

fn main() {
    println!("================================================================================");
    println!("  YIP Regime F: Poly-Vector RLNC & Scaling Microbenchmark");
    println!("================================================================================");
    println!("CPU Feature Detection:");
    println!("  SSSE3:      {}", rs_simd::ssse3_supported());
    println!("  AVX2:       {}", rs_simd::avx2_supported());
    println!("  AVX-512BW:  {}", rs_simd::avx512bw_supported());
    println!("  GFNI:       {}", rs_simd::gfni_supported());
    println!("  NEON:       {}", rs_simd::neon_supported());
    println!("  WASM SIMD:  {}", rs_simd::wasm_simd_supported());
    println!("--------------------------------------------------------------------------------\n");

    // ─────────────────────────────────────────────────────────────────────────
    // Part 1: Rateless RLNC Encoding (produce_coded_symbol)
    // ─────────────────────────────────────────────────────────────────────────
    println!(
        "### 1. Rateless RLNC Encoding: produce_coded_symbol (Payload: {} B)",
        SYMBOL_SIZE
    );
    println!(
        "| {:<15} | {:<15} | {:>14} | {:>14} | {:>16} | {:>17} |",
        "Window (W)",
        "Symbol Size (B)",
        "Latency (ns)",
        "Latency (µs)",
        "Pkt Rate (Mpps)",
        "Throughput (Gbps)"
    );
    println!(
        "|-----------------|-----------------|----------------|----------------|------------------|-------------------|"
    );

    let mut enc_latencies_ns = Vec::new();

    for &w in &WINDOW_SIZES {
        let sources = generate_source_symbols(w, SYMBOL_SIZE);
        let mut encoder = RlncEncoder::new(w);
        for s in &sources {
            encoder.push_source(s);
        }

        // Warm up
        let mut seed = 1000u32;
        for _ in 0..5_000 {
            let res = encoder.produce_coded_symbol(black_box(seed));
            black_box(res);
            seed = seed.wrapping_add(1);
        }

        let iters = 50_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            let res = encoder.produce_coded_symbol(black_box(seed));
            black_box(res);
            seed = seed.wrapping_add(1);
        }
        let elapsed = t0.elapsed();
        let lat_ns = elapsed.as_nanos() as f64 / iters as f64;
        let lat_us = lat_ns / 1000.0;
        let mpps = 1000.0 / lat_ns;
        let gbps = (SYMBOL_SIZE as f64 * 8.0) / lat_ns;

        enc_latencies_ns.push(lat_ns);

        println!(
            "| {:<15} | {:<15} | {:>11.1} ns | {:>11.3} µs | {:>11.2} Mpps | {:>12.2} Gbps |",
            w, SYMBOL_SIZE, lat_ns, lat_us, mpps, gbps
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // Part 2: Incremental Gaussian Elimination Decoding (consume_coded_symbol)
    // ─────────────────────────────────────────────────────────────────────────
    println!("### 2A. Incremental Gaussian Elimination: Mean Ingestion (0 -> W Rank)");
    println!(
        "| {:<15} | {:<15} | {:>14} | {:>14} | {:>16} | {:>17} |",
        "Window (W)",
        "Symbol Size (B)",
        "Mean Lat (ns)",
        "Mean Lat (µs)",
        "Ingestion (Mpps)",
        "Ingestion (Gbps)"
    );
    println!(
        "|-----------------|-----------------|----------------|----------------|------------------|-------------------|"
    );

    let mut dec_mean_latencies_ns = Vec::new();

    for &w in &WINDOW_SIZES {
        let sources = generate_source_symbols(w, SYMBOL_SIZE);
        let mut encoder = RlncEncoder::new(w);
        for s in &sources {
            encoder.push_source(s);
        }

        let coded_symbols = pregenerate_full_rank_coded_symbols(&encoder, w, SYMBOL_SIZE, 4242);

        // Warm up
        for _ in 0..1_000 {
            let mut decoder = RlncDecoder::new(w, SYMBOL_SIZE);
            for (coeffs, coded) in &coded_symbols {
                decoder.consume_coded_symbol(black_box(coeffs), black_box(coded));
            }
            black_box(decoder);
        }

        let trials = 20_000;
        let t0 = Instant::now();
        for _ in 0..trials {
            let mut decoder = RlncDecoder::new(w, SYMBOL_SIZE);
            for (coeffs, coded) in &coded_symbols {
                decoder.consume_coded_symbol(black_box(coeffs), black_box(coded));
            }
            black_box(decoder);
        }
        let elapsed = t0.elapsed();
        let total_symbols = (trials * w) as f64;
        let mean_lat_ns = elapsed.as_nanos() as f64 / total_symbols;
        let mean_lat_us = mean_lat_ns / 1000.0;
        let mpps = 1000.0 / mean_lat_ns;
        let gbps = (SYMBOL_SIZE as f64 * 8.0) / mean_lat_ns;

        dec_mean_latencies_ns.push(mean_lat_ns);

        println!(
            "| {:<15} | {:<15} | {:>11.1} ns | {:>11.3} µs | {:>11.2} Mpps | {:>12.2} Gbps |",
            w, SYMBOL_SIZE, mean_lat_ns, mean_lat_us, mpps, gbps
        );
    }
    println!();

    println!("### 2B. Incremental GE Ingestion Latency by Rank Stage (First vs Midpoint vs Final)");
    println!(
        "| {:<15} | {:>16} | {:>19} | {:>18} | {:>16} |",
        "Window (W)",
        "Rank 0 (First)",
        "Rank W/2 (Midpoint)",
        "Rank W-1 (Final)",
        "Ratio (Last/1st)"
    );
    println!(
        "|-----------------|------------------|---------------------|--------------------|------------------|"
    );

    for &w in &WINDOW_SIZES {
        let sources = generate_source_symbols(w, SYMBOL_SIZE);
        let mut encoder = RlncEncoder::new(w);
        for s in &sources {
            encoder.push_source(s);
        }

        let coded_symbols = pregenerate_full_rank_coded_symbols(&encoder, w, SYMBOL_SIZE, 9999);
        let mid_idx = w / 2;
        let last_idx = w - 1;

        let iters = 20_000;

        // Rank 0 (first symbol ingestion into empty decoder)
        let t0 = Instant::now();
        for _ in 0..iters {
            let mut decoder = RlncDecoder::new(w, SYMBOL_SIZE);
            decoder.consume_coded_symbol(
                black_box(&coded_symbols[0].0),
                black_box(&coded_symbols[0].1),
            );
            black_box(decoder);
        }
        let lat_first_ns = t0.elapsed().as_nanos() as f64 / iters as f64;

        // Rank mid_idx (ingestion into half-full decoder)
        let mut base_mid_decoder = RlncDecoder::new(w, SYMBOL_SIZE);
        for (coeffs, coded) in &coded_symbols[..mid_idx] {
            base_mid_decoder.consume_coded_symbol(coeffs, coded);
        }
        let t1 = Instant::now();
        for _ in 0..iters {
            let mut decoder = base_mid_decoder.clone();
            decoder.consume_coded_symbol(
                black_box(&coded_symbols[mid_idx].0),
                black_box(&coded_symbols[mid_idx].1),
            );
            black_box(decoder);
        }
        let lat_mid_ns = t1.elapsed().as_nanos() as f64 / iters as f64;

        // Rank last_idx (ingestion into rank W-1 decoder, full pivot traversal)
        let mut base_last_decoder = RlncDecoder::new(w, SYMBOL_SIZE);
        for (coeffs, coded) in &coded_symbols[..last_idx] {
            base_last_decoder.consume_coded_symbol(coeffs, coded);
        }
        let t2 = Instant::now();
        for _ in 0..iters {
            let mut decoder = base_last_decoder.clone();
            decoder.consume_coded_symbol(
                black_box(&coded_symbols[last_idx].0),
                black_box(&coded_symbols[last_idx].1),
            );
            black_box(decoder);
        }
        let lat_last_ns = t2.elapsed().as_nanos() as f64 / iters as f64;

        let ratio = lat_last_ns / lat_first_ns.max(0.001);

        println!(
            "| {:<15} | {:>13.1} ns | {:>16.1} ns | {:>15.1} ns | {:>15.2}x |",
            w, lat_first_ns, lat_mid_ns, lat_last_ns, ratio
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // Part 3: Full Round-Trip Block Decode (Incremental GE + Back-Substitution)
    // ─────────────────────────────────────────────────────────────────────────
    println!("### 3. Full Round-Trip Block Decode (Incremental GE 0->W + Back-Substitution)");
    println!(
        "| {:<12} | {:>14} | {:>16} | {:>16} | {:>16} | {:>14} |",
        "Window (W)",
        "GE Phase (µs)",
        "Back-Sub (µs)",
        "Total Decode (µs)",
        "Goodput (Gbps)",
        "Rate (Mpps)"
    );
    println!(
        "|--------------|----------------|------------------|------------------|------------------|----------------|"
    );

    let mut full_decode_times_us = Vec::new();

    for &w in &WINDOW_SIZES {
        let sources = generate_source_symbols(w, SYMBOL_SIZE);
        let mut encoder = RlncEncoder::new(w);
        for s in &sources {
            encoder.push_source(s);
        }

        let coded_symbols = pregenerate_full_rank_coded_symbols(&encoder, w, SYMBOL_SIZE, 5555);

        // Pre-measure back-sub alone on completed decoder
        let mut full_decoder = RlncDecoder::new(w, SYMBOL_SIZE);
        for (coeffs, coded) in &coded_symbols {
            full_decoder.consume_coded_symbol(coeffs, coded);
        }
        assert!(full_decoder.is_complete());

        let iters = 10_000;

        // Measure Back-Substitution alone
        let t_bs = Instant::now();
        for _ in 0..iters {
            let extracted = full_decoder.extract_source_symbols();
            black_box(extracted);
        }
        let backsub_us = (t_bs.elapsed().as_nanos() as f64 / iters as f64) / 1000.0;

        // Measure GE Phase alone
        let t_ge = Instant::now();
        for _ in 0..iters {
            let mut decoder = RlncDecoder::new(w, SYMBOL_SIZE);
            for (coeffs, coded) in &coded_symbols {
                decoder.consume_coded_symbol(black_box(coeffs), black_box(coded));
            }
            black_box(decoder);
        }
        let ge_us = (t_ge.elapsed().as_nanos() as f64 / iters as f64) / 1000.0;

        // Measure Total Full Block Decode (GE + Back-Substitution)
        let t_tot = Instant::now();
        for _ in 0..iters {
            let mut decoder = RlncDecoder::new(w, SYMBOL_SIZE);
            for (coeffs, coded) in &coded_symbols {
                decoder.consume_coded_symbol(black_box(coeffs), black_box(coded));
            }
            let extracted = decoder.extract_source_symbols();
            black_box(extracted);
        }
        let tot_us = (t_tot.elapsed().as_nanos() as f64 / iters as f64) / 1000.0;
        let tot_ns = tot_us * 1000.0;

        let total_bits = (w * SYMBOL_SIZE * 8) as f64;
        let goodput_gbps = total_bits / tot_ns;
        let rate_mpps = (w as f64 * 1000.0) / tot_ns;

        full_decode_times_us.push(tot_us);

        println!(
            "| {:<12} | {:>11.2} µs | {:>13.2} µs | {:>13.2} µs | {:>13.2} Gbps | {:>11.2} Mpps |",
            w, ge_us, backsub_us, tot_us, goodput_gbps, rate_mpps
        );
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────
    // Part 4: Comparative Analysis: RLNC vs Cauchy Reed–Solomon Block Encoding
    // ─────────────────────────────────────────────────────────────────────────
    println!("### 4A. Single Symbol Generation: 1 RLNC Coded Symbol vs 1 Cauchy RS Repair Symbol");
    println!(
        "| {:<12} | {:>16} | {:>16} | {:>14} | {:>14} | {:>14} |",
        "Window / K",
        "RLNC Coded (ns)",
        "Cauchy Rep (ns)",
        "RLNC (Gbps)",
        "Cauchy (Gbps)",
        "Cost Delta"
    );
    println!(
        "|--------------|------------------|------------------|----------------|----------------|----------------|"
    );

    for (idx, &w) in WINDOW_SIZES.iter().enumerate() {
        let sources = generate_source_symbols(w, SYMBOL_SIZE);
        let mut encoder = RlncEncoder::new(w);
        for s in &sources {
            encoder.push_source(s);
        }

        let rlnc_ns = enc_latencies_ns[idx];
        let rlnc_gbps = (SYMBOL_SIZE as f64 * 8.0) / rlnc_ns;

        let mut cauchy_dst = vec![0u8; SYMBOL_SIZE];
        let iters = 50_000;

        // Warm up Cauchy
        for _ in 0..5_000 {
            encode_single_cauchy_repair_symbol(&sources, 0, &mut cauchy_dst);
        }

        let t0 = Instant::now();
        for _ in 0..iters {
            encode_single_cauchy_repair_symbol(black_box(&sources), 0, black_box(&mut cauchy_dst));
        }
        let cauchy_ns = t0.elapsed().as_nanos() as f64 / iters as f64;
        let cauchy_gbps = (SYMBOL_SIZE as f64 * 8.0) / cauchy_ns;
        let ratio = rlnc_ns / cauchy_ns.max(0.001);

        println!(
            "| {:<12} | {:>13.1} ns | {:>13.1} ns | {:>11.2} Gbps | {:>11.2} Gbps | {:>13.2}x |",
            w, rlnc_ns, cauchy_ns, rlnc_gbps, cauchy_gbps, ratio
        );
    }
    println!();

    println!(
        "### 4B. Block Comparison: RLNC Full Decode vs Cauchy RS Block Encoding (M = 4 Repair)"
    );
    println!(
        "| {:<12} | {:>16} | {:>16} | {:>16} | {:>16} | {:<25} |",
        "Window / K",
        "RLNC Decode (µs)",
        "Cauchy Enc (µs)",
        "RLNC Goodput",
        "Cauchy Goodput",
        "Trade-Off Property"
    );
    println!(
        "|--------------|------------------|------------------|------------------|------------------|---------------------------|"
    );

    let m_repair = 4;
    for (idx, &w) in WINDOW_SIZES.iter().enumerate() {
        let sources = generate_source_symbols(w, SYMBOL_SIZE);
        let rlnc_dec_us = full_decode_times_us[idx];
        let rlnc_goodput_gbps = (w * SYMBOL_SIZE * 8) as f64 / (rlnc_dec_us * 1000.0);

        let iters = 10_000;
        let t0 = Instant::now();
        for _ in 0..iters {
            let repair = encode_cauchy_block(black_box(&sources), m_repair);
            black_box(repair);
        }
        let cauchy_us = (t0.elapsed().as_nanos() as f64 / iters as f64) / 1000.0;
        let cauchy_goodput_gbps = (w * SYMBOL_SIZE * 8) as f64 / (cauchy_us * 1000.0);

        let tradeoff = match w {
            8 => "Rateless / Fountain vs Fixed",
            16 => "Zero-Coord vs Fixed R",
            32 => "Continuous Stream vs Fixed",
            _ => "Rateless vs Fixed MDS",
        };

        println!(
            "| {:<12} | {:>13.2} µs | {:>13.2} µs | {:>13.2} Gbps | {:>13.2} Gbps | {:<25} |",
            w, rlnc_dec_us, cauchy_us, rlnc_goodput_gbps, cauchy_goodput_gbps, tradeoff
        );
    }

    println!("================================================================================");
}
