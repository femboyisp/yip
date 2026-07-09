//! De-risk spike for throughput 4a (plan-cached FEC). Proves a cached
//! SourceBlockEncodingPlan reused via SourceBlockEncoder::with_encoding_plan is
//! byte-identical to Encoder::new(..).get_encoded_packets(repair), and measures
//! the per-encode cost with a cached plan vs a freshly-built Encoder.
//!
//! Run: cargo run --release -p yip-bench --example plan_cache_spike
use std::collections::HashMap;
use std::time::Instant;

use raptorq::{
    calculate_block_offsets, Encoder, EncodingPacket, ObjectTransmissionInformation,
    SourceBlockEncoder, SourceBlockEncodingPlan,
};

const SYMBOL_SIZE: u16 = 1200;

/// Mirror of raptorq's Encoder::new single-source-block construction: returns the
/// zero-padded block bytes and its source `symbol_count`. Returns None if the OTI
/// implies more than one source block (the cached path does not apply).
fn single_block(ciphertext: &[u8], oti: &ObjectTransmissionInformation) -> Option<(Vec<u8>, u16)> {
    let offsets = calculate_block_offsets(ciphertext, oti);
    if oti.sub_blocks() != 1 || offsets.len() != 1 {
        return None;
    }
    let (start, end) = offsets[0];
    let block: Vec<u8> = if end > ciphertext.len() {
        let mut v = Vec::from(&ciphertext[start..]);
        v.resize(end - start, 0);
        v
    } else {
        ciphertext[start..end].to_vec()
    };
    let sym = usize::from(oti.symbol_size());
    let symbol_count = u16::try_from(block.len() / sym).expect("symbol_count fits u16");
    Some((block, symbol_count))
}

fn cached_encode(
    cache: &mut HashMap<u16, SourceBlockEncodingPlan>,
    ciphertext: &[u8],
    oti: &ObjectTransmissionInformation,
    repair: u32,
) -> Vec<EncodingPacket> {
    let (block, symbol_count) = single_block(ciphertext, oti).expect("single source block");
    let plan = cache
        .entry(symbol_count)
        .or_insert_with(|| SourceBlockEncodingPlan::generate(symbol_count));
    let sbe = SourceBlockEncoder::with_encoding_plan(0, oti, &block, plan);
    sbe.source_packets()
        .into_iter()
        .chain(sbe.repair_packets(0, repair))
        .collect()
}

fn fresh_encode(
    ciphertext: &[u8],
    oti: &ObjectTransmissionInformation,
    repair: u32,
) -> Vec<EncodingPacket> {
    Encoder::new(ciphertext, *oti).get_encoded_packets(repair)
}

fn main() {
    // (a) Byte-identity across sizes (symbol_count 1..3) and repair 1..=8.
    let mut cache = HashMap::new();
    for &len in &[600usize, 1200, 1201, 2400, 3000] {
        let ct: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let oti =
            ObjectTransmissionInformation::with_defaults(u64::try_from(len).unwrap(), SYMBOL_SIZE);
        for repair in 1u32..=8 {
            let a = cached_encode(&mut cache, &ct, &oti, repair);
            let b = fresh_encode(&ct, &oti, repair);
            assert_eq!(a.len(), b.len(), "len differs len={len} repair={repair}");
            for (x, y) in a.iter().zip(b.iter()) {
                assert_eq!(
                    x.serialize(),
                    y.serialize(),
                    "bytes differ len={len} repair={repair}"
                );
            }
        }
    }
    println!("byte-identity: OK (sizes 600..3000, repair 1..=8)");

    // (b) Residual timing: fresh Encoder per call vs cached plan per call.
    // Use the Default-class hot case: ~1300-byte object, repair = 1.
    let ct = vec![0xCDu8; 1300];
    let oti = ObjectTransmissionInformation::with_defaults(1300, SYMBOL_SIZE);
    let iters = 20_000u32;

    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(fresh_encode(&ct, &oti, 1));
    }
    let fresh_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    let mut cache2 = HashMap::new();
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(cached_encode(&mut cache2, &ct, &oti, 1));
    }
    let cached_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    println!("fresh  encode : {fresh_us:.2} us/packet");
    println!("cached encode : {cached_us:.2} us/packet");
    println!("speedup       : {:.1}x", fresh_us / cached_us);
}
