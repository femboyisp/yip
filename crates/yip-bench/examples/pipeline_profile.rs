//! Per-stage egress/ingress profile. Run:
//!   cargo run --release -p yip-bench --example pipeline_profile
use std::time::Instant;
use yip_transport::Transport;

fn main() {
    let iters = 5000u32;
    let inner = vec![0xABu8; 1184]; // inner MTU the bench uses
                                    // Stand in for the sealed ciphertext (inner + 16-byte AEAD tag).
    let ciphertext = vec![0xCDu8; inner.len() + 16];

    // Egress: FEC encode (the suspected dominant cost).
    let mut tx = Transport::new(vec![], 1200);
    let t = Instant::now();
    let mut nsym = 0usize;
    for _ in 0..iters {
        let (_c, syms) = tx.encode(&ciphertext, &inner, false, 0);
        nsym += syms.len();
    }
    let enc_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    // Ingress: FEC decode.
    let mut rx = Transport::new(vec![], 1200);
    let t = Instant::now();
    let mut decoded = 0u32;
    for _ in 0..iters {
        let (cls, syms) = tx.encode(&ciphertext, &inner, false, 0);
        for s in &syms {
            if rx.decode(s, cls).is_some() {
                decoded += 1;
                break;
            }
        }
    }
    let encdec_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    let nsym_f = f64::from(u32::try_from(nsym).expect("symbol count fits u32"));
    println!("symbols/packet : {:.2}", nsym_f / f64::from(iters));
    println!("encode         : {enc_us:.1} us/packet");
    println!("decode (approx): {:.1} us/packet", encdec_us - enc_us);
    println!("decoded ok     : {decoded}/{iters}");
}
