//! #59 FEC-rate experiment: does the Default class's proactive repair actually
//! DECAY on a clean link, or does its non-ARQ floor keep it permanently at
//! ~1 repair per single-symbol object? Drives the real
//! `Transport::observe_loss` clean-link feedback (loss = 0.0) many times, then
//! measures symbols emitted per 1184-byte Default packet (1 source symbol).
//!
//! Run: cargo run --release -p yip-bench --example fec_rate_experiment
use yip_transport::{FlowClass, Transport};

fn measure(clean_reports: u32) -> f64 {
    let mut tx = Transport::new(vec![], 1200);
    // Simulate a sustained clean link: the receiver's periodic (30 ms)
    // LossReport drives observe_loss(Default, 0.0) each interval.
    for _ in 0..clean_reports {
        tx.observe_loss(FlowClass::Default, 0.0);
    }
    // A 1184-byte inner packet -> 1200-byte ciphertext -> exactly 1 source symbol.
    let inner = vec![0xABu8; 1184];
    let ciphertext = vec![0xCDu8; inner.len() + 16];
    let iters = 2000u32;
    let mut nsym = 0usize;
    for _ in 0..iters {
        // Keep the link clean while sending so the ratio stays decayed.
        tx.observe_loss(FlowClass::Default, 0.0);
        let (_c, syms) = tx.encode(&ciphertext, &inner, false, 0);
        nsym += syms.len();
    }
    nsym as f64 / f64::from(iters)
}

fn main() {
    println!("Default class, 1184-byte packet (1 source symbol), after clean-link decay:");
    for reports in [0u32, 10, 50, 200, 1000] {
        let spp = measure(reports);
        println!("  {reports:>5} clean LossReports -> {spp:.3} symbols/packet (datagrams/packet)");
    }
    println!();
    println!("Interpretation: 2.000 = permanent +1 repair (floor never reaches 0);");
    println!("                1.000 = repair decayed to 0 (single datagram per packet).");
}
