//! #59 measurement spike: how the FEC symbol count per inner packet varies
//! with the inner packet size and the FEC `symbol_size`. Real code path
//! (`yip_transport::Transport::encode`), so the counts are authoritative, not
//! arithmetic. Run:
//!   cargo run --release -p yip-bench --example mtu_symbol_sweep
//!
//! Reports, for each (inner_size, symbol_size): the source-symbol count
//! (= ceil((inner+16)/symbol_size)), the total symbols emitted (source +
//! adaptive FEC repair), and the resulting outer wire bytes per inner packet
//! (symbols x (symbol_size + per-symbol overhead)). Overhead per symbol is the
//! yip-wire frame (HEADER_LEN 15 + TAG_LEN 8 = 23) + obf envelope
//! (MIN_ENVELOPE 11) + IP/UDP (28 v4), a lower bound (ignores Symbol metadata
//! + random obf pad).
use yip_transport::Transport;

const AEAD_TAG: usize = 16; // ChaCha20-Poly1305 tag (Session::seal)
const WIRE_OVERHEAD: usize = 15 + 8; // yip-wire HEADER_LEN + TAG_LEN
const OBF_ENVELOPE: usize = 11; // yip-obf MIN_ENVELOPE (nonce 8 + type 1 + len 2)
const IP_UDP_V4: usize = 28; // 20 IPv4 + 8 UDP

fn main() {
    // A fresh Transport classifies filler as the Default class; its adaptive
    // repair ratio starts at the class default (no observed loss here), so the
    // repair count is the clean-link baseline.
    let inner_sizes = [576usize, 1184, 1400, 1448, 1500, 4000, 8972];
    let symbol_sizes = [1200u16, 1452, 1500, 9000];

    println!(
        "{:>10} {:>11} {:>7} {:>7} {:>6} {:>11} {:>9}",
        "inner", "symbol_size", "source", "total", "repair", "outer_bytes", "overhead%"
    );
    for &inner_size in &inner_sizes {
        let inner = vec![0xABu8; inner_size];
        let ciphertext = vec![0xCDu8; inner_size + AEAD_TAG];
        for &symbol_size in &symbol_sizes {
            let mut tx = Transport::new(vec![], symbol_size);
            let (_class, syms) = tx.encode(&ciphertext, &inner, false, 0);
            let source = ciphertext.len().div_ceil(usize::from(symbol_size));
            let total = syms.len();
            let repair = total.saturating_sub(source);
            let per_symbol = usize::from(symbol_size) + WIRE_OVERHEAD + OBF_ENVELOPE + IP_UDP_V4;
            let outer_bytes = total * per_symbol;
            let overhead_pct = 100.0 * (outer_bytes as f64 - inner_size as f64) / inner_size as f64;
            println!(
                "{inner_size:>10} {symbol_size:>11} {source:>7} {total:>7} {repair:>6} {outer_bytes:>11} {overhead_pct:>8.0}%"
            );
        }
        println!();
    }
}
