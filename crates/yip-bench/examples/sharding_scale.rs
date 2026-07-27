//! Sharding-scale spike, task 1: single-worker (N=1) receive-chain loop.
//!
//! De-risking spike for multi-core sharding (#10). This example reassembles
//! the REAL yip receive chain from the library crates (`yip-crypto`,
//! `yip-wire`, `yip-transport`) — the authoritative reference is
//! `bin/yipd/src/dataplane.rs` (`on_udp_datagram`'s data arm) plus
//! `bin/yipd/src/wire_glue.rs` for how a FEC `Symbol` maps to/from a wire
//! `Frame`. `yip-bench` is a separate crate and cannot import `yipd`'s
//! `DataPlane`, so the `symbol_to_frame`/`frame_to_symbol` glue below is a
//! direct port of `wire_glue.rs` (same field layout, same 12-byte
//! counter+object_size prefix), not a fallback: the full
//! deframe -> parse Symbol -> FEC-decode -> AEAD-open chain runs per packet.
//!
//! Run: `cargo run --release -p yip-bench --example sharding_scale`
//! Test: `cargo test -p yip-bench --example sharding_scale`

use std::time::{Duration, Instant};

use yip_bench::{established_pair, sample_inner};
use yip_crypto::Session;
use yip_transport::{FlowClass, Symbol, Transport};
use yip_wire::{Codec, Frame, WireCodec};

/// A fixed connection tag for this synthetic single-connection worker.
const CONN_TAG: u64 = 1;

/// Build a wire frame for one FEC symbol (port of `yipd`'s
/// `wire_glue::symbol_to_frame`): the AEAD counter and object size ride in
/// the (authenticated) payload prefix; the class rides in flags.
fn symbol_to_frame(conn_tag: u64, sym: &Symbol, counter: u64, class: FlowClass) -> Frame {
    let mut payload = Vec::with_capacity(12 + sym.data.len());
    payload.extend_from_slice(&counter.to_be_bytes());
    payload.extend_from_slice(&sym.object_size.to_be_bytes());
    payload.extend_from_slice(&sym.data);
    Frame {
        conn_tag,
        object_id: sym.object_id,
        payload_id: sym.payload_id,
        flags: class_to_flags(class),
        payload,
    }
}

/// Parse a received frame back into a `(Symbol, counter, class)` (port of
/// `yipd`'s `wire_glue::frame_to_symbol`), or `None` if the payload is
/// shorter than the 12-byte counter+object_size prefix.
fn frame_to_symbol(frame: &Frame) -> Option<(Symbol, u64, FlowClass)> {
    if frame.payload.len() < 12 {
        return None;
    }
    let counter = u64::from_be_bytes(frame.payload[0..8].try_into().ok()?);
    let object_size = u32::from_be_bytes(frame.payload[8..12].try_into().ok()?);
    let sym = Symbol {
        object_id: frame.object_id,
        object_size,
        payload_id: frame.payload_id,
        data: frame.payload[12..].to_vec(),
    };
    Some((sym, counter, flags_to_class(frame.flags)))
}

/// Encode a flow class into the low bits of the frame flags byte.
fn class_to_flags(c: FlowClass) -> u8 {
    match c {
        FlowClass::Realtime => 0,
        FlowClass::Bulk => 1,
        FlowClass::Default => 2,
    }
}

/// Decode the flow class from the frame flags byte.
fn flags_to_class(f: u8) -> FlowClass {
    match f & 0x03 {
        0 => FlowClass::Realtime,
        1 => FlowClass::Bulk,
        _ => FlowClass::Default,
    }
}

/// A fully self-contained receive-chain worker: one AEAD session pair, one
/// wire codec, and one send-side / receive-side FEC transport. No globals,
/// no shared state — later tasks spawn N of these across pinned cores.
struct Worker {
    sender: Session,
    receiver: Session,
    codec: Codec,
    tx: Transport,
    rx: Transport,
}

impl Worker {
    fn new() -> Self {
        let (sender, receiver) = established_pair();
        Worker {
            sender,
            receiver,
            codec: Codec::new([1u8; 16], [2u8; 16]),
            tx: Transport::new(vec![], 1200),
            rx: Transport::new(vec![], 1200),
        }
    }

    /// One fresh-counter roundtrip through the real receive chain:
    /// seal -> FEC-encode -> frame -> deframe -> parse Symbol -> FEC-decode
    /// -> AEAD-open. Each call uses a strictly increasing AEAD counter (own
    /// `Session`, never shared), so the replay window never rejects.
    ///
    /// Returns the number of inner bytes recovered (0 if the chain didn't
    /// produce a decoded frame this call, which should not happen since no
    /// datagrams are dropped here).
    fn step(&mut self, inner: &[u8]) -> usize {
        let sealed = self.sender.seal(inner).expect("seal");
        let (class, symbols) = self.tx.encode(&sealed.ciphertext, inner, false, 0);

        let datagrams: Vec<Vec<u8>> = symbols
            .iter()
            .map(|sym| {
                let frame = symbol_to_frame(CONN_TAG, sym, sealed.counter, class);
                self.codec.frame(&frame)
            })
            .collect();

        let mut recovered_len = 0usize;
        for dg in &datagrams {
            let Ok(frame) = self.codec.deframe(dg) else {
                continue;
            };
            let Some((sym, counter, class)) = frame_to_symbol(&frame) else {
                continue;
            };
            if let Some(ciphertext) = self.rx.decode(&sym, class) {
                if let Ok(inner_bytes) = self.receiver.open(counter, &ciphertext) {
                    recovered_len = inner_bytes.len();
                }
            }
        }
        recovered_len
    }
}

/// Run one worker for `dur`, cycling through `inners`, returning the total
/// number of recovered inner bytes processed in the window.
fn run_worker(inners: &[Vec<u8>], dur: Duration) -> u64 {
    let mut w = Worker::new();
    let deadline = Instant::now() + dur;
    let mut bytes = 0u64;
    let mut i = 0usize;
    while Instant::now() < deadline {
        let inner = &inners[i % inners.len()];
        bytes += w.step(inner) as u64;
        i += 1;
    }
    bytes
}

fn main() {
    // A few hundred distinct payloads so the loop isn't just re-processing
    // one cached packet.
    let inners: Vec<Vec<u8>> = (0..256u32)
        .map(|i| {
            let mut p = sample_inner(1300);
            let l = p.len();
            p[l - 4..].copy_from_slice(&i.to_be_bytes());
            p
        })
        .collect();

    let dur = Duration::from_secs(5);
    let bytes = run_worker(&inners, dur);
    let gbps = (bytes as f64 * 8.0) / dur.as_secs_f64() / 1e9;
    println!("N=1  {gbps:.2} Gbps");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_roundtrips_inner() {
        let mut w = Worker::new();
        let inner = sample_inner(1300);
        assert_eq!(w.step(&inner), inner.len());
    }
}

#[cfg(test)]
mod wrap_check {
    use super::*;

    #[test]
    #[ignore]
    fn wraparound_sanity() {
        let mut w = Worker::new();
        let inner = sample_inner(1300);
        let mut fails = 0u32;
        for i in 0..70_000u32 {
            let r = w.step(&inner);
            if r != inner.len() {
                fails += 1;
                if fails <= 5 {
                    eprintln!("step {i} returned {r}, expected {}", inner.len());
                }
            }
        }
        eprintln!("total fails: {fails} / 70000");
        assert_eq!(fails, 0);
    }
}
