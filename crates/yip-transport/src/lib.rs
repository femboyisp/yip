//! Adaptive RaptorQ-FEC transport: per-flow classification, the adaptive
//! redundancy controller, and thin ARQ. Implemented across M5; this
//! milestone fixes the public surface and the flow taxonomy.
#![forbid(unsafe_code)]

pub mod classify;
pub use classify::{Classifier, PolicyRule};

pub mod flow;
pub use flow::FlowTable;

pub mod control;
pub use control::AdaptiveController;

pub mod fec;
pub use fec::{FecEncoder, FecReassembler, Symbol};

pub mod feedback;
pub use feedback::{LossReport, MAX_NACK};

pub mod lossdetect;
pub use lossdetect::LossDetector;

pub mod retxbuf;
pub use retxbuf::RetxBuffer;

use std::collections::HashMap;
use std::time::Duration;

/// Latency/reliability class assigned to a flow by the classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowClass {
    /// Latency-critical (games/voice): tiny block, no ARQ.
    Realtime,
    /// Bulk / L2-IXP: larger block, heavier redundancy, ARQ on.
    Bulk,
    /// Baseline when nothing else applies.
    #[default]
    Default,
}

/// Per-class FEC parameters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlowParams {
    /// RaptorQ symbol size for this class (fixed, so it need not be signaled per packet).
    pub symbol_size: u16,
    /// Initial proactive repair fraction (the controller adjusts from here).
    pub initial_repair_ratio: f32,
    /// How long to keep a partially-received object before evicting it.
    pub deadline: Duration,
    /// Whether this class uses reactive ARQ (wired in M6).
    pub arq: bool,
}

impl FlowClass {
    /// Default FEC parameters for this class.
    pub fn params(self) -> FlowParams {
        match self {
            FlowClass::Realtime => FlowParams {
                symbol_size: 1200,
                initial_repair_ratio: 0.15,
                deadline: Duration::from_millis(20),
                arq: false,
            },
            FlowClass::Bulk => FlowParams {
                symbol_size: 1200,
                initial_repair_ratio: 0.05,
                deadline: Duration::from_millis(500),
                arq: true,
            },
            FlowClass::Default => FlowParams {
                symbol_size: 1200,
                initial_repair_ratio: 0.10,
                deadline: Duration::from_millis(100),
                arq: false,
            },
        }
    }
}

/// Map a `FlowClass` to a stable small index for keying arrays / maps.
fn class_index(c: FlowClass) -> usize {
    match c {
        FlowClass::Realtime => 0,
        FlowClass::Bulk => 1,
        FlowClass::Default => 2,
    }
}

/// The FEC transport: classifies, encodes sealed frames into symbols, and
/// reassembles received symbols back into frames.
pub struct Transport {
    classifier: Classifier,
    encoder: FecEncoder,
    controllers: [AdaptiveController; 3],
    reassemblers: HashMap<u8, FecReassembler>,
}

impl Transport {
    /// Build a transport with the given classifier policy rules.
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self {
            classifier: Classifier::new(rules),
            encoder: FecEncoder::new(),
            controllers: [
                AdaptiveController::new_for(FlowClass::Realtime.params()),
                AdaptiveController::new_for(FlowClass::Bulk.params()),
                AdaptiveController::new_for(FlowClass::Default.params()),
            ],
            reassemblers: HashMap::new(),
        }
    }

    /// Classify `inner`, then FEC-encode the sealed `ciphertext` for that class.
    /// `now_ms` is the current wall-clock time in milliseconds, forwarded to the
    /// flow-table heuristic inside the classifier.
    pub fn encode(
        &mut self,
        ciphertext: &[u8],
        inner: &[u8],
        l2: bool,
        now_ms: u64,
    ) -> (FlowClass, Vec<Symbol>) {
        let class = self.classifier.classify(inner, l2, now_ms);
        let params = class.params();
        let source = u32::try_from(ciphertext.len().div_ceil(usize::from(params.symbol_size)))
            .unwrap_or(u32::MAX)
            .max(1);
        let repair = self.controllers[class_index(class)].repair_count(source);
        let syms = self.encoder.encode(ciphertext, params, repair);
        (class, syms)
    }

    /// Feed a received symbol for `class`; returns the frame when its object decodes.
    pub fn decode(&mut self, symbol: &Symbol, class: FlowClass) -> Option<Vec<u8>> {
        let params = class.params();
        let idx = u8::try_from(class_index(class)).expect("3 classes");
        self.reassemblers
            .entry(idx)
            .or_insert_with(|| FecReassembler::new(params.symbol_size, 256))
            .push(symbol)
    }

    /// Generate fresh RaptorQ repair symbols for a previously-sent object,
    /// carrying the ORIGINAL `object_id` so the receiver's existing decoder
    /// can be topped up rather than starting a new one.
    ///
    /// Returns all source + `extra_repair` repair symbols — enough that a
    /// receiver that got zero original symbols can still reconstruct.
    pub fn repair_object(
        &mut self,
        ciphertext: &[u8],
        class: FlowClass,
        object_id: u16,
        extra_repair: u32,
    ) -> Vec<Symbol> {
        let params = class.params();
        self.encoder
            .repair_with_id(ciphertext, params, object_id, extra_repair)
    }

    /// Feed an observed loss fraction into `class`'s controller.
    pub fn observe_loss(&mut self, class: FlowClass, loss: f32) {
        self.controllers[class_index(class)].observe_loss(loss);
    }

    /// Current repair ratio for the `Bulk` class controller.
    ///
    /// Useful for diagnostics: on a clean link this decays to 0.0 (ARQ bypass
    /// fires, no proactive FEC symbols sent for bulk traffic).
    pub fn bulk_repair_ratio(&self) -> f32 {
        self.controllers[class_index(FlowClass::Bulk)].ratio()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flow_class_is_default() {
        assert_eq!(FlowClass::default(), FlowClass::Default);
    }

    #[test]
    fn transport_encodes_classifies_and_decodes_through_loss() {
        let mut tx = Transport::new(vec![]);
        let mut rx = Transport::new(vec![]);
        // a "sealed ciphertext" blob + the inner packet used only for classification
        let ciphertext: Vec<u8> = (0..4000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut inner = vec![0u8; 64];
        inner[0] = 0x45;
        inner[1] = 46 << 2; // DSCP EF -> Realtime
        let (class, mut syms) = tx.encode(&ciphertext, &inner, false, 0);
        assert_eq!(class, FlowClass::Realtime);
        // drop every 6th symbol; decode the rest
        let mut out = None;
        for (i, s) in syms.drain(..).enumerate() {
            if i % 6 == 0 {
                continue;
            }
            if let Some(frame) = rx.decode(&s, class) {
                out = Some(frame);
                break;
            }
        }
        assert_eq!(out.as_deref(), Some(ciphertext.as_slice()));
    }

    #[test]
    fn observe_loss_routes_to_correct_class_controller() {
        let mut t = Transport::new(vec![]);
        // Feed heavy loss to Bulk class; Realtime and Default ratios should be unaffected
        let bulk_ratio_before = t.controllers[class_index(FlowClass::Bulk)].ratio();
        let realtime_ratio_before = t.controllers[class_index(FlowClass::Realtime)].ratio();
        t.observe_loss(FlowClass::Bulk, 0.5);
        let bulk_ratio_after = t.controllers[class_index(FlowClass::Bulk)].ratio();
        let realtime_ratio_after = t.controllers[class_index(FlowClass::Realtime)].ratio();
        assert!(
            bulk_ratio_after > bulk_ratio_before,
            "bulk ratio rises under 50% loss"
        );
        assert_eq!(
            realtime_ratio_after, realtime_ratio_before,
            "realtime ratio unaffected"
        );
    }

    #[test]
    fn decode_late_symbol_returns_none_after_completion() {
        let mut tx = Transport::new(vec![]);
        let mut rx = Transport::new(vec![]);
        let ciphertext: Vec<u8> = (0..1200u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let inner = vec![0u8; 20]; // malformed -> Default class
        let (class, syms) = tx.encode(&ciphertext, &inner, false, 0);
        // Decode to completion
        let mut decoded = false;
        for s in &syms {
            if rx.decode(s, class).is_some() {
                decoded = true;
                break;
            }
        }
        assert!(decoded, "object decoded successfully");
        // Push a late/duplicate symbol after decode: should return None
        let late = rx.decode(&syms[0], class);
        assert!(late.is_none(), "late symbol returns None after completion");
    }

    #[test]
    fn retransmitted_repair_completes_a_missing_object() {
        let mut tx = Transport::new(vec![]);
        let ct = vec![0x33u8; 2400]; // 2 source symbols
        let (cls, syms) = tx.encode(&ct, &ct, false, 0);
        let oid = syms[0].object_id; // the original object's identity
                                     // Deliver only ONE symbol of a 2-source-symbol object; decode stalls.
                                     // (The class emits 3 symbols — 2 source + 1 proactive repair — so
                                     // skipping a single symbol would still leave enough to decode; feed
                                     // exactly one to guarantee the object is genuinely incomplete.)
        let mut rx = Transport::new(vec![]);
        let mut out = None;
        for s in syms.iter().take(1) {
            out = out.or(rx.decode(s, cls));
        }
        assert!(out.is_none(), "one symbol short -> not yet decoded");
        // Retransmit: fresh repair symbols carrying the SAME object_id top up the decoder.
        let repair = tx.repair_object(&ct, cls, oid, 2);
        assert!(
            repair.iter().all(|s| s.object_id == oid),
            "repair reuses object identity"
        );
        for s in &repair {
            out = out.or(rx.decode(s, cls));
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn classify_ipv6_ef_maps_to_realtime() {
        let mut tx = Transport::new(vec![]);
        let ciphertext = vec![0u8; 100];
        // Construct a minimal IPv6 packet with Traffic Class EF (DSCP 46)
        // IPv6 header: version(4b)=6, TC(8b)=0xB8 (DSCP 46 << 2), Flow(20b), ...
        // Byte 0: 0x60 | (TC >> 4), Byte 1: (TC << 4) | ...
        // TC = 46 << 2 = 184 = 0xB8
        // Byte 0 = 0x60 | (0xB8 >> 4) = 0x60 | 0x0B = 0x6B
        // Byte 1 = (0xB8 << 4) & 0xF0 = 0x80
        let mut inner = vec![0u8; 44]; // 40-byte IPv6 header + 4 bytes L4
        inner[0] = 0x6B; // version=6, TC high nibble = 0xB
        inner[1] = 0x80; // TC low nibble = 0x8, flow = 0
        inner[6] = 17; // next header = UDP
                       // dst port at offset 40 + 2 = 42
        inner[42] = 0x13;
        inner[43] = 0x88; // port 5000
        let (class, _syms) = tx.encode(&ciphertext, &inner, false, 0);
        assert_eq!(class, FlowClass::Realtime);
    }
}
