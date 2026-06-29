//! Adaptive RaptorQ-FEC transport: per-flow classification, the adaptive
//! redundancy controller, and thin ARQ. Implemented across M5; this
//! milestone fixes the public surface and the flow taxonomy.
#![forbid(unsafe_code)]

pub mod classify;
pub use classify::{Classifier, PolicyRule};

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

/// The FEC transport: accepts sealed frames, emits decoded frames.
/// Implemented in M5.
pub trait Transport {
    /// Encode and queue a sealed frame for transmission under `class`.
    fn send(&mut self, frame: &[u8], class: FlowClass);
    /// Return the next fully decoded frame, if one is ready.
    fn recv(&mut self) -> Option<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flow_class_is_default() {
        assert_eq!(FlowClass::default(), FlowClass::Default);
    }
}
