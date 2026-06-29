//! Adaptive RaptorQ-FEC transport: per-flow classification, the adaptive
//! redundancy controller, and thin ARQ. Implemented across M5; this
//! milestone fixes the public surface and the flow taxonomy.
#![forbid(unsafe_code)]

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
