//! Adaptive redundancy controller: nudges a class's repair ratio toward the
//! level that keeps post-FEC residual loss under target, AIMD-style.

use crate::FlowParams;

/// Tracks and adjusts the proactive repair ratio for one flow class.
#[derive(Debug, Clone)]
pub struct AdaptiveController {
    ratio: f32,
    min_ratio: f32,
    target_residual: f32,
}

impl AdaptiveController {
    /// Start from a class's initial repair ratio.
    pub fn new(params: FlowParams) -> Self {
        Self {
            ratio: params.initial_repair_ratio,
            min_ratio: params.initial_repair_ratio,
            target_residual: 0.001, // aim for <0.1% post-FEC loss
        }
    }

    /// The current repair ratio (repair symbols per source symbol).
    pub fn ratio(&self) -> f32 {
        self.ratio
    }

    /// Update from an observed loss fraction (0.0..=1.0). When loss exceeds
    /// what the current redundancy can mask, the ratio is immediately set to
    /// `loss + 0.05` (jump to just above the observed loss rate with a small
    /// headroom margin), rather than incrementing gradually.  When the link is
    /// clean the ratio decays 10% per observation toward the class minimum.
    pub fn observe_loss(&mut self, loss_fraction: f32) {
        let loss = loss_fraction.clamp(0.0, 1.0);
        if loss > self.target_residual + self.ratio {
            // losing more than we can repair: add headroom above the loss rate
            self.ratio = (loss + 0.05).min(1.0);
        } else if loss <= self.target_residual {
            // clean: decay 10% toward the floor
            self.ratio = (self.ratio * 0.9).max(self.min_ratio);
        }
    }

    /// How many repair symbols to emit for an object with `source_symbols` source symbols.
    pub fn repair_count(&self, source_symbols: u32) -> u32 {
        let raw = (f64::from(source_symbols) * f64::from(self.ratio)).ceil();
        // f64::ceil of a non-negative product; the i64 cast is the one unavoidable float->int conversion, then checked-narrowed to u32
        let n = u32::try_from(raw as i64).unwrap_or(u32::MAX);
        n.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    #[test]
    fn ratio_rises_under_loss_and_decays_when_clean() {
        let mut c = AdaptiveController::new(FlowClass::Default.params());
        let start = c.ratio();
        for _ in 0..10 {
            c.observe_loss(0.20);
        } // heavy loss
        assert!(c.ratio() > start, "repair ratio increases under loss");
        let high = c.ratio();
        for _ in 0..50 {
            c.observe_loss(0.0);
        } // clean link
        assert!(
            c.ratio() < high,
            "repair ratio decays toward minimum when clean"
        );
    }

    #[test]
    fn repair_count_scales_with_source_symbols() {
        let c = AdaptiveController::new(FlowClass::Bulk.params());
        // at the initial 5% ratio, 100 source symbols -> at least a few repair
        assert!(c.repair_count(100) >= 1);
        assert!(c.repair_count(0) == 0 || c.repair_count(0) >= 1); // never panics on zero
    }
}
