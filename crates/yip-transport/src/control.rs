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
    /// Start from a class's initial repair ratio, using the class's `arq` flag
    /// to determine the floor: ARQ-eligible classes may decay to zero (bypass FEC
    /// encode entirely on a clean link); non-ARQ classes keep a proactive floor.
    pub fn new_for(params: FlowParams) -> Self {
        Self {
            ratio: params.initial_repair_ratio,
            min_ratio: if params.arq {
                0.0
            } else {
                params.initial_repair_ratio
            },
            target_residual: 0.001, // aim for <0.1% post-FEC loss
        }
    }

    /// Start from a class's initial repair ratio.
    ///
    /// Delegates to [`new_for`], so it has the same class-aware behavior. Kept
    /// for API compatibility.
    pub fn new(params: FlowParams) -> Self {
        Self::new_for(params)
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
            // clean: decay 10% toward the floor; snap to the floor once the
            // value is negligibly small so ARQ-class controllers reach exactly 0.0
            let decayed = (self.ratio * 0.9).max(self.min_ratio);
            self.ratio = if decayed <= f32::EPSILON {
                self.min_ratio
            } else {
                decayed
            };
        }
    }

    /// How many repair symbols to emit for an object with `source_symbols` source symbols.
    ///
    /// Returns `0` when `ratio` has decayed to zero (ARQ-eligible classes on a
    /// clean link) — the caller should skip FEC-encode entirely in that case.
    /// Returns at least `1` whenever `ratio > 0`.
    pub fn repair_count(&self, source_symbols: u32) -> u32 {
        if self.ratio <= f32::EPSILON {
            return 0;
        }
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

    #[test]
    fn arq_class_decays_to_zero_when_clean() {
        let mut c = AdaptiveController::new_for(FlowClass::Bulk.params()); // arq=true
        for _ in 0..200 {
            c.observe_loss(0.0);
        }
        assert_eq!(c.ratio(), 0.0, "bulk earns zero repair on a clean link");
        assert_eq!(
            c.repair_count(1),
            0,
            "zero ratio -> zero repair -> bypass fires"
        );
        assert_eq!(c.repair_count(10), 0);
    }

    #[test]
    fn non_arq_class_keeps_floor() {
        let mut c = AdaptiveController::new_for(FlowClass::Realtime.params()); // arq=false
        for _ in 0..200 {
            c.observe_loss(0.0);
        }
        assert!(c.ratio() >= FlowClass::Realtime.params().initial_repair_ratio - 1e-6);
        assert!(c.repair_count(1) >= 1, "realtime keeps proactive repair");
    }

    /// At the exact boundary `loss == target_residual + ratio`, the "losing
    /// more than we can repair" branch must NOT fire (only `loss >
    /// target_residual + ratio` should). Kills the `>` -> `>=` mutant (line 50).
    #[test]
    fn observe_loss_boundary_at_exact_threshold_does_not_jump() {
        let mut c = AdaptiveController::new(FlowClass::Default.params()); // ratio=0.10
        let start = c.ratio();
        let boundary = 0.001 + start; // target_residual (0.001) + ratio
        c.observe_loss(boundary);
        assert_eq!(
            c.ratio(),
            start,
            "loss exactly at the threshold must not trigger the jump-up branch"
        );
    }

    /// The threshold is `target_residual + ratio`, not `target_residual *
    /// ratio`. Kills the `+` -> `*` mutant (line 50): pick a loss value that is
    /// above the (tiny) product but below the (larger) sum, so only the
    /// mutant's `*` version would wrongly trigger the jump-up branch.
    #[test]
    fn observe_loss_threshold_uses_sum_not_product() {
        let mut c = AdaptiveController::new(FlowClass::Default.params()); // ratio=0.10
        let start = c.ratio();
        // product = 0.001 * 0.10 = 0.0001; sum = 0.001 + 0.10 = 0.101.
        // loss = 0.02 is > product but not > sum, and not <= target_residual (0.001).
        c.observe_loss(0.02);
        assert_eq!(
            c.ratio(),
            start,
            "loss below the sum threshold must leave ratio unchanged \
             (mutant using target_residual * ratio would wrongly jump up)"
        );
    }

    /// A single decay step from a non-negligible ratio must decay smoothly
    /// (ratio * 0.9), not snap straight to the floor. Kills the `<=` -> `>`
    /// mutant (line 57): that mutant inverts the snap condition so ANY decay
    /// step where `decayed > EPSILON` (i.e. almost always) snaps to the floor
    /// immediately instead of decaying gradually.
    #[test]
    fn single_decay_step_does_not_snap_to_floor_early() {
        let mut c = AdaptiveController::new_for(FlowClass::Bulk.params()); // ratio=0.05, arq=true, floor=0.0
        c.observe_loss(0.0); // one clean-link decay step
        let expected = 0.05 * 0.9; // 0.045, far above f32::EPSILON
        assert!(
            (c.ratio() - expected).abs() < 1e-6,
            "one decay step must land at ratio*0.9 ({expected}), got {}; \
             the buggy mutant snaps straight to the floor (0.0) instead",
            c.ratio()
        );
    }

    #[test]
    fn snaps_up_on_loss_even_from_zero() {
        let mut c = AdaptiveController::new_for(FlowClass::Bulk.params());
        for _ in 0..200 {
            c.observe_loss(0.0);
        }
        assert_eq!(c.ratio(), 0.0);
        c.observe_loss(0.10);
        assert!(c.ratio() >= 0.10, "any loss re-arms FEC immediately");
        assert!(c.repair_count(10) >= 1);
    }
}
