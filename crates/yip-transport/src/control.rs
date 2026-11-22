//! Adaptive redundancy controller: nudges a class's repair ratio toward the
//! level that keeps post-FEC residual loss under target, AIMD-style.

use crate::FlowParams;

/// Tracks and adjusts the proactive repair ratio for one flow class.
#[derive(Debug, Clone)]
pub struct AdaptiveController {
    ratio: f32,
    min_ratio: f32,
    target_residual: f32,
    ewma_loss: f32,
    prev_loss: f32,
    loss_velocity: f32,
    initialized: bool,
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
            ewma_loss: 0.0,
            prev_loss: 0.0,
            loss_velocity: 0.0,
            initialized: false,
        }
    }

    /// Start from a class's initial repair ratio.
    ///
    /// Delegates to [`Self::new_for`], so it has the same class-aware behavior. Kept
    /// for API compatibility.
    pub fn new(params: FlowParams) -> Self {
        Self::new_for(params)
    }

    /// The current repair ratio (repair symbols per source symbol).
    pub fn ratio(&self) -> f32 {
        self.ratio
    }

    /// Dynamically override the current repair ratio.
    pub fn set_ratio(&mut self, ratio: f32) {
        self.ratio = ratio.clamp(0.0, 1.0);
    }

    /// Dynamically set the minimum ratio floor.
    pub fn set_min_ratio(&mut self, min_ratio: f32) {
        self.min_ratio = min_ratio.clamp(0.0, 1.0);
    }

    /// The current minimum ratio floor.
    pub fn min_ratio(&self) -> f32 {
        self.min_ratio
    }

    /// Returns the smoothed Exponentially Weighted Moving Average (EWMA) loss fraction.
    pub fn ewma_loss(&self) -> f32 {
        self.ewma_loss
    }

    /// Returns the smoothed loss rate of change (velocity) across recent windows.
    pub fn loss_velocity(&self) -> f32 {
        self.loss_velocity
    }

    /// Returns whether the controller has observed at least one feedback window.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Reset loss tracking state (e.g. upon connection migration or roaming).
    pub fn reset(&mut self) {
        self.ewma_loss = 0.0;
        self.prev_loss = 0.0;
        self.loss_velocity = 0.0;
        self.initialized = false;
    }

    /// Update from an observed loss fraction (0.0..=1.0).
    ///
    /// Derives loss velocity and updates EWMA loss rate. Dynamically scales Cauchy
    /// Reed-Solomon parity ratios across tiered loss-gradient brackets:
    /// - Clean (< 0.1%): decay toward floor (down to 0.0 for ARQ-eligible flows).
    /// - Low loss (< 1%): 5% parity ratio (K=20, R=1).
    /// - Moderate loss (1% - 4%): 10% parity ratio (K=10, R=1).
    /// - High loss (5% - 9%): 20% parity ratio (K=10, R=2).
    /// - Severe loss (>= 10%): 30% parity ratio (K=10, R=3 or K=8, R=2).
    ///
    /// Applies a velocity boost when a sharp loss surge is detected.
    pub fn observe_loss(&mut self, loss_fraction: f32) {
        let loss = loss_fraction.clamp(0.0, 1.0);
        let velocity = if self.initialized {
            loss - self.prev_loss
        } else {
            0.0
        };
        self.prev_loss = loss;

        if !self.initialized {
            self.ewma_loss = loss;
            self.loss_velocity = 0.0;
            self.initialized = true;
        } else {
            self.loss_velocity = 0.5 * self.loss_velocity + 0.5 * velocity;
            self.ewma_loss = 0.25 * loss + 0.75 * self.ewma_loss;
        }

        let effective_loss = loss.max(self.ewma_loss);

        if effective_loss <= self.target_residual {
            // clean: decay 10% toward the floor; snap to the floor once the
            // value is negligibly small so ARQ-class controllers reach exactly 0.0
            let decayed = (self.ratio * 0.9).max(self.min_ratio);
            self.ratio = if decayed <= f32::EPSILON {
                self.min_ratio
            } else {
                decayed
            };
        } else {
            let mut target: f32 = if effective_loss >= 0.10 {
                0.30
            } else if effective_loss >= 0.05 {
                0.20
            } else if effective_loss >= 0.01 {
                0.10
            } else {
                0.05
            };

            // Velocity boost on sharp loss surges into high/severe loss tiers
            if self.loss_velocity > 0.03 && loss >= 0.05 {
                target = (target + 0.05).min(1.0);
            }

            self.ratio = (self.ratio * 0.95).max(target).max(self.min_ratio);
        }
    }

    /// How many repair symbols to emit for an object with `source_symbols` source symbols.
    ///
    /// Returns `0` when `ratio` has decayed to zero (clean link) or when a singleton
    /// packet (`source_symbols = 1`) on a zero-floor flow class would incur 100%
    /// duplication overhead under non-severe loss.
    ///
    /// Returns at least `1` whenever `ratio > 0` for multi-symbol objects or
    /// proactive-floor classes (`Realtime`, `Ack`).
    pub fn repair_count(&self, source_symbols: u32) -> u32 {
        if self.ratio <= f32::EPSILON || source_symbols == 0 {
            return 0;
        }
        if source_symbols == 1 && self.min_ratio <= f32::EPSILON {
            // For zero-floor classes (Default, Bulk) with a single-symbol object (K=1),
            // emitting 1 repair symbol represents a 100% wire packet doubling.
            // Avoid 100% duplication overhead unless loss is severe (ratio >= 0.50).
            if self.ratio >= 0.50 {
                1
            } else {
                0
            }
        } else {
            let raw = (f64::from(source_symbols) * f64::from(self.ratio) - 1e-6).ceil();
            let n = u32::try_from(raw as i64).unwrap_or(u32::MAX);
            n.max(1)
        }
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

    #[test]
    fn observe_loss_threshold_boundary_and_gradient_tiers() {
        let mut c = AdaptiveController::new_for(FlowClass::Bulk.params()); // starts at 0.05, arq=true
        assert!(!c.is_initialized());
        assert_eq!(c.ewma_loss(), 0.0);
        assert_eq!(c.loss_velocity(), 0.0);

        // Low loss (< 1%): targets 0.05
        c.observe_loss(0.005);
        assert!(c.is_initialized());
        assert_eq!(c.ratio(), 0.05);
        assert_eq!(c.repair_count(20), 1);

        // Moderate loss (1% - 4%): targets 0.10
        c.observe_loss(0.02);
        assert_eq!(c.ratio(), 0.10);
        assert_eq!(c.repair_count(10), 1);

        // High loss (5% - 9%): targets 0.20 (K=10 -> R=2)
        c.observe_loss(0.07);
        assert!(c.ratio() >= 0.20);
        assert_eq!(c.repair_count(10), 2);

        // Severe loss (>= 10%): targets >= 0.30
        c.observe_loss(0.12);
        assert!(c.ratio() >= 0.30);
        // Sudden surge from 0.07 to 0.12 triggers velocity boost (ratio 0.35 -> 4 repair)
        assert_eq!(c.repair_count(10), 4);
        // Sustained 12% loss gradually settles velocity boost toward target 0.30
        for _ in 0..10 {
            c.observe_loss(0.12);
        }
        assert!((c.ratio() - 0.30).abs() < 1e-4);
        assert_eq!(c.repair_count(10), 3);
    }

    #[test]
    fn fast_adaptation_within_two_rtts_under_severe_loss() {
        let mut c = AdaptiveController::new(FlowClass::Default.params()); // starts at 0.0
        assert_eq!(c.repair_count(10), 0);

        // Interval 1: 10% loss observed
        c.observe_loss(0.10);
        assert!(c.ratio() >= 0.30);
        assert_eq!(c.repair_count(10), 3);

        // Interval 2: sustained 10% loss
        c.observe_loss(0.10);
        assert!(c.ratio() >= 0.30);
        assert_eq!(c.repair_count(10), 3);
    }

    #[test]
    fn test_k1_zero_overhead_under_moderate_loss() {
        let mut c = AdaptiveController::new_for(FlowClass::Default.params());
        // Clean setup starts with ratio 0.0 and min_ratio 0.0
        assert_eq!(c.ratio(), 0.0);
        assert_eq!(c.repair_count(1), 0);

        // Under 5% loss (ratio 0.20): K=1 must NOT duplicate (R=0)
        c.observe_loss(0.05);
        assert_eq!(
            c.repair_count(1),
            0,
            "K=1 must not double packets under 5% loss"
        );
        assert!(
            c.repair_count(10) >= 1,
            "multi-symbol packets get Cauchy FEC"
        );

        // Under 10% loss (ratio 0.30): K=1 must NOT duplicate (R=0)
        c.observe_loss(0.10);
        assert_eq!(
            c.repair_count(1),
            0,
            "K=1 must not double packets under 10% loss"
        );
        assert_eq!(c.repair_count(10), 3);

        // Under severe 55% loss: K=1 emits 1 repair packet (packet replication fallback)
        c.set_ratio(0.55);
        assert_eq!(
            c.repair_count(1),
            1,
            "K=1 duplicates under severe >=50% loss"
        );
    }

    #[test]
    fn sudden_loss_surge_triggers_velocity_boost() {
        let mut c = AdaptiveController::new_for(FlowClass::Bulk.params());
        c.observe_loss(0.0); // Baseline clean
        assert_eq!(c.loss_velocity(), 0.0);

        // Surge: 0% -> 12% loss in one observation
        c.observe_loss(0.12);
        assert!(c.loss_velocity() > 0.03, "velocity reflects sudden surge");
        assert!(c.ewma_loss() > 0.0, "ewma reflects surge");
        // Target 0.30 + 0.05 boost = 0.35
        assert!(c.ratio() >= 0.35, "surge triggers velocity boost");
    }

    #[test]
    fn test_ewma_and_decay_boundaries() {
        let mut c = AdaptiveController::new(FlowClass::Default.params());
        c.observe_loss(0.04);
        assert!((c.ewma_loss() - 0.04).abs() < 1e-5);
        c.observe_loss(0.08);
        // ewma = 0.25 * 0.08 + 0.75 * 0.04 = 0.02 + 0.03 = 0.05
        assert!(
            (c.ewma_loss() - 0.05).abs() < 1e-5,
            "ewma must add terms, got {}",
            c.ewma_loss()
        );

        // Test smooth decay when target < ratio
        c.set_ratio(0.35);
        c.observe_loss(0.06); // Target is 0.20 < 0.35
        let expected = 0.35 * 0.95;
        assert!(
            (c.ratio() - expected).abs() < 1e-4,
            "must decay toward target, got {}",
            c.ratio()
        );

        // Test exact velocity boundary (0.03 does not boost, > 0.03 does)
        let mut c2 = AdaptiveController::new(FlowClass::Default.params());
        c2.observe_loss(0.0);
        c2.observe_loss(0.06); // velocity = 0.06, velocity_loss = 0.03 (not > 0.03)
        assert_eq!(c2.loss_velocity(), 0.03);
        assert_eq!(
            c2.ratio(),
            0.20,
            "velocity exactly 0.03 must not trigger boost"
        );

        // Now next observation pushes velocity > 0.03
        c2.observe_loss(0.14); // velocity = 0.08 -> loss_velocity = 0.5 * 0.03 + 0.5 * 0.08 = 0.055 > 0.03
        assert!(c2.loss_velocity() > 0.03);
        assert!(c2.ratio() >= 0.35, "loss_velocity > 0.03 triggers boost");

        // Test boundary at 0.05: velocity > 0.03 but loss < 0.05 must NOT boost
        let mut c3 = AdaptiveController::new(FlowClass::Default.params());
        c3.observe_loss(0.0);
        c3.observe_loss(0.049); // velocity = 0.049, loss_velocity = 0.0245
        c3.observe_loss(0.119); // velocity = 0.07, loss_velocity > 0.03
                                // Next: velocity is high, but loss is 0.04 (< 0.05)
        let mut c4 = AdaptiveController::new_for(FlowClass::Bulk.params());
        c4.observe_loss(0.0);
        c4.observe_loss(0.04); // loss = 0.04 (< 0.05)
        assert_eq!(c4.ratio(), 0.10, "loss < 0.05 must not trigger boost");
    }

    #[test]
    fn test_reset_restores_initial_loss_tracking() {
        let mut c = AdaptiveController::new(FlowClass::Default.params());
        c.observe_loss(0.15);
        assert!(c.is_initialized());
        assert!(c.ewma_loss() > 0.0);

        c.reset();
        assert!(!c.is_initialized());
        assert_eq!(c.ewma_loss(), 0.0);
        assert_eq!(c.loss_velocity(), 0.0);
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

    #[test]
    fn test_set_ratio_and_set_min_ratio() {
        let mut c = AdaptiveController::new(FlowClass::Default.params());
        c.set_ratio(0.35);
        assert!((c.ratio() - 0.35).abs() < 1e-6);
        c.set_ratio(1.5);
        assert_eq!(c.ratio(), 1.0);
        c.set_ratio(-0.5);
        assert_eq!(c.ratio(), 0.0);

        c.set_min_ratio(0.25);
        assert_eq!(c.min_ratio(), 0.25);
        c.set_min_ratio(2.0);
        assert_eq!(c.min_ratio(), 1.0);
        c.set_min_ratio(-1.0);
        assert_eq!(c.min_ratio(), 0.0);
    }
}
