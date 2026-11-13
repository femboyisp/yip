//! Algorithmic step accounting and complexity bounds enforcement.

use std::cell::Cell;

thread_local! {
    static OPERATION_STEPS: Cell<u64> = const { Cell::new(0) };
}

/// Increments the calling thread's algorithmic step counter by 1.
#[inline(always)]
pub fn record_algorithmic_step() {
    OPERATION_STEPS.with(|s| s.set(s.get().saturating_add(1)));
}

/// Increments the calling thread's algorithmic step counter by the given count.
#[inline(always)]
pub fn record_algorithmic_steps(steps: u64) {
    OPERATION_STEPS.with(|s| s.set(s.get().saturating_add(steps)));
}

/// Resets the calling thread's algorithmic step counter to 0.
#[inline(always)]
pub fn reset_step_counter() {
    OPERATION_STEPS.with(|s| s.set(0));
}

/// Returns the current value of the calling thread's algorithmic step counter.
#[inline(always)]
pub fn get_step_counter() -> u64 {
    OPERATION_STEPS.with(|s| s.get())
}

/// Asserts that the enclosed block executes no more than `max_steps` algorithmic operations.
#[macro_export]
macro_rules! assert_bounded_ops {
    (max_steps = $max:expr, $block:expr) => {{
        $crate::steps::reset_step_counter();
        let result = $block;
        let count = $crate::steps::get_step_counter();
        assert!(
            count <= $max,
            "Algorithmic operation exceeded bound: executed {} steps (expected <= {})",
            count,
            $max
        );
        result
    }};
    ($max:expr, $block:expr) => {{
        $crate::assert_bounded_ops!(max_steps = $max, $block)
    }};
}
