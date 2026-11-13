//! Invariant assertion engine and tracking allocators for zero-allocation,
//! bounded-algorithmic-complexity, and lock-freedom verification in yip.

#![deny(clippy::undocumented_unsafe_blocks)]

pub mod alloc;
pub mod steps;
pub mod syscall;

// Provide profile alias for compatibility with design references
pub use syscall as profile;

pub use alloc::{
    get_thread_alloc_count, get_thread_bytes_allocated, get_thread_dealloc_count,
    get_thread_hard_limit_bytes, get_thread_realloc_count, is_tracking_enabled,
    AllocationScopeGuard, TrackingAllocator,
};
pub use steps::{
    get_step_counter, record_algorithmic_step, record_algorithmic_steps, reset_step_counter,
};
pub use syscall::get_thread_rusage;
