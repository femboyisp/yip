use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static TRACKING_ENABLED: Cell<bool> = const { Cell::new(false) };
    static ALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
    static REALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
    static DEALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
    static BYTES_ALLOCATED: Cell<u64> = const { Cell::new(0) };
    static HARD_LIMIT_BYTES: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Global tracking allocator wrapping an inner allocator with thread-local instrumentation.
pub struct TrackingAllocator<A = System>(pub A);

impl<A> TrackingAllocator<A> {
    /// Creates a new tracking allocator wrapping the provided inner allocator.
    #[inline]
    pub const fn new(inner: A) -> Self {
        Self(inner)
    }
}

impl Default for TrackingAllocator<System> {
    #[inline]
    fn default() -> Self {
        Self(System)
    }
}

// SAFETY: TrackingAllocator forwards all allocation and deallocation operations
// directly to the underlying GlobalAlloc instance, adding thread-local bookkeeping
// without violating any memory invariants.
unsafe impl<A: GlobalAlloc> GlobalAlloc for TrackingAllocator<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TRACKING_ENABLED.with(|enabled| {
            if enabled.get() {
                // Reentrancy guard: temporarily disable tracking during accounting
                enabled.set(false);
                let current_bytes = BYTES_ALLOCATED.get();
                let requested = layout.size() as u64;
                if let Some(limit) = HARD_LIMIT_BYTES.get() {
                    if current_bytes.saturating_add(requested) > limit {
                        enabled.set(true);
                        return std::ptr::null_mut();
                    }
                }
                ALLOC_COUNT.set(ALLOC_COUNT.get().saturating_add(1));
                BYTES_ALLOCATED.set(current_bytes.saturating_add(requested));
                enabled.set(true);
            }
            // SAFETY: Caller guarantees layout has valid non-zero characteristics for the underlying allocator.
            unsafe { self.0.alloc(layout) }
        })
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        TRACKING_ENABLED.with(|enabled| {
            if enabled.get() {
                enabled.set(false);
                let current_bytes = BYTES_ALLOCATED.get();
                let requested = new_size as u64;
                if let Some(limit) = HARD_LIMIT_BYTES.get() {
                    if current_bytes.saturating_add(requested) > limit {
                        enabled.set(true);
                        return std::ptr::null_mut();
                    }
                }
                REALLOC_COUNT.set(REALLOC_COUNT.get().saturating_add(1));
                BYTES_ALLOCATED.set(current_bytes.saturating_add(requested));
                enabled.set(true);
            }
            // SAFETY: Caller guarantees ptr was allocated by this allocator with layout, and new_size is valid.
            unsafe { self.0.realloc(ptr, layout, new_size) }
        })
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        TRACKING_ENABLED.with(|enabled| {
            if enabled.get() {
                DEALLOC_COUNT.set(DEALLOC_COUNT.get().saturating_add(1));
            }
            // SAFETY: Caller guarantees ptr was allocated by this allocator with layout.
            unsafe { self.0.dealloc(ptr, layout) }
        });
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        TRACKING_ENABLED.with(|enabled| {
            if enabled.get() {
                enabled.set(false);
                let current_bytes = BYTES_ALLOCATED.get();
                let requested = layout.size() as u64;
                if let Some(limit) = HARD_LIMIT_BYTES.get() {
                    if current_bytes.saturating_add(requested) > limit {
                        enabled.set(true);
                        return std::ptr::null_mut();
                    }
                }
                ALLOC_COUNT.set(ALLOC_COUNT.get().saturating_add(1));
                BYTES_ALLOCATED.set(current_bytes.saturating_add(requested));
                enabled.set(true);
            }
            // SAFETY: Caller guarantees layout has valid non-zero characteristics for the underlying allocator.
            unsafe { self.0.alloc_zeroed(layout) }
        })
    }
}

/// RAII guard enabling allocation tracking on the current thread for its lifetime.
#[derive(Debug)]
pub struct AllocationScopeGuard {
    prev_enabled: bool,
    prev_limit: Option<u64>,
}

impl AllocationScopeGuard {
    /// Enters a zero-allocation tracking scope, resetting current thread allocation counters.
    #[inline]
    pub fn enter() -> Self {
        let prev_enabled = TRACKING_ENABLED.with(|e| {
            let prev = e.get();
            ALLOC_COUNT.with(|c| c.set(0));
            REALLOC_COUNT.with(|c| c.set(0));
            DEALLOC_COUNT.with(|c| c.set(0));
            BYTES_ALLOCATED.with(|b| b.set(0));
            e.set(true);
            prev
        });
        let prev_limit = HARD_LIMIT_BYTES.with(|l| l.replace(None));
        Self {
            prev_enabled,
            prev_limit,
        }
    }

    /// Enters a tracking scope with a hard allocation byte limit for chaos and bounds verification.
    #[inline]
    pub fn enter_with_limit(limit_bytes: u64) -> Self {
        let prev_enabled = TRACKING_ENABLED.with(|e| {
            let prev = e.get();
            ALLOC_COUNT.with(|c| c.set(0));
            REALLOC_COUNT.with(|c| c.set(0));
            DEALLOC_COUNT.with(|c| c.set(0));
            BYTES_ALLOCATED.with(|b| b.set(0));
            e.set(true);
            prev
        });
        let prev_limit = HARD_LIMIT_BYTES.with(|l| l.replace(Some(limit_bytes)));
        Self {
            prev_enabled,
            prev_limit,
        }
    }
}

impl Drop for AllocationScopeGuard {
    #[inline]
    fn drop(&mut self) {
        TRACKING_ENABLED.with(|e| e.set(self.prev_enabled));
        HARD_LIMIT_BYTES.with(|l| l.set(self.prev_limit));
    }
}

/// Returns the number of heap allocations observed on the calling thread during the active scope.
#[inline]
pub fn get_thread_alloc_count() -> u64 {
    ALLOC_COUNT.with(|c| c.get())
}

/// Returns the number of reallocations observed on the calling thread during the active scope.
#[inline]
pub fn get_thread_realloc_count() -> u64 {
    REALLOC_COUNT.with(|c| c.get())
}

/// Returns the number of deallocations observed on the calling thread during the active scope.
#[inline]
pub fn get_thread_dealloc_count() -> u64 {
    DEALLOC_COUNT.with(|c| c.get())
}

/// Returns the cumulative heap bytes allocated on the calling thread during the active scope.
#[inline]
pub fn get_thread_bytes_allocated() -> u64 {
    BYTES_ALLOCATED.with(|b| b.get())
}

/// Returns the active hard limit in bytes on the calling thread, if any.
#[inline]
pub fn get_thread_hard_limit_bytes() -> Option<u64> {
    HARD_LIMIT_BYTES.with(|l| l.get())
}

/// Returns true if allocation tracking is currently enabled on the calling thread.
#[inline]
pub fn is_tracking_enabled() -> bool {
    TRACKING_ENABLED.with(|e| e.get())
}

/// Asserts that the enclosed block performs zero heap allocations or reallocations on the executing thread.
#[macro_export]
macro_rules! assert_no_alloc {
    ($block:expr) => {{
        let _guard = $crate::alloc::AllocationScopeGuard::enter();
        let result = $block;
        drop(_guard);
        let allocs = $crate::alloc::get_thread_alloc_count();
        let reallocs = $crate::alloc::get_thread_realloc_count();
        let bytes = $crate::alloc::get_thread_bytes_allocated();
        assert_eq!(
            allocs + reallocs,
            0,
            "Detected {} heap allocations and {} reallocations (totaling {} bytes) on zero-alloc hotpath",
            allocs,
            reallocs,
            bytes
        );
        result
    }};
}
