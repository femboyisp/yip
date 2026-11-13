use std::alloc::System;
use yip_verify::{
    assert_bounded_ops, assert_no_alloc, assert_no_blocking_io, get_step_counter,
    get_thread_alloc_count, get_thread_bytes_allocated, get_thread_dealloc_count,
    get_thread_hard_limit_bytes, is_tracking_enabled, record_algorithmic_step,
    record_algorithmic_steps, reset_step_counter, AllocationScopeGuard, TrackingAllocator,
};

#[global_allocator]
static GLOBAL: TrackingAllocator<System> = TrackingAllocator(System);

#[test]
fn test_assert_no_alloc_passes_on_stack_operations() {
    assert_no_alloc!({
        let mut arr = [0u8; 1024];
        arr[0] = 42;
        assert_eq!(arr[0], 42);
    });
}

#[test]
#[should_panic(expected = "heap allocations")]
fn test_assert_no_alloc_panics_on_vector_allocation() {
    assert_no_alloc!({
        let mut v = vec![1u8, 2, 3, 4];
        v.push(5);
        assert_eq!(v.len(), 5);
    });
}

#[test]
#[should_panic(expected = "reallocations")]
fn test_assert_no_alloc_panics_on_realloc() {
    let mut v = Vec::with_capacity(2);
    v.push(1);
    v.push(2);
    assert_no_alloc!({
        v.push(3);
    });
}

#[test]
fn test_allocation_scope_guard_tracks_metrics() {
    let guard = AllocationScopeGuard::enter();
    assert!(is_tracking_enabled());
    assert_eq!(get_thread_alloc_count(), 0);
    assert_eq!(get_thread_dealloc_count(), 0);
    assert_eq!(get_thread_hard_limit_bytes(), None);
    let boxed = Box::new(99u64);
    assert_eq!(*boxed, 99);
    assert_eq!(get_thread_alloc_count(), 1);
    assert_eq!(get_thread_dealloc_count(), 0);
    assert!(get_thread_bytes_allocated() >= 8);
    drop(boxed);
    assert_eq!(get_thread_dealloc_count(), 1);
    drop(guard);
    assert!(!is_tracking_enabled());
}

#[test]
fn test_allocation_scope_guard_enter_with_limit_ok() {
    let _guard = AllocationScopeGuard::enter_with_limit(1024);
    assert_eq!(get_thread_hard_limit_bytes(), Some(1024));
    let mut v = vec![1u8, 2, 3, 4];
    v.push(5);
    assert_eq!(v.len(), 5);
}

#[test]
fn test_allocation_scope_guard_limit_exceeded_try_reserve() {
    let _guard = AllocationScopeGuard::enter_with_limit(16);
    let mut v: Vec<u8> = Vec::new();
    let res = v.try_reserve_exact(4096);
    assert!(res.is_err());
}

#[test]
fn test_nested_scope_guard_restores_state() {
    assert!(!is_tracking_enabled());
    {
        let _outer = AllocationScopeGuard::enter();
        assert!(is_tracking_enabled());
        {
            let _inner = AllocationScopeGuard::enter();
            assert!(is_tracking_enabled());
        }
        assert!(is_tracking_enabled());
    }
    assert!(!is_tracking_enabled());
}

#[test]
fn test_assert_bounded_ops_tracks_steps() {
    assert_bounded_ops!(max_steps = 10, {
        for _ in 0..5 {
            record_algorithmic_step();
        }
    });
}

#[test]
fn test_assert_bounded_ops_shorthand_syntax() {
    assert_bounded_ops!(10, {
        record_algorithmic_steps(5);
    });
}

#[test]
#[should_panic(expected = "exceeded bound")]
fn test_assert_bounded_ops_panics_when_exceeded() {
    assert_bounded_ops!(max_steps = 3, {
        for _ in 0..5 {
            record_algorithmic_step();
        }
    });
}

#[test]
fn test_steps_reset_and_manual_recording() {
    reset_step_counter();
    assert_eq!(get_step_counter(), 0);
    record_algorithmic_step();
    assert_eq!(get_step_counter(), 1);
    record_algorithmic_steps(4);
    assert_eq!(get_step_counter(), 5);
    reset_step_counter();
    assert_eq!(get_step_counter(), 0);
}

#[test]
fn test_assert_no_blocking_io_passes_on_cpu_work() {
    assert_no_blocking_io!({
        let mut sum = 0u64;
        for i in 0..10_000 {
            sum = sum.wrapping_add(i);
        }
        assert!(sum > 0);
    });
}

#[test]
#[cfg(target_os = "linux")]
#[should_panic(expected = "Voluntary context switch detected")]
fn test_assert_no_blocking_io_panics_on_blocking_sleep() {
    assert_no_blocking_io!({
        std::thread::sleep(std::time::Duration::from_millis(10));
    });
}
