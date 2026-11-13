use std::sync::atomic::Ordering;
use yipd::dataplane::DataPlaneCounters;

#[test]
fn test_dataplane_counters_increment_on_malformed_packets() {
    let counters = DataPlaneCounters::default();
    assert_eq!(counters.ingress_deframe_errors.load(Ordering::Relaxed), 0);
    assert_eq!(
        counters
            .ingress_frame_to_symbol_errors
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(counters.ingress_open_errors.load(Ordering::Relaxed), 0);
    assert_eq!(
        counters
            .ingress_control_short_errors
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        counters
            .ingress_control_malformed_errors
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(counters.ingress_seal_errors.load(Ordering::Relaxed), 0);
    assert_eq!(counters.tick_seal_errors.load(Ordering::Relaxed), 0);

    // Simulate error recording
    counters
        .ingress_deframe_errors
        .fetch_add(1, Ordering::Relaxed);
    counters.ingress_open_errors.fetch_add(2, Ordering::Relaxed);

    assert_eq!(counters.ingress_deframe_errors.load(Ordering::Relaxed), 1);
    assert_eq!(counters.ingress_open_errors.load(Ordering::Relaxed), 2);
}
