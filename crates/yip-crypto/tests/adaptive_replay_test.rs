use yip_crypto::{ReplayProfile, ReplayWindow};

#[test]
fn test_adaptive_replay_profile_sizing_and_promotion() {
    let mut w = ReplayWindow::new_with_profile(ReplayProfile::Standard);
    assert_eq!(w.profile(), ReplayProfile::Standard);

    // Initial packets
    assert!(w.check_and_set(100));
    assert!(w.check_and_set(200));
    assert!(w.check_and_set(1000));

    // Replay of seen packet rejected
    assert!(!w.check_and_set(100));
    assert!(!w.check_and_set(200));

    // Advance to 5000
    assert!(w.check_and_set(5000));
    assert!(!w.check_and_set(1000));

    // Counter too old for Standard profile (8,192 bits):
    // Advance to 15,000
    assert!(w.check_and_set(15_000));
    // 5000 is diff 10,000 >= 8,192 -> rejected as too old
    assert!(!w.check(5000));

    // Now test promotion to HighThroughput
    let mut w2 = ReplayWindow::new_with_profile(ReplayProfile::Standard);
    assert!(w2.check_and_set(10));
    assert!(w2.check_and_set(20));
    assert!(w2.check_and_set(500));

    w2.promote_to_high_throughput();
    assert_eq!(w2.profile(), ReplayProfile::HighThroughput);

    // Past seen packets must STILL be rejected after promotion
    assert!(!w2.check(10));
    assert!(!w2.check(20));
    assert!(!w2.check(500));
    assert!(!w2.check_and_set(500));

    // In-window un-seen counter must be accepted
    assert!(w2.check(400));
    assert!(w2.check_and_set(400));
    assert!(!w2.check(400));

    // Advance by a large jump within HighThroughput window (131,072 bits)
    assert!(w2.check_and_set(50_000));
    // In HighThroughput, diff 49,600 < 131,072, but not seen -> accepted
    assert!(w2.check_and_set(45_000));
    assert!(!w2.check_and_set(45_000));
}
