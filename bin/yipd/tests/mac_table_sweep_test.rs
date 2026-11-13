#![forbid(unsafe_code)]

use std::alloc::System;
use yip_transport::FlowClass;
use yip_verify::{assert_no_alloc, TrackingAllocator};
use yipd::dataplane::{ClassCounts, SentLog};
use yipd::mac_table::{LearnOrigin, MacTable};

#[global_allocator]
static ALLOC: TrackingAllocator<System> = TrackingAllocator(System);

fn make_mac(b: u8) -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, 0x00, b]
}

#[test]
fn test_mac_table_expired_items_evicted_from_tail_in_ok() {
    let ttl_ms = 1_000;
    let mut table = MacTable::new(16, ttl_ms);
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);

    table.learn(make_mac(1), 10, LearnOrigin::Peer, 100);
    assert!(!table.is_empty());
    table.learn(make_mac(2), 20, LearnOrigin::Peer, 200);
    table.learn(make_mac(3), 30, LearnOrigin::Peer, 300);
    table.learn(make_mac(4), 40, LearnOrigin::Peer, 400);
    table.learn(make_mac(5), 50, LearnOrigin::Peer, 500);
    assert_eq!(table.len(), 5);

    // Exact boundary test: at now_ms = 1100, age = 1000 == ttl_ms, must NOT expire
    table.sweep(1100);
    assert_eq!(table.len(), 5);
    assert!(table.lookup(make_mac(1), 1100).is_some());

    // At now_ms = 1150:
    // mac(1): age = 1050 > 1000 -> expired
    // mac(2): age = 950 <= 1000 -> valid
    table.sweep(1150);
    assert_eq!(table.len(), 4);
    assert!(table.lookup(make_mac(1), 1150).is_none());
    assert!(table.lookup(make_mac(2), 1150).is_some());
    assert!(table.lookup(make_mac(3), 1150).is_some());
    assert!(table.lookup(make_mac(4), 1150).is_some());
    assert!(table.lookup(make_mac(5), 1150).is_some());

    // At now_ms = 1350:
    // mac(2): age = 1150 > 1000 -> expired
    // mac(3): age = 1050 > 1000 -> expired
    // mac(4): age = 950 <= 1000 -> valid
    // Evicts k=2 expired items from tail.
    table.sweep(1350);
    assert_eq!(table.len(), 2);
    assert!(table.lookup(make_mac(2), 1350).is_none());
    assert!(table.lookup(make_mac(3), 1350).is_none());
    assert!(table.lookup(make_mac(4), 1350).is_some());
    assert!(table.lookup(make_mac(5), 1350).is_some());

    // At now_ms = 2000: all remaining items expired
    table.sweep(2000);
    assert_eq!(table.len(), 0);
    assert!(table.is_empty());
}

#[test]
fn test_mac_table_non_expired_items_remain_intact() {
    let ttl_ms = 5_000;
    let mut table = MacTable::new(8, ttl_ms);

    let m1 = make_mac(10);
    let m2 = make_mac(20);
    let m3 = make_mac(30);

    table.learn(m1, 101, LearnOrigin::Peer, 1_000);
    table.learn(m2, 102, LearnOrigin::LocalTap, 1_500);
    table.learn(m3, 103, LearnOrigin::Peer, 2_000);

    // Sweep before expiration: no items should be removed
    table.sweep(4_000);
    assert_eq!(table.len(), 3);

    let e1 = table.lookup(m1, 4_000).expect("m1 must remain");
    assert_eq!(e1.peer_id, 101);
    assert_eq!(e1.last_seen_ms, 1_000);
    assert_eq!(e1.origin, LearnOrigin::Peer);

    let e2 = table.lookup(m2, 4_000).expect("m2 must remain");
    assert_eq!(e2.peer_id, 102);
    assert_eq!(e2.last_seen_ms, 1_500);
    assert_eq!(e2.origin, LearnOrigin::LocalTap);

    let e3 = table.lookup(m3, 4_000).expect("m3 must remain");
    assert_eq!(e3.peer_id, 103);
    assert_eq!(e3.last_seen_ms, 2_000);
    assert_eq!(e3.origin, LearnOrigin::Peer);
}

#[test]
fn test_mac_table_refreshed_items_not_evicted_prematurely() {
    let ttl_ms = 500;
    let mut table = MacTable::new(8, ttl_ms);

    let a = make_mac(1);
    let b = make_mac(2);
    let c = make_mac(3);

    // Initial learn: order (head -> tail) is c -> b -> a
    table.learn(a, 1, LearnOrigin::Peer, 100);
    table.learn(b, 2, LearnOrigin::Peer, 200);
    table.learn(c, 3, LearnOrigin::Peer, 300);

    // Refresh 'a' at t=400: 'a' moves to front (head).
    // New order: a (400) -> c (300) -> b (200, tail)
    table.learn(a, 1, LearnOrigin::Peer, 400);

    // At now_ms = 750:
    // b: age = 550 > 500 -> expired
    // c: age = 450 <= 500 -> valid
    // a: age = 350 <= 500 -> valid (would have been age 650 without refresh)
    table.sweep(750);
    assert_eq!(table.len(), 2);
    assert!(table.lookup(b, 750).is_none(), "b must be evicted");
    assert!(table.lookup(c, 750).is_some(), "c must remain intact");
    assert!(
        table.lookup(a, 750).is_some(),
        "refreshed a must not be evicted prematurely"
    );

    // At now_ms = 850:
    // c: age = 550 > 500 -> expired
    // a: age = 450 <= 500 -> valid
    table.sweep(850);
    assert_eq!(table.len(), 1);
    assert!(table.lookup(c, 850).is_none(), "c must be evicted");
    assert!(table.lookup(a, 850).is_some(), "refreshed a still valid");

    // At now_ms = 950:
    // a: age = 550 > 500 -> expired
    table.sweep(950);
    assert_eq!(table.len(), 0);
    assert!(table.is_empty());
}

#[test]
fn test_mac_table_sweep_zero_heap_allocations_when_warm() {
    let capacity = 64;
    let ttl_ms = 1_000;
    let mut table = MacTable::new(capacity, ttl_ms);

    // 1. Warm-up: populate to capacity and sweep to pre-allocate internal structures
    for i in 0..u8::try_from(capacity).unwrap() {
        table.learn(make_mac(i), u64::from(i), LearnOrigin::Peer, 100);
    }
    table.sweep(2_000);
    assert_eq!(table.len(), 0);

    // Re-populate table
    for i in 0..u8::try_from(capacity).unwrap() {
        table.learn(
            make_mac(i),
            u64::from(i),
            LearnOrigin::Peer,
            1_000 + u64::from(i),
        );
    }
    assert_eq!(table.len(), capacity);

    // 2. Assert zero heap allocations on sweep with no expired items
    assert_no_alloc!({
        table.sweep(1_050);
    });
    assert_eq!(table.len(), capacity);

    // 3. Assert zero heap allocations on sweep evicting half the items from tail
    let half = capacity / 2;
    let sweep_time = 1_000 + (half as u64) + ttl_ms;
    assert_no_alloc!({
        table.sweep(sweep_time);
    });
    assert_eq!(table.len(), capacity - half);

    // 4. Assert zero heap allocations on sweep evicting all remaining items
    assert_no_alloc!({
        table.sweep(sweep_time + ttl_ms + 1_000);
    });
    assert_eq!(table.len(), 0);
    assert!(table.is_empty());

    // 5. Assert zero heap allocations on sweep when table is already empty
    assert_no_alloc!({
        table.sweep(100_000);
    });
}

#[test]
fn test_sent_log_binary_search_monotonic_range_zero_alloc() {
    let capacity = 128;
    let empty_log = SentLog::new(10);
    assert!(empty_log.is_empty());
    assert_eq!(empty_log.len(), 0);

    let mut log = SentLog::new(capacity);

    // Warm-up: populate log to trigger wrapped buffer state
    for i in 1..=200u64 {
        let class = match i % 3 {
            0 => FlowClass::Realtime,
            1 => FlowClass::Bulk,
            _ => FlowClass::Default,
        };
        log.insert(i, class);
    }
    assert!(!log.is_empty());
    assert_eq!(log.len(), capacity);

    // Inverted range check: start > end must return default counts immediately
    assert_eq!(log.count_classes_in_range(150, 100), ClassCounts::default());

    // Single item range check: start == end
    let single = log.count_classes_in_range(100, 100);
    assert_eq!(
        single,
        ClassCounts {
            realtime: 0,
            bulk: 1, // 100 % 3 == 1
            default: 0,
        }
    );

    // Assert zero allocations on monotonic binary-search count queries
    for _ in 0..50 {
        assert_no_alloc!({
            let counts = log.count_classes_in_range(100, 150);
            assert!(counts.realtime + counts.bulk + counts.default > 0);
        });
    }

    // Verify correct counts matching exact manual scan
    let expected_realtime = (100..=150).filter(|c| c % 3 == 0).count() as u32;
    let expected_bulk = (100..=150).filter(|c| c % 3 == 1).count() as u32;
    let expected_default = (100..=150).filter(|c| c % 3 == 2).count() as u32;

    let actual = log.count_classes_in_range(100, 150);
    assert_eq!(
        actual,
        ClassCounts {
            realtime: expected_realtime,
            bulk: expected_bulk,
            default: expected_default,
        }
    );
}
