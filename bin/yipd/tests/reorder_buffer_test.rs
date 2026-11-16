//! Tests for the bounded in-order Reorder Buffer (ROB).
#![forbid(unsafe_code)]

use yipd::crypto_pool::reorder::{ReorderBuffer, ReorderError};

#[test]
fn test_reorder_buffer_in_order() {
    let mut rob = ReorderBuffer::<String, 64>::new(0);
    assert_eq!(rob.next_expected_seq(), 0);
    assert_eq!(rob.len(), 0);

    rob.insert(0, "pkt-0".to_string()).unwrap();
    rob.insert(1, "pkt-1".to_string()).unwrap();
    rob.insert(2, "pkt-2".to_string()).unwrap();
    assert_eq!(rob.len(), 3);

    let mut drained = Vec::new();
    let count = rob.drain_contiguous(|seq, item| {
        drained.push((seq, item));
    });

    assert_eq!(count, 3);
    assert_eq!(rob.len(), 0);
    assert_eq!(rob.next_expected_seq(), 3);
    assert_eq!(
        drained,
        vec![
            (0, "pkt-0".to_string()),
            (1, "pkt-1".to_string()),
            (2, "pkt-2".to_string()),
        ]
    );
}

#[test]
fn test_reorder_buffer_out_of_order() {
    let mut rob = ReorderBuffer::<u32, 64>::new(100);

    // Arrive out of order: 102, 100, 103, 101
    rob.insert(102, 200).unwrap();
    rob.insert(100, 0).unwrap();
    rob.insert(103, 300).unwrap();
    rob.insert(101, 100).unwrap();
    assert_eq!(rob.len(), 4);

    let mut drained = Vec::new();
    let count = rob.drain_contiguous(|seq, val| {
        drained.push((seq, val));
    });

    assert_eq!(count, 4);
    assert_eq!(rob.len(), 0);
    assert_eq!(rob.next_expected_seq(), 104);
    assert_eq!(drained, vec![(100, 0), (101, 100), (102, 200), (103, 300)]);
}

#[test]
fn test_reorder_buffer_gapped_drain() {
    let mut rob = ReorderBuffer::<u32, 64>::new(0);

    // Insert 0 and 2 (missing 1)
    rob.insert(0, 10).unwrap();
    rob.insert(2, 30).unwrap();

    let mut drained = Vec::new();
    let count = rob.drain_contiguous(|seq, val| {
        drained.push((seq, val));
    });

    assert_eq!(count, 1);
    assert_eq!(drained, vec![(0, 10)]);
    assert_eq!(rob.next_expected_seq(), 1);
    assert_eq!(rob.len(), 1); // 2 is still buffered

    // Missing packet 1 arrives
    rob.insert(1, 20).unwrap();
    assert_eq!(rob.len(), 2);

    drained.clear();
    let count2 = rob.drain_contiguous(|seq, val| {
        drained.push((seq, val));
    });

    assert_eq!(count2, 2);
    assert_eq!(drained, vec![(1, 20), (2, 30)]);
    assert_eq!(rob.next_expected_seq(), 3);
    assert_eq!(rob.len(), 0);
}

#[test]
fn test_reorder_buffer_stale_and_duplicate_rejected() {
    let mut rob = ReorderBuffer::<&'static str, 32>::new(10);

    rob.insert(10, "ten").unwrap();
    rob.insert(11, "eleven").unwrap();

    // Duplicate insertion
    assert_eq!(
        rob.insert(10, "ten-again"),
        Err(ReorderError::Duplicate(10))
    );

    // Drain
    rob.drain_contiguous(|_, _| {});
    assert_eq!(rob.next_expected_seq(), 12);

    // Stale insertion for seq < next_expected_seq
    assert_eq!(rob.insert(11, "eleven-stale"), Err(ReorderError::Stale(11)));
}

#[test]
fn test_reorder_buffer_window_full() {
    let mut rob = ReorderBuffer::<u32, 8>::new(0);

    // Capacity is 8. seq 0..7 are in-window. seq 8 is out of window.
    rob.insert(7, 70).unwrap();
    assert_eq!(rob.insert(8, 80), Err(ReorderError::Full(8)));

    // Fill the window and check full condition
    for i in 0..7 {
        rob.insert(i, (i * 10) as u32).unwrap();
    }
    assert_eq!(rob.len(), 8);

    // Drain everything
    let count = rob.drain_contiguous(|_, _| {});
    assert_eq!(count, 8);
    assert_eq!(rob.next_expected_seq(), 8);

    // Now 8 is accepted
    assert!(rob.insert(8, 80).is_ok());
}
