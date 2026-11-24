use yipd::crypto_pool::reorder::{ReorderBuffer, ReorderError};

#[test]
fn test_reorder_buffer_in_order_insertion_and_drain() {
    let mut rob = ReorderBuffer::<String, 64>::new(0);
    assert_eq!(rob.next_expected_seq(), 0);
    assert!(rob.is_empty());

    rob.insert(0, "packet-0".to_string()).unwrap();
    rob.insert(1, "packet-1".to_string()).unwrap();
    rob.insert(2, "packet-2".to_string()).unwrap();

    assert_eq!(rob.len(), 3);
    assert_eq!(rob.next_expected_seq(), 0);

    let mut drained = Vec::new();
    let count = rob.drain_contiguous(|seq, item| {
        drained.push((seq, item));
    });

    assert_eq!(count, 3);
    assert_eq!(rob.len(), 0);
    assert!(rob.is_empty());
    assert_eq!(rob.next_expected_seq(), 3);
    assert_eq!(
        drained,
        vec![
            (0, "packet-0".to_string()),
            (1, "packet-1".to_string()),
            (2, "packet-2".to_string()),
        ]
    );
}

#[test]
fn test_reorder_buffer_out_of_order_insertion() {
    let mut rob = ReorderBuffer::<u32, 16>::new(100);

    // Insert out of order: 102, 100, 103, 101
    rob.insert(102, 1020).unwrap();
    rob.insert(100, 1000).unwrap();
    rob.insert(103, 1030).unwrap();
    rob.insert(101, 1010).unwrap();

    let mut drained = Vec::new();
    let count = rob.drain_contiguous(|seq, item| {
        drained.push((seq, item));
    });

    assert_eq!(count, 4);
    assert_eq!(
        drained,
        vec![(100, 1000), (101, 1010), (102, 1020), (103, 1030)]
    );
    assert_eq!(rob.next_expected_seq(), 104);
}

#[test]
fn test_reorder_buffer_partial_drain_when_gap_exists() {
    let mut rob = ReorderBuffer::<u32, 16>::new(0);

    // Insert 0, 1, 3 (gap at 2)
    rob.insert(0, 10).unwrap();
    rob.insert(1, 11).unwrap();
    rob.insert(3, 13).unwrap();

    let mut drained = Vec::new();
    let count = rob.drain_contiguous(|seq, item| {
        drained.push((seq, item));
    });

    // Only 0 and 1 should drain; 3 remains buffered
    assert_eq!(count, 2);
    assert_eq!(drained, vec![(0, 10), (1, 11)]);
    assert_eq!(rob.len(), 1);
    assert_eq!(rob.next_expected_seq(), 2);

    // Now insert the missing packet 2
    rob.insert(2, 12).unwrap();
    assert_eq!(rob.len(), 2);

    drained.clear();
    let count2 = rob.drain_contiguous(|seq, item| {
        drained.push((seq, item));
    });

    assert_eq!(count2, 2);
    assert_eq!(drained, vec![(2, 12), (3, 13)]);
    assert_eq!(rob.len(), 0);
    assert_eq!(rob.next_expected_seq(), 4);
}

#[test]
fn test_reorder_buffer_stale_and_duplicate_rejection() {
    let mut rob = ReorderBuffer::<u32, 16>::new(10);

    rob.insert(10, 100).unwrap();
    let _ = rob.drain_contiguous(|_, _| {});
    assert_eq!(rob.next_expected_seq(), 11);

    // Stale sequence (seq < head)
    let err_stale = rob.insert(9, 90).unwrap_err();
    assert_eq!(
        err_stale,
        ReorderError::StaleSequence {
            seq: 9,
            expected: 11
        }
    );

    let err_stale_10 = rob.insert(10, 100).unwrap_err();
    assert_eq!(
        err_stale_10,
        ReorderError::StaleSequence {
            seq: 10,
            expected: 11
        }
    );

    // Duplicate sequence
    rob.insert(12, 120).unwrap();
    let err_dup = rob.insert(12, 121).unwrap_err();
    assert_eq!(err_dup, ReorderError::DuplicateSequence { seq: 12 });
}

#[test]
fn test_reorder_buffer_capacity_overflow() {
    let mut rob = ReorderBuffer::<u32, 4>::new(0);

    // Capacity is 4: valid sequences are 0, 1, 2, 3
    rob.insert(3, 30).unwrap();

    let err_overflow = rob.insert(4, 40).unwrap_err();
    assert_eq!(
        err_overflow,
        ReorderError::BufferFull {
            seq: 4,
            max_capacity: 4
        }
    );
}
