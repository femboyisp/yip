use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use yip_io::spsc::spsc_pair;

#[test]
fn basic_push_pop_fifo() {
    let (tx, rx) = spsc_pair::<u32, 8>();
    assert_eq!(tx.capacity(), 8);
    assert!(rx.is_empty());

    assert_eq!(tx.push(1), Ok(()));
    assert_eq!(tx.push(2), Ok(()));
    assert_eq!(tx.push(3), Ok(()));
    assert!(!rx.is_empty());

    assert_eq!(rx.pop(), Some(1));
    assert_eq!(rx.pop(), Some(2));
    assert_eq!(rx.pop(), Some(3));
    assert_eq!(rx.pop(), None);
    assert!(rx.is_empty());
}

#[test]
fn full_capacity_rejection() {
    let (tx, rx) = spsc_pair::<u32, 4>();
    assert_eq!(tx.push(10), Ok(()));
    assert_eq!(tx.push(20), Ok(()));
    assert_eq!(tx.push(30), Ok(()));
    assert_eq!(tx.push(40), Ok(()));

    // Full: push should fail and return the item intact
    assert_eq!(tx.push(50), Err(50));

    // Pop one item, freeing a slot
    assert_eq!(rx.pop(), Some(10));

    // Push now succeeds
    assert_eq!(tx.push(50), Ok(()));
    // And is full again
    assert_eq!(tx.push(60), Err(60));

    assert_eq!(rx.pop(), Some(20));
    assert_eq!(rx.pop(), Some(30));
    assert_eq!(rx.pop(), Some(40));
    assert_eq!(rx.pop(), Some(50));
    assert_eq!(rx.pop(), None);
}

#[test]
fn batch_draining() {
    let (tx, rx) = spsc_pair::<usize, 16>();
    for i in 0..10 {
        assert_eq!(tx.push(i), Ok(()));
    }

    let mut batch = Vec::new();
    let drained = rx.drain_batch(&mut batch, 4);
    assert_eq!(drained, 4);
    assert_eq!(batch, vec![0, 1, 2, 3]);

    let drained = rx.drain_batch(&mut batch, 10);
    assert_eq!(drained, 6);
    assert_eq!(batch, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    let drained = rx.drain_batch(&mut batch, 4);
    assert_eq!(drained, 0);
    assert!(rx.is_empty());
}

#[test]
fn ring_buffer_wraparound() {
    let (tx, rx) = spsc_pair::<usize, 4>();
    // Cycle through multiple buffer wrap-arounds
    for cycle in 0..100 {
        let base = cycle * 3;
        assert_eq!(tx.push(base), Ok(()));
        assert_eq!(tx.push(base + 1), Ok(()));
        assert_eq!(tx.push(base + 2), Ok(()));

        assert_eq!(rx.pop(), Some(base));
        assert_eq!(rx.pop(), Some(base + 1));
        assert_eq!(rx.pop(), Some(base + 2));
        assert_eq!(rx.pop(), None);
    }
}

#[test]
fn concurrent_producer_consumer_stress() {
    const N: usize = 100_000;
    let (tx, rx) = spsc_pair::<usize, 1024>();

    let producer = thread::spawn(move || {
        for mut i in 0..N {
            loop {
                match tx.push(i) {
                    Ok(()) => break,
                    Err(item) => {
                        i = item;
                        std::hint::spin_loop();
                    }
                }
            }
        }
    });

    let consumer = thread::spawn(move || {
        let mut received = Vec::with_capacity(N);
        while received.len() < N {
            let drained = rx.drain_batch(&mut received, 64);
            if drained == 0 {
                std::hint::spin_loop();
            }
        }
        received
    });

    producer.join().expect("producer thread joined cleanly");
    let received = consumer.join().expect("consumer thread joined cleanly");

    assert_eq!(received.len(), N);
    for (idx, &val) in received.iter().enumerate() {
        assert_eq!(val, idx, "FIFO sequence corrupted at index {idx}");
    }
}

#[test]
fn proper_dropping_of_unconsumed_elements_when_dropped() {
    struct DropDetector {
        _val: usize,
        counter: Arc<AtomicUsize>,
    }

    impl Drop for DropDetector {
        fn drop(&mut self) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drop_count = Arc::new(AtomicUsize::new(0));

    // Case 1: Drop with items remaining in queue (both tx and rx alive then dropped)
    {
        let (tx, rx) = spsc_pair::<DropDetector, 8>();
        for i in 0..5 {
            let item = DropDetector {
                _val: i,
                counter: Arc::clone(&drop_count),
            };
            assert!(tx.push(item).is_ok());
        }

        // Pop 2 items and drop them explicitly
        let p1 = rx.pop();
        let p2 = rx.pop();
        assert_eq!(drop_count.load(Ordering::SeqCst), 0);
        drop(p1);
        drop(p2);
        assert_eq!(drop_count.load(Ordering::SeqCst), 2);

        // 3 items remain in the ring buffer. Dropping tx and rx should drop the 3 remaining.
        drop(tx);
        drop(rx);
    }
    assert_eq!(drop_count.load(Ordering::SeqCst), 5);

    // Case 2: tx dropped before rx, rx dropped with remaining items
    drop_count.store(0, Ordering::SeqCst);
    {
        let (tx, rx) = spsc_pair::<DropDetector, 8>();
        for i in 0..4 {
            let item = DropDetector {
                _val: i,
                counter: Arc::clone(&drop_count),
            };
            assert!(tx.push(item).is_ok());
        }
        drop(tx);
        assert_eq!(drop_count.load(Ordering::SeqCst), 0);
        drop(rx);
    }
    assert_eq!(drop_count.load(Ordering::SeqCst), 4);

    // Case 3: rx dropped before tx, remaining items dropped
    drop_count.store(0, Ordering::SeqCst);
    {
        let (tx, rx) = spsc_pair::<DropDetector, 8>();
        for i in 0..4 {
            let item = DropDetector {
                _val: i,
                counter: Arc::clone(&drop_count),
            };
            assert!(tx.push(item).is_ok());
        }
        drop(rx);
        drop(tx);
    }
    assert_eq!(drop_count.load(Ordering::SeqCst), 4);
}

#[test]
#[should_panic(expected = "capacity must be a power of two")]
fn non_power_of_two_capacity_panics() {
    let (_tx, _rx) = spsc_pair::<u32, 5>();
}

#[test]
#[should_panic(expected = "capacity must be greater than zero")]
fn zero_capacity_panics() {
    let (_tx, _rx) = spsc_pair::<u32, 0>();
}

#[test]
fn test_spsc_debug_and_zero_drain() {
    let (tx, rx) = spsc_pair::<u32, 8>();
    let tx_dbg = format!("{tx:?}");
    let rx_dbg = format!("{rx:?}");
    assert!(tx_dbg.contains("SpscProducer"));
    assert!(rx_dbg.contains("SpscConsumer"));
    assert_eq!(tx.capacity(), 8);

    let mut out = Vec::new();
    assert_eq!(rx.drain_batch(&mut out, 0), 0);
    assert!(out.is_empty());
}
