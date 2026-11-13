#![cfg(loom)]

#[test]
fn loom_spsc_concurrent_push_pop_permutation() {
    loom::model(|| {
        let (tx, rx) = yip_io::spsc::spsc_channel::<u32, 2>();
        let handle = loom::thread::spawn(move || {
            let _ = tx.push(10);
            let _ = tx.push(20);
        });
        let _ = rx.pop();
        let _ = rx.pop();
        handle.join().unwrap();
    });
}

#[test]
fn loom_spsc_wraparound() {
    loom::model(|| {
        let (tx, rx) = yip_io::spsc::spsc_channel::<u32, 2>();
        let handle = loom::thread::spawn(move || {
            let _ = tx.push(1);
            let _ = tx.push(2);
            let _ = tx.push(3);
        });
        let _ = rx.pop();
        let _ = rx.pop();
        let _ = rx.pop();
        handle.join().unwrap();
    });
}

#[test]
fn loom_spsc_drain_batch() {
    loom::model(|| {
        let (tx, rx) = yip_io::spsc::spsc_channel::<u32, 2>();
        let handle = loom::thread::spawn(move || {
            let _ = tx.push(10);
            let _ = tx.push(20);
        });
        let mut out = Vec::new();
        let _ = rx.drain_batch(&mut out, 2);
        let _ = rx.is_empty();
        handle.join().unwrap();
    });
}
