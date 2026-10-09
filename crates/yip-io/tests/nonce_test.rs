use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use yip_io::nonce::ChunkedNonceDispenser;

#[test]
fn test_chunked_nonce_dispenser_concurrency() {
    let dispenser = Arc::new(ChunkedNonceDispenser::new(64));
    let threads = 8;
    let nonces_per_thread = 10_000;

    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let d = Arc::clone(&dispenser);
            thread::spawn(move || {
                let mut local = d.claim_chunk();
                let mut collected = Vec::with_capacity(nonces_per_thread);
                for _ in 0..nonces_per_thread {
                    let n = local.next_nonce(&d).expect("nonce available");
                    collected.push(n);
                }
                collected
            })
        })
        .collect();

    let mut all_nonces = HashSet::new();
    for h in handles {
        let list = h.join().unwrap();
        for n in list {
            assert!(all_nonces.insert(n), "duplicate nonce detected: {n}");
        }
    }
    assert_eq!(all_nonces.len(), threads * nonces_per_thread);
}

#[test]
fn test_local_nonce_window_empty_and_replenish() {
    let dispenser = ChunkedNonceDispenser::new(yip_io::nonce::DEFAULT_NONCE_CHUNK_SIZE);
    let mut empty_win = yip_io::nonce::LocalNonceWindow::empty();
    // empty window triggers claim_chunk branch in next_nonce
    let n1 = empty_win.next_nonce(&dispenser);
    assert_eq!(n1, Some(0));
    let n2 = empty_win.next_nonce(&dispenser);
    assert_eq!(n2, Some(1));
}
