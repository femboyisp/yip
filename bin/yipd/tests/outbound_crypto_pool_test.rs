use std::sync::Arc;
use yip_crypto::session::ChaCha20Poly1305Cipher;
use yipd::crypto_pool::outbound::{CompletedDatagram, EncryptTask, OutboundCryptoPool};

#[test]
fn test_outbound_crypto_pool_parallel_encryption_and_in_order_drain() {
    let key = [0x42u8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));
    let mut pool = OutboundCryptoPool::new(4, 0);

    let num_packets = 100u64;
    let dst = "10.0.0.2:51820".parse().unwrap();

    // Dispatch 100 packets across 4 workers
    for seq in 0..num_packets {
        let plaintext = format!("hello packet {seq}").into_bytes();
        let task = EncryptTask {
            peer_id: 1,
            counter: seq,
            dst,
            fate: (seq % 10) as u16,
            conn_tag: 0x12345678,
            cipher: Arc::clone(&cipher),
            payload: plaintext,
        };
        pool.dispatch_encrypt(task).expect("dispatch must succeed");
    }

    let mut drained = Vec::new();
    let start = std::time::Instant::now();
    while drained.len() < num_packets as usize && start.elapsed().as_secs() < 5 {
        pool.drain_completed(|dg: CompletedDatagram| {
            drained.push(dg);
        });
        std::thread::yield_now();
    }

    assert_eq!(drained.len(), num_packets as usize);

    // Verify monotonic in-order delivery
    for (i, dg) in drained.iter().enumerate() {
        assert_eq!(
            dg.counter, i as u64,
            "counter must strictly match monotonic index"
        );
        assert_eq!(dg.dst, dst);
        assert_eq!(dg.fate, (i % 10) as u16);

        // Verify decryption roundtrip
        let mut ct = dg.bytes.clone();
        let pt_len = cipher
            .open_in_place(dg.counter, &mut ct, dg.bytes.len())
            .expect("decryption must succeed");
        let pt = String::from_utf8(ct[..pt_len].to_vec()).unwrap();
        assert_eq!(pt, format!("hello packet {i}"));
    }

    pool.shutdown();
}

#[test]
fn test_outbound_crypto_pool_burst_stress_1000_packets() {
    let key = [0x99u8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));
    let mut pool = OutboundCryptoPool::new(4, 0);

    let total_packets = 1000u64;
    let dst = "192.168.1.100:51820".parse().unwrap();
    let mut seq = 0u64;
    let mut drained = Vec::new();

    while seq < total_packets {
        let burst_size = (total_packets - seq).min(32);
        for _ in 0..burst_size {
            let plaintext = format!("payload {seq}").into_bytes();
            let task = EncryptTask {
                peer_id: 2,
                counter: seq,
                dst,
                fate: (seq % 8) as u16,
                conn_tag: 0x87654321,
                cipher: Arc::clone(&cipher),
                payload: plaintext,
            };
            pool.dispatch_encrypt(task).expect("dispatch must succeed");
            seq += 1;
        }

        pool.drain_completed(|dg| {
            drained.push(dg);
        });
    }

    let start = std::time::Instant::now();
    while drained.len() < total_packets as usize && start.elapsed().as_secs() < 5 {
        pool.drain_completed(|dg| {
            drained.push(dg);
        });
        std::thread::yield_now();
    }

    assert_eq!(drained.len(), total_packets as usize);
    for (i, dg) in drained.iter().enumerate() {
        assert_eq!(dg.counter, i as u64);
    }

    pool.shutdown();
}
