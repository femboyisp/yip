//! Integration tests for parallel inbound decryption worker pool.
#![forbid(unsafe_code)]

use std::sync::Arc;

use yip_crypto::session::ChaCha20Poly1305Cipher;
use yipd::crypto_pool::inbound::{DecryptTask, DecryptedPacket, InboundCryptoPool};

#[test]
fn test_inbound_crypto_pool_parallel_decryption_and_in_order_delivery() {
    let key = [0x7Eu8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));

    let num_workers = 4;
    let mut pool = InboundCryptoPool::new(num_workers);
    let peer_id = 1;
    pool.register_cipher(peer_id, Arc::clone(&cipher));

    let packet_count = 64;
    let mut plaintexts = Vec::with_capacity(packet_count);
    let mut ciphertexts = Vec::with_capacity(packet_count);

    // Pre-encrypt 64 packets
    for seq in 0..packet_count as u64 {
        let plain = vec![(seq & 0xFF) as u8; 1200];
        plaintexts.push(plain.clone());

        let mut buf = vec![0u8; 1200 + 16];
        buf[..1200].copy_from_slice(&plain);
        let sealed_len = cipher
            .seal_in_place(seq + 1, &mut buf, 1200)
            .expect("seal succeeds");
        buf.truncate(sealed_len);
        ciphertexts.push(buf);
    }

    // Dispatch ciphertexts across workers
    for seq in 0..packet_count as u64 {
        let task = DecryptTask {
            seq,
            peer_id,
            counter: seq + 1,
            ciphertext: ciphertexts[seq as usize].clone(),
        };
        pool.dispatch_decrypt(task).expect("pool must accept task");
    }

    // Drain completed plaintext packets
    let mut completed: Vec<DecryptedPacket> = Vec::with_capacity(packet_count);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

    while completed.len() < packet_count && std::time::Instant::now() < deadline {
        pool.drain_completed(|item| {
            completed.push(item);
        });
        std::thread::yield_now();
    }

    assert_eq!(
        completed.len(),
        packet_count,
        "all dispatched packets must be decrypted"
    );

    // Verify in-order sequence and plaintext accuracy
    for (idx, item) in completed.iter().enumerate() {
        let seq = idx as u64;
        assert_eq!(item.seq, seq, "decrypted packet must preserve strict order");
        assert_eq!(
            &item.plaintext[..],
            &plaintexts[idx][..],
            "decrypted plaintext must match original payload for sequence {seq}"
        );
    }

    pool.shutdown();
}

#[test]
fn test_inbound_crypto_pool_rejects_corrupted_ciphertext() {
    let key = [0x3Cu8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));

    let mut pool = InboundCryptoPool::new(2);
    let peer_id = 1;
    pool.register_cipher(peer_id, Arc::clone(&cipher));

    // Corrupted tag
    let corrupted_task = DecryptTask {
        seq: 0,
        peer_id,
        counter: 1,
        ciphertext: vec![0xFF; 64],
    };

    pool.dispatch_decrypt(corrupted_task).expect("accepted");

    let mut completed = Vec::new();
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(100) {
        pool.drain_completed(|item| completed.push(item));
        std::thread::yield_now();
    }

    assert!(completed.is_empty(), "corrupt packet must be dropped");
    pool.shutdown();
}
