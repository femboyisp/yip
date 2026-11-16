//! Integration tests for parallel outbound crypto worker pool.
#![forbid(unsafe_code)]

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_io::EventFd;
use yip_transport::FlowClass;
use yipd::crypto_pool::outbound::{
    CompletedDatagram, EncryptTask, OutboundCryptoPool, MAX_PACKET_LEN,
};

#[test]
fn test_outbound_crypto_pool_parallel_encryption_and_in_order_delivery() {
    let key = [0x5Au8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));

    let num_workers = 4;
    let eventfd = Arc::new(EventFd::new().unwrap());
    let sleeping = Arc::new(AtomicBool::new(false));
    let mut pool = OutboundCryptoPool::new(num_workers, eventfd, sleeping);
    let peer_id = 1;
    pool.register_cipher(peer_id, Arc::clone(&cipher));

    let packet_count = 64;
    let mut expected_payloads = Vec::with_capacity(packet_count);

    // Dispatch 64 packets striped across 4 workers
    for seq in 0..packet_count as u64 {
        let p = vec![(seq & 0xFF) as u8; 1200];
        expected_payloads.push(p);

        let mut payload = [0u8; MAX_PACKET_LEN];
        payload[..1200].copy_from_slice(&expected_payloads[seq as usize]);

        let task = EncryptTask {
            seq,
            peer_id,
            counter: seq + 1,
            fate: (seq & 0xFFFF) as u16,
            class: FlowClass::Default,
            payload_len: 1200,
            payload,
        };

        pool.dispatch_encrypt(task).expect("pool must accept task");
    }

    // Collect completed packets in strict sequential order
    let mut completed: Vec<CompletedDatagram> = Vec::with_capacity(packet_count);
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
        "all dispatched packets must complete"
    );

    // Verify strict sequential ordering and AEAD authenticity
    for (idx, item) in completed.iter().enumerate() {
        let seq = idx as u64;
        assert_eq!(
            item.seq, seq,
            "completed packet must preserve strict sequence"
        );
        assert!(item.success);
        assert_eq!(item.fate, (seq & 0xFFFF) as u16);

        // Verify that the ciphertext decrypts cleanly with the peer cipher
        let mut decrypt_buf = item.ciphertext;
        let decrypted_len = cipher
            .open_in_place(seq + 1, &mut decrypt_buf, item.ciphertext_len)
            .expect("ciphertext must authenticate and decrypt cleanly");

        assert_eq!(
            &decrypt_buf[..decrypted_len],
            &expected_payloads[idx][..],
            "decrypted plaintext must match original payload for sequence {seq}"
        );
    }

    pool.shutdown();
}

#[test]
fn test_outbound_crypto_pool_handles_unregistered_peer() {
    let eventfd = Arc::new(EventFd::new().unwrap());
    let sleeping = Arc::new(AtomicBool::new(false));
    let mut pool = OutboundCryptoPool::new(2, eventfd, sleeping);

    let mut payload = [0u8; MAX_PACKET_LEN];
    payload[..3].copy_from_slice(&[1, 2, 3]);

    let task = EncryptTask {
        seq: 0,
        peer_id: 99, // Unregistered peer
        counter: 1,
        fate: 0,
        class: FlowClass::Default,
        payload_len: 3,
        payload,
    };

    pool.dispatch_encrypt(task).expect("accepted into queue");

    // Draining should safely skip/drop tasks for missing peers (success is false)
    let mut completed = Vec::new();
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(100) {
        pool.drain_completed(|item| completed.push(item));
        std::thread::yield_now();
    }

    assert_eq!(completed.len(), 0);
    pool.shutdown();
}
