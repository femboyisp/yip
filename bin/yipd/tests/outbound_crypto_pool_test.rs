//! Integration tests for parallel outbound crypto worker pool.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_transport::FlowClass;
use yipd::crypto_pool::outbound::{CompletedDatagram, EncryptTask, OutboundCryptoPool};

#[test]
fn test_outbound_crypto_pool_parallel_encryption_and_in_order_delivery() {
    let key = [0x5Au8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));
    let peer_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();

    let num_workers = 4;
    let mut pool = OutboundCryptoPool::new(num_workers);
    let peer_id = 1;
    pool.register_cipher(peer_id, Arc::clone(&cipher));

    let packet_count = 64;
    let mut expected_payloads = Vec::with_capacity(packet_count);

    // Dispatch 64 packets striped across 4 workers
    for seq in 0..packet_count as u64 {
        let payload = vec![(seq & 0xFF) as u8; 1200];
        expected_payloads.push(payload.clone());

        let task = EncryptTask {
            seq,
            peer_id,
            counter: seq + 1,
            fate: (seq & 0xFFFF) as u16,
            dst: peer_addr,
            conn_tag: 0x1122334455667788,
            class: FlowClass::Default,
            symbol_size: 1200,
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
        assert_eq!(item.datagrams.len(), 1);
        let dg = &item.datagrams[0];
        assert_eq!(dg.dst, peer_addr);
        assert_eq!(dg.fate, (seq & 0xFFFF) as u16);

        // Verify that the ciphertext decrypts cleanly with the peer cipher
        let mut decrypt_buf = dg.bytes.clone();
        let decrypted_len = cipher
            .open_in_place(seq + 1, &mut decrypt_buf, dg.bytes.len())
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
    let mut pool = OutboundCryptoPool::new(2);
    let peer_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();

    let task = EncryptTask {
        seq: 0,
        peer_id: 99, // Unregistered peer
        counter: 1,
        fate: 0,
        dst: peer_addr,
        conn_tag: 0x1234,
        class: FlowClass::Default,
        symbol_size: 1200,
        payload: vec![1, 2, 3],
    };

    pool.dispatch_encrypt(task).expect("accepted into queue");

    // Draining should safely skip/drop tasks for missing peers
    let mut completed = Vec::new();
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(100) {
        pool.drain_completed(|item| completed.push(item));
        std::thread::yield_now();
    }

    pool.shutdown();
}
