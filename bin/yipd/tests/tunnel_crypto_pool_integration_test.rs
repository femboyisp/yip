//! Integration tests for crypto worker pool integration and configuration.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_transport::FlowClass;
use yipd::config::Config;
use yipd::crypto_pool::inbound::DecryptTask;
use yipd::crypto_pool::outbound::EncryptTask;
use yipd::crypto_pool::CryptoWorkerPool;

#[test]
fn test_config_parses_crypto_workers() {
    let base = r#"
local_private=0101010101010101010101010101010101010101010101010101010101010101
local_public=0202020202020202020202020202020202020202020202020202020202020202
peer_public=0303030303030303030303030303030303030303030303030303030303030303
peer_endpoint=127.0.0.1:51820
listen=127.0.0.1:51821
device=yip0
"#;

    // Default when omitted
    let c_default = Config::parse(base).unwrap();
    assert_eq!(c_default.crypto_workers, 0);

    // Explicit count
    let text_count = format!("{base}crypto_workers=4\n");
    let c_count = Config::parse(&text_count).unwrap();
    assert_eq!(c_count.crypto_workers, 4);

    // Alias crypto_threads
    let text_alias = format!("{base}crypto_threads=8\n");
    let c_alias = Config::parse(&text_alias).unwrap();
    assert_eq!(c_alias.crypto_workers, 8);

    // Auto detection
    let text_auto = format!("{base}crypto_workers=auto\n");
    let c_auto = Config::parse(&text_auto).unwrap();
    assert!(c_auto.crypto_workers <= 16);
}

#[test]
fn test_crypto_worker_pool_bidirectional_roundtrip() {
    let mut pool = CryptoWorkerPool::new(4);
    assert_eq!(pool.num_workers(), 4);

    let send_key = [0x11u8; 32];
    let recv_key = [0x22u8; 32];
    let send_cipher = Arc::new(ChaCha20Poly1305Cipher::new(send_key));
    let recv_cipher = Arc::new(ChaCha20Poly1305Cipher::new(recv_key));

    let peer_id = 42;
    pool.register_cipher(peer_id, Arc::clone(&send_cipher), Arc::clone(&recv_cipher));

    let dst: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let packet_count = 32;
    let mut original_payloads = Vec::with_capacity(packet_count);

    // 1. Dispatch outbound encryption
    for seq in 0..packet_count as u64 {
        let payload = vec![(seq & 0xFF) as u8; 1000];
        original_payloads.push(payload.clone());

        let task = EncryptTask {
            seq,
            peer_id,
            counter: seq + 1,
            fate: 0,
            dst,
            conn_tag: 0x9999,
            class: FlowClass::Default,
            symbol_size: 1200,
            payload,
        };
        pool.outbound.dispatch_encrypt(task).unwrap();
    }

    let mut sealed_packets = Vec::with_capacity(packet_count);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while sealed_packets.len() < packet_count && std::time::Instant::now() < deadline {
        pool.outbound.drain_completed(|item| {
            sealed_packets.push(item);
        });
        std::thread::yield_now();
    }
    assert_eq!(sealed_packets.len(), packet_count);

    // 2. Feed into inbound decryption using the matching key
    let matching_dec_cipher = Arc::new(ChaCha20Poly1305Cipher::new(send_key));
    pool.inbound
        .register_cipher(peer_id, Arc::clone(&matching_dec_cipher));

    for item in &sealed_packets {
        let dec_task = DecryptTask {
            seq: item.seq,
            peer_id,
            counter: item.seq + 1,
            ciphertext: item.datagrams[0].bytes.clone(),
        };
        pool.inbound.dispatch_decrypt(dec_task).unwrap();
    }

    let mut decrypted_packets = Vec::with_capacity(packet_count);
    let deadline2 = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while decrypted_packets.len() < packet_count && std::time::Instant::now() < deadline2 {
        pool.inbound.drain_completed(|item| {
            decrypted_packets.push(item);
        });
        std::thread::yield_now();
    }
    assert_eq!(decrypted_packets.len(), packet_count);

    // 3. Verify exact byte-for-byte roundtrip in strict in-order sequence
    for (idx, item) in decrypted_packets.iter().enumerate() {
        assert_eq!(item.seq, idx as u64);
        assert_eq!(&item.plaintext[..], &original_payloads[idx][..]);
    }

    pool.shutdown();
}
