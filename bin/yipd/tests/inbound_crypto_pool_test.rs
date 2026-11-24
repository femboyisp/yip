use std::sync::Arc;
use yip_crypto::session::ChaCha20Poly1305Cipher;
use yipd::crypto_pool::inbound::{DecryptTask, DecryptedPacket, InboundCryptoPool};

#[test]
fn test_inbound_crypto_pool_parallel_decryption_and_in_order_drain() {
    let key = [0x55u8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));
    let mut pool = InboundCryptoPool::new(4, 0);

    let num_packets = 100u64;

    // Encrypt 100 packets first
    let mut ciphertexts = Vec::new();
    for seq in 0..num_packets {
        let plaintext = format!("hello inbound {seq}").into_bytes();
        let mut buf = plaintext.clone();
        let pt_len = plaintext.len();
        buf.resize(pt_len + 16, 0);
        let sealed_len = cipher
            .seal_in_place(seq, &mut buf, pt_len)
            .expect("seal must succeed");
        buf.truncate(sealed_len);
        ciphertexts.push((seq, buf));
    }

    // Dispatch out of order or interleaved across workers
    for (seq, ct) in ciphertexts {
        let task = DecryptTask {
            peer_id: 1,
            counter: seq,
            cipher: Arc::clone(&cipher),
            ciphertext: ct,
        };
        pool.dispatch_decrypt(task).expect("dispatch must succeed");
    }

    let mut drained = Vec::new();
    let start = std::time::Instant::now();
    while drained.len() < num_packets as usize && start.elapsed().as_secs() < 5 {
        pool.drain_completed(|pkt: DecryptedPacket| {
            drained.push(pkt);
        });
        std::thread::yield_now();
    }

    assert_eq!(drained.len(), num_packets as usize);

    // Verify monotonic in-order delivery and decrypted plaintext
    for (i, pkt) in drained.iter().enumerate() {
        assert_eq!(
            pkt.counter, i as u64,
            "counter must strictly match monotonic index"
        );
        assert_eq!(pkt.peer_id, 1);
        let pt = pkt.result.as_ref().expect("decryption must succeed");
        let s = String::from_utf8(pt.clone()).unwrap();
        assert_eq!(s, format!("hello inbound {i}"));
    }

    pool.shutdown();
}

#[test]
fn test_inbound_crypto_pool_tamper_detection() {
    let key = [0x77u8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));
    let mut pool = InboundCryptoPool::new(2, 0);

    // Encrypt packet 0
    let mut buf0 = b"valid packet 0".to_vec();
    let pt_len = buf0.len();
    buf0.resize(pt_len + 16, 0);
    let sealed_len = cipher.seal_in_place(0, &mut buf0, pt_len).unwrap();
    buf0.truncate(sealed_len);

    // Encrypt packet 1 and tamper with byte
    let mut buf1 = b"tampered packet 1".to_vec();
    let pt_len1 = buf1.len();
    buf1.resize(pt_len1 + 16, 0);
    let sealed_len1 = cipher.seal_in_place(1, &mut buf1, pt_len1).unwrap();
    buf1.truncate(sealed_len1);
    buf1[5] ^= 0xff; // Tamper with ciphertext

    pool.dispatch_decrypt(DecryptTask {
        peer_id: 1,
        counter: 0,
        cipher: Arc::clone(&cipher),
        ciphertext: buf0,
    })
    .unwrap();

    pool.dispatch_decrypt(DecryptTask {
        peer_id: 1,
        counter: 1,
        cipher: Arc::clone(&cipher),
        ciphertext: buf1,
    })
    .unwrap();

    let mut drained = Vec::new();
    let start = std::time::Instant::now();
    while drained.len() < 2 && start.elapsed().as_secs() < 5 {
        pool.drain_completed(|pkt| {
            drained.push(pkt);
        });
        std::thread::yield_now();
    }

    assert_eq!(drained.len(), 2);
    assert!(drained[0].result.is_ok());
    assert!(drained[1].result.is_err());

    pool.shutdown();
}
