use std::sync::Arc;
use yip_crypto::session::ChaCha20Poly1305Cipher;
use yipd::crypto_pool::inbound::{DecryptTask, DecryptedPacket, InboundCryptoPool, MAX_PACKET_LEN};

#[test]
fn test_inbound_crypto_pool_parallel_decryption() {
    let key = [0x55u8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));
    let mut pool = InboundCryptoPool::new(4, 0);

    let num_packets = 100u64;

    // Encrypt 100 packets first
    let mut ciphertexts = Vec::new();
    for seq in 0..num_packets {
        let plaintext = format!("hello inbound {seq}").into_bytes();
        let mut buf = [0u8; MAX_PACKET_LEN];
        let pt_len = plaintext.len();
        buf[..pt_len].copy_from_slice(&plaintext);
        let sealed_len = cipher
            .seal_in_place(seq, &mut buf, pt_len)
            .expect("seal must succeed");
        ciphertexts.push((seq, buf, sealed_len));
    }

    // Dispatch across workers
    for (seq, ct, ct_len) in ciphertexts {
        let task = DecryptTask {
            peer_id: 1,
            counter: seq,
            cipher: Arc::clone(&cipher),
            len: ct_len,
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

    // Verify all decrypted plaintexts match
    drained.sort_by_key(|p| p.counter);
    for (i, pkt) in drained.iter().enumerate() {
        assert_eq!(pkt.counter, i as u64);
        assert_eq!(pkt.peer_id, 1);
        assert!(pkt.success);
        let s = String::from_utf8(pkt.plain[..pkt.len].to_vec()).unwrap();
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
    let mut buf0 = [0u8; MAX_PACKET_LEN];
    let pt0 = b"valid packet 0";
    buf0[..pt0.len()].copy_from_slice(pt0);
    let len0 = cipher.seal_in_place(0, &mut buf0, pt0.len()).unwrap();

    // Encrypt packet 1 and tamper with byte
    let mut buf1 = [0u8; MAX_PACKET_LEN];
    let pt1 = b"tampered packet 1";
    buf1[..pt1.len()].copy_from_slice(pt1);
    let len1 = cipher.seal_in_place(1, &mut buf1, pt1.len()).unwrap();
    buf1[5] ^= 0xff; // Tamper with ciphertext

    pool.dispatch_decrypt(DecryptTask {
        peer_id: 1,
        counter: 0,
        cipher: Arc::clone(&cipher),
        len: len0,
        ciphertext: buf0,
    })
    .unwrap();

    pool.dispatch_decrypt(DecryptTask {
        peer_id: 1,
        counter: 1,
        cipher: Arc::clone(&cipher),
        len: len1,
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
    drained.sort_by_key(|p| p.counter);
    assert!(drained[0].success);
    assert!(!drained[1].success);

    pool.shutdown();
}

#[test]
fn test_inbound_crypto_pool_packet_loss_does_not_block_subsequent_packets() {
    let key = [0x88u8; 32];
    let cipher = Arc::new(ChaCha20Poly1305Cipher::new(key));
    let mut pool = InboundCryptoPool::new(2, 0);

    // Packet 0 is lost over the network!
    // Packets 1, 2, 5, 10 arrive.
    let sequences = [1u64, 2, 5, 10];
    for &seq in &sequences {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let pt = format!("packet {seq}").into_bytes();
        buf[..pt.len()].copy_from_slice(&pt);
        let sealed_len = cipher.seal_in_place(seq, &mut buf, pt.len()).unwrap();

        pool.dispatch_decrypt(DecryptTask {
            peer_id: 1,
            counter: seq,
            cipher: Arc::clone(&cipher),
            len: sealed_len,
            ciphertext: buf,
        })
        .unwrap();
    }

    let mut drained = Vec::new();
    let start = std::time::Instant::now();
    while drained.len() < sequences.len() && start.elapsed().as_secs() < 5 {
        pool.drain_completed(|pkt| {
            drained.push(pkt);
        });
        std::thread::yield_now();
    }

    // Must NOT stall or deadlock on missing packet 0!
    assert_eq!(
        drained.len(),
        sequences.len(),
        "all arrived packets must drain despite missing sequence 0"
    );
    for pkt in &drained {
        assert!(pkt.success);
        let s = String::from_utf8(pkt.plain[..pkt.len].to_vec()).unwrap();
        assert_eq!(s, format!("packet {}", pkt.counter));
    }

    pool.shutdown();
}
