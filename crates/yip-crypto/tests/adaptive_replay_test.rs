use yip_crypto::{ReplayProfile, ReplayWindow};

#[test]
fn test_adaptive_replay_profile_sizing_and_promotion() {
    let mut w = ReplayWindow::new_with_profile(ReplayProfile::Standard);
    assert_eq!(w.profile(), ReplayProfile::Standard);

    // Initial packets
    assert!(w.check_and_set(100));
    assert!(w.check_and_set(200));
    assert!(w.check_and_set(1000));

    // Replay of seen packet rejected
    assert!(!w.check_and_set(100));
    assert!(!w.check_and_set(200));

    // Advance to 5000
    assert!(w.check_and_set(5000));
    assert!(!w.check_and_set(1000));

    // Counter too old for Standard profile (8,192 bits):
    // Advance to 15,000
    assert!(w.check_and_set(15_000));
    // 5000 is diff 10,000 >= 8,192 -> rejected as too old
    assert!(!w.check(5000));

    // Now test promotion to HighThroughput
    let mut w2 = ReplayWindow::new_with_profile(ReplayProfile::Standard);
    assert!(w2.check_and_set(10));
    assert!(w2.check_and_set(20));
    assert!(w2.check_and_set(500));

    w2.promote_to_high_throughput();
    assert_eq!(w2.profile(), ReplayProfile::HighThroughput);

    // Past seen packets must STILL be rejected after promotion
    assert!(!w2.check(10));
    assert!(!w2.check(20));
    assert!(!w2.check(500));
    assert!(!w2.check_and_set(500));

    // In-window un-seen counter must be accepted
    assert!(w2.check(400));
    assert!(w2.check_and_set(400));
    assert!(!w2.check(400));

    // Advance by a large jump within HighThroughput window (131,072 bits)
    assert!(w2.check_and_set(50_000));
    // In HighThroughput, diff 49,600 < 131,072, but not seen -> accepted
    assert!(w2.check_and_set(45_000));
    assert!(!w2.check_and_set(45_000));
}

#[test]
fn test_stride_session_sealing_and_opening() {
    let k_send = [0x42u8; 32];
    let k_recv = [0x24u8; 32];
    let mut s1 = yip_crypto::Session::from_raw_keys(&k_send, &k_recv, 2, 4).unwrap();
    assert_eq!(s1.stride(), 4);
    let mut s_recv = yip_crypto::Session::from_raw_keys(&k_recv, &k_send, 0, 1).unwrap();

    let sealed1 = s1.seal(b"packet1").unwrap();
    assert_eq!(sealed1.counter, 2);
    let sealed2 = s1.seal(b"packet2").unwrap();
    assert_eq!(sealed2.counter, 6);

    let opened1 = s_recv.open(sealed1.counter, &sealed1.ciphertext).unwrap();
    assert_eq!(opened1, b"packet1");
    let opened2 = s_recv.open(sealed2.counter, &sealed2.ciphertext).unwrap();
    assert_eq!(opened2, b"packet2");
}

#[test]
fn test_multi_shard_stride_nonce_skew_does_not_drop_lagger_shards() {
    let k_send = [0x55u8; 32];
    let k_recv = [0xaau8; 32];

    // Shard 0 (idle / low volume, e.g. tick / control packets)
    let mut shard_0 = yip_crypto::Session::from_raw_keys(&k_send, &k_recv, 0, 4).unwrap();
    // Shard 1 (high volume, bulk TCP data)
    let mut shard_1 = yip_crypto::Session::from_raw_keys(&k_send, &k_recv, 1, 4).unwrap();

    // Receiver configured with 4 shards
    let mut s_recv = yip_crypto::Session::from_raw_keys(&k_recv, &k_send, 0, 4).unwrap();

    // Shard 0 sends an initial packet (counter = 0)
    let p0 = shard_0.seal(b"tick-0").unwrap();
    assert_eq!(p0.counter, 0);
    assert_eq!(s_recv.open(p0.counter, &p0.ciphertext).unwrap(), b"tick-0");

    // Shard 1 sends 200,000 packets, advancing far past the 131,072 bit replay window
    let mut last_p1 = None;
    for _ in 0..200_000 {
        last_p1 = Some(shard_1.seal(b"bulk-tcp").unwrap());
    }
    let p1 = last_p1.unwrap();
    assert!(p1.counter >= 799_997);
    assert_eq!(
        s_recv.open(p1.counter, &p1.ciphertext).unwrap(),
        b"bulk-tcp"
    );

    // Shard 0 sends its second packet (counter = 4)
    // Under a naive single replay window, diff = (800_000+ - 4) >> 131,072 bits, which would drop as replay!
    // Under per-stride window, Shard 0's stream is isolated and must open successfully.
    let p0_next = shard_0.seal(b"tick-1").unwrap();
    assert_eq!(p0_next.counter, 4);
    assert_eq!(
        s_recv.open(p0_next.counter, &p0_next.ciphertext).unwrap(),
        b"tick-1"
    );

    // Replay of p0_next must still be strictly rejected
    assert!(s_recv.open(p0_next.counter, &p0_next.ciphertext).is_err());
}

#[test]
fn test_session_multi_stride_replay_window_mapping() {
    let k_send = [0x33u8; 32];
    let k_recv = [0x77u8; 32];
    let mut s_recv = yip_crypto::Session::from_raw_keys(&k_recv, &k_send, 0, 4).unwrap();
    assert_eq!(s_recv.stride(), 4);

    let mut shard0 = yip_crypto::Session::from_raw_keys(&k_send, &k_recv, 0, 4).unwrap();
    let mut shard1 = yip_crypto::Session::from_raw_keys(&k_send, &k_recv, 1, 4).unwrap();
    let mut shard2 = yip_crypto::Session::from_raw_keys(&k_send, &k_recv, 2, 4).unwrap();
    let mut shard3 = yip_crypto::Session::from_raw_keys(&k_send, &k_recv, 3, 4).unwrap();

    let p0 = shard0.seal(b"p0").unwrap();
    let p1 = shard1.seal(b"p1").unwrap();
    let p2 = shard2.seal(b"p2").unwrap();
    let p3 = shard3.seal(b"p3").unwrap();

    assert_eq!(p0.counter, 0);
    assert_eq!(p1.counter, 1);
    assert_eq!(p2.counter, 2);
    assert_eq!(p3.counter, 3);

    // Each must open and commit into its specific stride window
    assert!(s_recv.open(p0.counter, &p0.ciphertext).is_ok());
    assert!(s_recv.open(p1.counter, &p1.ciphertext).is_ok());
    assert!(s_recv.open(p2.counter, &p2.ciphertext).is_ok());
    assert!(s_recv.open(p3.counter, &p3.ciphertext).is_ok());

    // Replay of each must be rejected
    assert!(s_recv.open(p0.counter, &p0.ciphertext).is_err());
    assert!(s_recv.open(p1.counter, &p1.ciphertext).is_err());
    assert!(s_recv.open(p2.counter, &p2.ciphertext).is_err());
    assert!(s_recv.open(p3.counter, &p3.ciphertext).is_err());

    // Shard 2 advances 100,000 packets; window 0, 1 and 3 must remain unaffected
    let mut last_p2 = None;
    for _ in 0..100_000 {
        last_p2 = Some(shard2.seal(b"p2_bulk").unwrap());
    }
    let p2_last = last_p2.unwrap();
    assert!(s_recv.open(p2_last.counter, &p2_last.ciphertext).is_ok());

    // Shard 0 sends its next packet (counter 4)
    let p0_next = shard0.seal(b"p0_next").unwrap();
    assert_eq!(p0_next.counter, 4);
    assert!(s_recv.open(p0_next.counter, &p0_next.ciphertext).is_ok());

    // Shard 1 sends its next packet (counter 5)
    let p1_next = shard1.seal(b"p1_next").unwrap();
    assert_eq!(p1_next.counter, 5);
    assert!(s_recv.open(p1_next.counter, &p1_next.ciphertext).is_ok());

    // Shard 3 sends its next packet (counter 7)
    let p3_next = shard3.seal(b"p3_next").unwrap();
    assert_eq!(p3_next.counter, 7);
    assert!(s_recv.open(p3_next.counter, &p3_next.ciphertext).is_ok());
}
