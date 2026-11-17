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
