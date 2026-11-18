use yip_transport::fec::MAX_POOL_BUFFERS;
use yip_transport::Transport;

#[test]
fn test_transport_reassembler_capacity_decode() {
    let mut tx = Transport::new(vec![], 1200);
    let mut rx = Transport::new(vec![], 1200);

    assert_eq!(rx.fec_unrecoverable_count(), 0);

    // Multi-symbol payload to ensure objects remain in flight when only 1 symbol is fed
    let payload = vec![0x42u8; 2500];
    let inner = vec![0x00u8; 64];

    // Feed 256 incomplete objects
    for _ in 0..256 {
        let (class, syms) = tx.encode(&payload, &inner, false, 0);
        assert!(syms.len() >= 3);
        let key = u64::from(syms[0].object_id);
        let res = rx.decode(key, &syms[0], class, 0);
        assert!(res.is_none());
    }
    assert_eq!(
        rx.fec_unrecoverable_count(),
        0,
        "256 in-flight objects should fit without eviction"
    );

    // Feed 257th incomplete object: should trigger eviction of oldest incomplete object
    let (class, syms) = tx.encode(&payload, &inner, false, 0);
    assert!(syms.len() >= 3);
    let key = u64::from(syms[0].object_id);
    let res = rx.decode(key, &syms[0], class, 0);
    assert!(res.is_none());
    assert_eq!(
        rx.fec_unrecoverable_count(),
        1,
        "257th in-flight object must evict the oldest uncompleted object at capacity 256"
    );
}

#[test]
fn test_transport_reassembler_capacity_decode_borrowed() {
    let mut tx = Transport::new(vec![], 1200);
    let mut rx = Transport::new(vec![], 1200);

    assert_eq!(rx.fec_unrecoverable_count(), 0);

    let payload = vec![0x5au8; 2500];
    let inner = vec![0x5au8; 64];

    // Feed 256 incomplete objects
    for _ in 0..256 {
        let (class, syms) = tx.encode(&payload, &inner, false, 0);
        assert!(syms.len() >= 3);
        let key = u64::from(syms[0].object_id);
        let res = rx.decode_borrowed(key, &syms[0], class, 0);
        assert!(res.is_none());
    }
    assert_eq!(
        rx.fec_unrecoverable_count(),
        0,
        "256 in-flight objects should fit without eviction in decode_borrowed"
    );

    // Feed 257th incomplete object
    let (class, syms) = tx.encode(&payload, &inner, false, 0);
    assert!(syms.len() >= 3);
    let key = u64::from(syms[0].object_id);
    let res = rx.decode_borrowed(key, &syms[0], class, 0);
    assert!(res.is_none());
    assert_eq!(
        rx.fec_unrecoverable_count(),
        1,
        "257th in-flight object must evict the oldest uncompleted object at capacity 256"
    );
}

#[test]
fn test_transport_reassemble_256_objects_cleanly() {
    let mut tx = Transport::new(vec![], 1200);
    let mut rx = Transport::new(vec![], 1200);

    assert_eq!(MAX_POOL_BUFFERS, 16);

    for i in 0..256 {
        let mut payload = vec![0u8; 1500];
        payload[0] = (i & 0xff) as u8;
        payload[1499] = ((i >> 8) & 0xff) as u8;
        let inner = vec![0x11u8; 64];

        let (class, syms) = tx.encode(&payload, &inner, false, 0);
        assert!(syms.len() >= 2);
        let key = u64::from(syms[0].object_id);

        let mut completed = None;
        for sym in &syms {
            if let Some(decoded) = rx.decode(key, sym, class, 0) {
                completed = Some(decoded);
                break;
            }
        }
        assert_eq!(
            completed.as_deref(),
            Some(payload.as_slice()),
            "object {i} must reassemble cleanly"
        );
    }
    assert_eq!(rx.fec_unrecoverable_count(), 0);

    // Verify decode_borrowed also handles sequential 256 objects cleanly
    for i in 0..256 {
        let mut payload = vec![0u8; 1500];
        payload[0] = (i & 0xff) as u8;
        payload[1] = 0xbb;
        let inner = vec![0x22u8; 64];

        let (class, syms) = tx.encode(&payload, &inner, false, 0);
        let key = u64::from(syms[0].object_id);

        let mut completed = false;
        for sym in &syms {
            if let Some(slice) = rx.decode_borrowed(key, sym, class, 0) {
                assert_eq!(slice, payload.as_slice());
                completed = true;
                break;
            }
        }
        assert!(completed, "borrowed object {i} must reassemble cleanly");
    }
    assert_eq!(rx.fec_unrecoverable_count(), 0);
}
