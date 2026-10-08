use yip_io::af_xdp::{
    RxRing, TxRing, UmemPool, XskBindMode, XskDesc, XskSocket, UMEM_CHUNK_SIZE, UMEM_RING_SIZE,
};

#[test]
fn test_xsk_bind_mode_variants_and_traits() {
    let mode_zc = XskBindMode::ZeroCopy;
    let mode_cp = XskBindMode::Copy;
    let mode_fb = XskBindMode::FallbackRecvmmsg;

    assert_ne!(mode_zc, mode_cp);
    assert_ne!(mode_cp, mode_fb);
    assert_ne!(mode_zc, mode_fb);

    // Clone, Copy, Debug
    let copied = mode_fb;
    assert_eq!(copied, XskBindMode::FallbackRecvmmsg);
    assert_eq!(format!("{:?}", mode_zc), "ZeroCopy");
}

#[test]
fn test_xsk_desc_fields_and_traits() {
    let desc = XskDesc {
        addr: 4096,
        len: 1500,
        flags: 0,
    };
    assert_eq!(desc.addr, 4096);
    assert_eq!(desc.len, 1500);
    assert_eq!(desc.flags, 0);

    let desc2 = desc;
    assert_eq!(desc, desc2);
    assert_eq!(
        format!("{:?}", desc),
        "XskDesc { addr: 4096, len: 1500, flags: 0 }"
    );
}

#[test]
fn test_rx_ring_operations_and_batching() {
    let mut ring = RxRing::new(64);
    assert_eq!(ring.capacity(), 64);
    assert_eq!(ring.len(), 0);
    assert!(ring.is_empty());
    assert!(!ring.is_full());

    // Produce single descriptor
    let desc1 = XskDesc {
        addr: 2048,
        len: 512,
        flags: 0,
    };
    assert!(ring.produce(desc1));
    assert_eq!(ring.len(), 1);
    assert!(!ring.is_empty());

    // Consume single descriptor
    assert_eq!(ring.consume(), Some(desc1));
    assert_eq!(ring.len(), 0);
    assert!(ring.is_empty());
    assert_eq!(ring.consume(), None);

    // Batch produce
    let batch = [
        XskDesc {
            addr: 0,
            len: 100,
            flags: 0,
        },
        XskDesc {
            addr: 2048,
            len: 200,
            flags: 1,
        },
        XskDesc {
            addr: 4096,
            len: 300,
            flags: 2,
        },
    ];
    let produced = ring.produce_batch(&batch);
    assert_eq!(produced, 3);
    assert_eq!(ring.len(), 3);

    // Batch consume
    let mut out = [XskDesc {
        addr: 0,
        len: 0,
        flags: 0,
    }; 4];
    let consumed = ring.consume_batch(&mut out);
    assert_eq!(consumed, 3);
    assert_eq!(&out[..3], &batch);
    assert!(ring.is_empty());
}

#[test]
fn test_tx_ring_operations_and_batching() {
    let mut ring = TxRing::new(4);
    assert_eq!(ring.capacity(), 4);

    let d0 = XskDesc {
        addr: 0,
        len: 64,
        flags: 0,
    };
    let d1 = XskDesc {
        addr: 2048,
        len: 128,
        flags: 0,
    };
    let d2 = XskDesc {
        addr: 4096,
        len: 256,
        flags: 0,
    };
    let d3 = XskDesc {
        addr: 6144,
        len: 512,
        flags: 0,
    };
    let d4 = XskDesc {
        addr: 8192,
        len: 1024,
        flags: 0,
    };

    assert!(ring.produce(d0));
    assert!(ring.produce(d1));
    assert!(ring.produce(d2));
    assert!(ring.produce(d3));
    assert!(ring.is_full());
    assert!(!ring.produce(d4)); // full, should fail

    assert_eq!(ring.consume(), Some(d0));
    assert!(!ring.is_full());
    assert!(ring.produce(d4)); // now fits, ring wrapped around

    let mut out = [XskDesc {
        addr: 0,
        len: 0,
        flags: 0,
    }; 4];
    let consumed = ring.consume_batch(&mut out);
    assert_eq!(consumed, 4);
    assert_eq!(&out, &[d1, d2, d3, d4]);
    assert!(ring.is_empty());
}

#[test]
#[should_panic(expected = "power of two")]
fn test_rx_ring_non_power_of_two_panics() {
    let _ = RxRing::new(3);
}

#[test]
#[should_panic(expected = "power of two")]
fn test_tx_ring_zero_capacity_panics() {
    let _ = TxRing::new(0);
}

#[test]
fn test_xsk_socket_fallback_mode() {
    let mut sock = XskSocket::fallback();
    assert_eq!(sock.mode(), XskBindMode::FallbackRecvmmsg);
    assert_eq!(sock.fd(), -1);

    // Rings should be accessible and operational
    assert_eq!(sock.rx_ring_mut().capacity(), UMEM_RING_SIZE);
    assert_eq!(sock.tx_ring_mut().capacity(), UMEM_RING_SIZE);
}

#[test]
fn test_bind_opportunistic_on_loopback() {
    let umem = UmemPool::new(16, UMEM_CHUNK_SIZE).expect("allocate UMEM pool");
    let res = XskSocket::bind_opportunistic("lo", 0, &umem);
    assert!(res.is_ok(), "bind_opportunistic must not fail with Err");
    let mut sock = res.unwrap();

    // In unprivileged test runs, mode must be FallbackRecvmmsg
    // In privileged environments with AF_XDP, mode may be ZeroCopy or Copy
    match sock.mode() {
        XskBindMode::FallbackRecvmmsg => {
            assert_eq!(sock.fd(), -1);
        }
        XskBindMode::ZeroCopy | XskBindMode::Copy => {
            assert!(sock.fd() >= 0);
        }
    }

    // Rings must be initialized and accessible
    assert!(sock.rx_ring_mut().is_empty());
    assert!(sock.tx_ring_mut().is_empty());
}

#[test]
fn test_bind_opportunistic_on_invalid_interface_falls_back() {
    let umem = UmemPool::new(16, UMEM_CHUNK_SIZE).expect("allocate UMEM pool");
    let res = XskSocket::bind_opportunistic("nonexistent_dev_42", 0, &umem);
    assert!(
        res.is_ok(),
        "bind_opportunistic must never panic or error out"
    );
    let sock = res.unwrap();
    assert_eq!(sock.mode(), XskBindMode::FallbackRecvmmsg);
    assert_eq!(sock.fd(), -1);
}

#[test]
fn test_xsk_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<XskBindMode>();
    assert_send_sync::<XskDesc>();
    assert_send_sync::<RxRing>();
    assert_send_sync::<TxRing>();
    assert_send_sync::<XskSocket>();
}
