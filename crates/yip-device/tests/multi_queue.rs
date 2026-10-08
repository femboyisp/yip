use yip_device::{DeviceKind, TunTap};

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and is safe to call.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn create_multi_queue_allocates_requested_fds() {
    if !is_root() {
        eprintln!("skipping root-gated test create_multi_queue_allocates_requested_fds");
        return;
    }

    let queues = TunTap::create_multi_queue("yiptest_mq%d", DeviceKind::Tun, 2, false)
        .expect("failed to create multi-queue TUN");
    assert_eq!(queues.len(), 2);
    assert_ne!(
        std::os::fd::AsRawFd::as_raw_fd(&queues[0]),
        std::os::fd::AsRawFd::as_raw_fd(&queues[1])
    );
    assert_eq!(queues[0].name(), queues[1].name());

    // Both queues should be non-blocking.
    for q in &queues {
        // SAFETY: q.as_raw_fd() is a valid open file descriptor.
        let flags = unsafe { libc::fcntl(q.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "fcntl F_GETFL failed");
        assert_ne!(
            flags & libc::O_NONBLOCK,
            0,
            "queue fd must be in non-blocking mode"
        );
    }
}

#[test]
fn create_multi_queue_single_delegates() {
    if !is_root() {
        eprintln!("skipping root-gated test create_multi_queue_single_delegates");
        return;
    }

    let queues = TunTap::create_multi_queue("yiptest_sq%d", DeviceKind::Tun, 1, false)
        .expect("failed to create single-queue via multi_queue");
    assert_eq!(queues.len(), 1);

    // SAFETY: queues[0].as_raw_fd() is a valid open file descriptor.
    let flags = unsafe { libc::fcntl(queues[0].as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0, "fcntl F_GETFL failed");
    assert_ne!(
        flags & libc::O_NONBLOCK,
        0,
        "single-queue fd must be in non-blocking mode"
    );
}

#[test]
fn create_multi_queue_with_vnet_hdr() {
    if !is_root() {
        eprintln!("skipping root-gated test create_multi_queue_with_vnet_hdr");
        return;
    }

    let queues = TunTap::create_multi_queue("yiptest_vnh%d", DeviceKind::Tun, 2, true)
        .expect("failed to create multi-queue TUN with vnet_hdr");
    assert_eq!(queues.len(), 2);
    assert_eq!(queues[0].vnet_hdr_len(), queues[1].vnet_hdr_len());
}

#[test]
fn create_multi_queue_zero_count_fails() {
    let result = TunTap::create_multi_queue("yiptest_z%d", DeviceKind::Tun, 0, false);
    assert!(result.is_err(), "queue_count=0 should return an error");
}
