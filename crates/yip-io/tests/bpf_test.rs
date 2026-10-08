use yip_io::af_xdp::XskSocket;
use yip_io::bpf::{
    bpf_map_create_xsk, bpf_prog_load_xdp, BpfFilterStatus, BpfInsn, XdpRedirectFilter,
};

#[test]
fn test_bpf_filter_attach_opportunistic_on_loopback() {
    let status = XdpRedirectFilter::attach_opportunistic("lo", 51820, 0, -1);
    assert!(
        status == BpfFilterStatus::FallbackUnprivileged
            || status == BpfFilterStatus::Unsupported
            || matches!(status, BpfFilterStatus::Attached(_)),
        "unexpected bpf status: {:?}",
        status
    );
}

#[test]
fn test_bpf_filter_invalid_interface() {
    let status = XdpRedirectFilter::attach_opportunistic("nonexistent_if_99", 51820, 0, -1);
    assert_eq!(status, BpfFilterStatus::Unsupported);
}

#[test]
fn test_bpf_filter_raii_and_lifecycle() {
    // Test RAII creation and dropping of synthetic file descriptors
    let filter = XdpRedirectFilter::new(-1, -1);
    assert_eq!(filter.map_fd(), -1);
    assert_eq!(filter.prog_fd(), -1);
    let (map_fd, prog_fd) = filter.into_raw();
    assert_eq!(map_fd, -1);
    assert_eq!(prog_fd, -1);
}

#[test]
fn test_bpf_insn_constructors() {
    let mov = BpfInsn::mov64_reg(6, 1);
    assert_eq!(mov.regs, (1 << 4) | 6);

    let imm = BpfInsn::mov64_imm(0, 2);
    assert_eq!(imm.imm, 2);

    let add = BpfInsn::add64_imm(4, 42);
    assert_eq!(add.imm, 42);

    let call = BpfInsn::call_helper(51);
    assert_eq!(call.imm, 51);

    let exit = BpfInsn::exit();
    assert_eq!(exit.code, 0x95);
}

#[test]
fn test_xsk_socket_bpf_filter_integration() {
    let mut sock = XskSocket::fallback();
    assert!(sock.filter().is_none());

    // Fallback socket has fd == -1, so attach_bpf_filter immediately returns Unsupported
    let status = sock.attach_bpf_filter("lo", 51820, 0);
    assert_eq!(status, BpfFilterStatus::Unsupported);
    assert!(sock.filter().is_none());
}

#[test]
fn test_direct_bpf_syscall_unprivileged_failsoft() {
    // Test direct helpers; on unprivileged systems they should return OS error (EPERM/EACCES)
    // rather than panicking or crashing.
    match bpf_map_create_xsk(64) {
        Ok(fd) => {
            assert!(fd >= 0);
            // SAFETY: Closing open file descriptor returned by successful map creation.
            unsafe {
                libc::close(fd);
            }
        }
        Err(err) => {
            assert!(
                err.raw_os_error() == Some(libc::EPERM)
                    || err.raw_os_error() == Some(libc::EACCES)
                    || err.raw_os_error() == Some(libc::ENOSYS)
            );
        }
    }

    match bpf_prog_load_xdp(51820, -1) {
        Ok(fd) => {
            assert!(fd >= 0);
            // SAFETY: Closing open file descriptor returned by successful prog load.
            unsafe {
                libc::close(fd);
            }
        }
        Err(err) => {
            assert!(
                err.raw_os_error() == Some(libc::EPERM)
                    || err.raw_os_error() == Some(libc::EACCES)
                    || err.raw_os_error() == Some(libc::EBADF)
                    || err.raw_os_error() == Some(libc::EINVAL)
                    || err.raw_os_error() == Some(libc::ENOSYS)
            );
        }
    }
}

#[test]
fn test_bpf_multi_queue_attach_opportunistic() {
    let queues = vec![(0, -1), (1, -1), (2, -1), (3, -1)];
    let status = XdpRedirectFilter::attach_multi_queue("lo", 52820, &queues);
    match status {
        BpfFilterStatus::Attached(_) => {}
        BpfFilterStatus::FallbackUnprivileged => {}
        BpfFilterStatus::Unsupported => {}
    }
}

#[test]
fn test_bpf_filter_set_socket_for_queue() {
    let mut filter = XdpRedirectFilter::new(-1, -1);
    let res = filter.set_socket_for_queue(0, 10);
    assert!(res.is_err());

    let res_neg = filter.set_socket_for_queue(1, -1);
    assert!(res_neg.is_err());
}

#[test]
fn test_bpf_multi_queue_invalid_interface() {
    let queues = vec![(0, -1)];
    let status = XdpRedirectFilter::attach_multi_queue("nonexistent_if_99", 52820, &queues);
    assert_eq!(status, BpfFilterStatus::Unsupported);
}

#[test]
fn test_xsk_socket_multi_queue_filter_integration() {
    let mut sock = XskSocket::fallback();
    let queues = vec![(0, -1), (1, -1)];
    let status = sock.attach_bpf_filter_multi_queue("lo", 52820, &queues);
    assert_eq!(status, BpfFilterStatus::Unsupported);

    let res = sock.set_bpf_filter_queue_socket(0, 5);
    assert!(res.is_err());
}
