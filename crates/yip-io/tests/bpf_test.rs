use yip_io::af_xdp::XskSocket;
use yip_io::bpf::{
    bpf_map_create_xsk, bpf_prog_assemble_xdp, bpf_prog_load_xdp, BpfFilterStatus, BpfInsn,
    XdpRedirectFilter,
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

    let add_reg = BpfInsn::add64_reg(4, 5);
    assert_eq!(add_reg.regs, (5 << 4) | 4);
    assert_eq!(add_reg.code, 0x0f);

    let and_imm = BpfInsn::and64_imm(5, 0x0f);
    assert_eq!(and_imm.imm, 0x0f);
    assert_eq!(and_imm.code, 0x57);

    let lsh_imm = BpfInsn::lsh64_imm(5, 2);
    assert_eq!(lsh_imm.imm, 2);
    assert_eq!(lsh_imm.code, 0x67);

    let jmp_ja = BpfInsn::ja(16);
    assert_eq!(jmp_ja.off, 16);
    assert_eq!(jmp_ja.code, 0x05);

    let jmp_jeq = BpfInsn::jeq_imm(4, 10, 9);
    assert_eq!(jmp_jeq.imm, 10);
    assert_eq!(jmp_jeq.off, 9);
    assert_eq!(jmp_jeq.code, 0x15);

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

#[test]
fn test_bpf_filter_dual_stack_bytecode_validation() {
    let listen_port = 52820u16;
    let insns = bpf_prog_assemble_xdp(listen_port, 42);

    // Bytecode validation: must assemble dual-stack instructions
    assert!(
        insns.len() >= 28,
        "dual-stack bytecode must have sufficient instructions (got {})",
        insns.len()
    );

    // Verify presence of IPv4 ethertype (0x0800) and IPv6 ethertype (0x86dd)
    let eth_p_ip = (0x0800u16).to_be() as i32;
    let eth_p_ipv6 = (0x86ddu16).to_be() as i32;
    let udp_port = listen_port.to_be() as i32;

    let has_ipv4 = insns.iter().any(|insn| insn.imm == eth_p_ip);
    let has_ipv6 = insns.iter().any(|insn| insn.imm == eth_p_ipv6);
    let has_port = insns.iter().any(|insn| insn.imm == udp_port);
    let has_udp_proto = insns.iter().any(|insn| insn.imm == 17);

    assert!(has_ipv4, "bytecode must check IPv4 ethertype (0x0800)");
    assert!(has_ipv6, "bytecode must check IPv6 ethertype (0x86dd)");
    assert!(has_port, "bytecode must check UDP destination port");
    assert!(has_udp_proto, "bytecode must check IPPROTO_UDP (17)");

    // Verify all branch offsets land on valid instruction indices
    for (idx, insn) in insns.iter().enumerate() {
        // Only JMP instructions (excluding CALL and EXIT) use insn.off as jump offset
        let is_jmp = (insn.code & 0x07) == yip_io::bpf::BPF_JMP
            && insn.code != (yip_io::bpf::BPF_JMP | yip_io::bpf::BPF_CALL)
            && insn.code != (yip_io::bpf::BPF_JMP | yip_io::bpf::BPF_EXIT);
        if is_jmp && insn.off != 0 {
            let target = (idx as i64) + 1 + (insn.off as i64);
            assert!(
                target >= 0 && (target as usize) < insns.len(),
                "jump at insn {} with offset {} lands out of bounds at {}",
                idx,
                insn.off,
                target
            );
        }
    }

    // Opportunistic attachment on loopback succeeds or degrades gracefully
    let queues = vec![(0, -1)];
    let filter = XdpRedirectFilter::attach_multi_queue("lo", listen_port, &queues);
    match filter {
        BpfFilterStatus::Attached(_)
        | BpfFilterStatus::FallbackUnprivileged
        | BpfFilterStatus::Unsupported => {}
    }
}
