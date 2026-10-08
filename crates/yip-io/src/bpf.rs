//! Self-contained eBPF XSK redirect driver and map loader.
//!
//! Provides a zero-dependency Linux eBPF/XDP driver using direct `bpf(2)` syscalls
//! to direct incoming tunnel UDP datagrams straight into AF_XDP rings (`BPF_MAP_TYPE_XSKMAP`)
//! at the NIC driver layer, bypassing `sk_buff` allocations.
//!
//! All raw syscalls and pointer manipulations are quarantined within this module,
//! with explicit `// SAFETY:` justifications on every unsafe block.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

/// Operational status of the opportunistic eBPF XDP filter attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfFilterStatus {
    /// Filter successfully loaded and attached to the network interface.
    Attached(RawFd),
    /// Unprivileged execution (missing `CAP_BPF` / `CAP_NET_ADMIN` / `EPERM`).
    FallbackUnprivileged,
    /// BPF or XDP unsupported on the interface or kernel.
    Unsupported,
}

// BPF syscall command constants
pub const BPF_MAP_CREATE: libc::c_int = 0;
pub const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
pub const BPF_PROG_LOAD: libc::c_int = 5;
pub const BPF_LINK_CREATE: libc::c_int = 28;

// BPF types
pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
pub const BPF_PROG_TYPE_XDP: u32 = 6;
pub const BPF_XDP: u32 = 37;

// BPF helper function IDs
pub const BPF_FUNC_REDIRECT_MAP: i32 = 51;

// XDP return actions
pub const XDP_PASS: i32 = 2;

// Pseudo map FD flag for BPF_LD_IMM64
pub const BPF_PSEUDO_MAP_FD: u8 = 1;

// eBPF instruction encoding constants
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ALU64: u8 = 0x07;
pub const BPF_JMP: u8 = 0x05;

pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_DW: u8 = 0x18;

pub const BPF_IMM: u8 = 0x00;
pub const BPF_MEM: u8 = 0x60;

pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

pub const BPF_ADD: u8 = 0x00;
pub const BPF_MOV: u8 = 0xb0;

pub const BPF_JGT: u8 = 0x20;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;

// Registers
pub const R0: u8 = 0;
pub const R1: u8 = 1;
pub const R2: u8 = 2;
pub const R3: u8 = 3;
pub const R4: u8 = 4;
pub const R6: u8 = 6;

/// 8-byte eBPF instruction binary layout matching Linux kernel ABI (`struct bpf_insn`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8, // (src_reg << 4) | (dst_reg & 0x0f)
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: ((src & 0x0f) << 4) | (dst & 0x0f),
            off,
            imm,
        }
    }

    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }

    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }

    pub const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
    }

    pub const fn ldx_mem_w(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_W, dst, src, off, 0)
    }

    pub const fn ldx_mem_h(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_H, dst, src, off, 0)
    }

    pub const fn ldx_mem_b(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_B, dst, src, off, 0)
    }

    pub const fn jgt_reg(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JGT | BPF_X, dst, src, off, 0)
    }

    pub const fn jne_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JNE | BPF_K, dst, 0, off, imm)
    }

    pub const fn call_helper(func: i32) -> Self {
        Self::new(BPF_JMP | BPF_CALL, 0, 0, 0, func)
    }

    pub const fn exit() -> Self {
        Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfMapCreateAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfMapElemAttr {
    pub map_fd: u32,
    pub _pad: u32,
    pub key: u64,
    pub value: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfProgLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    pub prog_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfLinkCreateAttr {
    pub prog_fd: u32,
    pub target_ifindex: u32,
    pub attach_type: u32,
    pub flags: u32,
}

/// Linux `union bpf_attr` representation, 152 bytes.
#[repr(C)]
pub union BpfAttr {
    pub map_create: BpfMapCreateAttr,
    pub map_elem: BpfMapElemAttr,
    pub prog_load: BpfProgLoadAttr,
    pub link_create: BpfLinkCreateAttr,
    pub pad: [u8; 152],
}

/// Raw syscall wrapper for Linux `bpf(2)`.
///
/// # Safety
///
/// Caller must ensure `attr` points to an initialized memory buffer of at least `size`
/// bytes matching the kernel's ABI for command `cmd`, or NULL if the command expects no attributes.
pub unsafe fn sys_bpf(cmd: libc::c_int, attr: *const libc::c_void, size: usize) -> libc::c_long {
    // SAFETY: Invokes the Linux bpf syscall with caller-verified arguments.
    libc::syscall(libc::SYS_bpf, cmd, attr, size)
}

/// Creates a `BPF_MAP_TYPE_XSKMAP` map holding up to `max_entries` AF_XDP socket descriptors.
pub fn bpf_map_create_xsk(max_entries: u32) -> io::Result<RawFd> {
    let mut attr = BpfAttr { pad: [0u8; 152] };
    attr.map_create = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_XSKMAP,
        key_size: 4,
        value_size: 4,
        max_entries,
        map_flags: 0,
    };

    // SAFETY: sys_bpf is called with BPF_MAP_CREATE, a valid pointer to stack-local
    // BpfAttr, and exact size of BpfAttr matching the kernel ABI.
    let res = unsafe {
        sys_bpf(
            BPF_MAP_CREATE,
            std::ptr::addr_of!(attr).cast::<libc::c_void>(),
            std::mem::size_of::<BpfAttr>(),
        )
    };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(res as RawFd)
}

/// Updates an entry in an XSK map mapping `queue_id` to `xsk_fd`.
pub fn bpf_map_update_xsk(map_fd: RawFd, queue_id: u32, xsk_fd: RawFd) -> io::Result<()> {
    let mut attr = BpfAttr { pad: [0u8; 152] };
    let key = queue_id;
    let value = xsk_fd as u32;

    attr.map_elem = BpfMapElemAttr {
        map_fd: map_fd as u32,
        _pad: 0,
        key: std::ptr::addr_of!(key) as u64,
        value: std::ptr::addr_of!(value) as u64,
        flags: 0,
    };

    // SAFETY: sys_bpf is called with BPF_MAP_UPDATE_ELEM, attr points to valid
    // initialized BpfMapElemAttr, key and value point to valid stack locals that
    // outlive the syscall, and size matches sizeof(BpfAttr).
    let res = unsafe {
        sys_bpf(
            BPF_MAP_UPDATE_ELEM,
            std::ptr::addr_of!(attr).cast::<libc::c_void>(),
            std::mem::size_of::<BpfAttr>(),
        )
    };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Compiles and loads an eBPF XDP filter redirecting UDP traffic for `listen_port` to `xsk_map_fd`.
pub fn bpf_prog_load_xdp(listen_port: u16, xsk_map_fd: RawFd) -> io::Result<RawFd> {
    let eth_p_ip = (0x0800u16).to_be() as i32;
    let udp_port = listen_port.to_be() as i32;
    let license = b"GPL\0";

    // 20-instruction eBPF packet filter:
    // Checks Ethernet (IPv4), IP (UDP), UDP dest port == listen_port -> bpf_redirect_map(map, rx_queue, 0)
    let insns = [
        // 0: r6 = r1 (save context)
        BpfInsn::mov64_reg(R6, R1),
        // 1: r2 = *(u32 *)(r6 + 0) (ctx->data)
        BpfInsn::ldx_mem_w(R2, R6, 0),
        // 2: r3 = *(u32 *)(r6 + 4) (ctx->data_end)
        BpfInsn::ldx_mem_w(R3, R6, 4),
        // 3: r4 = r2
        BpfInsn::mov64_reg(R4, R2),
        // 4: r4 += 42 (14 eth + 20 ip + 8 udp)
        BpfInsn::add64_imm(R4, 42),
        // 5: if r4 > r3 goto +12 (index 18: LABEL_PASS)
        BpfInsn::jgt_reg(R4, R3, 12),
        // 6: r4 = *(u16 *)(r2 + 12) (eth->proto)
        BpfInsn::ldx_mem_h(R4, R2, 12),
        // 7: if r4 != eth_p_ip goto +10 (index 18: LABEL_PASS)
        BpfInsn::jne_imm(R4, eth_p_ip, 10),
        // 8: r4 = *(u8 *)(r2 + 23) (ip->proto: 14 + 9 = 23)
        BpfInsn::ldx_mem_b(R4, R2, 23),
        // 9: if r4 != 17 (IPPROTO_UDP) goto +8 (index 18: LABEL_PASS)
        BpfInsn::jne_imm(R4, 17, 8),
        // 10: r4 = *(u16 *)(r2 + 36) (udp->dest: 14 + 20 + 2 = 36)
        BpfInsn::ldx_mem_h(R4, R2, 36),
        // 11: if r4 != udp_port goto +6 (index 18: LABEL_PASS)
        BpfInsn::jne_imm(R4, udp_port, 6),
        // 12, 13: r1 = xsk_map_fd (BPF_LD_IMM64 pseudo map fd)
        BpfInsn::new(
            BPF_LD | BPF_DW | BPF_IMM,
            R1,
            BPF_PSEUDO_MAP_FD,
            0,
            xsk_map_fd,
        ),
        BpfInsn::new(0, 0, 0, 0, 0),
        // 14: r2 = *(u32 *)(r6 + 16) (ctx->rx_queue_index)
        BpfInsn::ldx_mem_w(R2, R6, 16),
        // 15: r3 = 0 (flags)
        BpfInsn::mov64_imm(R3, 0),
        // 16: call bpf_redirect_map(r1, r2, r3) -> r0
        BpfInsn::call_helper(BPF_FUNC_REDIRECT_MAP),
        // 17: exit (returns r0)
        BpfInsn::exit(),
        // 18: LABEL_PASS: r0 = XDP_PASS (2)
        BpfInsn::mov64_imm(R0, XDP_PASS),
        // 19: exit
        BpfInsn::exit(),
    ];

    let mut attr = BpfAttr { pad: [0u8; 152] };
    attr.prog_load = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
    };

    // SAFETY: sys_bpf is called with BPF_PROG_LOAD, attr points to valid stack-local
    // BpfProgLoadAttr, insns and license buffers outlive the syscall, and size matches sizeof(BpfAttr).
    let res = unsafe {
        sys_bpf(
            BPF_PROG_LOAD,
            std::ptr::addr_of!(attr).cast::<libc::c_void>(),
            std::mem::size_of::<BpfAttr>(),
        )
    };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(res as RawFd)
}

/// Fallback netlink-based attachment for older Linux kernels.
fn netlink_attach_xdp(ifindex: u32, prog_fd: RawFd) -> io::Result<RawFd> {
    // SAFETY: Invokes socket() to allocate an AF_NETLINK socket for ROUTE subsystem.
    let nl_sock = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if nl_sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let _sock_guard = AutoCloseFd(nl_sock);

    #[repr(C)]
    struct NlReq {
        nlh: libc::nlmsghdr,
        ifi: libc::ifinfomsg,
        xdp_hdr: libc::nlattr,
        fd_hdr: libc::nlattr,
        fd_val: i32,
    }

    let fd_attr_len = std::mem::size_of::<libc::nlattr>() + std::mem::size_of::<i32>();
    let xdp_attr_len = std::mem::size_of::<libc::nlattr>() + fd_attr_len;
    let total_len = std::mem::size_of::<libc::nlmsghdr>()
        + std::mem::size_of::<libc::ifinfomsg>()
        + xdp_attr_len;

    // SAFETY: Zeroed NlReq POD structure is safely formatted before sending.
    let mut req: NlReq = unsafe { std::mem::zeroed() };
    req.nlh.nlmsg_len = total_len as u32;
    req.nlh.nlmsg_type = libc::RTM_SETLINK;
    req.nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = libc::AF_UNSPEC as u8;
    req.ifi.ifi_index = ifindex as i32;

    req.xdp_hdr.nla_len = xdp_attr_len as u16;
    req.xdp_hdr.nla_type = libc::NLA_F_NESTED as u16 | 43; // 43 = IFLA_XDP

    req.fd_hdr.nla_len = fd_attr_len as u16;
    req.fd_hdr.nla_type = 1; // 1 = IFLA_XDP_FD
    req.fd_val = prog_fd;

    // SAFETY: Sending exactly total_len bytes from stack-local req to valid open netlink socket.
    let send_ret = unsafe {
        libc::send(
            nl_sock,
            std::ptr::addr_of!(req).cast::<libc::c_void>(),
            total_len,
            0,
        )
    };
    if send_ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = [0u8; 256];
    // SAFETY: Receiving netlink reply into stack-allocated buffer.
    let recv_ret = unsafe {
        libc::recv(
            nl_sock,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            0,
        )
    };
    if recv_ret < 0 {
        return Err(io::Error::last_os_error());
    }

    if recv_ret as usize
        >= std::mem::size_of::<libc::nlmsghdr>() + std::mem::size_of::<libc::nlmsgerr>()
    {
        // SAFETY: Byte offsets are bounds-checked by recv_ret check above; read_unaligned prevents alignment UB.
        let nlh = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::nlmsghdr>()) };
        if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
            // SAFETY: Byte offset arithmetic strictly within buffer bounds; read_unaligned avoids alignment preconditions.
            let err = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr()
                        .add(std::mem::size_of::<libc::nlmsghdr>())
                        .cast::<libc::nlmsgerr>(),
                )
            };
            if err.error != 0 {
                return Err(io::Error::from_raw_os_error(-err.error));
            }
        }
    }

    Ok(prog_fd)
}

/// Attaches an XDP program to the network interface specified by `ifindex`.
///
/// Tries modern `BPF_LINK_CREATE` first, falling back to netlink `RTM_SETLINK` if unsupported.
pub fn bpf_attach_xdp(ifindex: u32, prog_fd: RawFd) -> io::Result<RawFd> {
    // 1. Try BPF_LINK_CREATE (Linux 5.7+)
    let mut attr = BpfAttr { pad: [0u8; 152] };
    attr.link_create = BpfLinkCreateAttr {
        prog_fd: prog_fd as u32,
        target_ifindex: ifindex,
        attach_type: BPF_XDP,
        flags: 0,
    };

    // SAFETY: sys_bpf called with BPF_LINK_CREATE and valid initialized link_create attributes.
    let res = unsafe {
        sys_bpf(
            BPF_LINK_CREATE,
            std::ptr::addr_of!(attr).cast::<libc::c_void>(),
            std::mem::size_of::<BpfAttr>(),
        )
    };

    if res >= 0 {
        return Ok(res as RawFd);
    }

    let link_err = io::Error::last_os_error();
    match link_err.raw_os_error() {
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) => {
            // Fallback to Netlink RTM_SETLINK
            netlink_attach_xdp(ifindex, prog_fd)
        }
        _ => Err(link_err),
    }
}

/// RAII helper ensuring raw file descriptors are closed if initialization fails early.
pub(crate) struct AutoCloseFd(pub RawFd);

impl AutoCloseFd {
    pub fn into_raw(mut self) -> RawFd {
        let fd = self.0;
        self.0 = -1;
        fd
    }
}

impl Drop for AutoCloseFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: Closing open file descriptor exclusively owned by AutoCloseFd.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// RAII container for loaded eBPF redirect map and XDP program.
pub struct XdpRedirectFilter {
    map_fd: RawFd,
    prog_fd: RawFd,
}

impl XdpRedirectFilter {
    /// Constructs a new `XdpRedirectFilter` from existing raw map and program file descriptors.
    pub fn new(map_fd: RawFd, prog_fd: RawFd) -> Self {
        Self { map_fd, prog_fd }
    }

    /// File descriptor of the underlying `BPF_MAP_TYPE_XSKMAP`.
    pub fn map_fd(&self) -> RawFd {
        self.map_fd
    }

    /// File descriptor of the loaded eBPF XDP redirect program.
    pub fn prog_fd(&self) -> RawFd {
        self.prog_fd
    }

    /// Consumes the filter container, returning raw file descriptors `(map_fd, prog_fd)`
    /// without closing them.
    pub fn into_raw(mut self) -> (RawFd, RawFd) {
        let map_fd = self.map_fd;
        let prog_fd = self.prog_fd;
        self.map_fd = -1;
        self.prog_fd = -1;
        (map_fd, prog_fd)
    }

    /// Dynamically sets or updates the AF_XDP socket file descriptor for a specific queue ID in the map.
    pub fn set_socket_for_queue(&mut self, queue_id: u32, xsk_fd: RawFd) -> io::Result<()> {
        if self.map_fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if xsk_fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        bpf_map_update_xsk(self.map_fd, queue_id, xsk_fd)
    }

    /// Loads and attaches a multi-queue XDP redirect filter to `ifname` for `listen_port`
    /// across the specified `queue_fds`.
    pub fn load_multi_queue(
        ifname: &str,
        listen_port: u16,
        queue_fds: &[(u32, RawFd)],
    ) -> Result<Self, BpfFilterStatus> {
        let c_ifname = match CString::new(ifname) {
            Ok(c) => c,
            Err(_) => return Err(BpfFilterStatus::Unsupported),
        };

        // SAFETY: c_ifname is a valid null-terminated C string.
        let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
        if ifindex == 0 {
            return Err(BpfFilterStatus::Unsupported);
        }

        // 1. Create BPF_MAP_TYPE_XSKMAP dimensioned to hold all specified queues.
        let max_queue_id = queue_fds.iter().map(|(q, _)| *q).max().unwrap_or(0);
        let max_entries = max_queue_id
            .checked_add(1)
            .unwrap_or(64)
            .max(queue_fds.len() as u32)
            .max(64);

        let map_fd = match bpf_map_create_xsk(max_entries) {
            Ok(fd) => fd,
            Err(e) => {
                return match e.raw_os_error() {
                    Some(libc::EPERM | libc::EACCES) => Err(BpfFilterStatus::FallbackUnprivileged),
                    _ => Err(BpfFilterStatus::Unsupported),
                };
            }
        };
        let map_guard = AutoCloseFd(map_fd);

        // 2. Populate each (queue_id, xsk_fd) entry into the map if valid.
        for &(queue_id, xsk_fd) in queue_fds {
            if xsk_fd >= 0 {
                if let Err(e) = bpf_map_update_xsk(map_fd, queue_id, xsk_fd) {
                    return match e.raw_os_error() {
                        Some(libc::EPERM | libc::EACCES) => {
                            Err(BpfFilterStatus::FallbackUnprivileged)
                        }
                        _ => Err(BpfFilterStatus::Unsupported),
                    };
                }
            } else {
                // Negative xsk_fd is invalid for map update
                return Err(BpfFilterStatus::Unsupported);
            }
        }

        // 3. Load XDP program
        let prog_fd = match bpf_prog_load_xdp(listen_port, map_fd) {
            Ok(fd) => fd,
            Err(e) => {
                return match e.raw_os_error() {
                    Some(libc::EPERM | libc::EACCES) => Err(BpfFilterStatus::FallbackUnprivileged),
                    _ => Err(BpfFilterStatus::Unsupported),
                };
            }
        };
        let prog_guard = AutoCloseFd(prog_fd);

        // 4. Attach XDP program to interface
        if let Err(e) = bpf_attach_xdp(ifindex, prog_fd) {
            return match e.raw_os_error() {
                Some(libc::EPERM | libc::EACCES) => Err(BpfFilterStatus::FallbackUnprivileged),
                _ => Err(BpfFilterStatus::Unsupported),
            };
        }

        let map_fd = map_guard.into_raw();
        let prog_fd = prog_guard.into_raw();
        Ok(Self { map_fd, prog_fd })
    }

    /// Loads and attaches an XDP redirect filter to `ifname` for `listen_port` on a single queue.
    pub fn load_and_attach(
        ifname: &str,
        listen_port: u16,
        queue_id: u32,
        xsk_fd: RawFd,
    ) -> Result<Self, BpfFilterStatus> {
        Self::load_multi_queue(ifname, listen_port, &[(queue_id, xsk_fd)])
    }

    /// Opportunistically attempts to attach the eBPF XDP redirect filter across multiple queues.
    ///
    /// Degrades fail-soft to `FallbackUnprivileged` or `Unsupported` without panicking.
    pub fn attach_multi_queue(
        ifname: &str,
        listen_port: u16,
        queue_fds: &[(u32, RawFd)],
    ) -> BpfFilterStatus {
        match Self::load_multi_queue(ifname, listen_port, queue_fds) {
            Ok(filter) => {
                let prog_fd = filter.prog_fd;
                let _ = filter.into_raw();
                BpfFilterStatus::Attached(prog_fd)
            }
            Err(status) => status,
        }
    }

    /// Opportunistically attempts to attach the eBPF XDP redirect filter on a single queue.
    ///
    /// Degrades fail-soft to `FallbackUnprivileged` or `Unsupported` without panicking.
    pub fn attach_opportunistic(
        ifname: &str,
        listen_port: u16,
        queue_id: u32,
        xsk_fd: RawFd,
    ) -> BpfFilterStatus {
        Self::attach_multi_queue(ifname, listen_port, &[(queue_id, xsk_fd)])
    }
}

impl Drop for XdpRedirectFilter {
    fn drop(&mut self) {
        if self.map_fd >= 0 {
            // SAFETY: self.map_fd is an open file descriptor owned by XdpRedirectFilter.
            // Closing it releases the kernel BPF map resource.
            unsafe {
                libc::close(self.map_fd);
            }
            self.map_fd = -1;
        }
        if self.prog_fd >= 0 {
            // SAFETY: self.prog_fd is an open file descriptor owned by XdpRedirectFilter.
            // Closing it releases userspace reference to the BPF program.
            unsafe {
                libc::close(self.prog_fd);
            }
            self.prog_fd = -1;
        }
    }
}
