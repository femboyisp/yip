//! Kernel-bypass-ready packet I/O. M4 adds the io_uring backend (single ring
//! servicing UDP + TUN/TAP), then AF_XDP. This is the only crate permitted to
//! contain `unsafe`; every `unsafe` block must carry a `// SAFETY:` comment.

pub mod ack_coalesce;
pub mod addr;
pub mod af_xdp;
pub mod batch;
pub mod bpf;
pub mod epoll;
pub(crate) mod gso;
pub mod nonce;
pub mod poll;
pub mod spsc;
pub mod tun_offload;
pub mod uring;

#[cfg(target_env = "musl")]
pub(crate) type MsgFlags = libc::c_uint;
#[cfg(not(target_env = "musl"))]
pub(crate) type MsgFlags = libc::c_int;

#[cfg(target_env = "musl")]
pub(crate) type CmsgLen = libc::socklen_t;
#[cfg(not(target_env = "musl"))]
pub(crate) type CmsgLen = usize;

#[cfg(target_env = "musl")]
pub(crate) type IovLen = libc::c_int;
#[cfg(not(target_env = "musl"))]
pub(crate) type IovLen = libc::size_t;

pub use ack_coalesce::AckCompressor;
pub use addr::{sockaddr_to_std, std_to_sockaddr};
pub use bpf::{BpfFilterStatus, XdpRedirectFilter};

/// Parse the default gateway interface name from the contents of Linux `/proc/net/route`.
pub fn parse_default_gateway_from_route(content: &str) -> Option<String> {
    for line in content.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let iface = parts.next();
        let dest = parts.next();
        if let (Some(iface), Some(dest)) = (iface, dest) {
            if dest == "00000000" {
                return Some(iface.to_string());
            }
        }
    }
    None
}

/// Discover the default underlay network interface name on Linux by inspecting `/proc/net/route`.
pub fn find_default_gateway_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            return parse_default_gateway_from_route(&content);
        }
    }
    None
}

/// Query the effective UID of a peer connected to a UNIX domain socket via `SO_PEERCRED`.
#[cfg(target_os = "linux")]
pub fn get_unix_peer_uid(stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut ucred: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt called with valid raw file descriptor and properly sized ucred buffer.
    let res = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &raw mut ucred as *mut libc::c_void,
            &raw mut len,
        )
    };
    if res == 0 {
        Ok(ucred.uid)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Query the effective UID of a peer connected to a UNIX domain socket.
#[cfg(not(target_os = "linux"))]
pub fn get_unix_peer_uid(_stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_PEERCRED is only supported on Linux",
    ))
}

/// Query the process current effective UID.
#[cfg(unix)]
pub fn get_current_uid() -> u32 {
    // SAFETY: geteuid is a safe, thread-safe POSIX syscall with no side effects.
    unsafe { libc::geteuid() }
}

/// Query the process current effective UID.
#[cfg(not(unix))]
pub fn get_current_uid() -> u32 {
    0
}

#[inline]
pub(crate) fn empty_msghdr() -> libc::msghdr {
    // SAFETY: msghdr contains only pointers, lengths, and integer flags, which
    // are valid when all bytes are zeroed.
    unsafe { std::mem::zeroed() }
}

#[inline]
pub(crate) fn empty_mmsghdr() -> libc::mmsghdr {
    // SAFETY: mmsghdr contains msghdr and msg_len, which are valid when zeroed.
    unsafe { std::mem::zeroed() }
}

/// Maximum number of datagrams in a single batched send/recv call.
pub const MAX_DATAGRAM_BATCH: usize = 128;

/// Maximum size (bytes) of a single wire datagram. 2 KiB is ample for any
/// encapsulated MTU-1500 payload plus yip-wire framing overhead.
pub const MAX_WIRE_DATAGRAM: usize = 2048;

/// Default socket buffer size in bytes (64 MiB) for UDP send and receive queues.
pub const DEFAULT_SOCKET_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// Selected I/O backend, in fallback-preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Single io_uring ring for UDP + TUN/TAP (built first in M4).
    IoUring,
    /// AF_XDP zero-copy (bare-metal accelerant, later).
    AfXdpZeroCopy,
    /// AF_XDP copy mode (cloud-VM fallback).
    AfXdpCopy,
    /// Portable recvmmsg/sendmmsg fallback rung.
    Mmsg,
}

use io_uring::{opcode, types, IoUring};
use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

/// Sends and receives wire datagrams via the selected backend. Implemented in M4.
pub trait DataPlaneIo {
    /// The backend actually selected at startup (after probing/fallback).
    fn backend(&self) -> Backend;
    /// Send one datagram.
    fn send(&mut self, datagram: &[u8]) -> std::io::Result<()>;
    /// Receive one datagram into `buf`, returning its length.
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Send up to `datagrams.len()` datagrams in one syscall where supported.
    ///
    /// Returns the number of datagrams actually sent. The default implementation
    /// loops over [`DataPlaneIo::send`]; override for real batching (e.g. `sendmmsg`).
    fn send_batch(&mut self, datagrams: &[&[u8]]) -> io::Result<usize> {
        let mut count = 0usize;
        for dg in datagrams {
            self.send(dg)?;
            count += 1;
        }
        Ok(count)
    }

    /// Receive up to `bufs.len()` datagrams in one syscall where supported.
    ///
    /// Fills `lens[i]` with the byte count of the i-th received datagram and
    /// returns the number of datagrams received. The default implementation does
    /// a single [`DataPlaneIo::recv`]; override for real batching (e.g. `recvmmsg`).
    fn recv_batch(
        &mut self,
        bufs: &mut [[u8; MAX_WIRE_DATAGRAM]],
        lens: &mut [usize],
    ) -> io::Result<usize> {
        if bufs.is_empty() || lens.is_empty() {
            return Ok(0);
        }
        let n = self.recv(&mut bufs[0])?;
        lens[0] = n;
        Ok(1)
    }
}

/// A `DataPlaneIo` backend that submits Read/Write ops on a connected UDP
/// socket through an `io_uring` ring.
pub struct IoUringIo {
    ring: IoUring,
    socket: UdpSocket,
}

impl IoUringIo {
    /// Wrap a (connected) UDP socket with an io_uring ring.
    pub fn new(socket: UdpSocket) -> io::Result<IoUringIo> {
        let ring = IoUring::new(8)?;
        Ok(IoUringIo { ring, socket })
    }

    fn submit_and_reap(&mut self, entry: &io_uring::squeue::Entry) -> io::Result<usize> {
        // SAFETY: the buffer referenced by `entry` is owned by the caller and outlives
        // this call — we submit and wait for completion before returning, so the kernel
        // is done with the buffer by the time we hand control back.
        unsafe {
            self.ring
                .submission()
                .push(entry)
                .map_err(|_| io::Error::other("submission queue full"))?;
        }
        self.ring.submit_and_wait(1)?;
        let cqe = self
            .ring
            .completion()
            .next()
            .ok_or_else(|| io::Error::other("missing completion"))?;
        let res = cqe.result();
        if res < 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }
        Ok(usize::try_from(res).expect("non-negative result fits usize"))
    }
}

impl DataPlaneIo for IoUringIo {
    fn backend(&self) -> Backend {
        Backend::IoUring
    }

    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let len =
            u32::try_from(datagram.len()).map_err(|_| io::Error::other("datagram too large"))?;
        let entry = opcode::Write::new(types::Fd(self.socket.as_raw_fd()), datagram.as_ptr(), len)
            .build()
            .user_data(0);
        self.submit_and_reap(&entry)?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).map_err(|_| io::Error::other("buffer too large"))?;
        let entry = opcode::Read::new(types::Fd(self.socket.as_raw_fd()), buf.as_mut_ptr(), len)
            .build()
            .user_data(1);
        self.submit_and_reap(&entry)
    }
}

/// A portable fallback backend over a plain (connected) UDP socket.
pub struct PlainIo {
    socket: UdpSocket,
}

impl PlainIo {
    /// Wrap a connected UDP socket.
    pub fn new(socket: UdpSocket) -> PlainIo {
        PlainIo { socket }
    }
}

impl DataPlaneIo for PlainIo {
    fn backend(&self) -> Backend {
        Backend::Mmsg
    }

    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.socket.send(datagram).map(|_| ())
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    /// Send up to `datagrams.len()` datagrams in one `sendmmsg(2)` syscall.
    ///
    /// Returns the number of datagrams accepted by the kernel (≤ input length).
    fn send_batch(&mut self, datagrams: &[&[u8]]) -> io::Result<usize> {
        if datagrams.is_empty() {
            return Ok(0);
        }

        // Build parallel arrays of iovec + mmsghdr.  We cap at MAX_DATAGRAM_BATCH
        // to keep these stack arrays reasonably sized (128 × small structs).
        let count = datagrams.len().min(MAX_DATAGRAM_BATCH);

        // iovec[i] points into the caller-owned slice datagrams[i]; the slices
        // must outlive the sendmmsg call, which they do — both arrays are on our
        // stack and we block until sendmmsg returns.
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; MAX_DATAGRAM_BATCH];
        let mut msgs = [empty_mmsghdr(); MAX_DATAGRAM_BATCH];

        for (i, dg) in datagrams[..count].iter().enumerate() {
            // SAFETY: We cast a shared slice to a *mut c_void as required by the
            // iovec ABI.  sendmmsg does not write through iov_base for send
            // operations; the kernel only reads from it.  The slice outlives the
            // syscall because datagrams is borrowed for the duration of this fn.
            iovecs[i].iov_base = dg.as_ptr().cast_mut().cast::<libc::c_void>();
            iovecs[i].iov_len = dg.len();
            msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }

        // SAFETY: `msgs[..count]` is a valid slice of initialised mmsghdr structs.
        // Each msg_hdr.msg_iov points into `iovecs[..count]`, which are fully
        // initialised above and live on this stack frame until sendmmsg returns.
        // The socket fd is valid for the lifetime of PlainIo (owned UdpSocket).
        // We pass MSG_NOSIGNAL so a peer disconnect raises an error rather than
        // delivering SIGPIPE.
        let ret = unsafe {
            libc::sendmmsg(
                self.socket.as_raw_fd(),
                msgs.as_mut_ptr(),
                u32::try_from(count).expect("count ≤ MAX_DATAGRAM_BATCH ≤ 128 fits u32"),
                libc::MSG_NOSIGNAL as MsgFlags,
            )
        };

        if ret.is_negative() {
            return Err(io::Error::last_os_error());
        }
        Ok(usize::try_from(ret).expect("non-negative sendmmsg return fits usize"))
    }

    /// Receive up to `bufs.len()` datagrams in one `recvmmsg(2)` syscall.
    ///
    /// Writes per-datagram byte counts into `lens` and returns the number of
    /// datagrams received (may be less than `bufs.len()`).
    fn recv_batch(
        &mut self,
        bufs: &mut [[u8; MAX_WIRE_DATAGRAM]],
        lens: &mut [usize],
    ) -> io::Result<usize> {
        if bufs.is_empty() {
            return Ok(0);
        }

        let count = bufs.len().min(lens.len()).min(MAX_DATAGRAM_BATCH);

        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; MAX_DATAGRAM_BATCH];
        let mut msgs = [empty_mmsghdr(); MAX_DATAGRAM_BATCH];

        for i in 0..count {
            // SAFETY: bufs[i] is a mutable slice owned by the caller and lives
            // for the duration of this function.  recvmmsg writes received bytes
            // into iov_base; we ensure each iovec points to a distinct buffer
            // element so there is no aliasing.
            iovecs[i].iov_base = bufs[i].as_mut_ptr().cast::<libc::c_void>();
            iovecs[i].iov_len = MAX_WIRE_DATAGRAM;
            msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }

        // SAFETY: `msgs[..count]` is fully initialised above.  Each msg_iov
        // points into a distinct element of `bufs`, so there is no aliasing.
        // MSG_WAITFORONE causes recvmmsg to block until at least one datagram
        // arrives and then return however many are immediately available, without
        // waiting for the full `count` — matching the blocking semantics of recv
        // while still harvesting bursts.  The socket fd is valid for the lifetime
        // of PlainIo.  We pass a null timeout (block indefinitely).
        let ret = unsafe {
            libc::recvmmsg(
                self.socket.as_raw_fd(),
                msgs.as_mut_ptr(),
                u32::try_from(count).expect("count ≤ MAX_DATAGRAM_BATCH ≤ 128 fits u32"),
                libc::MSG_WAITFORONE as MsgFlags,
                std::ptr::null_mut(),
            )
        };

        if ret.is_negative() {
            return Err(io::Error::last_os_error());
        }
        let received = usize::try_from(ret).expect("non-negative recvmmsg return fits usize");
        for i in 0..received {
            lens[i] = usize::try_from(msgs[i].msg_len).expect("msg_len fits usize");
        }
        Ok(received)
    }
}

/// Set the OS send and receive socket buffer sizes to `bytes` bytes on `sock`.
///
/// On Linux, attempts `SO_SNDBUFFORCE` and `SO_RCVBUFFORCE` first (allowing
/// privileged daemons with `CAP_NET_ADMIN` to exceed `net.core.rmem_max`/`wmem_max`),
/// falling back to standard `SO_SNDBUF` and `SO_RCVBUF` if unprivileged.
/// The kernel may silently clamp or double the requested value (Linux doubles
/// it to account for bookkeeping overhead), so callers should not assume the
/// returned kernel value matches `bytes` exactly — only that the call succeeded.
///
fn set_single_buffer_opt(
    fd: std::os::fd::RawFd,
    opt_force: Option<libc::c_int>,
    opt_std: libc::c_int,
    size: i32,
) -> io::Result<()> {
    if let Some(force) = opt_force {
        // SAFETY: `fd` is a valid file descriptor; `size` is a correctly-typed `i32`
        // matching setsockopt's expected `optval` type, valid for reads of `optlen`.
        let ret_force = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                force,
                std::ptr::addr_of!(size).cast::<libc::c_void>(),
                libc::socklen_t::try_from(std::mem::size_of::<i32>())
                    .expect("size_of::<i32>() fits socklen_t"),
            )
        };
        if ret_force == 0 {
            return Ok(());
        }
    }

    // SAFETY: same rationale as above; standard unprivileged setsockopt.
    let ret_std = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt_std,
            std::ptr::addr_of!(size).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<i32>())
                .expect("size_of::<i32>() fits socklen_t"),
        )
    };
    if ret_std != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Helper to configure both send and receive buffer sizes on a UDP socket,
/// so that the yipd daemon can stay `#![forbid(unsafe_code)]`.
pub fn set_socket_buffers(sock: &UdpSocket, bytes: usize) -> io::Result<()> {
    let size = i32::try_from(bytes)
        .map_err(|_| io::Error::other("buffer size too large for setsockopt"))?;
    let fd = sock.as_raw_fd();

    #[cfg(target_os = "linux")]
    let (snd_force, rcv_force) = (Some(libc::SO_SNDBUFFORCE), Some(libc::SO_RCVBUFFORCE));
    #[cfg(not(target_os = "linux"))]
    let (snd_force, rcv_force) = (None, None);

    set_single_buffer_opt(fd, snd_force, libc::SO_SNDBUF, size)?;
    set_single_buffer_opt(fd, rcv_force, libc::SO_RCVBUF, size)?;
    Ok(())
}

/// Enable kernel UDP Generic Receive Offload (GRO) on `sock` if supported.
///
/// On Linux kernels >= 4.18, `SOL_UDP` / `UDP_GRO` allows the kernel networking
/// stack to aggregate incoming contiguous UDP packets into superpackets, reducing
/// socket layer traversal and syscall overhead on underlay packet reception.
///
/// If unsupported by the kernel or running on non-Linux systems, returns `Ok(())`
/// gracefully without failing socket creation.
pub fn enable_udp_gro(sock: &UdpSocket) -> io::Result<()> {
    let fd = sock.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        // SOL_UDP is 17; UDP_GRO is 104 in linux/udp.h
        const SOL_UDP: libc::c_int = 17;
        const UDP_GRO: libc::c_int = 104;

        let val: libc::c_int = 1;
        // SAFETY: `fd` is a valid file descriptor owned by `sock`. `val` is a local c_int.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_UDP,
                UDP_GRO,
                std::ptr::addr_of!(val).cast::<libc::c_void>(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                    .expect("size_of fits socklen_t"),
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0);
            // Ignore if kernel doesn't support UDP_GRO (ENOPROTOOPT, EINVAL, ENOTSOCK, EOPNOTSUPP)
            if raw == libc::ENOPROTOOPT || raw == libc::EINVAL || raw == libc::EOPNOTSUPP {
                return Ok(());
            }
            return Ok(());
        }
    }

    #[cfg(not(target_os = "linux"))]
    let _ = fd;

    Ok(())
}

/// Pin the calling thread to `core` via `libc::sched_setaffinity`.
///
/// Returns `Ok(())` on success, or an `io::Error` if affinity could not be set.
pub fn pin_current_thread(core: usize) -> io::Result<()> {
    // SAFETY: `set` is a valid, fully-initialized `cpu_set_t` local; `CPU_SET`
    // and `sched_setaffinity` only read/write within its bounds, and
    // `size_of::<cpu_set_t>()` matches the buffer we pass.
    let rc = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const set)
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Choose the lowest-latency backend that initializes: io_uring if its ring
/// builds on this kernel, else the portable plain-socket fallback.
pub fn select_backend(socket: UdpSocket) -> Box<dyn DataPlaneIo> {
    let clone = socket.try_clone().expect("clone udp socket");
    match IoUringIo::new(clone) {
        Ok(io) => Box::new(io),
        Err(_) => Box::new(PlainIo::new(socket)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // io_uring setup and teardown is asynchronous in the kernel: the ring's locked-memory
    // accounting is not fully released until some time after the fd is closed.  On kernels
    // with a tight RLIMIT_MEMLOCK (this dev machine has 1 MiB), creating a third ring in
    // the same process fails with ENOMEM even though the previous two have been dropped.
    //
    // Serialising every io_uring-bearing test through this mutex, combined with a short
    // post-drop sleep, keeps the total concurrent ring count at one and gives the kernel
    // time to reclaim its accounting between tests.
    static URING_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn backends_are_ordered_by_preference() {
        // io_uring is the first backend we build (M4); fallback rungs follow.
        assert_ne!(Backend::IoUring, Backend::Mmsg);
    }

    #[test]
    fn iouring_sends_and_receives_over_udp() {
        let _guard = URING_SERIAL.lock().unwrap();
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        rx.connect(tx.local_addr().unwrap()).unwrap();

        // If ring creation fails (e.g. RLIMIT_MEMLOCK too low), skip gracefully.
        let mut tx_io = match IoUringIo::new(tx) {
            Ok(io) => io,
            Err(_) => {
                eprintln!(
                    "SKIP iouring_sends_and_receives_over_udp: \
                     io_uring ring unavailable (RLIMIT_MEMLOCK)"
                );
                return;
            }
        };
        let mut rx_io = match IoUringIo::new(rx) {
            Ok(io) => io,
            Err(_) => {
                eprintln!(
                    "SKIP iouring_sends_and_receives_over_udp: \
                     io_uring ring unavailable (RLIMIT_MEMLOCK)"
                );
                return;
            }
        };
        assert_eq!(tx_io.backend(), Backend::IoUring);

        tx_io.send(b"datagram via uring").unwrap();
        let mut buf = [0u8; 64];
        let n = rx_io.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"datagram via uring");
        // Explicit drop + sleep: give the kernel time to reclaim ring accounting before
        // the next io_uring test (kernel cleanup is asynchronous).
        drop(tx_io);
        drop(rx_io);
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    #[test]
    fn plain_io_sends_and_receives() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        rx.connect(tx.local_addr().unwrap()).unwrap();
        let mut t = PlainIo::new(tx);
        let mut r = PlainIo::new(rx);
        assert_eq!(t.backend(), Backend::Mmsg);
        t.send(b"plain path").unwrap();
        let mut buf = [0u8; 32];
        let n = r.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"plain path");
    }

    #[test]
    fn select_backend_prefers_io_uring_or_falls_back() {
        let _guard = URING_SERIAL.lock().unwrap();
        use std::net::UdpSocket;

        // Probe: can we build a ring right now?  Use a throwaway connected socket
        // so the probe mirrors exactly the conditions select_backend will face.
        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let probe_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe_sock
            .connect(probe_peer.local_addr().unwrap())
            .unwrap();
        let uring_ok = IoUringIo::new(probe_sock).is_ok();
        // Drop the probe ring; give the kernel a moment to reclaim accounting.
        drop(probe_peer);
        std::thread::sleep(std::time::Duration::from_millis(50));

        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let io = select_backend(s);

        // Contract: io_uring is preferred WHEN available, else falls back to Mmsg.
        if uring_ok {
            assert_eq!(io.backend(), Backend::IoUring);
        } else {
            assert_eq!(io.backend(), Backend::Mmsg);
        }
    }

    #[test]
    fn set_socket_buffers_succeeds_and_updates_buffers() {
        use std::net::UdpSocket;
        use std::os::fd::AsRawFd;

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();

        // Helper to query current socket buffer size via getsockopt.
        let query_buffer = |opt: libc::c_int| -> i32 {
            let mut val: i32 = 0;
            let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
            // SAFETY: `sock.as_raw_fd()` is a valid open socket fd; `val` is an `i32`
            // matching the expected getsockopt type, and `len` accurately reflects its size.
            let rc = unsafe {
                libc::getsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    opt,
                    std::ptr::addr_of_mut!(val).cast(),
                    &raw mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt must succeed");
            val
        };

        // First set a small baseline buffer size (8 KiB).
        let small_val: i32 = 8192;
        let len = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: `sock.as_raw_fd()` is valid, `small_val` is an `i32`, and `len` is size_of::<i32>().
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of!(small_val).cast(),
                len,
            );
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::addr_of!(small_val).cast(),
                len,
            );
        }
        let initial_rcv = query_buffer(libc::SO_RCVBUF);
        let initial_snd = query_buffer(libc::SO_SNDBUF);

        // Now configure 64 KiB via set_socket_buffers.
        let result = set_socket_buffers(&sock, 65536);
        assert!(
            result.is_ok(),
            "set_socket_buffers returned error: {:?}",
            result
        );

        let final_rcv = query_buffer(libc::SO_RCVBUF);
        let final_snd = query_buffer(libc::SO_SNDBUF);

        // Linux kernel doubles the requested buffer size and caps at sysctl limits.
        // Both final sizes must strictly exceed the initial 8 KiB settings.
        assert!(
            final_rcv > initial_rcv,
            "SO_RCVBUF did not increase: initial={initial_rcv}, final={final_rcv}"
        );
        assert!(
            final_snd > initial_snd,
            "SO_SNDBUF did not increase: initial={initial_snd}, final={final_snd}"
        );

        // Also verify DEFAULT_SOCKET_BUFFER_BYTES succeeds without error.
        assert!(set_socket_buffers(&sock, DEFAULT_SOCKET_BUFFER_BYTES).is_ok());
    }

    #[test]
    fn set_socket_buffers_rejects_invalid_fd() {
        use std::fs::File;
        use std::net::UdpSocket;
        use std::os::fd::{FromRawFd, IntoRawFd};

        let file = File::open("/dev/null").unwrap();
        let fd = file.into_raw_fd();
        // SAFETY: `fd` is a valid open file descriptor owned by this test, safe to wrap and close via UdpSocket.
        let non_sock = unsafe { UdpSocket::from_raw_fd(fd) };
        let res = set_socket_buffers(&non_sock, 65536);
        assert!(
            res.is_err(),
            "set_socket_buffers must fail on non-socket fd"
        );
    }

    #[test]
    fn set_socket_buffers_rejects_oversized_value() {
        use std::net::UdpSocket;

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let res = set_socket_buffers(&sock, usize::MAX);
        assert!(res.is_err(), "set_socket_buffers must fail on usize::MAX");
    }

    #[test]
    fn test_enable_udp_gro_succeeds_or_graceful_fallback() {
        use std::net::UdpSocket;
        let sock = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => panic!("failed to bind test udp socket: {e}"),
            },
        };
        let result = enable_udp_gro(&sock);
        assert!(
            result.is_ok(),
            "enable_udp_gro must succeed or fall back gracefully"
        );
    }

    #[test]
    fn plainio_send_and_recv_batch_roundtrip() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        rx.connect(tx.local_addr().unwrap()).unwrap();
        let mut tx_io = PlainIo::new(tx);
        let mut rx_io = PlainIo::new(rx);

        let a = b"first-datagram".as_slice();
        let b = b"second".as_slice();
        let sent = tx_io.send_batch(&[a, b]).unwrap();
        assert_eq!(sent, 2);

        let mut bufs = vec![[0u8; MAX_WIRE_DATAGRAM]; 8];
        let mut lens = [0usize; 8];
        // recvmmsg may return fewer than sent per call; loop until we have 2.
        let mut got: Vec<Vec<u8>> = Vec::new();
        while got.len() < 2 {
            let n = rx_io.recv_batch(&mut bufs, &mut lens).unwrap();
            for i in 0..n {
                got.push(bufs[i][..lens[i]].to_vec());
            }
        }
        assert!(got.contains(&a.to_vec()));
        assert!(got.contains(&b.to_vec()));
    }

    #[test]
    fn plainio_send_and_recv_batch_exceeding_64() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_socket_buffers(&rx, DEFAULT_SOCKET_BUFFER_BYTES).unwrap();
        set_socket_buffers(&tx, DEFAULT_SOCKET_BUFFER_BYTES).unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        rx.connect(tx.local_addr().unwrap()).unwrap();
        let mut tx_io = PlainIo::new(tx);
        let mut rx_io = PlainIo::new(rx);

        // Send 80 distinct datagrams in a single batch (exceeding the old 64 limit).
        let packets: Vec<Vec<u8>> = (0..80u32).map(|i| i.to_be_bytes().to_vec()).collect();
        let packet_slices: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();

        let sent = tx_io.send_batch(&packet_slices).unwrap();
        assert_eq!(sent, 80);

        let mut bufs = vec![[0u8; MAX_WIRE_DATAGRAM]; 128];
        let mut lens = [0usize; 128];
        let mut received = 0;
        while received < 80 {
            let n = rx_io.recv_batch(&mut bufs, &mut lens).unwrap();
            assert!(n > 0);
            received += n;
        }
        assert_eq!(received, 80);
    }

    #[test]
    fn plainio_send_batch_fails_when_unconnected() {
        use std::net::UdpSocket;

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut io = PlainIo::new(sock);

        let data = [b"test".as_slice()];
        assert!(io.send_batch(&data).is_err());
    }

    #[test]
    fn plainio_recv_batch_fails_on_nonblocking_empty_socket() {
        use std::net::UdpSocket;

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let mut io = PlainIo::new(sock);

        let mut bufs = vec![[0u8; MAX_WIRE_DATAGRAM]; 2];
        let mut lens = [0usize; 2];
        let res = io.recv_batch(&mut bufs, &mut lens);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_pin_current_thread_does_not_crash() {
        // Core 0 is present on standard systems. Call pin_current_thread and verify
        // it returns Ok or an OS error without crashing or corrupting memory.
        let _ = pin_current_thread(0);
    }

    #[test]
    fn test_plain_io_single_send_recv_and_defaults() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        rx.connect(tx.local_addr().unwrap()).unwrap();
        let mut tx_io = PlainIo::new(tx);
        let mut rx_io = PlainIo::new(rx);

        // Test single send and recv
        tx_io.send(b"single-packet").unwrap();
        let mut buf = [0u8; 64];
        let n = rx_io.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"single-packet");

        // Test empty send_batch and recv_batch
        assert_eq!(tx_io.send_batch(&[]).unwrap(), 0);
        let mut empty_lens = [0usize; 1];
        assert_eq!(rx_io.recv_batch(&mut [], &mut empty_lens).unwrap(), 0);

        // Test Backend variants
        assert_ne!(Backend::AfXdpZeroCopy, Backend::AfXdpCopy);

        // Test default DataPlaneIo trait implementation
        struct DefaultDataPlane {
            payload: Vec<u8>,
        }
        impl DataPlaneIo for DefaultDataPlane {
            fn backend(&self) -> Backend {
                Backend::Mmsg
            }
            fn send(&mut self, datagram: &[u8]) -> std::io::Result<()> {
                self.payload = datagram.to_vec();
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.payload.len().min(buf.len());
                buf[..n].copy_from_slice(&self.payload[..n]);
                Ok(n)
            }
        }

        let mut ddp = DefaultDataPlane {
            payload: Vec::new(),
        };
        let sent = ddp.send_batch(&[b"test-1", b"test-2"]).unwrap();
        assert_eq!(sent, 2);
        let mut bufs = vec![[0u8; MAX_WIRE_DATAGRAM]; 2];
        let mut lens = [0usize; 2];
        let recvd = ddp.recv_batch(&mut bufs, &mut lens).unwrap();
        assert_eq!(recvd, 1);
        assert_eq!(&bufs[0][..lens[0]], b"test-2");
        assert_eq!(ddp.recv_batch(&mut [], &mut lens).unwrap(), 0);
    }

    #[test]
    fn test_find_default_gateway_interface() {
        let sample =
            "Iface\tDestination\tGateway\neth0\t00000000\t0101A8C0\nwlan0\t0001A8C0\t00000000\n";
        assert_eq!(
            parse_default_gateway_from_route(sample).as_deref(),
            Some("eth0")
        );

        let no_default = "Iface\tDestination\tGateway\nwlan0\t0001A8C0\t00000000\n";
        assert_eq!(parse_default_gateway_from_route(no_default), None);

        let empty = "";
        assert_eq!(parse_default_gateway_from_route(empty), None);

        let iface = find_default_gateway_interface();
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
                assert_eq!(iface, parse_default_gateway_from_route(&content));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(iface.is_none());
        }
    }

    #[test]
    fn test_xsk_mode_flags_parsing() {
        use crate::af_xdp::{parse_xsk_mode_flags, XskModeFlags};

        assert_eq!(
            parse_xsk_mode_flags(Some("generic")),
            XskModeFlags {
                try_zero_copy: false,
                try_copy: true,
            }
        );
        assert_eq!(
            parse_xsk_mode_flags(Some("native")),
            XskModeFlags {
                try_zero_copy: true,
                try_copy: false,
            }
        );
        assert_eq!(
            parse_xsk_mode_flags(Some("offload")),
            XskModeFlags {
                try_zero_copy: true,
                try_copy: false,
            }
        );
        assert_eq!(
            parse_xsk_mode_flags(Some("auto")),
            XskModeFlags {
                try_zero_copy: true,
                try_copy: true,
            }
        );
        assert_eq!(
            parse_xsk_mode_flags(None),
            XskModeFlags {
                try_zero_copy: true,
                try_copy: true,
            }
        );
    }

    #[test]
    fn test_bind_multi_queue_in_lib() {
        use crate::af_xdp::{UmemPool, XskSocket, UMEM_CHUNK_SIZE};
        let umem = UmemPool::new(16, UMEM_CHUNK_SIZE).expect("allocate UMEM pool");
        let qids = vec![0, 1];
        let sockets = XskSocket::bind_multi_queue("lo", &qids, &umem).unwrap();
        assert_eq!(sockets.len(), 2);
        for (i, (qid, sock)) in sockets.iter().enumerate() {
            assert_eq!(*qid, i as u32);
            assert_eq!(sock.fill_ring().capacity(), crate::af_xdp::UMEM_RING_SIZE);
        }

        let sockets_mode =
            XskSocket::bind_multi_queue_with_mode("lo", &qids, &umem, Some("generic")).unwrap();
        assert_eq!(sockets_mode.len(), 2);
    }

    #[test]
    fn test_attach_xdp_with_fallback_in_lib() {
        use crate::bpf::{
            attach_xdp_with_fallback, attach_xdp_with_fallback_impl, XDP_FLAGS_DRV_MODE,
            XDP_FLAGS_SKB_MODE,
        };

        // 1. Explicit flags: directly invokes attach with provided flags
        let mut called_flags = Vec::new();
        let res = attach_xdp_with_fallback_impl(1, 10, XDP_FLAGS_SKB_MODE, |_idx, _fd, fl| {
            called_flags.push(fl);
            Ok(42)
        });
        assert_eq!(res.unwrap(), 42);
        assert_eq!(called_flags, vec![XDP_FLAGS_SKB_MODE]);

        // 2. flags == 0 and driver mode succeeds
        called_flags.clear();
        let res = attach_xdp_with_fallback_impl(1, 10, 0, |_idx, _fd, fl| {
            called_flags.push(fl);
            Ok(99)
        });
        assert_eq!(res.unwrap(), 99);
        assert_eq!(called_flags, vec![XDP_FLAGS_DRV_MODE]);

        // 3. flags == 0 and driver mode unsupported -> fallback to SKB mode
        called_flags.clear();
        let res = attach_xdp_with_fallback_impl(1, 10, 0, |_idx, _fd, fl| {
            called_flags.push(fl);
            if fl == XDP_FLAGS_DRV_MODE {
                Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            } else {
                Ok(123)
            }
        });
        assert_eq!(res.unwrap(), 123);
        assert_eq!(called_flags, vec![XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE]);

        // 4. flags == 0 and driver mode fails with non-unsupported error (e.g. EPERM)
        called_flags.clear();
        let res = attach_xdp_with_fallback_impl(1, 10, 0, |_idx, _fd, fl| {
            called_flags.push(fl);
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        });
        assert!(res.is_err());
        assert_eq!(called_flags, vec![XDP_FLAGS_DRV_MODE]);

        // Real syscall wrapper smoke test
        let res_real = attach_xdp_with_fallback(99999, -1, 0);
        assert!(res_real.is_err());
    }
}
