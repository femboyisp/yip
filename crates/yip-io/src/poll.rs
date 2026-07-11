//! Single-threaded epoll-driven event loop for the yip data plane.
//!
//! `run_poll` drives both the UDP socket and TUN fd from a single OS thread,
//! eliminating the need for `Arc<Mutex<...>>` across two threads.  The caller
//! provides a [`Dispatch`] implementor that owns all mutable data-plane state.
//!
//! This module contains all Linux `epoll`/`fcntl` unsafe code for yipd.  Every
//! `unsafe` block carries a `// SAFETY:` comment explaining the invariants.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::time::Instant;

use crate::{sockaddr_to_std, std_to_sockaddr, MAX_DATAGRAM_BATCH, MAX_WIRE_DATAGRAM};

/// A single-threaded data-plane dispatch interface.
///
/// Implementors hold all mutable state (AEAD session, FEC transport, codec,
/// auxiliary logs).  [`run_poll`] drives this trait from an `epoll` loop.
///
/// # Addressing (multipeer 2a seam)
///
/// `on_udp` is told the datagram's source address and every egress datagram
/// carries its own destination (see [`EgressDatagram::dst`]), so a future
/// multi-peer `Dispatch` can route by address. A single-peer implementor is
/// free to ignore `src` and stamp a fixed `dst` on everything it emits —
/// exactly what [`crate::poll`]'s test dispatches below do, and what
/// `yipd`'s `DataPlane` does until the Task 5 `PeerManager` lands.
pub trait Dispatch {
    /// Called when a UDP datagram arrives, with the address it came from.
    /// Returns what [`run_poll`] must forward (to TUN, back to UDP, both, or
    /// nothing).
    fn on_udp(&mut self, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_>;

    /// Called when a TUN frame arrives.  Returns egress datagrams to send on
    /// the UDP socket (may be empty), each tagged with its FEC fate group and
    /// destination so a GSO-capable driver can coalesce safely (see
    /// [`EgressDatagram`]).
    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram];

    /// Called at least every 10 ms.  Returns addressed feedback/keepalive
    /// datagrams (usually 0 or 1) that should be sent on the UDP socket.
    fn tick(&mut self, now_ms: u64) -> Option<&[EgressDatagram]>;
}

/// One egress datagram: its destination, plus the FEC "fate group" it
/// belongs to.
///
/// GSO coalesces same-length, same-destination UDP datagrams into one
/// `UDP_SEGMENT` super-skb; under loss the whole skb is dropped/delayed as a
/// unit (segmentation is deferred to the receiver). Two datagrams that are
/// symbols of the same RaptorQ object must never share a skb — losing them
/// together can defeat FEC recovery for that object. `fate` is the RaptorQ
/// object id (source symbols and this object's repair symbols share it; a
/// different object gets a different value). A GSO-capable driver must
/// guarantee at most one datagram per distinct `fate` *and* per distinct
/// `dst` in any single coalesced send (datagrams to different peers must
/// never share a skb either). Non-GSO drivers ignore `fate`.
#[derive(Debug, Clone)]
pub struct EgressDatagram {
    pub fate: u16,
    pub dst: SocketAddr,
    pub bytes: Vec<u8>,
}

impl AsRef<[u8]> for EgressDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// What [`run_poll`] must do after a call to [`Dispatch::on_udp`].
pub enum DispatchOut<'a> {
    /// Nothing to forward.
    None,
    /// Write this slice to the TUN device (decoded inner packet).
    Tun(&'a [u8]),
    /// Send these datagrams on the UDP socket (ARQ retransmits).
    Udp(&'a [EgressDatagram]),
    /// Write to TUN *and* send datagrams.
    Both(&'a [u8], &'a [EgressDatagram]),
}

// ── internal helpers ──────────────────────────────────────────────────────────

/// Set a file descriptor to non-blocking mode via `fcntl(O_NONBLOCK)`.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open file descriptor supplied by the caller.
    // `fcntl(F_SETFL, O_NONBLOCK)` is a pure flag-set on the open-file
    // description; it cannot invalidate memory or cause UB.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Drain all pending datagrams from `udp_fd` (non-blocking) and call
/// `d.on_udp` for each, forwarding the outcome to TUN/UDP as appropriate.
fn drain_udp(udp_fd: RawFd, tun_fd: RawFd, d: &mut impl Dispatch, now_ms: u64) -> io::Result<()> {
    let mut buf = [0u8; MAX_WIRE_DATAGRAM];
    loop {
        // SAFETY: `storage` is a valid, suitably-sized/aligned stack buffer for
        // any sockaddr the kernel writes back into it (see `sockaddr_storage`'s
        // definition). `addr_len` is initialized to its capacity, as `recvfrom`
        // requires on entry.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addr_len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
            .expect("size_of::<sockaddr_storage>() fits socklen_t");

        // SAFETY: `buf` is a valid stack buffer of length MAX_WIRE_DATAGRAM.
        // `recvfrom` with MSG_DONTWAIT is a non-blocking receive into that
        // buffer; `storage`/`addr_len` are valid out-parameters for the
        // sender's address as described above. `udp_fd` is a valid UDP
        // socket fd supplied by the caller (unconnected — the seam is
        // addressed, not connected).
        let n = unsafe {
            libc::recvfrom(
                udp_fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
                std::ptr::from_mut(&mut storage).cast::<libc::sockaddr>(),
                &raw mut addr_len,
            )
        };

        if n < 0 {
            let e = io::Error::last_os_error();
            let raw = e.raw_os_error().unwrap_or(0);
            if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN {
                // Fd fully drained — normal exit condition.
                break;
            }
            if raw == libc::EINTR {
                // Signal interrupted the syscall; retry.
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            // No data available (treat as drained).
            break;
        }

        let src = match sockaddr_to_std(&storage, addr_len) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("poll: dropping datagram with unparseable source address: {e}");
                continue;
            }
        };

        let dg = &buf[..usize::try_from(n).expect("non-negative recv return fits usize")];

        // Dispatch and forward the result.  The borrow of `d` from `on_udp`
        // (inside `DispatchOut`) is dropped at the end of the match arm.
        match d.on_udp(src, dg, now_ms) {
            DispatchOut::None => {}
            DispatchOut::Tun(inner) => {
                send_to_tun(tun_fd, inner);
            }
            DispatchOut::Udp(pkts) => {
                for pkt in pkts {
                    send_to_udp(udp_fd, pkt)?;
                }
            }
            DispatchOut::Both(inner, pkts) => {
                send_to_tun(tun_fd, inner);
                for pkt in pkts {
                    send_to_udp(udp_fd, pkt)?;
                }
            }
        }
    }
    Ok(())
}

/// Drain all pending frames from `tun_fd` (non-blocking) and call
/// `d.on_tun` for each, sending the resulting datagrams on `udp_fd`.
fn drain_tun(tun_fd: RawFd, udp_fd: RawFd, d: &mut impl Dispatch, now_ms: u64) -> io::Result<()> {
    // TUN frames are at most the kernel's MTU (default 1500 bytes for an IP
    // TUN device), but MAX_WIRE_DATAGRAM (2 KiB) comfortably covers any
    // standard MTU plus a small margin.
    let mut buf = [0u8; MAX_WIRE_DATAGRAM];
    loop {
        // SAFETY: `buf` is a valid stack buffer.  `tun_fd` is a valid TUN
        // device fd (bidirectional: reads pull kernel-injected IP frames).
        // We call `read` instead of `recv` because TUN is not a socket.
        let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr().cast(), buf.len()) };

        if n < 0 {
            let e = io::Error::last_os_error();
            let raw = e.raw_os_error().unwrap_or(0);
            if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN {
                break;
            }
            if raw == libc::EINTR {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }

        let inner = &buf[..usize::try_from(n).expect("non-negative read return fits usize")];
        // Clone the packet slices so we don't hold an immutable borrow on `d`
        // while calling the mutable send_to_udp.
        let pkts_owned: Vec<EgressDatagram> = d.on_tun(inner, now_ms).to_vec();
        for pkt in &pkts_owned {
            send_to_udp(udp_fd, pkt)?;
        }
    }
    Ok(())
}

/// Write one packet to the TUN device.
///
/// Errors are logged and swallowed — a single failed TUN write should not
/// tear down the tunnel.
#[inline]
fn send_to_tun(tun_fd: RawFd, buf: &[u8]) {
    // SAFETY: `buf` is a valid slice and `tun_fd` is a valid TUN fd.
    // `write` writes at most `buf.len()` bytes from `buf`; partial writes
    // are unusual on TUN devices (atomic for MTU-sized frames) but we do
    // not retry them here — a dropped inner frame is less harmful than a
    // busy-loop.
    let rc = unsafe { libc::write(tun_fd, buf.as_ptr().cast(), buf.len()) };
    if rc < 0 {
        eprintln!("poll: tun write error: {}", io::Error::last_os_error());
    }
}

/// Send one datagram on the UDP socket, to its own [`EgressDatagram::dst`].
///
/// Transient errors (`EWOULDBLOCK`, `EAGAIN`, `ENOBUFS`) cause the datagram to
/// be silently dropped — the UDP socket send buffer is momentarily full and this
/// single packet loss is acceptable.  All other errors (e.g. `EBADF`) propagate
/// so that a closed or invalid socket terminates the event loop.
#[inline]
fn send_to_udp(udp_fd: RawFd, dg: &EgressDatagram) -> io::Result<()> {
    let (storage, addr_len) = std_to_sockaddr(dg.dst);
    let buf = &dg.bytes;
    // SAFETY: `buf` is a valid slice.  `udp_fd` is a valid UDP socket fd
    // (unconnected — the seam is addressed).  `storage`/`addr_len` describe a
    // valid destination sockaddr built by `std_to_sockaddr`. MSG_NOSIGNAL
    // suppresses SIGPIPE if the peer has closed.
    let rc = unsafe {
        libc::sendto(
            udp_fd,
            buf.as_ptr().cast(),
            buf.len(),
            libc::MSG_NOSIGNAL,
            std::ptr::from_ref(&storage).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        // EWOULDBLOCK == EAGAIN on Linux; list both for portability.
        // ENOBUFS means the socket send buffer is exhausted — drop the packet
        // rather than tearing down the tunnel.
        let raw = e.raw_os_error().unwrap_or(0);
        if raw == libc::EAGAIN || raw == libc::EWOULDBLOCK || raw == libc::ENOBUFS {
            eprintln!("poll: udp send dropped ({e})");
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

/// Send up to `datagrams.len().min(MAX_DATAGRAM_BATCH)` datagrams in one
/// `sendmmsg(2)`, each to its own [`EgressDatagram::dst`]. Returns the count the
/// kernel accepted (may be fewer; the caller loops the remainder).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the drain loop in Task 2 of the batched-UDP-I/O milestone"
    )
)]
fn send_mmsg(udp_fd: RawFd, datagrams: &[EgressDatagram]) -> io::Result<usize> {
    if datagrams.is_empty() {
        return Ok(0);
    }
    let count = datagrams.len().min(MAX_DATAGRAM_BATCH);

    // Parallel per-datagram arrays; all live on this stack frame until sendmmsg
    // returns, so the pointers stored in `msgs` stay valid across the syscall.
    // SAFETY: `sockaddr_storage` is plain-old-data; an all-zero value is a valid
    // (unspecified) initial state that we fully overwrite per datagram below.
    let mut storages: [libc::sockaddr_storage; MAX_DATAGRAM_BATCH] = unsafe { std::mem::zeroed() };
    let mut addrlens = [0 as libc::socklen_t; MAX_DATAGRAM_BATCH];
    let mut iovecs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; MAX_DATAGRAM_BATCH];
    let mut msgs = [libc::mmsghdr {
        msg_hdr: libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        },
        msg_len: 0,
    }; MAX_DATAGRAM_BATCH];

    for (i, dg) in datagrams[..count].iter().enumerate() {
        let (storage, addr_len) = std_to_sockaddr(dg.dst);
        storages[i] = storage;
        addrlens[i] = addr_len;
        // SAFETY: cast a shared slice to *mut c_void for the iovec ABI; sendmmsg
        // only reads through iov_base. `dg.bytes` outlives the syscall (borrowed
        // for this fn).
        iovecs[i].iov_base = dg.bytes.as_ptr().cast_mut().cast::<libc::c_void>();
        iovecs[i].iov_len = dg.bytes.len();
        msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = std::ptr::from_mut(&mut storages[i]).cast::<libc::c_void>();
        msgs[i].msg_hdr.msg_namelen = addrlens[i];
    }

    // SAFETY: `msgs[..count]` is fully initialised; each msg_iov/msg_name points
    // into `iovecs`/`storages` on this frame, valid until sendmmsg returns.
    // MSG_NOSIGNAL suppresses SIGPIPE on a closed peer.
    let ret = unsafe {
        libc::sendmmsg(
            udp_fd,
            msgs.as_mut_ptr(),
            u32::try_from(count).expect("count ≤ 64 fits u32"),
            libc::MSG_NOSIGNAL,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        let raw = e.raw_os_error().unwrap_or(0);
        // Transient full send buffer: report 0 sent (caller drops this burst's tail).
        if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
            return Ok(0);
        }
        return Err(e);
    }
    Ok(usize::try_from(ret).expect("non-negative sendmmsg return fits usize"))
}

/// Non-blocking `recvmmsg(2)`: drain up to `bufs.len().min(MAX_DATAGRAM_BATCH)`
/// queued datagrams in one syscall, writing each datagram's byte count into
/// `lens` and source address into `srcs`. Returns the count received (0 if the
/// socket is momentarily empty). Requires a non-blocking `udp_fd`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the drain loop in Task 2 of the batched-UDP-I/O milestone"
    )
)]
fn recv_mmsg(
    udp_fd: RawFd,
    bufs: &mut [[u8; MAX_WIRE_DATAGRAM]],
    lens: &mut [usize],
    srcs: &mut [SocketAddr],
) -> io::Result<usize> {
    let count = bufs
        .len()
        .min(lens.len())
        .min(srcs.len())
        .min(MAX_DATAGRAM_BATCH);
    if count == 0 {
        return Ok(0);
    }
    // SAFETY: all-zero sockaddr_storage is a valid initial out-buffer that
    // recvmmsg fills; we read it back only for the datagrams it reports received.
    let mut storages: [libc::sockaddr_storage; MAX_DATAGRAM_BATCH] = unsafe { std::mem::zeroed() };
    let addrlens = [libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
        .expect("size fits socklen_t"); MAX_DATAGRAM_BATCH];
    let mut iovecs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; MAX_DATAGRAM_BATCH];
    let mut msgs = [libc::mmsghdr {
        msg_hdr: libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        },
        msg_len: 0,
    }; MAX_DATAGRAM_BATCH];

    for i in 0..count {
        // SAFETY: each iov_base/msg_name points to a distinct element of
        // `bufs`/`storages` on this frame — no aliasing — valid until recvmmsg returns.
        iovecs[i].iov_base = bufs[i].as_mut_ptr().cast::<libc::c_void>();
        iovecs[i].iov_len = MAX_WIRE_DATAGRAM;
        msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = std::ptr::from_mut(&mut storages[i]).cast::<libc::c_void>();
        msgs[i].msg_hdr.msg_namelen = addrlens[i];
    }

    // SAFETY: `msgs[..count]` fully initialised; msg_iov/msg_name point into
    // distinct `bufs`/`storages` elements. MSG_DONTWAIT: non-blocking (the fd is
    // epoll-ready); null timeout. On empty socket, returns EWOULDBLOCK → Ok(0).
    let ret = unsafe {
        libc::recvmmsg(
            udp_fd,
            msgs.as_mut_ptr(),
            u32::try_from(count).expect("count ≤ 64 fits u32"),
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        let raw = e.raw_os_error().unwrap_or(0);
        if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN {
            return Ok(0);
        }
        return Err(e);
    }
    let received = usize::try_from(ret).expect("non-negative recvmmsg return fits usize");
    for i in 0..received {
        lens[i] = usize::try_from(msgs[i].msg_len).expect("msg_len fits usize");
        // recvmmsg writes the actual namelen back into each msg_hdr.
        srcs[i] = sockaddr_to_std(&storages[i], msgs[i].msg_hdr.msg_namelen)
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    }
    Ok(received)
}

// ── public entry point ────────────────────────────────────────────────────────

/// Run the epoll event loop until an I/O error is returned.
///
/// Both `udp_fd` and `tun_fd` are set non-blocking.  An `epoll` instance
/// watches both for `EPOLLIN`.  `epoll_wait` uses a 10 ms timeout so that
/// [`Dispatch::tick`] fires on cadence even when there is no network traffic.
///
/// The function returns when:
/// - `drain_udp` or `drain_tun` returns a fatal I/O error, OR
/// - `send_to_udp` returns a fatal I/O error (e.g. socket closed).
pub fn run_poll<D: Dispatch>(udp_fd: RawFd, tun_fd: RawFd, d: &mut D) -> io::Result<()> {
    set_nonblocking(udp_fd)?;
    set_nonblocking(tun_fd)?;

    // SAFETY: `epoll_create1` creates a new epoll instance.  EPOLL_CLOEXEC
    // is the only valid flag; passing it is safe.  We check the return value.
    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Register `udp_fd` with the epoll instance.
    let mut ev_udp = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: udp_fd as u64,
    };
    // SAFETY: `epoll_fd` and `udp_fd` are valid fds.  `ev_udp` is a
    // correctly initialised `epoll_event` with EPOLLIN and `udp_fd` as the
    // user data so we can identify which fd is ready in the event loop.
    let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, udp_fd, &raw mut ev_udp) };
    if rc < 0 {
        // SAFETY: `epoll_fd` is a valid fd we just created.
        unsafe { libc::close(epoll_fd) };
        return Err(io::Error::last_os_error());
    }

    // Register `tun_fd` with the epoll instance.
    let mut ev_tun = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: tun_fd as u64,
    };
    // SAFETY: same rationale as for `ev_udp` above; `tun_fd` is a valid
    // open TUN device fd.
    let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, tun_fd, &raw mut ev_tun) };
    if rc < 0 {
        // SAFETY: `epoll_fd` is a valid fd we just created.
        unsafe { libc::close(epoll_fd) };
        return Err(io::Error::last_os_error());
    }

    let start = Instant::now();
    // Stack-allocated event buffer: 4 events per wait is ample since we
    // only have 2 fds registered.
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];

    loop {
        // SAFETY: `epoll_fd` is a valid epoll fd.  `events` is a valid
        // stack-allocated array; we pass its length as `maxevents`.
        // A timeout of 10 ms ensures `tick` fires on cadence.
        let nfds = unsafe {
            libc::epoll_wait(
                epoll_fd,
                events.as_mut_ptr(),
                libc::c_int::try_from(events.len()).expect("event array len fits c_int"),
                10, // 10 ms timeout
            )
        };

        if nfds < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                // Interrupted by a signal — retry.
                continue;
            }
            // SAFETY: `epoll_fd` is valid.
            unsafe { libc::close(epoll_fd) };
            return Err(e);
        }

        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        for ev in &events[..usize::try_from(nfds).expect("non-negative nfds fits usize")] {
            let ready_fd = ev.u64 as RawFd;
            if ready_fd == udp_fd {
                if let Err(e) = drain_udp(udp_fd, tun_fd, d, now_ms) {
                    // SAFETY: `epoll_fd` is valid.
                    unsafe { libc::close(epoll_fd) };
                    return Err(e);
                }
            } else if ready_fd == tun_fd {
                if let Err(e) = drain_tun(tun_fd, udp_fd, d, now_ms) {
                    // SAFETY: `epoll_fd` is valid.
                    unsafe { libc::close(epoll_fd) };
                    return Err(e);
                }
            }
        }

        // Always tick — even on timeout with no events.
        if let Some(pkts) = d.tick(now_ms) {
            for pkt in pkts {
                if let Err(e) = send_to_udp(udp_fd, pkt) {
                    // SAFETY: `epoll_fd` is valid.
                    unsafe { libc::close(epoll_fd) };
                    return Err(e);
                }
            }
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    /// A minimal [`Dispatch`] that records received UDP payloads and counts
    /// calls.
    struct CountDispatch {
        received: Vec<Vec<u8>>,
        call_count: usize,
    }

    impl CountDispatch {
        fn new() -> Self {
            Self {
                received: Vec::new(),
                call_count: 0,
            }
        }
    }

    impl Dispatch for CountDispatch {
        fn on_udp(&mut self, _src: SocketAddr, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.received.push(dg.to_vec());
            self.call_count += 1;
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            &[]
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            None
        }
    }

    /// Verify that `drain_udp` reads a datagram from a ready UDP socket and
    /// passes it to the `Dispatch::on_udp` callback.
    #[test]
    fn drain_udp_delivers_datagram() {
        // Two connected loopback sockets.
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();

        // Set `b` non-blocking so drain_udp can drain it without blocking.
        set_nonblocking(b.as_raw_fd()).unwrap();

        // Send a payload to `b` before draining.
        a.send(b"hello from drain_udp test").unwrap();

        // We need a throwaway tun_fd for drain_udp; use /dev/null (write-only
        // is fine — we never actually write for DispatchOut::None).
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let null_fd = devnull.as_raw_fd();

        let mut d = CountDispatch::new();
        drain_udp(b.as_raw_fd(), null_fd, &mut d, 0).unwrap();

        assert_eq!(d.call_count, 1, "on_udp must be called exactly once");
        assert_eq!(d.received[0], b"hello from drain_udp test");
    }

    /// Verify that `drain_udp` handles multiple queued datagrams in one call.
    #[test]
    fn drain_udp_drains_multiple_datagrams() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();
        set_nonblocking(b.as_raw_fd()).unwrap();

        a.send(b"first").unwrap();
        a.send(b"second").unwrap();
        a.send(b"third").unwrap();

        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let null_fd = devnull.as_raw_fd();

        let mut d = CountDispatch::new();
        drain_udp(b.as_raw_fd(), null_fd, &mut d, 0).unwrap();

        assert_eq!(d.call_count, 3);
    }

    /// Verify that `set_nonblocking` idempotently works on a socket fd.
    #[test]
    fn set_nonblocking_is_idempotent() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_nonblocking(sock.as_raw_fd()).unwrap();
        set_nonblocking(sock.as_raw_fd()).unwrap(); // second call must not error
    }

    /// A [`Dispatch`] whose `on_udp` returns `DispatchOut::Udp` — i.e. it
    /// reflects the received datagram back out on the UDP socket (to the
    /// datagram's own source address), optionally replacing its payload.
    /// This exercises the forwarding arm and `send_to_udp` end-to-end via
    /// `drain_udp`.
    struct ForwardDispatch {
        /// Payload to send back.  Cloned once per `on_udp` call.
        reply: Vec<u8>,
        /// Scratch storage so the `&[EgressDatagram]` returned by `on_udp`
        /// lives long enough (it borrows `self`).
        scratch: Vec<EgressDatagram>,
    }

    impl ForwardDispatch {
        fn new(reply: impl Into<Vec<u8>>) -> Self {
            Self {
                reply: reply.into(),
                scratch: Vec::new(),
            }
        }
    }

    impl Dispatch for ForwardDispatch {
        fn on_udp(&mut self, src: SocketAddr, _dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.scratch = vec![EgressDatagram {
                fate: 0,
                dst: src,
                bytes: self.reply.clone(),
            }];
            DispatchOut::Udp(&self.scratch)
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            &[]
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            None
        }
    }

    /// Verify that `drain_udp` honours `DispatchOut::Udp`: a datagram arriving
    /// on socket `b` causes `on_udp` to return `DispatchOut::Udp`, whose
    /// payload is forwarded by `send_to_udp` and received on the peer socket
    /// `a`.
    #[test]
    fn drain_udp_forwards_dispatch_out_udp_to_peer() {
        // Two connected loopback sockets: a ↔ b.
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();

        // `b` must be non-blocking so drain_udp can drain it.
        set_nonblocking(b.as_raw_fd()).unwrap();
        // `a` must be non-blocking so we can do a best-effort receive check.
        set_nonblocking(a.as_raw_fd()).unwrap();

        // Send a trigger datagram from `a` → `b`.
        a.send(b"trigger").unwrap();

        // Use /dev/null as the TUN fd (DispatchOut::Udp never writes to TUN).
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let null_fd = devnull.as_raw_fd();

        // `ForwardDispatch` will reply with "forwarded" for each received dg.
        let mut d = ForwardDispatch::new(b"forwarded".as_slice());
        drain_udp(b.as_raw_fd(), null_fd, &mut d, 0).unwrap();

        // The forwarded datagram must now be readable on `a`.
        let mut recv_buf = [0u8; 64];
        let n = a
            .recv(&mut recv_buf)
            .expect("forwarded datagram must arrive on peer socket");
        assert_eq!(&recv_buf[..n], b"forwarded");
    }

    #[test]
    fn send_mmsg_delivers_each_datagram_to_its_own_dst() {
        use std::net::UdpSocket;
        // Two receiver sockets on distinct ports; one sender.
        let rx_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_a.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        rx_b.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst_a = rx_a.local_addr().unwrap();
        let dst_b = rx_b.local_addr().unwrap();

        let batch = [
            EgressDatagram {
                fate: 0,
                dst: dst_a,
                bytes: b"to-a-1".to_vec(),
            },
            EgressDatagram {
                fate: 0,
                dst: dst_b,
                bytes: b"to-b".to_vec(),
            },
            EgressDatagram {
                fate: 0,
                dst: dst_a,
                bytes: b"to-a-2".to_vec(),
            },
        ];
        let mut sent = 0;
        while sent < batch.len() {
            sent += send_mmsg(tx.as_raw_fd(), &batch[sent..]).unwrap();
        }
        assert_eq!(sent, 3);

        let mut buf = [0u8; 64];
        // rx_a receives two datagrams (order preserved within a dst).
        let (n1, _) = rx_a.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n1], b"to-a-1");
        let (n2, _) = rx_a.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n2], b"to-a-2");
        // rx_b receives its one.
        let (n3, _) = rx_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n3], b"to-b");
    }

    #[test]
    fn recv_mmsg_returns_bytes_and_source_per_datagram() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx_addr = tx.local_addr().unwrap();
        tx.send_to(b"hello", rx_addr).unwrap();
        tx.send_to(b"world!!", rx_addr).unwrap();
        // Give the datagrams time to queue, then drain non-blocking.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut bufs = [[0u8; MAX_WIRE_DATAGRAM]; 4];
        let mut lens = [0usize; 4];
        let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); 4];
        let n = recv_mmsg(rx.as_raw_fd(), &mut bufs, &mut lens, &mut srcs).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&bufs[0][..lens[0]], b"hello");
        assert_eq!(&bufs[1][..lens[1]], b"world!!");
        assert_eq!(srcs[0], tx_addr);
        assert_eq!(srcs[1], tx_addr);
    }

    #[test]
    fn recv_mmsg_returns_zero_when_nothing_queued() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut bufs = [[0u8; MAX_WIRE_DATAGRAM]; 4];
        let mut lens = [0usize; 4];
        let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); 4];
        assert_eq!(
            recv_mmsg(rx.as_raw_fd(), &mut bufs, &mut lens, &mut srcs).unwrap(),
            0
        );
    }
}
