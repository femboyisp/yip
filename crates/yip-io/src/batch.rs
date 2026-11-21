//! Vectorized `recvmmsg` and `sendmmsg` socket engine.
//!
//! Provides [`BatchUdpSocket`] to send and receive datagram bursts of up to
//! [`BATCH_SIZE`] (32 datagrams) in a single syscall, reducing syscall overhead
//! and maximizing throughput in multi-core packet pipelines.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};

use crate::MAX_WIRE_DATAGRAM;

/// Maximum number of datagrams transferred in a single default batched syscall.
pub const BATCH_SIZE: usize = 32;

/// Expanded 64-datagram burst size for high-packet-rate 10G/25G interfaces.
pub const BATCH_SIZE_64: usize = 64;

/// Ultra-high 128-datagram burst size for maximum syscall amortization at 40G+ line rate.
pub const BATCH_SIZE_128: usize = 128;

/// Metadata for a single datagram received via [`BatchUdpSocket::recvmmsg_batch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedDatagram {
    /// Actual byte length of the received datagram payload.
    pub len: usize,
    /// Source socket address from which the datagram originated.
    pub src: SocketAddr,
}

impl ReceivedDatagram {
    /// Return an empty `ReceivedDatagram` with length 0 and unspecified source address.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            len: 0,
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}

impl Default for ReceivedDatagram {
    fn default() -> Self {
        Self::empty()
    }
}

/// A non-owning wrapper around a UDP socket file descriptor providing vectorized
/// batch send and receive operations via `libc::sendmmsg` and `libc::recvmmsg`,
/// with hardware UDP Generic Segmentation Offload (`UDP_SEGMENT` / GSO) acceleration.
#[derive(Debug)]
pub struct BatchUdpSocket {
    fd: RawFd,
    gso_enabled: bool,
    gso_segment_size: Option<u16>,
}

impl BatchUdpSocket {
    /// Create a new `BatchUdpSocket` borrowing the raw file descriptor of `sock`.
    ///
    /// Automatically probes and latches `UDP_SEGMENT` GSO support on the socket.
    #[must_use]
    pub fn new(sock: &UdpSocket) -> Self {
        let fd = sock.as_raw_fd();
        let gso_enabled = Self::detect_gso_support(fd);
        Self {
            fd,
            gso_enabled,
            gso_segment_size: None,
        }
    }

    /// Create a new `BatchUdpSocket` from an existing raw file descriptor.
    ///
    /// Note: `is_gso_enabled()` defaults to `false` for raw file descriptors.
    /// Call [`BatchUdpSocket::probe_gso`] to probe and enable kernel GSO support.
    #[must_use]
    pub const fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            fd,
            gso_enabled: false,
            gso_segment_size: None,
        }
    }

    /// Return the underlying raw file descriptor.
    #[must_use]
    pub const fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Return whether UDP segmentation offload (GSO) is currently enabled.
    #[must_use]
    pub const fn is_gso_enabled(&self) -> bool {
        self.gso_enabled
    }

    /// Explicitly enable or disable UDP segmentation offload (GSO).
    pub fn set_gso_enabled(&mut self, enabled: bool) {
        self.gso_enabled = enabled;
    }

    /// Return the currently configured socket-level GSO segment size, if any.
    #[must_use]
    pub const fn gso_segment_size(&self) -> Option<u16> {
        self.gso_segment_size
    }

    /// Probe whether the underlying socket supports `UDP_SEGMENT` via `getsockopt`.
    ///
    /// Updates `self.gso_enabled` and returns `true` if supported, `false` otherwise.
    pub fn probe_gso(&mut self) -> bool {
        let supported = Self::detect_gso_support(self.fd);
        self.gso_enabled = supported;
        supported
    }

    /// Internal probe helper using `getsockopt(SOL_UDP, UDP_SEGMENT)`.
    fn detect_gso_support(fd: RawFd) -> bool {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt with SOL_UDP / UDP_SEGMENT. If supported, returns 0.
        // If unsupported by the kernel or on non-socket, returns -1 with EINVAL/ENOPROTOOPT/ENOTSOCK.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_UDP,
                libc::UDP_SEGMENT,
                std::ptr::from_mut(&mut val).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        ret == 0
    }

    /// Configure socket-level `UDP_SEGMENT` segment size on the underlying socket.
    ///
    /// When set to a non-zero value, standard datagrams larger than `segment_size`
    /// sent on this socket will be automatically segmented by kernel/NIC hardware.
    /// Setting `segment_size = 0` disables socket-level segmentation.
    ///
    /// Returns `Ok(true)` if configured successfully, `Ok(false)` if unsupported by the kernel.
    pub fn set_socket_gso_segment(&mut self, segment_size: u16) -> io::Result<bool> {
        let val: libc::c_int = libc::c_int::from(segment_size);
        // SAFETY: setsockopt with SOL_UDP / UDP_SEGMENT.
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_UDP,
                libc::UDP_SEGMENT,
                std::ptr::from_ref(&val).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            self.gso_segment_size = if segment_size > 0 {
                Some(segment_size)
            } else {
                None
            };
            self.gso_enabled = true;
            Ok(true)
        } else {
            let err = io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0);
            if raw == libc::EINVAL || raw == libc::ENOPROTOOPT || raw == libc::EOPNOTSUPP {
                self.gso_enabled = false;
                Ok(false)
            } else {
                Err(err)
            }
        }
    }

    /// Send a single GSO superpacket using a `UDP_SEGMENT` cmsg header.
    ///
    /// Returns `Ok(bytes_sent)` on success (0 if the socket would block).
    pub fn send_gso_superpacket(
        &self,
        payload: &[u8],
        segment_size: u16,
        dst: SocketAddr,
    ) -> io::Result<usize> {
        send_gso_superpacket_fd(self.fd, payload, segment_size, dst)
    }

    /// Receive a burst of up to `N` datagrams into `buffers` via `libc::recvmmsg`.
    ///
    /// For each received datagram:
    /// - The datagram payload bytes are written into `buffers[i]`.
    /// - Metadata (byte length and source address) is recorded in `out[i]`.
    ///
    /// Returns the number of datagrams actually received (0 if the socket would block).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the underlying `recvmmsg` syscall fails with any error
    /// other than `EAGAIN` or `EWOULDBLOCK`.
    pub fn recvmmsg_batch<const N: usize>(
        &mut self,
        buffers: &mut [[u8; MAX_WIRE_DATAGRAM]; N],
        out: &mut [ReceivedDatagram; N],
    ) -> io::Result<usize> {
        if N == 0 {
            return Ok(0);
        }

        let mut storages: [libc::sockaddr_storage; N] = unsafe {
            // SAFETY: `sockaddr_storage` is a plain-old-data struct consisting of integer
            // and byte array fields. The all-zero bit pattern is a valid initial state that
            // `libc::recvmmsg` overwrites upon receipt.
            std::mem::zeroed()
        };
        let addrlens = [libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
            .expect("sockaddr_storage size fits socklen_t"); N];
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; N];
        let mut msgs = [crate::empty_mmsghdr(); N];

        for i in 0..N {
            iovecs[i].iov_base = buffers[i].as_mut_ptr().cast::<libc::c_void>();
            iovecs[i].iov_len = MAX_WIRE_DATAGRAM;
            msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = std::ptr::from_mut(&mut storages[i]).cast::<libc::c_void>();
            msgs[i].msg_hdr.msg_namelen = addrlens[i];
        }

        loop {
            // SAFETY: `msgs` is fully initialized with non-overlapping pointers:
            // each `msg_iov` points to `iovecs[i]`, and each `msg_name` points to `storages[i]`,
            // both residing on this stack frame. `iovecs[i].iov_base` points to caller-supplied
            // `buffers[i]` which outlives this call. No pointers alias each other, and all remain
            // valid throughout the syscall. `MSG_DONTWAIT` ensures the call returns immediately
            // if no packets are queued.
            let ret = unsafe {
                libc::recvmmsg(
                    self.fd,
                    msgs.as_mut_ptr(),
                    u32::try_from(N).expect("N fits u32"),
                    libc::MSG_DONTWAIT as crate::MsgFlags,
                    std::ptr::null_mut(),
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                let raw = err.raw_os_error().unwrap_or(0);
                if raw == libc::EINTR {
                    continue;
                }
                if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN {
                    return Ok(0);
                }
                return Err(err);
            }

            let received = usize::try_from(ret).expect("recvmmsg return fits usize");
            assert!(received <= N, "recvmmsg returned count exceeding N");

            for i in 0..received {
                let len = usize::try_from(msgs[i].msg_len).expect("msg_len fits usize");
                let src = crate::addr::sockaddr_to_std(&storages[i], msgs[i].msg_hdr.msg_namelen)
                    .unwrap_or_else(|_| {
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                    });
                out[i] = ReceivedDatagram { len, src };
            }

            return Ok(received);
        }
    }

    /// Send a burst of up to [`BATCH_SIZE`] (32) datagrams in a single `libc::sendmmsg` syscall.
    ///
    /// If `packets.len() > BATCH_SIZE`, only the first [`BATCH_SIZE`] packets are submitted.
    /// Returns the number of datagrams accepted by the kernel (0 if the socket would block).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the underlying `sendmmsg` syscall fails with an unrecoverable error.
    pub fn sendmmsg_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        self.sendmmsg_burst::<BATCH_SIZE>(packets)
    }

    /// Send a burst of up to `N` datagrams in a single `libc::sendmmsg` syscall.
    ///
    /// If `packets.len() > N`, only the first `N` packets are submitted.
    /// Returns the number of datagrams accepted by the kernel (0 if the socket would block).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the underlying `sendmmsg` syscall fails with an unrecoverable error.
    pub fn sendmmsg_burst<const N: usize>(
        &mut self,
        packets: &[(&[u8], SocketAddr)],
    ) -> io::Result<usize> {
        let count = packets.len().min(N);
        if count == 0 {
            return Ok(0);
        }

        let mut storages: [libc::sockaddr_storage; N] = unsafe {
            // SAFETY: `sockaddr_storage` is plain-old-data. An all-zero value is a valid
            // initial state that is overwritten for the first `count` items below.
            std::mem::zeroed()
        };
        let mut addrlens = [0 as libc::socklen_t; N];
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; N];
        let mut msgs = [crate::empty_mmsghdr(); N];

        for (i, &(payload, dst)) in packets[..count].iter().enumerate() {
            let (storage, addr_len) = crate::addr::std_to_sockaddr(dst);
            storages[i] = storage;
            addrlens[i] = addr_len;
            iovecs[i].iov_base = payload.as_ptr().cast_mut().cast::<libc::c_void>();
            iovecs[i].iov_len = payload.len();
            msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = std::ptr::from_mut(&mut storages[i]).cast::<libc::c_void>();
            msgs[i].msg_hdr.msg_namelen = addrlens[i];
        }

        loop {
            // SAFETY: `msgs[..count]` is fully initialized: each `msg_iov` points to `iovecs[i]`
            // and `msg_name` points to `storages[i]` on this stack frame. The `payload` slices
            // are borrowed from `packets` and remain valid for the duration of the call.
            // `MSG_NOSIGNAL` suppresses SIGPIPE if a peer connection is reset.
            let ret = unsafe {
                libc::sendmmsg(
                    self.fd,
                    msgs.as_mut_ptr(),
                    u32::try_from(count).expect("count fits u32"),
                    libc::MSG_NOSIGNAL as crate::MsgFlags,
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                let raw = err.raw_os_error().unwrap_or(0);
                if raw == libc::EINTR {
                    continue;
                }
                if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
                    return Ok(0);
                }
                return Err(err);
            }

            return Ok(usize::try_from(ret).expect("sendmmsg return fits usize"));
        }
    }

    /// Send a batch of up to [`BATCH_SIZE`] (32) [`crate::poll::EgressDatagram`] packets in a single `sendmmsg` syscall.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the underlying `sendmmsg` syscall fails with an unrecoverable error.
    pub fn sendmmsg_datagrams(&mut self, dgs: &[crate::poll::EgressDatagram]) -> io::Result<usize> {
        self.sendmmsg_datagrams_burst::<BATCH_SIZE>(dgs)
    }

    /// Send a burst of up to `N` [`crate::poll::EgressDatagram`] packets in a single `libc::sendmmsg` syscall.
    ///
    /// If `dgs.len() > N`, only the first `N` packets are submitted.
    /// Returns the number of datagrams accepted by the kernel (0 if the socket would block).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the underlying `sendmmsg` syscall fails with an unrecoverable error.
    pub fn sendmmsg_datagrams_burst<const N: usize>(
        &mut self,
        dgs: &[crate::poll::EgressDatagram],
    ) -> io::Result<usize> {
        let count = dgs.len().min(N);
        if count == 0 {
            return Ok(0);
        }

        let mut storages: [libc::sockaddr_storage; N] = unsafe {
            // SAFETY: `sockaddr_storage` is plain-old-data. An all-zero value is a valid
            // initial state that is overwritten for the first `count` items below.
            std::mem::zeroed()
        };
        let mut addrlens = [0 as libc::socklen_t; N];
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; N];
        let mut msgs = [crate::empty_mmsghdr(); N];

        for (i, dg) in dgs[..count].iter().enumerate() {
            let (storage, addr_len) = crate::addr::std_to_sockaddr(dg.dst);
            storages[i] = storage;
            addrlens[i] = addr_len;
            iovecs[i].iov_base = dg.bytes.as_ptr().cast_mut().cast::<libc::c_void>();
            iovecs[i].iov_len = dg.bytes.len();
            msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = std::ptr::from_mut(&mut storages[i]).cast::<libc::c_void>();
            msgs[i].msg_hdr.msg_namelen = addrlens[i];
        }

        loop {
            // SAFETY: `msgs[..count]` is fully initialized: each `msg_iov` points to `iovecs[i]`
            // and `msg_name` points to `storages[i]` on this stack frame. The `bytes` buffers
            // are borrowed from `dgs` and remain valid for the duration of the call.
            // `MSG_NOSIGNAL` suppresses SIGPIPE if a peer connection is reset.
            let ret = unsafe {
                libc::sendmmsg(
                    self.fd,
                    msgs.as_mut_ptr(),
                    u32::try_from(count).expect("count fits u32"),
                    libc::MSG_NOSIGNAL as crate::MsgFlags,
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                let raw = err.raw_os_error().unwrap_or(0);
                if raw == libc::EINTR {
                    continue;
                }
                if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
                    return Ok(0);
                }
                return Err(err);
            }

            return Ok(usize::try_from(ret).expect("sendmmsg return fits usize"));
        }
    }

    /// Send a batch of packets using hardware UDP Generic Segmentation Offload (GSO).
    ///
    /// Coalesces contiguous packets sharing destination address and segment length
    /// into `UDP_SEGMENT` super-datagrams. Falls back gracefully to standard `sendmmsg`
    /// if `UDP_SEGMENT` is unsupported by the host kernel or interface.
    ///
    /// Returns the number of datagrams accepted by the kernel (0 if the socket would block).
    pub fn send_gso_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        self.send_gso_burst::<BATCH_SIZE>(packets)
    }

    /// Send a batch of packets using GSO, aliased to `sendmmsg_or_gso`.
    pub fn sendmmsg_or_gso(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        self.send_gso_burst::<BATCH_SIZE>(packets)
    }

    /// Send a burst of up to `N` packets using GSO, aliased to `sendmmsg_or_gso_burst`.
    pub fn sendmmsg_or_gso_burst<const N: usize>(
        &mut self,
        packets: &[(&[u8], SocketAddr)],
    ) -> io::Result<usize> {
        self.send_gso_burst::<N>(packets)
    }

    /// Send a burst of up to `N` packets using hardware UDP Generic Segmentation Offload (GSO).
    ///
    /// Contiguous packets sharing destination address and segment size are coalesced
    /// into a single `UDP_SEGMENT` super-skb using control messages (`cmsg`).
    /// If GSO is unsupported or returns `EINVAL`/`ENOPROTOOPT`/`EOPNOTSUPP`/`EIO`,
    /// GSO is automatically latched off and remaining packets are dispatched via `sendmmsg`.
    ///
    /// Operates with ZERO heap allocations on the hot path.
    pub fn send_gso_burst<const N: usize>(
        &mut self,
        packets: &[(&[u8], SocketAddr)],
    ) -> io::Result<usize> {
        let count = packets.len().min(N);
        if count == 0 {
            return Ok(0);
        }

        if !self.gso_enabled {
            return self.sendmmsg_burst::<N>(packets);
        }

        let mut sent_total = 0;
        let mut i = 0;

        while i < count {
            let dst = packets[i].1;
            let seg_len = packets[i].0.len();
            let mut j = i + 1;

            if seg_len > 0 && seg_len <= u16::MAX as usize {
                let max_segs = crate::gso::max_gso_run_len(
                    seg_len as u16,
                    N.min(crate::gso::MAX_GSO_SEGMENTS_PER_SEND),
                );
                while j < count && (j - i) < max_segs {
                    if packets[j].1 != dst || packets[j].0.len() != seg_len {
                        break;
                    }
                    j += 1;
                }
            }

            let run_len = j - i;
            if run_len >= 2 && seg_len > 0 && seg_len <= u16::MAX as usize {
                match self.send_gso_packet_run::<N>(&packets[i..j], seg_len as u16, dst) {
                    Ok(true) => {
                        sent_total += run_len;
                        i = j;
                    }
                    Ok(false) => {
                        break;
                    }
                    Err(e) => {
                        let raw = e.raw_os_error().unwrap_or(0);
                        if raw == libc::EINVAL
                            || raw == libc::ENOPROTOOPT
                            || raw == libc::EOPNOTSUPP
                            || raw == libc::EIO
                        {
                            self.gso_enabled = false;
                            let fb = self.sendmmsg_burst::<N>(&packets[i..count])?;
                            return Ok(sent_total + fb);
                        }
                        return Err(e);
                    }
                }
            } else {
                let mut k = j;
                while k < count {
                    let k_dst = packets[k].1;
                    let k_len = packets[k].0.len();
                    if k + 1 < count
                        && packets[k + 1].1 == k_dst
                        && packets[k + 1].0.len() == k_len
                        && k_len > 0
                        && k_len <= u16::MAX as usize
                    {
                        break;
                    }
                    k += 1;
                }
                let singletons_sent = self.sendmmsg_burst::<N>(&packets[i..k])?;
                sent_total += singletons_sent;
                if singletons_sent < (k - i) {
                    break;
                }
                i = k;
            }
        }

        Ok(sent_total)
    }

    /// Send a batch of `EgressDatagram` packets using hardware UDP Generic Segmentation Offload (GSO).
    ///
    /// Enforces FEC fate group safety (datagrams sharing a non-zero `fate` object id
    /// are never coalesced together into the same super-skb). Falls back gracefully
    /// to standard `sendmmsg` if `UDP_SEGMENT` is unsupported.
    pub fn send_gso_datagrams(&mut self, dgs: &[crate::poll::EgressDatagram]) -> io::Result<usize> {
        self.send_gso_datagrams_burst::<BATCH_SIZE>(dgs)
    }

    /// Send a burst of up to `N` `EgressDatagram` packets using GSO.
    pub fn send_gso_datagrams_burst<const N: usize>(
        &mut self,
        dgs: &[crate::poll::EgressDatagram],
    ) -> io::Result<usize> {
        let count = dgs.len().min(N);
        if count == 0 {
            return Ok(0);
        }

        if !self.gso_enabled {
            return self.sendmmsg_datagrams_burst::<N>(dgs);
        }

        let mut sent_total = 0;
        let mut i = 0;

        while i < count {
            let dst = dgs[i].dst;
            let seg_len = dgs[i].bytes.len();
            let mut j = i + 1;

            if seg_len > 0 && seg_len <= u16::MAX as usize {
                let max_segs = crate::gso::max_gso_run_len(
                    seg_len as u16,
                    N.min(crate::gso::MAX_GSO_SEGMENTS_PER_SEND),
                );
                while j < count && (j - i) < max_segs {
                    let next = &dgs[j];
                    if next.dst != dst || next.bytes.len() != seg_len {
                        break;
                    }
                    if next.fate != 0 && dgs[i..j].iter().any(|prev| prev.fate == next.fate) {
                        break;
                    }
                    j += 1;
                }
            }

            let run_len = j - i;
            if run_len >= 2 && seg_len > 0 && seg_len <= u16::MAX as usize {
                match self.send_gso_datagram_run::<N>(&dgs[i..j], seg_len as u16, dst) {
                    Ok(true) => {
                        sent_total += run_len;
                        i = j;
                    }
                    Ok(false) => {
                        break;
                    }
                    Err(e) => {
                        let raw = e.raw_os_error().unwrap_or(0);
                        if raw == libc::EINVAL
                            || raw == libc::ENOPROTOOPT
                            || raw == libc::EOPNOTSUPP
                            || raw == libc::EIO
                        {
                            self.gso_enabled = false;
                            let fb = self.sendmmsg_datagrams_burst::<N>(&dgs[i..count])?;
                            return Ok(sent_total + fb);
                        }
                        return Err(e);
                    }
                }
            } else {
                let mut k = j;
                while k < count {
                    let k_dst = dgs[k].dst;
                    let k_len = dgs[k].bytes.len();
                    if k + 1 < count
                        && dgs[k + 1].dst == k_dst
                        && dgs[k + 1].bytes.len() == k_len
                        && k_len > 0
                        && k_len <= u16::MAX as usize
                        && (dgs[k].fate == 0 || dgs[k].fate != dgs[k + 1].fate)
                    {
                        break;
                    }
                    k += 1;
                }
                let singletons_sent = self.sendmmsg_datagrams_burst::<N>(&dgs[i..k])?;
                sent_total += singletons_sent;
                if singletons_sent < (k - i) {
                    break;
                }
                i = k;
            }
        }

        Ok(sent_total)
    }

    /// Transmit a contiguous run of packets as a single GSO super-datagram with UDP_SEGMENT cmsg.
    fn send_gso_packet_run<const N: usize>(
        &self,
        run: &[(&[u8], SocketAddr)],
        segment_size: u16,
        dst: SocketAddr,
    ) -> io::Result<bool> {
        let (mut storage, addr_len) = crate::addr::std_to_sockaddr(dst);
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; N];

        for (k, pkt) in run.iter().enumerate().take(N) {
            iovecs[k].iov_base = pkt.0.as_ptr().cast_mut().cast::<libc::c_void>();
            iovecs[k].iov_len = pkt.0.len();
        }

        let mut control = [0u64; 8];
        // SAFETY: msghdr is plain-old-data; zeroed is a valid initial state.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = std::ptr::from_mut(&mut storage).cast::<libc::c_void>();
        msg.msg_namelen = addr_len;
        msg.msg_iov = iovecs.as_mut_ptr();
        msg.msg_iovlen = run.len().min(N) as crate::IovLen;
        msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
        // SAFETY: CMSG_SPACE is a pure size computation.
        let cmsg_space =
            usize::try_from(unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) })
                .unwrap_or(std::mem::size_of_val(&control));
        msg.msg_controllen = cmsg_space as crate::CmsgLen;

        // SAFETY: msg points to valid control storage; write SOL_UDP / UDP_SEGMENT cmsg.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            if cmsg.is_null() {
                return Err(io::Error::other("failed to acquire cmsg header"));
            }
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            (*cmsg).cmsg_len = usize::try_from(libc::CMSG_LEN(std::mem::size_of::<u16>() as u32))
                .unwrap_or(0) as crate::CmsgLen;
            let seg_ptr = libc::CMSG_DATA(cmsg).cast::<u16>();
            *seg_ptr = segment_size;
        }

        loop {
            // SAFETY: msg is fully initialized and points to valid stack frame structures.
            let ret = unsafe { libc::sendmsg(self.fd, &raw const msg, libc::MSG_NOSIGNAL) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                let raw = err.raw_os_error().unwrap_or(0);
                if raw == libc::EINTR {
                    continue;
                }
                if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
                    return Ok(false);
                }
                return Err(err);
            }
            return Ok(true);
        }
    }

    /// Transmit a contiguous run of datagrams as a single GSO super-datagram with UDP_SEGMENT cmsg.
    fn send_gso_datagram_run<const N: usize>(
        &self,
        run: &[crate::poll::EgressDatagram],
        segment_size: u16,
        dst: SocketAddr,
    ) -> io::Result<bool> {
        let (mut storage, addr_len) = crate::addr::std_to_sockaddr(dst);
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; N];

        for (k, dg) in run.iter().enumerate().take(N) {
            iovecs[k].iov_base = dg.bytes.as_ptr().cast_mut().cast::<libc::c_void>();
            iovecs[k].iov_len = dg.bytes.len();
        }

        let mut control = [0u64; 8];
        // SAFETY: msghdr is plain-old-data; zeroed is a valid initial state.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = std::ptr::from_mut(&mut storage).cast::<libc::c_void>();
        msg.msg_namelen = addr_len;
        msg.msg_iov = iovecs.as_mut_ptr();
        msg.msg_iovlen = run.len().min(N) as crate::IovLen;
        msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
        // SAFETY: CMSG_SPACE is a pure size computation.
        let cmsg_space =
            usize::try_from(unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) })
                .unwrap_or(std::mem::size_of_val(&control));
        msg.msg_controllen = cmsg_space as crate::CmsgLen;

        // SAFETY: msg points to valid control storage; write SOL_UDP / UDP_SEGMENT cmsg.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            if cmsg.is_null() {
                return Err(io::Error::other("failed to acquire cmsg header"));
            }
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            (*cmsg).cmsg_len = usize::try_from(libc::CMSG_LEN(std::mem::size_of::<u16>() as u32))
                .unwrap_or(0) as crate::CmsgLen;
            let seg_ptr = libc::CMSG_DATA(cmsg).cast::<u16>();
            *seg_ptr = segment_size;
        }

        loop {
            // SAFETY: msg is fully initialized and points to valid stack frame structures.
            let ret = unsafe { libc::sendmsg(self.fd, &raw const msg, libc::MSG_NOSIGNAL) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                let raw = err.raw_os_error().unwrap_or(0);
                if raw == libc::EINTR {
                    continue;
                }
                if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
                    return Ok(false);
                }
                return Err(err);
            }
            return Ok(true);
        }
    }
}

impl AsRawFd for BatchUdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Probe and optionally set socket-level `UDP_SEGMENT` size if supported by kernel.
/// Returns `Ok(true)` if supported and configured, `Ok(false)` if unsupported by kernel/NIC.
pub fn set_udp_gso_segment(sock: &UdpSocket, segment_size: u16) -> io::Result<bool> {
    let val: libc::c_int = libc::c_int::from(segment_size);
    // SAFETY: setsockopt with SOL_UDP / UDP_SEGMENT. If unsupported, EINVAL/ENOPROTOOPT/EOPNOTSUPP returned.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            std::ptr::from_ref(&val).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        let raw = err.raw_os_error().unwrap_or(0);
        if raw == libc::EINVAL || raw == libc::ENOPROTOOPT || raw == libc::EOPNOTSUPP {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

/// Send a GSO superpacket using a `UDP_SEGMENT` cmsg header.
/// Returns `Ok(bytes_sent)` on success.
pub fn send_gso_superpacket(
    sock: &UdpSocket,
    payload: &[u8],
    segment_size: u16,
    dst: SocketAddr,
) -> io::Result<usize> {
    send_gso_superpacket_fd(sock.as_raw_fd(), payload, segment_size, dst)
}

/// Internal helper to send a GSO superpacket over raw fd.
fn send_gso_superpacket_fd(
    fd: RawFd,
    payload: &[u8],
    segment_size: u16,
    dst: SocketAddr,
) -> io::Result<usize> {
    let (mut storage, addr_len) = crate::addr::std_to_sockaddr(dst);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut control = [0u64; 8];
    // SAFETY: msghdr is POD; zeroed is a valid initial state.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::from_mut(&mut storage).cast::<libc::c_void>();
    msg.msg_namelen = addr_len;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: CMSG_SPACE is a pure size computation.
    let cmsg_space =
        usize::try_from(unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) })
            .unwrap_or(std::mem::size_of_val(&control));
    msg.msg_controllen = cmsg_space as crate::CmsgLen;

    // SAFETY: msg points to valid control storage; write SOL_UDP / UDP_SEGMENT cmsg.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            return Err(io::Error::other("failed to acquire cmsg header"));
        }
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = usize::try_from(libc::CMSG_LEN(std::mem::size_of::<u16>() as u32))
            .unwrap_or(0) as crate::CmsgLen;
        let seg_ptr = libc::CMSG_DATA(cmsg).cast::<u16>();
        *seg_ptr = segment_size;
    }

    loop {
        // SAFETY: msg is fully initialized and points to valid stack frame structures.
        let ret = unsafe { libc::sendmsg(fd, &raw const msg, libc::MSG_NOSIGNAL) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0);
            if raw == libc::EINTR {
                continue;
            }
            if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
                return Ok(0);
            }
            return Err(err);
        }
        return Ok(usize::try_from(ret).unwrap_or(0));
    }
}
