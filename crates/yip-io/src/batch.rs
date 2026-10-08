//! Vectorized `recvmmsg` and `sendmmsg` socket engine.
//!
//! Provides [`BatchUdpSocket`] to send and receive datagram bursts of up to
//! [`BATCH_SIZE`] (32 datagrams) in a single syscall, reducing syscall overhead
//! and maximizing throughput in multi-core packet pipelines.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};

use crate::MAX_WIRE_DATAGRAM;

/// Maximum number of datagrams transferred in a single batched syscall.
pub const BATCH_SIZE: usize = 32;

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
/// batch send and receive operations via `libc::sendmmsg` and `libc::recvmmsg`.
#[derive(Debug)]
pub struct BatchUdpSocket {
    fd: RawFd,
}

impl BatchUdpSocket {
    /// Create a new `BatchUdpSocket` borrowing the raw file descriptor of `sock`.
    #[must_use]
    pub fn new(sock: &UdpSocket) -> Self {
        Self {
            fd: sock.as_raw_fd(),
        }
    }

    /// Create a new `BatchUdpSocket` from an existing raw file descriptor.
    #[must_use]
    pub const fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Return the underlying raw file descriptor.
    #[must_use]
    pub const fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Receive a burst of up to [`BATCH_SIZE`] datagrams into `buffers` via `libc::recvmmsg`.
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
    pub fn recvmmsg_batch(
        &mut self,
        buffers: &mut [[u8; MAX_WIRE_DATAGRAM]; BATCH_SIZE],
        out: &mut [ReceivedDatagram; BATCH_SIZE],
    ) -> io::Result<usize> {
        let mut storages: [libc::sockaddr_storage; BATCH_SIZE] = unsafe {
            // SAFETY: `sockaddr_storage` is a plain-old-data struct consisting of integer
            // and byte array fields. The all-zero bit pattern is a valid initial state that
            // `libc::recvmmsg` overwrites upon receipt.
            std::mem::zeroed()
        };
        let addrlens = [libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
            .expect("sockaddr_storage size fits socklen_t"); BATCH_SIZE];
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; BATCH_SIZE];
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
        }; BATCH_SIZE];

        for i in 0..BATCH_SIZE {
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
                    u32::try_from(BATCH_SIZE).expect("BATCH_SIZE fits u32"),
                    libc::MSG_DONTWAIT,
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
            assert!(
                received <= BATCH_SIZE,
                "recvmmsg returned count exceeding BATCH_SIZE"
            );

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

    /// Send a burst of up to [`BATCH_SIZE`] datagrams in a single `libc::sendmmsg` syscall.
    ///
    /// If `packets.len() > BATCH_SIZE`, only the first [`BATCH_SIZE`] packets are submitted.
    /// Returns the number of datagrams accepted by the kernel (0 if the socket would block).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the underlying `sendmmsg` syscall fails with an unrecoverable error.
    pub fn sendmmsg_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        let count = packets.len().min(BATCH_SIZE);
        if count == 0 {
            return Ok(0);
        }

        let mut storages: [libc::sockaddr_storage; BATCH_SIZE] = unsafe {
            // SAFETY: `sockaddr_storage` is plain-old-data. An all-zero value is a valid
            // initial state that is overwritten for the first `count` items below.
            std::mem::zeroed()
        };
        let mut addrlens = [0 as libc::socklen_t; BATCH_SIZE];
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; BATCH_SIZE];
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
        }; BATCH_SIZE];

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
                    libc::MSG_NOSIGNAL,
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
}

impl AsRawFd for BatchUdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
