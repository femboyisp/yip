//! Kernel-bypass-ready packet I/O. M4 adds the io_uring backend (single ring
//! servicing UDP + TUN/TAP), then AF_XDP. This is the only crate permitted to
//! contain `unsafe`; every `unsafe` block must carry a `// SAFETY:` comment.

pub mod poll;

/// Maximum number of datagrams in a single batched send/recv call.
pub const MAX_DATAGRAM_BATCH: usize = 64;

/// Maximum size (bytes) of a single wire datagram. 2 KiB is ample for any
/// encapsulated MTU-1500 payload plus yip-wire framing overhead.
pub const MAX_WIRE_DATAGRAM: usize = 2048;

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
        // to keep these stack arrays reasonably sized (64 × small structs).
        let count = datagrams.len().min(MAX_DATAGRAM_BATCH);

        // iovec[i] points into the caller-owned slice datagrams[i]; the slices
        // must outlive the sendmmsg call, which they do — both arrays are on our
        // stack and we block until sendmmsg returns.
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
                u32::try_from(count).expect("count ≤ MAX_DATAGRAM_BATCH ≤ 64 fits u32"),
                libc::MSG_NOSIGNAL,
            )
        };

        if ret < 0 {
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
                u32::try_from(count).expect("count ≤ MAX_DATAGRAM_BATCH ≤ 64 fits u32"),
                libc::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
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
/// Raises `SO_SNDBUF` and `SO_RCVBUF` via `setsockopt(2)`.  The kernel may
/// silently clamp or double the requested value (Linux doubles it to account for
/// bookkeeping overhead), so callers should not assume the returned kernel value
/// matches `bytes` exactly — only that the call succeeded.
///
/// This function lives in yip-io (the only crate where `unsafe` is permitted)
/// so that the yipd daemon can stay `#![forbid(unsafe_code)]`.
pub fn set_socket_buffers(sock: &UdpSocket, bytes: usize) -> io::Result<()> {
    let size = i32::try_from(bytes)
        .map_err(|_| io::Error::other("buffer size too large for setsockopt"))?;
    let fd = sock.as_raw_fd();

    // SAFETY: `fd` is a valid file descriptor owned by `sock`, which outlives
    // this call.  `size` is a correctly-typed `i32` matching `SO_SNDBUF`/
    // `SO_RCVBUF`'s expected `optval` type.  We pass its address and exact
    // `size_of::<i32>()` as `optlen`, which is what the kernel expects for
    // these two socket options.  No aliasing or memory-safety issues arise
    // because `size` is a stack-local that we only read (never write) in the
    // unsafe block.
    let ret_snd = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::addr_of!(size).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<i32>())
                .expect("size_of::<i32>() fits socklen_t"),
        )
    };
    if ret_snd != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: same rationale as above; only the option name differs.
    let ret_rcv = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(size).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<i32>())
                .expect("size_of::<i32>() fits socklen_t"),
        )
    };
    if ret_rcv != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
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
    fn set_socket_buffers_succeeds_on_loopback() {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Request 4 MiB buffers; the kernel may clamp or double the value, so
        // we only assert that the call itself succeeds.
        let result = set_socket_buffers(&sock, 4 * 1024 * 1024);
        assert!(
            result.is_ok(),
            "set_socket_buffers returned error: {:?}",
            result
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
}
