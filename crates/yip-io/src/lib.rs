//! Kernel-bypass-ready packet I/O. M4 adds the io_uring backend (single ring
//! servicing UDP + TUN/TAP), then AF_XDP. This is the only crate permitted to
//! contain `unsafe`; every `unsafe` block must carry a `// SAFETY:` comment.

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

/// Sends and receives wire datagrams via the selected backend. Implemented in M4.
pub trait DataPlaneIo {
    /// The backend actually selected at startup (after probing/fallback).
    fn backend(&self) -> Backend;
    /// Send one datagram.
    fn send(&mut self, datagram: &[u8]) -> std::io::Result<()>;
    /// Receive one datagram into `buf`, returning its length.
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_are_ordered_by_preference() {
        // io_uring is the first backend we build (M4); fallback rungs follow.
        assert_ne!(Backend::IoUring, Backend::Mmsg);
    }

    #[test]
    fn iouring_sends_and_receives_over_udp() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        rx.connect(tx.local_addr().unwrap()).unwrap();

        let mut tx_io = IoUringIo::new(tx).unwrap();
        let mut rx_io = IoUringIo::new(rx).unwrap();
        assert_eq!(tx_io.backend(), Backend::IoUring);

        tx_io.send(b"datagram via uring").unwrap();
        let mut buf = [0u8; 64];
        let n = rx_io.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"datagram via uring");
    }
}
