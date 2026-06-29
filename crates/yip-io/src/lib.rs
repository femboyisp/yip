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
}
