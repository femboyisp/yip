//! A minimal, safe `epoll` primitive for the QUIC-mimicry driver (3c.1).
//!
//! `yipd` is `#![forbid(unsafe_code)]`, but the QUIC pump (`bin/yipd/src/quic.rs`)
//! needs the same "wait on UDP + TUN with a caller-chosen timeout" capability
//! that [`crate::poll::run_poll`] has — except `quinn-proto`'s decoupled I/O
//! and dynamic timers want the loop *outside* yip-io, with the driver choosing
//! `min(Connection::poll_timeout(), 10ms)` per iteration. This module exposes
//! exactly that as a small safe wrapper ([`Epoll`]) so all the `epoll`/`fcntl`
//! `unsafe` stays here, in the one crate permitted to hold it.
//!
//! This is intentionally *not* an event loop — it only blocks until one of the
//! two fds is readable (or the timeout fires) and reports which. The driver
//! owns the recv/send/timer logic.

use std::io;
use std::os::fd::RawFd;

/// Which of the two watched fds became readable in the last [`Epoll::wait`].
///
/// Both may be set (both fds ready), or neither (the `wait` timed out — the
/// driver should still run its timer/tick work).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ready {
    /// The UDP socket has at least one datagram to read.
    pub udp: bool,
    /// The TUN/TAP device has at least one frame to read.
    pub tun: bool,
}

/// An `epoll` instance watching a UDP socket fd and a TUN/TAP fd for `EPOLLIN`.
///
/// Owns the epoll fd and closes it on drop. The two watched fds are *not*
/// owned (they belong to the caller's `UdpSocket`/`TunTap`) and are only
/// referenced to identify readiness in [`Epoll::wait`].
pub struct Epoll {
    epoll_fd: RawFd,
    udp_fd: RawFd,
    tun_fd: RawFd,
}

/// Set a file descriptor to non-blocking mode via `fcntl(O_NONBLOCK)`.
///
/// Exposed so a `forbid(unsafe_code)` driver (yipd's QUIC pump) can make its
/// socket/device non-blocking without an `unsafe` block of its own.
pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
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

/// Read from a raw fd into `buf`, returning the number of bytes read.
///
/// A thin safe wrapper over `read(2)` so a `forbid(unsafe_code)` driver can
/// pull frames off a non-socket fd (e.g. a TUN/TAP device, which is not a
/// `UdpSocket` and so has no std read method available through this crate's
/// callers). A would-block condition surfaces as `io::ErrorKind::WouldBlock`.
pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is a valid, writable slice of length `buf.len()`; `fd` is a
    // valid open fd supplied by the caller. `read` writes at most `buf.len()`
    // bytes into `buf` and never beyond it.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(n).expect("non-negative read return fits usize"))
}

/// Write `buf` to a raw fd, returning the number of bytes written.
///
/// The safe counterpart of [`read_fd`] for a non-socket fd (e.g. writing a
/// decoded inner frame to a TUN/TAP device).
pub fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is a valid, readable slice of length `buf.len()`; `fd` is a
    // valid open fd supplied by the caller. `write` reads at most `buf.len()`
    // bytes from `buf` and never beyond it.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(n).expect("non-negative write return fits usize"))
}

impl Epoll {
    /// Create an `epoll` instance registered for `EPOLLIN` on both `udp_fd`
    /// and `tun_fd`. Both fds are set non-blocking as a side effect (the
    /// driver drains them edge-safely with `MSG_DONTWAIT`/non-blocking reads).
    pub fn new(udp_fd: RawFd, tun_fd: RawFd) -> io::Result<Self> {
        set_nonblocking(udp_fd)?;
        set_nonblocking(tun_fd)?;

        // SAFETY: `epoll_create1` creates a new epoll instance. `EPOLL_CLOEXEC`
        // is the only flag passed; the return value is checked below.
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let this = Self {
            epoll_fd,
            udp_fd,
            tun_fd,
        };
        this.register(udp_fd)?;
        this.register(tun_fd)?;
        Ok(this)
    }

    /// Register one fd for `EPOLLIN`, tagging its epoll user-data with the raw
    /// fd so [`Epoll::wait`] can identify which fd is ready.
    fn register(&self, fd: RawFd) -> io::Result<()> {
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fd as u64,
        };
        // SAFETY: `self.epoll_fd` is a valid epoll fd we created and still own;
        // `fd` is a valid fd supplied by the caller; `ev` is a correctly
        // initialised `epoll_event` living on this stack frame for the duration
        // of the call.
        let rc = unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &raw mut ev) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Block until one of the watched fds is readable, or `timeout_ms`
    /// milliseconds elapse (`-1` blocks indefinitely). Returns which fds are
    /// ready; an `EINTR` is reported as "nothing ready" so the caller retries
    /// its loop (running its timers) rather than erroring out.
    pub fn wait(&self, timeout_ms: i32) -> io::Result<Ready> {
        // Two watched fds ⇒ at most two ready events per wait.
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
        // SAFETY: `self.epoll_fd` is a valid epoll fd. `events` is a valid,
        // stack-allocated array whose length we pass as `maxevents`. The kernel
        // writes at most `maxevents` initialised entries, which we read below.
        let nfds = unsafe {
            libc::epoll_wait(
                self.epoll_fd,
                events.as_mut_ptr(),
                libc::c_int::try_from(events.len()).expect("event array len fits c_int"),
                timeout_ms,
            )
        };
        if nfds < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                return Ok(Ready::default());
            }
            return Err(e);
        }

        let mut ready = Ready::default();
        for ev in &events[..usize::try_from(nfds).expect("non-negative nfds fits usize")] {
            let fd = ev.u64 as RawFd;
            if fd == self.udp_fd {
                ready.udp = true;
            } else if fd == self.tun_fd {
                ready.tun = true;
            }
        }
        Ok(ready)
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        // SAFETY: `self.epoll_fd` is a valid fd we created in `new` and have not
        // closed elsewhere; closing it exactly once here is correct.
        unsafe { libc::close(self.epoll_fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    #[test]
    fn wait_reports_each_fd_independently() {
        // Two loopback UDP sockets stand in for the "udp" and "tun" fds — both
        // are epoll-able (a regular file like /dev/null is not: epoll_ctl EPERM).
        let udp_rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp_tx.connect(udp_rx.local_addr().unwrap()).unwrap();

        let tun_rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tun_tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tun_tx.connect(tun_rx.local_addr().unwrap()).unwrap();

        let ep = Epoll::new(udp_rx.as_raw_fd(), tun_rx.as_raw_fd()).unwrap();

        // Nothing sent yet ⇒ a short wait times out with neither fd ready.
        assert_eq!(ep.wait(10).unwrap(), Ready::default());

        // Only the "udp" fd is fed ⇒ only `udp` is reported.
        udp_tx.send(b"ping").unwrap();
        let after_udp = ep.wait(200).unwrap();
        assert!(after_udp.udp, "udp must be ready after a datagram arrives");
        assert!(
            !after_udp.tun,
            "tun must not be reported when only udp was fed"
        );
        udp_rx.recv(&mut [0u8; 8]).unwrap(); // drain so the next wait is clean

        // Only the "tun" fd is fed ⇒ only `tun` is reported.
        tun_tx.send(b"frame").unwrap();
        let after_tun = ep.wait(200).unwrap();
        assert!(after_tun.tun, "tun must be ready after a frame arrives");
        assert!(
            !after_tun.udp,
            "udp must not be reported when only tun was fed"
        );
    }

    #[test]
    fn wait_times_out_with_nothing_ready() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ep = Epoll::new(a.as_raw_fd(), b.as_raw_fd()).unwrap();
        assert_eq!(
            ep.wait(5).unwrap(),
            Ready::default(),
            "idle fds must report nothing ready"
        );
    }
}
