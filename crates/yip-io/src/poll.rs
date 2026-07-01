//! Single-threaded epoll-driven event loop for the yip data plane.
//!
//! `run_poll` drives both the UDP socket and TUN fd from a single OS thread,
//! eliminating the need for `Arc<Mutex<...>>` across two threads.  The caller
//! provides a [`Dispatch`] implementor that owns all mutable data-plane state.
//!
//! This module contains all Linux `epoll`/`fcntl` unsafe code for yipd.  Every
//! `unsafe` block carries a `// SAFETY:` comment explaining the invariants.

use std::io;
use std::os::fd::RawFd;
use std::time::Instant;

use crate::MAX_WIRE_DATAGRAM;

/// A single-threaded data-plane dispatch interface.
///
/// Implementors hold all mutable state (AEAD session, FEC transport, codec,
/// auxiliary logs).  [`run_poll`] drives this trait from an `epoll` loop.
pub trait Dispatch {
    /// Called when a UDP datagram arrives.  Returns what [`run_poll`] must
    /// forward (to TUN, back to UDP, both, or nothing).
    fn on_udp(&mut self, dg: &[u8], now_ms: u64) -> DispatchOut<'_>;

    /// Called when a TUN frame arrives.  Returns egress datagrams to send on
    /// the UDP socket (may be empty).
    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[Vec<u8>];

    /// Called at least every 10 ms.  Returns `Some(pkt)` if a feedback
    /// control packet should be sent on the UDP socket.
    fn tick(&mut self, now_ms: u64) -> Option<&[u8]>;
}

/// What [`run_poll`] must do after a call to [`Dispatch::on_udp`].
pub enum DispatchOut<'a> {
    /// Nothing to forward.
    None,
    /// Write this slice to the TUN device (decoded inner packet).
    Tun(&'a [u8]),
    /// Send these datagrams on the UDP socket (ARQ retransmits).
    Udp(&'a [Vec<u8>]),
    /// Write to TUN *and* send datagrams.
    Both(&'a [u8], &'a [Vec<u8>]),
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
        // SAFETY: `buf` is a valid stack buffer of length MAX_WIRE_DATAGRAM.
        // `recv` with MSG_DONTWAIT is a non-blocking receive into that buffer.
        // `udp_fd` is a valid connected UDP socket fd supplied by the caller.
        let n = unsafe {
            libc::recv(
                udp_fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
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

        let dg = &buf[..usize::try_from(n).expect("non-negative recv return fits usize")];

        // Dispatch and forward the result.  The borrow of `d` from `on_udp`
        // (inside `DispatchOut`) is dropped at the end of the match arm.
        match d.on_udp(dg, now_ms) {
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
        let pkts_owned: Vec<Vec<u8>> = d.on_tun(inner, now_ms).to_vec();
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

/// Send one datagram on the UDP socket.
///
/// Propagates errors so that a closed socket terminates the event loop.
#[inline]
fn send_to_udp(udp_fd: RawFd, buf: &[u8]) -> io::Result<()> {
    // SAFETY: `buf` is a valid slice.  `udp_fd` is a valid connected UDP
    // socket fd.  MSG_NOSIGNAL suppresses SIGPIPE if the peer has closed.
    let rc = unsafe { libc::send(udp_fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
                events.len() as libc::c_int,
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
        if let Some(pkt) = d.tick(now_ms) {
            if let Err(e) = send_to_udp(udp_fd, pkt) {
                // SAFETY: `epoll_fd` is valid.
                unsafe { libc::close(epoll_fd) };
                return Err(e);
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
        fn on_udp(&mut self, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.received.push(dg.to_vec());
            self.call_count += 1;
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[Vec<u8>] {
            &[]
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[u8]> {
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
}
