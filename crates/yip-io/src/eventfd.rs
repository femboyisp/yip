//! Non-blocking Linux eventfd wrapper for reactor wakeup signaling.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Non-blocking Linux eventfd wrapper for cross-thread reactor wakeups.
#[derive(Debug)]
pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    /// Create a new non-blocking, close-on-exec eventfd.
    pub fn new() -> io::Result<Self> {
        // SAFETY: Calling libc::eventfd with EFD_NONBLOCK and EFD_CLOEXEC.
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a valid open file descriptor returned by libc::eventfd.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd: owned })
    }

    /// Notify the eventfd counter by incrementing it by 1.
    ///
    /// Never blocks: returns Ok(()) immediately, ignoring EAGAIN if the counter is full.
    pub fn notify(&self) -> io::Result<()> {
        let val: u64 = 1;
        // SAFETY: Writing 8 bytes from stack into a valid eventfd descriptor.
        let ret = unsafe { libc::write(self.fd.as_raw_fd(), (&raw const val).cast(), 8) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    /// Drain and reset the eventfd counter to 0, returning the accumulated value.
    ///
    /// Never blocks: returns Ok(0) if no notifications were pending (EAGAIN).
    pub fn drain(&self) -> io::Result<u64> {
        let mut val: u64 = 0;
        // SAFETY: Reading 8 bytes into stack from a valid eventfd descriptor.
        let ret = unsafe { libc::read(self.fd.as_raw_fd(), (&raw mut val).cast(), 8) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(val)
    }

    /// Duplicate the underlying file descriptor.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
        })
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eventfd_notify_and_drain() {
        let efd = EventFd::new().expect("eventfd creation succeeds");
        assert_eq!(efd.drain().unwrap(), 0);

        efd.notify().unwrap();
        efd.notify().unwrap();
        assert_eq!(efd.drain().unwrap(), 2);
        assert_eq!(efd.drain().unwrap(), 0);
    }
}
