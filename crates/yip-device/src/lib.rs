//! L3 (TUN) and L2 (TAP) tunnel endpoints behind one trait. Real device
//! I/O lands in M4; this milestone fixes the public surface.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::os::fd::AsRawFd;

const TUN_PATH: &str = "/dev/net/tun";
const IFF_TUN: libc::c_short = 0x0001;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
// _IOW('T', 202, int) on Linux.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Errors creating or configuring a tunnel device.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// Interface name does not fit in `IFNAMSIZ` (including the NUL terminator).
    #[error("interface name too long")]
    NameTooLong,
    /// Underlying OS error (open / ioctl / read / write).
    #[error("device io error: {0}")]
    Io(#[from] io::Error),
}

/// Encode an interface name into a NUL-padded `IFNAMSIZ` buffer.
fn encode_ifname(name: &str) -> Result<[u8; libc::IFNAMSIZ], DeviceError> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(DeviceError::NameTooLong);
    }
    let mut buf = [0u8; libc::IFNAMSIZ];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

/// Whether a device operates at L3 (IP) or L2 (Ethernet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// L3 IP tunnel (`/dev/net/tun`, TUN mode).
    Tun,
    /// L2 Ethernet tap (`/dev/net/tun`, TAP mode) with MAC learning.
    Tap,
}

/// A tunnel endpoint that yields and accepts inner frames. Implemented in M4.
pub trait Device {
    /// Whether this is an L3 (TUN) or L2 (TAP) device.
    fn kind(&self) -> DeviceKind;
    /// Read one inner frame into `buf`, returning its length.
    fn read_frame(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Write one inner frame, returning the number of bytes written.
    fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<usize>;
}

/// Bring a network interface up (set IFF_UP | IFF_RUNNING).
///
/// Opens a temporary AF_INET socket to issue `SIOCGIFFLAGS` / `SIOCSIFFLAGS`.
fn bring_up(ifname: &[u8; libc::IFNAMSIZ]) -> Result<(), DeviceError> {
    // struct ifreq layout for SIOCGIFFLAGS / SIOCSIFFLAGS: name then ifr_flags (c_short).
    #[repr(C)]
    struct IfReqFlags {
        name: [u8; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req = IfReqFlags {
        name: *ifname,
        flags: 0,
        _pad: [0; 22],
    };

    // SAFETY: `sock_fd` is a valid AF_INET socket returned by `socket(2)`; `req` is a
    // correctly-laid-out `ifreq` for SIOCGIFFLAGS / SIOCSIFFLAGS, exclusively owned here.
    // We check both ioctl return values and close the socket before returning.
    let err = unsafe {
        let sock_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock_fd < 0 {
            return Err(DeviceError::Io(io::Error::last_os_error()));
        }
        let rc_get = libc::ioctl(sock_fd, libc::SIOCGIFFLAGS, &raw mut req);
        if rc_get == 0 {
            req.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let rc_set = libc::ioctl(sock_fd, libc::SIOCSIFFLAGS, &raw mut req);
            libc::close(sock_fd);
            if rc_set != 0 {
                Some(io::Error::last_os_error())
            } else {
                None
            }
        } else {
            let e = io::Error::last_os_error();
            libc::close(sock_fd);
            Some(e)
        }
    };
    match err {
        Some(e) => Err(DeviceError::Io(e)),
        None => Ok(()),
    }
}

/// A TUN (L3) or TAP (L2) tunnel device.
pub struct TunTap {
    file: std::fs::File,
    kind: DeviceKind,
    name: String,
}

impl TunTap {
    /// Create a tunnel device of `kind` named `name`. Requires `CAP_NET_ADMIN`.
    pub fn create(name: &str, kind: DeviceKind) -> Result<TunTap, DeviceError> {
        let ifname = encode_ifname(name)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_PATH)?;

        // struct ifreq: name[IFNAMSIZ] then a union; we only set ifr_flags.
        #[repr(C)]
        struct IfReq {
            name: [u8; libc::IFNAMSIZ],
            flags: libc::c_short,
            _pad: [u8; 22],
        }
        let type_flag = match kind {
            DeviceKind::Tun => IFF_TUN,
            DeviceKind::Tap => IFF_TAP,
        };
        let mut req = IfReq {
            name: ifname,
            flags: type_flag | IFF_NO_PI,
            _pad: [0; 22],
        };

        // SAFETY: `req` is a correctly-sized, properly-initialized `ifreq` for TUNSETIFF;
        // the fd is a freshly-opened /dev/net/tun. The kernel reads `req` and writes back
        // the resolved name into the same buffer, which we own exclusively here.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) };
        if rc != 0 {
            return Err(DeviceError::Io(io::Error::last_os_error()));
        }

        // Bring the interface up so that reads and writes work immediately.
        bring_up(&ifname)?;

        Ok(TunTap {
            file,
            kind,
            name: name.to_owned(),
        })
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Device for TunTap {
    fn kind(&self) -> DeviceKind {
        self.kind
    }
    fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.file.read(buf)
    }
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        self.file.write(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_kinds_are_distinct() {
        assert_ne!(DeviceKind::Tun, DeviceKind::Tap);
    }

    #[test]
    fn ifname_encodes_and_rejects_too_long() {
        let enc = encode_ifname("yip0").unwrap();
        assert_eq!(&enc[..4], b"yip0");
        assert_eq!(enc[4], 0, "NUL-padded");
        let long = "x".repeat(libc::IFNAMSIZ); // == IFNAMSIZ chars, no room for NUL
        assert!(matches!(
            encode_ifname(&long),
            Err(DeviceError::NameTooLong)
        ));
    }

    /// Returns true if we can create tunnel devices (root / CAP_NET_ADMIN).
    fn can_create_devices() -> bool {
        TunTap::create("yipcap0", DeviceKind::Tun).map(drop).is_ok()
    }

    #[test]
    fn tun_create_roundtrips_a_write() {
        if !can_create_devices() {
            eprintln!("SKIP tun_create_roundtrips_a_write: needs CAP_NET_ADMIN (run under sudo)");
            return;
        }
        let mut dev = TunTap::create("yiptun0", DeviceKind::Tun).unwrap();
        assert_eq!(dev.kind(), DeviceKind::Tun);
        assert_eq!(dev.name(), "yiptun0");
        // Writing a minimal IPv4 packet to the device must not error (kernel accepts the inject).
        let pkt = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 9, 1, 10, 9, 9, 2,
        ];
        let n = dev.write_frame(&pkt).unwrap();
        assert_eq!(n, pkt.len());
    }
}
