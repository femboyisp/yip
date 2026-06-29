//! L3 (TUN) and L2 (TAP) tunnel endpoints behind one trait. Real device
//! I/O lands in M4; this milestone fixes the public surface.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;

#[expect(dead_code, reason = "used in Task 2 device open/ioctl")]
const TUN_PATH: &str = "/dev/net/tun";
#[expect(dead_code, reason = "used in Task 2 device open/ioctl")]
const IFF_TUN: libc::c_short = 0x0001;
#[expect(dead_code, reason = "used in Task 2 device open/ioctl")]
const IFF_TAP: libc::c_short = 0x0002;
#[expect(dead_code, reason = "used in Task 2 device open/ioctl")]
const IFF_NO_PI: libc::c_short = 0x1000;
// _IOW('T', 202, int) on Linux.
#[expect(dead_code, reason = "used in Task 2 device open/ioctl")]
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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used in Task 2 device open/ioctl")
)]
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
}
