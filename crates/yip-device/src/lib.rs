//! L3 (TUN) and L2 (TAP) tunnel endpoints behind one trait. Real device
//! I/O lands in M4; this milestone fixes the public surface.
#![forbid(unsafe_code)]

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
}
