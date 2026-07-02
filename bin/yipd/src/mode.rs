//! Tunnel mode selection derived from config.

use std::io;

/// Runtime tunnel mode used by yipd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelMode {
    /// Layer-3 tunnel path over a TUN device.
    #[default]
    L3Tun,
    /// Layer-2 tunnel path over a TAP device.
    L2Tap,
}

impl TunnelMode {
    /// Parse config value for `device_kind`.
    pub fn parse_device_kind(value: &str) -> io::Result<Self> {
        match value {
            "tun" => Ok(Self::L3Tun),
            "tap" => Ok(Self::L2Tap),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid device_kind: {value}"),
            )),
        }
    }
}
