//! L3 (TUN) and L2 (TAP) tunnel endpoints behind one trait. Real device
//! I/O lands in M4; this milestone fixes the public surface.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const TUN_PATH: &str = "/dev/net/tun";
const IFF_TUN: libc::c_short = 0x0001;
const IFF_TAP: libc::c_short = 0x0002;
/// Support multiple independent queue file descriptors for the same interface.
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
const IFF_NO_PI: libc::c_short = 0x1000;
/// Prefix every TUN read/write with a `virtio_net_hdr` (GSO/GRO framing).
const IFF_VNET_HDR: libc::c_short = 0x4000;
// _IOW('T', 202, int) on Linux.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
// _IOW('T', 208, unsigned int) on Linux.
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;
const TUN_F_CSUM: libc::c_uint = 0x01;
const TUN_F_TSO4: libc::c_uint = 0x02;
const TUN_F_TSO6: libc::c_uint = 0x04;

/// Length (bytes) of the `virtio_net_hdr` prefix on every TUN read/write when
/// [`TunTap::vnet_hdr_len`] is `Some`. Kept as its own constant (rather than
/// depending on `yip-io`) so `yip-device` has no dependency on `yip-io`.
pub const VNET_HDR_LEN: usize = 10;

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

/// Decode a NUL-padded `IFNAMSIZ` buffer into a `String`.
fn decode_ifname(buf: &[u8; libc::IFNAMSIZ]) -> Result<String, DeviceError> {
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..nul_pos])
        .map_err(|e| DeviceError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
    Ok(s.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffloadMode {
    Full,
    CsumOnly,
}

fn negotiate_offload(fd: std::os::fd::RawFd) -> Option<OffloadMode> {
    // SAFETY: `fd` is a valid open /dev/net/tun fd on which TUNSETIFF (with IFF_VNET_HDR)
    // just succeeded. TUNSETOFFLOAD takes its flags as an integer argument passed by value.
    let full = unsafe {
        libc::ioctl(
            fd,
            TUNSETOFFLOAD,
            libc::c_ulong::from(TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6),
        )
    };
    if full == 0 {
        return Some(OffloadMode::Full);
    }

    // SAFETY: same rationale as the previous TUNSETOFFLOAD call.
    let csum_only = unsafe { libc::ioctl(fd, TUNSETOFFLOAD, libc::c_ulong::from(TUN_F_CSUM)) };
    if csum_only == 0 {
        return Some(OffloadMode::CsumOnly);
    }

    None
}

fn apply_offload(fd: std::os::fd::RawFd, mode: OffloadMode) -> Result<(), DeviceError> {
    let flags = match mode {
        OffloadMode::Full => libc::c_ulong::from(TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6),
        OffloadMode::CsumOnly => libc::c_ulong::from(TUN_F_CSUM),
    };
    // SAFETY: `fd` is a valid open /dev/net/tun fd. TUNSETOFFLOAD takes its flags as an integer passed by value.
    let rc = unsafe { libc::ioctl(fd, TUNSETOFFLOAD, flags) };
    if rc != 0 {
        return Err(DeviceError::Io(io::Error::last_os_error()));
    }
    Ok(())
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
            // FFI: libc exposes IFF_UP/IFF_RUNNING as c_int, but `ifreq.ifr_flags`
            // is c_short; the combined value (0x41) fits trivially.
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

// struct ifreq: name[IFNAMSIZ] then a union; we only set ifr_flags.
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// A TUN (L3) or TAP (L2) tunnel device.
pub struct TunTap {
    file: std::fs::File,
    kind: DeviceKind,
    name: String,
    /// `Some(VNET_HDR_LEN)` iff `IFF_VNET_HDR` framing + kernel GSO/GRO
    /// offload are both active on this fd; `None` for a plain device.
    vnet_hdr_len: Option<usize>,
}

impl TunTap {
    /// Create a tunnel device of `kind` named `name`. Requires `CAP_NET_ADMIN`.
    ///
    /// When `want_vnet_hdr` is set, first attempts to open with `IFF_VNET_HDR`
    /// framing and kernel GSO/GRO offload (`TUNSETOFFLOAD`) enabled. If the
    /// kernel or driver doesn't support one of the two, this falls back
    /// transparently to a plain device (no vnet_hdr framing) with a fresh fd
    /// — see [`TunTap::vnet_hdr_len`] to check which mode was actually
    /// negotiated.
    pub fn create(
        name: &str,
        kind: DeviceKind,
        want_vnet_hdr: bool,
    ) -> Result<TunTap, DeviceError> {
        let ifname = encode_ifname(name)?;

        if want_vnet_hdr {
            if let Some(tun) = Self::open_with_offload(kind, &ifname)? {
                return Ok(tun);
            }
        }

        Self::open_plain(kind, &ifname)
    }

    /// Create a multi-queue TUN/TAP device with `queue_count` independent queue fds.
    ///
    /// When `queue_count == 1`, delegates transparently to [`TunTap::create`].
    /// When `queue_count > 1`, opens `/dev/net/tun` `queue_count` times with
    /// `IFF_MULTI_QUEUE` set, returning one [`TunTap`] per queue.
    ///
    /// All returned queue fds are placed in non-blocking mode (`O_NONBLOCK`).
    /// If `want_vnet_hdr` is requested, `IFF_VNET_HDR` and kernel offload
    /// (`TUNSETOFFLOAD`) are negotiated across all queues, falling back
    /// transparently to plain queues if unsupported.
    pub fn create_multi_queue(
        name: &str,
        kind: DeviceKind,
        queue_count: usize,
        want_vnet_hdr: bool,
    ) -> Result<Vec<TunTap>, DeviceError> {
        if queue_count == 0 {
            return Err(DeviceError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "queue_count must be at least 1",
            )));
        }

        if queue_count == 1 {
            let tun = Self::create(name, kind, want_vnet_hdr)?;
            tun.set_nonblocking()?;
            return Ok(vec![tun]);
        }

        let ifname = encode_ifname(name)?;

        if want_vnet_hdr {
            if let Some(queues) = Self::open_multi_queue_with_offload(kind, &ifname, queue_count)? {
                return Ok(queues);
            }
        }

        Self::open_multi_queue_plain(kind, &ifname, queue_count)
    }

    /// Attempt to open with `IFF_VNET_HDR` framing and kernel GSO/GRO
    /// offload (`TUNSETOFFLOAD`) enabled. Returns `Ok(Some(_))` only when
    /// `TUNSETIFF` (with `IFF_VNET_HDR`) *and* `TUNSETOFFLOAD` both succeed;
    /// `Ok(None)` on any unsupported step (the freshly-opened fd is dropped/
    /// closed here), so the caller falls back to [`Self::open_plain`] with a
    /// fresh fd — clean framing, no half-enabled state. A hard I/O failure
    /// that would fail identically on the plain path (e.g. `/dev/net/tun`
    /// cannot be opened at all) is propagated as `Err`.
    fn open_with_offload(
        kind: DeviceKind,
        ifname: &[u8; libc::IFNAMSIZ],
    ) -> Result<Option<TunTap>, DeviceError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_PATH)?;

        let type_flag = match kind {
            DeviceKind::Tun => IFF_TUN,
            DeviceKind::Tap => IFF_TAP,
        };
        let mut req = IfReq {
            name: *ifname,
            flags: type_flag | IFF_NO_PI | IFF_VNET_HDR,
            _pad: [0; 22],
        };

        // SAFETY: `req` is a correctly-sized, properly-initialized `ifreq` for
        // TUNSETIFF; the fd is a freshly-opened /dev/net/tun. The kernel reads
        // `req` and writes back the resolved name into the same buffer, which
        // we own exclusively here.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) };
        if rc != 0 {
            // Driver rejected IFF_VNET_HDR (or the type/name flags altogether).
            // `file` drops here, closing the fd; caller reopens plain.
            return Ok(None);
        }

        if let Some(_mode) = negotiate_offload(file.as_raw_fd()) {
            bring_up(&req.name)?;
            let actual_name = decode_ifname(&req.name)?;
            return Ok(Some(TunTap {
                file,
                kind,
                name: actual_name,
                vnet_hdr_len: Some(VNET_HDR_LEN),
            }));
        }

        // Neither offload attempt was accepted: the fd has vnet_hdr framing
        // but no GSO/GRO — not a state we run with. `file` drops here
        // (closing the fd); the caller reopens plain.
        Ok(None)
    }

    /// Open without `IFF_VNET_HDR` framing (today's plain TUN/TAP path).
    fn open_plain(kind: DeviceKind, ifname: &[u8; libc::IFNAMSIZ]) -> Result<TunTap, DeviceError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_PATH)?;

        let type_flag = match kind {
            DeviceKind::Tun => IFF_TUN,
            DeviceKind::Tap => IFF_TAP,
        };
        let mut req = IfReq {
            name: *ifname,
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
        bring_up(&req.name)?;
        let actual_name = decode_ifname(&req.name)?;

        Ok(TunTap {
            file,
            kind,
            name: actual_name,
            vnet_hdr_len: None,
        })
    }

    fn open_multi_queue_with_offload(
        kind: DeviceKind,
        ifname: &[u8; libc::IFNAMSIZ],
        queue_count: usize,
    ) -> Result<Option<Vec<TunTap>>, DeviceError> {
        let file0 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_PATH)?;

        let type_flag = match kind {
            DeviceKind::Tun => IFF_TUN,
            DeviceKind::Tap => IFF_TAP,
        };
        let mut req0 = IfReq {
            name: *ifname,
            flags: type_flag | IFF_NO_PI | IFF_MULTI_QUEUE | IFF_VNET_HDR,
            _pad: [0; 22],
        };

        // SAFETY: req0 is a correctly-sized ifreq for TUNSETIFF; file0 is a freshly-opened /dev/net/tun.
        let rc = unsafe { libc::ioctl(file0.as_raw_fd(), TUNSETIFF, &raw mut req0) };
        if rc != 0 {
            return Ok(None);
        }

        let offload_mode = match negotiate_offload(file0.as_raw_fd()) {
            Some(mode) => mode,
            None => return Ok(None),
        };

        bring_up(&req0.name)?;
        let actual_name = decode_ifname(&req0.name)?;

        let q0 = TunTap {
            file: file0,
            kind,
            name: actual_name.clone(),
            vnet_hdr_len: Some(VNET_HDR_LEN),
        };
        q0.set_nonblocking()?;

        let mut queues = Vec::with_capacity(queue_count);
        queues.push(q0);

        for _ in 1..queue_count {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(TUN_PATH)?;

            let mut req = IfReq {
                name: req0.name,
                flags: type_flag | IFF_NO_PI | IFF_MULTI_QUEUE | IFF_VNET_HDR,
                _pad: [0; 22],
            };

            // SAFETY: req is a correctly-sized ifreq for TUNSETIFF; file is a freshly-opened /dev/net/tun.
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) };
            if rc != 0 {
                return Err(DeviceError::Io(io::Error::last_os_error()));
            }

            apply_offload(file.as_raw_fd(), offload_mode)?;

            let q = TunTap {
                file,
                kind,
                name: actual_name.clone(),
                vnet_hdr_len: Some(VNET_HDR_LEN),
            };
            q.set_nonblocking()?;
            queues.push(q);
        }

        Ok(Some(queues))
    }

    fn open_multi_queue_plain(
        kind: DeviceKind,
        ifname: &[u8; libc::IFNAMSIZ],
        queue_count: usize,
    ) -> Result<Vec<TunTap>, DeviceError> {
        let file0 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_PATH)?;

        let type_flag = match kind {
            DeviceKind::Tun => IFF_TUN,
            DeviceKind::Tap => IFF_TAP,
        };
        let mut req0 = IfReq {
            name: *ifname,
            flags: type_flag | IFF_NO_PI | IFF_MULTI_QUEUE,
            _pad: [0; 22],
        };

        // SAFETY: req0 is a correctly-sized ifreq for TUNSETIFF; file0 is a freshly-opened /dev/net/tun.
        let rc = unsafe { libc::ioctl(file0.as_raw_fd(), TUNSETIFF, &raw mut req0) };
        if rc != 0 {
            return Err(DeviceError::Io(io::Error::last_os_error()));
        }

        bring_up(&req0.name)?;
        let actual_name = decode_ifname(&req0.name)?;

        let q0 = TunTap {
            file: file0,
            kind,
            name: actual_name.clone(),
            vnet_hdr_len: None,
        };
        q0.set_nonblocking()?;

        let mut queues = Vec::with_capacity(queue_count);
        queues.push(q0);

        for _ in 1..queue_count {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(TUN_PATH)?;

            let mut req = IfReq {
                name: req0.name,
                flags: type_flag | IFF_NO_PI | IFF_MULTI_QUEUE,
                _pad: [0; 22],
            };

            // SAFETY: req is a correctly-sized ifreq for TUNSETIFF; file is a freshly-opened /dev/net/tun.
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &raw mut req) };
            if rc != 0 {
                return Err(DeviceError::Io(io::Error::last_os_error()));
            }

            let q = TunTap {
                file,
                kind,
                name: actual_name.clone(),
                vnet_hdr_len: None,
            };
            q.set_nonblocking()?;
            queues.push(q);
        }

        Ok(queues)
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `virtio_net_hdr` prefix length (bytes) on every TUN read/write
    /// when kernel GSO/GRO offload is active, or `None` for a plain device
    /// (see [`TunTap::create`]'s `want_vnet_hdr` parameter).
    pub fn vnet_hdr_len(&self) -> Option<usize> {
        self.vnet_hdr_len
    }

    /// Return the raw file descriptor for this TUN/TAP device.
    ///
    /// The fd is bidirectional: `read` pulls frames injected by the kernel
    /// (egress path for the tunnel), and `write` injects frames into the
    /// kernel network stack (ingress path for the tunnel).
    ///
    /// The fd is valid as long as this `TunTap` value lives.
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }

    /// Set the TUN/TAP fd non-blocking via `fcntl(F_SETFL, O_NONBLOCK)`.
    ///
    /// Required before passing the fd to an `epoll`-based event loop that
    /// drains with `MSG_DONTWAIT` / non-blocking `read`.
    pub fn set_nonblocking(&self) -> Result<(), DeviceError> {
        // SAFETY: `self.file` is a valid open fd owned by this `TunTap`
        // instance, which outlives this call.  `fcntl(F_SETFL, O_NONBLOCK)`
        // is a pure flag-set on the open-file description and cannot cause UB.
        let rc = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        if rc < 0 {
            Err(DeviceError::Io(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

/// The read half of a split [`TunTap`].
pub struct TunReader {
    file: std::fs::File,
}

/// The write half of a split [`TunTap`].
pub struct TunWriter {
    file: std::fs::File,
}

impl TunReader {
    /// Read one inner frame.
    pub fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.file.read(buf)
    }

    /// Return the raw fd for this reader half.
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

impl TunWriter {
    /// Write one inner frame.
    pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        self.file.write(frame)
    }

    /// Return the raw fd for this writer half.
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

impl TunTap {
    /// Split into independent reader/writer halves backed by duplicated fds,
    /// so one thread can read while another writes the same device.
    pub fn split(self) -> Result<(TunReader, TunWriter), DeviceError> {
        let raw = self.file.as_raw_fd();
        // SAFETY: `raw` is a valid open fd owned by `self.file`; `dup` returns a new
        // independent fd referring to the same TUN/TAP device, or -1 on error.
        let dup = unsafe { libc::dup(raw) };
        if dup < 0 {
            return Err(DeviceError::Io(io::Error::last_os_error()));
        }
        // SAFETY: `dup` is a fresh, valid, exclusively-owned fd from `dup`.
        let dup_file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(dup) });
        let reader = TunReader { file: dup_file };
        let writer = TunWriter { file: self.file };
        Ok((reader, writer))
    }
}

// NOTE: a TAP device yields raw Ethernet frames. MAC learning and L2 forwarding
// (bridging frames between peers by destination MAC) belong to the data-plane
// forwarding loop wired in M6, not to the device itself, which is a dumb fd.
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

impl AsRawFd for TunTap {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

impl AsRawFd for TunReader {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

impl AsRawFd for TunWriter {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
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
        TunTap::create("yipcap0", DeviceKind::Tun, false)
            .map(drop)
            .is_ok()
    }

    #[test]
    fn tun_create_roundtrips_a_write() {
        if !can_create_devices() {
            eprintln!("SKIP tun_create_roundtrips_a_write: needs CAP_NET_ADMIN (run under sudo)");
            return;
        }
        let mut dev = TunTap::create("yiptun0", DeviceKind::Tun, false).unwrap();
        assert_eq!(dev.kind(), DeviceKind::Tun);
        assert_eq!(dev.name(), "yiptun0");
        // Writing a minimal IPv4 packet to the device must not error (kernel accepts the inject).
        let pkt = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 9, 1, 10, 9, 9, 2,
        ];
        let n = dev.write_frame(&pkt).unwrap();
        assert_eq!(n, pkt.len());
    }

    #[test]
    fn tap_create_reports_l2_kind() {
        if !can_create_devices() {
            eprintln!("SKIP tap_create_reports_l2_kind: needs CAP_NET_ADMIN (run under sudo)");
            return;
        }
        let dev = TunTap::create("yiptap0", DeviceKind::Tap, false).unwrap();
        assert_eq!(dev.kind(), DeviceKind::Tap);
        assert_eq!(dev.name(), "yiptap0");
    }

    #[test]
    fn split_yields_independent_reader_writer() {
        if !can_create_devices() {
            eprintln!("SKIP split_yields_independent_reader_writer: needs CAP_NET_ADMIN");
            return;
        }
        let dev = TunTap::create("yipsplit0", DeviceKind::Tun, false).unwrap();
        let (_reader, mut writer) = dev.split().unwrap();
        // the writer half can still inject a frame
        let pkt = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 9, 1, 10, 9, 9, 2,
        ];
        assert_eq!(writer.write_frame(&pkt).unwrap(), pkt.len());
    }

    #[test]
    fn plain_create_reports_no_vnet_hdr() {
        if !can_create_devices() {
            eprintln!(
                "SKIP plain_create_reports_no_vnet_hdr: needs CAP_NET_ADMIN (run under sudo)"
            );
            return;
        }
        let dev = TunTap::create("yipvnh0", DeviceKind::Tun, false).unwrap();
        assert_eq!(
            dev.vnet_hdr_len(),
            None,
            "want_vnet_hdr=false must never activate vnet_hdr framing"
        );
    }
}
