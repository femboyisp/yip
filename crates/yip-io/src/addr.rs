//! `sockaddr` ⇄ [`SocketAddr`] conversions for the addressed socket seam.
//!
//! `recvfrom`/`recvmsg`/`sendto`/`sendmsg` all speak `libc::sockaddr_storage`
//! (IPv4 *or* IPv6, selected by `ss_family`); the rest of yip works with
//! `std::net::SocketAddr`. These two helpers are the only place that bridges
//! the two representations, and the only new `unsafe` this task introduces
//! (confined to `yip-io`, per the crate's `unsafe`-only-here contract).

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Convert a `sockaddr_storage` (as filled in by `recvfrom`/`recvmsg`) into a
/// [`SocketAddr`], given the address length the kernel reported.
///
/// # Errors
///
/// Returns an error if `len` is too short for the address family the kernel
/// reported, or if the family is neither `AF_INET` nor `AF_INET6`.
pub fn sockaddr_to_std(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let len = usize::try_from(len).unwrap_or(0);
    let family = i32::from(storage.ss_family);

    if family == libc::AF_INET {
        if len < mem::size_of::<libc::sockaddr_in>() {
            return Err(io::Error::other("sockaddr_in shorter than expected"));
        }
        // SAFETY: `storage.ss_family == AF_INET` and `len` covers a full
        // `sockaddr_in`, so reinterpreting the start of `storage` (a
        // `sockaddr_storage`, which is defined to be large enough and
        // suitably aligned for any address family) as `sockaddr_in` reads
        // only initialized bytes of a compatible layout.
        let sin = unsafe {
            std::ptr::read_unaligned(std::ptr::from_ref(storage).cast::<libc::sockaddr_in>())
        };
        let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
        let port = u16::from_be(sin.sin_port);
        return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }

    if family == libc::AF_INET6 {
        if len < mem::size_of::<libc::sockaddr_in6>() {
            return Err(io::Error::other("sockaddr_in6 shorter than expected"));
        }
        // SAFETY: same rationale as the `AF_INET` arm above, for `sockaddr_in6`.
        let sin6 = unsafe {
            std::ptr::read_unaligned(std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>())
        };
        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        let port = u16::from_be(sin6.sin6_port);
        return Ok(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            sin6.sin6_flowinfo,
            sin6.sin6_scope_id,
        )));
    }

    Err(io::Error::other(format!(
        "unsupported sockaddr family: {family}"
    )))
}

/// Convert a [`SocketAddr`] into a `sockaddr_storage` + length suitable for
/// `sendto`/`sendmsg`'s `msg_name`/`msg_namelen`.
pub fn std_to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: `sockaddr_storage` is a plain-old-data struct of integers and
    // byte arrays; the all-zero bit pattern is a valid value for all of them.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };

    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET)
                    .expect("AF_INET fits sa_family_t"),
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `sockaddr_storage` is defined to be large enough and
            // suitably aligned to hold any address family's sockaddr, so
            // writing a fully-initialized `sockaddr_in` at its start is valid.
            unsafe {
                std::ptr::write_unaligned(
                    std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in>(),
                    sin,
                );
            }
            let len = libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_in>())
                .expect("size_of::<sockaddr_in>() fits socklen_t");
            (storage, len)
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::sa_family_t::try_from(libc::AF_INET6)
                    .expect("AF_INET6 fits sa_family_t"),
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: same rationale as the `V4` arm above, for `sockaddr_in6`.
            unsafe {
                std::ptr::write_unaligned(
                    std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in6>(),
                    sin6,
                );
            }
            let len = libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_in6>())
                .expect("size_of::<sockaddr_in6>() fits socklen_t");
            (storage, len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrips() {
        let addr: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let (storage, len) = std_to_sockaddr(addr);
        let back = sockaddr_to_std(&storage, len).unwrap();
        assert_eq!(back, addr);
    }

    #[test]
    fn v4_loopback_roundtrips() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (storage, len) = std_to_sockaddr(addr);
        let back = sockaddr_to_std(&storage, len).unwrap();
        assert_eq!(back, addr);
    }

    #[test]
    fn v6_roundtrips() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let (storage, len) = std_to_sockaddr(addr);
        let back = sockaddr_to_std(&storage, len).unwrap();
        assert_eq!(back, addr);
    }

    #[test]
    fn truncated_length_is_rejected() {
        let addr: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let (storage, _) = std_to_sockaddr(addr);
        let too_short = libc::socklen_t::try_from(2usize).unwrap();
        assert!(sockaddr_to_std(&storage, too_short).is_err());
    }

    #[test]
    fn unknown_family_is_rejected() {
        // SAFETY: all-zero sockaddr_storage is a valid bit pattern; ss_family
        // == 0 (AF_UNSPEC) is neither AF_INET nor AF_INET6.
        let storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_storage>()).unwrap();
        assert!(sockaddr_to_std(&storage, len).is_err());
    }
}
