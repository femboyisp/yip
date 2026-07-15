//! Plausible-port bind helpers (anti-DPI 3d, R8/#45): auto-selected ports try
//! 443 and fall back to 8443 (with a warning) when binding a privileged port is
//! denied. Explicit operator ports never fall back.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "bind_udp/bind_tcp are wired into the transport binds in 3d Task 3"
    )
)]
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};

use crate::config::FALLBACK_LISTEN_PORT;

fn fallback_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip(), FALLBACK_LISTEN_PORT)
}

fn warn_fallback(kind: &str, addr: SocketAddr) {
    eprintln!(
        "yipd: cannot bind {kind} {addr} (needs CAP_NET_BIND_SERVICE); using {} — grant it \
         with 'setcap cap_net_bind_service+ep <yipd>' or run privileged (anti-DPI R8)",
        FALLBACK_LISTEN_PORT
    );
}

pub(crate) fn bind_udp(addr: SocketAddr, port_auto: bool) -> io::Result<UdpSocket> {
    match UdpSocket::bind(addr) {
        Ok(s) => Ok(s),
        Err(e) if port_auto && e.kind() == io::ErrorKind::PermissionDenied => {
            warn_fallback("udp", addr);
            UdpSocket::bind(fallback_addr(addr))
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn bind_tcp(addr: SocketAddr, port_auto: bool) -> io::Result<TcpListener> {
    match TcpListener::bind(addr) {
        Ok(s) => Ok(s),
        Err(e) if port_auto && e.kind() == io::ErrorKind::PermissionDenied => {
            warn_fallback("tcp", addr);
            TcpListener::bind(fallback_addr(addr))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn bind_udp_explicit_high_port_binds_directly() {
        // An explicit, unprivileged port binds with no fallback.
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0); // 0 = OS-assigned, always bindable
        let sock = bind_udp(addr, false).unwrap();
        assert!(sock.local_addr().is_ok());
    }

    #[test]
    fn bind_tcp_auto_falls_back_when_privileged_port_denied() {
        // As a non-root test process, binding 443 yields PermissionDenied and,
        // with port_auto, falls back to 8443. If the test runs AS root (CI sudo),
        // 443 binds directly — accept either a 443 or 8443 result, but never an error.
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443);
        match bind_tcp(addr, true) {
            Ok(l) => {
                let p = l.local_addr().unwrap().port();
                assert!(p == 443 || p == super::super::config::FALLBACK_LISTEN_PORT);
            }
            Err(e) => panic!("auto bind must not error (443 or 8443): {e}"),
        }
    }
}
