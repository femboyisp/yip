//! Plausible-port bind helpers (anti-DPI 3d, R8/#45): auto-selected ports try
//! 443 and fall back to 8443 (with a warning) when binding a privileged port is
//! denied. Explicit operator ports never fall back.
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

fn create_reuseport_socket(addr: SocketAddr) -> io::Result<socket2::Socket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by multi-core sharding in later tasks")
)]
pub(crate) fn bind_udp_reuseport(
    addr: SocketAddr,
    port_auto: bool,
    count: usize,
) -> io::Result<Vec<UdpSocket>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut sockets = Vec::with_capacity(count);
    let mut bound_addr = addr;

    let sock0 = create_reuseport_socket(bound_addr)?;
    let sock0 = match sock0.bind(&bound_addr.into()) {
        Ok(()) => sock0,
        Err(e) if port_auto && e.kind() == io::ErrorKind::PermissionDenied => {
            warn_fallback("udp", bound_addr);
            bound_addr = fallback_addr(bound_addr);
            let fb_sock = create_reuseport_socket(bound_addr)?;
            fb_sock.bind(&bound_addr.into())?;
            fb_sock
        }
        Err(e) => return Err(e),
    };
    let std_sock0: UdpSocket = sock0.into();
    yip_io::set_socket_buffers(&std_sock0, 4 * 1024 * 1024)?;
    if bound_addr.port() == 0 {
        bound_addr = SocketAddr::new(bound_addr.ip(), std_sock0.local_addr()?.port());
    }
    sockets.push(std_sock0);

    for _ in 1..count {
        let sock = create_reuseport_socket(bound_addr)?;
        sock.bind(&bound_addr.into())?;
        let std_sock: UdpSocket = sock.into();
        yip_io::set_socket_buffers(&std_sock, 4 * 1024 * 1024)?;
        sockets.push(std_sock);
    }

    Ok(sockets)
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
                assert!(p == 443 || p == FALLBACK_LISTEN_PORT);
            }
            Err(e) => panic!("auto bind must not error (443 or 8443): {e}"),
        }
    }

    #[test]
    fn bind_tcp_explicit_privileged_port_never_falls_back() {
        // The headline safety invariant: an EXPLICITLY-configured port is never
        // silently substituted. As a non-root process, binding a privileged
        // port with port_auto=false must surface PermissionDenied — it must NOT
        // fall back to 8443 (that guard is gated on port_auto). If the test runs
        // AS root (CI sudo), it binds directly on the configured port. Either
        // outcome is fine; a listener on the 8443 fallback port is NOT.
        //
        // Uses 1023 (privileged, no standard service) rather than 443 so it
        // never races the auto-fallback test above for the same port under the
        // root/sudo path, where both could otherwise contend on 443 in parallel.
        const EXPLICIT_PRIV_PORT: u16 = 1023;
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), EXPLICIT_PRIV_PORT);
        match bind_tcp(addr, false) {
            Ok(l) => assert_eq!(
                l.local_addr().unwrap().port(),
                EXPLICIT_PRIV_PORT,
                "an explicit port must bind as-configured, never fall back to {FALLBACK_LISTEN_PORT}"
            ),
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "explicit privileged bind must surface PermissionDenied, not fall back"
            ),
        }
    }

    #[test]
    fn bind_udp_auto_propagates_addr_in_use_without_falling_back() {
        // Fallback fires ONLY on PermissionDenied. AddrInUse must propagate even
        // when port_auto=true — never be swallowed into an 8443 fallback, which
        // would mask a real port conflict and silently move the listener. We
        // hold an OS-assigned (always unprivileged) port, then try to re-bind it.
        let held = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap();
        let taken = held.local_addr().unwrap();
        match bind_udp(taken, true) {
            Ok(s) => panic!(
                "AddrInUse must not fall back; got a socket on {}",
                s.local_addr().unwrap()
            ),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::AddrInUse),
        }
    }

    #[test]
    fn bind_udp_reuseport_zero_count_returns_empty() {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let socks = bind_udp_reuseport(addr, false, 0).unwrap();
        assert!(socks.is_empty());
    }

    #[test]
    fn bind_udp_reuseport_single_socket() {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let socks = bind_udp_reuseport(addr, false, 1).unwrap();
        assert_eq!(socks.len(), 1);
        assert!(socks[0].local_addr().is_ok());
    }

    #[test]
    fn bind_udp_reuseport_multiple_sockets_same_port() {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let socks = bind_udp_reuseport(addr, false, 3).expect("bind reuseport sockets");
        assert_eq!(socks.len(), 3);
        let port0 = socks[0].local_addr().unwrap().port();
        assert_ne!(port0, 0);
        for sock in &socks[1..] {
            assert_eq!(sock.local_addr().unwrap().port(), port0);
        }
    }

    #[test]
    fn bind_udp_reuseport_sockets_send_and_receive_independently() {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let socks = bind_udp_reuseport(addr, false, 2).expect("bind 2 reuseport sockets");
        let target_port = socks[0].local_addr().unwrap().port();
        let target_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), target_port);

        // 1. Verify each socket can send independently to a client.
        let client = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap();
        let client_addr = client.local_addr().unwrap();

        socks[0].send_to(b"from-sock-0", client_addr).unwrap();
        let mut buf = [0u8; 64];
        let (len, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"from-sock-0");
        assert_eq!(from.port(), target_port);

        socks[1].send_to(b"from-sock-1", client_addr).unwrap();
        let (len, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"from-sock-1");
        assert_eq!(from.port(), target_port);

        // 2. Verify each socket can receive independently.
        // Linux SO_REUSEPORT hashes (src_ip, src_port, dst_ip, dst_port) to pick
        // the receiving socket. With multiple distinct client sockets, datagrams
        // will route to both socket 0 and socket 1.
        let mut sock0_received = false;
        let mut sock1_received = false;

        for i in 0..100 {
            if sock0_received && sock1_received {
                break;
            }
            let sender = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap();
            sender
                .send_to(format!("probe {i}").as_bytes(), target_addr)
                .unwrap();

            std::thread::sleep(std::time::Duration::from_millis(1));
            let mut recv_buf = [0u8; 64];
            while let Ok((n, _)) = socks[0].recv_from(&mut recv_buf) {
                if n > 0 {
                    sock0_received = true;
                }
            }
            while let Ok((n, _)) = socks[1].recv_from(&mut recv_buf) {
                if n > 0 {
                    sock1_received = true;
                }
            }
        }

        assert!(sock0_received, "socket 0 should have received packets");
        assert!(sock1_received, "socket 1 should have received packets");
    }

    #[test]
    fn bind_udp_reuseport_auto_falls_back_when_privileged_port_denied() {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443);
        match bind_udp_reuseport(addr, true, 2) {
            Ok(socks) => {
                assert_eq!(socks.len(), 2);
                let p0 = socks[0].local_addr().unwrap().port();
                let p1 = socks[1].local_addr().unwrap().port();
                assert_eq!(p0, p1);
                assert!(p0 == 443 || p0 == FALLBACK_LISTEN_PORT);
            }
            Err(e) => panic!("auto reuseport bind must not error (443 or 8443): {e}"),
        }
    }

    #[test]
    fn bind_udp_reuseport_explicit_privileged_port_never_falls_back() {
        const EXPLICIT_PRIV_PORT: u16 = 1023;
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), EXPLICIT_PRIV_PORT);
        match bind_udp_reuseport(addr, false, 2) {
            Ok(socks) => {
                assert_eq!(socks.len(), 2);
                let p0 = socks[0].local_addr().unwrap().port();
                let p1 = socks[1].local_addr().unwrap().port();
                assert_eq!(p0, p1);
                assert_eq!(
                    p0,
                    EXPLICIT_PRIV_PORT,
                    "an explicit port must bind as-configured, never fall back to {FALLBACK_LISTEN_PORT}"
                );
            }
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "explicit privileged bind must surface PermissionDenied, not fall back"
            ),
        }
    }
}
