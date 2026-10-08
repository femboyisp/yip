use std::net::UdpSocket;
use yip_io::batch::{send_gso_superpacket, set_udp_gso_segment};

#[test]
fn test_set_udp_gso_segment_probe() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
    // Probe GSO segment setting - should succeed or cleanly report unsupported without error
    let res = set_udp_gso_segment(&sock, 1280);
    assert!(res.is_ok(), "GSO probe should succeed or return Ok(false)");
}

#[test]
fn test_send_gso_superpacket_or_unsupported() {
    let s1 = UdpSocket::bind("127.0.0.1:0").expect("bind s1");
    let s2 = UdpSocket::bind("127.0.0.1:0").expect("bind s2");
    s1.set_nonblocking(true).unwrap();
    s2.set_nonblocking(true).unwrap();

    let addr2 = s2.local_addr().unwrap();
    let payload = vec![0x42u8; 1280 * 2]; // 2 segments

    match send_gso_superpacket(&s1, &payload, 1280, addr2) {
        Ok(sent) => {
            // Kernel accepted GSO send or transient full buffer
            assert!(sent == 0 || sent == payload.len());
        }
        Err(e) => {
            // Kernel lacks UDP_SEGMENT or unsupported on this device loopback
            let raw = e.raw_os_error().unwrap_or(0);
            assert!(
                raw == libc::EINVAL || raw == libc::EOPNOTSUPP || raw == libc::EIO,
                "unexpected GSO error: {e}"
            );
        }
    }
}
