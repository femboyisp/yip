#![forbid(unsafe_code)]

use tokio as _;
use turmoil::Builder;
use yip_crypto as _;
use yip_membership as _;
use yip_transport as _;
use yip_wire as _;

#[test]
fn test_turmoil_virtual_udp_ping_pong() -> Result<(), Box<dyn std::error::Error>> {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9000").await?;
        let mut buf = [0u8; 64];
        let (len, peer) = socket.recv_from(&mut buf).await?;
        assert_eq!(&buf[..len], b"ping");
        socket.send_to(b"pong", peer).await?;
        Ok(())
    });

    sim.client("client", async {
        let socket = turmoil::net::UdpSocket::bind("0.0.0.0:9001").await?;
        socket.send_to(b"ping", "server:9000").await?;
        let mut buf = [0u8; 64];
        let (len, _) = socket.recv_from(&mut buf).await?;
        assert_eq!(&buf[..len], b"pong");
        Ok(())
    });

    sim.run()
}
