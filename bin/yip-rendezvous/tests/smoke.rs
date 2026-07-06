//! Socket-level smoke: spawn the server, register from one socket, look up from
//! another, and relay a payload — asserting the observed reflexive addr and the
//! blind forward both work over real UDP.
use std::net::UdpSocket;
use std::process::{Child, Command};
use std::time::Duration;

use yip_rendezvous::{decode, encode, node_id, Message};

fn spawn_server(listen: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_yip-rendezvous"))
        .arg(listen)
        .spawn()
        .expect("spawn server")
}

#[test]
fn register_lookup_relay_over_udp() {
    let listen = "127.0.0.1:51821";
    let mut server = spawn_server(listen);
    std::thread::sleep(Duration::from_millis(300)); // let it bind

    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let a_id = node_id(&[1u8; 32]);
    let b_id = node_id(&[2u8; 32]);

    // A registers.
    let mut buf = Vec::new();
    encode(&Message::Register { node: a_id }, &mut buf);
    a.send_to(&buf, listen).unwrap();
    std::thread::sleep(Duration::from_millis(100));

    // B looks up A -> expects PeerInfo(A, A's reflexive addr).
    buf.clear();
    encode(&Message::Lookup { node: a_id }, &mut buf);
    b.send_to(&buf, listen).unwrap();
    let mut rx = [0u8; 2048];
    let (n, _) = b.recv_from(&mut rx).expect("B receives PeerInfo");
    match decode(&rx[..n]) {
        Some(Message::PeerInfo { node, reflexive }) => {
            assert_eq!(node, a_id);
            assert_eq!(reflexive, a.local_addr().unwrap());
        }
        other => panic!("expected PeerInfo, got {other:?}"),
    }

    // B's Lookup above also caused the server to send A a PunchHint (the
    // simultaneous-open trigger): A is told to punch toward B's reflexive addr.
    let (n, _) = a
        .recv_from(&mut rx)
        .expect("A receives PunchHint from the lookup");
    match decode(&rx[..n]) {
        Some(Message::PunchHint { reflexive, .. }) => {
            assert_eq!(reflexive, b.local_addr().unwrap());
        }
        other => panic!("expected PunchHint, got {other:?}"),
    }

    // B relays a payload to A -> A receives RelayDeliver{src=B, payload}.
    buf.clear();
    encode(
        &Message::RelaySend {
            src: b_id,
            dst: a_id,
            payload: vec![7, 7, 7],
        },
        &mut buf,
    );
    b.send_to(&buf, listen).unwrap();
    let (n, _) = a.recv_from(&mut rx).expect("A receives RelayDeliver");
    match decode(&rx[..n]) {
        Some(Message::RelayDeliver { src, payload }) => {
            assert_eq!(src, b_id);
            assert_eq!(payload, vec![7, 7, 7]);
        }
        other => panic!("expected RelayDeliver, got {other:?}"),
    }

    let _ = server.kill();
    let _ = server.wait(); // reap the child so it doesn't linger as a zombie
}
