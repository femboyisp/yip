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
    encode(
        &Message::Register {
            node: a_id,
            counter: 1,
        },
        &mut buf,
    );
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

fn spawn_server_with_obf_psk(listen: &str, hex_psk: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_yip-rendezvous"))
        .arg(listen)
        .arg("--obf-psk")
        .arg(hex_psk)
        .spawn()
        .expect("spawn server")
}

/// Same register/lookup/relay flow as `register_lookup_relay_over_udp`, but
/// with the real `yip-rendezvous` process started under `--obf-psk`: every
/// datagram sent to and received from the server on the wire is a
/// `yip_obf`-wrapped envelope (a plain `decode` of the raw bytes must fail),
/// and unwrapping with the SAME key recovers the exact `Message` the plain
/// test asserts on. Proves the client-side wrap/unwrap this task adds to
/// `yipd` is symmetric with the server's, end-to-end over a real socket.
#[test]
fn register_lookup_relay_over_udp_with_obf_psk() {
    let listen = "127.0.0.1:51822";
    let hex_psk = "11".repeat(32);
    let key = yip_obf::derive_key(&hex_decode(&hex_psk));
    let mut server = spawn_server_with_obf_psk(listen, &hex_psk);
    std::thread::sleep(Duration::from_millis(300)); // let it bind

    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let a_id = node_id(&[3u8; 32]);
    let b_id = node_id(&[4u8; 32]);

    let send_wrapped = |sock: &UdpSocket, msg: &Message| {
        let mut plain = Vec::new();
        encode(msg, &mut plain);
        let wrapped = yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &plain, 6);
        sock.send_to(&wrapped, listen).unwrap();
    };
    let recv_wrapped = |sock: &UdpSocket, rx: &mut [u8]| -> Message {
        let (n, _) = sock.recv_from(rx).expect("recv");
        // The raw wire bytes must NOT decode as a plain Message — they are
        // hidden behind the obf envelope.
        assert!(
            decode(&rx[..n]).is_none(),
            "server reply must be obf-wrapped on the wire, not plaintext"
        );
        let (ptype, body) = yip_obf::deobfuscate(&key, &rx[..n]).expect("unwraps with our key");
        assert_eq!(ptype, yip_obf::RDV_TYPE);
        decode(&body).expect("unwrapped body decodes as a Message")
    };

    // A registers.
    send_wrapped(
        &a,
        &Message::Register {
            node: a_id,
            counter: 1,
        },
    );
    std::thread::sleep(Duration::from_millis(100));

    // B looks up A -> expects PeerInfo(A, A's reflexive addr).
    send_wrapped(&b, &Message::Lookup { node: a_id });
    let mut rx = [0u8; 2048];
    match recv_wrapped(&b, &mut rx) {
        Message::PeerInfo { node, reflexive } => {
            assert_eq!(node, a_id);
            assert_eq!(reflexive, a.local_addr().unwrap());
        }
        other => panic!("expected PeerInfo, got {other:?}"),
    }

    // A receives the PunchHint the Lookup triggered.
    match recv_wrapped(&a, &mut rx) {
        Message::PunchHint { reflexive, .. } => {
            assert_eq!(reflexive, b.local_addr().unwrap());
        }
        other => panic!("expected PunchHint, got {other:?}"),
    }

    // B relays a payload to A -> A receives RelayDeliver{src=B, payload}, the
    // inner payload preserved verbatim (it is plaintext INSIDE the obf'd RDV
    // envelope, per the addendum — never itself obf-wrapped).
    send_wrapped(
        &b,
        &Message::RelaySend {
            src: b_id,
            dst: a_id,
            payload: vec![9, 9, 9],
        },
    );
    match recv_wrapped(&a, &mut rx) {
        Message::RelayDeliver { src, payload } => {
            assert_eq!(src, b_id);
            assert_eq!(payload, vec![9, 9, 9]);
        }
        other => panic!("expected RelayDeliver, got {other:?}"),
    }

    let _ = server.kill();
    let _ = server.wait();
}

/// Local hex decode mirroring the binary's own (unexported) `hex_to_32`, just
/// enough for this test to derive the same key it passes on the command line.
fn hex_decode(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let b = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => unreachable!("test-only hex"),
            }
        };
        out[i] = (b(chunk[0]) << 4) | b(chunk[1]);
    }
    out
}
