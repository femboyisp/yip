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

/// Grab a currently-free loopback UDP port by binding an ephemeral socket,
/// reading back the kernel-assigned port, then dropping the socket. Replaces
/// the hardcoded ports (51821/51822) so concurrent tests — and leftover server
/// processes from a prior run — can never collide on a fixed port and let a
/// stale server answer a fresh test's datagrams. There is a small TOCTOU window
/// between drop and the child re-binding; on loopback in a test that is far more
/// robust than a fixed port. (This is hardening, not the primary flake fix — see
/// `register_lookup_relay_over_udp_with_obf_psk`'s `recv_wrapped`.)
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Block until the freshly spawned server is actually bound and answering on
/// `listen`, replacing a fixed `sleep(300ms)` that raced a slow-starting child.
/// Probes from a throwaway socket with a `Lookup` for an unregistered node —
/// side-effect free (no registered target => `NotFound`, and no `PunchHint` is
/// emitted, per `Server::handle`), so it cannot perturb the register/lookup/
/// relay flow under test. When `key` is `Some`, the probe is obf-wrapped and the
/// reply unwrapped, matching a server started under `--obf-psk`.
fn wait_until_listening(listen: &str, key: Option<&[u8; 16]>) {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    probe
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut plain = Vec::new();
    encode(
        &Message::Lookup {
            node: node_id(&[0xADu8; 32]),
        },
        &mut plain,
    );
    let on_wire = match key {
        Some(k) => yip_obf::obfuscate(k, yip_obf::RDV_TYPE, &plain, 6),
        None => plain.clone(),
    };
    let mut rx = [0u8; 2048];
    for _ in 0..100 {
        probe.send_to(&on_wire, listen).expect("probe send");
        if let Ok((n, _)) = probe.recv_from(&mut rx) {
            let decoded = match key {
                Some(k) => yip_obf::deobfuscate(k, &rx[..n]).and_then(|(_, b)| decode(&b)),
                None => decode(&rx[..n]),
            };
            if matches!(decoded, Some(Message::NotFound { .. })) {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server never started answering on {listen}");
}

#[test]
fn register_lookup_relay_over_udp() {
    let listen = format!("127.0.0.1:{}", free_udp_port());
    let listen = listen.as_str();
    let mut server = spawn_server(listen);
    wait_until_listening(listen, None);

    // `connect` pins each client's peer to the server addr, so the kernel drops
    // datagrams from any other source — a foreign server that reused our port on
    // loopback can't inject a stray reply and trip the assertions below.
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    a.connect(listen).unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    b.connect(listen).unwrap();

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
    a.send(&buf).unwrap();
    std::thread::sleep(Duration::from_millis(100));

    // B looks up A -> expects PeerInfo(A, A's reflexive addr).
    buf.clear();
    encode(&Message::Lookup { node: a_id }, &mut buf);
    b.send(&buf).unwrap();
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
    b.send(&buf).unwrap();
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
/// `yip_obf`-wrapped envelope (a plain `decode` of the raw bytes never recovers
/// the real `Message` — it is hidden behind the envelope), and unwrapping with
/// the SAME key recovers the exact `Message` the plain test asserts on. Proves
/// the client-side wrap/unwrap this task adds to `yipd` is symmetric with the
/// server's, end-to-end over a real socket.
#[test]
fn register_lookup_relay_over_udp_with_obf_psk() {
    let listen = format!("127.0.0.1:{}", free_udp_port());
    let listen = listen.as_str();
    let hex_psk = "11".repeat(32);
    let key = yip_obf::derive_key(&hex_decode(&hex_psk));
    let mut server = spawn_server_with_obf_psk(listen, &hex_psk);
    wait_until_listening(listen, Some(&key));

    // `connect` pins each client to the server addr (see the plain test), so a
    // foreign server reusing our port on loopback can't inject a plaintext reply
    // and trip the "must be obf-wrapped on the wire" assertion below.
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    a.connect(listen).unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    b.connect(listen).unwrap();

    let a_id = node_id(&[3u8; 32]);
    let b_id = node_id(&[4u8; 32]);

    let send_wrapped = |sock: &UdpSocket, msg: &Message| {
        let mut plain = Vec::new();
        encode(msg, &mut plain);
        let wrapped = yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &plain, 6);
        sock.send(&wrapped).unwrap();
    };
    let recv_wrapped = |sock: &UdpSocket, rx: &mut [u8]| -> Message {
        let (n, _) = sock.recv_from(rx).expect("recv");
        let (ptype, body) = yip_obf::deobfuscate(&key, &rx[..n]).expect("unwraps with our key");
        assert_eq!(ptype, yip_obf::RDV_TYPE);
        let real = decode(&body).expect("unwrapped body decodes as a Message");
        // The envelope must actually HIDE the control message: a plain `decode`
        // of the raw wire bytes must never recover the real `Message`. We assert
        // this against the real message, NOT `decode(...).is_none()` — the
        // envelope leads with a random nonce, so ~2% of the time `decode` parses
        // those random bytes into a *different*, garbage `Message` (several tags
        // ignore trailing bytes). That garbage leaks nothing; the security
        // property is only that the TRUE message isn't readable in the clear.
        assert_ne!(
            decode(&rx[..n]).as_ref(),
            Some(&real),
            "the real message must not be recoverable by a plain decode of the wire"
        );
        real
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
