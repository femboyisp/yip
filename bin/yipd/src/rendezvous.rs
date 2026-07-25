//! The `yipd` side of the rendezvous protocol: a `Rendezvous` trait (so a 2c
//! DHT backend can replace the configured-server one) and the
//! `ConfiguredServerRendezvous` impl that produces `EgressDatagram`s aimed at a
//! configured server and parses server datagrams into `RdvEvent`s the path
//! state machine reacts to.
use std::net::SocketAddr;

use yip_io::poll::EgressDatagram;
use yip_membership::Record;
use yip_rendezvous::{decode, encode, Message, NodeId};

/// A parsed inbound rendezvous datagram, normalized for the path SM.
///
/// Not yet consumed outside tests — Task 6 wires this into `PeerManager`'s
/// path state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdvEvent {
    /// The server told us where a peer is (answer to our `lookup`). `record`
    /// is the peer's signed directory record when the server has one on file
    /// (mesh mode) — `parse` cannot verify it (no roots), so it is surfaced
    /// as-is for `PeerManager` to verify against `Membership::verify_record`
    /// before acting on the candidate (#37 Task 5). Boxed: `Record` (a `Cert`
    /// plus endpoints/sig) is far larger than the other variants, and
    /// clippy's `large_enum_variant` flags an unboxed `Option<Record>` here.
    PeerCandidate {
        node: NodeId,
        addr: SocketAddr,
        record: Option<Box<Record>>,
    },
    /// The server asked us to punch toward a peer that looked us up.
    PunchTo { node: NodeId, addr: SocketAddr },
    /// A relayed tunnel datagram from `src`; `payload` is fed to the peer path.
    Relayed { src: NodeId, payload: Vec<u8> },
    /// The looked-up peer is not registered.
    NotFound { node: NodeId },
    /// Not a message we act on.
    Ignored,
}

/// Abstraction over "how do I find/reach a peer by node id". 2b ships the
/// configured-server impl; 2c adds a DHT impl without touching `PeerManager`.
///
/// Not yet consumed outside tests — Task 6 wires a `Rendezvous` impl into
/// `PeerManager`.
pub trait Rendezvous {
    /// Emit a registration datagram, or `None` if registration is handled
    /// elsewhere (the 3c.4 relay thread sends `Register` itself). UDP impls
    /// return `Some`. `signed` is `Some(record)` when the caller (mesh mode,
    /// membership configured) has minted a fresh signed registration record
    /// via `Membership::sign_registration` — emitted as `RegisterSigned`.
    /// `None` (non-mesh) falls back to the legacy unauthenticated `Register`
    /// (#37 Task 5).
    fn register(&mut self, node: NodeId, signed: Option<Record>) -> Option<EgressDatagram>;
    fn lookup(&mut self, node: NodeId) -> EgressDatagram;
    fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram;
    fn parse(&self, dg: &[u8]) -> RdvEvent;
    fn server_addr(&self) -> SocketAddr;
}

/// Talks to a single configured rendezvous+relay server.
///
/// Not yet constructed outside tests — Task 6 builds one from
/// `Config::rendezvous` and drives it from `PeerManager`.
pub struct ConfiguredServerRendezvous {
    server: SocketAddr,
}

impl ConfiguredServerRendezvous {
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    fn to_server(&self, msg: &Message) -> EgressDatagram {
        let mut bytes = Vec::new();
        encode(msg, &mut bytes);
        EgressDatagram {
            fate: 0,
            dst: self.server,
            bytes,
        }
    }
}

impl Rendezvous for ConfiguredServerRendezvous {
    fn register(&mut self, node: NodeId, signed: Option<Record>) -> Option<EgressDatagram> {
        match signed {
            Some(record) => Some(self.to_server(&Message::RegisterSigned { record })),
            // counter bumped per-registration in 3c.4; 0 is accepted as first-seen
            None => Some(self.to_server(&Message::Register { node, counter: 0 })),
        }
    }
    fn lookup(&mut self, node: NodeId) -> EgressDatagram {
        self.to_server(&Message::Lookup { node })
    }
    fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram {
        self.to_server(&Message::RelaySend {
            src,
            dst,
            payload: payload.to_vec(),
        })
    }
    fn parse(&self, dg: &[u8]) -> RdvEvent {
        match decode(dg) {
            Some(Message::PeerInfo {
                node,
                reflexive,
                record,
            }) => RdvEvent::PeerCandidate {
                node,
                addr: reflexive,
                record: record.map(Box::new),
            },
            Some(Message::PunchHint { node, reflexive }) => RdvEvent::PunchTo {
                node,
                addr: reflexive,
            },
            Some(Message::RelayDeliver { src, payload }) => RdvEvent::Relayed { src, payload },
            Some(Message::NotFound { node }) => RdvEvent::NotFound { node },
            _ => RdvEvent::Ignored,
        }
    }
    fn server_addr(&self) -> SocketAddr {
        self.server
    }
}

/// The 3c.4 relay-dial client's `Rendezvous` view: `Register` is owned by the
/// relay thread (so `register` is `None`), and `relay`/`parse` behave exactly
/// like the UDP impl but addressed at the relay's routing-key `SocketAddr`.
pub struct TlsRelayRendezvous {
    relay_addr: SocketAddr,
}

impl TlsRelayRendezvous {
    pub fn new(relay_addr: SocketAddr) -> Self {
        Self { relay_addr }
    }
    fn to_server(&self, msg: &Message) -> EgressDatagram {
        let mut bytes = Vec::new();
        encode(msg, &mut bytes);
        EgressDatagram {
            fate: 0,
            dst: self.relay_addr,
            bytes,
        }
    }
}

impl Rendezvous for TlsRelayRendezvous {
    fn register(&mut self, _node: NodeId, _signed: Option<Record>) -> Option<EgressDatagram> {
        None // the relay thread owns Register (first-on-connect + keepalive)
    }
    fn lookup(&mut self, _node: NodeId) -> EgressDatagram {
        // Never called on the straight-to-relay path (no hole-punch). Kept a
        // harmless server-addressed no-op rather than `unreachable!` so a stray
        // call can never panic the data plane.
        self.to_server(&Message::Lookup { node: [0u8; 16] })
    }
    fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram {
        self.to_server(&Message::RelaySend {
            src,
            dst,
            payload: payload.to_vec(),
        })
    }
    fn parse(&self, dg: &[u8]) -> RdvEvent {
        ConfiguredServerRendezvous::new(self.relay_addr).parse(dg)
    }
    fn server_addr(&self) -> SocketAddr {
        self.relay_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yip_rendezvous::{encode, node_id, Message};

    fn server() -> SocketAddr {
        "203.0.113.1:51821".parse().unwrap()
    }

    #[test]
    fn register_targets_server_with_our_node_id() {
        let mut r = ConfiguredServerRendezvous::new(server());
        let me = node_id(&[1u8; 32]);
        let dg = r.register(me, None).expect("UDP register is always Some");
        assert_eq!(dg.dst, server());
        assert_eq!(
            yip_rendezvous::decode(&dg.bytes),
            Some(Message::Register {
                node: me,
                counter: 0
            })
        );
    }

    /// Decode an `EgressDatagram`'s bytes as a rendezvous `Message` (test
    /// helper mirroring `register`/`relay`'s wire framing).
    fn decode_to_server(dg: &EgressDatagram) -> Option<Message> {
        yip_rendezvous::decode(&dg.bytes)
    }

    /// Build a decode-valid `Record` whose `node_id` is exactly `node` (a
    /// test fixture, not a correctly-derived-from-pubkey record — `register`
    /// passes `signed` through unverified, so only the wire round-trip
    /// matters here). Mirrors `yip-rendezvous/src/proto.rs`'s own
    /// `sample_record` fixture, with deterministic (non-OsRng) keys since
    /// `yipd`'s dev-deps don't pull in `rand_core`.
    fn sample_record_with_node(node: NodeId) -> Record {
        use ed25519_dalek::{Signer, SigningKey};
        use yip_membership::cert::cert_signing_body;
        use yip_membership::record::{record_signing_body, sign};
        use yip_membership::Cert;

        let ca = SigningKey::from_bytes(&[9u8; 32]);
        let member_pubkey = [1u8; 32];
        let member_sign_key = SigningKey::from_bytes(&[2u8; 32]);
        let member_sign_pubkey = member_sign_key.verifying_key().to_bytes();
        let network_id = [7u8; 16];

        let mut cert = Cert {
            version: 1,
            member_pubkey,
            member_sign_pubkey,
            network_id,
            not_before: 100,
            not_after: 200,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        cert.ca_sig = ca.sign(&cert_signing_body(&cert)).to_bytes();

        let mut record = Record {
            node_id: node,
            cert,
            endpoints: vec!["192.0.2.1:8080".parse().unwrap()],
            seq: 1,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&record);
        record.sig = sign(&body, &member_sign_key.to_bytes());
        record
    }

    #[test]
    fn register_emits_signed_when_record_present() {
        let mut r = ConfiguredServerRendezvous::new(server());
        let me = [3u8; 16];
        let rec = sample_record_with_node(me);
        let dg = r.register(me, Some(rec.clone())).expect("Some");
        let msg = decode_to_server(&dg);
        assert!(matches!(msg, Some(Message::RegisterSigned { record }) if record.node_id == me));
    }

    #[test]
    fn register_falls_back_to_unsigned_without_record() {
        let mut r = ConfiguredServerRendezvous::new(server());
        let me = [3u8; 16];
        let dg = r.register(me, None).expect("Some");
        assert!(
            matches!(decode_to_server(&dg), Some(Message::Register { node, .. }) if node == me)
        );
    }

    #[test]
    fn lookup_targets_server_with_queried_node_id() {
        let mut r = ConfiguredServerRendezvous::new(server());
        let peer = node_id(&[2u8; 32]);
        let dg = r.lookup(peer);
        assert_eq!(dg.dst, server());
        assert_eq!(
            yip_rendezvous::decode(&dg.bytes),
            Some(Message::Lookup { node: peer })
        );
    }

    #[test]
    fn server_addr_returns_configured_server() {
        let r = ConfiguredServerRendezvous::new(server());
        assert_eq!(r.server_addr(), server());
    }

    #[test]
    fn relay_wraps_payload_for_dst() {
        let mut r = ConfiguredServerRendezvous::new(server());
        let me = node_id(&[1u8; 32]);
        let peer = node_id(&[2u8; 32]);
        let dg = r.relay(me, peer, &[4, 5, 6]);
        assert_eq!(dg.dst, server());
        assert_eq!(
            yip_rendezvous::decode(&dg.bytes),
            Some(Message::RelaySend {
                src: me,
                dst: peer,
                payload: vec![4, 5, 6]
            })
        );
    }

    #[test]
    fn parse_maps_server_messages_to_events() {
        let r = ConfiguredServerRendezvous::new(server());
        let n = node_id(&[2u8; 32]);
        let a: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let mut buf = Vec::new();
        encode(
            &Message::PeerInfo {
                node: n,
                reflexive: a,
                record: None,
            },
            &mut buf,
        );
        assert!(
            matches!(r.parse(&buf), RdvEvent::PeerCandidate { node, addr, record } if node == n && addr == a && record.is_none())
        );
        buf.clear();
        encode(
            &Message::PunchHint {
                node: n,
                reflexive: a,
            },
            &mut buf,
        );
        assert!(
            matches!(r.parse(&buf), RdvEvent::PunchTo { node, addr } if node == n && addr == a)
        );
        buf.clear();
        encode(
            &Message::RelayDeliver {
                src: n,
                payload: vec![1, 2],
            },
            &mut buf,
        );
        assert!(
            matches!(r.parse(&buf), RdvEvent::Relayed { src, payload } if src == n && payload == vec![1, 2])
        );
        assert!(matches!(r.parse(&[0xFF]), RdvEvent::Ignored));
    }

    #[test]
    fn tls_relay_register_is_none_but_relay_works() {
        let addr: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let mut r = TlsRelayRendezvous::new(addr);
        let n = node_id(&[7u8; 32]);
        assert!(
            r.register(n, None).is_none(),
            "thread owns Register on the TLS path"
        );
        let dg = r.relay(node_id(&[1u8; 32]), n, b"payload");
        assert_eq!(dg.dst, addr, "relay egress is addressed to the relay");
    }
}
