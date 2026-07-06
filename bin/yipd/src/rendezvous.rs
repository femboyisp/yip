//! The `yipd` side of the rendezvous protocol: a `Rendezvous` trait (so a 2c
//! DHT backend can replace the configured-server one) and the
//! `ConfiguredServerRendezvous` impl that produces `EgressDatagram`s aimed at a
//! configured server and parses server datagrams into `RdvEvent`s the path
//! state machine reacts to.
use std::net::SocketAddr;

use yip_io::poll::EgressDatagram;
use yip_rendezvous::{decode, encode, Message, NodeId};

/// A parsed inbound rendezvous datagram, normalized for the path SM.
///
/// Not yet consumed outside tests — Task 6 wires this into `PeerManager`'s
/// path state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdvEvent {
    /// The server told us where a peer is (answer to our `lookup`).
    PeerCandidate { node: NodeId, addr: SocketAddr },
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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "exercised via ConfiguredServerRendezvous in tests today; wired into PeerManager in Task 6"
    )
)]
pub trait Rendezvous {
    fn register(&mut self, node: NodeId) -> EgressDatagram;
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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "constructed in tests today; built from Config::rendezvous in Task 6"
        )
    )]
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
    fn register(&mut self, node: NodeId) -> EgressDatagram {
        self.to_server(&Message::Register { node })
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
            Some(Message::PeerInfo { node, reflexive }) => RdvEvent::PeerCandidate {
                node,
                addr: reflexive,
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
        let dg = r.register(me);
        assert_eq!(dg.dst, server());
        assert_eq!(
            yip_rendezvous::decode(&dg.bytes),
            Some(Message::Register { node: me })
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
            },
            &mut buf,
        );
        assert!(
            matches!(r.parse(&buf), RdvEvent::PeerCandidate { node, addr } if node == n && addr == a)
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
}
