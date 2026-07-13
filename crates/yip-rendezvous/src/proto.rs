//! Node-id derivation and the rendezvous wire `Message` codec.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;

/// Domain separation so node-id can't collide with the mesh-address derivation.
const DOMAIN: &[u8] = b"yip-rdv-v1";

/// A rendezvous identity: `BLAKE2s(DOMAIN || pubkey)[..16]`. Distinct domain
/// from `yipd`'s `node_addr` so the two derivations never coincide.
pub type NodeId = [u8; 16];

/// Derive a node's rendezvous id from its X25519 public key.
pub fn node_id(pubkey: &[u8; 32]) -> NodeId {
    let mut h = Blake2sVar::new(16).expect("16 is a valid blake2s output len");
    h.update(DOMAIN);
    h.update(pubkey);
    let mut out = [0u8; 16];
    h.finalize_variable(&mut out).expect("output len matches");
    out
}

/// Message-type discriminants (the only permitted `as u8` in this crate).
#[repr(u8)]
enum Tag {
    Register = 0,
    Lookup = 1,
    PeerInfo = 2,
    NotFound = 3,
    PunchHint = 4,
    RelaySend = 5,
    RelayDeliver = 6,
}

/// A rendezvous/relay control message. See the 2b spec for direction/semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Register {
        node: NodeId,
        /// Monotonic per-node freshness counter (anti-replay). Strictly
        /// increasing across a node's registrations; the relay rejects any
        /// Register whose counter is not greater than the last seen.
        counter: u64,
    },
    Lookup {
        node: NodeId,
    },
    PeerInfo {
        node: NodeId,
        reflexive: SocketAddr,
    },
    NotFound {
        node: NodeId,
    },
    PunchHint {
        node: NodeId,
        reflexive: SocketAddr,
    },
    RelaySend {
        src: NodeId,
        dst: NodeId,
        payload: Vec<u8>,
    },
    RelayDeliver {
        src: NodeId,
        payload: Vec<u8>,
    },
}

fn put_addr(out: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn take_addr(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let (&fam, rest) = buf.split_first()?;
    let (ip, used): (IpAddr, usize) = match fam {
        4 => {
            let o: [u8; 4] = rest.get(..4)?.try_into().ok()?;
            (IpAddr::V4(Ipv4Addr::from(o)), 4)
        }
        6 => {
            let o: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(o)), 16)
        }
        _ => return None,
    };
    let port_bytes: [u8; 2] = rest.get(used..used + 2)?.try_into().ok()?;
    let port = u16::from_be_bytes(port_bytes);
    Some((SocketAddr::new(ip, port), 1 + used + 2))
}

/// Serialize `msg` onto `out` (appends; caller clears if reusing).
pub fn encode(msg: &Message, out: &mut Vec<u8>) {
    match msg {
        Message::Register { node, counter } => {
            out.push(Tag::Register as u8);
            out.extend_from_slice(node);
            out.extend_from_slice(&counter.to_be_bytes());
        }
        Message::Lookup { node } => {
            out.push(Tag::Lookup as u8);
            out.extend_from_slice(node);
        }
        Message::PeerInfo { node, reflexive } => {
            out.push(Tag::PeerInfo as u8);
            out.extend_from_slice(node);
            put_addr(out, reflexive);
        }
        Message::NotFound { node } => {
            out.push(Tag::NotFound as u8);
            out.extend_from_slice(node);
        }
        Message::PunchHint { node, reflexive } => {
            out.push(Tag::PunchHint as u8);
            out.extend_from_slice(node);
            put_addr(out, reflexive);
        }
        Message::RelaySend { src, dst, payload } => {
            out.push(Tag::RelaySend as u8);
            out.extend_from_slice(src);
            out.extend_from_slice(dst);
            out.extend_from_slice(payload);
        }
        Message::RelayDeliver { src, payload } => {
            out.push(Tag::RelayDeliver as u8);
            out.extend_from_slice(src);
            out.extend_from_slice(payload);
        }
    }
}

/// Parse one datagram into a `Message`, or `None` if malformed/truncated.
pub fn decode(buf: &[u8]) -> Option<Message> {
    let (&tag, rest) = buf.split_first()?;
    let node16 = |b: &[u8]| -> Option<NodeId> { b.get(..16)?.try_into().ok() };
    match tag {
        t if t == Tag::Register as u8 => {
            let node = node16(rest)?;
            let counter = u64::from_be_bytes(rest.get(16..24)?.try_into().ok()?);
            Some(Message::Register { node, counter })
        }
        t if t == Tag::Lookup as u8 => Some(Message::Lookup {
            node: node16(rest)?,
        }),
        t if t == Tag::NotFound as u8 => Some(Message::NotFound {
            node: node16(rest)?,
        }),
        t if t == Tag::PeerInfo as u8 => {
            let node = node16(rest)?;
            let (reflexive, _) = take_addr(rest.get(16..)?)?;
            Some(Message::PeerInfo { node, reflexive })
        }
        t if t == Tag::PunchHint as u8 => {
            let node = node16(rest)?;
            let (reflexive, _) = take_addr(rest.get(16..)?)?;
            Some(Message::PunchHint { node, reflexive })
        }
        t if t == Tag::RelaySend as u8 => {
            let src = node16(rest)?;
            let dst = node16(rest.get(16..)?)?;
            Some(Message::RelaySend {
                src,
                dst,
                payload: rest.get(32..)?.to_vec(),
            })
        }
        t if t == Tag::RelayDeliver as u8 => {
            let src = node16(rest)?;
            Some(Message::RelayDeliver {
                src,
                payload: rest.get(16..)?.to_vec(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn node_id_is_deterministic_and_16_bytes() {
        let pk = [7u8; 32];
        let a = node_id(&pk);
        assert_eq!(a.len(), 16);
        assert_eq!(node_id(&pk), a);
        assert_ne!(node_id(&pk), node_id(&[8u8; 32]));
    }

    fn roundtrip(msg: Message) {
        let mut buf = Vec::new();
        encode(&msg, &mut buf);
        assert_eq!(decode(&buf), Some(msg));
    }

    #[test]
    fn all_messages_roundtrip() {
        let n = [1u8; 16];
        let v4: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        roundtrip(Message::Register {
            node: n,
            counter: 1,
        });
        roundtrip(Message::Lookup { node: n });
        roundtrip(Message::PeerInfo {
            node: n,
            reflexive: v4,
        });
        roundtrip(Message::PeerInfo {
            node: n,
            reflexive: v6,
        });
        roundtrip(Message::NotFound { node: n });
        roundtrip(Message::PunchHint {
            node: n,
            reflexive: v4,
        });
        roundtrip(Message::RelaySend {
            src: [3u8; 16],
            dst: n,
            payload: vec![9, 8, 7],
        });
        roundtrip(Message::RelayDeliver {
            src: n,
            payload: vec![1, 2, 3, 4],
        });
    }

    #[test]
    fn decode_rejects_garbage_and_truncation() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0xFF]), None); // unknown discriminant
        let mut buf = Vec::new();
        encode(
            &Message::PeerInfo {
                node: [2u8; 16],
                reflexive: "1.2.3.4:5".parse().unwrap(),
            },
            &mut buf,
        );
        buf.truncate(buf.len() - 1);
        assert_eq!(decode(&buf), None); // truncated addr
    }

    #[test]
    fn register_roundtrips_with_counter() {
        let n = node_id(&[7u8; 32]);
        let msg = Message::Register {
            node: n,
            counter: 0x0102_0304_0506_0708,
        };
        let mut buf = Vec::new();
        encode(&msg, &mut buf);
        assert_eq!(decode(&buf), Some(msg));
    }

    #[test]
    fn register_truncated_counter_is_none() {
        // tag(1) + node(16) + only 4 of the 8 counter bytes
        let mut buf = vec![0u8]; // Tag::Register
        buf.extend_from_slice(&[9u8; 16]);
        buf.extend_from_slice(&[0u8; 4]);
        assert_eq!(decode(&buf), None);
    }
}
