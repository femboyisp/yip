//! Node-id derivation and the rendezvous wire `Message` codec.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;
use yip_membership::Record;

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
    RegisterSigned = 7,
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
        /// The requested node's signed directory record, when the relay has
        /// one on file. `None` for legacy datagrams (no trailing presence
        /// byte) or when no record is available.
        record: Option<Record>,
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
    /// A self-authenticating registration: the relay verifies `record`
    /// itself rather than trusting an unauthenticated `counter`.
    RegisterSigned {
        record: Record,
    },
}

/// Encode `record` onto `out` as a big-endian `u16` length prefix followed
/// by its `Record::encode` bytes, mirroring how `record_signing_body`
/// length-prefixes the embedded cert (`Record::decode` requires an exact
/// slice, so a self-delimiting length prefix is required to embed one
/// record inside another message).
fn put_record(out: &mut Vec<u8>, record: &Record) {
    let mut bytes = Vec::new();
    record.encode(&mut bytes);
    let len = u16::try_from(bytes.len()).expect("record fits in u16");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes);
}

/// Parse a length-prefixed record from the front of `buf`. Returns the
/// record and the number of bytes consumed, or `None` if the length prefix,
/// slice, or record contents are invalid/truncated (fail-closed).
fn take_record(buf: &[u8]) -> Option<(Record, usize)> {
    let len = usize::from(u16::from_be_bytes(buf.get(..2)?.try_into().ok()?));
    let record_bytes = buf.get(2..2 + len)?;
    let record = Record::decode(record_bytes)?;
    Some((record, 2 + len))
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
        Message::PeerInfo {
            node,
            reflexive,
            record,
        } => {
            out.push(Tag::PeerInfo as u8);
            out.extend_from_slice(node);
            put_addr(out, reflexive);
            match record {
                Some(r) => {
                    out.push(1);
                    put_record(out, r);
                }
                None => out.push(0),
            }
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
        Message::RegisterSigned { record } => {
            out.push(Tag::RegisterSigned as u8);
            put_record(out, record);
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
            let (reflexive, used) = take_addr(rest.get(16..)?)?;
            let after_addr = rest.get(16 + used..)?;
            let record = match after_addr.first() {
                Some(0) => None,
                Some(1) => {
                    let (record, _) = take_record(after_addr.get(1..)?)?;
                    Some(record)
                }
                Some(_) => return None,
                // No trailing presence byte: a legacy datagram. Treat as
                // `None` for backward compatibility.
                None => None,
            };
            Some(Message::PeerInfo {
                node,
                reflexive,
                record,
            })
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
        t if t == Tag::RegisterSigned as u8 => {
            let (record, _) = take_record(rest)?;
            Some(Message::RegisterSigned { record })
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
    fn decode_rejects_invalid_address_family() {
        // A PeerInfo whose address family byte is neither 4 nor 6 must be
        // rejected (fail-closed), not misparsed.
        let mut buf = vec![Tag::PeerInfo as u8];
        buf.extend_from_slice(&[7u8; 16]); // node
        buf.push(99); // invalid family (valid are 4 / 6)
        buf.extend_from_slice(&[0u8; 4]);
        assert_eq!(decode(&buf), None);
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
            record: None,
        });
        roundtrip(Message::PeerInfo {
            node: n,
            reflexive: v6,
            record: None,
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
                record: None,
            },
            &mut buf,
        );
        // Cut 2 bytes: the trailing `record: None` presence byte plus the
        // last byte of the port, so the address itself is genuinely
        // truncated (not just the presence byte, which legacy decode
        // tolerates).
        buf.truncate(buf.len() - 2);
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

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Build a decode-valid `Record`: a CA-signed `Cert` binding a member
    /// key, and the record itself signed with the member's record-signing
    /// key. Mirrors `yip_membership::record`'s own `make_signed_record` test
    /// fixture (not exposed outside that crate, so reconstructed here).
    fn sample_record() -> Record {
        use ed25519_dalek::{Signer, SigningKey};
        use rand_core::OsRng;
        use yip_membership::cert::cert_signing_body;
        use yip_membership::record::{record_signing_body, sign};
        use yip_membership::{node_id, Cert};

        let ca = SigningKey::generate(&mut OsRng);
        let member_pubkey = [1u8; 32];
        let member_sign_key = SigningKey::generate(&mut OsRng);
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
            node_id: node_id(&member_pubkey),
            cert,
            endpoints: vec![addr("192.0.2.1:8080")],
            seq: 1,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&record);
        record.sig = sign(
            &body,
            member_sign_key.to_bytes().as_ref().try_into().unwrap(),
        );
        record
    }

    #[test]
    fn register_signed_roundtrips() {
        let rec = sample_record();
        roundtrip(Message::RegisterSigned { record: rec });
    }

    #[test]
    fn peerinfo_with_record_roundtrips() {
        roundtrip(Message::PeerInfo {
            node: [7u8; 16],
            reflexive: addr("198.51.100.7:41000"),
            record: Some(sample_record()),
        });
    }

    #[test]
    fn peerinfo_without_record_roundtrips_and_is_backward_compatible() {
        roundtrip(Message::PeerInfo {
            node: [7u8; 16],
            reflexive: addr("198.51.100.7:41000"),
            record: None,
        });
    }

    #[test]
    fn peerinfo_legacy_datagram_with_no_presence_byte_decodes_as_none() {
        // A legacy encoder that predates the `record` field never writes the
        // trailing presence byte at all. Decode must still accept it and
        // treat it as `record: None`.
        let mut buf = vec![Tag::PeerInfo as u8];
        buf.extend_from_slice(&[7u8; 16]); // node
        put_addr(&mut buf, &addr("198.51.100.7:41000")); // no presence byte after
        assert_eq!(
            decode(&buf),
            Some(Message::PeerInfo {
                node: [7u8; 16],
                reflexive: addr("198.51.100.7:41000"),
                record: None,
            })
        );
    }

    #[test]
    fn register_signed_length_prefix_exceeding_buffer_is_none() {
        // A `RegisterSigned` whose u16 length prefix claims more bytes than
        // are actually present must fail closed, not panic.
        let mut buf = vec![Tag::RegisterSigned as u8];
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // claims 65535 bytes
        buf.extend_from_slice(&[0u8; 4]); // far fewer bytes actually follow
        assert_eq!(decode(&buf), None);
    }

    #[test]
    fn peerinfo_record_length_prefix_exceeding_buffer_is_none() {
        let mut buf = vec![Tag::PeerInfo as u8];
        buf.extend_from_slice(&[7u8; 16]); // node
        put_addr(&mut buf, &addr("198.51.100.7:41000"));
        buf.push(1); // presence byte: record follows
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // claims 65535 bytes
        buf.extend_from_slice(&[0u8; 4]); // far fewer bytes actually follow
        assert_eq!(decode(&buf), None);
    }
}
