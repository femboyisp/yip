//! Anti-entropy gossip wire messages exchanged between members to
//! reconcile their directory (`Record`) state: a compact digest of
//! known `(node_id, seq)` pairs, a pull request for specific nodes'
//! full records, and the records themselves.
use crate::ids::NodeId;
use crate::record::Record;

const TAG_DIGEST: u8 = 0;
const TAG_PULL_REQUEST: u8 = 1;
const TAG_RECORDS: u8 = 2;

/// A gossip anti-entropy message.
#[derive(Debug, Clone, PartialEq)]
pub enum GossipMsg {
    /// `(node_id, seq)` for every record the sender knows about, so the
    /// peer can diff against its own state.
    Digest(Vec<(NodeId, u64)>),
    /// Request the full, current `Record` for each listed `node_id`.
    PullRequest(Vec<NodeId>),
    /// Full records, sent in response to a `PullRequest` (or pushed
    /// unsolicited).
    Records(Vec<Record>),
}

impl GossipMsg {
    /// Serialize `self` onto `out`: a one-byte discriminant, then a
    /// `u16`-length-prefixed, variant-specific body.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            GossipMsg::Digest(entries) => {
                out.push(TAG_DIGEST);
                let count = u16::try_from(entries.len()).expect("digest entries fit in u16");
                out.extend_from_slice(&count.to_be_bytes());
                for (id, seq) in entries {
                    out.extend_from_slice(id);
                    out.extend_from_slice(&seq.to_be_bytes());
                }
            }
            GossipMsg::PullRequest(ids) => {
                out.push(TAG_PULL_REQUEST);
                let count = u16::try_from(ids.len()).expect("pull-request ids fit in u16");
                out.extend_from_slice(&count.to_be_bytes());
                for id in ids {
                    out.extend_from_slice(id);
                }
            }
            GossipMsg::Records(records) => {
                out.push(TAG_RECORDS);
                let count = u16::try_from(records.len()).expect("records fit in u16");
                out.extend_from_slice(&count.to_be_bytes());
                for r in records {
                    let mut buf = Vec::new();
                    r.encode(&mut buf);
                    let len = u16::try_from(buf.len()).expect("encoded record fits in u16");
                    out.extend_from_slice(&len.to_be_bytes());
                    out.extend_from_slice(&buf);
                }
            }
        }
    }

    /// Parse a full message (discriminant + body), or `None` if
    /// malformed/truncated/has trailing bytes or an unknown discriminant.
    pub fn decode(buf: &[u8]) -> Option<GossipMsg> {
        let (&tag, rest) = buf.split_first()?;
        match tag {
            TAG_DIGEST => {
                let mut pos = 0usize;
                let count = u16::from_be_bytes(rest.get(pos..pos + 2)?.try_into().ok()?);
                pos += 2;
                let mut entries = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let id: NodeId = rest.get(pos..pos + 16)?.try_into().ok()?;
                    pos += 16;
                    let seq = u64::from_be_bytes(rest.get(pos..pos + 8)?.try_into().ok()?);
                    pos += 8;
                    entries.push((id, seq));
                }
                if pos != rest.len() {
                    return None;
                }
                Some(GossipMsg::Digest(entries))
            }
            TAG_PULL_REQUEST => {
                let mut pos = 0usize;
                let count = u16::from_be_bytes(rest.get(pos..pos + 2)?.try_into().ok()?);
                pos += 2;
                let mut ids = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let id: NodeId = rest.get(pos..pos + 16)?.try_into().ok()?;
                    pos += 16;
                    ids.push(id);
                }
                if pos != rest.len() {
                    return None;
                }
                Some(GossipMsg::PullRequest(ids))
            }
            TAG_RECORDS => {
                let mut pos = 0usize;
                let count = u16::from_be_bytes(rest.get(pos..pos + 2)?.try_into().ok()?);
                pos += 2;
                let mut records = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let len = u16::from_be_bytes(rest.get(pos..pos + 2)?.try_into().ok()?);
                    pos += 2;
                    let len = usize::from(len);
                    let sub = rest.get(pos..pos + len)?;
                    pos += len;
                    records.push(Record::decode(sub)?);
                }
                if pos != rest.len() {
                    return None;
                }
                Some(GossipMsg::Records(records))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{cert_signing_body, Cert};
    use crate::ids::node_id;
    use crate::record::{record_signing_body, sign};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn signed_record(seq: u64) -> Record {
        let ca = SigningKey::generate(&mut OsRng);
        let member = [3u8; 32];
        let member_sign_key = SigningKey::generate(&mut OsRng);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let net = [7u8; 16];

        let mut cert = Cert {
            version: 1,
            member_pubkey: member,
            member_sign_pubkey: member_sign_pub,
            network_id: net,
            not_before: 0,
            not_after: 1_000_000,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        cert.ca_sig = ca.sign(&cert_signing_body(&cert)).to_bytes();

        let mut r = Record {
            node_id: node_id(&member),
            cert,
            endpoints: vec!["192.0.2.1:8080".parse().unwrap()],
            seq,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&r);
        r.sig = sign(
            &body,
            member_sign_key.to_bytes().as_ref().try_into().unwrap(),
        );
        r
    }

    #[test]
    fn digest_roundtrips() {
        let msg = GossipMsg::Digest(vec![([1u8; 16], 5), ([2u8; 16], 9)]);
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(GossipMsg::decode(&buf), Some(msg));
    }

    #[test]
    fn digest_roundtrips_empty() {
        let msg = GossipMsg::Digest(vec![]);
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(GossipMsg::decode(&buf), Some(msg));
    }

    #[test]
    fn pull_request_roundtrips() {
        let msg = GossipMsg::PullRequest(vec![[1u8; 16], [2u8; 16], [3u8; 16]]);
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(GossipMsg::decode(&buf), Some(msg));
    }

    #[test]
    fn records_roundtrips() {
        let r1 = signed_record(1);
        let r2 = signed_record(2);
        let msg = GossipMsg::Records(vec![r1, r2]);
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(GossipMsg::decode(&buf), Some(msg));
    }

    #[test]
    fn decode_rejects_unknown_tag_and_trailing_bytes() {
        assert_eq!(GossipMsg::decode(&[99u8]), None);

        let msg = GossipMsg::PullRequest(vec![[1u8; 16]]);
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        buf.push(0xff); // trailing garbage
        assert_eq!(GossipMsg::decode(&buf), None);
    }
}
