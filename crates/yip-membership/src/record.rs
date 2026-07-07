//! Member-signed directory record: a node's cert, current endpoints, and a
//! sequence number, signed by the member's record-signing key
//! (`cert.member_sign_pubkey`). This is what gets gossiped between members
//! during anti-entropy.
use std::net::SocketAddr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cert::{put_addr, take_addr, verify_cert, Cert, CertError};
use crate::ids::{node_id, NodeId};

/// A member-signed directory entry: identity (`node_id`), the CA-issued
/// `cert` proving membership, the node's currently-known reachable
/// `endpoints`, a monotonic `seq` for anti-entropy freshness comparison,
/// and the member's `sig` over everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub node_id: NodeId,
    pub cert: Cert,
    pub endpoints: Vec<SocketAddr>,
    pub seq: u64,
    pub sig: [u8; 64],
}

/// Canonical bytes the member signs: `node_id`, then the embedded `cert`
/// (length-prefixed with a big-endian `u16`, since `Cert::decode` requires
/// an exact slice), then `endpoints` (`u16` count, then each address via
/// the shared family-tagged codec), then `seq`.
pub fn record_signing_body(r: &Record) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&r.node_id);

    let mut cert_bytes = Vec::new();
    r.cert.encode(&mut cert_bytes);
    let cert_len = u16::try_from(cert_bytes.len()).expect("cert fits in u16");
    out.extend_from_slice(&cert_len.to_be_bytes());
    out.extend_from_slice(&cert_bytes);

    let endpoint_count = u16::try_from(r.endpoints.len()).expect("endpoints fit in u16");
    out.extend_from_slice(&endpoint_count.to_be_bytes());
    for addr in &r.endpoints {
        put_addr(&mut out, addr);
    }

    out.extend_from_slice(&r.seq.to_be_bytes());
    out
}

/// Ed25519-sign `body` (expected to be `record_signing_body` of the record
/// being minted) with the member's record-signing private key.
pub fn sign(body: &[u8], member_sign_priv: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(member_sign_priv)
        .sign(body)
        .to_bytes()
}

impl Record {
    /// Serialize `self` onto `out`: `record_signing_body` followed by the
    /// 64-byte `sig`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&record_signing_body(self));
        out.extend_from_slice(&self.sig);
    }

    /// Parse a full record (body + `sig`), or `None` if
    /// malformed/truncated/has trailing bytes.
    pub fn decode(buf: &[u8]) -> Option<Record> {
        let mut pos = 0usize;
        let node_id: NodeId = buf.get(pos..pos + 16)?.try_into().ok()?;
        pos += 16;

        let cert_len = u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?);
        pos += 2;
        let cert_len = usize::from(cert_len);
        let cert_bytes = buf.get(pos..pos + cert_len)?;
        let cert = Cert::decode(cert_bytes)?;
        pos += cert_len;

        let endpoint_count = u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?);
        pos += 2;
        let mut endpoints = Vec::with_capacity(usize::from(endpoint_count));
        for _ in 0..endpoint_count {
            let (addr, used) = take_addr(buf.get(pos..)?)?;
            pos += used;
            endpoints.push(addr);
        }

        let seq = u64::from_be_bytes(buf.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;

        let sig: [u8; 64] = buf.get(pos..pos + 64)?.try_into().ok()?;
        pos += 64;

        if pos != buf.len() {
            return None;
        }

        Some(Record {
            node_id,
            cert,
            endpoints,
            seq,
            sig,
        })
    }

    /// Verify record authenticity: (1) the embedded `cert` is a valid,
    /// in-window CA-issued cert for `cert.member_pubkey`; (2) `sig` is a
    /// valid Ed25519 signature over `record_signing_body` under
    /// `cert.member_sign_pubkey`; (3) `self.node_id` matches
    /// `node_id(&cert.member_pubkey)` (the record isn't claiming someone
    /// else's identity).
    pub fn verify(
        &self,
        ca_pubkeys: &[[u8; 32]],
        network_id: &[u8; 16],
        now: u64,
        skew: u64,
    ) -> Result<(), CertError> {
        verify_cert(
            &self.cert,
            ca_pubkeys,
            network_id,
            &self.cert.member_pubkey,
            now,
            skew,
        )?;

        let vk = VerifyingKey::from_bytes(&self.cert.member_sign_pubkey)
            .map_err(|_| CertError::BadSig)?;
        let sig = Signature::from_bytes(&self.sig);
        vk.verify_strict(&record_signing_body(self), &sig)
            .map_err(|_| CertError::BadSig)?;

        if self.node_id != node_id(&self.cert.member_pubkey) {
            return Err(CertError::WrongMember);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as MemberSigningKey;
    use rand_core::OsRng;

    fn ca() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Mint a CA-signed cert whose `member_sign_pubkey` is `member_sign_pub`.
    fn make_cert(
        ca: &SigningKey,
        member_pubkey: [u8; 32],
        member_sign_pub: [u8; 32],
        net: [u8; 16],
        nb: u64,
        na: u64,
    ) -> Cert {
        let mut c = Cert {
            version: 1,
            member_pubkey,
            member_sign_pubkey: member_sign_pub,
            network_id: net,
            not_before: nb,
            not_after: na,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        let sig = ca.sign(&crate::cert::cert_signing_body(&c));
        c.ca_sig = sig.to_bytes();
        c
    }

    fn addrs() -> Vec<SocketAddr> {
        vec![
            "192.0.2.1:8080".parse().unwrap(),
            "[2001:db8::1]:9090".parse().unwrap(),
        ]
    }

    /// Build and sign a fresh, valid `Record`; returns it along with the
    /// pieces needed to verify it (`ca_pub`, `network_id`).
    fn make_signed_record() -> (Record, [u8; 32], [u8; 16]) {
        let ca = ca();
        let ca_pub = ca.verifying_key().to_bytes();
        let member = [1u8; 32];
        let member_sign_key = MemberSigningKey::generate(&mut OsRng);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let net = [7u8; 16];

        let cert = make_cert(&ca, member, member_sign_pub, net, 100, 200);

        let mut r = Record {
            node_id: node_id(&member),
            cert,
            endpoints: addrs(),
            seq: 1,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&r);
        r.sig = sign(
            &body,
            member_sign_key.to_bytes().as_ref().try_into().unwrap(),
        );

        (r, ca_pub, net)
    }

    #[test]
    fn valid_record_verifies() {
        let (r, ca_pub, net) = make_signed_record();
        assert!(r.verify(&[ca_pub], &net, 150, 0).is_ok());
    }

    #[test]
    fn tampered_endpoints_fail_verify() {
        let (mut r, ca_pub, net) = make_signed_record();
        r.endpoints[0] = "192.0.2.200:1234".parse().unwrap();
        assert_eq!(r.verify(&[ca_pub], &net, 150, 0), Err(CertError::BadSig));
    }

    #[test]
    fn wrong_member_sign_key_fails_verify() {
        let ca = ca();
        let ca_pub = ca.verifying_key().to_bytes();
        let member = [1u8; 32];
        let member_sign_key = MemberSigningKey::generate(&mut OsRng);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let net = [7u8; 16];
        let cert = make_cert(&ca, member, member_sign_pub, net, 100, 200);

        let mut r = Record {
            node_id: node_id(&member),
            cert,
            endpoints: addrs(),
            seq: 1,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&r);
        // Sign with a DIFFERENT key than cert.member_sign_pubkey.
        let other_key = MemberSigningKey::generate(&mut OsRng);
        r.sig = sign(&body, other_key.to_bytes().as_ref().try_into().unwrap());

        assert_eq!(r.verify(&[ca_pub], &net, 150, 0), Err(CertError::BadSig));
    }

    #[test]
    fn wrong_node_id_fails_verify() {
        // The claimed node_id doesn't match node_id(&cert.member_pubkey),
        // but the record is otherwise legitimately signed over that wrong
        // node_id — isolates check (3) (the sig itself is valid).
        let ca = ca();
        let ca_pub = ca.verifying_key().to_bytes();
        let member = [1u8; 32];
        let member_sign_key = MemberSigningKey::generate(&mut OsRng);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let net = [7u8; 16];
        let cert = make_cert(&ca, member, member_sign_pub, net, 100, 200);

        let mut r = Record {
            node_id: [0xffu8; 16], // wrong: doesn't derive from `member`
            cert,
            endpoints: addrs(),
            seq: 1,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&r);
        r.sig = sign(
            &body,
            member_sign_key.to_bytes().as_ref().try_into().unwrap(),
        );

        assert_eq!(
            r.verify(&[ca_pub], &net, 150, 0),
            Err(CertError::WrongMember)
        );
    }

    #[test]
    fn record_roundtrips() {
        let (r, _ca_pub, _net) = make_signed_record();
        let mut buf = Vec::new();
        r.encode(&mut buf);
        assert_eq!(Record::decode(&buf), Some(r));
    }
}
