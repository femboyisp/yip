//! CA-signed member certificates and the signed root set.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ed25519_dalek::{Signature, VerifyingKey};

/// A CA-issued certificate binding a member's data-plane key
/// (`member_pubkey`) and record-signing key (`member_sign_pubkey`) to a
/// network for a validity window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    pub version: u8,
    pub member_pubkey: [u8; 32],
    pub member_sign_pubkey: [u8; 32],
    pub network_id: [u8; 16],
    pub not_before: u64,
    pub not_after: u64,
    pub tags: Vec<(u8, Vec<u8>)>,
    pub ca_sig: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError {
    BadSig,
    Expired,
    NotYetValid,
    WrongNetwork,
    WrongMember,
}

/// Canonical bytes the CA signs: every `Cert` field except `ca_sig`, in
/// declared order, with `tags` length-prefixed (`u16` count, then each
/// `(u8 tag, u16 len, bytes)`).
pub fn cert_signing_body(c: &Cert) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(c.version);
    out.extend_from_slice(&c.member_pubkey);
    out.extend_from_slice(&c.member_sign_pubkey);
    out.extend_from_slice(&c.network_id);
    out.extend_from_slice(&c.not_before.to_be_bytes());
    out.extend_from_slice(&c.not_after.to_be_bytes());
    let tag_count = u16::try_from(c.tags.len()).expect("tags fit in u16");
    out.extend_from_slice(&tag_count.to_be_bytes());
    for (tag, bytes) in &c.tags {
        out.push(*tag);
        let len = u16::try_from(bytes.len()).expect("tag value fits in u16");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

impl Cert {
    /// Serialize `self` onto `out` (appends; caller clears if reusing):
    /// the signing body followed by the 64-byte `ca_sig`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&cert_signing_body(self));
        out.extend_from_slice(&self.ca_sig);
    }

    /// Parse a full certificate (body + `ca_sig`), or `None` if
    /// malformed/truncated/has trailing bytes.
    pub fn decode(buf: &[u8]) -> Option<Cert> {
        let mut pos = 0usize;
        let version = *buf.get(pos)?;
        pos += 1;
        let member_pubkey: [u8; 32] = buf.get(pos..pos + 32)?.try_into().ok()?;
        pos += 32;
        let member_sign_pubkey: [u8; 32] = buf.get(pos..pos + 32)?.try_into().ok()?;
        pos += 32;
        let network_id: [u8; 16] = buf.get(pos..pos + 16)?.try_into().ok()?;
        pos += 16;
        let not_before = u64::from_be_bytes(buf.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let not_after = u64::from_be_bytes(buf.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let tag_count = u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?);
        pos += 2;
        let mut tags = Vec::with_capacity(usize::from(tag_count));
        for _ in 0..tag_count {
            let tag = *buf.get(pos)?;
            pos += 1;
            let len = u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?);
            pos += 2;
            let len = usize::from(len);
            let bytes = buf.get(pos..pos + len)?.to_vec();
            pos += len;
            tags.push((tag, bytes));
        }
        let ca_sig: [u8; 64] = buf.get(pos..pos + 64)?.try_into().ok()?;
        pos += 64;
        if pos != buf.len() {
            return None;
        }
        Some(Cert {
            version,
            member_pubkey,
            member_sign_pubkey,
            network_id,
            not_before,
            not_after,
            tags,
            ca_sig,
        })
    }
}

fn verify_any(body: &[u8], sig_bytes: &[u8; 64], ca_pubkeys: &[[u8; 32]]) -> bool {
    let sig = Signature::from_bytes(sig_bytes);
    ca_pubkeys.iter().any(|pk| {
        VerifyingKey::from_bytes(pk)
            .map(|vk| vk.verify_strict(body, &sig).is_ok())
            .unwrap_or(false)
    })
}

/// Verify `c` against any of `ca_pubkeys`: Ed25519 signature over
/// `cert_signing_body`, that the cert covers `member_pubkey`, matches
/// `network_id`, and is within its validity window widened by `skew` on
/// both ends.
pub fn verify_cert(
    c: &Cert,
    ca_pubkeys: &[[u8; 32]],
    network_id: &[u8; 16],
    member_pubkey: &[u8; 32],
    now: u64,
    skew: u64,
) -> Result<(), CertError> {
    let body = cert_signing_body(c);
    if !verify_any(&body, &c.ca_sig, ca_pubkeys) {
        return Err(CertError::BadSig);
    }
    if &c.member_pubkey != member_pubkey {
        return Err(CertError::WrongMember);
    }
    if &c.network_id != network_id {
        return Err(CertError::WrongNetwork);
    }
    if c.not_before > now.saturating_add(skew) {
        return Err(CertError::NotYetValid);
    }
    if now >= c.not_after.saturating_add(skew) {
        return Err(CertError::Expired);
    }
    Ok(())
}

/// A CA-signed set of bootstrap root nodes (pubkey + reachable address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSet {
    pub roots: Vec<([u8; 32], SocketAddr)>,
    pub version: u64,
    pub ca_sig: [u8; 64],
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

/// Canonical bytes the CA signs for a `RootSet`: `version`, then each
/// root's `(pubkey, encoded SocketAddr)`.
pub fn rootset_signing_body(r: &RootSet) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&r.version.to_be_bytes());
    let count = u16::try_from(r.roots.len()).expect("roots fit in u16");
    out.extend_from_slice(&count.to_be_bytes());
    for (pk, addr) in &r.roots {
        out.extend_from_slice(pk);
        put_addr(&mut out, addr);
    }
    out
}

impl RootSet {
    /// Serialize `self` onto `out`: the signing body followed by the
    /// 64-byte `ca_sig`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&rootset_signing_body(self));
        out.extend_from_slice(&self.ca_sig);
    }

    /// Parse a full root set (body + `ca_sig`), or `None` if
    /// malformed/truncated/has trailing bytes.
    pub fn decode(buf: &[u8]) -> Option<RootSet> {
        let mut pos = 0usize;
        let version = u64::from_be_bytes(buf.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let count = u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?);
        pos += 2;
        let mut roots = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let pk: [u8; 32] = buf.get(pos..pos + 32)?.try_into().ok()?;
            pos += 32;
            let (addr, used) = take_addr(buf.get(pos..)?)?;
            pos += used;
            roots.push((pk, addr));
        }
        let ca_sig: [u8; 64] = buf.get(pos..pos + 64)?.try_into().ok()?;
        pos += 64;
        if pos != buf.len() {
            return None;
        }
        Some(RootSet {
            roots,
            version,
            ca_sig,
        })
    }

    /// Verify `ca_sig` over `rootset_signing_body` against any of
    /// `ca_pubkeys`.
    pub fn verify_rootset(&self, ca_pubkeys: &[[u8; 32]]) -> bool {
        verify_any(&rootset_signing_body(self), &self.ca_sig, ca_pubkeys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn ca() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_cert(ca: &SigningKey, member: [u8; 32], net: [u8; 16], nb: u64, na: u64) -> Cert {
        let mut c = Cert {
            version: 1,
            member_pubkey: member,
            member_sign_pubkey: [9u8; 32],
            network_id: net,
            not_before: nb,
            not_after: na,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        let sig = ca.sign(&cert_signing_body(&c));
        c.ca_sig = sig.to_bytes();
        c
    }

    #[test]
    fn cert_roundtrips() {
        let c = make_cert(&ca(), [1u8; 32], [7u8; 16], 100, 200);
        let mut buf = Vec::new();
        c.encode(&mut buf);
        assert_eq!(Cert::decode(&buf), Some(c));
    }

    #[test]
    fn valid_cert_verifies_and_matrix_of_failures() {
        let ca = ca();
        let ca_pub = ca.verifying_key().to_bytes();
        let member = [1u8; 32];
        let net = [7u8; 16];
        let c = make_cert(&ca, member, net, 100, 200);
        // valid at now=150
        assert!(verify_cert(&c, &[ca_pub], &net, &member, 150, 0).is_ok());
        // expired
        assert_eq!(
            verify_cert(&c, &[ca_pub], &net, &member, 250, 0),
            Err(CertError::Expired)
        );
        // not yet valid
        assert_eq!(
            verify_cert(&c, &[ca_pub], &net, &member, 50, 0),
            Err(CertError::NotYetValid)
        );
        // skew lets a just-expired cert pass within tolerance
        assert!(verify_cert(&c, &[ca_pub], &net, &member, 205, 10).is_ok());
        // wrong network
        assert_eq!(
            verify_cert(&c, &[ca_pub], &[8u8; 16], &member, 150, 0),
            Err(CertError::WrongNetwork)
        );
        // cert doesn't cover the presented key
        assert_eq!(
            verify_cert(&c, &[ca_pub], &net, &[2u8; 32], 150, 0),
            Err(CertError::WrongMember)
        );
        // wrong CA
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert_eq!(
            verify_cert(&c, &[other], &net, &member, 150, 0),
            Err(CertError::BadSig)
        );
        // tampered body
        let mut t = c.clone();
        t.not_after = 9999;
        assert_eq!(
            verify_cert(&t, &[ca_pub], &net, &member, 150, 0),
            Err(CertError::BadSig)
        );
    }

    #[test]
    fn rootset_roundtrips() {
        let ca = ca();
        let root1_pk = [1u8; 32];
        let root1_addr = "192.0.2.1:8080".parse::<SocketAddr>().unwrap();
        let root2_pk = [2u8; 32];
        let root2_addr = "[2001:db8::1]:9090".parse::<SocketAddr>().unwrap();
        let mut rs = RootSet {
            roots: vec![(root1_pk, root1_addr), (root2_pk, root2_addr)],
            version: 42,
            ca_sig: [0u8; 64],
        };
        let sig = ca.sign(&rootset_signing_body(&rs));
        rs.ca_sig = sig.to_bytes();
        let mut buf = Vec::new();
        rs.encode(&mut buf);
        assert_eq!(RootSet::decode(&buf), Some(rs));
    }

    #[test]
    fn rootset_verifies_and_rejects_wrong_ca_and_tampering() {
        let ca = ca();
        let ca_pub = ca.verifying_key().to_bytes();
        let root_pk = [3u8; 32];
        let root_addr = "192.0.2.100:5000".parse::<SocketAddr>().unwrap();
        let mut rs = RootSet {
            roots: vec![(root_pk, root_addr)],
            version: 7,
            ca_sig: [0u8; 64],
        };
        let sig = ca.sign(&rootset_signing_body(&rs));
        rs.ca_sig = sig.to_bytes();

        // valid CA signs and verifies
        assert!(rs.verify_rootset(&[ca_pub]));

        // wrong CA rejects
        let other_ca = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert!(!rs.verify_rootset(&[other_ca]));

        // tampered version rejects
        let mut tampered = rs.clone();
        tampered.version = 999;
        assert!(!tampered.verify_rootset(&[ca_pub]));

        // tampered root pk rejects
        let mut tampered = rs.clone();
        tampered.roots[0].0 = [99u8; 32];
        assert!(!tampered.verify_rootset(&[ca_pub]));

        // tampered root addr rejects
        let mut tampered = rs.clone();
        tampered.roots[0].1 = "192.0.2.200:6000".parse::<SocketAddr>().unwrap();
        assert!(!tampered.verify_rootset(&[ca_pub]));
    }
}
