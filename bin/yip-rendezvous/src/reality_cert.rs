//! REALITY.3 §1: the stolen-cert authed acceptor. Fetches the real `dest`
//! site's live leaf certificate at startup, forges a leaf that mimics its
//! identity (subject/SAN/validity/serial/keyUsage/EKU/basicConstraints)
//! signed by a relay-ephemeral key, and serves it from a TLS-1.3-only
//! `SslAcceptor` — one per configured server_name. The outer TLS is
//! zero-CA-auth by design, so the forged chain intentionally does not
//! validate against a public CA; the inner yip handshake is the real
//! security. See the design spec's §1 + Threat model.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "REALITY.3 Task 1: pure leaf-forging core, exercised by its own unit test; \
                   not yet called from main.rs — Task 2 wires it into the async TLS front"
    )
)]

/// The subset of a real leaf certificate we copy into the forged leaf.
/// AIA / SCTs / the original CA signature are intentionally NOT copied:
/// they are bound to the real CA/CT-log keys and unreproducible, and in
/// TLS 1.3 the Certificate message is encrypted so passive DPI never sees
/// them. See spec §1 "Forge a leaf".
pub struct StolenFields {
    pub subject_cn: Option<String>,
    pub dns_sans: Vec<String>,
    pub ip_sans: Vec<std::net::IpAddr>,
    pub not_before: time::OffsetDateTime,
    pub not_after: time::OffsetDateTime,
    pub serial: Vec<u8>,
    pub key_usages: Vec<rcgen::KeyUsagePurpose>,
    pub eku: Vec<rcgen::ExtendedKeyUsagePurpose>,
    pub is_ca: bool,
}

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, Ia5String, IsCa, KeyPair,
    SanType, SerialNumber,
};

/// Build a forged leaf whose identity fields copy `fields`, self-signed by
/// `key` (the relay-ephemeral key). Self-signed is sufficient: the outer TLS
/// is zero-CA-auth, so no chain-building is needed. Unreproducible fields
/// (CA signature, SCTs, AIA) are omitted by design — see `StolenFields`.
pub fn forge_leaf(
    fields: &StolenFields,
    key: &KeyPair,
) -> Result<rcgen::Certificate, rcgen::Error> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    if let Some(cn) = &fields.subject_cn {
        dn.push(DnType::CommonName, cn.clone());
    }
    params.distinguished_name = dn;

    for name in &fields.dns_sans {
        // A malformed name from a hostile/broken upstream must not abort the
        // whole forge — skip it. `Ia5String::try_from` enforces IA5.
        if let Ok(ia5) = Ia5String::try_from(name.clone()) {
            params.subject_alt_names.push(SanType::DnsName(ia5));
        }
    }
    for ip in &fields.ip_sans {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }

    params.not_before = fields.not_before;
    params.not_after = fields.not_after;
    params.serial_number = Some(SerialNumber::from_slice(&fields.serial));
    params.key_usages = fields.key_usages.clone();
    params.extended_key_usages = fields.eku.clone();
    params.is_ca = if fields.is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::ExplicitNoCa
    };

    params.self_signed(key)
}

use std::net::IpAddr;

/// boring renders an `Asn1Time` as `"%b %e %H:%M:%S %Y GMT"` (month abbrev,
/// space-padded day). Parse that back into an `OffsetDateTime`. On any parse
/// failure fall back to a wide window anchored at the Unix epoch / far future
/// so a forged cert is never accidentally "already expired" (the client does
/// not validate it, but an obviously-expired notAfter would be a needless
/// tell) — validity copying is best-effort per spec §1.
fn parse_asn1_time(t: &boring::asn1::Asn1TimeRef) -> time::OffsetDateTime {
    let s = t.to_string(); // e.g. "Feb  3 04:05:06 2025 GMT"
    let fmt = time::format_description::parse_borrowed::<1>(
        "[month repr:short] [day padding:space] [hour]:[minute]:[second] [year] GMT",
    );
    let parsed = fmt
        .ok()
        .and_then(|f| time::PrimitiveDateTime::parse(&s, &f).ok())
        .map(|p| p.assume_utc());
    parsed.unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// Extract the copyable identity fields from a real leaf. Fields boring does
/// not cleanly expose (AIA, SCTs) are intentionally not copied (see
/// `StolenFields` / spec §1 — best-effort, passively invisible under TLS 1.3).
pub fn extract_fields(leaf: &boring::x509::X509Ref) -> StolenFields {
    let subject_cn = leaf
        .subject_name()
        .entries_by_nid(boring::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()));

    let mut dns_sans = Vec::new();
    let mut ip_sans: Vec<IpAddr> = Vec::new();
    if let Some(names) = leaf.subject_alt_names() {
        for n in names.iter() {
            if let Some(dns) = n.dnsname() {
                dns_sans.push(dns.to_owned());
            } else if let Some(ip) = n.ipaddress() {
                // boring yields raw 4- or 16-byte IP bytes.
                if let Ok(v4) = <[u8; 4]>::try_from(ip) {
                    ip_sans.push(IpAddr::from(v4));
                } else if let Ok(v6) = <[u8; 16]>::try_from(ip) {
                    ip_sans.push(IpAddr::from(v6));
                }
            }
        }
    }

    let serial = leaf
        .serial_number()
        .to_bn()
        .ok()
        .map(|bn| bn.to_vec())
        .unwrap_or_default();

    StolenFields {
        subject_cn,
        dns_sans,
        ip_sans,
        not_before: parse_asn1_time(leaf.not_before()),
        not_after: parse_asn1_time(leaf.not_after()),
        serial,
        // Copy standard server-leaf usages; boring's per-bit keyUsage
        // accessor is awkward, and a server leaf's usages are near-universal.
        // This is best-effort mimicry, not byte-parity (spec §1).
        key_usages: vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ],
        eku: vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
        is_ca: false,
    }
}

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Dial `dest` as a TLS client borrowing `sni`, and extract the peer leaf's
/// `StolenFields`. Verification is disabled (we only want the presented
/// bytes, not a trust decision) and the whole dial is bounded by `timeout`
/// so a black-holed `dest` cannot stall startup/refresh.
pub async fn fetch_dest_leaf(
    dest: SocketAddr,
    sni: &str,
    timeout: Duration,
) -> Result<StolenFields, String> {
    let dial = async {
        let tcp = TcpStream::connect(dest)
            .await
            .map_err(|e| format!("connect {dest}: {e}"))?;
        let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
        b.set_verify(SslVerifyMode::NONE);
        let cfg = b.build().configure().map_err(|e| e.to_string())?;
        let stream = tokio_boring::connect(cfg, sni, tcp)
            .await
            .map_err(|e| format!("tls to {sni}: {e}"))?;
        let leaf = stream
            .ssl()
            .peer_cert_chain()
            .and_then(|chain| chain.get(0))
            .ok_or_else(|| "no peer cert".to_owned())?;
        Ok::<StolenFields, String>(extract_fields(leaf))
    };
    tokio::time::timeout(timeout, dial)
        .await
        .map_err(|_| format!("fetch_dest_leaf({sni}) timed out after {timeout:?}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_leaf_copies_subject_san_validity_serial() {
        let fields = StolenFields {
            subject_cn: Some("www.example.com".to_owned()),
            dns_sans: vec!["www.example.com".to_owned(), "example.com".to_owned()],
            ip_sans: Vec::new(),
            not_before: time::macros::datetime!(2025-01-01 0:00 UTC),
            not_after: time::macros::datetime!(2025-12-31 23:59 UTC),
            serial: vec![0x01, 0x02, 0x03, 0x04],
            key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
            eku: vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
            is_ca: false,
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = forge_leaf(&fields, &key).unwrap();

        // Re-parse the forged DER via boring and assert the copied fields.
        let der = cert.der().as_ref().to_vec();
        let x = boring::x509::X509::from_der(&der).unwrap();

        // SAN copied (both DNS names present).
        let sans: Vec<String> = x
            .subject_alt_names()
            .unwrap()
            .iter()
            .filter_map(|n| n.dnsname().map(|s| s.to_owned()))
            .collect();
        assert!(sans.contains(&"www.example.com".to_owned()));
        assert!(sans.contains(&"example.com".to_owned()));

        // Serial copied.
        let serial = x.serial_number().to_bn().unwrap().to_vec();
        assert_eq!(serial, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn extract_fields_reads_a_forged_sample() {
        // Build a known leaf with rcgen, serialize to DER, parse via boring,
        // and assert extract_fields recovers what we put in.
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "sample.test");
        params.distinguished_name = dn;
        params.subject_alt_names.push(SanType::DnsName(
            "sample.test".to_owned().try_into().unwrap(),
        ));
        params.not_before = time::macros::datetime!(2025-02-03 04:05:06 UTC);
        params.not_after = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        params.serial_number = Some(SerialNumber::from_slice(&[0xAA, 0xBB]));
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let sample = params.self_signed(&key).unwrap();

        let x = boring::x509::X509::from_der(sample.der().as_ref()).unwrap();
        let got = extract_fields(&x);

        assert_eq!(got.dns_sans, vec!["sample.test".to_owned()]);
        assert_eq!(got.serial, vec![0xAA, 0xBB]);
        assert_eq!(
            got.not_before,
            time::macros::datetime!(2025-02-03 04:05:06 UTC)
        );
        assert_eq!(
            got.not_after,
            time::macros::datetime!(2026-02-03 04:05:06 UTC)
        );
        assert!(!got.is_ca);
    }

    #[tokio::test]
    #[ignore] // network; run with `cargo test -p yip-rendezvous-bin -- --ignored`
    async fn fetch_real_leaf_from_cloudflare() {
        let addr = tokio::net::lookup_host("cloudflare.com:443")
            .await
            .unwrap()
            .next()
            .unwrap();
        let f = fetch_dest_leaf(addr, "cloudflare.com", std::time::Duration::from_secs(10))
            .await
            .expect("fetch cloudflare leaf");
        assert!(f.dns_sans.iter().any(|s| s.contains("cloudflare")));
    }
}
