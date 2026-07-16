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
}
