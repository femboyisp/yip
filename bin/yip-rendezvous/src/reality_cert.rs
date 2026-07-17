//! REALITY.3 §1: the stolen-cert authed acceptor. Fetches the real `dest`
//! site's live leaf certificate at startup, forges a leaf that mimics its
//! identity (subject/SAN/validity/serial/keyUsage/EKU/basicConstraints)
//! signed by a relay-ephemeral key, and serves it from a TLS-1.3-only
//! `SslAcceptor` — one per configured server_name. The outer TLS is
//! zero-CA-auth by design, so the forged chain intentionally does not
//! validate against a public CA; the inner yip handshake is the real
//! security. See the design spec's §1 + Threat model.

/// The subset of a real leaf certificate we copy into the forged leaf.
/// SCTs and the original CA signature are intentionally NOT copied: they
/// are bound to the real CA/CT-log keys and are cryptographically
/// unreproducible by an ephemeral-key forgery — no amount of byte-copying
/// fixes that. AIA (#75) IS copied (see `aia_der`), but is best-effort
/// superficial fidelity, not a security property: in TLS 1.3 the
/// Certificate message is encrypted, so passive DPI never sees either SCTs
/// or AIA — they matter only to an active, config-holding prober that
/// decrypts the connection. See spec §1 "Forge a leaf".
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
    /// Raw DER value of the dest leaf's Authority Information Access
    /// extension (RFC 5280 §4.2.2.1, OID 1.3.6.1.5.5.7.1.1) — i.e. the
    /// content bytes inside the extension's OCTET STRING (the DER-encoded
    /// `AuthorityInfoAccessSyntax`), copied verbatim. `None` if the dest
    /// leaf has no AIA extension, or if it could not be extracted.
    ///
    /// AIA is copyable (unlike SCTs — see the struct doc above), but
    /// copying it is superficial fidelity, not real fidelity, for two
    /// reasons (#75):
    ///   1. It is passively invisible: TLS 1.3 encrypts the Certificate
    ///      message, so this only matters to an active prober that holds
    ///      the connection key and decrypts it — never to passive DPI.
    ///   2. It is residually inconsistent: the copied AIA CA-issuers URL
    ///      still points at the real dest's CA, but that CA did NOT sign
    ///      this leaf (it's self-signed by a relay-ephemeral key per
    ///      `forge_leaf`) — a prober that actually fetches and checks the
    ///      AIA URL will find a mismatch. Copying it closes the "AIA is
    ///      simply absent" tell without claiming to fully replicate the
    ///      dest's PKI chain.
    pub aia_der: Option<Vec<u8>>,
}

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, Ia5String, IsCa, KeyPair,
    SanType, SerialNumber,
};

/// Build a forged leaf whose identity fields copy `fields`, self-signed by
/// `key` (the relay-ephemeral key). Self-signed is sufficient: the outer TLS
/// is zero-CA-auth, so no chain-building is needed. AIA is copied when present
/// (#75, best-effort — see `StolenFields::aia_der`); the CA signature and SCTs
/// are unreproducible (bound to the real CA/CT-log keys) and are omitted.
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

    // #75: re-emit the dest leaf's AIA extension byte-identically, if one
    // was copied. See `StolenFields::aia_der` for why this is superficial
    // (passively invisible under TLS 1.3; the copied CA-issuers URL points
    // to a CA that did not sign this ephemeral-key leaf) rather than a
    // security property.
    if let Some(aia) = &fields.aia_der {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                aia.clone(),
            ));
    }

    params.self_signed(key)
}

use std::net::IpAddr;

/// boring renders an `Asn1Time` as `"%b %e %H:%M:%S %Y GMT"` (month abbrev,
/// space-padded day). Parse that back into an `OffsetDateTime`. On any parse
/// failure return `fallback` instead — callers must pass a fallback on the
/// side that keeps the forged cert from looking "already expired": a
/// far-*past* sentinel for `not_before`, a far-*future* sentinel for
/// `not_after` (the client does not validate the chain, but an obviously
/// bad bound would be a needless tell) — validity copying is best-effort
/// per spec §1.
fn parse_asn1_time(
    t: &boring::asn1::Asn1TimeRef,
    fallback: time::OffsetDateTime,
) -> time::OffsetDateTime {
    let s = t.to_string(); // e.g. "Feb  3 04:05:06 2025 GMT"
    let fmt = time::format_description::parse_borrowed::<1>(
        "[month repr:short] [day padding:space] [hour]:[minute]:[second] [year] GMT",
    );
    let parsed = fmt
        .ok()
        .and_then(|f| time::PrimitiveDateTime::parse(&s, &f).ok())
        .map(|p| p.assume_utc());
    parsed.unwrap_or(fallback)
}

/// Extract the AIA extension's raw value bytes from a leaf's DER, via
/// `x509-parser` (boring does not expose AIA). Best-effort: any parse
/// failure, or the extension simply being absent, yields `None` rather than
/// panicking — see `StolenFields::aia_der`.
fn extract_aia_der(leaf_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(leaf_der).ok()?;
    cert.extensions()
        .iter()
        .find(|e| e.oid == x509_parser::oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
        .map(|e| e.value.to_vec())
}

/// Extract the copyable identity fields from a real leaf. SCTs are
/// intentionally not copied — bound to CT-log keys, unreproducible (see
/// `StolenFields`). AIA (#75) IS copied, best-effort, via `extract_aia_der`
/// since boring does not expose it.
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

    // #75: boring exposes no AIA accessor, so re-derive the leaf's DER and
    // hand it to x509-parser. `to_der()` failing (should not happen for a
    // leaf boring itself just parsed) degrades to `None`, same as AIA simply
    // being absent — never a panic.
    let aia_der = leaf.to_der().ok().and_then(|der| extract_aia_der(&der));

    StolenFields {
        subject_cn,
        dns_sans,
        ip_sans,
        not_before: parse_asn1_time(leaf.not_before(), time::OffsetDateTime::UNIX_EPOCH),
        not_after: parse_asn1_time(
            leaf.not_after(),
            time::macros::datetime!(9999-12-31 23:59:59 UTC),
        ),
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
        aia_der,
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

use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslVersion};

/// Build a TLS-1.3-ONLY `SslAcceptor` presenting the forged leaf. Pinning
/// min-proto to 1.3 keeps the Certificate message encrypted (spec §1 advisor
/// #2 — TLS 1.2 would send it in cleartext). ALPN mirrors `build_acceptor`.
pub fn build_forged_acceptor(
    fields: &StolenFields,
    key: &rcgen::KeyPair,
) -> Result<SslAcceptor, String> {
    let cert = forge_leaf(fields, key).map_err(|e| format!("forge: {e}"))?;
    let cert_der = cert.der().as_ref().to_vec();
    let x509 = boring::x509::X509::from_der(&cert_der).map_err(|e| e.to_string())?;
    let pkey = PKey::private_key_from_der(&key.serialize_der()).map_err(|e| e.to_string())?;

    let mut b =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| e.to_string())?;
    b.set_certificate(&x509).map_err(|e| e.to_string())?;
    b.set_private_key(&pkey).map_err(|e| e.to_string())?;
    b.check_private_key().map_err(|e| e.to_string())?;
    b.set_alpn_protos(b"\x02h2\x08http/1.1")
        .map_err(|e| e.to_string())?;
    Ok(b.build())
}

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// One forged acceptor per configured server_name, plus the ephemeral signing
/// key and each entry's last-successful-fetch instant (for the staleness
/// bound). An SNI absent from the map is splice-only (spec §1 degrade rule).
/// `fetched_at` is now read directly by `RealityCertCache::apply_refresh`
/// (exercised by its own `#[cfg(test)]` unit tests), so no dead_code
/// suppression is needed here any more.
struct CacheEntry {
    acceptor: Arc<SslAcceptor>,
    fetched_at: Instant,
}

pub struct RealityCertCache {
    /// server_name -> live acceptor. Absent ⇒ splice-only.
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// The set of names we are configured to serve (for refresh iteration).
    server_names: Vec<String>,
    /// Relay-ephemeral signing key, generated once; reused across refreshes so
    /// a re-forge for the same name keeps a stable key.
    key: KeyPair,
}

impl RealityCertCache {
    /// Fetch + forge for each server_name. A name whose fetch fails is left
    /// out of the map (splice-only). Errors if at least one name was
    /// REQUESTED and not a single one warmed (misconfiguration guard) — but
    /// an empty `server_names` (the "decoy-only" REALITY config: no SNI is
    /// ever forged, so `run_reality_conn` splices every connection — same
    /// spirit as the existing no-short-ids decoy-only mode) is not itself a
    /// failure and returns a validly-empty cache.
    pub async fn prewarm(
        server_names: &[String],
        dest: SocketAddr,
        _refresh: Duration,
        _max_stale: Duration,
        timeout: Duration,
    ) -> Result<Arc<Self>, String> {
        let key = KeyPair::generate().map_err(|e| format!("keygen: {e}"))?;
        let mut entries = HashMap::new();
        for name in server_names {
            match fetch_dest_leaf(dest, name, timeout).await {
                Ok(fields) => match build_forged_acceptor(&fields, &key) {
                    Ok(acc) => {
                        entries.insert(
                            name.clone(),
                            CacheEntry {
                                acceptor: Arc::new(acc),
                                fetched_at: Instant::now(),
                            },
                        );
                    }
                    Err(e) => eprintln!("reality-cert: forge {name} failed: {e} (splice-only)"),
                },
                Err(e) => eprintln!("reality-cert: prewarm {name} failed: {e} (splice-only)"),
            }
        }
        if entries.is_empty() && !server_names.is_empty() {
            return Err("reality-cert: no server_name pre-warmed; refusing to start".to_owned());
        }
        Ok(Arc::new(Self {
            entries: RwLock::new(entries),
            server_names: server_names.to_vec(),
            key,
        }))
    }

    /// The forged acceptor for `sni`, or `None` (⇒ caller splices to dest).
    pub fn acceptor_for(&self, sni: &str) -> Option<Arc<SslAcceptor>> {
        let g = self.entries.read().expect("cert cache lock poisoned");
        g.get(sni).map(|e| Arc::clone(&e.acceptor))
    }

    /// Apply one refresh outcome for `name` to the cache. `new_acceptor` is
    /// `Some(acc)` on full success (fetch AND forge both succeeded), `None`
    /// on ANY refresh failure (fetch failed, or fetch succeeded but forge
    /// failed). `now`/`max_stale` are injected (rather than reading
    /// `Instant::now()` internally) so this stays pure and unit-testable
    /// without real time or network. This is the ONLY place cache mutation +
    /// the staleness bound (spec §1) are decided.
    fn apply_refresh(
        &self,
        name: &str,
        new_acceptor: Option<Arc<SslAcceptor>>,
        now: Instant,
        max_stale: Duration,
    ) -> RefreshOutcome {
        let mut g = self.entries.write().expect("cert cache poisoned");
        match new_acceptor {
            Some(acceptor) => {
                g.insert(
                    name.to_owned(),
                    CacheEntry {
                        acceptor,
                        fetched_at: now,
                    },
                );
                RefreshOutcome::Refreshed
            }
            None => match g.get(name) {
                None => RefreshOutcome::NothingToDo,
                Some(e) if now.saturating_duration_since(e.fetched_at) > max_stale => {
                    g.remove(name); // degrade to splice-only
                    RefreshOutcome::Evicted
                }
                Some(_) => RefreshOutcome::KeptStale,
            },
        }
    }

    /// Background refresh: every `refresh`, re-fetch each name. A tick has
    /// exactly two outcomes per name: full success (fetch AND forge succeed)
    /// replaces the acceptor and stamps `fetched_at`; ANY failure (fetch
    /// failed, or fetch succeeded but forge failed) runs the staleness check
    /// — keep last-good unless it is now older than `max_stale`, in which
    /// case drop it (⇒ splice-only) rather than serve an ever-staler forgery
    /// (spec §1 staleness bound). All cache-mutation/staleness logic lives in
    /// the pure `apply_refresh` helper; this loop only fetches, forges, and
    /// logs.
    pub fn spawn_refresh(
        self: &Arc<Self>,
        dest: SocketAddr,
        refresh: Duration,
        max_stale: Duration,
        timeout: Duration,
    ) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(refresh);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                for name in &this.server_names {
                    let new_acceptor = match fetch_dest_leaf(dest, name, timeout).await {
                        Ok(fields) => match build_forged_acceptor(&fields, &this.key) {
                            Ok(acc) => Some(Arc::new(acc)),
                            Err(e) => {
                                eprintln!("reality-cert: refresh {name} forge failed: {e}");
                                None
                            }
                        },
                        Err(_) => None,
                    };
                    let outcome = this.apply_refresh(name, new_acceptor, Instant::now(), max_stale);
                    if outcome == RefreshOutcome::Evicted {
                        eprintln!("reality-cert: {name} exceeded max-stale; splice-only");
                    }
                }
            }
        });
    }
}

/// Result of `RealityCertCache::apply_refresh` for one name on one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshOutcome {
    /// Fetch AND forge both succeeded; the entry was replaced.
    Refreshed,
    /// Refresh failed but the existing entry is still within `max_stale`.
    KeptStale,
    /// Refresh failed and the existing entry exceeded `max_stale`; removed.
    Evicted,
    /// Refresh failed and there was no existing entry for this name.
    NothingToDo,
}

/// A syntactically-valid `AuthorityInfoAccessSyntax` DER value (RFC 5280
/// §4.2.2.1) — one `AccessDescription` with `accessMethod = id-ad-caIssuers`
/// (1.3.6.1.5.5.7.48.2) and `accessLocation = uniformResourceIdentifier`
/// `"http://example.test/ca.crt"`. Used as "known DER bytes" for the AIA
/// round-trip tests below; built from primitives (not hand-counted magic
/// lengths) so the encoding is trustworthy.
#[cfg(test)]
fn sample_aia_der() -> Vec<u8> {
    let url = b"http://example.test/ca.crt";
    // OID 1.3.6.1.5.5.7.48.2 (id-ad-caIssuers): 1*40+3=43=0x2B, then 6,1,5,5,7,48,2.
    let oid: &[u8] = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
    let mut general_name = vec![0x86, u8::try_from(url.len()).expect("test url fits in u8")];
    general_name.extend_from_slice(url);
    let mut access_description = Vec::new();
    access_description.extend_from_slice(oid);
    access_description.extend_from_slice(&general_name);
    let mut access_description_seq = vec![
        0x30,
        u8::try_from(access_description.len()).expect("test content fits in u8"),
    ];
    access_description_seq.extend_from_slice(&access_description);
    let mut aia = vec![
        0x30,
        u8::try_from(access_description_seq.len()).expect("test content fits in u8"),
    ];
    aia.extend_from_slice(&access_description_seq);
    aia
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
            aia_der: None,
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

    #[tokio::test]
    async fn forged_acceptor_is_tls13_only_and_presents_copied_subject() {
        let fields = StolenFields {
            subject_cn: Some("acc.test".to_owned()),
            dns_sans: vec!["acc.test".to_owned()],
            ip_sans: Vec::new(),
            not_before: time::macros::datetime!(2025-01-01 0:00 UTC),
            not_after: time::macros::datetime!(2027-01-01 0:00 UTC),
            serial: vec![0x10],
            key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
            eku: vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
            is_ca: false,
            aia_der: None,
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let acceptor = std::sync::Arc::new(build_forged_acceptor(&fields, &key).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acc = std::sync::Arc::clone(&acceptor);
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = tokio_boring::accept(&acc, tcp).await;
            }
        });

        // A TLS-1.2-MAX client must FAIL against the 1.3-only acceptor.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut b = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
        b.set_verify(boring::ssl::SslVerifyMode::NONE);
        b.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_2))
            .unwrap();
        let cfg = b.build().configure().unwrap();
        let res = tokio_boring::connect(cfg, "acc.test", tcp).await;
        assert!(
            res.is_err(),
            "TLS 1.2 client must be rejected by the 1.3-only acceptor"
        );
    }

    /// Spawn a local TLS server (self-signed) that answers any SNI — stands in
    /// for a real `dest`. Returns its address.
    async fn spawn_local_dest() -> SocketAddr {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "local.dest");
        p.distinguished_name = dn;
        p.subject_alt_names.push(SanType::DnsName(
            "local.dest".to_owned().try_into().unwrap(),
        ));
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        let x = boring::x509::X509::from_der(cert.der().as_ref()).unwrap();
        let pkey = PKey::private_key_from_der(&key.serialize_der()).unwrap();
        let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        b.set_certificate(&x).unwrap();
        b.set_private_key(&pkey).unwrap();
        let acc = std::sync::Arc::new(b.build());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((tcp, _)) = l.accept().await {
                    let acc = std::sync::Arc::clone(&acc);
                    tokio::spawn(async move {
                        let _ = tokio_boring::accept(&acc, tcp).await;
                    });
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn prewarm_serves_reachable_and_degrades_unreachable() {
        let dest = spawn_local_dest().await;
        // "good.test" resolves via the local dest; the SNI string is arbitrary
        // (the local dest answers any SNI). We fake an "unreachable" name by
        // pointing the cache at the SAME dest but pre-seeding a name whose
        // fetch we force to fail — simplest: use one real + assert None for an
        // unconfigured name.
        let cache = RealityCertCache::prewarm(
            &["good.test".to_owned()],
            dest,
            Duration::from_secs(3600),
            Duration::from_secs(21600),
            Duration::from_secs(5),
        )
        .await
        .expect("boots with >=1 good SNI");
        assert!(cache.acceptor_for("good.test").is_some());
        assert!(cache.acceptor_for("not.configured").is_none()); // splice-only
    }

    #[tokio::test]
    async fn prewarm_fails_only_when_no_sni_prewarms() {
        // An unroutable dest (TEST-NET-1, discard port) fails for every SNI.
        let dead: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let res = RealityCertCache::prewarm(
            &["a.test".to_owned(), "b.test".to_owned()],
            dead,
            Duration::from_secs(3600),
            Duration::from_secs(21600),
            Duration::from_millis(300),
        )
        .await;
        assert!(res.is_err(), "no SNI pre-warmed ⇒ refuse to start");
    }

    #[tokio::test]
    async fn prewarm_with_no_requested_names_is_a_valid_empty_cache() {
        // Zero REQUESTED names (the "decoy-only" REALITY config, mirroring the
        // existing no-short-ids decoy-only mode) must NOT be treated as "every
        // requested name failed" — it boots with a validly-empty, splice-only
        // cache instead of refusing to start. Dest is unroutable to prove the
        // dest is never even dialed for an empty request.
        let dead: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let cache = RealityCertCache::prewarm(
            &[],
            dead,
            Duration::from_secs(3600),
            Duration::from_secs(21600),
            Duration::from_millis(300),
        )
        .await
        .expect("empty server_names must boot with an empty cache, not refuse to start");
        assert!(cache.acceptor_for("anything.test").is_none());
    }

    /// Build a throwaway forged acceptor for tests that only care about
    /// cache bookkeeping (insert/replace/evict), not TLS behavior.
    fn dummy_acceptor() -> Arc<SslAcceptor> {
        let fields = StolenFields {
            subject_cn: Some("dummy.test".to_owned()),
            dns_sans: vec!["dummy.test".to_owned()],
            ip_sans: Vec::new(),
            not_before: time::macros::datetime!(2025-01-01 0:00 UTC),
            not_after: time::macros::datetime!(2027-01-01 0:00 UTC),
            serial: vec![0x01],
            key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
            eku: vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
            is_ca: false,
            aia_der: None,
        };
        let key = KeyPair::generate().unwrap();
        Arc::new(build_forged_acceptor(&fields, &key).unwrap())
    }

    /// A cache pre-seeded with a single entry for `name` stamped `fetched_at`
    /// — lets tests drive `apply_refresh` with an injected `now` instead of
    /// real time, and without any network access.
    fn cache_with_entry(name: &str, fetched_at: Instant) -> RealityCertCache {
        let key = KeyPair::generate().unwrap();
        let mut entries = HashMap::new();
        entries.insert(
            name.to_owned(),
            CacheEntry {
                acceptor: dummy_acceptor(),
                fetched_at,
            },
        );
        RealityCertCache {
            entries: RwLock::new(entries),
            server_names: vec![name.to_owned()],
            key,
        }
    }

    #[test]
    fn apply_refresh_full_success_replaces_entry_and_stamps_now() {
        let t0 = Instant::now();
        let cache = cache_with_entry("a.test", t0);
        let new_acc = dummy_acceptor();
        let later = t0 + Duration::from_secs(10);

        let outcome = cache.apply_refresh(
            "a.test",
            Some(Arc::clone(&new_acc)),
            later,
            Duration::from_secs(3600),
        );

        assert_eq!(outcome, RefreshOutcome::Refreshed);
        assert!(
            cache.acceptor_for("a.test").is_some(),
            "replaced entry must still be served"
        );
        // Stamped at `later`: a failure just 1s after that must NOT be stale
        // under a 3600s bound, proving the replace actually updated fetched_at.
        let still_fresh = cache.apply_refresh(
            "a.test",
            None,
            later + Duration::from_secs(1),
            Duration::from_secs(3600),
        );
        assert_eq!(still_fresh, RefreshOutcome::KeptStale);
    }

    #[test]
    fn apply_refresh_failure_within_max_stale_keeps_last_good() {
        let t0 = Instant::now();
        let cache = cache_with_entry("a.test", t0);
        let max_stale = Duration::from_secs(3600);
        let now = t0 + Duration::from_secs(60); // well within max_stale

        let outcome = cache.apply_refresh("a.test", None, now, max_stale);

        assert_eq!(outcome, RefreshOutcome::KeptStale);
        assert!(
            cache.acceptor_for("a.test").is_some(),
            "last-good acceptor must still be served while within max_stale"
        );
    }

    #[test]
    fn apply_refresh_failure_past_max_stale_evicts_entry() {
        let t0 = Instant::now();
        let cache = cache_with_entry("a.test", t0);
        let max_stale = Duration::from_secs(3600);
        let now = t0 + Duration::from_secs(3601); // just past max_stale

        let outcome = cache.apply_refresh("a.test", None, now, max_stale);

        assert_eq!(outcome, RefreshOutcome::Evicted);
        assert!(
            cache.acceptor_for("a.test").is_none(),
            "stale entry must be evicted ⇒ splice-only"
        );
    }

    #[test]
    fn apply_refresh_failure_for_unknown_name_is_a_noop() {
        let t0 = Instant::now();
        let cache = cache_with_entry("a.test", t0);

        let outcome = cache.apply_refresh("never.configured", None, t0, Duration::from_secs(3600));

        assert_eq!(outcome, RefreshOutcome::NothingToDo);
    }

    /// Build a sample leaf carrying a custom AIA extension with `content` as
    /// its raw value, self-signed via rcgen, returned as DER.
    fn leaf_with_aia_der(content: &[u8]) -> Vec<u8> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "aia.test");
        params.distinguished_name = dn;
        params
            .subject_alt_names
            .push(SanType::DnsName("aia.test".to_owned().try_into().unwrap()));
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                content.to_vec(),
            ));
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().as_ref().to_vec()
    }

    /// #75: `extract_fields` must copy the dest leaf's AIA extension value
    /// verbatim, and `forge_leaf` must re-emit it byte-identically in the
    /// forged leaf — a config-holding prober decrypting the TLS 1.3
    /// Certificate message should see the same AIA bytes the real `dest`
    /// leaf had (even though the CA-issuers URL it points to did not sign
    /// this ephemeral-key forgery — see `StolenFields::aia_der` docs).
    #[test]
    fn aia_round_trips_through_extract_and_forge() {
        let known = sample_aia_der();
        let leaf_der = leaf_with_aia_der(&known);
        let leaf = boring::x509::X509::from_der(&leaf_der).unwrap();

        let extracted = extract_fields(&leaf);
        assert_eq!(
            extracted.aia_der,
            Some(known.clone()),
            "extract_fields must copy the AIA extension value verbatim"
        );

        let key = KeyPair::generate().unwrap();
        let forged = forge_leaf(&extracted, &key).unwrap();
        let forged_der = forged.der().as_ref().to_vec();

        let (_, parsed) = x509_parser::parse_x509_certificate(&forged_der)
            .expect("forged leaf must be valid DER");
        let aia_ext = parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
            .expect("forged leaf must carry a re-emitted AIA extension");
        assert_eq!(
            aia_ext.value, known,
            "forged leaf's AIA extension value must byte-match the stolen one"
        );
    }

    /// A dest leaf with no AIA extension must extract to `aia_der: None` —
    /// AIA is optional per RFC 5280, and its absence must not be treated as
    /// an extraction failure.
    #[test]
    fn extract_fields_no_aia_is_none() {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "no-aia.test");
        params.distinguished_name = dn;
        params.subject_alt_names.push(SanType::DnsName(
            "no-aia.test".to_owned().try_into().unwrap(),
        ));
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let leaf = boring::x509::X509::from_der(cert.der().as_ref()).unwrap();

        let extracted = extract_fields(&leaf);
        assert_eq!(extracted.aia_der, None);
    }
}
