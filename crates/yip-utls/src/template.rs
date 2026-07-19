//! The structural fingerprint of a real `dest`'s TLS 1.3 server flight,
//! captured by a Chrome-faithful probe (REALITY.5a). Later REALITY.5
//! sub-milestones (5b/5c/5d) reproduce this structure on the relay's
//! authed path so a passive DPI cannot distinguish it from a genuine
//! Chrome↔`dest` session. This module is pure data — no networking, no
//! parsing; see [`crate::handshake::parse_server_hello_shape`] for the
//! `ServerHelloShape` producer and (future) `capture_dest_flight` for the
//! full `ServerFlightTemplate` producer.

/// The structural fingerprint of a real dest's TLS 1.3 server flight,
/// captured by a Chrome-faithful probe. Later REALITY.5 sub-milestones
/// reproduce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFlightTemplate {
    pub server_hello: ServerHelloShape,
    pub encrypted_flight: EncryptedFlightShape,
    pub cert_chain: CertChainShape,
}

/// The cleartext ServerHello structure to byte-match (5b), EXCLUDING the two
/// per-connection values (the 32-byte `random` and the `key_share` value),
/// which 5b substitutes with the relay's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloShape {
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    /// Extensions in wire order, each `(id, body_bytes)` — INCLUDING any GREASE
    /// extension and its exact placement (order is a fingerprint). The
    /// `key_share` extension's body records the group; its 1-per-connection
    /// public-key VALUE is present here as captured but is substituted by 5b.
    pub extensions: Vec<(u16, Vec<u8>)>,
    /// The negotiated `key_share` group (echoed for convenience; also derivable
    /// from `extensions`).
    pub key_share_group: u16,
}

/// The observable shape of the encrypted flight to length/framing-match (5c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFlightShape {
    /// The **ciphertext-payload length** of each TLS record carrying the
    /// encrypted flight, in order — i.e. the value of each record's length
    /// field (bytes 3–4 of the 5-byte record header), which is what a passive
    /// DPI reads; it EXCLUDES the 5-byte outer header. This is how dest split
    /// EE‖Cert‖CertVerify‖Finished into records (a fingerprint). AEAD overhead:
    /// all three TLS 1.3 suites `yip_utls` supports use a 16-byte tag, and TLS
    /// 1.3 appends a 1-byte inner content-type before sealing, so for record
    /// `i` the plaintext(+any TLS-record padding) chunk 5c must seal to hit
    /// this length is exactly `record_lengths[i] - 17` (1 content-type + 16
    /// tag). Stating this fixes the framing math in 5c and avoids off-by-17.
    pub record_lengths: Vec<usize>,
    /// Per-message plaintext lengths (handshake-message length incl. the 4-byte
    /// header), so 5c can pad each forged message to match.
    pub encrypted_extensions_len: usize,
    pub certificate_len: usize,
    pub certificate_verify_len: usize,
    pub finished_len: usize,
}

/// The Certificate message's chain shape. 5c forges + pads ONLY the leaf and
/// appends dest's real intermediates verbatim — intermediates are public,
/// CA-signed, and carry no connection-specific data, so copying their exact
/// DER (rather than a size-only pad) gives full structural AND content chain
/// parity even to an adversary who decrypts the flight, at zero extra forging
/// (the outer TLS is zero-CA-auth, so the chain need not validate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertChainShape {
    /// dest's leaf-cert DER length — 5c pads the forged leaf's DER to this.
    pub leaf_der_len: usize,
    /// dest's intermediate certificates' raw DER bytes, in chain order
    /// (verbatim; 5c appends these after the forged leaf). Empty if dest sent a
    /// leaf-only chain.
    pub intermediates_der: Vec<Vec<u8>>,
}

/// What `capture_dest_flight` returns: the leaf DER (for the caller to parse
/// into its own cert fields) + the structural template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFlight {
    pub leaf_der: Vec<u8>,
    pub template: ServerFlightTemplate,
}
