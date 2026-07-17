//! Unified error type for [`crate::stream::connect`] / [`crate::stream::RealityStream`]
//! — wraps the per-module error from [`crate::handshake`] plus the I/O, RNG,
//! and protocol-framing failures that only arise once those primitives are
//! driven over a real socket.

use std::fmt;

/// Everything that can go wrong establishing a REALITY-mimicking TLS 1.3
/// client connection. Fail-closed: every fallible step in
/// [`crate::stream::connect`] returns one of these rather than panicking on
/// untrusted peer input.
#[derive(Debug)]
pub enum Error {
    /// The underlying transport failed (read/write/EOF).
    Io(std::io::Error),
    /// A [`crate::handshake`] primitive rejected malformed/out-of-scope TLS
    /// bytes, or a record-layer AEAD seal/open failed.
    Handshake(crate::handshake::Error),
    /// The OS CSPRNG failed while generating the ephemeral key, the
    /// `client_random`, or a `ClientHello` filler field.
    Rng(getrandom::Error),
    /// The peer's record/handshake framing violated an invariant `connect`
    /// or `RealityStream` requires: an unexpected record type at a given
    /// step, a record/message exceeding this client's sane length bound, or
    /// sequence-counter exhaustion.
    Protocol(&'static str),
    /// The system clock reads before the Unix epoch, so `ts_min` cannot be
    /// computed for the REALITY auth seal.
    Clock,
    /// REALITY.4b relay verification failed (leaf key mismatch, bad
    /// CertificateVerify, wrong scheme, or a missing/malformed message). The
    /// caller must treat the relay as unauthenticated and NOT tunnel.
    RealityVerify(&'static str),
    /// REALITY.5b: the relay's [`crate::server::server_key_share`] was asked
    /// to key a TLS group it does not implement server-side KEX for (only
    /// `29`/X25519 and `4588`/X25519MLKEM768 are supported).
    UnsupportedGroup(u16),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Handshake(e) => write!(f, "TLS handshake error: {e}"),
            Error::Rng(e) => write!(f, "OS RNG failure: {e}"),
            Error::Protocol(msg) => write!(f, "REALITY/TLS protocol error: {msg}"),
            Error::Clock => write!(f, "system clock reads before the Unix epoch"),
            Error::RealityVerify(m) => write!(f, "REALITY relay verification failed: {m}"),
            Error::UnsupportedGroup(g) => write!(f, "REALITY server cannot key TLS group {g}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Handshake(e) => Some(e),
            Error::Rng(e) => Some(e),
            Error::Protocol(_)
            | Error::Clock
            | Error::RealityVerify(_)
            | Error::UnsupportedGroup(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<crate::handshake::Error> for Error {
    fn from(e: crate::handshake::Error) -> Self {
        Error::Handshake(e)
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Rng(e)
    }
}
