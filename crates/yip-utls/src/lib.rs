//! Pure-Rust uTLS-equivalent REALITY client (REALITY.2). Crafts a byte-faithful
//! Chrome-150 ClientHello carrying a REALITY auth seal and completes a TLS 1.3
//! handshake to an application-data stream. Standalone — not wired into yipd.
#![forbid(unsafe_code)]

pub mod ja;
pub mod wire;
