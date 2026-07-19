//! Pure-Rust uTLS-equivalent REALITY client (REALITY.2). Crafts a byte-faithful
//! Chrome-150 ClientHello carrying a REALITY auth seal and completes a TLS 1.3
//! handshake to an application-data stream. Standalone — not wired into yipd.
#![forbid(unsafe_code)]

pub mod auth;
pub mod error;
pub mod handshake;
pub mod hello;
pub mod ja;
pub mod server;
pub mod stream;
pub mod template;
pub mod wire;

pub use error::Error;
pub use server::server_key_share;
pub use stream::{capture_dest_flight, connect, RealityStream};
pub use template::{
    CapturedFlight, CertChainShape, EncryptedFlightShape, ServerFlightTemplate, ServerHelloShape,
};
