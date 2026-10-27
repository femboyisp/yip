//! # yip-mesh
//!
//! High-performance userspace WireGuard-alternative overlay network protocol and Rust SDK.
//!
//! `yip-mesh` unifies the sub-crates of the yip project into a modular, cohesive library.
//! Whether you are integrating yip's slotted Reed-Solomon FEC into custom network protocols,
//! verifying self-certifying mesh certificates, or orchestrating FROST threshold signers,
//! `yip` provides typed, memory-safe primitives.
//!
//! ## Feature Flags
//!
//! By default, the following core features are enabled:
//! - `crypto`: Noise-IK cryptography, AEAD ciphers, BLAKE2s hashing.
//! - `wire`: Packet framing, wire codec, and header obfuscation.
//! - `transport`: Slotted Reed-Solomon FEC, sliding-window reassembly, and adaptive ARQ.
//! - `membership`: Cryptographic node identity, self-certifying IPv6 addressing, RootSet verification, and gossip.
//!
//! Optional features:
//! - `device`: TUN/TAP device drivers for userspace packet injection/capture.
//! - `io`: Linux `epoll` and `io_uring` event dispatchers with zero-copy buffer slabs.
//! - `rendezvous`: Symmetric NAT traversal and authenticated relay rendezvous protocols.
//! - `obf`: Traffic padding transforms, steganographic masks, and anti-DPI framing.
//! - `utls`: REALITY active-probe camouflage and TLS 1.3 browser fingerprint mimicry.
//! - `ca`: RFC 9591 FROST threshold certificate authority coordinator and signer engines.
//! - `full`: Activates all available features above.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
pub use yip_crypto as crypto;

#[cfg(feature = "wire")]
#[cfg_attr(docsrs, doc(cfg(feature = "wire")))]
pub use yip_wire as wire;

#[cfg(feature = "transport")]
#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
pub use yip_transport as transport;

#[cfg(feature = "membership")]
#[cfg_attr(docsrs, doc(cfg(feature = "membership")))]
pub use yip_membership as membership;

#[cfg(feature = "device")]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub use yip_device as device;

#[cfg(feature = "io")]
#[cfg_attr(docsrs, doc(cfg(feature = "io")))]
pub use yip_io as io;

#[cfg(feature = "rendezvous")]
#[cfg_attr(docsrs, doc(cfg(feature = "rendezvous")))]
pub use yip_rendezvous as rendezvous;

#[cfg(feature = "obf")]
#[cfg_attr(docsrs, doc(cfg(feature = "obf")))]
pub use yip_obf as obf;

#[cfg(feature = "utls")]
#[cfg_attr(docsrs, doc(cfg(feature = "utls")))]
pub use yip_utls as utls;

#[cfg(feature = "ca")]
#[cfg_attr(docsrs, doc(cfg(feature = "ca")))]
pub use yip_ca as ca;
