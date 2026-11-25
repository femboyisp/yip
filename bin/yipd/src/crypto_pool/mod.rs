//! Parallel cryptographic execution engine and reordering buffer.
//!
//! Provides multi-threaded ChaCha20-Poly1305 AEAD offload across dedicated worker
//! threads for high-throughput pipelines, utilizing lock-free Single-Producer
//! Single-Consumer (SPSC) ring buffers and an in-order [`ReorderBuffer`].
//!
//! # Architecture
//!
//! - [`OutboundCryptoPool`]: Distributes packet sealing across worker threads via
//!   lock-free bounded SPSC ring buffers. Outbound packets are stamped with a monotonic
//!   sequence number (`seq`). Completed encrypted datagrams are reordered in the
//!   [`ReorderBuffer`] to guarantee in-order transmission onto the wire without TCP reordering.
//! - [`InboundCryptoPool`]: Distributes packet decryption and authentication across worker
//!   threads via SPSC rings. Decrypted packets are drained without head-of-line blocking on
//!   dropped network datagrams, ensuring loss on UDP underlays does not stall unrelated traffic.
//! - [`ReorderBuffer`]: Circular bounded reorder buffer ensuring zero heap allocation on the hot path
//!   while restoring strict monotonically increasing sequence ordering.

pub mod inbound;
pub mod outbound;
pub mod reorder;

pub use inbound::InboundCryptoPool;
pub use outbound::OutboundCryptoPool;
pub use reorder::ReorderBuffer;
