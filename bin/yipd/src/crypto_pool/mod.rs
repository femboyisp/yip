//! Parallel worker crypto pools for multi-core ChaCha20-Poly1305 acceleration.
//!
//! Provides lock-free SPSC task dispatch to crypto worker threads and in-order
//! sequence reassembly to scale single-peer throughput past 5+ Gbps without
//! packet reordering.

#![forbid(unsafe_code)]

pub mod outbound;
pub mod reorder;
