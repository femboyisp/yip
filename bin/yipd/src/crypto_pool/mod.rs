//! Parallel worker crypto pools for multi-core ChaCha20-Poly1305 acceleration.
//!
//! Provides lock-free SPSC task dispatch to crypto worker threads and in-order
//! sequence reassembly to scale single-peer throughput past 5+ Gbps without
//! packet reordering.

#![forbid(unsafe_code)]

use std::sync::Arc;
use yip_crypto::session::ChaCha20Poly1305Cipher;

pub mod inbound;
pub mod outbound;
pub mod reorder;

use self::inbound::InboundCryptoPool;
use self::outbound::OutboundCryptoPool;

/// Combined crypto worker pool orchestrating outbound encryption and inbound decryption.
pub struct CryptoWorkerPool {
    /// Outbound encryption worker pool.
    pub outbound: OutboundCryptoPool,
    /// Inbound decryption worker pool.
    pub inbound: InboundCryptoPool,
    num_workers: usize,
}

impl CryptoWorkerPool {
    /// Create a new worker pool with `num_workers` dedicated encryption and decryption threads.
    ///
    /// # Panics
    /// Panics if `num_workers == 0`.
    pub fn new(num_workers: usize) -> Self {
        Self {
            outbound: OutboundCryptoPool::new(num_workers),
            inbound: InboundCryptoPool::new(num_workers),
            num_workers,
        }
    }

    /// Number of worker threads allocated per direction.
    #[inline]
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Register or update the symmetric send and receive ciphers for a peer session.
    pub fn register_cipher(
        &mut self,
        peer_id: usize,
        send_cipher: Arc<ChaCha20Poly1305Cipher>,
        recv_cipher: Arc<ChaCha20Poly1305Cipher>,
    ) {
        self.outbound.register_cipher(peer_id, send_cipher);
        self.inbound.register_cipher(peer_id, recv_cipher);
    }

    /// Register or update symmetric ciphers and wire codec for full datagram framing and deframing.
    pub fn register_session(
        &mut self,
        peer_id: usize,
        send_cipher: Arc<ChaCha20Poly1305Cipher>,
        recv_cipher: Arc<ChaCha20Poly1305Cipher>,
        codec: Arc<yip_wire::Codec>,
    ) {
        self.outbound
            .register_cipher_and_codec(peer_id, send_cipher, Some(Arc::clone(&codec)));
        self.inbound
            .register_cipher_and_codec(peer_id, recv_cipher, Some(codec));
    }

    /// Shut down both worker pools and join all threads.
    pub fn shutdown(self) {
        self.outbound.shutdown();
        self.inbound.shutdown();
    }
}
