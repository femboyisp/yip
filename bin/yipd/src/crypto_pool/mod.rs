//! Parallel worker crypto pools for multi-core ChaCha20-Poly1305 acceleration.
//!
//! Provides lock-free SPSC task dispatch to crypto worker threads and in-order
//! sequence reassembly to scale single-peer throughput past 5+ Gbps without
//! packet reordering.

#![forbid(unsafe_code)]

use std::sync::atomic::AtomicBool;
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
    eventfd: Arc<yip_io::EventFd>,
    reactor_sleeping: Arc<AtomicBool>,
}

impl CryptoWorkerPool {
    /// Create a new worker pool with `num_workers` dedicated encryption and decryption threads.
    ///
    /// # Panics
    /// Panics if `num_workers == 0`.
    pub fn new(num_workers: usize) -> Self {
        let eventfd = Arc::new(yip_io::EventFd::new().expect("eventfd creation succeeds"));
        let reactor_sleeping = Arc::new(AtomicBool::new(false));

        Self {
            outbound: OutboundCryptoPool::new(
                num_workers,
                Arc::clone(&eventfd),
                Arc::clone(&reactor_sleeping),
            ),
            inbound: InboundCryptoPool::new(
                num_workers,
                Arc::clone(&eventfd),
                Arc::clone(&reactor_sleeping),
            ),
            num_workers,
            eventfd,
            reactor_sleeping,
        }
    }

    /// Eventfd file descriptor for waking up the epoll event loop when workers complete tasks.
    #[inline]
    pub fn eventfd(&self) -> &Arc<yip_io::EventFd> {
        &self.eventfd
    }

    /// Shared atomic flag signaling whether the reactor thread is currently sleeping in epoll_wait.
    #[inline]
    pub fn reactor_sleeping(&self) -> &Arc<AtomicBool> {
        &self.reactor_sleeping
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
