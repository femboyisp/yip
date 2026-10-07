use crossbeam_utils::CachePadded;
use std::sync::atomic::{AtomicU64, Ordering};

pub const DEFAULT_NONCE_CHUNK_SIZE: u64 = 64;

/// Dispenses nonces in contiguous chunks to worker threads to prevent
/// atomic MESI cache-line contention across multi-core systems.
pub struct ChunkedNonceDispenser {
    next_nonce: CachePadded<AtomicU64>,
    chunk_size: u64,
}

impl ChunkedNonceDispenser {
    pub fn new(chunk_size: u64) -> Self {
        Self {
            next_nonce: CachePadded::new(AtomicU64::new(0)),
            chunk_size: chunk_size.max(1),
        }
    }

    pub fn claim_chunk(&self) -> LocalNonceWindow {
        let base = self
            .next_nonce
            .fetch_add(self.chunk_size, Ordering::Relaxed);
        LocalNonceWindow {
            current: base,
            limit: base.saturating_add(self.chunk_size),
        }
    }
}

/// Thread-local nonce allocation window.
#[derive(Debug, Clone, Copy)]
pub struct LocalNonceWindow {
    current: u64,
    limit: u64,
}

impl LocalNonceWindow {
    pub fn empty() -> Self {
        Self {
            current: 0,
            limit: 0,
        }
    }

    /// Dispenses the next 64-bit nonce. Increments local counter with zero atomic instructions.
    /// Replenishes from `dispenser` when the local chunk is exhausted.
    #[inline]
    pub fn next_nonce(&mut self, dispenser: &ChunkedNonceDispenser) -> Option<u64> {
        if self.current < self.limit {
            let n = self.current;
            self.current += 1;
            Some(n)
        } else {
            *self = dispenser.claim_chunk();
            if self.current < self.limit {
                let n = self.current;
                self.current += 1;
                Some(n)
            } else {
                None
            }
        }
    }
}
