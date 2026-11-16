//! Parallel worker pool for outbound ChaCha20-Poly1305 encryption.
//!
//! Stripes inner TUN packets across a pool of worker threads via lock-free SPSC
//! bounded ring buffers, performs AEAD sealing in parallel with zero heap allocations,
//! and collects completed encrypted buffers into an in-order reorder buffer before socket transmission.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_io::spsc::{spsc_pair, SpscConsumer, SpscProducer};
use yip_transport::FlowClass;

use super::reorder::ReorderBuffer;

const STATE_RUNNING: u8 = 0;
const STATE_SLEEPING: u8 = 1;

pub const WORKER_QUEUE_CAP: usize = 1024;
pub const ROB_CAPACITY: usize = 4096;
pub const MAX_PACKET_LEN: usize = 2048;

/// Packet encryption task dispatched to worker threads with inline zero-allocation buffer.
#[derive(Clone, Copy, Debug)]
pub struct EncryptTask {
    /// Local sequencing index for in-order completion reassembly.
    pub seq: u64,
    /// Identifier for peer cipher lookup.
    pub peer_id: usize,
    /// Monotonic Noise/AEAD session counter.
    pub counter: u64,
    /// Datagram fate / scheduling tag.
    pub fate: u16,
    /// Flow classification priority.
    pub class: FlowClass,
    /// Raw inner plaintext payload byte count.
    pub payload_len: usize,
    /// Raw inner plaintext payload inline buffer.
    pub payload: [u8; MAX_PACKET_LEN],
}

/// Completed encrypted ciphertext buffer ready for transport framing and socket transmission.
#[derive(Clone, Copy, Debug)]
pub struct CompletedEncrypt {
    /// Local sequence index matching [`EncryptTask::seq`].
    pub seq: u64,
    /// Identifier for peer cipher lookup.
    pub peer_id: usize,
    /// Monotonic Noise/AEAD session counter.
    pub counter: u64,
    /// Datagram fate / scheduling tag.
    pub fate: u16,
    /// Flow classification priority.
    pub class: FlowClass,
    /// Encrypted ciphertext byte count.
    pub ciphertext_len: usize,
    /// Encrypted ciphertext inline buffer.
    pub ciphertext: [u8; MAX_PACKET_LEN],
    /// Whether encryption succeeded.
    pub success: bool,
}

/// Backwards compatibility alias for completed tasks.
pub type CompletedDatagram = CompletedEncrypt;

#[expect(
    clippy::large_enum_variant,
    reason = "zero-allocation worker ring buffers require inline packet arrays"
)]
enum WorkerCommand {
    RegisterCipher {
        peer_id: usize,
        cipher: Arc<ChaCha20Poly1305Cipher>,
        codec: Option<Arc<yip_wire::Codec>>,
    },
    Task(EncryptTask),
    Shutdown,
}

/// Multi-threaded outbound crypto worker pool.
pub struct OutboundCryptoPool {
    worker_txs: Vec<SpscProducer<WorkerCommand, WORKER_QUEUE_CAP>>,
    worker_rxs: Vec<SpscConsumer<CompletedEncrypt, WORKER_QUEUE_CAP>>,
    worker_handles: Vec<JoinHandle<()>>,
    worker_states: Vec<Arc<AtomicU8>>,
    reorder_buffer: ReorderBuffer<CompletedEncrypt, ROB_CAPACITY>,
    next_worker_idx: usize,
    shutdown_flag: Arc<AtomicBool>,
}

impl OutboundCryptoPool {
    /// Create a new worker pool with `num_workers` dedicated encryption threads.
    ///
    /// # Panics
    /// Panics if `num_workers == 0`.
    pub fn new(
        num_workers: usize,
        eventfd: Arc<yip_io::EventFd>,
        reactor_sleeping: Arc<AtomicBool>,
    ) -> Self {
        assert!(num_workers > 0, "num_workers must be at least 1");

        let mut worker_txs = Vec::with_capacity(num_workers);
        let mut worker_rxs = Vec::with_capacity(num_workers);
        let mut worker_handles = Vec::with_capacity(num_workers);
        let mut worker_states = Vec::with_capacity(num_workers);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers {
            let (cmd_tx, cmd_rx) = spsc_pair::<WorkerCommand, WORKER_QUEUE_CAP>();
            let (out_tx, out_rx) = spsc_pair::<CompletedEncrypt, WORKER_QUEUE_CAP>();
            let flag = Arc::clone(&shutdown_flag);
            let state = Arc::new(AtomicU8::new(STATE_RUNNING));
            let state_worker = Arc::clone(&state);
            let efd = Arc::clone(&eventfd);
            let sleeping = Arc::clone(&reactor_sleeping);

            let handle = std::thread::Builder::new()
                .name(format!("yipd-enc-{worker_id}"))
                .spawn(move || {
                    worker_loop(cmd_rx, out_tx, flag, state_worker, efd, sleeping);
                })
                .expect("failed to spawn outbound crypto worker thread");

            worker_txs.push(cmd_tx);
            worker_rxs.push(out_rx);
            worker_handles.push(handle);
            worker_states.push(state);
        }

        Self {
            worker_txs,
            worker_rxs,
            worker_handles,
            worker_states,
            reorder_buffer: ReorderBuffer::new(0),
            next_worker_idx: 0,
            shutdown_flag,
        }
    }

    /// Register or update the symmetric cipher for a peer across all worker threads.
    pub fn register_cipher(&mut self, peer_id: usize, cipher: Arc<ChaCha20Poly1305Cipher>) {
        self.register_cipher_and_codec(peer_id, cipher, None);
    }

    /// Register or update symmetric cipher and optional wire codec for full datagram framing.
    pub fn register_cipher_and_codec(
        &mut self,
        peer_id: usize,
        cipher: Arc<ChaCha20Poly1305Cipher>,
        codec: Option<Arc<yip_wire::Codec>>,
    ) {
        for (i, tx) in self.worker_txs.iter().enumerate() {
            let mut cmd = WorkerCommand::RegisterCipher {
                peer_id,
                cipher: Arc::clone(&cipher),
                codec: codec.as_ref().map(Arc::clone),
            };
            while let Err(returned) = tx.push(cmd) {
                cmd = returned;
                std::hint::spin_loop();
            }
            self.worker_handles[i].thread().unpark();
        }
    }

    /// Dispatch an encryption task to the next worker thread in round-robin sequence.
    ///
    /// Returns `Ok(())` on success, or `Err(task)` if the target worker queue is full.
    #[expect(
        clippy::result_large_err,
        reason = "zero-allocation task retry without heap indirection"
    )]
    pub fn dispatch_encrypt(&mut self, task: EncryptTask) -> Result<(), EncryptTask> {
        let worker_idx = self.next_worker_idx % self.worker_txs.len();
        self.next_worker_idx = self.next_worker_idx.wrapping_add(1);

        match self.worker_txs[worker_idx].push(WorkerCommand::Task(task)) {
            Ok(()) => {
                if self.worker_states[worker_idx].swap(STATE_RUNNING, Ordering::SeqCst)
                    == STATE_SLEEPING
                {
                    self.worker_handles[worker_idx].thread().unpark();
                }
                Ok(())
            }
            Err(WorkerCommand::Task(rejected)) => Err(rejected),
            Err(_) => unreachable!("dispatched WorkerCommand::Task"),
        }
    }

    /// Next expected sequence number that will be emitted by [`drain_completed`].
    #[inline]
    pub fn next_expected_seq(&self) -> u64 {
        self.reorder_buffer.next_expected_seq()
    }

    /// Dispatch an encryption task with bounded backpressure.
    ///
    /// If the target worker queue is full, drains completed datagrams into `drain_fn`
    /// until the queue accepts the task, guaranteeing no tasks are ever dropped.
    pub fn dispatch_encrypt_backpressure<F: FnMut(CompletedEncrypt)>(
        &mut self,
        mut task: EncryptTask,
        mut drain_fn: F,
    ) {
        loop {
            match self.dispatch_encrypt(task) {
                Ok(()) => break,
                Err(returned) => {
                    task = returned;
                    self.drain_completed(&mut drain_fn);
                    std::hint::spin_loop();
                }
            }
        }
    }

    /// Drain all completed datagrams in strict in-order sequence.
    ///
    /// Polls worker completion queues, inserts into the reorder buffer, and calls `f`
    /// for all contiguous sequences. Returns the number of items yielded.
    pub fn drain_completed<F: FnMut(CompletedEncrypt)>(&mut self, mut f: F) -> usize {
        let mut count = 0;
        // 1. Drain worker completion queues into reorder buffer
        for rx in &self.worker_rxs {
            while let Some(item) = rx.pop() {
                let seq = item.seq;
                let mut current = item;
                loop {
                    match self.reorder_buffer.insert(seq, current) {
                        Ok(()) => break,
                        Err((returned_item, super::reorder::ReorderError::Full(_))) => {
                            current = returned_item;
                            self.reorder_buffer.drain_contiguous(|_seq, ready| {
                                if ready.success && ready.ciphertext_len > 0 {
                                    f(ready);
                                    count += 1;
                                }
                            });
                            std::hint::spin_loop();
                        }
                        Err(_) => break, // Stale or duplicate
                    }
                }
            }
        }

        // 2. Yield contiguous in-order elements
        self.reorder_buffer.drain_contiguous(|_seq, item| {
            if item.success && item.ciphertext_len > 0 {
                f(item);
                count += 1;
            }
        });
        count
    }

    /// Shut down the crypto worker pool and join all worker threads.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        if self.worker_handles.is_empty() {
            return;
        }
        self.shutdown_flag.store(true, Ordering::Release);
        for (i, tx) in self.worker_txs.iter().enumerate() {
            let _ = tx.push(WorkerCommand::Shutdown);
            if let Some(h) = self.worker_handles.get(i) {
                h.thread().unpark();
            }
        }
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for OutboundCryptoPool {
    fn drop(&mut self) {
        self.stop();
    }
}

fn worker_loop(
    rx: SpscConsumer<WorkerCommand, WORKER_QUEUE_CAP>,
    tx: SpscProducer<CompletedEncrypt, WORKER_QUEUE_CAP>,
    shutdown: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
    eventfd: Arc<yip_io::EventFd>,
    reactor_sleeping: Arc<AtomicBool>,
) {
    let mut ciphers: HashMap<usize, (Arc<ChaCha20Poly1305Cipher>, Option<Arc<yip_wire::Codec>>)> =
        HashMap::new();
    let mut idle_spins = 0;

    while !shutdown.load(Ordering::Relaxed) {
        match rx.pop() {
            Some(WorkerCommand::Task(task)) => {
                idle_spins = 0;
                let mut ciphertext = [0u8; MAX_PACKET_LEN];
                let mut ciphertext_len = 0;
                let mut success = false;

                if let Some((cipher, _)) = ciphers.get(&task.peer_id) {
                    if task.payload_len <= MAX_PACKET_LEN.saturating_sub(16) {
                        ciphertext[..task.payload_len]
                            .copy_from_slice(&task.payload[..task.payload_len]);
                        match cipher.seal_in_place(task.counter, &mut ciphertext, task.payload_len)
                        {
                            Ok(sealed_len) => {
                                ciphertext_len = sealed_len;
                                success = true;
                            }
                            Err(_) => {
                                success = false;
                            }
                        }
                    }
                }

                let mut item = CompletedEncrypt {
                    seq: task.seq,
                    peer_id: task.peer_id,
                    counter: task.counter,
                    fate: task.fate,
                    class: task.class,
                    ciphertext_len,
                    ciphertext,
                    success,
                };

                while let Err(returned) = tx.push(item) {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    item = returned;
                    std::hint::spin_loop();
                }

                if reactor_sleeping.load(Ordering::Acquire) {
                    let _ = eventfd.notify();
                }
            }
            Some(WorkerCommand::RegisterCipher {
                peer_id,
                cipher,
                codec,
            }) => {
                idle_spins = 0;
                ciphers.insert(peer_id, (cipher, codec));
            }
            Some(WorkerCommand::Shutdown) => break,
            None => {
                if idle_spins < 64 {
                    idle_spins += 1;
                    std::hint::spin_loop();
                } else {
                    idle_spins = 0;
                    state.store(STATE_SLEEPING, Ordering::SeqCst);
                    if !rx.is_empty() {
                        state.store(STATE_RUNNING, Ordering::SeqCst);
                        continue;
                    }
                    std::thread::park_timeout(std::time::Duration::from_millis(1));
                    state.store(STATE_RUNNING, Ordering::SeqCst);
                }
            }
        }
    }
}
