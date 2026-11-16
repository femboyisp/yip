//! Parallel worker pool for inbound ChaCha20-Poly1305 decryption.
//!
//! Stripes received UDP datagrams across worker threads via lock-free SPSC bounded
//! ring buffers, performs AEAD opening in parallel, and collects decrypted plaintext
//! packets into an in-order reorder buffer before TUN injection.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_io::spsc::{spsc_pair, SpscConsumer, SpscProducer};

use super::reorder::ReorderBuffer;

const STATE_RUNNING: u8 = 0;
const STATE_SLEEPING: u8 = 1;

pub const WORKER_QUEUE_CAP: usize = 1024;
pub const ROB_CAPACITY: usize = 4096;

/// Packet decryption task dispatched to worker threads.
#[derive(Debug)]
pub struct DecryptTask {
    /// Local sequencing index for in-order completion reassembly.
    pub seq: u64,
    /// Identifier for peer cipher lookup.
    pub peer_id: usize,
    /// Monotonic Noise/AEAD session counter.
    pub counter: u64,
    /// Raw AEAD ciphertext with Poly1305 authentication tag appended.
    pub ciphertext: Vec<u8>,
}

/// Decrypted plaintext packet ready for TUN writing.
#[derive(Debug)]
pub struct DecryptedPacket {
    /// Local sequence index matching [`DecryptTask::seq`].
    pub seq: u64,
    /// Decrypted inner plaintext bytes.
    pub plaintext: Vec<u8>,
}

enum WorkerCommand {
    RegisterCipher {
        peer_id: usize,
        cipher: Arc<ChaCha20Poly1305Cipher>,
        codec: Option<Arc<yip_wire::Codec>>,
    },
    Task(DecryptTask),
    Shutdown,
}

/// Multi-threaded inbound crypto worker pool.
pub struct InboundCryptoPool {
    worker_txs: Vec<SpscProducer<WorkerCommand, WORKER_QUEUE_CAP>>,
    worker_rxs: Vec<SpscConsumer<DecryptedPacket, WORKER_QUEUE_CAP>>,
    worker_handles: Vec<JoinHandle<()>>,
    worker_states: Vec<Arc<AtomicU8>>,
    reorder_buffer: ReorderBuffer<DecryptedPacket, ROB_CAPACITY>,
    next_worker_idx: usize,
    shutdown_flag: Arc<AtomicBool>,
}

impl InboundCryptoPool {
    /// Create a new worker pool with `num_workers` dedicated decryption threads.
    ///
    /// # Panics
    /// Panics if `num_workers == 0`.
    pub fn new(num_workers: usize) -> Self {
        assert!(num_workers > 0, "num_workers must be at least 1");

        let mut worker_txs = Vec::with_capacity(num_workers);
        let mut worker_rxs = Vec::with_capacity(num_workers);
        let mut worker_handles = Vec::with_capacity(num_workers);
        let mut worker_states = Vec::with_capacity(num_workers);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers {
            let (cmd_tx, cmd_rx) = spsc_pair::<WorkerCommand, WORKER_QUEUE_CAP>();
            let (out_tx, out_rx) = spsc_pair::<DecryptedPacket, WORKER_QUEUE_CAP>();
            let flag = Arc::clone(&shutdown_flag);
            let state = Arc::new(AtomicU8::new(STATE_RUNNING));
            let state_worker = Arc::clone(&state);

            let handle = std::thread::Builder::new()
                .name(format!("yipd-dec-{worker_id}"))
                .spawn(move || {
                    worker_loop(cmd_rx, out_tx, flag, state_worker);
                })
                .expect("failed to spawn inbound crypto worker thread");

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

    /// Register or update symmetric cipher and optional wire codec for full datagram deframing.
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

    /// Dispatch a decryption task to the next worker thread in round-robin sequence.
    ///
    /// Returns `Ok(())` on success, or `Err(task)` if the target worker queue is full.
    pub fn dispatch_decrypt(&mut self, task: DecryptTask) -> Result<(), DecryptTask> {
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

    /// Dispatch a decryption task with bounded backpressure.
    ///
    /// If the target worker queue is full, drains completed plaintext packets into `drain_fn`
    /// until the queue accepts the task, guaranteeing no tasks are ever dropped.
    pub fn dispatch_decrypt_backpressure<F: FnMut(DecryptedPacket)>(
        &mut self,
        mut task: DecryptTask,
        mut drain_fn: F,
    ) {
        loop {
            match self.dispatch_decrypt(task) {
                Ok(()) => break,
                Err(returned) => {
                    task = returned;
                    self.drain_completed(&mut drain_fn);
                    std::hint::spin_loop();
                }
            }
        }
    }

    /// Drain all decrypted packets in strict in-order sequence.
    ///
    /// Polls worker completion queues, inserts into the reorder buffer, and calls `f`
    /// for all contiguous sequences. Returns the number of items yielded.
    pub fn drain_completed<F: FnMut(DecryptedPacket)>(&mut self, mut f: F) -> usize {
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
                                if !ready.plaintext.is_empty() {
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
            if !item.plaintext.is_empty() {
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

impl Drop for InboundCryptoPool {
    fn drop(&mut self) {
        self.stop();
    }
}

fn worker_loop(
    rx: SpscConsumer<WorkerCommand, WORKER_QUEUE_CAP>,
    tx: SpscProducer<DecryptedPacket, WORKER_QUEUE_CAP>,
    shutdown: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
) {
    let mut ciphers: HashMap<usize, (Arc<ChaCha20Poly1305Cipher>, Option<Arc<yip_wire::Codec>>)> =
        HashMap::new();
    let mut buf = Vec::with_capacity(2048);
    let mut idle_spins = 0;

    while !shutdown.load(Ordering::Relaxed) {
        match rx.pop() {
            Some(WorkerCommand::Task(task)) => {
                idle_spins = 0;
                let plain_opt = if let Some((cipher, _)) = ciphers.get(&task.peer_id) {
                    let sealed_len = task.ciphertext.len();
                    if sealed_len < 16 {
                        None
                    } else {
                        buf.clear();
                        buf.extend_from_slice(&task.ciphertext);
                        if let Ok(plain_len) =
                            cipher.open_in_place(task.counter, &mut buf, sealed_len)
                        {
                            Some(buf[..plain_len].to_vec())
                        } else {
                            None
                        }
                    }
                } else {
                    None
                };

                let item = DecryptedPacket {
                    seq: task.seq,
                    plaintext: plain_opt.unwrap_or_default(),
                };

                let mut to_send = item;
                while let Err(returned) = tx.push(to_send) {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    to_send = returned;
                    std::hint::spin_loop();
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
