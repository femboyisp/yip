//! Parallel worker pool for outbound ChaCha20-Poly1305 encryption.
//!
//! Stripes inner TUN packets across a pool of worker threads via lock-free SPSC
//! bounded ring buffers, performs AEAD sealing in parallel, and collects completed
//! datagrams into an in-order reorder buffer before socket transmission.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_io::spsc::{spsc_pair, SpscConsumer, SpscProducer};
use yip_transport::FlowClass;

use super::reorder::ReorderBuffer;

const WORKER_QUEUE_CAP: usize = 512;
const ROB_CAPACITY: usize = 1024;

/// Packet encryption task dispatched to worker threads.
#[derive(Debug)]
pub struct EncryptTask {
    /// Local sequencing index for in-order completion reassembly.
    pub seq: u64,
    /// Identifier for peer cipher lookup.
    pub peer_id: usize,
    /// Monotonic Noise/AEAD session counter.
    pub counter: u64,
    /// Datagram fate / scheduling tag.
    pub fate: u16,
    /// Destination UDP socket address.
    pub dst: SocketAddr,
    /// Connection identifier tag for wire framing.
    pub conn_tag: u64,
    /// Flow classification priority.
    pub class: FlowClass,
    /// Raw inner plaintext payload.
    pub payload: Vec<u8>,
}

/// Completed datagram ready for socket transmission.
#[derive(Debug)]
pub struct CompletedDatagram {
    /// Local sequence index matching [`EncryptTask::seq`].
    pub seq: u64,
    /// Datagram fate / scheduling tag.
    pub fate: u16,
    /// Destination UDP socket address.
    pub dst: SocketAddr,
    /// Encrypted wire datagram bytes.
    pub bytes: Vec<u8>,
}

enum WorkerCommand {
    RegisterCipher {
        peer_id: usize,
        cipher: Arc<ChaCha20Poly1305Cipher>,
    },
    Task(EncryptTask),
    Shutdown,
}

/// Multi-threaded outbound crypto worker pool.
pub struct OutboundCryptoPool {
    worker_txs: Vec<SpscProducer<WorkerCommand, WORKER_QUEUE_CAP>>,
    worker_rxs: Vec<SpscConsumer<CompletedDatagram, WORKER_QUEUE_CAP>>,
    worker_handles: Vec<JoinHandle<()>>,
    reorder_buffer: ReorderBuffer<CompletedDatagram, ROB_CAPACITY>,
    next_worker_idx: usize,
    shutdown_flag: Arc<AtomicBool>,
}

impl OutboundCryptoPool {
    /// Create a new worker pool with `num_workers` dedicated encryption threads.
    ///
    /// # Panics
    /// Panics if `num_workers == 0`.
    pub fn new(num_workers: usize) -> Self {
        assert!(num_workers > 0, "num_workers must be at least 1");

        let mut worker_txs = Vec::with_capacity(num_workers);
        let mut worker_rxs = Vec::with_capacity(num_workers);
        let mut worker_handles = Vec::with_capacity(num_workers);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers {
            let (cmd_tx, cmd_rx) = spsc_pair::<WorkerCommand, WORKER_QUEUE_CAP>();
            let (out_tx, out_rx) = spsc_pair::<CompletedDatagram, WORKER_QUEUE_CAP>();
            let flag = Arc::clone(&shutdown_flag);

            let handle = std::thread::Builder::new()
                .name(format!("yipd-enc-{worker_id}"))
                .spawn(move || {
                    worker_loop(cmd_rx, out_tx, flag);
                })
                .expect("failed to spawn outbound crypto worker thread");

            worker_txs.push(cmd_tx);
            worker_rxs.push(out_rx);
            worker_handles.push(handle);
        }

        Self {
            worker_txs,
            worker_rxs,
            worker_handles,
            reorder_buffer: ReorderBuffer::new(0),
            next_worker_idx: 0,
            shutdown_flag,
        }
    }

    /// Register or update the symmetric cipher for a peer across all worker threads.
    pub fn register_cipher(&mut self, peer_id: usize, cipher: Arc<ChaCha20Poly1305Cipher>) {
        for tx in &self.worker_txs {
            let mut cmd = WorkerCommand::RegisterCipher {
                peer_id,
                cipher: Arc::clone(&cipher),
            };
            while let Err(returned) = tx.push(cmd) {
                cmd = returned;
                std::hint::spin_loop();
            }
        }
    }

    /// Dispatch an encryption task to the next worker thread in round-robin sequence.
    ///
    /// Returns `Ok(())` on success, or `Err(task)` if the target worker queue is full.
    pub fn dispatch_encrypt(&mut self, task: EncryptTask) -> Result<(), EncryptTask> {
        let worker_idx = self.next_worker_idx % self.worker_txs.len();
        self.next_worker_idx = self.next_worker_idx.wrapping_add(1);

        match self.worker_txs[worker_idx].push(WorkerCommand::Task(task)) {
            Ok(()) => Ok(()),
            Err(WorkerCommand::Task(rejected)) => Err(rejected),
            Err(_) => unreachable!("dispatched WorkerCommand::Task"),
        }
    }

    /// Drain all completed datagrams in strict in-order sequence.
    ///
    /// Polls worker completion queues, inserts into the reorder buffer, and calls `f`
    /// for all contiguous sequences. Returns the number of items yielded.
    pub fn drain_completed<F: FnMut(CompletedDatagram)>(&mut self, mut f: F) -> usize {
        // 1. Drain worker completion queues into reorder buffer
        for rx in &self.worker_rxs {
            while let Some(item) = rx.pop() {
                let seq = item.seq;
                let _ = self.reorder_buffer.insert(seq, item);
            }
        }

        // 2. Yield contiguous in-order elements
        self.reorder_buffer.drain_contiguous(|_seq, item| {
            f(item);
        })
    }

    /// Shut down the crypto worker pool and join all worker threads.
    pub fn shutdown(mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        for tx in &self.worker_txs {
            let _ = tx.push(WorkerCommand::Shutdown);
        }
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for OutboundCryptoPool {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        for tx in &self.worker_txs {
            let _ = tx.push(WorkerCommand::Shutdown);
        }
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }
    }
}

fn worker_loop(
    rx: SpscConsumer<WorkerCommand, WORKER_QUEUE_CAP>,
    tx: SpscProducer<CompletedDatagram, WORKER_QUEUE_CAP>,
    shutdown: Arc<AtomicBool>,
) {
    let mut ciphers: HashMap<usize, Arc<ChaCha20Poly1305Cipher>> = HashMap::new();
    let mut scratch = Vec::with_capacity(2048);

    while !shutdown.load(Ordering::Relaxed) {
        match rx.pop() {
            Some(WorkerCommand::Task(task)) => {
                let Some(cipher) = ciphers.get(&task.peer_id) else {
                    continue;
                };

                let plain_len = task.payload.len();
                let sealed_len = plain_len + 16;
                scratch.clear();
                scratch.resize(sealed_len, 0);
                scratch[..plain_len].copy_from_slice(&task.payload);

                if cipher
                    .seal_in_place(task.counter, &mut scratch, plain_len)
                    .is_ok()
                {
                    let mut item = CompletedDatagram {
                        seq: task.seq,
                        fate: task.fate,
                        dst: task.dst,
                        bytes: scratch.clone(),
                    };

                    while let Err(returned) = tx.push(item) {
                        if shutdown.load(Ordering::Relaxed) {
                            return;
                        }
                        item = returned;
                        std::hint::spin_loop();
                    }
                }
            }
            Some(WorkerCommand::RegisterCipher { peer_id, cipher }) => {
                ciphers.insert(peer_id, cipher);
            }
            Some(WorkerCommand::Shutdown) => break,
            None => {
                std::hint::spin_loop();
            }
        }
    }
}
