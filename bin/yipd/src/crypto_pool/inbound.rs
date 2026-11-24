//! Parallel inbound cryptographic execution engine.
//!
//! Distributes ChaCha20-Poly1305 AEAD decryption across dedicated worker threads
//! using lock-free bounded SPSC rings. Decrypted datagrams are collected and delivered
//! to the caller without blocking on dropped UDP sequences. Zero heap allocations on hot path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{Builder, JoinHandle};
use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_io::spsc::{spsc_pair, SpscConsumer, SpscProducer};

pub const QUEUE_CAP: usize = 512;
pub const MAX_PACKET_LEN: usize = 2048;

#[derive(Debug)]
pub struct DecryptTask {
    pub peer_id: usize,
    pub counter: u64,
    pub cipher: Arc<ChaCha20Poly1305Cipher>,
    pub len: usize,
    pub ciphertext: [u8; MAX_PACKET_LEN],
}

#[derive(Clone, Debug)]
pub struct DecryptedPacket {
    pub peer_id: usize,
    pub counter: u64,
    pub len: usize,
    pub plain: [u8; MAX_PACKET_LEN],
    pub success: bool,
}

#[expect(
    clippy::large_enum_variant,
    reason = "zero-allocation inline buffer in task variant"
)]
enum WorkerMsg {
    Task(DecryptTask),
    Shutdown,
}

pub struct InboundCryptoPool {
    worker_tx: Vec<SpscProducer<WorkerMsg, QUEUE_CAP>>,
    worker_rx: Vec<SpscConsumer<DecryptedPacket, QUEUE_CAP>>,
    threads: Vec<JoinHandle<()>>,
    rr_idx: usize,
    shutdown_flag: Arc<AtomicBool>,
    rx_batch_scratch: Vec<DecryptedPacket>,
}

impl InboundCryptoPool {
    /// Construct a new `InboundCryptoPool` with `num_workers` dedicated threads.
    pub fn new(num_workers: usize, _initial_counter: u64) -> Self {
        let num_workers = num_workers.max(1);
        let mut worker_tx = Vec::with_capacity(num_workers);
        let mut worker_rx = Vec::with_capacity(num_workers);
        let mut threads = Vec::with_capacity(num_workers);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers {
            let (tx_task, rx_task) = spsc_pair::<WorkerMsg, QUEUE_CAP>();
            let (tx_done, rx_done) = spsc_pair::<DecryptedPacket, QUEUE_CAP>();

            worker_tx.push(tx_task);
            worker_rx.push(rx_done);

            let flag = Arc::clone(&shutdown_flag);
            let handle = Builder::new()
                .name(format!("yipd-crypto-rx-{worker_id}"))
                .spawn(move || {
                    let mut batch = Vec::with_capacity(64);
                    while !flag.load(Ordering::Relaxed) {
                        batch.clear();
                        let count = rx_task.drain_batch(&mut batch, 32);
                        if count == 0 {
                            std::hint::spin_loop();
                            continue;
                        }

                        for msg in batch.drain(..) {
                            match msg {
                                WorkerMsg::Task(mut task) => {
                                    let ct_len = task.len;
                                    let (success, pt_len) = match task.cipher.open_in_place(
                                        task.counter,
                                        &mut task.ciphertext,
                                        ct_len,
                                    ) {
                                        Ok(pt_len) => (true, pt_len),
                                        Err(_) => (false, 0),
                                    };

                                    let mut completed = DecryptedPacket {
                                        peer_id: task.peer_id,
                                        counter: task.counter,
                                        len: pt_len,
                                        plain: task.ciphertext,
                                        success,
                                    };

                                    loop {
                                        if flag.load(Ordering::Relaxed) {
                                            return;
                                        }
                                        match tx_done.push(completed) {
                                            Ok(()) => break,
                                            Err(rej) => {
                                                completed = rej;
                                                std::hint::spin_loop();
                                            }
                                        }
                                    }
                                }
                                WorkerMsg::Shutdown => return,
                            }
                        }
                    }
                })
                .expect("failed to spawn inbound crypto worker");

            threads.push(handle);
        }

        Self {
            worker_tx,
            worker_rx,
            threads,
            rr_idx: 0,
            shutdown_flag,
            rx_batch_scratch: Vec::with_capacity(64),
        }
    }

    /// Dispatch a decryption task to one of the worker threads (round-robin).
    #[expect(
        clippy::result_large_err,
        reason = "returns rejected task upon queue saturation for inline fallback"
    )]
    pub fn dispatch_decrypt(&mut self, task: DecryptTask) -> Result<(), DecryptTask> {
        let num_workers = self.worker_tx.len();
        let target_worker = self.rr_idx % num_workers;
        self.rr_idx = self.rr_idx.wrapping_add(1);

        match self.worker_tx[target_worker].push(WorkerMsg::Task(task)) {
            Ok(()) => Ok(()),
            Err(WorkerMsg::Task(task)) => Err(task),
            Err(WorkerMsg::Shutdown) => unreachable!(),
        }
    }

    /// Drain completed decrypted packets without blocking on dropped sequence gaps.
    pub fn drain_completed<F: FnMut(DecryptedPacket)>(&mut self, mut f: F) -> usize {
        let mut drained = 0;
        for rx in &self.worker_rx {
            self.rx_batch_scratch.clear();
            let count = rx.drain_batch(&mut self.rx_batch_scratch, 32);
            if count > 0 {
                for item in self.rx_batch_scratch.drain(..) {
                    f(item);
                    drained += 1;
                }
            }
        }
        drained
    }

    /// Gracefully shutdown all worker threads.
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for InboundCryptoPool {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        for tx in &self.worker_tx {
            let _ = tx.push(WorkerMsg::Shutdown);
        }
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}
