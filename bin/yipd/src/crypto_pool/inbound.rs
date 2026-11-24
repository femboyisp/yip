//! Parallel inbound cryptographic execution engine.
//!
//! Distributes ChaCha20-Poly1305 AEAD decryption across dedicated worker threads
//! using lock-free bounded SPSC rings, reassembling decrypted datagrams in-order
//! through a ReorderBuffer before replay verification and TUN write.

use super::reorder::ReorderBuffer;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{Builder, JoinHandle};
use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_crypto::CryptoError;
use yip_io::spsc::{spsc_pair, SpscConsumer, SpscProducer};

const QUEUE_CAP: usize = 8192;

#[derive(Debug)]
pub struct DecryptTask {
    pub peer_id: usize,
    pub counter: u64,
    pub cipher: Arc<ChaCha20Poly1305Cipher>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct DecryptedPacket {
    pub peer_id: usize,
    pub counter: u64,
    pub result: Result<Vec<u8>, CryptoError>,
}

enum WorkerMsg {
    Task(DecryptTask),
    Shutdown,
}

pub struct InboundCryptoPool {
    worker_tx: Vec<SpscProducer<WorkerMsg, QUEUE_CAP>>,
    worker_rx: Vec<SpscConsumer<DecryptedPacket, QUEUE_CAP>>,
    rob: ReorderBuffer<DecryptedPacket, QUEUE_CAP>,
    threads: Vec<JoinHandle<()>>,
    rr_idx: usize,
    shutdown_flag: Arc<AtomicBool>,
    rx_batch_scratch: Vec<DecryptedPacket>,
}

impl InboundCryptoPool {
    /// Construct a new `InboundCryptoPool` with `num_workers` dedicated threads.
    pub fn new(num_workers: usize, initial_seq: u64) -> Self {
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
                    let mut batch = Vec::with_capacity(128);
                    while !flag.load(Ordering::Relaxed) {
                        batch.clear();
                        let count = rx_task.drain_batch(&mut batch, 64);
                        if count == 0 {
                            std::hint::spin_loop();
                            continue;
                        }

                        for msg in batch.drain(..) {
                            match msg {
                                WorkerMsg::Task(mut task) => {
                                    let ct_len = task.ciphertext.len();
                                    let result = match task.cipher.open_in_place(
                                        task.counter,
                                        &mut task.ciphertext,
                                        ct_len,
                                    ) {
                                        Ok(pt_len) => {
                                            task.ciphertext.truncate(pt_len);
                                            Ok(task.ciphertext)
                                        }
                                        Err(e) => Err(e),
                                    };

                                    let mut completed = DecryptedPacket {
                                        peer_id: task.peer_id,
                                        counter: task.counter,
                                        result,
                                    };

                                    loop {
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
            rob: ReorderBuffer::new(initial_seq),
            threads,
            rr_idx: 0,
            shutdown_flag,
            rx_batch_scratch: Vec::with_capacity(128),
        }
    }

    /// Dispatch a decryption task to one of the worker threads (round-robin).
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

    /// Drain completed decrypted packets in strict monotonic sequence.
    pub fn drain_completed<F: FnMut(DecryptedPacket)>(&mut self, mut f: F) -> usize {
        for rx in &self.worker_rx {
            self.rx_batch_scratch.clear();
            let count = rx.drain_batch(&mut self.rx_batch_scratch, 64);
            if count > 0 {
                for item in self.rx_batch_scratch.drain(..) {
                    let _ = self.rob.insert(item.counter, item);
                }
            }
        }

        let mut drained = 0;
        let _ = self.rob.drain_contiguous(|_seq, item| {
            f(item);
            drained += 1;
        });
        drained
    }

    /// Gracefully shutdown all worker threads.
    pub fn shutdown(mut self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        for tx in &self.worker_tx {
            let _ = tx.push(WorkerMsg::Shutdown);
        }
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}
