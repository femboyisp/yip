//! Parallel outbound cryptographic execution engine.
//!
//! Distributes ChaCha20-Poly1305 AEAD sealing across dedicated worker threads
//! using lock-free bounded SPSC rings, gathering encrypted datagrams into an in-order
//! ReorderBuffer before socket transmission. Zero heap allocations on the hot path.

use super::reorder::ReorderBuffer;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{Builder, JoinHandle};
use yip_crypto::session::ChaCha20Poly1305Cipher;
use yip_io::spsc::{spsc_pair, SpscConsumer, SpscProducer};
use yip_transport::FlowClass;

pub const QUEUE_CAP: usize = 512;
pub const ROB_CAP: usize = 2048;
pub const MAX_PACKET_LEN: usize = 2048;

#[derive(Debug)]
pub struct EncryptTask {
    pub peer_id: usize,
    pub seq: u64,
    pub counter: u64,
    pub dst: SocketAddr,
    pub fate: u16,
    pub conn_tag: u64,
    pub cipher: Arc<ChaCha20Poly1305Cipher>,
    pub class: FlowClass,
    pub len: usize,
    pub payload: [u8; MAX_PACKET_LEN],
}

#[derive(Clone, Debug)]
pub struct CompletedDatagram {
    pub seq: u64,
    pub fate: u16,
    pub dst: SocketAddr,
    pub counter: u64,
    pub class: FlowClass,
    pub len: usize,
    pub bytes: [u8; MAX_PACKET_LEN],
}

#[expect(
    clippy::large_enum_variant,
    reason = "zero-allocation inline buffer in task variant"
)]
enum WorkerMsg {
    Task(EncryptTask),
    Shutdown,
}

pub struct OutboundCryptoPool {
    worker_tx: Vec<SpscProducer<WorkerMsg, QUEUE_CAP>>,
    worker_rx: Vec<SpscConsumer<CompletedDatagram, QUEUE_CAP>>,
    rob: ReorderBuffer<CompletedDatagram, ROB_CAP>,
    threads: Vec<JoinHandle<()>>,
    rr_idx: usize,
    next_seq: u64,
    shutdown_flag: Arc<AtomicBool>,
    rx_batch_scratch: Vec<CompletedDatagram>,
}

impl OutboundCryptoPool {
    /// Construct a new `OutboundCryptoPool` with `num_workers` dedicated threads.
    pub fn new(num_workers: usize, _initial_counter: u64) -> Self {
        let num_workers = num_workers.max(1);
        let mut worker_tx = Vec::with_capacity(num_workers);
        let mut worker_rx = Vec::with_capacity(num_workers);
        let mut threads = Vec::with_capacity(num_workers);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers {
            let (tx_task, rx_task) = spsc_pair::<WorkerMsg, QUEUE_CAP>();
            let (tx_done, rx_done) = spsc_pair::<CompletedDatagram, QUEUE_CAP>();

            worker_tx.push(tx_task);
            worker_rx.push(rx_done);

            let flag = Arc::clone(&shutdown_flag);
            let handle = Builder::new()
                .name(format!("yipd-crypto-tx-{worker_id}"))
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
                                    let pt_len = task.len;
                                    if pt_len.saturating_add(16) <= MAX_PACKET_LEN {
                                        if let Ok(sealed_len) = task.cipher.seal_in_place(
                                            task.counter,
                                            &mut task.payload,
                                            pt_len,
                                        ) {
                                            let mut completed = CompletedDatagram {
                                                seq: task.seq,
                                                fate: task.fate,
                                                dst: task.dst,
                                                counter: task.counter,
                                                class: task.class,
                                                len: sealed_len,
                                                bytes: task.payload,
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
                                    }
                                }
                                WorkerMsg::Shutdown => return,
                            }
                        }
                    }
                })
                .expect("failed to spawn outbound crypto worker");

            threads.push(handle);
        }

        Self {
            worker_tx,
            worker_rx,
            rob: ReorderBuffer::new(0),
            threads,
            rr_idx: 0,
            next_seq: 0,
            shutdown_flag,
            rx_batch_scratch: Vec::with_capacity(64),
        }
    }

    /// Dispatch an encryption task to one of the worker threads (round-robin).
    #[expect(
        clippy::result_large_err,
        reason = "returns rejected task upon queue saturation for inline fallback"
    )]
    pub fn dispatch_encrypt(&mut self, mut task: EncryptTask) -> Result<(), EncryptTask> {
        if self.next_seq >= self.rob.next_expected_seq().saturating_add(ROB_CAP as u64) {
            return Err(task);
        }

        let num_workers = self.worker_tx.len();
        let target_worker = self.rr_idx % num_workers;
        self.rr_idx = self.rr_idx.wrapping_add(1);

        task.seq = self.next_seq;
        match self.worker_tx[target_worker].push(WorkerMsg::Task(task)) {
            Ok(()) => {
                self.next_seq = self.next_seq.wrapping_add(1);
                Ok(())
            }
            Err(WorkerMsg::Task(task)) => Err(task),
            Err(WorkerMsg::Shutdown) => unreachable!(),
        }
    }

    /// Drain completed datagrams in strict monotonic sequence.
    pub fn drain_completed<F: FnMut(CompletedDatagram)>(&mut self, mut f: F) -> usize {
        for rx in &self.worker_rx {
            self.rx_batch_scratch.clear();
            let count = rx.drain_batch(&mut self.rx_batch_scratch, 32);
            if count > 0 {
                for item in self.rx_batch_scratch.drain(..) {
                    let _ = self.rob.insert(item.seq, item);
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
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for OutboundCryptoPool {
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
