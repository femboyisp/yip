//! Parallel worker pool for outbound ChaCha20-Poly1305 encryption.
//!
//! Stripes inner TUN packets across a pool of worker threads via lock-free SPSC
//! bounded ring buffers, performs AEAD sealing in parallel, and collects completed
//! datagrams into an in-order reorder buffer before socket transmission.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
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
    /// Reed-Solomon symbol size for wire fragmentation (e.g. 1200).
    pub symbol_size: u16,
    /// Raw inner plaintext payload.
    pub payload: Vec<u8>,
}

/// Completed datagram batch ready for socket transmission.
#[derive(Debug)]
pub struct CompletedDatagram {
    /// Local sequence index matching [`EncryptTask::seq`].
    pub seq: u64,
    /// Encrypted wire datagrams produced from this inner packet.
    pub datagrams: Vec<yip_io::poll::EgressDatagram>,
}

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
    worker_rxs: Vec<SpscConsumer<CompletedDatagram, WORKER_QUEUE_CAP>>,
    worker_handles: Vec<JoinHandle<()>>,
    worker_states: Vec<Arc<AtomicU8>>,
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
        let mut worker_states = Vec::with_capacity(num_workers);
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        for worker_id in 0..num_workers {
            let (cmd_tx, cmd_rx) = spsc_pair::<WorkerCommand, WORKER_QUEUE_CAP>();
            let (out_tx, out_rx) = spsc_pair::<CompletedDatagram, WORKER_QUEUE_CAP>();
            let flag = Arc::clone(&shutdown_flag);
            let state = Arc::new(AtomicU8::new(STATE_RUNNING));
            let state_worker = Arc::clone(&state);

            let handle = std::thread::Builder::new()
                .name(format!("yipd-enc-{worker_id}"))
                .spawn(move || {
                    worker_loop(cmd_rx, out_tx, flag, state_worker);
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
    pub fn dispatch_encrypt_backpressure<F: FnMut(CompletedDatagram)>(
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
    pub fn drain_completed<F: FnMut(CompletedDatagram)>(&mut self, mut f: F) -> usize {
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
                                if !ready.datagrams.is_empty() {
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
            if !item.datagrams.is_empty() {
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
    tx: SpscProducer<CompletedDatagram, WORKER_QUEUE_CAP>,
    shutdown: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
) {
    let mut ciphers: HashMap<usize, (Arc<ChaCha20Poly1305Cipher>, Option<Arc<yip_wire::Codec>>)> =
        HashMap::new();
    let mut scratch = Vec::with_capacity(2048);
    let mut wire_scratch = Vec::with_capacity(2048);
    let mut arena = yip_transport::FecScratchArena::with_capacity(4, 2048);
    let mut idle_spins = 0;

    while !shutdown.load(Ordering::Relaxed) {
        match rx.pop() {
            Some(WorkerCommand::Task(task)) => {
                idle_spins = 0;
                let mut dgs = Vec::with_capacity(2);

                if let Some((cipher, codec_opt)) = ciphers.get(&task.peer_id) {
                    let plain_len = task.payload.len();
                    let sealed_len = plain_len + 16;
                    scratch.clear();
                    scratch.resize(sealed_len, 0);
                    scratch[..plain_len].copy_from_slice(&task.payload);

                    if cipher
                        .seal_in_place(task.counter, &mut scratch, plain_len)
                        .is_ok()
                    {
                        if let Some(codec) = codec_opt.as_ref() {
                            if task.conn_tag != 0 {
                                let sym_size = if task.symbol_size == 0 {
                                    1200
                                } else {
                                    task.symbol_size
                                };
                                let params = yip_transport::FlowParams {
                                    symbol_size: sym_size,
                                    initial_repair_ratio: 0.0,
                                    deadline: std::time::Duration::from_millis(100),
                                    arq: false,
                                };
                                let syms = yip_transport::FecEncoder::build_with_arena(
                                    &scratch[..sealed_len],
                                    params,
                                    task.fate,
                                    0,
                                    &mut arena,
                                );
                                for sym in syms {
                                    let frame = crate::wire_glue::symbol_to_frame(
                                        task.conn_tag,
                                        sym,
                                        task.counter,
                                        task.class,
                                    );
                                    let frame_ref = yip_wire::FrameRef {
                                        conn_tag: frame.conn_tag,
                                        object_id: frame.object_id,
                                        payload_id: frame.payload_id,
                                        flags: frame.flags,
                                        payload: &frame.payload,
                                    };
                                    wire_scratch.clear();
                                    wire_scratch.push(crate::handshake::PacketType::Data as u8);
                                    codec.frame_ref_into(&frame_ref, &mut wire_scratch);
                                    dgs.push(yip_io::poll::EgressDatagram {
                                        fate: sym.object_id,
                                        dst: task.dst,
                                        bytes: wire_scratch.clone(),
                                    });
                                }
                            } else {
                                dgs.push(yip_io::poll::EgressDatagram {
                                    fate: task.fate,
                                    dst: task.dst,
                                    bytes: scratch[..sealed_len].to_vec(),
                                });
                            }
                        } else {
                            dgs.push(yip_io::poll::EgressDatagram {
                                fate: task.fate,
                                dst: task.dst,
                                bytes: scratch[..sealed_len].to_vec(),
                            });
                        }
                    }
                }

                let mut item = CompletedDatagram {
                    seq: task.seq,
                    datagrams: dgs,
                };

                while let Err(returned) = tx.push(item) {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    item = returned;
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
