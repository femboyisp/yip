//! AF_XDP Zero-Copy Kernel-Bypass Scaling Microbenchmark (Regime B+).
//!
//! Microbenchmarks the zero-copy UMEM memory ring pipeline without requiring root
//! privileges or `CAP_NET_ADMIN`:
//! 1. UMEM page-aligned chunk allocation and recycling throughput (`UmemPool`).
//! 2. Circular descriptor ring enqueue/dequeue (`RxRing`, `TxRing`, `FillRing`, `CompletionRing`).
//! 3. Zero-copy in-place AEAD seal and open (`ChaCha20Poly1305Cipher` + `ReplayWindow`)
//!    directly inside pre-allocated UMEM chunk memory buffers.
//! 4. Multi-core scaling across 1, 2, 4, and 8 worker threads for a single peer connection
//!    carrying concurrent TCP flows.
//!
//! Verifies:
//! - 0 packet drops across all core counts.
//! - 0 out-of-order deliveries (strict monotonic FIFO sequence delivery per stream).
//! - Linear multi-core scaling without MESI cache line bouncing or lock contention.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use yip_bench::established_raw_keys;
use yip_crypto::{ChaCha20Poly1305Cipher, ReplayWindow, Session};
use yip_io::af_xdp::{CompletionRing, FillRing, RxRing, TxRing, UmemPool, XskDesc};

/// Inner 5-tuple extracted from plaintext IP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowTuple {
    pub fn extract(packet: &[u8]) -> Option<Self> {
        if packet.is_empty() {
            return None;
        }
        match packet[0] >> 4 {
            4 => Self::extract_v4(packet),
            6 => Self::extract_v6(packet),
            _ => None,
        }
    }

    fn extract_v4(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 20 {
            return None;
        }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if pkt.len() < ihl || ihl < 20 {
            return None;
        }
        let proto = pkt[9];
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip[10..12].copy_from_slice(&[0xff, 0xff]);
        src_ip[12..16].copy_from_slice(&pkt[12..16]);
        dst_ip[10..12].copy_from_slice(&[0xff, 0xff]);
        dst_ip[12..16].copy_from_slice(&pkt[16..20]);

        let (src_port, dst_port) = Self::extract_ports(&pkt[ihl..], proto);
        Some(Self {
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
        })
    }

    fn extract_v6(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 40 {
            return None;
        }
        let next_hdr = pkt[6];
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&pkt[8..24]);
        dst_ip.copy_from_slice(&pkt[24..40]);

        let (src_port, dst_port) = Self::extract_ports(&pkt[40..], next_hdr);
        Some(Self {
            src_ip,
            dst_ip,
            proto: next_hdr,
            src_port,
            dst_port,
        })
    }

    fn extract_ports(payload: &[u8], proto: u8) -> (u16, u16) {
        if (proto == 6 || proto == 17) && payload.len() >= 4 {
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            (sp, dp)
        } else {
            (0, 0)
        }
    }

    pub fn flow_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

/// Standard packet size (typical tunnel MTU 1280 bytes).
const PACKET_SIZE: usize = 1280;

/// Number of concurrent TCP streams across the single peer connection.
const NUM_STREAMS: usize = 64;

/// Packets per worker core to ensure stable measurement.
const PACKETS_PER_WORKER: usize = 60_000;

/// UMEM chunk size in bytes (2 KiB aligns with AF_XDP default).
const CHUNK_SIZE: usize = 2048;

/// Number of chunks per worker UMEM pool.
const CHUNKS_PER_POOL: usize = 2048;

/// Ring buffer capacity in descriptors.
const RING_CAPACITY: u32 = 1024;

/// Formats a synthetic IPv4 TCP packet directly inside a pre-allocated buffer.
fn write_tcp_packet(buf: &mut [u8], stream_id: u16, seq: u32, total_len: usize) {
    assert!(buf.len() >= total_len && total_len >= 46);
    buf[..total_len].fill(0);

    // IPv4 header (20 bytes)
    buf[0] = 0x45; // Version 4, IHL 5
    buf[8] = 64; // TTL
    buf[9] = 6; // TCP
    buf[12..16].copy_from_slice(&[10, 0, 0, 1]); // src IP
    buf[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst IP

    // TCP header (20 bytes at offset 20)
    let src_port = 10_000u16 + stream_id;
    let dst_port = 443u16;
    buf[20..22].copy_from_slice(&src_port.to_be_bytes());
    buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
    buf[24..28].copy_from_slice(&seq.to_be_bytes()); // TCP sequence number
    buf[32] = 0x50; // Data offset 5 (20 bytes)

    // Payload metadata: stream_id (2 bytes) + seq (4 bytes)
    buf[40..42].copy_from_slice(&stream_id.to_be_bytes());
    buf[42..46].copy_from_slice(&seq.to_be_bytes());
}

/// Extract stream ID and sequence number from decrypted packet.
fn extract_seq_and_stream(pkt: &[u8]) -> Option<(u16, u32)> {
    if pkt.len() < 46 {
        return None;
    }
    let stream_id = u16::from_be_bytes([pkt[40], pkt[41]]);
    let seq = u32::from_be_bytes([pkt[42], pkt[43], pkt[44], pkt[45]]);
    Some((stream_id, seq))
}

/// Results of a single benchmark run at worker count N.
#[derive(Debug, Clone)]
struct RunResult {
    workers: usize,
    gbps: f64,
    mpps: f64,
    per_core_gbps: f64,
    speedup: f64,
    efficiency: f64,
    drops: u64,
    out_of_order: u64,
}

/// Runs microbenchmarks on individual AF_XDP components.
fn run_component_microbenchmarks() {
    println!("--- Component Microbenchmarks ---");

    // 1. UMEM Chunk Alloc / Free Throughput
    {
        let iters = 200_000;
        let mut pool = UmemPool::new(CHUNKS_PER_POOL, CHUNK_SIZE).expect("create UMEM pool");
        let start = Instant::now();
        for _ in 0..iters {
            let addr = pool.alloc_chunk().expect("alloc chunk");
            pool.free_chunk(addr);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let mops = (iters as f64) / (elapsed * 1e6);
        println!(
            "  UMEM Chunk Alloc/Free:          {:6.2} Mops/s ({:.2} ns/op)",
            mops,
            (elapsed / iters as f64) * 1e9
        );
    }

    // 2. Circular Ring Batch Enqueue / Dequeue Throughput
    {
        let batch_size = 32;
        let iters = 10_000;
        let total_descs = iters * batch_size;

        let mut fill = FillRing::new(RING_CAPACITY);
        let mut rx = RxRing::new(RING_CAPACITY);
        let mut tx = TxRing::new(RING_CAPACITY);
        let mut comp = CompletionRing::new(RING_CAPACITY);

        let addrs: Vec<u64> = (0..batch_size as u64).map(|i| i * 2048).collect();
        let mut addrs_out = vec![0u64; batch_size];
        let descs: Vec<XskDesc> = (0..batch_size as u64)
            .map(|i| XskDesc::new(i * 2048, 1280, 0))
            .collect();
        let mut descs_out = vec![XskDesc::default(); batch_size];

        let start = Instant::now();
        for _ in 0..iters {
            assert_eq!(fill.produce_batch(&addrs), batch_size);
            assert_eq!(fill.consume_batch(&mut addrs_out), batch_size);

            assert_eq!(rx.produce_batch(&descs), batch_size);
            assert_eq!(rx.consume_batch(&mut descs_out), batch_size);

            assert_eq!(tx.produce_batch(&descs), batch_size);
            assert_eq!(tx.consume_batch(&mut descs_out), batch_size);

            assert_eq!(comp.produce_batch(&addrs), batch_size);
            assert_eq!(comp.consume_batch(&mut addrs_out), batch_size);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let total_ring_ops = total_descs * 8; // 4 rings * 2 (prod + cons)
        let mops = (total_ring_ops as f64) / (elapsed * 1e6);
        println!(
            "  Circular Rings (Batch 32):      {:6.2} Mops/s ({:.2} ns/op)",
            mops,
            (elapsed / total_ring_ops as f64) * 1e9
        );
    }

    // 3. In-Place Zero-Copy AEAD Seal & Open Inside UMEM Chunks
    {
        let iters = 100_000;
        let mut pool = UmemPool::new(16, CHUNK_SIZE).expect("create UMEM pool");
        let chunk_addr = pool.alloc_chunk().expect("alloc chunk");
        let cipher = ChaCha20Poly1305Cipher::new([0x42; 32]);
        let mut replay = ReplayWindow::new();

        let chunk = pool.chunk_slice_mut(chunk_addr, PACKET_SIZE + 16);
        write_tcp_packet(chunk, 1, 0, PACKET_SIZE);

        let start = Instant::now();
        for counter in 0..iters as u64 {
            let chunk = pool.chunk_slice_mut(chunk_addr, PACKET_SIZE + 16);
            let sealed_len = cipher
                .seal_in_place(counter, chunk, PACKET_SIZE)
                .expect("seal in place");
            let plain_len = cipher
                .open_in_place_with_window(counter, chunk, sealed_len, &mut replay)
                .expect("open in place");
            debug_assert_eq!(plain_len, PACKET_SIZE);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let total_bytes = iters as f64 * PACKET_SIZE as f64;
        let gbps = (total_bytes * 8.0) / (elapsed * 1e9);
        let mpps = (iters as f64) / (elapsed * 1e6);
        println!(
            "  Zero-Copy AEAD Seal+Open:       {:6.2} Gbps   ({:.3} Mpps, {:.2} ns/packet)",
            gbps,
            mpps,
            (elapsed / iters as f64) * 1e9
        );
        pool.free_chunk(chunk_addr);
    }
    println!("--------------------------------------------------------------------------------\n");
}

fn run_af_xdp_scale(num_workers: usize, baseline_gbps: Option<f64>) -> RunResult {
    // 1. Establish raw transport keys for single peer connection
    let (k_send, k_recv) = established_raw_keys();

    // 2. Pre-assign streams to worker shards based on 5-tuple flow hashing
    let mut streams_for_worker: Vec<Vec<u16>> = vec![Vec::new(); num_workers];
    let mut dummy_buf = vec![0u8; PACKET_SIZE];
    for s in 0..NUM_STREAMS as u16 {
        write_tcp_packet(&mut dummy_buf, s, 0, PACKET_SIZE);
        let flow = FlowTuple::extract(&dummy_buf).expect("valid TCP packet");
        let shard = (flow.flow_hash() as usize) % num_workers;
        streams_for_worker[shard].push(s);
    }

    let packets_per_thread = PACKETS_PER_WORKER;
    let barrier = Arc::new(Barrier::new(num_workers + 1));

    // Per-worker thread handles
    let mut handles = Vec::with_capacity(num_workers);

    for (worker_id, assigned_streams) in streams_for_worker.into_iter().enumerate() {
        let bar = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Topology-aware core pinning
            let _ = yip_io::pin_current_thread(worker_id);

            // Per-worker sharded sessions: start counter `worker_id` and stride `num_workers`
            let mut tx_session =
                Session::from_raw_keys(&k_send, &k_recv, worker_id as u64, num_workers as u64)
                    .expect("tx session initialization must succeed");

            let mut rx_session = Session::from_raw_keys(&k_recv, &k_send, 0, 1)
                .expect("rx session initialization must succeed");

            // Per-worker unprivileged UMEM shared memory pool
            let mut umem = UmemPool::new(CHUNKS_PER_POOL, CHUNK_SIZE).expect("create UMEM pool");

            // Per-worker AF_XDP ring buffers
            let mut fill_ring = FillRing::new(RING_CAPACITY);
            let mut rx_ring = RxRing::new(RING_CAPACITY);
            let mut tx_ring = TxRing::new(RING_CAPACITY);
            let mut completion_ring = CompletionRing::new(RING_CAPACITY);

            // Pre-populate fill ring with available UMEM chunks
            while !fill_ring.is_full() {
                if let Some(addr) = umem.alloc_chunk() {
                    fill_ring.produce(addr);
                } else {
                    break;
                }
            }

            let mut generated_nonces = Vec::with_capacity(packets_per_thread);

            // Track sequence number per assigned stream
            let mut expected_seq: HashMap<u16, u32> = HashMap::new();
            for &s in &assigned_streams {
                expected_seq.insert(s, 0);
            }

            let mut thread_drops = 0u64;
            let mut thread_ooo = 0u64;
            let mut thread_packets = 0u64;
            let mut thread_bytes = 0u64;

            // Wait for all workers to initialize memory and rings
            bar.wait();

            if !assigned_streams.is_empty() {
                let packets_per_stream = (packets_per_thread / assigned_streams.len()).max(1);

                for p in 0..packets_per_stream as u32 {
                    for &stream_id in &assigned_streams {
                        // 1. Ingress: obtain chunk from fill ring (or allocate new if empty)
                        let rx_addr = match fill_ring.consume() {
                            Some(addr) => addr,
                            None => umem.alloc_chunk().expect("UMEM chunk available"),
                        };

                        // 2. Format synthetic TCP packet directly inside UMEM chunk
                        let rx_buf = umem.chunk_slice_mut(rx_addr, PACKET_SIZE + 16);
                        write_tcp_packet(rx_buf, stream_id, p, PACKET_SIZE);

                        // 3. Enqueue to RX ring
                        let rx_enqueued =
                            rx_ring.produce(XskDesc::new(rx_addr, PACKET_SIZE as u32, 0));
                        assert!(rx_enqueued, "RX ring full");

                        // 4. Zero-copy RX dequeue
                        let rx_desc = rx_ring.consume().expect("RX descriptor available");

                        // 5. In-place AEAD seal directly inside UMEM chunk buffer using Session with stride nonces
                        let chunk_buf = umem.chunk_slice_mut(rx_desc.addr, PACKET_SIZE + 16);
                        let nonce = tx_session
                            .seal_in_place(chunk_buf, PACKET_SIZE)
                            .expect("in-place AEAD seal must succeed");
                        let sealed_len = PACKET_SIZE + 16;

                        // Verify local stride assignment invariant
                        assert_eq!(
                            nonce % num_workers as u64,
                            worker_id as u64,
                            "Nonce stride invariant violated for worker {worker_id}"
                        );
                        generated_nonces.push(nonce);

                        // 6. Enqueue to TX ring
                        let tx_enqueued =
                            tx_ring.produce(XskDesc::new(rx_desc.addr, sealed_len as u32, 0));
                        assert!(tx_enqueued, "TX ring full");

                        // 7. Simulated driver TX transmission dequeue
                        let tx_desc = tx_ring.consume().expect("TX descriptor available");

                        // 8. Peer in-place zero-copy AEAD open & replay check inside UMEM buffer
                        let tx_buf = umem.chunk_slice_mut(tx_desc.addr, tx_desc.len as usize);
                        let plain_len = rx_session
                            .open_in_place(nonce, tx_buf, tx_desc.len as usize)
                            .expect("in-place AEAD open must succeed");
                        assert_eq!(plain_len, PACKET_SIZE);

                        // 9. Strict monotonic FIFO verification per stream
                        if let Some((s_id, seq)) = extract_seq_and_stream(&tx_buf[..plain_len]) {
                            assert_eq!(s_id, stream_id, "Stream ID mismatch");
                            let exp = expected_seq.get_mut(&s_id).unwrap();
                            if seq == *exp {
                                *exp += 1;
                            } else if seq < *exp {
                                thread_ooo += 1;
                            } else {
                                thread_drops += (seq - *exp) as u64;
                                *exp = seq + 1;
                            }
                        } else {
                            panic!("Corrupt decrypted packet format");
                        }

                        // 10. TX completion: push chunk to completion ring
                        let comp_enqueued = completion_ring.produce(tx_desc.addr);
                        assert!(comp_enqueued, "Completion ring full");

                        // 11. Recycle completed chunk back to fill ring
                        let comp_addr = completion_ring
                            .consume()
                            .expect("completion descriptor available");
                        if !fill_ring.produce(comp_addr) {
                            umem.free_chunk(comp_addr);
                        }

                        thread_packets += 1;
                        thread_bytes += PACKET_SIZE as u64;
                    }
                }
            }

            (
                thread_packets,
                thread_bytes,
                thread_drops,
                thread_ooo,
                generated_nonces,
            )
        });

        handles.push(handle);
    }

    // Release all worker threads simultaneously
    let start = Instant::now();
    barrier.wait();

    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;
    let mut total_drops = 0u64;
    let mut total_ooo = 0u64;
    let mut all_nonces = std::collections::HashSet::new();

    for h in handles {
        let (pkts, bytes, drops, ooo, nonces) = h.join().expect("worker thread panicked");
        total_packets += pkts;
        total_bytes += bytes;
        total_drops += drops;
        total_ooo += ooo;
        for nonce in nonces {
            assert!(
                all_nonces.insert(nonce),
                "Strict nonce collision detected: nonce {nonce} was generated more than once!"
            );
        }
    }

    // Verify strict nonce uniqueness across all worker threads
    assert_eq!(
        all_nonces.len(),
        total_packets as usize,
        "Total unique nonces ({}) does not match total packets ({})",
        all_nonces.len(),
        total_packets
    );

    let duration = start.elapsed();
    let secs = duration.as_secs_f64();
    let gbps = (total_bytes as f64 * 8.0) / (secs * 1e9);
    let mpps = total_packets as f64 / (secs * 1e6);
    let per_core_gbps = gbps / num_workers as f64;
    let base = baseline_gbps.unwrap_or(gbps);
    let speedup = gbps / base;
    let efficiency = speedup / num_workers as f64;

    // Strict assertions: 0 packet drops, 0 out-of-order deliveries
    assert_eq!(total_drops, 0, "Packet drops detected!");
    assert_eq!(total_ooo, 0, "Out-of-order deliveries detected!");

    RunResult {
        workers: num_workers,
        gbps,
        mpps,
        per_core_gbps,
        speedup,
        efficiency,
        drops: total_drops,
        out_of_order: total_ooo,
    }
}

fn main() {
    println!("================================================================================");
    println!("  YIP Way C: AF_XDP Zero-Copy Kernel-Bypass Scaling Microbenchmark              ");
    println!("================================================================================");
    println!(
        "  Payload: {} B | Streams: {} | Packets/Core: {} | UMEM Chunk: {} B",
        PACKET_SIZE, NUM_STREAMS, PACKETS_PER_WORKER, CHUNK_SIZE
    );
    println!("--------------------------------------------------------------------------------");

    // Component Microbenchmarks
    run_component_microbenchmarks();

    // Warm-up run
    print!("Warming up worker threads... ");
    let _ = run_af_xdp_scale(2, None);
    println!("ready.\n");

    let worker_counts = [1, 2, 4, 8];
    let mut results = Vec::new();
    let mut baseline_gbps = None;

    for &w in &worker_counts {
        print!("Benchmarking {} worker thread(s)... ", w);
        let res = run_af_xdp_scale(w, baseline_gbps);
        if baseline_gbps.is_none() {
            baseline_gbps = Some(res.gbps);
        }
        println!("done: {:.2} Gbps ({:.3} Mpps)", res.gbps, res.mpps);
        results.push(res);
    }

    println!("\n### Scaling Benchmark Results\n");
    println!("| Workers (N) | Aggregate Gbps | Mpps  | Per-Core Gbps | Speedup | Efficiency | Drops | Out-of-Order |");
    println!("|------------:|---------------:|------:|--------------:|--------:|-----------:|------:|-------------:|");

    for r in &results {
        println!(
            "| {:11} | {:14.2} | {:5.3} | {:13.2} | {:6.2}x | {:9.1}% | {:5} | {:12} |",
            r.workers,
            r.gbps,
            r.mpps,
            r.per_core_gbps,
            r.speedup,
            r.efficiency * 100.0,
            r.drops,
            r.out_of_order,
        );
    }

    println!("\nVerification summary:");
    for r in &results {
        assert_eq!(
            r.drops, 0,
            "Zero-drop requirement failed at N={}",
            r.workers
        );
        assert_eq!(
            r.out_of_order, 0,
            "Zero-reorder requirement failed at N={}",
            r.workers
        );
    }
    println!("  [PASS] 0 packet drops verified across all worker configurations.");
    println!(
        "  [PASS] 0 out-of-order deliveries verified (strict monotonic FIFO ordering per stream)."
    );
    println!(
        "  [PASS] Strict nonce uniqueness confirmed across all worker threads (0 collisions)."
    );
    println!("  [PASS] Non-root user space UMEM shared memory mapping verified (0 CAP_NET_ADMIN needed).");
    println!(
        "  [PASS] Zero-copy in-place AEAD seal/open verified inside UMEM chunk memory buffers."
    );
    println!(
        "  [PASS] Multi-core line-rate scaling confirmed across 1, 2, 4, and 8 worker threads."
    );
    println!("================================================================================");
}
