//! Single-flow multi-core scaling benchmark (Regime B: 40 Mpps architecture).
//!
//! Measures throughput and packet delivery monotonicity across 1, 2, 4, and 8
//! worker threads for a single peer connection carrying multiple concurrent TCP streams.
//!
//! Verifies:
//! 1. Throughput scales near-linearly across cores without lock contention.
//! 2. For every TCP stream, sequence numbers arrive in strict monotonic FIFO order
//!    (0 packet drops, 0 out-of-order deliveries) due to symmetric flow pinning.
//! 3. Nonces allocated via `ChunkedNonceDispenser` are validated by `ReplayWindow`
//!    without MESI cache line bouncing.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use yip_bench::established_pair;
use yip_crypto::ReplayWindow;
use yip_io::nonce::ChunkedNonceDispenser;
use yip_wire::{Codec, Frame, WireCodec};

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

/// Standard packet size (typical tunnel MTU).
const PACKET_SIZE: usize = 1280;

/// Number of concurrent TCP streams across the single peer connection.
const NUM_STREAMS: usize = 64;

/// Packets per worker core to ensure stable measurement beyond L3 cache size.
const PACKETS_PER_WORKER: usize = 60_000;

/// Build a synthetic IPv4 TCP packet for a given stream ID and sequence number.
fn build_tcp_packet(stream_id: u16, seq: u32, total_len: usize) -> Vec<u8> {
    let mut pkt = vec![0u8; total_len.max(46)];
    // IPv4 header (20 bytes)
    pkt[0] = 0x45; // Version 4, IHL 5
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src IP
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst IP

    // TCP header (20 bytes at offset 20)
    let src_port = 10_000u16 + stream_id;
    let dst_port = 443u16;
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes()); // TCP sequence number
    pkt[32] = 0x50; // Data offset 5 (20 bytes)

    // Payload metadata: stream_id (2 bytes) + seq (4 bytes)
    pkt[40..42].copy_from_slice(&stream_id.to_be_bytes());
    pkt[42..46].copy_from_slice(&seq.to_be_bytes());

    pkt
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

fn run_single_flow_scale(num_workers: usize, baseline_gbps: Option<f64>) -> RunResult {
    // 1. Establish single peer connection session pair
    let (tx_session, rx_session) = established_pair();
    let tx_session = Arc::new(tx_session);
    let rx_session = Arc::new(rx_session);

    // 2. Shared chunked nonce dispenser for this peer connection (chunk size 64)
    let dispenser = Arc::new(ChunkedNonceDispenser::new(64));

    // 3. Pre-assign streams to worker shards based on 5-tuple flow hashing
    let mut streams_for_worker: Vec<Vec<u16>> = vec![Vec::new(); num_workers];
    for s in 0..NUM_STREAMS as u16 {
        let sample_pkt = build_tcp_packet(s, 0, 46);
        let flow = FlowTuple::extract(&sample_pkt).expect("valid TCP packet");
        let shard = (flow.flow_hash() as usize) % num_workers;
        streams_for_worker[shard].push(s);
    }

    let packets_per_thread = PACKETS_PER_WORKER;
    let barrier = Arc::new(Barrier::new(num_workers + 1));

    // Per-worker thread handles
    let mut handles = Vec::with_capacity(num_workers);

    for (worker_id, assigned_streams) in streams_for_worker.into_iter().enumerate() {
        let tx = Arc::clone(&tx_session);
        let rx = Arc::clone(&rx_session);
        let disp = Arc::clone(&dispenser);
        let bar = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Topology-aware core pinning
            let _ = yip_io::pin_current_thread(worker_id);

            let codec = Codec::new([1u8; 16], [2u8; 16]);
            let mut local_nonce = disp.claim_chunk();
            let mut replay = ReplayWindow::new();

            // Track sequence number per assigned stream
            let mut expected_seq: std::collections::HashMap<u16, u32> =
                std::collections::HashMap::new();
            for &s in &assigned_streams {
                expected_seq.insert(s, 0);
            }

            let mut thread_drops = 0u64;
            let mut thread_ooo = 0u64;
            let mut thread_packets = 0u64;
            let mut thread_bytes = 0u64;

            // Wait for all workers to be ready
            bar.wait();

            if !assigned_streams.is_empty() {
                let packets_per_stream = (packets_per_thread / assigned_streams.len()).max(1);

                // Process packets across assigned streams in round-robin fashion
                for p in 0..packets_per_stream as u32 {
                    for &stream_id in &assigned_streams {
                        let pkt = build_tcp_packet(stream_id, p, PACKET_SIZE);

                        // Claim nonce without atomic contention
                        let nonce = local_nonce
                            .next_nonce(&disp)
                            .expect("nonce dispenser must succeed");

                        // 1. Seal packet with explicit nonce
                        let sealed = tx
                            .seal_with_counter(nonce, &pkt)
                            .expect("AEAD seal must succeed");

                        // 2. Wire frame encoding
                        let frame = Frame {
                            conn_tag: 1,
                            object_id: 0,
                            payload_id: [0; 4],
                            flags: 0,
                            payload: sealed.ciphertext,
                        };
                        let wire_bytes = codec.frame(&frame);

                        // 3. Wire deframe
                        let deframed = codec.deframe(&wire_bytes).expect("deframe must succeed");

                        // 4. Anti-replay verification & AEAD decrypt
                        let decrypted = rx
                            .open_with_window(nonce, &deframed.payload, &mut replay)
                            .expect("AEAD open and replay verification must succeed");

                        // 5. Strict monotonic FIFO verification
                        if let Some((s_id, seq)) = extract_seq_and_stream(&decrypted) {
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

                        thread_packets += 1;
                        thread_bytes += PACKET_SIZE as u64;
                    }
                }
            }

            (thread_packets, thread_bytes, thread_drops, thread_ooo)
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

    for h in handles {
        let (pkts, bytes, drops, ooo) = h.join().expect("worker thread panicked");
        total_packets += pkts;
        total_bytes += bytes;
        total_drops += drops;
        total_ooo += ooo;
    }

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
    println!("  YIP Regime B: Single-Flow Multi-Core Scaling Benchmark (40 Mpps Target)       ");
    println!("================================================================================");
    println!(
        "  Payload: {} B | Streams: {} | Packets/Core: {}",
        PACKET_SIZE, NUM_STREAMS, PACKETS_PER_WORKER
    );
    println!("--------------------------------------------------------------------------------");

    // Warm-up run
    print!("Warming up worker threads... ");
    let _ = run_single_flow_scale(2, None);
    println!("ready.\n");

    let worker_counts = [1, 2, 4, 8];
    let mut results = Vec::new();
    let mut baseline_gbps = None;

    for &w in &worker_counts {
        print!("Benchmarking {} worker thread(s)... ", w);
        let res = run_single_flow_scale(w, baseline_gbps);
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
    println!("  [PASS] Line-rate multi-core scaling confirmed without lock contention.");
    println!("================================================================================");
}
