//! The yipd tunnel: binds a UDP socket, runs the Noise-IK handshake, creates
//! the TUN device, then drives the two data loops (egress and ingress) that
//! move packets between the device and the network.
//!
//! # conn_tag
//!
//! Each wire frame carries an 8-byte `conn_tag` that the receiver uses to
//! select the right session / decoder. For M6 we derive it from the first 8
//! bytes of the Noise channel binding (which both peers compute identically
//! after the handshake, so both will use the same tag). This is a placeholder:
//! M7+ will rotate the tag every epoch for unlinkability.
//!
//! # Feedback loop
//!
//! Both peers run identical code: the ingress side tracks gaps via
//! `LossDetector` and periodically seals a `LossReport` into a `Control`
//! packet (`[PacketType::Control][counter:8be][ciphertext]`) sent to the peer.
//! The peer's ingress thread decrypts the report, looks up each missing counter
//! in a bounded `sent_log` (`counter → FlowClass`), computes per-class loss
//! fractions, and feeds them to `Transport::observe_loss`, which adjusts the
//! FEC repair ratios.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use yip_device::{DeviceKind, TunTap};
use yip_io::{set_socket_buffers, DataPlaneIo, PlainIo, MAX_DATAGRAM_BATCH, MAX_WIRE_DATAGRAM};
use yip_transport::{FlowClass, LossDetector, LossReport, RetxBuffer, Transport};
use yip_wire::{Codec, WireCodec};

use crate::config::Config;
use crate::handshake::{self, PacketType};
use crate::wire_glue;

// Maximum UDP datagram we ever allocate for recv.
const MAX_DATAGRAM: usize = 65_535;

// How often (in milliseconds of elapsed tunnel time) the ingress thread emits
// a loss-feedback Control packet to the peer.
const FEEDBACK_INTERVAL_MS: u64 = 30;

// Maximum number of entries in the sent-log (counter → FlowClass).  Once full,
// the oldest entry is evicted before each new insertion, so memory is O(1).
const SENT_LOG_CAPACITY: usize = 4096;

// ARQ retransmit buffer: maximum number of sent ciphertext objects to hold.
// Sized so that even a high-rate flow retains objects long enough for a NACK to
// round-trip: at ~100k objects/s a 1024-entry cap held only ~10 ms, far shorter
// than the feedback interval + RTT, so NACKed objects were already evicted.
// 16384 covers ~160 ms at that rate; the TTL still bounds memory at lower rates.
// Worst-case memory ≈ 16384 × ~1.25 KiB ciphertext ≈ 20 MiB.
const RETX_BUFFER_MAX: usize = 16_384;
// How long (ms) to keep a sent object available for retransmission.
const RETX_BUFFER_TTL_MS: u64 = 2000;
// Number of extra repair symbols to emit per ARQ retransmit.
const RETX_EXTRA_REPAIR: u32 = 4;

/// A bounded ring-log that maps sealed-packet counters to their `FlowClass`.
///
/// Entries are inserted in arrival order (monotone counter sequence from the
/// AEAD) and evicted oldest-first once `capacity` is reached.  Lookup is
/// O(1) via the `HashMap`; eviction is O(1) via the `VecDeque`.
struct SentLog {
    capacity: usize,
    map: HashMap<u64, FlowClass>,
    order: VecDeque<u64>,
}

impl SentLog {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    fn insert(&mut self, counter: u64, class: FlowClass) {
        if self.map.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(counter, class);
        self.order.push_back(counter);
    }

    fn get(&self, counter: u64) -> Option<FlowClass> {
        self.map.get(&counter).copied()
    }

    /// Number of entries in the log whose `FlowClass` matches `class`.
    fn count_class(&self, class: FlowClass) -> u32 {
        u32::try_from(self.map.values().filter(|&&c| c == class).count()).unwrap_or(u32::MAX)
    }
}

// ── conn_tag derivation ───────────────────────────────────────────────────────

/// Derive the per-session `conn_tag` from the first 8 bytes of the Noise
/// channel binding. Both peers compute the same binding after a successful
/// handshake, so they end up with the same tag without any extra signaling.
///
/// M7 will rotate this every ~120 s epoch for unlinkability.
fn conn_tag_from_cb(channel_binding: &[u8; 32]) -> u64 {
    u64::from_be_bytes(channel_binding[..8].try_into().expect("8 bytes"))
}

// ── public entry point ────────────────────────────────────────────────────────

/// Run the tunnel: bind, handshake, create TUN, loop forever (or until an I/O
/// error terminates one of the two threads).
///
/// Blocks until both threads exit. In practice this function only returns on a
/// fatal I/O error.
pub fn run(config: Config) -> io::Result<()> {
    // ── bind the UDP socket ───────────────────────────────────────────────────
    let sock = UdpSocket::bind(config.listen)?;

    // ── handshake ─────────────────────────────────────────────────────────────
    let (established, peer_addr) = if config.initiate {
        let est = handshake::run_initiator(
            &sock,
            config.peer_endpoint,
            &config.local_private,
            &config.peer_public,
        )?;
        (est, config.peer_endpoint)
    } else {
        let (est, addr) = handshake::run_responder(&sock, &config.local_private)?;
        (est, addr)
    };

    // Connect the socket so plain send/recv work on both threads without
    // carrying the peer address on every call.
    sock.connect(peer_addr)?;

    // Raise kernel socket buffers to 4 MiB so bursts do not overflow the
    // OS receive ring.  The kernel may clamp or double the value; we ignore
    // the exact result and only propagate hard errors.
    set_socket_buffers(&sock, 4 * 1024 * 1024)?;

    let cb = {
        // We need the channel binding to derive conn_tag; it was consumed during
        // the handshake. Re-derive it from auth_key||hp_key (both are 16-byte
        // sub-slices of the same BLAKE2s digest of the channel binding, so we
        // cannot recover the full CB here without re-exposing it from Established).
        //
        // Instead we expose a stable tag from the auth_key: the first 8 bytes
        // uniquely identify the session and are already derived from the CB.
        // Both peers hold the same auth_key, so both derive the same conn_tag.
        let mut combined = [0u8; 32];
        combined[..16].copy_from_slice(&established.auth_key);
        combined[16..].copy_from_slice(&established.hp_key);
        combined
    };
    let conn_tag = conn_tag_from_cb(&cb);

    // ── build shared state ────────────────────────────────────────────────────
    let codec = Codec::new(established.auth_key, established.hp_key);
    let session = Arc::new(Mutex::new(established.session));
    let transport = Arc::new(Mutex::new(Transport::new(vec![])));

    // Sent-log: egress records counter→class; ingress control-handler reads it.
    let sent_log: Arc<Mutex<SentLog>> = Arc::new(Mutex::new(SentLog::new(SENT_LOG_CAPACITY)));

    // Loss detector: ingress updates it from every received datagram; the
    // ingress thread also reads it periodically to emit feedback.
    let detector: Arc<Mutex<LossDetector>> = Arc::new(Mutex::new(LossDetector::new(5, 1024)));

    // ARQ retransmit buffer: egress puts sent ciphertext objects here; ingress
    // retrieves them by counter when a NACK arrives.
    let retx: Arc<Mutex<RetxBuffer>> = Arc::new(Mutex::new(RetxBuffer::new(
        RETX_BUFFER_MAX,
        RETX_BUFFER_TTL_MS,
    )));

    // ── create + split the TUN device ────────────────────────────────────────
    let tun = TunTap::create(&config.device, DeviceKind::Tun).map_err(io::Error::other)?;
    let (mut tun_reader, mut tun_writer) = tun.split().map_err(io::Error::other)?;

    // ── clone sockets for the two threads ────────────────────────────────────
    let udp_tx = sock.try_clone()?;
    let udp_rx = sock;

    // ── shared codec (immutable, so Arc<> rather than Mutex<>) ───────────────
    let codec = Arc::new(codec);
    let codec_tx = Arc::clone(&codec);
    let codec_rx = codec;

    // ── egress thread: TUN → UDP ──────────────────────────────────────────────
    let session_tx = Arc::clone(&session);
    let transport_tx = Arc::clone(&transport);
    let sent_log_tx = Arc::clone(&sent_log);
    let retx_tx = Arc::clone(&retx);

    let egress = std::thread::Builder::new()
        .name("yipd-egress".into())
        .spawn(move || -> io::Result<()> {
            let start = Instant::now();
            let mut buf = vec![0u8; MAX_DATAGRAM];

            // Thread-owned arena of pre-allocated datagram buffers, reused every
            // packet to avoid per-symbol heap allocation.  Each slot holds one
            // framed datagram (1-byte PacketType prefix + codec output).
            let mut arena: Vec<Vec<u8>> = (0..MAX_DATAGRAM_BATCH).map(|_| Vec::new()).collect();

            // Wrap the egress socket in the DataPlaneIo abstraction so that we can
            // emit all of a packet's symbols in a single sendmmsg(2) syscall.
            let mut io = PlainIo::new(udp_tx);

            loop {
                // Read one inner frame from the TUN device.
                let n = tun_reader.read_frame(&mut buf)?;
                let inner = &buf[..n];

                let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

                // Seal the inner frame with AEAD.
                let sealed = session_tx
                    .lock()
                    .expect("session lock poisoned")
                    .seal(inner)
                    .map_err(io::Error::other)?;

                // FEC-encode the sealed ciphertext.
                let (class, symbols) = transport_tx
                    .lock()
                    .expect("transport lock poisoned")
                    .encode(&sealed.ciphertext, inner, false, now_ms);

                // Record counter → class in the sent-log so the ingress thread
                // can attribute received loss reports to the right flow class.
                sent_log_tx
                    .lock()
                    .expect("sent_log lock poisoned")
                    .insert(sealed.counter, class);

                // Record in the ARQ retransmit buffer so NACKs can top up the
                // receiver's decoder with fresh repair symbols.
                if let Some(oid) = symbols.first().map(|s| s.object_id) {
                    retx_tx.lock().expect("retx lock poisoned").put(
                        sealed.counter,
                        sealed.ciphertext.clone(),
                        class,
                        oid,
                        now_ms,
                    );
                }

                // Frame each symbol into a reused arena slot, then emit all
                // datagrams in one batched syscall (chunked by MAX_DATAGRAM_BATCH).
                let n_syms = symbols.len();

                // Grow the arena on the (rare) first call or overflow.
                if arena.len() < n_syms {
                    arena.resize_with(n_syms, Vec::new);
                }

                for (slot, sym) in arena[..n_syms].iter_mut().zip(symbols.iter()) {
                    let frame = wire_glue::symbol_to_frame(conn_tag, sym, sealed.counter, class);
                    let dg = codec_tx.frame(&frame);
                    slot.clear();
                    slot.push(PacketType::Data as u8);
                    slot.extend_from_slice(&dg);
                }

                // Collect &[u8] views pointing into the populated arena slots.
                // The arena owns the bytes and lives for the entire loop iteration,
                // so the slices are valid across the send_batch call.
                // This is a small stack-scoped Vec of pointer-sized elements.
                let slices: Vec<&[u8]> = arena[..n_syms].iter().map(Vec::as_slice).collect();

                // Send in chunks of MAX_DATAGRAM_BATCH (one sendmmsg per chunk).
                for chunk in slices.chunks(MAX_DATAGRAM_BATCH) {
                    match io.send_batch(chunk) {
                        Ok(sent) if sent < chunk.len() => {
                            eprintln!(
                                "yipd egress: short batch send ({sent}/{} datagrams)",
                                chunk.len()
                            );
                        }
                        Ok(_) => {}
                        // A transient send error (e.g. ENOBUFS) is logged but does
                        // not terminate the egress loop; the packet is simply dropped.
                        Err(e) => {
                            eprintln!("yipd egress: send_batch error: {e}");
                        }
                    }
                }
            }
        })?;

    // ── ingress thread: UDP → TUN ─────────────────────────────────────────────
    let session_rx = Arc::clone(&session);
    let transport_rx = Arc::clone(&transport);
    let sent_log_rx = Arc::clone(&sent_log);
    let detector_rx = Arc::clone(&detector);
    let retx_rx = Arc::clone(&retx);

    let ingress = std::thread::Builder::new()
        .name("yipd-ingress".into())
        .spawn(move || -> io::Result<()> {
            // Wrap the ingress socket in the DataPlaneIo abstraction so that
            // recvmmsg(2) harvests bursts of datagrams in a single syscall.
            let mut io = PlainIo::new(udp_rx);

            // Allocate batch buffers once on the heap; reused every iteration
            // to avoid per-datagram allocation.
            let mut bufs = vec![[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH];
            let mut lens = vec![0usize; MAX_DATAGRAM_BATCH];

            // Track when we last emitted a feedback packet (in tunnel-uptime ms).
            let start = Instant::now();
            let mut last_feedback_ms: u64 = 0;

            // Periodic log interval for controller ratio (every ~5 s).
            let mut last_log_ms: u64 = 0;
            const LOG_INTERVAL_MS: u64 = 5_000;

            loop {
                // Block until ≥1 datagram arrives (MSG_WAITFORONE), then drain
                // however many are immediately available (up to MAX_DATAGRAM_BATCH).
                let n = io.recv_batch(&mut bufs, &mut lens)?;

                let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

                for i in 0..n {
                    let dg = &bufs[i][..lens[i]];

                    if dg.is_empty() {
                        continue;
                    }

                    match dg[0] {
                        b if b == PacketType::Data as u8 => {
                            let wire = &dg[1..];

                            // Deframe (auth + header-deprotect). On failure, drop the
                            // packet without killing the loop.
                            let frame = match codec_rx.deframe(wire) {
                                Ok(f) => f,
                                Err(e) => {
                                    eprintln!("yipd ingress: deframe error: {e}");
                                    continue;
                                }
                            };

                            // Parse the FEC symbol + counter out of the frame.
                            let (sym, counter, class) = match wire_glue::frame_to_symbol(&frame) {
                                Some(t) => t,
                                None => {
                                    eprintln!(
                                        "yipd ingress: frame_to_symbol returned None (short payload)"
                                    );
                                    continue;
                                }
                            };

                            // Notify the loss detector that we saw this counter.
                            detector_rx
                                .lock()
                                .expect("detector lock poisoned")
                                .on_seen(counter, now_ms);

                            // Feed the symbol to the FEC reassembler; continue until an
                            // object decodes.
                            let ciphertext = match transport_rx
                                .lock()
                                .expect("transport lock poisoned")
                                .decode(&sym, class)
                            {
                                Some(ct) => ct,
                                None => continue,
                            };

                            // The object decoded: tell the detector it was delivered.
                            detector_rx
                                .lock()
                                .expect("detector lock poisoned")
                                .on_delivered(counter);

                            // Open the AEAD ciphertext. Replay / AEAD failures are logged
                            // and the packet is dropped.
                            let inner = match session_rx
                                .lock()
                                .expect("session lock poisoned")
                                .open(counter, &ciphertext)
                            {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("yipd ingress: open error: {e}");
                                    continue;
                                }
                            };

                            // Inject the plaintext inner frame into the TUN device.
                            // An I/O error here is fatal (device gone).
                            tun_writer.write_frame(&inner)?;
                        }

                        b if b == PacketType::Control as u8 => {
                            // Control packet layout:
                            //   [1-byte type][8-byte counter BE][ciphertext...]
                            if dg.len() < 9 {
                                eprintln!("yipd ingress: control packet too short");
                                continue;
                            }
                            let counter = u64::from_be_bytes(
                                dg[1..9].try_into().expect("exactly 8 bytes"),
                            );
                            let ct = &dg[9..];

                            // Decrypt the control payload FIRST — authenticate before
                            // any side-effect. A forged packet with a bogus counter
                            // must not poison the loss detector's high_counter.
                            let plaintext = match session_rx
                                .lock()
                                .expect("session lock poisoned")
                                .open(counter, ct)
                            {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("yipd ingress: control open error: {e}");
                                    continue;
                                }
                            };

                            // Authentication succeeded: notify the detector that we
                            // saw this control counter, keeping the unified counter
                            // sequence consistent.
                            detector_rx
                                .lock()
                                .expect("detector lock poisoned")
                                .on_seen(counter, now_ms);

                            // Decode the LossReport.
                            let report = match LossReport::decode(&plaintext) {
                                Some(r) => r,
                                None => {
                                    eprintln!("yipd ingress: malformed LossReport");
                                    continue;
                                }
                            };

                            // Attribute missing counters to flow classes via the sent-log.
                            //
                            // Per-class fraction estimate:
                            //   fraction = class_missing / max(1, class_sent_in_log)
                            //
                            // `class_sent_in_log` is the count of entries in the bounded
                            // sent-log for that class — a conservative approximation of
                            // how many packets of that class were recently in-flight.
                            // It underestimates the true window (the log only holds the
                            // last SENT_LOG_CAPACITY entries) but is always ≥ class_missing,
                            // so the fraction stays ∈ [0, 1].
                            let log = sent_log_rx.lock().expect("sent_log lock poisoned");

                            let mut missing_rt: u32 = 0;
                            let mut missing_bulk: u32 = 0;
                            let mut missing_default: u32 = 0;

                            for &c in &report.missing {
                                match log.get(c) {
                                    Some(FlowClass::Realtime) => {
                                        missing_rt =
                                            missing_rt.saturating_add(1);
                                    }
                                    Some(FlowClass::Bulk) => {
                                        missing_bulk =
                                            missing_bulk.saturating_add(1);
                                    }
                                    Some(FlowClass::Default) => {
                                        missing_default =
                                            missing_default.saturating_add(1);
                                    }
                                    None => {
                                        // Counter not in log (too old or was a
                                        // control packet) — ignore for attribution.
                                    }
                                }
                            }

                            let sent_rt = log.count_class(FlowClass::Realtime).max(1);
                            let sent_bulk = log.count_class(FlowClass::Bulk).max(1);
                            let sent_default = log.count_class(FlowClass::Default).max(1);

                            drop(log); // release before locking transport

                            // Compute loss fractions by narrowing u32 counts to u16
                            // (saturating), then converting to f32 without any numeric cast.
                            let frac_rt = fraction_f32(missing_rt, sent_rt);
                            let frac_bulk = fraction_f32(missing_bulk, sent_bulk);
                            let frac_default = fraction_f32(missing_default, sent_default);

                            {
                                let mut t =
                                    transport_rx.lock().expect("transport lock poisoned");
                                t.observe_loss(FlowClass::Realtime, frac_rt);
                                t.observe_loss(FlowClass::Bulk, frac_bulk);
                                t.observe_loss(FlowClass::Default, frac_default);
                            } // transport lock released here

                            // ARQ: for each missing counter reported by the peer,
                            // retransmit fresh repair symbols carrying the original
                            // object_id so the receiver's in-progress decoder is
                            // topped up rather than starting over.
                            //
                            // Lock discipline: never hold retx lock across transport
                            // or io operations — copy data out first.
                            for &counter in &report.missing {
                                let retx_entry = {
                                    let buf =
                                        retx_rx.lock().expect("retx lock poisoned");
                                    buf.get(counter, now_ms)
                                        .map(|(ct, cls, oid)| (ct.to_vec(), cls, oid))
                                };

                                let Some((ct, cls, oid)) = retx_entry else {
                                    continue;
                                };
                                if !cls.params().arq {
                                    continue;
                                }

                                // Generate fresh repair symbols with the original object_id.
                                let repair_syms = transport_rx
                                    .lock()
                                    .expect("transport lock poisoned")
                                    .repair_object(&ct, cls, oid, RETX_EXTRA_REPAIR);

                                // Frame and collect all repair datagrams, then send.
                                let mut repair_frames: Vec<Vec<u8>> =
                                    Vec::with_capacity(repair_syms.len());
                                for sym in &repair_syms {
                                    let frame = wire_glue::symbol_to_frame(
                                        conn_tag, sym, counter, cls,
                                    );
                                    let dg = codec_rx.frame(&frame);
                                    let mut pkt =
                                        Vec::with_capacity(1 + dg.len());
                                    pkt.push(PacketType::Data as u8);
                                    pkt.extend_from_slice(&dg);
                                    repair_frames.push(pkt);
                                }
                                let slices: Vec<&[u8]> = repair_frames
                                    .iter()
                                    .map(Vec::as_slice)
                                    .collect();
                                for chunk in slices.chunks(MAX_DATAGRAM_BATCH) {
                                    if let Err(e) = io.send_batch(chunk) {
                                        eprintln!(
                                            "yipd ingress: retransmit send error: {e}"
                                        );
                                    }
                                }
                            }
                        }

                        _ => {
                            // Unknown packet type — drop silently.
                        }
                    }
                }

                // ── periodic feedback emission ────────────────────────────────
                // After processing this batch, check if it is time to send a
                // loss-feedback Control packet to the peer.
                if now_ms.saturating_sub(last_feedback_ms) >= FEEDBACK_INTERVAL_MS {
                    last_feedback_ms = now_ms;

                    // Build the report from the current detector state.
                    let report = detector_rx
                        .lock()
                        .expect("detector lock poisoned")
                        .report(now_ms);

                    let report_bytes = report.encode();

                    // Seal the report. The counter comes from the unified session
                    // sequence; the peer's detector will call on_seen for it.
                    let sealed = session_rx
                        .lock()
                        .expect("session lock poisoned")
                        .seal(&report_bytes)
                        .map_err(io::Error::other)?;

                    // Build and send:  [type:1][counter:8be][ciphertext]
                    let mut pkt = Vec::with_capacity(9 + sealed.ciphertext.len());
                    pkt.push(PacketType::Control as u8);
                    pkt.extend_from_slice(&sealed.counter.to_be_bytes());
                    pkt.extend_from_slice(&sealed.ciphertext);

                    // A transient send error is logged but not fatal.
                    if let Err(e) = io.send_batch(&[pkt.as_slice()]) {
                        eprintln!("yipd ingress: control send error: {e}");
                    }
                }

                // ── periodic controller ratio log ─────────────────────────────
                if now_ms.saturating_sub(last_log_ms) >= LOG_INTERVAL_MS {
                    last_log_ms = now_ms;
                    // Use a try_lock to avoid blocking the ingress hot path if
                    // transport is momentarily held by egress.
                    if let Ok(t) = transport_rx.try_lock() {
                        eprintln!(
                            "yipd [{}ms] bulk controller repair ratio: {:.4}",
                            now_ms,
                            t.bulk_repair_ratio(),
                        );
                    }
                }
            }
        })?;

    // Block until both threads finish.  In practice this only happens when a
    // fatal I/O error (device gone, socket closed) terminates one of them.
    let egress_result = egress
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("egress thread panicked")));
    let ingress_result = ingress
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("ingress thread panicked")));

    // Report the first error, if any.
    egress_result.and(ingress_result)
}

/// Compute `numerator / denominator` as an `f32` loss fraction ∈ [0.0, 1.0].
///
/// Both operands are narrowed to `u16` (saturating) so that `f32::from`
/// can accept them without any numeric `as` cast.  For the small counts
/// that arise from the bounded sent-log (capacity 4096) and MAX_NACK (64),
/// u16 is always large enough.
#[inline]
fn fraction_f32(numerator: u32, denominator: u32) -> f32 {
    if denominator == 0 {
        return 0.0_f32;
    }
    let n = f32::from(u16::try_from(numerator).unwrap_or(u16::MAX));
    let d = f32::from(u16::try_from(denominator).unwrap_or(u16::MAX));
    (n / d).clamp(0.0_f32, 1.0_f32)
}
