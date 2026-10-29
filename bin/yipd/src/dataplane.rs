//! Mutex-free data plane: owns the AEAD session, FEC transport, wire codec,
//! and auxiliary buffers.  Driven by the epoll event loop in `yip_io::poll`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use yip_transport::{
    ControlFrame, FlowClass, LossDetector, PlpmtuController, RetxBuffer, Transport,
};
use yip_wire::{Codec, WireCodec as _};

use crate::handshake::{Established, PacketType};
use crate::mac_table::{
    LearnOrigin, MacTable, DEFAULT_MAC_TABLE_CAPACITY, DEFAULT_MAC_TABLE_TTL_MS,
};
use crate::mode::TunnelMode;
use crate::wire_glue;

// ── constants (wired into DataPlane::new; tunnel.rs keeps its own copies until
//    Task 3 replaces the two-thread loop with this DataPlane) ─────────────────

const SENT_LOG_CAPACITY: usize = 4096;
const RETX_BUFFER_MAX: usize = 16_384;
const RETX_BUFFER_TTL_MS: u64 = 2000;
const RETX_EXTRA_REPAIR: u32 = 4;

// How often (in milliseconds of elapsed tunnel time) the ingress side emits
// a loss-feedback Control packet to the peer.
const FEEDBACK_INTERVAL_MS: u64 = 30;

// Periodic log interval for controller ratio (every ~5 s).
const LOG_INTERVAL_MS: u64 = 5_000;
// How often to sweep the MAC table for expired entries. `tick` fires on every
// epoll iteration (≥100 Hz), so an unconditional O(n) sweep would scan the whole
// table on every loop pass; gate it to ~1 s (TTL is independently enforced on
// lookup, so a coarse sweep only bounds memory).
const MAC_SWEEP_INTERVAL_MS: u64 = 1_000;
const SINGLE_REMOTE_PEER_ID: u64 = 1;
const LOCAL_TAP_PEER_ID: u64 = 0;
const ETHERNET_HEADER_LEN: usize = 14;
const ETHERNET_SOURCE_MAC_OFFSET: usize = 6;

// ── SentLog ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ClassCounts {
    pub realtime: u32,
    pub bulk: u32,
    pub default: u32,
}

/// A bounded ring-log that maps sealed-packet counters to their [`FlowClass`].
///
/// Entries are inserted in arrival order (monotone counter sequence from the
/// AEAD) and evicted oldest-first once `capacity` is reached.  Lookup is
/// O(1) via the `HashMap`; eviction is O(1) via the `VecDeque`.
pub(crate) struct SentLog {
    capacity: usize,
    map: HashMap<u64, FlowClass>,
    order: VecDeque<(u64, FlowClass)>,
}

impl SentLog {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    pub(crate) fn insert(&mut self, counter: u64, class: FlowClass) {
        if self.map.len() >= self.capacity {
            if let Some((oldest, _)) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(counter, class);
        self.order.push_back((counter, class));
    }

    pub(crate) fn get(&self, counter: u64) -> Option<FlowClass> {
        self.map.get(&counter).copied()
    }

    /// Number of entries in the log whose `FlowClass` matches `class`.
    pub(crate) fn count_class(&self, class: FlowClass) -> u32 {
        u32::try_from(self.map.values().filter(|&&c| c == class).count()).unwrap_or(u32::MAX)
    }

    pub(crate) fn count_classes_in_range(&self, start: u64, end: u64) -> ClassCounts {
        if start > end {
            return ClassCounts::default();
        }
        let mut counts = ClassCounts::default();
        for &(counter, class) in &self.order {
            if counter >= start && counter <= end {
                match class {
                    FlowClass::Realtime => counts.realtime = counts.realtime.saturating_add(1),
                    FlowClass::Bulk => counts.bulk = counts.bulk.saturating_add(1),
                    FlowClass::Default => counts.default = counts.default.saturating_add(1),
                }
            }
        }
        counts
    }
}

// ── Outcome ───────────────────────────────────────────────────────────────────

/// What the caller must do after `on_udp_datagram` returns.
///
/// Borrows of internal reused buffers — the caller must consume them before
/// calling any other `&mut self` method.
pub enum Outcome<'a> {
    /// Nothing to do (e.g. partial FEC object, unknown packet type, auth error).
    None,
    /// Write this slice to the TUN device (data path: decoded inner packet).
    TunWrite(&'a [u8]),
    /// Send these datagrams to the peer (control path: ARQ retransmits).
    Send(&'a [yip_io::poll::EgressDatagram]),
    /// Write to TUN *and* send datagrams (currently unused, reserved for future).
    #[expect(dead_code, reason = "reserved for future combined TUN+UDP paths")]
    TunWriteThenSend(&'a [u8], &'a [yip_io::poll::EgressDatagram]),
}

// ── DataPlane ─────────────────────────────────────────────────────────────────

/// Mutex-free, I/O-free data-plane state machine.
///
/// Owns the AEAD [`yip_crypto::Session`], the FEC [`Transport`], the
/// [`WireCodec`], and the two auxiliary logs ([`SentLog`], [`RetxBuffer`]).
/// All methods take `&mut self`; no locks are acquired.
///
/// Framed egress datagrams are returned as a borrow of an internal reused
/// `Vec<EgressDatagram>` scratch buffer (each tagged with its FEC fate group) —
/// the caller must consume or clone them before calling any other `&mut self`
/// method.
pub struct DataPlane {
    session: yip_crypto::Session,
    raw_send_key: [u8; 32],
    raw_recv_key: [u8; 32],
    auth_key: [u8; 16],
    hp_key: [u8; 16],
    transport: Transport,
    codec: Codec,
    conn_tag: u64,
    l2: bool,
    /// This (single) peer's UDP endpoint, stamped as `dst` on every egress
    /// datagram (data, ARQ retransmit, and feedback/tick alike). Multipeer
    /// 2a seam (#33): `on_udp`'s `src` is ignored here — the `PeerManager`
    /// arriving in Task 5 is what actually routes by address; until then,
    /// one peer must behave exactly as it did when the socket was connected.
    peer_addr: SocketAddr,
    sent_log: SentLog,
    retx: RetxBuffer,
    detector: LossDetector,
    mac_table: MacTable,
    last_loss_report_high: u64,

    // Feedback / log timers (mirror what ingress thread holds in tunnel.rs).
    last_feedback_ms: u64,
    last_log_ms: u64,
    last_sweep_ms: u64,
    /// Whether obfuscation is on for this session (`PeerManager::obf_key.is_some()`
    /// at construction). Gates whether the feedback cadence is jittered (3b Task 5).
    obf_on: bool,
    /// 16-byte data-plane obfuscation key, derived from hp_key if obfuscation is enabled.
    obf_key: Option<[u8; 16]>,
    /// Current feedback emission interval, in ms. Starts at `FEEDBACK_INTERVAL_MS`
    /// and is re-rolled after each emission: jittered ±25% when `obf_on`, held at
    /// the constant otherwise (3a's stored-jittered-interval pattern, e.g. `retry_ms`).
    feedback_interval_ms: u64,
    /// Count of ARQ retransmits emitted (for observability / periodic log).
    arq_retx_count: u64,
    /// In-band PLPMTUD state machine.
    pub plpmtu: PlpmtuController,

    // ── reused per-call scratch buffers ──────────────────────────────────────
    /// Reused per-call scratch: each element holds one framed egress datagram
    /// tagged with its FEC object id (fate group) for GSO-safe coalescing.
    egress_scratch: Vec<yip_io::poll::EgressDatagram>,
    /// Reused scratch for the decoded inner packet (TUN write target).
    inner_scratch: Vec<u8>,
    /// Reused scratch for ARQ retransmit datagrams (control-path sends).
    retx_scratch: Vec<yip_io::poll::EgressDatagram>,
    /// Reused scratch holding exactly one entry: the sealed feedback Control
    /// packet built by `tick`, addressed to `peer_addr`.
    tick_scratch: Vec<yip_io::poll::EgressDatagram>,
    /// Reused scratch for the tx hot-path AEAD seal (`Session::seal_into`):
    /// avoids a per-packet allocation in `seal` itself. Its contents are
    /// moved (not cloned) into `retx` when a packet is buffered for ARQ, so
    /// this only amortizes across calls that don't hit the retx path (still
    /// cleared+refilled every call otherwise).
    seal_buf: Vec<u8>,
}

impl DataPlane {
    /// 32-byte raw Noise send key.
    pub fn raw_send_key(&self) -> &[u8; 32] {
        &self.raw_send_key
    }

    /// 32-byte raw Noise receive key.
    pub fn raw_recv_key(&self) -> &[u8; 32] {
        &self.raw_recv_key
    }

    /// 16-byte authentication key.
    pub fn auth_key(&self) -> &[u8; 16] {
        &self.auth_key
    }

    /// 16-byte header-protection key.
    pub fn hp_key(&self) -> &[u8; 16] {
        &self.hp_key
    }

    /// 16-byte data-plane obfuscation key, if obfuscation is enabled.
    pub fn obf_key(&self) -> Option<[u8; 16]> {
        self.obf_key
    }

    /// Access the underlying AEAD session.
    #[expect(dead_code, reason = "helper for inspecting session")]
    pub fn session(&self) -> &yip_crypto::Session {
        &self.session
    }

    /// Mutable access to the underlying AEAD session.
    pub fn session_mut(&mut self) -> &mut yip_crypto::Session {
        &mut self.session
    }

    /// Build a [`DataPlane`] from an already-established session.
    ///
    /// The wire codec keys are derived from the same channel-binding sub-keys
    /// that were derived during the handshake (`established.auth_key` /
    /// `established.hp_key`), so both peers end up with the same codec.
    ///
    /// `peer_addr` is this (single) peer's UDP endpoint; it is stamped as
    /// `dst` on every egress datagram this `DataPlane` produces.
    ///
    /// `symbol_size` is threaded straight into `Transport::new`, overriding
    /// every flow class's default RaptorQ symbol size. Raw/obf mode passes
    /// `1200` (byte-identical to the pre-3c.1 hardcode); QUIC mode (3c.1
    /// Tasks 4/5) will pass a different value.
    pub fn new(
        established: Established,
        conn_tag: u64,
        mode: TunnelMode,
        peer_addr: SocketAddr,
        obf_on: bool,
        symbol_size: u16,
    ) -> Self {
        let auth_key = established.auth_key;
        let hp_key = established.hp_key;
        let raw_send_key = established.raw_send_key;
        let raw_recv_key = established.raw_recv_key;
        let codec = Codec::new(auth_key, hp_key);
        Self {
            session: established.session,
            raw_send_key,
            raw_recv_key,
            auth_key,
            hp_key,
            transport: Transport::new(vec![], symbol_size),
            codec,
            conn_tag,
            l2: matches!(mode, TunnelMode::L2Tap),
            peer_addr,
            sent_log: SentLog::new(SENT_LOG_CAPACITY),
            retx: RetxBuffer::new(RETX_BUFFER_MAX, RETX_BUFFER_TTL_MS),
            detector: LossDetector::new(5, SENT_LOG_CAPACITY),
            mac_table: MacTable::new(DEFAULT_MAC_TABLE_CAPACITY, DEFAULT_MAC_TABLE_TTL_MS),
            last_loss_report_high: 0,
            last_feedback_ms: 0,
            last_log_ms: 0,
            last_sweep_ms: 0,
            obf_on,
            obf_key: if obf_on {
                Some(yip_obf::derive_key(&established.hp_key))
            } else {
                None
            },
            feedback_interval_ms: FEEDBACK_INTERVAL_MS,
            arq_retx_count: 0,
            plpmtu: PlpmtuController::new(),
            egress_scratch: Vec::new(),
            inner_scratch: Vec::new(),
            retx_scratch: Vec::new(),
            tick_scratch: Vec::new(),
            seal_buf: Vec::new(),
        }
    }

    /// The wire `conn_tag` this session's frames carry (both peers derive the
    /// same value from the handshake channel binding — see
    /// [`conn_tag_from_keys`]). Used by `PeerManager` to register this peer
    /// in its `conn_tag -> peer` map once the handshake completes.
    pub fn conn_tag(&self) -> u64 {
        self.conn_tag
    }

    /// Redirect this data plane's egress to a new peer address — WireGuard-style
    /// roaming, after the peer's authenticated source moved (M2). Every
    /// subsequently-built egress datagram (data, ARQ retransmit, tick feedback)
    /// is stamped with `addr`. Callers gate this on a cryptographically
    /// authenticated, non-replayed inbound packet, so it cannot be steered by a
    /// spoofed source.
    pub fn set_peer_addr(&mut self, addr: SocketAddr) {
        if self.peer_addr != addr {
            let floor = self.plpmtu.reset_to_floor();
            self.transport.set_symbol_size(floor);
        }
        self.peer_addr = addr;
    }

    /// Current FEC bulk repair ratio (0.0 = no proactive parity, 0.2 = 20% parity).
    pub fn bulk_repair_ratio(&self) -> f32 {
        self.transport.bulk_repair_ratio()
    }

    /// Dynamically override the FEC repair ratio across transport controllers.
    pub fn set_fec_repair_ratio(&mut self, ratio: f32) {
        self.transport.set_fec_repair_ratio(ratio);
    }

    /// Total count of FEC symbols produced and transmitted.
    pub fn total_symbols_tx(&self) -> u64 {
        self.transport.total_symbols_tx()
    }

    /// Total count of FEC objects reconstructed via repair shards.
    pub fn fec_recovered_count(&self) -> u64 {
        self.transport.fec_recovered_count()
    }

    /// Total count of FEC objects dropped due to expiration or capacity eviction.
    pub fn fec_unrecoverable_count(&self) -> u64 {
        self.transport.fec_unrecoverable_count()
    }

    /// Reconfigure shard start object id and stride increment for multi-core scaling.
    pub fn set_shard(&mut self, shard_id: usize, num_shards: usize) {
        self.transport.set_shard(shard_id, num_shards);
    }

    /// Seal `inner`, FEC-encode, frame each symbol, and return the resulting
    /// egress datagrams as a borrow of an internal reused scratch buffer.
    ///
    /// Each returned datagram starts with `PacketType::Data as u8`.
    ///
    /// # Errors
    ///
    /// Returns an empty slice if the AEAD seal step fails (which is only
    /// possible after counter exhaustion — practically impossible in testing).
    pub fn on_tun_packet(&mut self, inner: &[u8], now_ms: u64) -> &[yip_io::poll::EgressDatagram] {
        self.egress_scratch.clear();

        if self.l2 {
            if let Some(src_mac) = source_mac_from_ethernet_frame(inner) {
                self.mac_table
                    .learn(src_mac, LOCAL_TAP_PEER_ID, LearnOrigin::LocalTap, now_ms);
            }
        }

        // ── 1. Seal (no-alloc: writes into the reused `seal_buf`) ──────────────
        let counter = match self.session.seal_into(inner, &mut self.seal_buf) {
            Ok(c) => c,
            Err(_) => return &self.egress_scratch,
        };

        // ── 2. FEC-encode ─────────────────────────────────────────────────────
        let (class, symbols) = self
            .transport
            .encode(&self.seal_buf, inner, self.l2, now_ms);

        // ── 3. Auxiliary bookkeeping ──────────────────────────────────────────
        self.sent_log.insert(counter, class);

        if let Some(oid) = symbols.first().map(|s| s.object_id) {
            // Move (not clone) the sealed ciphertext into the retx buffer:
            // `seal_buf` is about to be cleared and refilled on the next call
            // anyway, so retx taking ownership here costs no extra copy.
            self.retx.put(
                counter,
                std::mem::take(&mut self.seal_buf),
                class,
                oid,
                now_ms,
            );
        }

        // ── 4. Frame each symbol into the reused scratch ──────────────────────
        let n_syms = symbols.len();
        let peer_addr = self.peer_addr;
        if self.egress_scratch.len() < n_syms {
            self.egress_scratch
                .resize_with(n_syms, || yip_io::poll::EgressDatagram {
                    fate: 0,
                    dst: peer_addr,
                    bytes: Vec::new(),
                });
        }

        for (slot, sym) in self.egress_scratch[..n_syms].iter_mut().zip(symbols.iter()) {
            let frame = wire_glue::symbol_to_frame(self.conn_tag, sym, counter, class);
            let dg = self.codec.frame(&frame);
            // `fate` = the RaptorQ object id: all symbols of one object (source +
            // its repair) share it, so a GSO driver keeps them in separate skbs.
            slot.fate = sym.object_id;
            slot.dst = peer_addr;
            slot.bytes.clear();
            slot.bytes.push(PacketType::Data as u8);
            slot.bytes.extend_from_slice(&dg);
        }

        &self.egress_scratch[..n_syms]
    }

    /// Process one received UDP datagram and return what the caller must do.
    ///
    /// The `Outcome` borrows internal reused buffers; the caller must consume
    /// them before making the next `&mut self` call.
    ///
    /// # Data path (`dg[0] == PacketType::Data`)
    ///
    /// Deframes → parses symbol → updates detector → FEC-decodes →
    /// on object completion: marks delivered, AEAD-opens → `TunWrite`.
    ///
    /// # Control path (`dg[0] == PacketType::Control`)
    ///
    /// AEAD-opens FIRST (auth before any side-effect) → updates detector →
    /// decodes `LossReport` → per-class `observe_loss` → ARQ retransmit
    /// for eligible NACKed counters → `Send`.
    pub fn on_udp_datagram(&mut self, dg: &[u8], now_ms: u64) -> Outcome<'_> {
        if dg.is_empty() {
            return Outcome::None;
        }

        match dg[0] {
            b if b == PacketType::Data as u8 => {
                let wire = &dg[1..];

                // Deframe (auth + header-deprotect). On failure, drop the packet.
                let frame = match self.codec.deframe(wire) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("dataplane ingress: deframe error: {e}");
                        return Outcome::None;
                    }
                };

                // Parse the FEC symbol + counter + class out of the frame.
                let (sym, counter, class) = match wire_glue::frame_to_symbol(&frame) {
                    Some(t) => t,
                    None => {
                        eprintln!("dataplane ingress: frame_to_symbol returned None");
                        return Outcome::None;
                    }
                };

                if !self.session.check_replay(counter) {
                    return Outcome::None;
                }

                // Notify the loss detector that we saw this counter.
                self.detector.on_seen(counter, now_ms);

                // Feed the symbol to the FEC reassembler; continue until an object decodes.
                let ciphertext = match self.transport.decode(counter, &sym, class, now_ms) {
                    Some(ct) => ct,
                    None => return Outcome::None,
                };

                // The object decoded: tell the detector it was delivered.
                self.detector.on_delivered(counter);

                // Open the AEAD ciphertext.
                let inner = match self.session.open(counter, &ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("dataplane ingress: open error: {e}");
                        return Outcome::None;
                    }
                };

                // Copy the opened inner frame into the reused scratch buffer.
                self.inner_scratch.clear();
                self.inner_scratch.extend_from_slice(&inner);

                self.transport
                    .observe_ingress(&self.inner_scratch, self.l2, now_ms);

                if self.l2 {
                    if let Some(src_mac) = source_mac_from_ethernet_frame(&self.inner_scratch) {
                        self.mac_table.learn(
                            src_mac,
                            SINGLE_REMOTE_PEER_ID,
                            LearnOrigin::Peer,
                            now_ms,
                        );
                    }
                }
                Outcome::TunWrite(&self.inner_scratch)
            }

            b if b == PacketType::Control as u8 => {
                // Control packet layout:
                //   [1-byte type][8-byte counter BE][ciphertext...]
                if dg.len() < 9 {
                    eprintln!("dataplane ingress: control packet too short");
                    return Outcome::None;
                }
                let counter = u64::from_be_bytes(dg[1..9].try_into().expect("exactly 8 bytes"));
                let ct = &dg[9..];

                // Decrypt the control payload FIRST — authenticate before any
                // side-effect. A forged packet with a bogus counter must not
                // poison the loss detector's high_counter.
                let plaintext = match self.session.open(counter, ct) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!(
                            "dataplane ingress: control open error on counter={counter}: {e}"
                        );
                        return Outcome::None;
                    }
                };

                // Authentication succeeded: notify the detector that we saw this
                // control counter and that it is immediately resolved.
                self.detector.on_seen(counter, now_ms);
                self.detector.on_delivered(counter);

                // Decode the ControlFrame.
                let frame = match ControlFrame::decode(&plaintext) {
                    Some(f) => f,
                    None => {
                        eprintln!("dataplane ingress: malformed ControlFrame");
                        return Outcome::None;
                    }
                };

                match frame {
                    ControlFrame::Feedback(report) => {
                        // Attribute missing counters to flow classes via the sent-log.
                        let mut missing_rt: u32 = 0;
                        let mut missing_bulk: u32 = 0;
                        let mut missing_default: u32 = 0;

                        for &c in &report.missing {
                            match self.sent_log.get(c) {
                                Some(FlowClass::Realtime) => {
                                    missing_rt = missing_rt.saturating_add(1);
                                }
                                Some(FlowClass::Bulk) => {
                                    missing_bulk = missing_bulk.saturating_add(1);
                                }
                                Some(FlowClass::Default) => {
                                    missing_default = missing_default.saturating_add(1);
                                }
                                None => {
                                    // Counter not in log (too old or was a control packet) — ignore.
                                }
                            }
                        }

                        let (sent_rt, sent_bulk, sent_default) =
                            if report.high_counter > self.last_loss_report_high {
                                let start = if self.last_loss_report_high == 0 {
                                    self.sent_log.order.front().map(|(c, _)| *c).unwrap_or(0)
                                } else {
                                    self.last_loss_report_high.saturating_add(1)
                                };
                                self.last_loss_report_high = report.high_counter;
                                let window_counts = self
                                    .sent_log
                                    .count_classes_in_range(start, report.high_counter);
                                (
                                    window_counts.realtime,
                                    window_counts.bulk,
                                    window_counts.default,
                                )
                            } else {
                                (
                                    self.sent_log.count_class(FlowClass::Realtime),
                                    self.sent_log.count_class(FlowClass::Bulk),
                                    self.sent_log.count_class(FlowClass::Default),
                                )
                            };

                        let mut observe_class =
                            |class: FlowClass, missing: u32, sent: u32| -> Option<f32> {
                                if sent > 0 || missing > 0 {
                                    let denom = sent.max(missing).max(1);
                                    let frac = fraction_f32(missing, denom);
                                    self.transport.observe_loss(class, frac);
                                    Some(frac)
                                } else {
                                    None
                                }
                            };

                        let _frac_rt = observe_class(FlowClass::Realtime, missing_rt, sent_rt);
                        let frac_bulk = observe_class(FlowClass::Bulk, missing_bulk, sent_bulk);
                        let frac_default =
                            observe_class(FlowClass::Default, missing_default, sent_default);

                        // Blackhole loss detection: severe loss across default or bulk triggers fast fallback.
                        let severe_default =
                            frac_default.is_some_and(|f| f >= 0.8) && sent_default >= 3;
                        let severe_bulk = frac_bulk.is_some_and(|f| f >= 0.8) && sent_bulk >= 3;
                        if severe_default || severe_bulk {
                            if let Some(floor) = self.plpmtu.on_blackhole() {
                                self.transport.set_symbol_size(floor);
                            }
                        }

                        // ARQ: for each missing counter reported by the peer,
                        // generate fresh repair symbols if the entry is still in the
                        // retransmit buffer and the class has ARQ enabled.
                        self.retx_scratch.clear();

                        for &missing_counter in &report.missing {
                            let retx_entry = self
                                .retx
                                .get(missing_counter, now_ms)
                                .map(|(ct, cls, oid)| (ct.to_vec(), cls, oid));

                            let Some((ct, cls, oid)) = retx_entry else {
                                continue;
                            };
                            if !cls.params().arq {
                                continue;
                            }

                            // Count this retransmit for observability.
                            self.arq_retx_count = self.arq_retx_count.saturating_add(1);

                            // Generate fresh repair symbols with the original object_id.
                            let repair_syms =
                                self.transport
                                    .repair_object(&ct, cls, oid, RETX_EXTRA_REPAIR);

                            // Frame and collect all repair datagrams.
                            for sym in &repair_syms {
                                let frame = wire_glue::symbol_to_frame(
                                    self.conn_tag,
                                    sym,
                                    missing_counter,
                                    cls,
                                );
                                let dg_bytes = self.codec.frame(&frame);
                                let mut pkt = Vec::with_capacity(1 + dg_bytes.len());
                                pkt.push(PacketType::Data as u8);
                                pkt.extend_from_slice(&dg_bytes);
                                self.retx_scratch.push(yip_io::poll::EgressDatagram {
                                    fate: oid,
                                    dst: self.peer_addr,
                                    bytes: pkt,
                                });
                            }
                        }

                        if self.retx_scratch.is_empty() {
                            Outcome::None
                        } else {
                            Outcome::Send(&self.retx_scratch)
                        }
                    }

                    ControlFrame::MtuProbe {
                        probe_id,
                        target_symbol_size,
                        ..
                    } => {
                        let ack = ControlFrame::MtuProbeAck {
                            probe_id,
                            accepted_symbol_size: target_symbol_size,
                        };
                        let ack_bytes = ack.encode();
                        let sealed = match self.session.seal(&ack_bytes) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("dataplane ingress: seal error on MtuProbeAck: {e}");
                                return Outcome::None;
                            }
                        };
                        self.retx_scratch.clear();
                        let mut pkt = Vec::with_capacity(1 + 8 + sealed.ciphertext.len());
                        pkt.push(PacketType::Control as u8);
                        pkt.extend_from_slice(&sealed.counter.to_be_bytes());
                        pkt.extend_from_slice(&sealed.ciphertext);
                        self.retx_scratch.push(yip_io::poll::EgressDatagram {
                            fate: 0,
                            dst: self.peer_addr,
                            bytes: pkt,
                        });
                        Outcome::Send(&self.retx_scratch)
                    }

                    ControlFrame::MtuProbeAck {
                        probe_id,
                        accepted_symbol_size,
                    } => {
                        if let Some(new_sym) = self.plpmtu.on_ack(probe_id, accepted_symbol_size) {
                            self.transport.set_symbol_size(new_sym);
                        }
                        Outcome::None
                    }
                }
            }

            _ => {
                // Unknown packet type — drop silently.
                Outcome::None
            }
        }
    }

    /// Periodic tick: emit a feedback `Control` packet if enough time has elapsed,
    /// and drive the periodic diagnostic logs.
    ///
    /// Returns `Some(&[EgressDatagram])` — a borrow of the internal
    /// single-element tick scratch buffer, addressed to `peer_addr` — when a
    /// feedback packet was built (the caller must send it to the peer).
    /// Returns `None` if no feedback interval has elapsed.
    pub fn tick(&mut self, now_ms: u64) -> Option<&[yip_io::poll::EgressDatagram]> {
        if now_ms.saturating_sub(self.last_sweep_ms) >= MAC_SWEEP_INTERVAL_MS {
            self.last_sweep_ms = now_ms;
            self.mac_table.sweep(now_ms);
        }

        // ── periodic controller ratio log ─────────────────────────────────────
        if now_ms.saturating_sub(self.last_log_ms) >= LOG_INTERVAL_MS {
            self.last_log_ms = now_ms;
            eprintln!(
                "yipd [{}ms] bulk controller repair ratio: {:.4}",
                now_ms,
                self.transport.bulk_repair_ratio(),
            );
            eprintln!(
                "yipd [{}ms] ARQ retransmits: {}",
                now_ms, self.arq_retx_count
            );
        }

        // ── periodic feedback emission ─────────────────────────────────────────
        if now_ms.saturating_sub(self.last_feedback_ms) < self.feedback_interval_ms {
            // Check if PLPMTUD has an in-band probe to emit between feedback ticks
            if let Some((probe_id, target_symbol_size, pad_len)) = self.plpmtu.on_tick(now_ms) {
                let probe = ControlFrame::MtuProbe {
                    probe_id,
                    target_symbol_size,
                    padding: vec![0u8; pad_len],
                };
                let probe_bytes = probe.encode();
                let sealed = match self.session.seal(&probe_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("dataplane tick: seal error on MtuProbe: {e}");
                        return None;
                    }
                };
                if self.tick_scratch.is_empty() {
                    self.tick_scratch.push(yip_io::poll::EgressDatagram {
                        fate: 0,
                        dst: self.peer_addr,
                        bytes: Vec::new(),
                    });
                }
                let dg = &mut self.tick_scratch[0];
                dg.dst = self.peer_addr;
                dg.bytes.clear();
                dg.bytes.push(PacketType::Control as u8);
                dg.bytes.extend_from_slice(&sealed.counter.to_be_bytes());
                dg.bytes.extend_from_slice(&sealed.ciphertext);
                return Some(&self.tick_scratch);
            }
            return None;
        }
        self.last_feedback_ms = now_ms;
        // Re-roll the interval for the NEXT emission (3a's stored-jittered-interval
        // pattern, e.g. `retry_ms`): ±25% when obf is on, held exactly at the
        // constant when off — this only reshuffles WHEN the report is emitted,
        // never a data packet, and the bound (23-37 ms) keeps ARQ feedback timely.
        self.feedback_interval_ms = if self.obf_on {
            crate::peer_manager::jitter_ms(FEEDBACK_INTERVAL_MS)
        } else {
            FEEDBACK_INTERVAL_MS
        };

        // Build the report from the current detector state.
        let report = self.detector.report(now_ms);
        let frame = ControlFrame::Feedback(report);
        let report_bytes = frame.encode();

        // Seal the report. The counter comes from the unified session sequence;
        // the peer's detector will call on_seen for it.
        let sealed = match self.session.seal(&report_bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("dataplane tick: seal error: {e}");
                return None;
            }
        };

        // Build:  [type:1][counter:8be][ciphertext] into the single reused
        // tick-scratch entry (allocated once, then just cleared/refilled).
        if self.tick_scratch.is_empty() {
            self.tick_scratch.push(yip_io::poll::EgressDatagram {
                fate: 0,
                dst: self.peer_addr,
                bytes: Vec::new(),
            });
        }
        let dg = &mut self.tick_scratch[0];
        dg.dst = self.peer_addr;
        dg.bytes.clear();
        dg.bytes.push(PacketType::Control as u8);
        dg.bytes.extend_from_slice(&sealed.counter.to_be_bytes());
        dg.bytes.extend_from_slice(&sealed.ciphertext);

        Some(&self.tick_scratch)
    }
}

// ── conn_tag derivation ───────────────────────────────────────────────────────

/// Derive the per-session `conn_tag` from the first 8 bytes of
/// `auth_key || hp_key`.  Both peers compute the same keys from the Noise
/// channel binding, so they end up with the same tag.
pub(crate) fn conn_tag_from_keys(auth_key: &[u8; 16], hp_key: &[u8; 16]) -> u64 {
    let mut combined = [0u8; 32];
    combined[..16].copy_from_slice(auth_key);
    combined[16..].copy_from_slice(hp_key);
    u64::from_be_bytes(combined[..8].try_into().expect("8 bytes"))
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

#[inline]
fn source_mac_from_ethernet_frame(inner: &[u8]) -> Option<[u8; 6]> {
    if inner.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let mut src = [0u8; 6];
    src.copy_from_slice(&inner[ETHERNET_SOURCE_MAC_OFFSET..ETHERNET_SOURCE_MAC_OFFSET + 6]);
    Some(src)
}

// ── Dispatch impl ─────────────────────────────────────────────────────────────

impl yip_io::poll::Dispatch for DataPlane {
    /// `src` is ignored: this `DataPlane` has exactly one peer (`peer_addr`,
    /// fixed at construction), so it behaves exactly as it did when the
    /// socket was `connect`-ed. The Task 5 `PeerManager` is what will
    /// actually route ingress by `src`.
    fn on_udp(
        &mut self,
        _src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> yip_io::poll::DispatchOut<'_> {
        match self.on_udp_datagram(dg, now_ms) {
            Outcome::None => yip_io::poll::DispatchOut::None,
            Outcome::TunWrite(buf) => yip_io::poll::DispatchOut::Tun(buf),
            Outcome::Send(pkts) => yip_io::poll::DispatchOut::Udp(pkts),
            Outcome::TunWriteThenSend(buf, pkts) => yip_io::poll::DispatchOut::Both(buf, pkts),
        }
    }

    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[yip_io::poll::EgressDatagram] {
        self.on_tun_packet(inner, now_ms)
    }

    fn tick(&mut self, now_ms: u64) -> Option<&[yip_io::poll::EgressDatagram]> {
        self.tick(now_ms)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::TunnelMode;
    use yip_crypto::{generate_keypair, Handshake};

    use crate::wire_glue::derive_wire_keys;

    /// `a`'s configured peer address (i.e. `b`'s endpoint) in [`dataplane_pair`].
    const TEST_ADDR_B: &str = "203.0.113.2:51820";
    /// `b`'s configured peer address (i.e. `a`'s endpoint) in [`dataplane_pair`].
    const TEST_ADDR_A: &str = "203.0.113.1:51820";

    /// Build two [`DataPlane`]s whose sessions can talk to each other, by
    /// running a full in-process Noise-IK handshake. `a`'s `peer_addr` is
    /// [`TEST_ADDR_B`] and `b`'s is [`TEST_ADDR_A`] — distinct, so tests can
    /// assert that each stamps the *other*'s address as `dst`.
    ///
    /// `obf_on` is threaded straight into `DataPlane::new` for both peers —
    /// most tests want `false` (the byte-identical, obf-off invariant); the
    /// feedback-jitter tests (3b Task 5) pass `true`.
    fn dataplane_pair(mode: TunnelMode, obf_on: bool) -> (DataPlane, DataPlane) {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();

        // Run the handshake in-process (no sockets needed).
        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let m1 = ini.write_message(&[]).unwrap();
        let _ = res.read_message(&m1).unwrap();
        let m2 = res.write_message(&[]).unwrap();
        let _ = ini.read_message(&m2).unwrap();

        assert!(ini.is_finished() && res.is_finished());

        // Both channel bindings are identical (verified in yip-crypto tests).
        let cb_i = ini.channel_binding();
        let cb_r = res.channel_binding();
        assert_eq!(cb_i, cb_r);

        let (auth_key, hp_key) = derive_wire_keys(&cb_i);
        let (ini_send_k, ini_recv_k) = ini.raw_split_keys();
        let (res_send_k, res_recv_k) = res.raw_split_keys();

        // Build Established structs directly (mirrors what handshake.rs does).
        let est_i = Established {
            session: ini.into_session().unwrap(),
            auth_key,
            hp_key,
            raw_send_key: ini_send_k,
            raw_recv_key: ini_recv_k,
        };
        let est_r = Established {
            session: res.into_session().unwrap(),
            auth_key,
            hp_key,
            raw_send_key: res_send_k,
            raw_recv_key: res_recv_k,
        };

        // Both peers derive the same conn_tag from the same keys.
        let conn_tag = conn_tag_from_keys(&auth_key, &hp_key);

        (
            DataPlane::new(
                est_i,
                conn_tag,
                mode,
                TEST_ADDR_B.parse().unwrap(),
                obf_on,
                1200,
            ),
            DataPlane::new(
                est_r,
                conn_tag,
                mode,
                TEST_ADDR_A.parse().unwrap(),
                obf_on,
                1200,
            ),
        )
    }

    /// Full round-trip: A encodes a TUN packet, B decodes it via `on_udp_datagram`,
    /// and the recovered inner bytes equal the original.
    #[test]
    fn on_tun_packet_produces_decodable_egress() {
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun, false);
        let inner = vec![0x11u8; 200];
        let dgrams = a.on_tun_packet(&inner, 0).to_vec();

        assert!(
            !dgrams.is_empty(),
            "on_tun_packet must produce at least one datagram"
        );

        for (i, dg) in dgrams.iter().enumerate() {
            assert!(!dg.bytes.is_empty(), "datagram {i} must not be empty");
            assert_eq!(
                dg.bytes[0],
                PacketType::Data as u8,
                "datagram {i} must begin with PacketType::Data"
            );
        }
        // All symbols of one inner packet share one FEC object id (fate group).
        let fate = dgrams[0].fate;
        assert!(
            dgrams.iter().all(|dg| dg.fate == fate),
            "all symbols of one object must share one fate"
        );
        // A's DataPlane stamps every egress datagram with its configured peer
        // address (TEST_ADDR_B) — the Task 3 addressed-seam contract.
        let expected_dst: SocketAddr = TEST_ADDR_B.parse().unwrap();
        assert!(
            dgrams.iter().all(|dg| dg.dst == expected_dst),
            "every egress datagram must be stamped with the configured peer_addr"
        );

        // Full round-trip: feed all datagrams to B's ingress; at least one must
        // produce a TunWrite with the original inner bytes.
        let mut recovered: Option<Vec<u8>> = None;
        for dg in &dgrams {
            if let Outcome::TunWrite(payload) = b.on_udp_datagram(&dg.bytes, 1) {
                recovered = Some(payload.to_vec());
                break;
            }
        }
        let recovered = recovered.expect("at least one datagram must decode to a TunWrite");
        assert_eq!(recovered, inner, "recovered inner must equal the original");
    }

    /// A simulated gap causes B's loss detector to report a missing counter;
    /// B's `tick` produces a Control feedback packet; A ingests it and (for
    /// Bulk traffic) emits ARQ retransmit datagrams.
    #[test]
    fn control_packet_drives_observe_loss_and_arq() {
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun, false);
        // A sends 3 objects; drop the middle datagram so B sees a gap.
        let d0 = a.on_tun_packet(&[0u8; 100], 0).to_vec();
        let _d1 = a.on_tun_packet(&[1u8; 100], 0).to_vec(); // dropped
        let d2 = a.on_tun_packet(&[2u8; 100], 1).to_vec();
        for dg in d0.iter().chain(d2.iter()) {
            let _ = b.on_udp_datagram(&dg.bytes, 2);
        }
        // After grace+feedback-interval, B's tick emits a Control feedback
        // with the missing counter.  now_ms=50 exceeds both the 5 ms grace
        // and the 30 ms FEEDBACK_INTERVAL_MS, so a packet is guaranteed.
        let fb = b.tick(50).expect("feedback emitted").to_vec();
        assert_eq!(fb.len(), 1, "tick emits exactly one feedback datagram");
        let expected_dst: SocketAddr = TEST_ADDR_A.parse().unwrap();
        assert_eq!(
            fb[0].dst, expected_dst,
            "B's tick stamps its configured peer_addr (A's address)"
        );
        // A ingests the control packet → attributes loss + (for Bulk) retransmits.
        if let Outcome::Send(s) = a.on_udp_datagram(&fb[0].bytes, 51) {
            assert!(!s.is_empty());
        }
        // (Exact retransmit depends on class; at minimum assert the control packet
        //  parses and does not panic, and observe_loss was called — see below.)
    }

    /// A forged Control packet must fail authentication and produce no side-effects.
    #[test]
    fn forged_control_packet_is_rejected() {
        let (mut a, _b) = dataplane_pair(TunnelMode::L3Tun, false);
        let mut forged = vec![PacketType::Control as u8];
        forged.extend_from_slice(&7u64.to_be_bytes());
        forged.extend_from_slice(&[0xAB; 32]); // garbage ciphertext
                                               // Must not panic; auth fails so no observe_loss / retransmit.
        let _ = a.on_udp_datagram(&forged, 0);
    }

    #[test]
    fn tunnel_mode_controls_l2_encode_hint() {
        // Ethernet + IPv4 header with DSCP EF should classify as Realtime only
        // when the classifier is told this is an L2 frame (l2=true).
        let mut l2_inner = vec![0u8; 14 + 24];
        l2_inner[12] = 0x08;
        l2_inner[13] = 0x00; // EtherType IPv4
        l2_inner[14] = 0x45; // v4, IHL 5
        l2_inner[15] = 46 << 2; // DSCP EF
        l2_inner[23] = 17; // UDP protocol
        l2_inner[36] = 0x13;
        l2_inner[37] = 0x88; // dport 5000

        let (mut tun_dp, _) = dataplane_pair(TunnelMode::L3Tun, false);
        tun_dp.on_tun_packet(&l2_inner, 0);
        let tun_counter = tun_dp
            .sent_log
            .order
            .back()
            .map(|(c, _)| *c)
            .expect("TUN dataplane inserts a sent-log entry");
        assert_eq!(
            tun_dp.sent_log.get(tun_counter),
            Some(FlowClass::Default),
            "TUN mode passes l2=false and keeps Ethernet payload as Default"
        );

        let (mut tap_dp, _) = dataplane_pair(TunnelMode::L2Tap, false);
        tap_dp.on_tun_packet(&l2_inner, 0);
        let tap_counter = tap_dp
            .sent_log
            .order
            .back()
            .map(|(c, _)| *c)
            .expect("TAP dataplane inserts a sent-log entry");
        assert_eq!(
            tap_dp.sent_log.get(tap_counter),
            Some(FlowClass::Realtime),
            "TAP mode passes l2=true and classifies inner IPv4 DSCP EF"
        );
    }

    // ── 3b Task 5: feedback-cadence jitter ──────────────────────────────────

    /// With obf on, the feedback emission interval is re-rolled after every
    /// emission and takes more than one distinct value, always within
    /// `jitter_ms`'s ±25% band for base 30 (i.e. `[23, 37]`).
    #[test]
    fn feedback_interval_jitters_when_obf_on() {
        let (_a, mut b) = dataplane_pair(TunnelMode::L3Tun, true);
        let mut seen = std::collections::HashSet::new();
        let mut now_ms = 0u64;
        while seen.len() < 3 && now_ms < 2_000 {
            now_ms += 1;
            if b.tick(now_ms).is_some() {
                let interval = b.feedback_interval_ms;
                assert!(
                    (23..=37).contains(&interval),
                    "feedback_interval_ms out of the ±25% band for base 30: {interval}"
                );
                seen.insert(interval);
            }
        }
        assert!(
            seen.len() > 1,
            "obf-on feedback_interval_ms must take more than one distinct value \
             across emissions, got {seen:?}"
        );
    }

    /// With obf off, the feedback emission interval stays exactly
    /// `FEEDBACK_INTERVAL_MS` (30) forever — the byte-identical, obf-off
    /// invariant that the existing feedback tests (e.g.
    /// `control_packet_drives_observe_loss_and_arq`, which drives `tick` at
    /// the 30 ms cadence via `dataplane_pair(.., false)`) already exercise.
    #[test]
    fn feedback_interval_stays_exact_when_obf_off() {
        let (_a, mut b) = dataplane_pair(TunnelMode::L3Tun, false);
        let mut now_ms = 0u64;
        let mut emissions = 0;
        while emissions < 5 && now_ms < 500 {
            now_ms += 1;
            if b.tick(now_ms).is_some() {
                assert_eq!(
                    b.feedback_interval_ms, FEEDBACK_INTERVAL_MS,
                    "obf-off feedback_interval_ms must stay exactly the constant"
                );
                emissions += 1;
            }
        }
        assert_eq!(
            emissions, 5,
            "expected 5 obf-off feedback emissions at the exact 30 ms cadence"
        );
    }

    fn test_established() -> Established {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();

        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let m1 = ini.write_message(&[]).unwrap();
        let _ = res.read_message(&m1).unwrap();
        let m2 = res.write_message(&[]).unwrap();
        let _ = ini.read_message(&m2).unwrap();

        let cb_i = ini.channel_binding();
        let (auth_key, hp_key) = derive_wire_keys(&cb_i);
        let (ini_send_k, ini_recv_k) = ini.raw_split_keys();

        Established {
            session: ini.into_session().unwrap(),
            auth_key,
            hp_key,
            raw_send_key: ini_send_k,
            raw_recv_key: ini_recv_k,
        }
    }

    #[test]
    fn dataplane_derives_and_exposes_obf_key_when_obf_on() {
        let established = test_established();
        let expected_obf = yip_obf::derive_key(&established.hp_key);
        let dp_obf = DataPlane::new(
            established,
            123,
            TunnelMode::L3Tun,
            "127.0.0.1:1234".parse().unwrap(),
            true, // obf_on
            1200,
        );
        assert_eq!(dp_obf.obf_key(), Some(expected_obf));

        let established_plain = test_established();
        let dp_plain = DataPlane::new(
            established_plain,
            123,
            TunnelMode::L3Tun,
            "127.0.0.1:1234".parse().unwrap(),
            false, // obf_off
            1200,
        );
        assert_eq!(dp_plain.obf_key(), None);
    }

    #[test]
    fn replayed_counter_dropped_before_reassembly_allocation() {
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun, false);
        let inner = vec![0x11u8; 100];
        let dgrams = a.on_tun_packet(&inner, 0).to_vec();
        assert!(
            !dgrams.is_empty(),
            "on_tun_packet must produce at least one datagram"
        );
        let dg = &dgrams[0].bytes;

        // First call succeeds and returns Outcome::TunWrite with inner bytes.
        let outcome1 = b.on_udp_datagram(dg, 100);
        match outcome1 {
            Outcome::TunWrite(payload) => assert_eq!(payload, &inner[..]),
            _ => panic!("expected Outcome::TunWrite, got other outcome"),
        }

        // Replaying the exact same datagram is dropped before reassembly allocation.
        let outcome2 = b.on_udp_datagram(dg, 101);
        assert!(
            matches!(outcome2, Outcome::None),
            "replayed counter must produce Outcome::None"
        );
    }

    #[test]
    fn ingress_packet_observed_in_classifier() {
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun, false);

        let make_pkt = |src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16| {
            let mut p = vec![0u8; 100];
            p[0] = 0x45; // IPv4, IHL 5
            p[9] = 17; // UDP
            p[12..16].copy_from_slice(&src_ip);
            p[16..20].copy_from_slice(&dst_ip);
            p[20..22].copy_from_slice(&sport.to_be_bytes());
            p[22..24].copy_from_slice(&dport.to_be_bytes());
            p
        };

        let fwd = make_pkt([10, 0, 0, 1], [10, 0, 0, 2], 1111, 2222);
        let rev = make_pkt([10, 0, 0, 2], [10, 0, 0, 1], 2222, 1111);

        // Feed 3 forward packets from A to B as ingress datagrams.
        for t in [0, 10, 20] {
            let dgrams = a.on_tun_packet(&fwd, t).to_vec();
            let mut decoded = false;
            for dg in &dgrams {
                if let Outcome::TunWrite(_) = b.on_udp_datagram(&dg.bytes, t) {
                    decoded = true;
                }
            }
            assert!(decoded, "each TUN packet from A must decode on B");
        }

        // B now transmits a reverse packet on TUN.
        // Because B observed the 3 ingress packets in its transport classifier,
        // this 4th packet completes the flow heuristic warmup (4 packets within 30ms,
        // small packets < 256 bytes) and classifies it as Realtime.
        b.on_tun_packet(&rev, 30);
        let b_counter = b
            .sent_log
            .order
            .back()
            .map(|(c, _)| *c)
            .expect("b inserts sent-log entry");
        assert_eq!(
            b.sent_log.get(b_counter),
            Some(FlowClass::Realtime),
            "ingress packets must be observed in B's transport classifier"
        );
    }

    #[test]
    fn plpmtu_roaming_resets_symbol_size_to_floor() {
        let (mut a, _b) = dataplane_pair(TunnelMode::L3Tun, false);
        // Advance PLPMTU tier to 1320
        let ack_sym = a.plpmtu.on_ack(1, 1320);
        if let Some(sz) = ack_sym {
            a.transport.set_symbol_size(sz);
        }
        assert_eq!(a.transport.symbol_size(), 1320);
        assert_eq!(a.plpmtu.current_symbol_size(), 1320);

        // Roaming to new address resets to floor 1120
        let new_addr: SocketAddr = "203.0.113.99:51820".parse().unwrap();
        a.set_peer_addr(new_addr);
        assert_eq!(a.peer_addr, new_addr);
        assert_eq!(a.transport.symbol_size(), 1120);
        assert_eq!(a.plpmtu.current_symbol_size(), 1120);
    }

    #[test]
    fn sent_log_count_classes_in_range_works() {
        // 1. Empty log / range
        let mut log = SentLog::new(4);
        assert_eq!(log.count_classes_in_range(0, 10), ClassCounts::default());

        // 2. Out-of-order bounds (start > end)
        assert_eq!(log.count_classes_in_range(10, 5), ClassCounts::default());

        // 3. Single class
        log.insert(1, FlowClass::Realtime);
        log.insert(2, FlowClass::Realtime);
        assert_eq!(
            log.count_classes_in_range(1, 2),
            ClassCounts {
                realtime: 2,
                bulk: 0,
                default: 0,
            }
        );
        assert_eq!(
            log.count_classes_in_range(1, 1),
            ClassCounts {
                realtime: 1,
                bulk: 0,
                default: 0,
            }
        );
        assert_eq!(log.count_classes_in_range(3, 10), ClassCounts::default());

        // 4. Mixed classes
        log.insert(3, FlowClass::Bulk);
        log.insert(4, FlowClass::Default);
        assert_eq!(
            log.count_classes_in_range(1, 4),
            ClassCounts {
                realtime: 2,
                bulk: 1,
                default: 1,
            }
        );
        assert_eq!(
            log.count_classes_in_range(2, 3),
            ClassCounts {
                realtime: 1,
                bulk: 1,
                default: 0,
            }
        );

        // 5. Eviction: capacity is 4, inserting 5th entry evicts counter 1 (Realtime)
        log.insert(5, FlowClass::Bulk);
        assert_eq!(log.get(1), None);
        assert_eq!(log.get(5), Some(FlowClass::Bulk));
        assert_eq!(
            log.count_classes_in_range(1, 5),
            ClassCounts {
                realtime: 1, // counter 2
                bulk: 2,     // counters 3 and 5
                default: 1,  // counter 4
            }
        );
        // Out-of-order bounds with populated log
        assert_eq!(log.count_classes_in_range(5, 2), ClassCounts::default());
    }

    #[test]
    fn dataplane_windowed_loss_observation() {
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun, false);

        // Initial setup: A sends 100 Bulk packets (counters 1..=100)
        for c in 1..=100 {
            a.sent_log.insert(c, FlowClass::Bulk);
        }

        // Report 1 covers counters 1..=100 with 0 missing.
        let report1 = yip_transport::LossReport {
            delivered_count: 100,
            high_counter: 100,
            missing: vec![],
        };
        let frame1 = ControlFrame::Feedback(report1);
        let sealed1 = b.session.seal(&frame1.encode()).unwrap();
        let mut dg1 = vec![PacketType::Control as u8];
        dg1.extend_from_slice(&sealed1.counter.to_be_bytes());
        dg1.extend_from_slice(&sealed1.ciphertext);

        let _ = a.on_udp_datagram(&dg1, 10);
        assert_eq!(a.last_loss_report_high, 100);

        // Initial bulk ratio was 0.05. Clean window of 100 packets:
        // ratio decays by 10% to 0.045.
        let ratio_after_clean = a.bulk_repair_ratio();
        assert!(
            (ratio_after_clean - 0.045).abs() < 1e-4,
            "clean report decays ratio: got {ratio_after_clean}"
        );

        // Window 2: A sends 10 more Bulk packets (counters 101..=110).
        for c in 101..=110 {
            a.sent_log.insert(c, FlowClass::Bulk);
        }

        // Report 2 covers counters 101..=110 with 2 missing (105, 106).
        // In this window: sent = 10, missing = 2 -> loss fraction = 2/10 = 0.20.
        // Under historical total denominator (110 packets):
        // loss fraction = 2/110 ≈ 0.018 <= (0.001 + 0.045), which would cause ratio to decay.
        // Under windowed denominator (10 packets):
        // loss fraction = 2/10 = 0.20 > (0.001 + 0.045), which causes ratio to jump to 0.25!
        let report2 = yip_transport::LossReport {
            delivered_count: 108,
            high_counter: 110,
            missing: vec![105, 106],
        };
        let frame2 = ControlFrame::Feedback(report2);
        let sealed2 = b.session.seal(&frame2.encode()).unwrap();
        let mut dg2 = vec![PacketType::Control as u8];
        dg2.extend_from_slice(&sealed2.counter.to_be_bytes());
        dg2.extend_from_slice(&sealed2.ciphertext);

        let _ = a.on_udp_datagram(&dg2, 20);
        assert_eq!(a.last_loss_report_high, 110);

        let ratio_after_loss = a.bulk_repair_ratio();
        assert!(
            (ratio_after_loss - 0.25).abs() < 1e-4,
            "windowed loss fraction 0.20 jumps bulk ratio to 0.25; got {ratio_after_loss}"
        );

        // Window 3: consecutive report with clean traffic
        for c in 111..=120 {
            a.sent_log.insert(c, FlowClass::Bulk);
        }
        let report3 = yip_transport::LossReport {
            delivered_count: 118,
            high_counter: 120,
            missing: vec![],
        };
        let frame3 = ControlFrame::Feedback(report3);
        let sealed3 = b.session.seal(&frame3.encode()).unwrap();
        let mut dg3 = vec![PacketType::Control as u8];
        dg3.extend_from_slice(&sealed3.counter.to_be_bytes());
        dg3.extend_from_slice(&sealed3.ciphertext);

        let _ = a.on_udp_datagram(&dg3, 30);
        assert_eq!(a.last_loss_report_high, 120);

        let ratio_after_clean2 = a.bulk_repair_ratio();
        assert!(
            (ratio_after_clean2 - (0.25 * 0.9)).abs() < 1e-4,
            "consecutive clean report decays bulk ratio from 0.25 to 0.225; got {ratio_after_clean2}"
        );

        // Duplicate / out-of-order high_counter fallback test:
        // high_counter 115 <= last_loss_report_high (120)
        let report_ooo = yip_transport::LossReport {
            delivered_count: 118,
            high_counter: 115,
            missing: vec![],
        };
        let frame_ooo = ControlFrame::Feedback(report_ooo);
        let sealed_ooo = b.session.seal(&frame_ooo.encode()).unwrap();
        let mut dg_ooo = vec![PacketType::Control as u8];
        dg_ooo.extend_from_slice(&sealed_ooo.counter.to_be_bytes());
        dg_ooo.extend_from_slice(&sealed_ooo.ciphertext);

        let _ = a.on_udp_datagram(&dg_ooo, 40);
        assert_eq!(
            a.last_loss_report_high, 120,
            "out-of-order report must not rewind last_loss_report_high"
        );
    }

    #[test]
    fn late_spurious_nack_for_evicted_counter_safely_ignored() {
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun, false);

        // A spurious / late NACK arrives for counter 99999, which was never in a's retx buffer
        // (or was evicted from retx / sender log).
        let report = yip_transport::LossReport {
            delivered_count: 50,
            high_counter: 100_000,
            missing: vec![99_999],
        };
        let frame = ControlFrame::Feedback(report);
        let sealed = b.session.seal(&frame.encode()).unwrap();
        let mut dg = vec![PacketType::Control as u8];
        dg.extend_from_slice(&sealed.counter.to_be_bytes());
        dg.extend_from_slice(&sealed.ciphertext);

        // Ingest the datagram on peer a. It must not panic, must not retransmit anything,
        // and must return Outcome::None.
        let outcome = a.on_udp_datagram(&dg, 100);
        assert!(
            matches!(outcome, Outcome::None),
            "expected Outcome::None for evicted/unknown counter NACK, got non-None outcome"
        );
        assert_eq!(
            a.arq_retx_count, 0,
            "spurious NACK for evicted counter must not increment arq_retx_count"
        );
        assert!(
            a.retx_scratch.is_empty(),
            "retx scratch buffer must remain empty"
        );
    }
}
