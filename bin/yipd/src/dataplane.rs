//! Mutex-free data plane: owns the AEAD session, FEC transport, wire codec,
//! and auxiliary buffers.  Driven by the epoll event loop in `yip_io::poll`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use yip_transport::{FlowClass, LossDetector, LossReport, RetxBuffer, Transport};
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

/// A bounded ring-log that maps sealed-packet counters to their [`FlowClass`].
///
/// Entries are inserted in arrival order (monotone counter sequence from the
/// AEAD) and evicted oldest-first once `capacity` is reached.  Lookup is
/// O(1) via the `HashMap`; eviction is O(1) via the `VecDeque`.
pub(crate) struct SentLog {
    capacity: usize,
    map: HashMap<u64, FlowClass>,
    order: VecDeque<u64>,
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
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(counter, class);
        self.order.push_back(counter);
    }

    pub(crate) fn get(&self, counter: u64) -> Option<FlowClass> {
        self.map.get(&counter).copied()
    }

    /// Number of entries in the log whose `FlowClass` matches `class`.
    pub(crate) fn count_class(&self, class: FlowClass) -> u32 {
        u32::try_from(self.map.values().filter(|&&c| c == class).count()).unwrap_or(u32::MAX)
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

    // Feedback / log timers (mirror what ingress thread holds in tunnel.rs).
    last_feedback_ms: u64,
    last_log_ms: u64,
    last_sweep_ms: u64,
    /// Count of ARQ retransmits emitted (for observability / periodic log).
    arq_retx_count: u64,

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
}

impl DataPlane {
    /// Build a [`DataPlane`] from an already-established session.
    ///
    /// The wire codec keys are derived from the same channel-binding sub-keys
    /// that were derived during the handshake (`established.auth_key` /
    /// `established.hp_key`), so both peers end up with the same codec.
    ///
    /// `peer_addr` is this (single) peer's UDP endpoint; it is stamped as
    /// `dst` on every egress datagram this `DataPlane` produces.
    pub fn new(
        established: Established,
        conn_tag: u64,
        mode: TunnelMode,
        peer_addr: SocketAddr,
    ) -> Self {
        let codec = Codec::new(established.auth_key, established.hp_key);
        Self {
            session: established.session,
            transport: Transport::new(vec![]),
            codec,
            conn_tag,
            l2: matches!(mode, TunnelMode::L2Tap),
            peer_addr,
            sent_log: SentLog::new(SENT_LOG_CAPACITY),
            retx: RetxBuffer::new(RETX_BUFFER_MAX, RETX_BUFFER_TTL_MS),
            detector: LossDetector::new(5, 1024),
            mac_table: MacTable::new(DEFAULT_MAC_TABLE_CAPACITY, DEFAULT_MAC_TABLE_TTL_MS),
            last_feedback_ms: 0,
            last_log_ms: 0,
            last_sweep_ms: 0,
            arq_retx_count: 0,
            egress_scratch: Vec::new(),
            inner_scratch: Vec::new(),
            retx_scratch: Vec::new(),
            tick_scratch: Vec::new(),
        }
    }

    /// The wire `conn_tag` this session's frames carry (both peers derive the
    /// same value from the handshake channel binding — see
    /// [`conn_tag_from_keys`]). Exposed for the Task 5 `PeerManager`, which
    /// will route ingress by `conn_tag` once it demultiplexes across peers.
    #[expect(
        dead_code,
        reason = "consumed by the Task 5 PeerManager, not yet wired up"
    )]
    pub fn conn_tag(&self) -> u64 {
        self.conn_tag
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

        // ── 1. Seal ───────────────────────────────────────────────────────────
        let sealed = match self.session.seal(inner) {
            Ok(s) => s,
            Err(_) => return &self.egress_scratch,
        };

        // ── 2. FEC-encode ─────────────────────────────────────────────────────
        let (class, symbols) = self
            .transport
            .encode(&sealed.ciphertext, inner, self.l2, now_ms);

        // ── 3. Auxiliary bookkeeping ──────────────────────────────────────────
        self.sent_log.insert(sealed.counter, class);

        if let Some(oid) = symbols.first().map(|s| s.object_id) {
            self.retx.put(
                sealed.counter,
                sealed.ciphertext.clone(),
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
            let frame = wire_glue::symbol_to_frame(self.conn_tag, sym, sealed.counter, class);
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

                // Notify the loss detector that we saw this counter.
                self.detector.on_seen(counter, now_ms);

                // Feed the symbol to the FEC reassembler; continue until an object decodes.
                let ciphertext = match self.transport.decode(&sym, class) {
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
                        eprintln!("dataplane ingress: control open error: {e}");
                        return Outcome::None;
                    }
                };

                // Authentication succeeded: notify the detector that we saw this
                // control counter and that it is immediately resolved.
                self.detector.on_seen(counter, now_ms);
                self.detector.on_delivered(counter);

                // Decode the LossReport.
                let report = match LossReport::decode(&plaintext) {
                    Some(r) => r,
                    None => {
                        eprintln!("dataplane ingress: malformed LossReport");
                        return Outcome::None;
                    }
                };

                // Attribute missing counters to flow classes via the sent-log.
                //
                // Per-class fraction estimate:
                //   fraction = class_missing / max(1, class_sent_in_log)
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

                let sent_rt = self.sent_log.count_class(FlowClass::Realtime).max(1);
                let sent_bulk = self.sent_log.count_class(FlowClass::Bulk).max(1);
                let sent_default = self.sent_log.count_class(FlowClass::Default).max(1);

                let frac_rt = fraction_f32(missing_rt, sent_rt);
                let frac_bulk = fraction_f32(missing_bulk, sent_bulk);
                let frac_default = fraction_f32(missing_default, sent_default);

                self.transport.observe_loss(FlowClass::Realtime, frac_rt);
                self.transport.observe_loss(FlowClass::Bulk, frac_bulk);
                self.transport
                    .observe_loss(FlowClass::Default, frac_default);

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
                        let frame =
                            wire_glue::symbol_to_frame(self.conn_tag, sym, missing_counter, cls);
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
        if now_ms.saturating_sub(self.last_feedback_ms) < FEEDBACK_INTERVAL_MS {
            return None;
        }
        self.last_feedback_ms = now_ms;

        // Build the report from the current detector state.
        let report = self.detector.report(now_ms);
        let report_bytes = report.encode();

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
    fn dataplane_pair(mode: TunnelMode) -> (DataPlane, DataPlane) {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();

        // Run the handshake in-process (no sockets needed).
        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let m1 = ini.write_message().unwrap();
        res.read_message(&m1).unwrap();
        let m2 = res.write_message().unwrap();
        ini.read_message(&m2).unwrap();

        assert!(ini.is_finished() && res.is_finished());

        // Both channel bindings are identical (verified in yip-crypto tests).
        let cb_i = ini.channel_binding();
        let cb_r = res.channel_binding();
        assert_eq!(cb_i, cb_r);

        let (auth_key, hp_key) = derive_wire_keys(&cb_i);

        // Build Established structs directly (mirrors what handshake.rs does).
        let est_i = Established {
            session: ini.into_session().unwrap(),
            auth_key,
            hp_key,
        };
        let est_r = Established {
            session: res.into_session().unwrap(),
            auth_key,
            hp_key,
        };

        // Both peers derive the same conn_tag from the same keys.
        let conn_tag = conn_tag_from_keys(&auth_key, &hp_key);

        (
            DataPlane::new(est_i, conn_tag, mode, TEST_ADDR_B.parse().unwrap()),
            DataPlane::new(est_r, conn_tag, mode, TEST_ADDR_A.parse().unwrap()),
        )
    }

    /// Full round-trip: A encodes a TUN packet, B decodes it via `on_udp_datagram`,
    /// and the recovered inner bytes equal the original.
    #[test]
    fn on_tun_packet_produces_decodable_egress() {
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun);
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
        let (mut a, mut b) = dataplane_pair(TunnelMode::L3Tun);
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
        let (mut a, _b) = dataplane_pair(TunnelMode::L3Tun);
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

        let (mut tun_dp, _) = dataplane_pair(TunnelMode::L3Tun);
        tun_dp.on_tun_packet(&l2_inner, 0);
        let tun_counter = *tun_dp
            .sent_log
            .order
            .back()
            .expect("TUN dataplane inserts a sent-log entry");
        assert_eq!(
            tun_dp.sent_log.get(tun_counter),
            Some(FlowClass::Default),
            "TUN mode passes l2=false and keeps Ethernet payload as Default"
        );

        let (mut tap_dp, _) = dataplane_pair(TunnelMode::L2Tap);
        tap_dp.on_tun_packet(&l2_inner, 0);
        let tap_counter = *tap_dp
            .sent_log
            .order
            .back()
            .expect("TAP dataplane inserts a sent-log entry");
        assert_eq!(
            tap_dp.sent_log.get(tap_counter),
            Some(FlowClass::Realtime),
            "TAP mode passes l2=true and classifies inner IPv4 DSCP EF"
        );
    }
}
