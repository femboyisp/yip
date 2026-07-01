//! Mutex-free data plane: owns the AEAD session, FEC transport, wire codec,
//! and auxiliary buffers.  Driven by the io_uring event loop (Task 3+); for
//! now it is constructed and tested in isolation.
//!
//! Task 3 will wire `DataPlane` into the binary entry point and remove the
//! `#[allow(dead_code)]` below.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};

use yip_transport::{FlowClass, RetxBuffer, Transport};
use yip_wire::{Codec, WireCodec as _};

use crate::handshake::{Established, PacketType};
use crate::wire_glue;

// ── constants (wired into DataPlane::new; tunnel.rs keeps its own copies until
//    Task 3 replaces the two-thread loop with this DataPlane) ─────────────────

const SENT_LOG_CAPACITY: usize = 4096;
const RETX_BUFFER_MAX: usize = 16_384;
const RETX_BUFFER_TTL_MS: u64 = 2000;

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

// ── DataPlane ─────────────────────────────────────────────────────────────────

/// Mutex-free, I/O-free data-plane state machine.
///
/// Owns the AEAD [`yip_crypto::Session`], the FEC [`Transport`], the
/// [`WireCodec`], and the two auxiliary logs ([`SentLog`], [`RetxBuffer`]).
/// All methods take `&mut self`; no locks are acquired.
///
/// Framed egress datagrams are returned as a borrow of an internal reused
/// `Vec<Vec<u8>>` scratch buffer — the caller must consume or clone them
/// before calling any other `&mut self` method.
pub struct DataPlane {
    session: yip_crypto::Session,
    transport: Transport,
    codec: Codec,
    conn_tag: u64,
    sent_log: SentLog,
    retx: RetxBuffer,
    /// Reused per-call scratch: each element holds one framed egress datagram.
    egress_scratch: Vec<Vec<u8>>,
}

impl DataPlane {
    /// Build a [`DataPlane`] from an already-established session.
    ///
    /// The wire codec keys are derived from the same channel-binding sub-keys
    /// that were derived during the handshake (`established.auth_key` /
    /// `established.hp_key`), so both peers end up with the same codec.
    pub fn new(established: Established, conn_tag: u64) -> Self {
        let codec = Codec::new(established.auth_key, established.hp_key);
        Self {
            session: established.session,
            transport: Transport::new(vec![]),
            codec,
            conn_tag,
            sent_log: SentLog::new(SENT_LOG_CAPACITY),
            retx: RetxBuffer::new(RETX_BUFFER_MAX, RETX_BUFFER_TTL_MS),
            egress_scratch: Vec::new(),
        }
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
    pub fn on_tun_packet(&mut self, inner: &[u8], now_ms: u64) -> &[Vec<u8>] {
        self.egress_scratch.clear();

        // ── 1. Seal ───────────────────────────────────────────────────────────
        let sealed = match self.session.seal(inner) {
            Ok(s) => s,
            Err(_) => return &self.egress_scratch,
        };

        // ── 2. FEC-encode ─────────────────────────────────────────────────────
        let (class, symbols) = self
            .transport
            .encode(&sealed.ciphertext, inner, false, now_ms);

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
        if self.egress_scratch.len() < n_syms {
            self.egress_scratch.resize_with(n_syms, Vec::new);
        }

        for (slot, sym) in self.egress_scratch[..n_syms].iter_mut().zip(symbols.iter()) {
            let frame = wire_glue::symbol_to_frame(self.conn_tag, sym, sealed.counter, class);
            let dg = self.codec.frame(&frame);
            slot.clear();
            slot.push(PacketType::Data as u8);
            slot.extend_from_slice(&dg);
        }

        &self.egress_scratch[..n_syms]
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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use yip_crypto::{generate_keypair, Handshake};

    use crate::wire_glue::derive_wire_keys;

    /// Build two [`DataPlane`]s whose sessions can talk to each other, by
    /// running a full in-process Noise-IK handshake.
    fn dataplane_pair() -> (DataPlane, DataPlane) {
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
            DataPlane::new(est_i, conn_tag),
            DataPlane::new(est_r, conn_tag),
        )
    }

    /// A1-scoped egress test: confirm that `on_tun_packet` produces at least
    /// one datagram and that every datagram is prefixed with `PacketType::Data`.
    /// The full round-trip (decoding via `on_udp_datagram`) is added in Task 2.
    #[test]
    fn on_tun_packet_produces_decodable_egress() {
        let (mut a, _b) = dataplane_pair();
        let inner = vec![0x11u8; 200];
        let dgrams: Vec<Vec<u8>> = a.on_tun_packet(&inner, 0).to_vec();

        assert!(
            !dgrams.is_empty(),
            "on_tun_packet must produce at least one datagram"
        );

        for (i, dg) in dgrams.iter().enumerate() {
            assert!(!dg.is_empty(), "datagram {i} must not be empty");
            assert_eq!(
                dg[0],
                PacketType::Data as u8,
                "datagram {i} must begin with PacketType::Data"
            );
        }
    }
}
