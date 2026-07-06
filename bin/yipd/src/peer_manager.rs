//! `PeerManager`: multi-peer routing/demux + in-loop lazy handshake.
//!
//! This is the integration crux of milestone 2a. It owns one [`DataPlane`]
//! per established remote peer, drives the [`HandshakeState`] step-functions
//! to bring a peer up from a cold start (no pre-loop blocking handshake, no
//! `sock.connect`), and implements [`Dispatch`] so [`yip_io::poll::run_poll`]
//! / `yip_io::uring::run_uring` can drive it directly.
//!
//! # Lazy handshake
//!
//! A peer starts in [`PeerState::Idle`]: nothing has been sent to it yet.
//! The first TUN packet routed to that peer (see "TUN routing" below)
//! buffers the packet in `pending_tun`, starts a [`HandshakeState`] initiator,
//! and emits `[HandshakeInit]`. The peer stays `Handshaking` until either:
//! - a `[HandshakeResp]` arrives from that peer's endpoint (→ `Established`,
//!   buffered `pending_tun` is drained through the new `DataPlane`), or
//! - `tick` decides a retry/timeout has elapsed (resend, or give up and
//!   revert to `Idle`, dropping anything buffered).
//!
//! Symmetrically, an incoming `[HandshakeInit]` is answered (admission
//! permitting) by `start_responder`, which *also* transitions that peer to
//! `Established` and drains its own `pending_tun` — covering the (rare, but
//! possible) race where both sides try to talk before either handshake
//! completes.
//!
//! # TUN routing
//!
//! In `L3Tun` mode, the inner packet's IPv6 destination is looked up in
//! `by_addr` (each configured peer's self-certifying `node_addr`). When
//! there is exactly one configured peer and the lookup misses — e.g. the
//! packet isn't IPv6 at all, or doesn't carry the mesh address, as is true
//! of today's single-peer netns tests, which assign plain IPv4 addresses to
//! the TUN device — the packet still routes to that one peer: with a single
//! peer there is no routing ambiguity to resolve, and requiring "real" mesh
//! addressing here would regress the existing single-peer tunnel tests.
//! With more than one configured peer, an unmatched destination is genuinely
//! ambiguous and the packet is dropped.
//!
//! In `L2Tap` mode there is no IPv6 destination to key off (frames are
//! Ethernet); 2a scope is a single TAP peer, so every frame forwards to the
//! sole configured peer regardless of its inner L2 destination. Multi-peer
//! L2 bridging/flooding across more than one TAP peer is out of scope for
//! 2a and left to a future milestone.
//!
//! # UDP demux: why routing is by source address, not raw `conn_tag` bytes
//!
//! Each peer's `DataPlane` frames `Data` packets through `yip_wire::Codec`,
//! which XORs the entire logical header — including the 8 `conn_tag` bytes
//! at `dg[1..9]` — under a keystream seeded by that frame's own auth tag
//! (see `yip-wire`'s `Codec::frame`). That mask is a function of the whole
//! frame's contents, so it is different on *every* datagram, even between
//! two datagrams of the same connection. The raw bytes at `dg[1..9]` are
//! therefore not recoverable as a stable `conn_tag` without first picking
//! the right peer's codec (`hp_key`) to unmask them — which is exactly the
//! question being asked. `Control` packets are worse: `dg[1..9]` there is
//! the *AEAD counter* (see `DataPlane::on_udp_datagram`'s `Control` arm),
//! not a conn_tag at all, sent unmasked.
//!
//! [`PeerManager::route_data`] therefore demuxes primarily by matching the
//! datagram's source address against each peer's learned/configured
//! `endpoint` — correct uniformly for `Data` and `Control` frames, and
//! exactly the mechanism the addendum itself specifies for routing
//! `[HandshakeResp]`. `by_tag` is still populated and consulted first as a
//! best-effort fast-path hint (it *will* hit for hand-built test datagrams
//! that place the raw tag directly, and costs nothing when it misses on
//! real, masked traffic). If neither the tag hint nor the address match
//! finds a peer (e.g. a NAT rebind changed the peer's source port), a
//! bounded fallback tries every `Established` peer's codec in turn — safe
//! because `DataPlane::on_udp_datagram` authenticates (AEAD / SipHash MAC)
//! before any side effect, so trying the wrong peer just yields
//! `Outcome::None`, never corrupted state.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};

use yip_io::poll::{Dispatch, DispatchOut, EgressDatagram};

use crate::addr::node_addr;
use crate::config::PeerConfig;
use crate::dataplane::{conn_tag_from_keys, DataPlane, Outcome};
use crate::handshake::{HandshakeState, PacketType};
use crate::mode::TunnelMode;

/// How long an in-flight initiator handshake waits before resending
/// `[HandshakeInit]`.
const HANDSHAKE_RETRY_MS: u64 = 1_000;
/// Total time an initiator keeps retransmitting *the same* `[HandshakeInit]`
/// (holding one Noise ephemeral) before giving up and reverting to `Idle`.
///
/// This is deliberately a long window (WireGuard's `REKEY_ATTEMPT_TIME`), not
/// a small retry count. A responder that admits our `Init` caches its
/// `[HandshakeResp]` keyed to *this* ephemeral and replays that cached reply
/// on every retransmit (see `handle_handshake_init`). If we instead gave up
/// early and later re-initiated with a *fresh* ephemeral, the responder —
/// which has no idle-timeout and never rebuilds a live session (there is no
/// anti-replay in the handshake yet, so it cannot safely tell a genuine
/// re-initiation from a replayed old `Init` — see issue: handshake
/// anti-replay) — would keep replaying its stale reply forever and we could
/// never complete. Retransmitting the *same* `Init` keeps our ephemeral
/// matching the responder's cached session, so ordinary handshake-packet loss
/// is overcome by retransmission rather than wedging the peer permanently.
const HANDSHAKE_TOTAL_MS: u64 = 90_000;

/// Cap on TUN packets buffered per peer while its handshake is in flight.
/// Bounds memory when a peer streams into an unestablished (or unreachable)
/// peer during the `HANDSHAKE_TOTAL_MS` window; the oldest are dropped, like
/// a small tail queue (WireGuard stages a single packet).
const MAX_PENDING_TUN: usize = 16;

/// An initiator handshake in flight, awaiting `[HandshakeResp]`. Boxed by
/// [`PeerState::Handshaking`] so that variant stays pointer-sized like
/// `Established(Box<DataPlane>)` — `HandshakeState`/`init_pkt` are much
/// larger than the other `PeerState` variants (clippy `large_enum_variant`).
struct HandshakingState {
    hs: HandshakeState,
    /// When this handshake attempt first started. The attempt is abandoned
    /// once `now - started_ms >= HANDSHAKE_TOTAL_MS`; until then the same
    /// `init_pkt` is retransmitted every `HANDSHAKE_RETRY_MS`.
    started_ms: u64,
    /// When `[HandshakeInit]` was last (re)sent.
    last_sent_ms: u64,
    /// How many times `[HandshakeInit]` has been resent (for logging/metrics).
    retries: u32,
    /// The framed `[HandshakeInit]` datagram, resent verbatim on retry.
    /// `HandshakeState` cannot regenerate this: Noise's ephemeral key is
    /// drawn once, in `start_initiator`'s `write_message`, and the peer must
    /// see that exact message again (not a fresh one) on retry.
    init_pkt: Vec<u8>,
}

/// One remote peer's handshake/session state.
enum PeerState {
    /// No handshake has been attempted yet.
    Idle,
    /// An initiator handshake is in flight, awaiting `[HandshakeResp]`.
    Handshaking(Box<HandshakingState>),
    /// A completed session; all data-plane traffic routes here.
    Established(Box<DataPlane>),
}

/// One configured remote peer plus its live handshake/session state.
struct Peer {
    pubkey: [u8; 32],
    /// This peer's self-certifying inner IPv6 address (`node_addr(pubkey)`).
    /// Routing itself goes through `by_addr` (kept alongside for tests and
    /// future logging/debugging use).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "kept for tests/future logging; routing uses by_addr"
        )
    )]
    addr: Ipv6Addr,
    /// This peer's UDP endpoint: the configured value until a `HandshakeInit`
    /// admission *learns* the actual observed source address (see
    /// `PeerManager::handle_handshake_init`).
    endpoint: SocketAddr,
    state: PeerState,
    /// TUN packets buffered while no `Established` session exists yet.
    pending_tun: Vec<Vec<u8>>,
    /// The `[HandshakeResp]` bytes that established the *current* session,
    /// cached when this peer was admitted as responder. A repeated
    /// `HandshakeInit` (a duplicate, or a retransmit after our reply was
    /// lost) is answered by re-sending these exact bytes rather than running
    /// the responder step again — see `handle_handshake_init`. `None` when we
    /// have no session, or hold one we built as the initiator.
    cached_resp: Option<Vec<u8>>,
}

/// Multi-peer router/demuxer + lazy in-loop handshake driver.
///
/// Implements [`Dispatch`] so it can be driven directly by
/// [`yip_io::poll::run_poll`] / `yip_io::uring::run_uring`. See the module
/// doc for the routing/demux design.
pub struct PeerManager {
    local_priv: [u8; 32],
    local_pub: [u8; 32],
    mode: TunnelMode,
    /// Small N (2a scope): linear scan for state transitions is fine.
    peers: Vec<Peer>,
    /// `conn_tag -> peers index`, populated whenever a peer reaches
    /// `Established`. Consulted as a fast-path hint by `route_data` (see the
    /// module doc for why it is not the primary demux mechanism). In 2a a peer
    /// establishes exactly once (duplicate/retransmitted inits re-send the
    /// cached reply rather than rebuilding — see `handle_handshake_init`), so
    /// each peer contributes one entry that never goes stale. M7 rekey will
    /// rotate `conn_tag`s per epoch and must evict the superseded entry here.
    by_tag: HashMap<u64, usize>,
    /// `node_addr -> peers index`, populated at construction (addresses are
    /// derived from each peer's configured public key and never change).
    by_addr: HashMap<Ipv6Addr, usize>,
    /// Reused scratch for `on_udp`/`on_tun` return values.
    egress: Vec<EgressDatagram>,
    /// Reused scratch for `tick`'s return value.
    tick_egress: Vec<EgressDatagram>,
    /// Reused scratch for a `Tun`/`Both` outcome reached via the
    /// address-unmatched fallback in `handle_data_or_control`. That path
    /// must materialize owned data (see its doc comment) rather than return
    /// a slice borrowed straight from a `DataPlane`, to sidestep a
    /// borrow-checker limitation around retrying a `&mut self`-returning
    /// call across loop iterations.
    tun_scratch: Vec<u8>,
}

impl PeerManager {
    /// Build a `PeerManager` from the local keypair and the configured peer
    /// list. Every peer starts `Idle`; no handshake is attempted until the
    /// first TUN packet (or an incoming `HandshakeInit`) needs it.
    pub fn new(
        local_priv: [u8; 32],
        local_pub: [u8; 32],
        peers_cfg: &[PeerConfig],
        mode: TunnelMode,
    ) -> Self {
        let mut peers = Vec::with_capacity(peers_cfg.len());
        let mut by_addr = HashMap::with_capacity(peers_cfg.len());
        for (i, p) in peers_cfg.iter().enumerate() {
            let addr = node_addr(&p.public_key);
            by_addr.insert(addr, i);
            peers.push(Peer {
                pubkey: p.public_key,
                addr,
                endpoint: p.endpoint,
                state: PeerState::Idle,
                pending_tun: Vec::new(),
                cached_resp: None,
            });
        }
        Self {
            local_priv,
            local_pub,
            mode,
            peers,
            by_tag: HashMap::new(),
            by_addr,
            egress: Vec::new(),
            tick_egress: Vec::new(),
            tun_scratch: Vec::new(),
        }
    }

    /// This node's own self-certifying mesh address, for assigning the
    /// local TUN/TAP device's address.
    pub fn local_addr(&self) -> Ipv6Addr {
        node_addr(&self.local_pub)
    }

    /// Append a TUN packet to a peer's pending buffer, dropping the oldest if
    /// the buffer is at [`MAX_PENDING_TUN`] so a peer streaming into an
    /// unestablished/unreachable peer cannot grow memory without bound.
    fn push_pending(pending: &mut Vec<Vec<u8>>, inner: &[u8]) {
        if pending.len() >= MAX_PENDING_TUN {
            pending.remove(0);
        }
        pending.push(inner.to_vec());
    }

    // ── TUN routing ───────────────────────────────────────────────────────

    /// Which configured peer a TUN/TAP frame should go to, or `None` if it
    /// cannot be routed (ambiguous multi-peer destination). See the module
    /// doc for the L2/L3 routing rules.
    fn route_tun_index(&self, inner: &[u8]) -> Option<usize> {
        match self.mode {
            TunnelMode::L2Tap => {
                if self.peers.len() == 1 {
                    Some(0)
                } else {
                    None
                }
            }
            TunnelMode::L3Tun => {
                if let Some(dst) = ipv6_dst(inner) {
                    if let Some(&idx) = self.by_addr.get(&dst) {
                        return Some(idx);
                    }
                }
                if self.peers.len() == 1 {
                    Some(0)
                } else {
                    None
                }
            }
        }
    }

    // ── UDP demux ─────────────────────────────────────────────────────────

    /// Which `Established` peer a `Data`/`Control` datagram should be
    /// dispatched to, or `None` if none can be determined. Pure routing
    /// decision — does not touch any `DataPlane` state. See the module doc
    /// for why source-address matching is primary and the raw `dg[1..9]`
    /// `by_tag` hint is secondary.
    fn route_data(&self, src: SocketAddr, dg: &[u8]) -> Option<usize> {
        if dg.len() >= 9 {
            let tag_bytes: [u8; 8] = dg[1..9].try_into().expect("checked len >= 9 above");
            let tag = u64::from_be_bytes(tag_bytes);
            if let Some(&idx) = self.by_tag.get(&tag) {
                if matches!(self.peers[idx].state, PeerState::Established(_)) {
                    return Some(idx);
                }
            }
        }
        self.peers
            .iter()
            .position(|p| p.endpoint == src && matches!(p.state, PeerState::Established(_)))
    }

    /// Dispatch a `Data`/`Control` datagram to peer `idx`'s `DataPlane` and
    /// re-map its `Outcome` into a `DispatchOut`. Returns `DispatchOut::None`
    /// if `idx` is not (or no longer) `Established`.
    fn dispatch_established(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        let PeerState::Established(dp) = &mut self.peers[idx].state else {
            return DispatchOut::None;
        };
        match dp.on_udp_datagram(dg, now_ms) {
            Outcome::None => DispatchOut::None,
            Outcome::TunWrite(buf) => DispatchOut::Tun(buf),
            Outcome::Send(pkts) => DispatchOut::Udp(pkts),
            Outcome::TunWriteThenSend(buf, pkts) => DispatchOut::Both(buf, pkts),
        }
    }

    fn handle_data_or_control(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        if let Some(idx) = self.route_data(src, dg) {
            return self.dispatch_established(idx, dg, now_ms);
        }
        // No address/tag match at all (e.g. the peer roamed) — try every
        // Established peer's codec once each. Safe (see module doc): a
        // failed authentication is a no-op, not corrupted state.
        //
        // This loop materializes owned copies of any hit rather than
        // returning a slice borrowed straight from `DataPlane::on_udp_datagram`:
        // a loop that calls a `&mut self`-borrowing method and conditionally
        // returns its (borrowed) result does not type-check under NLL — the
        // borrow from the *first* call is typed as lasting until the
        // function returns (because *some* branch escapes it), which then
        // conflicts with the *next* iteration's call needing its own `&mut
        // self`. Cloning decouples each attempt from any borrow so the loop
        // itself is unremarkable; the final hit (if any) is copied once into
        // `self.tun_scratch`/`self.egress` and returned borrowed from there.
        let candidates: Vec<usize> = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, p)| matches!(p.state, PeerState::Established(_)))
            .map(|(i, _)| i)
            .collect();
        for idx in candidates {
            let hit = {
                let PeerState::Established(dp) = &mut self.peers[idx].state else {
                    continue;
                };
                match dp.on_udp_datagram(dg, now_ms) {
                    Outcome::None => None,
                    Outcome::TunWrite(buf) => Some((Some(buf.to_vec()), Vec::new())),
                    Outcome::Send(pkts) => Some((None, pkts.to_vec())),
                    Outcome::TunWriteThenSend(buf, pkts) => {
                        Some((Some(buf.to_vec()), pkts.to_vec()))
                    }
                }
            };
            let Some((tun, udp)) = hit else {
                continue;
            };
            return match (tun, udp.is_empty()) {
                (Some(t), true) => {
                    self.tun_scratch = t;
                    DispatchOut::Tun(&self.tun_scratch)
                }
                (Some(t), false) => {
                    self.tun_scratch = t;
                    self.egress = udp;
                    DispatchOut::Both(&self.tun_scratch, &self.egress)
                }
                (None, false) => {
                    self.egress = udp;
                    DispatchOut::Udp(&self.egress)
                }
                (None, true) => DispatchOut::None,
            };
        }
        DispatchOut::None
    }

    // ── handshake admission ───────────────────────────────────────────────

    /// Handle an incoming `[HandshakeInit]`: run the responder step, admit
    /// only if the recovered static key matches a *configured* peer, and on
    /// admission transition that peer to `Established` (learning its
    /// endpoint from `src`) and drain any buffered `pending_tun`.
    fn handle_handshake_init(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        let (established, resp_pkt, remote_static) =
            match HandshakeState::start_responder(&self.local_priv, dg) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("peer_manager: start_responder failed: {e}");
                    return DispatchOut::None;
                }
            };

        let Some(idx) = self.peers.iter().position(|p| p.pubkey == remote_static) else {
            // Not a configured peer: drop, do not create a peer.
            return DispatchOut::None;
        };

        // `start_responder` above drew a fresh Noise ephemeral, so `established`
        // is a BRAND-NEW session distinct from any we already hold — installing
        // it unconditionally would silently rekey. Branch on our current state
        // with that in mind.
        match &self.peers[idx].state {
            // Already have a live session: this `Init` is a duplicate, a
            // retransmit after our earlier reply was lost, or a peer restart.
            // Never tear down the running session (2a has no rekey — a rebuilt
            // session would strand a peer that stays on the old keys and drops
            // the new reply). Re-send the cached `[HandshakeResp]` verbatim so a
            // peer still handshaking (its reply was lost) completes on the SAME
            // session; a peer already established harmlessly ignores it. Discard
            // the freshly-built `established`/`resp_pkt`.
            PeerState::Established(_) => match &self.peers[idx].cached_resp {
                Some(resp) => {
                    self.egress.clear();
                    self.egress.push(EgressDatagram {
                        fate: 0,
                        dst: src,
                        bytes: resp.clone(),
                    });
                    DispatchOut::Udp(&self.egress)
                }
                // We hold this session as the initiator (no cached reply): a new
                // `Init` from the peer is a restart/rekey, deferred to M7.
                None => DispatchOut::None,
            },
            // Glare: both sides initiated simultaneously (e.g. the TUN's IPv6
            // autoconf multicast races the peer's traffic at startup). Break
            // the tie deterministically by static-key order so both converge on
            // ONE session: the larger public key adopts the responder role
            // (accepts this `Init`); the smaller key is the designated
            // initiator and ignores the competing `Init`, keeping its own
            // attempt (it completes when the peer's `[HandshakeResp]` arrives).
            PeerState::Handshaking(_) if self.local_pub < self.peers[idx].pubkey => {
                DispatchOut::None
            }
            // `Idle` (no competition — whoever initiates first wins, preserving
            // lazy establishment) or `Handshaking` with the larger key (adopt
            // responder role): admit this session.
            PeerState::Idle | PeerState::Handshaking(_) => {
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                let mut dp = Box::new(DataPlane::new(established, conn_tag, self.mode, src));

                self.peers[idx].endpoint = src; // learn the observed endpoint
                self.peers[idx].cached_resp = Some(resp_pkt.clone());
                self.by_tag.insert(dp.conn_tag(), idx);

                self.egress.clear();
                self.egress.push(EgressDatagram {
                    fate: 0,
                    dst: src,
                    bytes: resp_pkt,
                });
                let pending = std::mem::take(&mut self.peers[idx].pending_tun);
                for inner in &pending {
                    let out = dp.on_tun_packet(inner, now_ms);
                    self.egress.extend(out.iter().cloned());
                }
                self.peers[idx].state = PeerState::Established(dp);

                DispatchOut::Udp(&self.egress)
            }
        }
    }

    /// Handle an incoming `[HandshakeResp]`: find the `Handshaking` peer
    /// whose endpoint matches `src`, resume via `read_response`, transition
    /// to `Established`, and drain any buffered `pending_tun`.
    fn handle_handshake_resp(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        let Some(idx) = self
            .peers
            .iter()
            .position(|p| p.endpoint == src && matches!(p.state, PeerState::Handshaking(_)))
        else {
            return DispatchOut::None;
        };

        let old_state = std::mem::replace(&mut self.peers[idx].state, PeerState::Idle);
        let PeerState::Handshaking(handshaking) = old_state else {
            unreachable!("index was matched against PeerState::Handshaking above");
        };

        match handshaking.hs.read_response(dg) {
            Ok(established) => {
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                let mut dp = Box::new(DataPlane::new(
                    established,
                    conn_tag,
                    self.mode,
                    self.peers[idx].endpoint,
                ));
                self.by_tag.insert(dp.conn_tag(), idx);

                self.egress.clear();
                let pending = std::mem::take(&mut self.peers[idx].pending_tun);
                for inner in &pending {
                    let out = dp.on_tun_packet(inner, now_ms);
                    self.egress.extend(out.iter().cloned());
                }
                self.peers[idx].state = PeerState::Established(dp);

                if self.egress.is_empty() {
                    DispatchOut::None
                } else {
                    DispatchOut::Udp(&self.egress)
                }
            }
            Err(e) => {
                eprintln!("peer_manager: read_response failed: {e}");
                // State was already reverted to `Idle` above (via the
                // `mem::replace`); `pending_tun` stays queued and the next
                // `on_tun` call will start a fresh handshake.
                DispatchOut::None
            }
        }
    }
}

impl Dispatch for PeerManager {
    fn on_udp(&mut self, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        if dg.is_empty() {
            return DispatchOut::None;
        }
        if dg[0] == PacketType::HandshakeInit as u8 {
            self.handle_handshake_init(src, dg, now_ms)
        } else if dg[0] == PacketType::HandshakeResp as u8 {
            self.handle_handshake_resp(src, dg, now_ms)
        } else {
            self.handle_data_or_control(src, dg, now_ms)
        }
    }

    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram] {
        let Some(idx) = self.route_tun_index(inner) else {
            return &[];
        };

        // Each branch below is a syntactically separate `match`/`if`, rather
        // than one `match` with arms that need different sibling `Peer`
        // fields (`pending_tun`, `pubkey`) alongside the state borrow: NLL
        // unifies a single match expression's borrow across all arms to the
        // arm that returns borrowed data, which then conflicts with any
        // other arm that also touches `self.peers[idx]`. Splitting into
        // independent statements gives each one its own borrow region.
        if matches!(self.peers[idx].state, PeerState::Established(_)) {
            let PeerState::Established(dp) = &mut self.peers[idx].state else {
                unreachable!("just matched Established above");
            };
            return dp.on_tun_packet(inner, now_ms);
        }

        if matches!(self.peers[idx].state, PeerState::Handshaking(_)) {
            Self::push_pending(&mut self.peers[idx].pending_tun, inner);
            return &[];
        }

        // Idle: buffer this packet and kick off a lazy handshake.
        Self::push_pending(&mut self.peers[idx].pending_tun, inner);
        match HandshakeState::start_initiator(&self.local_priv, &self.peers[idx].pubkey) {
            Ok((hs, init_pkt)) => {
                let peer_endpoint = self.peers[idx].endpoint;
                self.egress.clear();
                self.egress.push(EgressDatagram {
                    fate: 0,
                    dst: peer_endpoint,
                    bytes: init_pkt.clone(),
                });
                self.peers[idx].state = PeerState::Handshaking(Box::new(HandshakingState {
                    hs,
                    started_ms: now_ms,
                    last_sent_ms: now_ms,
                    retries: 0,
                    init_pkt,
                }));
                &self.egress
            }
            Err(e) => {
                eprintln!("peer_manager: failed to start handshake: {e}");
                &[]
            }
        }
    }

    fn tick(&mut self, now_ms: u64) -> Option<&[EgressDatagram]> {
        self.tick_egress.clear();
        for i in 0..self.peers.len() {
            let endpoint = self.peers[i].endpoint;
            let old_state = std::mem::replace(&mut self.peers[i].state, PeerState::Idle);
            let new_state = match old_state {
                PeerState::Established(mut dp) => {
                    if let Some(pkts) = dp.tick(now_ms) {
                        self.tick_egress.extend(pkts.iter().cloned());
                    }
                    PeerState::Established(dp)
                }
                PeerState::Handshaking(mut handshaking)
                    if now_ms.saturating_sub(handshaking.last_sent_ms) >= HANDSHAKE_RETRY_MS =>
                {
                    if now_ms.saturating_sub(handshaking.started_ms) >= HANDSHAKE_TOTAL_MS {
                        // Whole attempt window elapsed without completing: the
                        // peer is unreachable. Give up and free the ephemeral;
                        // the next TUN packet starts a fresh attempt.
                        self.peers[i].pending_tun.clear();
                        PeerState::Idle
                    } else {
                        // Retransmit the SAME init (same ephemeral) so the
                        // responder's cached reply stays valid — see
                        // HANDSHAKE_TOTAL_MS.
                        handshaking.retries = handshaking.retries.saturating_add(1);
                        handshaking.last_sent_ms = now_ms;
                        self.tick_egress.push(EgressDatagram {
                            fate: 0,
                            dst: endpoint,
                            bytes: handshaking.init_pkt.clone(),
                        });
                        PeerState::Handshaking(handshaking)
                    }
                }
                other => other,
            };
            self.peers[i].state = new_state;
        }
        if self.tick_egress.is_empty() {
            None
        } else {
            Some(&self.tick_egress)
        }
    }
}

/// Parse an inner packet's IPv6 destination address (bytes 24..40 of a
/// standard fixed IPv6 header), or `None` if `inner` is too short or its
/// first nibble isn't `6` (IPv4, ARP, or a bare Ethernet frame in L2 mode
/// all fail this check, which is intentional — see `route_tun_index`).
fn ipv6_dst(inner: &[u8]) -> Option<Ipv6Addr> {
    if inner.len() < 40 || inner[0] >> 4 != 6 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&inner[24..40]);
    Some(Ipv6Addr::from(octets))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Established;
    use crate::wire_glue::derive_wire_keys;
    use yip_crypto::{generate_keypair, Handshake};

    fn peer_cfg(tag_byte: u8, endpoint: &str) -> PeerConfig {
        PeerConfig {
            public_key: [tag_byte; 32],
            endpoint: endpoint.parse().unwrap(),
        }
    }

    /// Build a real `DataPlane` (via an in-process Noise handshake) with a
    /// specific `conn_tag`, standing in for "a peer that has already
    /// completed its handshake" — the "test seam" for demux tests: rather
    /// than a special production API, the test module (being a child of
    /// `peer_manager`) can just construct a `DataPlane` directly and splice
    /// it into a `PeerManager`'s private `peers`/`by_tag` fields.
    fn fake_established_dataplane(conn_tag: u64, peer_addr: SocketAddr) -> DataPlane {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();
        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();
        let m1 = ini.write_message().unwrap();
        res.read_message(&m1).unwrap();
        let m2 = res.write_message().unwrap();
        ini.read_message(&m2).unwrap();
        let cb = ini.channel_binding();
        let (auth_key, hp_key) = derive_wire_keys(&cb);
        let established = Established {
            session: ini.into_session().unwrap(),
            auth_key,
            hp_key,
        };
        DataPlane::new(established, conn_tag, TunnelMode::L3Tun, peer_addr)
    }

    #[test]
    fn by_addr_maps_each_peers_node_addr() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let peer_b = peer_cfg(2, "10.0.0.2:2000");
        let pm = PeerManager::new(
            [9u8; 32],
            [8u8; 32],
            &[peer_a.clone(), peer_b.clone()],
            TunnelMode::L3Tun,
        );

        let addr_a = node_addr(&peer_a.public_key);
        let addr_b = node_addr(&peer_b.public_key);
        assert_eq!(pm.by_addr.get(&addr_a), Some(&0));
        assert_eq!(pm.by_addr.get(&addr_b), Some(&1));
        assert_eq!(pm.peers[0].addr, addr_a);
        assert_eq!(pm.peers[1].addr, addr_b);
    }

    #[test]
    fn route_tun_index_picks_peer_owning_the_inner_ipv6_dst() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let peer_b = peer_cfg(2, "10.0.0.2:2000");
        let pm = PeerManager::new(
            [9u8; 32],
            [8u8; 32],
            &[peer_a.clone(), peer_b.clone()],
            TunnelMode::L3Tun,
        );
        let addr_b = node_addr(&peer_b.public_key);

        // Build a minimal 40-byte IPv6 header addressed to peer B.
        let mut inner = vec![0u8; 40];
        inner[0] = 0x60; // version 6
        inner[24..40].copy_from_slice(&addr_b.octets());

        assert_eq!(pm.route_tun_index(&inner), Some(1));
    }

    #[test]
    fn route_tun_index_falls_back_to_sole_peer_for_unmatched_l3_traffic() {
        // Mirrors the existing single-peer netns tests, which assign plain
        // IPv4 addresses to the TUN device (not the IPv6 mesh address).
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let pm = PeerManager::new([9u8; 32], [8u8; 32], &[peer_a], TunnelMode::L3Tun);

        // A bare IPv4 packet: first nibble is 4, not 6.
        let inner = vec![0x45u8; 40];
        assert_eq!(pm.route_tun_index(&inner), Some(0));
    }

    #[test]
    fn route_tun_index_l3_ambiguous_multi_peer_drops() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let peer_b = peer_cfg(2, "10.0.0.2:2000");
        let pm = PeerManager::new([9u8; 32], [8u8; 32], &[peer_a, peer_b], TunnelMode::L3Tun);

        let inner = vec![0x45u8; 40]; // IPv4, matches no by_addr entry
        assert_eq!(pm.route_tun_index(&inner), None);
    }

    #[test]
    fn route_tun_index_l2_single_peer_forwards_regardless_of_inner() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let pm = PeerManager::new([9u8; 32], [8u8; 32], &[peer_a], TunnelMode::L2Tap);

        // An arbitrary Ethernet-looking frame; L2 mode ignores its contents
        // entirely and forwards to the sole configured peer.
        let inner = vec![0xffu8; 14];
        assert_eq!(pm.route_tun_index(&inner), Some(0));
    }

    #[test]
    fn routes_inner_dst_to_owning_peer_and_demuxes_by_tag() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let peer_b = peer_cfg(2, "10.0.0.2:2000");
        let mut pm = PeerManager::new(
            [9u8; 32],
            [8u8; 32],
            &[peer_a.clone(), peer_b.clone()],
            TunnelMode::L3Tun,
        );

        // by_addr maps each peer's node_addr to its index.
        assert_eq!(pm.by_addr.get(&node_addr(&peer_a.public_key)), Some(&0));
        assert_eq!(pm.by_addr.get(&node_addr(&peer_b.public_key)), Some(&1));

        // Splice in a fake Established peer at index 1 with a known conn_tag
        // (the "test seam": direct access to private fields from the child
        // `tests` module).
        const FAKE_TAG: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        pm.peers[1].state = PeerState::Established(Box::new(fake_established_dataplane(
            FAKE_TAG,
            peer_b.endpoint,
        )));
        pm.by_tag.insert(FAKE_TAG, 1);

        // A hand-built "Data" datagram carrying that conn_tag in dg[1..9]
        // (real wire traffic never has literal tag bytes here — see the
        // module doc — but route_data's by_tag fast path is still exercised
        // and verified this way).
        let mut dg = vec![PacketType::Data as u8];
        dg.extend_from_slice(&FAKE_TAG.to_be_bytes());
        dg.extend_from_slice(&[0u8; 8]);

        // Demuxes to peer 1 via the tag hint even from an unrelated source
        // address (proving the tag path, not the address-match fallback).
        let unrelated_src: SocketAddr = "203.0.113.9:9".parse().unwrap();
        assert_eq!(pm.route_data(unrelated_src, &dg), Some(1));

        // And also demuxes correctly by address alone (no tag hint) once
        // the datagram no longer carries the registered tag.
        let mut untagged_dg = vec![PacketType::Data as u8];
        untagged_dg.extend_from_slice(&0u64.to_be_bytes());
        untagged_dg.extend_from_slice(&[0u8; 8]);
        assert_eq!(pm.route_data(peer_b.endpoint, &untagged_dg), Some(1));
    }

    #[test]
    fn handshake_init_from_unconfigured_key_is_not_admitted() {
        // A real local keypair, so a HandshakeInit correctly targeting it
        // completes the Noise handshake successfully — isolating the
        // admission check (not Noise itself) as the thing under test.
        let local_kp = generate_keypair();
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let mut pm = PeerManager::new(
            local_kp.private,
            local_kp.public,
            &[peer_a],
            TunnelMode::L3Tun,
        );

        // A valid HandshakeInit from a real, but unconfigured, key.
        let stranger = generate_keypair();
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&stranger.private, &local_kp.public).unwrap();

        let src: SocketAddr = "203.0.113.5:5".parse().unwrap();
        match pm.on_udp(src, &init_pkt, 0) {
            DispatchOut::None => {}
            _ => panic!("must not admit or reply to an unconfigured HandshakeInit"),
        }
        assert!(pm.by_tag.is_empty(), "no peer must have been admitted");
    }

    #[test]
    fn local_addr_matches_node_addr_of_local_pub() {
        let local_pub = [42u8; 32];
        let pm = PeerManager::new([1u8; 32], local_pub, &[], TunnelMode::L3Tun);
        assert_eq!(pm.local_addr(), node_addr(&local_pub));
    }

    /// The `conn_tag` of a peer's Established session, or `None` if it is not
    /// (yet) Established. Used by the handshake state-machine tests below.
    fn established_tag(pm: &PeerManager, idx: usize) -> Option<u64> {
        match &pm.peers[idx].state {
            PeerState::Established(dp) => Some(dp.conn_tag()),
            _ => None,
        }
    }

    /// Copy out every `[HandshakeResp]` datagram's bytes from a `DispatchOut`
    /// (decoupling from the borrow so the caller can keep driving the manager).
    fn resp_bytes(out: &DispatchOut<'_>) -> Vec<Vec<u8>> {
        let egress: &[EgressDatagram] = match out {
            DispatchOut::Udp(e) | DispatchOut::Both(_, e) => e,
            _ => &[],
        };
        egress
            .iter()
            .filter(|d| d.bytes.first() == Some(&(PacketType::HandshakeResp as u8)))
            .map(|d| d.bytes.clone())
            .collect()
    }

    /// A minimal IPv4 packet, enough to drive `on_tun` (single-peer fallback
    /// routes it to the sole peer regardless of contents).
    fn dummy_tun_pkt() -> Vec<u8> {
        vec![0x45u8; 40]
    }

    #[test]
    fn glare_simultaneous_init_converges_on_one_session() {
        // Both peers configured with each other; neither initiates until it
        // has traffic. Drive *both* to initiate at once (the startup-glare
        // race), then cross-feed the messages and assert both converge on ONE
        // shared session (identical conn_tag) rather than two mismatched ones.
        let kp_a = generate_keypair();
        let kp_b = generate_keypair();
        let ep_a: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let ep_b: SocketAddr = "10.0.0.2:2000".parse().unwrap();
        let cfg_b = PeerConfig {
            public_key: kp_b.public,
            endpoint: ep_b,
        };
        let cfg_a = PeerConfig {
            public_key: kp_a.public,
            endpoint: ep_a,
        };
        let mut pm_a = PeerManager::new(kp_a.private, kp_a.public, &[cfg_b], TunnelMode::L3Tun);
        let mut pm_b = PeerManager::new(kp_b.private, kp_b.public, &[cfg_a], TunnelMode::L3Tun);

        // Each side sends a HandshakeInit (triggered by its own outbound TUN
        // traffic) before hearing from the other — the glare.
        let pkt = dummy_tun_pkt();
        let init_a = pm_a.on_tun(&pkt, 0)[0].bytes.clone();
        let init_b = pm_b.on_tun(&pkt, 0)[0].bytes.clone();
        assert_eq!(init_a[0], PacketType::HandshakeInit as u8);
        assert_eq!(init_b[0], PacketType::HandshakeInit as u8);

        // Cross-feed the competing inits. Exactly one side (the larger key)
        // adopts the responder role and replies; the other (smaller key)
        // ignores the competing init and keeps its own attempt.
        let resp_from_a = resp_bytes(&pm_a.on_udp(ep_b, &init_b, 0));
        let resp_from_b = resp_bytes(&pm_b.on_udp(ep_a, &init_a, 0));
        let total_resps = resp_from_a.len() + resp_from_b.len();
        assert_eq!(
            total_resps, 1,
            "exactly one side must adopt the responder role under glare"
        );

        // Deliver whichever HandshakeResp was produced back to the initiator
        // that is still handshaking; it completes on the responder's session.
        for r in &resp_from_a {
            pm_b.on_udp(ep_a, r, 0);
        }
        for r in &resp_from_b {
            pm_a.on_udp(ep_b, r, 0);
        }

        let tag_a = established_tag(&pm_a, 0).expect("pm_a must be Established");
        let tag_b = established_tag(&pm_b, 0).expect("pm_b must be Established");
        assert_eq!(
            tag_a, tag_b,
            "both peers must converge on ONE shared session (matching conn_tag)"
        );
    }

    #[test]
    fn duplicate_init_after_established_does_not_tear_down_session() {
        // Regression: a duplicated/retransmitted HandshakeInit arriving after
        // the responder has already established MUST NOT rebuild the session
        // (a fresh Noise ephemeral would strand the peer on the old keys).
        // The responder re-sends its cached HandshakeResp verbatim instead.
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.7:7000".parse().unwrap();
        let cfg_i = PeerConfig {
            public_key: kp_i.public,
            endpoint: ep_i,
        };
        let mut pm_r = PeerManager::new(kp_r.private, kp_r.public, &[cfg_i], TunnelMode::L3Tun);

        // The initiator's HandshakeInit (built out-of-band, as if received).
        let (_hs, init_pkt) = HandshakeState::start_initiator(&kp_i.private, &kp_r.public).unwrap();

        // First delivery establishes the responder session; capture its reply.
        let resp1 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt, 0));
        assert_eq!(resp1.len(), 1, "first init must produce one HandshakeResp");
        let tag1 = established_tag(&pm_r, 0).expect("responder must be Established");

        // A duplicate of the SAME init: session must be untouched and the
        // reply must be the exact cached bytes (not a freshly-built one).
        let resp2 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt, 0));
        let tag2 = established_tag(&pm_r, 0).expect("responder must stay Established");
        assert_eq!(tag1, tag2, "duplicate init must not rekey the live session");
        assert_eq!(
            resp2, resp1,
            "duplicate init must re-send the cached HandshakeResp verbatim"
        );
    }

    #[test]
    fn initiator_retransmits_same_init_within_total_window_then_gives_up() {
        // Regression for the loss-induced wedge: the initiator must keep
        // retransmitting the SAME init (holding one ephemeral) well past the
        // old 5-retry cap, so a responder's cached reply stays valid and
        // ordinary handshake-packet loss is overcome by retransmission — never
        // resetting to a fresh ephemeral mid-attempt. Only after the whole
        // HANDSHAKE_TOTAL_MS window does it give up.
        let kp_local = generate_keypair();
        let peer = PeerConfig {
            public_key: [7u8; 32],
            endpoint: "10.0.0.9:9000".parse().unwrap(),
        };
        let mut pm = PeerManager::new(
            kp_local.private,
            kp_local.public,
            &[peer],
            TunnelMode::L3Tun,
        );

        // Kick off a lazy handshake with an outbound TUN packet.
        let init_out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert_eq!(init_out.len(), 1);
        let init_bytes = init_out[0].bytes.clone();
        assert_eq!(init_bytes[0], PacketType::HandshakeInit as u8);
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));

        // Drive tick ~20 retry intervals — 4x the old MAX_RETRIES=5 cap. Each
        // interval must retransmit the identical init and keep it Handshaking.
        let mut t = 0u64;
        for _ in 0..20 {
            t += HANDSHAKE_RETRY_MS;
            let out = pm.tick(t).map(<[_]>::to_vec).unwrap_or_default();
            assert_eq!(out.len(), 1, "a retransmit is emitted every retry interval");
            assert_eq!(
                out[0].bytes, init_bytes,
                "retransmit reuses the same init (same ephemeral)"
            );
            assert!(
                matches!(pm.peers[0].state, PeerState::Handshaking(_)),
                "peer keeps handshaking within the total window (past the old 5-retry cap)"
            );
        }

        // Once the whole window elapses, the attempt is abandoned.
        let out = pm
            .tick(HANDSHAKE_TOTAL_MS + HANDSHAKE_RETRY_MS)
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        assert!(
            out.is_empty(),
            "no further init once the total window elapsed"
        );
        assert!(
            matches!(pm.peers[0].state, PeerState::Idle),
            "peer reverts to Idle after the total window"
        );
        assert!(
            pm.peers[0].pending_tun.is_empty(),
            "pending buffer cleared on give-up"
        );
    }

    #[test]
    fn pending_tun_is_capped_while_handshaking() {
        let kp_local = generate_keypair();
        let peer = PeerConfig {
            public_key: [7u8; 32],
            endpoint: "10.0.0.9:9000".parse().unwrap(),
        };
        let mut pm = PeerManager::new(
            kp_local.private,
            kp_local.public,
            &[peer],
            TunnelMode::L3Tun,
        );

        // Stream far more packets than the cap while the peer is Handshaking.
        for _ in 0..(MAX_PENDING_TUN + 50) {
            let _ = pm.on_tun(&dummy_tun_pkt(), 0);
        }
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
        assert!(
            pm.peers[0].pending_tun.len() <= MAX_PENDING_TUN,
            "pending buffer must stay capped at MAX_PENDING_TUN"
        );
    }
}
