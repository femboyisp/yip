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
use yip_rendezvous::{node_id, NodeId};

use crate::addr::node_addr;
use crate::config::PeerConfig;
use crate::dataplane::{conn_tag_from_keys, DataPlane, Outcome};
use crate::handshake::{HandshakeState, PacketType};
use crate::mode::TunnelMode;
use crate::path::{PathAction, PathKind, PathStage, PathState};
use crate::rendezvous::{RdvEvent, Rendezvous};

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

/// How often (ms) we re-emit `register(local_node_id)` to the rendezvous
/// server so it keeps our reflexive UDP binding fresh (only when a rendezvous
/// server is configured).
const REG_REFRESH_MS: u64 = 20_000;

/// Minimum spacing (ms) between successive `lookup` datagrams for the same
/// peer while it is still searching for a candidate — debounces the
/// `NeedLookup` action so `tick`/`on_tun` do not spam the server every call.
const LOOKUP_INTERVAL_MS: u64 = 1_000;

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
    /// The address this `Init` is being probed toward (the path SM's chosen
    /// candidate: the configured endpoint for a Direct probe, a reflexive
    /// candidate for a Punch probe, or the rendezvous server for a Relay
    /// probe). Retransmits target this address (or are relay-wrapped when the
    /// peer is `relay`).
    target: SocketAddr,
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
    /// `PeerManager::handle_handshake_init`). `None` until a direct candidate
    /// is known — a peer configured with no `endpoint` is reachable only via
    /// rendezvous/relay, which Task 6 wires into this path; such a peer
    /// cannot yet be routed to directly (see `on_tun`'s `Idle` branch).
    endpoint: Option<SocketAddr>,
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
    /// This peer's self-certifying rendezvous node id (`node_id(pubkey)`),
    /// used to `lookup`/`relay` for it and to demux `RdvEvent`s back to it.
    node: NodeId,
    /// Per-peer connection path state machine (Direct → Punch → Relay). Only
    /// consulted when a rendezvous server is configured; with no rendezvous a
    /// peer's direct endpoint is probed exactly as in 2a and this SM is never
    /// advanced.
    path: PathState,
    /// The committed path kind, set once a handshake completes. `None` until
    /// the session is established. Drives relay egress re-wrap for `Relayed`.
    path_kind: Option<PathKind>,
    /// Whether this peer is currently reached via the relay (server) rather
    /// than directly: every egress datagram for it (handshake and data plane)
    /// is wrapped through `rendezvous.relay`. Set on a Relay-stage probe or on
    /// admitting a relayed handshake; only mutated while the peer is
    /// non-`Established` (anti-hijack).
    relay: bool,
    /// When we last emitted a `lookup` for this peer (debounces `NeedLookup`);
    /// `None` until the first lookup is sent.
    last_lookup_ms: Option<u64>,
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
    /// `node_id -> peers index`, populated at construction. Used to demux
    /// `RdvEvent`s (which are keyed by rendezvous node id) back to a peer.
    by_node: HashMap<NodeId, usize>,
    /// The configured rendezvous+relay client, or `None` for a pure-2a
    /// (direct-only) deployment. When `None`, `on_udp`/`on_tun`/`tick` never
    /// consult the path SM and behave byte-identically to 2a.
    rendezvous: Option<Box<dyn Rendezvous>>,
    /// This node's own rendezvous node id (`node_id(local_pub)`), the `src`
    /// for `register`/`relay`.
    local_node_id: NodeId,
    /// When we last emitted `register(local_node_id)` (see [`REG_REFRESH_MS`]).
    last_register_ms: u64,
    /// Whether we have registered at least once (so the first `tick` registers
    /// promptly rather than waiting a full [`REG_REFRESH_MS`] interval — the
    /// loop clock starts at 0).
    registered_once: bool,
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
        rendezvous: Option<Box<dyn Rendezvous>>,
    ) -> Self {
        let has_rendezvous = rendezvous.is_some();
        let mut peers = Vec::with_capacity(peers_cfg.len());
        let mut by_addr = HashMap::with_capacity(peers_cfg.len());
        let mut by_node = HashMap::with_capacity(peers_cfg.len());
        for (i, p) in peers_cfg.iter().enumerate() {
            let addr = node_addr(&p.public_key);
            by_addr.insert(addr, i);
            let node = node_id(&p.public_key);
            by_node.insert(node, i);
            // A peer with a configured endpoint starts in the Direct stage with
            // that endpoint seeded; a rendezvous-only peer starts in Punching
            // (if a server is configured) or Failed. See `PathState::new`.
            let mut path = PathState::new(p.endpoint.is_some(), has_rendezvous, 0);
            if let Some(ep) = p.endpoint {
                path.on_direct_addr(ep);
            }
            peers.push(Peer {
                pubkey: p.public_key,
                addr,
                endpoint: p.endpoint,
                state: PeerState::Idle,
                pending_tun: Vec::new(),
                cached_resp: None,
                node,
                path,
                path_kind: None,
                relay: false,
                last_lookup_ms: None,
            });
        }
        Self {
            local_priv,
            local_pub,
            mode,
            peers,
            by_tag: HashMap::new(),
            by_addr,
            by_node,
            rendezvous,
            local_node_id: node_id(&local_pub),
            last_register_ms: 0,
            registered_once: false,
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

    // ── rendezvous / path helpers ─────────────────────────────────────────

    /// The configured rendezvous server address (only meaningful when a
    /// rendezvous is configured; falls back to the unspecified address).
    fn server_addr(&self) -> SocketAddr {
        self.rendezvous
            .as_ref()
            .map(|r| r.server_addr())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// Map a path stage to the committed [`PathKind`] for a session that
    /// completes while in that stage. `Relayed` peers are committed
    /// explicitly (they never sit in the `Relaying` *stage* when admitted via
    /// a relayed handshake), so `Relaying`/`Failed` fall back to `Punched`.
    fn kind_for_stage(stage: PathStage) -> PathKind {
        match stage {
            PathStage::Direct => PathKind::Direct,
            PathStage::Punching => PathKind::Punched,
            // Lossy fallback: only reached for a *non-relayed* completion (a
            // relayed completion commits `Relayed` explicitly, never routing
            // here), so mapping these residual stages to `Punched` is safe.
            PathStage::Relaying | PathStage::Failed => PathKind::Punched,
        }
    }

    /// Wrap a raw egress datagram destined for peer `idx` through the relay
    /// (`rendezvous.relay(local, peer_node, raw)` → dst = server). Returns
    /// `None` if no rendezvous is configured (should not happen for a peer
    /// marked `relay`).
    fn relay_wrap(&mut self, idx: usize, raw: Vec<u8>) -> Option<EgressDatagram> {
        let node = self.peers[idx].node;
        let local = self.local_node_id;
        self.rendezvous.as_mut().map(|r| r.relay(local, node, &raw))
    }

    /// Start a fresh initiator handshake toward `target` for peer `idx`,
    /// returning the framed egress datagram to send (relay-wrapped when
    /// `via_relay`). Transitions the peer to `Handshaking`. Returns `None`
    /// (leaving the peer as it was) if the Noise step or the relay wrap fails.
    ///
    /// The caller is responsible for only invoking this on a peer that is not
    /// already `Handshaking`/`Established`.
    fn begin_handshake(
        &mut self,
        idx: usize,
        target: SocketAddr,
        via_relay: bool,
        now_ms: u64,
    ) -> Option<EgressDatagram> {
        let pubkey = self.peers[idx].pubkey;
        let (hs, init_pkt) = match HandshakeState::start_initiator(&self.local_priv, &pubkey, &[]) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("peer_manager: failed to start handshake: {e}");
                return None;
            }
        };
        let dg = if via_relay {
            self.relay_wrap(idx, init_pkt.clone())?
        } else {
            EgressDatagram {
                fate: 0,
                dst: target,
                bytes: init_pkt.clone(),
            }
        };
        if via_relay {
            self.peers[idx].relay = true;
        } else {
            // Direct/Punch probe: route this peer's traffic (and the
            // `[HandshakeResp]` match in `handle_handshake_resp`) to `target`.
            self.peers[idx].endpoint = Some(target);
        }
        self.peers[idx].state = PeerState::Handshaking(Box::new(HandshakingState {
            hs,
            started_ms: now_ms,
            last_sent_ms: now_ms,
            retries: 0,
            init_pkt,
            target,
        }));
        Some(dg)
    }

    /// Emit a `lookup(peer_node)` for peer `idx`, debounced to at most one per
    /// [`LOOKUP_INTERVAL_MS`]. Returns `None` if throttled or no rendezvous.
    fn maybe_lookup(&mut self, idx: usize, now_ms: u64) -> Option<EgressDatagram> {
        let due = match self.peers[idx].last_lookup_ms {
            None => true,
            Some(t) => now_ms.saturating_sub(t) >= LOOKUP_INTERVAL_MS,
        };
        if !due {
            return None;
        }
        let node = self.peers[idx].node;
        let dg = self.rendezvous.as_mut().map(|r| r.lookup(node))?;
        self.peers[idx].last_lookup_ms = Some(now_ms);
        Some(dg)
    }

    /// Drive the path SM for a non-`Established`, non-`Handshaking` (i.e.
    /// `Idle`) peer `idx` and act on the resulting [`PathAction`], pushing any
    /// egress into `tick_egress`. Only called when a rendezvous is configured.
    fn drive_path_idle(&mut self, idx: usize, now_ms: u64) {
        match self.peers[idx].path.advance(now_ms) {
            PathAction::Probe(addr) => {
                if let Some(dg) = self.begin_handshake(idx, addr, false, now_ms) {
                    self.tick_egress.push(dg);
                }
            }
            PathAction::Relay => {
                let server = self.server_addr();
                if let Some(dg) = self.begin_handshake(idx, server, true, now_ms) {
                    self.tick_egress.push(dg);
                }
            }
            PathAction::NeedLookup => {
                if let Some(dg) = self.maybe_lookup(idx, now_ms) {
                    self.tick_egress.push(dg);
                }
            }
            PathAction::Idle | PathAction::Failed => {}
        }
    }

    /// Demux a datagram that arrived from the rendezvous server: parse it into
    /// an [`RdvEvent`] and drive the path SM / relay path accordingly. Every
    /// mutation is guarded to affect only a non-`Established` peer
    /// (anti-hijack): a live session's committed egress target is never
    /// redirected by an unauthenticated server message.
    fn on_rdv(&mut self, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        let ev = match self.rendezvous.as_ref() {
            Some(r) => r.parse(dg),
            None => return DispatchOut::None,
        };
        match ev {
            RdvEvent::PeerCandidate { node, addr } => {
                if let Some(&idx) = self.by_node.get(&node) {
                    if !matches!(self.peers[idx].state, PeerState::Established(_)) {
                        self.peers[idx].path.on_peer_candidate(addr, now_ms);
                    }
                }
                DispatchOut::None
            }
            RdvEvent::PunchTo { node, addr } => {
                if let Some(&idx) = self.by_node.get(&node) {
                    if !matches!(self.peers[idx].state, PeerState::Established(_)) {
                        self.peers[idx].path.on_peer_candidate(addr, now_ms);
                        // Open our own binding toward `addr` immediately so the
                        // two NATs punch simultaneously — but only if we are not
                        // already probing (keep the in-flight ephemeral).
                        if matches!(self.peers[idx].state, PeerState::Idle) {
                            if let Some(dg) = self.begin_handshake(idx, addr, false, now_ms) {
                                self.egress.clear();
                                self.egress.push(dg);
                                return DispatchOut::Udp(&self.egress);
                            }
                        }
                    }
                }
                DispatchOut::None
            }
            RdvEvent::Relayed { src, payload } => self.on_relayed(src, &payload, now_ms),
            RdvEvent::NotFound { .. } | RdvEvent::Ignored => DispatchOut::None,
        }
    }

    /// Process a peer datagram delivered *through the relay* (`RdvEvent::Relayed`):
    /// it is a handshake or data-plane packet from `src_node`, and any egress it
    /// produces must go back out through the relay (dst = server). Mirrors the
    /// direct `on_udp` demux but relay-wraps replies and commits `Relayed`.
    fn on_relayed(&mut self, src_node: NodeId, payload: &[u8], now_ms: u64) -> DispatchOut<'_> {
        if payload.is_empty() {
            return DispatchOut::None;
        }
        let Some(&idx) = self.by_node.get(&src_node) else {
            return DispatchOut::None;
        };
        // Mark this peer as relay-reached before producing any egress — but only
        // while it is not Established (anti-hijack: never re-route a live
        // session onto the relay from an unauthenticated server message).
        if !matches!(self.peers[idx].state, PeerState::Established(_)) {
            self.peers[idx].relay = true;
        }

        if payload[0] == PacketType::HandshakeInit as u8 {
            self.relayed_handshake_init(idx, payload, now_ms)
        } else if payload[0] == PacketType::HandshakeResp as u8 {
            self.relayed_handshake_resp(idx, payload, now_ms)
        } else {
            self.relayed_data(idx, payload, now_ms)
        }
    }

    /// Relay-path counterpart of [`handle_handshake_init`]: admit a relayed
    /// `[HandshakeInit]` from peer `idx`, reply and drain via the relay, and
    /// commit `PathKind::Relayed`.
    fn relayed_handshake_init(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        let (established, resp_pkt, remote_static, _initiator_payload) =
            match HandshakeState::start_responder(&self.local_priv, dg, &[]) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("peer_manager: relayed start_responder failed: {e}");
                    return DispatchOut::None;
                }
            };
        if remote_static != self.peers[idx].pubkey {
            return DispatchOut::None;
        }

        match &self.peers[idx].state {
            PeerState::Established(_) => match self.peers[idx].cached_resp.clone() {
                Some(resp) => {
                    self.egress.clear();
                    if let Some(d) = self.relay_wrap(idx, resp) {
                        self.egress.push(d);
                    }
                    DispatchOut::Udp(&self.egress)
                }
                None => DispatchOut::None,
            },
            PeerState::Handshaking(_) if self.local_pub < self.peers[idx].pubkey => {
                DispatchOut::None
            }
            PeerState::Idle | PeerState::Handshaking(_) => {
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                // A relay peer's egress is always re-wrapped, so the DataPlane's
                // stamped `dst` is unused: seed it with the server address.
                let placeholder = self.server_addr();
                let mut dp = Box::new(DataPlane::new(
                    established,
                    conn_tag,
                    self.mode,
                    placeholder,
                ));

                self.peers[idx].cached_resp = Some(resp_pkt.clone());
                self.peers[idx].relay = true;
                self.peers[idx].path.committed(PathKind::Relayed);
                self.peers[idx].path_kind = Some(PathKind::Relayed);
                self.by_tag.insert(dp.conn_tag(), idx);

                self.egress.clear();
                if let Some(d) = self.relay_wrap(idx, resp_pkt) {
                    self.egress.push(d);
                }
                let pending = std::mem::take(&mut self.peers[idx].pending_tun);
                let mut owned: Vec<Vec<u8>> = Vec::new();
                for inner in &pending {
                    owned.extend(
                        dp.on_tun_packet(inner, now_ms)
                            .iter()
                            .map(|d| d.bytes.clone()),
                    );
                }
                self.peers[idx].state = PeerState::Established(dp);
                for b in owned {
                    if let Some(d) = self.relay_wrap(idx, b) {
                        self.egress.push(d);
                    }
                }
                DispatchOut::Udp(&self.egress)
            }
        }
    }

    /// Relay-path counterpart of [`handle_handshake_resp`]: complete a relayed
    /// `[HandshakeResp]` from peer `idx` and commit `PathKind::Relayed`.
    fn relayed_handshake_resp(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        if !matches!(self.peers[idx].state, PeerState::Handshaking(_)) {
            return DispatchOut::None;
        }
        let old_state = std::mem::replace(&mut self.peers[idx].state, PeerState::Idle);
        let PeerState::Handshaking(handshaking) = old_state else {
            unreachable!("just matched Handshaking above");
        };
        match handshaking.hs.read_response(dg) {
            Ok((established, _responder_payload)) => {
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                let placeholder = self.server_addr();
                let mut dp = Box::new(DataPlane::new(
                    established,
                    conn_tag,
                    self.mode,
                    placeholder,
                ));
                self.by_tag.insert(dp.conn_tag(), idx);
                self.peers[idx].relay = true;
                self.peers[idx].path.committed(PathKind::Relayed);
                self.peers[idx].path_kind = Some(PathKind::Relayed);

                self.egress.clear();
                let pending = std::mem::take(&mut self.peers[idx].pending_tun);
                let mut owned: Vec<Vec<u8>> = Vec::new();
                for inner in &pending {
                    owned.extend(
                        dp.on_tun_packet(inner, now_ms)
                            .iter()
                            .map(|d| d.bytes.clone()),
                    );
                }
                self.peers[idx].state = PeerState::Established(dp);
                for b in owned {
                    if let Some(d) = self.relay_wrap(idx, b) {
                        self.egress.push(d);
                    }
                }
                if self.egress.is_empty() {
                    DispatchOut::None
                } else {
                    DispatchOut::Udp(&self.egress)
                }
            }
            Err(e) => {
                eprintln!("peer_manager: relayed read_response failed: {e}");
                DispatchOut::None
            }
        }
    }

    /// Relay-path counterpart of the `Data`/`Control` demux: dispatch a relayed
    /// data-plane datagram to peer `idx`'s `DataPlane` and relay-wrap any UDP
    /// egress it produces (TUN writes still go to the local device).
    fn relayed_data(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        let (tun, udp): (Option<Vec<u8>>, Vec<Vec<u8>>) = {
            let PeerState::Established(dp) = &mut self.peers[idx].state else {
                return DispatchOut::None;
            };
            match dp.on_udp_datagram(dg, now_ms) {
                Outcome::None => (None, Vec::new()),
                Outcome::TunWrite(buf) => (Some(buf.to_vec()), Vec::new()),
                Outcome::Send(pkts) => (None, pkts.iter().map(|d| d.bytes.clone()).collect()),
                Outcome::TunWriteThenSend(buf, pkts) => (
                    Some(buf.to_vec()),
                    pkts.iter().map(|d| d.bytes.clone()).collect(),
                ),
            }
        };
        self.egress.clear();
        for b in udp {
            if let Some(d) = self.relay_wrap(idx, b) {
                self.egress.push(d);
            }
        }
        match (tun, self.egress.is_empty()) {
            (Some(t), true) => {
                self.tun_scratch = t;
                DispatchOut::Tun(&self.tun_scratch)
            }
            (Some(t), false) => {
                self.tun_scratch = t;
                DispatchOut::Both(&self.tun_scratch, &self.egress)
            }
            (None, false) => DispatchOut::Udp(&self.egress),
            (None, true) => DispatchOut::None,
        }
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
            .position(|p| p.endpoint == Some(src) && matches!(p.state, PeerState::Established(_)))
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
        let (established, resp_pkt, remote_static, _initiator_payload) =
            match HandshakeState::start_responder(&self.local_priv, dg, &[]) {
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

                self.peers[idx].endpoint = Some(src); // learn the observed endpoint
                self.peers[idx].cached_resp = Some(resp_pkt.clone());
                self.by_tag.insert(dp.conn_tag(), idx);
                // Commit the path we completed over. `src` is a direct address
                // (this arm is only reached for non-relayed inits — relayed
                // inits go through `relayed_handshake_init`), so the kind is
                // Direct (stage Direct) or Punched (stage Punching).
                let kind = Self::kind_for_stage(self.peers[idx].path.stage());
                self.peers[idx].path.committed(kind);
                self.peers[idx].path_kind = Some(kind);
                // A non-relayed init completed: this is a direct/punched
                // session. Clear any stale `relay` flag left by an earlier
                // escalation whose relayed attempt this direct/punch completion
                // raced (else `on_tun`/`tick` would relay-wrap direct egress).
                self.peers[idx].relay = false;

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
            .position(|p| p.endpoint == Some(src) && matches!(p.state, PeerState::Handshaking(_)))
        else {
            return DispatchOut::None;
        };

        let old_state = std::mem::replace(&mut self.peers[idx].state, PeerState::Idle);
        let PeerState::Handshaking(handshaking) = old_state else {
            unreachable!("index was matched against PeerState::Handshaking above");
        };

        match handshaking.hs.read_response(dg) {
            Ok((established, _responder_payload)) => {
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                // `idx` was matched above via `p.endpoint == Some(src)`, so `src`
                // is exactly this peer's endpoint.
                let mut dp = Box::new(DataPlane::new(established, conn_tag, self.mode, src));
                self.by_tag.insert(dp.conn_tag(), idx);
                // `src` == this peer's `endpoint` (matched above). Commit the
                // path stage we completed over (Direct or Punched); a relayed
                // resp is handled by `relayed_handshake_resp` instead.
                self.peers[idx].endpoint = Some(src);
                let kind = Self::kind_for_stage(self.peers[idx].path.stage());
                self.peers[idx].path.committed(kind);
                self.peers[idx].path_kind = Some(kind);
                // Non-relayed resp completed a direct/punched session: clear any
                // stale `relay` flag from a raced escalation (see the mirror in
                // `handle_handshake_init`).
                self.peers[idx].relay = false;

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
        // Rendezvous-server demux: a datagram from the configured server is a
        // control/relay message, not peer traffic. Skipped entirely when no
        // rendezvous is configured (pure-2a: no server-addr check at all).
        if let Some(server) = self.rendezvous.as_ref().map(|r| r.server_addr()) {
            if src == server {
                return self.on_rdv(dg, now_ms);
            }
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
            // A relay-reached peer's data-plane egress must be re-wrapped
            // through the server (dst = server); copy the bytes out first (the
            // DataPlane borrows `self.peers[idx]`) then wrap. A direct/punched
            // peer's datagrams already carry the correct `dst` — return them
            // borrowed, byte-identical to 2a.
            if !self.peers[idx].relay {
                let PeerState::Established(dp) = &mut self.peers[idx].state else {
                    unreachable!("just matched Established above");
                };
                return dp.on_tun_packet(inner, now_ms);
            }
            let owned: Vec<Vec<u8>> = {
                let PeerState::Established(dp) = &mut self.peers[idx].state else {
                    unreachable!("just matched Established above");
                };
                dp.on_tun_packet(inner, now_ms)
                    .iter()
                    .map(|d| d.bytes.clone())
                    .collect()
            };
            self.egress.clear();
            for b in owned {
                if let Some(d) = self.relay_wrap(idx, b) {
                    self.egress.push(d);
                }
            }
            return &self.egress;
        }

        if matches!(self.peers[idx].state, PeerState::Handshaking(_)) {
            Self::push_pending(&mut self.peers[idx].pending_tun, inner);
            return &[];
        }

        // Idle: buffer this packet and decide how to bring the peer up.
        Self::push_pending(&mut self.peers[idx].pending_tun, inner);
        // With no rendezvous configured, behave exactly as 2a: probe the
        // configured endpoint if there is one (else the peer is unreachable and
        // the packet stays buffered). With a rendezvous configured, ask the
        // path SM which candidate/action to take.
        let action = if self.rendezvous.is_some() {
            self.peers[idx].path.advance(now_ms)
        } else {
            match self.peers[idx].endpoint {
                Some(ep) => PathAction::Probe(ep),
                None => PathAction::Idle,
            }
        };
        let dg = match action {
            PathAction::Probe(addr) => self.begin_handshake(idx, addr, false, now_ms),
            PathAction::Relay => {
                let server = self.server_addr();
                self.begin_handshake(idx, server, true, now_ms)
            }
            PathAction::NeedLookup => self.maybe_lookup(idx, now_ms),
            PathAction::Idle | PathAction::Failed => None,
        };
        match dg {
            Some(d) => {
                self.egress.clear();
                self.egress.push(d);
                &self.egress
            }
            None => &[],
        }
    }

    fn tick(&mut self, now_ms: u64) -> Option<&[EgressDatagram]> {
        self.tick_egress.clear();

        // ── registration refresh ──────────────────────────────────────────
        // Keep our reflexive binding fresh on the server so peers can find us.
        if self.rendezvous.is_some()
            && (!self.registered_once
                || now_ms.saturating_sub(self.last_register_ms) >= REG_REFRESH_MS)
        {
            let node = self.local_node_id;
            if let Some(r) = self.rendezvous.as_mut() {
                self.tick_egress.push(r.register(node));
            }
            self.last_register_ms = now_ms;
            self.registered_once = true;
        }

        for i in 0..self.peers.len() {
            // ── proactive escalation of an in-flight direct/punch handshake ──
            // With a rendezvous configured, keep driving the path SM while a
            // *non-relay* handshake is in flight (pure-2a peers set no
            // rendezvous and never enter this block, so they cannot regress).
            // The probed candidate's window may have elapsed; escalate NOW
            // rather than retransmitting a doomed Init for the full
            // HANDSHAKE_TOTAL_MS. Escalation supersedes the 2a retransmit arm
            // below — we `continue`, so a peer is never both retransmitted (old
            // target) AND escalated in the same tick.
            if self.rendezvous.is_some()
                && !self.peers[i].relay
                && matches!(self.peers[i].state, PeerState::Handshaking(_))
            {
                let target = match &self.peers[i].state {
                    PeerState::Handshaking(h) => h.target,
                    _ => unreachable!("matched Handshaking above"),
                };
                match self.peers[i].path.advance(now_ms) {
                    PathAction::Relay => {
                        // Abandon the in-flight direct/punch handshake (drop its
                        // ephemeral) and begin a relay handshake. `pending_tun`
                        // is left intact — it drains when the relay session
                        // completes (strictly better than the 90s-then-clear
                        // give-up path).
                        self.peers[i].state = PeerState::Idle;
                        // Clear the stale direct/punch `endpoint` (the abandoned
                        // attempt's candidate `C`): a relayed peer routes egress
                        // via the `relay` flag through `rendezvous.relay`, NOT
                        // via `endpoint`, and the relay handshake completes
                        // through the `RdvEvent::Relayed` ->
                        // `relayed_handshake_resp` path, which does not use
                        // `endpoint` matching at all. Without this clear, a
                        // late-arriving direct `[HandshakeResp]` from `C` for the
                        // abandoned ephemeral (very plausible on a lossy/
                        // high-latency link — a punch reply just past the
                        // PUNCH_MS window) would still match this peer in
                        // `handle_handshake_resp` (`p.endpoint == Some(src) &&
                        // Handshaking`) and get fed into the *new* relay
                        // ephemeral's `read_response`, which fails
                        // cryptographically and silently discards the fresh
                        // relay attempt (reverting to `Idle` and re-escalating
                        // forever, since `PathStage` only moves forward). With
                        // `endpoint` cleared the stray reply matches no peer and
                        // is dropped harmlessly instead. (Preferring a late punch
                        // reply over the already-committed relay attempt would be
                        // a nicer recovery, but is out of 2b scope.)
                        self.peers[i].endpoint = None;
                        let server = self.server_addr();
                        if let Some(dg) = self.begin_handshake(i, server, true, now_ms) {
                            self.tick_egress.push(dg);
                        }
                        continue;
                    }
                    PathAction::Probe(addr) if addr != target => {
                        // The SM chose a *different* candidate: re-target by
                        // abandoning the current attempt and probing `addr`.
                        self.peers[i].state = PeerState::Idle;
                        if let Some(dg) = self.begin_handshake(i, addr, false, now_ms) {
                            self.tick_egress.push(dg);
                        }
                        continue;
                    }
                    PathAction::NeedLookup => {
                        // The path SM escalated into (or is still in) the punch
                        // stage but has no reflexive candidate yet — e.g. a peer
                        // configured with BOTH a direct endpoint and a
                        // rendezvous: it starts `Handshaking` on the direct
                        // endpoint (via `on_tun`'s Idle branch, which never
                        // touches the path SM again once `Handshaking`), so
                        // without this arm the escalation-only `advance` call
                        // above would see `Direct -> Punching` and return
                        // `NeedLookup` here forever, and this match's old
                        // catch-all treated that as "do nothing" — no `Lookup`
                        // is ever sent, no reflexive candidate is learned, and
                        // the peer can never punch (it just rides out
                        // `HANDSHAKE_TOTAL_MS` on the doomed direct `Init` and
                        // eventually gives up). Emit the debounced lookup, same
                        // as `drive_path_idle` does for an `Idle` peer.
                        //
                        // This does NOT abandon the in-flight direct `Init` —
                        // no state mutation happens here, so the retransmit arm
                        // below still fires this tick if due, keeping the
                        // direct attempt alive alongside the new lookup. Once a
                        // candidate arrives (`on_rdv` -> `on_peer_candidate`), a
                        // later tick's `advance` returns `Probe(candidate)`,
                        // which the `addr != target` arm above re-targets to.
                        if let Some(dg) = self.maybe_lookup(i, now_ms) {
                            self.tick_egress.push(dg);
                        }
                    }
                    // Same target / Idle / Failed: leave the in-flight
                    // handshake alone; the retransmit arm below handles it (do
                    // not double-send).
                    _ => {}
                }
            }

            let relay = self.peers[i].relay;
            let old_state = std::mem::replace(&mut self.peers[i].state, PeerState::Idle);
            let new_state = match old_state {
                PeerState::Established(mut dp) => {
                    if let Some(pkts) = dp.tick(now_ms) {
                        if relay {
                            // Relay-reached peer: re-wrap each datagram through
                            // the server. Copy bytes out (borrow ends) then wrap.
                            let owned: Vec<Vec<u8>> =
                                pkts.iter().map(|d| d.bytes.clone()).collect();
                            for b in owned {
                                if let Some(d) = self.relay_wrap(i, b) {
                                    self.tick_egress.push(d);
                                }
                            }
                        } else {
                            self.tick_egress.extend(pkts.iter().cloned());
                        }
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
                        // HANDSHAKE_TOTAL_MS. Relay-reached peers re-wrap the
                        // retransmit through the server; direct/punched peers
                        // target the probed `target` address.
                        handshaking.retries = handshaking.retries.saturating_add(1);
                        handshaking.last_sent_ms = now_ms;
                        if relay {
                            if let Some(d) = self.relay_wrap(i, handshaking.init_pkt.clone()) {
                                self.tick_egress.push(d);
                            }
                        } else {
                            self.tick_egress.push(EgressDatagram {
                                fate: 0,
                                dst: handshaking.target,
                                bytes: handshaking.init_pkt.clone(),
                            });
                        }
                        PeerState::Handshaking(handshaking)
                    }
                }
                other => other,
            };
            self.peers[i].state = new_state;
        }

        // ── proactive path advancement ────────────────────────────────────
        // Only with a rendezvous configured (pure-2a `tick` is byte-identical
        // to before this block). For each Idle peer, drive the path SM: probe a
        // learned candidate, request a lookup, or escalate to relay — this is
        // what brings up a rendezvous-only (endpoint:None) peer, and keeps
        // hole-punching proactive rather than waiting on TUN traffic.
        if self.rendezvous.is_some() {
            for i in 0..self.peers.len() {
                if matches!(self.peers[i].state, PeerState::Idle) {
                    self.drive_path_idle(i, now_ms);
                }
            }
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
            endpoint: Some(endpoint.parse().unwrap()),
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
        let m1 = ini.write_message(&[]).unwrap();
        let _ = res.read_message(&m1).unwrap();
        let m2 = res.write_message(&[]).unwrap();
        let _ = ini.read_message(&m2).unwrap();
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
            None,
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
            None,
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
        let pm = PeerManager::new([9u8; 32], [8u8; 32], &[peer_a], TunnelMode::L3Tun, None);

        // A bare IPv4 packet: first nibble is 4, not 6.
        let inner = vec![0x45u8; 40];
        assert_eq!(pm.route_tun_index(&inner), Some(0));
    }

    #[test]
    fn route_tun_index_l3_ambiguous_multi_peer_drops() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let peer_b = peer_cfg(2, "10.0.0.2:2000");
        let pm = PeerManager::new(
            [9u8; 32],
            [8u8; 32],
            &[peer_a, peer_b],
            TunnelMode::L3Tun,
            None,
        );

        let inner = vec![0x45u8; 40]; // IPv4, matches no by_addr entry
        assert_eq!(pm.route_tun_index(&inner), None);
    }

    #[test]
    fn route_tun_index_l2_single_peer_forwards_regardless_of_inner() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let pm = PeerManager::new([9u8; 32], [8u8; 32], &[peer_a], TunnelMode::L2Tap, None);

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
            None,
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
            peer_b.endpoint.unwrap(),
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
        assert_eq!(
            pm.route_data(peer_b.endpoint.unwrap(), &untagged_dg),
            Some(1)
        );
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
            None,
        );

        // A valid HandshakeInit from a real, but unconfigured, key.
        let stranger = generate_keypair();
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&stranger.private, &local_kp.public, &[]).unwrap();

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
        let pm = PeerManager::new([1u8; 32], local_pub, &[], TunnelMode::L3Tun, None);
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
            endpoint: Some(ep_b),
        };
        let cfg_a = PeerConfig {
            public_key: kp_a.public,
            endpoint: Some(ep_a),
        };
        let mut pm_a =
            PeerManager::new(kp_a.private, kp_a.public, &[cfg_b], TunnelMode::L3Tun, None);
        let mut pm_b =
            PeerManager::new(kp_b.private, kp_b.public, &[cfg_a], TunnelMode::L3Tun, None);

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
            endpoint: Some(ep_i),
        };
        let mut pm_r =
            PeerManager::new(kp_r.private, kp_r.public, &[cfg_i], TunnelMode::L3Tun, None);

        // The initiator's HandshakeInit (built out-of-band, as if received).
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&kp_i.private, &kp_r.public, &[]).unwrap();

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
            endpoint: Some("10.0.0.9:9000".parse().unwrap()),
        };
        let mut pm = PeerManager::new(
            kp_local.private,
            kp_local.public,
            &[peer],
            TunnelMode::L3Tun,
            None,
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
            endpoint: Some("10.0.0.9:9000".parse().unwrap()),
        };
        let mut pm = PeerManager::new(
            kp_local.private,
            kp_local.public,
            &[peer],
            TunnelMode::L3Tun,
            None,
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

    // ── rendezvous wiring (mock Rendezvous) ───────────────────────────────

    /// A mock `Rendezvous` that records the messages it is asked to send (so a
    /// test can assert on them) and parses injected server datagrams the same
    /// way `ConfiguredServerRendezvous` does. `parse` reuses the real decoder,
    /// so a test injects an event by `encode`-ing a `Message` and feeding it to
    /// `on_udp(server, ..)`.
    struct MockRdv {
        server: SocketAddr,
        sent: std::rc::Rc<std::cell::RefCell<Vec<yip_rendezvous::Message>>>,
    }

    impl MockRdv {
        fn to_server(&self, msg: yip_rendezvous::Message) -> EgressDatagram {
            self.sent.borrow_mut().push(msg.clone());
            let mut bytes = Vec::new();
            yip_rendezvous::encode(&msg, &mut bytes);
            EgressDatagram {
                fate: 0,
                dst: self.server,
                bytes,
            }
        }
    }

    impl Rendezvous for MockRdv {
        fn register(&mut self, node: NodeId) -> EgressDatagram {
            self.to_server(yip_rendezvous::Message::Register { node })
        }
        fn lookup(&mut self, node: NodeId) -> EgressDatagram {
            self.to_server(yip_rendezvous::Message::Lookup { node })
        }
        fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram {
            self.to_server(yip_rendezvous::Message::RelaySend {
                src,
                dst,
                payload: payload.to_vec(),
            })
        }
        fn parse(&self, dg: &[u8]) -> RdvEvent {
            match yip_rendezvous::decode(dg) {
                Some(yip_rendezvous::Message::PeerInfo { node, reflexive }) => {
                    RdvEvent::PeerCandidate {
                        node,
                        addr: reflexive,
                    }
                }
                Some(yip_rendezvous::Message::PunchHint { node, reflexive }) => RdvEvent::PunchTo {
                    node,
                    addr: reflexive,
                },
                Some(yip_rendezvous::Message::RelayDeliver { src, payload }) => {
                    RdvEvent::Relayed { src, payload }
                }
                Some(yip_rendezvous::Message::NotFound { node }) => RdvEvent::NotFound { node },
                _ => RdvEvent::Ignored,
            }
        }
        fn server_addr(&self) -> SocketAddr {
            self.server
        }
    }

    fn mock_server() -> SocketAddr {
        "203.0.113.1:51821".parse().unwrap()
    }

    /// Build a `PeerManager` with a `MockRdv` rendezvous, returning the manager
    /// and a shared handle to the messages the mock is asked to send.
    fn pm_with_mock_rdv(
        local: &yip_crypto::Keypair,
        peers: &[PeerConfig],
    ) -> (
        PeerManager,
        std::rc::Rc<std::cell::RefCell<Vec<yip_rendezvous::Message>>>,
    ) {
        let sent = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let rdv: Box<dyn Rendezvous> = Box::new(MockRdv {
            server: mock_server(),
            sent: sent.clone(),
        });
        let pm = PeerManager::new(
            local.private,
            local.public,
            peers,
            TunnelMode::L3Tun,
            Some(rdv),
        );
        (pm, sent)
    }

    /// (a) A rendezvous-only peer (endpoint `None`) with a rendezvous
    /// configured emits a `Lookup` when TUN traffic first needs it.
    #[test]
    fn rendezvous_only_peer_emits_lookup_on_tun_traffic() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, sent) = pm_with_mock_rdv(&local, &[peer]);

        let out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert_eq!(out.len(), 1, "one lookup datagram is emitted");
        assert_eq!(out[0].dst, mock_server(), "lookup targets the server");
        assert_eq!(
            yip_rendezvous::decode(&out[0].bytes),
            Some(yip_rendezvous::Message::Lookup {
                node: node_id(&peer_kp.public),
            }),
            "the datagram is a Lookup for the peer's node id"
        );
        assert!(
            sent.borrow()
                .iter()
                .any(|m| matches!(m, yip_rendezvous::Message::Lookup { .. })),
            "the mock recorded a Lookup"
        );
        // Still Idle (searching), packet buffered.
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
        assert_eq!(pm.peers[0].pending_tun.len(), 1);
    }

    /// (b) Feeding a `PeerCandidate` and then ticking produces a handshake
    /// `Init` whose `dst` is the candidate address.
    #[test]
    fn peer_candidate_then_tick_probes_candidate_with_init() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);

        // Inject a PeerInfo (→ PeerCandidate) from the server for this peer.
        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
            },
            &mut buf,
        );
        // Arrives from the server address → routed to on_rdv → sets candidate.
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));
        assert_eq!(pm.peers[0].path.stage(), PathStage::Punching);

        // Tick drives the path SM: probe the candidate with a fresh Init.
        // (Filter by dst — a `Register` control datagram to the server shares
        // the leading byte 0 with `HandshakeInit`, but goes to the server.)
        let out = pm.tick(1).map(<[_]>::to_vec).unwrap_or_default();
        let init = out
            .iter()
            .find(|d| d.dst == candidate)
            .expect("a handshake Init is emitted toward the candidate");
        assert_eq!(
            init.bytes[0],
            PacketType::HandshakeInit as u8,
            "the datagram to the candidate is a handshake Init"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
    }

    /// (c) With NO rendezvous configured, a peer with a direct endpoint behaves
    /// exactly as 2a: the first TUN packet emits an `Init` to the configured
    /// endpoint (no server-addr demux, no path-SM escalation).
    #[test]
    fn no_rendezvous_direct_endpoint_is_pure_2a() {
        let local = generate_keypair();
        let endpoint: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        let peer = PeerConfig {
            public_key: [7u8; 32],
            endpoint: Some(endpoint),
        };
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[peer],
            TunnelMode::L3Tun,
            None,
        );

        let out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst, endpoint, "Init targets the configured endpoint");
        assert_eq!(out[0].bytes[0], PacketType::HandshakeInit as u8);
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
        // No relay flag, no path commitment yet.
        assert!(!pm.peers[0].relay);
        assert_eq!(pm.peers[0].path_kind, None);
    }

    /// (d) Anti-hijack: an `Established` peer that receives a `PeerCandidate`
    /// or `PunchTo` from the (unauthenticated) server does NOT change its
    /// egress target — no path mutation, no fresh probe.
    #[test]
    fn anti_hijack_established_peer_ignores_rendezvous_candidates() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let endpoint: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: Some(endpoint),
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);

        // Splice in a live Established session reaching `endpoint`.
        const TAG: u64 = 0x0102_0304_0506_0708;
        pm.peers[0].state =
            PeerState::Established(Box::new(fake_established_dataplane(TAG, endpoint)));
        pm.by_tag.insert(TAG, 0);
        pm.peers[0].path_kind = Some(PathKind::Direct);

        let hijack: SocketAddr = "198.51.100.9:40000".parse().unwrap();

        // A PeerCandidate pointing at a different address must be ignored.
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: hijack,
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));

        // And a PunchTo must not start a competing probe.
        buf.clear();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PunchHint {
                node: node_id(&peer_kp.public),
                reflexive: hijack,
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));

        // Egress target unchanged: still Established, endpoint still `endpoint`,
        // relay never enabled, and the path never left Direct (on_peer_candidate
        // was never applied — it would have moved the stage to Punching).
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
        assert_eq!(pm.peers[0].endpoint, Some(endpoint));
        assert!(!pm.peers[0].relay);
        assert_eq!(pm.peers[0].path.stage(), PathStage::Direct);
    }

    /// (e) Escalation regression (the Critical fix): a rendezvous-only peer
    /// driven to `Handshaking` on a punch candidate must escalate to the relay
    /// at ~`PUNCH_MS` — NOT keep retransmitting the doomed punch `Init` for the
    /// full `HANDSHAKE_TOTAL_MS` (90s). Pre-fix `tick` advanced the path SM only
    /// for `Idle` peers, so a `Handshaking` peer froze; this test asserts a
    /// relay-wrapped `Init` (a `RelaySend` to the server) is emitted just past
    /// the punch window, and FAILS against the pre-fix code.
    #[test]
    fn punch_handshake_escalates_to_relay_at_punch_window_not_90s() {
        use crate::path::PUNCH_MS;
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None, // rendezvous-only: starts in the Punching stage
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);

        // Learn a reflexive candidate for the peer (arrives from the server).
        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));

        // Tick once inside the punch window: the SM probes the candidate, so the
        // peer transitions to Handshaking on a punch probe (dst = candidate).
        let out = pm.tick(1).map(<[_]>::to_vec).unwrap_or_default();
        assert!(
            out.iter().any(|d| d.dst == candidate
                && d.bytes.first() == Some(&(PacketType::HandshakeInit as u8))),
            "punch Init is probed toward the candidate"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
        assert!(!pm.peers[0].relay);

        // Tick just past the punch window (measured from the candidate/stage
        // start at 0). Pre-fix: the Handshaking peer only retransmits to the
        // candidate — NO server-addressed relay datagram appears until 90s.
        // Post-fix: it escalates to the relay now.
        let out = pm.tick(PUNCH_MS + 2).map(<[_]>::to_vec).unwrap_or_default();
        let relayed = out.iter().find(|d| {
            d.dst == mock_server()
                && matches!(
                    yip_rendezvous::decode(&d.bytes),
                    Some(yip_rendezvous::Message::RelaySend { .. })
                )
        });
        let relayed = relayed.expect(
            "escalated to relay at ~PUNCH_MS: a RelaySend (relay-wrapped Init) is sent to the server",
        );
        // The relayed payload is the handshake Init itself.
        if let Some(yip_rendezvous::Message::RelaySend { payload, .. }) =
            yip_rendezvous::decode(&relayed.bytes)
        {
            assert_eq!(
                payload.first(),
                Some(&(PacketType::HandshakeInit as u8)),
                "the relay-wrapped payload is a HandshakeInit"
            );
        } else {
            unreachable!("matched RelaySend above");
        }
        // The escalation flipped the peer onto the relay, still handshaking.
        assert!(pm.peers[0].relay, "peer is now relay-reached");
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
    }

    /// (f) Anti-hijack over the relay: an `RdvEvent::Relayed` HandshakeInit whose
    /// `src` maps to an ALREADY-`Established` peer must NOT disturb the live
    /// session — the `on_relayed`/`relayed_handshake_init` Established-guard keeps
    /// `relay`, `endpoint`, and the session (conn_tag) untouched. This fails if
    /// either guard is removed (the peer would be flipped onto the relay).
    #[test]
    fn anti_hijack_established_peer_ignores_relayed_handshake_init() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let endpoint: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: Some(endpoint),
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);

        // Splice in a live direct session reaching `endpoint`.
        const TAG: u64 = 0x1122_3344_5566_7788;
        pm.peers[0].state =
            PeerState::Established(Box::new(fake_established_dataplane(TAG, endpoint)));
        pm.by_tag.insert(TAG, 0);
        pm.peers[0].path_kind = Some(PathKind::Direct);
        assert!(!pm.peers[0].relay);
        let tag_before = established_tag(&pm, 0).expect("established");

        // A valid HandshakeInit from the peer, delivered THROUGH the relay
        // (RelayDeliver from the server, src = peer node).
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&peer_kp.private, &local.public, &[]).unwrap();
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::RelayDeliver {
                src: node_id(&peer_kp.public),
                payload: init_pkt,
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));

        // The live session is untouched: not flipped onto the relay, endpoint
        // and conn_tag unchanged.
        assert!(!pm.peers[0].relay, "relay flag must not be flipped");
        assert_eq!(pm.peers[0].endpoint, Some(endpoint), "endpoint unchanged");
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag_before),
            "session (conn_tag) unchanged"
        );
    }

    /// (g) Fix-pass-2 regression: escalating an in-flight punch handshake to
    /// relay MUST clear the stale `endpoint` left pointing at the abandoned
    /// punch candidate `C`. Pre-fix, `endpoint` stayed `Some(C)` after
    /// escalation, so a late direct `[HandshakeResp]` arriving from `C` (very
    /// plausible on a lossy/high-latency link — a punch reply just past the
    /// `PUNCH_MS` window) matched this peer in `handle_handshake_resp`
    /// (`p.endpoint == Some(src) && Handshaking`) and was fed into the *new*
    /// relay ephemeral's `read_response`, which fails cryptographically and
    /// silently discards the fresh relay attempt (peer reverts to `Idle`).
    /// Post-fix, `endpoint` is cleared on escalation so the stray reply
    /// matches no peer and is dropped harmlessly, leaving the relay
    /// handshake intact.
    #[test]
    fn late_punch_reply_after_relay_escalation_does_not_poison_relay() {
        use crate::path::PUNCH_MS;
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None, // rendezvous-only: starts in the Punching stage
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);

        // 1. Learn a reflexive candidate `C` for the peer, then tick inside
        // the punch window: the peer probes `C` directly (endpoint = Some(C)).
        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));
        let out = pm.tick(1).map(<[_]>::to_vec).unwrap_or_default();
        assert!(
            out.iter().any(|d| d.dst == candidate
                && d.bytes.first() == Some(&(PacketType::HandshakeInit as u8))),
            "punch Init is probed toward the candidate C"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
        assert_eq!(
            pm.peers[0].endpoint,
            Some(candidate),
            "endpoint is the punch candidate C while probing directly"
        );
        assert!(!pm.peers[0].relay);

        // 2. Tick past PUNCH_MS: escalates to relay. The fix: `endpoint` is
        // cleared (no longer pointing at the abandoned punch target C).
        let out = pm.tick(PUNCH_MS + 2).map(<[_]>::to_vec).unwrap_or_default();
        assert!(
            out.iter().any(|d| d.dst == mock_server()
                && matches!(
                    yip_rendezvous::decode(&d.bytes),
                    Some(yip_rendezvous::Message::RelaySend { .. })
                )),
            "escalated to relay: a RelaySend goes to the server"
        );
        assert!(pm.peers[0].relay, "peer is now relay-reached");
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
        assert_eq!(
            pm.peers[0].endpoint, None,
            "fix: stale punch-candidate endpoint C must be cleared on escalation \
             to relay, so a late direct reply from C cannot match this peer"
        );

        // 3. Simulate a late direct HandshakeResp arriving from C — a
        // plausible handshake-resp-shaped datagram (only the leading
        // PacketType byte and the source/state match matter for demux; its
        // payload need not decrypt against anything, since — post-fix — it
        // must never even reach `read_response`).
        let stray = vec![PacketType::HandshakeResp as u8; 64];
        let result = pm.on_udp(candidate, &stray, PUNCH_MS + 3);
        assert!(
            matches!(result, DispatchOut::None),
            "the stray late reply from C produces no egress"
        );

        // The load-bearing assertions: the relay handshake must NOT have been
        // poisoned/discarded by the stray datagram. Pre-fix, `endpoint` would
        // still equal `Some(candidate)`, so `handle_handshake_resp` would have
        // matched this peer, fed the garbage into the relay ephemeral's
        // `read_response` (which errors), and reverted the peer to `Idle` —
        // silently destroying the in-flight relay attempt. Post-fix,
        // `endpoint == None` means no match, so the relay attempt survives
        // untouched.
        assert!(
            matches!(pm.peers[0].state, PeerState::Handshaking(_)),
            "relay handshake must survive the stray late punch reply from C \
             (pre-fix this would be Idle, having been poisoned)"
        );
        assert!(
            pm.peers[0].relay,
            "peer must still be relay-reached after the stray datagram"
        );

        // A subsequent tick still drives the (intact) relay attempt rather
        // than starting over from a clobbered Idle state.
        let out2 = pm
            .tick(PUNCH_MS + HANDSHAKE_RETRY_MS + 3)
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        assert!(
            out2.iter().any(|d| d.dst == mock_server()
                && matches!(
                    yip_rendezvous::decode(&d.bytes),
                    Some(yip_rendezvous::Message::RelaySend { .. })
                )),
            "the relay attempt keeps retransmitting via the server, unbroken by the stray reply"
        );
    }

    /// (h) F2 fix: a peer configured with BOTH a direct endpoint AND a
    /// rendezvous must still hole-punch. It starts `Handshaking` on the direct
    /// endpoint via `on_tun`'s `Idle` branch (not via `drive_path_idle`, which
    /// only ever runs for `Idle` peers), so the *only* place that can drive its
    /// path SM onward is the tick escalation arm. Pre-fix, that arm's `match`
    /// treated `PathAction::NeedLookup` as `_ => {}` — once the direct window
    /// (`DIRECT_MS`) elapses and the SM escalates `Direct -> Punching` with no
    /// candidate yet known, `advance` returns `NeedLookup` every tick and NONE
    /// of them ever emit a `Lookup`: no reflexive candidate is ever learned, so
    /// this peer can never punch (it just rides the direct `Init` out to
    /// `HANDSHAKE_TOTAL_MS` and gives up, or — with the 2b relay-escalation
    /// fix — eventually relays instead of punching). Step 2's assertion below
    /// is the load-bearing one and FAILS pre-fix (the mock records no `Lookup`
    /// at all).
    #[test]
    fn endpoint_peer_emits_lookup_and_punches_after_direct_window() {
        use crate::path::DIRECT_MS;
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let endpoint: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: Some(endpoint), // BOTH a direct endpoint AND (via the mock) a rendezvous
        };
        let (mut pm, sent) = pm_with_mock_rdv(&local, &[peer]);

        // 1. First TUN packet: on_tun's Idle branch drives the path SM, which
        // (still within DIRECT_MS at t=0) returns Probe(endpoint) — the peer
        // starts Handshaking on the direct endpoint, exactly like 2a.
        let out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst, endpoint, "Init targets the configured endpoint");
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
        assert_eq!(pm.peers[0].path.stage(), PathStage::Direct);

        // 2. Tick past DIRECT_MS: the peer is still Handshaking (no resp
        // arrived), so only the tick escalation arm touches its path SM. The
        // SM escalates Direct -> Punching and (no candidate known yet) returns
        // NeedLookup. THE LOAD-BEARING ASSERTION: a Lookup for this peer's
        // node id must have been emitted — this fails pre-fix, where
        // NeedLookup fell into the escalation arm's `_ => {}` and nothing was
        // ever sent.
        let out = pm
            .tick(DIRECT_MS + 1)
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        assert_eq!(pm.peers[0].path.stage(), PathStage::Punching);
        assert!(
            out.iter().any(|d| d.dst == mock_server()
                && matches!(
                    yip_rendezvous::decode(&d.bytes),
                    Some(yip_rendezvous::Message::Lookup { node })
                        if node == node_id(&peer_kp.public)
                )),
            "a Lookup for the peer's node id must be emitted once the direct \
             window elapses and the SM escalates to Punching, even though the \
             peer is still Handshaking on the direct endpoint"
        );
        assert!(
            sent.borrow()
                .iter()
                .any(|m| matches!(m, yip_rendezvous::Message::Lookup { .. })),
            "the mock recorded a Lookup"
        );
        // The direct Init stays in flight alongside the lookup (NeedLookup
        // does not abandon it) — the peer is still Handshaking, not relayed.
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
        assert!(!pm.peers[0].relay);

        // 3. A reflexive candidate for the peer now arrives (as if the lookup
        // above had been answered). A later tick's `advance` returns
        // `Probe(candidate)`, which the escalation arm's existing
        // `addr != target` re-target branch handles: abandon the direct Init,
        // begin a fresh handshake toward the punch candidate.
        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, DIRECT_MS + 2),
            DispatchOut::None
        ));

        let out = pm
            .tick(DIRECT_MS + 3)
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        assert!(
            out.iter().any(|d| d.dst == candidate
                && d.bytes.first() == Some(&(PacketType::HandshakeInit as u8))),
            "the peer re-targets to the punch candidate: a fresh Init is sent \
             to it, proving the punch path is reachable for an \
             endpoint-configured peer"
        );
        assert_eq!(
            pm.peers[0].endpoint,
            Some(candidate),
            "endpoint re-stamped to the punch candidate"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
    }
}
