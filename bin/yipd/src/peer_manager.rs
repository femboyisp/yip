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
use yip_membership::{Cert, GossipMsg};
use yip_rendezvous::{node_id, NodeId};

use crate::addr::node_addr;
use crate::config::PeerConfig;
use crate::dataplane::{conn_tag_from_keys, DataPlane};
use crate::handshake::{Established, HandshakeState, PacketType};
use crate::membership::Membership;
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

/// Cap on the number of gossip partners a single `tick` fans a digest out to
/// (bounded chattiness / anti-DoS): a small sample of Established peers plus
/// the roots. `Membership::tick_digest` already debounces the digest itself.
const MAX_GOSSIP_TARGETS: usize = 4;

/// Cap on the number of `GossipMsg` replies emitted for one inbound gossip
/// datagram. `Membership::on_gossip` already bounds each `Records` message to
/// `MAX_GOSSIP_RECORDS_PER_REPLY` records (splitting a large `PullRequest`
/// answer across multiple messages rather than one unboundedly large one), so
/// this is a belt-and-suspenders ceiling on the number of such messages sent
/// per inbound datagram (also caps `Digest`/`PullRequest` replies, which are
/// always exactly one message).
const MAX_GOSSIP_REPLIES: usize = 8;

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
    /// The retransmit spacing to apply the NEXT time `last_sent_ms` is
    /// checked against `now_ms` (see the retransmit arm in `tick_dispatch`).
    /// Set to `HANDSHAKE_RETRY_MS` exactly when obfuscation is off (obf-off
    /// timing is byte-identical); re-rolled via `jitter_ms(HANDSHAKE_RETRY_MS)`
    /// at creation and after every retransmit when `obf_key.is_some()` (3a) —
    /// stored and compared, never re-derived per-tick (see `jitter_ms`'s doc).
    retry_ms: u64,
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
    Established(Box<crate::epoch::EpochSet>),
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
    /// The initiator Noise ephemeral (`handshake::init_ephemeral`) of the
    /// `[HandshakeInit]` that produced `cached_resp`, i.e. the ORIGINAL
    /// cold-start (or relayed) `Init` that established the *current*
    /// session. Set alongside `cached_resp`, `None` under the same
    /// conditions.
    ///
    /// `HANDSHAKE_TOTAL_MS` (90s) is bigger than `REKEY_INTERVAL_MS`/2
    /// (60s), so a very-late retransmit of this ORIGINAL Init can land
    /// after `EpochSet::accept_rekey_init` would otherwise treat it as a
    /// plausible genuine rekey. `handle_rekey_init` checks this field FIRST
    /// (milestone 9a final review, Important-2) so that case still resends
    /// `cached_resp` — the cold-start dedup path — rather than being
    /// misclassified as a rekey round.
    cached_resp_init_eph: Option<[u8; 32]>,
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
    /// Per-peer session obfuscation key = `yip_obf::derive_key(&hp_key)`, set
    /// when the peer reaches `Established` *and* obfuscation is enabled
    /// (`PeerManager::obf_key.is_some()`); `None` otherwise. Used to wrap/unwrap
    /// this peer's Data/Control/Gossip datagrams (3a). Independent of the
    /// network-wide `obf_psk` key, which wraps handshakes (pre-session).
    session_obf_key: Option<[u8; 16]>,
    /// Monotonic `now_ms` timestamp of the last REAL Data datagram sent to or
    /// received from this peer (3b Task 4). Updated at the on_tun →
    /// `DataPlane` data-egress site and the `Data`-ptype arm of the ingress
    /// dispatch — never by control/gossip/junk. Defaults to `0`, so a
    /// freshly-`Established` peer that has carried no real traffic yet reads
    /// as idle immediately (cover starts right away, matching "the flow
    /// never goes tellingly silent"). Drives the idle gate in `tick_dispatch`'s
    /// cover-traffic emission; irrelevant when `cover_traffic_ms` is unset.
    last_activity_ms: u64,
    /// Monotonic `now_ms` timestamp of the last cover (junk) datagram emitted
    /// to this peer (3b Task 4). Defaults to `0`. Bounds cover emission to at
    /// most one datagram per peer per `cover_traffic_ms` interval.
    last_cover_ms: u64,
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
    /// module doc for why it is not the primary demux mechanism) — a miss or
    /// a stale entry always falls back to source-address matching, which is
    /// authoritative, so this map never needs to be perfectly up to date for
    /// correctness. Pre-9a a peer established exactly once (duplicate/
    /// retransmitted inits re-send the cached reply rather than rebuilding —
    /// see `handle_handshake_init`), so each peer contributed one entry that
    /// never went stale.
    ///
    /// 9a rekey rotates `conn_tag` per epoch. The initiator's explicit
    /// promotion (`PeerManager::handle_rekey_resp`) evicts the superseded
    /// tag and inserts the new one, since it has direct access to this map.
    /// The responder's confirmed-switch promotion, however, happens
    /// automatically inside `EpochSet::inbound_open` (Task 1), which is
    /// pure/I-O-free and has no access to `PeerManager` fields — so on that
    /// side the old tag is simply left behind as a harmless dead entry (it
    /// can never match a live datagram's `conn_tag` bytes again) rather than
    /// actively evicted. New datagrams under the responder's promoted epoch
    /// still route correctly via the source-address fallback in
    /// `route_data` until (if ever) a later inbound datagram happens to
    /// warm this map's `insert` path for the peer again.
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
    /// The mesh membership directory (2c), or `None` for a pure-2a/2b
    /// deployment. When `None`, every membership branch is skipped and the
    /// manager behaves byte-identically to 2a/2b: no cert is presented or
    /// verified in the handshake, `on_tun` never resolves an unknown address,
    /// and no gossip is emitted or ingested. A separate field from `peers`, so
    /// a membership borrow can be split from a `peers` mutation.
    membership: Option<Membership>,
    /// This node's own rendezvous node id (`node_id(local_pub)`), the `src`
    /// for `register`/`relay`.
    local_node_id: NodeId,
    /// When we last emitted `register(local_node_id)` (see [`REG_REFRESH_MS`]).
    last_register_ms: u64,
    /// The registration-refresh spacing to apply the NEXT time
    /// `last_register_ms` is checked against `now_ms`. `REG_REFRESH_MS`
    /// exactly when obfuscation is off (byte-identical timing); re-rolled via
    /// `jitter_ms(REG_REFRESH_MS)` after every register fire when
    /// `obf_key.is_some()` (3a) — stored and compared, never re-derived
    /// per-tick.
    reg_refresh_ms: u64,
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
    /// The network-wide anti-DPI obfuscation key = `yip_obf::derive_key(&obf_psk)`,
    /// or `None` when obfuscation is disabled. When `None`, the `Dispatch`
    /// methods take the exact 2a/2b/2c plaintext path (byte-identical — no
    /// wrap/unwrap ever runs). When `Some`, every outgoing peer datagram is
    /// wrapped via `yip-obf` (masked type + padding) and ingress is demuxed by
    /// source + trial-unmask. This is the *pre-session* key: it wraps
    /// handshakes; established peers use their per-session `session_obf_key`
    /// for Data/Control/Gossip. Set once, before the event loop starts (see
    /// [`PeerManager::set_obf_psk`]).
    obf_key: Option<[u8; 16]>,
    /// Fast userspace PRNG for junk-datagram sizing/content (3b) — see
    /// [`PeerManager::build_junk`]. Seeded once from the OS RNG; never used
    /// for any security decision (junk bytes are keystream-masked by
    /// `yip_obf::obfuscate`, so their content is irrelevant).
    junk_rng: yip_obf::XorShift64,
    /// Opt-in idle cover-traffic interval (3b Task 4), or `None` to disable.
    /// Only consulted when `obf_key.is_some()` — with obfuscation off, cover
    /// traffic never fires regardless of this value (there is no wrapper to
    /// hide it, and junk-in-the-clear would be worse than silence). Set once,
    /// before the event loop starts, via [`PeerManager::set_cover_traffic_ms`].
    cover_traffic_ms: Option<u64>,
    /// RaptorQ symbol size passed to `DataPlane::new` at every establish site
    /// (3c.1 Task 2). Defaults to `1200` — the pre-3c.1 hardcode, byte-identical
    /// for raw/obf mode. QUIC mode (3c.1 Tasks 4/5) overrides it via
    /// [`PeerManager::set_data_symbol_size`], set once before the event loop
    /// starts, like `obf_key`/`cover_traffic_ms`.
    data_symbol_size: u16,
    /// When `true`, every `PathState` (initial peers at construction, and
    /// members admitted later via `admit_member`) is created via
    /// `PathState::relay_only` instead of `PathState::new` — the
    /// `rendezvous=tls://` client (3c.4), where UDP (hence Direct and
    /// hole-punch) is blocked. Set once at construction from the
    /// `PeerManager::new` parameter of the same name; `false` reproduces the
    /// UDP-path Direct→Punch→Relay escalation byte-identically.
    relay_only: bool,
    /// Mid-session rekey cadence (9a Task 3): an `Established` peer's
    /// `current` epoch is rekeyed once it is this old (glare-winner side) or
    /// `2×` this old (loser-fallback side — see `EpochSet::needs_rekey`).
    /// Defaults to [`crate::epoch::REKEY_INTERVAL_MS`]; overridden via
    /// `YIP_REKEY_INTERVAL_MS` at construction so netns/unit tests can drive
    /// the schedule without a multi-minute real-time wait.
    rekey_interval_ms: u64,
}

/// MTU budget (bytes) used to size obfuscation padding: handshakes are padded
/// generously up to this ceiling (their true size is small and highly
/// distinctive otherwise); data/control/gossip get modest padding, room
/// permitting under this ceiling, since their bodies are already near the path
/// MTU. Only consulted on the obfuscation-enabled path.
const OBF_MTU_BUDGET: usize = 1200;
/// Maximum modest padding (bytes) added to a data/control/gossip envelope.
const OBF_DATA_PAD_MAX: usize = 64;
/// Minimum/maximum length (bytes) of a junk datagram's throwaway body, drawn
/// uniformly by [`PeerManager::build_junk`]. Content is irrelevant (masked by
/// `obfuscate`); the range just varies the on-wire size like real traffic.
const JUNK_MIN_LEN: usize = 64;
const JUNK_MAX_LEN: usize = 1024;
/// Minimum/maximum number of junk datagrams in a single decoy burst, drawn by
/// `begin_handshake` when obfuscation is on and the handshake is direct (not
/// relayed) (Task 3).
const JUNK_BURST_MIN: u64 = 3;
const JUNK_BURST_MAX: u64 = 12;
/// Default RaptorQ symbol size passed to every `DataPlane` (3c.1 Task 2) —
/// the pre-3c.1 hardcode, byte-identical for raw/obf mode. QUIC mode (3c.1
/// Tasks 4/5) overrides it via [`PeerManager::set_data_symbol_size`].
const DEFAULT_DATA_SYMBOL_SIZE: u16 = 1200;

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
        membership: Option<Membership>,
        relay_only: bool,
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
            // `relay_only` (rendezvous=tls://, 3c.4) instead starts every peer
            // straight in Relaying — UDP is blocked there, so Direct/Punch would
            // just waste ~8 s failing.
            let mut path = if relay_only {
                PathState::relay_only(0)
            } else {
                PathState::new(p.endpoint.is_some(), has_rendezvous, 0)
            };
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
                cached_resp_init_eph: None,
                node,
                path,
                path_kind: None,
                relay: false,
                last_lookup_ms: None,
                session_obf_key: None,
                last_activity_ms: 0,
                last_cover_ms: 0,
            });
        }
        let mut mgr = Self {
            local_priv,
            local_pub,
            mode,
            peers,
            by_tag: HashMap::new(),
            by_addr,
            by_node,
            rendezvous,
            membership,
            local_node_id: node_id(&local_pub),
            last_register_ms: 0,
            reg_refresh_ms: REG_REFRESH_MS,
            registered_once: false,
            egress: Vec::new(),
            tick_egress: Vec::new(),
            tun_scratch: Vec::new(),
            obf_key: None,
            junk_rng: yip_obf::XorShift64::from_getrandom(),
            cover_traffic_ms: None,
            data_symbol_size: DEFAULT_DATA_SYMBOL_SIZE,
            relay_only,
            rekey_interval_ms: std::env::var("YIP_REKEY_INTERVAL_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(crate::epoch::REKEY_INTERVAL_MS),
        };
        // Roots are pre-vetted (CA-signed root set) and therefore always-admit,
        // exactly like configured peers: seed them into the peer table so an
        // incoming handshake from a root is admitted and `tick` can bootstrap
        // gossip against one. `admit_member` is idempotent (a root that is also
        // a configured peer, or our own key, is a no-op).
        let roots: Vec<([u8; 32], SocketAddr)> = mgr
            .membership
            .as_ref()
            .map(|m| m.roots().to_vec())
            .unwrap_or_default();
        for (pubkey, addr) in roots {
            mgr.admit_member(pubkey, vec![addr], 0);
        }
        mgr
    }

    /// Runtime admission of a discovered member: push a fresh `Idle` [`Peer`]
    /// (endpoint = first of `endpoints`; a `PathState` seeded from every
    /// endpoint) and register it in `by_addr`/`by_node`. Idempotent — a no-op
    /// if `pubkey` is already a peer (or is our own key). This is the peer-table
    /// mutation the 2a/2b `PeerManager` lacked; the just-admitted peer is now
    /// routable, so the existing lazy-handshake / path-escalation path brings it
    /// up. Membership only ever supplies a *candidate*: the Noise handshake
    /// still gates the session (anti-hijack).
    fn admit_member(&mut self, pubkey: [u8; 32], endpoints: Vec<SocketAddr>, now_ms: u64) {
        if pubkey == self.local_pub || self.peers.iter().any(|p| p.pubkey == pubkey) {
            return;
        }
        let idx = self.peers.len();
        let addr = node_addr(&pubkey);
        let node = node_id(&pubkey);
        let mut path = if self.relay_only {
            PathState::relay_only(now_ms)
        } else {
            PathState::new(!endpoints.is_empty(), self.rendezvous.is_some(), now_ms)
        };
        for ep in &endpoints {
            path.on_direct_addr(*ep);
        }
        self.by_addr.insert(addr, idx);
        self.by_node.insert(node, idx);
        self.peers.push(Peer {
            pubkey,
            addr,
            endpoint: endpoints.first().copied(),
            state: PeerState::Idle,
            pending_tun: Vec::new(),
            cached_resp: None,
            cached_resp_init_eph: None,
            node,
            path,
            path_kind: None,
            relay: false,
            last_lookup_ms: None,
            session_obf_key: None,
            last_activity_ms: 0,
            last_cover_ms: 0,
        });
    }

    /// Enable (or disable) anti-DPI obfuscation for this manager from the
    /// network-wide `obf_psk`. Called once by `tunnel.rs` right after
    /// construction, before the event loop begins, so every subsequently
    /// established peer derives its `session_obf_key` and every datagram is
    /// wrapped/unwrapped. `None` leaves obfuscation disabled — the `Dispatch`
    /// methods then run the 2a/2b/2c plaintext path byte-identically.
    ///
    /// This is a post-construction setter rather than a `new` parameter
    /// deliberately: it keeps the ~25 existing multi-arg `PeerManager::new`
    /// call sites (and their behaviour) untouched, minimizing regression
    /// surface for the obf-off gate. Functionally equivalent to a constructor
    /// argument since no handshake can complete before the loop starts.
    pub fn set_obf_psk(&mut self, obf_psk: Option<[u8; 32]>) {
        self.obf_key = obf_psk.map(|p| yip_obf::derive_key(&p));
    }

    /// Enable (or disable) opt-in idle cover traffic (3b Task 4) from the
    /// configured `cover_traffic_ms`. Called once by `tunnel.rs` right after
    /// `set_obf_psk`, before the event loop begins. `None` leaves cover
    /// traffic disabled. Only takes effect when obfuscation is also enabled
    /// (`obf_key.is_some()`) — see `tick_dispatch`'s cover-emission gate.
    ///
    /// A post-construction setter for the same reason as `set_obf_psk`: it
    /// keeps the existing `PeerManager::new` call sites untouched.
    pub fn set_cover_traffic_ms(&mut self, cover_traffic_ms: Option<u64>) {
        self.cover_traffic_ms = cover_traffic_ms;
    }

    /// Set the RaptorQ symbol size passed to `DataPlane::new` at every
    /// establish site (3c.1 Task 2). Defaults to `1200`; QUIC mode (3c.1 Task 4)
    /// calls this with the QUIC-safe symbol size (see `quic::run_quic`) before
    /// the event loop begins, like `set_obf_psk`/`set_cover_traffic_ms`.
    pub fn set_data_symbol_size(&mut self, s: u16) {
        self.data_symbol_size = s;
    }

    /// This node's own self-certifying mesh address, for assigning the
    /// local TUN/TAP device's address.
    pub fn local_addr(&self) -> Ipv6Addr {
        node_addr(&self.local_pub)
    }

    /// The per-session obfuscation key for a just-established peer, derived
    /// from its handshake `hp_key` — but only when obfuscation is enabled
    /// (`obf_key.is_some()`); `None` otherwise (obf off ⇒ nothing to store,
    /// byte-identical). Both peers derive the same `hp_key` from the Noise
    /// channel binding, so both derive the same session obf key.
    fn session_obf_key_for(&self, hp_key: &[u8; 16]) -> Option<[u8; 16]> {
        self.obf_key.map(|_| yip_obf::derive_key(hp_key))
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

    /// Emit one rekey-related datagram into `self.egress`: relay-wrapped when
    /// `via_relay` (a `relay_wrap` `None` is a clean skip — the rekey just
    /// retries), else pushed AS-IS. Used by the rekey cores so the
    /// Direct/Relay split lives in exactly one place.
    ///
    /// Takes the full `EgressDatagram` (not bare bytes) so the Direct path
    /// preserves whatever `fate`/`dst` the caller built — `fate: 0` for
    /// handshake emits (a Resp/cached-resp has no FEC object), but the REAL
    /// per-FEC-object `fate` for `rekey_resp_core`'s prime-emit (#91 Task 1
    /// review, Important). The relay path only ever needs `.bytes` (the
    /// inner `fate` rides inside the `RelaySend` payload; the outer
    /// `RelaySend`'s own fate is `relay_wrap`'s, moot for the inner one).
    fn push_rekey_egress(&mut self, idx: usize, dg: EgressDatagram, via_relay: bool) {
        if via_relay {
            if let Some(d) = self.relay_wrap(idx, dg.bytes) {
                self.egress.push(d);
            }
        } else {
            self.egress.push(dg);
        }
    }

    /// Start a fresh initiator handshake toward `target` for peer `idx`,
    /// returning the framed egress datagram(s) to send (relay-wrapped when
    /// `via_relay`), the real `HandshakeInit` always last. Transitions the
    /// peer to `Handshaking`. Returns `None` (leaving the peer as it was) if
    /// the Noise step or the relay wrap fails.
    ///
    /// When obfuscation is on (`obf_key.is_some()`) and the handshake is
    /// direct (`!via_relay`), the Init is preceded by a burst of `Jc ∈
    /// [JUNK_BURST_MIN, JUNK_BURST_MAX]` junk datagrams (`build_junk`) to the
    /// same `target`, so the flow no longer opens with a countable "2
    /// packets then data" — junk never touches Noise/session state. Relay-path
    /// junk is out of scope (Task 3) — the relay path always returns exactly
    /// one datagram. With `obf_key: None` this returns exactly one datagram
    /// (the Init), byte-identical to pre-Task-3 behavior.
    ///
    /// The caller is responsible for only invoking this on a peer that is not
    /// already `Handshaking`/`Established`.
    fn begin_handshake(
        &mut self,
        idx: usize,
        target: SocketAddr,
        via_relay: bool,
        now_ms: u64,
    ) -> Option<Vec<EgressDatagram>> {
        let pubkey = self.peers[idx].pubkey;
        // Present our CA-signed membership cert as msg1's Noise payload so the
        // responder can admit us by cert (2c). Empty when membership is None —
        // byte-identical to 2a/2b.
        let payload = self
            .membership
            .as_ref()
            .map(Membership::own_cert_bytes)
            .unwrap_or_default();
        let (hs, init_pkt) =
            match HandshakeState::start_initiator(&self.local_priv, &pubkey, &payload) {
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
        let retry_ms = if self.obf_key.is_some() {
            jitter_ms(HANDSHAKE_RETRY_MS)
        } else {
            HANDSHAKE_RETRY_MS
        };
        self.peers[idx].state = PeerState::Handshaking(Box::new(HandshakingState {
            hs,
            started_ms: now_ms,
            last_sent_ms: now_ms,
            retry_ms,
            retries: 0,
            init_pkt,
            target,
        }));
        // Direct-path junk burst (Task 3): obfuscation on, not relayed. The
        // relay path keeps its single-datagram shape — relay-path junk would
        // need a different (RelaySend) envelope and is out of scope here.
        if !via_relay && self.obf_key.is_some() {
            let jc = self.junk_rng.gen_range(JUNK_BURST_MIN, JUNK_BURST_MAX);
            let jc = usize::try_from(jc).expect("JUNK_BURST_MAX fits usize");
            let mut dgs = Vec::with_capacity(jc + 1);
            for _ in 0..jc {
                dgs.push(EgressDatagram {
                    fate: 0,
                    dst: target,
                    bytes: self.build_junk(),
                });
            }
            dgs.push(dg);
            return Some(dgs);
        }
        Some(vec![dg])
    }

    /// Re-point an in-flight handshake at `new_target` over the given path,
    /// PRESERVING the Noise ephemeral: resend the existing `init_pkt` rather than
    /// drawing a fresh one, so a responder that already adopted us on the old path
    /// completes us via its `cached_resp` (#36). Falls back to a fresh
    /// `begin_handshake` only when no handshake is in flight (Idle/cold).
    ///
    /// `started_ms` is intentionally NOT reset — the `HANDSHAKE_TOTAL_MS` give-up
    /// clock keeps running across re-targets (a re-target does not buy a fresh
    /// 90 s). On a `via_relay` re-target `endpoint` is cleared: a late direct
    /// `[HandshakeResp]` for this same ephemeral must not complete us onto a now
    /// `relay`-flagged peer (that would mismatch egress — data-plane egress is
    /// re-wrapped by the `relay` flag, not the stamped dst).
    fn retarget_handshake(
        &mut self,
        idx: usize,
        new_target: SocketAddr,
        via_relay: bool,
        now_ms: u64,
    ) -> Option<Vec<EgressDatagram>> {
        let PeerState::Handshaking(h) = &mut self.peers[idx].state else {
            // No handshake in flight: a fresh attempt is correct here.
            return self.begin_handshake(idx, new_target, via_relay, now_ms);
        };
        h.target = new_target;
        let init_pkt = h.init_pkt.clone();
        self.peers[idx].relay = via_relay;
        if via_relay {
            self.peers[idx].endpoint = None;
            return self.relay_wrap(idx, init_pkt).map(|d| vec![d]);
        }
        // Direct/Punch re-target: re-stamp `endpoint` to the new candidate, as
        // `begin_handshake`'s direct branch does — `handle_handshake_resp`
        // matches an inbound Resp against `peers[idx].endpoint == Some(src)`,
        // so without this a Resp from the new candidate would not complete us.
        self.peers[idx].endpoint = Some(new_target);
        Some(vec![EgressDatagram {
            fate: 0,
            dst: new_target,
            bytes: init_pkt,
        }])
    }

    /// Mid-session rekey scheduler (9a Task 3, relay-completed in #91 Task
    /// 3), driven once per tick for an `Established` peer `idx` (`relay`
    /// mirrors `tick_dispatch`'s same-named local — whether `idx` is
    /// relay-reached). Starts a fresh initiator rekey handshake when due,
    /// retransmits one already in flight, or abandons it — entirely
    /// alongside `epochs.current`, which this function never touches: a
    /// failed/abandoned rekey is therefore a no-op on the live session
    /// (fail-closed). Any egress produced is pushed onto `self.tick_egress`.
    ///
    /// Mirrors `begin_handshake`'s initiator construction (same
    /// `cert_payload`, same relay/direct wrap, same `jitter_ms`-derived
    /// retry cadence as `HandshakingState`'s cold-start retransmit arm in
    /// `tick_dispatch`) so the rekey `Init` carries no new fingerprint
    /// distinguishing it from a cold-start one. Unlike `begin_handshake`, it
    /// does not transition `PeerState` (the peer stays `Established`) and
    /// does not emit an obfuscation junk burst (Task 3 scope: scheduling
    /// only, not a new decoy shape).
    ///
    /// Relay-reached peers (`relay == true`) DO get scheduled here (#91 Task
    /// 3 removed the earlier gate, now that `rekey_resp_core`/the relay
    /// handshake handlers complete a relay rekey): the Init is emitted via
    /// `relay_wrap` (a `RelaySend` to the rendezvous server) instead of a raw
    /// datagram to a direct endpoint, and `RekeyInFlight.target` is set to
    /// `self.server_addr()` (nominal — `rekey_resp_core` uses `server_addr()`
    /// as a relay peer's `peer_addr` too). A `relay_wrap` `None` (no
    /// rendezvous configured — should not happen for a peer marked `relay`)
    /// skips *this send only*: `RekeyInFlight` is still installed/retried, so
    /// the round is not aborted (fail-closed, same spirit as the rest of this
    /// function).
    fn drive_rekey_schedule(
        &mut self,
        idx: usize,
        relay: bool,
        epochs: &mut crate::epoch::EpochSet,
        now_ms: u64,
    ) {
        if epochs.rekey.is_none() {
            // Glare tiebreak: reuse the EXACT static-key-order comparison
            // `handle_handshake_init`/`relayed_handshake_init` use to decide
            // who adopts the responder role on a simultaneous cold-start
            // handshake (the smaller public key is the designated
            // initiator). The same side is the designated rekey initiator;
            // the other side only rekeys via `needs_rekey`'s loser-fallback
            // (2x the interval) if the winner never does.
            let is_glare_winner = self.local_pub < self.peers[idx].pubkey;
            if !epochs.needs_rekey(now_ms, is_glare_winner, self.rekey_interval_ms) {
                return;
            }
            // Direct: target this peer's known endpoint (no known endpoint
            // this tick — shouldn't normally happen for a non-relay
            // Established peer — skips: no egress, no state change, retried
            // next tick). Relay: nominal target is the rendezvous server
            // (`rekey_resp_core` uses `server_addr()` as a relay peer's
            // `peer_addr` too), and there is no endpoint to be missing.
            let target = if relay {
                self.server_addr()
            } else {
                match self.peers[idx].endpoint {
                    Some(ep) => ep,
                    None => return,
                }
            };
            let pubkey = self.peers[idx].pubkey;
            let payload = self
                .membership
                .as_ref()
                .map(Membership::own_cert_bytes)
                .unwrap_or_default();
            let (hs, init_pkt) =
                match HandshakeState::start_initiator(&self.local_priv, &pubkey, &payload) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("peer_manager: failed to start rekey handshake: {e}");
                        return;
                    }
                };
            let retry_ms = if self.obf_key.is_some() {
                jitter_ms(HANDSHAKE_RETRY_MS)
            } else {
                HANDSHAKE_RETRY_MS
            };
            epochs.rekey = Some(crate::epoch::RekeyInFlight {
                hs,
                init_pkt: init_pkt.clone(),
                started_ms: now_ms,
                last_sent_ms: now_ms,
                retry_ms,
                target,
            });
            if relay {
                // A `None` (no rendezvous configured — should not happen for
                // a peer marked `relay`) skips this send only: the round
                // stays installed above and retries on the next tick's
                // retransmit arm.
                if let Some(d) = self.relay_wrap(idx, init_pkt) {
                    self.tick_egress.push(d);
                }
            } else {
                self.tick_egress.push(EgressDatagram {
                    fate: 0,
                    dst: target,
                    bytes: init_pkt,
                });
            }
            return;
        }

        // A rekey is already in flight: retransmit (same cadence as
        // `HandshakingState`'s cold-start arm) or abandon it once
        // `HANDSHAKE_TOTAL_MS` elapses. `current` is never touched by either
        // path — abandoning just clears `epochs.rekey`, leaving the live
        // session exactly as it was; `needs_rekey` tries again next interval.
        let (started_ms, last_sent_ms, retry_ms, target) = {
            let rekey = epochs.rekey.as_ref().expect("checked is_some above");
            (
                rekey.started_ms,
                rekey.last_sent_ms,
                rekey.retry_ms,
                rekey.target,
            )
        };
        if now_ms.saturating_sub(started_ms) >= HANDSHAKE_TOTAL_MS {
            epochs.rekey = None;
            return;
        }
        if now_ms.saturating_sub(last_sent_ms) < retry_ms {
            return;
        }
        let pkt = epochs
            .rekey
            .as_ref()
            .expect("checked is_some above")
            .init_pkt
            .clone();
        // Resend the SAME `init_pkt` verbatim, relay-wrapped when `relay`
        // (a `relay_wrap` `None` skips this send only — the round stays in
        // flight and retries again next tick), else direct to `target`.
        if relay {
            if let Some(d) = self.relay_wrap(idx, pkt) {
                self.tick_egress.push(d);
            }
        } else {
            self.tick_egress.push(EgressDatagram {
                fate: 0,
                dst: target,
                bytes: pkt,
            });
        }
        let new_retry_ms = if self.obf_key.is_some() {
            jitter_ms(HANDSHAKE_RETRY_MS)
        } else {
            HANDSHAKE_RETRY_MS
        };
        if let Some(rk) = epochs.rekey.as_mut() {
            rk.last_sent_ms = now_ms;
            rk.retry_ms = new_retry_ms;
        }
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
                if let Some(dgs) = self.begin_handshake(idx, addr, false, now_ms) {
                    self.tick_egress.extend(dgs);
                }
            }
            PathAction::Relay => {
                let server = self.server_addr();
                if let Some(dgs) = self.begin_handshake(idx, server, true, now_ms) {
                    self.tick_egress.extend(dgs);
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
                            if let Some(dgs) = self.begin_handshake(idx, addr, false, now_ms) {
                                self.egress.clear();
                                self.egress.extend(dgs);
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
        // Present our cert in msg2 (2c mutual proof); empty when membership is
        // None. The relayed peer was resolved via `by_node`, so it is already a
        // configured/root/admitted peer (always-admit) — the `remote_static`
        // pubkey match below is the admission check, as in 2b.
        let resp_payload = self
            .membership
            .as_ref()
            .map(Membership::own_cert_bytes)
            .unwrap_or_default();
        let (established, resp_pkt, remote_static, _initiator_payload) =
            match HandshakeState::start_responder(&self.local_priv, dg, &resp_payload) {
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
            // Established (9a/relay-path completion, #91 Task 2): route
            // through the shared core exactly like the direct path's
            // `handle_handshake_init` does. `rekey_init_core`'s
            // `cached_resp_init_eph` dedup subsumes the old unconditional
            // `cached_resp` resend below: a cold-start Init retransmit
            // (ephemeral matches `cached_resp_init_eph`, set when the Idle
            // branch below first cached its resp) still resends
            // `cached_resp` verbatim; a genuine mid-session rekey Init
            // installs `next` instead.
            // Only complete a relayed rekey Init when this peer's live path
            // IS relay (final review, Important): a direct peer receiving a
            // relayed Init — reachable via a source-spoofed server address
            // or a malicious/compromised blind relay (`on_relayed` only
            // requires `src == server`), or with NO attacker under
            // asymmetric reachability (the peer relays to us while we reach
            // it directly) — must NOT complete via this relay-addressed
            // core. Completing it would stamp the new epoch's
            // `DataPlane.peer_addr` to `server_addr()` while
            // `peers[idx].relay` stays `false`, so `on_tun`'s relay-wrap
            // decision (keyed off `peers[idx].relay`) would then emit BARE
            // datagrams to the server — black-holing `current`. Fail-closed
            // drop instead; `current` (and the in-flight rekey, if any)
            // stays untouched.
            PeerState::Established(_) if self.peers[idx].relay => {
                let Some(init_eph) = crate::handshake::init_ephemeral(dg) else {
                    return DispatchOut::None; // malformed Init
                };
                self.rekey_init_core(
                    idx,
                    established,
                    resp_pkt,
                    init_eph,
                    now_ms,
                    self.server_addr(),
                    true,
                )
            }
            PeerState::Established(_) => DispatchOut::None,
            PeerState::Handshaking(_) if self.local_pub < self.peers[idx].pubkey => {
                DispatchOut::None
            }
            PeerState::Idle | PeerState::Handshaking(_) => {
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                let sess_obf = self.session_obf_key_for(&established.hp_key);
                // A relay peer's egress is always re-wrapped, so the DataPlane's
                // stamped `dst` is unused: seed it with the server address.
                let placeholder = self.server_addr();
                let mut dp = Box::new(DataPlane::new(
                    established,
                    conn_tag,
                    self.mode,
                    placeholder,
                    self.obf_key.is_some(),
                    self.data_symbol_size,
                ));

                self.peers[idx].session_obf_key = sess_obf;
                self.peers[idx].cached_resp = Some(resp_pkt.clone());
                self.peers[idx].cached_resp_init_eph = crate::handshake::init_ephemeral(dg);
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
                self.peers[idx].state =
                    PeerState::Established(Box::new(crate::epoch::EpochSet::new(dp, now_ms)));
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
        // Established with a rekey in flight (#91 Task 2): this is the
        // relay-path completion of a mid-session rekey — route through the
        // shared core exactly like the direct path's `handle_rekey_resp`.
        // An Established peer with NO rekey in flight still falls through
        // to the check below and drops (unchanged). Gated on `peers[idx].relay`
        // (final review, Important): a DIRECT peer's rekey must never
        // complete via the relay-addressed core — see the matching guard in
        // `relayed_handshake_init` for the full black-hole rationale. A
        // direct peer with a relayed Resp falls through to the
        // non-`Handshaking` drop below (fail-closed; `current` untouched).
        if matches!(&self.peers[idx].state, PeerState::Established(epochs) if epochs.rekey.is_some())
            && self.peers[idx].relay
        {
            return self.rekey_resp_core(idx, dg, now_ms, true);
        }
        if !matches!(self.peers[idx].state, PeerState::Handshaking(_)) {
            return DispatchOut::None;
        }
        let old_state = std::mem::replace(&mut self.peers[idx].state, PeerState::Idle);
        let PeerState::Handshaking(handshaking) = old_state else {
            unreachable!("just matched Handshaking above");
        };
        match handshaking.hs.read_response(dg) {
            Ok((established, responder_payload)) => {
                if !self.responder_cert_ok(&responder_payload, self.peers[idx].pubkey) {
                    eprintln!("peer_manager: relayed responder cert rejected");
                    return DispatchOut::None;
                }
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                let sess_obf = self.session_obf_key_for(&established.hp_key);
                let placeholder = self.server_addr();
                let mut dp = Box::new(DataPlane::new(
                    established,
                    conn_tag,
                    self.mode,
                    placeholder,
                    self.obf_key.is_some(),
                    self.data_symbol_size,
                ));
                self.by_tag.insert(dp.conn_tag(), idx);
                self.peers[idx].session_obf_key = sess_obf;
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
                self.peers[idx].state =
                    PeerState::Established(Box::new(crate::epoch::EpochSet::new(dp, now_ms)));
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
    /// data-plane datagram to peer `idx`'s `EpochSet` (via `inbound_open`) and
    /// relay-wrap any UDP egress it produces (TUN writes still go to the local
    /// device). Relay egress always goes through `relay_wrap`, so only the
    /// `EpochInbound::Send`/`TunThenSend` payload bytes are needed here — the
    /// real `dst`/`fate` on each `EgressDatagram` are irrelevant for a
    /// relayed peer (the actual wire destination is the relay server).
    fn relayed_data(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        let (tun, udp): (Option<Vec<u8>>, Vec<Vec<u8>>) = {
            let PeerState::Established(epochs) = &mut self.peers[idx].state else {
                return DispatchOut::None;
            };
            match epochs.inbound_open(dg, now_ms) {
                crate::epoch::EpochInbound::None => (None, Vec::new()),
                crate::epoch::EpochInbound::Tun(buf) => (Some(buf), Vec::new()),
                crate::epoch::EpochInbound::Send(dgs) => {
                    (None, dgs.iter().map(|d| d.bytes.clone()).collect())
                }
                crate::epoch::EpochInbound::TunThenSend(buf, dgs) => {
                    (Some(buf), dgs.iter().map(|d| d.bytes.clone()).collect())
                }
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
    ///
    /// `L3Tun`'s single-peer fallback (`self.peers.len() == 1 => Some(0)`)
    /// splits into two cases (2c/Task 7 fix):
    /// - `ipv6_dst` returns `None` — not a recognizable mesh IPv6 packet at
    ///   all (2a/2b's plain, non-mesh tunnel addressing, ARP, etc.). There is
    ///   no `resolve` to try instead, so the sole-peer fallback applies
    ///   unconditionally, exactly as before — this keeps every pure-2a/2b
    ///   test (and any single-peer test that also happens to pass a
    ///   `Membership` for unrelated reasons, e.g. cert-handshake tests using
    ///   a non-IPv6 dummy TUN packet) byte-identical.
    /// - `ipv6_dst` returns `Some(dst)` but `dst` doesn't match any known
    ///   peer — a legitimate mesh address just not (yet) resolved. With
    ///   membership enabled this must fall through to `on_tun`'s
    ///   gossip-directory `resolve` fallback instead of being misrouted to
    ///   whichever one peer happens to already be known (the common
    ///   post-bootstrap state: just the seed root, before anyone else has
    ///   been resolved) — otherwise every not-yet-discovered destination
    ///   would be silently (and wrongly) routed to that one peer forever,
    ///   and dynamic discovery could never engage. Without membership this
    ///   case still falls back to the sole peer (byte-identical to 2a/2b:
    ///   there is no resolve path to try instead there either).
    fn route_tun_index(&self, inner: &[u8]) -> Option<usize> {
        match self.mode {
            TunnelMode::L2Tap => {
                if self.peers.len() == 1 {
                    Some(0)
                } else {
                    None
                }
            }
            TunnelMode::L3Tun => match ipv6_dst(inner) {
                Some(dst) => {
                    if let Some(&idx) = self.by_addr.get(&dst) {
                        return Some(idx);
                    }
                    if self.membership.is_none() && self.peers.len() == 1 {
                        Some(0)
                    } else {
                        None
                    }
                }
                None => {
                    if self.peers.len() == 1 {
                        Some(0)
                    } else {
                        None
                    }
                }
            },
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

    /// Dispatch a `Data`/`Control` datagram to peer `idx`'s `EpochSet` (via
    /// `inbound_open`) and re-map its `EpochInbound` into a `DispatchOut`.
    /// Returns `DispatchOut::None` if `idx` is not (or no longer)
    /// `Established`.
    fn dispatch_established(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        let PeerState::Established(epochs) = &mut self.peers[idx].state else {
            return DispatchOut::None;
        };
        // `EpochInbound::Send`/`TunThenSend` carry the full `EgressDatagram`
        // (real `dst` + `fate`), so no reconstruction from
        // `self.peers[idx].endpoint` is needed — that placeholder is wrong
        // for relay-established peers (their `DataPlane::peer_addr` is a
        // `server_addr()` stand-in; `endpoint` may hold an unconfirmed
        // candidate or `None`).
        match epochs.inbound_open(dg, now_ms) {
            crate::epoch::EpochInbound::None => DispatchOut::None,
            crate::epoch::EpochInbound::Tun(buf) => {
                self.tun_scratch = buf;
                DispatchOut::Tun(&self.tun_scratch)
            }
            crate::epoch::EpochInbound::Send(dgs) => {
                self.egress = dgs;
                DispatchOut::Udp(&self.egress)
            }
            crate::epoch::EpochInbound::TunThenSend(buf, dgs) => {
                self.tun_scratch = buf;
                self.egress = dgs;
                DispatchOut::Both(&self.tun_scratch, &self.egress)
            }
        }
    }

    fn handle_data_or_control(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        if let Some(idx) = self.route_data(src, dg) {
            // Real Data ingress for this peer (3b Task 4): only the `Data`
            // ptype counts as activity, not `Control` (the loss-feedback
            // packet also routes through here).
            if dg[0] == PacketType::Data as u8 {
                self.peers[idx].last_activity_ms = now_ms;
            }
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
                let PeerState::Established(epochs) = &mut self.peers[idx].state else {
                    continue;
                };
                match epochs.inbound_open(dg, now_ms) {
                    crate::epoch::EpochInbound::None => None,
                    crate::epoch::EpochInbound::Tun(buf) => Some((Some(buf), Vec::new())),
                    crate::epoch::EpochInbound::Send(dgs) => Some((None, dgs)),
                    crate::epoch::EpochInbound::TunThenSend(buf, dgs) => Some((Some(buf), dgs)),
                }
            };
            let Some((tun, udp)) = hit else {
                continue;
            };
            // `udp` already carries each datagram's real `dst`/`fate` (see
            // `EpochInbound`); no reconstruction from `self.peers[idx].endpoint`
            // needed (that placeholder is wrong for relay-established peers).
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
    /// Whether a responder's msg2 cert payload admits the peer whose static key
    /// is `peer_pub`. With membership disabled the payload is ignored (returns
    /// `true` — byte-identical to 2a/2b). With membership enabled the payload
    /// must decode to a `Cert` that `verify_cert`s against `peer_pub` at the
    /// current wall clock — mutual membership proof.
    fn responder_cert_ok(&self, payload: &[u8], peer_pub: [u8; 32]) -> bool {
        match self.membership.as_ref() {
            None => true,
            Some(m) => Cert::decode(payload)
                .is_some_and(|cert| m.verify_cert(&cert, &peer_pub, now_secs())),
        }
    }

    fn handle_handshake_init(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        // Present our cert in msg2 (2c); empty when membership is None.
        let resp_payload = self
            .membership
            .as_ref()
            .map(Membership::own_cert_bytes)
            .unwrap_or_default();
        let (established, resp_pkt, remote_static, initiator_payload) =
            match HandshakeState::start_responder(&self.local_priv, dg, &resp_payload) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("peer_manager: start_responder failed: {e}");
                    return DispatchOut::None;
                }
            };

        // Admission: a configured/root/already-admitted peer (static-key match)
        // OR — with membership enabled — the initiator presented a valid
        // CA-signed cert covering its static key (`remote_static`). A cert-admit
        // of a not-yet-known peer runs `admit_member` before completing. Neither
        // path → drop with NO reply, PRE-session, exactly like 2a's allowlist
        // drop. Membership only supplies a candidate; the Noise session that
        // `start_responder` just built still gates admission (anti-hijack).
        let idx = match self.peers.iter().position(|p| p.pubkey == remote_static) {
            Some(i) => i,
            None => {
                let cert_admits = self.membership.as_ref().is_some_and(|m| {
                    Cert::decode(&initiator_payload)
                        .is_some_and(|cert| m.verify_cert(&cert, &remote_static, now_secs()))
                });
                if !cert_admits {
                    // Not a configured peer and no valid cert: drop, no peer.
                    return DispatchOut::None;
                }
                // Admit the cert-verified member (endpoint learned from `src`
                // in the establish arm below). Cert carries no endpoints.
                self.admit_member(remote_static, Vec::new(), now_ms);
                match self.peers.iter().position(|p| p.pubkey == remote_static) {
                    Some(i) => i,
                    None => return DispatchOut::None,
                }
            }
        };

        // `start_responder` above drew a fresh Noise ephemeral, so `established`
        // is a BRAND-NEW session distinct from any we already hold — installing
        // it unconditionally would silently rekey. Branch on our current state
        // with that in mind.
        match &self.peers[idx].state {
            // Already `Established` (9a): this `Init` is either (a) a
            // duplicate/retransmit of the ORIGINAL completing handshake
            // (peer hasn't seen our reply yet) or a peer restart, or (b) a
            // genuine mid-session rekey `Init` from the peer
            // (`drive_rekey_schedule`'s counterpart on their side).
            // `EpochSet::accept_rekey_init` is the discriminator: a rekey
            // can only legitimately arrive once `current` is at least
            // `interval/2` old, so anything younger is (a) — handled
            // exactly as before rekey existed (9a Task 4 must not regress
            // this). `handle_rekey_init` owns the (b) path.
            //
            // `init_eph`: `start_responder` above already parsed `dg`'s
            // msg1 successfully, and Noise-IK's msg1 leads with the
            // unencrypted `e` token, so `dg[1..33]` is guaranteed present —
            // this is the same per-round identity `handle_rekey_init` uses
            // to deduplicate retransmitted Inits (9a final review).
            // Only complete a DIRECT rekey Init when this peer's live path is
            // NOT relay (final review, Important): a relay peer receiving a
            // direct Init (e.g. `peers[idx].relay == true` but the peer
            // somehow reached us directly) must NOT complete via this
            // direct-addressed core — its Inits are meant to arrive relayed.
            // Fail-closed drop instead, mirroring the guard in
            // `relayed_handshake_init`; `current` stays untouched.
            PeerState::Established(_) if !self.peers[idx].relay => {
                let init_eph = crate::handshake::init_ephemeral(dg).expect(
                    "start_responder already parsed dg's msg1; its leading 32 bytes are `e`",
                );
                self.handle_rekey_init(idx, src, established, resp_pkt, now_ms, init_eph)
            }
            PeerState::Established(_) => DispatchOut::None,
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
                let sess_obf = self.session_obf_key_for(&established.hp_key);
                let mut dp = Box::new(DataPlane::new(
                    established,
                    conn_tag,
                    self.mode,
                    src,
                    self.obf_key.is_some(),
                    self.data_symbol_size,
                ));

                self.peers[idx].session_obf_key = sess_obf;
                self.peers[idx].endpoint = Some(src); // learn the observed endpoint
                self.peers[idx].cached_resp = Some(resp_pkt.clone());
                self.peers[idx].cached_resp_init_eph = crate::handshake::init_ephemeral(dg);
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
                self.peers[idx].state =
                    PeerState::Established(Box::new(crate::epoch::EpochSet::new(dp, now_ms)));

                DispatchOut::Udp(&self.egress)
            }
        }
    }

    /// Rekey (9a Task 4) counterpart of the `Established(_)` arm in
    /// `handle_handshake_init`: `established`/`resp_pkt` were already built
    /// by the SAME `start_responder` call (and this peer already passed
    /// admission — it was found by static-key match, not by cert) at the
    /// top of `handle_handshake_init`, so there is no re-verification to do
    /// here. `init_eph` is that Init's Noise ephemeral
    /// (`handshake::init_ephemeral`) — the per-round identity used below to
    /// tell a RETRANSMIT of an already-answered round from a genuinely new
    /// one.
    ///
    /// In order:
    ///
    /// 1. `init_eph` matches `cached_resp_init_eph` (Important-2, 9a final
    ///    review): this Init is a retransmit of the ORIGINAL cold-start (or
    ///    relayed) Init that established the *current* session — possible
    ///    even past `interval/2` since `HANDSHAKE_TOTAL_MS` (90s) exceeds it
    ///    (60s). Resend `cached_resp` verbatim; never build a rekey `next`
    ///    off it.
    /// 2. `init_eph` matches the ephemeral behind the currently-held `next`
    ///    (the Critical fix, 9a final review): this Init is a retransmit of
    ///    a rekey round already answered — e.g. the initiator retransmitted
    ///    before seeing our first `[HandshakeResp]` (RTT > retry_ms), or a
    ///    `[HandshakeResp]` was reordered/duplicated in flight. Resend that
    ///    round's cached resp verbatim and do NOT mint a second session:
    ///    minting a fresh one here would discard the `next` the initiator is
    ///    about to promote to, stranding the two sides on different epochs
    ///    (initiator locks onto the FIRST `[HandshakeResp]` it reads and
    ///    never revisits later ones) and black-holing the tunnel.
    /// 3. `!EpochSet::accept_rekey_init`: `current` is too young for this to
    ///    plausibly be a genuine rekey. Falls back to the pre-9a behavior
    ///    (re-send the cached `[HandshakeResp]` verbatim if we hold one;
    ///    otherwise ignore, no reply). This is what keeps
    ///    `duplicate_init_after_established_does_not_tear_down_session`
    ///    green: that regression fires at `now_ms == current_created_ms`,
    ///    always younger than `interval/2`. The freshly-built
    ///    `established`/`resp_pkt` are discarded on this path — installing
    ///    them would silently rekey off a mere retransmit.
    /// 4. Otherwise: a genuinely NEW rekey round. Install `established` as
    ///    the responder's unconfirmed `next` epoch, keyed by `init_eph`
    ///    (`EpochSet::install_next`) — `current` is untouched, so this side
    ///    keeps SENDING on the old epoch. The responder's own switch happens
    ///    later, automatically, inside `EpochSet::inbound_open` (Task 1) on
    ///    the first inbound frame that authenticates under `next`.
    fn handle_rekey_init(
        &mut self,
        idx: usize,
        src: SocketAddr,
        established: Established,
        resp_pkt: Vec<u8>,
        now_ms: u64,
        init_eph: [u8; 32],
    ) -> DispatchOut<'_> {
        self.rekey_init_core(idx, established, resp_pkt, init_eph, now_ms, src, false)
    }

    /// Shared core for [`handle_rekey_init`] (`via_relay = false`) and its
    /// relay-path counterpart (#91 Task 2, `via_relay = true`). See
    /// `handle_rekey_init`'s doc comment above for the four-way dedup/gate
    /// logic (UNCHANGED here — only `peer_addr` and the emit are
    /// parameterized by `via_relay`, via [`push_rekey_egress`]).
    ///
    /// `direct_src` is the direct-path peer address (`Direct`/`Punched`
    /// `src`); for the relay path it is unused for addressing (the emit goes
    /// through `relay_wrap` instead) but is still threaded through so the
    /// two paths share one signature.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the pre-existing handle_rekey_init parameter set plus via_relay; the params are all distinct handshake-derived values"
    )]
    fn rekey_init_core(
        &mut self,
        idx: usize,
        established: Established,
        resp_pkt: Vec<u8>,
        init_eph: [u8; 32],
        now_ms: u64,
        direct_src: SocketAddr,
        via_relay: bool,
    ) -> DispatchOut<'_> {
        let peer_addr = if via_relay {
            self.server_addr()
        } else {
            direct_src
        };

        if self.peers[idx].cached_resp_init_eph == Some(init_eph) {
            return match self.peers[idx].cached_resp.clone() {
                Some(resp) => {
                    self.egress.clear();
                    self.push_rekey_egress(
                        idx,
                        EgressDatagram {
                            fate: 0,
                            dst: peer_addr,
                            bytes: resp,
                        },
                        via_relay,
                    );
                    if self.egress.is_empty() {
                        DispatchOut::None
                    } else {
                        DispatchOut::Udp(&self.egress)
                    }
                }
                None => DispatchOut::None,
            };
        }

        let PeerState::Established(epochs) = &mut self.peers[idx].state else {
            unreachable!("rekey_init_core is only called for an Established peer")
        };

        if let Some(cached) = epochs.next_cached_resp_for(&init_eph).map(<[u8]>::to_vec) {
            self.egress.clear();
            self.push_rekey_egress(
                idx,
                EgressDatagram {
                    fate: 0,
                    dst: peer_addr,
                    bytes: cached,
                },
                via_relay,
            );
            return if self.egress.is_empty() {
                DispatchOut::None
            } else {
                DispatchOut::Udp(&self.egress)
            };
        }

        let PeerState::Established(epochs) = &self.peers[idx].state else {
            unreachable!("state cannot change between the two borrows above")
        };
        if !epochs.accept_rekey_init(now_ms, self.rekey_interval_ms) {
            return match self.peers[idx].cached_resp.clone() {
                Some(resp) => {
                    self.egress.clear();
                    self.push_rekey_egress(
                        idx,
                        EgressDatagram {
                            fate: 0,
                            dst: peer_addr,
                            bytes: resp,
                        },
                        via_relay,
                    );
                    if self.egress.is_empty() {
                        DispatchOut::None
                    } else {
                        DispatchOut::Udp(&self.egress)
                    }
                }
                None => DispatchOut::None,
            };
        }

        // NOTE: `session_obf_key` (the outer anti-DPI wrap key, keyed off
        // `hp_key`) is intentionally left untouched here — see the doc
        // comment on `handle_rekey_resp`.
        let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
        let dp = Box::new(DataPlane::new(
            established,
            conn_tag,
            self.mode,
            peer_addr,
            self.obf_key.is_some(),
            self.data_symbol_size,
        ));
        let PeerState::Established(epochs) = &mut self.peers[idx].state else {
            unreachable!("state cannot change between the two borrows above")
        };
        epochs.install_next(dp, init_eph, resp_pkt.clone());

        self.egress.clear();
        self.push_rekey_egress(
            idx,
            EgressDatagram {
                fate: 0,
                dst: peer_addr,
                bytes: resp_pkt,
            },
            via_relay,
        );
        if self.egress.is_empty() {
            DispatchOut::None
        } else {
            DispatchOut::Udp(&self.egress)
        }
    }

    /// Handle an incoming `[HandshakeResp]`: either complete an in-flight
    /// rekey for an already-`Established` peer (9a Task 4), or — the
    /// cold-start path — find the `Handshaking` peer whose endpoint matches
    /// `src`, resume via `read_response`, transition to `Established`, and
    /// drain any buffered `pending_tun`.
    fn handle_handshake_resp(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        if let Some(idx) = self.peers.iter().position(|p| {
            p.endpoint == Some(src)
                && matches!(&p.state, PeerState::Established(epochs) if epochs.rekey.is_some())
                && !p.relay
        }) {
            return self.handle_rekey_resp(idx, dg, now_ms);
        }

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
            Ok((established, responder_payload)) => {
                if !self.responder_cert_ok(&responder_payload, self.peers[idx].pubkey) {
                    // Responder failed to prove membership: do not establish.
                    // State was already reverted to `Idle`; `pending_tun` stays
                    // queued for the next attempt.
                    eprintln!("peer_manager: responder cert rejected");
                    return DispatchOut::None;
                }
                let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
                let sess_obf = self.session_obf_key_for(&established.hp_key);
                // `idx` was matched above via `p.endpoint == Some(src)`, so `src`
                // is exactly this peer's endpoint.
                let mut dp = Box::new(DataPlane::new(
                    established,
                    conn_tag,
                    self.mode,
                    src,
                    self.obf_key.is_some(),
                    self.data_symbol_size,
                ));
                self.by_tag.insert(dp.conn_tag(), idx);
                self.peers[idx].session_obf_key = sess_obf;
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
                self.peers[idx].state =
                    PeerState::Established(Box::new(crate::epoch::EpochSet::new(dp, now_ms)));

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

    /// Complete an in-flight rekey handshake for an `Established` peer `idx`
    /// (initiator side of the WireGuard-style confirmed switch, 9a Task 4)
    /// on receipt of the matching `[HandshakeResp]`.
    ///
    /// `HandshakeState::read_response` consumes the handshake BY VALUE, so
    /// the `RekeyInFlight` is taken out of `epochs.rekey` first — after
    /// that, `epochs.rekey` is `None` regardless of what happens next, so
    /// every early return below is already a fail-closed no-op: `current`
    /// is untouched and `drive_rekey_schedule`'s `needs_rekey` will try
    /// again at the next interval.
    ///
    /// KNOWN LIMITATION (9a final review, Important-1), left as-is on
    /// purpose: `epochs.rekey.take()` runs BEFORE `rk.hs.read_response(dg)`
    /// below, so a delayed/duplicate/spoofed-src `[HandshakeResp]` that
    /// fails to `read_response` (wrong bytes, replayed old Resp, or a
    /// same-endpoint attacker's garbage — UDP has no source authentication)
    /// silently ABANDONS the in-flight rekey rather than just ignoring the
    /// bad datagram and letting the real Resp complete it later. This is a
    /// rekey-*liveness* DoS only: `current` is never touched (fail-closed
    /// per the constraint above), so the live session survives untouched —
    /// only the rotation is denied, and `drive_rekey_schedule` starts a
    /// fresh rekey attempt next interval. The clean fix would be to `clone`
    /// `rk.hs`, try `read_response` on the clone, and only `take()`/clear
    /// `rekey` on success — but `snow::HandshakeState` (which
    /// `yip_crypto::Handshake`/`crate::handshake::HandshakeState` wrap) is
    /// NOT `Clone` (it owns `Box<dyn Dh>`/`Box<dyn Random>` trait objects),
    /// so that fix is not available without hand-rolling handshake state
    /// duplication in `yip-crypto` — out of scope here. An off-path
    /// attacker that can spoof this peer's endpoint as `src` can therefore
    /// repeatedly deny rekey rotation (never break the tunnel); closing that
    /// rides with the #34 authenticated-endpoint work (verifying `src`
    /// against the session before acting on it).
    ///
    /// On success: builds the new epoch's `DataPlane` exactly like
    /// cold-start completion, promotes it via `EpochSet::promote_from_rekey`
    /// (switching `current` immediately — the initiator already knows the
    /// responder installed this epoch, since it just sent the `Resp`), and
    /// emits one outbound frame on the NEW epoch (draining `pending_tun`, or
    /// a bare empty-payload frame if none is queued) so the responder
    /// observes a `next`-epoch datagram and confirms its own switch inside
    /// `EpochSet::inbound_open` (Task 1).
    ///
    /// `session_obf_key` (the outer anti-DPI wrap key, keyed off `hp_key`)
    /// is intentionally left untouched across the promotion: it is derived
    /// once at cold start and shared by both peers for the connection's
    /// lifetime. The responder's own confirmed-switch promotion happens
    /// entirely inside `EpochSet::inbound_open`, which has no access to
    /// `PeerManager`/`Peer` fields — so it has no way to resync
    /// `session_obf_key` on that side. Rotating it here, on the initiator
    /// side only, would desync the two peers' outer-wrap keys rather than
    /// fix anything; leaving it alone keeps both sides on the one key they
    /// already agree on. (The security-relevant per-epoch key material — the
    /// inner AEAD/wire `Codec` — DOES rotate correctly: it is rebuilt fresh
    /// inside `DataPlane::new` from this epoch's own `auth_key`/`hp_key`.)
    fn handle_rekey_resp(&mut self, idx: usize, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        self.rekey_resp_core(idx, dg, now_ms, false)
    }

    /// Shared core for [`handle_rekey_resp`] (`via_relay = false`) and its
    /// relay-path counterpart (#91 Task 2, `via_relay = true`). See
    /// `handle_rekey_resp`'s doc comment above for the full behavior
    /// (UNCHANGED here — only `peer_addr` and the prime-emit are
    /// parameterized by `via_relay`, via [`push_rekey_egress`]).
    fn rekey_resp_core(
        &mut self,
        idx: usize,
        dg: &[u8],
        now_ms: u64,
        via_relay: bool,
    ) -> DispatchOut<'_> {
        let rk = {
            let PeerState::Established(epochs) = &mut self.peers[idx].state else {
                unreachable!("rekey_resp_core is only called for an Established peer")
            };
            match epochs.rekey.take() {
                Some(rk) => rk,
                None => return DispatchOut::None,
            }
        };
        let peer_addr = if via_relay {
            self.server_addr()
        } else {
            rk.target
        };

        let (established, responder_payload) = match rk.hs.read_response(dg) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("peer_manager: rekey read_response failed: {e}");
                return DispatchOut::None;
            }
        };
        if !self.responder_cert_ok(&responder_payload, self.peers[idx].pubkey) {
            eprintln!("peer_manager: rekey responder cert rejected");
            return DispatchOut::None;
        }

        let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
        let mut dp = Box::new(DataPlane::new(
            established,
            conn_tag,
            self.mode,
            peer_addr,
            self.obf_key.is_some(),
            self.data_symbol_size,
        ));

        // Prime the new epoch (BEFORE `dp` moves into `promote_from_rekey`
        // below), emitting via the helper. Clone the FULL `EgressDatagram`s
        // (not just `.bytes`) so the Direct path preserves the real
        // per-FEC-object `fate` `dp.on_tun_packet` assigns (byte-identical to
        // the pre-refactor `.cloned()`) — `push_rekey_egress` relay-wraps
        // `.bytes` alone for the relay path, so cloning the full datagram
        // here costs nothing there.
        let pending = std::mem::take(&mut self.peers[idx].pending_tun);
        self.egress.clear();
        let primed: Vec<EgressDatagram> = if pending.is_empty() {
            dp.on_tun_packet(&[], now_ms).to_vec()
        } else {
            pending
                .iter()
                .flat_map(|inner| dp.on_tun_packet(inner, now_ms).to_vec())
                .collect()
        };
        for dg in primed {
            self.push_rekey_egress(idx, dg, via_relay);
        }

        let old_tag = {
            let PeerState::Established(epochs) = &mut self.peers[idx].state else {
                unreachable!("state cannot change between the borrows above")
            };
            let old_tag = epochs.current().conn_tag();
            epochs.promote_from_rekey(dp, now_ms);
            old_tag
        };
        self.by_tag.remove(&old_tag);
        self.by_tag.insert(conn_tag, idx);

        if self.egress.is_empty() {
            DispatchOut::None
        } else {
            DispatchOut::Udp(&self.egress)
        }
    }

    // ── membership gossip ─────────────────────────────────────────────────

    /// Handle an inbound `[Gossip]` datagram from `src`: decode the
    /// [`GossipMsg`], feed it to `Membership::on_gossip` (which verifies every
    /// record's CA→cert→record-sig chain, so a forged/injected record is
    /// rejected — no in-session encryption is needed for integrity), and send
    /// any bounded reply back to `src` as `[Gossip ++ msg]` datagrams
    /// (relay-wrapped iff `src` maps to a `Relayed` peer). Only called with
    /// membership configured.
    ///
    /// Source-restricted to `Established` peers ONLY: gossip only ever
    /// legitimately flows between admitted members (a joining node
    /// cert-verifies into `Established` before it gossips), so a `src` that
    /// does not match a currently `Established` peer's endpoint is dropped
    /// before decoding, let alone before any per-record Ed25519 verify or
    /// reply is produced. Without this, `src` is fully attacker-controlled
    /// (UDP has no source authentication) and a spoofed `PullRequest` would
    /// be an unauthenticated reflection/amplification primitive (a small
    /// request naming known `node_id`s reflecting a much larger `Records`
    /// reply at a forged victim address) plus an unbounded per-record-verify
    /// CPU sink for inbound `Records`. Restricting to `Established` peers
    /// bounds both costs to already-admitted members.
    fn on_gossip(&mut self, src: SocketAddr, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
        let Some(peer_idx) = self
            .peers
            .iter()
            .position(|p| p.endpoint == Some(src) && matches!(p.state, PeerState::Established(_)))
        else {
            return DispatchOut::None;
        };
        let Some(msg) = GossipMsg::decode(&dg[1..]) else {
            return DispatchOut::None;
        };
        let replies = match self.membership.as_mut() {
            Some(m) => m.on_gossip(msg, now_secs()),
            None => return DispatchOut::None,
        };
        if replies.is_empty() {
            return DispatchOut::None;
        }
        // Decide the return path: if `src` is reached via the relay, wrap
        // replies through the server; otherwise reply direct to `src`. (The
        // peer's committed egress is untouched — we only read its `relay`
        // flag.)
        let relay = self.peers[peer_idx].relay;
        self.egress.clear();
        for reply in replies.iter().take(MAX_GOSSIP_REPLIES) {
            let mut bytes = Vec::new();
            bytes.push(PacketType::Gossip as u8);
            reply.encode(&mut bytes);
            if relay {
                if let Some(d) = self.relay_wrap(peer_idx, bytes) {
                    self.egress.push(d);
                }
            } else {
                self.egress.push(EgressDatagram {
                    fate: 0,
                    dst: src,
                    bytes,
                });
            }
        }
        if self.egress.is_empty() {
            DispatchOut::None
        } else {
            DispatchOut::Udp(&self.egress)
        }
    }

    /// The gossip fan-out targets for a `tick` digest: a bounded sample of
    /// Established peers (relay-wrapped when `Relayed`) plus the roots (direct).
    /// Returns `(dst, relay_peer_idx)` — `Some(idx)` means relay-wrap through
    /// the server for that peer.
    fn gossip_targets(&self) -> Vec<(SocketAddr, Option<usize>)> {
        let mut out: Vec<(SocketAddr, Option<usize>)> = Vec::new();
        for (i, p) in self.peers.iter().enumerate() {
            if out.len() >= MAX_GOSSIP_TARGETS {
                return out;
            }
            if matches!(p.state, PeerState::Established(_)) {
                if p.relay {
                    out.push((self.server_addr(), Some(i)));
                } else if let Some(ep) = p.endpoint {
                    out.push((ep, None));
                }
            }
        }
        if let Some(m) = self.membership.as_ref() {
            for (_, addr) in m.roots() {
                if out.len() >= MAX_GOSSIP_TARGETS {
                    break;
                }
                out.push((*addr, None));
            }
        }
        out
    }

    /// Periodic gossip from `tick` (membership only): emit a debounced digest to
    /// a bounded set of partners (roots + a sample of Established peers) and, if
    /// no live session exists yet, bootstrap by handshaking to a root so gossip
    /// can seed a fresh node. Pushes into `tick_egress`.
    fn tick_gossip(&mut self, now_ms: u64) {
        let have_established = self
            .peers
            .iter()
            .any(|p| matches!(p.state, PeerState::Established(_)));

        // Debounced digest (spacing handled inside `tick_digest`).
        let obf_on = self.obf_key.is_some();
        if let Some(digest) = self
            .membership
            .as_mut()
            .and_then(|m| m.tick_digest(now_ms, obf_on))
        {
            let mut bytes = Vec::new();
            bytes.push(PacketType::Gossip as u8);
            digest.encode(&mut bytes);
            for (dst, relay_idx) in self.gossip_targets() {
                match relay_idx {
                    Some(i) => {
                        if let Some(d) = self.relay_wrap(i, bytes.clone()) {
                            self.tick_egress.push(d);
                        }
                    }
                    None => self.tick_egress.push(EgressDatagram {
                        fate: 0,
                        dst,
                        bytes: bytes.clone(),
                    }),
                }
            }
        }

        // Bootstrap: with no Established peer yet, initiate a handshake to a
        // root (always-admit) so a session — and gossip — can seed. One at a
        // time; a root already Handshaking/Established is not re-probed.
        if !have_established {
            let root_addrs: Vec<SocketAddr> = self
                .membership
                .as_ref()
                .map(|m| m.roots().iter().map(|(_, a)| *a).collect())
                .unwrap_or_default();
            for addr in root_addrs {
                if let Some(i) = self
                    .peers
                    .iter()
                    .position(|p| p.endpoint == Some(addr) && matches!(p.state, PeerState::Idle))
                {
                    if let Some(dgs) = self.begin_handshake(i, addr, false, now_ms) {
                        self.tick_egress.extend(dgs);
                    }
                    break;
                }
            }
        }
    }

    // ── anti-DPI obfuscation (3a) ─────────────────────────────────────────
    //
    // A thin wrap/unwrap LAYER around the existing `[PacketType][…]` datagrams,
    // active only when `obf_key.is_some()`. It never weakens the inner
    // Noise/AEAD/yip-wire crypto — a wrong key deobfuscates to garbage that the
    // inner verify then rejects (fail-closed). When `obf_key` is `None` these
    // helpers are never called and every `Dispatch` method takes the exact
    // 2a/2b/2c plaintext path (byte-identical).

    /// Recover the plaintext `[ptype] ‖ body` datagram from an obfuscated
    /// ingress datagram `dg` that arrived from `src`, by source + trial-unmask,
    /// or `None` if it unmasks to nothing dispatchable (⇒ drop). Only called on
    /// the obfuscation-enabled path.
    ///
    /// Order (matches the addendum):
    /// (a) If `src` is a known `Established` peer, try that peer's
    ///     `session_obf_key`; accept only `Data`/`Control`/`Gossip`.
    /// (b) Otherwise (or if (a) did not yield one of those types), try the
    ///     network `obf_key`; accept only `HandshakeInit`/`HandshakeResp` — this
    ///     covers a brand-new peer's `Init` AND a re-handshake from a known src.
    ///
    /// A wrong key yields `None` or a garbage `(ptype, body)`; the type-set
    /// filters and, ultimately, the inner Noise/AEAD/frame verify make every
    /// mismatch a safe drop — never a mis-dispatch with side effects.
    fn deobf_ingress(&self, src: SocketAddr, dg: &[u8]) -> Option<Vec<u8>> {
        // (a) established peer whose endpoint matches src → session key.
        if let Some(key) = self.peers.iter().find_map(|p| {
            if p.endpoint == Some(src) && matches!(p.state, PeerState::Established(_)) {
                p.session_obf_key
            } else {
                None
            }
        }) {
            if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
                if ptype == yip_obf::JUNK_TYPE {
                    return None; // idle-cover decoy: inert, dropped, no fall-through
                }
                if ptype == PacketType::Data as u8
                    || ptype == PacketType::Control as u8
                    || ptype == PacketType::Gossip as u8
                {
                    return Some(reassemble(ptype, &body));
                }
            }
        }
        // (b) pre-session network key → handshakes only.
        if let Some(key) = self.obf_key {
            if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
                if ptype == yip_obf::JUNK_TYPE {
                    return None; // idle-cover decoy: inert, dropped, no fall-through
                }
                if ptype == PacketType::HandshakeInit as u8
                    || ptype == PacketType::HandshakeResp as u8
                {
                    return Some(reassemble(ptype, &body));
                }
            }
        }
        None
    }

    /// Build a plaintext JUNK decoy datagram `[JUNK_TYPE][random body]`. The
    /// caller's `obf_egress` pass wraps it once (network key for a
    /// handshake-burst dst, session key for an established-peer cover dst) —
    /// do NOT pre-obfuscate here, or it would be double-wrapped. Body length
    /// is random in `[JUNK_MIN_LEN, JUNK_MAX_LEN]`, drawn from `junk_rng`
    /// (content is irrelevant — masked once `obf_egress` wraps it). The
    /// receiver recovers `(JUNK_TYPE, _)` via a single `yip_obf::deobfuscate`
    /// and drops it (see `deobf_ingress`) — junk never touches
    /// Noise/AEAD/session state. Only meaningful on the obfuscation-enabled
    /// path (`begin_handshake` only calls this when `obf_key.is_some()`).
    fn build_junk(&mut self) -> Vec<u8> {
        let lo = u64::try_from(JUNK_MIN_LEN).expect("JUNK_MIN_LEN fits u64");
        let hi = u64::try_from(JUNK_MAX_LEN).expect("JUNK_MAX_LEN fits u64");
        let len = usize::try_from(self.junk_rng.gen_range(lo, hi)).expect("gen_range in usize");
        let mut out = vec![0u8; 1 + len];
        out[0] = yip_obf::JUNK_TYPE;
        self.junk_rng.fill(&mut out[1..]);
        out
    }

    /// The obfuscation key to wrap an egress datagram to `dst` whose plaintext
    /// leads with `ptype`: the network `obf_key` for handshakes (pre-session);
    /// otherwise the `session_obf_key` of the `Established` peer reached at
    /// `dst`. Falls back to the network key when no session key is found (e.g. a
    /// gossip digest to a not-yet-`Established` root) so wrapping never silently
    /// drops a datagram.
    fn obf_key_for_egress(&self, dst: SocketAddr, ptype: u8) -> Option<[u8; 16]> {
        if ptype == PacketType::HandshakeInit as u8 || ptype == PacketType::HandshakeResp as u8 {
            return self.obf_key;
        }
        self.peers
            .iter()
            .find_map(|p| {
                if p.endpoint == Some(dst) && matches!(p.state, PeerState::Established(_)) {
                    p.session_obf_key
                } else {
                    None
                }
            })
            .or(self.obf_key)
    }

    /// Wrap every egress datagram in `dgs` in place via `yip_obf::obfuscate`
    /// (masked type + random padding), so the `PacketType` byte never appears on
    /// the wire. Datagrams addressed to the rendezvous server carry a plaintext
    /// `yip_rendezvous::Message` rather than a `[PacketType][…]` tunnel
    /// datagram, so they are wrapped whole (no leading byte stripped) under the
    /// dedicated `yip_obf::RDV_TYPE` and the network `obf_key` (the server is
    /// never an `Established` peer, so it has no session key). Only called on
    /// the obfuscation-enabled path.
    fn obf_egress(&self, dgs: &mut [EgressDatagram]) {
        let server = self.rendezvous.as_ref().map(|r| r.server_addr());
        for d in dgs.iter_mut() {
            if d.bytes.is_empty() {
                continue;
            }
            if Some(d.dst) == server {
                let Some(key) = self.obf_key else {
                    continue;
                };
                let pad = random_pad(obf_pad_max(yip_obf::RDV_TYPE, d.bytes.len() + 1));
                d.bytes = yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &d.bytes, pad);
                continue;
            }
            let ptype = d.bytes[0];
            let Some(key) = self.obf_key_for_egress(d.dst, ptype) else {
                continue;
            };
            let pad = random_pad(obf_pad_max(ptype, d.bytes.len()));
            d.bytes = yip_obf::obfuscate(&key, ptype, &d.bytes[1..], pad);
        }
    }

    /// Wrap `udp` egress and re-materialize a `DispatchOut` from the owned
    /// `(tun, udp)` parts produced by [`own_dispatch`]. Used by the
    /// obfuscation-enabled `on_udp` path.
    fn finish_wrapped(
        &mut self,
        tun: Option<Vec<u8>>,
        mut udp: Vec<EgressDatagram>,
    ) -> DispatchOut<'_> {
        self.obf_egress(&mut udp);
        self.egress = udp;
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
}

impl Dispatch for PeerManager {
    /// UDP ingress. Obfuscation off ⇒ the plaintext 2a/2b/2c demux, verbatim.
    /// Obfuscation on ⇒ recover the real datagram — rendezvous-server
    /// datagrams via the network `obf_key` + `RDV_TYPE`, everything else by
    /// source + trial-unmask — run the SAME demux on it, then wrap the
    /// egress it produces.
    fn on_udp(&mut self, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        if self.obf_key.is_none() {
            return self.on_udp_dispatch(src, dg, now_ms);
        }
        if dg.is_empty() {
            return DispatchOut::None;
        }
        // A datagram from the configured rendezvous server is an obfuscated
        // control/relay message under the network `obf_key` and `RDV_TYPE`;
        // unwrap it before handing the plaintext `yip_rendezvous::Message`
        // bytes to `on_rdv`, then wrap only the peer-directed egress it
        // yields. Wrong key / wrong ptype ⇒ drop (fail-closed), never a panic.
        let server = self.rendezvous.as_ref().map(|r| r.server_addr());
        if Some(src) == server {
            let Some(key) = self.obf_key else {
                return DispatchOut::None;
            };
            let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) else {
                return DispatchOut::None;
            };
            if ptype != yip_obf::RDV_TYPE {
                return DispatchOut::None;
            }
            let (tun, udp) = own_dispatch(self.on_rdv(&body, now_ms));
            return self.finish_wrapped(tun, udp);
        }
        let Some(plain) = self.deobf_ingress(src, dg) else {
            return DispatchOut::None;
        };
        let (tun, udp) = own_dispatch(self.on_udp_dispatch(src, &plain, now_ms));
        self.finish_wrapped(tun, udp)
    }

    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram] {
        if self.obf_key.is_none() {
            return self.on_tun_dispatch(inner, now_ms);
        }
        // Copy the (borrowed) egress out so the DataPlane/self borrow ends, then
        // wrap in place and return from `self.egress`.
        let mut owned: Vec<EgressDatagram> = self.on_tun_dispatch(inner, now_ms).to_vec();
        self.obf_egress(&mut owned);
        self.egress = owned;
        &self.egress
    }

    fn tick(&mut self, now_ms: u64) -> Option<&[EgressDatagram]> {
        if self.obf_key.is_none() {
            return self.tick_dispatch(now_ms);
        }
        let mut owned: Vec<EgressDatagram> = self.tick_dispatch(now_ms)?.to_vec();
        self.obf_egress(&mut owned);
        self.tick_egress = owned;
        Some(&self.tick_egress)
    }
}

impl PeerManager {
    fn on_udp_dispatch(&mut self, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
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
        } else if self.membership.is_some() && dg[0] == PacketType::Gossip as u8 {
            // Membership anti-entropy: a self-verifying gossip datagram. Only
            // reached with membership configured — a pure-2a/2b deployment never
            // sees `Gossip` traffic, so this branch is byte-identical there.
            self.on_gossip(src, dg, now_ms)
        } else {
            self.handle_data_or_control(src, dg, now_ms)
        }
    }

    fn on_tun_dispatch(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram] {
        let idx = match self.route_tun_index(inner) {
            Some(i) => i,
            None => {
                // No configured peer owns this inner dst. With membership
                // enabled, try the gossip directory: an unknown mesh address may
                // resolve to a member we can admit at runtime and then bring up
                // via the normal lazy handshake. Without membership (or if the
                // dst isn't a mesh address, or isn't in the directory), fall
                // back to 2a/2b's drop — byte-identical.
                let resolved = match (self.membership.as_ref(), ipv6_dst(inner)) {
                    (Some(m), Some(dst)) => m.resolve(&dst),
                    _ => None,
                };
                match resolved {
                    Some(info) => {
                        self.admit_member(info.pubkey, info.endpoints, now_ms);
                        // The just-admitted peer registered `by_addr`, so this
                        // now resolves to it; re-drive the normal path below.
                        match self.route_tun_index(inner) {
                            Some(i) => i,
                            None => return &[],
                        }
                    }
                    None => return &[],
                }
            }
        };

        // Each branch below is a syntactically separate `match`/`if`, rather
        // than one `match` with arms that need different sibling `Peer`
        // fields (`pending_tun`, `pubkey`) alongside the state borrow: NLL
        // unifies a single match expression's borrow across all arms to the
        // arm that returns borrowed data, which then conflicts with any
        // other arm that also touches `self.peers[idx]`. Splitting into
        // independent statements gives each one its own borrow region.
        if matches!(self.peers[idx].state, PeerState::Established(_)) {
            // Real Data egress for this peer (3b Task 4): mark it active so
            // the idle-cover-traffic gate in `tick_dispatch` does not fire
            // while real traffic is flowing.
            self.peers[idx].last_activity_ms = now_ms;
            // A relay-reached peer's data-plane egress must be re-wrapped
            // through the server (dst = server); copy the bytes out first (the
            // DataPlane borrows `self.peers[idx]`) then wrap. A direct/punched
            // peer's datagrams already carry the correct `dst` — return them
            // borrowed, byte-identical to 2a.
            if !self.peers[idx].relay {
                let PeerState::Established(epochs) = &mut self.peers[idx].state else {
                    unreachable!("just matched Established above");
                };
                return epochs.current_mut().on_tun_packet(inner, now_ms);
            }
            let owned: Vec<Vec<u8>> = {
                let PeerState::Established(epochs) = &mut self.peers[idx].state else {
                    unreachable!("just matched Established above");
                };
                epochs
                    .current_mut()
                    .on_tun_packet(inner, now_ms)
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
        let dgs = match action {
            PathAction::Probe(addr) => self.begin_handshake(idx, addr, false, now_ms),
            PathAction::Relay => {
                let server = self.server_addr();
                self.begin_handshake(idx, server, true, now_ms)
            }
            PathAction::NeedLookup => self.maybe_lookup(idx, now_ms).map(|d| vec![d]),
            PathAction::Idle | PathAction::Failed => None,
        };
        match dgs {
            Some(dgs) => {
                self.egress.clear();
                self.egress.extend(dgs);
                &self.egress
            }
            None => &[],
        }
    }

    fn tick_dispatch(&mut self, now_ms: u64) -> Option<&[EgressDatagram]> {
        self.tick_egress.clear();

        // ── registration refresh ──────────────────────────────────────────
        // Keep our reflexive binding fresh on the server so peers can find us.
        if self.rendezvous.is_some()
            && (!self.registered_once
                || now_ms.saturating_sub(self.last_register_ms) >= self.reg_refresh_ms)
        {
            let node = self.local_node_id;
            if let Some(r) = self.rendezvous.as_mut() {
                if let Some(dg) = r.register(node) {
                    self.tick_egress.push(dg);
                }
            }
            self.last_register_ms = now_ms;
            self.reg_refresh_ms = if self.obf_key.is_some() {
                jitter_ms(REG_REFRESH_MS)
            } else {
                REG_REFRESH_MS
            };
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
                        // Escalate the in-flight direct/punch attempt to the relay, PRESERVING
                        // the ephemeral (#36): resend the same Init over the relay so a responder
                        // already Established on the old path completes us via its cached_resp.
                        // `retarget_handshake` clears `endpoint` (anti-mismatch) as the old
                        // Idle+begin_handshake path did.
                        let server = self.server_addr();
                        if let Some(dgs) = self.retarget_handshake(i, server, true, now_ms) {
                            self.tick_egress.extend(dgs);
                        }
                        continue;
                    }
                    PathAction::Probe(addr) if addr != target => {
                        // The SM chose a *different* candidate: re-target the in-flight attempt,
                        // PRESERVING the ephemeral (#36) instead of abandoning it to a fresh one.
                        if let Some(dgs) = self.retarget_handshake(i, addr, false, now_ms) {
                            self.tick_egress.extend(dgs);
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
                PeerState::Established(mut epochs) => {
                    epochs.retire_previous_if_due(now_ms);
                    self.drive_rekey_schedule(i, relay, &mut epochs, now_ms);
                    if let Some(pkts) = epochs.current_mut().tick(now_ms) {
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
                    PeerState::Established(epochs)
                }
                PeerState::Handshaking(mut handshaking)
                    if now_ms.saturating_sub(handshaking.last_sent_ms) >= handshaking.retry_ms =>
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
                        handshaking.retry_ms = if self.obf_key.is_some() {
                            jitter_ms(HANDSHAKE_RETRY_MS)
                        } else {
                            HANDSHAKE_RETRY_MS
                        };
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

        // ── membership gossip ─────────────────────────────────────────────
        // Skipped entirely without membership (pure-2a/2b `tick` is unchanged).
        if self.membership.is_some() {
            self.tick_gossip(now_ms);
        }

        // ── idle cover traffic (3b Task 4) ──────────────────────────────────
        // Opt-in decoy traffic: only when obfuscation is on AND a
        // `cover_traffic_ms` interval is configured. For each direct
        // (non-relay) `Established` peer with a known endpoint that has been
        // idle (no real Data sent or received) for at least the interval,
        // AND hasn't had a cover datagram emitted in at least the interval,
        // push exactly one session-keyed junk datagram (`build_junk` is
        // plaintext; `tick`/`obf_egress` wraps it once with that peer's
        // session key, since `dst` is an `Established` peer's endpoint).
        // Gated on `last_activity_ms` so this never races or delays real
        // data — latency-free, idle-only, bounded to one datagram per peer
        // per tick. A relay-reached peer (`relay == true`) is skipped: its
        // `endpoint` is a stale/candidate direct address left over from
        // before the passive `relayed_handshake_*` path took over (see the
        // real-Data egress arm above, which likewise checks `!relay`) —
        // firing cover at it would leak junk to an unrelated address and
        // miss the peer entirely. Relay-path cover is out of scope for 3b
        // (mirrors Task 3's handshake junk, which is direct-path-only).
        if let (true, Some(iv)) = (self.obf_key.is_some(), self.cover_traffic_ms) {
            for i in 0..self.peers.len() {
                if !matches!(self.peers[i].state, PeerState::Established(_)) || self.peers[i].relay
                {
                    continue;
                }
                let Some(endpoint) = self.peers[i].endpoint else {
                    continue;
                };
                if now_ms.saturating_sub(self.peers[i].last_activity_ms) < iv
                    || now_ms.saturating_sub(self.peers[i].last_cover_ms) < iv
                {
                    continue;
                }
                let bytes = self.build_junk();
                self.tick_egress.push(EgressDatagram {
                    fate: 0,
                    dst: endpoint,
                    bytes,
                });
                self.peers[i].last_cover_ms = now_ms;
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
/// Wall-clock UNIX seconds, for cert-validity checks (`not_before`/
/// `not_after`, widened by the membership clock-skew tolerance). This is a
/// **distinct** clock from the monotonic `now_ms` the event loop threads
/// through `on_udp`/`on_tun`/`tick`: `now_ms` drives handshake/path timers and
/// gossip debounce and must never be compared against a cert's validity
/// window. A pre-1970 clock (impossible in practice) degrades to `0`, which
/// simply fails every not-yet-valid cert closed — never panics.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ipv6_dst(inner: &[u8]) -> Option<Ipv6Addr> {
    if inner.len() < 40 || inner[0] >> 4 != 6 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&inner[24..40]);
    Some(Ipv6Addr::from(octets))
}

// ── obfuscation free helpers (3a) ───────────────────────────────────────────

/// Rebuild the plaintext datagram `[ptype] ‖ body` that the pre-obfuscation
/// demux expects, from a deobfuscated `(ptype, body)` pair.
fn reassemble(ptype: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(ptype);
    v.extend_from_slice(body);
    v
}

/// Decompose a borrowed [`DispatchOut`] into owned `(tun, udp)` parts so the
/// `self` borrow it holds can end before the egress is wrapped and re-returned.
/// Mirrors the clone-to-owned pattern already used by `relayed_data` /
/// `handle_data_or_control` where borrows would otherwise fight.
fn own_dispatch(out: DispatchOut<'_>) -> (Option<Vec<u8>>, Vec<EgressDatagram>) {
    match out {
        DispatchOut::None => (None, Vec::new()),
        DispatchOut::Tun(b) => (Some(b.to_vec()), Vec::new()),
        DispatchOut::Udp(e) => (None, e.to_vec()),
        DispatchOut::Both(b, e) => (Some(b.to_vec()), e.to_vec()),
    }
}

/// The maximum obfuscation padding (bytes) for an envelope leading with
/// `ptype`, whose current plaintext datagram (type byte + body) is `dg_len`
/// bytes: generous for handshakes (they are small and otherwise highly
/// fingerprintable), modest for data/control/gossip (already near the path
/// MTU), always bounded so the wrapped datagram stays within [`OBF_MTU_BUDGET`].
fn obf_pad_max(ptype: u8, dg_len: usize) -> usize {
    // `dg_len` counts the leading type byte too; the envelope re-adds its own
    // header (nonce+type+len), so budget against the body length.
    let body_len = dg_len.saturating_sub(1);
    let room = OBF_MTU_BUDGET.saturating_sub(body_len + yip_obf::MIN_ENVELOPE);
    if ptype == PacketType::HandshakeInit as u8 || ptype == PacketType::HandshakeResp as u8 {
        room
    } else {
        room.min(OBF_DATA_PAD_MAX)
    }
}

/// A uniformly-random padding length in `0..=max`, drawn from the OS RNG.
/// `max == 0` ⇒ `0` (no `getrandom` call). No numeric `as` casts.
fn random_pad(max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG");
    let v = u64::from_le_bytes(b);
    let span = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    usize::try_from(v % span).unwrap_or(0)
}

/// Draw a value uniformly in `[base - base/4, base + base/4]` (±25%) via the
/// OS RNG — used to jitter a control-plane timing cadence under `obf_psk` so
/// repeated fires (handshake retry, registration refresh, gossip digest)
/// don't emit a clean lockstep inter-arrival signature to a traffic-analysis
/// observer. Mirrors `random_pad`'s `getrandom` usage.
///
/// Callers MUST re-roll and STORE the result after each fire, then compare
/// the next fire against the stored value — never re-derive/re-roll the
/// comparison threshold on every tick. A per-tick re-roll would resample the
/// remaining-time comparison on every poll before it is due, which biases
/// and compresses the effective interval instead of jittering it.
///
/// `base < 4` ⇒ `base` exactly (no `getrandom` call) since `base / 4 == 0`
/// leaves nothing to jitter; not reached by any of the three cadences this
/// is applied to (1_000 / 20_000 / 5_000 ms). No numeric `as` casts.
pub(crate) fn jitter_ms(base: u64) -> u64 {
    let spread = base / 4;
    if spread == 0 {
        return base;
    }
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG");
    let v = u64::from_le_bytes(b);
    let span = spread.saturating_mul(2).saturating_add(1);
    (base - spread) + (v % span)
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
        DataPlane::new(
            established,
            conn_tag,
            TunnelMode::L3Tun,
            peer_addr,
            false,
            1200,
        )
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
            None,
            false,
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
            None,
            false,
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
        let pm = PeerManager::new(
            [9u8; 32],
            [8u8; 32],
            &[peer_a],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );

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
            None,
            false,
        );

        let inner = vec![0x45u8; 40]; // IPv4, matches no by_addr entry
        assert_eq!(pm.route_tun_index(&inner), None);
    }

    #[test]
    fn route_tun_index_l2_single_peer_forwards_regardless_of_inner() {
        let peer_a = peer_cfg(1, "10.0.0.1:1000");
        let pm = PeerManager::new(
            [9u8; 32],
            [8u8; 32],
            &[peer_a],
            TunnelMode::L2Tap,
            None,
            None,
            false,
        );

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
            None,
            false,
        );

        // by_addr maps each peer's node_addr to its index.
        assert_eq!(pm.by_addr.get(&node_addr(&peer_a.public_key)), Some(&0));
        assert_eq!(pm.by_addr.get(&node_addr(&peer_b.public_key)), Some(&1));

        // Splice in a fake Established peer at index 1 with a known conn_tag
        // (the "test seam": direct access to private fields from the child
        // `tests` module).
        const FAKE_TAG: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        pm.peers[1].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(
                FAKE_TAG,
                peer_b.endpoint.unwrap(),
            )),
            0,
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
            None,
            false,
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
        let pm = PeerManager::new(
            [1u8; 32],
            local_pub,
            &[],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        assert_eq!(pm.local_addr(), node_addr(&local_pub));
    }

    // ── 3c.1 Task 2: parameterized symbol_size ──────────────────────────────

    /// `PeerManager::new` defaults `data_symbol_size` to `1200` — the pre-3c.1
    /// hardcode, byte-identical for raw/obf mode — and `set_data_symbol_size`
    /// overrides it (wired to `DataPlane::new` at every establish site; QUIC
    /// mode plumbing lands in 3c.1 Tasks 4/5).
    #[test]
    fn data_symbol_size_defaults_to_1200_and_is_settable() {
        let mut pm = PeerManager::new(
            [1u8; 32],
            [2u8; 32],
            &[],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        assert_eq!(pm.data_symbol_size, DEFAULT_DATA_SYMBOL_SIZE);
        assert_eq!(pm.data_symbol_size, 1200);
        pm.set_data_symbol_size(1350);
        assert_eq!(pm.data_symbol_size, 1350);
    }

    /// The `conn_tag` of a peer's Established session, or `None` if it is not
    /// (yet) Established. Used by the handshake state-machine tests below.
    fn established_tag(pm: &PeerManager, idx: usize) -> Option<u64> {
        match &pm.peers[idx].state {
            PeerState::Established(epochs) => Some(epochs.current().conn_tag()),
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

    // ── 9a Task 3: mid-session rekey scheduling ─────────────────────────────

    /// Build a `PeerManager` with a single already-`Established` peer (via
    /// `fake_established_dataplane`, spliced in like
    /// `routes_inner_dst_to_owning_peer_and_demuxes_by_tag` does), its
    /// `EpochSet.current_created_ms` pinned to `0`, and `rekey_interval_ms`
    /// overridden to `interval_ms` (bypassing the real
    /// `YIP_REKEY_INTERVAL_MS`/120s cadence so tests don't need a multi-minute
    /// wait). `local_pub`/peer `public_key` are chosen by the caller so the
    /// glare-winner tiebreak (`local_pub < peer.pubkey`) lands as intended.
    fn pm_with_established_peer(
        local_pub: [u8; 32],
        peer_pubkey: [u8; 32],
        interval_ms: u64,
    ) -> (PeerManager, u64, SocketAddr) {
        let ep: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let cfg = PeerConfig {
            public_key: peer_pubkey,
            endpoint: Some(ep),
        };
        let mut pm = PeerManager::new(
            [7u8; 32],
            local_pub,
            &[cfg],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm.rekey_interval_ms = interval_ms;
        const FAKE_TAG: u64 = 0x1234_5678_9abc_def0;
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(FAKE_TAG, ep)),
            0,
        )));
        pm.by_tag.insert(FAKE_TAG, 0);
        (pm, FAKE_TAG, ep)
    }

    /// `true` iff `out` (a `tick` return) carries a `[HandshakeInit]` datagram.
    fn has_handshake_init(out: Option<&[EgressDatagram]>) -> bool {
        out.into_iter()
            .flatten()
            .any(|d| d.bytes.first() == Some(&(PacketType::HandshakeInit as u8)))
    }

    /// `true` iff `out` carries a rekey `[HandshakeInit]` relay-wrapped in a
    /// `yip_rendezvous::Message::RelaySend` — i.e. what `relay_wrap` produces
    /// for a relay-reached peer. Decoding the rendezvous envelope (rather
    /// than checking the outer byte, as `has_handshake_init` does) matters
    /// here: `RelaySend`'s own wire tag is 5, but a coincidental Register
    /// refresh (tag 0, sent once per `tick_dispatch` when a `Rendezvous` is
    /// freshly configured) would otherwise be misread as a raw
    /// `[HandshakeInit]` (also discriminant 0) by `has_handshake_init`.
    fn has_relayed_handshake_init(out: Option<&[EgressDatagram]>) -> bool {
        out.into_iter().flatten().any(|d| {
            matches!(
                yip_rendezvous::decode(&d.bytes),
                Some(yip_rendezvous::Message::RelaySend { payload, .. })
                    if payload.first() == Some(&(PacketType::HandshakeInit as u8))
            )
        })
    }

    #[test]
    fn tick_initiates_rekey_for_established_winner_once() {
        // local_pub = [1;32] < peer pubkey = [2;32]: local is the
        // glare-winner (the smaller static key), exactly the comparison
        // `handle_handshake_init`/`relayed_handshake_init` use to decide who
        // adopts the initiator role on a cold-start glare.
        let (mut pm, tag, _ep) = pm_with_established_peer([1u8; 32], [2u8; 32], 100);

        // Past the interval (age 150 >= 100): tick emits a HandshakeInit and
        // schedules a rekey, WITHOUT touching the live `current` epoch.
        let out = pm.tick(150).map(<[EgressDatagram]>::to_vec);
        assert!(
            has_handshake_init(out.as_deref()),
            "winner past the interval must emit a rekey HandshakeInit"
        );
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag),
            "current epoch must be untouched by scheduling a rekey"
        );
        match &pm.peers[0].state {
            PeerState::Established(epochs) => assert!(
                epochs.rekey.is_some(),
                "EpochSet.rekey must be populated once a rekey is in flight"
            ),
            _ => panic!("peer must still be Established"),
        }

        // A second tick shortly after, before the rekey completes: one rekey
        // in flight already, so `needs_rekey` must suppress a second Init.
        let out2 = pm.tick(160).map(<[EgressDatagram]>::to_vec);
        assert!(
            !has_handshake_init(out2.as_deref()),
            "a rekey already in flight must not emit a second HandshakeInit"
        );
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag),
            "current epoch must remain untouched on the second tick too"
        );
    }

    /// A relay-reached `Established` peer (`relay == true`, mirroring how
    /// `relayed_handshake_init`/`relayed_handshake_resp` leave a peer) DOES
    /// have a mid-session rekey scheduled by `tick`/`drive_rekey_schedule`
    /// when it is the glare-winner and past `rekey_interval_ms` (#91 Task 3:
    /// rekey completion is now wired for the relay handshake handlers, so
    /// the gate that used to suppress relay scheduling is gone). The Init is
    /// relay-wrapped (`relay_wrap` → a `RelaySend` to the rendezvous server),
    /// not sent as a raw `[HandshakeInit]` to a direct endpoint. Contrast
    /// with `tick_initiates_rekey_for_established_winner_once`, whose
    /// otherwise-identical direct peer (`relay == false`) emits the Init
    /// un-wrapped.
    #[test]
    fn tick_schedules_rekey_for_relay_winner_via_relay_wrap() {
        let (mut pm, tag, _ep) = pm_with_established_peer([1u8; 32], [2u8; 32], 100);
        pm.peers[0].relay = true;
        // A relay-reached peer routes rekey Inits through `relay_wrap`, which
        // needs a configured `Rendezvous` to succeed. Wire up the same
        // `MockRdv` the rendezvous-wiring tests use.
        let sent = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        pm.rendezvous = Some(Box::new(MockRdv {
            server: mock_server(),
            sent,
        }));
        // Pre-mark registration done, and push its refresh interval out
        // past this test's horizon, so `tick_dispatch`'s periodic
        // registration refresh (a `Register` datagram, wire tag 0 — the same
        // numeric value as `PacketType::HandshakeInit`) never fires and
        // confounds the `has_handshake_init`/`has_relayed_handshake_init`
        // assertions below.
        pm.registered_once = true;
        pm.last_register_ms = 150;
        pm.reg_refresh_ms = u64::MAX;

        // Past the interval (age 150 >= 100): a relay peer now rekeys here,
        // just like a direct peer (see
        // `tick_initiates_rekey_for_established_winner_once`), but the Init
        // rides inside a relay-wrapped `RelaySend`, not a raw datagram.
        let out = pm.tick(150).map(<[EgressDatagram]>::to_vec);
        assert!(
            has_relayed_handshake_init(out.as_deref()),
            "a relay peer past the interval, as glare-winner, must emit a relay-wrapped rekey HandshakeInit"
        );
        assert!(
            !has_handshake_init(out.as_deref()),
            "the relay peer's rekey Init must never be sent as a raw (unwrapped) HandshakeInit"
        );
        match &pm.peers[0].state {
            PeerState::Established(epochs) => assert!(
                epochs.rekey.is_some(),
                "EpochSet.rekey must be populated once a relay rekey is in flight"
            ),
            _ => panic!("peer must still be Established"),
        }
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag),
            "current epoch must be untouched by scheduling a relay rekey"
        );
    }

    #[test]
    fn tick_rekey_loser_waits_for_2x_interval() {
        // local_pub = [3;32] > peer pubkey = [2;32]: local is the
        // glare-LOSER, so it only rekeys via the fallback at 2x the interval.
        let (mut pm, tag, _ep) = pm_with_established_peer([3u8; 32], [2u8; 32], 100);

        // Past 1x the interval only: the loser must NOT rekey yet.
        let out = pm.tick(150).map(<[EgressDatagram]>::to_vec);
        assert!(
            !has_handshake_init(out.as_deref()),
            "a glare-loser must not rekey before 2x the interval"
        );
        match &pm.peers[0].state {
            PeerState::Established(epochs) => {
                assert!(epochs.rekey.is_none(), "no rekey should be scheduled yet")
            }
            _ => panic!("peer must still be Established"),
        }

        // Past 2x the interval: the loser-fallback fires.
        let out2 = pm.tick(250).map(<[EgressDatagram]>::to_vec);
        assert!(
            has_handshake_init(out2.as_deref()),
            "a glare-loser must rekey once past 2x the interval"
        );
        assert_eq!(established_tag(&pm, 0), Some(tag));
    }

    #[test]
    fn tick_rekey_retransmits_same_init_after_retry_ms() {
        let (mut pm, tag, ep) = pm_with_established_peer([1u8; 32], [2u8; 32], 100);

        let out = pm.tick(100).map(<[EgressDatagram]>::to_vec).unwrap();
        let first_init = out
            .iter()
            .find(|d| d.bytes.first() == Some(&(PacketType::HandshakeInit as u8)))
            .expect("rekey Init on the triggering tick")
            .bytes
            .clone();

        // Before HANDSHAKE_RETRY_MS (obf off => exactly 1000ms) elapses: no
        // retransmit.
        let mid = pm.tick(100 + HANDSHAKE_RETRY_MS - 1).map(|s| s.to_vec());
        assert!(
            !has_handshake_init(mid.as_deref()),
            "must not retransmit before retry_ms elapses"
        );

        // At/after retry_ms: the SAME init_pkt is retransmitted (same
        // ephemeral, so a responder's cached reply — if any — stays valid).
        let out2 = pm
            .tick(100 + HANDSHAKE_RETRY_MS)
            .map(<[EgressDatagram]>::to_vec)
            .unwrap();
        let retransmit = out2
            .iter()
            .find(|d| d.bytes.first() == Some(&(PacketType::HandshakeInit as u8)) && d.dst == ep)
            .expect("retransmitted rekey Init");
        assert_eq!(
            retransmit.bytes, first_init,
            "retransmit must resend the exact same Init bytes"
        );
        assert_eq!(established_tag(&pm, 0), Some(tag));
    }

    #[test]
    fn tick_rekey_abandoned_after_handshake_total_ms_keeps_current() {
        let (mut pm, tag, _ep) = pm_with_established_peer([1u8; 32], [2u8; 32], 100);

        pm.tick(100);
        match &pm.peers[0].state {
            PeerState::Established(epochs) => assert!(epochs.rekey.is_some()),
            _ => panic!("peer must still be Established"),
        }

        // The whole HANDSHAKE_TOTAL_MS window elapses without completing:
        // the rekey is abandoned, but `current` (the live session) is a
        // no-op survivor — untouched.
        pm.tick(100 + HANDSHAKE_TOTAL_MS);
        match &pm.peers[0].state {
            PeerState::Established(epochs) => assert!(
                epochs.rekey.is_none(),
                "an abandoned rekey must clear EpochSet.rekey"
            ),
            _ => panic!("peer must still be Established"),
        }
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag),
            "abandoning a rekey must be a no-op on the live current epoch"
        );
    }

    // ── 9a Task 4: rekey handshake completion wiring ────────────────────────

    /// Build two real `PeerManager`s and drive them through a cold-start
    /// handshake (A initiates) so both land `Established` on the SAME
    /// session, with `rekey_interval_ms` set to `interval_ms` on both.
    /// Returns `(pm_a, pm_b, ep_a, ep_b, kp_a, kp_b)`.
    fn established_pm_pair(
        interval_ms: u64,
    ) -> (
        PeerManager,
        PeerManager,
        SocketAddr,
        SocketAddr,
        yip_crypto::Keypair,
        yip_crypto::Keypair,
    ) {
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
        let mut pm_a = PeerManager::new(
            kp_a.private,
            kp_a.public,
            &[cfg_b],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let mut pm_b = PeerManager::new(
            kp_b.private,
            kp_b.public,
            &[cfg_a],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm_a.rekey_interval_ms = interval_ms;
        pm_b.rekey_interval_ms = interval_ms;

        let init = pm_a.on_tun(&dummy_tun_pkt(), 0)[0].bytes.clone();
        let resp = resp_bytes(&pm_b.on_udp(ep_a, &init, 0));
        assert_eq!(resp.len(), 1, "cold-start init must produce one resp");
        pm_a.on_udp(ep_b, &resp[0], 0);
        assert!(established_tag(&pm_a, 0).is_some());
        assert_eq!(established_tag(&pm_a, 0), established_tag(&pm_b, 0));

        (pm_a, pm_b, ep_a, ep_b, kp_a, kp_b)
    }

    #[test]
    fn rekey_resp_promotes_initiator_and_keeps_previous_for_grace() {
        let (mut pm_a, mut pm_b, ep_a, ep_b, kp_a, kp_b) = established_pm_pair(100);
        let old_tag = established_tag(&pm_a, 0).unwrap();

        // Capture an OLD-epoch frame (B -> A) sealed on B's still-untouched
        // `current`, to prove after the switch that `previous` still opens
        // it (the grace window).
        let old_payload = vec![0xAAu8; 24];
        let old_frame = pm_b.on_tun(&old_payload, 50)[0].bytes.clone();
        assert_eq!(old_frame[0], PacketType::Data as u8);

        // Drive a rekey `Init` directly (bypassing `tick`'s glare-winner
        // scheduling, which depends on the random keypair ordering — Task 4
        // is only exercising the COMPLETION wiring, already covered
        // separately by Task 3's scheduling tests) by splicing a
        // `RekeyInFlight` into A's `EpochSet`, exactly as
        // `drive_rekey_schedule` would have.
        let (hs, init_pkt) =
            HandshakeState::start_initiator(&kp_a.private, &kp_b.public, &[]).unwrap();
        {
            let PeerState::Established(epochs) = &mut pm_a.peers[0].state else {
                panic!("pm_a must be Established");
            };
            epochs.rekey = Some(crate::epoch::RekeyInFlight {
                hs,
                init_pkt: init_pkt.clone(),
                started_ms: 100,
                last_sent_ms: 100,
                retry_ms: 1000,
                target: ep_b,
            });
        }

        // B (current old enough: age 100 >= interval/2 = 50) accepts the
        // rekey Init, installs `next`, and replies — `current` untouched.
        let resp = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt, 100));
        assert_eq!(resp.len(), 1, "a genuine rekey Init must produce a Resp");
        assert_eq!(
            established_tag(&pm_b, 0),
            Some(old_tag),
            "B's current must stay on the old epoch until confirmed"
        );
        match &pm_b.peers[0].state {
            PeerState::Established(epochs) => assert!(epochs.next.is_some()),
            _ => panic!("pm_b must still be Established"),
        }

        // A completes: read_response promotes `current` to the NEW epoch
        // immediately, moves the OLD epoch to `previous`, and clears
        // `epochs.rekey`.
        let out = pm_a.on_udp(ep_b, &resp[0], 100);
        let confirm_frames: Vec<Vec<u8>> = match &out {
            DispatchOut::Udp(e) => e.iter().map(|d| d.bytes.clone()).collect(),
            _ => panic!("expected Udp egress (the new-epoch confirm frame)"),
        };
        assert!(
            !confirm_frames.is_empty(),
            "A must emit at least one NEW-epoch frame so B can confirm the switch"
        );

        let new_tag = established_tag(&pm_a, 0).unwrap();
        assert_ne!(new_tag, old_tag, "current must become the NEW epoch");
        match &pm_a.peers[0].state {
            PeerState::Established(epochs) => {
                assert!(
                    epochs.rekey.is_none(),
                    "rekey must be cleared on completion"
                );
                assert!(epochs.previous.is_some(), "old epoch must move to previous");
                assert_eq!(
                    epochs.previous.as_ref().unwrap().conn_tag(),
                    old_tag,
                    "previous must hold the OLD epoch"
                );
            }
            _ => panic!("pm_a must still be Established"),
        }

        // OLD-epoch frame (captured before the switch) still opens via
        // `previous`.
        match pm_a.on_udp(ep_b, &old_frame, 101) {
            DispatchOut::Tun(buf) => assert_eq!(buf, old_payload.as_slice()),
            _ => panic!("expected the old-epoch frame to open via `previous`"),
        }

        // Feed A's confirm frame(s) to B: B's `EpochSet::inbound_open`
        // (Task 1) authenticates under `next`, promoting it there too.
        for f in &confirm_frames {
            pm_b.on_udp(ep_a, f, 101);
        }
        assert_eq!(
            established_tag(&pm_b, 0),
            Some(new_tag),
            "B must have confirmed the switch to the SAME new epoch"
        );

        // NEW-epoch frame (B -> A, now both on `current`) opens via
        // `current`.
        let new_payload = vec![0xBBu8; 24];
        let new_frame = pm_b.on_tun(&new_payload, 101)[0].bytes.clone();
        match pm_a.on_udp(ep_b, &new_frame, 102) {
            DispatchOut::Tun(buf) => assert_eq!(buf, new_payload.as_slice()),
            _ => panic!("expected the new-epoch frame to open via `current`"),
        }
    }

    /// Regression for the #91 Task 1 review Important finding: the
    /// prime-emit in `rekey_resp_core` (draining `pending_tun` through the
    /// NEW epoch's `dp.on_tun_packet(..)`) must preserve each datagram's real
    /// per-FEC-object `fate` (`sym.object_id`, distinct per queued
    /// `pending_tun` packet) on the Direct path — NOT hardcode `fate: 0` as
    /// `push_rekey_egress` does for handshake emits (correct there: a
    /// Resp/cached-resp has no FEC object). Dropping `fate` to a shared 0
    /// silently defeats GSO coalescing (`yip_io::gso::partition_fate_safe`
    /// treats equal `fate` as non-coalescable) for every 2nd+ primed
    /// datagram — a real GSO-perf divergence from the pre-refactor
    /// `.cloned()` of the full `EgressDatagram`s, even though it is never an
    /// FEC-safety violation.
    #[test]
    fn rekey_resp_prime_emit_preserves_distinct_fec_fate() {
        let (mut pm_a, mut pm_b, ep_a, ep_b, kp_a, kp_b) = established_pm_pair(100);

        // Queue 2 distinct TUN packets directly into `pending_tun` — the
        // field the prime-emit drains — so `rekey_resp_core` primes the new
        // epoch with 2 separate `dp.on_tun_packet(..)` calls, each of which
        // allocates a fresh FEC object id (see
        // `yip_transport::fec::Encoder::encode`, `next_object_id`). A real
        // in-flight-rekey run only ever gets pending_tun populated while
        // `Handshaking`/`Idle`, not `Established` — direct field access is
        // the pragmatic way to drive this Established-peer scenario in a
        // unit test (an Established peer's own `on_tun` sends straight
        // through `current`, never touching `pending_tun`).
        pm_a.peers[0].pending_tun.push(vec![0x11u8; 40]);
        pm_a.peers[0].pending_tun.push(vec![0x22u8; 40]);

        // Splice a `RekeyInFlight` into A's `EpochSet`, exactly as the
        // sibling `rekey_resp_promotes_initiator_and_keeps_previous_for_grace`
        // test does, to drive rekey completion without depending on
        // `tick`'s glare-winner scheduling.
        let (hs, init_pkt) =
            HandshakeState::start_initiator(&kp_a.private, &kp_b.public, &[]).unwrap();
        {
            let PeerState::Established(epochs) = &mut pm_a.peers[0].state else {
                panic!("pm_a must be Established");
            };
            epochs.rekey = Some(crate::epoch::RekeyInFlight {
                hs,
                init_pkt: init_pkt.clone(),
                started_ms: 100,
                last_sent_ms: 100,
                retry_ms: 1000,
                target: ep_b,
            });
        }

        let resp = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt, 100));
        assert_eq!(resp.len(), 1, "a genuine rekey Init must produce a Resp");

        // Complete the rekey on A: this drives `rekey_resp_core`'s
        // prime-emit over the 2 queued `pending_tun` packets.
        let out = pm_a.on_udp(ep_b, &resp[0], 100);
        let primed: Vec<EgressDatagram> = match out {
            DispatchOut::Udp(e) => e.to_vec(),
            _ => panic!("expected Udp egress (the primed new-epoch frames)"),
        };
        assert!(
            primed.len() >= 2,
            "2 distinct pending_tun packets must prime at least 2 egress datagrams, got {}",
            primed.len()
        );

        let fates: std::collections::HashSet<u16> = primed.iter().map(|d| d.fate).collect();
        assert!(
            fates.len() >= 2,
            "primed datagrams from 2 distinct pending_tun packets must carry DISTINCT FEC \
             fates (one per FEC object), not all collapsed to a shared value \
             (fate: 0) — got fates {:?} across {} datagrams",
            primed.iter().map(|d| d.fate).collect::<Vec<_>>(),
            primed.len()
        );
    }

    /// `pm`'s Established peer 0's `next` epoch's `conn_tag`, panicking if
    /// there is no `next` installed. Test helper for the retransmit-dedup
    /// regressions below.
    fn next_conn_tag(pm: &PeerManager) -> u64 {
        match &pm.peers[0].state {
            PeerState::Established(epochs) => epochs
                .next
                .as_ref()
                .expect("next must be installed")
                .dp
                .conn_tag(),
            _ => panic!("peer must be Established"),
        }
    }

    #[test]
    fn retransmitted_rekey_init_is_idempotent_new_ephemeral_builds_new_next() {
        // Critical-bug regression (9a final review): the responder must
        // treat a retransmit of the SAME rekey `Init` (identical bytes,
        // hence identical Noise ephemeral) as a no-op — resend the cached
        // Resp, do NOT mint a second `next` session. A genuinely NEW Init
        // (fresh ephemeral) must still build a new `next`, replacing the
        // old one.
        let (_pm_a, mut pm_b, ep_a, _ep_b, kp_a, kp_b) = established_pm_pair(100);

        let (_hs1, init_pkt_1) =
            HandshakeState::start_initiator(&kp_a.private, &kp_b.public, &[]).unwrap();

        // First delivery: B installs `next`, replies.
        let resp1 = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt_1, 100));
        assert_eq!(resp1.len(), 1, "a genuine rekey Init must produce a Resp");
        let next_tag_1 = next_conn_tag(&pm_b);

        // RETRANSMIT: the exact same Init bytes again, later. Must resend
        // the SAME cached Resp and must NOT rebuild `next`.
        let resp2 = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt_1, 150));
        assert_eq!(
            resp2, resp1,
            "a retransmitted rekey Init must resend the cached Resp verbatim"
        );
        assert_eq!(
            next_conn_tag(&pm_b),
            next_tag_1,
            "a retransmitted rekey Init must NOT mint a second `next` session"
        );

        // A second retransmit, again: still idempotent.
        let resp3 = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt_1, 200));
        assert_eq!(resp3, resp1);
        assert_eq!(next_conn_tag(&pm_b), next_tag_1);

        // A GENUINELY NEW Init (fresh ephemeral) — e.g. the initiator gave
        // up on round 1 and started a new round — DOES build a new `next`,
        // replacing the old one.
        let (_hs2, init_pkt_2) =
            HandshakeState::start_initiator(&kp_a.private, &kp_b.public, &[]).unwrap();
        assert_ne!(
            init_pkt_1, init_pkt_2,
            "sanity: the two Inits must actually differ"
        );
        let resp4 = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt_2, 250));
        assert_eq!(resp4.len(), 1);
        assert_ne!(
            resp4, resp1,
            "a genuinely new rekey round must produce a NEW Resp"
        );
        assert_ne!(
            next_conn_tag(&pm_b),
            next_tag_1,
            "a genuinely new rekey round must replace `next`"
        );
    }

    #[test]
    fn rekey_init_retransmit_before_resp_converges_on_one_session() {
        // Critical-bug end-to-end regression (9a final review): under RTT >
        // retry_ms, the initiator retransmits its rekey Init before it has
        // seen the responder's first Resp. Pre-fix, the responder minted a
        // FRESH session on every Init it saw — including retransmits — so
        // the initiator (which locks onto the FIRST Resp it reads) and the
        // responder (now holding a DIFFERENT `next`) diverged onto two
        // different epochs and the tunnel black-holed. Post-fix, both sides
        // converge on ONE session regardless.
        let (mut pm_a, mut pm_b, ep_a, ep_b, kp_a, kp_b) = established_pm_pair(100);

        // Splice a `RekeyInFlight` into A directly (as
        // `rekey_resp_promotes_initiator_and_keeps_previous_for_grace`
        // does), so the SAME `init_pkt` bytes can be "retransmitted" to B
        // by simply calling `on_udp` twice.
        let (hs, init_pkt) =
            HandshakeState::start_initiator(&kp_a.private, &kp_b.public, &[]).unwrap();
        {
            let PeerState::Established(epochs) = &mut pm_a.peers[0].state else {
                panic!("pm_a must be Established");
            };
            epochs.rekey = Some(crate::epoch::RekeyInFlight {
                hs,
                init_pkt: init_pkt.clone(),
                started_ms: 100,
                last_sent_ms: 100,
                retry_ms: 1000,
                target: ep_b,
            });
        }

        // B receives Init #1 (t=100): installs `next`, replies Resp1.
        let resp1 = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt, 100));
        assert_eq!(resp1.len(), 1);
        let next_tag_after_init1 = next_conn_tag(&pm_b);

        // High RTT: A retransmits the IDENTICAL Init before it has seen
        // Resp1. B must reply with the SAME cached Resp and must NOT
        // rebuild `next`.
        let resp2 = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt, 101));
        assert_eq!(
            resp2, resp1,
            "a retransmitted rekey Init must be answered with the cached Resp verbatim"
        );
        assert_eq!(
            next_conn_tag(&pm_b),
            next_tag_after_init1,
            "a retransmitted rekey Init must NOT mint a second `next` session"
        );

        // Resp1 (produced by the FIRST Init) finally reaches A. A promotes
        // to the epoch B actually still holds as `next` (unchanged across
        // the retransmit) — the two sides converge on ONE session.
        let out = pm_a.on_udp(ep_b, &resp1[0], 102);
        let confirm_frames: Vec<Vec<u8>> = match &out {
            DispatchOut::Udp(e) => e.iter().map(|d| d.bytes.clone()).collect(),
            _ => panic!("expected Udp egress (the new-epoch confirm frame)"),
        };
        let a_new_tag = established_tag(&pm_a, 0).unwrap();
        assert_eq!(
            a_new_tag, next_tag_after_init1,
            "A must promote to the SAME epoch B is holding as `next`"
        );

        // A's confirm frame lets B's own `inbound_open` promote too.
        for f in &confirm_frames {
            pm_b.on_udp(ep_a, f, 103);
        }
        assert_eq!(
            established_tag(&pm_b, 0),
            Some(a_new_tag),
            "both sides must converge on the SAME session despite the Init retransmit"
        );
    }

    #[test]
    fn rekey_init_on_established_installs_next_without_switching_send() {
        let (mut pm_a, mut pm_b, ep_a, ep_b, kp_a, kp_b) = established_pm_pair(100);
        let old_tag_a = established_tag(&pm_a, 0).unwrap();
        let old_tag_b = established_tag(&pm_b, 0).unwrap();

        // Too-fresh: A's `current` was just established at t=0, well under
        // interval/2 = 50. B's rekey Init must be IGNORED outright — no
        // `next` installed, no Resp. (A was the cold-start INITIATOR, so it
        // holds no `cached_resp` — unlike B, testing this on A isolates the
        // pure `accept_rekey_init`-false-ignore path from the separate
        // cached-resp-retransmit fallback, which
        // `duplicate_init_after_established_does_not_tear_down_session`
        // already covers.)
        let (_hs_early, init_pkt_early) =
            HandshakeState::start_initiator(&kp_b.private, &kp_a.public, &[]).unwrap();
        match pm_a.on_udp(ep_b, &init_pkt_early, 10) {
            DispatchOut::None => {}
            _ => panic!("too-fresh rekey Init must be ignored: no Resp"),
        }
        match &pm_a.peers[0].state {
            PeerState::Established(epochs) => assert!(
                epochs.next.is_none(),
                "too-fresh current must never install `next`"
            ),
            _ => panic!("pm_a must still be Established"),
        }
        assert_eq!(established_tag(&pm_a, 0), Some(old_tag_a));

        // Old enough (t=100 >= 50): a genuine rekey Init installs `next`,
        // replies with a Resp, and leaves `current` untouched (B keeps
        // sending on the OLD epoch).
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&kp_a.private, &kp_b.public, &[]).unwrap();
        let resp = resp_bytes(&pm_b.on_udp(ep_a, &init_pkt, 100));
        assert_eq!(resp.len(), 1, "an admitted rekey Init must produce a Resp");
        match &pm_b.peers[0].state {
            PeerState::Established(epochs) => {
                assert!(epochs.next.is_some(), "next must be installed");
            }
            _ => panic!("pm_b must still be Established"),
        }
        assert_eq!(
            established_tag(&pm_b, 0),
            Some(old_tag_b),
            "current must be UNCHANGED — B still sends on the old epoch"
        );

        // B still sends on the OLD epoch (current untouched): a frame it
        // emits now still carries the OLD tag.
        let still_old = pm_b.on_tun(&dummy_tun_pkt(), 100);
        assert_eq!(still_old[0].bytes[0], PacketType::Data as u8);
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
        let mut pm_a = PeerManager::new(
            kp_a.private,
            kp_a.public,
            &[cfg_b],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let mut pm_b = PeerManager::new(
            kp_b.private,
            kp_b.public,
            &[cfg_a],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );

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
        let mut pm_r = PeerManager::new(
            kp_r.private,
            kp_r.public,
            &[cfg_i],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );

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
    fn cold_start_init_retransmit_past_interval_half_resends_original_not_rekey() {
        // Important-2 regression (9a final review): `HANDSHAKE_TOTAL_MS`
        // (90s) exceeds `REKEY_INTERVAL_MS`/2, so a retransmit of the
        // ORIGINAL cold-start Init can legitimately still be in flight once
        // `EpochSet::accept_rekey_init` alone would treat any Init as a
        // plausible rekey. It must still be recognized (by ephemeral match
        // against `cached_resp_init_eph`) as the SAME cold-start round and
        // answered with the original cached reply — never misclassified as
        // a rekey round, which would install a spurious `next`.
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.20:2000".parse().unwrap();
        let cfg_i = PeerConfig {
            public_key: kp_i.public,
            endpoint: Some(ep_i),
        };
        let mut pm_r = PeerManager::new(
            kp_r.private,
            kp_r.public,
            &[cfg_i],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm_r.rekey_interval_ms = 100; // interval/2 = 50, well under the retransmit's t=70

        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&kp_i.private, &kp_r.public, &[]).unwrap();

        let resp1 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt, 0));
        assert_eq!(resp1.len(), 1, "first init must produce one HandshakeResp");
        let tag1 = established_tag(&pm_r, 0).expect("responder must be Established");

        // Retransmit of the SAME cold-start Init, arriving at t=70 — past
        // interval/2 (50), so `accept_rekey_init` alone would consider it a
        // plausible rekey. It is NOT: it must resend the cached original
        // reply and must NOT install a `next`.
        let resp2 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt, 70));
        assert_eq!(
            resp2, resp1,
            "a cold-start retransmit past interval/2 must still resend the ORIGINAL cached resp"
        );
        assert_eq!(
            established_tag(&pm_r, 0),
            Some(tag1),
            "current must be unchanged"
        );
        match &pm_r.peers[0].state {
            PeerState::Established(epochs) => assert!(
                epochs.next.is_none(),
                "a cold-start retransmit must NOT install a rekey `next`"
            ),
            _ => panic!("responder must stay Established"),
        }
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
            None,
            false,
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
            None,
            false,
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
        fn register(&mut self, node: NodeId) -> Option<EgressDatagram> {
            // counter bumped per-registration in 3c.4; 0 is accepted as first-seen
            Some(self.to_server(yip_rendezvous::Message::Register { node, counter: 0 }))
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
            None,
            false,
        );
        (pm, sent)
    }

    /// Build a `PeerManager` (with a `MockRdv` rendezvous, so relay egress
    /// works) whose sole peer has a configured direct `endpoint` and has
    /// already been driven into `Handshaking` on that endpoint (a single TUN
    /// packet, mirroring `on_tun`'s Idle branch — see
    /// `punch_handshake_escalates_to_relay_at_punch_window_not_90s` for the
    /// punch-stage sibling of this setup). Used by the `retarget_handshake`
    /// tests below (#36 Task 1), which need a `Handshaking` peer holding a
    /// real in-flight `init_pkt`/ephemeral to re-target.
    fn pm_handshaking_direct_peer(
        peer_pubkey: [u8; 32],
        endpoint: &str,
        started_ms: u64,
    ) -> (PeerManager, usize) {
        let local = generate_keypair();
        let ep: SocketAddr = endpoint.parse().expect("valid test endpoint");
        let peer = PeerConfig {
            public_key: peer_pubkey,
            endpoint: Some(ep),
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);
        pm.on_tun(&dummy_tun_pkt(), started_ms);
        assert!(
            matches!(pm.peers[0].state, PeerState::Handshaking(_)),
            "setup must drive the peer into Handshaking on the direct endpoint"
        );
        (pm, 0)
    }

    /// #36 Task 1: `retarget_handshake` must preserve the in-flight Noise
    /// ephemeral (resend the SAME `init_pkt`) across a path re-target rather
    /// than minting a fresh one — see the module-level #36 discussion at the
    /// `PathAction::Relay`/`PathAction::Probe` escalation arms in
    /// `tick_dispatch`.
    #[test]
    fn retarget_handshake_preserves_ephemeral_and_flips_relay() {
        // A peer mid-handshake toward a direct candidate.
        let (mut pm, idx) = pm_handshaking_direct_peer([7u8; 32], "10.0.0.9:9000", 100);
        let (orig_init, orig_started, orig_target) = match &pm.peers[idx].state {
            PeerState::Handshaking(h) => (h.init_pkt.clone(), h.started_ms, h.target),
            _ => panic!("peer must be Handshaking"),
        };
        let server = pm.server_addr();

        // Re-target to the relay (Punch->Relay escalation).
        let out = pm
            .retarget_handshake(idx, server, true, 5_000)
            .expect("emits an Init");

        // Ephemeral preserved: the resent Init is byte-identical, still Handshaking,
        // started_ms unchanged (the 90s give-up clock keeps running).
        match &pm.peers[idx].state {
            PeerState::Handshaking(h) => {
                assert_eq!(
                    h.init_pkt, orig_init,
                    "init_pkt (ephemeral) must be preserved"
                );
                assert_eq!(
                    h.started_ms, orig_started,
                    "started_ms must not reset on re-target"
                );
                assert_eq!(h.target, server, "target must update to the new path");
                assert_ne!(h.target, orig_target);
            }
            _ => panic!("peer must stay Handshaking"),
        }
        assert!(
            pm.peers[idx].relay,
            "relay flag must be set for a relay re-target"
        );
        assert!(
            pm.peers[idx].endpoint.is_none(),
            "relay re-target clears endpoint (anti-mismatch)"
        );
        // The emitted datagram is the relay-wrapped Init (a RelaySend), carrying the SAME ephemeral.
        assert!(
            has_relayed_handshake_init(Some(&out)),
            "must emit a relay-wrapped Init"
        );
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
            None,
            false,
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
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, endpoint)),
            0,
        )));
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
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, endpoint)),
            0,
        )));
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

    /// `true` iff `out` carries a `[HandshakeResp]` relay-wrapped in a
    /// `yip_rendezvous::Message::RelaySend` — the relay-path counterpart of
    /// `has_relayed_handshake_init`, used to assert a responder replayed its
    /// cached resp over the relay (#36 Task 1, Step 6).
    fn has_relayed_handshake_resp(out: &DispatchOut<'_>) -> bool {
        let egress: &[EgressDatagram] = match out {
            DispatchOut::Udp(e) | DispatchOut::Both(_, e) => e,
            _ => &[],
        };
        egress.iter().any(|d| {
            matches!(
                yip_rendezvous::decode(&d.bytes),
                Some(yip_rendezvous::Message::RelaySend { payload, .. })
                    if payload.first() == Some(&(PacketType::HandshakeResp as u8))
            )
        })
    }

    /// Wrap `payload` as a `RelayDeliver` sourced from `pm`'s sole configured
    /// peer (its `node`) — the relay-deliver counterpart of `relay_deliver`
    /// for a test that already has a single-peer `PeerManager` in hand rather
    /// than a raw `Keypair`. Used to redeliver an Init as if freshly
    /// forwarded by the rendezvous server (#36 Task 1, Step 6).
    fn wrap_relay_deliver(pm: &PeerManager, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::RelayDeliver {
                src: pm.peers[0].node,
                payload: payload.to_vec(),
            },
            &mut buf,
        );
        buf
    }

    /// Build a responder `PeerManager` that has genuinely `Established` as
    /// responder for a fresh initiator A, via a REAL (relayed) cold-start
    /// Noise handshake — real `cached_resp`/`cached_resp_init_eph`, keyed to
    /// A's actual ephemeral, and `relay == true` (required by
    /// `relayed_handshake_init`'s `Established(_) if self.peers[idx].relay`
    /// gate, #91 final review, for a *subsequent* relayed Init on this peer
    /// to be admitted at all). This is exactly the state #36's fix depends on
    /// downstream: a responder holding a `cached_resp` for A's ephemeral that
    /// a re-targeted (but ephemeral-preserving) retry can complete against.
    ///
    /// `local_seed`/`peer_seed` are accepted for a readable, distinguishable
    /// call shape at each call site; X25519 keys must be real key-exchange
    /// material for the handshake to actually succeed (there is no
    /// seeded-keygen primitive in `yip_crypto`), so both keypairs are freshly
    /// generated with `generate_keypair()` and the seeds are not fed into the
    /// crypto.
    fn responder_established_for_initiator(
        _local_seed: [u8; 32],
        _peer_seed: [u8; 32],
        now_ms: u64,
    ) -> (PeerManager, Vec<u8>) {
        let kp_r = generate_keypair();
        let kp_a = generate_keypair();
        let cfg_a = PeerConfig {
            public_key: kp_a.public,
            endpoint: None,
        };
        let (mut pm_r, _sent) = pm_with_mock_rdv(&kp_r, &[cfg_a]);

        let (_hs, a_init_pkt) =
            HandshakeState::start_initiator(&kp_a.private, &kp_r.public, &[]).unwrap();
        let buf = relay_deliver(&kp_a, a_init_pkt.clone());
        let out = pm_r.on_udp(mock_server(), &buf, now_ms);
        assert!(
            has_relayed_handshake_resp(&out),
            "cold-start relayed init must produce one relay-wrapped resp"
        );
        assert!(
            established_tag(&pm_r, 0).is_some(),
            "responder must be Established"
        );
        assert!(pm_r.peers[0].relay, "responder must be relay-reached for A");

        (pm_r, a_init_pkt)
    }

    /// #36 Task 1, Step 6/7: the end-to-end #36 mechanism at the unit level —
    /// a responder that is `Established` (holding `cached_resp` for
    /// initiator A's ephemeral E1) replays that resp when the SAME Init (E1)
    /// arrives again over the relay, rather than churning a new session or
    /// dropping it. This is the mechanism `retarget_handshake`'s
    /// ephemeral-preserving re-target relies on: no responder-side change was
    /// needed for #36 — `rekey_init_core` case 1 (cached_resp_init_eph match)
    /// already replays.
    #[test]
    fn established_responder_completes_retargeted_initiator_via_cached_resp() {
        // Responder that adopted initiator A and is Established, caching resp for A's ephemeral.
        let (mut pm_r, a_init_pkt) = responder_established_for_initiator([3u8; 32], [4u8; 32], 100);
        let tag_before = established_tag(&pm_r, 0);

        // A re-targeted to relay and resent the SAME init (E1). It arrives relay-wrapped.
        let relayed = wrap_relay_deliver(&pm_r, &a_init_pkt); // src = A's node
        let out = pm_r.on_udp(mock_server(), &relayed, 5_000);

        // Responder replays its cached resp (a RelaySend) — completing A — and does
        // NOT churn a new session: current tag unchanged.
        assert!(
            has_relayed_handshake_resp(&out),
            "must replay cached resp over the relay"
        );
        assert_eq!(
            established_tag(&pm_r, 0),
            tag_before,
            "current session must be untouched"
        );
    }

    // ── #91 Task 2: relay-path rekey completion ─────────────────────────────

    /// Build a `PeerManager` (with a `MockRdv` rendezvous, so `relay_wrap`
    /// succeeds) whose sole peer is already `Established` AND relay-reached
    /// (`relay = true`, `path_kind = Relayed`) — mirroring the state
    /// `relayed_handshake_init`'s own Idle branch commits at cold start,
    /// without needing a second full `PeerManager` on the "peer" side. The
    /// `current` epoch is a `fake_established_dataplane` (crypto-agnostic
    /// stand-in, exactly like `anti_hijack_established_peer_ignores_*`'s
    /// splice): rekey completion never reads `current`'s own key material,
    /// only its `conn_tag`/existence, so the fake is sufficient here — the
    /// GENUINE crypto in each test below is the fresh rekey Init/Resp itself.
    fn established_relay_pm(
        rekey_interval_ms: u64,
    ) -> (
        PeerManager,
        yip_crypto::Keypair,
        yip_crypto::Keypair,
        u64, // old (current) conn_tag
    ) {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);
        pm.rekey_interval_ms = rekey_interval_ms;

        const OLD_TAG: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(OLD_TAG, mock_server())),
            0,
        )));
        pm.by_tag.insert(OLD_TAG, 0);
        pm.peers[0].relay = true;
        pm.peers[0].path_kind = Some(PathKind::Relayed);

        (pm, local, peer_kp, OLD_TAG)
    }

    /// Copy out every `[HandshakeResp]` payload carried inside a
    /// relay-wrapped (`RelaySend`) egress datagram — the relay-path
    /// counterpart of `resp_bytes`, which expects the Resp unwrapped (as on
    /// the direct path).
    fn relayed_resp_bytes(out: &DispatchOut<'_>) -> Vec<Vec<u8>> {
        let egress: &[EgressDatagram] = match out {
            DispatchOut::Udp(e) | DispatchOut::Both(_, e) => e,
            _ => &[],
        };
        egress
            .iter()
            .filter_map(|d| match yip_rendezvous::decode(&d.bytes) {
                Some(yip_rendezvous::Message::RelaySend { payload, .. })
                    if payload.first() == Some(&(PacketType::HandshakeResp as u8)) =>
                {
                    Some(payload)
                }
                _ => None,
            })
            .collect()
    }

    /// Wrap `payload` (raw handshake bytes) as a `RelayDeliver` datagram from
    /// `src_kp`, as the server would forward it — the input side of the
    /// relay tests below, mirroring `anti_hijack_established_peer_ignores_relayed_handshake_init`.
    fn relay_deliver(src_kp: &yip_crypto::Keypair, payload: Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::RelayDeliver {
                src: node_id(&src_kp.public),
                payload,
            },
            &mut buf,
        );
        buf
    }

    #[test]
    fn relay_rekey_init_retransmit_is_idempotent_new_ephemeral_builds_new_next() {
        // Relay-path counterpart of
        // `retransmitted_rekey_init_is_idempotent_new_ephemeral_builds_new_next`:
        // a relay-Established responder receiving a rekey `Init` through the
        // relay must dedupe identically — same ephemeral resends the SAME
        // cached (relay-wrapped) Resp and does NOT mint a second `next`; a
        // genuinely new ephemeral DOES build a new `next`.
        let (mut pm, local, peer_kp, _old_tag) = established_relay_pm(100);

        let (_hs1, init_pkt_1) =
            HandshakeState::start_initiator(&peer_kp.private, &local.public, &[]).unwrap();
        let buf1 = relay_deliver(&peer_kp, init_pkt_1.clone());

        // First delivery at t=100 (current age 100 >= interval/2 = 50):
        // installs `next`, replies via the relay.
        let out1 = pm.on_udp(mock_server(), &buf1, 100);
        let resp1 = relayed_resp_bytes(&out1);
        assert_eq!(
            resp1.len(),
            1,
            "a genuine relay rekey Init must produce a relay-wrapped Resp"
        );
        let next_tag_1 = next_conn_tag(&pm);

        // RETRANSMIT: identical Init bytes -> identical ephemeral. Must
        // resend the SAME cached Resp and must NOT rebuild `next`.
        let out2 = pm.on_udp(mock_server(), &buf1, 150);
        let resp2 = relayed_resp_bytes(&out2);
        assert_eq!(
            resp2, resp1,
            "a retransmitted relay rekey Init must resend the cached Resp verbatim"
        );
        assert_eq!(
            next_conn_tag(&pm),
            next_tag_1,
            "a retransmitted relay rekey Init must NOT mint a second `next` session"
        );

        // A second retransmit, again: still idempotent.
        let out3 = pm.on_udp(mock_server(), &buf1, 200);
        assert_eq!(relayed_resp_bytes(&out3), resp1);
        assert_eq!(next_conn_tag(&pm), next_tag_1);

        // A GENUINELY NEW Init (fresh ephemeral) DOES build a new `next`,
        // replacing the old one.
        let (_hs2, init_pkt_2) =
            HandshakeState::start_initiator(&peer_kp.private, &local.public, &[]).unwrap();
        assert_ne!(
            init_pkt_1, init_pkt_2,
            "sanity: the two Inits must actually differ"
        );
        let buf2 = relay_deliver(&peer_kp, init_pkt_2);
        let out4 = pm.on_udp(mock_server(), &buf2, 250);
        let resp4 = relayed_resp_bytes(&out4);
        assert_eq!(resp4.len(), 1);
        assert_ne!(
            resp4, resp1,
            "a genuinely new relay rekey round must produce a NEW Resp"
        );
        assert_ne!(
            next_conn_tag(&pm),
            next_tag_1,
            "a genuinely new relay rekey round must replace `next`"
        );
    }

    #[test]
    fn relay_rekey_resp_completes_and_promotes() {
        // Relay-path counterpart of
        // `rekey_resp_promotes_initiator_and_keeps_previous_for_grace`: a
        // relay-Established peer with a rekey in flight, on receiving the
        // matching relayed `[HandshakeResp]`, must promote exactly like the
        // direct path — `current` becomes the new epoch, the old epoch
        // moves to `previous`, `rekey` clears, and `by_tag` is updated.
        let (mut pm, local, peer_kp, old_tag) = established_relay_pm(100);

        // Splice a `RekeyInFlight` in as the INITIATOR side (pm's own rekey
        // attempt), exactly as the direct-path sibling test does.
        let (hs, init_pkt) =
            HandshakeState::start_initiator(&local.private, &peer_kp.public, &[]).unwrap();
        {
            let PeerState::Established(epochs) = &mut pm.peers[0].state else {
                panic!("pm must be Established");
            };
            epochs.rekey = Some(crate::epoch::RekeyInFlight {
                hs,
                init_pkt: init_pkt.clone(),
                started_ms: 100,
                last_sent_ms: 100,
                retry_ms: 1000,
                target: mock_server(), // unused: the relay path overrides addressing
            });
        }

        // The peer's real responder completes the handshake and builds the
        // matching Resp — mirrors what a genuine peer PeerManager would send.
        let (_established, resp_pkt, remote_static, _payload) =
            HandshakeState::start_responder(&peer_kp.private, &init_pkt, &[]).unwrap();
        assert_eq!(
            remote_static, local.public,
            "sanity: Resp matches pm's own Init"
        );

        let buf = relay_deliver(&peer_kp, resp_pkt);
        let out = pm.on_udp(mock_server(), &buf, 100);

        // The prime-emit (empty pending_tun -> one bare new-epoch frame) must
        // go out relay-wrapped, not bare.
        let egress: &[EgressDatagram] = match &out {
            DispatchOut::Udp(e) => e,
            _ => panic!("expected relay-wrapped prime-emit egress"),
        };
        assert!(!egress.is_empty(), "the prime-emit must produce egress");
        assert!(
            egress.iter().all(|d| matches!(
                yip_rendezvous::decode(&d.bytes),
                Some(yip_rendezvous::Message::RelaySend { .. })
            )),
            "the prime-emit must be relay-wrapped (RelaySend), not sent bare"
        );

        let new_tag = established_tag(&pm, 0).unwrap();
        assert_ne!(new_tag, old_tag, "current must become the NEW epoch");
        match &pm.peers[0].state {
            PeerState::Established(epochs) => {
                assert!(
                    epochs.rekey.is_none(),
                    "rekey must be cleared on completion"
                );
                assert!(epochs.previous.is_some(), "old epoch must move to previous");
                assert_eq!(
                    epochs.previous.as_ref().unwrap().conn_tag(),
                    old_tag,
                    "previous must hold the OLD epoch"
                );
            }
            _ => panic!("pm must still be Established"),
        }
        assert_eq!(
            pm.by_tag.get(&new_tag),
            Some(&0),
            "by_tag updated for the new conn_tag"
        );
        assert_eq!(
            pm.by_tag.get(&old_tag),
            None,
            "by_tag no longer maps the retired old conn_tag"
        );
    }

    #[test]
    fn direct_peer_ignores_relayed_rekey_resp() {
        // Regression (final review, Important): a DIRECT (`relay = false`)
        // Established peer with a rekey in flight must NOT complete that
        // rekey via a RELAYED `[HandshakeResp]`. Completing it would stamp
        // the new epoch's `DataPlane.peer_addr` to `server_addr()` (via
        // `rekey_resp_core(.., via_relay = true)`) while `peers[idx].relay`
        // stays `false`, so `on_tun`'s relay-wrap decision (keyed off
        // `peers[idx].relay`) would then send BARE datagrams to the
        // rendezvous server — a black hole. `current` must stay untouched
        // and the completion must not happen at all: fail-closed drop.
        let (mut pm, local, peer_kp, old_tag) = established_relay_pm(100);
        // Override to a DIRECT peer — the only difference from
        // `relay_rekey_resp_completes_and_promotes`'s setup.
        pm.peers[0].relay = false;
        pm.peers[0].path_kind = Some(PathKind::Direct);

        // Splice a `RekeyInFlight` in as the INITIATOR side (pm's own rekey
        // attempt), exactly as the relay-path sibling test does.
        let (hs, init_pkt) =
            HandshakeState::start_initiator(&local.private, &peer_kp.public, &[]).unwrap();
        {
            let PeerState::Established(epochs) = &mut pm.peers[0].state else {
                panic!("pm must be Established");
            };
            epochs.rekey = Some(crate::epoch::RekeyInFlight {
                hs,
                init_pkt: init_pkt.clone(),
                started_ms: 100,
                last_sent_ms: 100,
                retry_ms: 1000,
                target: mock_server(), // unused: this test never reaches addressing
            });
        }

        // The peer's real responder completes the handshake and builds the
        // matching Resp — mirrors what a genuine peer PeerManager would
        // send. Delivered here via a RELAY (`RelayDeliver`/`on_udp(server,
        // ..)`), reachable either via a source-spoofed server address or a
        // malicious/compromised blind relay (`on_relayed` only requires
        // `src == server`).
        let (_established, resp_pkt, remote_static, _payload) =
            HandshakeState::start_responder(&peer_kp.private, &init_pkt, &[]).unwrap();
        assert_eq!(
            remote_static, local.public,
            "sanity: Resp matches pm's own Init"
        );

        let buf = relay_deliver(&peer_kp, resp_pkt);
        {
            // Scoped so `out`'s borrow of `pm` ends before the state checks
            // below.
            let out = pm.on_udp(mock_server(), &buf, 100);

            // No emitted datagram may be a bare (un-wrapped) send to
            // `server_addr()` (which would black-hole against the
            // rendezvous server).
            let egress: &[EgressDatagram] = match &out {
                DispatchOut::Udp(e) | DispatchOut::Both(_, e) => e,
                _ => &[],
            };
            assert!(
                egress.iter().all(
                    |d| !(d.dst == mock_server() && yip_rendezvous::decode(&d.bytes).is_none())
                ),
                "no bare (un-wrapped) datagram may be sent to server_addr()"
            );
        }

        // The rekey must NOT complete: `current` stays on the OLD epoch,
        // and `epochs.rekey` stays populated (still awaiting a legitimately
        // DIRECT Resp).
        assert_eq!(
            established_tag(&pm, 0),
            Some(old_tag),
            "current must remain the OLD epoch — a relayed Resp must not \
             complete a direct peer's rekey"
        );
        match &pm.peers[0].state {
            PeerState::Established(epochs) => {
                assert!(
                    epochs.rekey.is_some(),
                    "rekey must stay in flight, awaiting a genuinely direct Resp"
                );
            }
            _ => panic!("pm must still be Established"),
        }
    }

    #[test]
    fn relay_rekey_emit_is_noop_when_relay_wrap_returns_none() {
        // Fail-closed regression: if `relay_wrap` cannot emit (no rendezvous
        // configured), a relay rekey Init at an Established peer must be a
        // clean no-op — no egress, and `current` is left completely intact.
        // (No rendezvous means `on_udp` could never route a `RelayDeliver`
        // here in production; the relay handler is called directly to
        // exercise the wiring's fail-closed behavior in isolation.)
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[peer],
            TunnelMode::L3Tun,
            None, // no rendezvous configured
            None,
            false,
        );
        pm.rekey_interval_ms = 100;

        const OLD_TAG: u64 = 0x1234_5678_9ABC_DEF0;
        let placeholder: SocketAddr = "203.0.113.1:51821".parse().unwrap();
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(OLD_TAG, placeholder)),
            0,
        )));
        pm.by_tag.insert(OLD_TAG, 0);
        pm.peers[0].relay = true;
        pm.peers[0].path_kind = Some(PathKind::Relayed);

        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&peer_kp.private, &local.public, &[]).unwrap();

        assert!(
            matches!(
                pm.relayed_handshake_init(0, &init_pkt, 100),
                DispatchOut::None
            ),
            "no rendezvous -> relay_wrap fails -> no egress"
        );

        assert_eq!(
            established_tag(&pm, 0),
            Some(OLD_TAG),
            "current must remain intact when the relay emit fails"
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

    // ── membership wiring (mock Membership via an in-test CA + certs) ──────
    //
    // A `Membership` built from an in-test Ed25519 CA and certs whose validity
    // window straddles the real wall clock (cert checks in `PeerManager` use
    // `now_secs()`, not the loop's `now_ms`), so `verify_cert` accepts them
    // when the daemon runs today.

    use ed25519_dalek::{Signer as _, SigningKey};
    use yip_membership::cert::cert_signing_body;
    use yip_membership::record::{record_signing_body, sign as record_sign};
    use yip_membership::{Record, RootSet};

    const TEST_NET: [u8; 16] = [7u8; 16];

    fn test_ca() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    /// A CA-signed cert covering `member_pubkey`, valid essentially forever so
    /// the real wall clock (`now_secs()`) always falls inside the window.
    fn mk_cert(ca: &SigningKey, member_pubkey: [u8; 32], member_sign_pub: [u8; 32]) -> Cert {
        let mut c = Cert {
            version: 1,
            member_pubkey,
            member_sign_pubkey: member_sign_pub,
            network_id: TEST_NET,
            not_before: 0,
            not_after: u64::MAX,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        c.ca_sig = ca.sign(&cert_signing_body(&c)).to_bytes();
        c
    }

    fn empty_roots() -> RootSet {
        RootSet {
            roots: vec![],
            version: 0,
            ca_sig: [0u8; 64],
        }
    }

    /// A `Membership` for a node whose own data-plane key is `own_pub`, trusting
    /// `ca`, on `TEST_NET`, with no roots.
    fn membership_for(ca: &SigningKey, own_pub: [u8; 32]) -> Membership {
        let ca_pub = ca.verifying_key().to_bytes();
        let own_sign = SigningKey::from_bytes(&[200u8; 32]);
        let own_cert = mk_cert(ca, own_pub, own_sign.verifying_key().to_bytes());
        Membership::new(
            vec![ca_pub],
            TEST_NET,
            own_cert,
            own_sign.to_bytes(),
            empty_roots(),
            vec!["10.0.0.1:51820".parse().unwrap()],
        )
    }

    /// A member-signed directory `Record` for `member_pub` at `endpoints`,
    /// signed by `sign_key` (whose public key is embedded in the cert), CA
    /// `ca`. When `ca` is untrusted by the verifier, the record is forged.
    fn mk_record(
        ca: &SigningKey,
        sign_seed: u8,
        member_pub: [u8; 32],
        endpoints: Vec<SocketAddr>,
        seq: u64,
    ) -> Record {
        let sign_key = SigningKey::from_bytes(&[sign_seed; 32]);
        let cert = mk_cert(ca, member_pub, sign_key.verifying_key().to_bytes());
        let mut r = Record {
            node_id: yip_membership::node_id(&member_pub),
            cert,
            endpoints,
            seq,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&r);
        r.sig = record_sign(&body, &sign_key.to_bytes());
        r
    }

    /// A minimal 40-byte IPv6 packet addressed to mesh address `dst`.
    fn ipv6_pkt_to(dst: Ipv6Addr) -> Vec<u8> {
        let mut inner = vec![0u8; 40];
        inner[0] = 0x60;
        inner[24..40].copy_from_slice(&dst.octets());
        inner
    }

    /// (a) `on_tun` to an unknown mesh address that `resolve`s admits the peer
    /// and emits a handshake `Init` toward its directory endpoint.
    #[test]
    fn on_tun_unknown_addr_resolves_admits_and_handshakes() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "198.51.100.50:6000".parse().unwrap();

        let mut membership = membership_for(&ca, local.public);
        let rec = mk_record(&ca, 201, peer.public, vec![peer_ep], 1);
        assert!(membership.ingest_record(rec, now_secs()));

        // No configured peers: the inner dst is unknown until resolved.
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[],
            TunnelMode::L3Tun,
            None,
            Some(membership),
            false,
        );
        assert!(pm.peers.is_empty());

        let pkt = ipv6_pkt_to(node_addr(&peer.public));
        let out = pm.on_tun(&pkt, 0).to_vec();

        // The peer was admitted at runtime …
        assert_eq!(pm.peers.len(), 1, "resolve+admit created one peer");
        assert_eq!(pm.peers[0].pubkey, peer.public);
        assert_eq!(pm.peers[0].endpoint, Some(peer_ep));
        // … and a handshake Init was emitted toward its endpoint.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst, peer_ep);
        assert_eq!(out[0].bytes[0], PacketType::HandshakeInit as u8);
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
    }

    /// (a2) Regression (2c/Task 7): with exactly one already-admitted peer
    /// (e.g. the seed root a mesh node bootstraps to), `on_tun` to a
    /// DIFFERENT, not-yet-known mesh address must NOT be misrouted to that
    /// lone peer by the 2a/2b "single configured peer" fallback in
    /// `route_tun_index` — it must fall through to the membership `resolve`
    /// path instead. Before the fix, `route_tun_index`'s
    /// `self.peers.len() == 1 => Some(0)` fallback fired unconditionally
    /// (membership-blind), so a mesh node holding just its root — exactly
    /// the state every node is in right after bootstrap, before it has
    /// resolved anyone else — would have every not-yet-discovered
    /// destination silently routed to the root instead of resolved via
    /// gossip, permanently breaking dynamic discovery whenever a node knew
    /// only one peer.
    #[test]
    fn on_tun_single_known_peer_still_resolves_a_different_dst() {
        let ca = test_ca();
        let local = generate_keypair();
        let root = generate_keypair();
        let root_ep: SocketAddr = "198.51.100.1:51820".parse().unwrap();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "198.51.100.50:6000".parse().unwrap();

        // The root's own cert isn't needed by this node's directory — only
        // its pubkey + endpoint (via the signed `RootSet`, which
        // `PeerManager::new` auto-admits).
        let roots = RootSet {
            roots: vec![(root.public, root_ep)],
            version: 1,
            ca_sig: [0u8; 64],
        };
        let own_sign = SigningKey::from_bytes(&[200u8; 32]);
        let own_cert = mk_cert(&ca, local.public, own_sign.verifying_key().to_bytes());
        let mut membership = Membership::new(
            vec![ca.verifying_key().to_bytes()],
            TEST_NET,
            own_cert,
            own_sign.to_bytes(),
            roots,
            vec!["10.0.0.1:51820".parse().unwrap()],
        );
        let rec = mk_record(&ca, 202, peer.public, vec![peer_ep], 1);
        assert!(membership.ingest_record(rec, now_secs()));

        // `PeerManager::new` auto-admits every root from the signed root set
        // (always-admit bootstrap seed), so `pm.peers` starts with exactly
        // one entry (the root) — the precondition this regression guards.
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[],
            TunnelMode::L3Tun,
            None,
            Some(membership),
            false,
        );
        assert_eq!(
            pm.peers.len(),
            1,
            "precondition: exactly one known peer (the root)"
        );
        assert_eq!(pm.peers[0].pubkey, root.public);

        // A TUN packet addressed to `peer` (a DIFFERENT node than the root)
        // must resolve+admit `peer`, not be routed to the root.
        let pkt = ipv6_pkt_to(node_addr(&peer.public));
        let out = pm.on_tun(&pkt, 0).to_vec();

        assert_eq!(pm.peers.len(), 2, "resolve+admit created a second peer");
        assert_eq!(pm.peers[1].pubkey, peer.public);
        assert_eq!(pm.peers[1].endpoint, Some(peer_ep));
        assert_eq!(
            out.len(),
            1,
            "a handshake Init toward the resolved peer's endpoint was emitted"
        );
        assert_eq!(
            out[0].dst, peer_ep,
            "must target the resolved peer, not the root"
        );
    }

    /// (b) `handle_handshake_init` with a valid presented cert admits + replies;
    /// with an absent or invalid cert (and not a configured peer) it drops with
    /// no reply and no session.
    #[test]
    fn cert_in_handshake_admits_valid_rejects_invalid() {
        let ca = test_ca();
        let local = generate_keypair();
        let src: SocketAddr = "203.0.113.5:5".parse().unwrap();

        // ── valid cert → admitted + reply ──
        {
            let stranger = generate_keypair();
            let mut pm = PeerManager::new(
                local.private,
                local.public,
                &[],
                TunnelMode::L3Tun,
                None,
                Some(membership_for(&ca, local.public)),
                false,
            );
            let stranger_sign = SigningKey::from_bytes(&[210u8; 32]);
            let cert = mk_cert(
                &ca,
                stranger.public,
                stranger_sign.verifying_key().to_bytes(),
            );
            let mut cert_bytes = Vec::new();
            cert.encode(&mut cert_bytes);
            let (_hs, init_pkt) =
                HandshakeState::start_initiator(&stranger.private, &local.public, &cert_bytes)
                    .unwrap();

            let replies = resp_bytes(&pm.on_udp(src, &init_pkt, 0));
            assert_eq!(replies.len(), 1, "a valid cert is admitted and replied to");
            assert_eq!(pm.peers.len(), 1, "the cert-verified member was admitted");
            assert_eq!(pm.peers[0].pubkey, stranger.public);
            assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
            assert_eq!(pm.peers[0].endpoint, Some(src), "endpoint learned from src");
        }

        // ── absent cert → dropped, no peer ──
        {
            let stranger = generate_keypair();
            let mut pm = PeerManager::new(
                local.private,
                local.public,
                &[],
                TunnelMode::L3Tun,
                None,
                Some(membership_for(&ca, local.public)),
                false,
            );
            let (_hs, init_pkt) =
                HandshakeState::start_initiator(&stranger.private, &local.public, &[]).unwrap();
            assert!(matches!(pm.on_udp(src, &init_pkt, 0), DispatchOut::None));
            assert!(pm.peers.is_empty(), "no cert ⇒ no admission");
            assert!(pm.by_tag.is_empty());
        }

        // ── cert from an untrusted CA → dropped, no peer ──
        {
            let stranger = generate_keypair();
            let untrusted_ca = SigningKey::from_bytes(&[99u8; 32]);
            let mut pm = PeerManager::new(
                local.private,
                local.public,
                &[],
                TunnelMode::L3Tun,
                None,
                Some(membership_for(&ca, local.public)),
                false,
            );
            let stranger_sign = SigningKey::from_bytes(&[211u8; 32]);
            let bad_cert = mk_cert(
                &untrusted_ca,
                stranger.public,
                stranger_sign.verifying_key().to_bytes(),
            );
            let mut cert_bytes = Vec::new();
            bad_cert.encode(&mut cert_bytes);
            let (_hs, init_pkt) =
                HandshakeState::start_initiator(&stranger.private, &local.public, &cert_bytes)
                    .unwrap();
            assert!(matches!(pm.on_udp(src, &init_pkt, 0), DispatchOut::None));
            assert!(pm.peers.is_empty(), "untrusted-CA cert ⇒ no admission");
            assert!(pm.by_tag.is_empty());
        }
    }

    /// (c) With NO membership configured, `on_tun` to an unknown mesh address is
    /// dropped and a `HandshakeInit` from an unconfigured key (even one bearing
    /// a cert) is not admitted — byte-identical to 2a/2b.
    #[test]
    fn no_membership_behaves_as_2a_2b() {
        let ca = test_ca();
        let local = generate_keypair();

        // on_tun to an unknown mesh addr: dropped, no peer created.
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let unknown = generate_keypair();
        let pkt = ipv6_pkt_to(node_addr(&unknown.public));
        assert!(pm.on_tun(&pkt, 0).is_empty(), "unknown addr dropped");
        assert!(pm.peers.is_empty(), "no resolve/admit without membership");

        // A HandshakeInit bearing a valid cert from an unconfigured key: still
        // dropped (no membership ⇒ only configured keys are admitted).
        let stranger = generate_keypair();
        let stranger_sign = SigningKey::from_bytes(&[212u8; 32]);
        let cert = mk_cert(
            &ca,
            stranger.public,
            stranger_sign.verifying_key().to_bytes(),
        );
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&stranger.private, &local.public, &cert_bytes).unwrap();
        let src: SocketAddr = "203.0.113.5:5".parse().unwrap();
        assert!(matches!(pm.on_udp(src, &init_pkt, 0), DispatchOut::None));
        assert!(pm.peers.is_empty());
        assert!(pm.by_tag.is_empty());
    }

    /// (d) Anti-hijack: a gossip/resolve event never redirects an already
    /// `Established` peer. A gossip `Records` frame advertising a DIFFERENT
    /// endpoint for a live peer updates only the directory — the peer's
    /// committed egress (endpoint, session) is untouched, and no peer is added.
    #[test]
    fn anti_hijack_established_peer_unmoved_by_gossip_and_resolve() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();
        let committed_ep: SocketAddr = "10.0.0.2:51820".parse().unwrap();

        let cfg = PeerConfig {
            public_key: peer.public,
            endpoint: Some(committed_ep),
        };
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[cfg],
            TunnelMode::L3Tun,
            None,
            Some(membership_for(&ca, local.public)),
            false,
        );

        // Splice in a live Established session reaching `committed_ep`.
        const TAG: u64 = 0x0a0b_0c0d_0e0f_1011;
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, committed_ep)),
            0,
        )));
        pm.by_tag.insert(TAG, 0);
        pm.peers[0].path_kind = Some(PathKind::Direct);

        // A gossip Records frame advertising a DIFFERENT endpoint for `peer`.
        // Gossip is source-restricted to `Established` peers (Task 6 fix), so
        // this must arrive from `committed_ep` — the only Established peer's
        // endpoint — for it to be processed at all.
        let hijack_ep: SocketAddr = "198.51.100.9:40000".parse().unwrap();
        let rec = mk_record(&ca, 213, peer.public, vec![hijack_ep], 9);
        let mut dg = vec![PacketType::Gossip as u8];
        GossipMsg::Records(vec![rec]).encode(&mut dg);
        assert!(matches!(pm.on_udp(committed_ep, &dg, 0), DispatchOut::None));

        // The directory learned the new endpoint …
        assert_eq!(
            pm.membership
                .as_ref()
                .unwrap()
                .resolve(&node_addr(&peer.public))
                .unwrap()
                .endpoints,
            vec![hijack_ep],
        );
        // … but the live peer is NOT redirected: same session, same endpoint,
        // no relay, and no extra peer admitted (resolve/admit is idempotent).
        assert_eq!(pm.peers.len(), 1);
        assert_eq!(established_tag(&pm, 0), Some(TAG), "session unchanged");
        assert_eq!(
            pm.peers[0].endpoint,
            Some(committed_ep),
            "committed egress unchanged"
        );
        assert!(!pm.peers[0].relay);

        // And a TUN packet to the peer still routes to the committed session
        // (the resolve path is never consulted for a peer already in the table).
        let pkt = ipv6_pkt_to(node_addr(&peer.public));
        let _ = pm.on_tun(&pkt, 0);
        assert_eq!(pm.peers.len(), 1, "no re-admit");
        assert_eq!(pm.peers[0].endpoint, Some(committed_ep));
    }

    /// (e) A `PacketType::Gossip` datagram with a valid record ingests into the
    /// directory (a subsequent `resolve` finds it); a forged record (untrusted
    /// CA) does not. Gossip is source-restricted to `Established` peers (Task
    /// 6 fix), so both datagrams are sent from a spliced-in Established
    /// peer's endpoint — a joining node handshakes into `Established` before
    /// it ever legitimately gossips.
    #[test]
    fn gossip_ingest_accepts_valid_rejects_forged() {
        let ca = test_ca();
        let local = generate_keypair();
        let gossip_peer = generate_keypair();
        let src: SocketAddr = "203.0.113.8:8".parse().unwrap();
        let cfg = PeerConfig {
            public_key: gossip_peer.public,
            endpoint: Some(src),
        };
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[cfg],
            TunnelMode::L3Tun,
            None,
            Some(membership_for(&ca, local.public)),
            false,
        );
        const TAG: u64 = 0x9988_7766_5544_3322;
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, src)),
            0,
        )));
        pm.by_tag.insert(TAG, 0);

        // Valid record → ingested → resolvable.
        let good = generate_keypair();
        let good_ep: SocketAddr = "192.0.2.20:6666".parse().unwrap();
        let good_rec = mk_record(&ca, 214, good.public, vec![good_ep], 3);
        let mut dg = vec![PacketType::Gossip as u8];
        GossipMsg::Records(vec![good_rec]).encode(&mut dg);
        assert!(matches!(pm.on_udp(src, &dg, 0), DispatchOut::None));
        assert_eq!(
            pm.membership
                .as_ref()
                .unwrap()
                .resolve(&node_addr(&good.public))
                .map(|i| i.endpoints),
            Some(vec![good_ep]),
            "valid gossip record is ingested and resolvable"
        );

        // Forged record (untrusted CA) → not ingested → not resolvable.
        let forged_ca = SigningKey::from_bytes(&[123u8; 32]);
        let bad = generate_keypair();
        let bad_rec = mk_record(
            &forged_ca,
            215,
            bad.public,
            vec!["192.0.2.30:7000".parse().unwrap()],
            3,
        );
        let mut dg2 = vec![PacketType::Gossip as u8];
        GossipMsg::Records(vec![bad_rec]).encode(&mut dg2);
        assert!(matches!(pm.on_udp(src, &dg2, 0), DispatchOut::None));
        assert!(
            pm.membership
                .as_ref()
                .unwrap()
                .resolve(&node_addr(&bad.public))
                .is_none(),
            "a forged record is rejected by ingest_record"
        );
    }

    /// (f) Fix-pass (Task 6, Important): gossip is source-restricted to
    /// `Established` peers. A `PacketType::Gossip` datagram from a `src` that
    /// matches no currently `Established` peer's endpoint is dropped
    /// outright — not decoded, not ingested into the directory, no reply —
    /// which is what closes the unauthenticated reflection/amplification
    /// vector (UDP `src` is otherwise fully attacker-controlled: a spoofed
    /// `PullRequest` would reflect a `Records` reply at a forged victim, and
    /// every inbound `Records` costs an unbounded number of Ed25519
    /// verifies). The identical datagram from the Established peer's own
    /// endpoint is accepted and ingested normally — legitimate gossip is
    /// unaffected.
    #[test]
    fn gossip_from_non_established_src_is_dropped() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "10.0.0.3:51820".parse().unwrap();
        let cfg = PeerConfig {
            public_key: peer.public,
            endpoint: Some(peer_ep),
        };
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[cfg],
            TunnelMode::L3Tun,
            None,
            Some(membership_for(&ca, local.public)),
            false,
        );
        const TAG: u64 = 0x1357_9bdf_2468_ace0;
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, peer_ep)),
            0,
        )));
        pm.by_tag.insert(TAG, 0);

        let member = generate_keypair();
        let member_ep: SocketAddr = "192.0.2.40:9000".parse().unwrap();
        let rec = mk_record(&ca, 216, member.public, vec![member_ep], 1);
        let mut dg = vec![PacketType::Gossip as u8];
        GossipMsg::Records(vec![rec]).encode(&mut dg);

        // A spoofed src matching no Established peer: dropped, not ingested.
        let spoofed_src: SocketAddr = "203.0.113.200:4000".parse().unwrap();
        assert!(matches!(pm.on_udp(spoofed_src, &dg, 0), DispatchOut::None));
        assert!(
            pm.membership
                .as_ref()
                .unwrap()
                .resolve(&node_addr(&member.public))
                .is_none(),
            "gossip from a non-Established src must be dropped, not ingested"
        );

        // The identical datagram from the Established peer's own endpoint:
        // accepted and ingested — legitimate gossip still works.
        assert!(matches!(pm.on_udp(peer_ep, &dg, 0), DispatchOut::None));
        assert_eq!(
            pm.membership
                .as_ref()
                .unwrap()
                .resolve(&node_addr(&member.public))
                .map(|i| i.endpoints),
            Some(vec![member_ep]),
            "gossip from an Established peer's endpoint is ingested normally"
        );
    }

    /// (g) Fix-pass (Task 6, Minor): mutual-proof rejection on the INITIATOR
    /// side. With membership configured, a `[HandshakeResp]` whose msg2 cert
    /// payload is absent or invalid must NOT establish the session — even
    /// though the underlying Noise handshake completes cryptographically —
    /// covering `handle_handshake_resp`'s `responder_cert_ok` guard.
    /// Complements (b) `cert_in_handshake_admits_valid_rejects_invalid`,
    /// which covers only the responder side of mutual proof.
    #[test]
    fn initiator_rejects_responder_with_bad_cert() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer_ep: SocketAddr = "10.0.0.4:51820".parse().unwrap();
        let cfg = PeerConfig {
            public_key: peer_kp.public,
            endpoint: Some(peer_ep),
        };

        // ── absent cert in msg2 → rejected ──
        {
            let mut pm = PeerManager::new(
                local.private,
                local.public,
                std::slice::from_ref(&cfg),
                TunnelMode::L3Tun,
                None,
                Some(membership_for(&ca, local.public)),
                false,
            );
            let init_out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
            assert_eq!(init_out.len(), 1);
            let init_pkt = init_out[0].bytes.clone();
            assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));

            // Out-of-band responder step with NO cert payload in msg2.
            let (_established, resp_pkt, _remote_static, _initiator_payload) =
                HandshakeState::start_responder(&peer_kp.private, &init_pkt, &[]).unwrap();

            assert!(matches!(
                pm.on_udp(peer_ep, &resp_pkt, 0),
                DispatchOut::None
            ));
            assert!(
                matches!(pm.peers[0].state, PeerState::Idle),
                "no responder cert ⇒ session must not establish, reverts to Idle"
            );
        }

        // ── invalid (untrusted-CA) cert in msg2 → rejected ──
        {
            let mut pm = PeerManager::new(
                local.private,
                local.public,
                &[cfg],
                TunnelMode::L3Tun,
                None,
                Some(membership_for(&ca, local.public)),
                false,
            );
            let init_out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
            let init_pkt = init_out[0].bytes.clone();

            let untrusted_ca = SigningKey::from_bytes(&[77u8; 32]);
            let peer_sign = SigningKey::from_bytes(&[78u8; 32]);
            let bad_cert = mk_cert(
                &untrusted_ca,
                peer_kp.public,
                peer_sign.verifying_key().to_bytes(),
            );
            let mut bad_cert_bytes = Vec::new();
            bad_cert.encode(&mut bad_cert_bytes);

            let (_established, resp_pkt, _remote_static, _initiator_payload) =
                HandshakeState::start_responder(&peer_kp.private, &init_pkt, &bad_cert_bytes)
                    .unwrap();

            assert!(matches!(
                pm.on_udp(peer_ep, &resp_pkt, 0),
                DispatchOut::None
            ));
            assert!(
                matches!(pm.peers[0].state, PeerState::Idle),
                "untrusted-CA responder cert ⇒ session must not establish, reverts to Idle"
            );
        }
    }

    // ── anti-DPI obfuscation (3a Task 3) ──────────────────────────────────

    /// Build a talking pair of `DataPlane`s (via an in-process Noise-IK
    /// handshake) and return `(initiator_dp, responder_dp, hp_key, conn_tag)`.
    /// The responder side can OPEN what the initiator SEALS (both derive the
    /// same `hp_key`), so a test can splice the responder side into a
    /// `PeerManager` and feed it frames the initiator side produced.
    fn established_pair(resp_peer_addr: SocketAddr) -> (DataPlane, DataPlane, [u8; 16], u64) {
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
        let conn_tag = conn_tag_from_keys(&auth_key, &hp_key);
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
        let any: SocketAddr = "0.0.0.0:0".parse().unwrap();
        (
            DataPlane::new(est_i, conn_tag, TunnelMode::L3Tun, any, false, 1200),
            DataPlane::new(
                est_r,
                conn_tag,
                TunnelMode::L3Tun,
                resp_peer_addr,
                false,
                1200,
            ),
            hp_key,
            conn_tag,
        )
    }

    /// (a) With obfuscation on, a `Data` datagram produced by the send path,
    /// obfuscated with the peer's session key, is deobfuscated by `on_udp` and
    /// routed to that peer's `DataPlane`, which decodes the original inner
    /// packet — a full send→wire→on_udp round-trip with the `PacketType` byte
    /// hidden on the wire.
    #[test]
    fn obf_on_data_roundtrips_through_send_and_on_udp() {
        let peer_ep: SocketAddr = "10.0.0.2:2000".parse().unwrap();
        let peer = peer_cfg(2, "10.0.0.2:2000");
        let mut pm = PeerManager::new(
            [9u8; 32],
            [8u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm.set_obf_psk(Some([0x11u8; 32]));

        // Splice the RESPONDER-side DataPlane so pm can open the initiator's
        // sealed frames; give the peer its matching session obf key.
        let (mut init_dp, resp_dp, hp_key, conn_tag) = established_pair(peer_ep);
        let sess = yip_obf::derive_key(&hp_key);
        pm.peers[0].state =
            PeerState::Established(Box::new(crate::epoch::EpochSet::new(Box::new(resp_dp), 0)));
        pm.peers[0].session_obf_key = Some(sess);
        pm.by_tag.insert(conn_tag, 0);

        // Sender seals a TUN packet → one or more [Data]‖frame egress datagrams.
        let inner = vec![0x33u8; 200];
        let dgs = init_dp.on_tun_packet(&inner, 0).to_vec();
        assert!(!dgs.is_empty());

        // Wrap each with the SESSION key (ptype Data) and feed through on_udp
        // until one decodes to the recovered inner (repair symbols may not).
        let mut recovered: Option<Vec<u8>> = None;
        for dg in &dgs {
            assert_eq!(dg.bytes[0], PacketType::Data as u8);
            let wrapped = yip_obf::obfuscate(&sess, PacketType::Data as u8, &dg.bytes[1..], 0);
            // The wire datagram carries no plaintext PacketType prefix.
            assert_ne!(
                wrapped[0],
                PacketType::Data as u8,
                "type byte must be masked"
            );
            if let DispatchOut::Tun(buf) = pm.on_udp(peer_ep, &wrapped, 1) {
                recovered = Some(buf.to_vec());
                break;
            }
        }
        assert_eq!(
            recovered.as_deref(),
            Some(inner.as_slice()),
            "obf-wrapped Data must deobfuscate + route to the peer and decode"
        );
    }

    /// (b) With obfuscation on, a datagram from an unknown (not-yet-Established)
    /// source that deobfuscates under the network `obf_psk` key to a
    /// `HandshakeInit` is processed: the peer establishes and the emitted
    /// `HandshakeResp` egress is itself obfuscated (no plaintext type byte).
    #[test]
    fn obf_on_unknown_src_handshake_init_via_obf_psk() {
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.7:7000".parse().unwrap();
        let cfg_i = PeerConfig {
            public_key: kp_i.public,
            endpoint: Some(ep_i),
        };
        let mut pm = PeerManager::new(
            kp_r.private,
            kp_r.public,
            &[cfg_i],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let psk = [0x22u8; 32];
        pm.set_obf_psk(Some(psk));
        let obf_key = yip_obf::derive_key(&psk);

        // A real [HandshakeInit]‖msg1, obfuscated with the network key.
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&kp_i.private, &kp_r.public, &[]).unwrap();
        assert_eq!(init_pkt[0], PacketType::HandshakeInit as u8);
        let wrapped = yip_obf::obfuscate(
            &obf_key,
            PacketType::HandshakeInit as u8,
            &init_pkt[1..],
            32,
        );

        // Arrives from a fresh source address (unknown / not Established). Step
        // (a) finds no session key; step (b) unmasks the handshake via obf_psk.
        let src: SocketAddr = "203.0.113.5:41000".parse().unwrap();
        let out = pm.on_udp(src, &wrapped, 0);
        let udp = match out {
            DispatchOut::Udp(e) => e.to_vec(),
            _ => panic!("expected a wrapped HandshakeResp egress"),
        };
        assert_eq!(udp.len(), 1);
        let (ptype, _body) = yip_obf::deobfuscate(&obf_key, &udp[0].bytes)
            .expect("resp is wrapped under the network obf key");
        assert_eq!(
            ptype,
            PacketType::HandshakeResp as u8,
            "the reply is an obfuscated HandshakeResp"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
        assert_eq!(
            pm.peers[0].endpoint,
            Some(src),
            "endpoint learned from the observed source"
        );
    }

    /// (c) With obfuscation on, a random-garbage datagram (wrong key under any
    /// trial) is dropped with no side effect and no panic — as are empty and
    /// too-short datagrams.
    #[test]
    fn obf_on_garbage_is_dropped_no_panic() {
        let kp = generate_keypair();
        let peer = peer_cfg(3, "10.0.0.3:3000");
        let mut pm = PeerManager::new(
            kp.private,
            kp.public,
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm.set_obf_psk(Some([0x44u8; 32]));

        let src: SocketAddr = "203.0.113.9:9".parse().unwrap();
        let junk = vec![0xABu8; 80];
        assert!(matches!(pm.on_udp(src, &junk, 0), DispatchOut::None));
        assert!(matches!(pm.on_udp(src, &[], 0), DispatchOut::None));
        assert!(matches!(pm.on_udp(src, &[0u8; 3], 0), DispatchOut::None));
        // No peer disturbed.
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
        assert!(pm.by_tag.is_empty());
    }

    /// (3b-a) `build_junk()` produces a PLAINTEXT `[JUNK_TYPE][body]`
    /// datagram, `JUNK_MIN_LEN..=JUNK_MAX_LEN` bytes of body — it must NOT
    /// pre-obfuscate, since the caller's `obf_egress` pass wraps it exactly
    /// once (double-wrapping would defeat the JUNK_TYPE recognition on
    /// ingress; see `single_wrap_...` below for the full round-trip).
    #[test]
    fn build_junk_roundtrips_to_junk_type() {
        let peer = peer_cfg(5, "10.0.0.5:5000");
        let mut pm = PeerManager::new(
            [1u8; 32],
            [2u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );

        let dg = pm.build_junk();
        assert_eq!(
            dg[0],
            yip_obf::JUNK_TYPE,
            "leading byte is the plaintext JUNK_TYPE"
        );
        let body_len = dg.len() - 1;
        assert!(
            (JUNK_MIN_LEN..=JUNK_MAX_LEN).contains(&body_len),
            "body length is within [JUNK_MIN_LEN, JUNK_MAX_LEN], got {body_len}"
        );
    }

    /// (3b-b) With obfuscation on, a junk datagram sent from an `Established`
    /// peer's source (session-keyed) is silently dropped by `on_udp`: no
    /// egress, and the peer's session state is left completely untouched.
    #[test]
    fn obf_on_session_keyed_junk_is_dropped_state_unchanged() {
        const TAG: u64 = 0xABCD_EF01;
        let peer_ep: SocketAddr = "10.0.0.6:6000".parse().unwrap();
        let peer = peer_cfg(6, "10.0.0.6:6000");
        let mut pm = PeerManager::new(
            [3u8; 32],
            [4u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm.set_obf_psk(Some([0x66u8; 32]));

        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, peer_ep)),
            0,
        )));
        let sess = [0x77u8; 16];
        pm.peers[0].session_obf_key = Some(sess);
        pm.by_tag.insert(TAG, 0);

        // `build_junk()` itself is plaintext now (single-wrapped by
        // `obf_egress` on the real egress path); reproduce that one wrap by
        // hand here to get wire-format bytes for `on_udp`'s ingress test.
        let plain = pm.build_junk();
        let junk = yip_obf::obfuscate(&sess, yip_obf::JUNK_TYPE, &plain[1..], 0);
        let before_tag = pm.by_tag.get(&TAG).copied();

        let out = pm.on_udp(peer_ep, &junk, 0);
        assert!(
            matches!(out, DispatchOut::None),
            "session-keyed junk must be dropped, not dispatched"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
        assert_eq!(
            pm.peers[0].session_obf_key,
            Some(sess),
            "session obf key untouched by a dropped junk datagram"
        );
        assert_eq!(pm.by_tag.get(&TAG).copied(), before_tag, "by_tag untouched");
    }

    /// (3b-c) With obfuscation on, a junk datagram from an entirely unknown
    /// source (no `Established` peer at that address, so it can only unmask
    /// under the network `obf_key`) is dropped with no panic and no peer
    /// admitted.
    #[test]
    fn obf_on_network_keyed_junk_from_unknown_src_is_dropped_no_panic() {
        let peer = peer_cfg(7, "10.0.0.7:7000");
        let mut pm = PeerManager::new(
            [5u8; 32],
            [6u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let psk = [0x88u8; 32];
        pm.set_obf_psk(Some(psk));
        let obf_key = yip_obf::derive_key(&psk);

        // Same rationale as the session-keyed test above: `build_junk()` is
        // plaintext, so wrap it once by hand to get wire-format bytes.
        let plain = pm.build_junk();
        let junk = yip_obf::obfuscate(&obf_key, yip_obf::JUNK_TYPE, &plain[1..], 0);
        let src: SocketAddr = "203.0.113.55:5555".parse().unwrap();
        assert!(matches!(pm.on_udp(src, &junk, 0), DispatchOut::None));
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
        assert!(pm.by_tag.is_empty());
    }

    /// (3b-d) With obfuscation OFF (`obf_key: None`), the `JUNK_TYPE` drop arm
    /// lives entirely inside `deobf_ingress`, which is never reached — a
    /// junk-shaped datagram (leading byte == `JUNK_TYPE`, which is not a
    /// recognized plaintext `PacketType`) takes the exact unchanged 2a/2b/2c
    /// plaintext path (falls into `handle_data_or_control`, finds no matching
    /// peer, drops with no panic) rather than being specially recognized.
    #[test]
    fn obf_off_junk_shaped_datagram_takes_unchanged_plaintext_path() {
        let peer = peer_cfg(8, "10.0.0.8:8000");
        let mut pm = PeerManager::new(
            [7u8; 32],
            [8u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        // No set_obf_psk ⇒ obf_key is None ⇒ deobf_ingress/build_junk's JUNK
        // handling is never consulted.
        assert!(pm.obf_key.is_none());

        let mut dg = vec![yip_obf::JUNK_TYPE];
        dg.extend_from_slice(&[0u8; 16]);
        let src: SocketAddr = "203.0.113.66:6666".parse().unwrap();
        assert!(matches!(pm.on_udp(src, &dg, 0), DispatchOut::None));
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
    }

    // ── Task 3: handshake junk burst ────────────────────────────────────────

    /// With obfuscation on and a direct (non-relay) handshake,
    /// `begin_handshake` returns `Jc ∈ [JUNK_BURST_MIN, JUNK_BURST_MAX]` junk
    /// datagrams — each a PLAINTEXT `[JUNK_TYPE][body]` (obfuscation happens
    /// one layer up, in `obf_egress`; see `single_wrap_...` below for the
    /// wrapped round-trip) — followed by exactly one real `HandshakeInit`,
    /// all addressed to `target`.
    #[test]
    fn begin_handshake_obf_on_direct_emits_junk_burst_then_init() {
        let peer = peer_cfg(9, "10.0.0.9:9000");
        let mut pm = PeerManager::new(
            [9u8; 32],
            [10u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let psk = [0x99u8; 32];
        pm.set_obf_psk(Some(psk));
        let target: SocketAddr = "203.0.113.9:9000".parse().unwrap();

        let dgs = pm
            .begin_handshake(0, target, false, 0)
            .expect("handshake starts");

        let min_len = 1 + usize::try_from(JUNK_BURST_MIN).expect("fits usize");
        let max_len = 1 + usize::try_from(JUNK_BURST_MAX).expect("fits usize");
        assert!(
            (min_len..=max_len).contains(&dgs.len()),
            "expected 1 Init + [JUNK_BURST_MIN, JUNK_BURST_MAX] junk, got {} datagrams",
            dgs.len()
        );
        for d in &dgs {
            assert_eq!(d.dst, target, "every datagram targets `target`");
        }

        let (junk, init) = dgs.split_at(dgs.len() - 1);
        assert!(!junk.is_empty(), "at least JUNK_BURST_MIN junk datagrams");
        for j in junk {
            assert_eq!(
                j.bytes[0],
                yip_obf::JUNK_TYPE,
                "junk datagram is plaintext [JUNK_TYPE][body] pre-obf_egress"
            );
        }
        // The real Init is last, still the plaintext `[PacketType]‖msg1`
        // framing `begin_handshake` has always produced (wrapping under
        // obfuscation happens one layer up, in `obf_egress`).
        assert_eq!(init.len(), 1, "exactly one real Init");
        assert_eq!(init[0].bytes[0], PacketType::HandshakeInit as u8);
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
    }

    /// Across many `begin_handshake` calls (obf on, direct), the junk count
    /// `Jc` varies — proving the burst size is actually drawn from
    /// `junk_rng` each time rather than a disguised constant.
    #[test]
    fn begin_handshake_obf_on_direct_junk_count_varies() {
        let peer = peer_cfg(10, "10.0.0.10:10000");
        let mut pm = PeerManager::new(
            [11u8; 32],
            [12u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm.set_obf_psk(Some([0xAAu8; 32]));
        let target: SocketAddr = "203.0.113.10:10000".parse().unwrap();

        let mut counts = std::collections::HashSet::new();
        for _ in 0..64 {
            // Reset to Idle so begin_handshake can restart the peer each call.
            pm.peers[0].state = PeerState::Idle;
            let dgs = pm
                .begin_handshake(0, target, false, 0)
                .expect("handshake starts");
            counts.insert(dgs.len() - 1); // junk count, excluding the trailing Init
        }
        assert!(
            counts.len() > 1,
            "junk count must vary across 64 calls, saw only {counts:?}"
        );
    }

    /// With obfuscation OFF, `begin_handshake` on the direct path returns
    /// exactly one datagram (the Init) — no junk, byte-identical to
    /// pre-Task-3 behavior.
    #[test]
    fn begin_handshake_obf_off_direct_emits_init_only() {
        let peer = peer_cfg(11, "10.0.0.11:11000");
        let mut pm = PeerManager::new(
            [13u8; 32],
            [14u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        assert!(pm.obf_key.is_none());
        let target: SocketAddr = "203.0.113.11:11000".parse().unwrap();

        let dgs = pm
            .begin_handshake(0, target, false, 0)
            .expect("handshake starts");
        assert_eq!(dgs.len(), 1, "no junk when obf is off");
        assert_eq!(dgs[0].dst, target);
        assert_eq!(dgs[0].bytes[0], PacketType::HandshakeInit as u8);
    }

    /// Scope guard: even with obfuscation on, the RELAY handshake path
    /// (`via_relay: true`) returns exactly one datagram — no junk. Relay-path
    /// junk needs a different (`RelaySend`) envelope and is out of scope for
    /// Task 3 (noted as future work).
    #[test]
    fn begin_handshake_obf_on_relay_emits_wrapped_init_only_no_junk() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);
        pm.set_obf_psk(Some([0xBBu8; 32]));

        let server = mock_server();
        let dgs = pm
            .begin_handshake(0, server, true, 0)
            .expect("relay handshake starts");
        assert_eq!(dgs.len(), 1, "relay path never emits junk (Task 3 scope)");
        assert_eq!(dgs[0].dst, server);
        assert!(pm.peers[0].relay, "peer marked relay-routed");
    }

    /// End-to-end single-wrap proof — the actual bug this fix addresses.
    /// Drives the real egress path (`on_tun` on an Idle peer, obf on), so
    /// `begin_handshake`'s junk burst flows through the caller's `obf_egress`
    /// pass exactly once, same as production. Before the fix, `build_junk`
    /// pre-obfuscated its output and `obf_egress` wrapped it a *second* time,
    /// so a single `deobfuscate` on the wire bytes recovered a garbage ptype
    /// (the leading byte of the *inner* envelope's random nonce, not
    /// `JUNK_TYPE`) — junk still got silently dropped, but via the generic
    /// unrecognized-ptype path rather than the dedicated `JUNK_TYPE` arm.
    /// Assert every datagram actually on the wire recovers under exactly one
    /// `yip_obf::deobfuscate(&network_key, _)` call, that at least
    /// `JUNK_BURST_MIN` of them decode to `JUNK_TYPE`, and exactly one
    /// decodes to a non-empty `HandshakeInit`.
    #[test]
    fn junk_burst_is_single_wrapped_end_to_end() {
        let peer = peer_cfg(12, "10.0.0.12:12000");
        let mut pm = PeerManager::new(
            [15u8; 32],
            [16u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let psk = [0xCCu8; 32];
        pm.set_obf_psk(Some(psk));
        let network_key = yip_obf::derive_key(&psk);

        let wire = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert!(!wire.is_empty(), "the first TUN packet starts a handshake");

        let mut junk_count = 0usize;
        let mut init_count = 0usize;
        for d in &wire {
            assert!(
                d.bytes.len() <= OBF_MTU_BUDGET,
                "wrapped datagram must stay within OBF_MTU_BUDGET, got {}",
                d.bytes.len()
            );
            let (ptype, body) = yip_obf::deobfuscate(&network_key, &d.bytes).expect(
                "every emitted datagram must recover under a SINGLE deobfuscate \
                 call — a double-wrap would leave the outer envelope's random \
                 ptype/len/body inconsistent or simply wrong",
            );
            if ptype == yip_obf::JUNK_TYPE {
                junk_count += 1;
            } else if ptype == PacketType::HandshakeInit as u8 {
                init_count += 1;
                assert!(!body.is_empty(), "the real Init carries msg1 bytes");
            } else {
                panic!(
                    "unexpected ptype {ptype} on the wire — this is exactly the \
                     symptom of the double-wrap bug (single deobfuscate peeling \
                     only the outer layer)"
                );
            }
        }
        assert!(
            junk_count >= usize::try_from(JUNK_BURST_MIN).expect("fits usize"),
            "at least JUNK_BURST_MIN junk datagrams, got {junk_count}"
        );
        assert_eq!(init_count, 1, "exactly one real HandshakeInit");
    }

    /// (d) With obfuscation OFF (no `set_obf_psk`), `on_udp` runs the unchanged
    /// plaintext demux: a plaintext `[HandshakeInit]‖msg1` establishes the peer
    /// and the reply carries a plaintext `PacketType` prefix — byte-identical
    /// to 2a (no envelope on the wire).
    #[test]
    fn obf_off_on_udp_is_plaintext_as_today() {
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.7:7000".parse().unwrap();
        let cfg_i = PeerConfig {
            public_key: kp_i.public,
            endpoint: Some(ep_i),
        };
        let mut pm = PeerManager::new(
            kp_r.private,
            kp_r.public,
            &[cfg_i],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        // No set_obf_psk ⇒ obfuscation disabled.
        let (_hs, init_pkt) =
            HandshakeState::start_initiator(&kp_i.private, &kp_r.public, &[]).unwrap();
        let resp = resp_bytes(&pm.on_udp(ep_i, &init_pkt, 0));
        assert_eq!(resp.len(), 1, "one plaintext HandshakeResp is emitted");
        assert_eq!(
            resp[0][0],
            PacketType::HandshakeResp as u8,
            "reply carries a plaintext PacketType prefix (no obfuscation envelope)"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
    }

    /// (e) With obfuscation on and a rendezvous server configured, a `Lookup`
    /// emitted toward the server is wrapped under the network `obf_key` and
    /// `yip_obf::RDV_TYPE` (Task 4's `obf_egress` server-dst branch) — it no
    /// longer decodes as a plain `yip_rendezvous::Message` on the wire, but
    /// `deobfuscate` + `Message::decode` recovers the original `Lookup`.
    #[test]
    fn obf_on_egress_to_server_is_wrapped_under_rdv_type() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);
        let psk = [0x55u8; 32];
        pm.set_obf_psk(Some(psk));
        let obf_key = yip_obf::derive_key(&psk);

        let out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert_eq!(out.len(), 1, "one lookup datagram is emitted");
        assert_eq!(out[0].dst, mock_server());
        // The on-wire bytes must not be the plaintext rendezvous encoding.
        // (A `decode(..).is_none()` check would be flaky: the obfuscated bytes
        // are random, so they can occasionally parse as a Message by chance.)
        let mut plaintext = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::Lookup {
                node: node_id(&peer_kp.public),
            },
            &mut plaintext,
        );
        assert_ne!(
            out[0].bytes, plaintext,
            "the on-wire bytes must be obfuscated, not the plaintext rendezvous encoding"
        );
        let (ptype, body) =
            yip_obf::deobfuscate(&obf_key, &out[0].bytes).expect("wrapped under the network key");
        assert_eq!(ptype, yip_obf::RDV_TYPE);
        assert_eq!(
            yip_rendezvous::decode(&body),
            Some(yip_rendezvous::Message::Lookup {
                node: node_id(&peer_kp.public),
            }),
            "unwrapping recovers the original Lookup"
        );
    }

    /// (f) With obfuscation on, an obf-wrapped server datagram (`RDV_TYPE`)
    /// arriving from the configured server address is unwrapped by `on_udp`
    /// and routed to `on_rdv` exactly like the plaintext 2b path — a
    /// `PeerInfo` sets the peer's candidate address. A wrong-key or
    /// wrong-ptype envelope from the same address is dropped, not mis-routed.
    #[test]
    fn obf_on_ingress_from_server_is_unwrapped_before_on_rdv() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);
        let psk = [0x66u8; 32];
        pm.set_obf_psk(Some(psk));
        let obf_key = yip_obf::derive_key(&psk);

        let candidate: SocketAddr = "198.51.100.9:41001".parse().unwrap();
        let mut plain = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
            },
            &mut plain,
        );

        // Wrong key: dropped, no candidate learned (rendezvous-only peer
        // starts in Punching with no candidate address set).
        let wrong_key = yip_obf::derive_key(&[0x67u8; 32]);
        let wrapped_wrong = yip_obf::obfuscate(&wrong_key, yip_obf::RDV_TYPE, &plain, 0);
        assert!(matches!(
            pm.on_udp(mock_server(), &wrapped_wrong, 0),
            DispatchOut::None
        ));
        assert_eq!(pm.peers[0].path.candidate(), None);

        // Right key, wrong ptype: dropped, no candidate learned.
        let wrapped_wrong_type = yip_obf::obfuscate(&obf_key, PacketType::Data as u8, &plain, 0);
        assert!(matches!(
            pm.on_udp(mock_server(), &wrapped_wrong_type, 0),
            DispatchOut::None
        ));
        assert_eq!(pm.peers[0].path.candidate(), None);

        // Right key, right type: recovers the PeerInfo and sets the candidate.
        let wrapped = yip_obf::obfuscate(&obf_key, yip_obf::RDV_TYPE, &plain, 5);
        assert!(matches!(
            pm.on_udp(mock_server(), &wrapped, 0),
            DispatchOut::None
        ));
        assert_eq!(pm.peers[0].path.candidate(), Some(candidate));
    }

    /// (g) With obfuscation OFF, egress to the server and ingress from the
    /// server stay plain `yip_rendezvous::Message` bytes — byte-identical to
    /// 2b, undisturbed by Task 4's obf-on branches.
    #[test]
    fn obf_off_rendezvous_traffic_stays_plaintext() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);
        // No set_obf_psk ⇒ obfuscation disabled.

        let out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert_eq!(out.len(), 1);
        assert_eq!(
            yip_rendezvous::decode(&out[0].bytes),
            Some(yip_rendezvous::Message::Lookup {
                node: node_id(&peer_kp.public),
            }),
            "obf-off Lookup egress is plain, unwrapped Message bytes"
        );

        let candidate: SocketAddr = "198.51.100.9:41002".parse().unwrap();
        let mut plain = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
            },
            &mut plain,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &plain, 0),
            DispatchOut::None
        ));
        assert_eq!(pm.peers[0].path.candidate(), Some(candidate));
    }

    // ── 3a: control-cadence jitter ─────────────────────────────────────────

    /// `jitter_ms(1000)` must land in the documented ±25% band and must not
    /// be a disguised constant (i.e. it actually draws from the OS RNG on
    /// every call, not just once).
    #[test]
    fn jitter_ms_within_bounds_and_not_constant() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let v = jitter_ms(1000);
            assert!(
                (750..=1250).contains(&v),
                "jitter_ms(1000) out of the ±25% band: {v}"
            );
            seen.insert(v);
        }
        assert!(
            seen.len() > 1,
            "jitter_ms(1000) returned the same value on every call across 64 draws"
        );
    }

    /// The obf-off proof: every call site gates jitter with
    /// `if obf_key.is_some() { jitter_ms(base) } else { base }`. With obf off
    /// (`obf_key: None`) that expression must yield exactly `base` every
    /// time — never a jittered value — so a timer built from it fires at
    /// exactly the base interval, byte-identical to pre-3a timing.
    #[test]
    fn obf_off_gating_yields_exact_base_interval() {
        let obf_key: Option<[u8; 16]> = None;
        for _ in 0..8 {
            let retry_ms = if obf_key.is_some() {
                jitter_ms(HANDSHAKE_RETRY_MS)
            } else {
                HANDSHAKE_RETRY_MS
            };
            let reg_ms = if obf_key.is_some() {
                jitter_ms(REG_REFRESH_MS)
            } else {
                REG_REFRESH_MS
            };
            assert_eq!(retry_ms, HANDSHAKE_RETRY_MS);
            assert_eq!(reg_ms, REG_REFRESH_MS);
        }
    }

    // ── 3b Task 4: idle cover traffic ───────────────────────────────────────

    /// Build an obf-on `PeerManager` with a single `Established` peer whose
    /// session obf key is known to the caller, ready to `tick`. Both
    /// `last_activity_ms`/`last_cover_ms` start at their `Peer::new` default
    /// (`0`) — "idle since the dawn of time" — so a caller only needs to
    /// override whichever one it wants non-idle.
    fn obf_on_established_peer_for_cover(
        cover_traffic_ms: Option<u64>,
        obf_on: bool,
    ) -> (PeerManager, SocketAddr, [u8; 16]) {
        const TAG: u64 = 0x1234_5678_9abc_def0;
        let peer_ep: SocketAddr = "10.0.0.20:2020".parse().unwrap();
        let peer = peer_cfg(20, "10.0.0.20:2020");
        let mut pm = PeerManager::new(
            [21u8; 32],
            [22u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        if obf_on {
            pm.set_obf_psk(Some([0xAAu8; 32]));
        }
        pm.set_cover_traffic_ms(cover_traffic_ms);

        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, peer_ep)),
            0,
        )));
        let sess = [0xBBu8; 16];
        pm.peers[0].session_obf_key = Some(sess);
        pm.by_tag.insert(TAG, 0);
        (pm, peer_ep, sess)
    }

    /// `tick`'s call into each `Established` peer's own `DataPlane::tick`
    /// (unrelated to cover traffic — it's the loss-feedback Control
    /// cadence) fires its own periodic Control datagram once
    /// `now_ms >= FEEDBACK_INTERVAL_MS` (30 ms in `dataplane.rs`, private to
    /// that module). Every cover test below keeps `now_ms` under that
    /// threshold so `tick_egress` contains only what THIS test is checking
    /// — the cover datagram (or nothing) — never an incidental feedback
    /// packet that would make an exact-count/`is_none` assertion flaky.
    const COVER_TEST_NOW_MS: u64 = 20;

    /// With obf on and `cover_traffic_ms = Some(iv)`, an `Established` peer
    /// idle for `>= iv` gets exactly one cover datagram from `tick`,
    /// addressed to its endpoint, that — after `tick`'s own `obf_egress`
    /// wrap — deobfuscates to plaintext `JUNK_TYPE` under that peer's
    /// session key (never the network `obf_key`, since junk cover to an
    /// `Established` peer is session-keyed).
    #[test]
    fn tick_emits_one_cover_for_idle_established_peer() {
        let (mut pm, peer_ep, sess) =
            obf_on_established_peer_for_cover(Some(COVER_TEST_NOW_MS), true);

        let out = pm
            .tick(COVER_TEST_NOW_MS)
            .expect("idle peer gets a cover datagram");
        assert_eq!(out.len(), 1, "exactly one cover datagram");
        assert_eq!(out[0].dst, peer_ep);
        let (ptype, _body) = yip_obf::deobfuscate(&sess, &out[0].bytes)
            .expect("cover is wrapped under the peer's session key");
        assert_eq!(
            ptype,
            yip_obf::JUNK_TYPE,
            "cover datagram deobfuscates to plaintext JUNK_TYPE"
        );
        assert_eq!(
            pm.peers[0].last_cover_ms, COVER_TEST_NOW_MS,
            "last_cover_ms updated so the next tick doesn't double-fire"
        );
    }

    /// A peer with recent activity (`last_activity_ms == now_ms`) is NOT
    /// idle — `tick` must emit no cover for it, proving cover never races or
    /// delays real data.
    #[test]
    fn tick_emits_no_cover_for_active_peer() {
        let (mut pm, _peer_ep, _sess) =
            obf_on_established_peer_for_cover(Some(COVER_TEST_NOW_MS), true);
        pm.peers[0].last_activity_ms = COVER_TEST_NOW_MS; // activity at "now"

        let out = pm.tick(COVER_TEST_NOW_MS);
        assert!(
            out.is_none(),
            "an active peer must not receive a cover datagram"
        );
    }

    /// With `cover_traffic_ms = None` (the default — cover traffic not
    /// configured), `tick` emits no cover even for an idle `Established`
    /// peer with obf on.
    #[test]
    fn tick_emits_no_cover_when_cover_traffic_ms_unset() {
        let (mut pm, _peer_ep, _sess) = obf_on_established_peer_for_cover(None, true);

        let out = pm.tick(COVER_TEST_NOW_MS);
        assert!(
            out.is_none(),
            "cover_traffic_ms absent ⇒ no cover, regardless of idle peers"
        );
    }

    /// With obfuscation OFF (no `set_obf_psk`), `tick` emits no cover even
    /// when `cover_traffic_ms` is configured — the byte-identical
    /// no-regression invariant (obf off ⇒ tick behaves exactly as pre-3b).
    #[test]
    fn tick_emits_no_cover_when_obf_off() {
        let (mut pm, _peer_ep, _sess) =
            obf_on_established_peer_for_cover(Some(COVER_TEST_NOW_MS), false);
        assert!(pm.obf_key.is_none());

        let out = pm.tick(COVER_TEST_NOW_MS);
        assert!(
            out.is_none(),
            "obf off ⇒ no cover, regardless of cover_traffic_ms"
        );
    }

    /// A relay-reached peer (`relay == true`, mirroring how
    /// `relayed_handshake_init`/`relayed_handshake_resp` leave a peer: session
    /// established but `endpoint` still holding the stale/candidate direct
    /// address from before relay took over) must NOT receive a cover
    /// datagram from `tick`, even with obf on, `cover_traffic_ms` set, and
    /// the peer idle — contrast with `tick_emits_one_cover_for_idle_established_peer`,
    /// whose otherwise-identical direct peer (`relay == false`) still gets
    /// one. Firing cover at a relay peer's stale `endpoint` would leak junk
    /// to an unrelated address and never reach the actual peer.
    #[test]
    fn tick_emits_no_cover_for_relay_peer() {
        let (mut pm, _peer_ep, _sess) =
            obf_on_established_peer_for_cover(Some(COVER_TEST_NOW_MS), true);
        pm.peers[0].relay = true;

        let out = pm.tick(COVER_TEST_NOW_MS);
        assert!(
            out.is_none(),
            "a relay-reached peer must not receive a cover datagram, even when idle"
        );
    }
}
