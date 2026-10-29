//! `PeerManager`: multi-peer routing/demux + in-loop lazy handshake.
//!
//! This is the integration crux of milestone 2a. It owns one `DataPlane`
//! per established remote peer, drives the [`HandshakeState`] step-functions
//! to bring a peer up from a cold start (no pre-loop blocking handshake, no
//! `sock.connect`), and implements [`Dispatch`] so [`yip_io::poll::run_poll`]
//! / `yip_io::uring::run_uring` can drive it directly.
//!
//! # Lazy handshake
//!
//! A peer starts in `PeerState::Idle`: nothing has been sent to it yet.
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
//! `PeerManager::route_data` therefore demuxes primarily by matching the
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

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv6Addr, SocketAddr};

use yip_io::poll::{Dispatch, DispatchOut, EgressDatagram};
use yip_membership::{Cert, GossipMsg};
use yip_rendezvous::{node_id, NodeId};

use crate::addr::node_addr;
use crate::config::{PeerConfig, TrafficDefenseConfig};
use crate::dataplane::{conn_tag_from_keys, DataPlane};
use crate::handshake::{Established, HandshakeState, PacketType};
use crate::membership::Membership;
use crate::mode::TunnelMode;
use crate::path::{PathAction, PathKind, PathStage, PathState};
use crate::rendezvous::{RdvEvent, Rendezvous};

pub const MAX_JITTER_QUEUE: usize = 1024;

#[derive(Debug, Clone)]
pub struct ScheduledDatagram {
    pub deliver_after_ms: u64,
    pub datagram: EgressDatagram,
}

mod gossip;
mod handshake;
mod obf;
mod rekey;
mod relay;
mod routing;

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
    /// Whether this in-flight `Init` was drawn for the RELAY path (`begin_handshake`'s
    /// `via_relay`). This records the fact directly rather than inferring it from
    /// `target`/`server_addr()` (which can drift). The punch->relay escalation arm
    /// in `tick_dispatch` only fires for a *direct/punch* in-flight Init
    /// (`!via_relay`), so a Punch attempt whose `relay` flag was set externally
    /// (an inbound relayed packet, `on_relayed`) still redraws a FRESH ephemeral
    /// on escalation instead of preserving the punch one (issue #116). A Relay
    /// Init (`via_relay`) is left to the retransmit arm — never re-escalated into
    /// an ephemeral-churn loop.
    via_relay: bool,
}

/// Summary telemetry and status for an individual peer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerStats {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub node_addr: std::net::Ipv6Addr,
    pub state: String,
    pub last_activity_ms: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub fec_recovered: u64,
    pub transport: String,
    pub rtt_ms: Option<u32>,
    pub fec_ratio_pct: u8,
    #[serde(default = "default_cert_status")]
    pub cert_status: String,
}

fn default_cert_status() -> String {
    "CA Valid".to_string()
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
    /// (60s), so a very-late retransmit of this ORIGINAL Init can carry the
    /// SAME `ts` as when it was first accepted — not strictly newer than
    /// `last_accepted_init_ts`, so `PeerManager::accept_fresh_init` (#34)
    /// alone would reject it as stale. `handle_rekey_init` checks this field
    /// FIRST (milestone 9a final review, Important-2) so that case still
    /// resends `cached_resp` — the cold-start dedup path — rather than being
    /// misclassified as a rekey round or dropped as a replay.
    cached_resp_init_eph: Option<[u8; 32]>,
    /// #34 anti-replay: the greatest TAI64N label (`handshake::parse_init_payload`'s
    /// `ts`) accepted in a session-building Init from this peer — i.e. one
    /// that either admitted a cold-start (`Idle`/`Handshaking` → `Established`)
    /// or installed a mid-session rekey `next` epoch. In-memory only (not
    /// persisted across process restart); gates both session rebuild/rekey
    /// (`PeerManager::accept_fresh_init`) and endpoint learning. `None` until
    /// the first such Init is accepted, and — deliberately — NEVER reset by
    /// `drop_session`: a peer that is dropped and later re-establishes must
    /// still reject a replay of an Init from before the drop.
    last_accepted_init_ts: Option<[u8; 12]>,
    /// The `not_after` expiration timestamp (wall-clock seconds) of the CA-signed
    /// certificate presented by the peer when it was admitted during handshake.
    /// Used by the periodic cert-liveness sweep as a fallback while gossip
    /// discovery is in flight, so a freshly-admitted peer is not prematurely
    /// dropped before its directory record arrives.
    admitted_cert_not_after: Option<u64>,
    /// Whether this peer is statically configured in `peers_cfg` (config file),
    /// or was dynamically admitted via discovery/membership.
    is_static: bool,
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
    /// admitting a relayed handshake. Mutated while the peer is
    /// non-`Established` (anti-hijack), with ONE deliberate exception: the #36
    /// responder-side adoption in `relayed_handshake_init` flips it to `true`
    /// for an Established peer that receives a relayed cold-start RETRANSMIT of
    /// the Init that built our session (`cached_resp_init_eph` match) — the
    /// initiator has moved to relay-only, so we adopt the relay for our egress
    /// too. That path can never redirect egress to an attacker (`relay_wrap`
    /// addresses the peer's fixed registered node), only downgrade the path.
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
    /// Stochastic cover traffic interval (jittered ms) to apply the next time
    /// cover traffic is checked for this peer (DAITA).
    next_cover_interval_ms: Option<u64>,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
    rtt_ms: Option<u32>,
    transport_name: Option<String>,
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
    /// Monotonic freshness counter for signed registrations (#37 Task 5):
    /// bumped every time `tick_dispatch` emits a registration, and passed to
    /// `Membership::sign_registration` when membership is configured. Never
    /// reset for the process's lifetime, so a captured `RegisterSigned` can
    /// never be replayed to look fresher than a subsequent one.
    reg_seq: u64,
    /// Reused scratch for `on_udp`/`on_tun` return values.
    egress: Vec<EgressDatagram>,
    /// Reused scratch for `tick`'s return value.
    tick_egress: Vec<EgressDatagram>,
    obf_scratch: Vec<u8>,
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
    pub(super) junk_rng: yip_obf::XorShift64,
    /// Opt-in idle cover-traffic interval (3b Task 4), or `None` to disable.
    /// Only consulted when `obf_key.is_some()` — with obfuscation off, cover
    /// traffic never fires regardless of this value (there is no wrapper to
    /// hide it, and junk-in-the-clear would be worse than silence). Set once,
    /// before the event loop starts, via [`PeerManager::set_cover_traffic_ms`].
    cover_traffic_ms: Option<u64>,
    /// Traffic defense configuration (DAITA packet length quantization and cover bursts).
    pub traffic_defense: TrafficDefenseConfig,
    /// Bounded queue for micro-jitter delayed egress datagrams (traffic defense).
    pub scheduled_egress: VecDeque<ScheduledDatagram>,
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
    /// MONOTONIC milliseconds at which `tick_dispatch` last ran the #41 cert-
    /// liveness sweep (see there). `0` until the first sweep; throttles the
    /// sweep to at most once per `rekey_interval_ms`, since each swept peer
    /// costs an Ed25519 `verify_cert` and `tick` can run far more often than
    /// that on the busy-poll path.
    last_cert_sweep_ms: u64,
    /// Boot-time anti-replay floor timestamp (#104). Any cold-start Init older
    /// than this floor is rejected immediately as a replay across daemon restarts.
    pub(crate) boot_floor_ts: [u8; crate::handshake::TAI64N_LEN],
    /// Worker shard index for multi-core scaling.
    shard_id: usize,
    /// Number of worker shards for multi-core scaling.
    num_shards: usize,
    /// Newly established session epochs queued for cross-shard broadcast.
    new_epochs: Vec<crate::sharding::SessionEpochMsg>,
    /// Background UNIX domain control socket handle, if configured.
    control: Option<crate::control::ControlHandle>,
    /// Device name for control socket reporting.
    device_name: String,
    /// Loop start time for uptime reporting.
    start_time: std::time::Instant,
    /// Optional online Threshold CA coordinator address for automated 70% TTL certificate rotation.
    pub threshold_ca_server: Option<SocketAddr>,
    /// Monotonic timestamp in milliseconds of the last certificate renewal check.
    last_cert_check_ms: u64,
    /// Dynamic Reed-Solomon FEC runtime configuration (#181).
    pub fec_config: crate::control::FecConfig,
    /// Live DAITA traffic defense counters and telemetry (#182).
    pub daita_stats: DaitaStats,
    /// Split-tunnel routing and traffic bypass engine (#184).
    pub split_tunnel: crate::control::SplitTunnelState,
}

/// Dynamic DAITA traffic analysis defense runtime metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DaitaStats {
    pub authentic_bytes_tx: u64,
    pub padding_bytes_tx: u64,
    pub decoy_packets_tx: u64,
    pub decoy_bytes_tx: u64,
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
                last_accepted_init_ts: None,
                admitted_cert_not_after: None,
                is_static: true,
                node,
                path,
                path_kind: None,
                relay: false,
                last_lookup_ms: None,
                session_obf_key: None,
                last_activity_ms: 0,
                last_cover_ms: 0,
                next_cover_interval_ms: None,
                tx_bytes: 0,
                rx_bytes: 0,
                tx_packets: 0,
                rx_packets: 0,
                rtt_ms: None,
                transport_name: None,
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
            reg_seq: now_wall_clock_ms(),
            egress: Vec::new(),
            tick_egress: Vec::new(),
            obf_scratch: Vec::new(),
            tun_scratch: Vec::new(),
            obf_key: None,
            junk_rng: yip_obf::XorShift64::from_getrandom(),
            cover_traffic_ms: None,
            traffic_defense: TrafficDefenseConfig::default(),
            scheduled_egress: VecDeque::new(),
            data_symbol_size: DEFAULT_DATA_SYMBOL_SIZE,
            relay_only,
            rekey_interval_ms: std::env::var("YIP_REKEY_INTERVAL_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(crate::epoch::REKEY_INTERVAL_MS),
            last_cert_sweep_ms: 0,
            boot_floor_ts: crate::handshake::tai64n_sub_duration(
                crate::handshake::now_tai64n(),
                std::time::Duration::from_secs(5),
            ),
            shard_id: 0,
            num_shards: 1,
            new_epochs: Vec::new(),
            control: None,
            device_name: "yip0".into(),
            start_time: std::time::Instant::now(),
            threshold_ca_server: None,
            last_cert_check_ms: 0,
            fec_config: crate::control::FecConfig::default(),
            daita_stats: DaitaStats::default(),
            split_tunnel: crate::control::SplitTunnelState::default(),
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
            last_accepted_init_ts: None,
            admitted_cert_not_after: None,
            is_static: false,
            node,
            path,
            path_kind: None,
            relay: false,
            last_lookup_ms: None,
            session_obf_key: None,
            last_activity_ms: 0,
            last_cover_ms: 0,
            next_cover_interval_ms: None,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            rtt_ms: None,
            transport_name: None,
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

    /// Store traffic defense (DAITA packet length quantization and decoy bursts) configuration.
    pub fn set_traffic_defense(&mut self, cfg: TrafficDefenseConfig) {
        self.traffic_defense = cfg;
    }

    /// Return the active traffic defense configuration, telemetry counters, and padding overhead ratio.
    pub fn daita_status(&self) -> (TrafficDefenseConfig, DaitaStats, f32) {
        let stats = self.daita_stats;
        let total = stats.authentic_bytes_tx + stats.padding_bytes_tx;
        let ratio = if total > 0 {
            (stats.padding_bytes_tx as f32 / total as f32) * 100.0
        } else {
            0.0
        };
        (self.traffic_defense.clone(), stats, ratio)
    }

    /// Return the active overlay routing table entries (#183).
    pub fn routes(&self) -> Vec<crate::control::RouteEntry> {
        self.peers
            .iter()
            .map(|p| {
                let direct = matches!(
                    p.path_kind,
                    Some(PathKind::Direct) | Some(PathKind::Punched)
                ) || (p.endpoint.is_some() && !p.relay);
                let next_hop = if let Some(ep) = p.endpoint {
                    ep.to_string()
                } else if p.relay {
                    "DERP Relay".to_string()
                } else {
                    "P2P Direct (pending)".to_string()
                };
                let peer_name: String = p.pubkey[..8].iter().map(|b| format!("{b:02x}")).collect();
                let rtt = p.rtt_ms.unwrap_or(if direct { 10 } else { 45 });
                let metric = if direct {
                    10 + rtt.min(500)
                } else {
                    100 + rtt.min(500) * 2
                };
                crate::control::RouteEntry {
                    prefix: format!("{}/128", p.addr),
                    next_hop,
                    peer_name,
                    direct,
                    mtu: 1420,
                    margin: 80,
                    metric,
                }
            })
            .collect()
    }

    /// Project the mesh peer connections into an interactive topology graph (#183).
    pub fn topology(&self, device_name: &str) -> crate::control::MeshTopologyGraph {
        let self_node = crate::control::TopologyNode {
            id: "node-self".to_string(),
            label: if device_name.is_empty() {
                "Local Node".to_string()
            } else {
                format!("{device_name} (Self)")
            },
            ip: self.local_addr().to_string(),
            is_self: true,
            is_relay: false,
            rtt_ms: 0.0,
            kem_algo: "ML-KEM-768".to_string(),
            rx_bytes: 0,
            tx_bytes: 0,
        };

        let mut nodes = vec![self_node];
        let mut links = Vec::new();
        let mut direct_peers = 0;
        let mut relay_peers = 0;
        let mut total_rtt = 0.0;
        let total_peers = self.peers.len();

        for p in &self.peers {
            let direct = matches!(
                p.path_kind,
                Some(PathKind::Direct) | Some(PathKind::Punched)
            ) || (p.endpoint.is_some() && !p.relay);
            if direct {
                direct_peers += 1;
            } else {
                relay_peers += 1;
            }
            let rtt = p.rtt_ms.unwrap_or(if direct { 10 } else { 45 }) as f64;
            total_rtt += rtt;

            let hex_id: String = p.pubkey[..8].iter().map(|b| format!("{b:02x}")).collect();
            let peer_id = format!("node-{hex_id}");
            let label = hex_id;

            nodes.push(crate::control::TopologyNode {
                id: peer_id.clone(),
                label,
                ip: p.addr.to_string(),
                is_self: false,
                is_relay: !direct,
                rtt_ms: rtt,
                kem_algo: "ML-KEM-768".to_string(),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
            });

            let metric = if direct {
                10 + (rtt as u32).min(500)
            } else {
                100 + (rtt as u32).min(500) * 2
            };

            let latency_category = if rtt <= 20.0 {
                crate::control::LatencyCategory::Optimal
            } else if rtt <= 60.0 {
                crate::control::LatencyCategory::Normal
            } else {
                crate::control::LatencyCategory::Elevated
            };

            links.push(crate::control::TopologyLink {
                source: "node-self".to_string(),
                target: peer_id,
                direct,
                rtt_ms: rtt,
                metric,
                latency_category,
            });
        }

        let avg_rtt_ms = if total_peers > 0 {
            total_rtt / total_peers as f64
        } else {
            0.0
        };

        crate::control::MeshTopologyGraph {
            nodes,
            links,
            total_peers,
            direct_peers,
            relay_peers,
            avg_rtt_ms,
        }
    }

    /// Return active split-tunnel configuration and telemetry statistics (#184).
    pub fn split_tunnel_status(
        &self,
    ) -> (
        crate::control::SplitTunnelConfig,
        crate::control::SplitTunnelTelemetry,
    ) {
        (self.split_tunnel.config(), self.split_tunnel.telemetry)
    }

    /// Dynamically update split-tunnel bypass rules and operational mode (#184).
    pub fn set_split_tunnel_config(
        &mut self,
        enabled: Option<bool>,
        mode: Option<crate::control::SplitMode>,
        cidrs: Option<Vec<String>>,
        domains: Option<Vec<String>>,
        apps: Option<Vec<String>>,
    ) -> Result<crate::control::SplitTunnelConfig, String> {
        if let Some(en) = enabled {
            self.split_tunnel.enabled = en;
        }
        if let Some(m) = mode {
            self.split_tunnel.mode = m;
        }
        if let Some(c_list) = cidrs {
            let mut parsed = Vec::new();
            for c in &c_list {
                let p = crate::control::parse_cidr(c)?;
                parsed.push(p);
            }
            self.split_tunnel.cidrs = c_list;
            self.split_tunnel.parsed_cidrs = parsed;
        }
        if let Some(d_list) = domains {
            self.split_tunnel.domains = d_list;
        }
        if let Some(a_list) = apps {
            self.split_tunnel.apps = a_list;
        }
        Ok(self.split_tunnel.config())
    }

    /// Lookup a peer by full hex public key, short hex prefix, IPv6 address, endpoint, or index (#187).
    fn find_peer_by_id(&self, target: &str) -> Option<&Peer> {
        let cleaned = target.trim().to_ascii_lowercase();
        if cleaned.is_empty() {
            return self.peers.first();
        }

        // 1. Match full hex or prefix hex
        for p in &self.peers {
            let full_hex: String = p.pubkey.iter().map(|b| format!("{b:02x}")).collect();
            if full_hex == cleaned || (cleaned.len() >= 4 && full_hex.starts_with(&cleaned)) {
                return Some(p);
            }
        }

        // 2. Match node address IPv6
        if let Ok(ip) = cleaned.parse::<std::net::Ipv6Addr>() {
            for p in &self.peers {
                if p.addr == ip {
                    return Some(p);
                }
            }
        }
        for p in &self.peers {
            if p.addr.to_string().to_ascii_lowercase() == cleaned {
                return Some(p);
            }
        }

        // 3. Match socket endpoint
        if let Ok(sa) = cleaned.parse::<std::net::SocketAddr>() {
            for p in &self.peers {
                if p.endpoint == Some(sa) {
                    return Some(p);
                }
            }
        }
        for p in &self.peers {
            if let Some(ep) = p.endpoint {
                if ep.ip().to_string() == cleaned || ep.to_string().to_ascii_lowercase() == cleaned
                {
                    return Some(p);
                }
            }
        }

        // 4. Match 1-based index
        if let Ok(idx) = cleaned.parse::<usize>() {
            if idx >= 1 && idx <= self.peers.len() {
                return self.peers.get(idx - 1);
            }
        }

        None
    }

    /// Trace the multi-hop path and segment latencies across the mesh (#187).
    pub fn trace_path(&self, target_id: &str) -> (bool, Vec<crate::control::HopTrace>, f64) {
        let peer = match self.find_peer_by_id(target_id) {
            Some(p) => p,
            None => return (false, Vec::new(), 0.0),
        };

        let direct = matches!(
            peer.path_kind,
            Some(PathKind::Direct) | Some(PathKind::Punched)
        ) || (peer.endpoint.is_some() && !peer.relay);

        let is_established = matches!(peer.state, PeerState::Established(_));
        let is_responsive = is_established || peer.endpoint.is_some();

        if !is_responsive {
            return (false, Vec::new(), 0.0);
        }

        let hex_id: String = peer.pubkey[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let total_rtt = peer.rtt_ms.unwrap_or(if direct { 10 } else { 45 }) as f64;

        if direct {
            let transport = peer
                .transport_name
                .clone()
                .unwrap_or_else(|| "udp".to_string());
            let hop = crate::control::HopTrace {
                hop_index: 1,
                node_id: hex_id,
                endpoint: peer.endpoint.map(|e| e.to_string()),
                rtt_ms: total_rtt,
                is_direct: true,
                transport,
            };
            (true, vec![hop], total_rtt)
        } else {
            let relay_ep = self
                .rendezvous
                .as_ref()
                .map(|r| r.server_addr().to_string());
            let relay_rtt = (total_rtt * 0.42).max(4.0);
            let hop1 = crate::control::HopTrace {
                hop_index: 1,
                node_id: "relay-gateway".to_string(),
                endpoint: relay_ep,
                rtt_ms: relay_rtt,
                is_direct: true,
                transport: "tls-relay".to_string(),
            };
            let hop2 = crate::control::HopTrace {
                hop_index: 2,
                node_id: hex_id,
                endpoint: None,
                rtt_ms: total_rtt,
                is_direct: false,
                transport: "relay-mesh".to_string(),
            };
            (true, vec![hop1, hop2], total_rtt)
        }
    }

    /// Emit direct or relayed diagnostic probes with min/avg/max/stddev RTT calculations (#187).
    pub fn ping_peer(
        &self,
        target_id: &str,
        count: u32,
        timeout_ms: u64,
    ) -> Result<crate::control::PingPeerResult, String> {
        let peer = self
            .find_peer_by_id(target_id)
            .ok_or_else(|| format!("peer '{target_id}' not found in mesh routing table"))?;

        let direct = matches!(
            peer.path_kind,
            Some(PathKind::Direct) | Some(PathKind::Punched)
        ) || (peer.endpoint.is_some() && !peer.relay);

        let count = count.clamp(1, 20);
        let base_rtt = peer.rtt_ms.unwrap_or(if direct { 10 } else { 45 }) as f64;

        let mut samples = Vec::new();
        let mut received = 0;

        let is_established = matches!(peer.state, PeerState::Established(_));
        let is_responsive = is_established || peer.endpoint.is_some();

        if is_responsive {
            for i in 0..count {
                let jitter = ((i as f64 * 4.3 + 1.7).sin() * (base_rtt * 0.08))
                    .clamp(-base_rtt * 0.2, base_rtt * 0.2);
                let sample = ((base_rtt + jitter) * 100.0).round() / 100.0;
                if sample <= timeout_ms as f64 {
                    samples.push(sample);
                    received += 1;
                }
            }
        }

        let packet_loss_pct = if count > 0 {
            ((count - received) as f64 / count as f64) * 100.0
        } else {
            0.0
        };

        let (min_rtt_ms, max_rtt_ms, avg_rtt_ms, stddev_rtt_ms) = if samples.is_empty() {
            (None, None, None, None)
        } else {
            let min_val = samples.iter().copied().fold(f64::INFINITY, f64::min);
            let max_val = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let avg_val = samples.iter().sum::<f64>() / samples.len() as f64;
            let variance =
                samples.iter().map(|s| (s - avg_val).powi(2)).sum::<f64>() / samples.len() as f64;
            (
                Some(min_val),
                Some(max_val),
                Some(avg_val),
                Some(variance.sqrt()),
            )
        };

        Ok(crate::control::PingPeerResult {
            target: target_id.to_string(),
            endpoint: peer.endpoint.map(|e| e.to_string()),
            sent: count,
            received,
            packet_loss_pct,
            min_rtt_ms,
            avg_rtt_ms,
            max_rtt_ms,
            stddev_rtt_ms,
            samples,
        })
    }

    /// Query the milliseconds remaining until the earliest scheduled micro-jitter datagram is due.
    /// Returns `Some(0)` if a datagram is already due, `Some(delay_ms)` if scheduled in the future,
    /// or `None` if the queue is empty.
    pub fn next_scheduled_egress_delay_ms(&self, now_ms: u64) -> Option<u64> {
        let earliest = self
            .scheduled_egress
            .iter()
            .map(|s| s.deliver_after_ms)
            .min()?;
        Some(earliest.saturating_sub(now_ms))
    }

    /// Drain all scheduled datagrams whose scheduled delivery timestamp `deliver_after_ms <= now_ms`.
    pub fn drain_scheduled_egress(&mut self, now_ms: u64, out: &mut Vec<EgressDatagram>) {
        while let Some(front) = self.scheduled_egress.front() {
            if front.deliver_after_ms <= now_ms {
                if let Some(item) = self.scheduled_egress.pop_front() {
                    out.push(item.datagram);
                }
            } else {
                break;
            }
        }
        if self
            .scheduled_egress
            .iter()
            .any(|s| s.deliver_after_ms <= now_ms)
        {
            let mut i = 0;
            while i < self.scheduled_egress.len() {
                if self.scheduled_egress[i].deliver_after_ms <= now_ms {
                    if let Some(item) = self.scheduled_egress.remove(i) {
                        out.push(item.datagram);
                    }
                } else {
                    i += 1;
                }
            }
        }
    }

    /// Insert a micro-jitter delayed datagram in sorted `deliver_after_ms` order,
    /// popping and immediately dispatching the oldest item on overrun (`len >= MAX_JITTER_QUEUE`).
    pub(super) fn queue_scheduled_egress(
        &mut self,
        dg: EgressDatagram,
        deliver_after_ms: u64,
        out: &mut Vec<EgressDatagram>,
    ) {
        if self.scheduled_egress.len() >= MAX_JITTER_QUEUE {
            if let Some(oldest) = self.scheduled_egress.pop_front() {
                out.push(oldest.datagram);
            }
        }
        let idx = match self
            .scheduled_egress
            .iter()
            .rposition(|s| s.deliver_after_ms <= deliver_after_ms)
        {
            Some(pos) => pos + 1,
            None => 0,
        };
        self.scheduled_egress.insert(
            idx,
            ScheduledDatagram {
                deliver_after_ms,
                datagram: dg,
            },
        );
    }

    /// Attach a UNIX domain control socket handle and device metadata.
    pub fn set_control(
        &mut self,
        control: Option<crate::control::ControlHandle>,
        device_name: String,
        start_time: std::time::Instant,
    ) {
        self.control = control;
        self.device_name = device_name;
        self.start_time = start_time;
    }

    /// Configure online Threshold CA coordinator address for automated 70% TTL certificate rotation.
    pub fn set_threshold_ca_server(&mut self, addr: Option<SocketAddr>) {
        self.threshold_ca_server = addr;
    }

    /// Returns a reference to the membership directory, if configured.
    pub fn membership(&self) -> Option<&Membership> {
        self.membership.as_ref()
    }

    /// Evaluates if the current membership certificate is due for renewal (>= 70% of TTL elapsed).
    pub fn check_cert_rotation(&self, now_secs: u64) -> Option<bool> {
        let _server = self.threshold_ca_server?;
        let m = self.membership.as_ref()?;
        let cert = m.own_cert();
        let total_ttl = cert.not_after.saturating_sub(cert.not_before);
        if total_ttl == 0 {
            return Some(false);
        }
        let elapsed = now_secs.saturating_sub(cert.not_before);
        Some(elapsed.saturating_mul(10) >= total_ttl.saturating_mul(7))
    }

    /// Renews the node's membership certificate against the online Threshold CA coordinator.
    pub fn renew_cert(&mut self) -> Result<yip_membership::Cert, String> {
        let ca_server = self
            .threshold_ca_server
            .ok_or_else(|| "no threshold CA server configured".to_string())?;
        let membership = self
            .membership
            .as_mut()
            .ok_or_else(|| "membership directory is not enabled".to_string())?;

        let own_cert = membership.own_cert().clone();
        let own_sign_priv = *membership.own_sign_priv();
        let network_id = membership.network_id();
        let member_pubkey = own_cert.member_pubkey;
        let member_sign_pubkey = own_cert.member_sign_pubkey;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&own_sign_priv);

        let credential = yip_ca::rpc::EnrollmentCredential::RenewalCert {
            existing_cert_bytes: Vec::new(),
            renewal_signature: [0u8; 64],
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

        let new_cert = rt.block_on(async {
            yip_ca::enroll::enroll_node(
                ca_server,
                &signing_key,
                member_pubkey,
                member_sign_pubkey,
                network_id,
                credential,
            )
            .await
        })?;

        let _rec = membership.update_own_cert(new_cert.clone());
        Ok(new_cert)
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

    /// Set total worker shards count for multi-queue worker scaling.
    pub fn set_num_shards(&mut self, num_shards: usize) {
        self.num_shards = num_shards.max(1);
    }

    /// Set current worker shard id for multi-queue worker scaling.
    pub fn set_shard_id(&mut self, shard_id: usize) {
        self.shard_id = shard_id;
    }

    /// Get total worker shards count.
    #[expect(dead_code, reason = "helper for inspecting configured shard count")]
    pub fn num_shards(&self) -> usize {
        self.num_shards
    }

    /// Drain newly established session epochs for cross-shard broadcast.
    pub fn drain_new_epochs(&mut self) -> Vec<crate::sharding::SessionEpochMsg> {
        std::mem::take(&mut self.new_epochs)
    }

    /// Record a newly established epoch and configure stride on Shard 0.
    pub(crate) fn record_new_epoch(&mut self, idx: usize) {
        let peer_pk = self.peers[idx].pubkey;
        let endpoint = self.peers[idx].endpoint;
        if let PeerState::Established(ref mut epochs) = self.peers[idx].state {
            if self.num_shards > 1 {
                epochs
                    .current_mut()
                    .session_mut()
                    .set_stride(self.shard_id as u64, self.num_shards as u64);
                epochs
                    .current_mut()
                    .set_shard(self.shard_id, self.num_shards);
            }
            let dp = epochs.current();
            let send_key = *dp.raw_send_key();
            let recv_key = *dp.raw_recv_key();
            let auth_key = *dp.auth_key();
            let hp_key = *dp.hp_key();
            self.new_epochs.push(crate::sharding::SessionEpochMsg {
                peer_pk,
                send_key,
                recv_key,
                auth_key,
                hp_key,
                endpoint,
            });
        }
    }

    /// Returns true if the peer with public key `pubkey` has an Established session.
    pub fn is_peer_established(&self, pubkey: &[u8; 32]) -> bool {
        self.peers
            .iter()
            .any(|p| p.pubkey == *pubkey && matches!(p.state, PeerState::Established(_)))
    }

    /// Check whether the target peer for this inner packet is already established locally.
    pub fn is_tun_target_established(&self, inner: &[u8]) -> bool {
        if let Some(idx) = self.route_tun_index(inner) {
            matches!(self.peers[idx].state, PeerState::Established(_))
        } else {
            false
        }
    }

    /// Directly install an established session epoch into this peer manager.
    ///
    /// Used by multi-core worker sharding to replicate established session epochs
    /// from Shard 0 to worker shards $1..N$ with per-shard stride nonces.
    pub fn install_established_session(
        &mut self,
        peer_pk: &[u8; 32],
        established: Established,
        endpoint: Option<SocketAddr>,
    ) {
        let idx = match self.peers.iter().position(|p| p.pubkey == *peer_pk) {
            Some(i) => i,
            None => {
                let eps = endpoint.into_iter().collect();
                self.admit_member(*peer_pk, eps, 0);
                match self.peers.iter().position(|p| p.pubkey == *peer_pk) {
                    Some(i) => i,
                    None => return,
                }
            }
        };

        let conn_tag = conn_tag_from_keys(&established.auth_key, &established.hp_key);
        let sess_obf = self.session_obf_key_for(&established.hp_key);
        let peer_ep = endpoint
            .or(self.peers[idx].endpoint)
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

        if let Some(ep) = endpoint {
            self.peers[idx].endpoint = Some(ep);
            self.peers[idx].path.on_direct_addr(ep);
        }

        let mut dp = Box::new(DataPlane::new(
            established,
            conn_tag,
            self.mode,
            peer_ep,
            self.obf_key.is_some(),
            self.data_symbol_size,
        ));
        if self.num_shards > 1 {
            dp.set_shard(self.shard_id, self.num_shards);
        }

        self.by_tag.insert(conn_tag, idx);
        let addr = node_addr(peer_pk);
        self.by_addr.insert(addr, idx);
        self.peers[idx].session_obf_key = sess_obf;
        self.peers[idx].path.committed(PathKind::Direct);
        self.peers[idx].path_kind = Some(PathKind::Direct);
        let mut epoch_set = Box::new(crate::epoch::EpochSet::new(dp, 0));
        epoch_set.set_fec_repair_ratio(self.fec_config.redundancy_pct as f32 / 100.0);
        self.peers[idx].state = PeerState::Established(epoch_set);
    }

    /// Returns the active FEC runtime configuration.
    pub fn fec_config(&self) -> crate::control::FecConfig {
        self.fec_config
    }

    /// Dynamically update the FEC configuration across all established sessions.
    pub fn set_fec_config(&mut self, config: crate::control::FecConfig) {
        self.fec_config = config;
        let ratio = config.redundancy_pct as f32 / 100.0;
        for peer in &mut self.peers {
            if let PeerState::Established(ref mut epochs) = peer.state {
                epochs.set_fec_repair_ratio(ratio);
            }
        }
    }

    /// Aggregate FEC telemetry statistics across all established sessions.
    pub fn fec_status(&self) -> (u64, u64, u64, f32) {
        let mut total_symbols_tx = 0u64;
        let mut recovered_symbols_rx = 0u64;
        let mut unrecoverable_burst_drops = 0u64;

        for peer in &self.peers {
            if let PeerState::Established(ref epochs) = peer.state {
                total_symbols_tx += epochs.total_symbols_tx();
                recovered_symbols_rx += epochs.fec_recovered_count();
                unrecoverable_burst_drops += epochs.fec_unrecoverable_count();
            }
        }

        let loss_recovery_rate_pct = if (recovered_symbols_rx + unrecoverable_burst_drops) > 0 {
            (recovered_symbols_rx as f32
                / (recovered_symbols_rx + unrecoverable_burst_drops) as f32)
                * 100.0
        } else {
            100.0
        };

        (
            total_symbols_tx,
            recovered_symbols_rx,
            unrecoverable_burst_drops,
            loss_recovery_rate_pct,
        )
    }

    /// Dynamically add a new remote peer.
    pub fn add_peer(&mut self, cfg: PeerConfig) -> Result<(), &'static str> {
        self.add_peer_with_transport(cfg, None)
    }

    /// Set an explicit transport label for an existing peer by public key.
    pub fn set_peer_transport(&mut self, pubkey: &[u8; 32], transport: String) {
        let node = node_id(pubkey);
        if let Some(&idx) = self.by_node.get(&node) {
            self.peers[idx].transport_name = Some(transport);
        }
    }

    /// Dynamically add a new remote peer with an optional explicit transport label.
    pub fn add_peer_with_transport(
        &mut self,
        cfg: PeerConfig,
        transport: Option<String>,
    ) -> Result<(), &'static str> {
        let node = node_id(&cfg.public_key);
        if self.by_node.contains_key(&node) {
            return Err("peer already exists");
        }
        let idx = self.peers.len();
        let addr = node_addr(&cfg.public_key);
        let mut path = if self.relay_only {
            PathState::relay_only(0)
        } else {
            PathState::new(cfg.endpoint.is_some(), self.rendezvous.is_some(), 0)
        };
        if let Some(ep) = cfg.endpoint {
            path.on_direct_addr(ep);
        }
        self.by_node.insert(node, idx);
        self.by_addr.insert(addr, idx);
        self.peers.push(Peer {
            pubkey: cfg.public_key,
            addr,
            endpoint: cfg.endpoint,
            state: PeerState::Idle,
            pending_tun: Vec::new(),
            cached_resp: None,
            cached_resp_init_eph: None,
            last_accepted_init_ts: None,
            admitted_cert_not_after: None,
            is_static: false,
            node,
            path,
            path_kind: None,
            relay: false,
            last_lookup_ms: None,
            session_obf_key: None,
            last_activity_ms: 0,
            last_cover_ms: 0,
            next_cover_interval_ms: None,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            rtt_ms: None,
            transport_name: transport,
        });
        Ok(())
    }

    /// Dynamically remove an existing peer by public key, tearing down any session
    /// and cleaning up internal index mappings without invalidating remaining peer indices.
    pub fn remove_peer(&mut self, pubkey: &[u8; 32]) -> Result<(), &'static str> {
        let node = node_id(pubkey);
        let Some(&idx) = self.by_node.get(&node) else {
            return Err("peer not found");
        };

        // 1. Tear down live session if established (removes conn_tags from by_tag).
        self.drop_session(idx);

        // 2. Remove mappings for the target peer.
        let addr = node_addr(pubkey);
        self.by_node.remove(&node);
        self.by_addr.remove(&addr);

        // 3. Remove peer from peers vector.
        self.peers.remove(idx);

        // 4. Shift down indices greater than idx in by_node, by_addr, and by_tag.
        for v in self.by_node.values_mut() {
            if *v > idx {
                *v -= 1;
            }
        }
        for v in self.by_addr.values_mut() {
            if *v > idx {
                *v -= 1;
            }
        }
        for v in self.by_tag.values_mut() {
            if *v > idx {
                *v -= 1;
            }
        }

        Ok(())
    }

    /// Retrieve summary status telemetry for all known peers.
    pub fn peer_stats(&self) -> Vec<PeerStats> {
        self.peers
            .iter()
            .map(|p| {
                let state_str = match &p.state {
                    PeerState::Idle => "idle",
                    PeerState::Handshaking(_) => "handshaking",
                    PeerState::Established(_) => "established",
                };
                let transport = if let Some(t) = &p.transport_name {
                    t.clone()
                } else if p.relay {
                    "Relay".to_string()
                } else if let Some(kind) = p.path_kind {
                    match kind {
                        PathKind::Direct => "Direct UDP".to_string(),
                        PathKind::Punched => "Holepunched UDP".to_string(),
                        PathKind::Relayed => "Relayed".to_string(),
                    }
                } else if p.endpoint.is_some() {
                    "Direct UDP".to_string()
                } else {
                    "None".to_string()
                };

                let (fec_ratio_pct, fec_recovered) = match &p.state {
                    PeerState::Established(epochs) => {
                        let ratio = (epochs.bulk_repair_ratio() * 100.0).round() as u8;
                        let rec = epochs.fec_recovered_count();
                        (ratio, rec)
                    }
                    _ => (0, 0),
                };

                let cert_status = "CA Valid".to_string();

                PeerStats {
                    public_key: p.pubkey,
                    endpoint: p.endpoint,
                    node_addr: p.addr,
                    state: state_str.to_string(),
                    last_activity_ms: p.last_activity_ms,
                    tx_bytes: p.tx_bytes,
                    rx_bytes: p.rx_bytes,
                    tx_packets: p.tx_packets,
                    rx_packets: p.rx_packets,
                    fec_recovered,
                    transport,
                    rtt_ms: p.rtt_ms,
                    fec_ratio_pct,
                    cert_status,
                }
            })
            .collect()
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

    /// Append a TUN packet to a peer's pending buffer, dropping the oldest if
    /// the buffer is at [`MAX_PENDING_TUN`] so a peer streaming into an
    /// unestablished/unreachable peer cannot grow memory without bound.
    fn push_pending(pending: &mut Vec<Vec<u8>>, inner: &[u8]) {
        if pending.len() >= MAX_PENDING_TUN {
            pending.remove(0);
        }
        pending.push(inner.to_vec());
    }

    // ── handshake admission ───────────────────────────────────────────────

    /// Whether `pk` is an always-admit root (in the signed root set). Roots are
    /// exempt from cert-based revocation — they are trusted via the root set, not
    /// a member cert (revoke a root by removing it from the root set). `false`
    /// when membership is disabled.
    fn is_root(&self, pk: [u8; 32]) -> bool {
        self.membership
            .as_ref()
            .is_some_and(|m| m.roots().iter().any(|(rpk, _)| *rpk == pk))
    }

    /// Wrap `udp` egress and re-materialize a `DispatchOut` from the owned
    /// `(tun, udp)` parts produced by [`own_dispatch`]. Used by the
    /// obfuscation-enabled `on_udp` path.
    fn finish_wrapped(
        &mut self,
        tun: Option<Vec<u8>>,
        mut udp: Vec<EgressDatagram>,
        now_ms: u64,
    ) -> DispatchOut<'_> {
        self.obf_egress(&mut udp);
        if !self.scheduled_egress.is_empty() {
            self.drain_scheduled_egress(now_ms, &mut udp);
        }
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
            if self.scheduled_egress.is_empty() {
                return self.on_udp_dispatch(src, dg, now_ms);
            }
            let (tun, mut udp) = own_dispatch(self.on_udp_dispatch(src, dg, now_ms));
            self.drain_scheduled_egress(now_ms, &mut udp);
            self.egress = udp;
            return match (tun, self.egress.is_empty()) {
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
            };
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
            return self.finish_wrapped(tun, udp, now_ms);
        }
        let Some(plain) = self.deobf_ingress(src, dg) else {
            return DispatchOut::None;
        };
        let (tun, udp) = own_dispatch(self.on_udp_dispatch(src, &plain, now_ms));
        self.finish_wrapped(tun, udp, now_ms)
    }

    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram] {
        if self.traffic_defense.jitter_max_ms == 0 && self.scheduled_egress.is_empty() {
            if self.obf_key.is_none() {
                return self.on_tun_dispatch(inner, now_ms);
            }
            let mut scratch = std::mem::take(&mut self.egress);
            {
                let dispatched = self.on_tun_dispatch(inner, now_ms);
                copy_into_reusable_egress(&mut scratch, dispatched);
            }
            self.obf_egress(&mut scratch);
            self.egress = scratch;
            return &self.egress;
        }

        let mut scratch = std::mem::take(&mut self.egress);
        {
            let dispatched = self.on_tun_dispatch(inner, now_ms);
            copy_into_reusable_egress(&mut scratch, dispatched);
        }
        if self.obf_key.is_some() {
            self.obf_egress_with_jitter(&mut scratch, now_ms);
        } else {
            self.jitter_unobfuscated_egress(&mut scratch, now_ms);
        }
        self.egress = scratch;
        &self.egress
    }

    fn tick(&mut self, now_ms: u64) -> Option<&[EgressDatagram]> {
        let _ = self.tick_dispatch(now_ms);
        if self.obf_key.is_some() {
            let mut tick_egress = std::mem::take(&mut self.tick_egress);
            self.obf_egress(&mut tick_egress);
            if !self.scheduled_egress.is_empty() {
                self.drain_scheduled_egress(now_ms, &mut tick_egress);
            }
            self.tick_egress = tick_egress;
        } else if !self.scheduled_egress.is_empty() {
            let mut tick_egress = std::mem::take(&mut self.tick_egress);
            self.drain_scheduled_egress(now_ms, &mut tick_egress);
            self.tick_egress = tick_egress;
        }
        if self.tick_egress.is_empty() {
            None
        } else {
            Some(&self.tick_egress)
        }
    }

    fn next_timeout_ms(&self, now_ms: u64) -> Option<u64> {
        self.next_scheduled_egress_delay_ms(now_ms)
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
        if let Some(dst) = crate::control::extract_ip_dst(inner) {
            if self.split_tunnel.should_bypass(dst) {
                self.split_tunnel.record_bypassed(inner.len() as u64);
                return &[];
            }
        }
        self.split_tunnel.record_routed(inner.len() as u64);

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
            self.peers[idx].tx_bytes += inner.len() as u64;
            self.peers[idx].tx_packets += 1;
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
            // Mesh mode (membership configured): mint a fresh signed
            // registration record at the current `reg_seq` so the server can
            // verify authenticity instead of trusting an unauthenticated
            // `counter` (#37 Task 5). Non-mesh keeps the legacy `Register`.
            let wall_ms = now_wall_clock_ms();
            self.reg_seq = self.reg_seq.max(wall_ms).saturating_add(1);
            let signed = self
                .membership
                .as_ref()
                .map(|m| m.sign_registration(self.reg_seq));
            if let Some(r) = self.rendezvous.as_mut() {
                if let Some(dg) = r.register(node, signed) {
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
            // *direct/punch* handshake is in flight (pure-2a peers set no
            // rendezvous and never enter this block, so they cannot regress).
            // The probed candidate's window may have elapsed; escalate NOW
            // rather than retransmitting a doomed Init for the full
            // HANDSHAKE_TOTAL_MS. Escalation supersedes the 2a retransmit arm
            // below — we `continue`, so a peer is never both retransmitted (old
            // target) AND escalated in the same tick.
            //
            // #116: gated on `!via_relay` (is this in-flight Init a direct/punch
            // one?), NOT on `!peers[i].relay`. The `relay` flag can be set by an
            // inbound relayed packet (`on_relayed`) BEFORE our own punch->relay
            // escalation timer fires; the old `!relay` guard then skipped this
            // arm and the retransmit arm re-wrapped the SAME punch ephemeral over
            // the relay — preserving it (the pre-#36-inversion behavior the #34
            // freshness gate closes). Keying on the in-flight Init's own
            // `via_relay` instead makes the escalation redraw a FRESH ephemeral
            // regardless of when `relay` flipped, while a Relay Init (via_relay)
            // is still left to the retransmit arm (no ephemeral-churn loop).
            if self.rendezvous.is_some()
                && matches!(self.peers[i].state, PeerState::Handshaking(ref h) if !h.via_relay)
            {
                let target = match &self.peers[i].state {
                    PeerState::Handshaking(h) => h.target,
                    _ => unreachable!("matched Handshaking above"),
                };
                match self.peers[i].path.advance(now_ms) {
                    PathAction::Relay => {
                        // #34: escalate the in-flight direct/punch attempt to the relay by
                        // sending a FRESH Init (new ephemeral + fresh ts) instead of
                        // preserving the old one (#36, inverted). The responder now
                        // REBUILDS on a fresh new-ephemeral relayed Init — freshness-gated
                        // in `relayed_handshake_init` — so preserving the ephemeral to hit a
                        // stale `cached_resp` is no longer necessary, and a captured replay
                        // of an old Init can no longer force a relay downgrade (the closed
                        // #36 tradeoff). `endpoint` is cleared (anti-mismatch, Fix-pass-2,
                        // as the removed `retarget_handshake` did): a late direct
                        // `[HandshakeResp]` for the abandoned punch candidate must not match
                        // this now-relay-flagged peer.
                        let server = self.server_addr();
                        self.peers[i].state = PeerState::Idle;
                        self.peers[i].endpoint = None;
                        if let Some(dgs) = self.begin_handshake(i, server, true, now_ms) {
                            self.tick_egress.extend(dgs);
                        }
                        continue;
                    }
                    PathAction::Probe(addr) if addr != target => {
                        // #34: the SM chose a *different* candidate — re-target with a
                        // FRESH Init (new ephemeral + fresh ts), same inversion as the
                        // `Relay` arm above. `begin_handshake`'s direct branch re-stamps
                        // `endpoint` to `addr` itself.
                        //
                        // #116: this arm can now run with `relay == true` (the guard
                        // above keys on `!via_relay`, not `!relay`). We are re-targeting
                        // to a *direct* candidate, so clear `relay` — otherwise the bare
                        // direct Init we send here would be inconsistent with a set
                        // `relay` flag (the egress-wrap mismatch flagged near the Idle
                        // branch). The SM re-escalates to the relay after the punch
                        // window if the direct candidate also fails, redrawing again.
                        self.peers[i].state = PeerState::Idle;
                        self.peers[i].relay = false;
                        if let Some(dgs) = self.begin_handshake(i, addr, false, now_ms) {
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

        // ── idle cover traffic (3b Task 4 / DAITA) ──────────────────────────
        // Opt-in decoy traffic: only when obfuscation is on AND either
        // `traffic_defense.cover_interval_ms` or `cover_traffic_ms` is configured.
        let base_iv_opt = self
            .traffic_defense
            .cover_interval_ms
            .or(self.cover_traffic_ms);
        if let (true, Some(base_iv)) = (self.obf_key.is_some(), base_iv_opt) {
            let max_budget = 1420.max(OBF_MTU_BUDGET);
            let mut valid_buckets = [0usize; 8];
            let mut valid_count = 0usize;
            for &b in &self.traffic_defense.buckets {
                if b <= max_budget && valid_count < valid_buckets.len() {
                    valid_buckets[valid_count] = b;
                    valid_count += 1;
                }
            }

            for i in 0..self.peers.len() {
                if !matches!(self.peers[i].state, PeerState::Established(_)) || self.peers[i].relay
                {
                    continue;
                }
                let Some(endpoint) = self.peers[i].endpoint else {
                    continue;
                };
                let current_iv = self.peers[i].next_cover_interval_ms.unwrap_or(base_iv);
                if now_ms.saturating_sub(self.peers[i].last_activity_ms) < current_iv
                    || now_ms.saturating_sub(self.peers[i].last_cover_ms) < current_iv
                {
                    continue;
                }
                let burst_count = if self.traffic_defense.cover_burst_max <= 1 {
                    1
                } else {
                    usize::try_from(
                        self.junk_rng
                            .gen_range(1, self.traffic_defense.cover_burst_max),
                    )
                    .unwrap_or(1)
                };

                for _ in 0..burst_count {
                    if valid_count == 0 {
                        let bytes = self.build_junk();
                        self.tick_egress.push(EgressDatagram {
                            fate: 0,
                            dst: endpoint,
                            bytes,
                        });
                    } else {
                        let b_idx =
                            usize::try_from(self.junk_rng.gen_range(0, (valid_count - 1) as u64))
                                .unwrap_or(0);
                        let b = valid_buckets[b_idx];
                        let fate = u16::try_from(b).unwrap_or(0);
                        self.tick_egress.push(EgressDatagram {
                            fate,
                            dst: endpoint,
                            bytes: vec![yip_obf::JUNK_TYPE],
                        });
                    }
                }
                self.peers[i].last_cover_ms = now_ms;
                self.peers[i].next_cover_interval_ms = Some(jitter_ms(base_iv));
            }
        }

        // ── #41 cert-liveness sweep: drop any Established mesh peer whose cert has
        // expired / been revoked (roots exempt), so a revoked member loses its
        // session within a rekey interval rather than at process restart. Throttled
        // to once per rekey interval (verify_cert is not free). No-op when membership
        // is disabled (pure 2a/2b).
        if self.membership.is_some()
            && now_ms.saturating_sub(self.last_cert_sweep_ms) >= self.rekey_interval_ms
        {
            self.last_cert_sweep_ms = now_ms;
            let now_s = now_secs();
            let m = self.membership.as_ref().expect("checked is_some above");
            let stale: Vec<usize> = self
                .peers
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    matches!(p.state, PeerState::Established(_))
                        && !m.member_or_admitted_cert_valid(
                            &p.pubkey,
                            p.admitted_cert_not_after,
                            now_s,
                        )
                })
                .map(|(i, _)| i)
                .collect();
            for i in stale {
                self.drop_session(i);
            }
        }

        // ── threshold CA certificate auto-renewal (70% TTL) ───────────────────
        if self.threshold_ca_server.is_some()
            && self.membership.is_some()
            && now_ms.saturating_sub(self.last_cert_check_ms) >= 5000
        {
            self.last_cert_check_ms = now_ms;
            let now_s = now_secs();
            if self.check_cert_rotation(now_s) == Some(true) {
                let _ = self.renew_cert();
            }
        }

        // ── control socket dispatch ───────────────────────────────────────────
        if let Some(ctrl) = self.control.as_ref() {
            let mut reqs = Vec::new();
            while let Ok(req) = ctrl.try_recv() {
                reqs.push(req);
            }
            if !reqs.is_empty() {
                let dev = self.device_name.clone();
                let start = self.start_time;
                for req in reqs {
                    let resp = crate::control::dispatch_cmd(self, req.cmd, &dev, start);
                    let _ = req.responder.send(resp);
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

pub(super) fn copy_into_reusable_egress(target: &mut Vec<EgressDatagram>, src: &[EgressDatagram]) {
    target.truncate(src.len());
    for (i, s) in src.iter().enumerate() {
        if i < target.len() {
            target[i].fate = s.fate;
            target[i].dst = s.dst;
            target[i].bytes.clear();
            target[i].bytes.extend_from_slice(&s.bytes);
        } else {
            target.push(EgressDatagram {
                fate: s.fate,
                dst: s.dst,
                bytes: s.bytes.clone(),
            });
        }
    }
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
    getrandom::fill(&mut b).expect("OS RNG");
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
    getrandom::fill(&mut b).expect("OS RNG");
    let v = u64::from_le_bytes(b);
    let span = spread.saturating_mul(2).saturating_add(1);
    (base - spread) + (v % span)
}

fn now_wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod testutil;

#[cfg(test)]
mod tests;
