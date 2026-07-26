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

mod gossip;
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
    /// MONOTONIC milliseconds at which `tick_dispatch` last ran the #41 cert-
    /// liveness sweep (see there). `0` until the first sweep; throttles the
    /// sweep to at most once per `rekey_interval_ms`, since each swept peer
    /// costs an Ed25519 `verify_cert` and `tick` can run far more often than
    /// that on the busy-poll path.
    last_cert_sweep_ms: u64,
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
            reg_seq: 0,
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
            last_cert_sweep_ms: 0,
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

    // ── rendezvous / path helpers ─────────────────────────────────────────

    /// The configured rendezvous server address (only meaningful when a
    /// rendezvous is configured; falls back to the unspecified address).
    fn server_addr(&self) -> SocketAddr {
        self.rendezvous
            .as_ref()
            .map(|r| r.server_addr())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
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
        let cert = self
            .membership
            .as_ref()
            .map(Membership::own_cert_bytes)
            .unwrap_or_default();
        // #34: frame the msg1 payload as [ts || cert] so the responder can
        // reject stale replays (Task 3 adds the freshness gate; this task
        // only establishes the wire format).
        let payload = crate::handshake::frame_init_payload(&cert);
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
            via_relay,
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

    /// Whether a handshake `payload` carries a cert that admits the peer whose
    /// static key is `peer_pub`. With membership disabled the payload is
    /// ignored (returns `true` — byte-identical to 2a/2b). With membership
    /// enabled the payload must decode to a `Cert` that `verify_cert`s against
    /// `peer_pub` at the current wall clock.
    ///
    /// Named for its original use — the initiator checking the responder's
    /// msg2 cert — but the check is symmetric and this branch also invokes it
    /// against the *initiator's* msg1 cert: the #41 rekey re-verify and
    /// re-admission gate (`is_root`-exempt) pass the initiator's cert +
    /// `remote_static`. Roots are exempted by the caller (`is_root`), not here.
    fn responder_cert_ok(&self, payload: &[u8], peer_pub: [u8; 32]) -> bool {
        match self.membership.as_ref() {
            None => true,
            Some(m) => Cert::decode(payload)
                .is_some_and(|cert| m.verify_cert(&cert, &peer_pub, now_secs())),
        }
    }

    /// Whether `pk` is an always-admit root (in the signed root set). Roots are
    /// exempt from cert-based revocation — they are trusted via the root set, not
    /// a member cert (revoke a root by removing it from the root set). `false`
    /// when membership is disabled.
    fn is_root(&self, pk: [u8; 32]) -> bool {
        self.membership
            .as_ref()
            .is_some_and(|m| m.roots().iter().any(|(rpk, _)| *rpk == pk))
    }

    /// #34 anti-replay: whether `ts` is strictly newer than the greatest
    /// label we have accepted in a session-building Init from peer `idx` (or
    /// this is the first such Init). Gates both session rebuild/rekey
    /// (`rekey_init_core`) and endpoint learning (the cold-start establish
    /// arms of `handle_handshake_init`/`relayed_handshake_init`).
    /// Retransmit/`cached_resp` paths do NOT call this — they replay
    /// idempotently without a freshness check (see `rekey_init_core`'s
    /// dedup cases 1/2).
    ///
    /// On refusal this logs a single-line stderr marker (same bare
    /// `eprintln!` convention as this file's other handshake-rejection
    /// notices, e.g. "peer_manager: relayed responder cert rejected") so a
    /// black-box observer (the netns money tests) can confirm a replay was
    /// actually refused here rather than by some other gate. The marker
    /// carries no packet contents and changes no wire format — the ts still
    /// rides only inside the encrypted msg1 payload.
    fn accept_fresh_init(&self, idx: usize, ts: &[u8; 12]) -> bool {
        match self.peers[idx].last_accepted_init_ts {
            None => true,
            Some(last) => {
                let fresh = *ts > last;
                if !fresh {
                    eprintln!("peer_manager: stale/replayed Init refused (freshness gate)");
                }
                fresh
            }
        }
    }

    /// Tear down a peer's live session: remove every `conn_tag` it holds
    /// (current + any in-flight `next` + grace `previous`) from `by_tag`, and
    /// revert the peer to `Idle`. Idempotent for a non-Established peer.
    /// Re-admission is guarded by the cold-start cert check, so a revoked
    /// peer cannot re-establish.
    fn drop_session(&mut self, idx: usize) {
        let tags: Vec<u64> = if let PeerState::Established(epochs) = &self.peers[idx].state {
            let mut t = vec![epochs.current.conn_tag()];
            if let Some(n) = epochs.next.as_ref() {
                t.push(n.dp.conn_tag());
            }
            if let Some(p) = epochs.previous.as_ref() {
                t.push(p.conn_tag());
            }
            t
        } else {
            Vec::new()
        };
        for tag in tags {
            self.by_tag.remove(&tag);
        }
        self.peers[idx].state = PeerState::Idle;
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

        // #34: the msg1 payload is [ts || cert]. Split the anti-replay label
        // off; the cert remainder is what admission checks. Too short to hold
        // the label ⇒ malformed ⇒ fail closed.
        let Some((init_ts, initiator_cert)) =
            crate::handshake::parse_init_payload(&initiator_payload)
        else {
            return DispatchOut::None;
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
                    Cert::decode(initiator_cert)
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
            // `PeerManager::accept_fresh_init` (#34) is the discriminator: a
            // rekey Init's `ts` must be strictly newer than the greatest
            // label we have ever accepted from this peer, else it is (a) — a
            // retransmit/replay/backwards-clock peer — handled by
            // `handle_rekey_init`'s cached-resp dedup (case 1/2) when it IS a
            // retransmit, or silently dropped otherwise. `handle_rekey_init`
            // owns the (b) path.
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
                // #41: a mid-session rekey Init must carry a currently-valid cert
                // (mesh mode). A revoked/expired member presenting a stale cert
                // loses its session within a rekey interval instead of at process
                // restart.
                if !self.is_root(remote_static)
                    && !self.responder_cert_ok(initiator_cert, remote_static)
                {
                    self.drop_session(idx);
                    return DispatchOut::None;
                }
                let init_eph = crate::handshake::init_ephemeral(dg).expect(
                    "start_responder already parsed dg's msg1; its leading 32 bytes are `e`",
                );
                self.handle_rekey_init(idx, src, established, resp_pkt, init_ts, init_eph)
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
                // #41: re-admission gate. A tabled mesh peer re-establishing
                // (its session was dropped by the rekey re-verify or the
                // liveness sweep) must present a currently-valid cert, else a
                // revoked member reconnects by static-key match (flapping, not
                // revocation). Always-admit ROOTS are exempt (as in the #41
                // sweep). No-op for pure 2a/2b: `responder_cert_ok` returns
                // `true` when membership is `None`.
                if !self.is_root(remote_static)
                    && !self.responder_cert_ok(initiator_cert, remote_static)
                {
                    return DispatchOut::None;
                }
                // #34: gate endpoint learning on a fresh accept. A cold-start
                // (Idle) peer's first-ever Init is always fresh
                // (`last_accepted_init_ts` is `None`); a peer that reached
                // `Idle` again after `drop_session` (revocation/liveness/
                // give-up) still remembers the greatest label it ever
                // accepted, so a replayed OLD Init cannot resurrect it and
                // hijack `endpoint` toward a spoofed source.
                if !self.accept_fresh_init(idx, &init_ts) {
                    return DispatchOut::None;
                }
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
                self.peers[idx].last_accepted_init_ts = Some(init_ts);
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
                if !self.is_root(self.peers[idx].pubkey)
                    && !self.responder_cert_ok(&responder_payload, self.peers[idx].pubkey)
                {
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
            // Mesh mode (membership configured): mint a fresh signed
            // registration record at the current `reg_seq` so the server can
            // verify authenticity instead of trusting an unauthenticated
            // `counter` (#37 Task 5). Non-mesh keeps the legacy `Register`.
            let signed = self
                .membership
                .as_ref()
                .map(|m| m.sign_registration(self.reg_seq));
            self.reg_seq = self.reg_seq.saturating_add(1);
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
                        && !m.member_cert_valid(&p.pubkey, now_s)
                })
                .map(|(i, _)| i)
                .collect();
            for i in stale {
                self.drop_session(i);
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
mod testutil;

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::handshake::Established;
    use crate::wire_glue::derive_wire_keys;
    use yip_crypto::{generate_keypair, Handshake};

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
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &stranger.private,
            &local_kp.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();

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

    #[test]
    fn stale_replayed_init_is_rejected_and_endpoint_unchanged() {
        // #34: an Established peer that already accepted an Init at ts T1
        // must reject a NEW-ephemeral Init carrying an OLDER ts T0 < T1 —
        // even from a SPOOFED source address — as a silent drop: `current`
        // untouched, the learned `endpoint` untouched, `last_accepted_init_ts`
        // untouched.
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.30:3000".parse().unwrap();
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
        pm_r.rekey_interval_ms = 100;

        let t1 = crate::handshake::now_tai64n();
        let (_hs1, init_pkt_1) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &init_payload_with_ts(t1, &[]),
        )
        .unwrap();
        let resp1 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt_1, 0));
        assert_eq!(resp1.len(), 1, "first fresh Init must establish");
        let tag1 = established_tag(&pm_r, 0).unwrap();
        assert_eq!(pm_r.peers[0].endpoint, Some(ep_i));
        assert_eq!(pm_r.peers[0].last_accepted_init_ts, Some(t1));

        // A NEW-ephemeral Init (distinct from init_pkt_1) carrying an OLDER
        // ts, arriving from a spoofed source, routes through the Established
        // (rekey) arm — `rekey_init_core`'s freshness gate must drop it.
        let t0 = older_ts(t1);
        let (_hs2, init_pkt_2) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &init_payload_with_ts(t0, &[]),
        )
        .unwrap();
        let spoofed: SocketAddr = "203.0.113.66:6".parse().unwrap();
        match pm_r.on_udp(spoofed, &init_pkt_2, 100) {
            DispatchOut::None => {}
            _ => panic!("a stale-ts new-ephemeral Init must be silently dropped"),
        }
        assert_eq!(
            established_tag(&pm_r, 0),
            Some(tag1),
            "current must be untouched by a rejected Init"
        );
        assert_eq!(
            pm_r.peers[0].endpoint,
            Some(ep_i),
            "endpoint must not change on a rejected Init"
        );
        assert_eq!(
            pm_r.peers[0].last_accepted_init_ts,
            Some(t1),
            "last_accepted_init_ts must not change on a rejected Init"
        );
    }

    #[test]
    fn fresh_new_ephemeral_init_rebuilds_and_relearns_endpoint() {
        // #34: a peer that was Established, got dropped back to `Idle` (e.g.
        // a #41 cert-revocation sweep or the liveness sweep), but still
        // remembers the greatest ts it ever accepted, correctly REBUILDS on
        // a genuinely fresh-ts cold-start Init: new epoch, endpoint relearned
        // from the new source, `last_accepted_init_ts` advances — while the
        // old session's `by_tag` entry (evicted at drop time) stays gone.
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.31:3100".parse().unwrap();
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

        let t1 = crate::handshake::now_tai64n();
        let (_hs1, init_pkt_1) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &init_payload_with_ts(t1, &[]),
        )
        .unwrap();
        let resp1 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt_1, 0));
        assert_eq!(resp1.len(), 1);
        let old_tag = established_tag(&pm_r, 0).unwrap();
        assert!(pm_r.by_tag.contains_key(&old_tag));

        // Drop the session: reverts to Idle, evicts by_tag — but
        // `last_accepted_init_ts` is in-memory and survives (never reset by
        // `drop_session`).
        pm_r.drop_session(0);
        assert!(matches!(pm_r.peers[0].state, PeerState::Idle));
        assert!(
            !pm_r.by_tag.contains_key(&old_tag),
            "drop_session must evict the old tag"
        );
        assert_eq!(
            pm_r.peers[0].last_accepted_init_ts,
            Some(t1),
            "last_accepted_init_ts survives drop_session"
        );

        // A genuinely fresh-ts NEW-ephemeral cold-start Init from a NEW
        // source address rebuilds the session.
        let t2 = newer_ts(t1);
        let new_src: SocketAddr = "10.0.0.32:3200".parse().unwrap();
        let (_hs2, init_pkt_2) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &init_payload_with_ts(t2, &[]),
        )
        .unwrap();
        let resp2 = resp_bytes(&pm_r.on_udp(new_src, &init_pkt_2, 200));
        assert_eq!(
            resp2.len(),
            1,
            "a fresh-ts cold-start Init must rebuild the session"
        );
        let new_tag = established_tag(&pm_r, 0).unwrap();
        assert_ne!(new_tag, old_tag);
        assert!(pm_r.by_tag.contains_key(&new_tag));
        assert!(
            !pm_r.by_tag.contains_key(&old_tag),
            "the old tag must stay evicted"
        );
        assert_eq!(
            pm_r.peers[0].endpoint,
            Some(new_src),
            "endpoint must be relearned from the new source"
        );
        assert_eq!(
            pm_r.peers[0].last_accepted_init_ts,
            Some(t2),
            "last_accepted_init_ts must advance to the new label"
        );
    }

    #[test]
    fn stale_replayed_cold_start_init_does_not_hijack_endpoint() {
        // #34 hijack fix, defensive direction: the sibling of
        // `fresh_new_ephemeral_init_rebuilds_and_relearns_endpoint`. A peer
        // that was Established (endpoint learned = `ep_i`), dropped back to
        // `Idle`, still remembers `last_accepted_init_ts = t1`. A captured
        // OLD Init (or any new-ephemeral Init with ts <= t1) replayed from a
        // SPOOFED source must be rejected by the `Idle` arm's
        // `accept_fresh_init` guard BEFORE it ever reaches the
        // `endpoint = Some(src)` line — proving the guard actually gates
        // endpoint learning, not just session admission. Without Step 3's
        // gate, this scenario would silently redirect the peer's `endpoint`
        // to the attacker's spoofed address.
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.34:3400".parse().unwrap();
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

        let t1 = crate::handshake::now_tai64n();
        let (_hs1, init_pkt_1) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &init_payload_with_ts(t1, &[]),
        )
        .unwrap();
        let resp1 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt_1, 0));
        assert_eq!(resp1.len(), 1);
        assert_eq!(pm_r.peers[0].endpoint, Some(ep_i));

        pm_r.drop_session(0);
        assert!(matches!(pm_r.peers[0].state, PeerState::Idle));
        assert_eq!(pm_r.peers[0].last_accepted_init_ts, Some(t1));

        // A NEW-ephemeral Init with ts <= t1, replayed from an attacker's
        // SPOOFED source address (not `ep_i`).
        let t0 = older_ts(t1);
        let (_hs2, init_pkt_2) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &init_payload_with_ts(t0, &[]),
        )
        .unwrap();
        let spoofed: SocketAddr = "203.0.113.77:7".parse().unwrap();
        match pm_r.on_udp(spoofed, &init_pkt_2, 200) {
            DispatchOut::None => {}
            _ => panic!("a stale-ts cold-start Init must be silently dropped"),
        }
        assert!(
            matches!(pm_r.peers[0].state, PeerState::Idle),
            "a rejected cold-start Init must not admit a session"
        );
        assert_eq!(
            pm_r.peers[0].endpoint,
            Some(ep_i),
            "endpoint must NOT be hijacked toward the spoofed source"
        );
        assert_eq!(
            pm_r.peers[0].last_accepted_init_ts,
            Some(t1),
            "last_accepted_init_ts must not change on a rejected Init"
        );
        assert!(
            pm_r.by_tag.is_empty(),
            "no session (hence no conn_tag) must have been admitted"
        );
    }

    #[test]
    fn retransmit_still_replays_cached_resp_regardless_of_ts() {
        // #34: a retransmit of the SAME Init (identical ephemeral == identical
        // ts) is recognized by the pre-existing `cached_resp_init_eph` dedup
        // — checked BEFORE the ts freshness gate — so it still replays
        // `cached_resp` verbatim and never rejects or mutates `endpoint`/
        // `last_accepted_init_ts`, even though its ts is NOT strictly newer
        // than itself (retransmit != rebuild).
        let kp_r = generate_keypair();
        let kp_i = generate_keypair();
        let ep_i: SocketAddr = "10.0.0.33:3300".parse().unwrap();
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

        let t1 = crate::handshake::now_tai64n();
        let (_hs1, init_pkt) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &init_payload_with_ts(t1, &[]),
        )
        .unwrap();
        let resp1 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt, 0));
        assert_eq!(resp1.len(), 1);
        let tag1 = established_tag(&pm_r, 0).unwrap();

        // Retransmit: EXACT same bytes (same ephemeral, same ts), delivered
        // much later.
        let resp2 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt, 500));
        assert_eq!(
            resp2, resp1,
            "a retransmit must resend the cached Resp verbatim"
        );
        assert_eq!(
            established_tag(&pm_r, 0),
            Some(tag1),
            "current must be untouched by a retransmit"
        );
        assert_eq!(pm_r.peers[0].endpoint, Some(ep_i));
        assert_eq!(
            pm_r.peers[0].last_accepted_init_ts,
            Some(t1),
            "last_accepted_init_ts must not change on a retransmit"
        );
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
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();

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

    /// #34 Task 4: retires #36's ephemeral-preservation hack. A path
    /// re-target of an in-flight `Handshaking` attempt now sends a FRESH
    /// Init (new ephemeral, drawn by `begin_handshake` off a fresh
    /// `Idle` state) instead of resending the old `init_pkt` — the inverse
    /// of the removed `retarget_handshake_preserves_ephemeral_and_flips_relay`.
    /// The old #36 concern (a fresh ephemeral orphans the responder's
    /// `cached_resp`) is resolved on the responder side instead: it REBUILDS
    /// on a fresh new-ephemeral relayed Init (see
    /// `direct_established_responder_adopts_relay_on_fresh_relayed_init_and_rebuilds`),
    /// so preserving the ephemeral here is no longer necessary.
    #[test]
    fn path_switch_sends_fresh_init_and_responder_rebuilds() {
        // A peer mid-handshake toward a direct candidate.
        let (mut pm, idx) = pm_handshaking_direct_peer([7u8; 32], "10.0.0.9:9000", 100);
        let (orig_init, orig_target) = match &pm.peers[idx].state {
            PeerState::Handshaking(h) => (h.init_pkt.clone(), h.target),
            _ => panic!("peer must be Handshaking"),
        };
        let orig_eph =
            crate::handshake::init_ephemeral(&orig_init).expect("valid Init carries an ephemeral");
        let server = pm.server_addr();

        // Re-target to the relay (Punch->Relay escalation): the #34 arm resets
        // to `Idle` (clearing `endpoint`, anti-mismatch) and calls
        // `begin_handshake`, exactly like the production `PathAction::Relay`
        // arm in `tick_dispatch`.
        pm.peers[idx].state = PeerState::Idle;
        pm.peers[idx].endpoint = None;
        let out = pm
            .begin_handshake(idx, server, true, 5_000)
            .expect("emits an Init");

        // A FRESH ephemeral is drawn — NOT the byte-identical resend #36 used to do.
        match &pm.peers[idx].state {
            PeerState::Handshaking(h) => {
                let new_eph = crate::handshake::init_ephemeral(&h.init_pkt)
                    .expect("valid Init carries an ephemeral");
                assert_ne!(
                    new_eph, orig_eph,
                    "path switch must draw a FRESH ephemeral, not resend the old Init (#34 inverts #36)"
                );
                assert_eq!(h.target, server, "target must update to the new path");
                assert_ne!(h.target, orig_target);
            }
            _ => panic!("peer must be Handshaking again after the fresh begin_handshake"),
        }
        assert!(
            pm.peers[idx].relay,
            "relay flag must be set for a relay re-target"
        );
        assert!(
            pm.peers[idx].endpoint.is_none(),
            "relay re-target clears endpoint (anti-mismatch)"
        );
        // The emitted datagram is the relay-wrapped Init (a RelaySend), carrying the NEW ephemeral.
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
                record: None,
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

    /// #37 Task 5: a `PeerCandidate` carrying a record that VERIFIES against
    /// our membership roots is accepted — the candidate is set and a
    /// subsequent tick probes it with a handshake `Init`, exactly like the
    /// no-record (`peer_candidate_then_tick_probes_candidate_with_init`)
    /// case above.
    #[test]
    fn peer_candidate_with_valid_signed_record_is_accepted_and_probed() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let membership = membership_trusting_ca_via_roots(&ca, local.public);
        let (mut pm, _sent) = pm_with_mock_rdv_and_membership(&local, &[peer], membership);

        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let valid_rec = mk_record(&ca, 55, peer_kp.public, vec![candidate], 1);
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
                record: Some(valid_rec),
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));
        assert_eq!(
            pm.peers[0].path.candidate(),
            Some(candidate),
            "a validly-signed record must set the candidate"
        );

        let out = pm.tick(1).map(<[_]>::to_vec).unwrap_or_default();
        let init = out
            .iter()
            .find(|d| d.dst == candidate)
            .expect("a handshake Init is emitted toward the verified candidate");
        assert_eq!(
            init.bytes[0],
            PacketType::HandshakeInit as u8,
            "the datagram to the candidate is a handshake Init"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));
    }

    /// #37 Task 5: a `PeerCandidate` carrying a record that FAILS
    /// `verify_record` (signed by a CA outside our membership roots — a
    /// forged/foreign record) must be DROPPED: no candidate is set and no
    /// probe is ever sent toward it, even after a tick. This is the
    /// discriminating half of the pair — it genuinely rejects, it doesn't
    /// just happen to also pass.
    #[test]
    fn peer_candidate_with_invalid_record_is_dropped_no_probe() {
        let ca = test_ca();
        let foreign_ca = SigningKey::from_bytes(&[177u8; 32]); // NOT in this membership's roots
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let membership = membership_trusting_ca_via_roots(&ca, local.public);
        let (mut pm, _sent) = pm_with_mock_rdv_and_membership(&local, &[peer], membership);

        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        // Signed under `foreign_ca`, not the trusted `ca` — a forged record
        // claiming to be `peer_kp`'s.
        let forged = mk_record(&foreign_ca, 55, peer_kp.public, vec![candidate], 1);
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
                record: Some(forged),
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));
        assert_eq!(
            pm.peers[0].path.candidate(),
            None,
            "an unverifiable record must NOT set the candidate"
        );

        let out = pm.tick(1).map(<[_]>::to_vec).unwrap_or_default();
        assert!(
            !out.iter().any(|d| d.dst == candidate),
            "no probe may be sent toward a candidate carrying an unverifiable record"
        );
        assert!(
            matches!(pm.peers[0].state, PeerState::Idle),
            "the peer must stay Idle: the forged candidate was never acted on"
        );
    }

    #[test]
    fn peer_candidate_with_valid_record_for_wrong_node_is_dropped() {
        // A record can be a GENUINE, trusted-CA member record and still be the
        // wrong one: the server answered Lookup(peer) with a valid record that
        // belongs to some OTHER member. `verify_record` passes it (it's real),
        // so the node_id binding is what must drop it.
        let ca = test_ca();
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let other_kp = generate_keypair(); // a different, validly-certed member
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let membership = membership_trusting_ca_via_roots(&ca, local.public);
        let (mut pm, _sent) = pm_with_mock_rdv_and_membership(&local, &[peer], membership);

        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        // Validly signed by the TRUSTED ca — but for `other_kp`, not `peer_kp`.
        let wrong_id = mk_record(&ca, 55, other_kp.public, vec![candidate], 1);
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
                record: Some(wrong_id),
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));
        assert_eq!(
            pm.peers[0].path.candidate(),
            None,
            "a valid record binding a DIFFERENT identity must NOT set the candidate",
        );
        let out = pm.tick(1).map(<[_]>::to_vec).unwrap_or_default();
        assert!(
            !out.iter().any(|d| d.dst == candidate),
            "no probe toward a candidate whose record binds a different identity",
        );
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
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
                record: None,
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

    /// (e') #116 regression: the punch->relay retarget must draw a FRESH
    /// ephemeral even when `relay` was ALREADY set (by an inbound relayed packet
    /// from the peer, `on_relayed`) before our own escalation timer fired. The
    /// pre-fix escalation arm was gated on `!peers[i].relay`, so if that race
    /// went the other way the arm was skipped and the retransmit arm re-wrapped
    /// the SAME punch ephemeral over the relay — preserving it, reproducing the
    /// pre-#36-inversion behavior the freshness gate (#34) exists to close. This
    /// is the intermittent `DISTINCT_INIT_EPHEMERALS=1` failure of
    /// run-netns-pathswitch-rehandshake.sh. Fails against the pre-fix code.
    #[test]
    fn punch_relay_retarget_draws_fresh_ephemeral_even_if_relay_flag_preset() {
        use crate::path::PUNCH_MS;
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None, // rendezvous-only: starts in the Punching stage
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[peer]);

        // Learn a reflexive candidate and tick into Handshaking on the punch
        // probe (dst = candidate), holding punch ephemeral E1.
        let candidate: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let mut buf = Vec::new();
        yip_rendezvous::encode(
            &yip_rendezvous::Message::PeerInfo {
                node: node_id(&peer_kp.public),
                reflexive: candidate,
                record: None,
            },
            &mut buf,
        );
        assert!(matches!(
            pm.on_udp(mock_server(), &buf, 0),
            DispatchOut::None
        ));
        let out = pm.tick(1).map(<[_]>::to_vec).unwrap_or_default();
        let punch_init = out
            .iter()
            .find(|d| {
                d.dst == candidate && d.bytes.first() == Some(&(PacketType::HandshakeInit as u8))
            })
            .expect("punch Init is probed toward the candidate");
        let e1 = crate::handshake::init_ephemeral(&punch_init.bytes).expect("E1 ephemeral");
        assert!(matches!(pm.peers[0].state, PeerState::Handshaking(_)));

        // RACE: a relayed packet from the peer arrives BEFORE our punch->relay
        // escalation timer fires, flipping `relay = true` while we still hold the
        // punch ephemeral E1 (models `on_relayed`'s non-Established relay-adopt).
        pm.peers[0].relay = true;

        // Escalate just past the punch window. The relay-wrapped Init MUST carry
        // a fresh ephemeral E2 != E1, not a re-wrapped retransmit of E1.
        let out = pm.tick(PUNCH_MS + 2).map(<[_]>::to_vec).unwrap_or_default();
        let relay_init = out
            .iter()
            .find_map(|d| {
                if d.dst != mock_server() {
                    return None;
                }
                match yip_rendezvous::decode(&d.bytes) {
                    Some(yip_rendezvous::Message::RelaySend { payload, .. })
                        if payload.first() == Some(&(PacketType::HandshakeInit as u8)) =>
                    {
                        Some(payload)
                    }
                    _ => None,
                }
            })
            .expect("a relay-wrapped Init is emitted on escalation");
        let e2 = crate::handshake::init_ephemeral(&relay_init).expect("E2 ephemeral");
        assert_ne!(
            e1, e2,
            "punch->relay retarget must draw a FRESH ephemeral even when the relay \
             flag was preset by an inbound relayed packet — a preserved punch \
             ephemeral reopens the #34 downgrade (issue #116)"
        );

        // No churn: now that the in-flight Init IS a relay Init (via_relay), the
        // NEXT tick past the retry interval must RETRANSMIT E2 (same ephemeral),
        // not draw yet another fresh E3 — the escalation arm must not re-fire on a
        // handshake already on the relay.
        let out = pm
            .tick(PUNCH_MS + 2 + HANDSHAKE_RETRY_MS + 1)
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        let relay_retx = out
            .iter()
            .find_map(|d| {
                if d.dst != mock_server() {
                    return None;
                }
                match yip_rendezvous::decode(&d.bytes) {
                    Some(yip_rendezvous::Message::RelaySend { payload, .. })
                        if payload.first() == Some(&(PacketType::HandshakeInit as u8)) =>
                    {
                        Some(payload)
                    }
                    _ => None,
                }
            })
            .expect("a relay-wrapped Init retransmit is emitted");
        let e3 = crate::handshake::init_ephemeral(&relay_retx).expect("retransmit ephemeral");
        assert_eq!(
            e2, e3,
            "a relay Init already in flight must be RETRANSMITTED (same ephemeral), \
             not re-escalated into a fresh ephemeral every tick"
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
                record: None,
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
                record: None,
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
            let (_hs, init_pkt) = HandshakeState::start_initiator(
                &stranger.private,
                &local.public,
                &crate::handshake::frame_init_payload(&cert_bytes),
            )
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
            let (_hs, init_pkt) = HandshakeState::start_initiator(
                &stranger.private,
                &local.public,
                &crate::handshake::frame_init_payload(&[]),
            )
            .unwrap();
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
            let (_hs, init_pkt) = HandshakeState::start_initiator(
                &stranger.private,
                &local.public,
                &crate::handshake::frame_init_payload(&cert_bytes),
            )
            .unwrap();
            assert!(matches!(pm.on_udp(src, &init_pkt, 0), DispatchOut::None));
            assert!(pm.peers.is_empty(), "untrusted-CA cert ⇒ no admission");
            assert!(pm.by_tag.is_empty());
        }
    }

    /// #34 Task 2: the msg1 payload is now `[ts || cert]`. A properly framed
    /// Init (built via `frame_init_payload`, exactly as the real initiator's
    /// `begin_handshake`/`drive_rekey_schedule` now do) still recovers the
    /// cert remainder after the responder strips the 12-byte ts label, and
    /// admits/establishes exactly as before the wire format changed.
    ///
    /// The negative counterpart proves the framing is actually enforced on
    /// the consume side, not merely a no-op: an Init carrying a RAW cert with
    /// NO ts prefix (the pre-#34 wire format) no longer admits, because the
    /// responder's parse consumes the cert's own leading 12 bytes as the ts
    /// label, corrupting the cert remainder handed to `Cert::decode`.
    #[test]
    fn framed_init_payload_still_establishes_and_admits_by_cert() {
        let ca = test_ca();
        let local = generate_keypair();
        let src: SocketAddr = "203.0.113.5:5".parse().unwrap();

        let stranger = generate_keypair();
        let stranger_sign = SigningKey::from_bytes(&[220u8; 32]);
        let cert = mk_cert(
            &ca,
            stranger.public,
            stranger_sign.verifying_key().to_bytes(),
        );
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);

        // ── properly framed [ts || cert] → admitted + establishes ──
        {
            let mut pm = PeerManager::new(
                local.private,
                local.public,
                &[],
                TunnelMode::L3Tun,
                None,
                Some(membership_for(&ca, local.public)),
                false,
            );
            let framed = crate::handshake::frame_init_payload(&cert_bytes);
            let (_hs, init_pkt) =
                HandshakeState::start_initiator(&stranger.private, &local.public, &framed).unwrap();

            let replies = resp_bytes(&pm.on_udp(src, &init_pkt, 0));
            assert_eq!(
                replies.len(),
                1,
                "a framed [ts || cert] Init is admitted and replied to"
            );
            assert_eq!(pm.peers.len(), 1, "the cert-verified member was admitted");
            assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
        }

        // ── raw (unframed) cert, no ts prefix → NOT admitted ──
        {
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
                HandshakeState::start_initiator(&stranger.private, &local.public, &cert_bytes)
                    .unwrap();
            assert!(
                matches!(pm.on_udp(src, &init_pkt, 0), DispatchOut::None),
                "an unframed raw-cert Init must no longer admit: the responder mis-reads \
                 its leading 12 bytes as the ts label, corrupting the cert remainder"
            );
            assert!(pm.peers.is_empty(), "no admission from an unframed payload");
            assert!(pm.by_tag.is_empty());
        }
    }

    /// A rekey Init whose payload is NOT a currently-valid cert (mesh mode)
    /// must drop the session (revert to `Idle`, purge `by_tag`, no reply)
    /// instead of completing the rekey — else a revoked/expired member keeps
    /// its live session until process restart (#41).
    #[test]
    fn rekey_init_with_invalid_cert_drops_session() {
        // Mesh Established peer; `rekey_init_with_payload` crafts each rekey
        // Init with a real, later `now_tai64n()` ts, so #34's freshness gate
        // admits it regardless of `interval_ms`.
        let (mut pm, tag) =
            pm_mesh_established_peer([5u8; 32], [6u8; 32], /*age past interval/2*/ 100_000);
        assert_eq!(established_tag(&pm, 0), Some(tag));

        // A rekey Init from that peer carrying an INVALID cert payload (membership on).
        let init = rekey_init_with_payload(&pm, 0, /*payload=*/ b"not-a-valid-cert");
        let out = match pm.on_udp(peer_src(&pm, 0), &init, 200_000) {
            DispatchOut::Udp(e) | DispatchOut::Both(_, e) => Some(e),
            _ => None,
        }
        .map(<[EgressDatagram]>::to_vec);

        // Session dropped: Idle, by_tag entry gone, no resp emitted.
        assert!(
            matches!(pm.peers[0].state, PeerState::Idle),
            "invalid-cert rekey drops the session"
        );
        assert!(
            !pm.by_tag.values().any(|&i| i == 0),
            "the peer's conn_tag is removed from by_tag"
        );
        assert!(
            out.is_none_or(|o| o.is_empty()),
            "no resp for a revoked rekey"
        );
    }

    /// Control for the test above: a VALID cert on the rekey Init still
    /// rekeys normally — the #41a guard must be a no-op on the legitimate
    /// path.
    #[test]
    fn rekey_init_with_valid_cert_still_rekeys() {
        let (mut pm, tag) = pm_mesh_established_peer([5u8; 32], [6u8; 32], 100_000);
        let init = rekey_init_with_payload(&pm, 0, &valid_cert_bytes(&pm, 0));
        let out = pm.on_udp(peer_src(&pm, 0), &init, 200_000);
        let resp = resp_bytes(&out);
        assert_eq!(
            resp.len(),
            1,
            "a genuine rekey Init with a valid cert must produce a Resp, proving the \
             rekey actually proceeded rather than merely not dropping"
        );
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag),
            "current stays on the OLD epoch until the initiator confirms (9a Task 4)"
        );
        match &pm.peers[0].state {
            PeerState::Established(epochs) => assert!(
                epochs.next.is_some(),
                "the valid-cert rekey Init installed a next epoch"
            ),
            _ => panic!("valid cert rekeys, no drop"),
        }
    }

    // ── #41(c)/Task 2b: re-admission gate on cold-start establishment ──────
    //
    // Closes the third piece of #41: a revoked (cert-expired, non-renewed)
    // mesh member whose session was dropped (by the rekey re-verify above, or
    // the future liveness sweep) stays TABLED in `self.peers`, just `Idle`.
    // Before this gate, `handle_handshake_init`'s tabled-lookup
    // (`Some(i) => i`) admitted it back in by static-key match alone — only
    // the `None`/new-peer path verified a cert — so a revoked member could
    // flap back in on every cold-start retry instead of staying revoked.

    /// A TABLED mesh peer whose live session was dropped is `Idle` but still
    /// present by static-key match. Its next cold-start Init, carrying an
    /// EXPIRED cert, must NOT be re-admitted: no session, no reply, state
    /// stays `Idle`. Drives the real dispatch path (`on_udp` ->
    /// `handle_handshake_init`).
    #[test]
    fn revoked_tabled_peer_cold_start_reinit_rejected() {
        let (mut pm, _tag) = pm_mesh_established_peer([5u8; 32], [6u8; 32], 100_000);
        // Session dropped (as the #41a rekey guard, or the liveness sweep,
        // would do): the peer stays tabled, reverts to Idle.
        pm.drop_session(0);
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
        assert!(pm.by_tag.is_empty());

        let init = rekey_init_with_payload(&pm, 0, &expired_cert_bytes(&pm, 0));
        let out = pm.on_udp(peer_src(&pm, 0), &init, 300_000);

        assert!(
            matches!(out, DispatchOut::None),
            "an expired cert must not re-admit a tabled peer"
        );
        assert!(
            matches!(pm.peers[0].state, PeerState::Idle),
            "peer stays Idle: no session was created for the rejected re-init"
        );
        assert!(
            pm.by_tag.is_empty(),
            "no conn_tag was installed for the rejected re-init"
        );
    }

    /// The `is_root` exemption: a peer whose pubkey IS in the signed root set
    /// is always-admit (mirrors the future liveness sweep's root exemption).
    /// Its cold-start Init is admitted even though its payload carries no
    /// cert at all — proving the exemption, not merely a passing cert check.
    #[test]
    fn root_exempt_from_readmission_check() {
        let ca = test_ca();
        let local = generate_keypair();
        let root = generate_keypair();
        let root_ep: SocketAddr = "198.51.100.1:51820".parse().unwrap();

        let roots = RootSet {
            roots: vec![(root.public, root_ep)],
            version: 1,
            ca_sig: [0u8; 64],
        };
        let own_sign = SigningKey::from_bytes(&[200u8; 32]);
        let own_cert = mk_cert(&ca, local.public, own_sign.verifying_key().to_bytes());
        let membership = Membership::new(
            vec![ca.verifying_key().to_bytes()],
            TEST_NET,
            own_cert,
            own_sign.to_bytes(),
            roots,
            vec!["10.0.0.1:51820".parse().unwrap()],
        );
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[],
            TunnelMode::L3Tun,
            None,
            Some(membership),
            false,
        );
        // `PeerManager::new` auto-admits the root: tabled, Idle.
        assert_eq!(pm.peers.len(), 1);
        assert_eq!(pm.peers[0].pubkey, root.public);
        assert!(matches!(pm.peers[0].state, PeerState::Idle));

        // Cold-start Init from the root, NO cert payload — would fail
        // `responder_cert_ok` for a non-root peer.
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &root.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
        let out = pm.on_udp(root_ep, &init_pkt, 0);

        assert_eq!(
            resp_bytes(&out).len(),
            1,
            "the root is admitted despite presenting no cert"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
    }

    /// Task 2's rekey re-verify must exempt roots exactly like Task 2b's
    /// re-admission gate does: an always-admit ROOT that is `Established`
    /// and receives a further `[HandshakeInit]` with an EMPTY (no-cert)
    /// payload — exactly what `root_exempt_from_readmission_check` proves a
    /// root is allowed to present — must NOT have its live session torn
    /// down. This arm also handles ordinary Init retransmits (lost Resp)
    /// and peer restarts, not just genuine rekeys, so this is reachable in
    /// normal operation. Before the fix, the rekey re-verify arm lacked the
    /// `is_root` bypass the re-admission gate has, so a certless root's
    /// session was wrongly dropped the moment any Init arrived from it.
    #[test]
    fn root_established_not_dropped_on_certless_rekey_init() {
        let ca = test_ca();
        let local = generate_keypair();
        let root = generate_keypair();
        let root_ep: SocketAddr = "198.51.100.1:51820".parse().unwrap();

        let roots = RootSet {
            roots: vec![(root.public, root_ep)],
            version: 1,
            ca_sig: [0u8; 64],
        };
        let own_sign = SigningKey::from_bytes(&[200u8; 32]);
        let own_cert = mk_cert(&ca, local.public, own_sign.verifying_key().to_bytes());
        let membership = Membership::new(
            vec![ca.verifying_key().to_bytes()],
            TEST_NET,
            own_cert,
            own_sign.to_bytes(),
            roots,
            vec!["10.0.0.1:51820".parse().unwrap()],
        );
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[],
            TunnelMode::L3Tun,
            None,
            Some(membership),
            false,
        );
        pm.rekey_interval_ms = 100_000;

        // Cold-start Init from the root, NO cert payload — admitted by the
        // Task 2b exemption (mirrors `root_exempt_from_readmission_check`).
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &root.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
        let out = pm.on_udp(root_ep, &init_pkt, 0);
        assert_eq!(resp_bytes(&out).len(), 1, "root cold-start admitted");
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
        let tag = established_tag(&pm, 0).expect("root established");

        // A further `[HandshakeInit]` from the root (fresh ephemeral — an
        // ordinary retransmit-of-a-different-round or a genuine rekey,
        // either reachable in normal operation), again carrying an EMPTY
        // (no-cert) payload, arriving well past interval/2.
        let (_hs2, init_pkt2) = HandshakeState::start_initiator(
            &root.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
        let _out2 = pm.on_udp(root_ep, &init_pkt2, 200_000);

        assert!(
            matches!(pm.peers[0].state, PeerState::Established(_)),
            "the root's session must NOT be dropped: roots are exempt from \
             cert-based revocation on rekey re-verify, same as the Task 2b gate"
        );
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag),
            "by_tag / established_tag unchanged — no drop_session teardown occurred"
        );
    }

    /// Control: with membership disabled (pure 2a/2b), the re-admission gate
    /// is a no-op — `responder_cert_ok` returns `true` unconditionally, so a
    /// configured peer re-establishing from `Idle` behaves byte-identically
    /// to before this gate existed.
    #[test]
    fn readmission_check_is_noop_without_membership() {
        let local = generate_keypair();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "10.0.0.2:2000".parse().unwrap();
        let cfg_peer = PeerConfig {
            public_key: peer.public,
            endpoint: Some(peer_ep),
        };
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[cfg_peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );

        let (_hs, init1) = HandshakeState::start_initiator(
            &peer.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
        let out1 = pm.on_udp(peer_ep, &init1, 0);
        assert_eq!(resp_bytes(&out1).len(), 1, "initial cold-start establishes");
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));

        // Drop the session (as a real revocation/liveness event would), then
        // re-establish from Idle with another empty-payload Init.
        pm.drop_session(0);
        assert!(matches!(pm.peers[0].state, PeerState::Idle));

        let (_hs2, init2) = HandshakeState::start_initiator(
            &peer.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
        let out2 = pm.on_udp(peer_ep, &init2, 1_000);
        assert_eq!(
            resp_bytes(&out2).len(),
            1,
            "re-establishment from Idle is unaffected by the gate when membership is None"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
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
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &stranger.private,
            &local.public,
            &crate::handshake::frame_init_payload(&cert_bytes),
        )
        .unwrap();
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

    /// #96 — symmetry with the init-side gates: an always-admit ROOT
    /// responder is exempt from the responder-cert check. A root is trusted
    /// via the signed root set, not a member cert (you revoke a root by
    /// removing it from the root set), so an initiator completing a handshake
    /// with a root establishes even if the root's msg2 carries no valid cert.
    #[test]
    fn initiator_admits_root_responder_despite_missing_cert() {
        let ca = test_ca();
        let local = generate_keypair();
        let root = generate_keypair();
        let root_ep: SocketAddr = "198.51.100.7:51820".parse().unwrap();
        let cfg = PeerConfig {
            public_key: root.public,
            endpoint: Some(root_ep),
        };
        let roots = RootSet {
            roots: vec![(root.public, root_ep)],
            version: 1,
            ca_sig: [0u8; 64],
        };
        let own_sign = SigningKey::from_bytes(&[200u8; 32]);
        let own_cert = mk_cert(&ca, local.public, own_sign.verifying_key().to_bytes());
        let membership = Membership::new(
            vec![ca.verifying_key().to_bytes()],
            TEST_NET,
            own_cert,
            own_sign.to_bytes(),
            roots,
            vec!["10.0.0.1:51820".parse().unwrap()],
        );
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            std::slice::from_ref(&cfg),
            TunnelMode::L3Tun,
            None,
            Some(membership),
            false,
        );
        let idx = pm
            .peers
            .iter()
            .position(|p| p.pubkey == root.public)
            .expect("root is a peer");

        // We initiate toward the root.
        let init_out = pm.on_tun(&dummy_tun_pkt(), 0).to_vec();
        let init_pkt = init_out
            .iter()
            .find(|d| d.dst == root_ep)
            .map(|d| d.bytes.clone())
            .expect("an Init toward the root");
        assert!(matches!(pm.peers[idx].state, PeerState::Handshaking(_)));

        // The root responds with NO cert in msg2 — rejected for a non-root
        // peer, but the root is exempt.
        let (_established, resp_pkt, _remote_static, _initiator_payload) =
            HandshakeState::start_responder(&root.private, &init_pkt, &[]).unwrap();
        let _ = pm.on_udp(root_ep, &resp_pkt, 0);

        assert!(
            matches!(pm.peers[idx].state, PeerState::Established(_)),
            "a root responder is admitted despite a missing cert (is_root exemption)"
        );
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
            let wrapped = yip_obf::obfuscate(&sess, PacketType::Data as u8, &dg.bytes[1..], 0)
                .expect("small test body fits u16");
            // The wire datagram carries no plaintext PacketType prefix and no
            // constant signature a DPI box could match: a second obfuscation of
            // the SAME (type, body) differs (fresh random nonce → different
            // keystream). Asserting a *single* wire byte differs from the
            // plaintext type is 1/256-flaky (the leading nonce byte can equal
            // it by chance); comparing two full wrappings is deterministic
            // (collision ≈ 2^-64) and captures the actual anti-DPI property.
            let wrapped2 = yip_obf::obfuscate(&sess, PacketType::Data as u8, &dg.bytes[1..], 0)
                .expect("small test body fits u16");
            assert_ne!(
                wrapped, wrapped2,
                "obfuscation must randomize the wire form (no constant signature)"
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
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
        assert_eq!(init_pkt[0], PacketType::HandshakeInit as u8);
        let wrapped = yip_obf::obfuscate(
            &obf_key,
            PacketType::HandshakeInit as u8,
            &init_pkt[1..],
            32,
        )
        .expect("small test body fits u16");

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
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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
                record: None,
            },
            &mut plain,
        );

        // Wrong key: dropped, no candidate learned (rendezvous-only peer
        // starts in Punching with no candidate address set).
        let wrong_key = yip_obf::derive_key(&[0x67u8; 32]);
        let wrapped_wrong = yip_obf::obfuscate(&wrong_key, yip_obf::RDV_TYPE, &plain, 0)
            .expect("small test body fits u16");
        assert!(matches!(
            pm.on_udp(mock_server(), &wrapped_wrong, 0),
            DispatchOut::None
        ));
        assert_eq!(pm.peers[0].path.candidate(), None);

        // Right key, wrong ptype: dropped, no candidate learned.
        let wrapped_wrong_type = yip_obf::obfuscate(&obf_key, PacketType::Data as u8, &plain, 0)
            .expect("small test body fits u16");
        assert!(matches!(
            pm.on_udp(mock_server(), &wrapped_wrong_type, 0),
            DispatchOut::None
        ));
        assert_eq!(pm.peers[0].path.candidate(), None);

        // Right key, right type: recovers the PeerInfo and sets the candidate.
        let wrapped = yip_obf::obfuscate(&obf_key, yip_obf::RDV_TYPE, &plain, 5)
            .expect("small test body fits u16");
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
                record: None,
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

    // ── #41(b): periodic cert-liveness sweep ────────────────────────────────

    /// Build a mesh (`membership: Some`) `PeerManager` with TWO already-
    /// `Established` (direct, non-relay) peers spliced in directly (like
    /// `pm_with_established_peer`), whose mesh membership directory holds an
    /// EXPIRED cert record for `expired_peer_pub` (peer 0) and a currently-
    /// valid one for `valid_peer_pub` (peer 1) — the #41(b) sweep fixture.
    /// Returns `(pm, established_tag_for_peer_1)`.
    fn pm_mesh_two_established_one_expired(
        expired_peer_pub: [u8; 32],
        valid_peer_pub: [u8; 32],
    ) -> (PeerManager, u64) {
        let ca = test_ca();
        let local = generate_keypair();
        let local_sign = SigningKey::from_bytes(&[230u8; 32]);
        let local_cert = mk_cert(&ca, local.public, local_sign.verifying_key().to_bytes());
        let mut membership = Membership::new(
            vec![ca.verifying_key().to_bytes()],
            TEST_NET,
            local_cert,
            local_sign.to_bytes(),
            empty_roots(),
            vec!["10.0.0.1:51820".parse().unwrap()],
        );

        // Peer 0's directory record: a cert that's ALREADY expired
        // (`not_after: 1`) — inserted at `now=0`, when its `[0, 1)` window is
        // (just barely) still open, so `ingest_record` accepts it; never
        // re-swept, so it stays in the directory holding its now-expired cert.
        let expired_sign = SigningKey::from_bytes(&[231u8; 32]);
        let mut expired_cert = Cert {
            version: 1,
            member_pubkey: expired_peer_pub,
            member_sign_pubkey: expired_sign.verifying_key().to_bytes(),
            network_id: TEST_NET,
            not_before: 0,
            not_after: 1,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        expired_cert.ca_sig = ca.sign(&cert_signing_body(&expired_cert)).to_bytes();
        let mut expired_rec = Record {
            node_id: yip_membership::node_id(&expired_peer_pub),
            cert: expired_cert,
            endpoints: vec!["10.0.0.2:2000".parse().unwrap()],
            seq: 1,
            sig: [0u8; 64],
        };
        let body = record_signing_body(&expired_rec);
        expired_rec.sig = record_sign(&body, &expired_sign.to_bytes());
        assert!(membership.ingest_record(expired_rec, 0));

        // Peer 1's directory record: an ordinary far-future-valid record.
        let valid_rec = mk_record(
            &ca,
            232,
            valid_peer_pub,
            vec!["10.0.0.3:3000".parse().unwrap()],
            1,
        );
        assert!(membership.ingest_record(valid_rec, 0));

        let cfg0 = PeerConfig {
            public_key: expired_peer_pub,
            endpoint: Some("10.0.0.2:2000".parse().unwrap()),
        };
        let cfg1 = PeerConfig {
            public_key: valid_peer_pub,
            endpoint: Some("10.0.0.3:3000".parse().unwrap()),
        };
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[cfg0, cfg1],
            TunnelMode::L3Tun,
            None,
            Some(membership),
            false,
        );
        pm.rekey_interval_ms = 100_000;

        const TAG0: u64 = 0xAAAA_0000_0000_0001;
        const TAG1: u64 = 0xBBBB_0000_0000_0002;
        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(
                TAG0,
                "10.0.0.2:2000".parse().unwrap(),
            )),
            0,
        )));
        pm.by_tag.insert(TAG0, 0);
        pm.peers[1].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(
                TAG1,
                "10.0.0.3:3000".parse().unwrap(),
            )),
            0,
        )));
        pm.by_tag.insert(TAG1, 1);

        (pm, TAG1)
    }

    #[test]
    fn tick_sweep_drops_established_peer_with_expired_cert() {
        // Two Established mesh peers: peer 0's directory cert is expired, peer 1's is valid.
        let (mut pm, tag1) = pm_mesh_two_established_one_expired([1u8; 32], [2u8; 32]);
        pm.tick(500_000); // a tick past the sweep cadence, now_secs shows peer 0 expired
        assert!(
            matches!(pm.peers[0].state, PeerState::Idle),
            "expired-cert peer's session is dropped"
        );
        assert!(
            !pm.by_tag.values().any(|&i| i == 0),
            "its conn_tag is removed"
        );
        assert_eq!(
            established_tag(&pm, 1),
            Some(tag1),
            "the valid peer is untouched"
        );
    }

    #[test]
    fn tick_sweep_is_noop_without_membership() {
        // Pure 2a/2b: no membership -> no sweep, Established peers untouched.
        let (mut pm, tag, _ep) = pm_with_established_peer([1u8; 32], [2u8; 32], 100);
        pm.tick(500_000);
        assert_eq!(
            established_tag(&pm, 0),
            Some(tag),
            "membership-off: sweep is a no-op"
        );
    }

    // ── M2 Task 1: endpoint roaming on authenticated inbound ────────────────

    #[test]
    fn authenticated_data_from_new_src_roams_endpoint() {
        // Two direct peers, established; pm_r.peers[0].endpoint == old_ep.
        let (mut pm_i, mut pm_r, old_ep) = established_pair_for_roaming();

        // The initiator sends a real Data packet; capture its on-wire bytes.
        // (Systematic FEC may emit extra parity datagrams alongside the
        // source symbol at index 0 — the source symbol alone is a complete,
        // independently-reconstructable frame, exactly like the existing
        // `rekey_resp_promotes_initiator_and_keeps_previous_for_grace` test's
        // use of `on_tun(..)[0]`.)
        let data = pm_i.on_tun(&dummy_tun_pkt(), 0).to_vec();
        assert_eq!(data[0].bytes[0], PacketType::Data as u8);
        let dg = data[0].bytes.clone();

        let new_src: SocketAddr = "198.51.100.222:60000".parse().unwrap();
        assert_ne!(new_src, old_ep);

        // Deliver from the NEW source. For real (masked) traffic `dg[1..9]`
        // is per-datagram garbage (see the module doc), so `by_tag` misses,
        // and `new_src != endpoint` so the address match misses too —
        // `route_data` returns `None` and this is handled by the OTHER
        // authenticated-decrypt site, the roaming fallback loop in
        // `handle_data_or_control` (same site `replayed_data_from_spoofed_src_does_not_roam_endpoint`
        // exercises for the rejection case). The datagram still
        // authenticates there via `inbound_open`.
        let out = pm_r.on_udp(new_src, &dg, 1_000);
        assert!(
            !matches!(out, DispatchOut::None),
            "a genuine Data datagram must authenticate"
        );
        assert_eq!(
            pm_r.peers[0].endpoint,
            Some(new_src),
            "endpoint must follow an authenticated packet from a new source",
        );
    }

    #[test]
    fn roam_redirects_egress_to_the_new_source() {
        // Relearning `endpoint` alone is a half-fix: egress datagrams are
        // stamped from the `EpochSet`'s `DataPlane::peer_addr`, not `endpoint`.
        // After an authenticated roam, the responder's OWN outbound data must
        // target the new source, or return traffic keeps hitting the peer's
        // stale (post-rebind, dead) address.
        let (mut pm_i, mut pm_r, old_ep) = established_pair_for_roaming();

        // Pre-roam: pm_r's egress targets the original endpoint.
        let before = pm_r.on_tun(&dummy_tun_pkt(), 500).to_vec();
        assert_eq!(
            before[0].dst, old_ep,
            "egress targets the original endpoint"
        );

        // pm_i sends an authenticated Data packet from a NEW source; pm_r roams.
        let data = pm_i.on_tun(&dummy_tun_pkt(), 0).to_vec();
        let dg = data[0].bytes.clone();
        let new_src: SocketAddr = "198.51.100.222:60000".parse().unwrap();
        assert_ne!(new_src, old_ep);
        let out = pm_r.on_udp(new_src, &dg, 1_000);
        assert!(
            !matches!(out, DispatchOut::None),
            "the roam packet must authenticate"
        );

        // Post-roam: pm_r's egress now targets the new source (not just `endpoint`).
        let after = pm_r.on_tun(&dummy_tun_pkt(), 2_000).to_vec();
        assert_eq!(
            after[0].dst, new_src,
            "egress must follow the roam to the new source, not the stale addr",
        );
    }

    #[test]
    fn replayed_data_from_spoofed_src_does_not_roam_endpoint() {
        let (mut pm_i, mut pm_r, old_ep) = established_pair_for_roaming();
        let data = pm_i.on_tun(&dummy_tun_pkt(), 0).to_vec();
        let dg = data[0].bytes.clone();

        // First delivery from the legit endpoint authenticates and is
        // consumed (advances the replay window). `src == old_ep` matches
        // `route_data`'s address check directly, reaching
        // `dispatch_established`.
        let out1_is_none = matches!(pm_r.on_udp(old_ep, &dg, 1_000), DispatchOut::None);
        assert!(!out1_is_none, "the first delivery must authenticate");
        assert_eq!(pm_r.peers[0].endpoint, Some(old_ep));

        // REPLAY the exact same datagram from a spoofed source: `dg[1..9]`
        // is masked per-datagram (see the module doc), so it does not match
        // `by_tag`, and `spoof != old_ep` so it does not match by address
        // either — `route_data` returns `None` and this exercises the OTHER
        // authenticated-decrypt site, the roaming fallback loop in
        // `handle_data_or_control`. The replay window there must reject it —
        // this must fail if the replay were (incorrectly) accepted.
        let spoof: SocketAddr = "203.0.113.66:5555".parse().unwrap();
        let out2_is_none = matches!(pm_r.on_udp(spoof, &dg, 1_001), DispatchOut::None);
        assert!(
            out2_is_none,
            "a replayed datagram must be rejected, not accepted"
        );
        assert_eq!(
            pm_r.peers[0].endpoint,
            Some(old_ep),
            "a replayed packet must not move the endpoint"
        );
    }

    // #34 preservation: an unauthenticated Init from a spoofed source against
    // an Established responder still must not move `endpoint` — M2 does not
    // touch the Init path (it never calls `inbound_open`), so the existing
    // guard covers this; see `stale_replayed_cold_start_init_does_not_hijack_endpoint`
    // and `stale_replayed_init_is_rejected_and_endpoint_unchanged` above.
}
