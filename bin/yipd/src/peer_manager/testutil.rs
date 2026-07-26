//! Shared test helpers for the peer_manager submodules.
#![cfg(test)]

use super::*;
use crate::wire_glue::derive_wire_keys;
use yip_crypto::{generate_keypair, Handshake};

use ed25519_dalek::{Signer as _, SigningKey};
use yip_membership::cert::cert_signing_body;
use yip_membership::record::{record_signing_body, sign as record_sign};
use yip_membership::{Record, RootSet};

pub(super) const TEST_NET: [u8; 16] = [7u8; 16];

pub(super) fn peer_cfg(tag_byte: u8, endpoint: &str) -> PeerConfig {
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
pub(super) fn fake_established_dataplane(conn_tag: u64, peer_addr: SocketAddr) -> DataPlane {
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

pub(super) fn established_tag(pm: &PeerManager, idx: usize) -> Option<u64> {
    match &pm.peers[idx].state {
        PeerState::Established(epochs) => Some(epochs.current().conn_tag()),
        _ => None,
    }
}

/// Copy out every `[HandshakeResp]` datagram's bytes from a `DispatchOut`
/// (decoupling from the borrow so the caller can keep driving the manager).
pub(super) fn resp_bytes(out: &DispatchOut<'_>) -> Vec<Vec<u8>> {
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
pub(super) fn dummy_tun_pkt() -> Vec<u8> {
    vec![0x45u8; 40]
}

// ── #34: handshake anti-replay test helpers ─────────────────────────────

/// Build a msg1 app payload `[ts || cert]` with an EXPLICIT, caller-chosen
/// `ts` label — the test-only counterpart of `handshake::frame_init_payload`
/// (which always stamps `now_tai64n()`), needed to hand-craft stale/fresh
/// Inits deterministically.
pub(super) fn init_payload_with_ts(ts: [u8; crate::handshake::TAI64N_LEN], cert: &[u8]) -> Vec<u8> {
    let mut out = ts.to_vec();
    out.extend_from_slice(cert);
    out
}

/// One second OLDER than `ts` (TAI64N is big-endian seconds ++ nanos, so
/// decrementing the leading 8-byte seconds field yields a label that
/// compares strictly less, lexicographically, regardless of the nanos
/// suffix).
pub(super) fn older_ts(
    ts: [u8; crate::handshake::TAI64N_LEN],
) -> [u8; crate::handshake::TAI64N_LEN] {
    let secs = u64::from_be_bytes(ts[..8].try_into().unwrap());
    let mut out = ts;
    out[..8].copy_from_slice(&(secs - 1).to_be_bytes());
    out
}

/// One second NEWER than `ts` — see `older_ts`.
pub(super) fn newer_ts(
    ts: [u8; crate::handshake::TAI64N_LEN],
) -> [u8; crate::handshake::TAI64N_LEN] {
    let secs = u64::from_be_bytes(ts[..8].try_into().unwrap());
    let mut out = ts;
    out[..8].copy_from_slice(&(secs + 1).to_be_bytes());
    out
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
pub(super) fn pm_with_established_peer(
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
pub(super) fn has_handshake_init(out: Option<&[EgressDatagram]>) -> bool {
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
pub(super) fn has_relayed_handshake_init(out: Option<&[EgressDatagram]>) -> bool {
    out.into_iter().flatten().any(|d| {
        matches!(
            yip_rendezvous::decode(&d.bytes),
            Some(yip_rendezvous::Message::RelaySend { payload, .. })
                if payload.first() == Some(&(PacketType::HandshakeInit as u8))
        )
    })
}

// ── 9a Task 4: rekey handshake completion wiring ────────────────────────

/// Build two real `PeerManager`s and drive them through a cold-start
/// handshake (A initiates) so both land `Established` on the SAME
/// session, with `rekey_interval_ms` set to `interval_ms` on both.
/// Returns `(pm_a, pm_b, ep_a, ep_b, kp_a, kp_b)`.
pub(super) fn established_pm_pair(
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

/// `pm`'s Established peer 0's `next` epoch's `conn_tag`, panicking if
/// there is no `next` installed. Test helper for the retransmit-dedup
/// regressions below.
pub(super) fn next_conn_tag(pm: &PeerManager) -> u64 {
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

// ── rendezvous wiring (mock Rendezvous) ───────────────────────────────

/// A mock `Rendezvous` that records the messages it is asked to send (so a
/// test can assert on them) and parses injected server datagrams the same
/// way `ConfiguredServerRendezvous` does. `parse` reuses the real decoder,
/// so a test injects an event by `encode`-ing a `Message` and feeding it to
/// `on_udp(server, ..)`.
pub(super) struct MockRdv {
    pub(super) server: SocketAddr,
    pub(super) sent: std::rc::Rc<std::cell::RefCell<Vec<yip_rendezvous::Message>>>,
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
    fn register(
        &mut self,
        node: NodeId,
        signed: Option<yip_membership::Record>,
    ) -> Option<EgressDatagram> {
        match signed {
            Some(record) => {
                Some(self.to_server(yip_rendezvous::Message::RegisterSigned { record }))
            }
            // counter bumped per-registration in 3c.4; 0 is accepted as first-seen
            None => Some(self.to_server(yip_rendezvous::Message::Register { node, counter: 0 })),
        }
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
            Some(yip_rendezvous::Message::PeerInfo {
                node,
                reflexive,
                record,
            }) => RdvEvent::PeerCandidate {
                node,
                addr: reflexive,
                record: record.map(Box::new),
            },
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

pub(super) fn mock_server() -> SocketAddr {
    "203.0.113.1:51821".parse().unwrap()
}

/// Build a `PeerManager` with a `MockRdv` rendezvous, returning the manager
/// and a shared handle to the messages the mock is asked to send.
pub(super) fn pm_with_mock_rdv(
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

/// Like `pm_with_mock_rdv`, but with `membership` configured (mesh
/// mode) — used by the `PeerCandidate`-record-verification tests (#37
/// Task 5), which need the `MockRdv` to decode a real `PeerInfo.record`
/// AND a `Membership` to verify it against.
pub(super) fn pm_with_mock_rdv_and_membership(
    local: &yip_crypto::Keypair,
    peers: &[PeerConfig],
    membership: Membership,
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
        Some(membership),
        false,
    );
    (pm, sent)
}

/// Build a mesh (`membership: Some`) `Membership` for `local_pub` trusting
/// `ca`, whose `roots` names `ca`'s own pubkey — the convention
/// `Membership::verify_record` relies on (it treats `roots.roots`'
/// pubkeys as the trusted CA set, mirroring `bin/yip-rendezvous`'s own
/// rooted-server convention). Shared by the two `PeerCandidate`-record
/// verification tests below (#37 Task 5).
pub(super) fn membership_trusting_ca_via_roots(ca: &SigningKey, local_pub: [u8; 32]) -> Membership {
    let ca_pub = ca.verifying_key().to_bytes();
    let own_sign = SigningKey::from_bytes(&[201u8; 32]);
    let own_cert = mk_cert(ca, local_pub, own_sign.verifying_key().to_bytes());
    let roots = RootSet {
        roots: vec![(ca_pub, "10.0.0.99:51820".parse().unwrap())],
        version: 0,
        ca_sig: [0u8; 64],
    };
    Membership::new(
        vec![ca_pub],
        TEST_NET,
        own_cert,
        own_sign.to_bytes(),
        roots,
        vec!["10.0.0.1:51820".parse().unwrap()],
    )
}

/// `true` iff `out` carries a `[HandshakeResp]` relay-wrapped in a
/// `yip_rendezvous::Message::RelaySend` — the relay-path counterpart of
/// `has_relayed_handshake_init`, used to assert a responder replayed its
/// cached resp over the relay (#36 Task 1, Step 6).
pub(super) fn has_relayed_handshake_resp(out: &DispatchOut<'_>) -> bool {
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
pub(super) fn wrap_relay_deliver(pm: &PeerManager, payload: &[u8]) -> Vec<u8> {
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
pub(super) fn responder_established_for_initiator(
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

    let (_hs, a_init_pkt) = HandshakeState::start_initiator(
        &kp_a.private,
        &kp_r.public,
        &crate::handshake::frame_init_payload(&[]),
    )
    .unwrap();
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

/// #36 Task 1b: build a responder `PeerManager` that adopted the
/// responder role over a DIRECT (non-relayed) path — real
/// `cached_resp`/`cached_resp_init_eph`, keyed to initiator A's actual
/// ephemeral, and `relay == false` — via a genuine cold-start Noise
/// handshake delivered straight to `on_udp` from a direct endpoint
/// address (mirroring `duplicate_init_after_established_does_not_tear_down_session`'s
/// direct completion, but with a `MockRdv` rendezvous so relay egress
/// works afterward). This is the peer state the headline #36 scenario
/// leaves B in: A escalated punch->relay after this handshake completed,
/// so B is Established-and-direct while A now only reaches it via relay.
pub(super) fn responder_established_direct_for_initiator(
    now_ms: u64,
) -> (PeerManager, yip_crypto::Keypair, Vec<u8>) {
    let kp_r = generate_keypair();
    let kp_a = generate_keypair();
    let ep_a: SocketAddr = "10.0.0.9:9000".parse().unwrap();
    let cfg_a = PeerConfig {
        public_key: kp_a.public,
        endpoint: Some(ep_a),
    };
    let (mut pm_r, _sent) = pm_with_mock_rdv(&kp_r, &[cfg_a]);

    let (_hs, a_init_pkt) = HandshakeState::start_initiator(
        &kp_a.private,
        &kp_r.public,
        &crate::handshake::frame_init_payload(&[]),
    )
    .unwrap();
    let resp1 = resp_bytes(&pm_r.on_udp(ep_a, &a_init_pkt, now_ms));
    assert_eq!(
        resp1.len(),
        1,
        "cold-start direct init must produce one HandshakeResp"
    );
    assert!(
        established_tag(&pm_r, 0).is_some(),
        "responder must be Established"
    );
    assert!(
        !pm_r.peers[0].relay,
        "responder must be direct (not relay) for A"
    );

    (pm_r, kp_a, a_init_pkt)
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
pub(super) fn established_relay_pm(
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

/// Wrap `payload` (raw handshake bytes) as a `RelayDeliver` datagram from
/// `src_kp`, as the server would forward it — the input side of the
/// relay tests below, mirroring `anti_hijack_established_peer_ignores_relayed_handshake_init`.
pub(super) fn relay_deliver(src_kp: &yip_crypto::Keypair, payload: Vec<u8>) -> Vec<u8> {
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

// ── membership wiring (mock Membership via an in-test CA + certs) ──────
//
// A `Membership` built from an in-test Ed25519 CA and certs whose validity
// window straddles the real wall clock (cert checks in `PeerManager` use
// `now_secs()`, not the loop's `now_ms`), so `verify_cert` accepts them
// when the daemon runs today.

pub(super) fn test_ca() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// A CA-signed cert covering `member_pubkey`, valid essentially forever so
/// the real wall clock (`now_secs()`) always falls inside the window.
pub(super) fn mk_cert(ca: &SigningKey, member_pubkey: [u8; 32], member_sign_pub: [u8; 32]) -> Cert {
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

pub(super) fn empty_roots() -> RootSet {
    RootSet {
        roots: vec![],
        version: 0,
        ca_sig: [0u8; 64],
    }
}

/// A `Membership` for a node whose own data-plane key is `own_pub`, trusting
/// `ca`, on `TEST_NET`, with no roots.
pub(super) fn membership_for(ca: &SigningKey, own_pub: [u8; 32]) -> Membership {
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
pub(super) fn mk_record(
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
pub(super) fn ipv6_pkt_to(dst: Ipv6Addr) -> Vec<u8> {
    let mut inner = vec![0u8; 40];
    inner[0] = 0x60;
    inner[24..40].copy_from_slice(&dst.octets());
    inner
}

// ── #41(a): re-verify the cert on a mid-session rekey Init ─────────────
//
// A registry mapping a peer's data-plane pubkey to its private key +
// Ed25519 signing-key seed, populated by `pm_mesh_established_peer` and
// read by `rekey_init_with_payload`/`valid_cert_bytes` so those helpers
// can mint further datagrams "from" that peer without threading its
// keys through every call site (the verbatim test bodies only pass
// `&pm`). Keyed (not thread-local) so it's safe under parallel test
// execution.
pub(super) type PeerTestKeyRegistry =
    std::sync::Mutex<std::collections::HashMap<[u8; 32], ([u8; 32], [u8; 32])>>;

pub(super) fn peer_test_key_registry() -> &'static PeerTestKeyRegistry {
    static REG: std::sync::OnceLock<PeerTestKeyRegistry> = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Build a mesh (`membership: Some`) `PeerManager` with a single peer
/// already `Established` over a direct (non-relay) cold-start handshake,
/// for exercising the #41(a) rekey cert-reverification guard.
/// `local_sign_seed`/`peer_sign_seed` seed the local/peer Ed25519
/// signing keys embedded in their CA-signed certs (mirrors
/// `membership_for`'s `[200u8; 32]` pattern); `interval_ms` becomes
/// `pm.rekey_interval_ms` (kept as a parameter for parity with the other
/// #41 rekey fixtures, though #34's freshness gate — not `current`'s age
/// — is what actually admits the rekey Inits these tests craft below,
/// via real `now_tai64n()` timestamps that are always fresher than the
/// cold-start's). The peer's data-plane keypair is generated fresh and
/// stashed in the registry above (keyed by its pubkey).
pub(super) fn pm_mesh_established_peer(
    local_sign_seed: [u8; 32],
    peer_sign_seed: [u8; 32],
    interval_ms: u64,
) -> (PeerManager, u64) {
    let ca = test_ca();
    let local = generate_keypair();
    let peer = generate_keypair();
    let peer_ep: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    let local_sign = SigningKey::from_bytes(&local_sign_seed);
    let local_cert = mk_cert(&ca, local.public, local_sign.verifying_key().to_bytes());
    let membership = Membership::new(
        vec![ca.verifying_key().to_bytes()],
        TEST_NET,
        local_cert,
        local_sign.to_bytes(),
        empty_roots(),
        vec!["10.0.0.1:51820".parse().unwrap()],
    );

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
        Some(membership),
        false,
    );
    pm.rekey_interval_ms = interval_ms;

    peer_test_key_registry()
        .lock()
        .unwrap()
        .insert(peer.public, (peer.private, peer_sign_seed));

    // Cold-start: the peer completes a direct handshake with `pm`. Even
    // though admission is by preconfigured static-key match (`cfg_peer`
    // above), Task 2b's re-admission gate now also requires a
    // currently-valid cert on THIS leg (mirroring the real initiator's
    // `begin_handshake`, which always attaches `own_cert_bytes()` when
    // membership is enabled) — so mint one here, exactly like a
    // legitimate, non-revoked member would present.
    let (_hs, init_pkt) = HandshakeState::start_initiator(
        &peer.private,
        &local.public,
        &crate::handshake::frame_init_payload(&valid_cert_bytes(&pm, 0)),
    )
    .unwrap();
    let out = pm.on_udp(peer_ep, &init_pkt, 0);
    assert!(
        matches!(out, DispatchOut::Udp(_)),
        "cold-start init must produce a resp and establish the session"
    );

    let tag = established_tag(&pm, 0).expect("pm established with the peer");
    (pm, tag)
}

/// The endpoint `pm` learned/was configured with for peer `idx`.
pub(super) fn peer_src(pm: &PeerManager, idx: usize) -> SocketAddr {
    pm.peers[idx]
        .endpoint
        .expect("peer has a learned/configured endpoint")
}

/// A `[HandshakeInit] ++ msg1` datagram "from" `pm.peers[idx]` (using its
/// private key stashed by `pm_mesh_established_peer`), carrying `payload`
/// as the msg1 app CERT payload — the slot `responder_cert_ok` reads the
/// cert from on a rekey Init. `payload` is framed as `[ts || payload]`
/// (#34), mirroring what a real initiator (`drive_rekey_schedule`) sends.
pub(super) fn rekey_init_with_payload(pm: &PeerManager, idx: usize, payload: &[u8]) -> Vec<u8> {
    let peer_pub = pm.peers[idx].pubkey;
    let (peer_priv, _sign_seed) = *peer_test_key_registry()
        .lock()
        .unwrap()
        .get(&peer_pub)
        .expect("peer keypair registered by pm_mesh_established_peer");
    let framed = crate::handshake::frame_init_payload(payload);
    let (_hs, init_pkt) =
        HandshakeState::start_initiator(&peer_priv, &pm.local_pub, &framed).unwrap();
    init_pkt
}

/// A freshly-minted, currently-valid CA-signed cert (encoded) covering
/// `pm.peers[idx]`'s static key — what a non-revoked member would present
/// on a rekey Init.
pub(super) fn valid_cert_bytes(pm: &PeerManager, idx: usize) -> Vec<u8> {
    let peer_pub = pm.peers[idx].pubkey;
    let (_priv, sign_seed) = *peer_test_key_registry()
        .lock()
        .unwrap()
        .get(&peer_pub)
        .expect("peer keypair registered by pm_mesh_established_peer");
    let ca = test_ca();
    let sign = SigningKey::from_bytes(&sign_seed);
    let cert = mk_cert(&ca, peer_pub, sign.verifying_key().to_bytes());
    let mut bytes = Vec::new();
    cert.encode(&mut bytes);
    bytes
}

/// A CA-signed but EXPIRED cert (encoded) covering `pm.peers[idx]`'s
/// static key — what a revoked/non-renewed member would present when
/// re-establishing after its session was dropped (#41/Task 2b).
/// `not_after: 1` is far enough in the past (wall-clock seconds since the
/// UNIX epoch) that it is expired even past `CLOCK_SKEW_SECS`.
pub(super) fn expired_cert_bytes(pm: &PeerManager, idx: usize) -> Vec<u8> {
    let peer_pub = pm.peers[idx].pubkey;
    let (_priv, sign_seed) = *peer_test_key_registry()
        .lock()
        .unwrap()
        .get(&peer_pub)
        .expect("peer keypair registered by pm_mesh_established_peer");
    let ca = test_ca();
    let sign = SigningKey::from_bytes(&sign_seed);
    let mut cert = Cert {
        version: 1,
        member_pubkey: peer_pub,
        member_sign_pubkey: sign.verifying_key().to_bytes(),
        network_id: TEST_NET,
        not_before: 0,
        not_after: 1,
        tags: vec![],
        ca_sig: [0u8; 64],
    };
    cert.ca_sig = ca.sign(&cert_signing_body(&cert)).to_bytes();
    let mut bytes = Vec::new();
    cert.encode(&mut bytes);
    bytes
}
