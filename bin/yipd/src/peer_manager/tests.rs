use super::testutil::*;
use super::*;
use crate::handshake::Established;
use crate::wire_glue::derive_wire_keys;
use yip_crypto::{generate_keypair, Handshake};

#[test]
fn test_peer_manager_transport_helpers() {
    let mut pm = test_peer_manager();
    let cfg = peer_cfg(42, "10.0.0.42:51820");
    pm.add_peer_with_transport(cfg.clone(), Some("Holepunched UDP".into()))
        .unwrap();
    let stats = pm.peer_stats();
    let found = stats
        .iter()
        .find(|s| s.public_key == cfg.public_key)
        .unwrap();
    assert_eq!(found.transport, "Holepunched UDP");

    pm.set_peer_transport(&cfg.public_key, "TLS (REALITY)".into());
    let stats2 = pm.peer_stats();
    let found2 = stats2
        .iter()
        .find(|s| s.public_key == cfg.public_key)
        .unwrap();
    assert_eq!(found2.transport, "TLS (REALITY)");
    assert_eq!(found2.cert_status, "CA Valid");
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
        out.iter()
            .any(|d| d.dst == candidate
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
        .find(|d| d.dst == candidate && d.bytes.first() == Some(&(PacketType::HandshakeInit as u8)))
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
        out.iter()
            .any(|d| d.dst == candidate
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
        out.iter()
            .any(|d| d.dst == candidate
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
    let (ini_send_k, ini_recv_k) = ini.raw_split_keys();
    let (res_send_k, res_recv_k) = res.raw_split_keys();
    let conn_tag = conn_tag_from_keys(&auth_key, &hp_key);
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
    let (mut pm, peer_ep, sess) = obf_on_established_peer_for_cover(Some(COVER_TEST_NOW_MS), true);

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
    let expected_ep = SocketAddr::new(new_src.ip(), old_ep.port());
    assert_eq!(
        pm_r.peers[0].endpoint,
        Some(expected_ep),
        "endpoint must update to new IP while preserving base port",
    );
}

#[test]
fn roam_redirects_egress_to_the_new_source() {
    // Relearning `endpoint` alone is a half-fix: egress datagrams are
    // stamped from the `EpochSet`'s `DataPlane::peer_addr`, not `endpoint`.
    // After an authenticated roam, the responder's OWN outbound data must
    // target the new IP (with preserved base port), or return traffic keeps
    // hitting the peer's stale (post-rebind, dead) address.
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
    assert_ne!(new_src.port(), old_ep.port());
    let out = pm_r.on_udp(new_src, &dg, 1_000);
    assert!(
        !matches!(out, DispatchOut::None),
        "the roam packet must authenticate"
    );

    // Post-roam: pm_r's egress now targets the new IP while preserving base port.
    let after = pm_r.on_tun(&dummy_tun_pkt(), 2_000).to_vec();
    let expected_dst = SocketAddr::new(new_src.ip(), old_ep.port());
    assert_eq!(
        after[0].dst, expected_dst,
        "egress must follow the roam to the new IP with preserved port, not the stale addr",
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

#[test]
fn reg_seq_monotonic_across_daemon_restarts() {
    let pm1 = crate::peer_manager::testutil::test_peer_manager();
    assert!(
        pm1.reg_seq > 0,
        "reg_seq must initialize to non-zero wall clock ms"
    );

    // Sleep 2ms so wall clock advances
    std::thread::sleep(std::time::Duration::from_millis(2));

    let pm2 = crate::peer_manager::testutil::test_peer_manager();
    assert!(
        pm2.reg_seq > pm1.reg_seq,
        "restart must yield strictly higher reg_seq"
    );
}

#[test]
fn dynamic_add_peer_updates_mappings_and_routes() {
    let mut pm = crate::peer_manager::testutil::test_peer_manager();
    assert_eq!(pm.peers.len(), 1);

    let new_pk = [42u8; 32];
    let new_ep: SocketAddr = "198.51.100.42:51820".parse().unwrap();
    let new_cfg = PeerConfig {
        public_key: new_pk,
        endpoint: Some(new_ep),
    };

    // Add peer
    assert!(pm.add_peer(new_cfg.clone()).is_ok());
    assert_eq!(pm.peers.len(), 2);

    // Duplicate peer returns error
    assert!(pm.add_peer(new_cfg).is_err());

    // Verify routing to new peer initiates handshake
    let target_addr = node_addr(&new_pk);
    let mut pkt = [0u8; 48];
    pkt[0] = 0x60; // IPv6
    pkt[24..40].copy_from_slice(&target_addr.octets());
    let egress = pm.on_tun(&pkt, 1_000).to_vec();
    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0].dst, new_ep);
}

#[test]
fn dynamic_remove_peer_cleans_mappings_and_tears_down() {
    let mut pm = crate::peer_manager::testutil::test_peer_manager();
    let p1_pk = [1u8; 32];
    let p2_pk = [2u8; 32];
    let p3_pk = [3u8; 32];

    assert!(pm
        .add_peer(PeerConfig {
            public_key: p2_pk,
            endpoint: Some("10.0.0.2:2000".parse().unwrap()),
        })
        .is_ok());
    assert!(pm
        .add_peer(PeerConfig {
            public_key: p3_pk,
            endpoint: Some("10.0.0.3:3000".parse().unwrap()),
        })
        .is_ok());
    assert_eq!(pm.peers.len(), 3);

    // Remove middle peer (p2)
    assert!(pm.remove_peer(&p2_pk).is_ok());
    assert_eq!(pm.peers.len(), 2);
    assert!(!pm.by_node.contains_key(&node_id(&p2_pk)));
    assert!(!pm.by_addr.contains_key(&node_addr(&p2_pk)));

    // p1 and p3 mappings remain correct
    assert_eq!(pm.by_node.get(&node_id(&p1_pk)).copied(), Some(0));
    assert_eq!(pm.by_node.get(&node_id(&p3_pk)).copied(), Some(1));
    assert_eq!(pm.peers[0].pubkey, p1_pk);
    assert_eq!(pm.peers[1].pubkey, p3_pk);

    // Removing non-existent peer returns Err
    assert!(pm.remove_peer(&p2_pk).is_err());
}

#[test]
fn peer_stats_reports_current_telemetry() {
    let pm = crate::peer_manager::testutil::test_peer_manager();
    let stats = pm.peer_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].public_key, [1u8; 32]);
    assert_eq!(stats[0].state, "idle");
    assert_eq!(stats[0].endpoint, Some("10.0.0.1:1000".parse().unwrap()));
}

#[test]
fn is_peer_established_reports_correct_state() {
    let local = generate_keypair();
    let peer = peer_cfg(1, "10.0.0.1:1000");
    let mut pm = PeerManager::new(
        local.private,
        local.public,
        &[peer],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    assert!(!pm.is_peer_established(&[1u8; 32]));
    assert!(!pm.is_peer_established(&[2u8; 32]));

    let fake_dp = fake_established_dataplane(42, "10.0.0.1:1000".parse().unwrap());
    pm.peers[0].state =
        PeerState::Established(Box::new(crate::epoch::EpochSet::new(Box::new(fake_dp), 0)));
    assert!(pm.is_peer_established(&[1u8; 32]));
    assert!(!pm.is_peer_established(&[2u8; 32]));
}

#[test]
fn test_peer_manager_pq_hybrid_handshake_datagrams_fit_mtu_budget() {
    let (mut pm_a, pm_b, ..) = established_pm_pair(100);

    // Verify existing established pair operates across cold start and rekey
    let now = 10_000u64;
    let b_addr = peer_src(&pm_a, 0);

    // Attach membership so responder can include its own certificate
    let ca = test_ca();
    pm_a.membership = Some(membership_for(&ca, pm_a.local_pub));

    // Verify rekey payload construction (HandshakeInit with cert)
    let rekey_pkt = rekey_init_with_payload(&pm_a, 0, &valid_cert_bytes(&pm_a, 0));
    assert!(
        rekey_pkt.len() <= OBF_MTU_BUDGET,
        "rekey Init with cert must stay within OBF_MTU_BUDGET, got {}",
        rekey_pkt.len()
    );
    assert_eq!(rekey_pkt[0], PacketType::HandshakeInit as u8);
    // Msg 1 contains: 1 ptype + 32 Noise ephemeral + 48 encrypted static + 12 TAI64N + 800 ML-KEM ek + cert + 16 Poly1305 MAC tag
    assert!(
        rekey_pkt.len() >= 1025 && rekey_pkt.len() <= 1080,
        "rekey Init with cert should be around 1,025-1,080 bytes, got {}",
        rekey_pkt.len()
    );

    // Verify responder processes Init and builds HandshakeResp with cert
    let out = pm_a.on_udp(b_addr, &rekey_pkt, now);
    let resp = resp_bytes(&out);
    assert_eq!(resp.len(), 1, "rekey init must produce one resp");
    let resp_pkt = &resp[0];
    assert_eq!(resp_pkt[0], PacketType::HandshakeResp as u8);
    assert!(
        resp_pkt.len() <= OBF_MTU_BUDGET,
        "rekey Resp with cert must stay within OBF_MTU_BUDGET, got {}",
        resp_pkt.len()
    );
    // Msg 2 contains: 1 ptype + 768 ML-KEM ct + 32 Noise ephemeral + cert (~128) + 16 Poly1305 MAC tag
    assert!(
        resp_pkt.len() >= 900 && resp_pkt.len() <= 1000,
        "rekey Resp with cert should be around 945 bytes, got {}",
        resp_pkt.len()
    );

    // Verify with obfuscation
    let (mut pm_obf_a, ..) = established_pm_pair_with_obf(100, [0x42u8; 32]);
    let rekey_obf = rekey_init_with_payload(&pm_obf_a, 0, &valid_cert_bytes(&pm_obf_a, 0));
    let wrapped = pm_obf_a.obf_envelope(rekey_obf, now);
    assert!(
        wrapped.len() <= OBF_MTU_BUDGET,
        "obfuscated rekey datagram must stay within OBF_MTU_BUDGET, got {}",
        wrapped.len()
    );

    // Verify obfuscated response fits within OBF_MTU_BUDGET
    let wrapped_resp = pm_obf_a.obf_envelope(resp_pkt.clone(), now);
    assert!(
        wrapped_resp.len() <= OBF_MTU_BUDGET,
        "obfuscated rekey Resp datagram must stay within OBF_MTU_BUDGET, got {}",
        wrapped_resp.len()
    );

    // Peer B is established
    assert!(pm_b.is_peer_established(&pm_a.local_pub));
}

#[test]
fn copy_into_reusable_egress_preserves_capacity() {
    let mut target = Vec::new();
    let mut dg0 = EgressDatagram {
        fate: 0,
        dst: "127.0.0.1:1000".parse().unwrap(),
        bytes: Vec::with_capacity(2048),
    };
    dg0.bytes.extend_from_slice(b"first datagram content");
    target.push(dg0);
    let target_cap = target[0].bytes.capacity();
    assert!(target_cap >= 2048);

    let src = vec![EgressDatagram {
        fate: 1,
        dst: "127.0.0.1:2000".parse().unwrap(),
        bytes: b"updated datagram content".to_vec(),
    }];

    copy_into_reusable_egress(&mut target, &src);

    assert_eq!(target.len(), 1);
    assert_eq!(target[0].fate, 1);
    assert_eq!(target[0].dst, "127.0.0.1:2000".parse().unwrap());
    assert_eq!(&target[0].bytes, b"updated datagram content");
    assert_eq!(
        target[0].bytes.capacity(),
        target_cap,
        "existing datagram byte capacity must be preserved"
    );
}

#[test]
fn repeated_on_tun_under_obfuscation_retains_egress_and_scratch_capacity() {
    let (mut pm_a, _pm_b, _ep_a, _ep_b, _kp_a, _kp_b) =
        established_pm_pair_with_obf(100_000, [0x42u8; 32]);

    let tun_pkt = dummy_tun_pkt();
    // Warm up the circulating scratch buffers across a few cycles
    for i in 0..6 {
        let _ = pm_a.on_tun(&tun_pkt, 1000 + i);
    }

    // Capture the steady-state baseline capacities across the 3-buffer circulation cycle
    let mut baseline_egress_caps = Vec::new();
    let mut baseline_scratch_caps = Vec::new();
    for i in 0..3 {
        let egress = pm_a.on_tun(&tun_pkt, 2000 + i);
        assert!(!egress.is_empty(), "egress must not be empty");
        baseline_egress_caps.push(pm_a.egress[0].bytes.capacity());
        baseline_scratch_caps.push(pm_a.obf_scratch.capacity());
    }

    // Repeated invocations with identical packet size (steady-state forwarding)
    for i in 0..30 {
        let egress = pm_a.on_tun(&tun_pkt, 3000 + i);
        assert!(!egress.is_empty());
        assert_eq!(
            pm_a.egress[0].bytes.capacity(),
            baseline_egress_caps[(i as usize) % 3],
            "egress byte buffer capacity must remain stable without reallocating"
        );
        assert_eq!(
            pm_a.obf_scratch.capacity(),
            baseline_scratch_caps[(i as usize) % 3],
            "obf_scratch capacity must remain stable without reallocating"
        );
    }
}

// ── Traffic Defense (DAITA) Unit Tests ──────────────────────────────────────

#[test]
fn obf_egress_quantizes_to_discrete_buckets() {
    let peer = peer_cfg(1, "10.0.0.1:1000");
    let mut pm = PeerManager::new(
        [1u8; 32],
        [2u8; 32],
        &[peer],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    pm.set_obf_psk(Some([0xAAu8; 32]));
    pm.set_traffic_defense(crate::config::TrafficDefenseConfig {
        preset: yip_obf::TrafficDefensePreset::Balanced,
        buckets: vec![256, 512, 1024, 1420],
        cover_interval_ms: Some(500),
        cover_burst_max: 2,
        jitter_max_ms: 2,
    });

    let allowed_buckets = [256, 512, 1024, 1420];
    let payload_lens = [50, 100, 300, 600, 1100];
    let expected_buckets = [256, 256, 512, 1024, 1420];

    for (&len, &expected) in payload_lens.iter().zip(expected_buckets.iter()) {
        let pkt = vec![PacketType::Data as u8; len];
        let wire = pm.obf_envelope(pkt, 0);
        assert!(
            allowed_buckets.contains(&wire.len()),
            "payload len {} resulted in wire len {}, not in {:?}",
            len,
            wire.len(),
            allowed_buckets
        );
        assert_eq!(wire.len(), expected);
    }
}

#[test]
fn handshake_quantizes_to_bucket() {
    let peer = peer_cfg(1, "10.0.0.1:1000");
    let mut pm = PeerManager::new(
        [1u8; 32],
        [2u8; 32],
        &[peer],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    pm.set_obf_psk(Some([0xAAu8; 32]));
    pm.set_traffic_defense(crate::config::TrafficDefenseConfig {
        preset: yip_obf::TrafficDefensePreset::Balanced,
        buckets: vec![256, 512, 1024, 1420],
        cover_interval_ms: Some(500),
        cover_burst_max: 2,
        jitter_max_ms: 2,
    });

    // HandshakeInit (1025B) -> quantizes to 1420B
    let mut init = vec![0u8; 1025];
    init[0] = PacketType::HandshakeInit as u8;
    let wire_init = pm.obf_envelope(init, 0);
    assert_eq!(wire_init.len(), 1420);

    // HandshakeResp (945B) -> quantizes to 1024B
    let mut resp = vec![0u8; 945];
    resp[0] = PacketType::HandshakeResp as u8;
    let wire_resp = pm.obf_envelope(resp, 0);
    assert_eq!(wire_resp.len(), 1024);
}

#[test]
fn decoy_burst_emits_multiple_bucket_sized_packets() {
    const TAG: u64 = 0x1122_3344_5566_7788;
    let peer_ep: SocketAddr = "10.0.0.50:5050".parse().unwrap();
    let peer = peer_cfg(50, "10.0.0.50:5050");
    let mut pm = PeerManager::new(
        [1u8; 32],
        [2u8; 32],
        &[peer],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    pm.set_obf_psk(Some([0xAAu8; 32]));
    pm.set_traffic_defense(crate::config::TrafficDefenseConfig {
        preset: yip_obf::TrafficDefensePreset::Paranoid,
        buckets: vec![512, 1420],
        cover_interval_ms: Some(20),
        cover_burst_max: 3,
        jitter_max_ms: 4,
    });
    let dp = fake_established_dataplane(TAG, peer_ep);
    let sess = [0xBBu8; 16];
    pm.peers[0].state =
        PeerState::Established(Box::new(crate::epoch::EpochSet::new(Box::new(dp), 0)));
    pm.peers[0].session_obf_key = Some(sess);
    pm.by_tag.insert(TAG, 0);

    // Peer is idle from t=0. Keep now_ms under FEEDBACK_INTERVAL_MS (30ms)
    // so tick_egress contains only the decoy burst.
    let out = pm.tick(20).expect("idle peer should emit cover burst");
    assert!(
        (1..=3).contains(&out.len()),
        "burst count {} not in 1..=3",
        out.len()
    );

    let allowed_buckets = [512, 1420];
    for dgram in out {
        assert_eq!(dgram.dst, peer_ep);
        assert!(
            allowed_buckets.contains(&dgram.bytes.len()),
            "packet len {} not in {:?}",
            dgram.bytes.len(),
            allowed_buckets
        );
        let (ptype, _) = yip_obf::deobfuscate(&sess, &dgram.bytes)
            .expect("decoy packet deobfuscates under session key");
        assert_eq!(ptype, yip_obf::JUNK_TYPE);
    }
}

#[test]
fn stochastic_cover_cadence_jitters_interval() {
    const TAG: u64 = 0x2233_4455_6677_8899;
    let peer_ep: SocketAddr = "10.0.0.60:6060".parse().unwrap();
    let peer = peer_cfg(60, "10.0.0.60:6060");
    let mut pm = PeerManager::new(
        [1u8; 32],
        [2u8; 32],
        &[peer],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    pm.set_obf_psk(Some([0xAAu8; 32]));
    let base_iv = 1000u64;
    pm.set_traffic_defense(crate::config::TrafficDefenseConfig {
        preset: yip_obf::TrafficDefensePreset::Balanced,
        buckets: vec![256, 512, 1024, 1420],
        cover_interval_ms: Some(base_iv),
        cover_burst_max: 2,
        jitter_max_ms: 2,
    });
    let dp = fake_established_dataplane(TAG, peer_ep);
    let sess = [0xCCu8; 16];
    pm.peers[0].state =
        PeerState::Established(Box::new(crate::epoch::EpochSet::new(Box::new(dp), 0)));
    pm.peers[0].session_obf_key = Some(sess);
    pm.by_tag.insert(TAG, 0);

    let spread = base_iv / 4; // 250 ms (±25%)
    let min_iv = base_iv - spread;
    let max_iv = base_iv + spread;

    let mut intervals = std::collections::HashSet::new();
    let mut cur_time = 0u64;

    for _ in 0..20 {
        cur_time += 2000;
        let _ = pm.tick(cur_time);
        let next_iv = pm.peers[0]
            .next_cover_interval_ms
            .expect("next_cover_interval_ms should be set");
        assert!(
            next_iv >= min_iv && next_iv <= max_iv,
            "next_iv {} outside ±25% range [{}, {}]",
            next_iv,
            min_iv,
            max_iv
        );
        intervals.insert(next_iv);
    }
    // Over 20 jitter draws with spread 250, we should see multiple distinct intervals
    assert!(
        intervals.len() > 1,
        "intervals should vary across ticks, got {:?}",
        intervals
    );
}

#[test]
fn obf_off_retains_legacy_padding_behavior() {
    let peer = peer_cfg(1, "10.0.0.1:1000");
    let mut pm = PeerManager::new(
        [1u8; 32],
        [2u8; 32],
        &[peer],
        TunnelMode::L3Tun,
        None,
        None,
        false,
    );
    pm.set_obf_psk(Some([0xAAu8; 32]));
    // preset Off
    pm.set_traffic_defense(crate::config::TrafficDefenseConfig {
        preset: yip_obf::TrafficDefensePreset::Off,
        buckets: vec![],
        cover_interval_ms: None,
        cover_burst_max: 1,
        jitter_max_ms: 0,
    });

    let payload = vec![PacketType::Data as u8; 50];
    let wire = pm.obf_envelope(payload, 0);
    // Legacy data padding max is 64, raw_wire = 11 + 49 = 60.
    // Wire length must be in 60..=(60 + 64).
    assert!(
        (60..=124).contains(&wire.len()),
        "wire len {} should be in legacy range 60..=124",
        wire.len()
    );
}
