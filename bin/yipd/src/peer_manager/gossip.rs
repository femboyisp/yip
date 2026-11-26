//! Mesh gossip: digest targets, periodic gossip tick, inbound gossip handling.
use super::*;

/// Maximum send nonce before refusing to seal control frames to avoid nonce reuse.
pub const CTRL_NONCE_REKEY_THRESHOLD: u64 = u64::MAX - 1024;

/// Seal an inner gossip message into an authenticated, uniformly-padded
/// encrypted control datagram (#207).
///
/// Returns `None` if the control send nonce has saturated (`>= u64::MAX - 1024`),
/// logging a warning and triggering a session rekey to prevent nonce reuse in ChaCha20-Poly1305.
pub(super) fn seal_gossip_reply<S: ControlSession + ?Sized>(
    est: &mut S,
    msg: &GossipMsg,
    target_bucket: usize,
) -> Option<Vec<u8>> {
    let nonce = est.ctrl_send_nonce();
    if nonce >= CTRL_NONCE_REKEY_THRESHOLD {
        eprintln!(
            "peer_manager: control send nonce saturated ({nonce}), refusing to seal and triggering rekey"
        );
        est.trigger_rekey();
        return None;
    }
    est.set_ctrl_send_nonce(nonce.saturating_add(1));
    let mut raw = Vec::new();
    msg.encode(&mut raw);
    Some(est.ctrl_codec().seal(
        nonce,
        crate::control_codec::INNER_TYPE_GOSSIP,
        &raw,
        target_bucket,
    ))
}

impl PeerManager {
    // ── membership gossip ─────────────────────────────────────────────────

    /// Process an authenticated inbound encrypted control frame (#207) for peer `peer_idx`.
    ///
    /// Verifies that the peer is in `Established` state, opens and authenticates the frame
    /// against `ctrl_codec` and anti-replay sliding window `ctrl_replay`, validates that the
    /// inner payload type is `INNER_TYPE_GOSSIP`, decodes `GossipMsg`, passes it to
    /// `Membership::on_gossip`, and emits replies sealed as `PacketType::EncryptedControl`
    /// uniformly padded to `OBF_MTU_BUDGET`.
    pub(super) fn process_encrypted_control(
        &mut self,
        peer_idx: usize,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        let (inner_type, payload) = {
            let (opened, promoted) = {
                let Some(est) = self.peers[peer_idx].state.as_established_mut() else {
                    return DispatchOut::None;
                };
                let prev_epoch = est.epoch();
                let opened = est.inbound_open_control(dg, now_ms);
                let promoted = if est.epoch() != prev_epoch {
                    Some((est.epoch(), est.current_obf_key()))
                } else {
                    None
                };
                (opened, promoted)
            };
            if let Some((new_epoch, obf)) = promoted {
                self.peers[peer_idx].session_obf_key = obf;
                self.metrics.record_rekey();
                self.metrics.set_current_epoch(new_epoch);
            }
            match opened {
                Ok(res) => res,
                Err(_) => return DispatchOut::None,
            }
        };

        if inner_type != crate::control_codec::INNER_TYPE_GOSSIP {
            return DispatchOut::None;
        }

        let Some(msg) = GossipMsg::decode(&payload) else {
            return DispatchOut::None;
        };

        let replies = match self.membership.as_mut() {
            Some(m) => m.on_gossip(msg, now_secs()),
            None => return DispatchOut::None,
        };
        if replies.is_empty() {
            return DispatchOut::None;
        }

        let relay = self.peers[peer_idx].relay;
        let peer_ep = self.peers[peer_idx].endpoint;
        self.egress.clear();
        let target_bucket = OBF_MTU_BUDGET;
        for reply in replies.iter().take(MAX_GOSSIP_REPLIES) {
            let bytes = {
                let Some(est) = self.peers[peer_idx].state.as_established_mut() else {
                    break;
                };
                match seal_gossip_reply(est, reply, target_bucket) {
                    Some(b) => b,
                    None => continue,
                }
            };
            if relay {
                if let Some(d) = self.relay_wrap(peer_idx, bytes) {
                    self.egress.push(d);
                }
            } else if let Some(dst) = peer_ep {
                self.egress.push(EgressDatagram {
                    fate: 0,
                    dst,
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

    /// Handle an inbound `[EncryptedControl]` datagram from `src`: source-restricted to
    /// `Established` peers ONLY.
    pub(super) fn on_encrypted_control(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        _now_ms: u64,
    ) -> DispatchOut<'_> {
        let Some(peer_idx) = self.peers.iter().position(|p| {
            p.endpoint == Some(src) && matches!(p.state, PeerSessionState::Established(_))
        }) else {
            return DispatchOut::None;
        };

        self.process_encrypted_control(peer_idx, dg, _now_ms)
    }

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
    pub(super) fn on_gossip(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        _now_ms: u64,
    ) -> DispatchOut<'_> {
        let Some(peer_idx) = self.peers.iter().position(|p| {
            p.endpoint == Some(src) && matches!(p.state, PeerSessionState::Established(_))
        }) else {
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
        let target_bucket = OBF_MTU_BUDGET;
        for reply in replies.iter().take(MAX_GOSSIP_REPLIES) {
            let bytes = {
                let Some(est) = self.peers[peer_idx].state.as_established_mut() else {
                    break;
                };
                match seal_gossip_reply(est, reply, target_bucket) {
                    Some(b) => b,
                    None => continue,
                }
            };
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
    /// Established peers (relay-wrapped when `Relayed`).
    /// Returns `(dst, peer_idx)`.
    fn gossip_targets(&self) -> Vec<(SocketAddr, usize)> {
        let mut out: Vec<(SocketAddr, usize)> = Vec::new();
        for (i, p) in self.peers.iter().enumerate() {
            if out.len() >= MAX_GOSSIP_TARGETS {
                return out;
            }
            if matches!(p.state, PeerSessionState::Established(_)) {
                if p.relay {
                    out.push((self.server_addr(), i));
                } else if let Some(ep) = p.endpoint {
                    out.push((ep, i));
                }
            }
        }
        out
    }

    /// Periodic gossip from `tick` (membership only): emit a debounced digest to
    /// a bounded set of partners (a sample of Established peers) and, if
    /// no live session exists yet, bootstrap by handshaking to a root so gossip
    /// can seed a fresh node. Pushes into `tick_egress`.
    pub(super) fn tick_gossip(&mut self, now_ms: u64) {
        let have_established = self
            .peers
            .iter()
            .any(|p| matches!(p.state, PeerSessionState::Established(_)));

        // Debounced digest (spacing handled inside `tick_digest`), chunked
        // (#44) into one or more `GossipMsg::Digest` messages when the
        // directory exceeds `MAX_GOSSIP_DIGEST_ENTRIES` — send each chunk to
        // every gossip target exactly as a single digest was sent before.
        let obf_on = self.obf_key.is_some();
        let digests: Vec<GossipMsg> = self
            .membership
            .as_mut()
            .map(|m| m.tick_digest(now_ms, obf_on))
            .unwrap_or_default();
        let target_bucket = OBF_MTU_BUDGET;
        let targets = self.gossip_targets();
        for digest in digests {
            for &(dst, peer_idx) in &targets {
                let relay = self.peers[peer_idx].relay;
                let bytes = {
                    let Some(est) = self.peers[peer_idx].state.as_established_mut() else {
                        continue;
                    };
                    match seal_gossip_reply(est, &digest, target_bucket) {
                        Some(b) => b,
                        None => continue,
                    }
                };
                if relay {
                    if let Some(d) = self.relay_wrap(peer_idx, bytes) {
                        self.tick_egress.push(d);
                    }
                } else {
                    self.tick_egress.push(EgressDatagram {
                        fate: 0,
                        dst,
                        bytes,
                    });
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
                if let Some(i) = self.peers.iter().position(|p| {
                    p.endpoint == Some(addr) && matches!(p.state, PeerSessionState::Idle)
                }) {
                    if let Some(dgs) = self.begin_handshake(i, addr, false, now_ms) {
                        self.tick_egress.extend(dgs);
                    }
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_codec::{derive_control_keys, ControlCodec, INNER_TYPE_GOSSIP};
    use crate::peer_manager::testutil::*;
    use crate::wire_glue::derive_wire_keys;
    use ed25519_dalek::SigningKey;
    use yip_crypto::{generate_keypair, Handshake, ReplayWindow};

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
            alias: None,
            kem: None,
            pq_public_key: None,
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
        pm.peers[0].state = PeerSessionState::Established(Box::new(crate::epoch::EpochSet::new(
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
            alias: None,
            kem: None,
            pq_public_key: None,
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
        pm.peers[0].state = PeerSessionState::Established(Box::new(crate::epoch::EpochSet::new(
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

    /// Datagrams emitted by `tick_gossip` and `on_gossip` for Established peers
    /// must be sealed via `seal_gossip_reply` as `PacketType::EncryptedControl`
    /// datagrams uniformly padded to `OBF_MTU_BUDGET` (1420 bytes) (#207).
    #[test]
    fn test_gossip_emits_encrypted() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "10.0.0.3:51820".parse().unwrap();
        let cfg = PeerConfig {
            public_key: peer.public,
            endpoint: Some(peer_ep),
            alias: None,
            kem: None,
            pq_public_key: None,
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

        // Perform actual handshake key derivation so we hold matching peer codec
        let mut ini = Handshake::initiator(&local.private, &peer.public).unwrap();
        let mut res = Handshake::responder(&peer.private).unwrap();
        let init_msg = ini.write_message(&[]).unwrap();
        res.read_message(&init_msg).unwrap();
        let resp_msg = res.write_message(&[]).unwrap();
        ini.read_message(&resp_msg).unwrap();
        let cb = ini.channel_binding();
        let (auth_key, hp_key) = derive_wire_keys(&cb);
        let (ini_send_k, ini_recv_k) = ini.raw_split_keys();
        let (init_ctrl, resp_ctrl) = derive_control_keys(&auth_key);

        let local_est = Established {
            session: ini.into_session().unwrap(),
            auth_key,
            hp_key,
            raw_send_key: ini_send_k,
            raw_recv_key: ini_recv_k,
            ctrl_codec: ControlCodec::new(init_ctrl, resp_ctrl),
            ctrl_send_nonce: 0,
            ctrl_replay: ReplayWindow::new(),
        };
        let peer_codec = ControlCodec::new(resp_ctrl, init_ctrl);
        let mut peer_replay = ReplayWindow::new();

        const TAG: u64 = 0x1357_9bdf_2468_ace0;
        let dp = DataPlane::new(local_est, TAG, TunnelMode::L3Tun, peer_ep, false, 1200);
        pm.peers[0].state =
            PeerSessionState::Established(Box::new(crate::epoch::EpochSet::new(Box::new(dp), 0)));
        pm.by_tag.insert(TAG, 0);

        // 1. tick_gossip must emit EncryptedControl datagrams of length >= 1420
        pm.tick_gossip(0);
        let tick_egress = pm.drain_tick_egress();
        let gossip_dgs: Vec<_> = tick_egress
            .into_iter()
            .filter(|d| d.dst == peer_ep)
            .collect();
        assert!(
            !gossip_dgs.is_empty(),
            "tick_gossip must emit gossip to established peer"
        );
        for dg in &gossip_dgs {
            assert_eq!(
                dg.bytes[0],
                PacketType::EncryptedControl as u8,
                "tick_gossip egress for established peer must use PacketType::EncryptedControl"
            );
            assert_eq!(
                dg.bytes.len(),
                OBF_MTU_BUDGET,
                "tick_gossip egress must be uniformly padded to OBF_MTU_BUDGET"
            );
            let (inner_type, payload) = peer_codec
                .open(&mut peer_replay, &dg.bytes)
                .expect("peer must open tick_gossip EncryptedControl frame");
            assert_eq!(inner_type, INNER_TYPE_GOSSIP);
            let decoded = GossipMsg::decode(&payload).expect("payload decodes to GossipMsg");
            assert!(matches!(decoded, GossipMsg::Digest(_)));
        }

        // 2. on_gossip must emit EncryptedControl reply datagrams of length >= 1420
        let other = generate_keypair();
        let other_ep: SocketAddr = "192.0.2.77:6000".parse().unwrap();
        let other_rec = mk_record(&ca, 217, other.public, vec![other_ep], 1);
        assert!(pm
            .membership
            .as_mut()
            .unwrap()
            .ingest_record(other_rec.clone(), now_secs()));

        let pull = GossipMsg::PullRequest(vec![yip_membership::node_id(&other.public)]);
        let mut pull_dg = vec![PacketType::Gossip as u8];
        pull.encode(&mut pull_dg);

        let out = pm.on_udp(peer_ep, &pull_dg, 0);
        let reply_dgs = match out {
            DispatchOut::Udp(e) => e,
            _ => panic!("expected DispatchOut::Udp from on_gossip"),
        };
        assert!(!reply_dgs.is_empty(), "on_gossip must emit reply datagrams");
        for dg in reply_dgs {
            assert_eq!(
                dg.bytes[0],
                PacketType::EncryptedControl as u8,
                "on_gossip reply must use PacketType::EncryptedControl"
            );
            assert_eq!(
                dg.bytes.len(),
                OBF_MTU_BUDGET,
                "on_gossip reply must be uniformly padded to OBF_MTU_BUDGET"
            );
            let (inner_type, payload) = peer_codec
                .open(&mut peer_replay, &dg.bytes)
                .expect("peer must open on_gossip EncryptedControl frame");
            assert_eq!(inner_type, INNER_TYPE_GOSSIP);
            let decoded = GossipMsg::decode(&payload).expect("payload decodes to GossipMsg");
            assert!(matches!(decoded, GossipMsg::Records(_)));
        }
    }

    #[test]
    fn test_encrypted_control_ingress() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "10.0.0.5:51820".parse().unwrap();
        let cfg = PeerConfig {
            public_key: peer.public,
            endpoint: Some(peer_ep),
            alias: None,
            kem: None,
            pq_public_key: None,
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

        // Derive mutual control keys
        let mut ini = Handshake::initiator(&local.private, &peer.public).unwrap();
        let mut res = Handshake::responder(&peer.private).unwrap();
        let init_msg = ini.write_message(&[]).unwrap();
        res.read_message(&init_msg).unwrap();
        let resp_msg = res.write_message(&[]).unwrap();
        ini.read_message(&resp_msg).unwrap();
        let cb = ini.channel_binding();
        let (auth_key, hp_key) = derive_wire_keys(&cb);
        let (ini_send_k, ini_recv_k) = ini.raw_split_keys();
        let (init_ctrl, resp_ctrl) = derive_control_keys(&auth_key);

        let local_est = Established {
            session: ini.into_session().unwrap(),
            auth_key,
            hp_key,
            raw_send_key: ini_send_k,
            raw_recv_key: ini_recv_k,
            ctrl_codec: ControlCodec::new(init_ctrl, resp_ctrl),
            ctrl_send_nonce: 0,
            ctrl_replay: ReplayWindow::new(),
        };
        let peer_codec = ControlCodec::new(resp_ctrl, init_ctrl);
        let mut peer_replay = ReplayWindow::new();

        const TAG: u64 = 0x2468_ace0_1357_9bdf;
        let dp = DataPlane::new(local_est, TAG, TunnelMode::L3Tun, peer_ep, false, 1200);
        pm.peers[0].state =
            PeerSessionState::Established(Box::new(crate::epoch::EpochSet::new(Box::new(dp), 0)));
        pm.by_tag.insert(TAG, 0);

        // Populate a record for another member in pm so PullRequest returns a record reply
        let other = generate_keypair();
        let other_ep: SocketAddr = "192.0.2.88:6000".parse().unwrap();
        let other_rec = mk_record(&ca, 201, other.public, vec![other_ep], 1);
        assert!(pm
            .membership
            .as_mut()
            .unwrap()
            .ingest_record(other_rec.clone(), now_secs()));

        // 1. Peer sends sealed PullRequest
        let pull = GossipMsg::PullRequest(vec![yip_membership::node_id(&other.public)]);
        let mut pull_raw = Vec::new();
        pull.encode(&mut pull_raw);

        let sealed_dg = peer_codec.seal(0, INNER_TYPE_GOSSIP, &pull_raw, OBF_MTU_BUDGET);
        assert_eq!(sealed_dg[0], PacketType::EncryptedControl as u8);

        let out = pm.on_udp(peer_ep, &sealed_dg, 0);
        let reply_dgs = match out {
            DispatchOut::Udp(e) => e,
            _ => panic!("expected DispatchOut::Udp from on_encrypted_control"),
        };
        assert!(!reply_dgs.is_empty(), "must emit replies");
        for dg in reply_dgs {
            assert_eq!(dg.bytes[0], PacketType::EncryptedControl as u8);
            assert_eq!(dg.bytes.len(), OBF_MTU_BUDGET);
            let (inner_type, payload) = peer_codec
                .open(&mut peer_replay, &dg.bytes)
                .expect("peer must open reply");
            assert_eq!(inner_type, INNER_TYPE_GOSSIP);
            let decoded = GossipMsg::decode(&payload).expect("payload decodes to GossipMsg");
            assert!(matches!(decoded, GossipMsg::Records(_)));
        }

        // 2. Replay rejection: ingesting identical datagram again must be dropped
        let replay_out = pm.on_udp(peer_ep, &sealed_dg, 0);
        assert!(
            matches!(replay_out, DispatchOut::None),
            "replayed control datagram must be dropped"
        );

        // 3. Tamper rejection: modified ciphertext must be dropped
        let mut tampered = peer_codec.seal(1, INNER_TYPE_GOSSIP, &pull_raw, OBF_MTU_BUDGET);
        tampered[20] ^= 0x01;
        let tamper_out = pm.on_udp(peer_ep, &tampered, 0);
        assert!(
            matches!(tamper_out, DispatchOut::None),
            "tampered control datagram must be dropped"
        );

        // 4. Source isolation: sealed datagram from unknown/spoofed address must be dropped
        let spoofed_ep: SocketAddr = "198.51.100.99:51820".parse().unwrap();
        let fresh_dg = peer_codec.seal(2, INNER_TYPE_GOSSIP, &pull_raw, OBF_MTU_BUDGET);
        let spoof_out = pm.on_udp(spoofed_ep, &fresh_dg, 0);
        assert!(
            matches!(spoof_out, DispatchOut::None),
            "control datagram from non-established source must be dropped"
        );

        // 5. Inner type validation: sealed datagram with non-gossip inner type must be dropped
        let invalid_inner_dg = peer_codec.seal(3, 0x99, &pull_raw, OBF_MTU_BUDGET);
        let invalid_out = pm.on_udp(peer_ep, &invalid_inner_dg, 0);
        assert!(
            matches!(invalid_out, DispatchOut::None),
            "control datagram with invalid inner type must be dropped"
        );
    }

    #[test]
    fn test_encrypted_control_ingress_previous_epoch() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "10.0.0.6:51820".parse().unwrap();
        let cfg = PeerConfig {
            public_key: peer.public,
            endpoint: Some(peer_ep),
            alias: None,
            kem: None,
            pq_public_key: None,
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

        // Epoch 1 keys
        let mut ini1 = Handshake::initiator(&local.private, &peer.public).unwrap();
        let mut res1 = Handshake::responder(&peer.private).unwrap();
        let m1 = ini1.write_message(&[]).unwrap();
        res1.read_message(&m1).unwrap();
        let m2 = res1.write_message(&[]).unwrap();
        ini1.read_message(&m2).unwrap();
        let (auth_key1, hp_key1) = derive_wire_keys(&ini1.channel_binding());
        let (ini_send1, ini_recv1) = ini1.raw_split_keys();
        let (init_ctrl1, resp_ctrl1) = derive_control_keys(&auth_key1);

        let local_est1 = Established {
            session: ini1.into_session().unwrap(),
            auth_key: auth_key1,
            hp_key: hp_key1,
            raw_send_key: ini_send1,
            raw_recv_key: ini_recv1,
            ctrl_codec: ControlCodec::new(init_ctrl1, resp_ctrl1),
            ctrl_send_nonce: 0,
            ctrl_replay: ReplayWindow::new(),
        };
        let peer_codec1 = ControlCodec::new(resp_ctrl1, init_ctrl1);

        const TAG1: u64 = 0x1111_2222_3333_4444;
        let dp1 = DataPlane::new(local_est1, TAG1, TunnelMode::L3Tun, peer_ep, false, 1200);
        let mut epochs = Box::new(crate::epoch::EpochSet::new(Box::new(dp1), 0));

        // Epoch 2 keys
        let mut ini2 = Handshake::initiator(&local.private, &peer.public).unwrap();
        let mut res2 = Handshake::responder(&peer.private).unwrap();
        let m3 = ini2.write_message(&[]).unwrap();
        res2.read_message(&m3).unwrap();
        let m4 = res2.write_message(&[]).unwrap();
        ini2.read_message(&m4).unwrap();
        let (auth_key2, hp_key2) = derive_wire_keys(&ini2.channel_binding());
        let (ini_send2, ini_recv2) = ini2.raw_split_keys();
        let (init_ctrl2, resp_ctrl2) = derive_control_keys(&auth_key2);

        let local_est2 = Established {
            session: ini2.into_session().unwrap(),
            auth_key: auth_key2,
            hp_key: hp_key2,
            raw_send_key: ini_send2,
            raw_recv_key: ini_recv2,
            ctrl_codec: ControlCodec::new(init_ctrl2, resp_ctrl2),
            ctrl_send_nonce: 0,
            ctrl_replay: ReplayWindow::new(),
        };
        const TAG2: u64 = 0x5555_6666_7777_8888;
        let dp2 = DataPlane::new(local_est2, TAG2, TunnelMode::L3Tun, peer_ep, false, 1200);

        // Promote epoch: dp1 moves to previous, dp2 becomes current
        epochs.promote_from_rekey(Box::new(dp2), 100);
        assert!(epochs.previous.is_some(), "previous epoch must be retained");
        pm.peers[0].state = PeerSessionState::Established(epochs);
        pm.by_tag.insert(TAG2, 0);

        // Member record so reply is generated
        let other = generate_keypair();
        let other_ep: SocketAddr = "192.0.2.89:6000".parse().unwrap();
        let other_rec = mk_record(&ca, 202, other.public, vec![other_ep], 1);
        assert!(pm
            .membership
            .as_mut()
            .unwrap()
            .ingest_record(other_rec.clone(), now_secs()));

        // Peer seals PullRequest using OLD epoch 1 keys (simulating in-flight packet during rekey)
        let pull = GossipMsg::PullRequest(vec![yip_membership::node_id(&other.public)]);
        let mut pull_raw = Vec::new();
        pull.encode(&mut pull_raw);
        let sealed_old = peer_codec1.seal(0, INNER_TYPE_GOSSIP, &pull_raw, OBF_MTU_BUDGET);

        // Deliver old-epoch encrypted control packet to pm: must succeed via `previous`
        let out = pm.on_udp(peer_ep, &sealed_old, 200);
        let reply_dgs = match out {
            DispatchOut::Udp(e) => e,
            _ => panic!("expected DispatchOut::Udp for control packet opened via previous epoch"),
        };
        assert!(
            !reply_dgs.is_empty(),
            "must emit replies for gossip opened via previous epoch"
        );
    }

    #[test]
    fn test_seal_gossip_reply_nonce_saturation_triggers_rekey() {
        let auth_key = [0x55u8; 16];
        let (init_ctrl, resp_ctrl) = derive_control_keys(&auth_key);
        let ctrl_codec = ControlCodec::new(init_ctrl, resp_ctrl);

        let local_est = crate::handshake::Established {
            session: yip_crypto::Session::from_raw_keys(&[1u8; 32], &[2u8; 32], 0, 1).unwrap(),
            auth_key,
            hp_key: [0u8; 16],
            raw_send_key: [1u8; 32],
            raw_recv_key: [2u8; 32],
            ctrl_codec,
            ctrl_send_nonce: CTRL_NONCE_REKEY_THRESHOLD - 1,
            ctrl_replay: ReplayWindow::new(),
        };

        const TAG: u64 = 0x9988_7766_5544_3322;
        let peer_ep: SocketAddr = "192.0.2.11:51820".parse().unwrap();
        let dp = DataPlane::new(local_est, TAG, TunnelMode::L3Tun, peer_ep, false, 1200);
        let mut epochs = crate::epoch::EpochSet::new(Box::new(dp), 0);

        let msg = GossipMsg::PullRequest(vec![]);

        // 1. Nonce just below threshold: sealing succeeds, nonce increments
        assert_eq!(epochs.ctrl_send_nonce(), CTRL_NONCE_REKEY_THRESHOLD - 1);
        let sealed_ok = seal_gossip_reply(&mut epochs, &msg, 128);
        assert!(sealed_ok.is_some());
        assert_eq!(epochs.ctrl_send_nonce(), CTRL_NONCE_REKEY_THRESHOLD);
        assert!(!epochs.is_rekey_forced());

        // 2. Nonce reaches threshold: sealing refused, returns None, nonce not reused, rekey triggered
        let sealed_fail = seal_gossip_reply(&mut epochs, &msg, 128);
        assert!(sealed_fail.is_none());
        assert_eq!(epochs.ctrl_send_nonce(), CTRL_NONCE_REKEY_THRESHOLD);
        assert!(epochs.is_rekey_forced());
        assert!(epochs.needs_rekey(0, false, 30_000));

        // 3. Nonce at u64::MAX: sealing refused, returns None, rekey still forced
        epochs.set_ctrl_send_nonce(u64::MAX);
        let sealed_max = seal_gossip_reply(&mut epochs, &msg, 128);
        assert!(sealed_max.is_none());
        assert_eq!(epochs.ctrl_send_nonce(), u64::MAX);
        assert!(epochs.is_rekey_forced());
    }

    #[test]
    fn test_allow_plaintext_gossip_flag_enforcement() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();
        let peer_ep: SocketAddr = "192.0.2.40:5000".parse().unwrap();

        let cfg = PeerConfig {
            public_key: peer.public,
            endpoint: Some(peer_ep),
            alias: None,
            kem: None,
            pq_public_key: None,
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

        let auth_key = [0x33u8; 16];
        let (init_ctrl, resp_ctrl) = derive_control_keys(&auth_key);
        let local_est = crate::handshake::Established {
            session: yip_crypto::Session::from_raw_keys(&[1u8; 32], &[2u8; 32], 0, 1).unwrap(),
            auth_key,
            hp_key: [0u8; 16],
            raw_send_key: [1u8; 32],
            raw_recv_key: [2u8; 32],
            ctrl_codec: ControlCodec::new(init_ctrl, resp_ctrl),
            ctrl_send_nonce: 0,
            ctrl_replay: ReplayWindow::new(),
        };

        const TAG: u64 = 0x1234_5678_9abc_def0;
        let dp = DataPlane::new(local_est, TAG, TunnelMode::L3Tun, peer_ep, false, 1200);
        pm.peers[0].state =
            PeerSessionState::Established(Box::new(crate::epoch::EpochSet::new(Box::new(dp), 0)));
        pm.by_tag.insert(TAG, 0);

        // Populate a member record to return
        let other = generate_keypair();
        let other_rec = mk_record(&ca, 202, other.public, vec![peer_ep], 1);
        assert!(pm
            .membership
            .as_mut()
            .unwrap()
            .ingest_record(other_rec.clone(), now_secs()));

        let pull = GossipMsg::PullRequest(vec![yip_membership::node_id(&other.public)]);
        let mut gossip_dg = vec![PacketType::Gossip as u8];
        pull.encode(&mut gossip_dg);

        // 1. With allow_plaintext_gossip = true (default), unencrypted gossip is processed
        assert!(pm.allow_plaintext_gossip);
        let out_allowed = pm.on_udp(peer_ep, &gossip_dg, 0);
        assert!(
            matches!(out_allowed, DispatchOut::Udp(_)),
            "plaintext gossip must be processed when allow_plaintext_gossip is true"
        );

        // 2. With allow_plaintext_gossip = false, unencrypted gossip is dropped
        pm.allow_plaintext_gossip = false;
        let out_dropped = pm.on_udp(peer_ep, &gossip_dg, 0);
        assert!(
            matches!(out_dropped, DispatchOut::None),
            "plaintext gossip must be dropped when allow_plaintext_gossip is false"
        );
    }
}
