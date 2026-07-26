//! Mesh gossip: digest targets, periodic gossip tick, inbound gossip handling.
use super::*;

impl PeerManager {
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
    pub(super) fn on_gossip(
        &mut self,
        src: SocketAddr,
        dg: &[u8],
        _now_ms: u64,
    ) -> DispatchOut<'_> {
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
    pub(super) fn tick_gossip(&mut self, now_ms: u64) {
        let have_established = self
            .peers
            .iter()
            .any(|p| matches!(p.state, PeerState::Established(_)));

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
        for digest in digests {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::testutil::*;
    use ed25519_dalek::SigningKey;
    use yip_crypto::generate_keypair;

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
}
