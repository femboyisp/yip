//! Relay/rendezvous path: relay-wrapping egress, rendezvous events, relayed handshake/data handling.
use super::*;

impl PeerManager {
    /// Wrap a raw egress datagram destined for peer `idx` through the relay
    /// (`rendezvous.relay(local, peer_node, raw)` → dst = server). Returns
    /// `None` if no rendezvous is configured (should not happen for a peer
    /// marked `relay`).
    pub(super) fn relay_wrap(&mut self, idx: usize, raw: Vec<u8>) -> Option<EgressDatagram> {
        let node = self.peers[idx].node;
        let local = self.local_node_id;
        self.rendezvous.as_mut().map(|r| r.relay(local, node, &raw))
    }

    /// Emit a `lookup(peer_node)` for peer `idx`, debounced to at most one per
    /// [`LOOKUP_INTERVAL_MS`]. Returns `None` if throttled or no rendezvous.
    pub(super) fn maybe_lookup(&mut self, idx: usize, now_ms: u64) -> Option<EgressDatagram> {
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

    /// Demux a datagram that arrived from the rendezvous server: parse it into
    /// an [`RdvEvent`] and drive the path SM / relay path accordingly. Every
    /// mutation is guarded to affect only a non-`Established` peer
    /// (anti-hijack): a live session's committed egress target is never
    /// redirected by an unauthenticated server message.
    pub(super) fn on_rdv(&mut self, dg: &[u8], now_ms: u64) -> DispatchOut<'_> {
        let ev = match self.rendezvous.as_ref() {
            Some(r) => r.parse(dg),
            None => return DispatchOut::None,
        };
        match ev {
            RdvEvent::PeerCandidate { node, addr, record } => {
                // Mesh mode (membership configured): a candidate carrying a
                // record must verify against our roots before we act on it —
                // an unverifiable/forged record drops the candidate entirely
                // (no probe). Non-mesh (no membership) or a candidate with no
                // record (legacy server) keeps today's unauthenticated
                // behavior (#37 Task 5).
                //
                // The record must also be FOR the peer we resolved: `verify_record`
                // proves the record is a valid member record (cert chains to a
                // root, signature valid, node_id binds its own cert), but the
                // outer `PeerInfo.node` and `record.node_id` are independent on
                // the wire. Binding them here stops a server from answering
                // `Lookup(Y)` with a genuine record belonging to some other
                // member X — otherwise a valid-but-wrong-identity record would
                // pass and let the server steer a probe for Y at an arbitrary
                // address.
                let record_ok = match (self.membership.as_ref(), &record) {
                    (Some(m), Some(r)) => r.node_id == node && m.verify_record(r, now_secs()),
                    _ => true,
                };
                if record_ok {
                    if let Some(&idx) = self.by_node.get(&node) {
                        if !matches!(self.peers[idx].state, PeerState::Established(_)) {
                            self.peers[idx].path.on_peer_candidate(addr, now_ms);
                        }
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
        let (established, resp_pkt, remote_static, initiator_payload) =
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

        // #34: the msg1 payload is [ts || cert]. Split the anti-replay label
        // off; the cert remainder is what admission checks. Too short to hold
        // the label ⇒ malformed ⇒ fail closed.
        let Some((init_ts, initiator_cert)) =
            crate::handshake::parse_init_payload(&initiator_payload)
        else {
            return DispatchOut::None;
        };

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
            //
            // #34 (retires #36): a direct/punch-established (relay==false)
            // peer receiving a relayed Init now adopts the relay only for a
            // FRESH new-ephemeral Init — never for a bare retransmit of the
            // Init that built its own session. See the freshness-gated
            // adoption block below.
            PeerState::Established(_) => {
                let Some(init_eph) = crate::handshake::init_ephemeral(dg) else {
                    return DispatchOut::None; // malformed Init
                };
                // #41: a mid-session rekey Init must carry a currently-valid cert
                // (mesh mode). A revoked/expired member presenting a stale cert
                // loses its session within a rekey interval instead of at process
                // restart. Checked before the #34/#36 adoption so a revoked peer
                // is never adopted onto the relay.
                if !self.is_root(remote_static)
                    && !self.responder_cert_ok(initiator_cert, remote_static)
                {
                    self.drop_session(idx);
                    return DispatchOut::None;
                }
                // #34/#36: a direct-established (relay==false) peer receiving a
                // relayed FRESH new-ephemeral Init means the initiator escalated
                // punch->relay (or restarted) with a fresh Init — adopt the relay
                // for our egress and rebuild. Freshness-gated (accept_fresh_init),
                // so a REPLAY (stale ts) is refused → no downgrade. A seen-ephemeral
                // relayed Init is a retransmit of the escalation Init we already
                // adopted+answered (this peer is then already relay==true) and is
                // replayed by rekey_init_core's cached_resp dedup. The #91
                // path-consistency guard is preserved: a direct peer never
                // completes a relayed Init unless it adopts the relay here.
                //
                // `last_accepted_init_ts.is_some()` is REQUIRED here (not present
                // in earlier drafts of this gate): a peer that reached `Established`
                // as the INITIATOR of its own direct session (it sent the cold-start
                // Init and completed on the responder's `[HandshakeResp]`) never
                // accepted an inbound Init from this peer, so `last_accepted_init_ts`
                // stays `None` — and `accept_fresh_init` treats "no baseline yet" as
                // always-fresh (by design, for genuine cold-start admission). Without
                // this guard that same "no baseline" reading would let ANY fresh
                // relayed Init hijack such a peer onto the relay, reintroducing
                // exactly the #91 anti-hijack hole
                // (`anti_hijack_established_peer_ignores_relayed_handshake_init`) —
                // the adoption exception only ever applied to a peer that
                // *previously responded* to a direct/punch Init (cached_resp_init_eph
                // + last_accepted_init_ts set together), never to an initiator-only
                // session.
                if !self.peers[idx].relay
                    && self.peers[idx].last_accepted_init_ts.is_some()
                    && self.peers[idx].cached_resp_init_eph != Some(init_eph)
                    && self.accept_fresh_init(idx, &init_ts)
                {
                    self.peers[idx].relay = true;
                }
                if self.peers[idx].relay {
                    self.rekey_init_core(
                        idx,
                        established,
                        resp_pkt,
                        init_eph,
                        init_ts,
                        self.server_addr(),
                        true,
                    )
                } else {
                    DispatchOut::None
                }
            }
            PeerState::Handshaking(_) if self.local_pub < self.peers[idx].pubkey => {
                DispatchOut::None
            }
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
                // #34: same freshness gate as the direct cold-start arm below.
                // A relay peer doesn't learn an `endpoint` (its egress is
                // always relay-wrapped, keyed off `relay`/`server_addr`, not a
                // direct address) but still records `last_accepted_init_ts` on
                // a fresh accept, so a later direct-path replay of an old Init
                // against this same peer can't rebuild a session either.
                if !self.accept_fresh_init(idx, &init_ts) {
                    return DispatchOut::None;
                }
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
                self.peers[idx].last_accepted_init_ts = Some(init_ts);
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
                if !self.is_root(self.peers[idx].pubkey)
                    && !self.responder_cert_ok(&responder_payload, self.peers[idx].pubkey)
                {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::testutil::*;
    use ed25519_dalek::SigningKey;
    use yip_crypto::generate_keypair;

    /// Relay-path counterpart of
    /// `stale_replayed_cold_start_init_does_not_hijack_endpoint`: the same
    /// #34 freshness gate, `if !self.accept_fresh_init(idx, &init_ts) {
    /// return DispatchOut::None; }`, guards `relayed_handshake_init`'s own
    /// `Idle | Handshaking` arm (~line 1241), not just the direct path's.
    /// A relay-reached peer that was `Established`, dropped back to `Idle`,
    /// still remembers `last_accepted_init_ts = t1`. A captured OLD Init
    /// (new ephemeral, ts <= t1) redelivered over the relay must be rejected
    /// BEFORE it re-admits a session, exactly like the direct-path sibling —
    /// proving the gate is wired into the relay cold-start arm too, not only
    /// `handle_handshake_init`'s.
    #[test]
    fn stale_replayed_relayed_cold_start_init_is_rejected() {
        let local = generate_keypair();
        let peer_kp = generate_keypair();
        let cfg_peer = PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
        };
        let (mut pm, _sent) = pm_with_mock_rdv(&local, &[cfg_peer]);

        // Cold-start over the relay with a genuine ts `t1`: establishes and
        // records `last_accepted_init_ts`.
        let t1 = crate::handshake::now_tai64n();
        let (_hs1, init_pkt_1) = HandshakeState::start_initiator(
            &peer_kp.private,
            &local.public,
            &init_payload_with_ts(t1, &[]),
        )
        .unwrap();
        let out1 = pm.on_udp(mock_server(), &relay_deliver(&peer_kp, init_pkt_1), 0);
        assert!(
            has_relayed_handshake_resp(&out1),
            "a genuine relayed cold-start Init must establish"
        );
        assert!(pm.peers[0].relay, "sanity: the peer adopted the relay path");
        assert_eq!(pm.peers[0].last_accepted_init_ts, Some(t1));

        // Drop the session: reverts to Idle, evicts by_tag — but
        // `last_accepted_init_ts` (and `relay`) are in-memory and survive
        // (never reset by `drop_session`), same as the direct-path sibling.
        pm.drop_session(0);
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
        assert_eq!(pm.peers[0].last_accepted_init_ts, Some(t1));

        // A NEW-ephemeral Init with ts < t1, redelivered over the relay (as
        // a captured/replayed datagram forwarded by the rendezvous server).
        let t0 = older_ts(t1);
        let (_hs2, init_pkt_2) = HandshakeState::start_initiator(
            &peer_kp.private,
            &local.public,
            &init_payload_with_ts(t0, &[]),
        )
        .unwrap();
        let out2 = pm.on_udp(mock_server(), &relay_deliver(&peer_kp, init_pkt_2), 200);

        match out2 {
            DispatchOut::None => {}
            _ => panic!("a stale-ts relayed cold-start Init must be silently dropped"),
        }
        assert!(
            matches!(pm.peers[0].state, PeerState::Idle),
            "a rejected relayed cold-start Init must not admit a session"
        );
        assert_eq!(
            pm.peers[0].last_accepted_init_ts,
            Some(t1),
            "last_accepted_init_ts must not change on a rejected relayed Init"
        );
        assert!(
            pm.by_tag.is_empty(),
            "no session (hence no conn_tag) must have been admitted"
        );
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
                record: None,
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
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &peer_kp.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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

    /// #34 Task 4 (retires #36): a peer that adopted the responder role over
    /// a DIRECT/punch path (`Established`, `relay == false`) receives a
    /// RELAYED FRESH new-ephemeral Init — the initiator escalated
    /// punch->relay and sent a FRESH Init (#34 inverts #36's ephemeral
    /// preservation, so this is no longer a byte-identical retransmit of the
    /// original). B adopts the relay for its own egress (else B keeps
    /// sending to A's dead punch address — the reverse black hole) and
    /// REBUILDS: `rekey_init_core` installs a fresh `next` epoch (a
    /// genuinely new session round, not a `cached_resp` replay) and advances
    /// `last_accepted_init_ts`.
    #[test]
    fn direct_established_responder_adopts_relay_on_fresh_relayed_init_and_rebuilds() {
        let (mut pm_r, kp_a, _a_init_pkt) = responder_established_direct_for_initiator(100);
        let local_pub = pm_r.local_pub;
        let tag_before = established_tag(&pm_r, 0).expect("responder established");
        let last_ts = pm_r.peers[0]
            .last_accepted_init_ts
            .expect("cold-start Init recorded a ts");

        // A escalated punch->relay with a FRESH Init: new ephemeral, fresh ts.
        let t_fresh = newer_ts(last_ts);
        let (_hs2, fresh_init_pkt) = HandshakeState::start_initiator(
            &kp_a.private,
            &local_pub,
            &init_payload_with_ts(t_fresh, &[]),
        )
        .unwrap();
        let relayed = wrap_relay_deliver(&pm_r, &fresh_init_pkt);
        let out = pm_r.on_udp(mock_server(), &relayed, 5_000);

        assert!(
            has_relayed_handshake_resp(&out),
            "must reply with a relay-wrapped Resp"
        );
        assert!(
            pm_r.peers[0].relay,
            "must adopt the relay for B's own egress"
        );
        assert_eq!(
            established_tag(&pm_r, 0),
            Some(tag_before),
            "current epoch stays untouched (rekey semantics: B keeps sending on it \
             until the initiator confirms the new one)"
        );
        match &pm_r.peers[0].state {
            PeerState::Established(epochs) => assert!(
                epochs.next.is_some(),
                "a fresh new-ephemeral Init must REBUILD: install a new `next` epoch, \
                 not replay a cached_resp"
            ),
            _ => panic!("must stay Established"),
        }
        assert_eq!(
            pm_r.peers[0].last_accepted_init_ts,
            Some(t_fresh),
            "last_accepted_init_ts must advance to the fresh label"
        );
    }

    /// #34 Task 4 (retires #36): the same direct-established peer receiving
    /// a RELAYED Init with a DIFFERENT ephemeral but a STALE ts (not
    /// strictly newer than what we already accepted from this peer) must NOT
    /// adopt the relay and must NOT rebuild — `accept_fresh_init` refuses it
    /// before `relay` is ever flipped. This is the downgrade #36 used to
    /// accept as a tradeoff (an attacker replaying a captured old Init could
    /// force a direct->relay downgrade); #34 closes it.
    #[test]
    fn direct_established_responder_ignores_relayed_new_ephemeral_init() {
        let (mut pm_r, kp_a, _a_init_pkt) = responder_established_direct_for_initiator(100);
        let local_pub = pm_r.local_pub;
        let tag_before = established_tag(&pm_r, 0).expect("responder established");
        let last_ts = pm_r.peers[0]
            .last_accepted_init_ts
            .expect("cold-start Init recorded a ts");

        // A relayed Init with a NEW ephemeral but a STALE ts (<= last accepted) — a replay.
        let t_stale = older_ts(last_ts);
        let (_hs2, stale_init_pkt) = HandshakeState::start_initiator(
            &kp_a.private,
            &local_pub,
            &init_payload_with_ts(t_stale, &[]),
        )
        .unwrap();
        let relayed = wrap_relay_deliver(&pm_r, &stale_init_pkt);
        let dropped = matches!(
            pm_r.on_udp(mock_server(), &relayed, 5_000),
            DispatchOut::None
        );

        assert!(
            !pm_r.peers[0].relay,
            "must NOT adopt relay for a stale-ts relayed init — the downgrade is closed"
        );
        assert!(dropped, "must fail-closed drop, no reply");
        assert_eq!(
            established_tag(&pm_r, 0),
            Some(tag_before),
            "must NOT rebuild: current session untouched"
        );
        assert_eq!(
            pm_r.peers[0].last_accepted_init_ts,
            Some(last_ts),
            "last_accepted_init_ts must not change on a rejected Init"
        );
    }

    // ── #91 Task 2: relay-path rekey completion ─────────────────────────────

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

    #[test]
    fn relay_rekey_init_retransmit_is_idempotent_new_ephemeral_builds_new_next() {
        // Relay-path counterpart of
        // `retransmitted_rekey_init_is_idempotent_new_ephemeral_builds_new_next`:
        // a relay-Established responder receiving a rekey `Init` through the
        // relay must dedupe identically — same ephemeral resends the SAME
        // cached (relay-wrapped) Resp and does NOT mint a second `next`; a
        // genuinely new ephemeral DOES build a new `next`.
        let (mut pm, local, peer_kp, _old_tag) = established_relay_pm(100);

        let (_hs1, init_pkt_1) = HandshakeState::start_initiator(
            &peer_kp.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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
        let (_hs2, init_pkt_2) = HandshakeState::start_initiator(
            &peer_kp.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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
        let (hs, init_pkt) = HandshakeState::start_initiator(
            &local.private,
            &peer_kp.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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
        let (hs, init_pkt) = HandshakeState::start_initiator(
            &local.private,
            &peer_kp.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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

        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &peer_kp.private,
            &local.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();

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

    /// Relay-path counterpart of `revoked_tabled_peer_cold_start_reinit_rejected`:
    /// a TABLED mesh peer reached over the relay, whose session was dropped,
    /// must not be re-admitted by `relayed_handshake_init`'s Idle|Handshaking
    /// arm when its cold-start re-Init carries an expired cert.
    #[test]
    fn revoked_tabled_relay_peer_cold_start_reinit_rejected() {
        let ca = test_ca();
        let local = generate_keypair();
        let peer = generate_keypair();

        let local_sign = SigningKey::from_bytes(&[5u8; 32]);
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
            endpoint: None,
        };
        let sent = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let rdv: Box<dyn Rendezvous> = Box::new(MockRdv {
            server: mock_server(),
            sent: sent.clone(),
        });
        let mut pm = PeerManager::new(
            local.private,
            local.public,
            &[cfg_peer],
            TunnelMode::L3Tun,
            Some(rdv),
            Some(membership),
            false,
        );

        peer_test_key_registry()
            .lock()
            .unwrap()
            .insert(peer.public, (peer.private, [6u8; 32]));

        // Cold-start over the relay: establishes. Task 2b's re-admission gate
        // requires a currently-valid cert on THIS leg too (mirroring the real
        // initiator's `begin_handshake`, which always attaches
        // `own_cert_bytes()` when membership is enabled), so mint one here.
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &peer.private,
            &local.public,
            &crate::handshake::frame_init_payload(&valid_cert_bytes(&pm, 0)),
        )
        .unwrap();
        let out = pm.on_udp(mock_server(), &relay_deliver(&peer, init_pkt), 0);
        assert!(
            has_relayed_handshake_resp(&out),
            "cold-start relayed init must establish"
        );
        assert!(pm.peers[0].relay);

        // Session dropped (revocation / sweep); the peer stays tabled, Idle.
        pm.drop_session(0);
        assert!(matches!(pm.peers[0].state, PeerState::Idle));

        // A fresh relayed cold-start Init carrying an EXPIRED cert.
        let expired = expired_cert_bytes(&pm, 0);
        let (_hs2, reinit_pkt) = HandshakeState::start_initiator(
            &peer.private,
            &local.public,
            &crate::handshake::frame_init_payload(&expired),
        )
        .unwrap();
        let out2 = pm.on_udp(mock_server(), &relay_deliver(&peer, reinit_pkt), 300_000);

        assert!(
            matches!(out2, DispatchOut::None),
            "an expired cert must not re-admit a tabled relay peer"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
    }
}
