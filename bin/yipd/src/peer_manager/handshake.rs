//! Cold-start Noise-IK handshake: initiator begin, responder Init/Resp handling, freshness gate, session drop.
use super::*;

impl PeerManager {
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
    pub(super) fn begin_handshake(
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
    pub(super) fn responder_cert_ok(&self, payload: &[u8], peer_pub: [u8; 32]) -> bool {
        match self.membership.as_ref() {
            None => true,
            Some(m) => Cert::decode(payload)
                .is_some_and(|cert| m.verify_cert(&cert, &peer_pub, now_secs())),
        }
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
    pub(super) fn accept_fresh_init(&self, idx: usize, ts: &[u8; 12]) -> bool {
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
    pub(super) fn drop_session(&mut self, idx: usize) {
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

    pub(super) fn handle_handshake_init(
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
    pub(super) fn handle_handshake_resp(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::testutil::*;
    use ed25519_dalek::SigningKey;
    use yip_crypto::generate_keypair;
    use yip_membership::RootSet;

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
}
