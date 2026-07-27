//! Epoch rekey: scheduling, initiator/responder rekey Init/Resp cores, rekey egress.
use super::*;

impl PeerManager {
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
    pub(super) fn drive_rekey_schedule(
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
            let cert = self
                .membership
                .as_ref()
                .map(Membership::own_cert_bytes)
                .unwrap_or_default();
            // #34: frame the msg1 payload as [ts || cert] (see begin_handshake).
            let payload = crate::handshake::frame_init_payload(&cert);
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
    /// 3. `!self.accept_fresh_init(idx, &init_ts)` (#34): `init_ts` is not
    ///    strictly newer than the greatest label we have accepted from this
    ///    peer in a session-building Init — a stale/replayed Init, or a
    ///    backwards-clock peer. SILENT DROP (`DispatchOut::None`): unlike the
    ///    retired age gate, this does NOT fall back to resending
    ///    `cached_resp` — a stale-ts Init is either an attacker replay or a
    ///    clock regression, and either way it gets no reply. Case 1 above
    ///    (`cached_resp_init_eph` match) already answers the legitimate "same
    ///    round, arrived again" case — with the SAME ts as when it was first
    ///    accepted — before this point is ever reached, so this only fires
    ///    for a genuinely DIFFERENT (new-ephemeral) Init whose ts fails to
    ///    advance. This keeps
    ///    `duplicate_init_after_established_does_not_tear_down_session`
    ///    green via case 1's dedup, not this gate.
    /// 4. Otherwise: a genuinely NEW, fresh-ts rekey round. Install
    ///    `established` as the responder's unconfirmed `next` epoch, keyed by
    ///    `init_eph` (`EpochSet::install_next`) — `current` is untouched, so
    ///    this side keeps SENDING on the old epoch. Record
    ///    `last_accepted_init_ts = init_ts` (#34) so a later replay of this
    ///    same round's ts can never be re-accepted. The responder's own
    ///    switch happens later, automatically, inside `EpochSet::inbound_open`
    ///    (Task 1) on the first inbound frame that authenticates under `next`.
    pub(super) fn handle_rekey_init(
        &mut self,
        idx: usize,
        src: SocketAddr,
        established: Established,
        resp_pkt: Vec<u8>,
        init_ts: [u8; 12],
        init_eph: [u8; 32],
    ) -> DispatchOut<'_> {
        self.rekey_init_core(idx, established, resp_pkt, init_eph, init_ts, src, false)
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
    pub(super) fn rekey_init_core(
        &mut self,
        idx: usize,
        established: Established,
        resp_pkt: Vec<u8>,
        init_eph: [u8; 32],
        init_ts: [u8; 12],
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

        // #34: `init_ts` must be strictly newer than the greatest label we
        // have ever accepted from this peer, else this is a stale/replayed
        // Init (or a backwards-clock peer) — silently dropped, no reply. See
        // `handle_rekey_init`'s doc comment (case 3) for why this is a
        // silent drop rather than the retired age gate's cached-resp
        // fallback.
        if !self.accept_fresh_init(idx, &init_ts) {
            return DispatchOut::None;
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
        // #34: record the accepted label so a replay of this same round (or
        // anything older) can never be re-accepted.
        self.peers[idx].last_accepted_init_ts = Some(init_ts);

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
    pub(super) fn handle_rekey_resp(
        &mut self,
        idx: usize,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        self.rekey_resp_core(idx, dg, now_ms, false)
    }

    /// Shared core for [`handle_rekey_resp`] (`via_relay = false`) and its
    /// relay-path counterpart (#91 Task 2, `via_relay = true`). See
    /// `handle_rekey_resp`'s doc comment above for the full behavior
    /// (UNCHANGED here — only `peer_addr` and the prime-emit are
    /// parameterized by `via_relay`, via [`push_rekey_egress`]).
    pub(super) fn rekey_resp_core(
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
        if !self.is_root(self.peers[idx].pubkey)
            && !self.responder_cert_ok(&responder_payload, self.peers[idx].pubkey)
        {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::testutil::*;
    use yip_crypto::generate_keypair;

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
        let (hs, init_pkt) = HandshakeState::start_initiator(
            &kp_a.private,
            &kp_b.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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
        let (hs, init_pkt) = HandshakeState::start_initiator(
            &kp_a.private,
            &kp_b.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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

    #[test]
    fn retransmitted_rekey_init_is_idempotent_new_ephemeral_builds_new_next() {
        // Critical-bug regression (9a final review): the responder must
        // treat a retransmit of the SAME rekey `Init` (identical bytes,
        // hence identical Noise ephemeral) as a no-op — resend the cached
        // Resp, do NOT mint a second `next` session. A genuinely NEW Init
        // (fresh ephemeral) must still build a new `next`, replacing the
        // old one.
        let (_pm_a, mut pm_b, ep_a, _ep_b, kp_a, kp_b) = established_pm_pair(100);

        let (_hs1, init_pkt_1) = HandshakeState::start_initiator(
            &kp_a.private,
            &kp_b.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();

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
        let (_hs2, init_pkt_2) = HandshakeState::start_initiator(
            &kp_a.private,
            &kp_b.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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
        let (hs, init_pkt) = HandshakeState::start_initiator(
            &kp_a.private,
            &kp_b.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();
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
    fn rekey_init_freshness_gate_replaces_age_gate() {
        // #34: `current`'s age is no longer the discriminator for whether a
        // NEW-ephemeral Init against an Established peer is a genuine rekey
        // — the retired `EpochSet::accept_rekey_init` age gate is replaced by
        // `PeerManager::accept_fresh_init`'s ts freshness check. This test
        // used to assert the OPPOSITE for its first case (a rekey Init
        // arriving well under interval/2 was REJECTED); that assertion is
        // now wrong by design (a fresh-ts Init completes regardless of
        // `current`'s age), so it is rewritten here per the #34 admission
        // change rather than left red.
        let (mut pm_a, mut pm_b, ep_a, ep_b, kp_a, kp_b) = established_pm_pair(100);
        let old_tag_a = established_tag(&pm_a, 0).unwrap();
        let old_tag_b = established_tag(&pm_b, 0).unwrap();

        // A never admitted an inbound Init (it was the cold-start
        // INITIATOR), so its `last_accepted_init_ts` is `None`: the very
        // first Init it receives is always fresh and completes — even at
        // t=10, well under the OLD interval/2 = 50 threshold that used to
        // gate this.
        let t_b = crate::handshake::now_tai64n();
        let (_hs_early, init_pkt_early) = HandshakeState::start_initiator(
            &kp_b.private,
            &kp_a.public,
            &init_payload_with_ts(t_b, &[]),
        )
        .unwrap();
        let resp_early = resp_bytes(&pm_a.on_udp(ep_b, &init_pkt_early, 10));
        assert_eq!(
            resp_early.len(),
            1,
            "a fresh-ts new-ephemeral Init must complete regardless of current's age"
        );
        match &pm_a.peers[0].state {
            PeerState::Established(epochs) => {
                assert!(epochs.next.is_some(), "next must be installed")
            }
            _ => panic!("pm_a must still be Established"),
        }
        assert_eq!(established_tag(&pm_a, 0), Some(old_tag_a));
        assert_eq!(pm_a.peers[0].last_accepted_init_ts, Some(t_b));

        // B DOES have a baseline (it admitted A's cold-start Init). A
        // fresh-ts rekey Init from A installs `next`, replies with a Resp,
        // and leaves `current` untouched (B keeps sending on the OLD epoch)
        // — exactly like before, just gated on `ts` now instead of age.
        let last_b = pm_b.peers[0]
            .last_accepted_init_ts
            .expect("B admitted A's cold-start Init");
        let t_fresh = newer_ts(last_b);
        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &kp_a.private,
            &kp_b.public,
            &init_payload_with_ts(t_fresh, &[]),
        )
        .unwrap();
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
        assert_eq!(pm_b.peers[0].last_accepted_init_ts, Some(t_fresh));

        // A STALE-ts new-ephemeral Init (older than the label B just
        // accepted) is dropped outright, no matter how much later in wall
        // time it arrives — `current`'s age is irrelevant either way.
        let t_stale = older_ts(t_fresh);
        let (_hs2, init_pkt_stale) = HandshakeState::start_initiator(
            &kp_a.private,
            &kp_b.public,
            &init_payload_with_ts(t_stale, &[]),
        )
        .unwrap();
        match pm_b.on_udp(ep_a, &init_pkt_stale, 100_000) {
            DispatchOut::None => {}
            _ => panic!("a stale-ts rekey Init must be dropped"),
        }
        assert_eq!(
            pm_b.peers[0].last_accepted_init_ts,
            Some(t_fresh),
            "a rejected Init must not move last_accepted_init_ts"
        );

        // B still sends on the OLD epoch (current untouched throughout): a
        // frame it emits now still carries the OLD tag.
        let still_old = pm_b.on_tun(&dummy_tun_pkt(), 100_000);
        assert_eq!(still_old[0].bytes[0], PacketType::Data as u8);
    }

    #[test]
    fn cold_start_init_retransmit_past_interval_half_resends_original_not_rekey() {
        // Important-2 regression (9a final review): `HANDSHAKE_TOTAL_MS`
        // (90s) exceeds `REKEY_INTERVAL_MS`/2, so a retransmit of the
        // ORIGINAL cold-start Init can legitimately still be in flight well
        // past interval/2. It must still be recognized (by ephemeral match
        // against `cached_resp_init_eph`) as the SAME cold-start round and
        // answered with the original cached reply — never misclassified as a
        // rekey round (which would install a spurious `next`) or, post-#34,
        // dropped as stale (the retransmit's `ts` equals — not exceeds —
        // `last_accepted_init_ts`, so the ephemeral dedup MUST run before the
        // freshness gate is ever consulted; see `rekey_init_core`'s case 1).
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

        let (_hs, init_pkt) = HandshakeState::start_initiator(
            &kp_i.private,
            &kp_r.public,
            &crate::handshake::frame_init_payload(&[]),
        )
        .unwrap();

        let resp1 = resp_bytes(&pm_r.on_udp(ep_i, &init_pkt, 0));
        assert_eq!(resp1.len(), 1, "first init must produce one HandshakeResp");
        let tag1 = established_tag(&pm_r, 0).expect("responder must be Established");

        // Retransmit of the SAME cold-start Init, arriving at t=70 — past
        // interval/2 (50). It is NOT a plausible rekey: it must resend the
        // cached original reply and must NOT install a `next`.
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
}
