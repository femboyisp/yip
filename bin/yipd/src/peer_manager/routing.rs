//! Path-SM driving for idle peers, inbound/outbound routing, and established-session dispatch.
use super::*;

impl PeerManager {
    /// Map a path stage to the committed [`PathKind`] for a session that
    /// completes while in that stage. `Relayed` peers are committed
    /// explicitly (they never sit in the `Relaying` *stage* when admitted via
    /// a relayed handshake), so `Relaying`/`Failed` fall back to `Punched`.
    pub(super) fn kind_for_stage(stage: PathStage) -> PathKind {
        match stage {
            PathStage::Direct => PathKind::Direct,
            PathStage::Punching => PathKind::Punched,
            // Lossy fallback: only reached for a *non-relayed* completion (a
            // relayed completion commits `Relayed` explicitly, never routing
            // here), so mapping these residual stages to `Punched` is safe.
            PathStage::Relaying | PathStage::Failed => PathKind::Punched,
        }
    }

    /// Drive the path SM for a non-`Established`, non-`Handshaking` (i.e.
    /// `Idle`) peer `idx` and act on the resulting [`PathAction`], pushing any
    /// egress into `tick_egress`. Only called when a rendezvous is configured.
    pub(super) fn drive_path_idle(&mut self, idx: usize, now_ms: u64) {
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
    pub(super) fn route_tun_index(&self, inner: &[u8]) -> Option<usize> {
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

    /// WireGuard-style roaming: after a datagram has AUTHENTICATED and passed
    /// the replay window (a non-`None` `inbound_open`), point a direct peer's
    /// `endpoint` at the observed source AND redirect its egress there. A
    /// `relay` peer's `endpoint` is a rendezvous placeholder and must not roam.
    /// Gated on `src` differing so steady-state traffic is a no-op. This never
    /// runs for an unauthenticated Init (that path does not call `inbound_open`),
    /// preserving #34.
    ///
    /// Updating `endpoint` alone heals ingress demux/deobfuscation, but egress
    /// datagrams are stamped from each epoch's `DataPlane::peer_addr` (not
    /// `endpoint`), so the roam must also be pushed into the live `EpochSet` or
    /// return traffic keeps targeting the peer's stale (post-rebind, dead)
    /// address.
    fn relearn_endpoint(&mut self, idx: usize, src: SocketAddr) {
        if !self.peers[idx].relay && self.peers[idx].endpoint != Some(src) {
            self.peers[idx].endpoint = Some(src);
            if let PeerState::Established(epochs) = &mut self.peers[idx].state {
                epochs.set_peer_addr(src);
            }
        }
    }

    /// Dispatch a `Data`/`Control` datagram to peer `idx`'s `EpochSet` (via
    /// `inbound_open`) and re-map its `EpochInbound` into a `DispatchOut`.
    /// Returns `DispatchOut::None` if `idx` is not (or no longer)
    /// `Established`.
    fn dispatch_established(
        &mut self,
        idx: usize,
        src: SocketAddr,
        dg: &[u8],
        now_ms: u64,
    ) -> DispatchOut<'_> {
        let PeerState::Established(epochs) = &mut self.peers[idx].state else {
            return DispatchOut::None;
        };
        // `EpochInbound::Send`/`TunThenSend` carry the full `EgressDatagram`
        // (real `dst` + `fate`), so no reconstruction from
        // `self.peers[idx].endpoint` is needed — that placeholder is wrong
        // for relay-established peers (their `DataPlane::peer_addr` is a
        // `server_addr()` stand-in; `endpoint` may hold an unconfirmed
        // candidate or `None`).
        let opened = epochs.inbound_open(dg, now_ms);
        if !matches!(opened, crate::epoch::EpochInbound::None) {
            // Authenticated + non-replayed (M2 roaming) — safe to roam.
            self.relearn_endpoint(idx, src);
        }
        match opened {
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

    pub(super) fn handle_data_or_control(
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
            return self.dispatch_established(idx, src, dg, now_ms);
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
            // Authenticated + non-replayed (M2 roaming) — safe to roam.
            self.relearn_endpoint(idx, src);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::testutil::*;

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
    fn dispatch_established_relearns_endpoint_directly() {
        // The `route_data` address-match path always calls
        // `dispatch_established` with `src == endpoint` (by construction of
        // the match), so `on_udp` alone can never exercise
        // `dispatch_established`'s own relearn call with a DIFFERING `src` —
        // real masked traffic that roams is only ever caught by the fallback
        // loop (see `authenticated_data_from_new_src_roams_endpoint`'s
        // comment). This test calls `dispatch_established` directly (it's a
        // private inherent method, reachable from `mod tests`) with a src
        // that differs from the learned endpoint, proving that authenticated-
        // decrypt site's own relearn call (added per the brief as
        // defense-in-depth for a future/hand-built `by_tag` hit) is wired
        // correctly, independent of which routing path reaches it.
        let (mut pm_i, mut pm_r, old_ep) = established_pair_for_roaming();
        let dg = pm_i.on_tun(&dummy_tun_pkt(), 0).to_vec()[0].bytes.clone();
        let new_src: SocketAddr = "198.51.100.7:5000".parse().unwrap();
        assert_ne!(new_src, old_ep);

        let out_is_none = matches!(
            pm_r.dispatch_established(0, new_src, &dg, 1_000),
            DispatchOut::None
        );
        assert!(!out_is_none, "a genuine Data datagram must authenticate");
        assert_eq!(
            pm_r.peers[0].endpoint,
            Some(new_src),
            "dispatch_established's own relearn call must move the endpoint"
        );
    }

    #[test]
    fn relay_peer_endpoint_does_not_roam() {
        // A relay-established peer (`established_relay_pm`: `relay = true`,
        // `endpoint` is whatever placeholder the config left it as).
        // `relearn_endpoint` must be a no-op regardless of `src`.
        let (mut pm, _local, _peer_kp, _old_tag) = established_relay_pm(100);
        assert!(pm.peers[0].relay);
        let placeholder = pm.peers[0].endpoint;

        pm.relearn_endpoint(0, "198.51.100.9:7000".parse().unwrap());

        assert_eq!(
            pm.peers[0].endpoint, placeholder,
            "a relay peer's endpoint must never roam"
        );
    }
}
