//! Obfuscation: ingress deobfuscation, egress masking, junk bursts, per-session obf keys.
use super::*;

impl PeerManager {
    /// The per-session obfuscation key for a just-established peer, derived
    /// from its handshake `hp_key` — but only when obfuscation is enabled
    /// (`obf_key.is_some()`); `None` otherwise (obf off ⇒ nothing to store,
    /// byte-identical). Both peers derive the same `hp_key` from the Noise
    /// channel binding, so both derive the same session obf key.
    pub(super) fn session_obf_key_for(&self, hp_key: &[u8; 16]) -> Option<[u8; 16]> {
        self.obf_key.map(|_| yip_obf::derive_key(hp_key))
    }

    // ── anti-DPI obfuscation (3a) ─────────────────────────────────────────
    //
    // A thin wrap/unwrap LAYER around the existing `[PacketType][…]` datagrams,
    // active only when `obf_key.is_some()`. It never weakens the inner
    // Noise/AEAD/yip-wire crypto — a wrong key deobfuscates to garbage that the
    // inner verify then rejects (fail-closed). When `obf_key` is `None` these
    // helpers are never called and every `Dispatch` method takes the exact
    // 2a/2b/2c plaintext path (byte-identical).

    /// Recover the plaintext `[ptype] ‖ body` datagram from an obfuscated
    /// ingress datagram `dg` that arrived from `src`, by source + trial-unmask,
    /// or `None` if it unmasks to nothing dispatchable (⇒ drop). Only called on
    /// the obfuscation-enabled path.
    ///
    /// Order (matches the addendum):
    /// (a) If `src` is a known `Established` peer, try that peer's
    ///     `session_obf_key`; accept only `Data`/`Control`/`Gossip`.
    /// (a') Otherwise (the peer may have roamed to a new source), trial every
    ///     `Established` peer's `session_obf_key` in turn; accept only
    ///     `Data`/`Control`/`Gossip` — mirrors `handle_data_or_control`'s
    ///     plaintext roaming fallback loop, one layer up.
    /// (b) Otherwise (or if (a)/(a') did not yield one of those types), try
    ///     the network `obf_key`; accept only `HandshakeInit`/`HandshakeResp`
    ///     — this covers a brand-new peer's `Init` AND a re-handshake from a
    ///     known src.
    ///
    /// A wrong key yields `None` or a garbage `(ptype, body)`; the type-set
    /// filters and, ultimately, the inner Noise/AEAD/frame verify make every
    /// mismatch a safe drop — never a mis-dispatch with side effects.
    pub(super) fn deobf_ingress(&self, src: SocketAddr, dg: &[u8]) -> Option<Vec<u8>> {
        // (a) established peer whose endpoint matches src → session key.
        if let Some(key) = self.peers.iter().find_map(|p| {
            if p.endpoint == Some(src) && matches!(p.state, PeerState::Established(_)) {
                p.session_obf_key
            } else {
                None
            }
        }) {
            if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
                if ptype == yip_obf::JUNK_TYPE {
                    return None; // idle-cover decoy: inert, dropped, no fall-through
                }
                if ptype == PacketType::Data as u8
                    || ptype == PacketType::Control as u8
                    || ptype == PacketType::Gossip as u8
                {
                    return Some(reassemble(ptype, &body));
                }
            }
        }
        // (a') Roaming fallback: no endpoint match, but the datagram may be a
        // roamed Established peer's Data/Control/Gossip under its session key.
        // Trial each Established peer's session key; a wrong key yields None or a
        // garbage type that the type-set + the downstream inner Noise/AEAD verify
        // drop safely. NOTE: `deobfuscate` is an unauthenticated keystream XOR, so
        // a wrong key CAN spuriously produce a Data/Control/Gossip type here — the
        // authenticated gate is downstream (`inbound_open`/`route_data`), unlike
        // `handle_data_or_control`'s plaintext loop which is itself AEAD-gated. A
        // genuine roamed datagram is therefore dropped with tiny probability when
        // an interfering peer's trial false-positives; FEC/ARQ absorb it, and the
        // endpoint self-heals on the next datagram that reaches (a).
        for p in &self.peers {
            if !matches!(p.state, PeerState::Established(_)) {
                continue;
            }
            let Some(key) = p.session_obf_key else {
                continue;
            };
            if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
                if ptype == yip_obf::JUNK_TYPE {
                    return None;
                }
                if ptype == PacketType::Data as u8
                    || ptype == PacketType::Control as u8
                    || ptype == PacketType::Gossip as u8
                {
                    return Some(reassemble(ptype, &body));
                }
            }
        }
        // (b) pre-session network key → handshakes only.
        if let Some(key) = self.obf_key {
            if let Some((ptype, body)) = yip_obf::deobfuscate(&key, dg) {
                if ptype == yip_obf::JUNK_TYPE {
                    return None; // idle-cover decoy: inert, dropped, no fall-through
                }
                if ptype == PacketType::HandshakeInit as u8
                    || ptype == PacketType::HandshakeResp as u8
                {
                    return Some(reassemble(ptype, &body));
                }
            }
        }
        None
    }

    /// Build a plaintext JUNK decoy datagram `[JUNK_TYPE][random body]`. The
    /// caller's `obf_egress` pass wraps it once (network key for a
    /// handshake-burst dst, session key for an established-peer cover dst) —
    /// do NOT pre-obfuscate here, or it would be double-wrapped. Body length
    /// is random in `[JUNK_MIN_LEN, JUNK_MAX_LEN]`, drawn from `junk_rng`
    /// (content is irrelevant — masked once `obf_egress` wraps it). The
    /// receiver recovers `(JUNK_TYPE, _)` via a single `yip_obf::deobfuscate`
    /// and drops it (see `deobf_ingress`) — junk never touches
    /// Noise/AEAD/session state. Only meaningful on the obfuscation-enabled
    /// path (`begin_handshake` only calls this when `obf_key.is_some()`).
    pub(super) fn build_junk(&mut self) -> Vec<u8> {
        let lo = u64::try_from(JUNK_MIN_LEN).expect("JUNK_MIN_LEN fits u64");
        let hi = u64::try_from(JUNK_MAX_LEN).expect("JUNK_MAX_LEN fits u64");
        let len = usize::try_from(self.junk_rng.gen_range(lo, hi)).expect("gen_range in usize");
        let mut out = vec![0u8; 1 + len];
        out[0] = yip_obf::JUNK_TYPE;
        self.junk_rng.fill(&mut out[1..]);
        out
    }

    /// The obfuscation key to wrap an egress datagram to `dst` whose plaintext
    /// leads with `ptype`: the network `obf_key` for handshakes (pre-session);
    /// otherwise the `session_obf_key` of the `Established` peer reached at
    /// `dst`. Falls back to the network key when no session key is found (e.g. a
    /// gossip digest to a not-yet-`Established` root) so wrapping never silently
    /// drops a datagram.
    fn obf_key_for_egress(&self, dst: SocketAddr, ptype: u8) -> Option<[u8; 16]> {
        if ptype == PacketType::HandshakeInit as u8 || ptype == PacketType::HandshakeResp as u8 {
            return self.obf_key;
        }
        self.peers
            .iter()
            .find_map(|p| {
                if p.endpoint == Some(dst) && matches!(p.state, PeerState::Established(_)) {
                    p.session_obf_key
                } else {
                    None
                }
            })
            .or(self.obf_key)
    }

    /// Wrap every egress datagram in `dgs` in place via `yip_obf::obfuscate`
    /// (masked type + random padding), so the `PacketType` byte never appears on
    /// the wire. Datagrams addressed to the rendezvous server carry a plaintext
    /// `yip_rendezvous::Message` rather than a `[PacketType][…]` tunnel
    /// datagram, so they are wrapped whole (no leading byte stripped) under the
    /// dedicated `yip_obf::RDV_TYPE` and the network `obf_key` (the server is
    /// never an `Established` peer, so it has no session key). Only called on
    /// the obfuscation-enabled path.
    ///
    /// Takes `&mut Vec` (not `&mut [_]`) so a datagram whose body can't fit
    /// the obf envelope's `u16` length field (#44 fail-soft: `obfuscate`
    /// returns `None` instead of panicking) can be dropped from `dgs`
    /// outright — unshippable, not merely emptied — rather than left behind
    /// as a stray zero-length datagram. `tick_gossip`'s digest chunking
    /// already keeps every gossip datagram well under this cap, so in
    /// practice this is defense-in-depth, not the expected path.
    pub(super) fn obf_egress(&self, dgs: &mut Vec<EgressDatagram>) {
        let server = self.rendezvous.as_ref().map(|r| r.server_addr());
        dgs.retain_mut(|d| {
            if d.bytes.is_empty() {
                return true;
            }
            if Some(d.dst) == server {
                let Some(key) = self.obf_key else {
                    return true;
                };
                let pad = random_pad(obf_pad_max(yip_obf::RDV_TYPE, d.bytes.len() + 1));
                return match yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &d.bytes, pad) {
                    Some(wrapped) => {
                        d.bytes = wrapped;
                        true
                    }
                    None => false,
                };
            }
            let ptype = d.bytes[0];
            let Some(key) = self.obf_key_for_egress(d.dst, ptype) else {
                return true;
            };
            let pad = random_pad(obf_pad_max(ptype, d.bytes.len()));
            match yip_obf::obfuscate(&key, ptype, &d.bytes[1..], pad) {
                Some(wrapped) => {
                    d.bytes = wrapped;
                    true
                }
                None => false,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::testutil::*;

    // ── M2 roaming: deobf_ingress trial fallback ────────────────────────────

    /// Build an obf-on `PeerManager` with a single `Established` peer at a
    /// known endpoint and a known `session_obf_key`, plus a plaintext
    /// `[Data][body]` datagram as `deobf_ingress` would return it — the
    /// shared fixture for the roaming trial-fallback tests below.
    fn established_obf_peer_with_data() -> (PeerManager, [u8; 16], Vec<u8>) {
        const TAG: u64 = 0x9999_1111_2222_3333;
        let peer_ep: SocketAddr = "10.0.0.30:3030".parse().unwrap();
        let peer = peer_cfg(30, "10.0.0.30:3030");
        let mut pm = PeerManager::new(
            [31u8; 32],
            [32u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm.set_obf_psk(Some([0xCCu8; 32]));

        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, peer_ep)),
            0,
        )));
        let sess = [0xDDu8; 16];
        pm.peers[0].session_obf_key = Some(sess);
        pm.by_tag.insert(TAG, 0);

        let mut plaintext = vec![PacketType::Data as u8];
        plaintext.extend_from_slice(&[0x55u8; 40]);
        (pm, sess, plaintext)
    }

    /// With obfuscation on, a `Data` datagram obfuscated under an
    /// `Established` peer's session key, but arriving from a source that does
    /// NOT match that peer's recorded `endpoint` (the peer roamed to a new
    /// NAT mapping), still deobfuscates: step (a)'s endpoint fast-path misses,
    /// but the (a') roaming trial fallback tries every `Established` peer's
    /// session key and finds this one.
    #[test]
    fn deobf_finds_roamed_peer_session_key_by_trial() {
        let (pm, sess, plaintext) = established_obf_peer_with_data();
        let obf = yip_obf::obfuscate(&sess, PacketType::Data as u8, &plaintext[1..], 0)
            .expect("small test body fits u16");
        let roamed: SocketAddr = "198.51.100.231:41111".parse().unwrap();
        assert_ne!(
            pm.peers[0].endpoint,
            Some(roamed),
            "fixture invariant: the roamed src must not match the peer's endpoint"
        );

        let out = pm.deobf_ingress(roamed, &obf);
        assert_eq!(
            out.as_deref(),
            Some(plaintext.as_slice()),
            "roamed peer's data must deobfuscate via the trial fallback"
        );
    }

    /// A datagram that decodes under no known key at all — not the (a)
    /// endpoint match, not the (a') trial over `Established` peers' session
    /// keys, not the (b) network key — is dropped, never mis-dispatched.
    #[test]
    fn deobf_trial_does_not_accept_foreign_datagram() {
        let (pm, _sess, _plaintext) = established_obf_peer_with_data();
        let garbage = vec![0xABu8; 64];
        let src: SocketAddr = "203.0.113.9:9".parse().unwrap();
        assert!(
            pm.deobf_ingress(src, &garbage).is_none(),
            "a datagram under no known session key must not deobfuscate"
        );
    }

    /// (3b-a) `build_junk()` produces a PLAINTEXT `[JUNK_TYPE][body]`
    /// datagram, `JUNK_MIN_LEN..=JUNK_MAX_LEN` bytes of body — it must NOT
    /// pre-obfuscate, since the caller's `obf_egress` pass wraps it exactly
    /// once (double-wrapping would defeat the JUNK_TYPE recognition on
    /// ingress; see `single_wrap_...` below for the full round-trip).
    #[test]
    fn build_junk_roundtrips_to_junk_type() {
        let peer = peer_cfg(5, "10.0.0.5:5000");
        let mut pm = PeerManager::new(
            [1u8; 32],
            [2u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );

        let dg = pm.build_junk();
        assert_eq!(
            dg[0],
            yip_obf::JUNK_TYPE,
            "leading byte is the plaintext JUNK_TYPE"
        );
        let body_len = dg.len() - 1;
        assert!(
            (JUNK_MIN_LEN..=JUNK_MAX_LEN).contains(&body_len),
            "body length is within [JUNK_MIN_LEN, JUNK_MAX_LEN], got {body_len}"
        );
    }

    /// (3b-b) With obfuscation on, a junk datagram sent from an `Established`
    /// peer's source (session-keyed) is silently dropped by `on_udp`: no
    /// egress, and the peer's session state is left completely untouched.
    #[test]
    fn obf_on_session_keyed_junk_is_dropped_state_unchanged() {
        const TAG: u64 = 0xABCD_EF01;
        let peer_ep: SocketAddr = "10.0.0.6:6000".parse().unwrap();
        let peer = peer_cfg(6, "10.0.0.6:6000");
        let mut pm = PeerManager::new(
            [3u8; 32],
            [4u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        pm.set_obf_psk(Some([0x66u8; 32]));

        pm.peers[0].state = PeerState::Established(Box::new(crate::epoch::EpochSet::new(
            Box::new(fake_established_dataplane(TAG, peer_ep)),
            0,
        )));
        let sess = [0x77u8; 16];
        pm.peers[0].session_obf_key = Some(sess);
        pm.by_tag.insert(TAG, 0);

        // `build_junk()` itself is plaintext now (single-wrapped by
        // `obf_egress` on the real egress path); reproduce that one wrap by
        // hand here to get wire-format bytes for `on_udp`'s ingress test.
        let plain = pm.build_junk();
        let junk = yip_obf::obfuscate(&sess, yip_obf::JUNK_TYPE, &plain[1..], 0)
            .expect("small test body fits u16");
        let before_tag = pm.by_tag.get(&TAG).copied();

        let out = pm.on_udp(peer_ep, &junk, 0);
        assert!(
            matches!(out, DispatchOut::None),
            "session-keyed junk must be dropped, not dispatched"
        );
        assert!(matches!(pm.peers[0].state, PeerState::Established(_)));
        assert_eq!(
            pm.peers[0].session_obf_key,
            Some(sess),
            "session obf key untouched by a dropped junk datagram"
        );
        assert_eq!(pm.by_tag.get(&TAG).copied(), before_tag, "by_tag untouched");
    }

    /// (3b-c) With obfuscation on, a junk datagram from an entirely unknown
    /// source (no `Established` peer at that address, so it can only unmask
    /// under the network `obf_key`) is dropped with no panic and no peer
    /// admitted.
    #[test]
    fn obf_on_network_keyed_junk_from_unknown_src_is_dropped_no_panic() {
        let peer = peer_cfg(7, "10.0.0.7:7000");
        let mut pm = PeerManager::new(
            [5u8; 32],
            [6u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        let psk = [0x88u8; 32];
        pm.set_obf_psk(Some(psk));
        let obf_key = yip_obf::derive_key(&psk);

        // Same rationale as the session-keyed test above: `build_junk()` is
        // plaintext, so wrap it once by hand to get wire-format bytes.
        let plain = pm.build_junk();
        let junk = yip_obf::obfuscate(&obf_key, yip_obf::JUNK_TYPE, &plain[1..], 0)
            .expect("small test body fits u16");
        let src: SocketAddr = "203.0.113.55:5555".parse().unwrap();
        assert!(matches!(pm.on_udp(src, &junk, 0), DispatchOut::None));
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
        assert!(pm.by_tag.is_empty());
    }

    /// (3b-d) With obfuscation OFF (`obf_key: None`), the `JUNK_TYPE` drop arm
    /// lives entirely inside `deobf_ingress`, which is never reached — a
    /// junk-shaped datagram (leading byte == `JUNK_TYPE`, which is not a
    /// recognized plaintext `PacketType`) takes the exact unchanged 2a/2b/2c
    /// plaintext path (falls into `handle_data_or_control`, finds no matching
    /// peer, drops with no panic) rather than being specially recognized.
    #[test]
    fn obf_off_junk_shaped_datagram_takes_unchanged_plaintext_path() {
        let peer = peer_cfg(8, "10.0.0.8:8000");
        let mut pm = PeerManager::new(
            [7u8; 32],
            [8u8; 32],
            &[peer],
            TunnelMode::L3Tun,
            None,
            None,
            false,
        );
        // No set_obf_psk ⇒ obf_key is None ⇒ deobf_ingress/build_junk's JUNK
        // handling is never consulted.
        assert!(pm.obf_key.is_none());

        let mut dg = vec![yip_obf::JUNK_TYPE];
        dg.extend_from_slice(&[0u8; 16]);
        let src: SocketAddr = "203.0.113.66:6666".parse().unwrap();
        assert!(matches!(pm.on_udp(src, &dg, 0), DispatchOut::None));
        assert!(matches!(pm.peers[0].state, PeerState::Idle));
    }
}
