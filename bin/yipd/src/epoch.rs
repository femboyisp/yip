//! The per-peer session-epoch set (milestone 9a). Holds the live `current`
//! DataPlane plus, during a ~120s rekey overlap, an optional responder-side
//! `next` (derived from a rekey Init, not yet used for sending) and an
//! optional receive-only `previous` (the just-superseded epoch, kept for
//! in-flight frames until a grace deadline). Pure/I-O-free: `PeerManager`
//! drives the schedule and feeds it handshake results.

use std::net::SocketAddr;

use crate::dataplane::{DataPlane, Outcome};
use crate::handshake::HandshakeState;
use yip_io::poll::EgressDatagram;

/// Production rekey cadence (§ Global Constraints). Test-overridden via
/// `YIP_REKEY_INTERVAL_MS` at `PeerManager` construction.
#[expect(
    dead_code,
    reason = "consumed by PeerManager's rekey scheduler once Task 2 wires EpochSet in"
)]
pub const REKEY_INTERVAL_MS: u64 = 120_000;
/// How long the superseded `previous` epoch stays open for inbound after a
/// switch — generous vs. reordering/loss, bounded so keys don't linger.
pub const PREVIOUS_EPOCH_GRACE_MS: u64 = 15_000;

/// An in-flight initiator rekey handshake, held alongside the live `current`
/// so the session never pauses. Mirrors `HandshakingState`'s retransmit fields.
#[expect(
    dead_code,
    reason = "constructed and its fields read by PeerManager's rekey driver in Task 2"
)]
pub struct RekeyInFlight {
    pub hs: HandshakeState,
    pub init_pkt: Vec<u8>,
    pub started_ms: u64,
    pub last_sent_ms: u64,
    pub retry_ms: u64,
    pub target: SocketAddr,
}

/// Owned inbound result (the `PeerManager` demux already copies the borrowed
/// `Outcome` into owned Vecs at its call sites, so returning owned here is
/// free — and it sidesteps the multi-epoch borrow-return limitation).
///
/// `Send`/`TunThenSend` carry the full [`EgressDatagram`] (not just its
/// bytes) so each datagram's real `dst` and `fate` survive the trip through
/// `EpochSet` — `dst` cannot be losslessly reconstructed from
/// `self.peers[idx].endpoint` for relay-established peers (their
/// `DataPlane::peer_addr` is a `server_addr()` placeholder; the real
/// destination is only known per-datagram), and dropping `fate` would forgo
/// GSO fate-coalescing on ARQ-retransmit bursts.
pub enum EpochInbound {
    None,
    Tun(Vec<u8>),
    Send(Vec<EgressDatagram>),
    TunThenSend(Vec<u8>, Vec<EgressDatagram>),
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "constructed by PeerManager once Task 2/3 wires EpochSet in"
    )
)]
pub struct EpochSet {
    pub(crate) current: Box<DataPlane>,
    pub(crate) current_created_ms: u64,
    pub(crate) next: Option<Box<DataPlane>>,
    pub(crate) previous: Option<Box<DataPlane>>,
    pub(crate) previous_retire_ms: u64,
    pub(crate) rekey: Option<RekeyInFlight>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "driven by PeerManager once Task 2/3 wires EpochSet in"
    )
)]
impl EpochSet {
    pub fn new(current: Box<DataPlane>, now_ms: u64) -> Self {
        Self {
            current,
            current_created_ms: now_ms,
            next: None,
            previous: None,
            previous_retire_ms: 0,
            rekey: None,
        }
    }

    pub fn current(&self) -> &DataPlane {
        &self.current
    }
    pub fn current_mut(&mut self) -> &mut DataPlane {
        &mut self.current
    }

    /// Convert a borrowed `Outcome` into the owned `EpochInbound` (same copies
    /// the caller already performed). Returns `None` for `Outcome::None`.
    fn own(outcome: Outcome<'_>) -> EpochInbound {
        match outcome {
            Outcome::None => EpochInbound::None,
            Outcome::TunWrite(b) => EpochInbound::Tun(b.to_vec()),
            Outcome::Send(pkts) => EpochInbound::Send(pkts.to_vec()),
            Outcome::TunWriteThenSend(b, pkts) => {
                EpochInbound::TunThenSend(b.to_vec(), pkts.to_vec())
            }
        }
    }

    /// Open an inbound datagram against the epochs in order (current, then the
    /// responder's `next`, then the grace `previous`). Each `DataPlane` fails
    /// closed on a wrong key (cheap failed AEAD, no misdecrypt), so a wrong
    /// epoch simply yields `Outcome::None` and we try the next. A NON-None
    /// result under `next` means the peer has switched to the new epoch →
    /// promote it (responder confirmed-switch). Steady state (no next/previous)
    /// is a single try, identical to today.
    pub fn inbound_open(&mut self, dg: &[u8], now_ms: u64) -> EpochInbound {
        // current
        let out = Self::own(self.current.on_udp_datagram(dg, now_ms));
        if !matches!(out, EpochInbound::None) {
            return out;
        }
        // next (responder-side unconfirmed new epoch)
        if self.next.is_some() {
            let out = Self::own(
                self.next
                    .as_mut()
                    .expect("checked is_some")
                    .on_udp_datagram(dg, now_ms),
            );
            if !matches!(out, EpochInbound::None) {
                // Confirmed: promote next -> current, old current -> previous.
                let new = self.next.take().expect("checked is_some");
                let old = std::mem::replace(&mut self.current, new);
                self.current_created_ms = now_ms;
                self.previous = Some(old);
                self.previous_retire_ms = now_ms.saturating_add(PREVIOUS_EPOCH_GRACE_MS);
                return out;
            }
        }
        // previous (grace)
        if let Some(prev) = self.previous.as_mut() {
            return Self::own(prev.on_udp_datagram(dg, now_ms));
        }
        EpochInbound::None
    }

    /// Initiator switch on rekey completion: it now holds `new` AND knows the
    /// responder installed it (the responder sent the Resp), so switch outbound
    /// immediately; the old epoch becomes receive-only `previous`.
    pub fn promote_from_rekey(&mut self, new_dp: Box<DataPlane>, now_ms: u64) {
        let old = std::mem::replace(&mut self.current, new_dp);
        self.current_created_ms = now_ms;
        self.previous = Some(old);
        self.previous_retire_ms = now_ms.saturating_add(PREVIOUS_EPOCH_GRACE_MS);
        self.rekey = None;
    }

    /// Responder: a new epoch derived from a received rekey Init, kept for
    /// inbound but NOT used for sending until confirmed (see `inbound_open`).
    pub fn install_next(&mut self, new_dp: Box<DataPlane>) {
        self.next = Some(new_dp);
    }

    pub fn retire_previous_if_due(&mut self, now_ms: u64) {
        if self.previous.is_some() && now_ms >= self.previous_retire_ms {
            self.previous = None;
        }
    }

    /// Initiator schedule: rekey when `current` is old enough, none in flight,
    /// and this side is the glare-winner — OR the loser-fallback fires
    /// (`current` aged past 2× the interval and the winner never rekeyed).
    pub fn needs_rekey(&self, now_ms: u64, is_glare_winner: bool, interval_ms: u64) -> bool {
        if self.rekey.is_some() {
            return false;
        }
        let age = now_ms.saturating_sub(self.current_created_ms);
        if is_glare_winner {
            age >= interval_ms
        } else {
            age >= interval_ms.saturating_mul(2)
        }
    }

    /// Responder guard: ignore a rekey Init that arrives against a very fresh
    /// `current` (< interval/2 old) — bounds attacker-induced speculative
    /// handshakes without full timestamp anti-replay (#34).
    pub fn accept_rekey_init(&self, now_ms: u64, interval_ms: u64) -> bool {
        now_ms.saturating_sub(self.current_created_ms) >= interval_ms / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::conn_tag_from_keys;
    use crate::handshake::{Established, HandshakeState};
    use crate::mode::TunnelMode;
    use crate::wire_glue::derive_wire_keys;
    use yip_crypto::{generate_keypair, Handshake};

    /// Build a fresh pair of talking `DataPlane`s (a "new epoch") via a real
    /// in-process Noise-IK handshake — mirrors `dataplane::tests::dataplane_pair`.
    /// Returns `(sender, opener)`: `sender.on_tun_packet` produces frames that
    /// `opener` (fed into an `EpochSet` under test) must be able to open.
    fn epoch_pair() -> (Box<DataPlane>, Box<DataPlane>) {
        let resp_kp = generate_keypair();
        let init_kp = generate_keypair();

        let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
        let mut res = Handshake::responder(&resp_kp.private).unwrap();

        let m1 = ini.write_message(&[]).unwrap();
        let _ = res.read_message(&m1).unwrap();
        let m2 = res.write_message(&[]).unwrap();
        let _ = ini.read_message(&m2).unwrap();
        assert!(ini.is_finished() && res.is_finished());

        let cb_i = ini.channel_binding();
        let cb_r = res.channel_binding();
        assert_eq!(cb_i, cb_r);

        let (auth_key, hp_key) = derive_wire_keys(&cb_i);

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

        let conn_tag = conn_tag_from_keys(&auth_key, &hp_key);
        let addr_a: SocketAddr = "203.0.113.1:51820".parse().unwrap();
        let addr_b: SocketAddr = "203.0.113.2:51820".parse().unwrap();

        (
            Box::new(DataPlane::new(
                est_i,
                conn_tag,
                TunnelMode::L3Tun,
                addr_b,
                false,
                1200,
            )),
            Box::new(DataPlane::new(
                est_r,
                conn_tag,
                TunnelMode::L3Tun,
                addr_a,
                false,
                1200,
            )),
        )
    }

    /// Seal `payload` with `sender`, feed every resulting datagram into
    /// `set.inbound_open`, and return the first non-`None` result (or
    /// `EpochInbound::None` if nothing opened it).
    fn feed(
        sender: &mut DataPlane,
        set: &mut EpochSet,
        payload: &[u8],
        now_ms: u64,
    ) -> EpochInbound {
        let dgrams = sender.on_tun_packet(payload, now_ms).to_vec();
        for dg in &dgrams {
            let out = set.inbound_open(&dg.bytes, now_ms);
            if !matches!(out, EpochInbound::None) {
                return out;
            }
        }
        EpochInbound::None
    }

    fn rekey_in_flight(target: SocketAddr) -> RekeyInFlight {
        let init_kp = generate_keypair();
        let resp_kp = generate_keypair();
        let (hs, init_pkt) =
            HandshakeState::start_initiator(&init_kp.private, &resp_kp.public, &[]).unwrap();
        RekeyInFlight {
            hs,
            init_pkt,
            started_ms: 0,
            last_sent_ms: 0,
            retry_ms: 0,
            target,
        }
    }

    #[test]
    fn steady_state_inbound_uses_current_only() {
        let (mut peer, us) = epoch_pair();
        let mut set = EpochSet::new(us, 0);

        let payload = vec![0x11u8; 64];
        match feed(&mut peer, &mut set, &payload, 0) {
            EpochInbound::Tun(got) => assert_eq!(got, payload),
            _ => panic!("expected Tun outcome from current"),
        }
        assert!(set.next.is_none());
        assert!(set.previous.is_none());
    }

    #[test]
    fn initiator_promote_switches_outbound_and_grace_keeps_previous() {
        let (mut peer_old, us_old) = epoch_pair();
        let mut set = EpochSet::new(us_old, 0);

        let (mut peer_new, us_new) = epoch_pair();
        let new_conn_tag = us_new.conn_tag();

        set.promote_from_rekey(us_new, 1000);
        assert_eq!(set.current().conn_tag(), new_conn_tag);
        assert_eq!(set.current_created_ms, 1000);
        assert_eq!(set.previous_retire_ms, 1000 + PREVIOUS_EPOCH_GRACE_MS);
        assert!(set.previous.is_some());
        assert!(set.rekey.is_none());

        // Old-epoch frame still opens (via `previous`).
        let old_payload = vec![0x22u8; 32];
        match feed(&mut peer_old, &mut set, &old_payload, 1001) {
            EpochInbound::Tun(got) => assert_eq!(got, old_payload),
            _ => panic!("expected old-epoch frame to open via previous"),
        }

        // New-epoch frame opens (via `current`).
        let new_payload = vec![0x33u8; 32];
        match feed(&mut peer_new, &mut set, &new_payload, 1002) {
            EpochInbound::Tun(got) => assert_eq!(got, new_payload),
            _ => panic!("expected new-epoch frame to open via current"),
        }
    }

    #[test]
    fn responder_install_next_then_first_inbound_promotes() {
        let (mut peer_old, us_old) = epoch_pair();
        let old_conn_tag = us_old.conn_tag();
        let mut set = EpochSet::new(us_old, 0);

        let (mut peer_new, us_new) = epoch_pair();
        let new_conn_tag = us_new.conn_tag();

        set.install_next(us_new);
        assert_eq!(set.current().conn_tag(), old_conn_tag, "current unchanged");
        assert!(set.next.is_some());

        let payload = vec![0x44u8; 32];
        match feed(&mut peer_new, &mut set, &payload, 500) {
            EpochInbound::Tun(got) => assert_eq!(got, payload),
            _ => panic!("expected next-epoch frame to open and promote"),
        }

        assert_eq!(
            set.current().conn_tag(),
            new_conn_tag,
            "next promoted to current"
        );
        assert!(set.next.is_none());
        assert!(set.previous.is_some());
        assert_eq!(set.previous.as_ref().unwrap().conn_tag(), old_conn_tag);
        assert_eq!(set.previous_retire_ms, 500 + PREVIOUS_EPOCH_GRACE_MS);
        // The promotion must REFRESH current_created_ms (the rekey schedule
        // ages from it) — a stale value here would make `needs_rekey` misfire.
        assert_eq!(set.current_created_ms, 500, "promotion refreshes epoch age");

        // Old-epoch frames still open too, via `previous`.
        let old_payload = vec![0x55u8; 32];
        match feed(&mut peer_old, &mut set, &old_payload, 501) {
            EpochInbound::Tun(got) => assert_eq!(got, old_payload),
            _ => panic!("expected old-epoch frame to still open via previous"),
        }
    }

    #[test]
    fn lost_msg2_leaves_both_on_old_no_blackhole() {
        let (mut peer_old, us_old) = epoch_pair();
        let old_conn_tag = us_old.conn_tag();
        let mut set = EpochSet::new(us_old, 0);

        let (_peer_new, us_new) = epoch_pair();
        set.install_next(us_new);
        assert!(set.next.is_some());

        // Never feed a `next` frame (models a lost msg2). Old-epoch frames
        // must keep opening via `current`, unaffected.
        let payload = vec![0x66u8; 32];
        match feed(&mut peer_old, &mut set, &payload, 10) {
            EpochInbound::Tun(got) => assert_eq!(got, payload),
            _ => panic!("expected old-epoch frame to open via current"),
        }
        assert_eq!(
            set.current().conn_tag(),
            old_conn_tag,
            "no promotion occurred"
        );
        assert!(set.next.is_some(), "next remains installed, unused");
    }

    #[test]
    fn previous_retired_at_grace_deadline() {
        let (mut peer_old, us_old) = epoch_pair();
        let mut set = EpochSet::new(us_old, 0);

        let (_peer_new, us_new) = epoch_pair();
        set.promote_from_rekey(us_new, 1000);
        let retire_at = set.previous_retire_ms;
        assert!(set.previous.is_some());

        // Before the deadline: previous survives, old-epoch frame still opens.
        set.retire_previous_if_due(retire_at - 1);
        assert!(set.previous.is_some());
        let payload = vec![0x77u8; 32];
        match feed(&mut peer_old, &mut set, &payload, retire_at - 1) {
            EpochInbound::Tun(got) => assert_eq!(got, payload),
            _ => panic!("expected old-epoch frame to still open before grace deadline"),
        }

        // At/after the deadline: previous is dropped.
        set.retire_previous_if_due(retire_at);
        assert!(set.previous.is_none());
        let payload2 = vec![0x88u8; 32];
        match feed(&mut peer_old, &mut set, &payload2, retire_at) {
            EpochInbound::None => {}
            _ => panic!("expected old-epoch frame to no longer open after retirement"),
        }
    }

    #[test]
    fn needs_rekey_trigger_and_one_in_flight_guard() {
        let (_peer, us) = epoch_pair();
        let mut set = EpochSet::new(us, 0);
        let interval = 1000u64;

        // Not old enough yet.
        assert!(!set.needs_rekey(500, true, interval));
        // Winner: age >= interval, no rekey in flight => triggers.
        assert!(set.needs_rekey(1000, true, interval));

        // One-in-flight guard: even though the winner condition holds, an
        // in-flight rekey suppresses another trigger.
        set.rekey = Some(rekey_in_flight("203.0.113.9:1".parse().unwrap()));
        assert!(!set.needs_rekey(10_000, true, interval));
        set.rekey = None;

        // Loser: doesn't trigger until 2x the interval (fallback).
        assert!(!set.needs_rekey(1500, false, interval));
        assert!(set.needs_rekey(2000, false, interval));
    }

    #[test]
    fn accept_rekey_init_ignores_too_fresh_current() {
        let (_peer, us) = epoch_pair();
        let set = EpochSet::new(us, 0);
        let interval = 1000u64;

        assert!(!set.accept_rekey_init(400, interval));
        assert!(set.accept_rekey_init(500, interval));
    }
}
