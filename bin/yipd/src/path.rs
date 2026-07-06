//! Per-peer connection path state machine: escalate Direct -> Punch -> Relay,
//! each with a bounded window, feeding candidate addresses to the caller's
//! handshake machinery. A candidate is ONLY ever a probe target — the caller
//! commits a path (via `committed`) only once a Noise handshake completes over
//! it (the anti-hijack invariant lives in the caller; this SM never sends).
use std::net::SocketAddr;

/// Direct-stage window before escalating to punch.
pub const DIRECT_MS: u64 = 3_000;
/// Punch-stage window before escalating to relay.
pub const PUNCH_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "constructed by these unit tests only until task 6"
        )
    )]
    Direct,
    #[expect(
        dead_code,
        reason = "constructed by PeerManager in task 6 on a punched commit"
    )]
    Punched,
    #[expect(
        dead_code,
        reason = "constructed by PeerManager in task 6 on a relayed commit"
    )]
    Relayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStage {
    Direct,
    Punching,
    Relaying,
    Failed,
}

/// What the caller should do this tick for a not-yet-established peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAction {
    /// Nothing to do (committed, or waiting within a window).
    Idle,
    /// Send a `Lookup` for this peer (entering/among the punch stage).
    NeedLookup,
    /// Probe this candidate with a handshake Init.
    Probe(SocketAddr),
    /// Send the handshake/data via the relay.
    Relay,
    /// No path available (no direct endpoint and no rendezvous).
    Failed,
}

pub struct PathState {
    stage: PathStage,
    has_rendezvous: bool,
    direct: Option<SocketAddr>,
    candidate: Option<SocketAddr>, // reflexive addr for the punch stage
    stage_started_ms: u64,
    committed: bool,
    looked_up: bool,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "driven by PeerManager in task 6")
)]
impl PathState {
    pub fn new(has_direct: bool, has_rendezvous: bool, now_ms: u64) -> Self {
        let stage = if has_direct {
            PathStage::Direct
        } else if has_rendezvous {
            PathStage::Punching
        } else {
            PathStage::Failed
        };
        Self {
            stage,
            has_rendezvous,
            direct: None,
            candidate: None,
            stage_started_ms: now_ms,
            committed: false,
            looked_up: false,
        }
    }

    pub fn stage(&self) -> PathStage {
        self.stage
    }

    #[expect(
        dead_code,
        reason = "getter surfaced for PeerManager in task 6; not exercised by these unit tests"
    )]
    pub fn candidate(&self) -> Option<SocketAddr> {
        match self.stage {
            PathStage::Direct => self.direct,
            PathStage::Punching => self.candidate,
            _ => None,
        }
    }

    pub fn on_direct_addr(&mut self, addr: SocketAddr) {
        self.direct = Some(addr);
    }

    pub fn on_peer_candidate(&mut self, addr: SocketAddr, now_ms: u64) {
        // A reflexive addr arrived (from PeerInfo or a PunchHint): enter/refresh
        // the punch stage targeting it.
        self.candidate = Some(addr);
        if self.stage == PathStage::Direct || self.stage == PathStage::Punching {
            if self.stage != PathStage::Punching {
                self.stage_started_ms = now_ms;
            }
            self.stage = PathStage::Punching;
        }
    }

    fn enter(&mut self, stage: PathStage, now_ms: u64) {
        self.stage = stage;
        self.stage_started_ms = now_ms;
    }

    pub fn advance(&mut self, now_ms: u64) -> PathAction {
        if self.committed {
            return PathAction::Idle;
        }
        let elapsed = now_ms.saturating_sub(self.stage_started_ms);
        match self.stage {
            PathStage::Direct => {
                if let Some(addr) = self.direct {
                    if elapsed < DIRECT_MS {
                        return PathAction::Probe(addr);
                    }
                }
                // Direct window elapsed (or never had an endpoint): escalate.
                if self.has_rendezvous {
                    self.enter(PathStage::Punching, now_ms);
                    self.punch_action(now_ms)
                } else {
                    self.enter(PathStage::Failed, now_ms);
                    PathAction::Failed
                }
            }
            PathStage::Punching => {
                if elapsed >= PUNCH_MS {
                    self.enter(PathStage::Relaying, now_ms);
                    return PathAction::Relay;
                }
                self.punch_action(now_ms)
            }
            PathStage::Relaying => PathAction::Relay,
            PathStage::Failed => PathAction::Failed,
        }
    }

    fn punch_action(&mut self, _now_ms: u64) -> PathAction {
        match self.candidate {
            Some(addr) => PathAction::Probe(addr),
            None => {
                if !self.looked_up {
                    self.looked_up = true;
                }
                PathAction::NeedLookup
            }
        }
    }

    pub fn committed(&mut self, _kind: PathKind) {
        self.committed = true;
    }

    pub fn reset(&mut self, now_ms: u64) {
        self.committed = false;
        self.candidate = None;
        self.looked_up = false;
        self.stage = if self.direct.is_some() {
            PathStage::Direct
        } else if self.has_rendezvous {
            PathStage::Punching
        } else {
            PathStage::Failed
        };
        self.stage_started_ms = now_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn direct_first_when_endpoint_known() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        assert!(matches!(p.advance(0), PathAction::Probe(x) if x == a("10.0.0.2:51820")));
        assert_eq!(p.stage(), PathStage::Direct);
    }

    #[test]
    fn escalates_direct_to_punch_after_window() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        let _ = p.advance(0);
        // After the direct window with no commit, ask for a lookup (enter punch).
        assert!(matches!(p.advance(DIRECT_MS + 1), PathAction::NeedLookup));
        assert_eq!(p.stage(), PathStage::Punching);
    }

    #[test]
    fn punch_probes_learned_candidate_then_relays_after_window() {
        let mut p = PathState::new(false, true, 0); // no direct endpoint
        assert!(matches!(p.advance(0), PathAction::NeedLookup));
        p.on_peer_candidate(a("198.51.100.7:41000"), 10);
        assert!(matches!(p.advance(10), PathAction::Probe(x) if x == a("198.51.100.7:41000")));
        // Punch window elapses without commit -> escalate to relay.
        assert!(matches!(p.advance(10 + PUNCH_MS + 1), PathAction::Relay));
        assert_eq!(p.stage(), PathStage::Relaying);
    }

    #[test]
    fn no_rendezvous_and_no_direct_is_failed() {
        let mut p = PathState::new(false, false, 0);
        assert!(matches!(p.advance(0), PathAction::Failed));
        assert_eq!(p.stage(), PathStage::Failed);
    }

    #[test]
    fn commit_pins_path_and_stops_escalating() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        let _ = p.advance(0);
        p.committed(PathKind::Direct);
        // Even past the direct window, a committed path does not escalate.
        assert!(matches!(p.advance(DIRECT_MS + 100), PathAction::Idle));
    }

    #[test]
    fn reset_reenters_from_direct() {
        let mut p = PathState::new(true, true, 0);
        p.on_direct_addr(a("10.0.0.2:51820"));
        p.committed(PathKind::Direct);
        p.reset(1000);
        assert!(matches!(p.advance(1000), PathAction::Probe(x) if x == a("10.0.0.2:51820")));
        assert_eq!(p.stage(), PathStage::Direct);
    }
}
