//! Packetization Layer Path MTU Discovery (PLPMTUD, RFC 8899).
//!
//! Provides in-band MTU probe and acknowledgment control frames alongside
//! the 4-tier discrete search ladder state machine (`PlpmtuController`).
#![forbid(unsafe_code)]

use crate::LossReport;

/// Magic 2-byte header identifying an MTU probe frame ("FP" = 0xFF50).
pub const MAGIC_MTU_PROBE: [u8; 2] = [0xFF, 0x50];

/// Magic 2-byte header identifying an MTU probe acknowledgment frame ("FA" = 0xFF41).
pub const MAGIC_MTU_PROBE_ACK: [u8; 2] = [0xFF, 0x41];

/// Discrete search ladder of candidate symbol sizes corresponding to common MTU standards:
/// - Tier 0: 1120 (safe minimum wire budget / IPv6 1280 / cellular relays)
/// - Tier 1: 1320 (PPPoE / tunnel-in-tunnel)
/// - Tier 2: 1400 (standard Ethernet WAN fits 1500B physical WAN without IP fragmentation)
/// - Tier 3: 1530 (jumbo / LAN / loopback)
pub const PLPMTU_LADDER: [u16; 4] = [1120, 1320, 1400, 1530];

/// Interval in milliseconds between probe attempts.
pub const PROBE_INTERVAL_MS: u64 = 1000;

/// Maximum number of probe attempts per candidate tier before declaring it failed.
pub const MAX_PROBE_ATTEMPTS: u8 = 3;

/// In-band control frames exchanged over the transport control channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFrame {
    /// Loss feedback report (receiver → sender).
    Feedback(LossReport),
    /// In-band MTU probe carrying zero user data, padded to target symbol size.
    MtuProbe {
        probe_id: u16,
        target_symbol_size: u16,
        padding: Vec<u8>,
    },
    /// Acknowledgment confirming candidate MTU arrived intact.
    MtuProbeAck {
        probe_id: u16,
        accepted_symbol_size: u16,
    },
}

impl ControlFrame {
    /// Serialize the control frame to bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Feedback(report) => report.encode(),
            Self::MtuProbe {
                probe_id,
                target_symbol_size,
                padding,
            } => {
                let mut bytes = Vec::with_capacity(6 + padding.len());
                bytes.extend_from_slice(&MAGIC_MTU_PROBE);
                bytes.extend_from_slice(&probe_id.to_be_bytes());
                bytes.extend_from_slice(&target_symbol_size.to_be_bytes());
                bytes.extend_from_slice(padding);
                bytes
            }
            Self::MtuProbeAck {
                probe_id,
                accepted_symbol_size,
            } => {
                let mut bytes = Vec::with_capacity(6);
                bytes.extend_from_slice(&MAGIC_MTU_PROBE_ACK);
                bytes.extend_from_slice(&probe_id.to_be_bytes());
                bytes.extend_from_slice(&accepted_symbol_size.to_be_bytes());
                bytes
            }
        }
    }

    /// Decode a control frame from untrusted bytes.
    ///
    /// Preserves full backward and forward compatibility with raw [`LossReport`]
    /// byte streams.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 6 && bytes[0..2] == MAGIC_MTU_PROBE {
            let probe_id = u16::from_be_bytes([bytes[2], bytes[3]]);
            let target_symbol_size = u16::from_be_bytes([bytes[4], bytes[5]]);
            if bytes.len() != usize::from(target_symbol_size) {
                return None;
            }
            let padding = bytes[6..].to_vec();
            Some(Self::MtuProbe {
                probe_id,
                target_symbol_size,
                padding,
            })
        } else if bytes.len() == 6 && bytes[0..2] == MAGIC_MTU_PROBE_ACK {
            let probe_id = u16::from_be_bytes([bytes[2], bytes[3]]);
            let accepted_symbol_size = u16::from_be_bytes([bytes[4], bytes[5]]);
            Some(Self::MtuProbeAck {
                probe_id,
                accepted_symbol_size,
            })
        } else {
            LossReport::decode(bytes).map(Self::Feedback)
        }
    }
}

/// Probing state of the search ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControllerState {
    Probing { tier_idx: usize, attempts: u8 },
    Converged,
}

/// Search ladder controller managing in-band PLPMTUD state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlpmtuController {
    confirmed_symbol_size: u16,
    state: ControllerState,
    next_probe_id: u16,
    active_probe_id: u16,
    last_probe_ms: Option<u64>,
    backoff_exp: u32,
}

impl Default for PlpmtuController {
    fn default() -> Self {
        Self::new()
    }
}

impl PlpmtuController {
    /// Create a new controller starting at confirmed Tier 0 (1120) and ready to probe Tier 1 (1320).
    pub fn new() -> Self {
        Self {
            confirmed_symbol_size: PLPMTU_LADDER[0],
            state: ControllerState::Probing {
                tier_idx: 1,
                attempts: 0,
            },
            next_probe_id: 2,
            active_probe_id: 1,
            last_probe_ms: Some(0),
            backoff_exp: 0,
        }
    }

    /// Return the currently confirmed symbol size.
    pub fn current_symbol_size(&self) -> u16 {
        self.confirmed_symbol_size
    }

    /// Return true if the controller has converged at its highest supported tier.
    pub fn is_converged(&self) -> bool {
        matches!(self.state, ControllerState::Converged)
    }

    /// Return the active candidate symbol size if probing.
    pub fn candidate_symbol_size(&self) -> Option<u16> {
        match self.state {
            ControllerState::Probing { tier_idx, .. } => Some(PLPMTU_LADDER[tier_idx]),
            ControllerState::Converged => None,
        }
    }

    /// Return the active probe ID if probing.
    pub fn active_probe_id(&self) -> Option<u16> {
        match self.state {
            ControllerState::Probing { .. } => Some(self.active_probe_id),
            ControllerState::Converged => None,
        }
    }

    /// Current probe interval in milliseconds, accounting for exponential backoff.
    pub fn probe_interval_ms(&self) -> u64 {
        PROBE_INTERVAL_MS.saturating_mul(1 << self.backoff_exp.min(5))
    }

    /// Periodic tick to advance probe transmission or detect timeout.
    ///
    /// If probing and `now_ms >= last_probe_ms + interval`:
    /// Increments `attempts`. If `attempts > MAX_PROBE_ATTEMPTS`, this candidate tier
    /// failed; the controller converges at the current confirmed tier and returns `None`.
    /// Otherwise, records `last_probe_ms = now_ms`, returns `Some((probe_id, target_symbol_size, pad_len))`
    /// where `pad_len` pads the probe wire size to `target_symbol_size`.
    pub fn on_tick(&mut self, now_ms: u64) -> Option<(u16, u16, usize)> {
        match self.state {
            ControllerState::Probing { tier_idx, attempts } => {
                let interval = self.probe_interval_ms();
                let due = now_ms.saturating_sub(self.last_probe_ms.unwrap_or(0)) >= interval;
                if !due {
                    return None;
                }

                let next_attempts = attempts.saturating_add(1);
                if next_attempts > MAX_PROBE_ATTEMPTS {
                    self.state = ControllerState::Converged;
                    return None;
                }

                self.last_probe_ms = Some(now_ms);
                self.state = ControllerState::Probing {
                    tier_idx,
                    attempts: next_attempts,
                };

                let target_symbol_size = PLPMTU_LADDER[tier_idx];
                let pad_len = usize::from(target_symbol_size).saturating_sub(6);
                Some((self.active_probe_id, target_symbol_size, pad_len))
            }
            ControllerState::Converged => None,
        }
    }

    /// Handle an incoming probe acknowledgment.
    ///
    /// If `probe_id` matches the active probe and `accepted_symbol_size == target_symbol_size`:
    /// Confirms tier, updates `confirmed_symbol_size = accepted_symbol_size`, and promotes
    /// to the next ladder tier (or transitions to `Converged` if at the highest tier).
    /// Returns `Some(new_symbol_size)` on promotion, or `None` if probe_id/size does not match.
    pub fn on_ack(&mut self, probe_id: u16, accepted_symbol_size: u16) -> Option<u16> {
        match self.state {
            ControllerState::Probing { tier_idx, .. } => {
                let target_symbol_size = PLPMTU_LADDER[tier_idx];
                if probe_id == self.active_probe_id && accepted_symbol_size == target_symbol_size {
                    self.confirmed_symbol_size = accepted_symbol_size;
                    self.backoff_exp = 0;

                    let next_tier = tier_idx + 1;
                    if next_tier < PLPMTU_LADDER.len() {
                        self.active_probe_id = self.next_probe_id;
                        self.next_probe_id = self.next_probe_id.wrapping_add(1);
                        self.state = ControllerState::Probing {
                            tier_idx: next_tier,
                            attempts: 0,
                        };
                    } else {
                        self.state = ControllerState::Converged;
                    }

                    Some(accepted_symbol_size)
                } else {
                    None
                }
            }
            ControllerState::Converged => None,
        }
    }

    /// Fast fallback on blackhole loss detection.
    ///
    /// If confirmed tier > Tier 0 (1120): drops confirmed tier back to Tier 0,
    /// restarts probing from Tier 1 with exponential backoff, and returns `Some(1120)`.
    /// Otherwise returns `None`.
    pub fn on_blackhole(&mut self) -> Option<u16> {
        if self.confirmed_symbol_size > PLPMTU_LADDER[0] {
            self.confirmed_symbol_size = PLPMTU_LADDER[0];
            self.state = ControllerState::Probing {
                tier_idx: 1,
                attempts: 0,
            };
            self.active_probe_id = self.next_probe_id;
            self.next_probe_id = self.next_probe_id.wrapping_add(1);
            self.backoff_exp = self.backoff_exp.saturating_add(1);
            Some(PLPMTU_LADDER[0])
        } else {
            None
        }
    }

    /// Fast fallback on path roaming or endpoint change.
    ///
    /// Resets confirmed tier to `PLPMTU_LADDER[0] = 1120`, clears backoff,
    /// restarts probing from Tier 1, and returns `1120`.
    pub fn reset_to_floor(&mut self) -> u16 {
        self.confirmed_symbol_size = PLPMTU_LADDER[0];
        self.state = ControllerState::Probing {
            tier_idx: 1,
            attempts: 0,
        };
        self.active_probe_id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);
        self.backoff_exp = 0;
        PLPMTU_LADDER[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_frame_roundtrips() {
        // 1. MtuProbe roundtrip
        let probe = ControlFrame::MtuProbe {
            probe_id: 42,
            target_symbol_size: 1320,
            padding: vec![0xAA; 1314],
        };
        let encoded_probe = probe.encode();
        assert_eq!(encoded_probe.len(), 1320);
        assert_eq!(&encoded_probe[0..2], &MAGIC_MTU_PROBE);
        let decoded_probe = ControlFrame::decode(&encoded_probe).expect("decode probe");
        assert_eq!(probe, decoded_probe);

        // 2. MtuProbeAck roundtrip
        let ack = ControlFrame::MtuProbeAck {
            probe_id: 42,
            accepted_symbol_size: 1320,
        };
        let encoded_ack = ack.encode();
        assert_eq!(encoded_ack.len(), 6);
        assert_eq!(&encoded_ack[0..2], &MAGIC_MTU_PROBE_ACK);
        let decoded_ack = ControlFrame::decode(&encoded_ack).expect("decode ack");
        assert_eq!(ack, decoded_ack);

        // 3. Feedback(LossReport) roundtrip
        let report = LossReport {
            delivered_count: 500,
            high_counter: 1200,
            missing: vec![10, 15, 20],
        };
        let feedback = ControlFrame::Feedback(report.clone());
        let encoded_feedback = feedback.encode();
        let decoded_feedback = ControlFrame::decode(&encoded_feedback).expect("decode feedback");
        assert_eq!(feedback, decoded_feedback);
    }

    #[test]
    fn test_forward_compatibility_raw_loss_report() {
        // Ensure raw LossReport byte streams from existing peers decode transparently into ControlFrame::Feedback
        let report = LossReport {
            delivered_count: 1234,
            high_counter: 5678,
            missing: vec![1, 2, 3],
        };
        let raw_bytes = report.encode();
        let frame = ControlFrame::decode(&raw_bytes).expect("decode raw LossReport bytes");
        assert_eq!(frame, ControlFrame::Feedback(report));
    }

    #[test]
    fn test_malformed_probe_handling() {
        // Empty slice
        assert_eq!(ControlFrame::decode(&[]), None);

        // Truncated probe (less than 6 bytes)
        assert_eq!(ControlFrame::decode(&[0xFF, 0x50, 0x00, 0x01]), None);

        // Probe whose payload length does not match target_symbol_size
        let mut bad_len_probe = vec![0xFF, 0x50, 0x00, 0x01, 0x05, 0x28]; // target 1320
        bad_len_probe.extend_from_slice(&[0u8; 100]); // only 106 bytes total
        assert_eq!(ControlFrame::decode(&bad_len_probe), None);

        // Probe ack with invalid length (!= 6)
        assert_eq!(
            ControlFrame::decode(&[0xFF, 0x41, 0x00, 0x01, 0x05, 0x00, 0x00]),
            None
        );
        assert_eq!(ControlFrame::decode(&[0xFF, 0x41, 0x00, 0x01, 0x05]), None);

        // Unknown magic header
        assert_eq!(
            ControlFrame::decode(&[0xFF, 0x99, 0x00, 0x01, 0x05, 0x00]),
            None
        );

        // Random garbage
        assert_eq!(ControlFrame::decode(&[0x12, 0x34, 0x56, 0x78]), None);
    }

    #[test]
    fn test_ladder_progression_to_converged() {
        let mut ctrl = PlpmtuController::new();
        assert_eq!(ctrl.current_symbol_size(), 1120);
        assert!(!ctrl.is_converged());
        assert_eq!(ctrl.candidate_symbol_size(), Some(1320));

        // Tier 1 (1320)
        let (id1, size1, pad1) = ctrl.on_tick(1000).expect("probe tier 1");
        assert_eq!(id1, 1);
        assert_eq!(size1, 1320);
        assert_eq!(pad1, 1314);

        // Early tick before interval elapses returns None
        assert_eq!(ctrl.on_tick(1500), None);

        // Invalid ack (mismatched ID or size) does not advance
        assert_eq!(ctrl.on_ack(999, 1320), None);
        assert_eq!(ctrl.on_ack(id1, 1400), None);
        assert_eq!(ctrl.current_symbol_size(), 1120);

        // Valid ack for Tier 1 confirms 1320 and promotes to Tier 2 (1400)
        assert_eq!(ctrl.on_ack(id1, 1320), Some(1320));
        assert_eq!(ctrl.current_symbol_size(), 1320);
        assert_eq!(ctrl.candidate_symbol_size(), Some(1400));
        assert!(!ctrl.is_converged());

        // Tier 2 (1400)
        let (id2, size2, pad2) = ctrl.on_tick(2000).expect("probe tier 2");
        assert_eq!(id2, 2);
        assert_eq!(size2, 1400);
        assert_eq!(pad2, 1394);

        assert_eq!(ctrl.on_ack(id2, 1400), Some(1400));
        assert_eq!(ctrl.current_symbol_size(), 1400);
        assert_eq!(ctrl.candidate_symbol_size(), Some(1530));
        assert!(!ctrl.is_converged());

        // Tier 3 (1530)
        let (id3, size3, pad3) = ctrl.on_tick(3000).expect("probe tier 3");
        assert_eq!(id3, 3);
        assert_eq!(size3, 1530);
        assert_eq!(pad3, 1524);

        // Valid ack for highest tier confirms 1530 and marks Converged
        assert_eq!(ctrl.on_ack(id3, 1530), Some(1530));
        assert_eq!(ctrl.current_symbol_size(), 1530);
        assert_eq!(ctrl.candidate_symbol_size(), None);
        assert!(ctrl.is_converged());

        // Once converged, further ticks and acks do nothing
        assert_eq!(ctrl.on_tick(4000), None);
        assert_eq!(ctrl.on_ack(id3, 1530), None);
    }

    #[test]
    fn test_max_attempts_timeout_drops_to_converged() {
        let mut ctrl = PlpmtuController::new();

        // Advance to Tier 1 first
        let (id1, _, _) = ctrl.on_tick(1000).unwrap();
        assert_eq!(ctrl.on_ack(id1, 1320), Some(1320));
        assert_eq!(ctrl.current_symbol_size(), 1320);

        // Attempt 1 for Tier 2
        let (id2_a, size2, _) = ctrl.on_tick(2000).expect("attempt 1");
        assert_eq!(id2_a, 2);
        assert_eq!(size2, 1400);

        // Attempt 2 for Tier 2
        let (id2_b, _, _) = ctrl.on_tick(3000).expect("attempt 2");
        assert_eq!(id2_b, 2);

        // Attempt 3 for Tier 2
        let (id2_c, _, _) = ctrl.on_tick(4000).expect("attempt 3");
        assert_eq!(id2_c, 2);

        // Attempt 4 times out (attempts > MAX_PROBE_ATTEMPTS = 3) -> converges at Tier 1 without promoting
        assert_eq!(ctrl.on_tick(5000), None);
        assert!(ctrl.is_converged());
        assert_eq!(ctrl.current_symbol_size(), 1320);
        assert_eq!(ctrl.candidate_symbol_size(), None);

        // Subsequent ticks remain Converged
        assert_eq!(ctrl.on_tick(6000), None);
    }

    #[test]
    fn test_blackhole_and_roam_resets_to_floor() {
        let mut ctrl = PlpmtuController::new();

        // Already at floor 1120: blackhole returns None
        assert_eq!(ctrl.on_blackhole(), None);
        assert_eq!(ctrl.current_symbol_size(), 1120);

        // Promote to Tier 2 (1400)
        let (id1, _, _) = ctrl.on_tick(1000).unwrap();
        ctrl.on_ack(id1, 1320);
        let (id2, _, _) = ctrl.on_tick(2000).unwrap();
        ctrl.on_ack(id2, 1400);
        assert_eq!(ctrl.current_symbol_size(), 1400);

        // Trigger blackhole: drops confirmed tier to 1120, restarts probing with backoff
        assert_eq!(ctrl.on_blackhole(), Some(1120));
        assert_eq!(ctrl.current_symbol_size(), 1120);
        assert!(!ctrl.is_converged());
        assert_eq!(ctrl.candidate_symbol_size(), Some(1320));
        assert_eq!(ctrl.probe_interval_ms(), 2000); // 1000 * 2^1

        // Blackhole while already at floor returns None
        assert_eq!(ctrl.on_blackhole(), None);

        // Verify backoff is observed during tick:
        // Last probe was at 2000, interval is 2000 => next probe due at >= 4000
        assert_eq!(ctrl.on_tick(3000), None);
        let (id_post_bh, size_post_bh, _) = ctrl.on_tick(4000).expect("probe after backoff");
        assert_eq!(size_post_bh, 1320);

        // Promoting clears backoff
        assert_eq!(ctrl.on_ack(id_post_bh, 1320), Some(1320));
        assert_eq!(ctrl.probe_interval_ms(), 1000);

        // Now test roaming / path reset
        assert_eq!(ctrl.reset_to_floor(), 1120);
        assert_eq!(ctrl.current_symbol_size(), 1120);
        assert_eq!(ctrl.candidate_symbol_size(), Some(1320));
        assert_eq!(ctrl.probe_interval_ms(), 1000);
        assert!(!ctrl.is_converged());
    }

    #[test]
    fn active_probe_id_tracks_probing_and_converged_states() {
        let mut ctrl = PlpmtuController::new();
        // Initially in Probing state with active_probe_id = 1
        assert_eq!(ctrl.active_probe_id(), Some(1));

        let (id1, _, _) = ctrl.on_tick(1000).expect("first probe");
        assert_eq!(id1, 1);
        assert_eq!(ctrl.active_probe_id(), Some(1));

        // Acking 1 transitions to next probe (id 2)
        assert_eq!(ctrl.on_ack(id1, 1320), Some(1320));
        assert_eq!(ctrl.active_probe_id(), Some(2));

        let (id2, _, _) = ctrl.on_tick(2000).expect("second probe");
        assert_eq!(id2, 2);
        assert_eq!(ctrl.on_ack(id2, 1400), Some(1400));
        assert_eq!(ctrl.active_probe_id(), Some(3));

        let (id3, _, _) = ctrl.on_tick(3000).expect("third probe");
        assert_eq!(id3, 3);
        assert_eq!(ctrl.on_ack(id3, 1530), Some(1530));
        assert!(ctrl.is_converged());
        assert_eq!(ctrl.active_probe_id(), None);
    }
}
