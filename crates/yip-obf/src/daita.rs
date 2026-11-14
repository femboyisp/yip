//! DAITA (Defending Against AI-guided Traffic Analysis) probabilistic state machine engine.
//!
//! Provides `DaitaProfile`, `DaitaAction`, and `DaitaEngine` wrapping `maybenot::Framework`
//! to defend tunnel traffic against website and application fingerprinting classifiers.

#![forbid(unsafe_code)]

use crate::XorShift64;
use maybenot::{Framework, Machine, MachineId, Timer, TriggerAction, TriggerEvent};
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Limits applied to Maybenot state machines.
pub const DEFAULT_MAX_PADDING_FRAC: f64 = 0.15;
pub const DEFAULT_MAX_BLOCKING_FRAC: f64 = 0.05;

/// Predefined profiles or custom state machine configurations for DAITA.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DaitaProfile {
    #[default]
    Off,
    Front,
    Regulator,
    Balanced,
    Paranoid,
    Custom(Vec<u8>),
}

/// Action emitted by the DAITA probabilistic state machine engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaitaAction {
    /// Inject a decoy/padding datagram after `timeout`.
    SendPadding { timeout: Duration },
    /// Apply micro-blocking / delay to outgoing data datagrams.
    BlockOutgoing {
        timeout: Duration,
        duration: Duration,
    },
}

/// Errors originating from DAITA initialization or parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaitaError {
    InvalidProfile(String),
    MachineParseError(String),
    FrameworkError(String),
}

impl std::fmt::Display for DaitaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProfile(msg) => write!(f, "invalid DAITA profile: {msg}"),
            Self::MachineParseError(msg) => write!(f, "failed to parse machine: {msg}"),
            Self::FrameworkError(msg) => write!(f, "DAITA framework error: {msg}"),
        }
    }
}

impl std::error::Error for DaitaError {}

/// Probabilistic state machine engine managing traffic analysis defense.
#[derive(Debug)]
pub struct DaitaEngine {
    profile: DaitaProfile,
    framework: Option<Framework<Vec<Machine>, XorShift64>>,
    internal_timers: Vec<Option<Instant>>,
    action_timers: Vec<Option<(Instant, DaitaAction)>>,
    blocking_until: Option<Instant>,
    last_padding_machine: Option<MachineId>,
    max_padding_frac: f64,
    max_blocking_frac: f64,
}

impl DaitaEngine {
    /// Construct a new `DaitaEngine` with the given profile and current timestamp.
    pub fn new(profile: DaitaProfile, now: Instant) -> Result<Self, DaitaError> {
        Self::with_limits(
            profile,
            now,
            DEFAULT_MAX_PADDING_FRAC,
            DEFAULT_MAX_BLOCKING_FRAC,
        )
    }

    /// Construct a new `DaitaEngine` with custom padding/blocking budget fractions.
    pub fn with_limits(
        profile: DaitaProfile,
        now: Instant,
        max_padding_frac: f64,
        max_blocking_frac: f64,
    ) -> Result<Self, DaitaError> {
        let mut rng = XorShift64::from_getrandom();
        let machines = build_machines(&profile, &mut rng)?;

        let framework = if profile == DaitaProfile::Off || machines.is_empty() {
            None
        } else {
            let fw = Framework::new(machines, max_padding_frac, max_blocking_frac, now, rng)
                .map_err(|e| DaitaError::FrameworkError(format!("{e:?}")))?;
            Some(fw)
        };

        let num_machines = framework.as_ref().map_or(0, |f| f.num_machines());
        Ok(Self {
            profile,
            framework,
            internal_timers: vec![None; num_machines],
            action_timers: vec![None; num_machines],
            blocking_until: None,
            last_padding_machine: None,
            max_padding_frac,
            max_blocking_frac,
        })
    }

    /// Returns the active profile.
    pub fn profile(&self) -> &DaitaProfile {
        &self.profile
    }

    /// Returns whether DAITA defense is active.
    pub fn is_active(&self) -> bool {
        self.framework.is_some()
    }

    /// Maximum fraction of padding traffic allowed.
    pub fn max_padding_frac(&self) -> f64 {
        self.max_padding_frac
    }

    /// Maximum fraction of blocking allowed.
    pub fn max_blocking_frac(&self) -> f64 {
        self.max_blocking_frac
    }

    /// Earliest deadline among internal or action timers, if any are pending.
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        let mut min_deadline = self.blocking_until;

        for &timer in &self.internal_timers {
            if let Some(t) = timer {
                min_deadline = Some(min_deadline.map_or(t, |curr| curr.min(t)));
            }
        }

        for &timer in &self.action_timers {
            if let Some((t, _)) = timer {
                min_deadline = Some(min_deadline.map_or(t, |curr| curr.min(t)));
            }
        }

        min_deadline
    }

    /// Record a packet sent over the tunnel wire.
    pub fn on_tunnel_sent(&mut self, now: Instant) -> Vec<DaitaAction> {
        self.dispatch_events(&[TriggerEvent::TunnelSent], now)
    }

    /// Record a packet received over the tunnel wire.
    pub fn on_tunnel_recv(&mut self, now: Instant) -> Vec<DaitaAction> {
        self.dispatch_events(&[TriggerEvent::TunnelRecv], now)
    }

    /// Record a normal (non-padding) packet sent.
    pub fn on_normal_sent(&mut self, now: Instant) -> Vec<DaitaAction> {
        self.dispatch_events(&[TriggerEvent::NormalSent], now)
    }

    /// Record a normal (non-padding) packet received.
    pub fn on_normal_recv(&mut self, now: Instant) -> Vec<DaitaAction> {
        self.dispatch_events(&[TriggerEvent::NormalRecv], now)
    }

    /// Record a padding packet sent.
    pub fn on_padding_sent(&mut self, now: Instant) -> Vec<DaitaAction> {
        let machine = self.last_padding_machine.unwrap_or(MachineId::from_raw(0));
        self.dispatch_events(&[TriggerEvent::PaddingSent { machine }], now)
    }

    /// Record a padding packet received.
    pub fn on_padding_recv(&mut self, now: Instant) -> Vec<DaitaAction> {
        self.dispatch_events(&[TriggerEvent::PaddingRecv], now)
    }

    /// Process timer expiration events and advance state machines.
    pub fn on_timer(&mut self, now: Instant) -> Vec<DaitaAction> {
        if self.framework.is_none() {
            return Vec::new();
        }

        let mut events = Vec::new();

        // 1. Check internal timers
        for mi in 0..self.internal_timers.len() {
            if let Some(deadline) = self.internal_timers[mi] {
                if now >= deadline {
                    self.internal_timers[mi] = None;
                    events.push(TriggerEvent::TimerEnd {
                        machine: MachineId::from_raw(mi),
                    });
                }
            }
        }

        // 2. Check action timers
        for mi in 0..self.action_timers.len() {
            if let Some((deadline, action)) = self.action_timers[mi] {
                if now >= deadline {
                    self.action_timers[mi] = None;
                    if let DaitaAction::BlockOutgoing { duration, .. } = action {
                        events.push(TriggerEvent::BlockingBegin {
                            machine: MachineId::from_raw(mi),
                        });
                        self.blocking_until = Some(now + duration);
                    }
                }
            }
        }

        // 3. Check blocking expiration
        if let Some(until) = self.blocking_until {
            if now >= until {
                self.blocking_until = None;
                events.push(TriggerEvent::BlockingEnd);
            }
        }

        if events.is_empty() {
            Vec::new()
        } else {
            self.dispatch_events(&events, now)
        }
    }

    fn dispatch_events(&mut self, events: &[TriggerEvent], now: Instant) -> Vec<DaitaAction> {
        let Some(fw) = self.framework.as_mut() else {
            return Vec::new();
        };

        let actions: Vec<TriggerAction<Instant>> =
            fw.trigger_events(events, now).cloned().collect();
        let mut out = Vec::new();

        for action in actions {
            match action {
                TriggerAction::Cancel { machine, timer } => {
                    let mi = machine.into_raw();
                    if (timer == Timer::Internal || timer == Timer::All)
                        && mi < self.internal_timers.len()
                    {
                        self.internal_timers[mi] = None;
                    }
                    if (timer == Timer::Action || timer == Timer::All)
                        && mi < self.action_timers.len()
                    {
                        self.action_timers[mi] = None;
                    }
                }
                TriggerAction::SendPadding {
                    timeout,
                    bypass: _,
                    replace: _,
                    machine,
                } => {
                    self.last_padding_machine = Some(machine);
                    let act = DaitaAction::SendPadding { timeout };
                    let mi = machine.into_raw();
                    if mi < self.action_timers.len() {
                        self.action_timers[mi] = Some((now + timeout, act));
                    }
                    out.push(act);
                }
                TriggerAction::BlockOutgoing {
                    timeout,
                    duration,
                    bypass: _,
                    replace: _,
                    machine,
                } => {
                    let act = DaitaAction::BlockOutgoing { timeout, duration };
                    let mi = machine.into_raw();
                    if mi < self.action_timers.len() {
                        self.action_timers[mi] = Some((now + timeout, act));
                    }
                    out.push(act);
                }
                TriggerAction::UpdateTimer {
                    duration,
                    replace,
                    machine,
                } => {
                    let mi = machine.into_raw();
                    let deadline = now + duration;
                    if mi < self.internal_timers.len() {
                        let slot = &mut self.internal_timers[mi];
                        if replace || slot.is_none() || slot.is_some_and(|curr| deadline > curr) {
                            *slot = Some(deadline);
                        }
                    }
                }
            }
        }

        out
    }
}

fn build_machines(
    profile: &DaitaProfile,
    rng: &mut XorShift64,
) -> Result<Vec<Machine>, DaitaError> {
    match profile {
        DaitaProfile::Off => Ok(Vec::new()),
        DaitaProfile::Front => {
            // FRONT defense: RAYLEIGH distributed padding bursts
            Ok(maybenot_machines::front::front(
                20,
                500_000.0,
                3_000_000.0,
                5,
                rng,
            ))
        }
        DaitaProfile::Regulator => {
            // RegulaTor client: rate regulation with bounded queue delay
            Ok(maybenot_machines::regulator::regulator_client(0.5, 0.05))
        }
        DaitaProfile::Balanced => {
            // Balanced defense: moderate padding budget and window
            Ok(maybenot_machines::front::front(
                15,
                400_000.0,
                2_000_000.0,
                5,
                rng,
            ))
        }
        DaitaProfile::Paranoid => {
            // Paranoid defense: higher padding budget and tighter burst interval
            Ok(maybenot_machines::front::front(
                40,
                100_000.0,
                1_000_000.0,
                8,
                rng,
            ))
        }
        DaitaProfile::Custom(bytes) => parse_custom_machines(bytes, rng),
    }
}

fn parse_custom_machines(bytes: &[u8], rng: &mut XorShift64) -> Result<Vec<Machine>, DaitaError> {
    let s = std::str::from_utf8(bytes).map_err(|e| {
        DaitaError::MachineParseError(format!("custom machine definition not valid UTF-8: {e}"))
    })?;

    let mut machines = Vec::new();
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Try parsing base64 serialized Machine first
        if let Ok(m) = Machine::from_str(trimmed) {
            machines.push(m);
            continue;
        }
        // Try parsing StaticMachine string
        if let Ok(sm) = maybenot_machines::StaticMachine::from_str(trimmed) {
            machines.extend(maybenot_machines::get_machine(&[sm], rng));
            continue;
        }
        // If neither, try splitting tokens on this line in case multiple base64 machines are space-separated
        let mut parsed_any = false;
        for token in trimmed.split_whitespace() {
            if let Ok(m) = Machine::from_str(token) {
                machines.push(m);
                parsed_any = true;
            }
        }
        if !parsed_any {
            return Err(DaitaError::MachineParseError(format!(
                "failed to parse machine definition: {trimmed}"
            )));
        }
    }

    if machines.is_empty() {
        return Err(DaitaError::MachineParseError(
            "custom machine definition contained no valid machines".to_string(),
        ));
    }

    Ok(machines)
}
