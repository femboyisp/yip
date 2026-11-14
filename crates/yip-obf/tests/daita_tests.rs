//! Unit tests for DAITA probabilistic state machines.
#![forbid(unsafe_code)]

use enum_map::enum_map;
use maybenot::action::Action;
use maybenot::dist::{Dist, DistType};
use maybenot::event::Event;
use maybenot::state::{State, Trans};
use maybenot::{Machine, Timer};
use std::time::{Duration, Instant};
use yip_obf::{DaitaAction, DaitaEngine, DaitaError, DaitaProfile};

fn const_dist(micros: f64) -> Dist {
    Dist {
        dist: DistType::Uniform {
            low: 0.0,
            high: 0.0,
        },
        start: micros,
        max: 0.0,
    }
}

fn create_custom_engine(states: Vec<State>, now: Instant) -> DaitaEngine {
    let machine = Machine::new(10_000, 1.0, 10_000_000, 1.0, states).expect("valid machine");
    let serialized = machine.serialize();
    DaitaEngine::new(DaitaProfile::Custom(serialized.into_bytes()), now)
        .expect("custom engine inits")
}

#[test]
fn test_off_profile_is_noop() {
    let now = Instant::now();
    let mut engine = DaitaEngine::new(DaitaProfile::Off, now).expect("Off profile inits");
    assert!(!engine.is_active());
    assert_eq!(engine.profile(), &DaitaProfile::Off);
    assert_eq!(engine.next_timer_deadline(), None);

    assert!(engine.on_tunnel_sent(now).is_empty());
    assert!(engine.on_tunnel_recv(now).is_empty());
    assert!(engine.on_normal_sent(now).is_empty());
    assert!(engine.on_normal_recv(now).is_empty());
    assert!(engine.on_padding_sent(now).is_empty());
    assert!(engine.on_padding_recv(now).is_empty());
    assert!(engine.on_timer(now).is_empty());
}

#[test]
fn test_daita_error_display() {
    let err1 = DaitaError::InvalidProfile("bad_profile".to_string());
    assert_eq!(format!("{err1}"), "invalid DAITA profile: bad_profile");

    let err2 = DaitaError::MachineParseError("parse fail".to_string());
    assert_eq!(format!("{err2}"), "failed to parse machine: parse fail");

    let err3 = DaitaError::FrameworkError("internal fw error".to_string());
    assert_eq!(
        format!("{err3}"),
        "DAITA framework error: internal fw error"
    );
}

#[test]
fn test_limits_configuration() {
    let now = Instant::now();
    let engine = DaitaEngine::with_limits(DaitaProfile::Front, now, 0.25, 0.10)
        .expect("Front with custom limits inits");
    assert_eq!(engine.max_padding_frac(), 0.25);
    assert_eq!(engine.max_blocking_frac(), 0.10);
    assert!(engine.is_active());
    assert_eq!(engine.profile(), &DaitaProfile::Front);

    let off_engine = DaitaEngine::with_limits(DaitaProfile::Off, now, 0.30, 0.20)
        .expect("Off with custom limits inits");
    assert_eq!(off_engine.max_padding_frac(), 0.30);
    assert_eq!(off_engine.max_blocking_frac(), 0.20);
    assert!(!off_engine.is_active());
    assert_eq!(off_engine.profile(), &DaitaProfile::Off);

    // Invalid limits (not fractions in 0.0..=1.0) must fail
    assert!(matches!(
        DaitaEngine::with_limits(DaitaProfile::Front, now, -0.1, 0.05).unwrap_err(),
        DaitaError::FrameworkError(_)
    ));
    assert!(matches!(
        DaitaEngine::with_limits(DaitaProfile::Front, now, 1.5, 0.05).unwrap_err(),
        DaitaError::FrameworkError(_)
    ));
    assert!(matches!(
        DaitaEngine::with_limits(DaitaProfile::Front, now, 0.1, -0.05).unwrap_err(),
        DaitaError::FrameworkError(_)
    ));
    assert!(matches!(
        DaitaEngine::with_limits(DaitaProfile::Front, now, 0.1, 1.5).unwrap_err(),
        DaitaError::FrameworkError(_)
    ));
}

#[test]
fn test_front_initialization_and_behavior() {
    let now = Instant::now();
    let mut engine = DaitaEngine::new(DaitaProfile::Front, now).expect("Front profile inits");
    assert!(engine.is_active());
    assert_eq!(engine.profile(), &DaitaProfile::Front);

    // Front starts in state 0, waiting for NormalSent or NormalRecv
    let actions = engine.on_normal_sent(now);
    assert!(
        !actions.is_empty(),
        "Front should emit actions upon normal packet sent"
    );

    let mut found_padding = false;
    for act in actions {
        if let DaitaAction::SendPadding { timeout } = act {
            found_padding = true;
            assert!(timeout >= Duration::ZERO);
        }
    }
    assert!(found_padding, "Front should emit SendPadding action");

    // Action timer should be scheduled
    let deadline = engine.next_timer_deadline();
    assert!(deadline.is_some(), "Front should have scheduled a timer");

    // Advancing timer before deadline: no expiration
    let earlier = deadline.unwrap() - Duration::from_millis(1);
    assert!(engine.on_timer(earlier).is_empty());
    assert_eq!(engine.next_timer_deadline(), deadline);

    // Advancing timer at deadline
    let future = deadline.unwrap() + Duration::from_millis(10);
    let _ = engine.on_timer(future);

    // Send padding notification
    let post_padding_actions = engine.on_padding_sent(future);
    let _ = post_padding_actions;

    // Send tunnel notification
    let post_tunnel_actions = engine.on_tunnel_sent(future);
    let _ = post_tunnel_actions;
}

#[test]
fn test_regulator_initialization_and_behavior() {
    let now = Instant::now();
    let mut engine =
        DaitaEngine::new(DaitaProfile::Regulator, now).expect("Regulator profile inits");
    assert!(engine.is_active());
    assert_eq!(engine.profile(), &DaitaProfile::Regulator);

    let actions = engine.on_normal_sent(now);
    for act in &actions {
        match act {
            DaitaAction::BlockOutgoing {
                timeout: _,
                duration,
            } => {
                assert!(*duration > Duration::ZERO);
            }
            DaitaAction::SendPadding { timeout } => {
                assert!(*timeout >= Duration::ZERO);
            }
        }
    }

    let deadline = engine.next_timer_deadline();
    if let Some(t) = deadline {
        let future = t + Duration::from_millis(50);
        let _ = engine.on_timer(future);
    }

    let _ = engine.on_tunnel_sent(now);
    let _ = engine.on_tunnel_recv(now);
}

#[test]
fn test_balanced_and_paranoid_profiles() {
    let now = Instant::now();

    let mut balanced =
        DaitaEngine::new(DaitaProfile::Balanced, now).expect("Balanced profile inits");
    assert!(balanced.is_active());
    let actions = balanced.on_normal_sent(now);
    assert!(!actions.is_empty(), "Balanced should emit padding actions");

    let mut paranoid =
        DaitaEngine::new(DaitaProfile::Paranoid, now).expect("Paranoid profile inits");
    assert!(paranoid.is_active());
    let actions2 = paranoid.on_normal_sent(now);
    assert!(!actions2.is_empty(), "Paranoid should emit padding actions");
}

#[test]
fn test_custom_machine_serialization_and_deserialization() {
    let now = Instant::now();

    // 1. Using a known valid serialized machine (no-op machine from maybenot)
    let no_op_serialized = "02eNpjYEAHjOgCAAA0AAI=";
    let custom_profile = DaitaProfile::Custom(no_op_serialized.as_bytes().to_vec());
    let mut engine = DaitaEngine::new(custom_profile, now).expect("Custom machine inits");
    assert!(engine.is_active());
    assert!(engine.on_normal_sent(now).is_empty());

    // Multiple space-separated base64 machines on a single line
    let multi_custom = format!("{no_op_serialized}   {no_op_serialized}");
    let multi_engine = DaitaEngine::new(DaitaProfile::Custom(multi_custom.into_bytes()), now)
        .expect("space-separated custom machines inits");
    assert!(multi_engine.is_active());

    // 2. Using StaticMachine text definition
    let static_def = b"front 10 100000 500000 3".to_vec();
    let custom_static = DaitaProfile::Custom(static_def);
    let mut static_engine = DaitaEngine::new(custom_static, now).expect("Static custom inits");
    assert!(static_engine.is_active());
    let acts = static_engine.on_normal_sent(now);
    assert!(!acts.is_empty(), "Custom FRONT machine emits actions");

    // 3. Invalid custom machine definitions fail cleanly
    let invalid = DaitaProfile::Custom(b"not a valid machine definition 12345".to_vec());
    let err = DaitaEngine::new(invalid, now).unwrap_err();
    assert!(matches!(err, DaitaError::MachineParseError(_)));

    let empty_spaces = DaitaProfile::Custom(b"   \n   \n\t ".to_vec());
    let err_empty = DaitaEngine::new(empty_spaces, now).unwrap_err();
    assert!(matches!(err_empty, DaitaError::MachineParseError(_)));

    let non_utf8 = DaitaProfile::Custom(vec![0xff, 0xfe, 0xfd]);
    let err_utf8 = DaitaEngine::new(non_utf8, now).unwrap_err();
    assert!(matches!(err_utf8, DaitaError::MachineParseError(_)));
}

#[test]
fn test_deterministic_event_dispatching_and_actions() {
    let now = Instant::now();

    // Machine with states 0..=6 where each event triggers SendPadding action:
    // 0: NormalSent -> 1 (timeout 50ms)
    // 1: NormalRecv -> 2 (timeout 60ms)
    // 2: PaddingSent -> 3 (timeout 70ms)
    // 3: PaddingRecv -> 4 (timeout 80ms)
    // 4: TunnelSent -> 5 (timeout 90ms)
    // 5: TunnelRecv -> 6 (timeout 100ms)
    // 6: Terminal state
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(50_000.0),
        limit: None,
    });

    let mut s2 = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(60_000.0),
        limit: None,
    });

    let mut s3 = State::new(enum_map! {
        Event::PaddingRecv => vec![Trans(4, 1.0)],
        _ => vec![],
    });
    s3.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(70_000.0),
        limit: None,
    });

    let mut s4 = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(5, 1.0)],
        _ => vec![],
    });
    s4.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(80_000.0),
        limit: None,
    });

    let mut s5 = State::new(enum_map! {
        Event::TunnelRecv => vec![Trans(6, 1.0)],
        _ => vec![],
    });
    s5.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(90_000.0),
        limit: None,
    });

    let mut s6 = State::new(enum_map! {
        _ => vec![],
    });
    s6.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(100_000.0),
        limit: None,
    });

    let mut engine = create_custom_engine(vec![s0, s1, s2, s3, s4, s5, s6], now);

    // 1. on_normal_sent -> transition to 1, emits SendPadding(50ms)
    let act1 = engine.on_normal_sent(now);
    assert_eq!(
        act1,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(50_000)
        }]
    );
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(50_000))
    );

    // 2. on_normal_recv -> transition to 2, emits SendPadding(60ms)
    let act2 = engine.on_normal_recv(now);
    assert_eq!(
        act2,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(60_000)
        }]
    );
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(60_000))
    );

    // 3. on_padding_sent -> transition to 3, emits SendPadding(70ms)
    let act3 = engine.on_padding_sent(now);
    assert_eq!(
        act3,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(70_000)
        }]
    );
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(70_000))
    );

    // 4. on_padding_recv -> transition to 4, emits SendPadding(80ms)
    let act4 = engine.on_padding_recv(now);
    assert_eq!(
        act4,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(80_000)
        }]
    );
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(80_000))
    );

    // 5. on_tunnel_sent -> transition to 5, emits SendPadding(90ms)
    let act5 = engine.on_tunnel_sent(now);
    assert_eq!(
        act5,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(90_000)
        }]
    );
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(90_000))
    );

    // 6. on_tunnel_recv -> transition to 6, emits SendPadding(100ms)
    let act6 = engine.on_tunnel_recv(now);
    assert_eq!(
        act6,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(100_000)
        }]
    );
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(100_000))
    );
}

#[test]
fn test_deterministic_block_outgoing_lifecycle() {
    let now = Instant::now();

    // Machine:
    // State 0: on NormalSent -> transitions to State 1 with BlockOutgoing(timeout=10ms, duration=25ms)
    // State 1: on BlockingBegin -> transitions to State 2
    // State 2: on BlockingEnd -> transitions to State 3 with SendPadding(timeout=5ms)
    // State 3: Terminal
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
        bypass: true,
        replace: true,
        timeout: const_dist(10_000.0),
        duration: const_dist(25_000.0),
        limit: None,
    });

    let s2 = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(3, 1.0)],
        _ => vec![],
    });

    let mut s3 = State::new(enum_map! {
        _ => vec![],
    });
    s3.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(5_000.0),
        limit: None,
    });

    let mut engine = create_custom_engine(vec![s0, s1, s2, s3], now);

    // Enter State 1: emits BlockOutgoing(timeout=10ms, duration=25ms)
    let acts = engine.on_normal_sent(now);
    assert_eq!(
        acts,
        vec![DaitaAction::BlockOutgoing {
            timeout: Duration::from_micros(10_000),
            duration: Duration::from_micros(25_000),
        }]
    );

    // Action timer set to now + 10ms
    let action_deadline = now + Duration::from_micros(10_000);
    assert_eq!(engine.next_timer_deadline(), Some(action_deadline));

    // Calling on_timer before action deadline must not trigger
    let early = now + Duration::from_micros(9_000);
    assert!(engine.on_timer(early).is_empty());
    assert_eq!(engine.next_timer_deadline(), Some(action_deadline));

    // Calling on_timer at action deadline triggers BlockingBegin and schedules blocking_until
    let _ = engine.on_timer(action_deadline);
    let blocking_deadline = action_deadline + Duration::from_micros(25_000);
    assert_eq!(engine.next_timer_deadline(), Some(blocking_deadline));

    // Calling on_timer before blocking expiration must not clear blocking
    let mid_block = action_deadline + Duration::from_micros(20_000);
    assert!(engine.on_timer(mid_block).is_empty());
    assert_eq!(engine.next_timer_deadline(), Some(blocking_deadline));

    // Calling on_timer at blocking expiration triggers BlockingEnd -> transitions to State 3 -> SendPadding
    let timer_acts = engine.on_timer(blocking_deadline);
    assert_eq!(
        timer_acts,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(5_000)
        }]
    );
    assert_eq!(
        engine.next_timer_deadline(),
        Some(blocking_deadline + Duration::from_micros(5_000))
    );
}

#[test]
fn test_deterministic_internal_timer_and_cancel_actions() {
    let now = Instant::now();

    // Machine with internal timers and cancel:
    // State 0: NormalSent -> State 1 (UpdateTimer 40ms, replace=false)
    // State 1: NormalRecv -> State 2 (UpdateTimer 50ms, replace=false) - updates because 50ms > 40ms
    // State 2: TunnelSent -> State 3 (UpdateTimer 30ms, replace=false) - does NOT update because 30ms < 50ms
    // State 3: TimerEnd -> State 4 (SendPadding 15ms)
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::UpdateTimer {
        replace: false,
        duration: const_dist(40_000.0),
        limit: None,
    });

    let mut s2 = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: const_dist(50_000.0),
        limit: None,
    });

    let mut s3 = State::new(enum_map! {
        Event::TimerEnd => vec![Trans(4, 1.0)],
        _ => vec![],
    });
    s3.action = Some(Action::UpdateTimer {
        replace: false,
        duration: const_dist(30_000.0),
        limit: None,
    });

    let mut s4 = State::new(enum_map! {
        _ => vec![],
    });
    s4.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(15_000.0),
        limit: None,
    });

    let mut engine = create_custom_engine(vec![s0, s1, s2, s3, s4], now);

    // Transition to 1: sets internal timer to now + 40ms
    engine.on_normal_sent(now);
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(40_000))
    );

    // Transition to 2: updates internal timer to now + 50ms because 50 > 40
    engine.on_normal_recv(now);
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(50_000))
    );

    // Transition to 3: receives 30ms, does not replace because 30 < 50
    engine.on_tunnel_sent(now);
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(50_000))
    );

    // on_timer before 50ms does not fire
    let early = now + Duration::from_micros(49_000);
    assert!(engine.on_timer(early).is_empty());
    assert_eq!(
        engine.next_timer_deadline(),
        Some(now + Duration::from_micros(50_000))
    );

    // on_timer at 50ms fires TimerEnd -> transitions to 4 -> emits SendPadding(15ms)
    let acts = engine.on_timer(now + Duration::from_micros(50_000));
    assert_eq!(
        acts,
        vec![DaitaAction::SendPadding {
            timeout: Duration::from_micros(15_000)
        }]
    );
}

#[test]
fn test_timer_cancellations() {
    let now = Instant::now();

    // 1. Cancel Internal while Action timer is also active
    // State 0: NormalSent -> State 1 (sets Action timer to 80ms)
    // State 1: NormalRecv -> State 2 (sets Internal timer to 40ms)
    // State 2: TunnelSent -> State 3 (Cancel Timer::Internal)
    // Internal timer is cleared; Action timer (80ms) must remain intact.
    let c0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut c1 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    c1.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(80_000.0),
        limit: None,
    });

    let mut c2 = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    c2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: const_dist(40_000.0),
        limit: None,
    });

    let mut c3 = State::new(enum_map! {
        _ => vec![],
    });
    c3.action = Some(Action::Cancel {
        timer: Timer::Internal,
    });

    let mut engine1 = create_custom_engine(vec![c0, c1, c2, c3], now);
    engine1.on_normal_sent(now); // Enter 1: action timer = 80ms
    assert_eq!(
        engine1.next_timer_deadline(),
        Some(now + Duration::from_micros(80_000))
    );
    engine1.on_normal_recv(now); // Enter 2: internal timer = 40ms, min deadline = 40ms
    assert_eq!(
        engine1.next_timer_deadline(),
        Some(now + Duration::from_micros(40_000))
    );
    engine1.on_tunnel_sent(now); // Enter 3: Cancel Internal -> only action timer (80ms) remains
    assert_eq!(
        engine1.next_timer_deadline(),
        Some(now + Duration::from_micros(80_000))
    );

    // 2. Cancel Action while Internal timer is also active
    // State 0: NormalSent -> State 1 (sets Action timer to 80ms)
    // State 1: NormalRecv -> State 2 (sets Internal timer to 40ms)
    // State 2: TunnelSent -> State 3 (Cancel Timer::Action)
    // Action timer is cleared; Internal timer (40ms) must remain intact.
    let a0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut a1 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    a1.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(80_000.0),
        limit: None,
    });

    let mut a2 = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    a2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: const_dist(40_000.0),
        limit: None,
    });

    let mut a3 = State::new(enum_map! {
        _ => vec![],
    });
    a3.action = Some(Action::Cancel {
        timer: Timer::Action,
    });

    let mut engine2 = create_custom_engine(vec![a0, a1, a2, a3], now);
    engine2.on_normal_sent(now); // Enter 1: action timer = 80ms
    assert_eq!(
        engine2.next_timer_deadline(),
        Some(now + Duration::from_micros(80_000))
    );
    engine2.on_normal_recv(now); // Enter 2: internal timer = 40ms, min deadline = 40ms
    assert_eq!(
        engine2.next_timer_deadline(),
        Some(now + Duration::from_micros(40_000))
    );
    engine2.on_tunnel_sent(now); // Enter 3: Cancel Action -> only internal timer (40ms) remains
    assert_eq!(
        engine2.next_timer_deadline(),
        Some(now + Duration::from_micros(40_000))
    );

    // 3. Cancel All clears both Internal and Action timers
    let all0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut all1 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    all1.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: const_dist(70_000.0),
        limit: None,
    });

    let mut all2 = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    all2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: const_dist(35_000.0),
        limit: None,
    });

    let mut all3 = State::new(enum_map! {
        _ => vec![],
    });
    all3.action = Some(Action::Cancel { timer: Timer::All });

    let mut engine3 = create_custom_engine(vec![all0, all1, all2, all3], now);
    engine3.on_normal_sent(now);
    assert_eq!(
        engine3.next_timer_deadline(),
        Some(now + Duration::from_micros(70_000))
    );
    engine3.on_normal_recv(now);
    assert_eq!(
        engine3.next_timer_deadline(),
        Some(now + Duration::from_micros(35_000))
    );
    engine3.on_tunnel_sent(now); // Cancel All
    assert_eq!(engine3.next_timer_deadline(), None);
}
