//! Unit tests for DAITA probabilistic state machines.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use yip_obf::{DaitaAction, DaitaEngine, DaitaError, DaitaProfile};

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

    // Advancing timer
    let future = deadline.unwrap() + Duration::from_millis(10);
    let timer_actions = engine.on_timer(future);
    // on_timer runs without panics and handles expired timers
    let _ = timer_actions;

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

    // Regulator client sets up seal machine and queue machine
    let actions = engine.on_normal_sent(now);
    // Regulator client may produce BlockOutgoing or SendPadding depending on sub-machines
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

    // Normal traffic on no-op produces no actions
    assert!(engine.on_normal_sent(now).is_empty());

    // 2. Using StaticMachine text definition
    let static_def = b"front 10 100000 500000 3".to_vec();
    let custom_static = DaitaProfile::Custom(static_def);
    let mut static_engine = DaitaEngine::new(custom_static, now).expect("Static custom inits");
    assert!(static_engine.is_active());
    let acts = static_engine.on_normal_sent(now);
    assert!(!acts.is_empty(), "Custom FRONT machine emits actions");

    // 3. Invalid custom machine definition fails cleanly
    let invalid = DaitaProfile::Custom(b"not a valid machine definition 12345".to_vec());
    let err = DaitaEngine::new(invalid, now).unwrap_err();
    assert!(matches!(err, DaitaError::MachineParseError(_)));
}

#[test]
fn test_limits_configuration() {
    let now = Instant::now();
    let engine = DaitaEngine::with_limits(DaitaProfile::Front, now, 0.25, 0.10)
        .expect("Front with custom limits inits");
    assert_eq!(engine.max_padding_frac(), 0.25);
    assert_eq!(engine.max_blocking_frac(), 0.10);

    // Invalid limits (not fractions in 0.0..=1.0) must fail
    let err = DaitaEngine::with_limits(DaitaProfile::Front, now, 1.5, 0.05).unwrap_err();
    assert!(matches!(err, DaitaError::FrameworkError(_)));
}
