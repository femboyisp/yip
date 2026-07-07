//! End-to-end tunnel test: two yipd in separate netns ping across the tunnel.
//! Requires root (CAP_NET_ADMIN + netns); SKIPs otherwise. Run in CI under sudo.
//!
//! `relay_path_ping` and `hole_punch_ping` (2b Task 7) are the rendezvous
//! money tests: each asserts not just that the ping succeeds, but *which*
//! path (blind relay vs. punch/direct) carried the traffic, via the
//! server's `relay-forwarded=<N>` counter. Graceful degradation (no
//! `rendezvous` configured) is already covered by the plain 2a tests above
//! (`ping_across_yipd_tunnel`, `triangle_full_mesh_ping`, etc.), and
//! optional-endpoint reachability is exercised by both money tests, whose
//! peers are configured by `public_key` only (no `endpoint`) — so no
//! separate script is needed for either.
use std::process::Command;

#[test]
fn ping_across_yipd_tunnel() {
    // Only run as root (the script needs netns + TUN).
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP ping_across_yipd_tunnel: needs root (run under sudo in CI)");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tunnel.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(status.success(), "netns tunnel ping failed");
}

#[test]
fn ping_across_yipd_tunnel_under_loss() {
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP ping_across_yipd_tunnel_under_loss: needs root");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/run-netns-tunnel-loss.sh"
    );
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(status.success(), "netns tunnel ping under 10% loss failed");
}

#[test]
fn l2_tap_ping_or_arp_across_tunnel() {
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP l2_tap_ping_or_arp_across_tunnel: needs root");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tunnel-l2.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(
        status.success(),
        "netns TAP tunnel L2 ping/ARP validation failed"
    );
}

#[test]
fn triangle_full_mesh_ping() {
    // Requires root: netns creation + TUN devices + a shared bridge underlay.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP triangle_full_mesh_ping: needs root (run under sudo in CI)");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-triangle.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(
        status.success(),
        "3-peer netns triangle full-mesh ping failed"
    );
}

#[test]
fn arq_recovers_bulk_loss() {
    // Requires root: netns creation + TUN device + tc netem.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP arq_recovers_bulk_loss: needs root (run under sudo in CI)");
        return;
    }
    // Use the release binary for this test: RaptorQ is ~75× slower in debug.
    // The release binary is at target/release/yipd relative to the workspace root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // Walk up from bin/yipd to the workspace root (two parent directories).
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels up from CARGO_MANIFEST_DIR");
    let yipd_release = workspace_root.join("target/release/yipd");
    if !yipd_release.exists() {
        eprintln!(
            "SKIP arq_recovers_bulk_loss: release yipd not found at {}; \
             run `cargo build --release -p yipd` first",
            yipd_release.display()
        );
        return;
    }
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-arq-integrity.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(&yipd_release)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "ARQ integrity test failed: FEC+ARQ did not recover 5% bulk loss or ARQ did not fire"
    );
}

/// Locate the `yip-rendezvous` debug binary in the shared workspace target
/// dir. Unlike `yipd` (built in-package via `CARGO_BIN_EXE_yipd`, resolved at
/// compile time), `yip-rendezvous` lives in a different workspace package
/// (`yip-rendezvous-bin`); Cargo only populates `CARGO_BIN_EXE_<name>` for a
/// package's own binaries on stable (cross-package binary exe paths need the
/// nightly-only `artifact-dependencies`/`-Z bindeps` feature), so this
/// resolves the path the same way `arq_recovers_bulk_loss` resolves the
/// release `yipd` binary: relative to `CARGO_MANIFEST_DIR`, two levels up to
/// the workspace root, then into `target/debug`.
fn yip_rendezvous_bin() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels up from CARGO_MANIFEST_DIR");
    workspace_root.join("target/debug/yip-rendezvous")
}

#[test]
fn relay_path_ping() {
    // Requires root: netns creation + TUN devices + yip-rendezvous.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP relay_path_ping: needs root (run under sudo in CI)");
        return;
    }
    let rdv = yip_rendezvous_bin();
    if !rdv.exists() {
        eprintln!(
            "SKIP relay_path_ping: yip-rendezvous binary not found at {}; \
             run `cargo build -p yip-rendezvous-bin` first",
            rdv.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-relay.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&rdv)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "relay-path netns test failed (ping did not succeed, or relay-forwarded stayed 0)"
    );
}

/// Locate the `yip-ca` debug binary the same way `yip_rendezvous_bin` locates
/// `yip-rendezvous`: a different workspace package, so `CARGO_BIN_EXE_yip-ca`
/// isn't populated for this (`yipd`) package's test binary on stable.
fn yip_ca_bin() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels up from CARGO_MANIFEST_DIR");
    workspace_root.join("target/debug/yip-ca")
}

#[test]
fn discovery_dynamic_ping() {
    // Requires root: netns creation + TUN devices + a shared bridge underlay.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP discovery_dynamic_ping: needs root (run under sudo in CI)");
        return;
    }
    let yip_ca = yip_ca_bin();
    if !yip_ca.exists() {
        eprintln!(
            "SKIP discovery_dynamic_ping: yip-ca binary not found at {}; \
             run `cargo build -p yip-ca` first",
            yip_ca.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-discovery.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&yip_ca)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "dynamic-discovery netns test failed (A did not discover+ping B via gossip, \
         or A's config was not free of static knowledge of B)"
    );
}

#[test]
fn admission_rejects_uncertified() {
    // Requires root: netns creation + TUN devices.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP admission_rejects_uncertified: needs root (run under sudo in CI)");
        return;
    }
    let yip_ca = yip_ca_bin();
    if !yip_ca.exists() {
        eprintln!(
            "SKIP admission_rejects_uncertified: yip-ca binary not found at {}; \
             run `cargo build -p yip-ca` first",
            yip_ca.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/run-netns-admission-reject.sh"
    );
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&yip_ca)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "admission-reject netns test failed (an uncertified peer's handshake was \
         unexpectedly admitted, or the harness itself errored)"
    );
}

#[test]
fn discovery_survives_root_outage() {
    // Requires root: netns creation + TUN devices + a shared bridge underlay.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP discovery_survives_root_outage: needs root (run under sudo in CI)");
        return;
    }
    let yip_ca = yip_ca_bin();
    if !yip_ca.exists() {
        eprintln!(
            "SKIP discovery_survives_root_outage: yip-ca binary not found at {}; \
             run `cargo build -p yip-ca` first",
            yip_ca.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/run-netns-root-outage.sh"
    );
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&yip_ca)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "root-outage netns test failed (A<->B connectivity did not survive the root's death, \
         or the initial discovery ping never converged)"
    );
}

/// Fixed 64-hex test PSK shared by the obf-on netns tests (3a Task 6).
const OBF_PSK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[test]
fn obfuscated_ping() {
    // Only run as root (the script needs netns + TUN).
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP obfuscated_ping: needs root (run under sudo in CI)");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tunnel.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .env("OBF_PSK", OBF_PSK)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "netns tunnel ping with obf_psk set failed (obfuscation broke direct connectivity)"
    );
}

#[test]
fn obf_psk_mismatch_no_connection() {
    // Only run as root (the script needs netns + TUN).
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP obf_psk_mismatch_no_connection: needs root (run under sudo in CI)");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/run-netns-obf-mismatch.sh"
    );
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(
        status.success(),
        "obf_psk mismatch netns test failed (script itself errored, or the ping \
         unexpectedly succeeded under mismatched PSKs)"
    );
}

#[test]
fn relay_path_ping_obfuscated() {
    // Requires root: netns creation + TUN devices + yip-rendezvous.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP relay_path_ping_obfuscated: needs root (run under sudo in CI)");
        return;
    }
    let rdv = yip_rendezvous_bin();
    if !rdv.exists() {
        eprintln!(
            "SKIP relay_path_ping_obfuscated: yip-rendezvous binary not found at {}; \
             run `cargo build -p yip-rendezvous-bin` first",
            rdv.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-relay.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&rdv)
        .env("OBF_PSK", OBF_PSK)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "relay-path netns test with obf_psk set failed (ping did not succeed, or \
         relay-forwarded stayed 0 — obfuscation broke rendezvous+relay)"
    );
}

#[test]
fn hole_punch_ping_obfuscated() {
    // Requires root: netns creation + TUN devices + yip-rendezvous + NAT.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP hole_punch_ping_obfuscated: needs root (run under sudo in CI)");
        return;
    }
    let rdv = yip_rendezvous_bin();
    if !rdv.exists() {
        eprintln!(
            "SKIP hole_punch_ping_obfuscated: yip-rendezvous binary not found at {}; \
             run `cargo build -p yip-rendezvous-bin` first",
            rdv.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-punch.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&rdv)
        .env("OBF_PSK", OBF_PSK)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "hole-punch netns test with obf_psk set failed (ping did not succeed, or \
         relay-forwarded was nonzero — obfuscation broke the punch path)"
    );
}

#[test]
fn discovery_dynamic_ping_obfuscated() {
    // Requires root: netns creation + TUN devices + a shared bridge underlay.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP discovery_dynamic_ping_obfuscated: needs root (run under sudo in CI)");
        return;
    }
    let yip_ca = yip_ca_bin();
    if !yip_ca.exists() {
        eprintln!(
            "SKIP discovery_dynamic_ping_obfuscated: yip-ca binary not found at {}; \
             run `cargo build -p yip-ca` first",
            yip_ca.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-discovery.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&yip_ca)
        .env("OBF_PSK", OBF_PSK)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "dynamic-discovery netns test with obf_psk set failed (A did not discover+ping B \
         via gossip — obfuscation broke gossip or the cert handshake)"
    );
}

#[test]
fn hole_punch_ping() {
    // Requires root: netns creation + TUN devices + yip-rendezvous + NAT.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP hole_punch_ping: needs root (run under sudo in CI)");
        return;
    }
    let rdv = yip_rendezvous_bin();
    if !rdv.exists() {
        eprintln!(
            "SKIP hole_punch_ping: yip-rendezvous binary not found at {}; \
             run `cargo build -p yip-rendezvous-bin` first",
            rdv.display()
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-punch.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .arg(&rdv)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "hole-punch netns test failed (ping did not succeed, or relay-forwarded was nonzero)"
    );
}
