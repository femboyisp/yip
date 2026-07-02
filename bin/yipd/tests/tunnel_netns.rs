//! End-to-end tunnel test: two yipd in separate netns ping across the tunnel.
//! Requires root (CAP_NET_ADMIN + netns); SKIPs otherwise. Run in CI under sudo.
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
