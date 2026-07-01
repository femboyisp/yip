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
