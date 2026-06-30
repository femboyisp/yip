//! Measures the yip tunnel's ping latency + effective loss under tc netem.
//! Requires root (netns + netem + TUN); SKIPs otherwise.
use std::process::Command;

#[test]
fn yip_tunnel_under_netem_loss() {
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP yip_tunnel_under_netem_loss: needs root");
        return;
    }

    // Locate the workspace root from this crate's manifest dir:
    //   CARGO_MANIFEST_DIR = <workspace>/crates/yip-bench
    //   workspace root     = ../../ from there
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .join("../..")
        .canonicalize()
        .expect("could not resolve workspace root");

    // Use the pre-built binary if it exists; the script will build it otherwise.
    let yipd_path = workspace_root.join("target/debug/yipd");
    let yipd_arg = if yipd_path.exists() {
        yipd_path.to_string_lossy().into_owned()
    } else {
        String::new()
    };

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-yip-netem.sh");

    let mut cmd = Command::new("bash");
    cmd.arg(script);
    if !yipd_arg.is_empty() {
        cmd.arg(&yipd_arg);
    }

    let status = cmd.status().expect("failed to launch netem harness script");
    assert!(status.success(), "yip netem harness failed");
}
