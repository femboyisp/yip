//! Measures the yip tunnel's ping latency + effective loss under tc netem.
//! Requires root (netns + netem + TUN); SKIPs otherwise.
use std::process::Command;

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("could not resolve workspace root")
}

#[test]
fn yip_tunnel_under_netem_loss() {
    if !is_root() {
        eprintln!("SKIP yip_tunnel_under_netem_loss: needs root");
        return;
    }

    // Locate the workspace root from this crate's manifest dir:
    //   CARGO_MANIFEST_DIR = <workspace>/crates/yip-bench
    //   workspace root     = ../../ from there
    let root = workspace_root();

    // Use the pre-built binary if it exists; the script will build it otherwise.
    // RELEASE, not debug: yipd's RaptorQ FEC path is ~75x slower unoptimized,
    // which throttles throughput and inflates latency — a debug binary measured
    // against in-kernel WireGuard is an apples-to-oranges comparison.
    let yipd_path = root.join("target/release/yipd");
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

/// Runs yip and kernel WireGuard side-by-side under the same tc netem loss
/// profiles and emits a comparison table.  The thesis: yip's RaptorQ FEC
/// keeps effective loss below WireGuard's (which has no FEC) at every nonzero
/// injected loss rate.
///
/// Requires root (netns, netem, TUN/WireGuard module).  SKIPs otherwise.
/// Saves the combined table to crates/yip-bench/RESULTS.md.
#[test]
fn comparison_under_netem_loss() {
    if !is_root() {
        eprintln!("SKIP comparison_under_netem_loss: needs root");
        return;
    }

    let root = workspace_root();

    // RELEASE: see note in yip_tunnel_under_netem_loss — debug RaptorQ is ~75x
    // slower and would make yip look artificially bad against kernel WireGuard.
    let yipd_path = root.join("target/release/yipd");
    let yipd_arg = if yipd_path.exists() {
        yipd_path.to_string_lossy().into_owned()
    } else {
        String::new()
    };

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-compare.sh");

    let mut cmd = Command::new("bash");
    cmd.arg(script);
    if !yipd_arg.is_empty() {
        cmd.arg(&yipd_arg);
    }

    let status = cmd
        .status()
        .expect("failed to launch compare harness script");
    assert!(status.success(), "yip vs WireGuard compare harness failed");
}

/// Measures scp (TCP) throughput over yip vs kernel WireGuard under tc netem
/// loss profiles.  The thesis: yip's RaptorQ FEC keeps TCP throughput higher
/// than WireGuard under loss (WireGuard's TCP sees real retransmits; yip's FEC
/// hides the loss from TCP).
///
/// Requires root (netns, netem, TUN/WireGuard module, sshd/scp).  SKIPs
/// otherwise.
#[test]
fn scp_throughput_comparison() {
    if !is_root() {
        eprintln!("SKIP scp_throughput_comparison: needs root");
        return;
    }

    let root = workspace_root();

    // RELEASE: see note in yip_tunnel_under_netem_loss — debug RaptorQ is ~75x
    // slower and would make yip look artificially bad against kernel WireGuard.
    let yipd_path = root.join("target/release/yipd");
    let yipd_arg = if yipd_path.exists() {
        yipd_path.to_string_lossy().into_owned()
    } else {
        String::new()
    };

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-scp-compare.sh");

    let mut cmd = std::process::Command::new("bash");
    cmd.arg(script);
    if !yipd_arg.is_empty() {
        cmd.arg(&yipd_arg);
    }

    let status = cmd
        .status()
        .expect("failed to launch scp compare harness script");
    assert!(
        status.success(),
        "yip vs WireGuard scp throughput harness failed"
    );
}

/// Measures UDP delivered-loss recovery across bare-link (no FEC), UDPspeeder
/// (RS-FEC), and yip (RaptorQ-FEC) under tc netem loss using a pure-UDP
/// sequenced blaster.  The FEC-vs-FEC headline: yip and UDPspeeder both recover
/// nearly all loss that the bare link drops.
///
/// Requires root (netns, netem, TUN).  SKIPs otherwise.  The UDPspeeder column
/// SKIPs cleanly inside the harness if the `speederv2` binary is absent.
#[test]
fn udp_loss_recovery_comparison() {
    if !is_root() {
        eprintln!("SKIP udp_loss_recovery_comparison: needs root");
        return;
    }

    let root = workspace_root();

    // RELEASE: see note in yip_tunnel_under_netem_loss — debug RaptorQ is ~75x
    // slower and would make yip look artificially bad against UDPspeeder.
    let yipd_path = root.join("target/release/yipd");
    let yipd_arg = if yipd_path.exists() {
        yipd_path.to_string_lossy().into_owned()
    } else {
        String::new()
    };

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-fec-compare.sh");

    let mut cmd = Command::new("bash");
    cmd.arg(script);
    if !yipd_arg.is_empty() {
        cmd.arg(&yipd_arg);
    }

    let status = cmd
        .status()
        .expect("failed to launch fec compare harness script");
    assert!(status.success(), "yip vs UDPspeeder fec harness failed");
}

/// Measures iperf3 TCP throughput + ping latency/loss across the full-IP
/// tunnels (yip, WireGuard, OpenVPN, n2n) under tc netem loss.  yip's FEC keeps
/// effective loss and TCP throughput ahead of the no-FEC tunnels as loss rises.
///
/// Requires root (netns, netem, TUN/WireGuard module).  SKIPs otherwise.  Each
/// non-yip contender SKIPs cleanly inside the harness if its tool/module is
/// absent; yip always runs.
#[test]
fn iperf_throughput_comparison() {
    if !is_root() {
        eprintln!("SKIP iperf_throughput_comparison: needs root");
        return;
    }

    let root = workspace_root();

    // RELEASE: see note in yip_tunnel_under_netem_loss — debug RaptorQ is ~75x
    // slower and would make yip look artificially bad against the other tunnels.
    let yipd_path = root.join("target/release/yipd");
    let yipd_arg = if yipd_path.exists() {
        yipd_path.to_string_lossy().into_owned()
    } else {
        String::new()
    };

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-iperf-compare.sh");

    let mut cmd = Command::new("bash");
    cmd.arg(script);
    if !yipd_arg.is_empty() {
        cmd.arg(&yipd_arg);
    }

    let status = cmd
        .status()
        .expect("failed to launch iperf compare harness script");
    assert!(status.success(), "yip iperf throughput harness failed");
}
