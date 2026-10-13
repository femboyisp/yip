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

/// True if we should run the root-gated netns/TUN tests. Skips when
/// `YIP_SKIP_PRIVILEGED_TESTS` is set (the non-privileged `build-test` CI job
/// runs as root in a container without netns/`ip` tooling, so these tests must
/// skip rather than fail); privileged integration jobs and local `sudo cargo
/// test` leave it unset and still run.
fn have_root() -> bool {
    if std::env::var_os("YIP_SKIP_PRIVILEGED_TESTS").is_some() {
        return false;
    }
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

#[test]
fn ping_across_yipd_tunnel() {
    // Only run as root (the script needs netns + TUN).
    let is_root = have_root();
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
    let is_root = have_root();
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
fn quic_tunnel_ping() {
    // Requires root: netns creation + TUN devices. QUIC is poll-only in 3c.1
    // (run_quic ignores YIP_USE_URING), so — unlike ping_across_yipd_tunnel —
    // this test is never exercised under the UringDriver in the netns CI
    // matrix; see .github/workflows/integration.yml's separate poll-only loop.
    let is_root = have_root();
    if !is_root {
        eprintln!("SKIP quic_tunnel_ping: needs root");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-quic.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(
        status.success(),
        "netns QUIC tunnel ping failed (transport=quic did not connect end-to-end: \
         outer QUIC handshake, inner yip Noise-IK handshake, or the DATAGRAM-frame pump)"
    );
}

#[test]
fn quic_ping_under_loss() {
    // Requires root: netns creation + TUN device + tc netem. Poll-only, same
    // reasoning as quic_tunnel_ping.
    let is_root = have_root();
    if !is_root {
        eprintln!("SKIP quic_ping_under_loss: needs root");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-quic-loss.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(
        status.success(),
        "netns QUIC tunnel ping under 10% loss failed (yip's FEC did not recover \
         dropped QUIC DATAGRAM frames)"
    );
}

#[test]
fn tls_tunnel_ping() {
    // Requires root: netns creation + TUN devices. Like QUIC (3c.1), the TLS
    // costume (3c.2) is its own poll-style pump and ignores YIP_USE_URING, so
    // it is not exercised under the UringDriver in the netns CI matrix. Two
    // sequential handshakes (outer TLS 1.3 over TCP, then inner yip Noise-IK
    // over the length-prefix-framed byte-stream) must complete before traffic
    // flows; the script's ping budget is sized for that warm-up.
    let is_root = have_root();
    if !is_root {
        eprintln!("SKIP tls_tunnel_ping: needs root");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tls.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(
        status.success(),
        "netns TLS tunnel test failed (transport=tls did not connect end-to-end: \
         outer TLS handshake, inner yip Noise-IK handshake, the length-prefix framing \
         pump, or the full-MTU integrity sweep)"
    );
}

#[test]
fn l2_tap_ping_or_arp_across_tunnel() {
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
fn obfuscated_ping_with_cover() {
    // Only run as root (the script needs netns + TUN).
    let is_root = have_root();
    if !is_root {
        eprintln!("SKIP obfuscated_ping_with_cover: needs root (run under sudo in CI)");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tunnel.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .env("OBF_PSK", OBF_PSK)
        .env("COVER_MS", "200")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "netns tunnel ping with obf_psk + cover_traffic_ms set failed (junk/cover broke direct connectivity)"
    );
}

#[test]
fn obf_psk_mismatch_no_connection() {
    // Only run as root (the script needs netns + TUN).
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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
    let is_root = have_root();
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

#[test]
fn flowshape_not_obviously_constant() {
    // Lightweight deterministic flow-shape structural check (3b Task 7,
    // Deliverable 2/3) — NOT the nDPId -A ML harness. Packet-count analogue
    // of 3a's `no_byte_position_is_constant`: for N independent obf-on
    // sessions (fresh handshake each, both peers bootstrap-initiate and
    // glare-resolve — see run-flowshape-check.sh's header comment), the
    // handshake DENSE-CLUSTER SPAN (the index of the last datagram in a run
    // of >=3 packets spaced <1ms apart, measured from the pcap in arrival
    // order — not by source address, since there is no fixed "initiator"
    // role, and NOT by a single gap cutoff, which a scheduling stall would
    // truncate) is gated two ways: (a) a loose sanity floor — every span >
    // SPAN_FLOOR (4) — that only rejects a broken capture, and (b) the PRIMARY
    // proof: the spread (max-min) of the N spans >= SPREAD_MIN (6). The Jc in
    // [JUNK_BURST_MIN, JUNK_BURST_MAX] burst on each side is redrawn per
    // handshake, so junk-ON spans vary widely (spread 14-19 on CI) while a
    // junk-free / fixed-junk handshake is near-constant (spread <= 4) — so the
    // spread proves BOTH junk-present and randomized in one shot, and is
    // LEVEL-INDEPENDENT (an earlier absolute "> 12" floor false-failed on CI
    // when contention pulled junk-on spans down to ~12). See
    // run-flowshape-check.sh for the full assertion set and derivation.
    //
    // Requires root: netns creation + TUN devices + tcpdump.
    let is_root = have_root();
    if !is_root {
        eprintln!("SKIP flowshape_not_obviously_constant: needs root (run under sudo in CI)");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-flowshape-check.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(
        status.success(),
        "flow-shape structural check failed (obf-on handshake dense-cluster span spread across \
         sessions was < SPREAD_MIN, or a capture was broken — the Jc junk burst is not reaching \
         the wire / randomizing the opener as expected)"
    );
}
