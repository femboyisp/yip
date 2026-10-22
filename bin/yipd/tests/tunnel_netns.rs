#![forbid(unsafe_code)]
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

/// Parse a PCAP file and extract all on-wire UDP payload lengths on the underlay.
fn parse_pcap_udp_payload_lengths(pcap_path: &std::path::Path) -> std::io::Result<Vec<usize>> {
    let data = std::fs::read(pcap_path)?;
    if data.len() < 24 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "pcap file too small for header",
        ));
    }
    let magic = &data[..4];
    let is_little_endian = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => true,
    };

    let mut lengths = Vec::new();
    let mut offset = 24;
    while offset + 16 <= data.len() {
        let incl_len_bytes: [u8; 4] = match data[offset + 8..offset + 12].try_into() {
            Ok(b) => b,
            Err(_) => break,
        };
        let incl_len = if is_little_endian {
            u32::from_le_bytes(incl_len_bytes) as usize
        } else {
            u32::from_be_bytes(incl_len_bytes) as usize
        };
        offset += 16;
        if offset + incl_len > data.len() {
            break;
        }
        let pkt = &data[offset..offset + incl_len];
        offset += incl_len;

        // Ethernet frame: 14 bytes header (dest 6, src 6, ethertype 2)
        if pkt.len() < 14 + 20 + 8 {
            continue;
        }
        let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
        if ethertype == 0x0800 {
            // IPv4
            let ip_hdr = &pkt[14..];
            let ihl = ((ip_hdr[0] & 0x0f) as usize) * 4;
            if ip_hdr.len() < ihl + 8 {
                continue;
            }
            let proto = ip_hdr[9];
            if proto == 17 {
                // UDP
                let udp_hdr = &ip_hdr[ihl..ihl + 8];
                let udp_len = u16::from_be_bytes([udp_hdr[4], udp_hdr[5]]) as usize;
                if udp_len >= 8 {
                    lengths.push(udp_len - 8);
                }
            }
        }
    }
    Ok(lengths)
}

/// Verify captured trace passes multi-engine DPI inspection.
fn verify_dpi_trace(pcap_path: &std::path::Path) {
    // 1. tshark DPI verification
    if Command::new("tshark").arg("-v").output().is_ok() {
        let pcap_str = pcap_path.to_str().expect("valid path");
        let filter_output = Command::new("tshark")
            .args([
                "-r",
                pcap_str,
                "-Y",
                "wg || openvpn || isakmp || esp || ah || udpencap || dtls",
                "-T",
                "fields",
                "-e",
                "frame.number",
            ])
            .output()
            .expect("run tshark protocol filter");
        assert!(filter_output.status.success(), "tshark execution failed");
        let matched = String::from_utf8_lossy(&filter_output.stdout);
        assert!(
            matched.trim().is_empty(),
            "DPI leak: tshark detected known VPN protocols in capture: {matched}"
        );

        let proto_output = Command::new("tshark")
            .args(["-r", pcap_str, "-T", "fields", "-e", "frame.protocols"])
            .output()
            .expect("run tshark proto inspection");
        assert!(proto_output.status.success());
        let protos = String::from_utf8_lossy(&proto_output.stdout);
        for line in protos.lines() {
            let line_lower = line.to_ascii_lowercase();
            for kw in &["wireguard", "openvpn", "ipsec", "socks"] {
                assert!(
                    !line_lower.contains(kw),
                    "DPI leak: protocol hierarchy contains '{kw}': {line}"
                );
            }
        }
    }

    // 2. nDPI verification
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let ndpi_candidates = [
        workspace_root.join("refrences/nDPI/example/ndpiReader"),
        std::path::PathBuf::from("/usr/bin/ndpiReader"),
    ];
    for ndpi in &ndpi_candidates {
        if ndpi.exists() {
            let ndpi_out = Command::new(ndpi)
                .args(["-i", pcap_path.to_str().expect("valid path"), "-v", "2"])
                .output()
                .expect("run ndpiReader");
            assert!(ndpi_out.status.success(), "ndpiReader failed");
            let stdout = String::from_utf8_lossy(&ndpi_out.stdout);
            assert!(
                !stdout.contains("[cat: VPN"),
                "nDPI classified obfuscated traffic as VPN category: {stdout}"
            );
            assert!(
                stdout.contains("Unknown") || stdout.contains("Unrated"),
                "nDPI expected to classify neutral-port traffic as Unknown/Unrated: {stdout}"
            );
            break;
        }
    }
}

/// Verify that decoy bursts (JUNK_TYPE) are silently dropped by the receiver with zero session mutation.
fn verify_decoy_burst_zero_mutation() {
    let psk_bytes = [0x42u8; 32];
    let net_key = yip_obf::derive_key(&psk_bytes);
    let session_key = yip_obf::derive_key(&[0x99u8; 16]);

    // Construct decoy datagrams of various sizes under both network and session keys
    for &key in &[net_key, session_key] {
        for body_len in [0, 50, 200, 500] {
            let dummy_body = vec![0xEEu8; body_len];
            let wrapped = yip_obf::obfuscate(&key, yip_obf::JUNK_TYPE, &dummy_body, 32)
                .expect("obfuscate decoy datagram");
            let recovered = yip_obf::deobfuscate(&key, &wrapped);
            assert!(recovered.is_some(), "must recover decoy datagram");
            let (ptype, body) = recovered.unwrap();
            assert_eq!(
                ptype,
                yip_obf::JUNK_TYPE,
                "recovered ptype must be JUNK_TYPE"
            );
            assert_eq!(body, dummy_body, "recovered body matches decoy payload");
        }
    }
}

#[test]
fn netns_tunnel_with_traffic_defense_balanced() {
    let is_root = have_root();
    if !is_root {
        eprintln!(
            "SKIP netns_tunnel_with_traffic_defense_balanced: needs root (run under sudo in CI)"
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tunnel.sh");
    let tmp_dir = std::env::temp_dir();
    let pcap_path = tmp_dir.join(format!("td_balanced_trace_{}.pcap", std::process::id()));

    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .env("OBF_PSK", OBF_PSK)
        .env("TRAFFIC_DEFENSE", "balanced")
        .env("CAPTURE_PCAP", &pcap_path)
        .env("PING_COUNT", "50")
        .env("BIDI_PING", "1")
        .env("RUN_IPERF", "1")
        .env("NS_A", "yipBalA")
        .env("NS_B", "yipBalB")
        .env("VETH_A", "vBalA")
        .env("VETH_B", "vBalB")
        .env("PORT_A", "34567")
        .env("PORT_B", "34568")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "netns tunnel with balanced defense failed (50-ping bidirectional or 3s TCP iperf3 loss)"
    );

    let lengths =
        parse_pcap_udp_payload_lengths(&pcap_path).expect("must parse captured PCAP file");
    assert!(!lengths.is_empty(), "PCAP trace captured no UDP datagrams");

    let allowed_buckets = [256, 512, 1024, 1420];
    let mut bucket_counts = std::collections::HashMap::new();
    for &len in &lengths {
        if len <= 1420 {
            assert!(
                allowed_buckets.contains(&len),
                "on-wire datagram length {len} does not belong to balanced bucket set {allowed_buckets:?}"
            );
            *bucket_counts.entry(len).or_insert(0usize) += 1;
        } else {
            assert!(
                len <= 1600,
                "on-wire datagram length {len} exceeds plausible MTU ceiling"
            );
        }
    }
    assert!(
        bucket_counts.get(&256).copied().unwrap_or(0) > 0,
        "expected at least one 256-byte bucket datagram in balanced trace"
    );

    verify_dpi_trace(&pcap_path);
    let _ = std::fs::remove_file(&pcap_path);
}

#[test]
fn netns_tunnel_with_traffic_defense_paranoid() {
    let is_root = have_root();
    if !is_root {
        eprintln!(
            "SKIP netns_tunnel_with_traffic_defense_paranoid: needs root (run under sudo in CI)"
        );
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tunnel.sh");
    let tmp_dir = std::env::temp_dir();
    let pcap_path = tmp_dir.join(format!("td_paranoid_trace_{}.pcap", std::process::id()));

    let status = Command::new("bash")
        .arg(script)
        .arg(yipd)
        .env("OBF_PSK", OBF_PSK)
        .env("TRAFFIC_DEFENSE", "paranoid")
        .env("CAPTURE_PCAP", &pcap_path)
        .env("PING_COUNT", "50")
        .env("BIDI_PING", "1")
        .env("RUN_IPERF", "1")
        .env("NS_A", "yipParA")
        .env("NS_B", "yipParB")
        .env("VETH_A", "vParA")
        .env("VETH_B", "vParB")
        .env("PORT_A", "34569")
        .env("PORT_B", "34570")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "netns tunnel with paranoid defense failed (50-ping bidirectional or 3s TCP iperf3 loss)"
    );

    let lengths =
        parse_pcap_udp_payload_lengths(&pcap_path).expect("must parse captured PCAP file");
    assert!(!lengths.is_empty(), "PCAP trace captured no UDP datagrams");

    let allowed_buckets = [512, 1420];
    let mut count_512 = 0usize;
    for &len in &lengths {
        if len <= 1420 {
            assert!(
                allowed_buckets.contains(&len),
                "on-wire datagram length {len} does not belong to 2-state paranoid bucket set {allowed_buckets:?}"
            );
            if len == 512 {
                count_512 += 1;
            }
        } else {
            assert!(
                len <= 1600,
                "on-wire datagram length {len} exceeds plausible MTU ceiling"
            );
        }
    }
    assert!(
        count_512 > 0,
        "expected 512-byte bucket datagrams in paranoid trace"
    );
    assert_eq!(
        lengths.iter().filter(|&&l| l == 256 || l == 1024).count(),
        0,
        "paranoid trace must not contain 256 or 1024 bucket sizes"
    );

    verify_dpi_trace(&pcap_path);
    let _ = std::fs::remove_file(&pcap_path);

    verify_decoy_burst_zero_mutation();
}
