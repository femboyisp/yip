//! Round-trip proof: a cert (and root set) emitted by the `yip-ca` binary
//! decodes and verifies against `yip-membership`'s own verifier.
use std::io::Write as _;
use std::process::{Command, Stdio};

use yip_membership::cert::{verify_cert, Cert, RootSet};

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_yip-ca"))
        .args(args)
        .output()
        .expect("failed to spawn yip-ca");
    assert!(
        output.status.success(),
        "yip-ca {args:?} exited with {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("yip-ca stdout was not utf8")
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("bad hex in {s:?}: {e}"))
        })
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

struct GenKey {
    ca_private: String,
    ca_public: String,
}

fn genkey() -> GenKey {
    let out = run(&["genkey"]);
    let mut ca_private = None;
    let mut ca_public = None;
    for line in out.lines() {
        if let Some(v) = line.strip_prefix("ca_private=") {
            ca_private = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("ca_public=") {
            ca_public = Some(v.to_string());
        }
    }
    GenKey {
        ca_private: ca_private.expect("genkey printed ca_private=<hex>"),
        ca_public: ca_public.expect("genkey printed ca_public=<hex>"),
    }
}

#[test]
fn cert_issued_by_yip_ca_verifies_in_yip_membership() {
    let key = genkey();

    let member_hex = "11".repeat(32);
    let member_sign_hex = "22".repeat(32);
    let network_hex = "33".repeat(16);

    let cert_out = run(&[
        "sign-cert",
        "--member",
        &member_hex,
        "--member-sign",
        &member_sign_hex,
        "--network",
        &network_hex,
        "--days",
        "30",
        "--ca-private",
        &key.ca_private,
    ]);
    let cert_bytes = hex_decode(cert_out.trim());
    let cert = Cert::decode(&cert_bytes).expect("emitted cert decodes");

    let member_pubkey: [u8; 32] = hex_decode(&member_hex).try_into().unwrap();
    let member_sign_pubkey: [u8; 32] = hex_decode(&member_sign_hex).try_into().unwrap();
    let network_id: [u8; 16] = hex_decode(&network_hex).try_into().unwrap();
    let ca_pub: [u8; 32] = hex_decode(&key.ca_public).try_into().unwrap();

    assert_eq!(cert.version, 1);
    assert_eq!(cert.member_pubkey, member_pubkey);
    assert_eq!(cert.member_sign_pubkey, member_sign_pubkey);
    assert_eq!(cert.network_id, network_id);
    assert_eq!(cert.not_after - cert.not_before, 30 * 86400);

    let now = now_secs();
    assert_eq!(
        verify_cert(&cert, &[ca_pub], &network_id, &member_pubkey, now, 0),
        Ok(())
    );

    // A cert against the wrong CA key must not verify.
    let other = genkey();
    let other_pub: [u8; 32] = hex_decode(&other.ca_public).try_into().unwrap();
    assert!(verify_cert(&cert, &[other_pub], &network_id, &member_pubkey, now, 0).is_err());
}

#[test]
fn rootset_issued_by_yip_ca_verifies_in_yip_membership() {
    let key = genkey();

    let root1_pk = "44".repeat(32);
    let root2_pk = "55".repeat(32);
    let roots_file = std::env::temp_dir().join(format!("yip-ca-roots-{}.txt", std::process::id()));
    std::fs::write(
        &roots_file,
        format!("{root1_pk} 192.0.2.1:8080\n{root2_pk} [2001:db8::1]:9090\n"),
    )
    .expect("write roots file");

    let out = run(&[
        "sign-roots",
        "--roots",
        roots_file.to_str().unwrap(),
        "--version",
        "7",
        "--ca-private",
        &key.ca_private,
    ]);
    let _ = std::fs::remove_file(&roots_file);

    let bytes = hex_decode(out.trim());
    let rootset = RootSet::decode(&bytes).expect("emitted rootset decodes");
    assert_eq!(rootset.version, 7);
    assert_eq!(rootset.roots.len(), 2);

    let ca_pub: [u8; 32] = hex_decode(&key.ca_public).try_into().unwrap();
    assert!(rootset.verify_rootset(&[ca_pub]));
}

#[test]
fn genkey_piped_into_sign_cert_works() {
    // Run yip-ca genkey and capture its two-line output
    let genkey_output = run(&["genkey"]);

    // Extract ca_public from the output for verification
    let mut ca_public = None;
    for line in genkey_output.lines() {
        if let Some(v) = line.strip_prefix("ca_public=") {
            ca_public = Some(v.to_string());
        }
    }
    let ca_public = ca_public.expect("genkey printed ca_public=<hex>");

    // Prepare sign-cert arguments
    let member_hex = "aa".repeat(32);
    let member_sign_hex = "bb".repeat(32);
    let network_hex = "cc".repeat(16);

    // Spawn yip-ca sign-cert with stdin piped and capture its output
    let mut child = Command::new(env!("CARGO_BIN_EXE_yip-ca"))
        .args([
            "sign-cert",
            "--member",
            &member_hex,
            "--member-sign",
            &member_sign_hex,
            "--network",
            &network_hex,
            "--days",
            "30",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn yip-ca sign-cert");

    {
        let mut stdin = child.stdin.take().expect("failed to open stdin");
        stdin
            .write_all(genkey_output.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait for yip-ca sign-cert");
    assert!(
        output.status.success(),
        "yip-ca sign-cert exited with {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_hex = String::from_utf8(output.stdout)
        .expect("yip-ca stdout was not utf8")
        .trim()
        .to_string();
    let cert_bytes = hex_decode(&cert_hex);
    let cert = Cert::decode(&cert_bytes).expect("emitted cert decodes");

    let member_pubkey: [u8; 32] = hex_decode(&member_hex).try_into().unwrap();
    let member_sign_pubkey: [u8; 32] = hex_decode(&member_sign_hex).try_into().unwrap();
    let network_id: [u8; 16] = hex_decode(&network_hex).try_into().unwrap();
    let ca_pub: [u8; 32] = hex_decode(&ca_public).try_into().unwrap();

    // Verify the cert is well-formed
    assert_eq!(cert.version, 1);
    assert_eq!(cert.member_pubkey, member_pubkey);
    assert_eq!(cert.member_sign_pubkey, member_sign_pubkey);
    assert_eq!(cert.network_id, network_id);
    assert_eq!(cert.not_after - cert.not_before, 30 * 86400);

    // Verify the cert signature is valid
    let now = now_secs();
    assert_eq!(
        verify_cert(&cert, &[ca_pub], &network_id, &member_pubkey, now, 0),
        Ok(())
    );
}
