use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use yip_ca::serve::{run_coordinator, run_signer};
use yip_ca::signer_daemon::SignerPolicy;
use yip_ca::threshold::dealer_generate;
use yip_membership::cert::verify_cert;
use yip_membership::{Cert, RootSet};
use yipd::control::{dispatch_cmd, ControlCmd, ControlResponse};
use yipd::membership::Membership;
use yipd::peer_manager::PeerManager;

#[test]
fn test_cert_status_and_renewal_flow() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let threshold = 2;
    let max_signers = 3;
    let (pubkey_package, key_packages) = dealer_generate(threshold, max_signers).unwrap();
    let root_pk: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();

    let (coord_addr, _handles) = rt.block_on(async {
        let coord_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let coord_addr: SocketAddr = coord_listener.local_addr().unwrap();

        let coord_pk = pubkey_package.clone();
        let c_handle = tokio::spawn(async move {
            let _ = run_coordinator(coord_listener, threshold as usize, coord_pk).await;
        });

        let mut signer_handles = Vec::new();
        let signers: Vec<_> = key_packages.values().take(2).cloned().collect();
        for kp in signers {
            let s_pk = pubkey_package.clone();
            let h = tokio::spawn(async move {
                if let Err(e) = run_signer(coord_addr, kp, s_pk, SignerPolicy::default()).await {
                    eprintln!("run_signer error: {e}");
                } else {
                    eprintln!("run_signer exited cleanly");
                }
            });
            signer_handles.push(h);
        }

        tokio::time::sleep(Duration::from_millis(1000)).await;
        (coord_addr, (c_handle, signer_handles))
    });

    // Create client node keypair
    let client_priv_bytes = [0x77u8; 32];
    let client_signing_key = SigningKey::from_bytes(&client_priv_bytes);
    let member_pubkey = client_signing_key.verifying_key().to_bytes();
    let member_sign_pubkey = member_pubkey;
    let network_id = [0x55u8; 16];

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Initial short-lived cert: valid for 100 seconds (not_before = now, not_after = now + 100)
    let initial_cert = Cert {
        version: 1,
        member_pubkey,
        member_sign_pubkey,
        network_id,
        not_before: now,
        not_after: now + 100,
        tags: Vec::new(),
        ca_sig: [0u8; 64],
    };

    let roots = RootSet {
        version: 1,
        roots: vec![(root_pk, "127.0.0.1:9000".parse().unwrap())],
        ca_sig: [0u8; 64],
    };

    let membership = Membership::new(
        vec![root_pk],
        network_id,
        initial_cert,
        client_priv_bytes,
        roots,
        Vec::new(),
    );

    let mut pm = PeerManager::new(
        client_priv_bytes,
        member_pubkey,
        &[],
        yipd::mode::TunnelMode::L3Tun,
        None,
        Some(membership),
        false,
    );
    pm.set_threshold_ca_server(Some(coord_addr));

    let start_time = Instant::now();

    // 1. Test ControlCmd::CertStatus
    let resp = dispatch_cmd(&mut pm, ControlCmd::CertStatus, "yip0", start_time);
    match resp {
        ControlResponse::CertStatus {
            ok,
            not_before,
            not_after,
            ttl_remaining_secs,
            renewal_threshold_secs,
            is_threshold_ca,
        } => {
            assert!(ok);
            assert_eq!(not_before, now);
            assert_eq!(not_after, now + 100);
            assert!(ttl_remaining_secs <= 100);
            assert_eq!(renewal_threshold_secs, 70); // 70% of 100s TTL
            assert!(is_threshold_ca);
        }
        other => panic!("expected CertStatus response, got: {other:?}"),
    }

    // 2. Test check_cert_rotation logic (70% rule)
    assert_eq!(
        pm.check_cert_rotation(now + 60),
        Some(false),
        "60% elapsed must not trigger renewal"
    );
    assert_eq!(
        pm.check_cert_rotation(now + 70),
        Some(true),
        "70% elapsed must trigger renewal"
    );
    assert_eq!(
        pm.check_cert_rotation(now + 90),
        Some(true),
        "90% elapsed must trigger renewal"
    );

    // 3. Test ControlCmd::CertRenew (triggers threshold online renewal)
    let renew_resp = dispatch_cmd(&mut pm, ControlCmd::CertRenew, "yip0", start_time);
    match renew_resp {
        ControlResponse::CertRenew {
            ok,
            renewed,
            new_not_after,
            ..
        } => {
            assert!(ok);
            assert!(renewed);
            assert!(new_not_after.is_some());
            let updated_not_after = new_not_after.unwrap();
            assert!(
                updated_not_after > now + 100,
                "renewed cert must have extended validity"
            );
        }
        other => panic!("expected CertRenew response, got: {other:?}"),
    }

    // 4. Verify updated cert passes RootSet verification against root_pk
    let renewed_cert = pm.membership().unwrap().own_cert();
    assert_eq!(renewed_cert.member_pubkey, member_pubkey);
    let verify_res = verify_cert(
        renewed_cert,
        &[root_pk],
        &network_id,
        &member_pubkey,
        now,
        10,
    );
    assert_eq!(
        verify_res,
        Ok(()),
        "renewed cert must verify against threshold group public key!"
    );
}
