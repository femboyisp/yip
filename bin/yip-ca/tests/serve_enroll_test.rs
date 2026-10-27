use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::RngCore;
use yip_ca::enroll::enroll_node;
use yip_ca::rpc::EnrollmentCredential;
use yip_ca::serve::{run_coordinator, run_signer};
use yip_ca::signer_daemon::SignerPolicy;
use yip_ca::threshold::dealer_generate;
use yip_membership::cert::verify_cert;

#[tokio::test]
async fn test_serve_and_enroll_loopback() {
    let threshold = 2;
    let max_signers = 3;
    let (pubkey_package, key_packages) = dealer_generate(threshold, max_signers).unwrap();
    let root_pk: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();

    let coord_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let coord_addr: SocketAddr = coord_listener.local_addr().unwrap();

    // Spawn Coordinator daemon
    let coord_pk = pubkey_package.clone();
    tokio::spawn(async move {
        run_coordinator(coord_listener, threshold as usize, coord_pk)
            .await
            .unwrap();
    });

    // Spawn 2 Signer daemons (meets the threshold of 2)
    let signers: Vec<_> = key_packages.values().take(2).cloned().collect();
    for kp in signers {
        let s_pk = pubkey_package.clone();
        tokio::spawn(async move {
            run_signer(coord_addr, kp, s_pk, SignerPolicy::default())
                .await
                .unwrap();
        });
    }

    // Give daemons a moment to connect and register commitments
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Now run client enroll
    let mut rng = rand::rngs::OsRng;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let client_signing_key = SigningKey::from_bytes(&secret_bytes);
    let member_pubkey = client_signing_key.verifying_key().to_bytes();
    let member_sign_pubkey = member_pubkey;
    let network_id = [0x42u8; 16];

    let credential = EnrollmentCredential::RenewalCert {
        existing_cert_bytes: vec![1, 2, 3],
        renewal_signature: [0u8; 64],
    };

    let cert = enroll_node(
        coord_addr,
        &client_signing_key,
        member_pubkey,
        member_sign_pubkey,
        network_id,
        credential,
    )
    .await
    .expect("enrollment over loopback must succeed");

    assert_eq!(cert.member_pubkey, member_pubkey);
    assert_eq!(cert.network_id, network_id);

    // Verify cert against standard RootSet / verify_cert
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let res = verify_cert(&cert, &[root_pk], &network_id, &member_pubkey, now, 10);
    assert_eq!(
        res,
        Ok(()),
        "enrolled cert must pass standard yip_membership verification!"
    );
}
