use yip_ca::threshold::{dealer_generate, threshold_sign_cert};
use yip_membership::cert::{cert_signing_body, verify_cert, Cert};

#[test]
fn test_dealer_generate_validity() {
    let threshold = 3;
    let max_signers = 5;
    let (pubkey_package, key_packages) =
        dealer_generate(threshold, max_signers).expect("dealer generation should succeed");

    assert_eq!(key_packages.len(), 5);
    // Verifying key should serialize to a valid 32-byte Ed25519 public key
    let vk_bytes = pubkey_package.verifying_key().serialize().unwrap();
    assert_eq!(vk_bytes.len(), 32);

    // Each key package should have min_signers == threshold
    for kp in key_packages.values() {
        assert_eq!(*kp.min_signers(), threshold);
    }
}

#[test]
fn test_threshold_cert_verification_compatibility() {
    let threshold = 3;
    let max_signers = 5;
    let (pubkey_package, key_packages) = dealer_generate(threshold, max_signers).unwrap();

    let root_pk_vec = pubkey_package.verifying_key().serialize().unwrap();
    let root_pk: [u8; 32] = root_pk_vec.try_into().unwrap();

    let member_pubkey = [0x42u8; 32];
    let member_sign_pubkey = [0x43u8; 32];
    let network_id = [0x11u8; 16];
    let now = 1_700_000_000u64;

    let mut cert = Cert {
        version: 1,
        member_pubkey,
        member_sign_pubkey,
        network_id,
        not_before: now - 60,
        not_after: now + 86400,
        tags: vec![(1, b"prod".to_vec())],
        ca_sig: [0u8; 64],
    };

    let tbs = cert_signing_body(&cert);

    // Pick 3 signers out of 5
    let selected: Vec<_> = key_packages
        .iter()
        .take(3)
        .map(|(id, kp)| (*id, kp))
        .collect();

    let mut rng = rand::rngs::OsRng;
    let mut signer_nonces = Vec::new();
    let mut commitments_map = std::collections::BTreeMap::new();

    for (id, kp) in &selected {
        let (nonces, commitments) = frost_ed25519::round1::commit(kp.signing_share(), &mut rng);
        commitments_map.insert(*id, commitments);
        signer_nonces.push((*id, *kp, nonces));
    }

    let sig = threshold_sign_cert(&tbs, commitments_map, signer_nonces, &pubkey_package)
        .expect("threshold signing should succeed");

    cert.ca_sig = sig;

    // Verify against standard yip_membership::cert::verify_cert
    let res = verify_cert(&cert, &[root_pk], &network_id, &member_pubkey, now, 0);
    assert_eq!(
        res,
        Ok(()),
        "threshold signature must verify under standard verify_cert!"
    );
}
