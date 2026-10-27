use frost_ed25519 as frost;
use yip_ca::threshold::dealer_generate;
use yip_ca::threshold::refresh::{proactive_refresh, repair_lost_share};
use yip_ca::threshold::threshold_sign_cert;

#[test]
fn test_proactive_refresh_preserves_group_key_and_signature_validity() {
    let threshold = 2;
    let max_signers = 3;
    let (pubkey_package, key_packages) = dealer_generate(threshold, max_signers).unwrap();

    let orig_vk = pubkey_package.verifying_key().serialize().unwrap();

    // Perform proactive refresh
    let refreshed_key_packages =
        proactive_refresh(&key_packages, threshold).expect("proactive refresh should succeed");

    assert_eq!(refreshed_key_packages.len(), 3);

    // Verify each refreshed key package still has min_signers == threshold
    for kp in refreshed_key_packages.values() {
        assert_eq!(*kp.min_signers(), threshold);
    }

    // Now test that the refreshed key packages can collaboratively sign a message
    // that verifies against the ORIGINAL group verifying key!
    let msg = b"Proactive Refresh Signature Verification Payload";
    let selected: Vec<_> = refreshed_key_packages
        .iter()
        .take(threshold as usize)
        .map(|(id, kp)| (*id, kp))
        .collect();

    let mut rng = rand::rngs::OsRng;
    let mut commitments_map = std::collections::BTreeMap::new();
    let mut signer_nonces = Vec::new();

    for (id, kp) in &selected {
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
        commitments_map.insert(*id, commitments);
        signer_nonces.push((*id, *kp, nonces));
    }

    let sig = threshold_sign_cert(msg, commitments_map, signer_nonces, &pubkey_package)
        .expect("signing with refreshed shares must succeed");

    let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&orig_vk.try_into().unwrap()).unwrap();
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig);
    assert!(ed_vk.verify_strict(msg, &ed_sig).is_ok());
}

#[test]
fn test_cve_2025_58359_guard_rejects_threshold_drift() {
    let threshold = 3;
    let max_signers = 5;
    let (_pubkey_package, key_packages) = dealer_generate(threshold, max_signers).unwrap();

    // Attempting to refresh with min_signers != active package threshold MUST fail
    let res = proactive_refresh(&key_packages, 2);
    assert!(
        res.is_err(),
        "refresh must reject differing threshold (CVE-2025-58359 defense)"
    );
}

#[test]
fn test_lost_share_repair() {
    let threshold = 2;
    let max_signers = 3;
    let (pubkey_package, key_packages) = dealer_generate(threshold, max_signers).unwrap();

    let id_lost = *key_packages.keys().next().unwrap();
    let original_lost_kp = key_packages[&id_lost].clone();

    // Reconstruct lost share using the other 2 surviving signers
    let helpers: Vec<_> = key_packages
        .iter()
        .filter(|(id, _)| **id != id_lost)
        .map(|(id, kp)| (*id, kp.clone()))
        .collect();

    let repaired_kp = repair_lost_share(id_lost, &helpers, &pubkey_package)
        .expect("lost share repair should succeed");

    assert_eq!(*repaired_kp.min_signers(), threshold);
    assert_eq!(
        repaired_kp.verifying_share(),
        original_lost_kp.verifying_share()
    );
}
