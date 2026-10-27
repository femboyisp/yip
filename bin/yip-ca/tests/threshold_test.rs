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

#[test]
fn test_interactive_dkg_and_signing() {
    use yip_ca::threshold::dkg::{dkg_part1, dkg_part2, dkg_part3};

    let max_signers = 3;
    let min_signers = 2;

    let id1 = frost_ed25519::Identifier::try_from(1u16).unwrap();
    let id2 = frost_ed25519::Identifier::try_from(2u16).unwrap();
    let id3 = frost_ed25519::Identifier::try_from(3u16).unwrap();
    let ids = vec![id1, id2, id3];

    // DKG Round 1
    let mut round1_secrets = std::collections::BTreeMap::new();
    let mut round1_packages = std::collections::BTreeMap::new();

    for id in &ids {
        let (sec, pkg) = dkg_part1(*id, max_signers, min_signers).unwrap();
        round1_secrets.insert(*id, sec);
        round1_packages.insert(*id, pkg);
    }

    // DKG Round 2
    let mut round2_secrets = std::collections::BTreeMap::new();
    let mut round2_packages_by_recipient: std::collections::BTreeMap<
        frost_ed25519::Identifier,
        std::collections::BTreeMap<
            frost_ed25519::Identifier,
            frost_ed25519::keys::dkg::round2::Package,
        >,
    > = std::collections::BTreeMap::new();

    for id in &ids {
        let sec = round1_secrets.remove(id).unwrap();
        let other_r1: std::collections::BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let (r2_sec, r2_pkgs) = dkg_part2(sec, &other_r1).unwrap();
        round2_secrets.insert(*id, r2_sec);
        for (recipient, pkg) in r2_pkgs {
            round2_packages_by_recipient
                .entry(recipient)
                .or_default()
                .insert(*id, pkg);
        }
    }

    // DKG Round 3
    let mut key_packages = std::collections::BTreeMap::new();
    let mut pubkey_package = None;

    for id in &ids {
        let r2_sec = round2_secrets.remove(id).unwrap();
        let r2_received = round2_packages_by_recipient.remove(id).unwrap();
        let other_r1: std::collections::BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let (kp, pk_pkg) = dkg_part3(&r2_sec, &other_r1, &r2_received).unwrap();
        key_packages.insert(*id, kp);
        pubkey_package = Some(pk_pkg);
    }

    let pubkey_package = pubkey_package.unwrap();
    assert_eq!(key_packages.len(), 3);

    // Verify sign with threshold 2 out of 3
    let selected: Vec<_> = key_packages
        .iter()
        .take(2)
        .map(|(id, kp)| (*id, kp))
        .collect();
    let mut rng = rand::rngs::OsRng;
    let mut commitments_map = std::collections::BTreeMap::new();
    let mut signer_nonces = Vec::new();

    for (id, kp) in &selected {
        let (nonces, commitments) = frost_ed25519::round1::commit(kp.signing_share(), &mut rng);
        commitments_map.insert(*id, commitments);
        signer_nonces.push((*id, *kp, nonces));
    }

    let msg = b"DKG-issued root authorization test";
    let sig = threshold_sign_cert(msg, commitments_map, signer_nonces, &pubkey_package)
        .expect("DKG sign should succeed");

    assert_eq!(sig.len(), 64);
}
