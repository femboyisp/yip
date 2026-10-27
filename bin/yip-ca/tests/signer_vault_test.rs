use yip_ca::rpc::{CertTbs, EnrollmentCredential, QuorumRpcMessage, SignCertRequestPayload};
use yip_ca::signer_daemon::{EphemeralNonceVault, SignerPolicy, SignerState};
use yip_ca::threshold::dealer_generate;

#[test]
fn test_ephemeral_nonce_vault_single_use() {
    let (_pubkey_package, key_packages) = dealer_generate(2, 3).unwrap();
    let kp = key_packages.values().next().unwrap();

    let mut vault = EphemeralNonceVault::new();
    let batch = vault.preprocess_batch(kp.signing_share(), 5);
    assert_eq!(batch.len(), 5);

    let (slot_0, _comm_0) = &batch[0];

    // First take_once must succeed
    let nonce_opt = vault.take_once(slot_0);
    assert!(nonce_opt.is_some(), "first nonce take_once must succeed");

    // Second take_once of the same slot MUST fail (single-use invariant)
    let second_opt = vault.take_once(slot_0);
    assert!(
        second_opt.is_none(),
        "re-taking consumed nonce must return None!"
    );
}

#[test]
fn test_ephemeral_nonce_vault_epoch_rejection() {
    let (_pubkey_package, key_packages) = dealer_generate(2, 3).unwrap();
    let kp = key_packages.values().next().unwrap();

    let mut vault1 = EphemeralNonceVault::new();
    let batch = vault1.preprocess_batch(kp.signing_share(), 2);
    let (slot, _) = batch[0];

    // Simulate reboot: new vault instance with different boot_epoch_id
    let mut vault2 = EphemeralNonceVault::new();
    assert_ne!(vault1.boot_epoch_id(), vault2.boot_epoch_id());

    // Presenting slot from vault1's epoch to vault2 must be rejected
    let take_res = vault2.take_once(&slot);
    assert!(
        take_res.is_none(),
        "slot from old boot_epoch_id must be rejected"
    );
}

#[test]
fn test_signer_state_handle_sign_request() {
    let (pubkey_package, key_packages) = dealer_generate(2, 3).unwrap();
    let mut kp_iter = key_packages.values();
    let kp = kp_iter.next().unwrap().clone();
    let kp2 = kp_iter.next().unwrap().clone();

    let signer = SignerState::new(kp.clone(), pubkey_package.clone(), SignerPolicy::default());

    // Preprocess 1 commitment for signer 1
    let (slot, commitments) = {
        let mut vault = signer.vault.lock().unwrap();
        vault.preprocess_batch(kp.signing_share(), 1).pop().unwrap()
    };

    // Preprocess 1 commitment for signer 2 (to satisfy threshold of 2)
    let mut rng = rand::rngs::OsRng;
    let (_nonces2, commitments2) = frost_ed25519::round1::commit(kp2.signing_share(), &mut rng);

    let cert_tbs = CertTbs {
        version: 1,
        member_pubkey: [0x30; 32],
        member_sign_pubkey: [0x40; 32],
        network_id: [0x10; 16],
        not_before: 1_700_000_000,
        not_after: 1_700_086_400,
        tags: Vec::new(),
    };

    let msg = cert_tbs.to_canonical_bytes();
    let mut commitments_map = std::collections::BTreeMap::new();
    commitments_map.insert(*kp.identifier(), commitments);
    commitments_map.insert(*kp2.identifier(), commitments2);
    let signing_package = frost_ed25519::SigningPackage::new(commitments_map, &msg);

    let req = SignCertRequestPayload {
        session_id: 100,
        slot_id: slot,
        signing_package,
        cert_tbs,
        credential: EnrollmentCredential::RenewalCert {
            existing_cert_bytes: vec![1, 2, 3],
            renewal_signature: [0u8; 64],
        },
        challenge_nonce: [0u8; 32],
        pop_signature: [0u8; 64],
    };

    let resp = signer.handle_sign_request(&req);
    match resp {
        QuorumRpcMessage::SignCertResponse(payload) => {
            assert_eq!(payload.session_id, 100);
            assert_eq!(payload.signer_id, *kp.identifier());
            assert!(payload.replenish_commitment.is_some());
        }
        QuorumRpcMessage::SignCertReject { reason, .. } => {
            panic!("sign request rejected unexpectedly: {reason}");
        }
        _ => panic!("unexpected response variant"),
    }
}
