use frost_ed25519 as frost;
use yip_ca::roast_coordinator::RoastCoordinator;
use yip_ca::rpc::NonceSlotId;
use yip_ca::threshold::dealer_generate;

#[test]
fn test_roast_coordinator_byzantine_resilience() {
    let threshold = 3;
    let max_signers = 5;
    let (pubkey_package, key_packages) = dealer_generate(threshold, max_signers).unwrap();

    let ids: Vec<_> = key_packages.keys().copied().collect();
    let msg = b"ROAST Byzantine Resilience Verification Payload";

    let mut coordinator =
        RoastCoordinator::new(threshold as usize, pubkey_package.clone(), msg.to_vec());

    let mut rng = rand::rngs::OsRng;
    let mut signer_nonces = std::collections::BTreeMap::new();

    // Register 2 preprocessed commitments per signer
    for (i, id) in ids.iter().enumerate() {
        let kp = &key_packages[id];
        let mut comms = Vec::new();
        for seq in 1..=2 {
            let slot = NonceSlotId {
                boot_epoch_id: 1,
                sequence_idx: (i as u64 * 10) + seq,
            };
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            signer_nonces.insert((slot, *id), nonces);
            comms.push((slot, commitments));
        }
        coordinator.register_commitments(*id, comms);
    }

    // Spawn first session S1: should pick 3 signers (say P1, P2, P3)
    let (s1_id, pkg1, slots1) = coordinator
        .try_spawn_session()
        .expect("should spawn initial session S1");
    assert_eq!(slots1.len(), 3);

    let s1_signers: Vec<_> = slots1.keys().copied().collect();
    let p1 = s1_signers[0];
    let _p2 = s1_signers[1];
    let _p3 = s1_signers[2];

    // P1 replies honestly
    let nonces1 = signer_nonces.remove(&(slots1[&p1], p1)).unwrap();
    let share1 = frost::round2::sign(&pkg1, &nonces1, &key_packages[&p1]).unwrap();
    let res1 = coordinator.receive_share(s1_id, p1, share1, None).unwrap();
    assert!(res1.is_none(), "1 of 3 shares cannot finish signing");

    // P2 and P3 are Byzantine / unresponsive in S1.
    // Meanwhile, signers P4 and P5 are idle and available, plus P1 was returned to responsive pool!
    // Now {P1, P4, P5} are responsive (3 signers), so coordinator can spawn session S2!
    let (s2_id, pkg2, slots2) = coordinator.try_spawn_session().expect(
        "ROAST should spawn parallel session S2 with {P1, P4, P5} without waiting on stalled P2/P3",
    );
    assert_eq!(slots2.len(), 3);

    // All 3 signers in S2 reply honestly
    let mut final_sig = None;
    for (id, slot) in slots2 {
        let nonces = signer_nonces.remove(&(slot, id)).unwrap();
        let share = frost::round2::sign(&pkg2, &nonces, &key_packages[&id]).unwrap();
        if let Some(sig) = coordinator.receive_share(s2_id, id, share, None).unwrap() {
            final_sig = Some(sig);
        }
    }

    // Verify S2 completed successfully
    assert!(
        final_sig.is_some(),
        "S2 must complete signature aggregation"
    );
    let sig_bytes = final_sig.unwrap().serialize().unwrap();
    assert_eq!(sig_bytes.len(), 64);

    // Verify against pubkey_package verifying key
    let vk = pubkey_package.verifying_key();
    let ed_vk =
        ed25519_dalek::VerifyingKey::from_bytes(&vk.serialize().unwrap().try_into().unwrap())
            .unwrap();
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
    assert!(ed_vk.verify_strict(msg, &ed_sig).is_ok());
}
