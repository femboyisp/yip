use std::collections::BTreeMap;

use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use frost_ed25519 as frost;

use crate::threshold::ThresholdError;

/// Performs a proactive share refresh across all signers while preserving the exact same
/// group verifying key.
///
/// **CVE-2025-58359 Hardening**: Explicitly enforces that `requested_threshold == current.min_signers()`.
/// Any change to the threshold MUST be performed through a full resharing/DKG ceremony, not an in-place refresh.
pub fn proactive_refresh(
    current_key_packages: &BTreeMap<Identifier, KeyPackage>,
    requested_threshold: u16,
) -> Result<BTreeMap<Identifier, KeyPackage>, ThresholdError> {
    if current_key_packages.is_empty() {
        return Err(ThresholdError::InvalidParams("empty key package set"));
    }

    let first_kp = current_key_packages.values().next().unwrap();
    if requested_threshold != *first_kp.min_signers() {
        return Err(ThresholdError::InvalidParams(
            "requested threshold does not match active key package threshold (CVE-2025-58359 guard)",
        ));
    }

    let identifiers: Vec<Identifier> = current_key_packages.keys().copied().collect();
    let mut verifying_shares = BTreeMap::new();
    for (id, kp) in current_key_packages {
        verifying_shares.insert(*id, *kp.verifying_share());
    }

    let pub_key_package = PublicKeyPackage::new(
        verifying_shares,
        *first_kp.verifying_key(),
        Some(requested_threshold),
    );

    let mut rng = rand::rngs::OsRng;
    let (refreshing_shares, _) =
        frost::keys::refresh::compute_refreshing_shares(pub_key_package, &identifiers, &mut rng)?;

    let mut refreshed_key_packages = BTreeMap::new();
    for (id, secret_share) in identifiers.into_iter().zip(refreshing_shares) {
        let current_kp = &current_key_packages[&id];
        let refreshed_kp = frost::keys::refresh::refresh_share(secret_share, current_kp)?;
        refreshed_key_packages.insert(id, refreshed_kp);
    }

    Ok(refreshed_key_packages)
}

/// Collaborative lost share reconstruction: allows a threshold subset of surviving signers
/// to reconstruct a lost participant's `KeyPackage` without ever reconstructing the group secret.
pub fn repair_lost_share(
    lost_participant: Identifier,
    helpers: &[(Identifier, KeyPackage)],
    pubkey_package: &PublicKeyPackage,
) -> Result<KeyPackage, ThresholdError> {
    let helper_ids: Vec<Identifier> = helpers.iter().map(|(id, _)| *id).collect();
    let mut rng = rand::rngs::OsRng;

    // Part 1: Each helper computes delta shares for all helpers
    let mut deltas_by_recipient: BTreeMap<Identifier, Vec<frost::keys::repairable::Delta>> =
        BTreeMap::new();

    for (_id, kp) in helpers {
        let deltas = frost::keys::repairable::repair_share_part1::<frost_ed25519::Ed25519Sha512, _>(
            &helper_ids,
            kp,
            &mut rng,
            lost_participant,
        )?;
        for (recipient, delta) in deltas {
            deltas_by_recipient
                .entry(recipient)
                .or_default()
                .push(delta);
        }
    }

    // Part 2: Each helper sums its received deltas to produce a sigma
    let mut sigmas = Vec::new();
    for id in &helper_ids {
        let deltas = deltas_by_recipient
            .remove(id)
            .ok_or(ThresholdError::InvalidParams("missing helper delta"))?;
        let sigma = frost::keys::repairable::repair_share_part2(&deltas);
        sigmas.push(sigma);
    }

    // Part 3: The recovering participant combines sigmas into its KeyPackage
    let repaired_kp =
        frost::keys::repairable::repair_share_part3(&sigmas, lost_participant, pubkey_package)?;

    Ok(repaired_kp)
}
