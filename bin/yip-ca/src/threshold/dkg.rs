use crate::threshold::ThresholdError;
use frost::keys::dkg::{round1, round2};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use frost_ed25519 as frost;
use std::collections::BTreeMap;

/// Step 1 of DKG: generate ephemeral polynomial and round 1 broadcast package.
pub fn dkg_part1(
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
) -> Result<(round1::SecretPackage, round1::Package), ThresholdError> {
    if min_signers == 0 || min_signers > max_signers {
        return Err(ThresholdError::InvalidParams(
            "min_signers must be >= 1 and <= max_signers",
        ));
    }
    let rng = rand::rngs::OsRng;
    let (secret_package, package) =
        frost::keys::dkg::part1(identifier, max_signers, min_signers, rng)?;
    Ok((secret_package, package))
}

/// Step 2 of DKG: compute secret share packages for all other participants.
pub fn dkg_part2(
    secret_package: round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), ThresholdError> {
    let (secret_package, packages) = frost::keys::dkg::part2(secret_package, round1_packages)?;
    Ok((secret_package, packages))
}

/// Step 3 of DKG: verify received shares and assemble the final KeyPackage and PublicKeyPackage.
pub fn dkg_part3(
    round2_secret_package: &round2::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
    round2_packages: &BTreeMap<Identifier, round2::Package>,
) -> Result<(KeyPackage, PublicKeyPackage), ThresholdError> {
    let (key_package, pubkey_package) =
        frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
    Ok((key_package, pubkey_package))
}
