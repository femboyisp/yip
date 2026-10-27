use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use frost_ed25519 as frost;
pub mod dkg;
pub mod refresh;

use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThresholdError {
    #[error("FROST error: {0}")]
    Frost(#[from] frost::Error),
    #[error("Invalid parameters: {0}")]
    InvalidParams(&'static str),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Generates a threshold key set using a trusted dealer.
pub fn dealer_generate(
    threshold: u16,
    max_signers: u16,
) -> Result<(PublicKeyPackage, BTreeMap<Identifier, KeyPackage>), ThresholdError> {
    if threshold == 0 || threshold > max_signers {
        return Err(ThresholdError::InvalidParams(
            "threshold must be >= 1 and <= max_signers",
        ));
    }

    let rng = rand::rngs::OsRng;
    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer(max_signers, threshold, IdentifierList::Default, rng)?;

    let mut key_packages = BTreeMap::new();
    for (id, secret_share) in shares {
        let key_package = KeyPackage::try_from(secret_share)?;
        key_packages.insert(id, key_package);
    }

    Ok((pubkey_package, key_packages))
}

/// Executes threshold signing over a canonical message buffer using the provided signers.
/// Returns a standard 64-byte Ed25519 signature.
pub fn threshold_sign_cert(
    tbs: &[u8],
    commitments_map: BTreeMap<Identifier, SigningCommitments>,
    signers: Vec<(Identifier, &KeyPackage, SigningNonces)>,
    pubkey_package: &PublicKeyPackage,
) -> Result<[u8; 64], ThresholdError> {
    let signing_package = SigningPackage::new(commitments_map, tbs);

    let mut signature_shares = BTreeMap::new();
    for (id, kp, nonces) in signers {
        let share: SignatureShare = frost::round2::sign(&signing_package, &nonces, kp)?;
        signature_shares.insert(id, share);
    }

    let signature = frost::aggregate(&signing_package, &signature_shares, pubkey_package)?;
    let sig_bytes = signature.serialize()?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ThresholdError::Serialization("expected 64-byte signature".into()))?;

    Ok(sig_array)
}
