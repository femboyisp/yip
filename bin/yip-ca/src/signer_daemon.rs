use std::collections::BTreeMap;
use std::sync::Mutex;

use frost_ed25519 as frost;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::rpc::{NonceSlotId, QuorumRpcMessage, SignCertRequestPayload, SignCertResponsePayload};

/// Policy rules enforced independently by each signer before computing partial signatures.
#[derive(Clone, Debug)]
pub struct SignerPolicy {
    pub max_ttl_secs: u64,
    pub admin_provisioning_pubkey: Option<ed25519_dalek::VerifyingKey>,
    pub ipv4_network_mask: Option<(u32, u32)>,
}

impl Default for SignerPolicy {
    fn default() -> Self {
        Self {
            max_ttl_secs: 7 * 86_400, // 7 days max TTL
            admin_provisioning_pubkey: None,
            ipv4_network_mask: None,
        }
    }
}

/// Ephemeral, in-memory vault for single-use FROST signing nonces.
/// Bound to a CSPRNG-generated `boot_epoch_id` to guarantee rollback immunity.
pub struct EphemeralNonceVault {
    boot_epoch_id: u128,
    next_gen_idx: u64,
    active_nonces: BTreeMap<NonceSlotId, frost::round1::SigningNonces>,
}

impl EphemeralNonceVault {
    /// Creates a fresh vault instance with a unique 128-bit boot epoch ID.
    pub fn new() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self {
            boot_epoch_id: u128::from_le_bytes(bytes),
            next_gen_idx: 1,
            active_nonces: BTreeMap::new(),
        }
    }

    /// The 128-bit boot epoch identifier for this vault instance.
    pub fn boot_epoch_id(&self) -> u128 {
        self.boot_epoch_id
    }

    /// Generates `count` fresh nonces and returns public commitments for the Coordinator.
    pub fn preprocess_batch(
        &mut self,
        signing_share: &frost::keys::SigningShare,
        count: usize,
    ) -> Vec<(NonceSlotId, frost::round1::SigningCommitments)> {
        let mut out = Vec::with_capacity(count);
        let mut rng = OsRng;
        for _ in 0..count {
            let seq = self.next_gen_idx;
            self.next_gen_idx = self
                .next_gen_idx
                .checked_add(1)
                .expect("nonce counter overflow");
            let (nonces, commitments) = frost::round1::commit(signing_share, &mut rng);
            let slot = NonceSlotId {
                boot_epoch_id: self.boot_epoch_id,
                sequence_idx: seq,
            };
            self.active_nonces.insert(slot, nonces);
            out.push((slot, commitments));
        }
        out
    }

    /// Atomically removes and returns the secret SigningNonces for `slot`.
    /// Enforces the single-use invariant: once taken, subsequent calls return None.
    pub fn take_once(&mut self, slot: &NonceSlotId) -> Option<frost::round1::SigningNonces> {
        if slot.boot_epoch_id != self.boot_epoch_id {
            return None;
        }
        self.active_nonces.remove(slot)
    }

    /// Count of active unconsumed nonces.
    pub fn len(&self) -> usize {
        self.active_nonces.len()
    }

    /// Checks if the vault is empty.
    pub fn is_empty(&self) -> bool {
        self.active_nonces.is_empty()
    }
}

impl Default for EphemeralNonceVault {
    fn default() -> Self {
        Self::new()
    }
}

/// Signer daemon state holding the KeyPackage share and policy.
pub struct SignerState {
    pub key_package: frost::keys::KeyPackage,
    pub pubkey_package: frost::keys::PublicKeyPackage,
    pub policy: SignerPolicy,
    pub vault: Mutex<EphemeralNonceVault>,
}

impl SignerState {
    pub fn new(
        key_package: frost::keys::KeyPackage,
        pubkey_package: frost::keys::PublicKeyPackage,
        policy: SignerPolicy,
    ) -> Self {
        Self {
            key_package,
            pubkey_package,
            policy,
            vault: Mutex::new(EphemeralNonceVault::new()),
        }
    }

    /// Handles a sign request from the Coordinator: validates payload and policy,
    /// atomically consumes the nonce, generates a replenishment commitment, and emits the share.
    pub fn handle_sign_request(&self, req: &SignCertRequestPayload) -> QuorumRpcMessage {
        let signer_id = *self.key_package.identifier();
        let session_id = req.session_id;

        // 1. Verify SigningPackage payload matches canonical CertTbs
        let expected_msg = req.cert_tbs.to_canonical_bytes();
        if req.signing_package.message() != expected_msg.as_slice() {
            return QuorumRpcMessage::SignCertReject {
                session_id,
                signer_id,
                reason: "SigningPackage payload mismatch with CertTbs".into(),
            };
        }

        // 2. Policy bounds checks
        if req.cert_tbs.expires_at_unix <= req.cert_tbs.issued_at_unix
            || (req.cert_tbs.expires_at_unix - req.cert_tbs.issued_at_unix)
                > self.policy.max_ttl_secs
        {
            return QuorumRpcMessage::SignCertReject {
                session_id,
                signer_id,
                reason: "Certificate TTL exceeds signer policy maximum".into(),
            };
        }

        // 3. Atomically consume the one-time nonce under mutex lock and generate 1 replenishment
        let (nonces, replenish) = {
            let mut vault = match self.vault.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(n) = vault.take_once(&req.slot_id) else {
                return QuorumRpcMessage::SignCertReject {
                    session_id,
                    signer_id,
                    reason: "NonceSlotId not found, already consumed, or stale boot epoch".into(),
                };
            };
            let rep = vault
                .preprocess_batch(self.key_package.signing_share(), 1)
                .pop();
            (n, rep)
        };

        // 4. Compute FROST Round 2 partial signature; nonces auto-zeroized on drop
        match frost::round2::sign(&req.signing_package, &nonces, &self.key_package) {
            Ok(signature_share) => {
                QuorumRpcMessage::SignCertResponse(Box::new(SignCertResponsePayload {
                    session_id,
                    signer_id,
                    signature_share,
                    replenish_commitment: replenish,
                }))
            }
            Err(e) => QuorumRpcMessage::SignCertReject {
                session_id,
                signer_id,
                reason: format!("FROST round2 sign error: {e}"),
            },
        }
    }
}
