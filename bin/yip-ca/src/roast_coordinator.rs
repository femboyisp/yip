use std::collections::{BTreeMap, BTreeSet, VecDeque};

use frost_ed25519 as frost;

use crate::rpc::NonceSlotId;

/// Active concurrent FROST signing session.
pub struct RoastSession {
    pub session_id: u128,
    pub participants: BTreeSet<frost::Identifier>,
    pub signing_package: frost::SigningPackage,
    pub collected_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
}

/// ROAST Coordinator (Ruffing et al., CCS 2022) wrapping preprocessed FROST(Ed25519, SHA-512).
/// Automatically spawns parallel sessions with available signers so up to n-t stalling or
/// malicious signers cannot delay certificate issuance.
pub struct RoastCoordinator {
    pub threshold: usize,
    pub pubkey_package: frost::keys::PublicKeyPackage,
    pub message: Vec<u8>,
    /// Signers currently available (not busy in an in-flight session).
    pub responsive_signers: BTreeSet<frost::Identifier>,
    /// Preprocessed commitments per signer.
    pub commitment_queues:
        BTreeMap<frost::Identifier, VecDeque<(NonceSlotId, frost::round1::SigningCommitments)>>,
    /// Active concurrent sessions.
    pub active_sessions: BTreeMap<u128, RoastSession>,
    /// Maps a busy signer to the session_id it is currently serving.
    pub signer_to_session: BTreeMap<frost::Identifier, u128>,
    /// Malicious signers detected via verify_signature_share failure.
    pub banished_signers: BTreeSet<frost::Identifier>,
    next_session_id: u128,
}

impl RoastCoordinator {
    /// Creates a fresh ROAST coordinator for a target message buffer.
    pub fn new(
        threshold: usize,
        pubkey_package: frost::keys::PublicKeyPackage,
        message: Vec<u8>,
    ) -> Self {
        Self {
            threshold,
            pubkey_package,
            message,
            responsive_signers: BTreeSet::new(),
            commitment_queues: BTreeMap::new(),
            active_sessions: BTreeMap::new(),
            signer_to_session: BTreeMap::new(),
            banished_signers: BTreeSet::new(),
            next_session_id: 1,
        }
    }

    /// Registers a batch of preprocessed commitments from a signer and marks it responsive.
    pub fn register_commitments(
        &mut self,
        signer_id: frost::Identifier,
        commitments: Vec<(NonceSlotId, frost::round1::SigningCommitments)>,
    ) {
        if self.banished_signers.contains(&signer_id) {
            return;
        }
        let queue = self.commitment_queues.entry(signer_id).or_default();
        queue.extend(commitments);
        if !self.signer_to_session.contains_key(&signer_id) {
            self.responsive_signers.insert(signer_id);
        }
    }

    /// Attempts to spawn a new parallel FROST session if `responsive_signers` has at least `threshold`
    /// signers with available preprocessed commitments.
    pub fn try_spawn_session(
        &mut self,
    ) -> Option<(
        u128,
        frost::SigningPackage,
        BTreeMap<frost::Identifier, NonceSlotId>,
    )> {
        let eligible: Vec<frost::Identifier> = self
            .responsive_signers
            .iter()
            .copied()
            .filter(|id| {
                !self.banished_signers.contains(id)
                    && self
                        .commitment_queues
                        .get(id)
                        .is_some_and(|q| !q.is_empty())
            })
            .take(self.threshold)
            .collect();

        if eligible.len() < self.threshold {
            return None;
        }

        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.checked_add(1).unwrap();

        let mut commitments_map = BTreeMap::new();
        let mut slot_map = BTreeMap::new();
        let mut participants = BTreeSet::new();

        for id in eligible {
            self.responsive_signers.remove(&id);
            self.signer_to_session.insert(id, session_id);
            let (slot_id, comm) = self
                .commitment_queues
                .get_mut(&id)
                .expect("queue exists")
                .pop_front()
                .expect("queue not empty");
            commitments_map.insert(id, comm);
            slot_map.insert(id, slot_id);
            participants.insert(id);
        }

        let signing_package = frost::SigningPackage::new(commitments_map, &self.message);

        self.active_sessions.insert(
            session_id,
            RoastSession {
                session_id,
                participants,
                signing_package: signing_package.clone(),
                collected_shares: BTreeMap::new(),
            },
        );

        Some((session_id, signing_package, slot_map))
    }

    /// Receives and verifies a partial SignatureShare from `signer_id`.
    /// Immediately isolates culprits via `verify_signature_share`, returns honest signers
    /// to the responsive pool, and completes signing as soon as any session gathers `threshold` shares.
    pub fn receive_share(
        &mut self,
        session_id: u128,
        signer_id: frost::Identifier,
        share: frost::round2::SignatureShare,
        replenish: Option<(NonceSlotId, frost::round1::SigningCommitments)>,
    ) -> Result<Option<frost::Signature>, frost::Error> {
        let session = match self.active_sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return Ok(None),
        };

        if !session.participants.contains(&signer_id) {
            return Ok(None);
        }

        let verifying_share = self
            .pubkey_package
            .verifying_shares()
            .get(&signer_id)
            .ok_or(frost::Error::UnknownIdentifier)?;

        // Identifiable abort: verify this individual signer's share
        if let Err(err) = frost_core::verify_signature_share(
            signer_id,
            verifying_share,
            &share,
            &session.signing_package,
            self.pubkey_package.verifying_key(),
        ) {
            self.banished_signers.insert(signer_id);
            self.signer_to_session.remove(&signer_id);
            return Err(err);
        }

        // Replenish commitment and return signer to responsive set
        if let Some(rep) = replenish {
            self.commitment_queues
                .entry(signer_id)
                .or_default()
                .push_back(rep);
        }
        self.signer_to_session.remove(&signer_id);
        self.responsive_signers.insert(signer_id);

        session.collected_shares.insert(signer_id, share);

        if session.collected_shares.len() == self.threshold {
            let final_sig = frost::aggregate(
                &session.signing_package,
                &session.collected_shares,
                &self.pubkey_package,
            )?;
            return Ok(Some(final_sig));
        }

        Ok(None)
    }
}
