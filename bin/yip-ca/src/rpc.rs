use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};

/// Serde helper for 64-byte signature arrays.
pub mod serde_bytes_64 {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice: &[u8] = serde::Deserialize::deserialize(deserializer)?;
        slice
            .try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes"))
    }
}

/// Domain separation context for Proof-of-Possession signatures during enrollment.
pub const ENROLL_POP_CONTEXT: &[u8] = b"YIP-CA-ENROLL-POP-V1";

/// Canonical certificate fields to be signed by the FROST quorum.
/// Maps directly to crates/yip-membership/src/cert.rs wire layout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertTbs {
    pub version: u8,
    pub member_pubkey: [u8; 32],
    pub member_sign_pubkey: [u8; 32],
    pub network_id: [u8; 16],
    pub not_before: u64,
    pub not_after: u64,
    pub tags: Vec<(u8, Vec<u8>)>,
}

impl CertTbs {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.member_pubkey);
        out.extend_from_slice(&self.member_sign_pubkey);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        let tag_count = u16::try_from(self.tags.len()).expect("tags fit in u16");
        out.extend_from_slice(&tag_count.to_be_bytes());
        for (tag, bytes) in &self.tags {
            out.push(*tag);
            let len = u16::try_from(bytes.len()).expect("tag value fits in u16");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }
}

/// Authorization proof presented by an enrolling or renewing node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentCredential {
    /// One-time administrator provisioning token signed by the enrollment auth key.
    BootstrapToken {
        token_id: [u8; 16],
        allowed_node_id: [u8; 32],
        assigned_ipv4: u32,
        assigned_ipv6: [u8; 16],
        allowed_flags: u32,
        not_after_unix: u64,
        #[serde(with = "serde_bytes_64")]
        admin_signature: [u8; 64],
    },
    /// Existing valid certificate presented for zero-touch rotation prior to expiry.
    RenewalCert {
        existing_cert_bytes: Vec<u8>,
        #[serde(with = "serde_bytes_64")]
        renewal_signature: [u8; 64],
    },
}

/// Payload for enrollment submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEnrollmentPayload {
    pub challenge_nonce: [u8; 32],
    pub csr_tbs: CertTbs,
    pub credential: EnrollmentCredential,
    #[serde(with = "serde_bytes_64")]
    pub pop_signature: [u8; 64],
}

/// Client -> Coordinator RPC messages (`yip-ca enroll` or `yipd`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientRpcRequest {
    GetChallenge,
    SubmitEnrollment(Box<SubmitEnrollmentPayload>),
}

/// Coordinator -> Client RPC responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientRpcResponse {
    Challenge {
        challenge_nonce: [u8; 32],
        expires_at_unix: u64,
    },
    Enrolled {
        /// Complete serialized `yip_membership::Cert` including the 64-byte FROST signature.
        cert_bytes: Vec<u8>,
        /// Group verifying key for RootSet verification.
        ca_public_key: [u8; 32],
    },
    Rejected {
        reason: String,
    },
}

/// Unique identifier for a preprocessed nonce slot within a Signer's boot epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NonceSlotId {
    pub boot_epoch_id: u128,
    pub sequence_idx: u64,
}

/// Payload for single-round signing request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignCertRequestPayload {
    pub session_id: u128,
    pub slot_id: NonceSlotId,
    pub signing_package: frost::SigningPackage,
    pub cert_tbs: CertTbs,
    pub credential: EnrollmentCredential,
    pub challenge_nonce: [u8; 32],
    #[serde(with = "serde_bytes_64")]
    pub pop_signature: [u8; 64],
}

/// Payload for signing response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignCertResponsePayload {
    pub session_id: u128,
    pub signer_id: frost::Identifier,
    pub signature_share: frost::round2::SignatureShare,
    pub replenish_commitment: Option<(NonceSlotId, frost::round1::SigningCommitments)>,
}

/// Coordinator <-> Signer internal quorum RPC protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum QuorumRpcMessage {
    /// Signer -> Coordinator: Registers a batch of preprocessed Round 1 commitments.
    PublishCommitments {
        signer_id: frost::Identifier,
        boot_epoch_id: u128,
        commitments: Vec<(NonceSlotId, frost::round1::SigningCommitments)>,
    },
    /// Coordinator -> Signer: Single-round signing request using a pre-cached commitment.
    SignCertRequest(Box<SignCertRequestPayload>),
    /// Signer -> Coordinator: Partial signature share + replenishment commitment.
    SignCertResponse(Box<SignCertResponsePayload>),
    /// Signer -> Coordinator: Policy or nonce-state rejection.
    SignCertReject {
        session_id: u128,
        signer_id: frost::Identifier,
        reason: String,
    },
}

/// Unified wire message envelope for all yip-ca TCP connections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CaWireMessage {
    Quorum(QuorumRpcMessage),
    ClientReq(ClientRpcRequest),
    ClientResp(ClientRpcResponse),
}

/// Verifies client Proof-of-Possession signature against the challenge and candidate certificate TBS bytes.
pub fn verify_enrollment_pop(
    pop_sig_bytes: &[u8; 64],
    signer_pubkey_bytes: &[u8; 32],
    challenge_nonce: &[u8; 32],
    csr_tbs: &CertTbs,
) -> Result<(), &'static str> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let vk =
        VerifyingKey::from_bytes(signer_pubkey_bytes).map_err(|_| "invalid signer public key")?;
    let sig = Signature::from_bytes(pop_sig_bytes);
    let mut pop_msg = Vec::new();
    pop_msg.extend_from_slice(ENROLL_POP_CONTEXT);
    pop_msg.extend_from_slice(challenge_nonce);
    pop_msg.extend_from_slice(&csr_tbs.to_canonical_bytes());
    vk.verify_strict(&pop_msg, &sig)
        .map_err(|_| "invalid Proof-of-Possession signature")
}
