use yip_ca::rpc::{
    CertTbs, ClientRpcRequest, ClientRpcResponse, EnrollmentCredential, NonceSlotId,
    ENROLL_POP_CONTEXT,
};

#[test]
fn test_cert_tbs_canonical_bytes() {
    let tbs = CertTbs {
        version: 1,
        member_pubkey: [0x02; 32],
        member_sign_pubkey: [0x03; 32],
        network_id: [0x01; 16],
        not_before: 1_700_000_000,
        not_after: 1_700_086_400,
        tags: vec![(1, b"tag".to_vec())],
    };

    let bytes = tbs.to_canonical_bytes();
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..33], &[0x02; 32]);
}

#[test]
fn test_rpc_message_serde_roundtrip() {
    let req = ClientRpcRequest::GetChallenge;
    let encoded = postcard::to_allocvec(&req).unwrap();
    let decoded: ClientRpcRequest = postcard::from_bytes(&encoded).unwrap();
    matches!(decoded, ClientRpcRequest::GetChallenge);

    let resp = ClientRpcResponse::Challenge {
        challenge_nonce: [0xaa; 32],
        expires_at_unix: 1_700_000_300,
    };
    let encoded = postcard::to_allocvec(&resp).unwrap();
    let decoded: ClientRpcResponse = postcard::from_bytes(&encoded).unwrap();
    if let ClientRpcResponse::Challenge {
        challenge_nonce,
        expires_at_unix,
    } = decoded
    {
        assert_eq!(challenge_nonce, [0xaa; 32]);
        assert_eq!(expires_at_unix, 1_700_000_300);
    } else {
        panic!("unexpected decoded response");
    }
}

#[test]
fn test_proof_of_possession_context() {
    assert_eq!(ENROLL_POP_CONTEXT, b"YIP-CA-ENROLL-POP-V1");
}

#[test]
fn test_enrollment_credential_roundtrip() {
    let cred = EnrollmentCredential::BootstrapToken {
        token_id: [0x55; 16],
        allowed_node_id: [0x66; 32],
        assigned_ipv4: 0x0a000002,
        assigned_ipv6: [0x20; 16],
        allowed_flags: 1,
        not_after_unix: 1_700_086_400,
        admin_signature: [0x77; 64],
    };
    let encoded = postcard::to_allocvec(&cred).unwrap();
    let decoded: EnrollmentCredential = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(cred, decoded);
}

#[test]
fn test_nonce_slot_id_ordering() {
    let slot1 = NonceSlotId {
        boot_epoch_id: 1,
        sequence_idx: 10,
    };
    let slot2 = NonceSlotId {
        boot_epoch_id: 1,
        sequence_idx: 20,
    };
    assert!(slot1 < slot2);
}
