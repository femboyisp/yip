use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use tokio::net::TcpStream;

use crate::rpc::{
    CaWireMessage, CertTbs, ClientRpcRequest, ClientRpcResponse, EnrollmentCredential,
    SubmitEnrollmentPayload, ENROLL_POP_CONTEXT,
};
use crate::serve::{read_framed, write_framed};
use yip_membership::cert::Cert;

/// Client function to enroll a node with the online threshold CA.
pub async fn enroll_node(
    server_addr: SocketAddr,
    client_signing_key: &SigningKey,
    member_pubkey: [u8; 32],
    member_sign_pubkey: [u8; 32],
    network_id: [u8; 16],
    credential: EnrollmentCredential,
) -> Result<Cert, String> {
    let mut stream = TcpStream::connect(server_addr)
        .await
        .map_err(|e| format!("connection error: {e}"))?;

    // 1. Request challenge
    let req = CaWireMessage::ClientReq(ClientRpcRequest::GetChallenge);
    write_framed(&mut stream, &req)
        .await
        .map_err(|e| format!("failed to send GetChallenge: {e}"))?;

    let challenge_resp: CaWireMessage = read_framed(&mut stream)
        .await
        .map_err(|e| format!("failed to read challenge: {e}"))?;

    let challenge_nonce = match challenge_resp {
        CaWireMessage::ClientResp(ClientRpcResponse::Challenge {
            challenge_nonce, ..
        }) => challenge_nonce,
        CaWireMessage::ClientResp(ClientRpcResponse::Rejected { reason }) => {
            return Err(format!("server rejected challenge request: {reason}"));
        }
        _ => return Err("expected challenge response from server".into()),
    };

    // 2. Build CertTbs
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let csr_tbs = CertTbs {
        version: 1,
        member_pubkey,
        member_sign_pubkey,
        network_id,
        not_before: now.saturating_sub(60),
        not_after: now + 86_400,
        tags: Vec::new(),
    };

    // 3. Compute Proof-of-Possession signature
    let tbs_bytes = csr_tbs.to_canonical_bytes();
    let mut pop_msg = Vec::new();
    pop_msg.extend_from_slice(ENROLL_POP_CONTEXT);
    pop_msg.extend_from_slice(&challenge_nonce);
    pop_msg.extend_from_slice(&tbs_bytes);

    let pop_signature: ed25519_dalek::Signature = client_signing_key.sign(&pop_msg);
    let mut pop_arr = [0u8; 64];
    pop_arr.copy_from_slice(&pop_signature.to_bytes());

    // 4. Submit Enrollment
    let submit_payload = SubmitEnrollmentPayload {
        challenge_nonce,
        csr_tbs,
        credential,
        pop_signature: pop_arr,
    };

    let submit_msg =
        CaWireMessage::ClientReq(ClientRpcRequest::SubmitEnrollment(Box::new(submit_payload)));
    write_framed(&mut stream, &submit_msg)
        .await
        .map_err(|e| format!("failed to send SubmitEnrollment: {e}"))?;

    // 5. Read enrollment response
    let enroll_resp: CaWireMessage = read_framed(&mut stream)
        .await
        .map_err(|e| format!("failed to read enroll response: {e}"))?;

    match enroll_resp {
        CaWireMessage::ClientResp(ClientRpcResponse::Enrolled { cert_bytes, .. }) => {
            Cert::decode(&cert_bytes).ok_or_else(|| "failed to decode certificate".to_string())
        }
        CaWireMessage::ClientResp(ClientRpcResponse::Rejected { reason }) => {
            Err(format!("enrollment rejected by CA: {reason}"))
        }
        _ => Err("unexpected enrollment response".into()),
    }
}
