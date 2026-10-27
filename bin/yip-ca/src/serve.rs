use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use frost_ed25519 as frost;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::roast_coordinator::RoastCoordinator;
use crate::rpc::{
    verify_enrollment_pop, CaWireMessage, ClientRpcRequest, ClientRpcResponse, QuorumRpcMessage,
    SignCertRequestPayload,
};
use crate::signer_daemon::{SignerPolicy, SignerState};
use yip_membership::cert::Cert;

/// Reads a length-prefixed postcard message from an async stream.
pub async fn read_framed<T: serde::de::DeserializeOwned>(
    stream: &mut TcpStream,
) -> Result<T, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Writes a length-prefixed postcard message to an async stream.
pub async fn write_framed<T: serde::Serialize>(
    stream: &mut TcpStream,
    msg: &T,
) -> Result<(), std::io::Error> {
    let bytes = postcard::to_allocvec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Shared coordinator state managing connected signers and ROAST coordination.
pub struct CoordinatorState {
    pub threshold: usize,
    pub pubkey_package: frost::keys::PublicKeyPackage,
    pub signer_txs: BTreeMap<frost::Identifier, mpsc::Sender<QuorumRpcMessage>>,
    pub roast: RoastCoordinator,
}

impl CoordinatorState {
    pub fn new(threshold: usize, pubkey_package: frost::keys::PublicKeyPackage) -> Self {
        Self {
            threshold,
            pubkey_package: pubkey_package.clone(),
            signer_txs: BTreeMap::new(),
            roast: RoastCoordinator::new(threshold, pubkey_package, Vec::new()),
        }
    }
}

/// Runs the Coordinator daemon loop.
pub async fn run_coordinator(
    listener: TcpListener,
    threshold: usize,
    pubkey_package: frost::keys::PublicKeyPackage,
) -> Result<(), std::io::Error> {
    let state = Arc::new(Mutex::new(CoordinatorState::new(threshold, pubkey_package)));

    loop {
        let (mut socket, _) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let first_msg: Result<CaWireMessage, _> = read_framed(&mut socket).await;
            match first_msg {
                Ok(CaWireMessage::Quorum(QuorumRpcMessage::PublishCommitments {
                    signer_id,
                    commitments,
                    ..
                })) => {
                    // Handle persistent Signer connection
                    let (tx, mut rx) = mpsc::channel::<QuorumRpcMessage>(32);
                    {
                        let mut s = state.lock().await;
                        s.signer_txs.insert(signer_id, tx);
                        s.roast.register_commitments(signer_id, commitments);
                    }

                    loop {
                        tokio::select! {
                            Some(out_msg) = rx.recv() => {
                                let wire_msg = CaWireMessage::Quorum(out_msg);
                                if write_framed(&mut socket, &wire_msg).await.is_err() {
                                    break;
                                }
                            }
                            in_msg = read_framed::<CaWireMessage>(&mut socket) => {
                                match in_msg {
                                    Ok(CaWireMessage::Quorum(QuorumRpcMessage::SignCertResponse(payload))) => {
                                        let mut s = state.lock().await;
                                        let _ = s.roast.receive_share(
                                            payload.session_id,
                                            payload.signer_id,
                                            payload.signature_share,
                                            payload.replenish_commitment,
                                        );
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }

                    let mut s = state.lock().await;
                    s.signer_txs.remove(&signer_id);
                }
                Ok(CaWireMessage::ClientReq(ClientRpcRequest::GetChallenge)) => {
                    // Handle client enrollment challenge request
                    let mut challenge_nonce = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut challenge_nonce);
                    let expires_at_unix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 300;

                    let resp = CaWireMessage::ClientResp(ClientRpcResponse::Challenge {
                        challenge_nonce,
                        expires_at_unix,
                    });
                    if write_framed(&mut socket, &resp).await.is_err() {
                        return;
                    }

                    // Await enrollment submission
                    let submit_req: Result<CaWireMessage, _> = read_framed(&mut socket).await;
                    let payload = match submit_req {
                        Ok(CaWireMessage::ClientReq(ClientRpcRequest::SubmitEnrollment(p))) => *p,
                        _ => return,
                    };

                    if payload.challenge_nonce != challenge_nonce {
                        let rej = CaWireMessage::ClientResp(ClientRpcResponse::Rejected {
                            reason: "challenge nonce mismatch".into(),
                        });
                        let _ = write_framed(&mut socket, &rej).await;
                        return;
                    }

                    if let Err(e) = verify_enrollment_pop(
                        &payload.pop_signature,
                        &payload.csr_tbs.member_sign_pubkey,
                        &challenge_nonce,
                        &payload.csr_tbs,
                    ) {
                        let rej = CaWireMessage::ClientResp(ClientRpcResponse::Rejected {
                            reason: format!("PoP verification failed: {e}"),
                        });
                        let _ = write_framed(&mut socket, &rej).await;
                        return;
                    }

                    let msg = payload.csr_tbs.to_canonical_bytes();

                    // Start ROAST signing round
                    let mut session_info = None;
                    let mut signers_to_dispatch = Vec::new();

                    {
                        let mut s = state.lock().await;
                        s.roast.message = msg.clone();
                        if let Some((session_id, pkg, slot_map)) = s.roast.try_spawn_session() {
                            session_info = Some((session_id, pkg.clone()));
                            for (id, slot) in slot_map {
                                if let Some(tx) = s.signer_txs.get(&id) {
                                    let req = SignCertRequestPayload {
                                        session_id,
                                        slot_id: slot,
                                        signing_package: pkg.clone(),
                                        cert_tbs: payload.csr_tbs.clone(),
                                        credential: payload.credential.clone(),
                                        challenge_nonce,
                                        pop_signature: payload.pop_signature,
                                    };
                                    signers_to_dispatch.push((tx.clone(), req));
                                }
                            }
                        }
                    }

                    if let Some((session_id, _)) = session_info {
                        for (tx, req) in signers_to_dispatch {
                            let _ = tx
                                .send(QuorumRpcMessage::SignCertRequest(Box::new(req)))
                                .await;
                        }

                        // Wait for ROAST completion (polling shares)
                        let mut final_sig = None;
                        for _ in 0..100 {
                            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                            let s = state.lock().await;
                            if let Some(session) = s.roast.active_sessions.get(&session_id) {
                                if session.collected_shares.len() >= s.threshold {
                                    if let Ok(sig) = frost::aggregate(
                                        &session.signing_package,
                                        &session.collected_shares,
                                        &s.pubkey_package,
                                    ) {
                                        final_sig = Some(sig);
                                        break;
                                    }
                                }
                            }
                        }

                        if let Some(sig) = final_sig {
                            let sig_bytes = sig.serialize().unwrap();
                            let mut sig_arr = [0u8; 64];
                            sig_arr.copy_from_slice(&sig_bytes);

                            let cert = Cert {
                                version: payload.csr_tbs.version,
                                member_pubkey: payload.csr_tbs.member_pubkey,
                                member_sign_pubkey: payload.csr_tbs.member_sign_pubkey,
                                network_id: payload.csr_tbs.network_id,
                                not_before: payload.csr_tbs.not_before,
                                not_after: payload.csr_tbs.not_after,
                                tags: payload.csr_tbs.tags.clone(),
                                ca_sig: sig_arr,
                            };

                            let mut cert_bytes = Vec::new();
                            cert.encode(&mut cert_bytes);

                            let root_vk = {
                                let s = state.lock().await;
                                let vk_b = s.pubkey_package.verifying_key().serialize().unwrap();
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&vk_b);
                                arr
                            };

                            let enrolled = CaWireMessage::ClientResp(ClientRpcResponse::Enrolled {
                                cert_bytes,
                                ca_public_key: root_vk,
                            });
                            let _ = write_framed(&mut socket, &enrolled).await;
                            return;
                        }
                    }

                    let rej = CaWireMessage::ClientResp(ClientRpcResponse::Rejected {
                        reason: "threshold signing quorum unreachable or stalled".into(),
                    });
                    let _ = write_framed(&mut socket, &rej).await;
                }
                _ => {}
            }
        });
    }
}

/// Runs a persistent Signer daemon connecting to the Coordinator.
pub async fn run_signer(
    coord_addr: SocketAddr,
    key_package: frost::keys::KeyPackage,
    pubkey_package: frost::keys::PublicKeyPackage,
    policy: SignerPolicy,
) -> Result<(), std::io::Error> {
    let mut stream = TcpStream::connect(coord_addr).await?;
    let signer = Arc::new(SignerState::new(key_package, pubkey_package, policy));

    // Preprocess initial batch of 16 commitments
    let commitments = {
        let mut vault = signer.vault.lock().unwrap();
        vault.preprocess_batch(signer.key_package.signing_share(), 16)
    };

    let pub_msg = CaWireMessage::Quorum(QuorumRpcMessage::PublishCommitments {
        signer_id: *signer.key_package.identifier(),
        boot_epoch_id: signer.vault.lock().unwrap().boot_epoch_id(),
        commitments,
    });
    write_framed(&mut stream, &pub_msg).await?;

    loop {
        let msg: CaWireMessage = match read_framed(&mut stream).await {
            Ok(m) => m,
            Err(_) => break,
        };

        if let CaWireMessage::Quorum(QuorumRpcMessage::SignCertRequest(req)) = msg {
            let resp = signer.handle_sign_request(&req);
            write_framed(&mut stream, &CaWireMessage::Quorum(resp)).await?;
        }
    }

    Ok(())
}
