use yip_crypto::handshake::{
    InitiatorHandshake, ResponderHandshake, FLIGHT_1_BASE_LEN, FLIGHT_2_BASE_LEN,
};
use yip_crypto::{generate_keypair, generate_pq_keypair, CryptoError};

#[test]
fn test_handshake_roundtrip_empty_payload() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];
    let prologue = b"prologue_v1";

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("initiator handshake creation");

    let mut responder = ResponderHandshake::new(
        &responder_static.private,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("responder handshake creation");

    // Flight 1: Initiator -> Responder (empty payload)
    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(&[], &mut msg1)
        .expect("write_message_1");
    assert_eq!(n1, FLIGHT_1_BASE_LEN);
    assert_eq!(n1, 864);

    let mut payload1_out = [0u8; 64];
    let p1_len = responder
        .read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out)
        .expect("read_message_1");
    assert_eq!(p1_len, 0);

    // Responder has authenticated initiator static public key
    assert_eq!(responder.remote_static(), Some(initiator_static.public));

    // Flight 2: Responder -> Initiator (empty payload)
    let mut msg2 = [0u8; 256];
    let n2 = responder
        .write_message_2(&[], &mut msg2)
        .expect("write_message_2");
    assert_eq!(n2, FLIGHT_2_BASE_LEN);
    assert_eq!(n2, 48);

    let mut payload2_out = [0u8; 64];
    let p2_len = initiator
        .read_message_2(&msg2[..n2], &mut payload2_out)
        .expect("read_message_2");
    assert_eq!(p2_len, 0);

    // Both sides verify identical transport keys from split()
    let (init_k1, init_k2) = initiator.split().expect("initiator split");
    let (resp_k1, resp_k2) = responder.split().expect("responder split");
    assert_eq!(init_k1, resp_k1);
    assert_eq!(init_k2, resp_k2);

    // Directional transport keys verify
    let (init_send, init_recv) = initiator
        .transport_keys()
        .expect("initiator transport keys");
    let (resp_send, resp_recv) = responder
        .transport_keys()
        .expect("responder transport keys");
    assert_eq!(init_send, resp_recv);
    assert_eq!(init_recv, resp_send);

    // Channel bindings match
    assert_eq!(initiator.channel_binding(), responder.channel_binding());
}

#[test]
fn test_handshake_roundtrip_with_payload() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x42u8; 32];
    let prologue = b"prologue_session";

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("initiator handshake creation");

    let mut responder = ResponderHandshake::new(
        &responder_static.private,
        &responder_pq_ek.0,
        &psk,
        prologue,
    )
    .expect("responder handshake creation");

    let payload_f1 = b"client_auth_ticket:xyz123";
    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(payload_f1, &mut msg1)
        .expect("write_message_1");
    assert_eq!(n1, FLIGHT_1_BASE_LEN + payload_f1.len());

    let mut payload1_out = [0u8; 128];
    let p1_len = responder
        .read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out)
        .expect("read_message_1");
    assert_eq!(&payload1_out[..p1_len], payload_f1);

    let payload_f2 = b"server_ok:session_accepted";
    let mut msg2 = [0u8; 256];
    let n2 = responder
        .write_message_2(payload_f2, &mut msg2)
        .expect("write_message_2");
    assert_eq!(n2, FLIGHT_2_BASE_LEN + payload_f2.len());

    let mut payload2_out = [0u8; 128];
    let p2_len = initiator
        .read_message_2(&msg2[..n2], &mut payload2_out)
        .expect("read_message_2");
    assert_eq!(&payload2_out[..p2_len], payload_f2);

    let init_split = initiator.split().expect("initiator split");
    let resp_split = responder.split().expect("responder split");
    assert_eq!(init_split, resp_split);

    // Into session conversion and data-plane ping-pong
    let mut session_init = initiator.into_session().expect("session init");
    let mut session_resp = responder.into_session().expect("session resp");

    let sealed_to_resp = session_init.seal(b"data plane ping").expect("seal");
    let opened_by_resp = session_resp
        .open(sealed_to_resp.counter, &sealed_to_resp.ciphertext)
        .expect("open");
    assert_eq!(opened_by_resp, b"data plane ping");

    let sealed_to_init = session_resp.seal(b"data plane pong").expect("seal");
    let opened_by_init = session_init
        .open(sealed_to_init.counter, &sealed_to_init.ciphertext)
        .expect("open");
    assert_eq!(opened_by_init, b"data plane pong");
}

#[test]
fn test_corruption_static_key_tag_fails_read_message_1() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(b"test", &mut msg1)
        .expect("write_message_1");

    // Static key ciphertext + Poly1305 tag is at offset 32..80
    // Corrupt 1 byte in the Poly1305 tag (e.g. byte 75)
    msg1[75] ^= 0x01;

    let mut payload1_out = [0u8; 64];
    let res = responder.read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out);
    assert_eq!(res, Err(CryptoError::Decrypt));

    // Intermediate state wiped, subsequent operations must fail
    let mut msg2 = [0u8; 256];
    assert!(responder.write_message_2(&[], &mut msg2).is_err());
}

#[test]
fn test_corruption_kem_ciphertext_fails_read_message_1() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(b"test", &mut msg1)
        .expect("write_message_1");

    // ML-KEM ciphertext is at offset 80..848
    // Corrupt 1 byte inside the ML-KEM ciphertext
    msg1[150] ^= 0x55;

    let mut payload1_out = [0u8; 64];
    let res = responder.read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out);
    // Implicit rejection causes mismatched ratchet key k_3 -> payload Poly1305 MAC failure
    assert_eq!(res, Err(CryptoError::Decrypt));
    assert!(responder.write_message_2(&[], &mut msg1).is_err());
}

#[test]
fn test_corruption_payload_mac_fails_read_message_1() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(b"test", &mut msg1)
        .expect("write_message_1");

    // Corrupt the last byte of the payload MAC
    msg1[n1 - 1] ^= 0x01;

    let mut payload1_out = [0u8; 64];
    let res = responder.read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out);
    assert_eq!(res, Err(CryptoError::Decrypt));
}

#[test]
fn test_corruption_flight_2_fails_read_message_2() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(&[], &mut msg1)
        .expect("write_message_1");

    let mut payload1_out = [0u8; 64];
    responder
        .read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out)
        .expect("read_message_1");

    let mut msg2 = [0u8; 256];
    let n2 = responder
        .write_message_2(b"payload2", &mut msg2)
        .expect("write_message_2");

    // Corrupt payload MAC in msg2
    msg2[n2 - 1] ^= 0xaa;

    let mut payload2_out = [0u8; 64];
    let res = initiator.read_message_2(&msg2[..n2], &mut payload2_out);
    assert_eq!(res, Err(CryptoError::Decrypt));
    assert!(initiator.split().is_err());
}

#[test]
fn test_low_order_x25519_point_rejected() {
    let initiator_static = generate_keypair();
    let (responder_pq_ek, _responder_pq_dk) = generate_pq_keypair();
    let psk = [0x55u8; 32];

    // Responder static public is all zeros (low-order point)
    let low_order_static = [0u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &low_order_static,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut msg1 = [0u8; 1024];
    let res = initiator.write_message_1(&[], &mut msg1);
    assert_eq!(res, Err(CryptoError::InvalidKey));
}

#[test]
fn test_truncated_message_rejected() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(&[], &mut msg1)
        .expect("write_message_1");

    // Truncate Flight 1 message
    let mut payload1_out = [0u8; 64];
    let res = responder.read_message_1(&msg1[..n1 - 1], &responder_dk_bytes, &mut payload1_out);
    assert_eq!(res, Err(CryptoError::Handshake));
}

#[test]
fn test_responder_rejects_low_order_ephemeral_point() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(&[], &mut msg1)
        .expect("write_message_1");

    // Overwrite ephemeral e_i with all zeros (low-order point)
    msg1[0..32].fill(0);

    let mut payload1_out = [0u8; 64];
    let res = responder.read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out);
    assert_eq!(res, Err(CryptoError::InvalidKey));
}

#[test]
fn test_initiator_rejects_low_order_ephemeral_point() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(&[], &mut msg1)
        .expect("write_message_1");

    let mut payload1_out = [0u8; 64];
    responder
        .read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out)
        .expect("read_message_1");

    let mut msg2 = [0u8; 256];
    let n2 = responder
        .write_message_2(&[], &mut msg2)
        .expect("write_message_2");

    // Overwrite ephemeral e_r with all zeros (low-order point)
    msg2[0..32].fill(0);

    let mut payload2_out = [0u8; 64];
    let res = initiator.read_message_2(&msg2[..n2], &mut payload2_out);
    assert_eq!(res, Err(CryptoError::InvalidKey));
}

#[test]
fn test_prologue_mismatch_fails_handshake() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        b"prologue_initiator",
    )
    .expect("initiator handshake creation");

    let mut responder = ResponderHandshake::new(
        &responder_static.private,
        &responder_pq_ek.0,
        &psk,
        b"prologue_responder_mismatch",
    )
    .expect("responder handshake creation");

    let mut msg1 = [0u8; 1024];
    let n1 = initiator
        .write_message_1(&[], &mut msg1)
        .expect("write_message_1");

    let mut payload1_out = [0u8; 64];
    let res = responder.read_message_1(&msg1[..n1], &responder_dk_bytes, &mut payload1_out);
    // Transcript mismatch leads to static key MAC verification failure
    assert_eq!(res, Err(CryptoError::Decrypt));
}

#[test]
fn test_buffer_too_small_errors() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, responder_pq_dk) = generate_pq_keypair();
    let responder_dk_bytes = responder_pq_dk.to_bytes();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    // Output buffer smaller than FLIGHT_1_BASE_LEN (864)
    let mut small_buf = [0u8; 800];
    assert_eq!(
        initiator.write_message_1(&[], &mut small_buf),
        Err(CryptoError::Handshake)
    );

    let mut ok_buf = [0u8; 1024];
    let n1 = initiator
        .write_message_1(b"four", &mut ok_buf)
        .expect("write_message_1");

    // Output payload buffer smaller than payload len (4)
    let mut small_payload = [0u8; 2];
    assert_eq!(
        responder.read_message_1(&ok_buf[..n1], &responder_dk_bytes, &mut small_payload),
        Err(CryptoError::Handshake)
    );
}

#[test]
fn test_state_machine_invalid_transitions() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, _responder_pq_dk) = generate_pq_keypair();
    let psk = [0x55u8; 32];

    let mut initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let mut responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    // Cannot call split() before completing handshake
    assert_eq!(initiator.split(), Err(CryptoError::Handshake));
    assert_eq!(responder.split(), Err(CryptoError::Handshake));

    // Initiator cannot read_message_2 before write_message_1
    let mut payload = [0u8; 64];
    assert_eq!(
        initiator.read_message_2(&[0u8; 64], &mut payload),
        Err(CryptoError::Handshake)
    );

    // Responder cannot write_message_2 before read_message_1
    let mut msg2 = [0u8; 256];
    assert_eq!(
        responder.write_message_2(&[], &mut msg2),
        Err(CryptoError::Handshake)
    );
}

#[test]
fn test_key_introspection() {
    let initiator_static = generate_keypair();
    let responder_static = generate_keypair();
    let (responder_pq_ek, _responder_pq_dk) = generate_pq_keypair();
    let psk = [0x55u8; 32];

    let initiator = InitiatorHandshake::new(
        &initiator_static.private,
        &responder_static.public,
        &responder_pq_ek.0,
        &psk,
        &[],
    )
    .expect("initiator handshake creation");

    let responder =
        ResponderHandshake::new(&responder_static.private, &responder_pq_ek.0, &psk, &[])
            .expect("responder handshake creation");

    assert_eq!(initiator.local_static(), initiator_static.public);
    assert_eq!(initiator.remote_static(), Some(responder_static.public));
    assert_eq!(responder.local_static(), responder_static.public);
    assert_eq!(responder.local_pq_ek(), &responder_pq_ek.0);
}
