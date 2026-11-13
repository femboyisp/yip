//! Deterministic golden vector tests for `PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3`.
//!
//! Validates:
//! - Exact hex values of intermediate chaining keys (ck) and transcript hashes (h).
//! - Intermediate cipher keys (k1, k2, k3) generated during Flight 1.
//! - Split directional transport keys (k_send, k_recv).
//! - 120-second epoch rekeying using BLAKE3 in keyed mode with domain tag 0x04.
//! - Directional transport session encryption and decryption round-trip across epoch rotations.

use std::fmt::Write;
use x25519_dalek::{PublicKey, StaticSecret};
use yip_crypto::generate_pq_keypair_from_seed;
use yip_crypto::handshake::{
    InitiatorHandshake, ResponderHandshake, FLIGHT_1_BASE_LEN, FLIGHT_2_BASE_LEN,
};
use yip_crypto::session::{rekey_transport_key, ReplayWindow, Session};

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[test]
fn test_pqnoise_deterministic_golden_vectors() {
    // ── 1. Deterministic Seeds and Key Material ──────────────────────────────
    let s_i_priv = [0x11u8; 32];
    let rs_priv = [0x22u8; 32];
    let rs_pq_seed = [0x33u8; 64];
    let e_i_priv = [0x44u8; 32];
    let kem_seed = [0x55u8; 32];
    let e_r_priv = [0x66u8; 32];
    let psk = [0x77u8; 32];
    let prologue = b"yip-pqnoise-blake3-golden-test-vector-v1";

    let rs_secret = StaticSecret::from(rs_priv);
    let rs_pub = PublicKey::from(&rs_secret).to_bytes();

    let (rs_pq_ek, rs_pq_dk) = generate_pq_keypair_from_seed(&rs_pq_seed);
    let rs_pq_dk_bytes = rs_pq_dk.to_bytes();

    // ── 2. Initialize Handshake Machines ─────────────────────────────────────
    let mut initiator = InitiatorHandshake::new(&s_i_priv, &rs_pub, &rs_pq_ek.0, &psk, prologue)
        .expect("initiator initialization");

    let mut responder = ResponderHandshake::new(&rs_priv, &rs_pq_ek.0, &psk, prologue)
        .expect("responder initialization");

    // Both peers compute identical initial ck and h
    let init_ck = initiator.symmetric_state().ck;
    let init_h = initiator.symmetric_state().h;
    assert_eq!(init_ck, responder.symmetric_state().ck);
    assert_eq!(init_h, responder.symmetric_state().h);

    assert_eq!(
        to_hex(&init_ck),
        "4d689c1c80ce9faf0664e9f3ebab0357092777bd566de90c763626522447e52f",
        "initial ck hex mismatch"
    );
    assert_eq!(
        to_hex(&init_h),
        "369d63377407f5d37848bdca71ced0b9999cc07c017d0070583b7db385de4642",
        "initial h hex mismatch"
    );

    // ── 3. Flight 1: Initiator -> Responder ──────────────────────────────────
    let payload_1 = b"initiator flight 1 payload message";
    let mut msg1 = vec![0u8; FLIGHT_1_BASE_LEN + payload_1.len()];

    let n1 = initiator
        .write_message_1_with_ephemeral(payload_1, &mut msg1, e_i_priv, Some(kem_seed))
        .expect("write flight 1");
    assert_eq!(n1, FLIGHT_1_BASE_LEN + payload_1.len());

    let (k1, k2, k3) = initiator
        .flight_1_keys()
        .expect("flight 1 keys must be captured");

    assert_eq!(
        to_hex(&k1),
        "185642fa901abdd08f46f3b39b46f4d42db531f273118619d77819b11dfbbd7c",
        "k1 hex mismatch"
    );
    assert_eq!(
        to_hex(&k2),
        "1a4979b5bd228514f9ec960c31905d85e55051d3c7731f53564fe6b64da4443b",
        "k2 hex mismatch"
    );
    assert_eq!(
        to_hex(&k3),
        "df4343564dc1b8cf85a2e42bd8159f33f99a594b5787fd7d0bf9770e6d919eb4",
        "k3 hex mismatch"
    );

    let f1_ck = initiator.symmetric_state().ck;
    let f1_h = initiator.symmetric_state().h;
    assert_eq!(
        to_hex(&f1_ck),
        "3b40e8c6bb644e78114524c44a09d3dc41f6aab84c5e3b9c5d0a05b3dd4853ab",
        "flight 1 ck hex mismatch"
    );
    assert_eq!(
        to_hex(&f1_h),
        "1b2ba51c2eef821b7bd2cca1efe1644d160541650a81c76679cb0574d25cb418",
        "flight 1 h hex mismatch"
    );

    let mut payload_1_recv = vec![0u8; payload_1.len()];
    let n1_recv = responder
        .read_message_1(&msg1[..n1], &rs_pq_dk_bytes, &mut payload_1_recv)
        .expect("read flight 1");
    assert_eq!(n1_recv, payload_1.len());
    assert_eq!(payload_1_recv, payload_1);

    // Transcript state matches after Flight 1
    assert_eq!(
        initiator.symmetric_state().ck,
        responder.symmetric_state().ck
    );
    assert_eq!(initiator.symmetric_state().h, responder.symmetric_state().h);

    // ── 4. Flight 2: Responder -> Initiator ──────────────────────────────────
    let payload_2 = b"responder flight 2 payload message";
    let mut msg2 = vec![0u8; FLIGHT_2_BASE_LEN + payload_2.len()];

    let n2 = responder
        .write_message_2_with_ephemeral(payload_2, &mut msg2, e_r_priv)
        .expect("write flight 2");
    assert_eq!(n2, FLIGHT_2_BASE_LEN + payload_2.len());

    let mut payload_2_recv = vec![0u8; payload_2.len()];
    let n2_recv = initiator
        .read_message_2(&msg2[..n2], &mut payload_2_recv)
        .expect("read flight 2");
    assert_eq!(n2_recv, payload_2.len());
    assert_eq!(payload_2_recv, payload_2);

    assert!(initiator.is_finished());
    assert!(responder.is_finished());
    assert_eq!(initiator.channel_binding(), responder.channel_binding());

    let f2_ck = initiator.symmetric_state().ck;
    let f2_h = initiator.symmetric_state().h;
    assert_eq!(
        to_hex(&f2_ck),
        "31734cfabb31969a4a079c22df5daea2712d34ffa5deb97df69c9bd2b5370c6e",
        "flight 2 ck hex mismatch"
    );
    assert_eq!(
        to_hex(&f2_h),
        "0bd705e1f8f5bf541a283e81ed69f62b30fe4a1a8bf038926a8d6315836b67d1",
        "flight 2 h hex mismatch"
    );

    // ── 5. Transport Keys Split ──────────────────────────────────────────────
    let (ini_send, ini_recv) = initiator
        .transport_keys()
        .expect("initiator transport keys");
    let (res_send, res_recv) = responder
        .transport_keys()
        .expect("responder transport keys");
    assert_eq!(
        ini_send, res_recv,
        "initiator send key must match responder recv key"
    );
    assert_eq!(
        ini_recv, res_send,
        "initiator recv key must match responder send key"
    );

    assert_eq!(
        to_hex(&ini_send),
        "be6cc65418a491408f67fec54bf47ebdb4bd68067c3c64c1ea154638ba9d60f4",
        "k_send hex mismatch"
    );
    assert_eq!(
        to_hex(&ini_recv),
        "a46978766360272cf427772bde73708d35d6b3f01865ee559b8a06b6a7dbb905",
        "k_recv hex mismatch"
    );

    // ── 6. 120s Epoch Rekeying (Tag 0x04) ────────────────────────────────────
    let ini_send_rekey1 = rekey_transport_key(&ini_send);
    let ini_recv_rekey1 = rekey_transport_key(&ini_recv);
    let res_send_rekey1 = rekey_transport_key(&res_send);
    let res_recv_rekey1 = rekey_transport_key(&res_recv);

    assert_eq!(ini_send_rekey1, res_recv_rekey1);
    assert_eq!(ini_recv_rekey1, res_send_rekey1);
    assert_ne!(
        ini_send_rekey1, ini_send,
        "rekeyed key must differ from prior key"
    );
    assert_ne!(
        ini_recv_rekey1, ini_recv,
        "rekeyed key must differ from prior key"
    );

    assert_eq!(
        to_hex(&ini_send_rekey1),
        "e44d0ed5fca91b6a60e530710e8bfa8aaf99597ed7a5e1e7faa29e9832deaefa",
        "k_send_rekey1 hex mismatch"
    );
    assert_eq!(
        to_hex(&ini_recv_rekey1),
        "5b98015a340df8b2325ae6c7f5c471fdabcaf0bb3d8d086fb300880dd297cb7d",
        "k_recv_rekey1 hex mismatch"
    );

    let ini_send_rekey2 = rekey_transport_key(&ini_send_rekey1);
    let ini_recv_rekey2 = rekey_transport_key(&ini_recv_rekey1);
    assert_ne!(ini_send_rekey2, ini_send_rekey1);
    assert_ne!(ini_recv_rekey2, ini_recv_rekey1);

    assert_eq!(
        to_hex(&ini_send_rekey2),
        "a027937a109b7c1b0b83ca7ea29f7678223d7e10d1acbc9d0f04a30adc49d9ce",
        "k_send_rekey2 hex mismatch"
    );
    assert_eq!(
        to_hex(&ini_recv_rekey2),
        "fc6ba0b7a8217c2d15a20fc70a2ca2fccfddf2f7f3a28ecc75c44b00b4122a19",
        "k_recv_rekey2 hex mismatch"
    );

    // ── 7. Directional Transport Session Integration ─────────────────────────
    let mut ini_pair = initiator
        .into_session_pair()
        .expect("initiator session pair");
    let mut res_pair = responder
        .into_session_pair()
        .expect("responder session pair");

    let mut buf = [0u8; 128];
    let test_data = b"in-place packet payload over PQNoise transport session";
    buf[..test_data.len()].copy_from_slice(test_data);

    let sealed_len = ini_pair
        .send
        .seal_in_place(0, &mut buf, test_data.len())
        .expect("seal in place");

    let mut res_replay = ReplayWindow::new();
    let plain_len = res_pair
        .recv
        .open_in_place_with_window(0, &mut buf, sealed_len, &mut res_replay)
        .expect("open in place");
    assert_eq!(plain_len, test_data.len());
    assert_eq!(&buf[..plain_len], test_data);

    // Session-level 120s epoch rekey
    ini_pair.rekey();
    res_pair.rekey();
    assert_eq!(ini_pair.send_key(), &ini_send_rekey1);
    assert_eq!(ini_pair.recv_key(), &ini_recv_rekey1);
    assert_eq!(res_pair.send_key(), &res_send_rekey1);
    assert_eq!(res_pair.recv_key(), &res_recv_rekey1);

    // Data-plane communication succeeds on rekeyed epoch
    let post_rekey_data = b"epoch 1 rekeyed data payload";
    buf[..post_rekey_data.len()].copy_from_slice(post_rekey_data);

    let sealed_len2 = ini_pair
        .send
        .seal_in_place(0, &mut buf, post_rekey_data.len())
        .expect("seal after rekey");

    let mut res_replay2 = ReplayWindow::new();
    let plain_len2 = res_pair
        .recv
        .open_in_place_with_window(0, &mut buf, sealed_len2, &mut res_replay2)
        .expect("open after rekey");
    assert_eq!(plain_len2, post_rekey_data.len());
    assert_eq!(&buf[..plain_len2], post_rekey_data);

    // ── 8. Session Construction and Forward-Secrecy Ratchet ──────────────────
    let mut session_sender =
        Session::from_raw_keys(&ini_send, &ini_recv, 0, 1).expect("session creation from raw keys");
    let mut session_receiver =
        Session::from_raw_keys(&ini_recv, &ini_send, 0, 1).expect("session creation from raw keys");

    let frame = session_sender
        .seal(b"monotonic counter frame")
        .expect("seal");
    assert_eq!(frame.counter, 0);
    let decrypted = session_receiver
        .open(frame.counter, &frame.ciphertext)
        .expect("open");
    assert_eq!(decrypted, b"monotonic counter frame");

    session_sender.rekey();
    session_receiver.rekey();
    assert_eq!(session_sender.send_key(), &ini_send_rekey1);
    assert_eq!(session_receiver.recv_key(), &ini_send_rekey1);

    let frame2 = session_sender.seal(b"post session rekey").expect("seal");
    assert_eq!(frame2.counter, 1);
    let decrypted2 = session_receiver
        .open(frame2.counter, &frame2.ciphertext)
        .expect("open");
    assert_eq!(decrypted2, b"post session rekey");
}
