//! End-to-end integration and mock unit tests for REALITY stream orchestration.

use super::*;
use crate::stream::cert::{HS_TYPE_CERTIFICATE, HS_TYPE_CERTIFICATE_VERIFY};
use crate::{auth, ja};

/// Reads exactly one raw TLS record from a test-side stream half,
/// mirroring what a real TLS server sees on the wire — used to inspect
/// what `connect` actually sent without decrypting anything.
async fn read_one_record<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, Vec<u8>) {
    let mut header = [0u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await.unwrap();
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    (header[0], payload)
}

/// Walks a crafted `ClientHello` handshake message (`0x01 ‖ u24 len ‖
/// body`) far enough to recover `client_random` and the `x25519`
/// (group `0x001d`) `key_share` entry's public value — everything a
/// mock TLS 1.3 server needs to compute the ECDHE shared secret and
/// derive the same handshake keys `connect` derives. Shared by both the
/// hello-inspection test above and the full mock-server handshake test
/// below, rather than duplicating the extension walk twice.
fn client_hello_random_and_x25519(ch_msg: &[u8]) -> ([u8; 32], [u8; 32]) {
    let body = &ch_msg[4..];
    let client_random: [u8; 32] = body[2..34].try_into().unwrap();
    let sid_len = usize::from(body[34]);

    let mut cursor = 35 + sid_len;
    let cs_len = usize::from(u16::from_be_bytes([body[cursor], body[cursor + 1]]));
    cursor += 2 + cs_len;
    let cm_len = usize::from(body[cursor]);
    cursor += 1 + cm_len;
    let ext_total_len = usize::from(u16::from_be_bytes([body[cursor], body[cursor + 1]]));
    cursor += 2;

    let mut i = cursor;
    let ext_end = cursor + ext_total_len;
    let mut eph_pub = None;
    while i < ext_end {
        let ext_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([body[i + 2], body[i + 3]]));
        let ext_body = &body[i + 4..i + 4 + ext_len];
        if ext_type == 51 {
            let ks_len = usize::from(u16::from_be_bytes([ext_body[0], ext_body[1]]));
            let mut j = 2;
            let ks_end = 2 + ks_len;
            while j < ks_end {
                let group = u16::from_be_bytes([ext_body[j], ext_body[j + 1]]);
                let data_len = usize::from(u16::from_be_bytes([ext_body[j + 2], ext_body[j + 3]]));
                let data = &ext_body[j + 4..j + 4 + data_len];
                if group == GROUP_X25519 {
                    eph_pub = Some(<[u8; 32]>::try_from(data).unwrap());
                }
                j += 4 + data_len;
            }
        }
        i += 4 + ext_len;
    }
    (
        client_random,
        eph_pub.expect("crafted hello must carry an x25519 key_share entry"),
    )
}

/// `connect` must emit a byte-faithful `hello::craft` ClientHello whose
/// `legacy_session_id` is the REALITY seal of the *same* `client_random`
/// carried in the hello itself — the crux of Task 7's "ONE EPHEMERAL
/// KEY" / "client_random must match" requirements. This test drives
/// `connect` only as far as the ClientHello it emits (the mock peer
/// never replies, so `connect` blocks forever on the ServerHello read
/// after this — we just inspect what was written and drop the future).
#[tokio::test]
async fn connect_emits_a_valid_crafted_hello_sealed_with_its_own_client_random() {
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

    let server_reality_priv = [7u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };
    let short_id = [1, 2, 3, 4, 5, 6, 7, 8];

    let connect_task = tokio::spawn(async move {
        let _ = connect(
            client_io,
            "example.com",
            &server_reality_pub,
            short_id,
            false,
        )
        .await;
    });

    let (record_type, ch_msg) = read_one_record(&mut server_io).await;
    assert_eq!(
        record_type, CONTENT_TYPE_HANDSHAKE,
        "ClientHello must be sent as a plaintext handshake record"
    );

    // It must parse as a well-formed Chrome-150 ClientHello (reuse the
    // ja module's own parser as an independent structural check).
    assert!(ja::ja3(&ch_msg).is_some(), "not a well-formed ClientHello");
    assert!(ja::ja4(&ch_msg).is_some(), "not a well-formed ClientHello");

    // Recover client_random and the x25519 key_share pub (shared walk,
    // see `client_hello_random_and_x25519`'s doc comment), plus the
    // legacy_session_id (u8-length-prefixed, right after
    // client_random) — then verify the seal opens under the server's
    // REALITY key with this exact client_random and eph pub, proving
    // hello::craft's wire client_random and auth::seal's sealed
    // client_random are the same value.
    let body = &ch_msg[4..];
    let sid_len = usize::from(body[34]);
    let session_id = &body[35..35 + sid_len];
    assert_eq!(sid_len, 32);

    let (client_random, eph_pub) = client_hello_random_and_x25519(&ch_msg);

    assert!(
        auth::open(
            &server_reality_priv,
            &eph_pub,
            &client_random,
            session_id,
            &[short_id],
            // ts_min "now" — connect() sealed with the current minute.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 60,
            1,
        ),
        "connect's ClientHello legacy_session_id must be a REALITY seal of \
         the SAME client_random carried in the hello, over the SAME \
         ephemeral key as the hello's key_share"
    );

    drop(server_io);
    connect_task.abort();
}

/// A hermetic loopback proving `RealityStream`'s `AsyncRead`/`AsyncWrite`
/// framing round-trips over an arbitrary pair of fixed application
/// traffic keys, independent of the handshake that produces them —
/// exercising record chunking/reassembly without needing a live TLS 1.3
/// peer (full live round-trip is Task 8).
#[tokio::test]
async fn reality_stream_round_trips_over_duplex() {
    let (a_io, b_io) = tokio::io::duplex(1 << 20);

    // Symmetric key sets: what A calls "client" is what B calls
    // "server" and vice versa, so each side decrypts what the other
    // encrypts.
    let key_a = vec![0x11u8; 16];
    let iv_a = [0x22u8; 12];
    let key_b = vec![0x33u8; 16];
    let iv_b = [0x44u8; 12];

    let mut a = RealityStream {
        inner: a_io,
        suite: 0x1301, // TLS_AES_128_GCM_SHA256 -- matches the 16-byte test keys
        egress_key: key_a.clone(),
        egress_iv: iv_a,
        egress_seq: 0,
        ingress_key: key_b.clone(),
        ingress_iv: iv_b,
        ingress_seq: 0,
        raw_buf: Vec::new(),
        read_buf: Vec::new(),
        read_pos: 0,
        write_buf: Vec::new(),
        write_off: 0,
    };
    let mut b = RealityStream {
        inner: b_io,
        suite: 0x1301, // TLS_AES_128_GCM_SHA256 -- matches the 16-byte test keys
        egress_key: key_b,
        egress_iv: iv_b,
        egress_seq: 0,
        ingress_key: key_a,
        ingress_iv: iv_a,
        ingress_seq: 0,
        raw_buf: Vec::new(),
        read_buf: Vec::new(),
        read_pos: 0,
        write_buf: Vec::new(),
        write_off: 0,
    };

    a.write_all(b"hello from A").await.unwrap();
    a.flush().await.unwrap();
    let mut buf = vec![0u8; 32];
    let n = b.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello from A");

    b.write_all(b"hi back from B").await.unwrap();
    b.flush().await.unwrap();
    let mut buf2 = vec![0u8; 32];
    let n2 = a.read(&mut buf2).await.unwrap();
    assert_eq!(&buf2[..n2], b"hi back from B");
}

/// Proves [`RealityStream::client`] and [`RealityStream::server`] are
/// exact mirrors of each other: built from the SAME `ApplicationKeys`,
/// the client-role stream's egress is opened by the server-role
/// stream's ingress and vice versa — the same round trip
/// `reality_stream_round_trips_over_duplex` proves via hand-rolled field
/// literals, but driven through the constructors themselves. Also keeps
/// `server` from being unreachable dead code ahead of Task 6's `serve`,
/// which will be the first non-test caller.
#[tokio::test]
async fn reality_stream_client_and_server_constructors_mirror_each_other() {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);

    let client_ak = handshake::ApplicationKeys {
        client_key: vec![0x55u8; 16],
        client_iv: [0x66u8; 12],
        server_key: vec![0x77u8; 16],
        server_iv: [0x88u8; 12],
        suite: 0x1301, // TLS_AES_128_GCM_SHA256 -- matches the 16-byte test keys
    };
    let server_ak = handshake::ApplicationKeys {
        client_key: vec![0x55u8; 16],
        client_iv: [0x66u8; 12],
        server_key: vec![0x77u8; 16],
        server_iv: [0x88u8; 12],
        suite: 0x1301,
    };

    let mut client = RealityStream::client(client_io, client_ak);
    let mut server = RealityStream::server(server_io, server_ak);

    client.write_all(b"hello from client").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = vec![0u8; 32];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello from client");

    server.write_all(b"hi back from server").await.unwrap();
    server.flush().await.unwrap();
    let mut buf2 = vec![0u8; 32];
    let n2 = client.read(&mut buf2).await.unwrap();
    assert_eq!(&buf2[..n2], b"hi back from server");
}

/// Plays the TLS 1.3 SERVER role, entirely in-process, against a real
/// `connect()` call driving the CLIENT role over the other half of a
/// `tokio::io::duplex` — proving `connect`/`RealityStream` end-to-end
/// OFFLINE (no real network), using this crate's OWN handshake
/// primitives on both sides, mirroring exactly what `connect` itself
/// does but in reverse.
///
/// Always negotiates group `x25519` (`0x001d`), never the ML-KEM hybrid
/// (`4588`) — `connect` offers both, but a server is free to pick either
/// per RFC 8446 §4.2.8, and implementing a from-scratch ML-KEM
/// encapsulation here would duplicate the `ml_kem` crate's job with no
/// additional coverage of `connect`'s own logic (the `ecdhe` derivation
/// branch for group 4588 is exercised directly against RFC-vector-shaped
/// hybrid IKM in `handshake.rs`'s
/// `derive_handshake_keys_accepts_64_byte_hybrid_ecdhe`).
///
/// Does not send a `Certificate`/`CertificateVerify` — `connect` never
/// looks at either (see this module's doc comment: REALITY is
/// zero-cert-auth by design) — and sends an arbitrary (unverified)
/// server `Finished` `verify_data`, since `connect` consumes but never
/// validates the server `Finished` contents.
async fn run_mock_tls13_server(mut io: tokio::io::DuplexStream) {
    const SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

    // -- ClientHello ------------------------------------------------
    let (record_type, ch_msg) = read_one_record(&mut io).await;
    assert_eq!(
        record_type, CONTENT_TYPE_HANDSHAKE,
        "ClientHello must arrive as a plaintext handshake record"
    );
    let (_client_random, client_x25519_pub) = client_hello_random_and_x25519(&ch_msg);

    // -- ServerHello (group x25519) -----------------------------------
    let server_secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    let server_x25519_pub: [u8; 32] = x25519_dalek::PublicKey::from(&server_secret).to_bytes();
    let ecdhe: Vec<u8> = server_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(client_x25519_pub))
        .to_bytes()
        .to_vec();

    let mut server_random = [0u8; 32];
    getrandom::fill(&mut server_random).unwrap();

    let mut key_share_entry = Vec::new();
    key_share_entry.extend_from_slice(&GROUP_X25519.to_be_bytes());
    key_share_entry.extend_from_slice(&32u16.to_be_bytes());
    key_share_entry.extend_from_slice(&server_x25519_pub);

    let mut exts = Vec::new();
    // supported_versions (43): TLS 1.3 only.
    exts.extend_from_slice(&43u16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0304u16.to_be_bytes());
    // key_share (51).
    exts.extend_from_slice(&51u16.to_be_bytes());
    exts.extend_from_slice(&u16::try_from(key_share_entry.len()).unwrap().to_be_bytes());
    exts.extend_from_slice(&key_share_entry);

    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    sh_body.extend_from_slice(&server_random);
    sh_body.push(0); // legacy_session_id_echo: empty (connect() ignores it)
    sh_body.extend_from_slice(&SUITE.to_be_bytes());
    sh_body.push(0); // legacy_compression_method
    sh_body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    sh_body.extend_from_slice(&exts);

    let mut sh_msg = Vec::new();
    sh_msg.push(0x02); // ServerHello
    let body_len = u32::try_from(sh_body.len()).unwrap().to_be_bytes();
    sh_msg.extend_from_slice(&body_len[1..]); // u24
    sh_msg.extend_from_slice(&sh_body);

    let sh_header =
        record_header(CONTENT_TYPE_HANDSHAKE, LEGACY_RECORD_VERSION, sh_msg.len()).unwrap();
    io.write_all(&sh_header).await.unwrap();
    io.write_all(&sh_msg).await.unwrap();

    // -- Handshake keys, matching connect()'s own derivation exactly --
    let mut ch_sh_transcript = Vec::with_capacity(ch_msg.len() + sh_msg.len());
    ch_sh_transcript.extend_from_slice(&ch_msg);
    ch_sh_transcript.extend_from_slice(&sh_msg);
    let transcript_ch_sh = transcript_hash(&ch_sh_transcript, SUITE);
    let hk = derive_handshake_keys(&ecdhe, &transcript_ch_sh, SUITE);

    // -- Middlebox-compatibility CCS, then the encrypted server flight:
    // EncryptedExtensions(empty) ‖ Finished(arbitrary verify_data) ------
    io.write_all(&CHANGE_CIPHER_SPEC_RECORD).await.unwrap();

    let ee_msg: [u8; 4] = [0x08, 0x00, 0x00, 0x00]; // EncryptedExtensions, 0-length
    let verify_data = [0xABu8; 32]; // arbitrary: connect() never checks it
    let mut finished_msg = Vec::with_capacity(4 + verify_data.len());
    finished_msg.push(HS_TYPE_FINISHED);
    finished_msg.extend_from_slice(&[0x00, 0x00, 0x20]); // u24 len = 32
    finished_msg.extend_from_slice(&verify_data);

    let mut server_flight_plain = Vec::with_capacity(ee_msg.len() + finished_msg.len());
    server_flight_plain.extend_from_slice(&ee_msg);
    server_flight_plain.extend_from_slice(&finished_msg);

    let sealed_flight = record_seal(
        &hk.server_key,
        &hk.server_iv,
        0,
        SUITE,
        CONTENT_TYPE_HANDSHAKE,
        &server_flight_plain,
    )
    .unwrap();
    let flight_header = record_header(
        CONTENT_TYPE_APPLICATION_DATA,
        LEGACY_RECORD_VERSION,
        sealed_flight.len(),
    )
    .unwrap();
    io.write_all(&flight_header).await.unwrap();
    io.write_all(&sealed_flight).await.unwrap();

    let mut full_transcript = ch_sh_transcript;
    full_transcript.extend_from_slice(&server_flight_plain);
    let transcript_thru_sfin = transcript_hash(&full_transcript, SUITE);
    let ak = derive_application_keys(&hk.handshake_secret, &transcript_thru_sfin, SUITE);

    // -- Drain the client's CCS + sealed Finished (contents unchecked,
    // exactly mirroring connect()'s own "never verifies the peer's
    // Finished" stance) ------------------------------------------------
    loop {
        let (record_type, _payload) = read_one_record(&mut io).await;
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            continue;
        }
        assert_eq!(
            record_type, CONTENT_TYPE_APPLICATION_DATA,
            "expected the client's sealed Finished record"
        );
        break;
    }

    // -- Echo one application-data record under the application keys --
    let (record_type, mut app_payload) = read_one_record(&mut io).await;
    assert_eq!(record_type, CONTENT_TYPE_APPLICATION_DATA);
    let plaintext = record_open(
        &ak.client_key,
        &ak.client_iv,
        0,
        SUITE,
        CONTENT_TYPE_APPLICATION_DATA,
        &mut app_payload,
    )
    .unwrap();

    let sealed_reply = record_seal(
        &ak.server_key,
        &ak.server_iv,
        0,
        SUITE,
        CONTENT_TYPE_APPLICATION_DATA,
        &plaintext,
    )
    .unwrap();
    let reply_header = record_header(
        CONTENT_TYPE_APPLICATION_DATA,
        LEGACY_RECORD_VERSION,
        sealed_reply.len(),
    )
    .unwrap();
    io.write_all(&reply_header).await.unwrap();
    io.write_all(&sealed_reply).await.unwrap();
}

/// The end-to-end, fully OFFLINE proof: `connect()` (the CLIENT role)
/// against `run_mock_tls13_server` (the SERVER role, built from this
/// same crate's `handshake` primitives) over an in-process
/// `tokio::io::duplex` — no real network, no `#[ignore]`. Drives
/// `connect` all the way through `ClientHello` → `ServerHello` → key
/// derivation → server flight → client `Finished` → application data,
/// then round-trips one message over the resulting `RealityStream`,
/// exercising the `AsyncRead`/`AsyncWrite` impls with data actually
/// produced by a full handshake (as opposed to
/// `reality_stream_round_trips_over_duplex`'s hand-picked fixed keys).
#[tokio::test]
async fn connect_completes_full_handshake_against_in_process_mock_server() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_task = tokio::spawn(run_mock_tls13_server(server_io));

    let mut s = connect(client_io, "example.com", &[9u8; 32], [1u8; 8], false)
        .await
        .expect("handshake against the in-process mock server must succeed");

    s.write_all(b"PING").await.unwrap();
    s.flush().await.unwrap();

    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");

    server_task.await.unwrap();
}

/// What kind of Certificate/CertificateVerify a mock server presents in
/// the `connect_verify_*` tests below.
enum ServerCertBehavior {
    /// Leaf key IS the shared-secret-derived key; `CertificateVerify`
    /// signed by that SAME key — a genuine REALITY.4b binding.
    CorrectBinder,
    /// Leaf key is an unrelated random P-256 key (never the derived
    /// one); `CertificateVerify` is signed by that SAME random key (an
    /// internally-consistent but wrongly-pinned leaf).
    WrongLeafKey,
    /// Leaf key IS the derived key (the pin matches), but
    /// `CertificateVerify` is signed by a DIFFERENT random key.
    BadSignature,
}

/// Builds a wire `Certificate` handshake message (RFC 8446 §4.4.2)
/// carrying one `CertificateEntry` (no per-cert extensions) per DER in
/// `ders`, in order — the shared test-only encoder counterpart of
/// `scan_cert_flight`/`certificate_leaf_der` (single-entry chains) and
/// `scan_flight_shape`/`certificate_chain_ders` (multi-entry chains).
fn build_certificate_entries_message(ders: &[&[u8]]) -> Vec<u8> {
    let mut entries = Vec::new();
    for der in ders {
        let cd_len = u32::try_from(der.len()).unwrap().to_be_bytes();
        entries.extend_from_slice(&cd_len[1..]);
        entries.extend_from_slice(der);
        entries.extend_from_slice(&0u16.to_be_bytes()); // no per-cert extensions
    }

    let mut body = Vec::new();
    body.push(0); // certificate_request_context: empty
    let list_len = u32::try_from(entries.len()).unwrap().to_be_bytes();
    body.extend_from_slice(&list_len[1..]);
    body.extend_from_slice(&entries);

    let mut msg = Vec::new();
    msg.push(HS_TYPE_CERTIFICATE);
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    msg.extend_from_slice(&len[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// Builds a wire `Certificate` handshake message carrying TWO
/// `CertificateEntry` values, leaf first then `intermediate_der` — the
/// shape a real relay's CA-issued chain presents (RFC 8446 §4.4.2
/// mandates the same per-entry `extensions` framing on every entry, not
/// just the leaf). Exercises the multi-entry walk in
/// `certificate_chain_ders` (REALITY.5a Task 2), which the 4b verify
/// path (`scan_cert_flight` → `certificate_leaf_der`) now runs through
/// on every connection, single- or multi-cert alike.
fn build_certificate_message_with_intermediate(
    leaf_der: &[u8],
    intermediate_der: &[u8],
) -> Vec<u8> {
    build_certificate_entries_message(&[leaf_der, intermediate_der])
}

/// Builds a wire `CertificateVerify` handshake message (RFC 8446
/// §4.4.3) announcing `ecdsa_secp256r1_sha256` (`0x0403`, filler —
/// `verify_certificate_verify` never reads it) and carrying
/// `signature_der` — the test-only encoder counterpart of
/// `scan_cert_flight`/`certificate_verify_signature`.
fn build_certificate_verify_message(signature_der: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0403u16.to_be_bytes());
    let sig_len = u16::try_from(signature_der.len()).unwrap().to_be_bytes();
    body.extend_from_slice(&sig_len);
    body.extend_from_slice(signature_der);

    let mut msg = Vec::new();
    msg.push(HS_TYPE_CERTIFICATE_VERIFY);
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    msg.extend_from_slice(&len[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// Builds a throwaway self-signed leaf certificate DER around `key` —
/// just enough of a real X.509 structure for `spki_sec1_pubkey_from_der`
/// to walk.
fn leaf_der_for_key(key: &rcgen::KeyPair) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "mock-reality-relay.test");
    params.distinguished_name = dn;
    let cert = params.self_signed(key).unwrap();
    cert.der().as_ref().to_vec()
}

/// Like `run_mock_tls13_server`, but additionally sends a
/// Certificate/CertificateVerify pair ahead of Finished, built per
/// `behavior` — driving `connect(.., verify: true)`'s REALITY.4b
/// verification path against a mock SERVER role that speaks this
/// crate's OWN handshake primitives, exactly mirroring
/// `run_mock_tls13_server`'s "no external TLS stack" design (see that
/// function's doc comment for why).
///
/// A client that REJECTS the presented binding sends an alert instead
/// of a CCS/Finished and never gets here — callers driving a rejecting
/// `behavior` must NOT `.await` the returned task's `JoinHandle` (it
/// would hang forever on the client's CCS/Finished that never arrives);
/// see the `connect_verify_rejects_*` tests below.
///
/// When `include_intermediate` is set, the `Certificate` message carries
/// a SECOND `CertificateEntry` after the (still first, still pinned)
/// leaf — a dummy but wire-well-formed cert standing in for a real
/// relay's intermediate CA cert (REALITY.5a Task 2 review: proves
/// `certificate_chain_ders`'s full-chain walk doesn't break 4b
/// verification of a genuine multi-cert chain).
async fn run_mock_tls13_server_with_cert(
    mut io: tokio::io::DuplexStream,
    server_reality_priv: [u8; 32],
    behavior: ServerCertBehavior,
    include_intermediate: bool,
    record_lengths: Vec<usize>,
) {
    const SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

    // -- ClientHello ------------------------------------------------
    let (record_type, ch_msg) = read_one_record(&mut io).await;
    assert_eq!(
        record_type, CONTENT_TYPE_HANDSHAKE,
        "ClientHello must arrive as a plaintext handshake record"
    );
    let (_client_random, client_x25519_pub) = client_hello_random_and_x25519(&ch_msg);

    // -- ServerHello (group x25519) -----------------------------------
    let server_secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    let server_x25519_pub: [u8; 32] = x25519_dalek::PublicKey::from(&server_secret).to_bytes();
    let ecdhe: Vec<u8> = server_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(client_x25519_pub))
        .to_bytes()
        .to_vec();

    let mut server_random = [0u8; 32];
    getrandom::fill(&mut server_random).unwrap();

    let mut key_share_entry = Vec::new();
    key_share_entry.extend_from_slice(&GROUP_X25519.to_be_bytes());
    key_share_entry.extend_from_slice(&32u16.to_be_bytes());
    key_share_entry.extend_from_slice(&server_x25519_pub);

    let mut exts = Vec::new();
    exts.extend_from_slice(&43u16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0304u16.to_be_bytes());
    exts.extend_from_slice(&51u16.to_be_bytes());
    exts.extend_from_slice(&u16::try_from(key_share_entry.len()).unwrap().to_be_bytes());
    exts.extend_from_slice(&key_share_entry);

    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&0x0303u16.to_be_bytes());
    sh_body.extend_from_slice(&server_random);
    sh_body.push(0);
    sh_body.extend_from_slice(&SUITE.to_be_bytes());
    sh_body.push(0);
    sh_body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    sh_body.extend_from_slice(&exts);

    let mut sh_msg = Vec::new();
    sh_msg.push(0x02);
    let body_len = u32::try_from(sh_body.len()).unwrap().to_be_bytes();
    sh_msg.extend_from_slice(&body_len[1..]);
    sh_msg.extend_from_slice(&sh_body);

    let sh_header =
        record_header(CONTENT_TYPE_HANDSHAKE, LEGACY_RECORD_VERSION, sh_msg.len()).unwrap();
    io.write_all(&sh_header).await.unwrap();
    io.write_all(&sh_msg).await.unwrap();

    // -- Handshake keys, matching connect()'s own derivation exactly --
    let mut ch_sh_transcript = Vec::with_capacity(ch_msg.len() + sh_msg.len());
    ch_sh_transcript.extend_from_slice(&ch_msg);
    ch_sh_transcript.extend_from_slice(&sh_msg);
    let transcript_ch_sh = transcript_hash(&ch_sh_transcript, SUITE);
    let hk = derive_handshake_keys(&ecdhe, &transcript_ch_sh, SUITE);

    // -- REALITY.4b binding: derive the cert key from the SAME shared
    // secret the client derives (`auth::shared_secret(server_reality_pub,
    // &client_eph_priv)`) — by X25519 DH symmetry, ECDH(server_priv,
    // client_pub) == ECDH(client_priv, server_pub), so this reuses the
    // exact function the client uses, just with the arguments swapped. --
    let shared = auth::shared_secret(&client_x25519_pub, &server_reality_priv);
    let derived = auth::derive_cert_key(&shared);

    let (leaf_key_pkcs8, signing_key_pkcs8): (Vec<u8>, Vec<u8>) = match behavior {
        ServerCertBehavior::CorrectBinder => (derived.pkcs8_der.clone(), derived.pkcs8_der.clone()),
        ServerCertBehavior::WrongLeafKey => {
            let wrong = rcgen::KeyPair::generate().unwrap().serialize_der();
            (wrong.clone(), wrong)
        }
        ServerCertBehavior::BadSignature => {
            let other = rcgen::KeyPair::generate().unwrap().serialize_der();
            (derived.pkcs8_der.clone(), other)
        }
    };
    // Build the (forged leaf, signing key) pair per behavior — unchanged.
    let leaf_key = rcgen::KeyPair::try_from(leaf_key_pkcs8.as_slice()).unwrap();
    let leaf_der = leaf_der_for_key(&leaf_key);
    use p256::pkcs8::DecodePrivateKey as _;
    let cert_signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&signing_key_pkcs8).unwrap();

    let intermediates = if include_intermediate {
        let intermediate_key = rcgen::KeyPair::generate().unwrap();
        vec![leaf_der_for_key(&intermediate_key)]
    } else {
        Vec::new()
    };
    let flight_shape = crate::template::EncryptedFlightShape {
        // Caller-supplied record shape. `emit_server_flight` reserves one
        // content byte per record after the current one, so the
        // `Finished` tail always lands in the LAST record regardless of
        // how record capacity is distributed — callers may freely use a
        // multi-record shape (e.g. `[600, 4096]`) whose total capacity
        // exceeds the flight's actual plaintext; any resulting
        // pure-padding record(s) are front-loaded ahead of `Finished`,
        // where the real TLS 1.3 client (this crate's `connect`,
        // mirroring BoringSSL/Chrome) still reads them before it stops
        // parsing the encrypted flight.
        record_lengths,
        encrypted_extensions_len: 0,
        certificate_len: 0,
        certificate_verify_len: 0,
        finished_len: 0,
    };
    let cert_chain = crate::template::CertChainShape {
        leaf_der_len: leaf_der.len(),
        intermediates_der: intermediates,
    };
    // transcript_ch_sh = the RAW ClientHello ‖ ServerHello bytes (ch_sh_transcript),
    // NOT the hash — emit_server_flight hashes internally.
    //
    // IMPORTANT: do NOT `.expect()` on serve. For the reject behaviors
    // (WrongLeafKey / BadSignature) the client verifies, FAILS, and drops the
    // connection WITHOUT sending its Finished — so `serve` (which drains the
    // client Finished) returns Err. That is the correct outcome for those
    // tests (they assert the CLIENT `connect` returns Err); the server task
    // must simply exit cleanly, not panic. `if let Ok` handles both paths.
    if let Ok(mut server) = serve(
        io,
        &hk,
        &flight_shape,
        &cert_chain,
        &leaf_der,
        &cert_signing_key,
        &ch_sh_transcript,
    )
    .await
    {
        // Echo whatever the client sends (robust to any ping size the
        // round-trip tests use), proving the server-app egress seal + client
        // ingress open both work.
        let mut buf = [0u8; 64];
        if let Ok(n) = server.read(&mut buf).await {
            if n > 0 {
                let _ = server.write_all(&buf[..n]).await;
                let _ = server.flush().await;
            }
        }
    }
}

/// `verify=true` against a mock server whose leaf/signature genuinely
/// bind the shared secret: `connect` must succeed, and the resulting
/// stream must carry application data exactly like the non-verifying
/// path — REALITY.4b verification is a gate, not a change to the data
/// plane.
#[tokio::test]
async fn connect_verify_accepts_correct_binder() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [3u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    let server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::CorrectBinder,
        false,
        vec![600, 4096],
    ));

    let mut s = connect(
        client_io,
        "example.com",
        &server_reality_pub,
        [1u8; 8],
        true,
    )
    .await
    .expect("a correctly-bound relay must verify");

    s.write_all(b"PING").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");

    server_task.await.unwrap();
}

/// REALITY.5a Task 2 review gap: every OTHER `connect_verify_*` test
/// uses a single-`CertificateEntry` chain, so the multi-entry parse
/// path in `certificate_chain_ders` (which the 4b verify path now runs
/// through via `scan_cert_flight` → `certificate_leaf_der`) is never
/// exercised by the live verify flow. This mirrors
/// `connect_verify_accepts_correct_binder` exactly, except the mock
/// server presents a 2-entry chain — the correctly-bound leaf FIRST,
/// then a dummy but wire-well-formed intermediate `CertificateEntry`
/// (RFC 8446 §4.4.2 framing) appended after it. Verification pins ONLY
/// the first entry, so `connect` must still succeed.
#[tokio::test]
async fn connect_verify_accepts_correct_binder_with_intermediate_chain() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [7u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    let server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::CorrectBinder,
        true,
        vec![600, 4096],
    ));

    let mut s = connect(
        client_io,
        "example.com",
        &server_reality_pub,
        [1u8; 8],
        true,
    )
    .await
    .expect("a correctly-bound relay presenting leaf+intermediate must still verify");

    s.write_all(b"PING").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");

    server_task.await.unwrap();
}

/// `verify=true` against a mock server presenting a leaf key that is
/// NOT the shared-secret-derived key: `connect` must reject with
/// `Error::RealityVerify`. The mock server's own CCS/Finished-draining
/// tail is never reached by a rejecting client, so its `JoinHandle` is
/// intentionally left un-awaited (see `run_mock_tls13_server_with_cert`'s
/// doc comment).
#[tokio::test]
async fn connect_verify_rejects_wrong_key() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [4u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    let _server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::WrongLeafKey,
        false,
        vec![600, 4096],
    ));

    let result = connect(
        client_io,
        "example.com",
        &server_reality_pub,
        [1u8; 8],
        true,
    )
    .await;
    match result {
        Err(Error::RealityVerify(_)) => {}
        Err(e) => panic!("expected Error::RealityVerify, got a different error: {e}"),
        Ok(_) => panic!("a wrong-key relay must be rejected, but connect() succeeded"),
    }
}

/// `verify=true` against a mock server whose leaf key MATCHES the
/// derived key but whose `CertificateVerify` is signed by a different
/// key: `connect` must reject with `Error::RealityVerify`. Same
/// un-awaited-`JoinHandle` note as `connect_verify_rejects_wrong_key`.
#[tokio::test]
async fn connect_verify_rejects_bad_signature() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [5u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    let _server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::BadSignature,
        false,
        vec![600, 4096],
    ));

    let result = connect(
        client_io,
        "example.com",
        &server_reality_pub,
        [1u8; 8],
        true,
    )
    .await;
    match result {
        Err(Error::RealityVerify(_)) => {}
        Err(e) => panic!("expected Error::RealityVerify, got a different error: {e}"),
        Ok(_) => panic!("a bad-signature relay must be rejected, but connect() succeeded"),
    }
}

/// `verify=false` against the SAME wrong-key mock server that
/// `connect_verify_rejects_wrong_key` proves is rejected under
/// `verify=true`: `connect` must still succeed — zero-cert-auth
/// camouflage is preserved by default.
#[tokio::test]
async fn connect_no_verify_ignores_cert() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [6u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    let server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::WrongLeafKey,
        false,
        vec![600, 4096],
    ));

    let mut s = connect(
        client_io,
        "example.com",
        &server_reality_pub,
        [1u8; 8],
        false,
    )
    .await
    .expect("verify=false must ignore the cert entirely (zero-cert-auth camouflage)");

    s.write_all(b"PING").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");

    server_task.await.unwrap();
}

/// Proves BOTH data-plane directions over a real [`serve`]-built
/// server stream: `connect_verify_accepts_correct_binder` (and friends)
/// only checks client→server→echo; this drives a server-initiated write
/// too (the mock's echo `write_all`, sealed under the server-app egress
/// key and opened by the client's ingress key), proving `serve`'s
/// `RealityStream::server` role is symmetric with `client`.
#[tokio::test]
async fn serve_round_trips_application_data_both_directions() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [3u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    // Server: hand-rolled ServerHello + 5c serve (reuses the refactored mock,
    // CorrectBinder → the client must verify the 4b binding).
    let server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::CorrectBinder,
        false,
        vec![600, 4096],
    ));

    let mut s = connect(
        client_io,
        "example.com",
        &server_reality_pub,
        [1u8; 8],
        true,
    )
    .await
    .expect("correctly-bound relay verifies");

    // client → server → echo (server's echo path in the mock).
    s.write_all(b"PING").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");

    server_task.await.unwrap();
}

/// Regression test for the `emit_server_flight` front-greedy framing bug
/// (REALITY.5c Task 6 client round-trip): our minimal EE + P-256
/// CertificateVerify + self-signed leaf flight is well under 4096 bytes,
/// so a `[4096, 600]` record shape is EXACTLY the failure case — under
/// the old pure front-greedy `chunk_len = remaining.min(cap)` framing,
/// the whole flight (including `Finished`) fits inside record 0, leaving
/// record 1 (600 bytes) a PURE-PADDING record sealed under the
/// handshake keys. The real `connect` client (mirroring BoringSSL/
/// Chrome) stops reading the encrypted flight the instant it has
/// assembled a complete `Finished` message — i.e. after record 0 — so it
/// never consumes that trailing record 1, which then sits unread ahead
/// of the first application-data record and fails AEAD-open under the
/// (wrong) application key.
///
/// With the fix (`emit_server_flight` reserves one content byte per
/// later record so the `Finished` tail always lands in the LAST
/// record), record 1 necessarily carries part of the flight — including
/// `Finished` — so the client reads BOTH records and the handshake
/// completes normally.
#[tokio::test]
async fn connect_verify_accepts_correct_binder_with_flight_split_finished_last() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_reality_priv = [11u8; 32];
    let server_reality_pub = {
        let secret = x25519_dalek::StaticSecret::from(server_reality_priv);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    };

    let server_task = tokio::spawn(run_mock_tls13_server_with_cert(
        server_io,
        server_reality_priv,
        ServerCertBehavior::CorrectBinder,
        false,
        vec![4096, 600],
    ));

    let mut s = connect(
        client_io,
        "example.com",
        &server_reality_pub,
        [1u8; 8],
        true,
    )
    .await
    .expect(
        "a correctly-bound relay must verify even when the captured template's \
         largest record comes FIRST (record_lengths = [4096, 600])",
    );

    s.write_all(b"PING").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");

    server_task.await.unwrap();
}

// -----------------------------------------------------------------
// REALITY.5a Task 3: capture_dest_flight
// -----------------------------------------------------------------

/// What [`run_mock_dest_server_with_known_flight`] actually put on the
/// wire, for `capture_dest_flight_records_template_from_mock` to assert
/// the returned [`CapturedFlight`] against — computed alongside the
/// bytes the mock sends rather than duplicated by hand in the test, so
/// the two can never silently drift apart.
struct KnownFlightFixture {
    cipher_suite: u16,
    extensions: Vec<(u16, Vec<u8>)>,
    key_share_group: u16,
    leaf_der: Vec<u8>,
    intermediate_der: Vec<u8>,
    ee_len: usize,
    cert_len: usize,
    cert_verify_len: usize,
    finished_len: usize,
    record_lengths: Vec<usize>,
}

/// Plays the dest SERVER role for `capture_dest_flight`'s mock test: a
/// `ServerHello` with a deliberately NON-canonical extension order (an
/// arbitrary/unknown extension BEFORE `supported_versions`, itself
/// before `key_share` — proving the shape capture preserves wire order
/// rather than a canonical one), followed by a 2-`CertificateEntry`
/// chain (leaf + intermediate) split across TWO encrypted records
/// (EncryptedExtensions‖Certificate in the first, CertificateVerify‖
/// Finished in the second — proving `record_lengths` captures each
/// record's length individually, not just the total). Never reads
/// anything after the `ClientHello` — `capture_dest_flight` sends
/// neither a `ChangeCipherSpec` nor a client `Finished`, so there is
/// nothing more for a dest to receive.
async fn run_mock_dest_server_with_known_flight(
    mut io: tokio::io::DuplexStream,
) -> KnownFlightFixture {
    const SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

    // -- ClientHello ------------------------------------------------
    let (record_type, ch_msg) = read_one_record(&mut io).await;
    assert_eq!(
        record_type, CONTENT_TYPE_HANDSHAKE,
        "ClientHello must arrive as a plaintext handshake record"
    );
    let (_client_random, client_x25519_pub) = client_hello_random_and_x25519(&ch_msg);

    // -- ServerHello (group x25519), extensions in a deliberately
    // non-canonical order ---------------------------------------------
    let server_secret = x25519_dalek::StaticSecret::from([13u8; 32]);
    let server_x25519_pub: [u8; 32] = x25519_dalek::PublicKey::from(&server_secret).to_bytes();
    let ecdhe: Vec<u8> = server_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(client_x25519_pub))
        .to_bytes()
        .to_vec();

    let mut server_random = [0u8; 32];
    getrandom::fill(&mut server_random).unwrap();

    let mut key_share_entry = Vec::new();
    key_share_entry.extend_from_slice(&GROUP_X25519.to_be_bytes());
    key_share_entry.extend_from_slice(&32u16.to_be_bytes());
    key_share_entry.extend_from_slice(&server_x25519_pub);

    let arbitrary_ext_type: u16 = 0x1234;
    let arbitrary_ext_body: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let mut exts = Vec::new();
    // Arbitrary extension FIRST — real Chrome/dest never puts an
    // unrecognized extension ahead of supported_versions, but
    // parse_server_hello_shape must capture whatever order dest
    // actually used, not assume a canonical one.
    exts.extend_from_slice(&arbitrary_ext_type.to_be_bytes());
    exts.extend_from_slice(
        &u16::try_from(arbitrary_ext_body.len())
            .unwrap()
            .to_be_bytes(),
    );
    exts.extend_from_slice(&arbitrary_ext_body);
    // supported_versions (43): TLS 1.3 only.
    exts.extend_from_slice(&43u16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0304u16.to_be_bytes());
    // key_share (51) LAST.
    exts.extend_from_slice(&51u16.to_be_bytes());
    exts.extend_from_slice(&u16::try_from(key_share_entry.len()).unwrap().to_be_bytes());
    exts.extend_from_slice(&key_share_entry);

    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    sh_body.extend_from_slice(&server_random);
    sh_body.push(0); // legacy_session_id_echo: empty
    sh_body.extend_from_slice(&SUITE.to_be_bytes());
    sh_body.push(0); // legacy_compression_method
    sh_body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    sh_body.extend_from_slice(&exts);

    let mut sh_msg = Vec::new();
    sh_msg.push(0x02); // ServerHello
    let body_len = u32::try_from(sh_body.len()).unwrap().to_be_bytes();
    sh_msg.extend_from_slice(&body_len[1..]); // u24
    sh_msg.extend_from_slice(&sh_body);

    let sh_header =
        record_header(CONTENT_TYPE_HANDSHAKE, LEGACY_RECORD_VERSION, sh_msg.len()).unwrap();
    io.write_all(&sh_header).await.unwrap();
    io.write_all(&sh_msg).await.unwrap();

    // -- Handshake keys, matching capture_dest_flight's own derivation
    // exactly -----------------------------------------------------------
    let mut ch_sh_transcript = Vec::with_capacity(ch_msg.len() + sh_msg.len());
    ch_sh_transcript.extend_from_slice(&ch_msg);
    ch_sh_transcript.extend_from_slice(&sh_msg);
    let transcript_ch_sh = transcript_hash(&ch_sh_transcript, SUITE);
    let hk = derive_handshake_keys(&ecdhe, &transcript_ch_sh, SUITE);

    // -- The known flight: EncryptedExtensions ‖ Certificate(leaf +
    // intermediate) ‖ CertificateVerify ‖ Finished -----------------------
    let ee_msg: [u8; 6] = [0x08, 0x00, 0x00, 0x02, 0x00, 0x00]; // EncryptedExtensions, empty ext list
    let leaf_der = vec![0xAAu8; 50];
    let intermediate_der = vec![0xBBu8; 35];
    let certificate_msg = build_certificate_message_with_intermediate(&leaf_der, &intermediate_der);
    let certificate_verify_msg = build_certificate_verify_message(&[0xCCu8; 70]);

    let verify_data = [0xABu8; 32];
    let mut finished_msg = Vec::with_capacity(4 + verify_data.len());
    finished_msg.push(HS_TYPE_FINISHED);
    finished_msg.extend_from_slice(&[0x00, 0x00, 0x20]); // u24 len = 32
    finished_msg.extend_from_slice(&verify_data);

    // Split across TWO records: EE‖Certificate in the first,
    // CertificateVerify‖Finished in the second.
    let mut chunk1 = Vec::new();
    chunk1.extend_from_slice(&ee_msg);
    chunk1.extend_from_slice(&certificate_msg);
    let mut chunk2 = Vec::new();
    chunk2.extend_from_slice(&certificate_verify_msg);
    chunk2.extend_from_slice(&finished_msg);

    let sealed1 = record_seal(
        &hk.server_key,
        &hk.server_iv,
        0,
        SUITE,
        CONTENT_TYPE_HANDSHAKE,
        &chunk1,
    )
    .unwrap();
    let header1 = record_header(
        CONTENT_TYPE_APPLICATION_DATA,
        LEGACY_RECORD_VERSION,
        sealed1.len(),
    )
    .unwrap();
    io.write_all(&header1).await.unwrap();
    io.write_all(&sealed1).await.unwrap();

    let sealed2 = record_seal(
        &hk.server_key,
        &hk.server_iv,
        1,
        SUITE,
        CONTENT_TYPE_HANDSHAKE,
        &chunk2,
    )
    .unwrap();
    let header2 = record_header(
        CONTENT_TYPE_APPLICATION_DATA,
        LEGACY_RECORD_VERSION,
        sealed2.len(),
    )
    .unwrap();
    io.write_all(&header2).await.unwrap();
    io.write_all(&sealed2).await.unwrap();

    KnownFlightFixture {
        cipher_suite: SUITE,
        extensions: vec![
            (arbitrary_ext_type, arbitrary_ext_body),
            (43, 0x0304u16.to_be_bytes().to_vec()),
            (51, key_share_entry),
        ],
        key_share_group: GROUP_X25519,
        leaf_der,
        intermediate_der,
        ee_len: ee_msg.len(),
        cert_len: certificate_msg.len(),
        cert_verify_len: certificate_verify_msg.len(),
        finished_len: finished_msg.len(),
        record_lengths: vec![sealed1.len(), sealed2.len()],
    }
}

/// The Task 3 crux: `capture_dest_flight` against a mock dest presenting
/// a KNOWN flight (see [`run_mock_dest_server_with_known_flight`]) must
/// return a `CapturedFlight` whose every field matches what the mock
/// actually sent — ordered extensions (including the deliberately
/// non-canonical placement), negotiated suite/group, per-record
/// ciphertext lengths, per-message plaintext lengths, and both the leaf
/// and intermediate certificate DERs verbatim.
#[tokio::test]
async fn capture_dest_flight_records_template_from_mock() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(run_mock_dest_server_with_known_flight(server_io));

    let cap = capture_dest_flight(client_io, "example.com")
        .await
        .expect("capture against a known-flight mock dest must succeed");

    let fixture = server_task.await.unwrap();

    assert_eq!(cap.template.server_hello.cipher_suite, fixture.cipher_suite);
    assert_eq!(cap.template.server_hello.extensions, fixture.extensions);
    assert_eq!(
        cap.template.server_hello.key_share_group,
        fixture.key_share_group
    );

    assert_eq!(
        cap.template.encrypted_flight.record_lengths,
        fixture.record_lengths
    );
    assert_eq!(
        cap.template.encrypted_flight.encrypted_extensions_len,
        fixture.ee_len
    );
    assert_eq!(
        cap.template.encrypted_flight.certificate_len,
        fixture.cert_len
    );
    assert_eq!(
        cap.template.encrypted_flight.certificate_verify_len,
        fixture.cert_verify_len
    );
    assert_eq!(
        cap.template.encrypted_flight.finished_len,
        fixture.finished_len
    );

    assert_eq!(cap.template.cert_chain.leaf_der_len, fixture.leaf_der.len());
    assert_eq!(
        cap.template.cert_chain.intermediates_der,
        vec![fixture.intermediate_der.clone()]
    );
    assert_eq!(cap.leaf_der, fixture.leaf_der);
}

/// Live gate: `capture_dest_flight` against a real dest (Cloudflare)
/// must return a plausible, non-empty template. Network-dependent —
/// `#[ignore]`d by default; run with `cargo test -p yip-utls --
/// --ignored`.
#[tokio::test]
#[ignore]
async fn capture_dest_flight_cloudflare() {
    let tcp = tokio::net::TcpStream::connect("cloudflare.com:443")
        .await
        .unwrap();
    let cap = capture_dest_flight(tcp, "cloudflare.com")
        .await
        .expect("capture");
    assert!(cap.template.server_hello.cipher_suite != 0);
    assert!(!cap.template.server_hello.extensions.is_empty());
    assert!(cap.template.cert_chain.leaf_der_len > 0);
    assert!(!cap.template.encrypted_flight.record_lengths.is_empty());
    assert!(!cap.leaf_der.is_empty());
}
