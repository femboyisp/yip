//! Per-connection TLS handling for the relay Trojan front (3c.3): classify the
//! first framed message, then either upgrade to a relay tunnel or hand off to
//! the decoy. No `unsafe`; all TLS/socket work is via tokio-boring / tokio.
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use yip_rendezvous::{decode, Message, NodeId, RendezvousServer};

use crate::tls_front::TlsFrontCfg;
use crate::TLS_FRAME_CAP as MAX_FIRST_FRAME;

/// Result of inspecting a connection's first framed message.
pub enum Classify {
    /// A valid, fresh Register from a client that knows `obf_psk`. `reply` is
    /// the framed obfuscated response to write back before entering the pump.
    Upgrade { node: NodeId, reply: Vec<u8> },
    /// Anything else — proxy this connection to the decoy backend.
    Decoy,
}

/// Pure classification of the first frame. De-frames `[u16 len][obf env]`,
/// deobfuscates with `obf_key` (requiring RDV_TYPE), decodes, and:
/// - In rooted mesh mode (`server.roots_cfg().is_some()`): requires a verified
///   `Message::RegisterSigned` (cert chain and signature verified against roots,
///   sequence within wall-clock bounds, and fresh on the TLS path). Rejects bare
///   `Register` as decoy.
/// - In rootless mode (`server.roots_cfg().is_none()`): accepts a fresh
///   `Message::Register` as before.
pub fn classify_first_frame(
    buf: &[u8],
    obf_key: &[u8; 16],
    server: &mut RendezvousServer,
    now_ms: u64,
) -> Classify {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    classify_first_frame_at(buf, obf_key, server, now_ms, now_secs)
}

/// Pure classification with explicit wall-clock `now_secs` for testing.
pub fn classify_first_frame_at(
    buf: &[u8],
    obf_key: &[u8; 16],
    server: &mut RendezvousServer,
    now_ms: u64,
    now_secs: u64,
) -> Classify {
    // Length prefix present and plausible?
    let Some(len_bytes) = buf.get(..2) else {
        return Classify::Decoy;
    };
    let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    if len == 0 || len > MAX_FIRST_FRAME {
        return Classify::Decoy;
    }
    let Some(env) = buf.get(2..2 + len) else {
        return Classify::Decoy;
    };
    // Deobfuscate; require the rendezvous packet type.
    let Some((ptype, body)) = yip_obf::deobfuscate(obf_key, env) else {
        return Classify::Decoy;
    };
    if ptype != yip_obf::RDV_TYPE {
        return Classify::Decoy;
    }
    let Some(msg) = decode(&body) else {
        return Classify::Decoy;
    };
    if server.roots_cfg().is_some() {
        // Rooted mode: reject bare Register, require verified RegisterSigned.
        let Message::RegisterSigned { record } = msg else {
            return Classify::Decoy;
        };
        if !server.verify_signed_record(&record, now_secs) {
            return Classify::Decoy;
        }
        if !server.register_if_fresh_tls(record.node_id, record.seq, now_ms) {
            return Classify::Decoy;
        }
        let reply = crate::frame_obf(
            obf_key,
            &Message::RegisterSigned {
                record: record.clone(),
            },
        );
        Classify::Upgrade {
            node: record.node_id,
            reply,
        }
    } else {
        // Rootless mode: accept bare Register.
        let Message::Register { node, counter } = msg else {
            return Classify::Decoy;
        };
        if !server.register_if_fresh_tls(node, counter, now_ms) {
            return Classify::Decoy;
        }
        let reply = crate::frame_obf(obf_key, &Message::Register { node, counter });
        Classify::Upgrade { node, reply }
    }
}

/// Short budget to decide tunnel-vs-decoy. NOT a connection lifetime: on the
/// decoy path we hand the stream to the backend and let ITS idle timeout
/// govern, so this classification window is never an observable close signature.
const CLASSIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Trial-read the first frame off a freshly-TLS-terminated connection and
/// route it: a fresh obfuscated Register upgrades to the relay tunnel;
/// anything else (a censor probe, a browser, garbage, silence) is
/// transparently reverse-proxied to the decoy backend, so the relay looks
/// like an ordinary web server to everyone but a real yip client.
pub async fn handle_connection<St>(mut stream: St, cfg: Arc<TlsFrontCfg>)
where
    St: AsyncRead + AsyncWrite + Unpin + Send,
{
    let now_ms = u64::try_from(cfg.base.elapsed().as_millis()).unwrap_or(u64::MAX);
    // The relay is blind to the real TCP peer identity, and the TLS-only
    // freshness gate (`register_if_fresh_tls`) no longer needs a source addr
    // (I4) — there is nothing left to key on this path.

    let mut buf = Vec::new();
    let (decision, backend_stream) = {
        let classify_fut = read_and_classify(&mut stream, &cfg, &mut buf, now_ms);
        tokio::pin!(classify_fut);

        if let Some(decoy_addr) = cfg.decoy.filter(|_| cfg.reality.is_none()) {
            let decoy_fut = TcpStream::connect(decoy_addr);
            tokio::pin!(decoy_fut);
            let mut backend_conn = None;
            let decision = loop {
                tokio::select! {
                    biased;
                    d = &mut classify_fut => {
                        break d;
                    }
                    res = &mut decoy_fut, if backend_conn.is_none() => {
                        backend_conn = Some(res);
                    }
                }
            };

            let backend = match decision {
                Some(Classify::Upgrade { .. }) => None,
                _ => match backend_conn {
                    Some(res) => res.ok(),
                    None => decoy_fut.await.ok(),
                },
            };
            (decision, backend)
        } else {
            (classify_fut.await, None)
        }
    };

    match decision {
        Some(Classify::Upgrade { node, reply }) => {
            if stream.write_all(&reply).await.is_err() {
                return;
            }
            // Hand any bytes read past the first frame to the tunnel
            // (pipelined frames in the same TLS read must not be lost). The
            // first frame's length prefix is buf[0..2]; it consumed
            // 2+len bytes.
            let consumed = 2 + usize::from(u16::from_be_bytes([buf[0], buf[1]]));
            let prefix = if buf.len() > consumed {
                buf.split_off(consumed)
            } else {
                Vec::new()
            };
            super::conn_tunnel::run_tunnel(stream, cfg, node, prefix).await;
        }
        _ => {
            if cfg.reality.is_some() {
                // REALITY authed path: this connection already passed the seal
                // check, so only a key-holding own-peer with a malformed inner
                // frame reaches here. Do NOT proxy (spec §3) — reject generically.
                reality_reject(stream).await;
            } else if let Some(backend) = backend_stream {
                into_decoy_with_stream(stream, &cfg, buf, backend).await;
            } else {
                into_decoy(stream, &cfg, buf).await;
            }
        }
    }
}

/// REALITY authed-but-inner-fail response (spec §3): a minimal generic error,
/// then shut the write half (which flushes a TLS close_notify on an SslStream).
/// Best-effort behavior parity with a real origin rejecting a bad request —
/// NOT a bare RST, and NOT a proxy of decrypted bytes to dest (see spec §3).
async fn reality_reject<S>(mut stream: S)
where
    S: AsyncWrite + Unpin,
{
    const BODY: &[u8] = b"<!doctype html><title>400</title>";
    let header = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    let mut msg = header.into_bytes();
    msg.extend_from_slice(BODY);
    let _ = stream.write_all(&msg).await;
    let _ = stream.shutdown().await; // close_notify on SslStream
}

/// Read the first frame (up to CLASSIFY_TIMEOUT) and classify it. Returns
/// `None` on idle-timeout/read-error (caller treats as decoy). All bytes read
/// are accumulated in `buf` so they can be replayed to the decoy.
async fn read_and_classify<St>(
    stream: &mut St,
    cfg: &TlsFrontCfg,
    buf: &mut Vec<u8>,
    now_ms: u64,
) -> Option<Classify>
where
    St: AsyncRead + AsyncWrite + Unpin + Send,
{
    let deadline = tokio::time::sleep(CLASSIFY_TIMEOUT);
    tokio::pin!(deadline);
    let mut chunk = [0u8; 2048];
    loop {
        // Enough to read the length prefix and the full framed body?
        if buf.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
            if len > 0 && len <= MAX_FIRST_FRAME && buf.len() >= 2 + len {
                let mut server = cfg.server.lock().await;
                return Some(classify_first_frame(buf, &cfg.obf_key, &mut server, now_ms));
            }
            if len == 0 || len > MAX_FIRST_FRAME {
                return Some(Classify::Decoy); // implausible length ⇒ decoy now
            }
        }
        tokio::select! {
            _ = &mut deadline => return None, // idle ⇒ decoy (empty/partial buf)
            r = stream.read(&mut chunk) => match r {
                Ok(0) => return Some(Classify::Decoy), // peer closed
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return Some(Classify::Decoy),
            },
        }
    }
}

/// Proxy this connection to the decoy backend: replay the buffered bytes, then
/// splice bidirectionally. The decoy's own behavior/timing governs from here.
pub(crate) async fn into_decoy<St>(mut stream: St, cfg: &TlsFrontCfg, buffered: Vec<u8>)
where
    St: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Some(decoy_addr) = cfg.decoy else {
        // No decoy configured: minimal static fallback (documented weaker
        // path). The Content-Length is computed from the actual body bytes
        // so the two can never drift out of sync — a mismatched
        // Content-Length is itself a DPI fingerprint (M5).
        const FALLBACK_BODY: &[u8] = b"<!doctype html><title>OK</title><p>OK</p>";
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            FALLBACK_BODY.len()
        );
        let mut page = header.into_bytes();
        page.extend_from_slice(FALLBACK_BODY);
        let _ = stream.write_all(&page).await;
        return;
    };
    let Ok(backend) = TcpStream::connect(decoy_addr).await else {
        return;
    };
    into_decoy_with_stream(stream, cfg, buffered, backend).await;
}

pub(crate) async fn into_decoy_with_stream<St>(
    mut stream: St,
    _cfg: &TlsFrontCfg,
    buffered: Vec<u8>,
    mut backend: TcpStream,
) where
    St: AsyncRead + AsyncWrite + Unpin + Send,
{
    if !buffered.is_empty() && backend.write_all(&buffered).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut backend).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use yip_rendezvous::{encode, node_id, Message};

    fn framed_register(obf_key: &[u8; 16], node: yip_rendezvous::NodeId, counter: u64) -> Vec<u8> {
        let mut plain = Vec::new();
        encode(&Message::Register { node, counter }, &mut plain);
        let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0)
            .expect("small test body fits u16");
        let mut framed = Vec::new();
        framed.extend_from_slice(&u16::try_from(env.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(&env);
        framed
    }

    #[test]
    fn fresh_register_upgrades() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let frame = framed_register(&key, node, 1);
        match classify_first_frame(&frame, &key, &mut s, 0) {
            Classify::Upgrade { node: got, reply } => {
                assert_eq!(got, node);
                assert!(!reply.is_empty());
                // The TLS-only freshness state (`register_if_fresh_tls`) must
                // NOT populate the UDP-servable `regs` map (I4) — a replay of
                // the same counter is rejected (proving the acceptance was
                // recorded), but `is_registered` (which reads `regs`) stays
                // false.
                assert!(!s.is_registered(&node, 0), "TLS path must not touch regs");
                assert!(matches!(
                    classify_first_frame(&frame, &key, &mut s, 0),
                    Classify::Decoy
                ));
            }
            Classify::Decoy => panic!("fresh Register must upgrade"),
        }
    }

    #[test]
    fn http_get_is_decoy() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let mut s = RendezvousServer::new(0);
        // A censor probe: raw HTTP, no length-prefixed obf envelope.
        let buf = b"GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n";
        assert!(matches!(
            classify_first_frame(buf, &key, &mut s, 0),
            Classify::Decoy
        ));
    }

    #[test]
    fn wrong_obf_key_is_decoy() {
        let real = yip_obf::derive_key(&[4u8; 32]);
        let attacker = yip_obf::derive_key(&[5u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let frame = framed_register(&attacker, node, 1); // obf'd with the WRONG key
        assert!(matches!(
            classify_first_frame(&frame, &real, &mut s, 0),
            Classify::Decoy
        ));
    }

    #[test]
    fn stale_replayed_register_is_decoy() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let frame = framed_register(&key, node, 7);
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, 0),
            Classify::Upgrade { .. }
        ));
        // Replaying the identical frame (counter 7) must now be a decoy.
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, 1),
            Classify::Decoy
        ));
    }

    /// End-to-end: a censor probe (`GET / HTTP/1.1`) hitting the real TLS front
    /// must be transparently reverse-proxied to the decoy backend — proving
    /// the "Trojan front" behavior, not just that `classify_first_frame`
    /// returns `Decoy` in isolation.
    #[tokio::test]
    async fn probe_is_proxied_to_decoy() {
        // Stub decoy: accept one connection, read whatever the probe sent, and
        // reply as an ordinary web server would.
        let decoy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _peer) = decoy_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .await
                .unwrap();
        });

        let dir = crate::tls_front::unique_tmp_dir("conn-decoy");
        let (cert, key) = crate::tls_front::write_self_signed(&dir);
        let acceptor = std::sync::Arc::new(crate::tls_front::build_acceptor(&cert, &key).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = RendezvousServer::new(0);
        let forwarded = server.forwarded_handle();
        let cfg = Arc::new(TlsFrontCfg {
            server: Arc::new(tokio::sync::Mutex::new(server)),
            forwarded,
            obf_key: yip_obf::derive_key(&[4u8; 32]),
            decoy: Some(decoy_addr),
            base: std::time::Instant::now(),
            routes: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            reality: None,
            max_conns: 1024,
        });
        tokio::spawn(crate::tls_front::run_tls_front(listener, acceptor, cfg));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let connector = crate::tls_front::build_test_client_connector();
        let config = connector.configure().unwrap();
        let mut client = tokio_boring::connect(config, "relay.test", tcp)
            .await
            .expect("client TLS handshake completes");

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n")
            .await
            .unwrap();

        let mut got = Vec::new();
        // The decoy backend closes after writing its reply, so read-to-end
        // completes once the proxied response has been relayed back.
        client.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8_lossy(&got);
        assert!(
            got.contains("200 OK") && got.contains("hi"),
            "probe must be transparently proxied to the decoy backend, got: {got:?}"
        );
    }

    #[tokio::test]
    async fn silent_probe_initiates_decoy_connect_at_handshake_start() {
        let decoy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy_listener.local_addr().unwrap();

        let dir = crate::tls_front::unique_tmp_dir("conn-decoy-silent");
        let (cert, key) = crate::tls_front::write_self_signed(&dir);
        let acceptor = std::sync::Arc::new(crate::tls_front::build_acceptor(&cert, &key).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = RendezvousServer::new(0);
        let forwarded = server.forwarded_handle();
        let cfg = Arc::new(TlsFrontCfg {
            server: Arc::new(tokio::sync::Mutex::new(server)),
            forwarded,
            obf_key: yip_obf::derive_key(&[4u8; 32]),
            decoy: Some(decoy_addr),
            base: std::time::Instant::now(),
            routes: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            reality: None,
            max_conns: 1024,
        });
        tokio::spawn(crate::tls_front::run_tls_front(listener, acceptor, cfg));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let connector = crate::tls_front::build_test_client_connector();
        let config = connector.configure().unwrap();
        let _client = tokio_boring::connect(config, "relay.test", tcp)
            .await
            .expect("client TLS handshake completes");

        // The client stays completely silent.
        // Before #63 fix, relay waits CLASSIFY_TIMEOUT (3s) before connecting to decoy.
        // With #63 fix, relay speculatively initiates decoy connect right at handshake start.
        let start = std::time::Instant::now();
        let accept_res = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            decoy_listener.accept(),
        )
        .await;
        assert!(
            accept_res.is_ok(),
            "decoy backend must receive connection immediately at handshake start, rather than waiting for 3s classify timeout"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "decoy connect took too long: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn upgrade_aborts_speculative_decoy_connect() {
        let decoy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy_listener.local_addr().unwrap();

        let dir = crate::tls_front::unique_tmp_dir("conn-decoy-upgrade");
        let (cert, key) = crate::tls_front::write_self_signed(&dir);
        let acceptor = std::sync::Arc::new(crate::tls_front::build_acceptor(&cert, &key).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let obf_key = yip_obf::derive_key(&[4u8; 32]);
        let node = node_id(&[1u8; 32]);
        let server = RendezvousServer::new(0);
        let forwarded = server.forwarded_handle();
        let cfg = Arc::new(TlsFrontCfg {
            server: Arc::new(tokio::sync::Mutex::new(server)),
            forwarded,
            obf_key,
            decoy: Some(decoy_addr),
            base: std::time::Instant::now(),
            routes: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            reality: None,
            max_conns: 1024,
        });
        tokio::spawn(crate::tls_front::run_tls_front(listener, acceptor, cfg));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let connector = crate::tls_front::build_test_client_connector();
        let config = connector.configure().unwrap();
        let mut client = tokio_boring::connect(config, "relay.test", tcp)
            .await
            .expect("client TLS handshake completes");

        // Send valid Register frame immediately
        let frame = framed_register(&obf_key, node, 1);
        client.write_all(&frame).await.unwrap();

        // Read upgrade reply from relay
        let mut reply_len_bytes = [0u8; 2];
        client.read_exact(&mut reply_len_bytes).await.unwrap();
        let reply_len = u16::from_be_bytes(reply_len_bytes) as usize;
        let mut reply_body = vec![0u8; reply_len];
        client.read_exact(&mut reply_body).await.unwrap();
        let (ptype, _) = yip_obf::deobfuscate(&obf_key, &reply_body).expect("valid reply");
        assert_eq!(ptype, yip_obf::RDV_TYPE);

        // If the decoy listener accepted a speculative connection, that connection
        // must be closed (reading returns EOF) because Upgrade aborted/dropped it.
        if let Ok(Ok((mut decoy_stream, _))) = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            decoy_listener.accept(),
        )
        .await
        {
            let mut buf = [0u8; 16];
            let read_res = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                decoy_stream.read(&mut buf),
            )
            .await;
            match read_res {
                Ok(Ok(0)) => { /* EOF: correctly closed/aborted */ }
                Ok(Ok(n)) => panic!("decoy backend received unexpected data: {n} bytes"),
                Ok(Err(_)) => { /* Connection reset/error: also closed */ }
                Err(_) => panic!("speculative decoy connection was not closed on upgrade"),
            }
        }
    }

    #[tokio::test]
    async fn reality_inner_fail_writes_generic_error_not_decoy() {
        // A duplex stand-in for the TLS stream.
        let (client, server) = tokio::io::duplex(4096);
        // reality_reject writes a generic error and shuts the write half.
        reality_reject(server).await;
        // The client side should read a 400 status line then EOF.
        let mut buf = Vec::new();
        let mut c = client;
        use tokio::io::AsyncReadExt;
        c.read_to_end(&mut buf).await.unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.starts_with("HTTP/1.1 400"), "got: {s:?}");
    }

    #[test]
    fn same_ms_replay_is_decoy() {
        // A censor capturing a Register and replaying it within the SAME
        // millisecond must not be waved through as a tunnel client: the
        // discriminator must not rely on expiry-timestamp inference, which
        // cannot distinguish "accepted just now" from "already live" when
        // both accepts land on the same now_ms.
        let key = yip_obf::derive_key(&[4u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let frame = framed_register(&key, node, 7);
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, 100),
            Classify::Upgrade { .. }
        ));
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, 100),
            Classify::Decoy
        ));
    }

    fn frame_obf_message(obf_key: &[u8; 16], msg: &Message) -> Vec<u8> {
        crate::frame_obf(obf_key, msg)
    }

    fn valid_registration() -> (
        [u8; 32],
        [u8; 16],
        yip_membership::Record,
        std::net::SocketAddr,
    ) {
        const CA_PRIV: [u8; 32] = [0x42; 32];
        const CA_PUB: [u8; 32] = [
            33, 82, 248, 209, 155, 121, 29, 36, 69, 50, 66, 225, 95, 46, 171, 108, 183, 207, 250,
            123, 106, 94, 211, 0, 151, 150, 14, 6, 152, 129, 219, 18,
        ];
        const MEMBER_SIGN_PRIV: [u8; 32] = [0x43; 32];
        const MEMBER_SIGN_PUB: [u8; 32] = [
            34, 252, 41, 119, 146, 240, 182, 255, 192, 191, 207, 219, 126, 219, 12, 10, 161, 78, 2,
            90, 54, 94, 192, 227, 66, 232, 110, 56, 41, 203, 116, 182,
        ];
        let network_id = [7u8; 16];
        let member_pub = [1u8; 32];
        let mut cert = yip_membership::Cert {
            version: 1,
            member_pubkey: member_pub,
            member_sign_pubkey: MEMBER_SIGN_PUB,
            network_id,
            not_before: 0,
            not_after: u64::MAX,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        cert.ca_sig =
            yip_membership::record::sign(&yip_membership::cert::cert_signing_body(&cert), &CA_PRIV);

        let now_wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut rec = yip_membership::Record {
            node_id: yip_rendezvous::node_id(&member_pub),
            cert,
            endpoints: vec!["192.0.2.1:9".parse().unwrap()],
            seq: now_wall_ms,
            sig: [0u8; 64],
        };
        rec.sig = yip_membership::record::sign(
            &yip_membership::record::record_signing_body(&rec),
            &MEMBER_SIGN_PRIV,
        );
        (
            CA_PUB,
            network_id,
            rec,
            "198.51.100.42:41000".parse().unwrap(),
        )
    }

    #[test]
    fn classify_first_frame_accepts_valid_register_signed_in_rooted_mode() {
        let (ca_pub, net_id, rec, _) = valid_registration();
        let mut server = RendezvousServer::new_with_roots(0, vec![ca_pub], net_id);
        let obf_key = yip_obf::derive_key(&[4u8; 32]);
        let buf = frame_obf_message(
            &obf_key,
            &Message::RegisterSigned {
                record: rec.clone(),
            },
        );
        let classified = classify_first_frame(&buf, &obf_key, &mut server, 0);
        match classified {
            Classify::Upgrade { node, reply } => {
                assert_eq!(node, rec.node_id);
                let len = usize::from(u16::from_be_bytes([reply[0], reply[1]]));
                let (ptype, body) = yip_obf::deobfuscate(&obf_key, &reply[2..2 + len]).unwrap();
                assert_eq!(ptype, yip_obf::RDV_TYPE);
                assert_eq!(decode(&body), Some(Message::RegisterSigned { record: rec }));
            }
            Classify::Decoy => panic!("valid RegisterSigned must upgrade in rooted mode"),
        }
    }

    #[test]
    fn classify_first_frame_rejects_unsigned_register_in_rooted_mode() {
        let (ca_pub, net_id, _, _) = valid_registration();
        let mut server = RendezvousServer::new_with_roots(0, vec![ca_pub], net_id);
        let obf_key = yip_obf::derive_key(&[4u8; 32]);
        let buf = frame_obf_message(
            &obf_key,
            &Message::Register {
                node: [1u8; 16],
                counter: 1,
            },
        );
        let classified = classify_first_frame(&buf, &obf_key, &mut server, 0);
        assert!(matches!(classified, Classify::Decoy));
    }

    #[test]
    fn classify_first_frame_rejects_forged_signed_record_in_rooted_mode() {
        let (ca_pub, net_id, rec, _) = valid_registration();
        let obf_key = yip_obf::derive_key(&[4u8; 32]);

        // 1. Corrupted signature
        let mut forged_sig = rec.clone();
        forged_sig.sig[0] ^= 0xff;
        let mut server = RendezvousServer::new_with_roots(0, vec![ca_pub], net_id);
        let buf = frame_obf_message(&obf_key, &Message::RegisterSigned { record: forged_sig });
        assert!(matches!(
            classify_first_frame(&buf, &obf_key, &mut server, 0),
            Classify::Decoy
        ));

        // 2. Untrusted CA
        let other_ca = [99u8; 32];
        let mut server2 = RendezvousServer::new_with_roots(0, vec![other_ca], net_id);
        let buf2 = frame_obf_message(
            &obf_key,
            &Message::RegisterSigned {
                record: rec.clone(),
            },
        );
        assert!(matches!(
            classify_first_frame(&buf2, &obf_key, &mut server2, 0),
            Classify::Decoy
        ));

        // 3. Squatting node_id
        let mut squatting = rec.clone();
        squatting.node_id = [99u8; 16];
        let mut server3 = RendezvousServer::new_with_roots(0, vec![ca_pub], net_id);
        let buf3 = frame_obf_message(&obf_key, &Message::RegisterSigned { record: squatting });
        assert!(matches!(
            classify_first_frame(&buf3, &obf_key, &mut server3, 0),
            Classify::Decoy
        ));

        // 4. Stale sequence number (past expiry window)
        let mut stale = rec.clone();
        stale.seq = 1; // 1 ms since epoch is decades in the past
        const MEMBER_SIGN_PRIV: [u8; 32] = [0x43; 32];
        stale.sig = yip_membership::record::sign(
            &yip_membership::record::record_signing_body(&stale),
            &MEMBER_SIGN_PRIV,
        );
        let mut server4 = RendezvousServer::new_with_roots(0, vec![ca_pub], net_id);
        let buf4 = frame_obf_message(&obf_key, &Message::RegisterSigned { record: stale });
        assert!(matches!(
            classify_first_frame(&buf4, &obf_key, &mut server4, 0),
            Classify::Decoy
        ));
    }
}
