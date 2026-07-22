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
/// deobfuscates with `obf_key` (requiring RDV_TYPE), decodes, and accepts only
/// a fresh `Register` (monotonic counter enforced by
/// `server.register_if_fresh_tls`, kept separate from the UDP-servable `regs`
/// map — see `RendezvousServer::register_if_fresh_tls`).
pub fn classify_first_frame(
    buf: &[u8],
    obf_key: &[u8; 16],
    server: &mut RendezvousServer,
    now_ms: u64,
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
    // Must be a Register.
    let Some(Message::Register { node, counter }) = decode(&body) else {
        return Classify::Decoy;
    };
    // The state machine reports whether THIS Register was accepted (fresh
    // insert / counter advance). A stale replay — even one in the same
    // millisecond — or a first-seen node at capacity returns false ⇒ decoy.
    // Uses the TLS-only freshness state (`register_if_fresh_tls`), NOT the
    // UDP-servable `regs` map: a TLS peer is not UDP-reachable and must never
    // appear in a UDP `Lookup`/`RelaySend` result with the synthetic
    // `0.0.0.0:0` address this path would otherwise register (I4).
    if !server.register_if_fresh_tls(node, counter, now_ms) {
        return Classify::Decoy;
    }
    // Build the framed obfuscated ack (an empty-payload Register echo is
    // enough for 3c.3; 3c.4's client only needs to see a well-formed reply).
    let reply = crate::frame_obf(obf_key, &Message::Register { node, counter });
    Classify::Upgrade { node, reply }
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
    let decision = read_and_classify(&mut stream, &cfg, &mut buf, now_ms).await;

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
async fn into_decoy<St>(mut stream: St, cfg: &TlsFrontCfg, buffered: Vec<u8>)
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
    let Ok(mut backend) = TcpStream::connect(decoy_addr).await else {
        return;
    };
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
        let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0);
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
}
