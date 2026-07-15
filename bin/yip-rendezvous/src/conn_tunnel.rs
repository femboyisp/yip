//! The upgraded-client pump for a TLS-connected relay peer (3c.3): register a
//! delivery channel by NodeId, then read framed obf messages and route
//! RelaySend to the destination's TLS channel.
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use yip_rendezvous::{decode, Message, NodeId};

use crate::tls_front::TlsFrontCfg;
use crate::TLS_FRAME_CAP;

const CHANNEL_DEPTH: usize = 64;

/// Drive one upgraded TLS connection to completion: register `node`'s
/// delivery channel, then pump reads/writes until the peer disconnects or a
/// malformed frame is seen (fail-closed teardown). `prefix` carries any bytes
/// already read past the first (Register) frame during classification — a
/// pipelined second frame in the same TLS read must not be lost.
pub async fn run_tunnel<S>(
    mut stream: tokio_boring::SslStream<S>,
    cfg: Arc<TlsFrontCfg>,
    node: NodeId,
    prefix: Vec<u8>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    // Keep an identity handle so the exit-time removal below can tell
    // "my registration" apart from a newer task's registration for the same
    // `node` (reconnect race) — a `Sender` clone used only for
    // `same_channel` identity does not keep `rx` alive in a way that matters,
    // since this task always drops it at exit.
    let tx_id = tx.clone();
    cfg.routes.lock().await.insert(node, tx);

    let mut read_buf = prefix;
    // Drain any complete frame(s) already sitting in the prefix before ever
    // touching the socket — a client that pipelines Register + RelaySend in
    // one TLS write must not have the second frame silently dropped.
    let mut ok = drain_frames(&mut read_buf, &cfg, node).await;

    let mut chunk = [0u8; 4096];
    while ok {
        tokio::select! {
            // Deliveries destined for THIS peer (framed already).
            Some(frame) = rx.recv() => {
                if stream.write_all(&frame).await.is_err() { break; }
            }
            r = stream.read(&mut chunk) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    read_buf.extend_from_slice(&chunk[..n]);
                    ok = drain_frames(&mut read_buf, &cfg, node).await;
                }
            },
        }
    }
    // Only remove the route if it's still ours: if `node` reconnected while
    // this task was unwinding, a newer `run_tunnel` task has already
    // overwritten the map entry with its own sender, and removing it here
    // would black-hole all future deliveries to `node` until it reconnects
    // again.
    let mut routes = cfg.routes.lock().await;
    if routes
        .get(&node)
        .is_some_and(|cur| cur.same_channel(&tx_id))
    {
        routes.remove(&node);
    }
}

/// Parse and act on every complete `[u16 len][obf Message]` frame in `buf`.
/// Returns false on a fail-closed condition (malformed frame ⇒ tear down).
async fn drain_frames(buf: &mut Vec<u8>, cfg: &TlsFrontCfg, _self_node: NodeId) -> bool {
    loop {
        if buf.len() < 2 {
            return true;
        }
        let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
        if len == 0 || len > TLS_FRAME_CAP {
            return false;
        }
        if buf.len() < 2 + len {
            return true;
        }
        let env: Vec<u8> = buf[2..2 + len].to_vec();
        buf.drain(..2 + len);
        let Some((pt, body)) = yip_obf::deobfuscate(&cfg.obf_key, &env) else {
            return false;
        };
        if pt != yip_obf::RDV_TYPE {
            return false;
        }
        let Some(msg) = decode(&body) else {
            return false;
        };
        route(msg, cfg).await;
    }
}

/// Route one decoded message from a TLS-connected peer.
async fn route(msg: Message, cfg: &TlsFrontCfg) {
    if let Message::RelaySend { dst, payload, src } = msg {
        let deliver = Message::RelayDeliver { src, payload };
        // Prefer a TLS-connected destination; the framed delivery goes on its
        // channel. (UDP-connected destinations are served by the UDP task via
        // the shared RendezvousServer; a future refinement can bridge here.)
        let frame = crate::frame_obf(&cfg.obf_key, &deliver);
        // Clone the sender and drop the `routes` guard before touching it:
        // holding the global routes mutex across delivery must never happen,
        // or it wedges all routing and registration on this front.
        let tx = cfg.routes.lock().await.get(&dst).cloned();
        if let Some(tx) = tx {
            // Best-effort, non-blocking delivery — matches the UDP path's
            // drop-on-full/errored `send_to`. This is a blind relay; the
            // inner Noise/ARQ session handles loss. Blocking here (`.send`)
            // would park this task's OWN read loop (both ends of `select!`
            // live in the caller) whenever the destination's channel is
            // full, and if A and B relay to each other simultaneously that
            // is a mutual deadlock (I2, reproduced in review) — `try_send`
            // is drop-on-full/closed and can never wedge.
            let _ = tx.try_send(frame);
            // Count this hop on the SAME `forwarded` counter the UDP path's
            // `RendezvousServer::handle` increments (`cfg.server` is the
            // identical `Arc<Mutex<RendezvousServer>>` main.rs hands to both
            // fronts) — see `record_relay_forward`'s doc comment for why
            // this is needed: this path never calls `handle` at all.
            cfg.server.lock().await.record_relay_forward();
        }
    }
    // Register refreshes and other control messages on an established tunnel
    // are handled by the shared state machine in a later refinement; 3c.3's
    // money path is RelaySend A->B over TLS.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Instant;
    use tokio::sync::Mutex;
    use yip_rendezvous::{node_id, RendezvousServer};

    fn framed(obf_key: &[u8; 16], msg: &Message) -> Vec<u8> {
        crate::frame_obf(obf_key, msg)
    }

    fn test_cfg(obf_key: [u8; 16]) -> Arc<TlsFrontCfg> {
        Arc::new(TlsFrontCfg {
            server: Arc::new(Mutex::new(RendezvousServer::new(0))),
            obf_key,
            decoy: None,
            base: Instant::now(),
            routes: Arc::new(Mutex::new(HashMap::new())),
            reality: None,
        })
    }

    /// A `RelaySend` fully contained in a `prefix` buffer handed to
    /// `run_tunnel` (i.e. bytes read past the classifying Register frame in
    /// the same TLS read) must still be routed — the pipelined-frame fix
    /// (F2). Drives `drain_frames` directly against a pre-registered
    /// destination channel, since that is the function `run_tunnel` seeds
    /// with `prefix` before ever touching the socket.
    #[tokio::test]
    async fn pipelined_prefix_frame_is_routed() {
        let key = yip_obf::derive_key(&[1u8; 32]);
        let cfg = test_cfg(key);
        let a = node_id(&[10u8; 32]);
        let b = node_id(&[11u8; 32]);

        // Register B's delivery channel as run_tunnel would on upgrade.
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
        cfg.routes.lock().await.insert(b, tx);

        // A's RelaySend, pre-framed, sitting in the "prefix" buffer.
        let mut prefix = framed(
            &key,
            &Message::RelaySend {
                src: a,
                dst: b,
                payload: b"hello".to_vec(),
            },
        );
        assert!(drain_frames(&mut prefix, &cfg, a).await);
        assert!(prefix.is_empty(), "the complete frame must be consumed");

        let got_frame = rx.try_recv().expect("B's channel got a delivery");
        let (pt, body) = yip_obf::deobfuscate(&key, &got_frame[2..]).unwrap();
        assert_eq!(pt, yip_obf::RDV_TYPE);
        assert_eq!(
            decode(&body),
            Some(Message::RelayDeliver {
                src: a,
                payload: b"hello".to_vec(),
            })
        );
        // The TLS-tunnel relay path must be visible on the SAME shared
        // counter the UDP path's `RendezvousServer::handle` increments —
        // `route` never calls `handle` at all, so without an explicit
        // `record_relay_forward` call this would silently stay 0 forever
        // (the bug the netns money test caught: `relay-forwarded=0` even
        // while a TLS-relayed ping succeeded).
        assert_eq!(
            cfg.server.lock().await.forwarded_count(),
            1,
            "a TLS-tunnel relay hop must be counted on the shared forwarded_count"
        );
    }

    /// Reconnect race (Fix 2): node X registers (tx1), then reconnects and
    /// registers again (tx2) before the old task's exit-removal runs. The
    /// old task's `same_channel`-guarded removal must NOT evict the newer
    /// registration — X's route must still resolve to tx2 afterward.
    #[tokio::test]
    async fn reconnect_does_not_evict_newer_route() {
        let cfg = test_cfg(yip_obf::derive_key(&[3u8; 32]));
        let x = node_id(&[30u8; 32]);

        let (tx1, _rx1) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
        let tx1_id = tx1.clone();
        cfg.routes.lock().await.insert(x, tx1);

        // X reconnects: a new task registers a fresh sender, overwriting the
        // map entry before the old task's exit path runs.
        let (tx2, _rx2) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
        cfg.routes.lock().await.insert(x, tx2.clone());

        // Simulate the OLD task's exit-removal logic: only remove if the map
        // still holds *our* sender.
        {
            let mut routes = cfg.routes.lock().await;
            if routes.get(&x).is_some_and(|cur| cur.same_channel(&tx1_id)) {
                routes.remove(&x);
            }
        }

        let routes = cfg.routes.lock().await;
        let current = routes.get(&x).expect("newer registration must survive");
        assert!(
            current.same_channel(&tx2),
            "route for X must still point at the newer sender (tx2), not be evicted by the stale task"
        );
    }

    /// End-to-end: two TLS clients connect to the real front, each registers,
    /// then A sends a framed `RelaySend { dst: B }` and B reads back a framed
    /// `RelayDeliver { src: A }` carrying the same payload — the money path
    /// this task implements.
    #[tokio::test]
    async fn relay_over_tls() {
        let key = yip_obf::derive_key(&[2u8; 32]);
        let a = node_id(&[20u8; 32]);
        let b = node_id(&[21u8; 32]);

        let dir = std::env::temp_dir().join(format!("yip-rdv-tunnel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key_path) = crate::tls_front::write_self_signed(&dir);
        let acceptor = Arc::new(crate::tls_front::build_acceptor(&cert, &key_path).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = test_cfg(key);
        // No decoy needed: both clients send a fresh Register, so every
        // connection upgrades.
        tokio::spawn(crate::tls_front::run_tls_front(listener, acceptor, cfg));

        async fn connect(addr: std::net::SocketAddr) -> tokio_boring::SslStream<TcpStream> {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let connector = crate::tls_front::build_test_client_connector();
            let config = connector.configure().unwrap();
            tokio_boring::connect(config, "relay.test", tcp)
                .await
                .expect("client TLS handshake completes")
        }

        let mut client_a = connect(addr).await;
        let mut client_b = connect(addr).await;

        // Each registers with a fresh counter to upgrade into the tunnel.
        client_a
            .write_all(&framed(
                &key,
                &Message::Register {
                    node: a,
                    counter: 1,
                },
            ))
            .await
            .unwrap();
        client_b
            .write_all(&framed(
                &key,
                &Message::Register {
                    node: b,
                    counter: 1,
                },
            ))
            .await
            .unwrap();

        // Consume each client's Register-ack reply before proceeding.
        let mut ack = [0u8; 256];
        let _ = client_a.read(&mut ack).await.unwrap();
        let _ = client_b.read(&mut ack).await.unwrap();

        // A relays a payload to B.
        client_a
            .write_all(&framed(
                &key,
                &Message::RelaySend {
                    src: a,
                    dst: b,
                    payload: b"hello".to_vec(),
                },
            ))
            .await
            .unwrap();

        // B reads the framed RelayDeliver.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = client_b.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before a full frame arrived");
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
                if buf.len() >= 2 + len {
                    break;
                }
            }
        }
        let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
        let env = &buf[2..2 + len];
        let (pt, body) = yip_obf::deobfuscate(&key, env).expect("valid obf envelope");
        assert_eq!(pt, yip_obf::RDV_TYPE);
        assert_eq!(
            decode(&body),
            Some(Message::RelayDeliver {
                src: a,
                payload: b"hello".to_vec(),
            }),
            "B must receive A's relayed payload"
        );
    }
}
