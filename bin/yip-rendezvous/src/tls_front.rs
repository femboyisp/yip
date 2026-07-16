//! The TCP/TLS Trojan front for the relay (3c.3). Terminates real-cert TLS,
//! trial-reads the first framed message, and routes a fresh obfuscated
//! Register to the tunnel or everything else to the decoy backend.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boring::error::ErrorStack;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use yip_rendezvous::RendezvousServer;

use crate::reality_io::{read_first_tls_record, FirstRecord, PrefixedStream};

/// Upper bound on how long a TLS handshake may take before we give up on the
/// connection. Without this, a client that sends a ClientHello and then
/// stalls (never completing the handshake) parks the accept future forever —
/// `CLASSIFY_TIMEOUT` in `conn.rs` only starts once the handshake has
/// completed, so it does nothing to bound this phase (I1, slowloris).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Allowed clock skew (in minutes) between a REALITY client's embedded
/// timestamp and the relay's wall clock (REALITY.1 Task 3). This is the
/// relay/control tier, not the data plane's rekey-driven clock — wall time
/// is fine here.
const REALITY_SKEW_MIN: u64 = 10;

/// REALITY-mode config for the TLS front (REALITY.1 Task 3): when present on
/// `TlsFrontCfg`, `run_tls_front` peeks the raw `ClientHello` and only hands
/// authenticated connections to the real BoringSSL acceptor / relay Trojan
/// front; anything else is transparently spliced to `dest` so an active
/// prober completes a genuine handshake with the real upstream site and
/// never observes our certificate.
pub struct RealityCfg {
    /// Real upstream to splice un-authed (or unparseable-hello) connections
    /// to, replaying the buffered `ClientHello` first.
    pub dest: SocketAddr,
    /// Relay's REALITY X25519 private key.
    pub priv_key: [u8; 32],
    /// Accepted short-ids for the auth seal.
    pub short_ids: Vec<[u8; 8]>,
    /// Allowed SNIs for the authenticated check; empty accepts any SNI.
    pub server_names: Vec<String>,
    /// Per-SNI forged acceptors (REALITY.3 §1). `None` from `acceptor_for`
    /// ⇒ splice-only for that SNI.
    pub certs: Arc<crate::reality_cert::RealityCertCache>,
    /// Anti-replay dedup on the auth seal (REALITY.3 §2).
    pub replay: Arc<crate::reality_replay::ReplayGuard>,
}

pub struct TlsFrontCfg {
    pub server: Arc<Mutex<RendezvousServer>>,
    pub obf_key: [u8; 16],
    pub decoy: Option<SocketAddr>,
    pub base: Instant,
    /// Delivery channels for TLS-connected relay peers, keyed by `NodeId`.
    /// Registered by `conn_tunnel::run_tunnel` on upgrade and removed on
    /// disconnect; `RelaySend { dst }` routes here when `dst` is TLS-connected.
    pub routes: Arc<
        Mutex<
            std::collections::HashMap<yip_rendezvous::NodeId, tokio::sync::mpsc::Sender<Vec<u8>>>,
        >,
    >,
    /// REALITY anti-probe mode (REALITY.1). `None` keeps the 3c.3 Trojan
    /// front's behavior byte-identical (terminate TLS immediately, classify
    /// the first frame, decoy-or-tunnel).
    pub reality: Option<RealityCfg>,
    /// Hard cap on concurrently in-flight TLS handshakes/connections on this
    /// front (I1, slowloris hardening — see `run_tls_front`). Callers outside
    /// this module default to `1024`.
    pub max_conns: usize,
}

/// Build a server TLS acceptor from PEM cert-chain + key files, configured to
/// resemble a mainstream web server (mozilla-intermediate profile: TLS 1.3+1.2,
/// standard ciphers, session tickets) with ALPN `h2`,`http/1.1`.
pub fn build_acceptor(cert_path: &str, key_path: &str) -> Result<SslAcceptor, ErrorStack> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    b.set_certificate_chain_file(cert_path)?;
    b.set_private_key_file(key_path, SslFiletype::PEM)?;
    b.check_private_key()?;
    // ALPN in the conventional browser-server order.
    b.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(b.build())
}

/// Accept TLS connections forever, spawning one handler task per connection.
/// Bounded on two axes (I1, slowloris hardening): each handshake is capped by
/// `HANDSHAKE_TIMEOUT`, and no more than `cfg.max_conns` connections may be
/// in flight (handshaking or tunneling) at once — at capacity, new TCP
/// connections are dropped immediately rather than queued.
pub async fn run_tls_front(
    listener: tokio::net::TcpListener,
    acceptor: Arc<SslAcceptor>,
    cfg: Arc<TlsFrontCfg>,
) {
    let permits = Arc::new(Semaphore::new(cfg.max_conns));
    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("tls-front: accept error: {e}");
                continue;
            }
        };
        // At capacity: refuse rather than queue unboundedly. The dropped `tcp`
        // closes on drop.
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            eprintln!(
                "tls-front: at capacity ({} connections), dropping",
                cfg.max_conns
            );
            continue;
        };
        let acceptor = Arc::clone(&acceptor);
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            // Move `permit` into the task so it is released on task end
            // (success, handshake failure, or timeout alike).
            let _permit = permit;
            if cfg.reality.is_some() {
                run_reality_conn(tcp, &cfg).await;
                return;
            }
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio_boring::accept(&acceptor, tcp))
                .await
            {
                Ok(Ok(stream)) => super::conn::handle_connection(stream, cfg).await,
                Ok(Err(e)) => eprintln!("tls-front: handshake failed: {e}"),
                Err(_) => eprintln!("tls-front: handshake timed out after {HANDSHAKE_TIMEOUT:?}"),
            }
        });
    }
}

/// The REALITY branch of the per-connection task (`cfg.reality` is `Some`,
/// checked by the caller): peek the raw `ClientHello` before terminating
/// TLS, decide REALITY auth fully before acting, then either hand the
/// already-read hello + connection to the real acceptor (authed) or
/// transparently splice to the real upstream `dest`, replaying whatever
/// bytes were already consumed (un-authed / unparseable / malformed —
/// same code path, so an active prober cannot distinguish the outcomes).
///
/// A stalled read (nothing arrives before `HANDSHAKE_TIMEOUT`) or a
/// genuinely empty connection (immediate EOF, nothing consumed) still just
/// drops — there is nothing to replay and a real server would see the same
/// thing. Everything else that consumed at least one byte, even a malformed
/// or oversized first record, gets spliced to `dest` rather than dropped: a
/// real upstream would answer a broken record with its own alert/close, and
/// silently dropping here would be an observable distinguisher (REALITY.1
/// Task 3 review I-1).
async fn run_reality_conn(mut tcp: TcpStream, cfg: &Arc<TlsFrontCfg>) {
    let Some(r) = cfg.reality.as_ref() else {
        return; // unreachable: caller only takes this branch when Some
    };

    // A stalled read has no buffered bytes to replay — drop, same slowloris
    // bound the non-REALITY path gets from HANDSHAKE_TIMEOUT.
    let outcome =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_first_tls_record(&mut tcp)).await {
            Ok(outcome) => outcome,
            Err(_) => return,
        };

    let rec = match outcome {
        FirstRecord::Complete(rec) => rec,
        FirstRecord::Passthrough(bytes) => {
            splice_to_dest(tcp, r.dest, &bytes).await;
            return;
        }
        FirstRecord::Empty => return,
    };

    let now_min = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        // Wall clock is fine on this relay/control tier; a clock that's
        // somehow before the epoch just fails REALITY auth (fail-closed),
        // not a panic.
        .unwrap_or(0);

    // Decide auth + routing fully before acting: no early return that fires
    // only on a parse failure ahead of the `dest` connect — that would leak
    // timing distinguishing "malformed hello" from "well-formed but unauthed".
    // Every failure mode below (parse failure, disallowed SNI, failed auth,
    // unparseable seal) collapses to `None` and falls through to the same
    // `splice_to_dest` call at the bottom, so an active prober cannot
    // distinguish them.
    let info_opt = super::reality::parse_client_hello(rec.get(5..).unwrap_or(&[]));
    let decision = info_opt.as_ref().and_then(|info| {
        let sni = info.sni.as_deref()?;
        if !(r.server_names.is_empty() || r.server_names.iter().any(|n| n == sni)) {
            return None; // SNI not allowed ⇒ treat as un-authed
        }
        let ts_min = super::reality::reality_auth_recover(
            &r.priv_key,
            info,
            &r.short_ids,
            now_min,
            REALITY_SKEW_MIN,
        )?;
        let seal = <[u8; 32]>::try_from(info.legacy_session_id.as_slice()).ok()?;
        let acc = r.certs.acceptor_for(sni);
        Some((sni.to_owned(), ts_min, seal, acc))
    });

    if let Some((sni, ts_min, seal, Some(acceptor))) = decision {
        match decide_authed(&r.replay, seal, ts_min, now_min, true) {
            Decision::Accept => {
                let stream = PrefixedStream::new(rec, tcp);
                match tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    tokio_boring::accept(&acceptor, stream),
                )
                .await
                {
                    Ok(Ok(s)) => super::conn::handle_connection(s, Arc::clone(cfg)).await,
                    Ok(Err(e)) => {
                        eprintln!("tls-front: reality forged handshake failed ({sni}): {e}")
                    }
                    Err(_) => eprintln!("tls-front: reality forged handshake timed out"),
                }
                return;
            }
            Decision::Splice => {} // fall through to splice
        }
    }

    splice_to_dest(tcp, r.dest, &rec).await;
}

/// Post-auth routing decision (pure, testable). An authed hello routes to the
/// forged acceptor only if (a) its SNI has a forged acceptor AND (b) the seal
/// is fresh per the replay guard; otherwise splice to dest.
pub(crate) enum Decision {
    Accept,
    Splice,
}

pub(crate) fn decide_authed(
    replay: &crate::reality_replay::ReplayGuard,
    seal: [u8; 32],
    ts_min: u64,
    now_min: u64,
    sni_has_acceptor: bool,
) -> Decision {
    if !sni_has_acceptor {
        return Decision::Splice;
    }
    match replay.check(seal, ts_min, now_min) {
        crate::reality_replay::Verdict::Fresh => Decision::Accept,
        crate::reality_replay::Verdict::Replay => Decision::Splice,
    }
}

/// Connect to the real upstream `dest`, replay `replay` (the bytes already
/// consumed off the client connection) to it, then splice the two sockets
/// together bidirectionally so `dest` — not us — produces the rest of the
/// TLS conversation (handshake, alert, whatever a real server would do).
///
/// Shared by every REALITY path that must forward rather than drop: an
/// un-authed-but-well-formed hello and a malformed/oversized/truncated first
/// record are indistinguishable to an active prober by construction, since
/// they both end up here.
async fn splice_to_dest(mut tcp: TcpStream, dest: SocketAddr, replay: &[u8]) {
    // Bound the connect: `dest` is a REMOTE site, so a black-holed/slow upstream
    // would otherwise pin this connection's `max_conns` permit for the full
    // OS connect timeout — a flood could exhaust the front, and a REALITY front
    // that stops answering is itself an availability distinguisher (review M-1).
    let Ok(Ok(mut up)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(dest)).await
    else {
        return;
    };
    if !replay.is_empty() && up.write_all(replay).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut up).await;
}

/// Build a temp dir unique to this *call*, not just this process: every test
/// thread in a `cargo test` run shares one process, so `std::process::id()`
/// alone is identical across all of them. A dir keyed only on the pid lets
/// two concurrently-running tests race `write_self_signed` against the same
/// cert/key files (mismatched-pair `KEY_VALUES_MISMATCH` / `NO_START_LINE`
/// flakes). A per-call counter keeps every caller's files distinct. Shared by
/// every test module (`tls_front`, `conn`, `conn_tunnel`) that needs a
/// throwaway cert directory.
#[cfg(test)]
pub(crate) fn unique_tmp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("yip-rdv-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write a throwaway self-signed cert/key PEM pair for `relay.test` into
/// `dir`, returning `(cert_path, key_path)`. Shared by `tls_front`'s and
/// `conn`'s tests (both need a real cert to hand `build_acceptor`/
/// `run_tls_front`).
#[cfg(test)]
pub(crate) fn write_self_signed(dir: &std::path::Path) -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    (
        cert_path.to_str().unwrap().to_owned(),
        key_path.to_str().unwrap().to_owned(),
    )
}

/// Accept-any-cert client connector, mirroring `yipd`'s
/// `build_client_connector` (zero-auth outer TLS by design — see module docs
/// on `TlsFrontCfg`/`run_tls_front`; the inner yip framing is the real
/// security). Shared by `tls_front`'s and `conn`'s tests.
#[cfg(test)]
pub(crate) fn build_test_client_connector() -> boring::ssl::SslConnector {
    let mut builder = boring::ssl::SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(boring::ssl::SslVerifyMode::NONE);
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn build_acceptor_from_pem_succeeds() {
        let dir = unique_tmp_dir("tls");
        let (cert, key) = write_self_signed(&dir);
        assert!(build_acceptor(&cert, &key).is_ok());
    }

    /// End-to-end localhost smoke test: `run_tls_front` accepts a real TCP
    /// connection and completes a real BoringSSL TLS handshake against it.
    /// `handle_connection` is still the Task-5/6 stub, so the connection
    /// closes right after — this only proves the listener + acceptor plumbing
    /// works, not the inner protocol.
    #[tokio::test]
    async fn localhost_tls_handshake_completes() {
        let dir = unique_tmp_dir("tls-hs");
        let (cert, key) = write_self_signed(&dir);
        let acceptor = Arc::new(build_acceptor(&cert, &key).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = Arc::new(TlsFrontCfg {
            server: Arc::new(Mutex::new(RendezvousServer::new(0))),
            obf_key: [0u8; 16],
            decoy: None,
            base: Instant::now(),
            routes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            reality: None,
            max_conns: 1024,
        });
        tokio::spawn(run_tls_front(listener, acceptor, cfg));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = build_test_client_connector();
        let config = connector.configure().unwrap();
        let result = tokio_boring::connect(config, "relay.test", tcp).await;
        assert!(
            result.is_ok(),
            "client TLS handshake against the listener must complete: {:?}",
            result.err()
        );
    }

    // ---- REALITY front (in-process, so coverage sees run_reality_conn/splice) ----

    /// A "dest" upstream: accept one connection, drain whatever the front
    /// replays, then answer a fixed banner. Returns its address.
    async fn spawn_dest_banner(banner: &'static [u8]) -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut sink = [0u8; 512];
                let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut sink)).await;
                let _ = s.write_all(banner).await;
                let _ = s.flush().await;
            }
        });
        addr
    }

    /// A minimal but well-formed TLS 1.3 ClientHello record (no REALITY auth):
    /// parses cleanly, so `reality_auth_open` runs and fails (no key_share).
    fn minimal_client_hello_record() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0xAB; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0xCD; 32]); // legacy_session_id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2, TLS_AES_128_GCM
        body.extend_from_slice(&[0x01, 0x00]); // compression: len 1, null
        body.extend_from_slice(&[0x00, 0x00]); // extensions: len 0
        let body_len = u16::try_from(body.len()).unwrap();
        let mut msg = vec![0x01, 0x00]; // client_hello, u24 high byte (body < 64 KiB)
        msg.extend_from_slice(&body_len.to_be_bytes());
        msg.extend_from_slice(&body);
        let rec_len = u16::try_from(msg.len()).unwrap();
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&rec_len.to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    /// A local TLS server (self-signed) that answers any SNI — a stand-in
    /// `dest` purely for `RealityCertCache::prewarm` to fetch a leaf from.
    /// Separate from `spawn_dest_banner` (the splice target), which is
    /// deliberately a bare TCP server and cannot itself serve TLS.
    ///
    /// Multiple `reality_*` tests call `start_reality_front` (and so this
    /// helper) concurrently; `unique_tmp_dir` keeps each call's cert/key
    /// files distinct so they can't race `write_self_signed` against the
    /// same files (mismatched-pair `KEY_VALUES_MISMATCH` flakes).
    async fn spawn_cert_source() -> SocketAddr {
        let dir = unique_tmp_dir("reality-certsrc");
        let (cert, key) = write_self_signed(&dir);
        let acceptor = Arc::new(build_acceptor(&cert, &key).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = Arc::clone(&acceptor);
                    tokio::spawn(async move {
                        let _ = tokio_boring::accept(&acceptor, tcp).await;
                    });
                }
            }
        });
        addr
    }

    async fn start_reality_front(dest: SocketAddr) -> SocketAddr {
        let dir = unique_tmp_dir("reality");
        let (cert, key) = write_self_signed(&dir);
        let acceptor = Arc::new(build_acceptor(&cert, &key).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Un-authed hellos never reach `certs`/`replay` (auth fails first), but
        // constructing `RealityCfg` still needs a real, non-empty cert cache —
        // `prewarm` refuses to start with zero warmed names.
        let cert_src = spawn_cert_source().await;
        let certs = crate::reality_cert::RealityCertCache::prewarm(
            &["cache.test".to_owned()],
            cert_src,
            Duration::from_secs(3600),
            Duration::from_secs(21600),
            Duration::from_secs(5),
        )
        .await
        .expect("prewarm at least one SNI against the local cert source");
        let replay = Arc::new(crate::reality_replay::ReplayGuard::new(0, 65536));

        let cfg = Arc::new(TlsFrontCfg {
            server: Arc::new(Mutex::new(RendezvousServer::new(0))),
            obf_key: [0u8; 16],
            decoy: None,
            base: Instant::now(),
            routes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            reality: Some(RealityCfg {
                dest,
                priv_key: [7u8; 32],
                short_ids: Vec::new(), // no client can authenticate ⇒ everything forwards
                server_names: Vec::new(),
                certs,
                replay,
            }),
            max_conns: 1024,
        });
        tokio::spawn(run_tls_front(listener, acceptor, cfg));
        addr
    }

    async fn assert_gets_banner(front: SocketAddr, first_bytes: &[u8], banner: &[u8]) {
        let mut client = tokio::net::TcpStream::connect(front).await.unwrap();
        client.write_all(first_bytes).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 128];
            loop {
                let n = client.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(banner.len()).any(|w| w == banner) {
                    break;
                }
            }
            buf
        })
        .await
        .expect("banner within timeout");
        assert!(
            got.windows(banner.len()).any(|w| w == banner),
            "expected dest banner spliced back, got {got:?}"
        );
    }

    /// Un-authed (well-formed, no seal) ClientHello ⇒ spliced to the real dest.
    #[tokio::test]
    async fn reality_unauthed_hello_is_spliced_to_dest() {
        let dest = spawn_dest_banner(b"HELLO-DEST-UNAUTH").await;
        let front = start_reality_front(dest).await;
        assert_gets_banner(front, &minimal_client_hello_record(), b"HELLO-DEST-UNAUTH").await;
    }

    /// A first record declaring an oversized body (> MAX_RECORD_BODY_LEN) ⇒
    /// Passthrough ⇒ spliced to dest (not silently dropped — review I-1).
    #[tokio::test]
    async fn reality_oversized_record_is_spliced_to_dest() {
        let dest = spawn_dest_banner(b"HELLO-DEST-OVERSIZE").await;
        let front = start_reality_front(dest).await;
        // 5-byte record header claiming a 16385-byte body (> 16384 cap).
        assert_gets_banner(
            front,
            &[0x16, 0x03, 0x01, 0x40, 0x01],
            b"HELLO-DEST-OVERSIZE",
        )
        .await;
    }

    // ---- decide_authed (pure routing decision) ----

    /// A seal that is `Fresh` the first time routes to `Accept`; the second,
    /// identical seal is a replay and must flip the decision to `Splice`.
    #[test]
    fn decide_replay_flips_to_splice() {
        let guard = crate::reality_replay::ReplayGuard::new(0, 65536);
        let seal = [5u8; 32];
        assert!(matches!(
            decide_authed(&guard, seal, 0, 0, /* sni_has_acceptor= */ true),
            Decision::Accept
        ));
        assert!(matches!(
            decide_authed(&guard, seal, 0, 0, true),
            Decision::Splice
        ));
    }

    /// An SNI with no forged acceptor is splice-only regardless of the seal's
    /// freshness — the replay guard is never even consulted.
    #[test]
    fn decide_unknown_sni_splices() {
        let guard = crate::reality_replay::ReplayGuard::new(0, 65536);
        assert!(matches!(
            decide_authed(&guard, [6u8; 32], 0, 0, /* sni_has_acceptor= */ false),
            Decision::Splice
        ));
    }
}
