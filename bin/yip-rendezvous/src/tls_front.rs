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

/// Hard cap on concurrently in-flight TLS handshakes/connections on this
/// front. Bounds the number of tasks/fds a slow-handshake flood can pin,
/// independent of the per-handshake timeout above (I1).
const MAX_TLS_CONNS: usize = 1024;

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
/// `HANDSHAKE_TIMEOUT`, and no more than `MAX_TLS_CONNS` connections may be
/// in flight (handshaking or tunneling) at once — at capacity, new TCP
/// connections are dropped immediately rather than queued.
pub async fn run_tls_front(
    listener: tokio::net::TcpListener,
    acceptor: Arc<SslAcceptor>,
    cfg: Arc<TlsFrontCfg>,
) {
    let permits = Arc::new(Semaphore::new(MAX_TLS_CONNS));
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
            eprintln!("tls-front: at capacity ({MAX_TLS_CONNS} connections), dropping");
            continue;
        };
        let acceptor = Arc::clone(&acceptor);
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            // Move `permit` into the task so it is released on task end
            // (success, handshake failure, or timeout alike).
            let _permit = permit;
            if cfg.reality.is_some() {
                run_reality_conn(tcp, &acceptor, &cfg).await;
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
async fn run_reality_conn(mut tcp: TcpStream, acceptor: &Arc<SslAcceptor>, cfg: &Arc<TlsFrontCfg>) {
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

    // Decide auth fully before acting: no early return that fires only on a
    // parse failure ahead of the `dest` connect — that would leak timing
    // distinguishing "malformed hello" from "well-formed but unauthed".
    let authed = super::reality::parse_client_hello(rec.get(5..).unwrap_or(&[]))
        .map(|info| {
            let sni_ok = r.server_names.is_empty()
                || info
                    .sni
                    .as_deref()
                    .is_some_and(|s| r.server_names.iter().any(|n| n == s));
            sni_ok
                && super::reality::reality_auth_open(
                    &r.priv_key,
                    &info,
                    &r.short_ids,
                    now_min,
                    REALITY_SKEW_MIN,
                )
        })
        .unwrap_or(false);

    if authed {
        let stream = PrefixedStream::new(rec, tcp);
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio_boring::accept(acceptor, stream)).await
        {
            Ok(Ok(s)) => super::conn::handle_connection(s, Arc::clone(cfg)).await,
            Ok(Err(e)) => eprintln!("tls-front: reality handshake failed: {e}"),
            Err(_) => {
                eprintln!("tls-front: reality handshake timed out after {HANDSHAKE_TIMEOUT:?}")
            }
        }
        return;
    }

    splice_to_dest(tcp, r.dest, &rec).await;
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
    let Ok(mut up) = TcpStream::connect(dest).await else {
        return;
    };
    if !replay.is_empty() && up.write_all(replay).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut up).await;
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

    #[test]
    fn build_acceptor_from_pem_succeeds() {
        let dir = std::env::temp_dir().join(format!("yip-rdv-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
        let dir = std::env::temp_dir().join(format!("yip-rdv-tls-hs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
}
