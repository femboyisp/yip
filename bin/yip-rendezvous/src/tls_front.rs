//! The TCP/TLS Trojan front for the relay (3c.3). Terminates real-cert TLS,
//! trial-reads the first framed message, and routes a fresh obfuscated
//! Register to the tunnel or everything else to the decoy backend.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boring::error::ErrorStack;
use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use p256::pkcs8::DecodePrivateKey as _;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use yip_rendezvous::RendezvousServer;

use crate::reality::ClientHelloInfo;
use crate::reality_io::{read_first_tls_record, FirstRecord};

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

/// Compile-time guard tying `reality_replay::WINDOW` to `REALITY_SKEW_MIN`.
/// The two constants live in different modules and there is no other static
/// link between them; a seal with a fixed `ts_min` passes the stateless skew
/// gate (`reality_auth_recover`, below) for any arrival minute in
/// `[ts_min - REALITY_SKEW_MIN, ts_min + REALITY_SKEW_MIN]` — a span
/// `2 * REALITY_SKEW_MIN` minutes wide — so the replay dedup memory must
/// cover at least that whole span or a seal can age out of the ring while
/// still inside the skew-gate's acceptance window and be wrongly re-accepted
/// as `Fresh` on replay (whole-branch review, REALITY.3). This fails the
/// build if `WINDOW` is ever lowered, or `REALITY_SKEW_MIN` raised, without
/// updating the other to match.
const _: () = assert!(crate::reality_replay::WINDOW >= 2 * REALITY_SKEW_MIN);

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
    /// Per-SNI stolen-cert fields + captured flight template (REALITY.3 §1 /
    /// REALITY.5a). `None` from `fields_for`/`template_for` ⇒ splice-only for
    /// that SNI; otherwise `run_reality_conn`'s authed branch forges a leaf
    /// and serves the hand-rolled flight per connection (REALITY.5d).
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

/// Build a throwaway, in-memory, self-signed `SslAcceptor` for the
/// REALITY-only case where the operator did not supply `--tls-cert`/
/// `--tls-key` (REALITY.3 §1 forges its own per-SNI cert from the stolen
/// `dest` leaf, so an operator cert is no longer required). This acceptor is
/// never actually used to serve a REALITY connection: the authed branch
/// (`run_reality_conn`) builds its acceptor from `RealityCfg::certs` instead,
/// and every other connection is either spliced to `dest` or dropped before
/// `tokio_boring::accept` is called on this one — it exists purely so
/// `run_tls_front`'s non-REALITY code path still has a well-formed acceptor
/// to hold. Generated fresh at each startup; no PEM files touch disk.
pub fn build_throwaway_acceptor() -> Result<SslAcceptor, String> {
    let certified =
        rcgen::generate_simple_self_signed(vec!["reality-throwaway.invalid".to_owned()])
            .map_err(|e| e.to_string())?;
    let der = certified.cert.der().as_ref().to_vec();
    let x509 = boring::x509::X509::from_der(&der).map_err(|e| e.to_string())?;
    let pkey = PKey::private_key_from_der(&certified.key_pair.serialize_der())
        .map_err(|e| e.to_string())?;

    let mut b =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_certificate(&x509).map_err(|e| e.to_string())?;
    b.set_private_key(&pkey).map_err(|e| e.to_string())?;
    b.check_private_key().map_err(|e| e.to_string())?;
    b.set_alpn_protos(b"\x02h2\x08http/1.1")
        .map_err(|e| e.to_string())?;
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

/// Which client X25519 public key feeds the server-side TLS DH, by negotiated
/// group: for X25519MLKEM768 (4588) it is the x25519 bundled in the client's
/// 4588 key_share entry (`key_share_mlkem_x25519`); for X25519 (29) it is the
/// standalone `0x001d` entry (`key_share_x25519`). Any other group is
/// unsupported here (P256/P384 + HelloRetryRequest is #84) → `None` → splice.
fn select_client_x25519(group: u16, info: &ClientHelloInfo) -> Option<[u8; 32]> {
    match group {
        4588 => info.key_share_mlkem_x25519,
        29 => info.key_share_x25519,
        _ => None,
    }
}

/// An OS-CSPRNG-backed [`yip_utls::hello::RandomSource`] for
/// `emit_server_hello` (mirrors yip_utls's own private `OsRng`: a `getrandom`
/// bridge that latches the first error so the caller fail-closes instead of
/// emitting predictable bytes). NEVER seed this — a predictable rng here
/// makes the ML-KEM encapsulation predictable.
#[derive(Default)]
struct OsRandomSource {
    error: bool,
}

impl yip_utls::hello::RandomSource for OsRandomSource {
    fn fill(&mut self, buf: &mut [u8]) {
        if self.error {
            return;
        }
        if getrandom::getrandom(buf).is_err() {
            self.error = true;
        }
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

    // `read_first_tls_record` enforces the deadline itself (per read), so a
    // client that stalls AFTER sending a partial record yields the consumed
    // bytes as `Passthrough` and gets spliced to `dest` — a real upstream
    // would likewise hold and answer a half-sent record, not drop it. Only a
    // connection that produced literally nothing before the deadline is
    // dropped (`Empty`).
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let rec = match read_first_tls_record(&mut tcp, deadline).await {
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
        // REALITY.4b: recover `shared` too, so the authed branch below can
        // derive the per-connection cert key from it (the fixed cache
        // acceptor is no longer served to a real client — only used to keep
        // `fields_for` warm).
        let (ts_min, shared) = super::reality::reality_auth_recover_shared(
            &r.priv_key,
            info,
            &r.short_ids,
            now_min,
            REALITY_SKEW_MIN,
        )?;
        let seal = <[u8; 32]>::try_from(info.legacy_session_id.as_slice()).ok()?;
        let fields = r.certs.fields_for(sni);
        Some((sni.to_owned(), ts_min, seal, shared, fields, info.clone()))
    });

    if let Some((sni, ts_min, seal, shared, Some(fields), info)) = decision {
        match decide_authed(&r.replay, seal, ts_min, now_min, true) {
            Decision::Accept => {
                // --- Pre-write: any failure SPLICES (connection still pristine). ---
                let Some(template) = r.certs.template_for(&sni) else {
                    splice_to_dest(tcp, r.dest, &rec).await;
                    return;
                };

                let group = template.server_hello.key_share_group;
                let Some(client_x25519) = select_client_x25519(group, &info) else {
                    splice_to_dest(tcp, r.dest, &rec).await;
                    return;
                };

                // The relay ALWAYS binds: derive the leaf-signing key from
                // THIS connection's `shared` (REALITY.4b) — not a fixed
                // cache key — so the presented leaf proves possession of
                // `reality_priv` for the client (Task 2) to pin against.
                let dk = yip_utls::auth::derive_cert_key(&shared);

                // Forge the natural leaf (no exact-length padding); SPKI = dk.
                let leaf_keypair = match rcgen::KeyPair::try_from(dk.pkcs8_der.as_slice()) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("tls-front: reality leaf keypair load failed ({sni}): {e}");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };
                let forged_leaf_der = match crate::reality_cert::forge_leaf(&fields, &leaf_keypair)
                {
                    Ok(cert) => cert.der().as_ref().to_vec(),
                    Err(e) => {
                        eprintln!("tls-front: reality forge_leaf failed ({sni}): {e}");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };

                let ch_msg = match rec.get(5..) {
                    Some(m) => m,
                    None => {
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };

                let mut rng = OsRandomSource::default();
                let (sh_msg, keys) = match yip_utls::server::emit_server_hello(
                    &template.server_hello,
                    ch_msg,
                    &info.legacy_session_id,
                    &client_x25519,
                    info.key_share_mlkem_ek.as_deref(),
                    &mut rng,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("tls-front: reality emit_server_hello failed ({sni}): {e}");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };
                if rng.error {
                    // getrandom failed → fail closed (still pre-write).
                    eprintln!("tls-front: reality OS rng failed ({sni})");
                    splice_to_dest(tcp, r.dest, &rec).await;
                    return;
                }

                // Load the CertVerify signing key while still pre-write, so its
                // (unreachable — `dk.pkcs8_der` already parsed as an rcgen KeyPair
                // above) failure splices rather than drops, keeping every fallible
                // step on the pre-write/splice side of the commit boundary.
                let signing_key = match p256::ecdsa::SigningKey::from_pkcs8_der(&dk.pkcs8_der) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("tls-front: reality signing key load failed ({sni}): {e}");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };

                // --- Commit point: write the ServerHello. From here, DROP on error. ---
                let mut transcript_ch_sh = Vec::with_capacity(ch_msg.len() + sh_msg.len());
                transcript_ch_sh.extend_from_slice(ch_msg);
                transcript_ch_sh.extend_from_slice(&sh_msg);

                let mut sh_record = Vec::with_capacity(5 + sh_msg.len());
                sh_record.push(0x16); // handshake
                sh_record.extend_from_slice(&[0x03, 0x03]); // legacy record version
                                                            // Still pre-write (nothing on the wire yet) → splice. A
                                                            // ServerHello never exceeds u16, so this is unreachable in
                                                            // practice, but it keeps the fail-safe boundary honest.
                let sh_len = match u16::try_from(sh_msg.len()) {
                    Ok(l) => l,
                    Err(_) => {
                        eprintln!("tls-front: reality ServerHello too large ({sni})");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };
                sh_record.extend_from_slice(&sh_len.to_be_bytes());
                sh_record.extend_from_slice(&sh_msg);
                if let Err(e) = tcp.write_all(&sh_record).await {
                    eprintln!("tls-front: reality ServerHello write failed ({sni}): {e}");
                    return;
                }

                let reality_stream = match tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    yip_utls::stream::serve(
                        tcp,
                        &keys,
                        &template.encrypted_flight,
                        &template.cert_chain,
                        &forged_leaf_der,
                        &signing_key,
                        &transcript_ch_sh,
                    ),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        eprintln!("tls-front: reality serve failed ({sni}): {e}");
                        return;
                    }
                    Err(_) => {
                        eprintln!("tls-front: reality serve timed out ({sni})");
                        return;
                    }
                };

                super::conn::handle_connection(reality_stream, Arc::clone(cfg)).await;
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

    /// `build_throwaway_acceptor` (Task 8: the REALITY-only, no-operator-cert
    /// fallback) must itself be a genuinely working TLS acceptor — a real
    /// client can complete a handshake against it — even though nothing in
    /// REALITY mode ever routes a live connection to it (that acceptor is
    /// only reachable via the non-REALITY `tokio_boring::accept` fallback in
    /// `run_tls_front`).
    #[tokio::test]
    async fn build_throwaway_acceptor_completes_a_real_handshake() {
        let acceptor = Arc::new(build_throwaway_acceptor().expect("build throwaway acceptor"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = tokio_boring::accept(&acceptor, tcp).await;
            }
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = build_test_client_connector();
        let config = connector.configure().unwrap();
        let result = tokio_boring::connect(config, "reality-throwaway.invalid", tcp).await;
        assert!(
            result.is_ok(),
            "client TLS handshake against the throwaway acceptor must complete: {:?}",
            result.err()
        );
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

    /// A self-signed cert/key PEM pair for `relay.test`, like
    /// `write_self_signed`, but additionally carrying the near-universal
    /// server-leaf extensions (`KeyUsage:
    /// digitalSignature|keyEncipherment`, `ExtendedKeyUsage: serverAuth`,
    /// explicit `BasicConstraints: CA:FALSE`) that
    /// `reality_cert::extract_fields` always copies into a forged leaf
    /// regardless of whether the SPECIFIC dest cert actually has them (its
    /// own doc comment: "a server leaf's usages are near-universal" —
    /// best-effort mimicry, not conditioned on the real cert's content).
    /// `write_self_signed`'s bare `rcgen::generate_simple_self_signed` cert
    /// omits all three (rcgen's own `CertificateParams::default()`:
    /// `is_ca: NoCa`, empty `key_usages`/`extended_key_usages`) — fine for
    /// the plain-handshake tests that share it, but a REAL destination
    /// site's CA-issued leaf virtually always carries these three
    /// extensions, so using the bare cert as `spawn_cert_source`'s "dest"
    /// understates the captured leaf's size relative to what `forge_leaf`
    /// always re-adds, artificially starving `RealityCertCache::prewarm`'s
    /// captured `record_lengths` slack for the REALITY.5d authed
    /// end-to-end test below. A test-fixture realism fix, not a production
    /// behavior change — `forge_leaf`/`extract_fields` are unmodified.
    fn write_realistic_leaf(dir: &std::path::Path) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["relay.test".to_owned()]).unwrap();
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        // A real dest leaf virtually always carries a Certificate Transparency
        // SCT list extension (RFC 6962, OID 1.3.6.1.4.1.11129.2.4.2) —
        // `StolenFields` deliberately does NOT copy SCTs into the forged leaf
        // (they are bound to the real CT-log keys and unreproducible by an
        // ephemeral-key forgery — see `StolenFields`'s doc comment), so a real
        // forged flight is reliably SMALLER than the real dest flight it must
        // fit within (`emit_server_flight`'s captured `record_lengths`
        // budget). Without this, this synthetic test dest's from-scratch
        // self-signed cert has near-zero slack over the forged leaf (both are
        // "the same fields, independently ECDSA-self-signed" — the only
        // delta is a few bytes of DER signature-length jitter), making the
        // budget check flaky. Filler bytes, not a real SCT — nothing here
        // ever parses this extension's content.
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
                vec![0u8; 200],
            ));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        (
            cert_path.to_str().unwrap().to_owned(),
            key_path.to_str().unwrap().to_owned(),
        )
    }

    /// A local TLS server (self-signed) that answers any SNI — a stand-in
    /// `dest` purely for `RealityCertCache::prewarm` to fetch a leaf from.
    /// Separate from `spawn_dest_banner` (the splice target), which is
    /// deliberately a bare TCP server and cannot itself serve TLS.
    ///
    /// Multiple `reality_*` tests call `start_reality_front` (and so this
    /// helper) concurrently; `unique_tmp_dir` keeps each call's cert/key
    /// files distinct so they can't race `write_realistic_leaf` against the
    /// same files (mismatched-pair `KEY_VALUES_MISMATCH` flakes).
    async fn spawn_cert_source() -> SocketAddr {
        let dir = unique_tmp_dir("reality-certsrc");
        let (cert, key) = write_realistic_leaf(&dir);
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

    /// Like [`spawn_cert_source`], but restricts the acceptor's supported
    /// groups to X25519 (group `29`) only, so `capture_dest_flight`'s
    /// Chrome-faithful probe (which offers both X25519MLKEM768/`4588` and
    /// X25519/`29`) negotiates group `29` — yielding a `ServerFlightTemplate`
    /// with `key_share_group == 29`. Lets the authed end-to-end test below
    /// exercise the group-29 server KEX/`select_client_x25519` wiring
    /// deterministically, independent of which hybrid groups the BoringSSL
    /// version happens to support.
    async fn spawn_cert_source_x25519() -> SocketAddr {
        let dir = unique_tmp_dir("reality-certsrc-x25519");
        let (cert, key) = write_realistic_leaf(&dir);
        let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        b.set_certificate_chain_file(&cert).unwrap();
        b.set_private_key_file(&key, SslFiletype::PEM).unwrap();
        b.check_private_key().unwrap();
        b.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
        // X25519 only ⇒ the probe's hybrid 4588 offer is declined, group 29 wins.
        b.set_curves_list("X25519").unwrap();
        let acceptor = Arc::new(b.build());
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

    /// General REALITY front spinner: parameterized on `priv_key`/`short_ids`/
    /// `server_names` so both the un-authed splice tests (empty `short_ids`/
    /// `server_names` ⇒ no client can ever authenticate) and the REALITY.4b
    /// authed end-to-end test (a real `short_id` + a warmed SNI) share one
    /// setup path.
    async fn start_reality_front_with(
        dest: SocketAddr,
        priv_key: [u8; 32],
        short_ids: Vec<[u8; 8]>,
        server_names: Vec<String>,
        cert_src: SocketAddr,
    ) -> SocketAddr {
        let dir = unique_tmp_dir("reality");
        let (cert, key) = write_self_signed(&dir);
        let acceptor = Arc::new(build_acceptor(&cert, &key).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // `prewarm` refuses to start with zero warmed names when at least one
        // was requested, so an un-authed-only caller still passes a
        // real-but-irrelevant name here (never reached — auth fails first).
        let warm_names = if server_names.is_empty() {
            vec!["cache.test".to_owned()]
        } else {
            server_names.clone()
        };
        let certs = crate::reality_cert::RealityCertCache::prewarm(
            &warm_names,
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
                priv_key,
                short_ids,
                server_names,
                certs,
                replay,
            }),
            max_conns: 1024,
        });
        tokio::spawn(run_tls_front(listener, acceptor, cfg));
        addr
    }

    async fn start_reality_front(dest: SocketAddr) -> SocketAddr {
        // No client can authenticate ⇒ everything forwards (empty short_ids
        // AND empty server_names — see `start_reality_front_with`).
        let cert_src = spawn_cert_source().await;
        start_reality_front_with(dest, [7u8; 32], Vec::new(), Vec::new(), cert_src).await
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

    /// REALITY.4b end-to-end: an authed connection is terminated with a
    /// PER-CONNECTION acceptor whose leaf key equals
    /// `derive_cert_key(shared).public_sec1` for THAT connection's `shared`
    /// — proven the same way a real yip client proves it, by driving the
    /// actual client-side `yip_utls::connect(.., verify: true)` REALITY.4b
    /// binding check against this front, rather than re-implementing the
    /// check here. `connect(verify: true)` fails closed
    /// (`Err(yip_utls::Error::RealityVerify(_))`) unless the server's
    /// `CertificateVerify` signature verifies under EXACTLY
    /// `derive_cert_key(shared).public_sec1`, where the client independently
    /// computes `shared` via its own ECDH — so a success here is direct
    /// evidence of the property under test, not a restatement of it.
    ///
    /// Two independent connections are driven, each with `connect`'s own
    /// fresh random ephemeral key (hence its own distinct `shared`) — both
    /// must succeed, proving the server re-forges a leaf bound to EACH
    /// connection individually rather than reusing one fixed leaf (which
    /// would only ever match a single, first-observed `shared`).
    #[tokio::test]
    async fn reality_authed_connection_leaf_is_bound_to_connections_shared() {
        let dest = spawn_dest_banner(b"SHOULD-NEVER-BE-SPLICED").await;

        let reality_priv = [55u8; 32];
        let reality_pub =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(reality_priv))
                .as_bytes();
        let short_id = [9u8; 8];
        let sni = "auth.test";

        let cert_src = spawn_cert_source().await;
        let front = start_reality_front_with(
            dest,
            reality_priv,
            vec![short_id],
            vec![sni.to_owned()],
            cert_src,
        )
        .await;

        for attempt in 0..2 {
            let tcp = tokio::net::TcpStream::connect(front).await.unwrap();
            let result = yip_utls::connect(tcp, sni, &reality_pub, short_id, true).await;
            assert!(
                result.is_ok(),
                "attempt {attempt}: REALITY.4b client verify must succeed against the \
                 per-connection re-forged leaf: {:?}",
                result.err()
            );
        }
    }

    /// The authed end-to-end path when `dest` negotiated **group 29 (X25519)**
    /// rather than the hybrid 4588 — i.e. `select_client_x25519` must feed the
    /// standalone `0x001d` share (not the 4588 tail) into `emit_server_hello`'s
    /// server KEX. Deterministically forced by an X25519-only cert source. A
    /// `verify=on` client must still complete the hand-rolled handshake and
    /// verify the 4b binding.
    #[tokio::test]
    async fn reality_authed_group29_dest_client_verify_succeeds() {
        let dest = spawn_dest_banner(b"SHOULD-NEVER-BE-SPLICED").await;

        let reality_priv = [77u8; 32];
        let reality_pub =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(reality_priv))
                .as_bytes();
        let short_id = [3u8; 8];
        let sni = "group29.test";

        let cert_src = spawn_cert_source_x25519().await;
        let front = start_reality_front_with(
            dest,
            reality_priv,
            vec![short_id],
            vec![sni.to_owned()],
            cert_src,
        )
        .await;

        let tcp = tokio::net::TcpStream::connect(front).await.unwrap();
        let result = yip_utls::connect(tcp, sni, &reality_pub, short_id, true).await;
        assert!(
            result.is_ok(),
            "verify=on client must complete the hand-rolled handshake against a \
             group-29 dest template: {:?}",
            result.err()
        );
    }

    // ---- select_client_x25519 (pure decision) ----

    fn info_with_shares(x0: Option<[u8; 32]>, x4588: Option<[u8; 32]>) -> ClientHelloInfo {
        ClientHelloInfo {
            sni: Some("example.com".to_string()),
            client_random: [0u8; 32],
            legacy_session_id: vec![0u8; 32],
            key_share_x25519: x0,
            key_share_mlkem_ek: None,
            key_share_mlkem_x25519: x4588,
        }
    }

    #[test]
    fn select_client_x25519_by_group() {
        let info = info_with_shares(Some([1u8; 32]), Some([2u8; 32]));
        // group 4588 → the 4588-entry tail; group 29 → the 0x001d entry.
        assert_eq!(select_client_x25519(4588, &info), Some([2u8; 32]));
        assert_eq!(select_client_x25519(29, &info), Some([1u8; 32]));
        // unsupported group → None (→ splice).
        assert_eq!(select_client_x25519(23, &info), None);
        // missing share for the selected group → None.
        assert_eq!(
            select_client_x25519(4588, &info_with_shares(Some([1u8; 32]), None)),
            None
        );
        assert_eq!(
            select_client_x25519(29, &info_with_shares(None, Some([2u8; 32]))),
            None
        );
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
