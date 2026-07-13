//! The TCP/TLS Trojan front for the relay (3c.3). Terminates real-cert TLS,
//! trial-reads the first framed message, and routes a fresh obfuscated
//! Register to the tunnel or everything else to the decoy backend.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use boring::error::ErrorStack;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use tokio::sync::Mutex;
use yip_rendezvous::RendezvousServer;

#[expect(
    dead_code,
    reason = "fields consumed by the Task 6 handle_connection (trial-read + Register/decoy \
              routing); the Task 4 conn::handle_connection stub does not touch them yet"
)]
pub struct TlsFrontCfg {
    pub server: Arc<Mutex<RendezvousServer>>,
    pub obf_key: [u8; 16],
    pub decoy: Option<SocketAddr>,
    pub base: Instant,
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
pub async fn run_tls_front(
    listener: tokio::net::TcpListener,
    acceptor: Arc<SslAcceptor>,
    cfg: Arc<TlsFrontCfg>,
) {
    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("tls-front: accept error: {e}");
                continue;
            }
        };
        let acceptor = Arc::clone(&acceptor);
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            match tokio_boring::accept(&acceptor, tcp).await {
                Ok(stream) => super::conn::handle_connection(stream, cfg).await,
                Err(e) => eprintln!("tls-front: handshake failed: {e}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_self_signed(dir: &std::path::Path) -> (String, String) {
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

    #[test]
    fn build_acceptor_from_pem_succeeds() {
        let dir = std::env::temp_dir().join(format!("yip-rdv-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = write_self_signed(&dir);
        assert!(build_acceptor(&cert, &key).is_ok());
    }

    /// Accept-any-cert client connector, mirroring `yipd`'s
    /// `build_client_connector` (zero-auth outer TLS by design — see module
    /// docs on `TlsFrontCfg`/`run_tls_front`; the inner yip handshake, added
    /// in Task 5/6, is the real security).
    fn build_test_client_connector() -> boring::ssl::SslConnector {
        let mut builder = boring::ssl::SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        builder.build()
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
