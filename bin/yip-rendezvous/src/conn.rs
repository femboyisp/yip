//! Per-connection handler for the TCP/TLS Trojan front (3c.3). TEMPORARY
//! stub: Task 5/6 fill this in with the trial-read + Register/decoy routing.
#[expect(
    clippy::unused_async,
    reason = "TEMPORARY stub (Task 4); Task 5/6 fill this in with the trial-read + \
              Register/decoy routing, which awaits on the TLS stream"
)]
pub async fn handle_connection(
    _s: tokio_boring::SslStream<tokio::net::TcpStream>,
    _cfg: std::sync::Arc<crate::tls_front::TlsFrontCfg>,
) {
}
