//! The relay tunnel pump for an upgraded (Register-classified) TLS
//! connection. TEMPORARY stub — Task 7 fills this in with the actual
//! relay-tunnel read/write loop driven by the shared `RendezvousServer`
//! state machine.
use std::sync::Arc;

use yip_rendezvous::NodeId;

use crate::tls_front::TlsFrontCfg;

#[expect(
    clippy::unused_async,
    reason = "TEMPORARY stub (3c.3 Task 6); Task 7 fills this in with the relay-tunnel pump, \
              which awaits on the TLS stream and the shared RendezvousServer lock"
)]
pub async fn run_tunnel(
    _s: tokio_boring::SslStream<tokio::net::TcpStream>,
    _cfg: Arc<TlsFrontCfg>,
    _node: NodeId,
) {
}
