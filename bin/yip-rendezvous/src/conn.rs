//! Per-connection TLS handling for the relay Trojan front (3c.3): classify the
//! first framed message, then either upgrade to a relay tunnel or hand off to
//! the decoy. No `unsafe`; all TLS/socket work is via tokio-boring / tokio.
use std::net::SocketAddr;
use std::sync::Arc;

use yip_rendezvous::{decode, Message, NodeId, RendezvousServer};

use crate::tls_front::TlsFrontCfg;

/// Largest first-frame we will buffer before deciding (a rendezvous Register is
/// tiny; anything larger is a decoy request). Matches yipd's TLS frame cap.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by classify_first_frame's unit tests (3c.3 Task 5); wired into the live \
                  trial-read in Task 6's handle_connection"
    )
)]
const MAX_FIRST_FRAME: usize = 2048;

/// Result of inspecting a connection's first framed message.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by classify_first_frame's unit tests (3c.3 Task 5); wired into the live \
                  upgrade/decoy routing by Task 6's handle_connection"
    )
)]
pub enum Classify {
    /// A valid, fresh Register from a client that knows `obf_psk`. `reply` is
    /// the framed obfuscated response to write back before entering the pump.
    Upgrade { node: NodeId, reply: Vec<u8> },
    /// Anything else — proxy this connection to the decoy backend.
    Decoy,
}

/// Pure classification of the first frame. De-frames `[u16 len][obf env]`,
/// deobfuscates with `obf_key` (requiring RDV_TYPE), decodes, and accepts only
/// a fresh `Register` (monotonic counter enforced by `server.handle`).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unit-tested by conn::tests (3c.3 Task 5); wired into the live TLS-front \
                  trial-read by Task 6's handle_connection"
    )
)]
pub fn classify_first_frame(
    buf: &[u8],
    obf_key: &[u8; 16],
    server: &mut RendezvousServer,
    src: SocketAddr,
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
    if !server.register_if_fresh(node, counter, src, now_ms) {
        return Classify::Decoy;
    }
    // Build the framed obfuscated ack (an empty-payload Register echo is
    // enough for 3c.3; 3c.4's client only needs to see a well-formed reply).
    let reply = crate::frame_obf(obf_key, &Message::Register { node, counter });
    Classify::Upgrade { node, reply }
}

/// TEMPORARY stub: Task 6 fills this in with the trial-read + Register/decoy
/// routing that drives `classify_first_frame` above.
#[expect(
    clippy::unused_async,
    reason = "TEMPORARY stub (Task 4); Task 6 fills this in with the trial-read + \
              Register/decoy routing, which awaits on the TLS stream"
)]
pub async fn handle_connection(
    _s: tokio_boring::SslStream<tokio::net::TcpStream>,
    _cfg: Arc<TlsFrontCfg>,
) {
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
        let src = "127.0.0.1:9".parse().unwrap();
        match classify_first_frame(&frame, &key, &mut s, src, 0) {
            Classify::Upgrade { node: got, reply } => {
                assert_eq!(got, node);
                assert!(!reply.is_empty());
                assert!(s.is_registered(&node, 0));
            }
            Classify::Decoy => panic!("fresh Register must upgrade"),
        }
    }

    #[test]
    fn http_get_is_decoy() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let mut s = RendezvousServer::new(0);
        let src = "127.0.0.1:9".parse().unwrap();
        // A censor probe: raw HTTP, no length-prefixed obf envelope.
        let buf = b"GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n";
        assert!(matches!(
            classify_first_frame(buf, &key, &mut s, src, 0),
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
        let src = "127.0.0.1:9".parse().unwrap();
        assert!(matches!(
            classify_first_frame(&frame, &real, &mut s, src, 0),
            Classify::Decoy
        ));
    }

    #[test]
    fn stale_replayed_register_is_decoy() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let src = "127.0.0.1:9".parse().unwrap();
        let frame = framed_register(&key, node, 7);
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, src, 0),
            Classify::Upgrade { .. }
        ));
        // Replaying the identical frame (counter 7) must now be a decoy.
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, src, 1),
            Classify::Decoy
        ));
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
        let src = "127.0.0.1:9".parse().unwrap();
        let frame = framed_register(&key, node, 7);
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, src, 100),
            Classify::Upgrade { .. }
        ));
        assert!(matches!(
            classify_first_frame(&frame, &key, &mut s, src, 100),
            Classify::Decoy
        ));
    }
}
