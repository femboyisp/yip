//! The 3c.4 TLS relay-dial client: a dedicated thread holds one browser-parrot
//! TLS connection to the relay, sends the obfuscated monotonic `Register`
//! (first-on-connect + keepalive), and pipes obf-wrapped RelaySend/RelayDeliver
//! envelopes to/from the data plane over a UnixStream socketpair. No tokio; all
//! TLS via 3c.2's `crate::tls` client primitives.
use yip_rendezvous::{encode, Message, NodeId};

/// Per-boot monotonic Register counter (starts at 1; the relay's freshness gate
/// requires strictly-greater).
#[derive(Default)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the relay_client thread in the next 3c.4 task"
    )
)]
pub(crate) struct Counter(u64);
impl Counter {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by the relay_client thread in the next 3c.4 task"
        )
    )]
    pub(crate) fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

/// Build the framed `[u16 len][obf(RDV_TYPE, Register{node,counter})]` bytes.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the relay_client thread in the next 3c.4 task"
    )
)]
pub(crate) fn build_register(obf_key: &[u8; 16], node: NodeId, counter: u64) -> Vec<u8> {
    let mut plain = Vec::new();
    encode(&Message::Register { node, counter }, &mut plain);
    let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0);
    let mut out = Vec::new();
    crate::tls::frame_datagram(&env, &mut out).expect("register envelope within frame cap");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_frame_deobfuscates_to_fresh_register() {
        let key = yip_obf::derive_key(&[9u8; 32]);
        let node = yip_rendezvous::node_id(&[1u8; 32]);
        let framed = build_register(&key, node, 1);
        // Strip the [u16 len] TLS frame, then deobf + decode.
        let mut r = crate::tls::FrameReader::default();
        r.push(&framed);
        let env = r.next().unwrap().unwrap();
        let (pt, body) = yip_obf::deobfuscate(&key, &env).unwrap();
        assert_eq!(pt, yip_obf::RDV_TYPE);
        assert_eq!(
            yip_rendezvous::decode(&body),
            Some(yip_rendezvous::Message::Register { node, counter: 1 })
        );
    }

    #[test]
    fn counter_is_monotonic_from_one() {
        let mut c = Counter::default();
        assert_eq!(c.next(), 1);
        assert_eq!(c.next(), 2);
        assert_eq!(c.next(), 3);
    }
}
