//! Key-derived identifiers, matching 2a's `node_addr` and 2b's `node_id`.
use std::net::Ipv6Addr;

pub const RENDEZVOUS_NODE_ID_CONTEXT_V2: &str = "yip-v2-rendezvous-node-id";
pub const OVERLAY_ADDR_CONTEXT_V2: &str = "yip-v2-overlay-ipv6-addr";

pub type NodeId = [u8; 16];

pub fn node_id(pubkey: &[u8; 32]) -> NodeId {
    derive_node_id(pubkey)
}

pub fn derive_node_id(pubkey: &[u8; 32]) -> NodeId {
    let digest = blake3::derive_key(RENDEZVOUS_NODE_ID_CONTEXT_V2, pubkey);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[0..16]);
    out
}

pub fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr {
    derive_overlay_ipv6(pubkey)
}

pub fn derive_overlay_ipv6(pubkey: &[u8; 32]) -> Ipv6Addr {
    let digest = blake3::derive_key(OVERLAY_ADDR_CONTEXT_V2, pubkey);
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    o[1..16].copy_from_slice(&digest[0..15]);
    Ipv6Addr::from(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_and_addr_deterministic() {
        let pk = [42u8; 32];
        let id1 = node_id(&pk);
        let id2 = node_id(&pk);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
        assert_ne!(id1, [0u8; 16]);

        let addr1 = node_addr(&pk);
        let addr2 = node_addr(&pk);
        assert_eq!(addr1, addr2);
        assert_eq!(addr1.octets()[0], 0xfd);
        assert_ne!(addr1.octets(), [0u8; 16]);
    }
}
