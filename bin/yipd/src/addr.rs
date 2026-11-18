//! Self-certifying, key-derived mesh addresses: a node's inner IPv6 is derived
//! from its X25519 public key, so the address IS the identity — no authority.
#![allow(dead_code)]

pub use yip_proto::addr::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_is_ula_and_deterministic() {
        let pk = [7u8; 32];
        let a = node_addr(&pk);
        assert_eq!(a.octets()[0], 0xfd, "must be in fd00::/8 ULA space");
        assert_eq!(node_addr(&pk), a, "derivation is deterministic");
    }

    #[test]
    fn addr_verifies_only_its_own_key() {
        let pk = [7u8; 32];
        let other = [8u8; 32];
        assert!(verify_addr(node_addr(&pk), &pk));
        assert!(!verify_addr(node_addr(&pk), &other));
    }

    #[test]
    fn distinct_keys_give_distinct_addrs() {
        assert_ne!(node_addr(&[1u8; 32]), node_addr(&[2u8; 32]));
    }

    #[test]
    fn test_overlay_addr_blake3_kat() {
        let pk = [7u8; 32];
        let addr = derive_overlay_ipv6(&pk);
        assert_eq!(addr.octets()[0], 0xfd);
        let digest = blake3::derive_key(OVERLAY_ADDR_CONTEXT_V2, &pk);
        assert_eq!(&addr.octets()[1..16], &digest[0..15]);
        assert_eq!(addr, node_addr(&pk));
    }
}
