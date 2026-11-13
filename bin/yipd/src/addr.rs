//! Self-certifying, key-derived mesh addresses: a node's inner IPv6 is derived
//! from its X25519 public key, so the address IS the identity — no authority.
#![allow(dead_code)]
use std::net::Ipv6Addr;

pub const OVERLAY_ADDR_CONTEXT_V2: &str = "yip-v2-overlay-ipv6-addr";
/// The mesh occupies fd00::/8 (IPv6 ULA); every node address begins with 0xfd.
pub const MESH_PREFIX_LEN: u8 = 8;

/// Derive a node's inner IPv6 address from its public key:
/// `0xfd || BLAKE3-KDF(OVERLAY_ADDR_CONTEXT_V2, pubkey)[0..15]`.
pub fn derive_overlay_ipv6(public_key: &[u8; 32]) -> Ipv6Addr {
    let digest = blake3::derive_key(OVERLAY_ADDR_CONTEXT_V2, public_key);
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..16].copy_from_slice(&digest[0..15]);
    Ipv6Addr::from(octets)
}

/// Derive a node's inner IPv6 address from its public key (alias for `derive_overlay_ipv6`).
pub fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr {
    derive_overlay_ipv6(pubkey)
}

/// True iff `addr` is the address `pubkey` derives to (self-certification check).
pub fn verify_addr(addr: Ipv6Addr, pubkey: &[u8; 32]) -> bool {
    derive_overlay_ipv6(pubkey) == addr
}

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
