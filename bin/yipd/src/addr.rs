//! Self-certifying, key-derived mesh addresses: a node's inner IPv6 is derived
//! from its X25519 public key, so the address IS the identity — no authority.
#![allow(dead_code)]
use std::net::Ipv6Addr;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;

/// Domain-separation context so the address derivation can't collide with any
/// other use of the key.
const DOMAIN: &[u8] = b"yip-addr-v1";
/// The mesh occupies fd00::/8 (IPv6 ULA); every node address begins with 0xfd.
pub const MESH_PREFIX_LEN: u8 = 8;

/// Derive a node's inner IPv6 address from its public key:
/// `0xfd || BLAKE2s(DOMAIN || pubkey)[0..15]`.
pub fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr {
    let mut h = Blake2sVar::new(15).expect("15 is a valid blake2s output len");
    h.update(DOMAIN);
    h.update(pubkey);
    let mut digest = [0u8; 15];
    h.finalize_variable(&mut digest)
        .expect("output len matches");
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..].copy_from_slice(&digest);
    Ipv6Addr::from(octets)
}

/// True iff `addr` is the address `pubkey` derives to (self-certification check).
pub fn verify_addr(addr: Ipv6Addr, pubkey: &[u8; 32]) -> bool {
    node_addr(pubkey) == addr
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
}
