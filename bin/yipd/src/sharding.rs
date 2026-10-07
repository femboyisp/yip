//! Deterministic peer-to-shard mapping and consistent address hashing.
//!
//! In multi-core throughput sharding (Way A), each peer session is pinned to an
//! exclusive worker shard. To avoid cross-shard hops on the outbound path
//! whenever possible, inner TUN packet destination IPv6 addresses are mapped to
//! shards using the exact same hash as peer public keys.
//!
//! Because yip node addresses in `fd00::/8` are self-certifying addresses
//! generated via `crate::addr::node_addr(pubkey)`, hashing address octets `[1..9]`
//! yields the exact same shard as the peer's public key.

use std::net::Ipv6Addr;

/// Map an IPv6 address to a shard index deterministically in `0..num_shards`.
///
/// For mesh addresses in `fd00::/8` (where octet 0 is `0xfd`), octets `[1..9]`
/// (the first 8 bytes of the BLAKE2s identity digest) are converted to a 64-bit integer
/// and modulo-divided by `num_shards`.
///
/// For non-mesh IPv6 addresses (e.g., link-local, loopback, or global unicast),
/// the remaining host octets `[8..16]` are hashed to avoid panics and distribute
/// non-mesh traffic across shards.
///
/// Returns `0` if `num_shards <= 1`.
pub fn shard_for_addr(addr: Ipv6Addr, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let octets = addr.octets();
    let hash = if octets[0] == 0xfd {
        u64::from_be_bytes(octets[1..9].try_into().expect("slice has length 8"))
    } else {
        u64::from_be_bytes(octets[8..16].try_into().expect("slice has length 8"))
    };
    (hash % num_shards as u64) as usize
}

/// Map a peer's X25519 public key to its home shard index in `0..num_shards`.
///
/// This evaluates to `shard_for_addr(crate::addr::node_addr(pubkey), num_shards)`,
/// guaranteeing that outbound packets routed by destination IP match the owning
/// peer's shard.
///
/// Returns `0` if `num_shards <= 1`.
pub fn shard_for_pubkey(pubkey: &[u8; 32], num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    shard_for_addr(crate::addr::node_addr(pubkey), num_shards)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn pseudo_key(seed: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut state = seed;
        for i in 0..4 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            key[i * 8..(i + 1) * 8].copy_from_slice(&state.to_le_bytes());
        }
        key
    }

    #[test]
    fn test_boundary_conditions() {
        let key = [42u8; 32];
        let mesh_addr = crate::addr::node_addr(&key);
        let non_mesh_addr = Ipv6Addr::from_str("2001:db8::1").unwrap();

        for shards in [0, 1] {
            assert_eq!(shard_for_pubkey(&key, shards), 0);
            assert_eq!(shard_for_addr(mesh_addr, shards), 0);
            assert_eq!(shard_for_addr(non_mesh_addr, shards), 0);
        }
    }

    #[test]
    fn test_pubkey_always_equals_node_addr() {
        let shard_counts = [2, 3, 4, 7, 8, 16, 32, 64];

        for i in 0..1000 {
            let key = pseudo_key(i);
            let addr = crate::addr::node_addr(&key);

            for &shards in &shard_counts {
                let pk_shard = shard_for_pubkey(&key, shards);
                let addr_shard = shard_for_addr(addr, shards);

                assert_eq!(
                    pk_shard, addr_shard,
                    "mismatch for seed {i} with {shards} shards"
                );
                assert!(
                    pk_shard < shards,
                    "shard index {pk_shard} out of bounds for {shards} shards"
                );
            }
        }
    }

    #[test]
    fn test_determinism() {
        let key = pseudo_key(999);
        let addr = crate::addr::node_addr(&key);

        for _ in 0..10 {
            assert_eq!(shard_for_pubkey(&key, 4), shard_for_pubkey(&key, 4));
            assert_eq!(shard_for_addr(addr, 4), shard_for_addr(addr, 4));
        }
    }

    #[test]
    fn test_uniformity_distribution() {
        let total = 10_000;
        let num_shards = 4;
        let mut counts = vec![0; num_shards];

        for i in 0..total {
            let key = pseudo_key(i as u64);
            let shard = shard_for_pubkey(&key, num_shards);
            counts[shard] += 1;
        }

        let expected = total / num_shards;
        for (shard, &count) in counts.iter().enumerate() {
            let diff = (count as isize - expected as isize).abs();
            // With 10,000 samples across 4 shards, expected is 2500 with std dev ~43.
            // 400 is ~9.3 std deviations, virtually impossible to fail randomly if uniform.
            assert!(
                diff < 400,
                "shard {shard} count {count} deviated too far from expected {expected}"
            );
        }

        // Test with 8 shards
        let num_shards = 8;
        let mut counts8 = vec![0; num_shards];
        for i in 0..total {
            let key = pseudo_key(i as u64);
            let shard = shard_for_pubkey(&key, num_shards);
            counts8[shard] += 1;
        }

        let expected8 = total / num_shards;
        for (shard, &count) in counts8.iter().enumerate() {
            let diff = (count as isize - expected8 as isize).abs();
            assert!(
                diff < 300,
                "shard {shard} count {count} deviated too far from expected {expected8}"
            );
        }
    }

    #[test]
    fn test_non_mesh_addresses_graceful_handling() {
        let non_mesh_addrs = [
            Ipv6Addr::from_str("::1").unwrap(),
            Ipv6Addr::from_str("::").unwrap(),
            Ipv6Addr::from_str("2001:db8::1").unwrap(),
            Ipv6Addr::from_str("fe80::1234:5678:9abc:def0").unwrap(),
            Ipv6Addr::from_str("ff02::1").unwrap(),
        ];

        for &addr in &non_mesh_addrs {
            assert_eq!(shard_for_addr(addr, 0), 0);
            assert_eq!(shard_for_addr(addr, 1), 0);

            for shards in [2, 4, 8, 16] {
                let shard = shard_for_addr(addr, shards);
                assert!(
                    shard < shards,
                    "shard index {shard} out of bounds for {shards} shards"
                );
            }
        }
    }
}
