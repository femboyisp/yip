//! Stateless L3 source/destination IP translation with RFC 1624 checksum updates.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Incremental RFC 1624 16-bit one's complement checksum adjustment.
fn adjust_checksum_16(old_csum: u16, old_bytes: &[u8], new_bytes: &[u8]) -> u16 {
    let mut sum: u32 = u32::from(!old_csum);
    for &chunk in old_bytes.as_chunks::<2>().0 {
        let word = u16::from_be_bytes(chunk);
        sum += u32::from(!word);
    }
    for &chunk in new_bytes.as_chunks::<2>().0 {
        let word = u16::from_be_bytes(chunk);
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn update_l4_checksum_ipv4(
    pkt: &mut [u8],
    ihl: usize,
    proto: u8,
    old_ip: [u8; 4],
    new_ip: [u8; 4],
) {
    if proto == 6 && pkt.len() >= ihl + 18 {
        let csum = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);
        let updated = adjust_checksum_16(csum, &old_ip, &new_ip);
        pkt[ihl + 16..ihl + 18].copy_from_slice(&updated.to_be_bytes());
    } else if proto == 17 && pkt.len() >= ihl + 8 {
        let csum = u16::from_be_bytes([pkt[ihl + 6], pkt[ihl + 7]]);
        if csum != 0 {
            let mut updated = adjust_checksum_16(csum, &old_ip, &new_ip);
            if updated == 0 {
                updated = 0xFFFF;
            }
            pkt[ihl + 6..ihl + 8].copy_from_slice(&updated.to_be_bytes());
        }
    }
}

fn update_l4_checksum_ipv6(pkt: &mut [u8], next_hdr: u8, old_ip: [u8; 16], new_ip: [u8; 16]) {
    let l4 = 40;
    if next_hdr == 6 && pkt.len() >= l4 + 18 {
        let csum = u16::from_be_bytes([pkt[l4 + 16], pkt[l4 + 17]]);
        let updated = adjust_checksum_16(csum, &old_ip, &new_ip);
        pkt[l4 + 16..l4 + 18].copy_from_slice(&updated.to_be_bytes());
    } else if next_hdr == 17 && pkt.len() >= l4 + 8 {
        let csum = u16::from_be_bytes([pkt[l4 + 6], pkt[l4 + 7]]);
        let mut updated = adjust_checksum_16(csum, &old_ip, &new_ip);
        if updated == 0 {
            updated = 0xFFFF;
        }
        pkt[l4 + 6..l4 + 8].copy_from_slice(&updated.to_be_bytes());
    } else if next_hdr == 58 && pkt.len() >= l4 + 4 {
        let csum = u16::from_be_bytes([pkt[l4 + 2], pkt[l4 + 3]]);
        let updated = adjust_checksum_16(csum, &old_ip, &new_ip);
        pkt[l4 + 2..l4 + 4].copy_from_slice(&updated.to_be_bytes());
    }
}

/// Rewrites the source IP of an outbound client IPv4/IPv6 packet and returns the
/// original client source address if translation succeeded.
pub fn rewrite_outbound_src(
    pkt: &mut [u8],
    assigned_v4: Ipv4Addr,
    assigned_v6: Ipv6Addr,
) -> Option<ClientOrigAddr> {
    let version = pkt.first().map(|b| b >> 4)?;
    if version == 4 {
        if pkt.len() < 20 {
            return None;
        }
        let ihl = usize::from(pkt[0] & 0x0F) * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        let orig = [pkt[12], pkt[13], pkt[14], pkt[15]];
        let new = assigned_v4.octets();
        if orig != new {
            let old_ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
            let new_ip_csum = adjust_checksum_16(old_ip_csum, &orig, &new);
            pkt[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());
            pkt[12..16].copy_from_slice(&new);
            let proto = pkt[9];
            update_l4_checksum_ipv4(pkt, ihl, proto, orig, new);
        }
        Some(ClientOrigAddr::V4(Ipv4Addr::from(orig)))
    } else if version == 6 {
        if pkt.len() < 40 {
            return None;
        }
        let orig: [u8; 16] = pkt[8..24].try_into().ok()?;
        let new = assigned_v6.octets();
        if orig != new {
            pkt[8..24].copy_from_slice(&new);
            let next_hdr = pkt[6];
            update_l4_checksum_ipv6(pkt, next_hdr, orig, new);
        }
        Some(ClientOrigAddr::V6(Ipv6Addr::from(orig)))
    } else {
        None
    }
}

/// Rewrites the destination IP of an inbound internet reply packet back to the
/// client's original TUN IP.
pub fn rewrite_inbound_dst(pkt: &mut [u8], target_v4: Ipv4Addr, target_v6: Ipv6Addr) -> bool {
    let Some(version) = pkt.first().map(|b| b >> 4) else {
        return false;
    };
    if version == 4 {
        if pkt.len() < 20 {
            return false;
        }
        let ihl = usize::from(pkt[0] & 0x0F) * 4;
        if ihl < 20 || pkt.len() < ihl {
            return false;
        }
        let old_dst = [pkt[16], pkt[17], pkt[18], pkt[19]];
        let new_dst = target_v4.octets();
        if old_dst != new_dst {
            let old_ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
            let new_ip_csum = adjust_checksum_16(old_ip_csum, &old_dst, &new_dst);
            pkt[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());
            pkt[16..20].copy_from_slice(&new_dst);
            let proto = pkt[9];
            update_l4_checksum_ipv4(pkt, ihl, proto, old_dst, new_dst);
        }
        true
    } else if version == 6 {
        if pkt.len() < 40 {
            return false;
        }
        let Ok(old_dst): Result<[u8; 16], _> = pkt[24..40].try_into() else {
            return false;
        };
        let new_dst = target_v6.octets();
        if old_dst != new_dst {
            pkt[24..40].copy_from_slice(&new_dst);
            let next_hdr = pkt[6];
            update_l4_checksum_ipv6(pkt, next_hdr, old_dst, new_dst);
        }
        true
    } else {
        false
    }
}

/// Original client TUN IP recorded during outbound translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientOrigAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_checksum(hdr: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for &chunk in hdr.as_chunks::<2>().0 {
            sum += u32::from(u16::from_be_bytes(chunk));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn test_ipv4_round_trip_preserves_checksum() {
        let mut pkt = [0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[192, 0, 2, 1]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let csum = ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
        pkt[26..28].copy_from_slice(&0x1234u16.to_be_bytes());

        let orig = pkt;
        let assigned_v4 = Ipv4Addr::new(10, 77, 0, 2);
        let assigned_v6 = "fd77::2".parse().unwrap();

        let recorded = rewrite_outbound_src(&mut pkt, assigned_v4, assigned_v6).unwrap();
        assert_eq!(recorded, ClientOrigAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(&pkt[12..16], &[10, 77, 0, 2]);
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);

        // Simulate reply: swap src & dst, then rewrite inbound dst back to 192.0.2.1.
        pkt[12..16].copy_from_slice(&[1, 1, 1, 1]);
        pkt[16..20].copy_from_slice(&[10, 77, 0, 2]);
        pkt[10..12].copy_from_slice(&0u16.to_be_bytes());
        let reply_csum = ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&reply_csum.to_be_bytes());

        assert!(rewrite_inbound_dst(
            &mut pkt,
            Ipv4Addr::new(192, 0, 2, 1),
            assigned_v6
        ));
        assert_eq!(&pkt[16..20], &[192, 0, 2, 1]);
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);
        assert_eq!(pkt[26..28], orig[26..28]);
    }
}
