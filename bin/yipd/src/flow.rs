//! Inner 5-tuple extraction and flow hashing for multi-core worker affinity.
//!
//! Enables Regime B single-peer multi-core throughput scaling by extracting the
//! inner L3/L4 5-tuple from plaintext TUN frames and computing a deterministic
//! 64-bit hash. Packets belonging to the same flow are routed to the same worker
//! core (guaranteeing in-order delivery and zero TCP reordering) and select an outer
//! UDP egress port from a pool.

#![allow(dead_code)]

use std::hash::{Hash, Hasher};

/// Inner 5-tuple extracted from plaintext IP packets.
///
/// IPv4 addresses are stored in IPv4-mapped IPv6 format (`::ffff:a.b.c.d`),
/// allowing uniform 128-bit address representation across IPv4 and IPv6 flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowTuple {
    /// Extract the 5-tuple from a raw IP packet (IPv4 or IPv6).
    ///
    /// Returns `None` if the packet is empty, truncated, or has an unsupported
    /// IP version. For non-TCP/UDP protocols (such as ICMP), ports default to `(0, 0)`.
    pub fn extract(packet: &[u8]) -> Option<Self> {
        if packet.is_empty() {
            return None;
        }

        let version = packet[0] >> 4;
        match version {
            4 => Self::extract_v4(packet),
            6 => Self::extract_v6(packet),
            _ => None,
        }
    }

    fn extract_v4(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 20 {
            return None;
        }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if pkt.len() < ihl || ihl < 20 {
            return None;
        }
        let proto = pkt[9];
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        // Store as IPv4-mapped IPv6 (RFC 4291)
        src_ip[10..12].copy_from_slice(&[0xff, 0xff]);
        src_ip[12..16].copy_from_slice(&pkt[12..16]);
        dst_ip[10..12].copy_from_slice(&[0xff, 0xff]);
        dst_ip[12..16].copy_from_slice(&pkt[16..20]);

        // If this is a non-first fragment, L4 headers are not present at ihl offset
        let frag_offset = u16::from_be_bytes([pkt[6] & 0x1f, pkt[7]]);
        let (src_port, dst_port) = if frag_offset == 0 {
            Self::extract_ports(&pkt[ihl..], proto)
        } else {
            (0, 0)
        };

        Some(Self {
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
        })
    }

    fn extract_v6(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 40 {
            return None;
        }
        let next_hdr = pkt[6];
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&pkt[8..24]);
        dst_ip.copy_from_slice(&pkt[24..40]);

        let (src_port, dst_port) = Self::extract_ports(&pkt[40..], next_hdr);
        Some(Self {
            src_ip,
            dst_ip,
            proto: next_hdr,
            src_port,
            dst_port,
        })
    }

    fn extract_ports(payload: &[u8], proto: u8) -> (u16, u16) {
        if (proto == 6 || proto == 17) && payload.len() >= 4 {
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            (sp, dp)
        } else {
            (0, 0)
        }
    }

    /// Compute a deterministic 64-bit hash of the flow 5-tuple.
    ///
    /// Uses standard library `DefaultHasher` which is fast, deterministic,
    /// and performs zero heap allocations.
    pub fn flow_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ipv4_tcp() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, ihl=5 (20 bytes)
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // TCP header at byte 20
        pkt[20..22].copy_from_slice(&8080u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());

        let flow = FlowTuple::extract(&pkt).expect("valid ipv4 tcp");
        assert_eq!(flow.proto, 6);
        assert_eq!(flow.src_port, 8080);
        assert_eq!(flow.dst_port, 443);
        assert_eq!(
            flow.src_ip,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]
        );
        assert_eq!(
            flow.dst_ip,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2]
        );
        assert_ne!(flow.flow_hash(), 0);
    }

    #[test]
    fn test_extract_ipv4_udp() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // IPv4, ihl=5
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 50]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 1]);
        // UDP header at byte 20
        pkt[20..22].copy_from_slice(&5353u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());

        let flow = FlowTuple::extract(&pkt).expect("valid ipv4 udp");
        assert_eq!(flow.proto, 17);
        assert_eq!(flow.src_port, 5353);
        assert_eq!(flow.dst_port, 53);
        assert_eq!(
            flow.src_ip,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 50]
        );
        assert_eq!(
            flow.dst_ip,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]
        );
        assert_ne!(flow.flow_hash(), 0);
    }

    #[test]
    fn test_extract_ipv6_tcp() {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60; // IPv6, version=6
        pkt[6] = 6; // Next header: TCP
        let src: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dst: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        // TCP header at byte 40
        pkt[40..42].copy_from_slice(&9000u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&80u16.to_be_bytes());

        let flow = FlowTuple::extract(&pkt).expect("valid ipv6 tcp");
        assert_eq!(flow.proto, 6);
        assert_eq!(flow.src_port, 9000);
        assert_eq!(flow.dst_port, 80);
        assert_eq!(flow.src_ip, src);
        assert_eq!(flow.dst_ip, dst);
        assert_ne!(flow.flow_hash(), 0);
    }

    #[test]
    fn test_extract_ipv6_udp() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60; // IPv6, version=6
        pkt[6] = 17; // Next header: UDP
        let src: [u8; 16] = [0xfd, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: [u8; 16] = [0xfd, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 2];
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        // UDP header at byte 40
        pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&54321u16.to_be_bytes());

        let flow = FlowTuple::extract(&pkt).expect("valid ipv6 udp");
        assert_eq!(flow.proto, 17);
        assert_eq!(flow.src_port, 12345);
        assert_eq!(flow.dst_port, 54321);
        assert_eq!(flow.src_ip, src);
        assert_eq!(flow.dst_ip, dst);
        assert_ne!(flow.flow_hash(), 0);
    }

    #[test]
    fn test_extract_icmp_v4_and_v6() {
        // IPv4 ICMP (proto = 1)
        let mut pkt_v4 = vec![0u8; 28];
        pkt_v4[0] = 0x45;
        pkt_v4[9] = 1; // ICMP
        pkt_v4[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt_v4[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let flow_v4 = FlowTuple::extract(&pkt_v4).expect("valid ipv4 icmp");
        assert_eq!(flow_v4.proto, 1);
        assert_eq!(flow_v4.src_port, 0);
        assert_eq!(flow_v4.dst_port, 0);

        // IPv6 ICMP (proto = 58)
        let mut pkt_v6 = vec![0u8; 48];
        pkt_v6[0] = 0x60;
        pkt_v6[6] = 58; // ICMPv6
        pkt_v6[8..24].copy_from_slice(&[1u8; 16]);
        pkt_v6[24..40].copy_from_slice(&[2u8; 16]);

        let flow_v6 = FlowTuple::extract(&pkt_v6).expect("valid ipv6 icmp");
        assert_eq!(flow_v6.proto, 58);
        assert_eq!(flow_v6.src_port, 0);
        assert_eq!(flow_v6.dst_port, 0);
    }

    #[test]
    fn test_extract_ipv4_with_options() {
        // IPv4 with IHL = 6 (24 bytes)
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x46; // IHL = 6 words (24 bytes)
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 168, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 0, 2]);
        // TCP header begins at byte 24
        pkt[24..26].copy_from_slice(&443u16.to_be_bytes());
        pkt[26..28].copy_from_slice(&8443u16.to_be_bytes());

        let flow = FlowTuple::extract(&pkt).expect("valid ipv4 with options");
        assert_eq!(flow.proto, 6);
        assert_eq!(flow.src_port, 443);
        assert_eq!(flow.dst_port, 8443);
    }

    #[test]
    fn test_extract_ipv4_non_first_fragment() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[6] = 0x01; // Fragment offset = 256
        pkt[7] = 0x00;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // Data at offset 20 should not be read as ports
        pkt[20..22].copy_from_slice(&8080u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());

        let flow = FlowTuple::extract(&pkt).expect("fragmented ipv4");
        assert_eq!(flow.proto, 6);
        assert_eq!(flow.src_port, 0);
        assert_eq!(flow.dst_port, 0);
    }

    #[test]
    fn test_extract_truncated_and_malformed() {
        // Empty buffer
        assert_eq!(FlowTuple::extract(&[]), None);

        // Unknown IP version (e.g., 0, 5, 7)
        assert_eq!(FlowTuple::extract(&[0x00; 20]), None);
        assert_eq!(FlowTuple::extract(&[0x50; 20]), None);
        assert_eq!(FlowTuple::extract(&[0x70; 40]), None);

        // Truncated IPv4 header (< 20 bytes)
        assert_eq!(FlowTuple::extract(&[0x45; 10]), None);
        assert_eq!(FlowTuple::extract(&[0x45; 19]), None);

        // Invalid IPv4 IHL < 5 (< 20 bytes)
        let mut bad_ihl = [0u8; 20];
        bad_ihl[0] = 0x44; // IHL = 4 (16 bytes, invalid)
        assert_eq!(FlowTuple::extract(&bad_ihl), None);

        let mut zero_ihl = [0u8; 20];
        zero_ihl[0] = 0x40; // IHL = 0 (invalid)
        assert_eq!(FlowTuple::extract(&zero_ihl), None);

        // IPv4 packet shorter than declared IHL
        let mut short_ihl = [0u8; 20];
        short_ihl[0] = 0x48; // IHL = 8 (32 bytes), but pkt is 20 bytes
        assert_eq!(FlowTuple::extract(&short_ihl), None);

        // Truncated IPv6 header (< 40 bytes)
        assert_eq!(FlowTuple::extract(&[0x60; 20]), None);
        assert_eq!(FlowTuple::extract(&[0x60; 39]), None);

        // IPv4 TCP with payload < 4 bytes (ports cannot be extracted, fall back to 0)
        let mut short_tcp_v4 = vec![0u8; 22]; // IHL=20, payload=2 bytes
        short_tcp_v4[0] = 0x45;
        short_tcp_v4[9] = 6;
        let flow = FlowTuple::extract(&short_tcp_v4).expect("short payload still extracts L3");
        assert_eq!(flow.src_port, 0);
        assert_eq!(flow.dst_port, 0);

        // IPv6 TCP with payload < 4 bytes
        let mut short_tcp_v6 = vec![0u8; 42]; // Header=40, payload=2 bytes
        short_tcp_v6[0] = 0x60;
        short_tcp_v6[6] = 6;
        let flow = FlowTuple::extract(&short_tcp_v6).expect("short payload still extracts L3");
        assert_eq!(flow.src_port, 0);
        assert_eq!(flow.dst_port, 0);
    }

    #[test]
    fn test_flow_hash_determinism() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&8080u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());

        let flow1 = FlowTuple::extract(&pkt).unwrap();
        let flow2 = FlowTuple::extract(&pkt).unwrap();

        assert_eq!(flow1, flow2);
        assert_eq!(flow1.flow_hash(), flow2.flow_hash());
        assert_ne!(flow1.flow_hash(), 0);

        // Different flow should yield different hash
        let mut pkt_diff = pkt.clone();
        pkt_diff[20..22].copy_from_slice(&8081u16.to_be_bytes());
        let flow3 = FlowTuple::extract(&pkt_diff).unwrap();
        assert_ne!(flow1.flow_hash(), flow3.flow_hash());
    }
}
