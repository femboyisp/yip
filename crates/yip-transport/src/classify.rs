//! Per-flow classification: map an inner packet to a [`FlowClass`] via the
//! precedence policy rule -> DSCP/ToS -> flow-table heuristic -> default.

use crate::flow::FlowTable;
use crate::FlowClass;

/// The 5-tuple that uniquely identifies a flow.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    /// Source address as a 16-byte array (IPv4 occupies the low 4 bytes; rest are 0).
    pub src: [u8; 16],
    /// Destination address as a 16-byte array (IPv4 occupies the low 4 bytes; rest are 0).
    pub dst: [u8; 16],
    /// Source L4 port (0 for non-TCP/UDP protocols).
    pub src_port: u16,
    /// Destination L4 port (0 for non-TCP/UDP protocols).
    pub dst_port: u16,
    /// IP protocol number.
    pub proto: u8,
}

impl FlowKey {
    /// Return the canonical symmetric representation of this 5-tuple,
    /// sorting endpoints lexicographically so forward and reverse packets
    /// of the same bidirectional conversation produce identical keys.
    #[inline]
    pub fn canonical(&self) -> Self {
        if (self.src, self.src_port) <= (self.dst, self.dst_port) {
            self.clone()
        } else {
            Self {
                src: self.dst,
                dst: self.src,
                src_port: self.dst_port,
                dst_port: self.src_port,
                proto: self.proto,
            }
        }
    }
}

/// A user policy rule pinning matching flows to a class (highest precedence).
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// IP protocol number to match (None = any).
    pub proto: Option<u8>,
    /// Destination L4 port to match (None = any). Note: non-TCP/UDP packets
    /// report port 0, so `Some(0)` also matches ICMP/ESP/etc.; discriminate
    /// non-port protocols with `proto`, not `dst_port`.
    pub dst_port: Option<u16>,
    /// Class assigned to matching flows.
    pub class: FlowClass,
}

/// Classifies inner packets into flow classes.
pub struct Classifier {
    rules: Vec<PolicyRule>,
    flows: FlowTable,
}

struct Parsed {
    dscp: u8,
    key: FlowKey,
}

impl Classifier {
    /// Build a classifier from an ordered list of policy rules.
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self {
            rules,
            flows: FlowTable::new(1024, 10_000),
        }
    }

    /// Classify an inner frame. `l2` = true when the frame is an Ethernet (TAP)
    /// frame (skip the 14-byte Ethernet header), false for an L3 (TUN) IP packet.
    /// `now_ms` is the current wall-clock time in milliseconds, used by the flow
    /// heuristic.
    pub fn classify(&mut self, inner: &[u8], l2: bool, now_ms: u64) -> FlowClass {
        // 0. stateless pure TCP ACK detection
        if is_pure_tcp_ack(inner, l2) {
            return FlowClass::Ack;
        }

        let Some(p) = parse_ip(inner, l2) else {
            return FlowClass::Default;
        };
        // 1. explicit policy
        for r in &self.rules {
            if r.proto.is_none_or(|x| x == p.key.proto)
                && r.dst_port.is_none_or(|x| x == p.key.dst_port)
            {
                return r.class;
            }
        }
        // 2. DSCP
        match p.dscp {
            46 | 40 | 48 | 56 => return FlowClass::Realtime, // EF, CS5, CS6, CS7
            8 | 10 | 12 | 14 => return FlowClass::Bulk,      // CS1, AF11..AF13 (bulk-ish)
            _ => {}
        }
        // 3. heuristic: observe this packet, then consult flow history
        if p.key.proto == 6 || p.key.proto == 17 {
            let canonical = p.key.canonical();
            self.flows.observe(&canonical, inner.len(), now_ms);
            if let Some(class) = self.flows.classify(&canonical) {
                return class;
            }
        }
        // ICMP (IPv4 proto 1) and ICMPv6 (IPv6 proto 58) are latency-critical network diagnostics
        if p.key.proto == 1 || p.key.proto == 58 {
            return FlowClass::Realtime;
        }
        // 4. default
        FlowClass::Default
    }

    /// Observe an ingress packet arriving from a peer to update the bidirectional
    /// flow heuristic state without emitting a classification decision.
    pub fn observe_ingress(&mut self, inner: &[u8], l2: bool, now_ms: u64) {
        if is_pure_tcp_ack(inner, l2) {
            return;
        }
        if let Some(p) = parse_ip(inner, l2) {
            if p.key.proto == 6 || p.key.proto == 17 {
                let canonical = p.key.canonical();
                self.flows.observe(&canonical, inner.len(), now_ms);
            }
        }
    }
}

/// Statelessly inspect an L3/L2 packet to check whether it is a pure TCP ACK
/// (zero payload bytes, ACK flag set, and SYN/FIN/RST cleared).
///
/// Pure TCP ACKs are latency-critical and cumulative; classifying them into
/// `FlowClass::Ack` provides 0-RTT proactive FEC protection without blocking
/// on reactive ARQ timeouts.
pub fn is_pure_tcp_ack(inner: &[u8], l2: bool) -> bool {
    let ip = if l2 {
        let Some(ethertype_bytes) = inner.get(12..14) else {
            return false;
        };
        let ethertype = u16::from_be_bytes([ethertype_bytes[0], ethertype_bytes[1]]);
        match ethertype {
            0x0800 | 0x86DD => match inner.get(14..) {
                Some(payload) => payload,
                None => return false,
            },
            _ => return false,
        }
    } else {
        inner
    };

    let Some(&first_byte) = ip.first() else {
        return false;
    };
    let version = first_byte >> 4;
    let tcp = match version {
        4 => {
            let ihl = usize::from(first_byte & 0x0F) * 4;
            if ihl < 20 {
                return false;
            }
            let total_len = match ip.get(2..4) {
                Some(b) => usize::from(u16::from_be_bytes([b[0], b[1]])),
                None => return false,
            };
            if total_len < ihl + 20 || ip.len() < total_len {
                return false;
            }
            let proto = match ip.get(9) {
                Some(&p) => p,
                None => return false,
            };
            if proto != 6 {
                return false;
            }
            &ip[ihl..total_len]
        }
        6 => {
            let proto = match ip.get(6) {
                Some(&p) => p,
                None => return false,
            };
            if proto != 6 {
                return false;
            }
            let payload_len = match ip.get(4..6) {
                Some(b) => usize::from(u16::from_be_bytes([b[0], b[1]])),
                None => return false,
            };
            let total_len = 40 + payload_len;
            if ip.len() < total_len {
                return false;
            }
            &ip[40..total_len]
        }
        _ => return false,
    };

    let Some(tcp_hdr) = tcp.get(..20) else {
        return false;
    };

    let data_offset = usize::from(tcp_hdr[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() != data_offset {
        return false;
    }

    let flags = tcp_hdr[13];
    // ACK must be set (0x10)
    // SYN (0x02), FIN (0x01), RST (0x04) must be cleared (flags & 0x07 == 0)
    (flags & 0x10) != 0 && (flags & 0x07) == 0
}

/// Extract DSCP/proto/dst-port from an IPv4/IPv6 inner packet (None if malformed).
fn parse_ip(inner: &[u8], l2: bool) -> Option<Parsed> {
    let ip = if l2 {
        // Ethernet header is 14 bytes; only handle plain (non-VLAN) IPv4/IPv6.
        let ethertype = u16::from_be_bytes([*inner.get(12)?, *inner.get(13)?]);
        match ethertype {
            0x0800 | 0x86DD => inner.get(14..)?,
            _ => return None,
        }
    } else {
        inner
    };
    let version = ip.first()? >> 4;
    let (dscp, proto, l4_off, src, dst) = match version {
        4 => {
            let ihl = usize::from(ip[0] & 0x0F) * 4;
            let dscp = ip.get(1)? >> 2;
            let proto = *ip.get(9)?;
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src[..4].copy_from_slice(ip.get(12..16)?);
            dst[..4].copy_from_slice(ip.get(16..20)?);
            (dscp, proto, ihl, src, dst)
        }
        6 => {
            let tc = (u16::from(*ip.first()? & 0x0F) << 4) | u16::from(ip.get(1)? >> 4);
            let dscp = u8::try_from(tc >> 2).ok()?;
            let proto = *ip.get(6)?; // next-header
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(ip.get(8..24)?);
            dst.copy_from_slice(ip.get(24..40)?);
            (dscp, proto, 40, src, dst)
        }
        _ => return None,
    };
    // src/dst ports = bytes 0..2 / 2..4 of the L4 header, for TCP(6)/UDP(17)
    let (src_port, dst_port) = if matches!(proto, 6 | 17) {
        let sp = ip
            .get(l4_off..l4_off + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .unwrap_or(0);
        let dp = ip
            .get(l4_off + 2..l4_off + 4)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .unwrap_or(0);
        (sp, dp)
    } else {
        (0, 0)
    };
    Some(Parsed {
        dscp,
        key: FlowKey {
            src,
            dst,
            src_port,
            dst_port,
            proto,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    fn ipv4(dscp: u8, proto: u8, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45; // v4, IHL 5
        p[1] = dscp << 2; // DSCP in top 6 bits of ToS
        p[9] = proto;
        // dst port at IP payload offset 20 (UDP/TCP dst is bytes 2..4 of L4)
        let port_bytes = dst_port.to_be_bytes();
        p[22] = port_bytes[0];
        p[23] = port_bytes[1];
        p
    }

    #[test]
    fn dscp_ef_maps_to_realtime() {
        let mut c = Classifier::new(vec![]);
        // DSCP 46 (EF) -> Realtime
        assert_eq!(
            c.classify(&ipv4(46, 17, 5000), false, 0),
            FlowClass::Realtime
        );
        // DSCP 0 default -> Default
        assert_eq!(c.classify(&ipv4(0, 17, 5000), false, 0), FlowClass::Default);
    }

    #[test]
    fn policy_rule_overrides_dscp() {
        let mut c = Classifier::new(vec![PolicyRule {
            proto: Some(17),
            dst_port: Some(5000),
            class: FlowClass::Bulk,
        }]);
        // policy wins even though DSCP says realtime
        assert_eq!(c.classify(&ipv4(46, 17, 5000), false, 0), FlowClass::Bulk);
    }

    #[test]
    fn malformed_packet_is_default() {
        let mut c = Classifier::new(vec![]);
        assert_eq!(c.classify(&[0u8; 3], false, 0), FlowClass::Default);
    }

    #[test]
    fn parse_ip_extracts_full_5_tuple() {
        // IPv4 UDP: src 10.0.0.1, dst 10.0.0.2, sport 1111, dport 2222
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        p[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        p[20..22].copy_from_slice(&1111u16.to_be_bytes()); // sport
        p[22..24].copy_from_slice(&2222u16.to_be_bytes()); // dport
        let parsed = parse_ip(&p, false).unwrap();
        assert_eq!(parsed.key.src[..4], [10, 0, 0, 1]);
        assert_eq!(parsed.key.dst[..4], [10, 0, 0, 2]);
        assert_eq!(parsed.key.src_port, 1111);
        assert_eq!(parsed.key.dst_port, 2222);
        assert_eq!(parsed.key.proto, 17);
    }

    /// A policy rule must match only when BOTH `proto` and `dst_port` agree.
    /// Kills the `&&` -> `||` mutant (line 66): a rule matching only proto
    /// (not port) must NOT win when only the port matches (or vice versa).
    #[test]
    fn policy_rule_requires_both_proto_and_port_to_match() {
        let mut c = Classifier::new(vec![PolicyRule {
            proto: Some(6), // TCP, packet below is UDP (17) -> proto mismatch
            dst_port: Some(5000),
            class: FlowClass::Bulk,
        }]);
        // proto mismatches (17 != 6) but dst_port matches (5000); DSCP is 0 (no
        // DSCP match either), so a correct implementation falls through to the
        // heuristic on a cold flow -> Default. The `||` mutant would treat the
        // dst_port-only match as a hit and wrongly return Bulk.
        assert_eq!(
            c.classify(&ipv4(0, 17, 5000), false, 0),
            FlowClass::Default,
            "rule must require BOTH proto and port to match, not either"
        );
    }

    /// DSCP CS1/AF11..AF13 (8, 10, 12, 14) must map to Bulk. Kills the `delete
    /// match arm 8 | 10 | 12 | 14` mutant (line 74): deleting the arm would let
    /// these DSCP values fall through to the heuristic/default path instead.
    #[test]
    fn dscp_bulk_marks_map_to_bulk() {
        let mut c = Classifier::new(vec![]);
        for dscp in [8u8, 10, 12, 14] {
            assert_eq!(
                c.classify(&ipv4(dscp, 17, 5000), false, 0),
                FlowClass::Bulk,
                "DSCP {dscp} must classify as Bulk"
            );
        }
    }

    /// `parse_ip` must actually strip the 14-byte Ethernet header and parse the
    /// inner IPv4 packet when `l2 = true` and the ethertype is 0x0800. Kills
    /// the `delete match arm 0x0800 | 0x86DD` mutant (line 93): deleting the
    /// arm makes `parse_ip` return `None` for every L2 frame, regardless of
    /// ethertype, so `classify` would always fall back to `Default`.
    #[test]
    fn l2_ethernet_ipv4_frame_is_parsed_and_classified() {
        let mut c = Classifier::new(vec![]);
        let mut frame = vec![0u8; 14 + 24]; // Ethernet header + minimal IPv4
        frame[12] = 0x08;
        frame[13] = 0x00; // ethertype 0x0800 (IPv4)
        let ip = &mut frame[14..];
        ip[0] = 0x45; // v4, IHL 5
        ip[1] = 46 << 2; // DSCP 46 (EF) -> Realtime
        ip[9] = 17; // UDP
        assert_eq!(
            c.classify(&frame, true, 0),
            FlowClass::Realtime,
            "L2 frame with ethertype 0x0800 must be parsed as IPv4 and classified via DSCP"
        );
    }

    #[test]
    fn heuristic_classifies_unmarked_small_flow_after_warmup() {
        let mut c = Classifier::new(vec![]);
        // unmarked (DSCP 0) small UDP packets on one flow
        let pkt = ipv4(0, 17, 5000); // 24 bytes, DSCP 0
                                     // first few packets: cold -> Default
        assert_eq!(c.classify(&pkt, false, 0), FlowClass::Default);
        // warm the flow up with several small packets
        for i in 1..6 {
            c.classify(&pkt, false, i * 5);
        }
        // now the heuristic should kick in -> Realtime
        assert_eq!(c.classify(&pkt, false, 30), FlowClass::Realtime);
    }

    #[test]
    fn canonical_flow_key_is_symmetric() {
        let mut src = [0u8; 16];
        src[..4].copy_from_slice(&[10, 0, 0, 1]);
        let mut dst = [0u8; 16];
        dst[..4].copy_from_slice(&[10, 0, 0, 2]);

        let fwd = FlowKey {
            src,
            dst,
            src_port: 1234,
            dst_port: 5678,
            proto: 6,
        };
        let rev = FlowKey {
            src: dst,
            dst: src,
            src_port: 5678,
            dst_port: 1234,
            proto: 6,
        };

        assert_eq!(fwd.canonical(), rev.canonical());
        assert_eq!(fwd.canonical().src, src);
        assert_eq!(fwd.canonical().src_port, 1234);
    }

    #[test]
    fn bidirectional_observation_accelerates_flow_classification() {
        let mut c = Classifier::new(vec![]);

        let make_udp = |src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16| {
            let mut p = vec![0u8; 100];
            p[0] = 0x45; // IPv4, IHL 5
            p[9] = 17; // UDP
            p[12..16].copy_from_slice(&src_ip);
            p[16..20].copy_from_slice(&dst_ip);
            p[20..22].copy_from_slice(&sport.to_be_bytes());
            p[22..24].copy_from_slice(&dport.to_be_bytes());
            p
        };

        let fwd = make_udp([192, 168, 1, 10], [192, 168, 1, 20], 10000, 20000);
        let rev = make_udp([192, 168, 1, 20], [192, 168, 1, 10], 20000, 10000);

        // Feed 2 forward packets and 2 reverse packets, spaced at 10ms intervals.
        assert_eq!(c.classify(&fwd, false, 0), FlowClass::Default);
        c.observe_ingress(&rev, false, 10);
        c.observe_ingress(&rev, false, 20);

        // After the 4th packet (2 forward + 2 reverse), the flow heuristic kicks in -> Realtime.
        assert_eq!(c.classify(&fwd, false, 30), FlowClass::Realtime);
    }

    #[test]
    fn test_tcp_data_stream_classification_with_reverse_acks() {
        let make_tcp_v4 =
            |src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16, size: usize| {
                let mut p = vec![0u8; size];
                p[0] = 0x45;
                p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
                p[9] = 6;
                p[12..16].copy_from_slice(&src_ip);
                p[16..20].copy_from_slice(&dst_ip);
                p[20..22].copy_from_slice(&sport.to_be_bytes());
                p[22..24].copy_from_slice(&dport.to_be_bytes());
                p[32] = 0x50; // data offset 5 (20 bytes)
                p
            };
        let make_tcp_v6 =
            |src_ip: [u8; 16], dst_ip: [u8; 16], sport: u16, dport: u16, size: usize| {
                let mut p = vec![0u8; size];
                p[0] = 0x60;
                let payload_len = (size - 40) as u16;
                p[4..6].copy_from_slice(&payload_len.to_be_bytes());
                p[6] = 6; // Next header: TCP
                p[8..24].copy_from_slice(&src_ip);
                p[24..40].copy_from_slice(&dst_ip);
                p[40..42].copy_from_slice(&sport.to_be_bytes());
                p[42..44].copy_from_slice(&dport.to_be_bytes());
                p[52] = 0x80; // data offset 8 (32 bytes with options)
                p
            };

        // Test IPv4: TCP data stream with reverse ACKs must stay Bulk
        let mut c4 = Classifier::new(vec![]);
        let fwd4_data = make_tcp_v4([10, 0, 0, 1], [10, 0, 0, 2], 1234, 5201, 1400);
        let mut rev4_ack = make_tcp_v4([10, 0, 0, 2], [10, 0, 0, 1], 5201, 1234, 52);
        rev4_ack[32] = 0x80;
        rev4_ack[33] = 0x10; // ACK flag

        for i in 0..10 {
            c4.classify(&fwd4_data, false, i * 10);
        }
        for i in 11..20 {
            c4.observe_ingress(&rev4_ack, false, i * 10);
            let cls = c4.classify(&fwd4_data, false, i * 10 + 5);
            assert_eq!(
                cls,
                FlowClass::Bulk,
                "IPv4 packet {i} must remain Bulk despite reverse ACKs"
            );
        }

        // Test IPv6: TCP data stream with reverse ACKs must stay Bulk
        let mut c6 = Classifier::new(vec![]);
        let mut src6 = [0u8; 16];
        src6[15] = 1;
        let mut dst6 = [0u8; 16];
        dst6[15] = 2;
        let fwd6_data = make_tcp_v6(src6, dst6, 1234, 5201, 1400);
        let mut rev6_ack = make_tcp_v6(dst6, src6, 5201, 1234, 72);
        rev6_ack[53] = 0x10; // ACK flag

        for i in 0..10 {
            c6.classify(&fwd6_data, false, i * 10);
        }
        for i in 11..20 {
            c6.observe_ingress(&rev6_ack, false, i * 10);
            let cls = c6.classify(&fwd6_data, false, i * 10 + 5);
            assert_eq!(
                cls,
                FlowClass::Bulk,
                "IPv6 packet {i} must remain Bulk despite reverse ACKs"
            );
        }
    }

    #[test]
    fn icmpv6_and_multicast_do_not_populate_flow_table() {
        let mut c = Classifier::new(vec![]);
        let make_ipv6 = |proto: u8, dst: [u8; 16]| {
            let mut p = vec![0u8; 48];
            p[0] = 0x60; // IPv6, TC 0
            p[6] = proto;
            p[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            p[24..40].copy_from_slice(&dst);
            p
        };

        // ICMPv6 unicast (proto 58)
        let icmpv6 = make_ipv6(
            58,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        );
        assert_eq!(c.classify(&icmpv6, false, 0), FlowClass::Realtime);
        assert!(c.flows.is_empty(), "ICMPv6 must not populate flow table");

        // IPv6 multicast discovery (ff02::1, all-nodes)
        let mut mcast_dst = [0u8; 16];
        mcast_dst[0] = 0xff;
        mcast_dst[1] = 0x02;
        mcast_dst[15] = 0x01;
        let mcast_icmp = make_ipv6(58, mcast_dst);
        assert_eq!(c.classify(&mcast_icmp, false, 10), FlowClass::Realtime);
        assert!(
            c.flows.is_empty(),
            "multicast ICMPv6 must not populate flow table"
        );

        // Also test observe_ingress with ICMPv6
        c.observe_ingress(&icmpv6, false, 20);
        assert!(
            c.flows.is_empty(),
            "observe_ingress on ICMPv6 must not populate flow table"
        );
    }

    #[test]
    fn pure_tcp_ack_classification_ipv4_and_ipv6() {
        let mut c = Classifier::new(vec![]);

        // 1. Minimal IPv4 pure ACK (20B IP + 20B TCP, ACK set, data_offset = 20B)
        let mut v4_ack = vec![0u8; 40];
        v4_ack[0] = 0x45; // IPv4, IHL 5
        v4_ack[2..4].copy_from_slice(&(40u16).to_be_bytes()); // total len = 40
        v4_ack[9] = 6; // TCP
        v4_ack[32] = 0x50; // data offset = 5 words (20 bytes)
        v4_ack[33] = 0x10; // ACK flag
        assert!(is_pure_tcp_ack(&v4_ack, false));
        assert_eq!(c.classify(&v4_ack, false, 0), FlowClass::Ack);

        // 2. IPv4 pure ACK with TCP Timestamps (20B IP + 32B TCP, total len = 52)
        let mut v4_ts_ack = vec![0u8; 52];
        v4_ts_ack[0] = 0x45;
        v4_ts_ack[2..4].copy_from_slice(&(52u16).to_be_bytes());
        v4_ts_ack[9] = 6;
        v4_ts_ack[32] = 0x80; // data offset = 8 words (32 bytes)
        v4_ts_ack[33] = 0x10; // ACK
        assert!(is_pure_tcp_ack(&v4_ts_ack, false));
        assert_eq!(c.classify(&v4_ts_ack, false, 0), FlowClass::Ack);

        // 3. IPv4 pure ACK with IP Options (24B IP + 20B TCP, total len = 44)
        let mut v4_opt_ack = vec![0u8; 44];
        v4_opt_ack[0] = 0x46; // IHL = 6 (24 bytes)
        v4_opt_ack[2..4].copy_from_slice(&(44u16).to_be_bytes());
        v4_opt_ack[9] = 6;
        v4_opt_ack[36] = 0x50; // TCP at offset 24, data offset = 20B
        v4_opt_ack[37] = 0x10; // ACK
        assert!(is_pure_tcp_ack(&v4_opt_ack, false));
        assert_eq!(c.classify(&v4_opt_ack, false, 0), FlowClass::Ack);

        // 4. Minimal IPv6 pure ACK (40B IP + 20B TCP, total len = 60, payload_len = 20)
        let mut v6_ack = vec![0u8; 60];
        v6_ack[0] = 0x60; // IPv6
        v6_ack[4..6].copy_from_slice(&(20u16).to_be_bytes()); // payload len = 20
        v6_ack[6] = 6; // TCP
        v6_ack[52] = 0x50; // data offset = 5 words (20 bytes)
        v6_ack[53] = 0x10; // ACK
        assert!(is_pure_tcp_ack(&v6_ack, false));
        assert_eq!(c.classify(&v6_ack, false, 0), FlowClass::Ack);

        // 4. IPv6 pure ACK with TCP Timestamps (40B IP + 32B TCP, payload_len = 32)
        let mut v6_ts_ack = vec![0u8; 72];
        v6_ts_ack[0] = 0x60;
        v6_ts_ack[4..6].copy_from_slice(&(32u16).to_be_bytes());
        v6_ts_ack[6] = 6;
        v6_ts_ack[52] = 0x80; // data offset = 8 words (32 bytes)
        v6_ts_ack[53] = 0x10; // ACK
        assert!(is_pure_tcp_ack(&v6_ts_ack, false));
        assert_eq!(c.classify(&v6_ts_ack, false, 0), FlowClass::Ack);

        // 5. Ethernet L2 pure ACK frame
        let mut l2_ack = vec![0u8; 14 + 40];
        l2_ack[12] = 0x08;
        l2_ack[13] = 0x00; // IPv4
        l2_ack[14..].copy_from_slice(&v4_ack);
        assert!(is_pure_tcp_ack(&l2_ack, true));
        assert_eq!(c.classify(&l2_ack, true, 0), FlowClass::Ack);
    }

    #[test]
    fn non_pure_tcp_acks_rejected() {
        // TCP packet without ACK flag (flags = 0x00)
        let mut no_ack = vec![0u8; 40];
        no_ack[0] = 0x45;
        no_ack[2..4].copy_from_slice(&(40u16).to_be_bytes());
        no_ack[9] = 6;
        no_ack[32] = 0x50;
        no_ack[33] = 0x00; // No ACK flag
        assert!(!is_pure_tcp_ack(&no_ack, false));

        // TCP packet with PSH only (flags = 0x08, no ACK)
        let mut psh_no_ack = no_ack.clone();
        psh_no_ack[33] = 0x08;
        assert!(!is_pure_tcp_ack(&psh_no_ack, false));

        // TCP ACK carrying payload (40B headers + 10B payload = 50B)
        let mut ack_with_payload = vec![0u8; 50];
        ack_with_payload[0] = 0x45;
        ack_with_payload[2..4].copy_from_slice(&(50u16).to_be_bytes());
        ack_with_payload[9] = 6;
        ack_with_payload[32] = 0x50; // 20B TCP header
        ack_with_payload[33] = 0x10; // ACK
        assert!(!is_pure_tcp_ack(&ack_with_payload, false));

        // TCP SYN-ACK (SYN bit set: 0x12)
        let mut syn_ack = vec![0u8; 40];
        syn_ack[0] = 0x45;
        syn_ack[2..4].copy_from_slice(&(40u16).to_be_bytes());
        syn_ack[9] = 6;
        syn_ack[32] = 0x50;
        syn_ack[33] = 0x12; // SYN | ACK
        assert!(!is_pure_tcp_ack(&syn_ack, false));

        // TCP FIN-ACK (FIN bit set: 0x11)
        let mut fin_ack = vec![0u8; 40];
        fin_ack[0] = 0x45;
        fin_ack[2..4].copy_from_slice(&(40u16).to_be_bytes());
        fin_ack[9] = 6;
        fin_ack[32] = 0x50;
        fin_ack[33] = 0x11; // FIN | ACK
        assert!(!is_pure_tcp_ack(&fin_ack, false));

        // TCP RST-ACK (RST bit set: 0x14)
        let mut rst_ack = vec![0u8; 40];
        rst_ack[0] = 0x45;
        rst_ack[2..4].copy_from_slice(&(40u16).to_be_bytes());
        rst_ack[9] = 6;
        rst_ack[32] = 0x50;
        rst_ack[33] = 0x14; // RST | ACK
        assert!(!is_pure_tcp_ack(&rst_ack, false));

        // Bogus data offset < 20 (e.g. data_offset = 16)
        let mut bogus_offset = vec![0u8; 40];
        bogus_offset[0] = 0x45;
        bogus_offset[2..4].copy_from_slice(&(40u16).to_be_bytes());
        bogus_offset[9] = 6;
        bogus_offset[32] = 0x40; // 4 words = 16 bytes (< 20)
        bogus_offset[33] = 0x10;
        assert!(!is_pure_tcp_ack(&bogus_offset, false));

        // Options advertised but packet truncated (data_offset = 32, but tcp.len() == 20)
        let mut truncated_options = vec![0u8; 40];
        truncated_options[0] = 0x45;
        truncated_options[2..4].copy_from_slice(&(40u16).to_be_bytes());
        truncated_options[9] = 6;
        truncated_options[32] = 0x80; // data_offset = 32
        truncated_options[33] = 0x10;
        assert!(!is_pure_tcp_ack(&truncated_options, false));

        // Non-TCP protocols (UDP = 17)
        let mut udp_pkt = vec![0u8; 40];
        udp_pkt[0] = 0x45;
        udp_pkt[2..4].copy_from_slice(&(40u16).to_be_bytes());
        udp_pkt[9] = 17; // UDP
        assert!(!is_pure_tcp_ack(&udp_pkt, false));

        // IPv4 IHL < 20 (IHL = 4 -> 16 bytes)
        let mut bad_ihl = vec![0u8; 40];
        bad_ihl[0] = 0x44;
        bad_ihl[2..4].copy_from_slice(&(40u16).to_be_bytes());
        bad_ihl[9] = 6;
        assert!(!is_pure_tcp_ack(&bad_ihl, false));

        // IPv4 total_len < ihl
        let mut short_total = vec![0u8; 40];
        short_total[0] = 0x45;
        short_total[2..4].copy_from_slice(&(16u16).to_be_bytes());
        short_total[9] = 6;
        assert!(!is_pure_tcp_ack(&short_total, false));

        // IPv4 packet buffer shorter than total_len
        let mut truncated_v4 = vec![0u8; 39];
        truncated_v4[0] = 0x45;
        truncated_v4[2..4].copy_from_slice(&(40u16).to_be_bytes());
        truncated_v4[9] = 6;
        assert!(!is_pure_tcp_ack(&truncated_v4, false));

        // IPv6 non-TCP (UDP = 17)
        let mut v6_udp = vec![0u8; 60];
        v6_udp[0] = 0x60;
        v6_udp[4..6].copy_from_slice(&(20u16).to_be_bytes());
        v6_udp[6] = 17; // UDP
        assert!(!is_pure_tcp_ack(&v6_udp, false));

        // IPv6 packet buffer shorter than 40 + payload_len
        let mut truncated_v6 = vec![0u8; 59];
        truncated_v6[0] = 0x60;
        truncated_v6[4..6].copy_from_slice(&(20u16).to_be_bytes()); // total 60
        truncated_v6[6] = 6;
        assert!(!is_pure_tcp_ack(&truncated_v6, false));

        // Unknown IP version (e.g. 5)
        let mut bad_ver = vec![0u8; 40];
        bad_ver[0] = 0x50;
        assert!(!is_pure_tcp_ack(&bad_ver, false));

        // L2 boundaries
        assert!(!is_pure_tcp_ack(&[0u8; 11], true));
        assert!(!is_pure_tcp_ack(&[0u8; 12], true));
        assert!(!is_pure_tcp_ack(&[0u8; 13], true));
        let mut l2_bad_ethertype = vec![0u8; 54];
        l2_bad_ethertype[12] = 0x88;
        l2_bad_ethertype[13] = 0x47; // MPLS
        assert!(!is_pure_tcp_ack(&l2_bad_ethertype, true));

        // Empty / truncated packets
        assert!(!is_pure_tcp_ack(&[], false));
        assert!(!is_pure_tcp_ack(&[0x45], false));
        assert!(!is_pure_tcp_ack(&[0x45, 0, 0, 40], false));
    }
}
