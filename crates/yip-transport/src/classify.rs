//! Per-flow classification: map an inner packet to a [`FlowClass`] via the
//! precedence policy rule -> DSCP/ToS -> heuristic -> default.

use crate::FlowClass;

/// A user policy rule pinning matching flows to a class (highest precedence).
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// IP protocol number to match (None = any).
    pub proto: Option<u8>,
    /// Destination L4 port to match (None = any).
    pub dst_port: Option<u16>,
    /// Class assigned to matching flows.
    pub class: FlowClass,
}

/// Classifies inner packets into flow classes.
#[derive(Debug, Clone)]
pub struct Classifier {
    rules: Vec<PolicyRule>,
}

struct Parsed {
    dscp: u8,
    proto: u8,
    dst_port: Option<u16>,
}

impl Classifier {
    /// Build a classifier from an ordered list of policy rules.
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// Classify an inner frame. `l2` = true when the frame is an Ethernet (TAP)
    /// frame (skip the 14-byte Ethernet header), false for an L3 (TUN) IP packet.
    pub fn classify(&self, inner: &[u8], l2: bool) -> FlowClass {
        let Some(p) = parse_ip(inner, l2) else {
            return FlowClass::Default;
        };
        // 1. explicit policy
        for r in &self.rules {
            if r.proto.is_none_or(|x| x == p.proto)
                && r.dst_port.is_none_or(|x| Some(x) == p.dst_port)
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
        // 3. default
        FlowClass::Default
    }
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
    let (dscp, proto, l4_off) = match version {
        4 => {
            let ihl = usize::from(ip[0] & 0x0F) * 4;
            let dscp = ip.get(1)? >> 2;
            let proto = *ip.get(9)?;
            (dscp, proto, ihl)
        }
        6 => {
            let tc = (u16::from(*ip.first()? & 0x0F) << 4) | u16::from(ip.get(1)? >> 4);
            let dscp = u8::try_from(tc >> 2).ok()?;
            let proto = *ip.get(6)?; // next-header
            (dscp, proto, 40)
        }
        _ => return None,
    };
    // dst port = bytes 2..4 of the L4 header, for TCP(6)/UDP(17)
    let dst_port = if matches!(proto, 6 | 17) {
        ip.get(l4_off + 2..l4_off + 4)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    } else {
        None
    };
    Some(Parsed {
        dscp,
        proto,
        dst_port,
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
        let c = Classifier::new(vec![]);
        // DSCP 46 (EF) -> Realtime
        assert_eq!(c.classify(&ipv4(46, 17, 5000), false), FlowClass::Realtime);
        // DSCP 0 default -> Default
        assert_eq!(c.classify(&ipv4(0, 17, 5000), false), FlowClass::Default);
    }

    #[test]
    fn policy_rule_overrides_dscp() {
        let c = Classifier::new(vec![PolicyRule {
            proto: Some(17),
            dst_port: Some(5000),
            class: FlowClass::Bulk,
        }]);
        // policy wins even though DSCP says realtime
        assert_eq!(c.classify(&ipv4(46, 17, 5000), false), FlowClass::Bulk);
    }

    #[test]
    fn malformed_packet_is_default() {
        let c = Classifier::new(vec![]);
        assert_eq!(c.classify(&[0u8; 3], false), FlowClass::Default);
    }
}
