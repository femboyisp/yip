//! Loss feedback: receiver → sender control message.
//!
//! Encodes delivered and missing packet ranges as a compact byte stream.
#![forbid(unsafe_code)]

/// Maximum number of missing packets to report in a single LossReport.
pub const MAX_NACK: usize = 64;

/// A loss report from receiver to sender.
///
/// Reports which packets were successfully delivered and which are missing.
/// The wire format is big-endian: 4-byte delivered count, 8-byte high counter,
/// 2-byte missing count, then n × 8-byte missing sequence numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossReport {
    /// Total number of packets delivered so far.
    pub delivered_count: u32,
    /// The highest sequence number received (even if not delivered).
    pub high_counter: u64,
    /// Sequence numbers of packets that were not delivered.
    pub missing: Vec<u64>,
}

impl LossReport {
    /// Encode the report to bytes (big-endian).
    ///
    /// Caps `missing` at `MAX_NACK` entries.
    pub fn encode(&self) -> Vec<u8> {
        let n_missing = self.missing.len().min(MAX_NACK);
        let mut bytes = Vec::with_capacity(14 + n_missing * 8);
        bytes.extend_from_slice(&self.delivered_count.to_be_bytes());
        bytes.extend_from_slice(&self.high_counter.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(n_missing).unwrap().to_be_bytes());
        for i in 0..n_missing {
            bytes.extend_from_slice(&self.missing[i].to_be_bytes());
        }
        bytes
    }

    /// Decode a report from untrusted bytes.
    ///
    /// Returns `None` if the input is malformed (too short, or inconsistent
    /// missing count vs. payload length).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        // Check minimum header length
        if bytes.len() < 14 {
            return None;
        }

        // Parse header
        let delivered_count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let high_counter = u64::from_be_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        let n_missing = u16::from_be_bytes([bytes[12], bytes[13]]);
        let n_missing_usize = usize::from(n_missing);

        // Validate length matches expected payload
        let expected_len = 14 + n_missing_usize * 8;
        if bytes.len() != expected_len {
            return None;
        }

        // Parse missing sequence numbers
        let mut missing = Vec::with_capacity(n_missing_usize);
        for i in 0..n_missing_usize {
            let offset = 14 + i * 8;
            let num = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            missing.push(num);
        }

        Some(LossReport {
            delivered_count,
            high_counter,
            missing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_report_roundtrips() {
        let r = LossReport {
            delivered_count: 1000,
            high_counter: 5_000,
            missing: vec![10, 42, 4_999],
        };
        let bytes = r.encode();
        let got = LossReport::decode(&bytes).expect("decodes");
        assert_eq!(got.delivered_count, 1000);
        assert_eq!(got.high_counter, 5_000);
        assert_eq!(got.missing, vec![10, 42, 4_999]);
    }

    #[test]
    fn loss_report_decode_rejects_short_input() {
        assert!(LossReport::decode(&[]).is_none());
        assert!(LossReport::decode(&[0u8; 5]).is_none()); // shorter than the 14-byte header
    }

    #[test]
    fn loss_report_encode_caps_missing_at_max_nack() {
        let r = LossReport {
            delivered_count: 0,
            high_counter: 0,
            missing: (0..1000).collect(),
        };
        let got = LossReport::decode(&r.encode()).expect("decodes");
        assert_eq!(got.missing.len(), MAX_NACK);
    }
}
