//! RaptorQ object encoding/decoding for the FEC transport. Encrypt-then-FEC:
//! the unit of coding is one sealed ciphertext frame ("object"), split into
//! source + repair symbols carrying an explicit OTI (object size) so the
//! decoder never has to infer it.

use raptorq::{Encoder, EncodingPacket, ObjectTransmissionInformation};

/// One wire-bound RaptorQ symbol plus the metadata the receiver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Which pipelined object this symbol belongs to.
    pub object_id: u16,
    /// The object's RaptorQ transfer length (ciphertext byte count).
    pub object_size: u32,
    /// RaptorQ payload identifier (SBN + ESI).
    pub payload_id: [u8; 4],
    /// The symbol bytes.
    pub data: Vec<u8>,
}

/// Encodes ciphertext frames into RaptorQ symbols, assigning monotonic object ids.
#[derive(Debug, Default)]
pub struct FecEncoder {
    next_object_id: u16,
}

impl FecEncoder {
    /// Create an encoder starting at object id 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode one ciphertext frame into source + `repair` symbols under `params`.
    pub fn encode(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        repair: u32,
    ) -> Vec<Symbol> {
        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        let object_size = u32::try_from(ciphertext.len()).expect("frame fits u32");
        let oti = ObjectTransmissionInformation::with_defaults(
            u64::from(object_size),
            params.symbol_size,
        );
        let encoder = Encoder::new(ciphertext, oti);
        encoder
            .get_encoded_packets(repair)
            .into_iter()
            .map(|p| split_packet(object_id, object_size, &p))
            .collect()
    }
}

/// Split a serialized EncodingPacket into the 4-byte payload-id and the symbol bytes.
fn split_packet(object_id: u16, object_size: u32, packet: &EncodingPacket) -> Symbol {
    let bytes = packet.serialize();
    let mut payload_id = [0u8; 4];
    payload_id.copy_from_slice(&bytes[..4]);
    Symbol {
        object_id,
        object_size,
        payload_id,
        data: bytes[4..].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    #[test]
    fn encode_produces_source_plus_repair_with_explicit_oti() {
        let mut enc = FecEncoder::new();
        let ct: Vec<u8> = (0..3000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let params = FlowClass::Bulk.params();
        let syms = enc.encode(&ct, params, 8);
        // object_size carried explicitly on every symbol
        assert!(syms.iter().all(|s| s.object_size == 3000));
        // distinct object_ids increment
        let syms2 = enc.encode(&ct, params, 8);
        assert_eq!(syms[0].object_id, 0);
        assert_eq!(syms2[0].object_id, 1);
        // payload_id is 4 bytes; data non-empty
        assert_eq!(syms[0].payload_id.len(), 4);
        assert!(!syms[0].data.is_empty());
        // at least source symbols (ceil(3000/1200)=3) plus 8 repair
        assert!(syms.len() >= 3 + 8);
    }
}
