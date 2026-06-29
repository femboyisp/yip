//! RaptorQ object encoding/decoding for the FEC transport. Encrypt-then-FEC:
//! the unit of coding is one sealed ciphertext frame ("object"), split into
//! source + repair symbols carrying an explicit OTI (object size) so the
//! decoder never has to infer it.

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use std::collections::{HashMap, VecDeque};

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

struct ObjState {
    decoder: Decoder,
    done: bool,
}

/// Reassembles RaptorQ symbols into objects, keeping multiple objects in flight
/// (keyed by `object_id`), tolerating loss and reordering, and evicting the
/// oldest object once `max_objects` is exceeded.
pub struct FecReassembler {
    symbol_size: u16,
    objects: HashMap<u16, ObjState>,
    order: VecDeque<u16>,
    max_objects: usize,
}

impl FecReassembler {
    /// Create a reassembler for a class's `symbol_size`, keeping at most
    /// `max_objects` partially-received objects.
    pub fn new(symbol_size: u16, max_objects: usize) -> Self {
        Self {
            symbol_size,
            objects: HashMap::new(),
            order: VecDeque::new(),
            max_objects: max_objects.max(1),
        }
    }

    /// Number of objects currently being reassembled.
    pub fn in_flight(&self) -> usize {
        self.objects.len()
    }

    /// Feed one received symbol. Returns the decoded object when it completes.
    pub fn push(&mut self, symbol: &Symbol) -> Option<Vec<u8>> {
        if !self.objects.contains_key(&symbol.object_id) {
            // Build the decoder from this first symbol's OTI.
            let oti = ObjectTransmissionInformation::with_defaults(
                u64::from(symbol.object_size),
                self.symbol_size,
            );
            let decoder = Decoder::new(oti);
            // Evict the oldest object if at capacity.
            if self.objects.len() >= self.max_objects {
                if let Some(oldest_id) = self.order.pop_front() {
                    self.objects.remove(&oldest_id);
                }
            }
            self.objects.insert(
                symbol.object_id,
                ObjState {
                    decoder,
                    done: false,
                },
            );
            self.order.push_back(symbol.object_id);
        }

        let state = self.objects.get_mut(&symbol.object_id)?;
        if state.done {
            return None; // late/duplicate symbol for an already-decoded object
        }

        let mut wire = Vec::with_capacity(4 + symbol.data.len());
        wire.extend_from_slice(&symbol.payload_id);
        wire.extend_from_slice(&symbol.data);
        let packet = EncodingPacket::deserialize(&wire);
        if let Some(object) = state.decoder.decode(packet) {
            state.done = true;
            return Some(object);
        }
        None
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

    #[test]
    fn reassembles_through_erasure_and_reordering() {
        let mut enc = FecEncoder::new();
        let ct: Vec<u8> = (0..5000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let params = crate::FlowClass::Bulk.params();
        let mut syms = enc.encode(&ct, params, 12);
        // reorder + drop every 4th
        syms.reverse();
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for (i, s) in syms.iter().enumerate() {
            if i % 4 == 0 {
                continue;
            } // erasure
            if let Some(frame) = re.push(s) {
                out = Some(frame);
                break;
            }
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn pipelines_two_objects_and_evicts_when_full() {
        let mut enc = FecEncoder::new();
        let params = crate::FlowClass::Default.params();
        let a = enc.encode(b"first object payload contents here", params, 4);
        let b = enc.encode(b"second object payload contents here", params, 4);
        let mut re = FecReassembler::new(params.symbol_size, 1); // cap 1 -> pushing b evicts a
                                                                 // feed only the first symbol of `a` (incomplete), then all of `b`
        re.push(&a[0]);
        assert_eq!(re.in_flight(), 1);
        let mut got_b = None;
        for s in &b {
            if let Some(f) = re.push(s) {
                got_b = Some(f);
            }
        }
        assert_eq!(
            got_b.as_deref(),
            Some(&b"second object payload contents here"[..])
        );
    }
}
