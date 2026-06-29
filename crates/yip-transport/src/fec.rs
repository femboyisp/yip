//! RaptorQ object encoding/decoding for the FEC transport. Encrypt-then-FEC:
//! the unit of coding is one sealed ciphertext frame ("object"), split into
//! source + repair symbols carrying an explicit OTI (object size) so the
//! decoder never has to infer it.

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use std::collections::{HashMap, VecDeque};

/// Maximum permitted object size for a single FEC-coded frame (256 KiB).
///
/// This caps the memory a single forged symbol can cause to be allocated in the
/// raptorq decoder's `vec![None; source_symbols]` pre-allocation.  256 KiB is
/// comfortably above any realistic coalesced ciphertext frame while keeping the
/// worst-case per-object footprint bounded.
const MAX_OBJECT_SIZE: u32 = 262_144;

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
    /// Number of source blocks (RFC 6330 Z), cached at construction time so
    /// subsequent symbols can be validated without a `Decoder` config getter.
    source_blocks: u8,
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
    ///
    /// Returns `None` (without panicking) for any of the following attacker-
    /// supplied values that would otherwise crash the raptorq decoder:
    ///
    /// * `object_size == 0` — raptorq divides by a zero symbol count (C1).
    /// * `object_size > MAX_OBJECT_SIZE` — bounds memory amplification (C1 ext).
    /// * `payload_id[0]` (Source Block Number) >= the object's source-block count —
    ///   raptorq would index past the end of `self.blocks` (C2).
    ///
    /// The C2 guard uses `oti.source_blocks()` (exposed by
    /// `ObjectTransmissionInformation` in raptorq 2.0) to derive the block count
    /// from the same OTI used to construct the decoder, so validation and
    /// construction are always consistent.
    pub fn push(&mut self, symbol: &Symbol) -> Option<Vec<u8>> {
        // --- C1: reject zero or oversized object_size before touching raptorq ---
        if symbol.object_size == 0 || symbol.object_size > MAX_OBJECT_SIZE {
            return None;
        }

        if !self.objects.contains_key(&symbol.object_id) {
            // Build the decoder from this first symbol's OTI.
            let oti = ObjectTransmissionInformation::with_defaults(
                u64::from(symbol.object_size),
                self.symbol_size,
            );

            // --- C2: reject symbols whose Source Block Number is out of range ---
            // `oti.source_blocks()` returns the Z parameter from RFC 6330; the
            // raptorq Decoder pre-allocates exactly Z slots and indexes them
            // directly by SBN, so SBN >= Z would panic with an out-of-bounds
            // access.  We cache `source_blocks` in ObjState so subsequent
            // symbols for the same object can be validated without requiring a
            // public config getter on `Decoder`.
            let source_blocks = oti.source_blocks();
            let sbn = symbol.payload_id[0];
            if sbn >= source_blocks {
                return None;
            }

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
                    source_blocks,
                    done: false,
                },
            );
            self.order.push_back(symbol.object_id);
        } else {
            // Object already tracked — still validate SBN against the cached
            // block count before handing the packet to raptorq.
            let sbn = symbol.payload_id[0];
            let source_blocks = self
                .objects
                .get(&symbol.object_id)
                .map(|s| s.source_blocks)
                .unwrap_or(0);
            if sbn >= source_blocks {
                return None;
            }
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

    // --- Malformed-input / DoS-prevention tests ----------------------------------
    //
    // Each test constructs a Symbol by hand (no real encoder needed) and confirms
    // that `push` returns `None` without panicking, regardless of how raptorq
    // would handle the malformed fields internally.

    fn dummy_symbol(object_size: u32, sbn: u8) -> Symbol {
        // payload_id[0] = SBN; bytes [1..3] = ESI 0.
        Symbol {
            object_id: 0,
            object_size,
            payload_id: [sbn, 0, 0, 0],
            data: vec![0u8; 1200], // plausible symbol body
        }
    }

    /// C1a: object_size == 0 → raptorq would divide by zero; must return None.
    #[test]
    fn push_zero_object_size_returns_none_no_panic() {
        let mut re = FecReassembler::new(1200, 64);
        let sym = dummy_symbol(0, 0);
        assert_eq!(re.push(&sym), None, "zero object_size must be rejected");
    }

    /// C1b: object_size > MAX_OBJECT_SIZE → memory amplification guard; None.
    #[test]
    fn push_oversized_object_size_returns_none_no_panic() {
        let mut re = FecReassembler::new(1200, 64);
        // u32::MAX is far above any realistic frame size.
        let sym = dummy_symbol(u32::MAX, 0);
        assert_eq!(
            re.push(&sym),
            None,
            "oversized object_size must be rejected"
        );

        // Also check the boundary: exactly MAX_OBJECT_SIZE + 1.
        let sym2 = dummy_symbol(MAX_OBJECT_SIZE + 1, 0);
        assert_eq!(
            re.push(&sym2),
            None,
            "object_size just above MAX must be rejected"
        );
    }

    /// C2: SBN (payload_id[0]) == 255 on a small object whose source-block
    /// count is 1 → raptorq would index blocks[255], which is out of bounds; None.
    #[test]
    fn push_out_of_range_sbn_returns_none_no_panic() {
        let mut re = FecReassembler::new(1200, 64);
        // A 1-KiB object with symbol_size 1200 fits in a single source block
        // (Z == 1), so SBN 255 is way out of range.
        let sym = dummy_symbol(1024, 255);
        assert_eq!(
            re.push(&sym),
            None,
            "SBN beyond source-block count must be rejected"
        );
    }

    // --- End malformed-input tests -----------------------------------------------

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
