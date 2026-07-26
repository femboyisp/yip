//! Systematic Reed–Solomon FEC (RS-v1, spec §3.2.1) for the transport. Encrypt-
//! then-FEC: one sealed ciphertext frame is the object, split into K source
//! symbols of `symbol_size` (last zero-padded) plus R repair symbols generated
//! under a `rs::Scheme` (P+Q for R<=2, Cauchy for R>=3). Each `Symbol` carries a
//! codec-tagged `payload_id = [0x01, idx_hi, idx_lo, scheme]`.
#![forbid(unsafe_code)]

use crate::rs;
use std::collections::{HashMap, VecDeque};

/// Maximum permitted object size for a single FEC-coded frame (256 KiB): bounds
/// the memory a forged symbol can cause the decoder to allocate.
const MAX_OBJECT_SIZE: u32 = 262_144;

/// Codec tag for RS-v1 in `payload_id[0]` (pre-slots RLC as 0x02).
const CODEC_RS_V1: u8 = 0x01;

/// One wire-bound RS symbol plus the metadata the receiver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Which pipelined object this symbol belongs to.
    pub object_id: u16,
    /// The object's original ciphertext byte count (yields K = ceil(size/symbol_size)).
    pub object_size: u32,
    /// `[codec_tag, symbol_index_hi, symbol_index_lo, scheme]`.
    pub payload_id: [u8; 4],
    /// The symbol bytes (exactly `symbol_size`).
    pub data: Vec<u8>,
}

/// Pack `[0x01, idx_be_hi, idx_be_lo, scheme]`.
fn pack_payload_id(symbol_index: u16, scheme: u8) -> [u8; 4] {
    let idx = symbol_index.to_be_bytes();
    [CODEC_RS_V1, idx[0], idx[1], scheme]
}

/// Return `(symbol_index, scheme)` if the codec tag is RS-v1 and the scheme id is
/// known, else `None`.
fn parse_payload_id(payload_id: &[u8; 4]) -> Option<(u16, rs::Scheme)> {
    if payload_id[0] != CODEC_RS_V1 {
        return None;
    }
    let scheme = rs::Scheme::from_u8(payload_id[3])?;
    Some((u16::from_be_bytes([payload_id[1], payload_id[2]]), scheme))
}

/// Number of source symbols for an object of `object_size` at `symbol_size`.
fn source_count(object_size: u32, symbol_size: u16) -> usize {
    let size = usize::try_from(object_size).expect("object_size fits usize");
    size.div_ceil(usize::from(symbol_size))
}

/// Split `ciphertext` into `k` source shards of `sym` bytes each (last zero-padded).
fn split_source(ciphertext: &[u8], k: usize, sym: usize) -> Vec<Vec<u8>> {
    let mut shards = vec![vec![0u8; sym]; k];
    for (i, shard) in shards.iter_mut().enumerate() {
        let start = i * sym;
        let end = (start + sym).min(ciphertext.len());
        if start < ciphertext.len() {
            shard[..end - start].copy_from_slice(&ciphertext[start..end]);
        }
    }
    shards
}

/// Encodes ciphertext frames into RS symbols, assigning monotonic object ids.
#[derive(Debug, Default)]
pub struct FecEncoder {
    next_object_id: u16,
}

impl FecEncoder {
    /// Create an encoder starting at object id 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode one ciphertext frame into K source + `repair` repair symbols.
    pub fn encode(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        repair: u32,
    ) -> Vec<Symbol> {
        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);
        self.build(ciphertext, params, object_id, repair)
    }

    /// Re-encode `ciphertext` under an EXPLICIT `object_id` (ARQ retransmit),
    /// returning all K source symbols + `extra_repair` repair symbols at indices
    /// K..K+extra_repair-1. Both `encode` and `repair_with_id` select the scheme
    /// via `build` from `(params.arq, r)`: an ARQ (retransmit-eligible) class
    /// always uses Cauchy, regardless of `r`, so a retransmit batch stays
    /// scheme-compatible with the original send and a receiver that got zero
    /// original symbols can reconstruct from this batch alone.
    pub fn repair_with_id(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        object_id: u16,
        extra_repair: u32,
    ) -> Vec<Symbol> {
        self.build(ciphertext, params, object_id, extra_repair)
    }

    /// Shared encode: K source + R repair (R clamped to 255-K), K bounds enforced.
    fn build(
        &self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        object_id: u16,
        repair: u32,
    ) -> Vec<Symbol> {
        let object_size = u32::try_from(ciphertext.len()).expect("frame fits u32");
        let sym = usize::from(params.symbol_size);
        let k = source_count(object_size, params.symbol_size);
        // Guard: K==0 (empty frame) or K>=255 (no GF(256) codeword room) → no symbols.
        if k == 0 || k >= 255 {
            return Vec::new();
        }
        let max_repair = 255 - k;
        let r = usize::try_from(repair)
            .unwrap_or(max_repair)
            .min(max_repair);

        let source = split_source(ciphertext, k, sym);
        let scheme = if !params.arq && (r == 1 || r == 2) {
            rs::Scheme::Pq
        } else {
            rs::Scheme::Cauchy
        };
        let scheme_u8 = scheme.to_u8();
        let mut out = Vec::with_capacity(k + r);
        for (i, shard) in source.iter().enumerate() {
            out.push(Symbol {
                object_id,
                object_size,
                payload_id: pack_payload_id(u16::try_from(i).expect("i < 255"), scheme_u8),
                data: shard.clone(),
            });
        }
        if r > 0 {
            for (m, rep) in rs::encode_repair(&source, r, scheme)
                .into_iter()
                .enumerate()
            {
                let idx = u16::try_from(k + m).expect("k+m < 255");
                out.push(Symbol {
                    object_id,
                    object_size,
                    payload_id: pack_payload_id(idx, scheme_u8),
                    data: rep,
                });
            }
        }
        out
    }
}

struct ObjState {
    /// Received shards keyed by symbol_index (deduped).
    shards: HashMap<u16, Vec<u8>>,
    k: usize,
    scheme: rs::Scheme,
    done: bool,
}

/// Reassembles RS symbols into objects, keeping multiple objects in flight
/// (keyed by `object_id`), tolerating loss/reordering, evicting oldest at cap.
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
    /// Returns `None` (never panics) for any malformed/attacker field.
    pub fn push(&mut self, symbol: &Symbol) -> Option<Vec<u8>> {
        // --- Guards: object_size, codec tag, symbol_index, K bounds ---
        if symbol.object_size == 0 || symbol.object_size > MAX_OBJECT_SIZE {
            return None;
        }
        let (symbol_index, scheme) = parse_payload_id(&symbol.payload_id)?; // bad tag/scheme → None
        if usize::from(symbol_index) >= 255 {
            return None;
        }
        if symbol.data.len() != usize::from(self.symbol_size) {
            return None;
        }
        let k = source_count(symbol.object_size, self.symbol_size);
        if k == 0 || k >= 255 {
            return None;
        }
        // Ingest guard: a P+Q repair row m>=2 (index >= K+2) is invalid.
        if scheme == rs::Scheme::Pq && usize::from(symbol_index) >= k + 2 {
            return None;
        }

        if !self.objects.contains_key(&symbol.object_id) {
            if self.objects.len() >= self.max_objects {
                if let Some(oldest) = self.order.pop_front() {
                    self.objects.remove(&oldest);
                }
            }
            self.objects.insert(
                symbol.object_id,
                ObjState {
                    shards: HashMap::new(),
                    k,
                    scheme,
                    done: false,
                },
            );
            self.order.push_back(symbol.object_id);
        }
        let state = self.objects.get_mut(&symbol.object_id)?;
        if state.done {
            return None; // late/duplicate for an already-decoded object
        }
        // Reject a symbol whose scheme disagrees with the block's (confusion guard).
        if state.scheme != scheme {
            return None;
        }
        // Dedupe by index; only store what we don't have.
        state
            .shards
            .entry(symbol_index)
            .or_insert_with(|| symbol.data.clone());

        if state.shards.len() < state.k {
            return None;
        }

        // Decode once we hold K distinct shards.
        let received: Vec<(u16, &[u8])> = state
            .shards
            .iter()
            .map(|(&idx, d)| (idx, d.as_slice()))
            .collect();
        let sources = rs::decode_source(
            state.k,
            usize::from(self.symbol_size),
            &received,
            state.scheme,
        )?;
        state.done = true;

        // Concatenate source shards and trim to the original object_size.
        let size = usize::try_from(symbol.object_size).expect("size fits usize");
        let mut object = Vec::with_capacity(state.k * usize::from(self.symbol_size));
        for shard in &sources {
            object.extend_from_slice(shard);
        }
        object.truncate(size);
        Some(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowClass;

    #[test]
    fn source_symbols_are_systematic_raw_data() {
        let params = FlowClass::Default.params();
        let ct = vec![0x5Au8; 1200];
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 0);
        assert_eq!(syms.len(), 1); // K=1, R=0
        assert_eq!(syms[0].payload_id, [CODEC_RS_V1, 0, 0, 0]);
        assert_eq!(syms[0].data, ct); // systematic: symbol == data
    }

    #[test]
    fn encode_indices_and_tags_are_correct() {
        let params = FlowClass::Bulk.params();
        let ct = vec![0x11u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 3); // R=3
        assert_eq!(syms.len(), 5);
        let idx: Vec<u16> = syms
            .iter()
            .map(|s| parse_payload_id(&s.payload_id).unwrap().0)
            .collect();
        assert_eq!(idx, vec![0, 1, 2, 3, 4]);
        assert!(syms
            .iter()
            .all(|s| s.object_size == 2400 && s.object_id == 0));
    }

    #[test]
    fn roundtrips_through_erasure_and_reordering() {
        let params = FlowClass::Bulk.params();
        let ct: Vec<u8> = (0..5000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut enc = FecEncoder::new();
        let mut syms = enc.encode(&ct, params, 4);
        syms.reverse();
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for (i, s) in syms.iter().enumerate() {
            if i % 4 == 0 {
                continue; // drop every 4th
            }
            if let Some(frame) = re.push(s) {
                out = Some(frame);
                break;
            }
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn no_loss_decodes_from_source_only() {
        let params = FlowClass::Default.params();
        let ct: Vec<u8> = (0..3600u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(); // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for s in syms.iter().take(3) {
            // only the 3 source symbols
            out = out.or(re.push(s));
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn repair_with_id_reencodes_full_object_for_zero_shard_receiver() {
        let params = FlowClass::Default.params();
        let ct = vec![0x33u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let first = enc.encode(&ct, params, 1);
        let oid = first[0].object_id;
        // Receiver got NOTHING from the first batch. ARQ re-encode with extra=4.
        let batch = enc.repair_with_id(&ct, params, oid, 4);
        assert!(batch.iter().all(|s| s.object_id == oid));
        assert_eq!(batch.len(), 6); // 2 source + 4 repair
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for s in &batch {
            out = out.or(re.push(s));
        }
        assert_eq!(
            out.as_deref(),
            Some(ct.as_slice()),
            "ARQ batch alone reconstructs"
        );
    }

    #[test]
    fn arq_retransmit_recovers_after_partial_original_send() {
        // Bulk = ARQ class → both original send and RETX_EXTRA_REPAIR=4 retransmit
        // must use Cauchy, so the retransmit batch is accepted and decodes.
        let params = FlowClass::Bulk.params();
        assert!(params.arq, "Bulk is the ARQ class");
        let ct: Vec<u8> = (0..2400u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(); // K=2
        let mut enc = FecEncoder::new();
        let original = enc.encode(&ct, params, 1); // R=1
        assert!(
            original
                .iter()
                .all(|s| s.payload_id[3] == crate::rs::SCHEME_CAUCHY),
            "ARQ class original send uses Cauchy"
        );
        let oid = original[0].object_id;
        // Receiver gets only ONE shard of the original — not enough to decode.
        let mut re = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re.push(&original[0]), None);
        // ARQ retransmit with the production constant (4). Must be Cauchy and accepted.
        let retx = enc.repair_with_id(&ct, params, oid, 4);
        assert!(
            retx.iter()
                .all(|s| s.payload_id[3] == crate::rs::SCHEME_CAUCHY),
            "ARQ retransmit uses Cauchy"
        );
        let mut out = None;
        for s in &retx {
            out = out.or(re.push(s));
        }
        assert_eq!(
            out.as_deref(),
            Some(ct.as_slice()),
            "retransmit batch reconstructs the object"
        );
    }

    // --- Guard / DoS tests ---

    fn sym(object_size: u32, index: u16, sym_size: usize) -> Symbol {
        Symbol {
            object_id: 0,
            object_size,
            payload_id: pack_payload_id(index, crate::rs::SCHEME_CAUCHY),
            data: vec![0u8; sym_size],
        }
    }

    #[test]
    fn rejects_zero_and_oversized_object_size() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(&sym(0, 0, 1200)), None);
        assert_eq!(re.push(&sym(MAX_OBJECT_SIZE + 1, 0, 1200)), None);
    }

    /// K >= 255 (no GF(256) codeword room) must be rejected by `build`'s guard,
    /// yielding no symbols. Kills the `replace || with && in FecEncoder::build`
    /// mutant (line 119): under `&&`, `k==0 || k>=255` becomes impossible to
    /// satisfy (both can never be true at once), so the guard never fires,
    /// and `max_repair = 255 - k` would underflow/panic for k >= 255.
    #[test]
    fn build_rejects_k_at_or_above_255() {
        let params = crate::FlowParams {
            symbol_size: 1,
            initial_repair_ratio: 0.0,
            deadline: std::time::Duration::from_millis(1),
            arq: false,
        };
        let mut enc = FecEncoder::new();
        let ct = vec![0u8; 300]; // symbol_size=1 -> K = 300 >= 255
        let syms = enc.encode(&ct, params, 0);
        assert!(
            syms.is_empty(),
            "K >= 255 must yield no symbols, not panic/overflow"
        );
    }

    /// The repair count must be capped at exactly `255 - k`, not some other
    /// arithmetic combination. Kills the `replace - with +/in FecEncoder::build`
    /// mutants (line 122): request far more repair than fits, and check the
    /// resulting symbol count matches `k + (255 - k) = 255` exactly.
    #[test]
    fn build_caps_repair_at_255_minus_k() {
        let params = FlowClass::Bulk.params();
        let ct = vec![0x11u8; 2400]; // K = 2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1000); // way more than max_repair
        assert_eq!(
            syms.len(),
            255,
            "total symbols must be k + (255 - k) = 255 when repair is requested \
             far beyond capacity"
        );
    }

    #[test]
    fn rejects_wrong_codec_tag() {
        let mut re = FecReassembler::new(1200, 64);
        let mut s = sym(1200, 0, 1200);
        s.payload_id[0] = 0x02; // not RS-v1
        assert_eq!(re.push(&s), None);
    }

    #[test]
    fn rejects_out_of_range_symbol_index() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(&sym(1200, 255, 1200)), None);
        assert_eq!(re.push(&sym(1200, 60000, 1200)), None);
    }

    #[test]
    fn rejects_wrong_symbol_length() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(&sym(1200, 0, 999)), None); // not symbol_size
    }

    #[test]
    fn duplicate_index_is_deduped_not_double_counted() {
        let params = FlowClass::Bulk.params();
        let ct = vec![0x42u8; 3600]; // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        // Push symbol 0 three times, then 1, 2 → only 3 distinct → decodes exactly once.
        assert_eq!(re.push(&syms[0]), None);
        assert_eq!(re.push(&syms[0]), None);
        assert_eq!(re.push(&syms[0]), None);
        assert_eq!(re.push(&syms[1]), None);
        let out = re.push(&syms[2]);
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn late_symbol_after_decode_returns_none() {
        let params = FlowClass::Default.params();
        let ct = vec![0xABu8; 1200];
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut decoded = false;
        for s in &syms {
            if re.push(s).is_some() {
                decoded = true;
                break;
            }
        }
        assert!(decoded);
        assert_eq!(re.push(&syms[0]), None); // late/dup after completion
    }

    #[test]
    fn evicts_oldest_when_full() {
        let params = FlowClass::Default.params();
        let mut enc = FecEncoder::new();
        let a = enc.encode(b"first object payload contents here!!", params, 4);
        let b = enc.encode(b"second object payload contents here!", params, 4);
        let mut re = FecReassembler::new(params.symbol_size, 1); // cap 1
        re.push(&a[0]); // partial a
        assert_eq!(re.in_flight(), 1);
        let mut got_b = None;
        for s in &b {
            got_b = got_b.or(re.push(s));
        }
        assert_eq!(
            got_b.as_deref(),
            Some(&b"second object payload contents here!"[..])
        );
    }

    #[test]
    fn r1_uses_pq_scheme_in_payload_id() {
        let params = FlowClass::Default.params(); // ratio 0.10 → R=1 at K=2
        let ct = vec![0x11u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1);
        // scheme byte (payload_id[3]) is SCHEME_PQ on every symbol
        assert!(syms.iter().all(|s| s.payload_id[3] == crate::rs::SCHEME_PQ));
    }

    #[test]
    fn r3_uses_cauchy_scheme() {
        let params = FlowClass::Bulk.params();
        let ct = vec![0x22u8; 3600]; // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 3);
        assert!(syms
            .iter()
            .all(|s| s.payload_id[3] == crate::rs::SCHEME_CAUCHY));
    }

    #[test]
    fn r1_pq_block_roundtrips_through_erasure() {
        let params = FlowClass::Default.params();
        let ct: Vec<u8> = (0..3600u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(); // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1); // K=3, R=1 (P), 4 symbols
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        // drop one source symbol; the P repair recovers it
        for (i, s) in syms.iter().enumerate() {
            if i == 1 {
                continue;
            }
            out = out.or(re.push(s));
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn r2_pq_block_recovers_two_losses() {
        let params = FlowClass::Realtime.params();
        let ct: Vec<u8> = (0..4800u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(); // K=4
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2); // K=4, R=2 (P+Q), 6 symbols
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        for (i, s) in syms.iter().enumerate() {
            if i == 0 || i == 2 {
                continue; // drop two sources
            }
            out = out.or(re.push(s));
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn reassembler_rejects_pq_repair_index_out_of_range() {
        let params = FlowClass::Default.params();
        let ct = vec![0x33u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1); // K=2, R=1, PQ
        let mut re = FecReassembler::new(params.symbol_size, 64);
        // Craft a PQ symbol at index K+2 (=4) — an invalid P/Q row — must be rejected.
        let mut bad = syms[0].clone();
        bad.payload_id = pack_payload_id(4, crate::rs::SCHEME_PQ);
        assert_eq!(re.push(&bad), None);
    }

    #[test]
    fn reassembler_rejects_unknown_scheme() {
        let mut re = FecReassembler::new(1200, 64);
        let mut s = sym(2400, 0, 1200);
        s.payload_id[3] = 9; // unknown scheme id
        assert_eq!(re.push(&s), None);
    }

    /// `in_flight` must report the exact number of in-progress objects, not a
    /// constant. Kills the `replace FecReassembler::in_flight -> usize with 1`
    /// mutant (line 192).
    #[test]
    fn in_flight_reports_exact_count() {
        let params = FlowClass::Default.params();
        let mut enc = FecEncoder::new();
        let mut re = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(
            re.in_flight(),
            0,
            "fresh reassembler has no in-flight objects"
        );
        let a = enc.encode(
            b"first partial object needing 2+ symbols to complete!",
            params,
            0,
        );
        let b = enc.encode(
            b"second partial object needing 2+ symbols to complete",
            params,
            0,
        );
        re.push(&a[0]);
        re.push(&b[0]);
        assert_eq!(
            re.in_flight(),
            2,
            "two distinct partial objects must both be tracked"
        );
    }

    /// A symbol implying `object_size > MAX_OBJECT_SIZE` must be rejected
    /// (returning `None`) even when enough valid-looking shards are supplied
    /// to otherwise complete a decode. Kills the `replace || with && in
    /// FecReassembler::push` mutant (line 199, col 36 — under `&&` the guard
    /// can never fire since `object_size == 0` and `object_size > MAX` are
    /// mutually exclusive) and the `replace > with == in ...push` mutant
    /// (line 199, col 58 — `262_145 == 262_144` is false, so a `==` mutant
    /// would also wrongly accept this oversized value). The `>=` variant at
    /// the same column is killed by the boundary test below.
    #[test]
    fn oversized_object_guard_rejects_before_touching_shards() {
        let symbol_size: u16 = 65535; // max u16, minimizes K for a > MAX_OBJECT_SIZE object
        let object_size = MAX_OBJECT_SIZE + 1; // 262_145: just over the cap
        let mut re = FecReassembler::new(symbol_size, 64);
        let k = 5usize; // ceil(262_145 / 65_535) = 5
        let mut out = None;
        for i in 0..k {
            let s = Symbol {
                object_id: 0,
                object_size,
                payload_id: pack_payload_id(u16::try_from(i).unwrap(), crate::rs::SCHEME_CAUCHY),
                data: vec![0u8; usize::from(symbol_size)],
            };
            out = out.or(re.push(&s));
        }
        assert!(
            out.is_none(),
            "object_size > MAX_OBJECT_SIZE must be rejected before any shard \
             is accepted, even when enough shards are supplied to decode"
        );
    }

    /// `object_size` exactly AT the cap (`MAX_OBJECT_SIZE`) must be ACCEPTED,
    /// not rejected. Kills the `replace > with ==/>= in FecReassembler::push`
    /// mutants (line 199, col 58): both wrongly treat the exact boundary value
    /// as over-cap.
    #[test]
    fn object_size_exactly_at_max_is_accepted() {
        let symbol_size: u16 = 65535;
        let object_size = MAX_OBJECT_SIZE; // exactly at the cap
        let mut re = FecReassembler::new(symbol_size, 64);
        let k = 5usize; // ceil(262_144 / 65_535) = 5
        let mut out = None;
        for i in 0..k {
            let s = Symbol {
                object_id: 0,
                object_size,
                payload_id: pack_payload_id(u16::try_from(i).unwrap(), crate::rs::SCHEME_CAUCHY),
                data: vec![0u8; usize::from(symbol_size)],
            };
            out = out.or(re.push(&s));
        }
        assert!(
            out.is_some(),
            "object_size exactly at MAX_OBJECT_SIZE must be accepted, not rejected"
        );
    }

    /// A symbol implying K >= 255 must be rejected before any per-object state
    /// is allocated. Kills the `replace || with && in FecReassembler::push`
    /// mutant (line 210): under `&&`, the (unreachable, given object_size != 0)
    /// `k == 0` conjunct neutralizes the whole guard, so the K >= 255 case is
    /// never rejected and an oversized object gets a map entry.
    #[test]
    fn oversized_k_guard_prevents_state_allocation() {
        let mut re = FecReassembler::new(1, 64); // symbol_size=1 -> tiny symbols inflate K
        let s = Symbol {
            object_id: 0,
            object_size: 300, // valid (<= MAX_OBJECT_SIZE), but K = 300 >= 255
            payload_id: pack_payload_id(0, crate::rs::SCHEME_CAUCHY),
            data: vec![0u8; 1],
        };
        let out = re.push(&s);
        assert!(out.is_none(), "K >= 255 must be rejected");
        assert_eq!(
            re.in_flight(),
            0,
            "a symbol implying K >= 255 must be rejected before any object \
             state is allocated"
        );
    }

    /// A Cauchy repair symbol at index >= K+2 is entirely valid (Cauchy has no
    /// such restriction — only P+Q does) and must decode correctly. Kills the
    /// `replace == with != in FecReassembler::push` mutant (line 214): under
    /// `!=`, the guard wrongly starts rejecting high-index CAUCHY symbols
    /// (the `scheme == Pq` restriction was meant to apply only to Pq).
    #[test]
    fn cauchy_repair_index_ge_k_plus_2_is_accepted() {
        let params = FlowClass::Bulk.params(); // ARQ class -> always Cauchy
        let ct: Vec<u8> = (0..2400u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(); // K=2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 4); // K=2, R=4 (Cauchy) -> indices 0..5
        assert_eq!(syms.len(), 6);
        assert!(syms
            .iter()
            .all(|s| s.payload_id[3] == crate::rs::SCHEME_CAUCHY));
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let mut out = None;
        // Only the two highest-index repair symbols (indices 4,5 = K+2, K+3):
        // both are >= K+2, exercising the guard for a Cauchy (not Pq) scheme,
        // where it must NOT reject.
        for s in syms.iter().skip(4) {
            out = out.or(re.push(s));
        }
        assert_eq!(
            out.as_deref(),
            Some(ct.as_slice()),
            "Cauchy repair symbols at index >= K+2 are valid and must decode"
        );
    }

    /// For K=1 P+Q, the Q row lives at index K+1 (=2), which must NOT be
    /// wrongly rejected. Kills the `replace + with * in FecReassembler::push`
    /// mutant (line 214): for K=1, `K+2 == 3` (correct: index 2 < 3, accepted)
    /// but `K*2 == 2` (mutant: index 2 >= 2, wrongly rejected).
    #[test]
    fn pq_k1_q_row_index_not_wrongly_rejected_by_arithmetic() {
        let params = FlowClass::Default.params(); // non-ARQ -> eligible for Pq at r in {1,2}
        let ct = vec![0xABu8; 500]; // fits in one symbol -> K=1
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2); // K=1, R=2 (Pq): indices 0(src),1(P),2(Q)
        assert_eq!(syms.len(), 3);
        assert!(syms.iter().all(|s| s.payload_id[3] == crate::rs::SCHEME_PQ));
        let mut re = FecReassembler::new(params.symbol_size, 64);
        // Feed ONLY the Q row (index 2 = K+1); it's the sole shard needed (K=1).
        let out = re.push(&syms[2]);
        assert_eq!(
            out.as_deref(),
            Some(ct.as_slice()),
            "the K+1 (Q) row for K=1 must be accepted, not wrongly rejected by \
             a K+2-vs-K*2 arithmetic mutant"
        );
    }

    /// Under churn well past `max_objects`, `in_flight()` must settle at
    /// exactly `max_objects`, not collapse below it. Kills the `replace >= with
    /// < in FecReassembler::push` mutant (line 219): that mutant evicts on
    /// every insert except when truly at capacity, so `in_flight()` collapses
    /// to 1 instead of staying pinned at `max_objects`.
    #[test]
    fn in_flight_stays_pinned_at_max_objects_under_churn() {
        let params = FlowClass::Default.params();
        let mut enc = FecEncoder::new();
        let mut re = FecReassembler::new(params.symbol_size, 2); // cap 2
        for i in 0u8..5 {
            let ct = vec![i; 1200]; // K=1 each; distinct content -> distinct object_id
            let syms = enc.encode(&ct, params, 0);
            re.push(&syms[0]);
        }
        assert_eq!(
            re.in_flight(),
            2,
            "in_flight must settle at exactly max_objects (2) after churning past capacity"
        );
    }
}
