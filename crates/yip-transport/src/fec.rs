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
    /// The symbol bytes (up to `symbol_size`, wire-trimmed on last source shard or when K=1).
    pub data: Vec<u8>,
}

/// Deterministically pin all source and repair symbols of an FEC object block
/// to a single worker shard to ensure Cauchy Reed-Solomon decoding remains hot in L1D cache.
pub fn shard_for_fec_symbol(conn_tag: u64, object_id: u16, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let mixed = conn_tag ^ ((object_id as u64).wrapping_mul(0x9e3779b97f4a7c15));
    (mixed as usize) % num_shards
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
    let sym = usize::from(symbol_size);
    if sym == 0 {
        return 0;
    }
    size.div_ceil(sym)
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
#[derive(Debug)]
pub struct FecEncoder {
    next_object_id: u16,
    stride: u16,
}

impl Default for FecEncoder {
    fn default() -> Self {
        Self {
            next_object_id: 0,
            stride: 1,
        }
    }
}

impl FecEncoder {
    /// Create an encoder starting at object id 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconfigure shard start object id and stride increment.
    pub fn set_shard(&mut self, shard_id: u16, num_shards: u16) {
        self.next_object_id = shard_id;
        self.stride = if num_shards == 0 { 1 } else { num_shards };
    }

    /// Encode one ciphertext frame into K source + `repair` repair symbols.
    pub fn encode(
        &mut self,
        ciphertext: &[u8],
        params: crate::FlowParams,
        repair: u32,
    ) -> Vec<Symbol> {
        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(self.stride);
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
        if sym == 0 {
            return Vec::new();
        }
        let k = source_count(object_size, params.symbol_size);
        // Guard: K==0 (empty frame) or K>=255 (no GF(256) codeword room) → no symbols.
        if k == 0 || k >= 255 {
            return Vec::new();
        }
        let max_repair = 255 - k;
        let r = usize::try_from(repair)
            .unwrap_or(max_repair)
            .min(max_repair);

        let scheme = if !params.arq && (r == 1 || r == 2) {
            rs::Scheme::Pq
        } else {
            rs::Scheme::Cauchy
        };
        let scheme_u8 = scheme.to_u8();
        let mut out = Vec::with_capacity(k + r);

        if k == 1 {
            let source = vec![ciphertext.to_vec()];
            out.push(Symbol {
                object_id,
                object_size,
                payload_id: pack_payload_id(0, scheme_u8),
                data: ciphertext.to_vec(),
            });
            if r > 0 {
                for (m, rep) in rs::encode_repair(&source, r, scheme)
                    .into_iter()
                    .enumerate()
                {
                    let idx = u16::try_from(1 + m).expect("1+m < 255");
                    out.push(Symbol {
                        object_id,
                        object_size,
                        payload_id: pack_payload_id(idx, scheme_u8),
                        data: rep,
                    });
                }
            }
        } else {
            let source = split_source(ciphertext, k, sym);
            let obj_len = usize::try_from(object_size).expect("fits usize");
            let last_source_len = obj_len - (k - 1) * sym;
            for (i, shard) in source.iter().enumerate() {
                let data = if i == k - 1 {
                    shard[..last_source_len].to_vec()
                } else {
                    shard.clone()
                };
                out.push(Symbol {
                    object_id,
                    object_size,
                    payload_id: pack_payload_id(u16::try_from(i).expect("i < 255"), scheme_u8),
                    data,
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
        }
        out
    }
}

struct ObjState {
    /// Pre-allocated buffer for the assembled object.
    payload: Vec<u8>,
    /// Bitset of received symbol indices (0..255).
    seen_mask: [u64; 4],
    /// Count of received source shards (symbol_index < k).
    source_count: usize,
    /// Total count of distinct shards received (source + repair).
    total_count: usize,
    k: usize,
    shard_len: usize,
    object_size: u32,
    scheme: rs::Scheme,
    done: bool,
    expires_at_ms: u64,
    /// Repair shards (symbol_index >= k), stored only when packet loss occurs.
    repair_shards: Vec<(u16, Vec<u8>)>,
}

#[inline]
fn is_seen(seen_mask: &[u64; 4], idx: u16) -> bool {
    let u = idx as usize;
    if u >= 256 {
        return false;
    }
    (seen_mask[u / 64] & (1u64 << (u % 64))) != 0
}

#[inline]
fn mark_seen(seen_mask: &mut [u64; 4], idx: u16) {
    let u = idx as usize;
    if u < 256 {
        seen_mask[u / 64] |= 1u64 << (u % 64);
    }
}

/// Reassembles RS symbols into objects, keeping multiple objects in flight
/// (keyed by `object_key: u64`), tolerating loss/reordering, evicting oldest at cap.
pub struct FecReassembler {
    symbol_size: u16,
    objects: HashMap<u64, ObjState>,
    order: VecDeque<u64>,
    max_objects: usize,
    recovered_count: u64,
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
            recovered_count: 0,
        }
    }

    /// Number of objects reconstructed via repair/parity shards.
    pub fn recovered_count(&self) -> u64 {
        self.recovered_count
    }

    /// Number of objects currently being reassembled.
    pub fn in_flight(&self) -> usize {
        self.objects.len()
    }

    /// Dynamically update the baseline symbol size for newly arriving objects.
    pub fn set_symbol_size(&mut self, s: u16) {
        self.symbol_size = s;
    }

    /// Feed one received symbol. Returns the decoded object when it completes.
    /// Returns `None` (never panics) for any malformed/attacker field.
    pub fn push(
        &mut self,
        object_key: u64,
        symbol: &Symbol,
        now_ms: u64,
        deadline_ms: u64,
    ) -> Option<Vec<u8>> {
        // --- Guards: object_size, codec tag, symbol_index, K bounds ---
        if symbol.object_size == 0 || symbol.object_size > MAX_OBJECT_SIZE || self.symbol_size == 0
        {
            return None;
        }
        let (symbol_index, scheme) = parse_payload_id(&symbol.payload_id)?; // bad tag/scheme → None
        if usize::from(symbol_index) >= 255 {
            return None;
        }
        // If object is already in flight, preserve its original k, shard_len, and object_size;
        // otherwise compute from self.symbol_size.
        let (k, sym_size) = if let Some(existing) = self.objects.get(&object_key) {
            if existing.object_size != symbol.object_size {
                return None;
            }
            (existing.k, existing.shard_len)
        } else {
            let k = source_count(symbol.object_size, self.symbol_size);
            (k, usize::from(self.symbol_size))
        };
        if k == 0 || k >= 255 {
            return None;
        }
        let obj_size = usize::try_from(symbol.object_size).ok()?;
        let expected_wire_len = if usize::from(symbol_index) == k - 1 {
            let prefix = (k - 1).checked_mul(sym_size)?;
            obj_size.checked_sub(prefix)?
        } else {
            obj_size.min(sym_size)
        };
        if symbol.data.len() != expected_wire_len {
            return None;
        }
        // Ingest guard: a P+Q repair row m>=2 (index >= K+2) is invalid.
        if scheme == rs::Scheme::Pq && usize::from(symbol_index) >= k + 2 {
            return None;
        }

        // FIFO sweep: sweep expired or completed objects from the head of order,
        // stopping if the head is the incoming symbol's object_key (handled below).
        while let Some(&oldest_id) = self.order.front() {
            if oldest_id == object_key {
                break;
            }
            if let Some(state) = self.objects.get(&oldest_id) {
                if now_ms > state.expires_at_ms || state.done {
                    self.order.pop_front();
                    self.objects.remove(&oldest_id);
                    continue;
                }
            } else {
                self.order.pop_front();
                continue;
            }
            break;
        }

        if !self.objects.contains_key(&object_key) {
            if self.objects.len() >= self.max_objects {
                if let Some(oldest) = self.order.pop_front() {
                    self.objects.remove(&oldest);
                }
            }
            let shard_len = obj_size.min(sym_size);
            let payload_len = k.checked_mul(shard_len).unwrap_or(0);
            self.objects.insert(
                object_key,
                ObjState {
                    payload: vec![0u8; payload_len],
                    seen_mask: [0; 4],
                    source_count: 0,
                    total_count: 0,
                    k,
                    shard_len,
                    object_size: symbol.object_size,
                    scheme,
                    done: false,
                    expires_at_ms: now_ms.saturating_add(deadline_ms),
                    repair_shards: Vec::new(),
                },
            );
            self.order.push_back(object_key);
        }
        let state = self.objects.get_mut(&object_key)?;
        if now_ms > state.expires_at_ms {
            state.done = true;
            state.payload.clear();
            state.payload.shrink_to_fit();
            state.repair_shards.clear();
            state.repair_shards.shrink_to_fit();
            return None;
        }
        if state.done {
            return None; // late/duplicate for an already-decoded or tombstoned object
        }
        // Reject a symbol whose scheme disagrees with the block's (confusion guard).
        if state.scheme != scheme {
            return None;
        }
        // Dedupe by index; only store what we don't have.
        if is_seen(&state.seen_mask, symbol_index) {
            return None;
        }
        mark_seen(&mut state.seen_mask, symbol_index);
        state.total_count += 1;

        let sym_idx = usize::from(symbol_index);
        if sym_idx < state.k {
            state.source_count += 1;
            let offset = sym_idx * state.shard_len;
            let copy_len = symbol.data.len().min(state.shard_len);
            state.payload[offset..offset + copy_len].copy_from_slice(&symbol.data[..copy_len]);
        } else {
            let mut shard_data = symbol.data.clone();
            if shard_data.len() < state.shard_len {
                shard_data.resize(state.shard_len, 0);
            }
            state.repair_shards.push((symbol_index, shard_data));
        }

        if state.total_count < state.k {
            return None;
        }

        // We hold at least K distinct shards: complete object reassembly.
        state.done = true;
        let size = usize::try_from(symbol.object_size).ok()?;

        if state.source_count == state.k {
            // All K source shards arrived: fast systematic path with no RS decode!
            let mut object = std::mem::take(&mut state.payload);
            state.repair_shards.clear();
            state.repair_shards.shrink_to_fit();
            object.truncate(size);
            return Some(object);
        }

        // Loss path: at least one repair shard is required.
        self.recovered_count += 1;

        let repair_refs: Vec<(u16, &[u8])> = state
            .repair_shards
            .iter()
            .map(|(idx, d)| (*idx, d.as_slice()))
            .collect();

        rs::reconstruct_missing_sources(
            state.k,
            state.shard_len,
            &mut state.payload,
            &state.seen_mask,
            &repair_refs,
            state.scheme,
        )?;

        let mut object = std::mem::take(&mut state.payload);
        state.repair_shards.clear();
        state.repair_shards.shrink_to_fit();
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
            if let Some(frame) = re.push(u64::from(s.object_id), s, 0, 1000) {
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
            out = out.or(re.push(u64::from(s.object_id), s, 0, 1000));
        }
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn out_of_order_source_shards_assemble_in_place() {
        let params = FlowClass::Default.params();
        let ct: Vec<u8> = (0..3600u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(); // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 0); // K=3, R=0
        assert_eq!(syms.len(), 3);

        let mut re = FecReassembler::new(params.symbol_size, 64);
        let obj_key = u64::from(syms[0].object_id);

        // Feed shard 2 first
        assert_eq!(re.push(obj_key, &syms[2], 100, 500), None);
        assert_eq!(re.recovered_count(), 0);

        // Feed shard 0 next
        assert_eq!(re.push(obj_key, &syms[0], 101, 500), None);
        assert_eq!(re.recovered_count(), 0);

        // Feed shard 1 last -> complete assembly
        let out = re.push(obj_key, &syms[1], 102, 500);
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
        // Must NOT increment recovered_count because all shards were source shards
        assert_eq!(re.recovered_count(), 0);
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
            out = out.or(re.push(u64::from(s.object_id), s, 0, 1000));
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
        assert_eq!(
            re.push(u64::from(original[0].object_id), &original[0], 0, 1000),
            None
        );
        // ARQ retransmit with the production constant (4). Must be Cauchy and accepted.
        let retx = enc.repair_with_id(&ct, params, oid, 4);
        assert!(
            retx.iter()
                .all(|s| s.payload_id[3] == crate::rs::SCHEME_CAUCHY),
            "ARQ retransmit uses Cauchy"
        );
        let mut out = None;
        for s in &retx {
            out = out.or(re.push(u64::from(s.object_id), s, 0, 1000));
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
        assert_eq!(re.push(0, &sym(0, 0, 1200), 0, 1000), None);
        assert_eq!(
            re.push(0, &sym(MAX_OBJECT_SIZE + 1, 0, 1200), 0, 1000),
            None
        );
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
        assert_eq!(re.push(u64::from(s.object_id), &s, 0, 1000), None);
    }

    #[test]
    fn rejects_out_of_range_symbol_index() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(0, &sym(1200, 255, 1200), 0, 1000), None);
        assert_eq!(re.push(0, &sym(1200, 60000, 1200), 0, 1000), None);
    }

    #[test]
    fn rejects_wrong_symbol_length() {
        let mut re = FecReassembler::new(1200, 64);
        assert_eq!(re.push(0, &sym(1200, 0, 999), 0, 1000), None); // not symbol_size
    }

    #[test]
    fn duplicate_index_is_deduped_not_double_counted() {
        let params = FlowClass::Bulk.params();
        let ct = vec![0x42u8; 3600]; // K=3
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        // Push symbol 0 three times, then 1, 2 → only 3 distinct → decodes exactly once.
        assert_eq!(
            re.push(u64::from(syms[0].object_id), &syms[0], 0, 1000),
            None
        );
        assert_eq!(
            re.push(u64::from(syms[0].object_id), &syms[0], 0, 1000),
            None
        );
        assert_eq!(
            re.push(u64::from(syms[0].object_id), &syms[0], 0, 1000),
            None
        );
        assert_eq!(
            re.push(u64::from(syms[1].object_id), &syms[1], 0, 1000),
            None
        );
        let out = re.push(u64::from(syms[2].object_id), &syms[2], 0, 1000);
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
            if re.push(u64::from(s.object_id), s, 0, 1000).is_some() {
                decoded = true;
                break;
            }
        }
        assert!(decoded);
        assert_eq!(
            re.push(u64::from(syms[0].object_id), &syms[0], 0, 1000),
            None
        ); // late/dup after completion
    }

    #[test]
    fn evicts_oldest_when_full() {
        let params = FlowClass::Default.params();
        let mut enc = FecEncoder::new();
        let a = enc.encode(b"first object payload contents here!!", params, 4);
        let b = enc.encode(b"second object payload contents here!", params, 4);
        let mut re = FecReassembler::new(params.symbol_size, 1); // cap 1
        re.push(u64::from(a[0].object_id), &a[0], 0, 1000); // partial a
        assert_eq!(re.in_flight(), 1);
        let mut got_b = None;
        for s in &b {
            got_b = got_b.or(re.push(u64::from(s.object_id), s, 0, 1000));
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
            out = out.or(re.push(u64::from(s.object_id), s, 0, 1000));
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
            out = out.or(re.push(u64::from(s.object_id), s, 0, 1000));
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
        assert_eq!(re.push(u64::from(bad.object_id), &bad, 0, 1000), None);
    }

    #[test]
    fn reassembler_rejects_unknown_scheme() {
        let mut re = FecReassembler::new(1200, 64);
        let mut s = sym(2400, 0, 1200);
        s.payload_id[3] = 9; // unknown scheme id
        assert_eq!(re.push(u64::from(s.object_id), &s, 0, 1000), None);
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
        let a = enc.encode(&vec![0xAAu8; 2400], params, 0);
        let b = enc.encode(&vec![0xBBu8; 2400], params, 0);
        re.push(u64::from(a[0].object_id), &a[0], 0, 1000);
        re.push(u64::from(b[0].object_id), &b[0], 0, 1000);
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
            let data_len = if i == k - 1 {
                usize::try_from(object_size).unwrap() - (k - 1) * usize::from(symbol_size)
            } else {
                usize::from(symbol_size)
            };
            let s = Symbol {
                object_id: 0,
                object_size,
                payload_id: pack_payload_id(u16::try_from(i).unwrap(), crate::rs::SCHEME_CAUCHY),
                data: vec![0u8; data_len],
            };
            out = out.or(re.push(u64::from(s.object_id), &s, 0, 1000));
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
            let len = if i == k - 1 {
                usize::try_from(object_size).unwrap() - (k - 1) * usize::from(symbol_size)
            } else {
                usize::from(symbol_size)
            };
            let s = Symbol {
                object_id: 0,
                object_size,
                payload_id: pack_payload_id(u16::try_from(i).unwrap(), crate::rs::SCHEME_CAUCHY),
                data: vec![0u8; len],
            };
            out = out.or(re.push(u64::from(s.object_id), &s, 0, 1000));
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
        let out = re.push(u64::from(s.object_id), &s, 0, 1000);
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
            out = out.or(re.push(u64::from(s.object_id), s, 0, 1000));
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
        let out = re.push(u64::from(syms[2].object_id), &syms[2], 0, 1000);
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
            let ct = vec![i; 2400]; // K=2 each; push only syms[0] so objects stay in flight
            let syms = enc.encode(&ct, params, 0);
            re.push(u64::from(syms[0].object_id), &syms[0], 0, 1000);
        }
        assert_eq!(
            re.in_flight(),
            2,
            "in_flight must settle at exactly max_objects (2) after churning past capacity"
        );
    }

    #[test]
    fn reassembler_evicts_expired_objects_on_deadline() {
        let params = FlowClass::Default.params();
        let ct = vec![0x42u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1);
        assert!(syms.len() >= 2);

        // Case A: receives at exact deadline (inclusive) -> decodes successfully
        let mut re = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(
            re.push(u64::from(syms[0].object_id), &syms[0], 100, 50),
            None
        ); // expires_at = 150
        let res = re.push(u64::from(syms[1].object_id), &syms[1], 150, 50); // 150 <= 150 -> ok
        assert_eq!(res.as_deref(), Some(ct.as_slice()));

        // Case B: receives after deadline -> fails (None) and tombstones
        let mut re2 = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(
            re2.push(u64::from(syms[0].object_id), &syms[0], 100, 50),
            None
        ); // expires_at = 150
        let res2 = re2.push(u64::from(syms[1].object_id), &syms[1], 151, 50); // 151 > 150 -> expired!
        assert_eq!(res2, None);
    }

    #[test]
    fn reassembler_trailing_symbols_do_not_resurrect_expired_object() {
        let params = FlowClass::Default.params();
        let ct = vec![0x42u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 2); // K=2, R=2 -> 4 symbols
        assert!(syms.len() >= 4);

        let mut re = FecReassembler::new(params.symbol_size, 64);
        // Push first symbol at t=100 with deadline 50ms (expires at 150ms)
        assert_eq!(
            re.push(u64::from(syms[0].object_id), &syms[0], 100, 50),
            None
        );
        assert_eq!(re.in_flight(), 1);

        // Arrive at t=160 (past deadline): symbol 1 triggers tombstoning
        assert_eq!(
            re.push(u64::from(syms[1].object_id), &syms[1], 160, 50),
            None
        );
        let state = re.objects.get(&u64::from(syms[0].object_id)).unwrap();
        assert!(state.done, "object must be marked done");
        assert!(
            state.payload.is_empty() && state.repair_shards.is_empty(),
            "shards must be freed"
        );

        // Trailing parity symbol 2 arrives at t=165: hits tombstone, does not resurrect
        assert_eq!(
            re.push(u64::from(syms[2].object_id), &syms[2], 165, 50),
            None
        );
        let state = re.objects.get(&u64::from(syms[0].object_id)).unwrap();
        assert!(state.done, "must remain done");
        assert!(
            state.payload.is_empty() && state.repair_shards.is_empty(),
            "must not store shard"
        );

        // Trailing parity symbol 3 arrives at t=170: hits tombstone
        assert_eq!(
            re.push(u64::from(syms[3].object_id), &syms[3], 170, 50),
            None
        );
        let state = re.objects.get(&u64::from(syms[0].object_id)).unwrap();
        assert!(state.done, "must remain done");
        assert!(
            state.payload.is_empty() && state.repair_shards.is_empty(),
            "must not store shard"
        );
    }

    #[test]
    fn reassembler_fifo_sweep_exact_boundary() {
        let params = FlowClass::Default.params();
        let ct_a = vec![0x11u8; 2400]; // K=2
        let ct_b = vec![0x22u8; 2400]; // K=2
        let mut enc = FecEncoder::new();
        let syms_a = enc.encode(&ct_a, params, 0);
        let syms_b = enc.encode(&ct_b, params, 0);

        let mut re = FecReassembler::new(params.symbol_size, 64);
        // Push A shard 0 at t=100, deadline 50 -> expires at 150
        assert_eq!(re.push(1, &syms_a[0], 100, 50), None);
        assert_eq!(re.in_flight(), 1);

        // At t=150 (exact deadline), push B shard 0: A must NOT be swept yet (now_ms > expires_at_ms is false)
        assert_eq!(re.push(2, &syms_b[0], 150, 50), None);
        assert_eq!(re.in_flight(), 2);
        assert!(re.objects.contains_key(&1));

        // At t=151 (past deadline), push another shard for B: A MUST now be swept
        assert_eq!(
            re.push(2, &syms_b[1], 151, 50).as_deref(),
            Some(ct_b.as_slice())
        );
        assert!(!re.objects.contains_key(&1));
    }

    #[test]
    fn multi_class_deadlines_do_not_head_block() {
        let bulk_params = FlowClass::Bulk.params();
        let rt_params = FlowClass::Realtime.params();

        let ct_bulk = vec![0x11u8; 2400]; // K=2
        let ct_rt = vec![0x22u8; 2400]; // K=2

        let mut enc = FecEncoder::new();
        let bulk_syms = enc.encode(&ct_bulk, bulk_params, 1);
        let rt_syms = enc.encode(&ct_rt, rt_params, 1);

        let mut re = FecReassembler::new(1200, 64);

        // t=100: Bulk object arrives first (deadline 500ms, expires at 600ms)
        assert_eq!(
            re.push(u64::from(bulk_syms[0].object_id), &bulk_syms[0], 100, 500),
            None
        );

        // t=105: Realtime object arrives second (deadline 20ms, expires at 125ms)
        assert_eq!(
            re.push(u64::from(rt_syms[0].object_id), &rt_syms[0], 105, 20),
            None
        );

        // Order head is Bulk object
        assert_eq!(re.order.front(), Some(&u64::from(bulk_syms[0].object_id)));

        // At t=130:
        // Realtime object has expired (130 > 125).
        // Bulk object has NOT expired (130 <= 600).
        // Bulk at head of queue must NOT block Realtime object from expiring.
        let rt_res = re.push(u64::from(rt_syms[1].object_id), &rt_syms[1], 130, 20);
        assert_eq!(
            rt_res, None,
            "Realtime object must expire despite Bulk at queue head"
        );

        // Realtime object should be tombstoned
        let rt_state = re.objects.get(&u64::from(rt_syms[0].object_id)).unwrap();
        assert!(rt_state.done);
        assert!(rt_state.payload.is_empty() && rt_state.repair_shards.is_empty());

        // Bulk object at head was NOT prematurely evicted and can still decode within its deadline
        let bulk_res = re.push(u64::from(bulk_syms[1].object_id), &bulk_syms[1], 200, 500); // 200 <= 600
        assert_eq!(
            bulk_res.as_deref(),
            Some(ct_bulk.as_slice()),
            "Bulk object decodes successfully"
        );

        // Both objects are now done. When a new object arrives, both get swept from order/objects.
        let ct_new = vec![0x33u8; 1200];
        let new_syms = enc.encode(&ct_new, rt_params, 0);
        let _ = re.push(u64::from(new_syms[0].object_id), &new_syms[0], 250, 20);
        assert!(
            !re.objects.contains_key(&u64::from(bulk_syms[0].object_id)),
            "Bulk object must be swept"
        );
        assert!(
            !re.objects.contains_key(&u64::from(rt_syms[0].object_id)),
            "Realtime object must be swept"
        );
    }

    #[test]
    fn reassembler_keys_by_u64_preventing_u16_wraparound_collision() {
        let mut re = FecReassembler::new(1200, 64);
        let key1 = 42u64;
        let key2 = 42u64 + 65536;

        let mut sym1 = sym(2400, 0, 1200); // K=2
        sym1.object_id = 42;
        let mut sym2 = sym(2400, 0, 1200); // K=2
        sym2.object_id = 42;

        let res1 = re.push(key1, &sym1, 0, 1000);
        assert!(res1.is_none());
        assert!(re.objects.contains_key(&key1));

        let res2 = re.push(key2, &sym2, 0, 1000);
        assert!(res2.is_none());
        assert!(re.objects.contains_key(&key2));

        assert_eq!(re.in_flight(), 2);

        let mut sym1_shard1 = sym(2400, 1, 1200);
        sym1_shard1.object_id = 42;
        let res1_done = re.push(key1, &sym1_shard1, 0, 1000);
        assert!(res1_done.is_some());
        assert!(re.objects[&key1].done);
        assert!(!re.objects[&key2].done);
    }

    #[test]
    fn test_fec_encoder_set_shard() {
        let mut enc = FecEncoder::new();
        enc.set_shard(2, 4);
        assert_eq!(enc.next_object_id, 2);
        assert_eq!(enc.stride, 4);

        let params = FlowClass::Default.params();
        let syms1 = enc.encode(&[1, 2, 3], params, 0);
        let id1 = syms1[0].object_id;
        assert_eq!(id1, 2);

        let syms2 = enc.encode(&[4, 5, 6], params, 0);
        let id2 = syms2[0].object_id;
        assert_eq!(id2, 6);

        // Zero shards falls back to stride 1
        enc.set_shard(5, 0);
        assert_eq!(enc.stride, 1);
    }

    #[test]
    fn k1_wire_trimming_source_and_repair_shards() {
        let params = FlowClass::Default.params();
        assert_eq!(params.symbol_size, 1200);

        // Test varying small object sizes: 64, 128, 576, 1199 bytes
        for size in [64usize, 128, 576, 1199] {
            let ct: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut enc = FecEncoder::new();
            let syms = enc.encode(&ct, params, 2); // K=1, R=2 (P+Q)
            assert_eq!(syms.len(), 3);
            assert_eq!(parse_payload_id(&syms[1].payload_id).unwrap().0, 1);
            assert_eq!(parse_payload_id(&syms[2].payload_id).unwrap().0, 2);

            // Shard 0 (source) and Shards 1, 2 (P, Q) must ALL have wire length == size (L_eff)
            for s in &syms {
                assert_eq!(s.data.len(), size, "wire length must match L_eff={size}");
            }

            // Direct decode with only source symbol
            let mut re = FecReassembler::new(params.symbol_size, 64);
            let out0 = re.push(u64::from(syms[0].object_id), &syms[0], 0, 1000);
            assert_eq!(out0.as_deref(), Some(ct.as_slice()));
            assert_eq!(re.recovered_count(), 0);

            // Decode from P repair shard only (erasure of source)
            let mut re_p = FecReassembler::new(params.symbol_size, 64);
            let out_p = re_p.push(u64::from(syms[1].object_id), &syms[1], 0, 1000);
            assert_eq!(out_p.as_deref(), Some(ct.as_slice()), "P shard decodes K=1");
            assert_eq!(re_p.recovered_count(), 1);

            // Decode from Q repair shard only (erasure of source and P)
            let mut re_q = FecReassembler::new(params.symbol_size, 64);
            let out_q = re_q.push(u64::from(syms[2].object_id), &syms[2], 0, 1000);
            assert_eq!(out_q.as_deref(), Some(ct.as_slice()), "Q shard decodes K=1");
            assert_eq!(re_q.recovered_count(), 1);

            // Wire length mismatch rejection: padded to 1200 instead of trimmed wire len
            let mut bad_s0 = syms[0].clone();
            bad_s0.data.resize(usize::from(params.symbol_size), 0);
            let mut re_bad0 = FecReassembler::new(params.symbol_size, 64);
            assert_eq!(re_bad0.push(0, &bad_s0, 0, 1000), None);

            let mut bad_s1 = syms[1].clone();
            bad_s1.data.resize(usize::from(params.symbol_size), 0);
            let mut re_bad1 = FecReassembler::new(params.symbol_size, 64);
            assert_eq!(re_bad1.push(0, &bad_s1, 0, 1000), None);
        }
    }

    #[test]
    fn k1_boundary_symbol_size_matches() {
        let params = FlowClass::Default.params();
        let ct = vec![0xEEu8; usize::from(params.symbol_size)]; // exactly 1200B
        let mut enc = FecEncoder::new();
        let syms = enc.encode(&ct, params, 1);
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].data.len(), 1200);
        assert_eq!(syms[1].data.len(), 1200);
        let mut re = FecReassembler::new(params.symbol_size, 64);
        let out = re.push(u64::from(syms[0].object_id), &syms[0], 0, 1000);
        assert_eq!(out.as_deref(), Some(ct.as_slice()));
    }

    #[test]
    fn k_ge_2_wire_trimming_and_repadding_roundtrip() {
        let params = FlowClass::Bulk.params(); // Cauchy
        let _sym_size = usize::from(params.symbol_size); // 1200

        // 1400B packet: K=2 (Shard 0: 1200B, Shard 1: 200B, Repair: 1200B each)
        let ct_1400: Vec<u8> = (0..1400usize).map(|i| (i % 251) as u8).collect();
        let mut enc = FecEncoder::new();
        let syms_1400 = enc.encode(&ct_1400, params, 2);
        assert_eq!(syms_1400.len(), 4); // 2 source + 2 repair

        assert_eq!(syms_1400[0].data.len(), 1200);
        assert_eq!(syms_1400[1].data.len(), 200); // trimmed to 1400 - 1200
        assert_eq!(syms_1400[2].data.len(), 1200); // repair full length
        assert_eq!(syms_1400[3].data.len(), 1200);

        // Recovery with source symbols only [0, 1]
        let mut re = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re.push(0, &syms_1400[0], 0, 1000), None);
        let res = re.push(0, &syms_1400[1], 0, 1000);
        assert_eq!(res.as_deref(), Some(ct_1400.as_slice()));

        // Recovery with [0, 2] (shard 1 missing)
        let mut re_drop1 = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re_drop1.push(0, &syms_1400[0], 0, 1000), None);
        let res_drop1 = re_drop1.push(0, &syms_1400[2], 0, 1000);
        assert_eq!(res_drop1.as_deref(), Some(ct_1400.as_slice()));

        // Recovery with [1, 2] (shard 0 missing; shard 1 trimmed + repair shard)
        let mut re_drop0 = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re_drop0.push(0, &syms_1400[1], 0, 1000), None);
        let res_drop0 = re_drop0.push(0, &syms_1400[2], 0, 1000);
        assert_eq!(res_drop0.as_deref(), Some(ct_1400.as_slice()));

        // Wire length validation:
        // shard 0 with 200B -> rejected
        let mut bad_s0 = syms_1400[0].clone();
        bad_s0.data.truncate(200);
        let mut re_bad0 = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re_bad0.push(0, &bad_s0, 0, 1000), None);

        // shard 1 with 1200B (untrimmed) -> rejected
        let mut bad_s1 = syms_1400[1].clone();
        bad_s1.data.resize(1200, 0);
        let mut re_bad1 = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re_bad1.push(0, &bad_s1, 0, 1000), None);

        // repair shard with 200B -> rejected
        let mut bad_r = syms_1400[2].clone();
        bad_r.data.truncate(200);
        let mut re_badr = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re_badr.push(0, &bad_r, 0, 1000), None);

        // 2500B packet: K=3 (Shard 0: 1200B, Shard 1: 1200B, Shard 2: 100B, Repair: 1200B)
        let ct_2500: Vec<u8> = (0..2500usize).map(|i| (i % 251) as u8).collect();
        let syms_2500 = enc.encode(&ct_2500, params, 3);
        assert_eq!(syms_2500.len(), 6); // 3 source + 3 repair
        assert_eq!(syms_2500[0].data.len(), 1200);
        assert_eq!(syms_2500[1].data.len(), 1200);
        assert_eq!(syms_2500[2].data.len(), 100); // 2500 - 2400
        assert_eq!(syms_2500[3].data.len(), 1200);
        assert_eq!(syms_2500[4].data.len(), 1200);
        assert_eq!(syms_2500[5].data.len(), 1200);

        // Recover with [1, 3, 5] (missing 0, 2, 4)
        let mut re_cauchy = FecReassembler::new(params.symbol_size, 64);
        assert_eq!(re_cauchy.push(0, &syms_2500[1], 0, 1000), None);
        assert_eq!(re_cauchy.push(0, &syms_2500[3], 0, 1000), None);
        let res_cauchy = re_cauchy.push(0, &syms_2500[5], 0, 1000);
        assert_eq!(res_cauchy.as_deref(), Some(ct_2500.as_slice()));
    }

    #[test]
    fn repair_with_id_produces_identical_wire_trimming() {
        let params = FlowClass::Bulk.params();
        let ct: Vec<u8> = (0..1400usize).map(|i| (i % 251) as u8).collect();
        let mut enc = FecEncoder::new();
        let regular = enc.encode(&ct, params, 2);
        let retx = enc.repair_with_id(&ct, params, regular[0].object_id, 2);

        assert_eq!(regular.len(), retx.len());
        for (a, b) in regular.iter().zip(retx.iter()) {
            assert_eq!(a.data.len(), b.data.len());
            assert_eq!(a.data, b.data);
            assert_eq!(a.payload_id, b.payload_id);
            assert_eq!(a.object_size, b.object_size);
        }
    }

    #[test]
    fn dynamic_symbol_size_transition_preserves_inflight_objects() {
        let mut re = FecReassembler::new(1200, 64);
        let mut enc = FecEncoder::new();

        // Object 1: 2400B at symbol_size 1200 (K=2, Shard 0: 1200B, Shard 1: 1200B)
        let ct1 = vec![0x41u8; 2400];
        let mut params1 = FlowClass::Bulk.params();
        params1.symbol_size = 1200;
        let syms1 = enc.encode(&ct1, params1, 1);
        assert_eq!(syms1[0].data.len(), 1200);

        // Receive shard 0 of Object 1 at t=10
        assert_eq!(re.push(101, &syms1[0], 10, 1000), None);
        assert_eq!(re.in_flight(), 1);

        // Dynamic MTU upgrade: receiver's symbol_size transitions to 1500
        re.set_symbol_size(1500);

        // Object 2 arrives: encoded with new symbol_size 1500 (1400B -> K=1, Shard 0: 1400B)
        let ct2 = vec![0x42u8; 1400];
        let mut params2 = FlowClass::Default.params();
        params2.symbol_size = 1500;
        let syms2 = enc.encode(&ct2, params2, 1);
        assert_eq!(syms2[0].data.len(), 1400);

        let res2 = re.push(102, &syms2[0], 20, 1000);
        assert_eq!(
            res2.as_deref(),
            Some(ct2.as_slice()),
            "Object 2 decodes with new symbol_size"
        );

        // Now shard 1 of Object 1 arrives (still using 1200B encoding)
        // Reassembler must NOT reject or corrupt Object 1 because its in-flight state is preserved
        let res1 = re.push(101, &syms1[1], 30, 1000);
        assert_eq!(
            res1.as_deref(),
            Some(ct1.as_slice()),
            "Object 1 completes using preserved in-flight parameters"
        );
    }
}
