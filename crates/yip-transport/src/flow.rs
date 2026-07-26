//! Stateful per-5-tuple flow table backing the classifier's heuristic layer.
//! Tracks each flow's EWMA packet size and rate to infer a [`FlowClass`] for
//! flows that carry no DSCP marking. Bounded by max-entries LRU + TTL eviction.

use crate::classify::FlowKey;
use crate::FlowClass;
use std::collections::{HashMap, VecDeque};

const MIN_PACKETS: u32 = 4;
const SMALL_BYTES: f32 = 256.0;
const LARGE_BYTES: f32 = 1000.0;
const EWMA_ALPHA: f32 = 0.25;
/// Minimum packet rate (packets per second) required to classify a small flow as Realtime.
const MIN_RATE_PPS: u64 = 20;

struct FlowStat {
    ewma_size: f32,
    packets: u32,
    first_ms: u64,
    last_ms: u64,
}

/// A bounded per-flow table feeding the classifier heuristic.
pub struct FlowTable {
    map: HashMap<FlowKey, FlowStat>,
    order: VecDeque<FlowKey>,
    max: usize,
    ttl_ms: u64,
}

impl FlowTable {
    /// Create a table holding at most `max` flows, evicting entries idle for `ttl_ms`.
    pub fn new(max: usize, ttl_ms: u64) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
            ttl_ms,
        }
    }

    /// Number of tracked flows.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Record one observed packet of `size` bytes on `key` at `now_ms`.
    pub fn observe(&mut self, key: &FlowKey, size: usize, now_ms: u64) {
        self.evict_expired(now_ms);
        // f32::from has no usize impl; this is a documented size->float widening.
        let size_f = u16::try_from(size)
            .map(f32::from)
            .unwrap_or(f32::from(u16::MAX));
        match self.map.get_mut(key) {
            Some(stat) => {
                stat.ewma_size = EWMA_ALPHA * size_f + (1.0 - EWMA_ALPHA) * stat.ewma_size;
                stat.packets = stat.packets.saturating_add(1);
                stat.last_ms = now_ms;
            }
            None => {
                if self.map.len() >= self.max {
                    if let Some(old) = self.order.pop_front() {
                        self.map.remove(&old);
                    }
                }
                self.map.insert(
                    key.clone(),
                    FlowStat {
                        ewma_size: size_f,
                        packets: 1,
                        first_ms: now_ms,
                        last_ms: now_ms,
                    },
                );
                self.order.push_back(key.clone());
            }
        }
    }

    /// Heuristic class for a tracked flow, or None when there is too little history
    /// or the flow does not fit a class.
    ///
    /// **Realtime** requires small packets (`ewma_size < SMALL_BYTES`) *and* a high
    /// packet rate (≥ `MIN_RATE_PPS` packets/sec). A slow trickle of small packets
    /// (e.g. heartbeats) is left unclassified rather than mis-classified as interactive.
    ///
    /// **Bulk** is rate-independent: large average packet size indicates a bulk transfer
    /// regardless of how fast packets arrive.
    pub fn classify(&self, key: &FlowKey) -> Option<FlowClass> {
        let stat = self.map.get(key)?;
        if stat.packets < MIN_PACKETS {
            return None;
        }
        if stat.ewma_size > LARGE_BYTES {
            return Some(FlowClass::Bulk);
        }
        if stat.ewma_size < SMALL_BYTES {
            // Rate check — integer-only arithmetic to avoid `as` casts.
            // duration_ms == 0 means all packets arrived in the same millisecond;
            // treat that as instantaneously high rate → Realtime.
            let duration_ms = stat.last_ms.saturating_sub(stat.first_ms);
            let is_frequent =
                duration_ms == 0 || u64::from(stat.packets) * 1000 >= MIN_RATE_PPS * duration_ms;
            if is_frequent {
                return Some(FlowClass::Realtime);
            }
        }
        None
    }

    fn evict_expired(&mut self, now_ms: u64) {
        while let Some(front) = self.order.front() {
            let expired = self
                .map
                .get(front)
                .is_none_or(|s| now_ms.saturating_sub(s.last_ms) > self.ttl_ms);
            if expired {
                let k = self.order.pop_front().expect("front exists");
                self.map.remove(&k);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::FlowKey;
    use crate::FlowClass;

    fn key(port: u16) -> FlowKey {
        FlowKey {
            src: [1; 16],
            dst: [2; 16],
            src_port: 1000,
            dst_port: port,
            proto: 17,
        }
    }

    #[test]
    fn small_frequent_flow_classifies_realtime() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(5000);
        // 8 small packets, 5ms apart
        for i in 0..8 {
            t.observe(&k, 80, i * 5);
        }
        assert_eq!(t.classify(&k), Some(FlowClass::Realtime));
    }

    #[test]
    fn large_flow_classifies_bulk() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(6000);
        for i in 0..8 {
            t.observe(&k, 1400, i * 2);
        }
        assert_eq!(t.classify(&k), Some(FlowClass::Bulk));
    }

    #[test]
    fn cold_flow_is_unclassified() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(7000);
        t.observe(&k, 80, 0); // only 1 packet < MIN_PACKETS
        assert_eq!(t.classify(&k), None);
    }

    #[test]
    fn table_evicts_to_stay_bounded() {
        let mut t = FlowTable::new(2, 10_000); // cap 2
        for p in 0..5u16 {
            t.observe(&key(8000 + p), 100, u64::from(p));
        }
        assert!(t.len() <= 2, "table never exceeds max");
    }

    #[test]
    fn small_but_slow_flow_is_not_realtime() {
        // 8 small (80-byte) packets spaced 1000 ms apart → ~1 pps, well below MIN_RATE_PPS (20).
        // The stateless size-only heuristic would return Realtime; the rate-aware one must not.
        let mut t = FlowTable::new(1024, 100_000);
        let k = key(9000);
        for i in 0..8u64 {
            t.observe(&k, 80, i * 1000);
        }
        // 8 packets over 7000 ms = ~1.14 pps < 20 pps → must be None, not Realtime.
        assert_eq!(
            t.classify(&k),
            None,
            "slow small-packet flow must not be classified as Realtime"
        );
    }

    /// `len()` must report the exact count, not a constant. Kills the
    /// `replace FlowTable::len -> usize with 0/1` mutants (line 44).
    #[test]
    fn len_reports_exact_flow_count() {
        let mut t = FlowTable::new(1024, 10_000);
        assert_eq!(t.len(), 0);
        t.observe(&key(1), 100, 0);
        t.observe(&key(2), 100, 0);
        t.observe(&key(3), 100, 0);
        assert_eq!(
            t.len(),
            3,
            "len must reflect the exact number of tracked flows"
        );
    }

    /// `is_empty()` must reflect actual emptiness in both directions. Kills the
    /// `replace FlowTable::is_empty -> bool with true/false` mutants (line 49).
    #[test]
    fn is_empty_reflects_actual_state() {
        let mut t = FlowTable::new(1024, 10_000);
        assert!(t.is_empty(), "freshly-created table must be empty");
        t.observe(&key(1), 100, 0);
        assert!(
            !t.is_empty(),
            "table with one tracked flow must not be empty"
        );
    }

    /// Pins the EWMA update formula (`alpha * size + (1-alpha) * old`) exactly.
    /// Kills the `replace * with + in FlowTable::observe` mutant (line 61):
    /// either multiplication turned into addition changes the numeric result.
    #[test]
    fn ewma_formula_is_precise() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(1);
        t.observe(&k, 100, 0); // first sample: ewma_size := 100.0 exactly
        t.observe(&k, 200, 1); // ewma = 0.25*200 + 0.75*100 = 125.0
        let stat = t.map.get(&k).expect("flow present");
        assert!(
            (stat.ewma_size - 125.0).abs() < 1e-3,
            "expected ewma_size == 125.0, got {}",
            stat.ewma_size
        );
    }

    /// At exact capacity, inserting one more distinct flow must evict exactly
    /// one entry, keeping `len()` pinned at `max` (not drifting below it).
    /// Kills the `replace >= with < in FlowTable::observe` mutant (line 66):
    /// that mutant evicts on every insert except when truly at capacity,
    /// causing `len()` to collapse to 1 instead of staying at `max`.
    #[test]
    fn eviction_keeps_len_pinned_at_capacity() {
        let mut t = FlowTable::new(2, 10_000);
        for p in 0..5u16 {
            t.observe(&key(8000 + p), 100, u64::from(p));
        }
        assert_eq!(
            t.len(),
            2,
            "table must settle at exactly `max` entries after repeated inserts past capacity"
        );
    }

    /// `stat.packets < MIN_PACKETS` boundary: exactly `MIN_PACKETS` (4) small,
    /// frequent packets must already be classified (not held back one more
    /// packet). Kills the `replace < with <= in FlowTable::classify` mutant
    /// (line 96).
    #[test]
    fn exactly_min_packets_is_classified() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(1);
        for i in 0..4u64 {
            t.observe(&k, 80, i * 5); // small, 5ms apart -> frequent
        }
        assert_eq!(
            t.classify(&k),
            Some(FlowClass::Realtime),
            "exactly MIN_PACKETS (4) packets must already be classified, not held back"
        );
    }

    /// `ewma_size > LARGE_BYTES` boundary: exactly `LARGE_BYTES` (1000.0) must
    /// NOT be classified as Bulk (needs to exceed, not just reach). Kills the
    /// `replace > with >= in FlowTable::classify` mutant (line 99).
    #[test]
    fn ewma_exactly_large_bytes_is_not_bulk() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(1);
        for i in 0..4u64 {
            t.observe(&k, 1000, i); // constant size -> ewma stays exactly 1000.0
        }
        assert_eq!(
            t.classify(&k),
            None,
            "ewma_size exactly at LARGE_BYTES (1000.0) must not classify as Bulk"
        );
    }

    /// `ewma_size < SMALL_BYTES` boundary: exactly `SMALL_BYTES` (256.0) must
    /// NOT take the small-packet Realtime path. Kills the `replace < with <=
    /// in FlowTable::classify` mutant (line 102).
    #[test]
    fn ewma_exactly_small_bytes_is_not_realtime() {
        let mut t = FlowTable::new(1024, 10_000);
        let k = key(1);
        for i in 0..4u64 {
            t.observe(&k, 256, i); // constant size -> ewma stays exactly 256.0, frequent
        }
        assert_eq!(
            t.classify(&k),
            None,
            "ewma_size exactly at SMALL_BYTES (256.0) must not classify as Realtime"
        );
    }

    /// Pins the rate-check formula `packets * 1000 >= MIN_RATE_PPS *
    /// duration_ms` exactly, distinguishing it from a `+`-mutated variant on
    /// either operand. Kills `replace * with + in FlowTable::classify` (line 108).
    #[test]
    fn rate_formula_is_precise_not_additive() {
        let mut t = FlowTable::new(1024, 10_000);
        // packets=5, duration_ms=1000: original 5*1000=5000 >= 20*1000=20000 is
        // FALSE (not frequent -> None). A `packets + 1000` mutant would compute
        // 5+1000=1005 >= 20000 (still false, doesn't distinguish this operand),
        // but a `MIN_RATE_PPS + duration_ms` mutant computes 5000 >= 20+1000=1020
        // (TRUE), flipping the result to Some(Realtime).
        let k1 = key(1);
        for i in 0..5u64 {
            t.observe(&k1, 80, if i == 4 { 1000 } else { 0 });
        }
        assert_eq!(
            t.classify(&k1),
            None,
            "packets=5 over 1000ms must be below the rate threshold (not frequent)"
        );

        // packets=5, duration_ms=200: original 5*1000=5000 >= 20*200=4000 is
        // TRUE (frequent -> Realtime). A `packets + 1000` mutant computes
        // 5+1000=1005 >= 20*200=4000 (FALSE), flipping the result to None.
        let k2 = key(2);
        for i in 0..5u64 {
            t.observe(&k2, 80, if i == 4 { 200 } else { 0 });
        }
        assert_eq!(
            t.classify(&k2),
            Some(FlowClass::Realtime),
            "packets=5 over 200ms must be above the rate threshold (frequent)"
        );
    }

    /// `evict_expired` must actually remove stale entries. Kills the
    /// `replace FlowTable::evict_expired with ()` mutant (line 117): a no-op
    /// body would leave expired flows in the table forever.
    #[test]
    fn evict_expired_actually_evicts_stale_entries() {
        let mut t = FlowTable::new(1024, 100); // ttl_ms = 100
        t.observe(&key(1), 80, 0);
        // Observe a distinct key far past the TTL of the first; evict_expired
        // (called at the top of `observe`) must drop the stale entry first.
        t.observe(&key(2), 80, 100_000);
        assert_eq!(
            t.len(),
            1,
            "stale entry must be evicted by TTL, leaving only the fresh one"
        );
    }

    /// At the exact TTL boundary (`age == ttl_ms`), an entry must NOT be
    /// evicted (only `age > ttl_ms` expires it). Kills the `replace > with
    /// ==/>= in FlowTable::evict_expired` mutants (line 121): either mutant
    /// would wrongly evict-and-reinsert the same key at the exact boundary,
    /// observably resetting its packet count back to 1.
    #[test]
    fn evict_expired_boundary_not_evicted_at_exact_ttl() {
        let mut t = FlowTable::new(1024, 100); // ttl_ms = 100
        let k = key(1);
        t.observe(&k, 80, 0); // packets = 1
        t.observe(&k, 80, 100); // age == ttl_ms exactly; must update in place
        let stat = t
            .map
            .get(&k)
            .expect("must still be present at exact ttl boundary");
        assert_eq!(
            stat.packets, 2,
            "second observe at the exact TTL boundary must update the same \
             entry (packets=2), not wrongly evict-and-reinsert (packets=1)"
        );
    }

    #[test]
    fn order_stays_bounded_under_churn() {
        let max = 64usize;
        let mut t = FlowTable::new(max, 1_000_000);
        let persistent = key(1);
        // Drive 5000 distinct keys through the table, re-observing the persistent key
        // each iteration to keep it live.
        for i in 0..5000u16 {
            // New distinct key each time (dst_port varies; port 1 is reserved for persistent).
            let churn_key = key(2 + i);
            t.observe(&churn_key, 100, u64::from(i));
            // Keep the persistent flow alive.
            t.observe(&persistent, 100, u64::from(i));
            assert!(
                t.len() <= max,
                "map.len() = {} exceeded max = {} at step {}",
                t.len(),
                max,
                i
            );
            assert!(
                t.order.len() <= max,
                "order.len() = {} exceeded max = {} at step {}",
                t.order.len(),
                max,
                i
            );
        }
    }
}
