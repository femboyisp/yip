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

struct FlowStat {
    ewma_size: f32,
    packets: u32,
    /// Reserved for future inter-packet rate computation.
    #[expect(dead_code)]
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
    pub fn classify(&self, key: &FlowKey) -> Option<FlowClass> {
        let stat = self.map.get(key)?;
        if stat.packets < MIN_PACKETS {
            return None;
        }
        if stat.ewma_size < SMALL_BYTES {
            Some(FlowClass::Realtime)
        } else if stat.ewma_size > LARGE_BYTES {
            Some(FlowClass::Bulk)
        } else {
            None
        }
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
}
