//! Bounded sender retransmit buffer.
//!
//! Holds at most `max` ciphertext objects keyed by send-counter, evicting the
//! oldest entry (by insertion order) when the cap is reached.  Entries older
//! than `ttl_ms` are considered expired and are not returned by `get`.

use crate::FlowClass;
use std::collections::{HashMap, VecDeque};

struct Entry {
    ciphertext: Vec<u8>,
    class: FlowClass,
    object_id: u16,
    inserted_ms: u64,
}

/// Bounded LRU+TTL buffer of sent ciphertext objects, keyed by send-counter.
///
/// Used by the ARQ sender: after [`put`]ting an object, a later NACK can
/// retrieve it via [`get`] and retransmit it with the *same* `object_id` so
/// the receiver's existing FEC decoder is topped up rather than a new one
/// being started.
pub struct RetxBuffer {
    map: HashMap<u64, Entry>,
    order: VecDeque<u64>,
    max: usize,
    ttl_ms: u64,
}

impl RetxBuffer {
    /// Create a buffer holding at most `max` entries, expiring any entry whose
    /// age exceeds `ttl_ms` milliseconds.
    pub fn new(max: usize, ttl_ms: u64) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
            ttl_ms,
        }
    }

    /// Number of entries currently in the buffer.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Store a sent object.  If the buffer is already at capacity the oldest
    /// entry is evicted to make room.
    ///
    /// Counters are expected to be unique and strictly increasing. If a duplicate
    /// counter is inserted, the stored fields (ciphertext, class, object_id, timestamp)
    /// are updated in place without adding a phantom entry to the order deque.
    pub fn put(
        &mut self,
        counter: u64,
        ciphertext: Vec<u8>,
        class: FlowClass,
        object_id: u16,
        now_ms: u64,
    ) {
        // Defensive: if this counter already exists, update it in place without
        // pushing to the order deque again (which would create a phantom entry).
        if let Some(existing) = self.map.get_mut(&counter) {
            existing.ciphertext = ciphertext;
            existing.class = class;
            existing.object_id = object_id;
            existing.inserted_ms = now_ms;
            return;
        }

        // Evict any entries that have passed their TTL before checking capacity.
        self.evict_expired(now_ms);

        if self.map.len() >= self.max {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }

        self.map.insert(
            counter,
            Entry {
                ciphertext,
                class,
                object_id,
                inserted_ms: now_ms,
            },
        );
        self.order.push_back(counter);
    }

    /// Retrieve a stored object by send-counter.
    ///
    /// Returns `None` if:
    /// - the entry does not exist, or
    /// - the entry is older than `ttl_ms` (measured from `now_ms`).
    pub fn get(&self, counter: u64, now_ms: u64) -> Option<(&[u8], FlowClass, u16)> {
        let entry = self.map.get(&counter)?;
        if now_ms.saturating_sub(entry.inserted_ms) > self.ttl_ms {
            return None;
        }
        Some((&entry.ciphertext, entry.class, entry.object_id))
    }

    /// Evict all entries whose age exceeds `ttl_ms`.
    fn evict_expired(&mut self, now_ms: u64) {
        while let Some(front) = self.order.front() {
            let expired = self
                .map
                .get(front)
                .is_none_or(|e| now_ms.saturating_sub(e.inserted_ms) > self.ttl_ms);
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
    use crate::FlowClass;

    #[test]
    fn retx_put_get_roundtrip() {
        let mut b = RetxBuffer::new(1024, 2000);
        b.put(7, vec![1, 2, 3], FlowClass::Bulk, 99, 0);
        let (ct, class, oid) = b.get(7, 100).expect("present");
        assert_eq!(ct, &[1, 2, 3]);
        assert_eq!(class, FlowClass::Bulk);
        assert_eq!(oid, 99);
    }

    #[test]
    fn retx_evicts_past_ttl() {
        let mut b = RetxBuffer::new(1024, 2000);
        b.put(7, vec![1], FlowClass::Bulk, 0, 0);
        assert!(b.get(7, 3000).is_none(), "expired past ttl");
    }

    #[test]
    fn retx_is_bounded_under_churn() {
        let mut b = RetxBuffer::new(16, 1_000_000);
        for c in 0..10_000u64 {
            b.put(c, vec![0u8; 4], FlowClass::Bulk, 0, c);
        }
        assert!(b.len() <= 16);
    }

    #[test]
    fn retx_duplicate_put_no_phantom_entry() {
        let mut b = RetxBuffer::new(10, 2_000_000);
        // Put the same counter twice with different ciphertext/class/object_id.
        b.put(42, vec![1], FlowClass::Bulk, 11, 0);
        assert_eq!(b.len(), 1, "first put: len == 1");
        let (ct, cls, oid) = b.get(42, 100).expect("present");
        assert_eq!(ct, &[1]);
        assert_eq!(cls, FlowClass::Bulk);
        assert_eq!(oid, 11);

        b.put(42, vec![2, 2, 2], FlowClass::Default, 22, 100);
        assert_eq!(b.len(), 1, "duplicate put: len still == 1 (no phantom)");
        let (ct, cls, oid) = b.get(42, 200).expect("present");
        assert_eq!(ct, &[2, 2, 2], "ciphertext updated");
        assert_eq!(cls, FlowClass::Default, "class updated");
        assert_eq!(oid, 22, "object_id updated");

        // Fill the buffer with duplicates of one counter; len should stay 1.
        for _ in 0..100 {
            b.put(42, vec![99], FlowClass::Realtime, 33, 200);
        }
        assert_eq!(b.len(), 1, "after 100 duplicate puts: len == 1");
    }
}
