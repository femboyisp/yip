use std::collections::HashMap;

pub(crate) const DEFAULT_MAC_TABLE_CAPACITY: usize = 4096;
pub(crate) const DEFAULT_MAC_TABLE_TTL_MS: u64 = 300_000;

/// Sentinel link value meaning "no node" (list end / empty slab).
const NIL: usize = usize::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LearnOrigin {
    Peer,
    LocalTap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MacEntry {
    pub(crate) peer_id: u64,
    pub(crate) last_seen_ms: u64,
    pub(crate) origin: LearnOrigin,
}

/// A slab node: the learned entry plus intrusive recency-list links.
///
/// `prev` points toward the front (more recently learned) and `next` toward
/// the back (less recently learned); both are `NIL` at the respective ends.
struct Node {
    mac: [u8; 6],
    entry: MacEntry,
    prev: usize,
    next: usize,
}

/// A bounded MAC learning table with TTL-based aging and O(1) LRU eviction.
///
/// Entries are keyed by source MAC address and carry a peer identifier,
/// timestamp, and origin metadata. Recency is tracked by an intrusive
/// doubly-linked list threaded through a slab (`nodes` + `free`): learning a
/// MAC (insert or refresh) moves it to the front, so the least-recently-learned
/// entry is always at the tail. Capacity is hard-capped and pressure is
/// resolved by evicting the tail in constant time — no per-insert scan.
///
/// Lookups deliberately do not reorder the list: a MAC ages by the recency of
/// frames seen *from* it (its last learn), matching L2-switch behaviour, so a
/// destination-only host still ages out on schedule.
pub(crate) struct MacTable {
    capacity: usize,
    ttl_ms: u64,
    index: HashMap<[u8; 6], usize>,
    nodes: Vec<Node>,
    free: Vec<usize>,
    head: usize,
    tail: usize,
}

impl MacTable {
    pub(crate) fn new(capacity: usize, ttl_ms: u64) -> Self {
        Self {
            capacity,
            ttl_ms,
            index: HashMap::with_capacity(capacity),
            nodes: Vec::with_capacity(capacity),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
        }
    }

    pub(crate) fn learn(
        &mut self,
        src_mac: [u8; 6],
        peer_id: u64,
        origin: LearnOrigin,
        now_ms: u64,
    ) {
        if !is_learnable_source_mac(src_mac) || self.capacity == 0 {
            return;
        }

        if let Some(&slot) = self.index.get(&src_mac) {
            let node = &mut self.nodes[slot];
            node.entry.peer_id = peer_id;
            node.entry.last_seen_ms = now_ms;
            node.entry.origin = origin;
            self.move_to_front(slot);
            return;
        }

        if self.index.len() >= self.capacity {
            self.evict_tail();
        }

        let entry = MacEntry {
            peer_id,
            last_seen_ms: now_ms,
            origin,
        };
        let slot = self.alloc(src_mac, entry);
        self.index.insert(src_mac, slot);
        self.push_front(slot);
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by multi-peer forwarding in later tasks")
    )]
    pub(crate) fn lookup(&self, mac: [u8; 6], now_ms: u64) -> Option<MacEntry> {
        let &slot = self.index.get(&mac)?;
        let entry = self.nodes[slot].entry;
        let age = now_ms.saturating_sub(entry.last_seen_ms);
        if age > self.ttl_ms {
            return None;
        }
        Some(entry)
    }

    pub(crate) fn sweep(&mut self, now_ms: u64) {
        let ttl_ms = self.ttl_ms;
        let expired: Vec<[u8; 6]> = self
            .index
            .iter()
            .filter(|&(_, &slot)| {
                now_ms.saturating_sub(self.nodes[slot].entry.last_seen_ms) > ttl_ms
            })
            .map(|(&mac, _)| mac)
            .collect();
        for mac in expired {
            self.remove(mac);
        }
    }

    /// Remove a MAC (if present), unlinking it and returning its slot to the
    /// free list. O(1).
    fn remove(&mut self, mac: [u8; 6]) {
        if let Some(slot) = self.index.remove(&mac) {
            self.unlink(slot);
            self.free.push(slot);
        }
    }

    /// Evict the least-recently-learned entry (the list tail). O(1).
    fn evict_tail(&mut self) {
        if self.tail != NIL {
            let mac = self.nodes[self.tail].mac;
            self.remove(mac);
        }
    }

    /// Claim a slab slot for a new node, reusing a freed slot when available.
    fn alloc(&mut self, mac: [u8; 6], entry: MacEntry) -> usize {
        let node = Node {
            mac,
            entry,
            prev: NIL,
            next: NIL,
        };
        if let Some(slot) = self.free.pop() {
            self.nodes[slot] = node;
            slot
        } else {
            self.nodes.push(node);
            self.nodes.len() - 1
        }
    }

    /// Detach `slot` from the recency list, repairing neighbour and end links.
    fn unlink(&mut self, slot: usize) {
        let (prev, next) = {
            let node = &self.nodes[slot];
            (node.prev, node.next)
        };
        if prev != NIL {
            self.nodes[prev].next = next;
        } else {
            self.head = next;
        }
        if next != NIL {
            self.nodes[next].prev = prev;
        } else {
            self.tail = prev;
        }
        self.nodes[slot].prev = NIL;
        self.nodes[slot].next = NIL;
    }

    /// Insert `slot` at the front of the recency list (most recently learned).
    fn push_front(&mut self, slot: usize) {
        self.nodes[slot].prev = NIL;
        self.nodes[slot].next = self.head;
        if self.head != NIL {
            self.nodes[self.head].prev = slot;
        }
        self.head = slot;
        if self.tail == NIL {
            self.tail = slot;
        }
    }

    fn move_to_front(&mut self, slot: usize) {
        if self.head == slot {
            return;
        }
        self.unlink(slot);
        self.push_front(slot);
    }
}

pub(crate) fn is_learnable_source_mac(mac: [u8; 6]) -> bool {
    if mac == [0u8; 6] {
        return false;
    }
    if mac == [0xFFu8; 6] {
        return false;
    }
    // I/G bit set means multicast/group address.
    if mac[0] & 0x01 != 0 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL_MS: u64 = 300_000;

    fn mac(byte: u8) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, byte]
    }

    impl MacTable {
        fn len(&self) -> usize {
            self.index.len()
        }

        /// Walk the recency list front-to-back, asserting it is a well-formed
        /// doubly-linked list consistent with the index (no cycles, both ends
        /// terminate at `NIL`, every indexed slot is visited exactly once).
        fn assert_list_consistent(&self) {
            let mut seen = 0usize;
            let mut cur = self.head;
            let mut prev = NIL;
            while cur != NIL {
                assert_eq!(self.nodes[cur].prev, prev, "prev link mismatch");
                assert_eq!(
                    self.index.get(&self.nodes[cur].mac),
                    Some(&cur),
                    "listed node not indexed to its slot"
                );
                prev = cur;
                cur = self.nodes[cur].next;
                seen += 1;
                assert!(seen <= self.index.len(), "cycle or over-long list");
            }
            assert_eq!(self.tail, prev, "tail is not the last node");
            assert_eq!(seen, self.index.len(), "list length != index length");
        }

        /// Front-to-back MACs, for asserting recency order.
        fn order(&self) -> Vec<[u8; 6]> {
            let mut out = Vec::new();
            let mut cur = self.head;
            while cur != NIL {
                out.push(self.nodes[cur].mac);
                cur = self.nodes[cur].next;
            }
            out
        }
    }

    #[test]
    fn learns_valid_unicast_source() {
        let mut table = MacTable::new(4, TTL_MS);
        let src = mac(1);
        table.learn(src, 7, LearnOrigin::Peer, 100);

        let entry = table.lookup(src, 100).expect("entry should be present");
        assert_eq!(entry.peer_id, 7);
        assert_eq!(entry.last_seen_ms, 100);
        assert_eq!(entry.origin, LearnOrigin::Peer);
        table.assert_list_consistent();
    }

    #[test]
    fn ignores_invalid_sources() {
        let mut table = MacTable::new(4, TTL_MS);
        table.learn([0; 6], 1, LearnOrigin::Peer, 0);
        table.learn([0xFF; 6], 1, LearnOrigin::Peer, 0);
        table.learn([0x01, 0, 0, 0, 0, 1], 1, LearnOrigin::Peer, 0);

        assert_eq!(table.len(), 0);
    }

    #[test]
    fn entry_ages_out_after_ttl() {
        let mut table = MacTable::new(4, TTL_MS);
        let src = mac(2);
        table.learn(src, 9, LearnOrigin::Peer, 1_000);

        assert!(table.lookup(src, 1_000 + TTL_MS).is_some());
        assert!(table.lookup(src, 1_000 + TTL_MS + 1).is_none());

        table.sweep(1_000 + TTL_MS + 1);
        assert_eq!(table.len(), 0);
        table.assert_list_consistent();
    }

    #[test]
    fn evicts_oldest_entry_when_full() {
        let mut table = MacTable::new(2, TTL_MS);
        let a = mac(10);
        let b = mac(11);
        let c = mac(12);

        table.learn(a, 1, LearnOrigin::Peer, 10);
        table.learn(b, 2, LearnOrigin::Peer, 20);
        table.learn(c, 3, LearnOrigin::Peer, 30);

        assert!(table.lookup(a, 30).is_none(), "oldest must be evicted");
        assert!(table.lookup(b, 30).is_some());
        assert!(table.lookup(c, 30).is_some());
        assert_eq!(table.len(), 2);
        table.assert_list_consistent();
    }

    #[test]
    fn refresh_moves_entry_to_front_and_spares_it_from_eviction() {
        let mut table = MacTable::new(2, TTL_MS);
        let a = mac(20);
        let b = mac(21);
        let c = mac(22);

        table.learn(a, 1, LearnOrigin::Peer, 10);
        table.learn(b, 2, LearnOrigin::Peer, 20);
        // Refresh `a`: it becomes most-recent, so `b` is now the LRU tail.
        table.learn(a, 1, LearnOrigin::Peer, 30);
        table.learn(c, 3, LearnOrigin::Peer, 40);

        assert!(
            table.lookup(a, 40).is_some(),
            "refreshed entry must survive"
        );
        assert!(table.lookup(b, 40).is_none(), "stale entry must be evicted");
        assert!(table.lookup(c, 40).is_some());
        table.assert_list_consistent();
    }

    #[test]
    fn updates_entry_when_mac_moves_between_peers() {
        let mut table = MacTable::new(4, TTL_MS);
        let src = mac(99);

        table.learn(src, 1, LearnOrigin::Peer, 100);
        table.learn(src, 2, LearnOrigin::LocalTap, 250);

        let entry = table.lookup(src, 250).expect("entry should still exist");
        assert_eq!(entry.peer_id, 2);
        assert_eq!(entry.last_seen_ms, 250);
        assert_eq!(entry.origin, LearnOrigin::LocalTap);
        assert_eq!(table.len(), 1, "move must not duplicate the entry");
        table.assert_list_consistent();
    }

    #[test]
    fn churn_reuses_slots_and_stays_bounded() {
        // Insert far more distinct MACs than capacity; the slab must reuse
        // freed slots (never grow past capacity) and stay list-consistent.
        let cap = 8usize;
        let mut table = MacTable::new(cap, TTL_MS);
        for i in 0..200u8 {
            let m = mac(i);
            table.learn(m, u64::from(i), LearnOrigin::Peer, u64::from(i));
            assert!(table.len() <= cap);
        }
        assert_eq!(table.len(), cap);
        assert!(table.nodes.len() <= cap, "slab must not grow past capacity");
        table.assert_list_consistent();

        // The survivors are the last `cap` learned, in reverse-recency order.
        let last = u8::try_from(200 - cap).expect("fits in u8");
        let expected: Vec<[u8; 6]> = (last..200u8).rev().map(mac).collect();
        assert_eq!(table.order(), expected);
    }

    #[test]
    fn zero_capacity_never_learns() {
        let mut table = MacTable::new(0, TTL_MS);
        table.learn(mac(1), 1, LearnOrigin::Peer, 0);
        assert_eq!(table.len(), 0);
        table.assert_list_consistent();
    }

    #[test]
    fn sweep_removes_only_expired_and_keeps_list_consistent() {
        let mut table = MacTable::new(8, TTL_MS);
        table.learn(mac(1), 1, LearnOrigin::Peer, 0);
        table.learn(mac(2), 2, LearnOrigin::Peer, 100);
        table.learn(mac(3), 3, LearnOrigin::Peer, TTL_MS + 50);

        // now = TTL_MS + 200: mac(1) (age TTL_MS+200) and mac(2) (age
        // TTL_MS+100) are past TTL; mac(3) (age 150) is still fresh.
        let now = TTL_MS + 200;
        table.sweep(now);
        assert_eq!(table.len(), 1);
        assert!(table.lookup(mac(3), now).is_some());
        table.assert_list_consistent();

        // A subsequent insert reuses a freed slot and remains consistent.
        table.learn(mac(4), 4, LearnOrigin::Peer, now + 10);
        assert_eq!(table.len(), 2);
        table.assert_list_consistent();
    }
}
