use std::collections::HashMap;

pub(crate) const DEFAULT_MAC_TABLE_CAPACITY: usize = 4096;
pub(crate) const DEFAULT_MAC_TABLE_TTL_MS: u64 = 300_000;

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

/// A bounded MAC learning table with TTL-based aging.
///
/// Entries are keyed by source MAC address and carry a peer identifier,
/// timestamp, and origin metadata. Capacity is hard-capped and pressure is
/// resolved by evicting the oldest `last_seen_ms` entry.
pub(crate) struct MacTable {
    capacity: usize,
    ttl_ms: u64,
    entries: HashMap<[u8; 6], MacEntry>,
}

impl MacTable {
    pub(crate) fn new(capacity: usize, ttl_ms: u64) -> Self {
        Self {
            capacity,
            ttl_ms,
            entries: HashMap::with_capacity(capacity),
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

        if let Some(entry) = self.entries.get_mut(&src_mac) {
            entry.peer_id = peer_id;
            entry.last_seen_ms = now_ms;
            entry.origin = origin;
            return;
        }

        if self.entries.len() >= self.capacity {
            self.evict_oldest();
        }

        self.entries.insert(
            src_mac,
            MacEntry {
                peer_id,
                last_seen_ms: now_ms,
                origin,
            },
        );
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by multi-peer forwarding in later tasks")
    )]
    pub(crate) fn lookup(&self, mac: [u8; 6], now_ms: u64) -> Option<MacEntry> {
        let entry = self.entries.get(&mac).copied()?;
        let age = now_ms.saturating_sub(entry.last_seen_ms);
        if age > self.ttl_ms {
            return None;
        }
        Some(entry)
    }

    pub(crate) fn sweep(&mut self, now_ms: u64) {
        let ttl_ms = self.ttl_ms;
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.last_seen_ms) <= ttl_ms);
    }

    fn evict_oldest(&mut self) {
        let oldest = self.entries.iter().min_by(|(mac_a, a), (mac_b, b)| {
            a.last_seen_ms
                .cmp(&b.last_seen_ms)
                .then_with(|| mac_a.cmp(mac_b))
        });

        if let Some((&oldest_mac, _)) = oldest {
            self.entries.remove(&oldest_mac);
        }
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

    #[test]
    fn learns_valid_unicast_source() {
        let mut table = MacTable::new(4, TTL_MS);
        let src = mac(1);
        table.learn(src, 7, LearnOrigin::Peer, 100);

        let entry = table.lookup(src, 100).expect("entry should be present");
        assert_eq!(entry.peer_id, 7);
        assert_eq!(entry.last_seen_ms, 100);
        assert_eq!(entry.origin, LearnOrigin::Peer);
    }

    #[test]
    fn ignores_invalid_sources() {
        let mut table = MacTable::new(4, TTL_MS);
        table.learn([0; 6], 1, LearnOrigin::Peer, 0);
        table.learn([0xFF; 6], 1, LearnOrigin::Peer, 0);
        table.learn([0x01, 0, 0, 0, 0, 1], 1, LearnOrigin::Peer, 0);

        assert!(table.entries.is_empty());
    }

    #[test]
    fn entry_ages_out_after_ttl() {
        let mut table = MacTable::new(4, TTL_MS);
        let src = mac(2);
        table.learn(src, 9, LearnOrigin::Peer, 1_000);

        assert!(table.lookup(src, 1_000 + TTL_MS).is_some());
        assert!(table.lookup(src, 1_000 + TTL_MS + 1).is_none());

        table.sweep(1_000 + TTL_MS + 1);
        assert!(table.entries.is_empty());
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
    }
}
