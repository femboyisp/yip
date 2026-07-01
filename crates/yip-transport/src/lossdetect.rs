//! Receiver-side gap-based loss detector.
//!
//! Turns a stream of seen/delivered packet counters into a [`LossReport`].
//! No I/O; pure logic.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::{LossReport, MAX_NACK};

/// Receiver-side loss detector.
///
/// Call [`on_seen`](Self::on_seen) for every received sealed packet, and
/// [`on_delivered`](Self::on_delivered) when an object fully decodes.
/// Call [`report`](Self::report) periodically to obtain a [`LossReport`].
///
/// # Gap model
///
/// The detector tracks `high_counter` (the maximum counter ever seen).
/// When `on_seen(c)` is called and `c > high_counter + 1`, every counter
/// in the half-open range `(prev_high, c)` is recorded as *implied-pending*
/// with timestamp `now_ms`.  When `on_delivered(c)` is called, `c` is
/// removed from the pending set.
///
/// `report(now_ms)` promotes all implied-pending entries whose timestamp is
/// older than `grace_ms` — and that have still not been delivered — into the
/// `missing` list of the returned [`LossReport`].  Counters that arrive
/// (via `on_seen` + `on_delivered`) within the grace window are silently
/// discarded, so transient reordering is not falsely reported.
///
/// The pending set is bounded to `window` entries; when it would exceed that
/// size the smallest (oldest-sequence) entries are evicted to prevent a huge
/// gap from exhausting memory.
///
/// # Limitation: Incomplete objects are not reported as missing
///
/// A counter that is *seen* (via `on_seen`) but never *delivered* (never
/// calls `on_delivered`) — such as a multi-symbol FEC object that received
/// some but insufficient symbols to decode — is **not** reported as missing.
/// Only fully-absent counters (true gaps in the sequence, where `on_seen` is
/// never called) produce `missing` entries. This is exact for single-symbol
/// (zero-repair) objects, where a loss is always a full gap.
pub struct LossDetector {
    /// Grace period in milliseconds before an implied-pending entry is
    /// promoted to missing.
    grace_ms: u64,
    /// Maximum number of entries to keep in the pending set.
    window: usize,
    /// Highest counter ever seen.
    high_counter: u64,
    /// Whether we have seen at least one packet (so `high_counter` is valid).
    seen_any: bool,
    /// Implied-pending counters: counter → timestamp when first implied.
    pending: BTreeMap<u64, u64>,
    /// Objects delivered since the last `report` call.
    delivered: u32,
}

impl LossDetector {
    /// Create a new detector.
    ///
    /// - `grace_ms`: reordering window; implied-pending entries younger than
    ///   this are not yet declared missing.
    /// - `window`: maximum number of entries in the pending set.
    pub fn new(grace_ms: u64, window: usize) -> Self {
        Self {
            grace_ms,
            window,
            high_counter: 0,
            seen_any: false,
            pending: BTreeMap::new(),
            delivered: 0,
        }
    }

    /// Record that a sealed packet with the given `counter` was received at
    /// wall-clock time `now_ms`.
    ///
    /// If `counter` is greater than `high_counter + 1`, every counter in the
    /// range `(high_counter, counter)` — i.e. the skipped ones — is inserted
    /// into the pending set with timestamp `now_ms` (if not already present).
    pub fn on_seen(&mut self, counter: u64, now_ms: u64) {
        if !self.seen_any {
            self.high_counter = counter;
            self.seen_any = true;
            return;
        }

        if counter > self.high_counter {
            // Mark every counter in the gap as implied-pending.
            let gap_start = self.high_counter + 1;
            for c in gap_start..counter {
                self.pending.entry(c).or_insert(now_ms);
            }
            self.high_counter = counter;
            // Enforce the window bound: evict smallest keys when over capacity.
            while self.pending.len() > self.window {
                // BTreeMap::pop_first is stable since Rust 1.66.
                self.pending.pop_first();
            }
        } else {
            // Counter is <= high_counter: it was either already recorded as
            // pending (gap filled / reorder) or already seen.  Remove it from
            // pending so it won't be declared missing.
            self.pending.remove(&counter);
        }
    }

    /// Record that the object for `counter` fully decoded.
    ///
    /// Removes `counter` from the pending set (so it is never reported missing)
    /// and increments the per-window delivered count.
    pub fn on_delivered(&mut self, counter: u64) {
        self.pending.remove(&counter);
        self.delivered = self.delivered.saturating_add(1);
    }

    /// Emit a [`LossReport`] for the current window.
    ///
    /// Counters that have been implied-pending for longer than `grace_ms` and
    /// have still not been delivered are promoted to `missing`.  Those
    /// counters are then removed from the pending set.  The `delivered_count`
    /// field reflects deliveries since the last call to `report`; it is reset
    /// afterwards.
    pub fn report(&mut self, now_ms: u64) -> LossReport {
        let mut missing: Vec<u64> = Vec::new();

        // Collect counters whose grace period has expired.
        let promoted: Vec<u64> = self
            .pending
            .iter()
            .filter_map(|(&c, &first_ms)| {
                // now_ms - first_ms >= grace_ms  (saturating to avoid underflow)
                let age = now_ms.saturating_sub(first_ms);
                if age >= self.grace_ms {
                    Some(c)
                } else {
                    None
                }
            })
            .collect();

        for c in promoted {
            self.pending.remove(&c);
            missing.push(c);
        }

        // Cap at MAX_NACK (the wire-format limit).
        missing.truncate(MAX_NACK);

        let high_counter = if self.seen_any { self.high_counter } else { 0 };
        let delivered_count = self.delivered;
        self.delivered = 0;

        LossReport {
            delivered_count,
            high_counter,
            missing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_no_loss() {
        let mut d = LossDetector::new(5, 1024);
        for c in 0..100u64 {
            d.on_seen(c, 0);
            d.on_delivered(c);
        }
        let r = d.report(100);
        assert!(r.missing.is_empty());
        assert_eq!(r.delivered_count, 100);
    }

    #[test]
    fn gap_reported_after_grace() {
        let mut d = LossDetector::new(5, 1024);
        // see 0,1,3 (2 is a gap); deliver the ones we saw
        for c in [0u64, 1, 3] {
            d.on_seen(c, 0);
            d.on_delivered(c);
        }
        // before grace elapses, 2 is not yet declared
        assert!(d.report(3).missing.is_empty());
        // after grace, 2 is missing
        let r = d.report(10);
        assert_eq!(r.missing, vec![2]);
    }

    #[test]
    fn reorder_within_grace_not_reported() {
        let mut d = LossDetector::new(5, 1024);
        d.on_seen(0, 0);
        d.on_delivered(0);
        d.on_seen(2, 0);
        d.on_delivered(2); // 1 appears skipped...
        d.on_seen(1, 2);
        d.on_delivered(1); // ...but arrives within grace
        let r = d.report(10);
        assert!(
            r.missing.is_empty(),
            "in-grace reorder must not be reported lost"
        );
    }

    #[test]
    fn missing_set_is_bounded() {
        let mut d = LossDetector::new(0, 8); // grace 0 → immediate; window 8
        d.on_seen(0, 0);
        d.on_seen(1000, 1); // implies a huge gap
        let r = d.report(5);
        assert!(r.missing.len() <= 8); // bounded by window
    }
}
