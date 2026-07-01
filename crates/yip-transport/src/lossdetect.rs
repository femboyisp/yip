//! Receiver-side loss detector.
//!
//! Turns a stream of seen/delivered packet counters into a [`LossReport`].
//! No I/O; pure logic.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::{LossReport, MAX_NACK};

/// Receiver-side loss detector.
///
/// Call [`on_seen`](Self::on_seen) for every received sealed packet, and
/// [`on_delivered`](Self::on_delivered) when an object fully decodes (or when
/// a control packet is authenticated, treating it as immediately resolved).
/// Call [`report`](Self::report) periodically to obtain a [`LossReport`].
///
/// # Unified pending model
///
/// The detector maintains a *pending* set: every counter that has been seen or
/// implied but not yet delivered accumulates here with its first-seen timestamp.
///
/// When `on_seen(c, now_ms)` is called:
/// - If `c` is already resolved (delivered or previously reported missing) it is
///   silently ignored, preventing late duplicate symbols from re-opening a
///   resolved entry.
/// - If `c > high_counter + 1`, every counter in the gap
///   `(high_counter, c)` is inserted into the pending set as *implied-pending*
///   (if not already present and not already resolved).
/// - `c` itself is also inserted into the pending set as *seen-awaiting-delivery*
///   (if not already present).  Repeated calls for the same in-flight counter
///   are idempotent — the first-seen timestamp is preserved.
///
/// When `on_delivered(c)` is called, `c` is removed from the pending set and
/// marked as resolved so it is never re-added.
///
/// `report(now_ms)` promotes all pending entries older than `grace_ms` and
/// still undelivered into the `missing` list of the returned [`LossReport`].
/// Those counters are then marked resolved and removed from the pending set.
///
/// This correctly reports:
/// - Fully-absent counters (true sequence gaps — no symbol ever arrived).
/// - Multi-symbol FEC objects that received ≥1 symbol but never decoded
///   (seen but undelivered after the grace window).
/// - Single-symbol / zero-repair objects (a loss is always a full gap).
///
/// Counters that arrive and are delivered within the grace window are silently
/// discarded, so transient reordering is not falsely reported.
///
/// # Resolved-counter tracking (bounded)
///
/// To prevent late duplicates from re-opening a resolved counter, the detector
/// tracks a monotone *resolved low-watermark* (`resolved_below`) plus a bounded
/// set of out-of-order resolved counters (`resolved_set`).  A counter `c` is
/// considered resolved if `c < resolved_below` or `resolved_set.contains(&c)`.
///
/// `resolved_set` is bounded to `window` entries.  When `on_delivered(c)` or a
/// `report` promotion marks a counter as resolved, the watermark is advanced as
/// far as possible (consuming any consecutive prefix of `resolved_set`) so that
/// `resolved_set` stays small even under sequential delivery.
///
/// # Pending-set bound
///
/// The pending set is also bounded to `window` entries; when it would exceed
/// that size the smallest (oldest-sequence) entries are evicted.
pub struct LossDetector {
    /// Grace period in milliseconds before a pending entry is promoted to missing.
    grace_ms: u64,
    /// Maximum number of entries to keep in the pending set and in the resolved set.
    window: usize,
    /// Highest counter ever seen.
    high_counter: u64,
    /// Whether we have seen at least one packet (so `high_counter` is valid).
    seen_any: bool,
    /// Pending counters: counter → timestamp when first seen/implied.
    pending: BTreeMap<u64, u64>,
    /// Objects delivered since the last `report` call.
    delivered: u32,
    /// All counters strictly below this value are considered resolved.
    resolved_below: u64,
    /// Out-of-order resolved counters at or above `resolved_below`.
    /// Bounded to `window` entries.
    resolved_set: BTreeMap<u64, ()>,
}

impl LossDetector {
    /// Create a new detector.
    ///
    /// - `grace_ms`: reordering window; pending entries younger than this are
    ///   not yet declared missing.
    /// - `window`: maximum number of entries in the pending set and the
    ///   resolved set.
    pub fn new(grace_ms: u64, window: usize) -> Self {
        Self {
            grace_ms,
            window,
            high_counter: 0,
            seen_any: false,
            pending: BTreeMap::new(),
            delivered: 0,
            resolved_below: 0,
            resolved_set: BTreeMap::new(),
        }
    }

    /// Return `true` if `c` is already resolved (delivered or reported missing).
    fn is_resolved(&self, c: u64) -> bool {
        c < self.resolved_below || self.resolved_set.contains_key(&c)
    }

    /// Mark `c` as resolved and advance the low-watermark if possible.
    fn mark_resolved(&mut self, c: u64) {
        if c < self.resolved_below {
            // Already below the watermark — nothing to do.
            return;
        }
        self.resolved_set.insert(c, ());

        // Advance the watermark over any consecutive prefix.
        // `saturating_add` is belt-and-suspenders: reaching u64::MAX would take
        // ~1.8e19 objects, but it keeps the loop panic-free in debug builds.
        while self.resolved_set.contains_key(&self.resolved_below) {
            self.resolved_set.remove(&self.resolved_below);
            self.resolved_below = self.resolved_below.saturating_add(1);
        }

        // Bound the resolved set: evict the smallest entries if over capacity.
        // This is safe because entries below `resolved_below` are captured by
        // the watermark; here we evict entries that are above the watermark but
        // old enough that we are unlikely to see late duplicates for them.
        while self.resolved_set.len() > self.window {
            self.resolved_set.pop_first();
        }
    }

    /// Record that a sealed packet with the given `counter` was received at
    /// wall-clock time `now_ms`.
    ///
    /// - If `counter` is already resolved, this call is a no-op (handles late
    ///   duplicate symbols for already-delivered objects).
    /// - `counter` itself is inserted into the pending set (idempotent — the
    ///   first-seen timestamp is preserved).
    /// - If `counter > high_counter + 1`, every counter in the gap
    ///   `(high_counter, counter)` is inserted as implied-pending.
    pub fn on_seen(&mut self, counter: u64, now_ms: u64) {
        // If already resolved, ignore silently (handles late duplicates).
        if self.is_resolved(counter) {
            return;
        }

        if !self.seen_any {
            self.high_counter = counter;
            self.seen_any = true;
            // Add counter itself to pending (seen-awaiting-delivery).
            self.pending.entry(counter).or_insert(now_ms);
            self.enforce_window();
            return;
        }

        if counter > self.high_counter {
            // Mark every counter in the gap as implied-pending.
            let gap_start = self.high_counter + 1;
            for c in gap_start..counter {
                if !self.is_resolved(c) {
                    self.pending.entry(c).or_insert(now_ms);
                }
            }
            self.high_counter = counter;
        }

        // Add counter itself to pending (seen-awaiting-delivery), idempotent.
        self.pending.entry(counter).or_insert(now_ms);

        self.enforce_window();
    }

    /// Enforce the window bound on the pending set, evicting smallest keys.
    fn enforce_window(&mut self) {
        while self.pending.len() > self.window {
            self.pending.pop_first();
        }
    }

    /// Record that the object for `counter` fully decoded (or was resolved by
    /// other means, e.g. an authenticated control packet).
    ///
    /// Removes `counter` from the pending set (so it is never reported missing)
    /// and increments the per-window delivered count.
    pub fn on_delivered(&mut self, counter: u64) {
        self.pending.remove(&counter);
        self.mark_resolved(counter);
        self.delivered = self.delivered.saturating_add(1);
    }

    /// Emit a [`LossReport`] for the current window.
    ///
    /// Counters that have been pending for longer than `grace_ms` and have
    /// still not been delivered are promoted to `missing` and marked resolved.
    /// The `delivered_count` field reflects deliveries since the last call to
    /// `report`; it is reset afterwards.
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
            self.mark_resolved(c);
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

    // ── New tests for the unified pending model ───────────────────────────────

    /// A counter that is *seen* but never *delivered* must be reported as
    /// missing after the grace window.  This is the main new capability: on
    /// the old gap-only model, a seen-but-undelivered counter was invisible.
    #[test]
    fn seen_but_undelivered_reported_after_grace() {
        let mut d = LossDetector::new(5, 1024);
        d.on_seen(5, 0);
        // No on_delivered — simulates a multi-symbol FEC object that received
        // some symbols but never decoded.

        // Before grace elapses: not yet declared.
        assert!(d.report(3).missing.is_empty());

        // After grace: must appear in missing.
        let r = d.report(10);
        assert!(
            r.missing.contains(&5),
            "seen-but-undelivered counter must be reported after grace; got {:?}",
            r.missing
        );
    }

    /// A late duplicate symbol arrives for a counter that was already delivered.
    /// The second `on_seen` must NOT re-open the counter or cause a false report.
    #[test]
    fn late_duplicate_after_delivery_not_reported() {
        let mut d = LossDetector::new(5, 1024);
        d.on_seen(5, 0);
        d.on_delivered(5);

        // Late duplicate symbol for the same counter.
        d.on_seen(5, 100);

        // Report well past grace: counter 5 must NOT appear in missing.
        let r = d.report(200);
        assert!(
            !r.missing.contains(&5),
            "late duplicate after delivery must not cause a false missing report; got {:?}",
            r.missing
        );
    }

    /// An object that is seen and delivered within the grace window must never
    /// be reported as missing.
    #[test]
    fn delivered_within_grace_not_reported() {
        let mut d = LossDetector::new(5, 1024);
        d.on_seen(10, 0);
        // Delivered at time 3, well within grace of 5 ms.
        d.on_delivered(10);
        let r = d.report(10);
        assert!(
            !r.missing.contains(&10),
            "counter delivered within grace must not be reported missing; got {:?}",
            r.missing
        );
    }

    /// Repeated on_seen calls for the same in-flight counter must be idempotent:
    /// grace is measured from the FIRST sight, not the latest.
    #[test]
    fn repeated_on_seen_is_idempotent() {
        let mut d = LossDetector::new(5, 1024);
        d.on_seen(7, 0); // first sight at t=0
        d.on_seen(7, 8); // repeated sight at t=8 (past grace), must not reset timer

        // Because grace is measured from first sight (t=0), reporting at t=10
        // must declare 7 as missing (age = 10 >= grace 5).
        // If the second on_seen reset the timer, the age would be 2, and 7
        // would NOT be reported — which would be wrong.
        let r = d.report(10);
        assert!(
            r.missing.contains(&7),
            "grace must be from first on_seen; got {:?}",
            r.missing
        );
    }

    /// A counter that was previously reported as missing must not be re-reported
    /// if a very late symbol for it arrives (on_seen called after report promoted it).
    #[test]
    fn already_reported_missing_not_re_reported() {
        let mut d = LossDetector::new(5, 1024);
        d.on_seen(0, 0);
        d.on_seen(2, 0); // counter 1 is an implied gap
                         // Deliver 0 and 2 normally.
        d.on_delivered(0);
        d.on_delivered(2);

        // After grace, 1 is reported missing.
        let r = d.report(10);
        assert!(
            r.missing.contains(&1),
            "gap must be reported; got {:?}",
            r.missing
        );

        // Now a very late symbol for counter 1 arrives.
        d.on_seen(1, 20);

        // Must not appear in missing again.
        let r2 = d.report(30);
        assert!(
            !r2.missing.contains(&1),
            "already-reported counter must not be re-reported; got {:?}",
            r2.missing
        );
    }
}
