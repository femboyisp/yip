//! REALITY.3 §2: anti-replay for authed ClientHellos. A time-bounded dedup
//! set keyed on the 32-byte auth seal (`legacy_session_id`), layered UNDER the
//! stateless `ts_min` skew gate already enforced by `reality_auth_open`. This
//! only has to catch replays WITHIN the freshness window; out-of-window seals
//! are already rejected statelessly. Sharded (contention), time-bucketed
//! (O(1) eviction), atomic check-and-insert (no TOCTOU). See spec §2.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "REALITY.3 Task 4: pure replay-dedup core, exercised by its own unit tests; \
                   not yet called from main.rs — a later task wires it into the authed accept path"
    )
)]
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Freshness window in minutes. The ring has `WINDOW + 1` buckets so minute
/// `m` and `m - WINDOW` never share a slot (spec §2 advisor #8 off-by-one).
///
/// MUST be `>= 2 * REALITY_SKEW_MIN` (the stateless skew gate in
/// `tls_front::reality_auth_recover`/`open_recover`, `REALITY_SKEW_MIN =
/// 10`). That gate accepts a seal with a FIXED `ts_min` for any arrival
/// minute in `[ts_min - REALITY_SKEW_MIN, ts_min + REALITY_SKEW_MIN]` — a
/// span `2 * REALITY_SKEW_MIN` minutes wide. If this replay memory only
/// covered `REALITY_SKEW_MIN` minutes (the old value, 10), a seal accepted
/// near one edge of the skew band could age out of the dedup ring while
/// still inside the skew-gate's acceptance window, and a replay arriving in
/// that outer half would be wrongly re-accepted as Fresh (whole-branch
/// review, REALITY.3). `pub(crate)` so `tls_front` can assert the
/// relationship at compile time instead of the two constants silently
/// drifting apart in separate modules.
pub(crate) const WINDOW: u64 = 20;
/// `WINDOW + 1`, at `usize` width. Not computed from `WINDOW` via
/// `usize::try_from` because `TryFrom` is not yet const-stable — kept in
/// sync by the `ring_size_matches_window` test instead of a numeric cast.
const RING: usize = 21;
/// Number of lock shards (power of two); seal low bits select the shard.
const SHARDS: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Fresh,
    Replay,
}

struct Bucket {
    minute: u64,
    seals: HashSet<[u8; 32]>,
}

struct Shard {
    ring: [Bucket; RING],
}

pub struct ReplayGuard {
    shards: Vec<Mutex<Shard>>,
    start_min: u64,
    max_bucket: usize,
    overflow: AtomicU64,
}

impl ReplayGuard {
    pub fn new(start_min: u64, max_bucket: usize) -> Self {
        let mut shards = Vec::with_capacity(SHARDS);
        for _ in 0..SHARDS {
            // Seed every bucket's minute to a value that cannot collide with a
            // real minute until it is first used (u64::MAX sentinel).
            let ring = std::array::from_fn(|_| Bucket {
                minute: u64::MAX,
                seals: HashSet::new(),
            });
            shards.push(Mutex::new(Shard { ring }));
        }
        Self {
            shards,
            start_min,
            max_bucket,
            overflow: AtomicU64::new(0),
        }
    }

    /// Atomic check-and-remember. Returns `Fresh` the first time a seal is
    /// seen within the window, `Replay` on a repeat / out-of-window / overflow.
    pub fn check(&self, seal: [u8; 32], ts_min: u64, now_min: u64) -> Verdict {
        // Cross-restart belt: reject anything minted before we started.
        if ts_min < self.start_min {
            return Verdict::Replay;
        }
        // Shard by the seal's low bits (seal is a MAC output ⇒ uniform).
        let shard_idx = usize::from(seal[0]) & (SHARDS - 1);
        // RING is a small compile-time constant (11), so this always fits.
        let ring_u64 = u64::try_from(RING).unwrap_or(u64::MAX);
        let slot = usize::try_from(now_min % ring_u64).unwrap_or(0);

        let mut shard = self.shards[shard_idx]
            .lock()
            .expect("replay shard poisoned");

        // Rotate: if this slot holds a different (older) minute, clear it.
        if shard.ring[slot].minute != now_min {
            shard.ring[slot].seals.clear();
            shard.ring[slot].minute = now_min;
        }

        // Membership across all live buckets within the window.
        for b in &shard.ring {
            if b.minute != u64::MAX
                && now_min.saturating_sub(b.minute) <= WINDOW
                && b.seals.contains(&seal)
            {
                return Verdict::Replay;
            }
        }

        // Insert into the current bucket, respecting the per-bucket cap.
        let bucket = &mut shard.ring[slot];
        if bucket.seals.len() >= self.max_bucket {
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return Verdict::Replay; // fail-safe: over cap ⇒ treat as replay/splice
        }
        bucket.seals.insert(seal);
        Verdict::Fresh
    }

    pub fn overflow_count(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(n: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = n;
        s[31] = n;
        s
    }

    /// `RING` is hand-written as `11` (see its doc comment: `usize::try_from`
    /// isn't const-stable, so it can't be computed from `WINDOW` in a const
    /// context) — this guards against the two literals drifting apart.
    #[test]
    fn ring_size_matches_window() {
        assert_eq!(RING, usize::try_from(WINDOW).unwrap() + 1);
    }

    #[test]
    fn fresh_then_replay_then_fresh_after_ageout() {
        let g = ReplayGuard::new(1000, 65536);
        assert_eq!(g.check(seal(1), 1000, 1000), Verdict::Fresh);
        assert_eq!(g.check(seal(1), 1000, 1000), Verdict::Replay);
        // Advance now past the window (WINDOW=20): the old bucket ages out,
        // seal is Fresh again only once `now - minute > WINDOW`.
        assert_eq!(g.check(seal(1), 1021, 1021), Verdict::Fresh);
    }

    /// Regression for the whole-branch-review anti-replay defect: the replay
    /// memory must span the FULL `2 * REALITY_SKEW_MIN` arrival window the
    /// stateless skew gate accepts a fixed seal over, not just
    /// `REALITY_SKEW_MIN`. A seal accepted at arrival minute `m` must still
    /// be remembered — and so rejected as `Replay` — at every arrival minute
    /// through `m + WINDOW` inclusive (in particular `m + 11 ..= m + 20`,
    /// which is exactly the outer half of the `REALITY_SKEW_MIN = 10` skew
    /// band that a `WINDOW = 10` ring would have already forgotten). It must
    /// only become `Fresh` again at `m + WINDOW + 1`.
    ///
    /// This test FAILS (asserts `Replay`, gets `Fresh`) at `now = m + 11`
    /// against the old `WINDOW = 10`, and PASSES against `WINDOW = 20`.
    #[test]
    fn replay_is_remembered_across_full_skew_span() {
        let m = 5000;
        let g = ReplayGuard::new(0, 65536);
        // ts_min = start_min = 0 so only the arrival-window memory is under
        // test, not the cross-restart belt or the (stateless, out of scope
        // here) skew gate itself.
        assert_eq!(g.check(seal(9), 0, m), Verdict::Fresh);
        // Literal 11..=20, NOT derived from `WINDOW`: the point of this test
        // is to fail against the old `WINDOW = 10` (where this range would
        // already have aged out) and pass against `WINDOW = 20`. Deriving
        // the bound from `WINDOW` itself would make the loop vacuously empty
        // under the old value and silently defeat the regression test.
        for offset in 11..=20u64 {
            let now = m + offset;
            assert_eq!(
                g.check(seal(9), 0, now),
                Verdict::Replay,
                "seal replayed at now={now} (m+{offset}) must still be remembered"
            );
        }
        assert_eq!(
            g.check(seal(9), 0, m + WINDOW + 1),
            Verdict::Fresh,
            "seal must age out and become Fresh again exactly one minute past WINDOW"
        );
    }

    #[test]
    fn ts_before_relay_start_is_replay() {
        // Cross-restart belt: a seal minted before the latched start minute is
        // rejected regardless of memory (spec §2 cross-model belt).
        let g = ReplayGuard::new(1000, 65536);
        assert_eq!(g.check(seal(2), 999, 1000), Verdict::Replay);
    }

    #[test]
    fn distinct_seals_are_independent() {
        let g = ReplayGuard::new(0, 65536);
        assert_eq!(g.check(seal(3), 5, 5), Verdict::Fresh);
        assert_eq!(g.check(seal(4), 5, 5), Verdict::Fresh);
        assert_eq!(g.check(seal(3), 5, 5), Verdict::Replay);
    }

    #[test]
    fn overflow_degrades_to_replay_and_counts() {
        let g = ReplayGuard::new(0, 2); // tiny cap
                                        // Fill one shard's current bucket. Seals mapping to the same shard:
                                        // low byte controls the shard (SHARDS=16 ⇒ low nibble). Use seals
                                        // whose byte[0] % 16 is constant.
        assert_eq!(g.check(seal(0x10), 0, 0), Verdict::Fresh);
        assert_eq!(g.check(seal(0x20), 0, 0), Verdict::Fresh);
        // Third distinct seal in the same shard/bucket exceeds cap ⇒ Replay.
        assert_eq!(g.check(seal(0x30), 0, 0), Verdict::Replay);
        assert!(g.overflow_count() >= 1);
    }

    #[test]
    fn concurrent_same_seal_yields_one_fresh() {
        use std::sync::Arc;
        let g = Arc::new(ReplayGuard::new(0, 65536));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let g = Arc::clone(&g);
            handles.push(std::thread::spawn(move || {
                matches!(g.check(seal(7), 0, 0), Verdict::Fresh)
            }));
        }
        let fresh = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&is_fresh| is_fresh)
            .count();
        assert_eq!(fresh, 1, "exactly one thread may see Fresh");
    }
}
