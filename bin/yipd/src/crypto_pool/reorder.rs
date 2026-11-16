//! Bounded in-order Reorder Buffer (ROB) for parallel packet processing.
//!
//! Reassembles out-of-order completions from worker threads back into strict
//! sequential order before socket transmission or TUN delivery, preventing
//! packet reordering and premature TCP retransmits.

#![forbid(unsafe_code)]

/// Errors encountered when inserting elements into the reorder buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReorderError {
    /// Sequence number is older than the current expected sequence (stale/already delivered).
    Stale(u64),
    /// Sequence number exceeds the maximum buffer horizon (`next_expected_seq + CAP`).
    Full(u64),
    /// Sequence number is already buffered.
    Duplicate(u64),
}

impl std::fmt::Display for ReorderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stale(seq) => write!(f, "reorder buffer rejected stale sequence {seq}"),
            Self::Full(seq) => write!(f, "reorder buffer is full, cannot buffer sequence {seq}"),
            Self::Duplicate(seq) => write!(f, "reorder buffer rejected duplicate sequence {seq}"),
        }
    }
}

impl std::error::Error for ReorderError {}

/// A bounded circular in-order Reorder Buffer.
///
/// Stores out-of-order completions and yields them strictly in sequential order.
/// All slot memory is pre-allocated upon creation, ensuring zero heap allocations
/// during steady-state packet processing.
pub struct ReorderBuffer<T, const CAP: usize> {
    next_expected_seq: u64,
    slots: Box<[Option<(u64, T)>]>,
    count: usize,
}

impl<T, const CAP: usize> ReorderBuffer<T, CAP> {
    /// Create a new reorder buffer with an initial expected sequence number.
    ///
    /// # Panics
    /// Panics if `CAP == 0` or if `CAP` is not a power of two.
    pub fn new(initial_seq: u64) -> Self {
        assert!(CAP > 0, "reorder buffer capacity must be greater than zero");
        assert!(
            CAP.is_power_of_two(),
            "reorder buffer capacity must be a power of two"
        );

        let slots = (0..CAP)
            .map(|_| None)
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            next_expected_seq: initial_seq,
            slots,
            count: 0,
        }
    }

    /// Next expected sequence number that will be emitted by [`drain_contiguous`].
    #[inline]
    pub fn next_expected_seq(&self) -> u64 {
        self.next_expected_seq
    }

    /// Number of elements currently buffered in the reorder window.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no elements are currently buffered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Insert an item with sequence number `seq`.
    ///
    /// # Errors
    /// Returns `(item, ReorderError)` if insertion cannot proceed:
    /// - `ReorderError::Stale`: `seq` is strictly less than `next_expected_seq`.
    /// - `ReorderError::Full`: `seq >= next_expected_seq + CAP`.
    /// - `ReorderError::Duplicate`: an item with sequence `seq` is already buffered.
    pub fn insert(&mut self, seq: u64, item: T) -> Result<(), (T, ReorderError)> {
        let delta = seq.wrapping_sub(self.next_expected_seq);
        if delta >= (1u64 << 63) {
            // Sequence is in the past
            return Err((item, ReorderError::Stale(seq)));
        }
        if delta >= CAP as u64 {
            // Sequence exceeds buffer capacity horizon
            return Err((item, ReorderError::Full(seq)));
        }

        let slot_idx = (seq as usize) & (CAP - 1);
        if let Some((existing_seq, _)) = &self.slots[slot_idx] {
            if *existing_seq == seq {
                return Err((item, ReorderError::Duplicate(seq)));
            }
            // Slot is occupied by a different sequence (should not occur if delta < CAP)
            return Err((item, ReorderError::Full(seq)));
        }

        self.slots[slot_idx] = Some((seq, item));
        self.count += 1;
        Ok(())
    }

    /// Drain all contiguous sequences starting from `next_expected_seq`.
    ///
    /// Calls `f(seq, item)` for each contiguous element and advances `next_expected_seq`.
    /// Stops immediately upon encountering an unfulfilled sequence gap or empty buffer.
    /// Returns the number of elements drained.
    pub fn drain_contiguous<F: FnMut(u64, T)>(&mut self, mut f: F) -> usize {
        let mut drained = 0;
        while self.count > 0 {
            let slot_idx = (self.next_expected_seq as usize) & (CAP - 1);
            match self.slots[slot_idx].take() {
                Some((seq, item)) if seq == self.next_expected_seq => {
                    f(seq, item);
                    self.next_expected_seq = self.next_expected_seq.wrapping_add(1);
                    self.count -= 1;
                    drained += 1;
                }
                Some(mismatched) => {
                    // Put back future entry that occupies this slot index
                    self.slots[slot_idx] = Some(mismatched);
                    break;
                }
                None => {
                    // Sequence gap: wait for the missing item to arrive
                    break;
                }
            }
        }
        drained
    }
}
