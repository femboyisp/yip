//! Bounded circular Reorder Buffer (ROB) for strict in-order packet completion.
//!
//! Maintains preallocated storage to resequence out-of-order completions from
//! parallel worker threads before socket transmission or TUN delivery, ensuring
//! zero TCP reordering.

#[derive(Debug, PartialEq, Eq)]
pub enum ReorderError {
    StaleSequence { seq: u64, expected: u64 },
    DuplicateSequence { seq: u64 },
    BufferFull { seq: u64, max_capacity: usize },
}

impl std::fmt::Display for ReorderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleSequence { seq, expected } => {
                write!(f, "stale sequence {seq}: already drained past {expected}")
            }
            Self::DuplicateSequence { seq } => {
                write!(f, "duplicate sequence {seq} already in reorder buffer")
            }
            Self::BufferFull { seq, max_capacity } => {
                write!(
                    f,
                    "reorder buffer full: seq {seq} exceeds capacity {max_capacity}"
                )
            }
        }
    }
}

impl std::error::Error for ReorderError {}

pub struct ReorderBuffer<T, const CAP: usize> {
    slots: Box<[Option<(u64, T)>]>,
    head: u64,
    len: usize,
}

impl<T, const CAP: usize> ReorderBuffer<T, CAP> {
    /// Construct a new `ReorderBuffer` expecting `initial_seq` as the first item.
    pub fn new(initial_seq: u64) -> Self {
        assert!(CAP > 0, "capacity must be positive");
        let mut slots = Vec::with_capacity(CAP);
        for _ in 0..CAP {
            slots.push(None);
        }
        Self {
            slots: slots.into_boxed_slice(),
            head: initial_seq,
            len: 0,
        }
    }

    /// Insert an item at a specific sequence number.
    pub fn insert(&mut self, seq: u64, item: T) -> Result<(), ReorderError> {
        if seq < self.head {
            return Err(ReorderError::StaleSequence {
                seq,
                expected: self.head,
            });
        }
        if seq >= self.head.saturating_add(CAP as u64) {
            return Err(ReorderError::BufferFull {
                seq,
                max_capacity: CAP,
            });
        }

        let idx = (seq % (CAP as u64)) as usize;
        if let Some((existing_seq, _)) = &self.slots[idx] {
            if *existing_seq == seq {
                return Err(ReorderError::DuplicateSequence { seq });
            }
        }

        self.slots[idx] = Some((seq, item));
        self.len += 1;
        Ok(())
    }

    /// Drain all contiguous available items starting from `next_expected_seq`.
    pub fn drain_contiguous<F: FnMut(u64, T)>(&mut self, mut f: F) -> usize {
        let mut drained = 0;
        while self.len > 0 {
            let idx = (self.head % (CAP as u64)) as usize;
            if let Some((seq, item)) = self.slots[idx].take() {
                assert_eq!(seq, self.head, "corrupted sequence alignment");
                self.head = self.head.wrapping_add(1);
                self.len -= 1;
                drained += 1;
                f(seq, item);
            } else {
                break;
            }
        }
        drained
    }

    /// Next expected sequence number that must be drained.
    #[inline]
    pub fn next_expected_seq(&self) -> u64 {
        self.head
    }

    /// Number of elements currently held in the reorder buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no elements are currently held.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
