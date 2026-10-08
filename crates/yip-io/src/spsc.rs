//! Lock-free Single-Producer Single-Consumer (SPSC) bounded ring buffer.
//!
//! Provides zero-lock inter-shard datagram routing with cache-line padded
//! atomic head and tail pointers to prevent false sharing across CPU cores.

use crossbeam_utils::CachePadded;
use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct RingBuffer<T, const CAP: usize> {
    /// Producer sequence counter (write index).
    head: CachePadded<AtomicUsize>,
    /// Consumer sequence counter (read index).
    tail: CachePadded<AtomicUsize>,
    /// Heap-allocated array of uninitialized slot storage.
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
}

// SAFETY: `RingBuffer` is an SPSC queue where slot access is synchronized
// by atomic Acquire/Release operations on `head` and `tail`.
// Items transferred across threads require `T: Send`.
unsafe impl<T: Send, const CAP: usize> Send for RingBuffer<T, CAP> {}

// SAFETY: `RingBuffer` allows simultaneous access by the single producer
// and single consumer threads without data races.
unsafe impl<T: Send, const CAP: usize> Sync for RingBuffer<T, CAP> {}

impl<T, const CAP: usize> Drop for RingBuffer<T, CAP> {
    fn drop(&mut self) {
        if std::mem::needs_drop::<T>() {
            let head = self.head.load(Ordering::Relaxed);
            let tail = self.tail.load(Ordering::Relaxed);
            let count = head.wrapping_sub(tail);
            for i in 0..count {
                let idx = tail.wrapping_add(i) & (CAP - 1);
                // SAFETY:
                // These items were pushed but never popped or dropped.
                // We have exclusive &mut self access during Drop.
                unsafe {
                    let slot = self.slots[idx].get();
                    (*slot).assume_init_drop();
                }
            }
        }
    }
}

/// Producer half of the lock-free SPSC ring buffer.
pub struct SpscProducer<T, const CAP: usize> {
    inner: Arc<RingBuffer<T, CAP>>,
    cached_tail: Cell<usize>,
    _not_sync: PhantomData<Cell<()>>,
}

/// Consumer half of the lock-free SPSC ring buffer.
pub struct SpscConsumer<T, const CAP: usize> {
    inner: Arc<RingBuffer<T, CAP>>,
    cached_head: Cell<usize>,
    _not_sync: PhantomData<Cell<()>>,
}

impl<T, const CAP: usize> std::fmt::Debug for SpscProducer<T, CAP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpscProducer")
            .field("capacity", &CAP)
            .finish()
    }
}

impl<T, const CAP: usize> std::fmt::Debug for SpscConsumer<T, CAP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpscConsumer")
            .field("capacity", &CAP)
            .finish()
    }
}

/// Create a connected lock-free Single-Producer Single-Consumer (SPSC) ring buffer pair.
///
/// # Panics
/// Panics if `CAP` is not greater than zero or is not a power of two.
pub fn spsc_pair<T, const CAP: usize>() -> (SpscProducer<T, CAP>, SpscConsumer<T, CAP>) {
    assert!(CAP > 0, "capacity must be greater than zero");
    assert!(CAP.is_power_of_two(), "capacity must be a power of two");

    let mut v: Vec<UnsafeCell<MaybeUninit<T>>> = Vec::with_capacity(CAP);
    // SAFETY: `UnsafeCell<MaybeUninit<T>>` has the same layout and size as
    // `MaybeUninit<T>`, for which uninitialized memory is a valid bit pattern.
    // We set the vector length to `CAP` matching its allocated capacity.
    unsafe {
        v.set_len(CAP);
    }
    let slots = v.into_boxed_slice();

    let inner = Arc::new(RingBuffer {
        head: CachePadded::new(AtomicUsize::new(0)),
        tail: CachePadded::new(AtomicUsize::new(0)),
        slots,
    });

    let producer = SpscProducer {
        inner: Arc::clone(&inner),
        cached_tail: Cell::new(0),
        _not_sync: PhantomData,
    };

    let consumer = SpscConsumer {
        inner,
        cached_head: Cell::new(0),
        _not_sync: PhantomData,
    };

    (producer, consumer)
}

impl<T, const CAP: usize> SpscProducer<T, CAP> {
    /// Attempts to push an item into the ring buffer.
    ///
    /// Returns `Ok(())` on success, or `Err(item)` if the buffer is full.
    pub fn push(&self, item: T) -> Result<(), T> {
        let head = self.inner.head.load(Ordering::Relaxed);
        let mut tail = self.cached_tail.get();
        if head.wrapping_sub(tail) >= CAP {
            tail = self.inner.tail.load(Ordering::Acquire);
            self.cached_tail.set(tail);
            if head.wrapping_sub(tail) >= CAP {
                return Err(item);
            }
        }

        let idx = head & (CAP - 1);
        // SAFETY:
        // 1. We confirmed that `head.wrapping_sub(tail) < CAP`, so slot `idx` is unoccupied.
        // 2. The previous occupant of slot `idx` (if any) was read by the consumer before
        //    the consumer stored its `tail` update with Release ordering, which synchronizes
        //    with our Acquire load of `tail`.
        // 3. Only this producer writes to slot `idx` and advances `head`.
        unsafe {
            let slot = self.inner.slots[idx].get();
            (*slot).write(item);
        }

        self.inner
            .head
            .store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Returns the capacity of the ring buffer.
    pub fn capacity(&self) -> usize {
        CAP
    }
}

impl<T, const CAP: usize> SpscConsumer<T, CAP> {
    /// Attempts to pop an item from the ring buffer.
    ///
    /// Returns `Some(item)` if an element is available, or `None` if the buffer is empty.
    pub fn pop(&self) -> Option<T> {
        let tail = self.inner.tail.load(Ordering::Relaxed);
        let mut head = self.cached_head.get();
        if head == tail {
            head = self.inner.head.load(Ordering::Acquire);
            self.cached_head.set(head);
            if head == tail {
                return None;
            }
        }

        let idx = tail & (CAP - 1);
        // SAFETY:
        // 1. `head != tail`, so there is at least one published element at sequence `tail`.
        // 2. The producer wrote to slot `idx` before advancing `head` with Release ordering,
        //    which synchronizes with our Acquire load of `head`.
        // 3. Only this consumer reads slot `idx` and advances `tail`.
        let item = unsafe {
            let slot = self.inner.slots[idx].get();
            (*slot).assume_init_read()
        };

        self.inner
            .tail
            .store(tail.wrapping_add(1), Ordering::Release);
        Some(item)
    }

    /// Drains up to `max` items from the ring buffer into the provided `out` vector.
    ///
    /// Returns the number of items drained.
    pub fn drain_batch(&self, out: &mut Vec<T>, max: usize) -> usize {
        if max == 0 {
            return 0;
        }

        let tail = self.inner.tail.load(Ordering::Relaxed);
        let mut head = self.cached_head.get();
        if head.wrapping_sub(tail) < max {
            head = self.inner.head.load(Ordering::Acquire);
            self.cached_head.set(head);
        }

        let available = head.wrapping_sub(tail);
        let to_drain = available.min(max);
        if to_drain == 0 {
            return 0;
        }

        out.reserve(to_drain);
        for i in 0..to_drain {
            let idx = tail.wrapping_add(i) & (CAP - 1);
            // SAFETY:
            // Slot `idx` was written by the producer before `head` was published with Release,
            // which synchronizes with our Acquire load. It has not yet been popped.
            let item = unsafe {
                let slot = self.inner.slots[idx].get();
                (*slot).assume_init_read()
            };
            out.push(item);
        }

        self.inner
            .tail
            .store(tail.wrapping_add(to_drain), Ordering::Release);
        to_drain
    }

    /// Returns `true` if the ring buffer contains no items.
    pub fn is_empty(&self) -> bool {
        let tail = self.inner.tail.load(Ordering::Relaxed);
        let head = self.inner.head.load(Ordering::Acquire);
        self.cached_head.set(head);
        head == tail
    }
}

impl<T, const CAP: usize> Drop for SpscConsumer<T, CAP> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}
