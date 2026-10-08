//! AF_XDP (XSK) kernel-bypass driver and UMEM shared memory pool.
//!
//! Provides zero-copy memory buffers (`UmemPool`) and ring buffer descriptors
//! (`FillRing`, `CompletionRing`) for kernel-bypass packet I/O.
//!
//! Low-level libc XSK/XDP structures and unsafe memory mappings are quarantined
//! within this module, with explicit `// SAFETY:` justifications on all unsafe blocks.

use std::io;

/// Default UMEM chunk size in bytes (2 KiB aligns with MTU 1500 + wire overhead).
pub const UMEM_CHUNK_SIZE: usize = 2048;

/// Default ring size in descriptors (must be a power of two).
pub const UMEM_RING_SIZE: u32 = 2048;

/// Pre-allocated page-aligned shared memory pool for AF_XDP kernel-bypass I/O.
pub struct UmemPool {
    area: *mut libc::c_void,
    size: usize,
    chunk_size: usize,
    free_chunks: Vec<u64>,
}

impl UmemPool {
    /// Allocates an anonymous, page-aligned shared memory region for `num_chunks` chunks
    /// of size `chunk_size`.
    pub fn new(num_chunks: usize, chunk_size: usize) -> io::Result<Self> {
        if num_chunks == 0 || chunk_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "num_chunks and chunk_size must be positive",
            ));
        }

        let size = num_chunks
            .checked_mul(chunk_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "UMEM size overflow"))?;

        // SAFETY: We request an anonymous, shared, page-aligned memory mapping of `size` bytes.
        // The address is NULL so the kernel selects the starting address.
        // We verify that the returned pointer is not `MAP_FAILED` before proceeding.
        let area = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_POPULATE,
                -1,
                0,
            )
        };

        if area == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Populates free_chunks so popping yields 0, chunk_size, 2*chunk_size, ...
        let free_chunks: Vec<u64> = (0..num_chunks)
            .rev()
            .map(|i| (i * chunk_size) as u64)
            .collect();

        Ok(Self {
            area,
            size,
            chunk_size,
            free_chunks,
        })
    }

    /// Allocates a chunk address from the free pool, returning `None` if exhausted.
    pub fn alloc_chunk(&mut self) -> Option<u64> {
        self.free_chunks.pop()
    }

    /// Returns a chunk address to the free pool.
    pub fn free_chunk(&mut self, addr: u64) {
        debug_assert!(
            (addr as usize) < self.size && addr.is_multiple_of(self.chunk_size as u64),
            "corrupt chunk address returned to free pool: addr={addr}, size={}, chunk_size={}",
            self.size,
            self.chunk_size
        );
        self.free_chunks.push(addr);
    }

    /// Returns a bounds-checked immutable slice into the chunk starting at `addr`.
    pub fn chunk_slice(&self, addr: u64, len: usize) -> &[u8] {
        assert!(
            (addr as usize)
                .checked_add(len)
                .is_some_and(|end| end <= self.size),
            "UMEM slice out of bounds: addr={addr}, len={len}, total size={}",
            self.size
        );
        let offset = (addr as usize) % self.chunk_size;
        assert!(
            offset
                .checked_add(len)
                .is_some_and(|end| end <= self.chunk_size),
            "UMEM slice len={len} with intra-chunk offset={offset} exceeds chunk_size={}",
            self.chunk_size
        );

        // SAFETY: `self.area` is valid mapped memory of `self.size` bytes. We verified that
        // `addr + len <= self.size`, so `self.area.add(addr as usize)` points to at least `len`
        // contiguous initialized bytes within the mapped region. The lifetime is tied to `&self`,
        // ensuring the memory remains mapped during the slice's lifetime.
        unsafe {
            let ptr = (self.area as *const u8).add(addr as usize);
            std::slice::from_raw_parts(ptr, len)
        }
    }

    /// Returns a bounds-checked mutable slice into the chunk starting at `addr`.
    pub fn chunk_slice_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
        assert!(
            (addr as usize)
                .checked_add(len)
                .is_some_and(|end| end <= self.size),
            "UMEM slice out of bounds: addr={addr}, len={len}, total size={}",
            self.size
        );
        let offset = (addr as usize) % self.chunk_size;
        assert!(
            offset
                .checked_add(len)
                .is_some_and(|end| end <= self.chunk_size),
            "UMEM slice len={len} with intra-chunk offset={offset} exceeds chunk_size={}",
            self.chunk_size
        );

        // SAFETY: `self.area` is valid mapped memory of `self.size` bytes. We verified that
        // `addr + len <= self.size`, so `self.area.add(addr as usize)` points to at least `len`
        // contiguous initialized bytes within the mapped region. The exclusive lifetime `&mut self`
        // guarantees that no other references to this memory exist during the returned slice's lifetime.
        unsafe {
            let ptr = (self.area as *mut u8).add(addr as usize);
            std::slice::from_raw_parts_mut(ptr, len)
        }
    }

    /// Raw pointer to the mapped UMEM memory area.
    pub fn area_ptr(&self) -> *mut libc::c_void {
        self.area
    }

    /// Total size in bytes of the mapped UMEM memory area.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Number of free chunks currently available in the pool.
    pub fn free_chunk_count(&self) -> usize {
        self.free_chunks.len()
    }
}

impl Drop for UmemPool {
    fn drop(&mut self) {
        if !self.area.is_null() && self.area != libc::MAP_FAILED {
            // SAFETY: `self.area` was mapped by `mmap` with size `self.size` in `new()`,
            // and has not been unmapped yet.
            unsafe {
                libc::munmap(self.area, self.size);
            }
        }
    }
}

// SAFETY: `UmemPool` exclusively owns the mapped memory region `self.area` of `self.size`
// bytes. Transferring ownership of `UmemPool` across threads transfers ownership of the
// entire memory pool safely without aliasing.
unsafe impl Send for UmemPool {}

// SAFETY: All methods taking `&self` only provide immutable, bounds-checked access to the
// mapped memory region and immutable fields. Any mutable access requires `&mut self`
// (such as `chunk_slice_mut`, `alloc_chunk`, `free_chunk`), which Rust's borrow checker
// guarantees to be exclusive.
unsafe impl Sync for UmemPool {}

/// Ring buffer for UMEM fill descriptors (chunk addresses pushed by userspace for the kernel/NIC to fill).
#[derive(Debug, Clone)]
pub struct FillRing {
    entries: Vec<u64>,
    capacity: u32,
    head: u32,
    tail: u32,
}

impl FillRing {
    /// Creates a new fill ring with `capacity` descriptors. `capacity` must be a power of two.
    pub fn new(capacity: u32) -> Self {
        assert!(
            capacity > 0 && capacity.is_power_of_two(),
            "FillRing capacity must be a power of two, got {capacity}"
        );
        Self {
            entries: vec![0u64; capacity as usize],
            capacity,
            head: 0,
            tail: 0,
        }
    }

    /// Maximum number of descriptors the ring can hold.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Number of descriptors currently queued in the ring.
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head) as usize
    }

    /// Returns `true` if the ring has no queued descriptors.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Returns `true` if the ring is at maximum capacity.
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity as usize
    }

    /// Enqueues a chunk address for the kernel/NIC to fill. Returns `false` if full.
    pub fn produce(&mut self, addr: u64) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.tail as usize) & ((self.capacity - 1) as usize);
        self.entries[idx] = addr;
        self.tail = self.tail.wrapping_add(1);
        true
    }

    /// Enqueues a batch of chunk addresses into the ring. Returns count enqueued.
    pub fn produce_batch(&mut self, addrs: &[u64]) -> usize {
        let mut count = 0;
        for &addr in addrs {
            if !self.produce(addr) {
                break;
            }
            count += 1;
        }
        count
    }

    /// Dequeues a chunk address from the ring.
    pub fn consume(&mut self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head as usize) & ((self.capacity - 1) as usize);
        let addr = self.entries[idx];
        self.head = self.head.wrapping_add(1);
        Some(addr)
    }

    /// Dequeues up to `out.len()` chunk addresses into `out`. Returns count dequeued.
    pub fn consume_batch(&mut self, out: &mut [u64]) -> usize {
        let mut count = 0;
        for item in out.iter_mut() {
            match self.consume() {
                Some(addr) => {
                    *item = addr;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

/// Ring buffer for UMEM completion descriptors (chunk addresses pushed by kernel/NIC after TX completion).
#[derive(Debug, Clone)]
pub struct CompletionRing {
    entries: Vec<u64>,
    capacity: u32,
    head: u32,
    tail: u32,
}

impl CompletionRing {
    /// Creates a new completion ring with `capacity` descriptors. `capacity` must be a power of two.
    pub fn new(capacity: u32) -> Self {
        assert!(
            capacity > 0 && capacity.is_power_of_two(),
            "CompletionRing capacity must be a power of two, got {capacity}"
        );
        Self {
            entries: vec![0u64; capacity as usize],
            capacity,
            head: 0,
            tail: 0,
        }
    }

    /// Maximum number of descriptors the ring can hold.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Number of descriptors currently queued in the ring.
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head) as usize
    }

    /// Returns `true` if the ring has no queued descriptors.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Returns `true` if the ring is at maximum capacity.
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity as usize
    }

    /// Enqueues a chunk address into the completion ring. Returns `false` if full.
    pub fn produce(&mut self, addr: u64) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.tail as usize) & ((self.capacity - 1) as usize);
        self.entries[idx] = addr;
        self.tail = self.tail.wrapping_add(1);
        true
    }

    /// Enqueues a batch of chunk addresses into the ring. Returns count enqueued.
    pub fn produce_batch(&mut self, addrs: &[u64]) -> usize {
        let mut count = 0;
        for &addr in addrs {
            if !self.produce(addr) {
                break;
            }
            count += 1;
        }
        count
    }

    /// Dequeues a completed chunk address from the ring.
    pub fn consume(&mut self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head as usize) & ((self.capacity - 1) as usize);
        let addr = self.entries[idx];
        self.head = self.head.wrapping_add(1);
        Some(addr)
    }

    /// Dequeues up to `out.len()` chunk addresses into `out`. Returns count dequeued.
    pub fn consume_batch(&mut self, out: &mut [u64]) -> usize {
        let mut count = 0;
        for item in out.iter_mut() {
            match self.consume() {
                Some(addr) => {
                    *item = addr;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}
