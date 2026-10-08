//! AF_XDP (XSK) kernel-bypass driver and UMEM shared memory pool.
//!
//! Provides zero-copy memory buffers (`UmemPool`) and ring buffer descriptors
//! (`FillRing`, `CompletionRing`) for kernel-bypass packet I/O.
//!
//! Low-level libc XSK/XDP structures and unsafe memory mappings are quarantined
//! within this module, with explicit `// SAFETY:` justifications on all unsafe blocks.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

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

/// Flag for copy-mode bind in AF_XDP (`XDP_COPY`).
pub const XDP_COPY: u16 = 1 << 1;

/// Flag for zero-copy mode bind in AF_XDP (`XDP_ZEROCOPY`).
pub const XDP_ZERO_COPY: u16 = 1 << 2;

/// Alias for `XDP_ZERO_COPY` matching kernel naming `XDP_ZEROCOPY`.
pub const XDP_ZEROCOPY: u16 = XDP_ZERO_COPY;

/// Linux internal errno for unsupported operation (`ENOTSUPP`).
pub const ENOTSUPP: i32 = 524;

/// The operational mode for AF_XDP binding, with automatic fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XskBindMode {
    /// Hardware/driver zero-copy mode directly to NIC ring.
    ZeroCopy,
    /// Kernel copy mode (skb copy into UMEM, used in cloud VMs).
    Copy,
    /// Graceful portable fallback using standard recvmmsg/sendmmsg socket I/O.
    FallbackRecvmmsg,
}

/// Descriptor for AF_XDP packets in RX and TX rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XskDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u32,
}

impl XskDesc {
    /// Creates a new `XskDesc` with the specified address, length, and flags.
    pub const fn new(addr: u64, len: u32, flags: u32) -> Self {
        Self { addr, len, flags }
    }
}

/// Circular descriptor ring for AF_XDP RX packets.
#[derive(Debug, Clone)]
pub struct RxRing {
    entries: Vec<XskDesc>,
    capacity: u32,
    head: u32,
    tail: u32,
}

impl RxRing {
    /// Creates a new RX ring with `capacity` descriptors. `capacity` must be a power of two.
    pub fn new(capacity: u32) -> Self {
        assert!(
            capacity > 0 && capacity.is_power_of_two(),
            "RxRing capacity must be a power of two, got {capacity}"
        );
        Self {
            entries: vec![XskDesc::default(); capacity as usize],
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

    /// Enqueues a descriptor into the RX ring. Returns `false` if full.
    pub fn produce(&mut self, desc: XskDesc) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.tail as usize) & ((self.capacity - 1) as usize);
        self.entries[idx] = desc;
        self.tail = self.tail.wrapping_add(1);
        true
    }

    /// Enqueues a batch of descriptors into the RX ring. Returns count enqueued.
    pub fn produce_batch(&mut self, descs: &[XskDesc]) -> usize {
        let mut count = 0;
        for &desc in descs {
            if !self.produce(desc) {
                break;
            }
            count += 1;
        }
        count
    }

    /// Dequeues a descriptor from the RX ring.
    pub fn consume(&mut self) -> Option<XskDesc> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head as usize) & ((self.capacity - 1) as usize);
        let desc = self.entries[idx];
        self.head = self.head.wrapping_add(1);
        Some(desc)
    }

    /// Dequeues up to `out.len()` descriptors into `out`. Returns count dequeued.
    pub fn consume_batch(&mut self, out: &mut [XskDesc]) -> usize {
        let mut count = 0;
        for item in out.iter_mut() {
            match self.consume() {
                Some(desc) => {
                    *item = desc;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

/// Circular descriptor ring for AF_XDP TX packets.
#[derive(Debug, Clone)]
pub struct TxRing {
    entries: Vec<XskDesc>,
    capacity: u32,
    head: u32,
    tail: u32,
}

impl TxRing {
    /// Creates a new TX ring with `capacity` descriptors. `capacity` must be a power of two.
    pub fn new(capacity: u32) -> Self {
        assert!(
            capacity > 0 && capacity.is_power_of_two(),
            "TxRing capacity must be a power of two, got {capacity}"
        );
        Self {
            entries: vec![XskDesc::default(); capacity as usize],
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

    /// Enqueues a descriptor into the TX ring. Returns `false` if full.
    pub fn produce(&mut self, desc: XskDesc) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.tail as usize) & ((self.capacity - 1) as usize);
        self.entries[idx] = desc;
        self.tail = self.tail.wrapping_add(1);
        true
    }

    /// Enqueues a batch of descriptors into the TX ring. Returns count enqueued.
    pub fn produce_batch(&mut self, descs: &[XskDesc]) -> usize {
        let mut count = 0;
        for &desc in descs {
            if !self.produce(desc) {
                break;
            }
            count += 1;
        }
        count
    }

    /// Dequeues a descriptor from the TX ring.
    pub fn consume(&mut self) -> Option<XskDesc> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.head as usize) & ((self.capacity - 1) as usize);
        let desc = self.entries[idx];
        self.head = self.head.wrapping_add(1);
        Some(desc)
    }

    /// Dequeues up to `out.len()` descriptors into `out`. Returns count dequeued.
    pub fn consume_batch(&mut self, out: &mut [XskDesc]) -> usize {
        let mut count = 0;
        for item in out.iter_mut() {
            match self.consume() {
                Some(desc) => {
                    *item = desc;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

/// RAII helper ensuring raw file descriptors are closed if initialization fails early.
struct AutoCloseFd(RawFd);

impl AutoCloseFd {
    fn into_raw(mut self) -> RawFd {
        let fd = self.0;
        self.0 = -1;
        fd
    }
}

impl Drop for AutoCloseFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: `self.0` is an open file descriptor owned by `AutoCloseFd`.
            // Closing it releases OS resources upon early return or failure.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// AF_XDP socket with three-tier opportunistic fallback engine.
pub struct XskSocket {
    fd: RawFd,
    mode: XskBindMode,
    rx_ring: RxRing,
    tx_ring: TxRing,
}

impl XskSocket {
    /// Attempts opportunistic binding of an AF_XDP socket.
    ///
    /// Fallback order:
    /// 1. Zero-Copy mode (`XskBindMode::ZeroCopy`)
    /// 2. Copy mode (`XskBindMode::Copy`)
    /// 3. Portable recvmmsg fallback (`XskBindMode::FallbackRecvmmsg`)
    ///
    /// If running unprivileged or kernel lacks AF_XDP, cleanly returns `FallbackRecvmmsg`.
    pub fn bind_opportunistic(ifname: &str, queue_id: u32, umem: &UmemPool) -> io::Result<Self> {
        // SAFETY: Calling `socket(AF_XDP, SOCK_RAW, 0)` requests a raw AF_XDP socket from the kernel.
        // It requires no initialized pointers or preconditions.
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(
                    libc::EPERM
                    | libc::EACCES
                    | libc::EAFNOSUPPORT
                    | libc::ENOPROTOOPT
                    | libc::EPROTONOSUPPORT,
                ) => return Ok(Self::fallback()),
                _ => return Ok(Self::fallback()),
            }
        }

        let sock_guard = AutoCloseFd(fd);

        // 1. Configure UMEM registration
        let mr = libc::xdp_umem_reg {
            addr: umem.area_ptr() as u64,
            len: umem.size() as u64,
            chunk_size: umem.chunk_size() as u32,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };

        // SAFETY: `fd` is a valid open AF_XDP socket. `mr` is a stack-local `xdp_umem_reg`
        // initialized with valid UMEM memory bounds and chunk parameters. The memory region
        // is guaranteed valid by `umem`. Size passed matches `sizeof(xdp_umem_reg)`.
        let ret_umem = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_UMEM_REG,
                std::ptr::addr_of!(mr).cast::<libc::c_void>(),
                std::mem::size_of::<libc::xdp_umem_reg>() as libc::socklen_t,
            )
        };
        if ret_umem != 0 {
            return Ok(Self::fallback());
        }

        let ring_size: u32 = UMEM_RING_SIZE;

        // 2. Configure Fill Ring
        // SAFETY: `fd` is an open AF_XDP socket. `ring_size` is a valid stack-local u32.
        // Size passed matches `sizeof(u32)`.
        let ret_fill = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_UMEM_FILL_RING,
                std::ptr::addr_of!(ring_size).cast::<libc::c_void>(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret_fill != 0 {
            return Ok(Self::fallback());
        }

        // 3. Configure Completion Ring
        // SAFETY: `fd` is an open AF_XDP socket. `ring_size` is a valid stack-local u32.
        // Size passed matches `sizeof(u32)`.
        let ret_comp = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_UMEM_COMPLETION_RING,
                std::ptr::addr_of!(ring_size).cast::<libc::c_void>(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret_comp != 0 {
            return Ok(Self::fallback());
        }

        // 4. Configure RX Ring
        // SAFETY: `fd` is an open AF_XDP socket. `ring_size` is a valid stack-local u32.
        // Size passed matches `sizeof(u32)`.
        let ret_rx = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_RX_RING,
                std::ptr::addr_of!(ring_size).cast::<libc::c_void>(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret_rx != 0 {
            return Ok(Self::fallback());
        }

        // 5. Configure TX Ring
        // SAFETY: `fd` is an open AF_XDP socket. `ring_size` is a valid stack-local u32.
        // Size passed matches `sizeof(u32)`.
        let ret_tx = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_TX_RING,
                std::ptr::addr_of!(ring_size).cast::<libc::c_void>(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret_tx != 0 {
            return Ok(Self::fallback());
        }

        // 6. Resolve network interface index
        let c_ifname = match CString::new(ifname) {
            Ok(c) => c,
            Err(_) => return Ok(Self::fallback()),
        };

        // SAFETY: `c_ifname` is a valid null-terminated C string.
        let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
        if ifindex == 0 {
            return Ok(Self::fallback());
        }

        // 7. Attempt bind with XDP_ZERO_COPY
        let mut sxdp: libc::sockaddr_xdp = unsafe {
            // SAFETY: zeroing a C struct with POD fields is safe.
            std::mem::zeroed()
        };
        sxdp.sxdp_family = libc::AF_XDP as u16;
        sxdp.sxdp_ifindex = ifindex;
        sxdp.sxdp_queue_id = queue_id;
        sxdp.sxdp_shared_umem_fd = 0;
        sxdp.sxdp_flags = XDP_ZERO_COPY;

        // SAFETY: `fd` is an open AF_XDP socket. `sxdp` is a valid stack-local sockaddr_xdp.
        // Size passed matches `sizeof(sockaddr_xdp)`.
        let ret_zc = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(sxdp).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
            )
        };

        if ret_zc == 0 {
            let fd = sock_guard.into_raw();
            return Ok(Self {
                fd,
                mode: XskBindMode::ZeroCopy,
                rx_ring: RxRing::new(UMEM_RING_SIZE),
                tx_ring: TxRing::new(UMEM_RING_SIZE),
            });
        }

        // 8. Attempt bind with XDP_COPY if ZeroCopy returned unsupported error
        let zc_err = io::Error::last_os_error();
        let should_try_copy = matches!(
            zc_err.raw_os_error(),
            Some(libc::EOPNOTSUPP | ENOTSUPP | libc::EINVAL)
        );

        if should_try_copy {
            sxdp.sxdp_flags = XDP_COPY;
            // SAFETY: `fd` is an open AF_XDP socket. `sxdp` is a valid stack-local sockaddr_xdp.
            // Size passed matches `sizeof(sockaddr_xdp)`.
            let ret_copy = unsafe {
                libc::bind(
                    fd,
                    std::ptr::addr_of!(sxdp).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
                )
            };

            if ret_copy == 0 {
                let fd = sock_guard.into_raw();
                return Ok(Self {
                    fd,
                    mode: XskBindMode::Copy,
                    rx_ring: RxRing::new(UMEM_RING_SIZE),
                    tx_ring: TxRing::new(UMEM_RING_SIZE),
                });
            }
        }

        // All AF_XDP attempts failed; fallback to portable recvmmsg mode
        Ok(Self::fallback())
    }

    /// Creates a fallback socket instance in `FallbackRecvmmsg` mode without an active AF_XDP socket.
    pub fn fallback() -> Self {
        Self {
            fd: -1,
            mode: XskBindMode::FallbackRecvmmsg,
            rx_ring: RxRing::new(UMEM_RING_SIZE),
            tx_ring: TxRing::new(UMEM_RING_SIZE),
        }
    }

    /// The active bind mode of this socket (ZeroCopy, Copy, or FallbackRecvmmsg).
    pub fn mode(&self) -> XskBindMode {
        self.mode
    }

    /// The raw file descriptor of the underlying AF_XDP socket, or -1 in fallback mode.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Mutable reference to the socket's RX ring buffer.
    pub fn rx_ring_mut(&mut self) -> &mut RxRing {
        &mut self.rx_ring
    }

    /// Mutable reference to the socket's TX ring buffer.
    pub fn tx_ring_mut(&mut self) -> &mut TxRing {
        &mut self.tx_ring
    }

    /// Immutable reference to the socket's RX ring buffer.
    pub fn rx_ring(&self) -> &RxRing {
        &self.rx_ring
    }

    /// Immutable reference to the socket's TX ring buffer.
    pub fn tx_ring(&self) -> &TxRing {
        &self.tx_ring
    }
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: `self.fd` is an open AF_XDP socket descriptor exclusively owned by
            // this `XskSocket`. Closing it releases the kernel socket resources.
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}
