use yip_io::af_xdp::{
    CompletionRing, FillRing, UmemPool, UmemSlab, UMEM_CHUNK_SIZE, UMEM_RING_SIZE,
};

#[test]
fn test_umem_pool_allocation_and_slicing() {
    let mut pool = UmemPool::new(64, UMEM_CHUNK_SIZE).expect("allocate UMEM pool");
    let c1 = pool.alloc_chunk().expect("alloc chunk 1");
    let c2 = pool.alloc_chunk().expect("alloc chunk 2");
    assert_ne!(c1, c2);

    {
        let slice = pool.chunk_slice_mut(c1, 100);
        slice[0] = 0x42;
        slice[99] = 0x99;
    }

    let read_slice = pool.chunk_slice(c1, 100);
    assert_eq!(read_slice[0], 0x42);
    assert_eq!(read_slice[99], 0x99);

    pool.free_chunk(c1);
    pool.free_chunk(c2);
}

#[test]
fn test_umem_pool_exhaustion_and_realloc() {
    let num_chunks = 4;
    let mut pool = UmemPool::new(num_chunks, UMEM_CHUNK_SIZE).expect("allocate small pool");
    assert_eq!(pool.free_chunk_count(), num_chunks);

    let mut allocated = Vec::new();
    for _ in 0..num_chunks {
        let chunk = pool.alloc_chunk().expect("alloc chunk");
        allocated.push(chunk);
    }
    assert_eq!(pool.free_chunk_count(), 0);
    assert!(pool.alloc_chunk().is_none(), "pool should be exhausted");

    // Free one chunk and verify re-allocation
    let freed = allocated.pop().unwrap();
    pool.free_chunk(freed);
    assert_eq!(pool.free_chunk_count(), 1);

    let reallocated = pool.alloc_chunk().expect("re-alloc chunk");
    assert_eq!(reallocated, freed);
    assert_eq!(pool.free_chunk_count(), 0);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn test_umem_slice_out_of_bounds_panics() {
    let pool = UmemPool::new(2, UMEM_CHUNK_SIZE).expect("allocate pool");
    // Size is 2 * 2048 = 4096. Address 4000 + len 200 exceeds 4096.
    let _ = pool.chunk_slice(4000, 200);
}

#[test]
#[should_panic(expected = "exceeds chunk_size")]
fn test_umem_slice_exceeds_chunk_size_panics() {
    let pool = UmemPool::new(4, UMEM_CHUNK_SIZE).expect("allocate pool");
    // Slicing more than UMEM_CHUNK_SIZE (2048) in a single chunk slice
    let _ = pool.chunk_slice(0, UMEM_CHUNK_SIZE + 1);
}

#[test]
fn test_fill_and_completion_rings() {
    let mut fill = FillRing::new(UMEM_RING_SIZE);
    assert_eq!(fill.capacity(), UMEM_RING_SIZE);
    assert_eq!(fill.len(), 0);
    assert!(fill.is_empty());
    assert!(!fill.is_full());

    // Produce addresses into FillRing
    assert!(fill.produce(1024));
    assert!(fill.produce(2048));
    assert_eq!(fill.len(), 2);
    assert!(!fill.is_empty());

    // Consume addresses
    assert_eq!(fill.consume(), Some(1024));
    assert_eq!(fill.consume(), Some(2048));
    assert_eq!(fill.consume(), None);
    assert!(fill.is_empty());

    // Batch produce and consume
    let batch = [4096u64, 8192, 12288];
    assert_eq!(fill.produce_batch(&batch), 3);
    assert_eq!(fill.len(), 3);

    let mut out = [0u64; 4];
    let consumed = fill.consume_batch(&mut out);
    assert_eq!(consumed, 3);
    assert_eq!(&out[..3], &batch);
    assert!(fill.is_empty());

    // CompletionRing
    let mut comp = CompletionRing::new(64);
    assert_eq!(comp.capacity(), 64);
    assert!(comp.produce(100));
    assert_eq!(comp.consume(), Some(100));
    assert_eq!(comp.consume(), None);
}

#[test]
fn test_umem_pool_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<UmemPool>();
    assert_send_sync::<UmemSlab>();
    assert_send_sync::<FillRing>();
    assert_send_sync::<CompletionRing>();
}

#[test]
fn test_umem_slab_creation_and_bounds() {
    let (pool, slabs) = UmemPool::new_slabs(64, UMEM_CHUNK_SIZE, 4).expect("create slabs");
    assert_eq!(slabs.len(), 4);
    assert_eq!(pool.size(), 64 * UMEM_CHUNK_SIZE);

    for (i, slab) in slabs.iter().enumerate() {
        assert_eq!(slab.slab_id(), i);
        assert_eq!(slab.num_chunks(), 16);
        assert_eq!(slab.total_chunks(), 16);
        assert_eq!(slab.free_chunk_count(), 16);
        assert_eq!(slab.chunk_size(), UMEM_CHUNK_SIZE);
        assert_eq!(slab.base_addr(), (i * 16 * UMEM_CHUNK_SIZE) as u64);
        assert_eq!(slab.end_addr(), ((i + 1) * 16 * UMEM_CHUNK_SIZE) as u64);

        // Test boundary conditions
        assert!(slab.contains_addr(slab.base_addr()));
        assert!(slab.contains_addr(slab.end_addr() - UMEM_CHUNK_SIZE as u64));
        assert!(!slab.contains_addr(slab.end_addr()));
        if slab.base_addr() > 0 {
            assert!(!slab.contains_addr(slab.base_addr() - UMEM_CHUNK_SIZE as u64));
        }
        // Unaligned address
        assert!(!slab.contains_addr(slab.base_addr() + 1));
    }
}

#[test]
fn test_umem_slab_allocation_and_slicing() {
    let (_pool, mut slabs) = UmemPool::new_slabs(32, UMEM_CHUNK_SIZE, 2).expect("create slabs");
    let mut slab0 = slabs.remove(0);
    let mut slab1 = slabs.remove(0);

    let c0 = slab0.alloc_chunk().expect("alloc from slab 0");
    let c1 = slab1.alloc_chunk().expect("alloc from slab 1");

    assert!(slab0.contains_addr(c0));
    assert!(slab1.contains_addr(c1));
    assert!(!slab0.contains_addr(c1));
    assert!(!slab1.contains_addr(c0));

    {
        let s0 = slab0.chunk_slice_mut(c0, 64);
        s0.fill(0xAA);
        let s1 = slab1.chunk_slice_mut(c1, 64);
        s1.fill(0xBB);
    }

    assert_eq!(slab0.chunk_slice(c0, 64), &[0xAA; 64]);
    assert_eq!(slab1.chunk_slice(c1, 64), &[0xBB; 64]);

    slab0.free_chunk(c0);
    slab1.free_chunk(c1);
    assert_eq!(slab0.free_chunk_count(), 16);
    assert_eq!(slab1.free_chunk_count(), 16);
}

#[test]
fn test_umem_slab_batch_allocation_and_freeing() {
    let (_pool, mut slabs) = UmemPool::new_slabs(16, UMEM_CHUNK_SIZE, 2).expect("create slabs");
    let mut slab = slabs.remove(0);
    assert_eq!(slab.free_chunk_count(), 8);

    let mut buf = [0u64; 4];
    let allocated = slab.alloc_batch(&mut buf);
    assert_eq!(allocated, 4);
    assert_eq!(slab.free_chunk_count(), 4);

    let mut buf2 = [0u64; 8];
    let allocated2 = slab.alloc_batch(&mut buf2);
    assert_eq!(allocated2, 4); // Only 4 were left
    assert_eq!(slab.free_chunk_count(), 0);
    assert_eq!(slab.alloc_chunk(), None);

    // Free in batches
    slab.free_batch(&buf[..allocated]);
    assert_eq!(slab.free_chunk_count(), 4);
    slab.free_batch(&buf2[..allocated2]);
    assert_eq!(slab.free_chunk_count(), 8);
}

#[test]
fn test_umem_slab_ring_populate_and_recycle() {
    let (_pool, mut slabs) = UmemPool::new_slabs(64, UMEM_CHUNK_SIZE, 1).expect("create slabs");
    let mut slab = slabs.remove(0);
    let mut fill = FillRing::new(32);
    let mut comp = CompletionRing::new(32);

    // Populate fill ring up to capacity
    let populated = slab.populate_fill_ring(&mut fill, 32);
    assert_eq!(populated, 32);
    assert_eq!(fill.len(), 32);
    assert_eq!(slab.free_chunk_count(), 32);

    // Consume from fill ring, simulate packet transmission, and push to completion ring
    let mut tx_addrs = [0u64; 16];
    let consumed = fill.consume_batch(&mut tx_addrs);
    assert_eq!(consumed, 16);
    assert_eq!(fill.len(), 16);

    let comp_produced = comp.produce_batch(&tx_addrs[..consumed]);
    assert_eq!(comp_produced, 16);
    assert_eq!(comp.len(), 16);

    // Recycle from completion ring back to fill ring
    let recycled = slab.recycle_from_rings(&mut comp, &mut fill, 16);
    assert_eq!(recycled, 16);
    assert_eq!(comp.len(), 0);
    assert_eq!(fill.len(), 32); // Fill ring replenished to full
    assert_eq!(slab.free_chunk_count(), 32);

    // Recycle when fill ring is already full -> should spill to slab
    let comp_produced2 = comp.produce_batch(&[tx_addrs[0], tx_addrs[1]]);
    assert_eq!(comp_produced2, 2);
    let recycled2 = slab.recycle_from_rings(&mut comp, &mut fill, 16);
    assert_eq!(recycled2, 2);
    assert_eq!(comp.len(), 0);
    assert_eq!(fill.len(), 32);
    assert_eq!(slab.free_chunk_count(), 34); // 2 surplus chunks returned to slab
}

#[test]
fn test_umem_slab_invalid_counts_and_bounds_panics() {
    let pool = std::sync::Arc::new(UmemPool::new(16, UMEM_CHUNK_SIZE).expect("pool"));
    assert!(pool.create_slabs(0).is_err());
    assert!(pool.create_slabs(32).is_err()); // More slabs than chunks

    let (_pool, mut slabs) = UmemPool::new_slabs(16, UMEM_CHUNK_SIZE, 2).expect("slabs");
    let mut slab0 = slabs.remove(0);
    let slab1 = slabs.remove(0);

    // Slicing out of slab bounds
    let foreign_addr = slab1.base_addr();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slab0.chunk_slice(foreign_addr, 64);
    }));
    assert!(res.is_err());

    let res_mut = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slab0.chunk_slice_mut(foreign_addr, 64);
    }));
    assert!(res_mut.is_err());
}

#[test]
fn test_ring_wraparound_batch_operations() {
    let mut ring = FillRing::new(8);
    // Fill 6 entries
    let initial = [1u64, 2, 3, 4, 5, 6];
    assert_eq!(ring.produce_batch(&initial), 6);

    // Consume 4 entries (advancing head to 4)
    let mut out = [0u64; 4];
    assert_eq!(ring.consume_batch(&mut out), 4);
    assert_eq!(out, [1, 2, 3, 4]);
    assert_eq!(ring.len(), 2);

    // Now produce 5 entries (from tail=6 wrapping past capacity 8)
    let wrapping_input = [10u64, 20, 30, 40, 50];
    assert_eq!(ring.produce_batch(&wrapping_input), 5);
    assert_eq!(ring.len(), 7);

    // Consume all 7 entries
    let mut all_out = [0u64; 7];
    assert_eq!(ring.consume_batch(&mut all_out), 7);
    assert_eq!(all_out, [5, 6, 10, 20, 30, 40, 50]);
    assert_eq!(ring.len(), 0);
}
