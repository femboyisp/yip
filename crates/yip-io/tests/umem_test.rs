use yip_io::af_xdp::{CompletionRing, FillRing, UmemPool, UMEM_CHUNK_SIZE, UMEM_RING_SIZE};

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
    assert_send_sync::<FillRing>();
    assert_send_sync::<CompletionRing>();
}
