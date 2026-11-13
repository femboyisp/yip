use std::alloc::System;
use yip_transport::{FecEncoder, FecReassembler, FecScratchArena, FlowClass, FlowParams};
use yip_verify::{assert_no_alloc, TrackingAllocator};

#[global_allocator]
static ALLOC: TrackingAllocator<System> = TrackingAllocator(System);

#[test]
fn test_fec_encoder_encode_zero_alloc_with_arena() {
    let mut encoder = FecEncoder::new();
    let mut arena = FecScratchArena::new();
    let params = FlowParams {
        symbol_size: 1200,
        initial_repair_ratio: 0.1,
        deadline: std::time::Duration::from_millis(50),
        arq: false,
    };

    // 1. Warm up arena and encoder for K=3, R=3
    let k3_data = vec![0x42u8; 3600];
    let _ = encoder.encode_with_arena(&k3_data, params, 3, &mut arena);

    // 2. Assert zero allocations on subsequent K=3, R=3 encoding under assert_no_alloc!
    for _ in 0..10 {
        assert_no_alloc!({
            let syms = encoder.encode_with_arena(&k3_data, params, 3, &mut arena);
            assert_eq!(syms.len(), 6);
        });
    }

    // 3. Assert zero allocations for K=1 with repair
    let k1_data = vec![0x77u8; 800];
    let _ = encoder.encode_with_arena(&k1_data, params, 2, &mut arena);
    for _ in 0..10 {
        assert_no_alloc!({
            let syms = encoder.encode_with_arena(&k1_data, params, 2, &mut arena);
            assert_eq!(syms.len(), 3);
            assert_eq!(syms[0].data.len(), 800);
            assert_eq!(syms[1].data.len(), 800);
            assert_eq!(syms[2].data.len(), 800);
        });
    }

    // 4. Assert zero allocations for sub-symbol wire trimming (K=2, 1400 bytes, symbol_size=1200)
    let k2_trim_data = vec![0x99u8; 1400];
    let _ = encoder.encode_with_arena(&k2_trim_data, params, 2, &mut arena);
    for _ in 0..10 {
        assert_no_alloc!({
            let syms = encoder.encode_with_arena(&k2_trim_data, params, 2, &mut arena);
            assert_eq!(syms.len(), 4);
            assert_eq!(syms[0].data.len(), 1200);
            assert_eq!(syms[1].data.len(), 200);
            assert_eq!(syms[2].data.len(), 1200);
            assert_eq!(syms[3].data.len(), 1200);
        });
    }

    // 5. Assert zero allocations with encode_into alias
    for _ in 0..10 {
        assert_no_alloc!({
            let syms = encoder.encode_into(&k3_data, params, 3, &mut arena);
            assert_eq!(syms.len(), 6);
        });
    }

    // 6. Assert zero allocations with ARQ retransmission (repair_with_id_with_arena)
    let arq_params = FlowClass::Bulk.params();
    let _ = encoder.repair_with_id_with_arena(&k3_data, arq_params, 42, 4, &mut arena);
    for _ in 0..10 {
        assert_no_alloc!({
            let syms = encoder.repair_with_id_with_arena(&k3_data, arq_params, 42, 4, &mut arena);
            assert_eq!(syms.len(), 7);
        });
    }

    // 7. Assert zero allocations with encoder's internal scratch arena (encode_scratch)
    let mut internal_enc = FecEncoder::new();
    let _ = internal_enc.encode_scratch(&k3_data, params, 3);
    for _ in 0..10 {
        assert_no_alloc!({
            let syms = internal_enc.encode_scratch(&k3_data, params, 3);
            assert_eq!(syms.len(), 6);
        });
    }

    // 8. Verify correctness: decoded output matches original payload
    let syms = encoder.encode_with_arena(&k2_trim_data, params, 2, &mut arena);
    let mut reassembler = FecReassembler::new(params.symbol_size, 64);
    let oid = u64::from(syms[0].object_id);
    assert_eq!(reassembler.push(oid, &syms[0], 0, 1000), None);
    let decoded = reassembler.push(oid, &syms[2], 0, 1000);
    assert_eq!(decoded.as_deref(), Some(k2_trim_data.as_slice()));
}

#[test]
fn test_fec_scratch_arena_ensure_capacity_boundaries() {
    let mut arena = FecScratchArena::with_capacity(4, 100);
    assert_eq!(arena.symbols().len(), 4);
    assert_eq!(arena.repair_shard_capacity(), 100);

    // Exact boundary: requesting equal capacity should not expand
    arena.ensure_capacity(4, 100);
    assert_eq!(arena.symbols().len(), 4);
    assert_eq!(arena.repair_shard_capacity(), 100);

    // Requesting larger symbol count expands symbols
    arena.ensure_capacity(10, 100);
    assert_eq!(arena.symbols().len(), 10);

    // Requesting larger shard len expands shard buffers
    arena.ensure_capacity(10, 250);
    assert!(arena.repair_shard_capacity() >= 250);
}
