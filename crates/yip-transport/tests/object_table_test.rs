use std::alloc::System;
use yip_transport::fec::{FecEncoder, FecReassembler, ObjState, ObjectTable, Symbol};
use yip_transport::FlowParams;
use yip_verify::{assert_no_alloc, TrackingAllocator};

#[global_allocator]
static ALLOC: TrackingAllocator<System> = TrackingAllocator(System);

fn dummy_obj(shard_len: usize) -> ObjState {
    ObjState {
        shard_len,
        object_size: shard_len as u32,
        ..Default::default()
    }
}

#[test]
fn test_circular_object_table_insert_and_lookup() {
    let mut table = ObjectTable::new(8);
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
    assert_eq!(table.capacity(), 8);

    table.insert(10, dummy_obj(100));
    table.insert(20, dummy_obj(200));
    table.insert(30, dummy_obj(300));

    assert_eq!(table.len(), 3);
    assert!(!table.is_empty());

    assert!(table.contains_key(&10));
    assert!(table.contains_key(&20));
    assert!(table.contains_key(&30));
    assert!(!table.contains_key(&40));

    assert_eq!(table.get(&10).unwrap().shard_len, 100);
    assert_eq!(table.get(&20).unwrap().shard_len, 200);
    assert_eq!(table[&30].shard_len, 300);

    // Mutation via get_mut
    if let Some(state) = table.get_mut(&20) {
        state.shard_len = 250;
    }
    assert_eq!(table.get(&20).unwrap().shard_len, 250);

    // Non-existent key lookups
    assert!(table.get(&999).is_none());
    assert!(table.get_mut(&999).is_none());

    // find_index checks
    table.insert(1, dummy_obj(50));
    assert_eq!(table.find_index(&10), Some(36));
    assert_eq!(table.find_index(&20), Some(8));
    assert_eq!(table.find_index(&30), Some(9));
    assert_eq!(table.find_index(&1), Some(20));
    assert_eq!(table.find_index(&999), None);
}

#[test]
fn test_circular_object_table_fallback_eviction() {
    let mut table = ObjectTable::new(1);
    table.insert(10, dummy_obj(100)); // bucket 9
    assert_eq!(table.len(), 1);
    // Key 20 hashes to bucket 2 (probes 2..5), which does not overlap 9..12.
    // At capacity 1, candidate slots in probe sequence are empty, triggering fallback eviction.
    let evicted = table.insert(20, dummy_obj(200));
    assert!(evicted.is_some());
    assert_eq!(evicted.unwrap().shard_len, 100);
    assert_eq!(table.len(), 1);
    assert!(!table.contains_key(&10));
    assert!(table.contains_key(&20));
}

#[test]
fn test_circular_object_table_removal() {
    let mut table = ObjectTable::new(8);
    table.insert(1, dummy_obj(10));
    table.insert(2, dummy_obj(20));
    table.insert(3, dummy_obj(30));

    assert_eq!(table.len(), 3);

    let removed = table.remove(&2);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().shard_len, 20);
    assert_eq!(table.len(), 2);

    assert!(table.contains_key(&1));
    assert!(!table.contains_key(&2));
    assert!(table.contains_key(&3));
    assert!(table.get(&2).is_none());

    // Second removal of the same key returns None
    assert!(table.remove(&2).is_none());
    assert_eq!(table.len(), 2);

    // Remove remaining
    assert!(table.remove(&1).is_some());
    assert!(table.remove(&3).is_some());
    assert_eq!(table.len(), 0);
    assert!(table.is_empty());
}

#[test]
fn test_circular_object_table_overwrite() {
    let mut table = ObjectTable::new(8);
    assert!(table.insert(42, dummy_obj(100)).is_none());
    assert_eq!(table.len(), 1);
    assert_eq!(table.get(&42).unwrap().shard_len, 100);

    let old = table.insert(42, dummy_obj(999));
    assert!(old.is_some());
    assert_eq!(old.unwrap().shard_len, 100);
    assert_eq!(table.len(), 1);
    assert_eq!(table.get(&42).unwrap().shard_len, 999);
}

#[test]
fn test_circular_object_table_capacity_eviction() {
    let mut table = ObjectTable::new(4);
    assert_eq!(table.capacity(), 4);

    table.insert(1, dummy_obj(10));
    table.insert(2, dummy_obj(20));
    table.insert(3, dummy_obj(30));
    table.insert(4, dummy_obj(40));
    assert_eq!(table.len(), 4);

    // Inserting 5th element at capacity evicts an entry to maintain capacity bounded to 4
    let evicted5 = table.insert(5, dummy_obj(50));
    assert!(evicted5.is_some());
    assert_eq!(table.len(), 4);
    assert!(table.contains_key(&5));

    // Inserting 6th element (sharing candidate buckets with 5) evicts candidate entry 5
    let evicted6 = table.insert(6, dummy_obj(60));
    assert_eq!(table.len(), 4);
    assert_eq!(evicted6.map(|s| s.shard_len), Some(50));
    assert!(!table.contains_key(&5), "Candidate key 5 must be evicted");
    assert!(table.contains_key(&6));
}

#[test]
fn test_circular_object_table_capacity_eviction_with_removals() {
    let mut table = ObjectTable::new(4);
    table.insert(1, dummy_obj(10));
    table.insert(2, dummy_obj(20));
    table.insert(3, dummy_obj(30));
    table.insert(4, dummy_obj(40));
    assert_eq!(table.len(), 4);

    // Explicitly remove 2
    assert!(table.remove(&2).is_some());
    assert_eq!(table.len(), 3);

    // Insert 5 -> table now holds [1, 3, 4, 5] without needing eviction
    assert!(table.insert(5, dummy_obj(50)).is_none());
    assert_eq!(table.len(), 4);
    assert!(table.contains_key(&1));
    assert!(table.contains_key(&3));
    assert!(table.contains_key(&4));
    assert!(table.contains_key(&5));

    // Insert 6 -> candidate-associative eviction evicts oldest in candidate buckets [12, 13] (key 5)
    let evicted6 = table.insert(6, dummy_obj(60));
    assert_eq!(table.len(), 4);
    assert_eq!(evicted6.map(|s| s.shard_len), Some(50));
    assert!(!table.contains_key(&5), "Key 5 must be evicted");
    assert!(table.contains_key(&1));
    assert!(table.contains_key(&3));
    assert!(table.contains_key(&4));
    assert!(table.contains_key(&6));
}

#[test]
fn test_circular_object_table_boundary_conditions() {
    // Capacity 1
    let mut single = ObjectTable::new(1);
    assert_eq!(single.capacity(), 1);
    assert_eq!(single.len(), 0);

    single.insert(100, dummy_obj(100));
    assert_eq!(single.len(), 1);
    assert!(single.contains_key(&100));

    // Overwrite existing in capacity 1
    let old = single.insert(100, dummy_obj(200));
    assert_eq!(old.unwrap().shard_len, 100);
    assert_eq!(single.len(), 1);
    assert_eq!(single[&100].shard_len, 200);

    // Evict in capacity 1
    single.insert(101, dummy_obj(300));
    assert_eq!(single.len(), 1);
    assert!(!single.contains_key(&100));
    assert!(single.contains_key(&101));

    // Extremes of u64 keys
    let mut boundaries = ObjectTable::new(8);
    let keys = [0u64, 1u64, u64::MAX, u64::MAX - 1, 1 << 63, 1 << 32];
    for (i, &k) in keys.iter().enumerate() {
        boundaries.insert(k, dummy_obj(i));
    }
    assert_eq!(boundaries.len(), keys.len());
    for (i, &k) in keys.iter().enumerate() {
        assert_eq!(boundaries.get(&k).unwrap().shard_len, i);
    }
}

#[test]
fn test_circular_object_table_high_churn() {
    let mut table = ObjectTable::new(32);
    assert_no_alloc!({
        for k in 0..1000u64 {
            table.insert(k, dummy_obj(k as usize));
            assert!(table.len() <= 32);
        }
    });
    assert_eq!(table.len(), 32);
    assert!(table.contains_key(&999));
    assert_eq!(table.get(&999).unwrap().shard_len, 999);
    let mut count = 0;
    for k in 0..1000u64 {
        if let Some(st) = table.get(&k) {
            assert_eq!(st.shard_len, k as usize);
            count += 1;
        }
    }
    assert_eq!(count, 32);
}

#[test]
fn test_zero_copy_repair_shards_under_loss() {
    let params = FlowParams {
        symbol_size: 1200,
        initial_repair_ratio: 0.5,
        deadline: std::time::Duration::from_millis(500),
        arq: false,
    };

    let original_payload = vec![0x37u8; 3600]; // K=3
    let mut encoder = FecEncoder::new();
    let symbols = encoder.encode(&original_payload, params, 2); // K=3, R=2
    assert_eq!(symbols.len(), 5);

    let mut reassembler = FecReassembler::new(params.symbol_size, 16);
    let obj_key = u64::from(symbols[0].object_id);

    // Push source shard 0 (creates ObjState and pre-allocates repair buffer slots)
    assert_eq!(reassembler.push(obj_key, &symbols[0], 0, 1000), None);

    // Assert zero allocations when receiving repair shard under packet loss
    assert_no_alloc!({
        let _ = reassembler.push(obj_key, &symbols[3], 0, 1000);
    });

    // Receive repair shard 4 (second parity) completing reassembly (shards 0, 3, 4 -> 3 shards for K=3)
    let decoded = reassembler.push(obj_key, &symbols[4], 0, 1000);
    assert_eq!(decoded.as_deref(), Some(original_payload.as_slice()));
    assert_eq!(reassembler.recovered_count(), 1);
}

#[test]
fn test_fec_reassembler_zero_alloc_under_steady_state_churn() {
    let symbol_size = 1200;
    let max_objects = 16;
    let mut reassembler = FecReassembler::new(symbol_size, max_objects);

    let dummy_symbol = Symbol {
        object_id: 1,
        object_size: 2400,
        payload_id: [0x01, 0, 0, 0],
        data: vec![0xAA; 1200],
    };

    // Warm up the reassembler across capacity to populate recycled buffer pools.
    for k in 0..(max_objects * 2) as u64 {
        let _ = reassembler.push(k, &dummy_symbol, 0, 10_000);
    }

    // Steady-state churn: stream 10,000 objects through FecReassembler.
    // Generational slot-map eviction and buffer recycling guarantee zero heap allocations.
    assert_no_alloc!({
        for k in 1000..11_000u64 {
            let _ = reassembler.push(k, &dummy_symbol, 0, 10_000);
        }
    });

    assert_eq!(reassembler.in_flight(), max_objects);
}

#[test]
fn test_fec_reassembler_collision_eviction_unrecoverable_accounting() {
    let symbol_size = 1200;
    // Capacity 64: max_objects is large enough that table capacity won't evict first
    let mut reassembler = FecReassembler::new(symbol_size, 64);

    let dummy_symbol = Symbol {
        object_id: 1,
        object_size: 2400,
        payload_id: [0x01, 0, 0, 0],
        data: vec![0xAA; 1200],
    };

    // Find keys that hash to the exact same bucket slot to trigger collision eviction
    let mask = 127; // For cap 64, num_buckets is 128 (mask 127)
    let target_hash = yip_transport::fec::hash_key(0, mask);
    let mut colliding_keys = Vec::new();
    let mut cand = 0u64;
    while colliding_keys.len() < 10 {
        if yip_transport::fec::hash_key(cand, mask) == target_hash {
            colliding_keys.push(cand);
        }
        cand += 1;
    }

    // Insert 8 colliding keys (filling all candidate ways across 2 probe buckets)
    for &k in &colliding_keys[..8] {
        let _ = reassembler.push(k, &dummy_symbol, 0, 10_000);
    }
    assert_eq!(reassembler.unrecoverable_count(), 0);

    // 9th colliding key must trigger collision eviction in candidate buckets
    let _ = reassembler.push(colliding_keys[8], &dummy_symbol, 0, 10_000);
    assert_eq!(reassembler.unrecoverable_count(), 1);
}
