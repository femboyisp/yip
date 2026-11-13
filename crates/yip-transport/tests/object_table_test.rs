use std::alloc::System;
use yip_transport::fec::{FecEncoder, FecReassembler, ObjState, ObjectTable};
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

    // Inserting 5th element evicts oldest (key 1)
    table.insert(5, dummy_obj(50));
    assert_eq!(table.len(), 4);
    assert!(!table.contains_key(&1), "Key 1 must be evicted");
    assert!(table.contains_key(&2));
    assert!(table.contains_key(&3));
    assert!(table.contains_key(&4));
    assert!(table.contains_key(&5));

    // Inserting 6th element evicts key 2
    table.insert(6, dummy_obj(60));
    assert_eq!(table.len(), 4);
    assert!(!table.contains_key(&2), "Key 2 must be evicted");
    assert!(table.contains_key(&3));
    assert!(table.contains_key(&4));
    assert!(table.contains_key(&5));
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
    table.insert(5, dummy_obj(50));
    assert_eq!(table.len(), 4);
    assert!(table.contains_key(&1));
    assert!(table.contains_key(&3));
    assert!(table.contains_key(&4));
    assert!(table.contains_key(&5));

    // Insert 6 -> oldest active is 1, so 1 must be evicted
    table.insert(6, dummy_obj(60));
    assert_eq!(table.len(), 4);
    assert!(!table.contains_key(&1), "Key 1 must be evicted");
    assert!(table.contains_key(&3));
    assert!(table.contains_key(&4));
    assert!(table.contains_key(&5));
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
    for k in 0..1000u64 {
        table.insert(k, dummy_obj(k as usize));
        assert!(table.len() <= 32);
    }
    assert_eq!(table.len(), 32);
    for k in 968..1000u64 {
        assert!(table.contains_key(&k), "Key {k} must be present");
        assert_eq!(table.get(&k).unwrap().shard_len, k as usize);
    }
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
