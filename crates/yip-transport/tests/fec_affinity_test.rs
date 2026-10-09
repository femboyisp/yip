use yip_transport::fec::shard_for_fec_symbol;
use yip_transport::Transport;

#[test]
fn test_all_symbols_of_object_map_to_same_shard() {
    let conn_tag = 0x1234_5678_9abc_def0;
    let num_shards = 8;

    for object_id in 0..100u16 {
        let expected_shard = shard_for_fec_symbol(conn_tag, object_id, num_shards);
        for _symbol_idx in 0..10 {
            let s = shard_for_fec_symbol(conn_tag, object_id, num_shards);
            assert_eq!(
                s, expected_shard,
                "all symbols of object {object_id} must map to shard {expected_shard}"
            );
        }
    }
}

#[test]
fn test_boundary_shards_zero_and_one() {
    let conn_tag = 0xdead_beef_cafe_babe;
    for object_id in [0, 1, 42, 65535] {
        assert_eq!(shard_for_fec_symbol(conn_tag, object_id, 0), 0);
        assert_eq!(shard_for_fec_symbol(conn_tag, object_id, 1), 0);
    }
}

#[test]
fn test_shard_index_always_within_bounds() {
    let conn_tag = 0xcafe_babe_dead_beef;
    for num_shards in [2, 3, 4, 7, 8, 16, 32, 64] {
        for object_id in 0..500u16 {
            let shard = shard_for_fec_symbol(conn_tag, object_id, num_shards);
            assert!(
                shard < num_shards,
                "shard {shard} must be strictly less than num_shards {num_shards}"
            );
        }
    }
}

#[test]
fn test_fec_encoded_symbols_share_identical_shard() {
    let mut transport = Transport::new(vec![], 1200);
    let ciphertext = vec![0x42u8; 4800]; // 4 source symbols
    let inner = vec![0u8; 64];

    let (_class, symbols) = transport.encode(&ciphertext, &inner, false, 0);
    assert!(symbols.len() >= 4, "must produce at least 4 symbols");

    let conn_tag = 0x9876_5432_10fe_dcba;
    let num_shards = 8;

    let first_shard = shard_for_fec_symbol(conn_tag, symbols[0].object_id, num_shards);
    for sym in &symbols {
        let s = shard_for_fec_symbol(conn_tag, sym.object_id, num_shards);
        assert_eq!(
            s, first_shard,
            "every source and repair symbol must route to shard {first_shard}"
        );
    }
}

#[test]
fn test_shard_distribution_uniformity() {
    let conn_tag = 0xa5a5_5a5a_3c3c_c3c3;
    let num_shards = 4;
    let total = 10_000;
    let mut counts = vec![0; num_shards];

    for object_id in 0..total as u16 {
        let shard = shard_for_fec_symbol(conn_tag, object_id, num_shards);
        counts[shard] += 1;
    }

    let expected = total / num_shards;
    for (shard, &count) in counts.iter().enumerate() {
        let diff = (count as isize - expected as isize).abs();
        // Golden ratio hash should distribute cleanly: tolerance 250 with 2500 expected
        assert!(
            diff < 250,
            "shard {shard} count {count} deviated too far from expected {expected}"
        );
    }
}

#[test]
fn test_shard_for_fec_symbol_exact_hash() {
    let conn_tag = 0x1234_5678_9abc_def0;
    let object_id = 42;
    let num_shards = 8;
    let mixed_factor = (object_id as u64).wrapping_mul(0x9e3779b97f4a7c15);
    let xor_val = ((conn_tag ^ mixed_factor) as usize) % num_shards;
    let and_val = ((conn_tag & mixed_factor) as usize) % num_shards;
    assert_ne!(
        xor_val, and_val,
        "test precondition: xor and and must differ"
    );
    assert_eq!(
        shard_for_fec_symbol(conn_tag, object_id, num_shards),
        xor_val
    );
}
