use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use yip_transport::{FecEncoder, FecReassembler, FlowClass};

fn bench_fec_reassemble(c: &mut Criterion) {
    let mut enc = FecEncoder::new();

    // 1. Clean-path K=1 (typical WAN / internet MTU packet: 1200 bytes, 1 shard)
    let k1_data = vec![0x42u8; 1200];
    let k1_params = FlowClass::Default.params();
    let k1_syms = enc.encode(&k1_data, k1_params, 0);
    assert_eq!(k1_syms.len(), 1);

    c.bench_function("fec_reassemble_clean_k1", |bn| {
        let mut re = FecReassembler::new(k1_params.symbol_size, 256);
        let mut key: u64 = 1;
        bn.iter(|| {
            let res = re.push(black_box(key), black_box(&k1_syms[0]), 1000, 5000);
            key = key.wrapping_add(1);
            black_box(res)
        })
    });

    // 2. Clean-path K=3 (3600 bytes, 3 source shards, 0 loss)
    let k3_data = vec![0x42u8; 3600];
    let k3_params = FlowClass::Bulk.params();
    let k3_syms = enc.encode(&k3_data, k3_params, 0);
    assert_eq!(k3_syms.len(), 3);

    c.bench_function("fec_reassemble_clean_k3", |bn| {
        let mut re = FecReassembler::new(k3_params.symbol_size, 256);
        let mut key: u64 = 1;
        bn.iter(|| {
            let cur_key = key;
            key = key.wrapping_add(1);
            let _s0 = re.push(cur_key, &k3_syms[0], 1000, 5000);
            let _s1 = re.push(cur_key, &k3_syms[1], 1000, 5000);
            let res = re.push(cur_key, &k3_syms[2], 1000, 5000);
            black_box(res)
        })
    });

    // 3. Loss recovery K=3, R=1 (shard 1 missing, recovered via repair shard 3)
    let k3_r1_syms = enc.encode(&k3_data, k3_params, 1);
    assert_eq!(k3_r1_syms.len(), 4);
    let s0 = &k3_r1_syms[0];
    let s2 = &k3_r1_syms[2];
    let repair3 = &k3_r1_syms[3];

    c.bench_function("fec_reassemble_loss_k3_r1", |bn| {
        let mut re = FecReassembler::new(k3_params.symbol_size, 256);
        let mut key: u64 = 1;
        bn.iter(|| {
            let cur_key = key;
            key = key.wrapping_add(1);
            let _s0 = re.push(cur_key, s0, 1000, 5000);
            let _s2 = re.push(cur_key, s2, 1000, 5000);
            let res = re.push(cur_key, repair3, 1000, 5000);
            black_box(res)
        })
    });
}

criterion_group!(benches, bench_fec_reassemble);
criterion_main!(benches);
