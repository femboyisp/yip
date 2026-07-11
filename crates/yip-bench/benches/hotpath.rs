use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use yip_bench::{established_pair, sample_inner};
use yip_transport::{FecEncoder, FlowClass, Transport};
use yip_wire::{Codec, Frame, WireCodec};

fn bench_aead(c: &mut Criterion) {
    let (mut a, mut b) = established_pair();
    let payload = vec![7u8; 1300];
    c.bench_function("aead_seal_1300", |bn| {
        bn.iter(|| black_box(a.seal(black_box(&payload)).unwrap()))
    });
    // aead_open: re-seal each iteration so the counter advances and the replay
    // window accepts it. We measure both seal+open together, which slightly
    // inflates the open measurement, but is the simplest approach that avoids
    // replay-window rejection without restructuring around iter_batched.
    c.bench_function("aead_open_1300", |bn| {
        bn.iter(|| {
            // re-seal each iter so the counter advances and the replay window accepts it
            let s = a.seal(&payload).unwrap();
            black_box(b.open(s.counter, &s.ciphertext).ok());
        })
    });
}

fn bench_wire(c: &mut Criterion) {
    let codec = Codec::new([1u8; 16], [2u8; 16]);
    let frame = Frame {
        conn_tag: 1,
        object_id: 0,
        payload_id: [0; 4],
        flags: 0,
        payload: vec![9u8; 1300],
    };
    c.bench_function("wire_frame_1300", |bn| {
        bn.iter(|| black_box(codec.frame(black_box(&frame))))
    });
    let dg = codec.frame(&frame);
    c.bench_function("wire_deframe_1300", |bn| {
        bn.iter(|| black_box(codec.deframe(black_box(&dg)).unwrap()))
    });
}

fn bench_fec_and_classify(c: &mut Criterion) {
    let (mut a, _b) = established_pair();
    let inner = sample_inner(1300);
    let sealed = a.seal(&inner).unwrap();
    let mut tx = Transport::new(vec![], 1200);
    c.bench_function("transport_encode_1300", |bn| {
        bn.iter(|| black_box(tx.encode(black_box(&sealed.ciphertext), black_box(&inner), false, 0)))
    });
    // classify alone is exercised inside encode; a dedicated classify bench can call a public
    // classify path if exposed, else this encode bench covers it.

    // Isolate the P+Q codec cost directly (Transport can't force R=2 on a packet-sized
    // object). K=3 object; repair=1 = P (pure XOR), repair=2 = P+Q.
    let fec_params = FlowClass::Default.params();
    let fec_ct = vec![0xCDu8; 3600]; // K = 3
    c.bench_function("fec_encode_r1_p", |bn| {
        let mut enc = FecEncoder::new();
        bn.iter(|| black_box(enc.encode(black_box(&fec_ct), black_box(fec_params), 1)))
    });
    c.bench_function("fec_encode_r2_pq", |bn| {
        let mut enc = FecEncoder::new();
        bn.iter(|| black_box(enc.encode(black_box(&fec_ct), black_box(fec_params), 2)))
    });
}

criterion_group!(benches, bench_aead, bench_wire, bench_fec_and_classify);
criterion_main!(benches);
