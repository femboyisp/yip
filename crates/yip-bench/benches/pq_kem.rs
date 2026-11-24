use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use yip_crypto::{
    generate_pq_keypair_from_seed_for_algo, pq_decapsulate_to_slice, pq_encapsulate_to_slice,
    InitiatorHandshake, PqKemAlgorithm, ResponderHandshake,
};
use yip_wire::{chunk_handshake_datagram, HandshakeReassembler};

fn bench_pq_primitives(c: &mut Criterion) {
    let algos = [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ];

    let mut group = c.benchmark_group("pq_kem_primitives");

    for algo in algos {
        let name = algo.as_str();

        // 1. Keygen from seed
        let seed = [0x42u8; 64];
        group.bench_with_input(BenchmarkId::new("keygen", name), &algo, |b, &alg| {
            b.iter(|| {
                let (ek, dk) = generate_pq_keypair_from_seed_for_algo(alg, black_box(&seed));
                black_box((ek, dk));
            });
        });

        // 2. Encapsulate to slice (zero allocation)
        let (ek, dk) = generate_pq_keypair_from_seed_for_algo(algo, &seed);
        let mut ct = vec![0u8; algo.ciphertext_len()];
        let mut ss = [0u8; 32];
        let m = [0x77u8; 32];
        group.bench_with_input(
            BenchmarkId::new("encapsulate_zero_alloc", name),
            &algo,
            |b, &alg| {
                b.iter(|| {
                    pq_encapsulate_to_slice(
                        alg,
                        black_box(ek.as_bytes()),
                        black_box(&m),
                        black_box(&mut ct),
                        black_box(&mut ss),
                    )
                    .unwrap();
                });
            },
        );

        // 3. Decapsulate to slice (zero allocation)
        let dk_bytes = dk.to_bytes();
        group.bench_with_input(
            BenchmarkId::new("decapsulate_zero_alloc", name),
            &algo,
            |b, &alg| {
                b.iter(|| {
                    pq_decapsulate_to_slice(
                        alg,
                        black_box(&dk_bytes),
                        black_box(&ct),
                        black_box(&mut ss),
                    )
                    .unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_pqnoise_handshake(c: &mut Criterion) {
    let algos = [
        PqKemAlgorithm::MlKem512,
        PqKemAlgorithm::MlKem768,
        PqKemAlgorithm::MlKem1024,
    ];

    let mut group = c.benchmark_group("pqnoise_handshake");

    let initiator_priv = [0x11u8; 32];
    let responder_kp = yip_crypto::generate_keypair();
    let responder_priv = responder_kp.private;
    let responder_pub = responder_kp.public;
    let psk = [0x33u8; 32];
    let payload = [0x44u8; 64];

    for algo in algos {
        let name = algo.as_str();
        let seed = [0x55u8; 64];
        let (ek_resp, dk_resp) = generate_pq_keypair_from_seed_for_algo(algo, &seed);
        let ek_resp_bytes = ek_resp.as_bytes().to_vec();
        let dk_resp_bytes = dk_resp.to_bytes();

        // Bench Flight 1 construction
        group.bench_with_input(BenchmarkId::new("flight1_write", name), &algo, |b, &alg| {
            let mut out = vec![0u8; 2048];
            b.iter(|| {
                let mut init = InitiatorHandshake::new_with_algo(
                    alg,
                    &initiator_priv,
                    &responder_pub,
                    &ek_resp_bytes,
                    &psk,
                    &[],
                )
                .unwrap();
                let n = init.write_message_1(&payload, &mut out).unwrap();
                black_box(n);
            });
        });

        // Prepare Flight 1 message for Flight 2 benchmark
        let mut msg1 = vec![0u8; 2048];
        let mut init = InitiatorHandshake::new_with_algo(
            algo,
            &initiator_priv,
            &responder_pub,
            &ek_resp_bytes,
            &psk,
            &[],
        )
        .unwrap();
        let n1 = init.write_message_1(&payload, &mut msg1).unwrap();
        msg1.truncate(n1);

        // Bench Flight 2 construction (responder reading flight 1 + writing flight 2)
        group.bench_with_input(
            BenchmarkId::new("flight2_resp_roundtrip", name),
            &algo,
            |b, &alg| {
                let mut payload_out = [0u8; 128];
                let mut out_msg2 = vec![0u8; 2048];
                b.iter(|| {
                    let mut resp = ResponderHandshake::new_with_algo(
                        alg,
                        &responder_priv,
                        &ek_resp_bytes,
                        &psk,
                        &[],
                    )
                    .unwrap();
                    resp.read_message_1(&msg1, &dk_resp_bytes, &mut payload_out)
                        .unwrap();
                    let n2 = resp.write_message_2(&payload, &mut out_msg2).unwrap();
                    black_box(n2);
                });
            },
        );
    }
    group.finish();
}

fn bench_wire_fragmentation(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_fragmentation");

    // Flight 1 sizes: 512 = 864 B, 768 = 1184 B, 1024 = 1664 B
    let flight1_1024 = vec![0u8; 1664];
    let mtu = 1400;

    group.bench_function("chunk_1664b_into_1400b_mtu", |b| {
        b.iter(|| {
            let chunks = chunk_handshake_datagram(black_box(&flight1_1024), black_box(mtu), 0x1234);
            black_box(chunks);
        });
    });

    let chunks = chunk_handshake_datagram(&flight1_1024, mtu, 0x5678);
    group.bench_function("reassemble_2_chunks_into_1664b", |b| {
        b.iter(|| {
            let mut reassembler = HandshakeReassembler::new();
            let _ = reassembler.process_datagram(black_box(&chunks[0])).unwrap();
            let full = reassembler.process_datagram(black_box(&chunks[1])).unwrap();
            black_box(full);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_pq_primitives,
    bench_pqnoise_handshake,
    bench_wire_fragmentation
);
criterion_main!(benches);
