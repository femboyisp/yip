//! Spike for issue #58: per-symbol coverage-auth MAC candidates.
//!
//! The yip-wire coverage-auth tag runs SipHash-2-4 over the full header‖symbol
//! (~1415 bytes) on every packet, both send and receive. The 4b re-profile put
//! it at ~9% of receiver CPU. The parked decision needs numbers: how much
//! cheaper is a faster keyed MAC over the *same* bytes, at equal 8-byte tag?
//!
//! This bench measures the MAC in isolation (no framing, no XOR mask) so the
//! comparison is apples-to-apples with `auth_tag` in yip-wire:
//!   - `siphash24` — today's construction (SipHasher24, 8-byte tag).
//!   - `siphash13` — SipHash-1-3, same crate, drop-in, ~2× faster per the note.
//!   - `blake3_keyed` — keyed BLAKE3, SIMD (AVX2) + constant-time, first 8 bytes.
//!
//! Covered length matches the real wire input: HEADER_LEN (15) + symbol payload.
//! We sweep a packet-sized symbol (1400) and a small control frame (48) so the
//! per-call fixed cost vs the per-byte cost are both visible.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hash::Hasher;
use std::hint::black_box;

use siphasher::sip::{SipHasher13, SipHasher24};

const HEADER_LEN: usize = 15;
const SIP_KEY: [u8; 16] = [0x5a; 16];
const BLAKE_KEY: [u8; 32] = [0x5a; 32];

/// Today's tag: SipHash-2-4, first 8 bytes (big-endian, as in yip-wire).
#[inline]
fn siphash24_tag(key: &[u8; 16], covered: &[u8]) -> [u8; 8] {
    let mut h = SipHasher24::new_with_key(key);
    h.write(covered);
    h.finish().to_be_bytes()
}

/// Candidate: SipHash-1-3, same 8-byte tag shape.
#[inline]
fn siphash13_tag(key: &[u8; 16], covered: &[u8]) -> [u8; 8] {
    let mut h = SipHasher13::new_with_key(key);
    h.write(covered);
    h.finish().to_be_bytes()
}

/// Candidate: keyed BLAKE3, truncated to an 8-byte tag.
#[inline]
fn blake3_tag(key: &[u8; 32], covered: &[u8]) -> [u8; 8] {
    let hash = blake3::keyed_hash(key, covered);
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hash.as_bytes()[..8]);
    tag
}

fn bench_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac_candidates");
    // Covered region = header + symbol payload, matching yip-wire's auth input.
    for &payload in &[48usize, 1400usize] {
        let covered_len = HEADER_LEN + payload;
        let covered = vec![0xa5u8; covered_len];
        group.throughput(Throughput::Bytes(covered_len as u64));

        group.bench_with_input(
            BenchmarkId::new("siphash24", covered_len),
            &covered,
            |b, cov| b.iter(|| black_box(siphash24_tag(&SIP_KEY, black_box(cov)))),
        );
        group.bench_with_input(
            BenchmarkId::new("siphash13", covered_len),
            &covered,
            |b, cov| b.iter(|| black_box(siphash13_tag(&SIP_KEY, black_box(cov)))),
        );
        group.bench_with_input(
            BenchmarkId::new("blake3_keyed", covered_len),
            &covered,
            |b, cov| b.iter(|| black_box(blake3_tag(&BLAKE_KEY, black_box(cov)))),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_mac);
criterion_main!(benches);
