//! Statistical constant-time verification using Welch's two-sample t-test (modeled on dudect).
//!
//! Evaluates timing distributions of cryptographic comparisons against fixed vs. randomized inputs.
//! Formally asserts:
//! 1. `subtle::ConstantTimeEq::ct_eq` exhibits no statistically significant timing leakage (|t| < 4.5).
//! 2. A deliberate early-exit variable-time comparator fails the t-test (|t| >= 15.0), proving
//!    the harness has high statistical power and avoids false negatives.

#![forbid(unsafe_code)]

use std::hint::black_box;
use std::time::Instant;
use subtle::ConstantTimeEq;

/// Online mean and variance tracker using Welford's algorithm.
#[derive(Default, Clone, Debug)]
pub struct Welford {
    count: usize,
    mean: f64,
    m2: f64,
}

impl Welford {
    /// Create a new, empty Welford accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a single timing measurement sample.
    pub fn update(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / (self.count as f64);
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    /// Total number of ingested samples.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Sample mean of the ingested distribution.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Sample variance (unbiased with N - 1 denominator).
    pub fn sample_variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / ((self.count - 1) as f64)
        }
    }
}

/// Compute Welch's two-sample t-statistic between two independent sample distributions.
///
/// Formula:
/// t = (mean_0 - mean_1) / sqrt(s_0^2 / N_0 + s_1^2 / N_1)
pub fn welch_t(c0: &Welford, c1: &Welford) -> f64 {
    let s0 = c0.sample_variance();
    let s1 = c1.sample_variance();
    let n0 = c0.count() as f64;
    let n1 = c1.count() as f64;
    let denom = (s0 / n0 + s1 / n1).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (c0.mean() - c1.mean()) / denom
    }
}

/// Lightweight deterministic 64-bit Xorshift PRNG for uniform trial randomization.
struct FastPrng(u64);

impl FastPrng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x5465_7374_5365_6564
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let val = self.next_u64().to_le_bytes();
            let len = chunk.len().min(8);
            chunk.copy_from_slice(&val[..len]);
        }
    }
}

/// Deliberate early-exit variable-time comparator serving as the mandatory negative control.
#[inline(never)]
fn variable_time_cmp(a: &[u8; 16], b: &[u8; 16]) -> bool {
    for i in 0..16 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

const NUM_TRIALS: usize = 50_000;

#[test]
fn test_negative_control_variable_time_rejected() {
    let secret = [0x5Au8; 16];

    let mut prng = FastPrng::new(0xFEED_FACE_CAFE_BEEF);
    let mut classes = Vec::with_capacity(NUM_TRIALS);
    let mut inputs = Vec::with_capacity(NUM_TRIALS);

    // Pre-populate input buffer symmetrically to avoid cache locality asymmetry between classes.
    for _ in 0..NUM_TRIALS {
        let is_random = prng.next_bool();
        classes.push(is_random);
        if is_random {
            let mut rnd = [0u8; 16];
            prng.fill_bytes(&mut rnd);
            inputs.push(rnd);
        } else {
            inputs.push(secret);
        }
    }

    let mut w0 = Welford::new();
    let mut w1 = Welford::new();

    for i in 0..NUM_TRIALS {
        let is_random = classes[i];
        let input = &inputs[i];

        let t0 = Instant::now();
        let res = variable_time_cmp(black_box(&secret), black_box(input));
        let dur = t0.elapsed().as_nanos() as f64;
        black_box(res);

        if is_random {
            w1.update(dur);
        } else {
            w0.update(dur);
        }
    }

    let t = welch_t(&w0, &w1);
    // Early-exit comparison on identical inputs vs random inputs (differing at index 0 in 99.6% of trials)
    // must be rejected by the statistical test (|t| >= 15.0 or >= 4.5).
    assert!(
        t.abs() >= 15.0,
        "negative control early-exit comparator failed rejection gate: |t| = {t:.4} (expected >= 15.0)"
    );
}

#[test]
fn test_constant_time_authentication_tags_16_bytes() {
    let secret = [0x37u8; 16];

    let mut prng = FastPrng::new(0x0123_4567_89AB_CDEF);
    let mut classes = Vec::with_capacity(NUM_TRIALS);
    let mut inputs = Vec::with_capacity(NUM_TRIALS);

    // Symmetrically pre-allocated inputs prevent CPU cache hierarchy bias between classes.
    for _ in 0..NUM_TRIALS {
        let is_random = prng.next_bool();
        classes.push(is_random);
        if is_random {
            let mut rnd = [0u8; 16];
            prng.fill_bytes(&mut rnd);
            inputs.push(rnd);
        } else {
            inputs.push(secret);
        }
    }

    let mut w0 = Welford::new();
    let mut w1 = Welford::new();

    for i in 0..NUM_TRIALS {
        let is_random = classes[i];
        let input = &inputs[i];

        let t0 = Instant::now();
        let res = black_box(&secret)
            .as_slice()
            .ct_eq(black_box(input).as_slice());
        let dur = t0.elapsed().as_nanos() as f64;
        black_box(res);

        if is_random {
            w1.update(dur);
        } else {
            w0.update(dur);
        }
    }

    let t = welch_t(&w0, &w1);
    // Subtle constant-time equality over 16-byte authentication tags must exhibit |t| < 4.5.
    assert!(
        t.abs() < 4.5,
        "16-byte authentication tag ct_eq leaked timing: |t| = {t:.4} (threshold < 4.5)"
    );
}

#[test]
fn test_constant_time_shared_secrets_32_bytes() {
    let secret = [0xA5u8; 32];

    let mut prng = FastPrng::new(0xCAFE_D00D_1234_5678);
    let mut classes = Vec::with_capacity(NUM_TRIALS);
    let mut inputs = Vec::with_capacity(NUM_TRIALS);

    // Symmetrically pre-allocated inputs prevent CPU cache hierarchy bias between classes.
    for _ in 0..NUM_TRIALS {
        let is_random = prng.next_bool();
        classes.push(is_random);
        if is_random {
            let mut rnd = [0u8; 32];
            prng.fill_bytes(&mut rnd);
            inputs.push(rnd);
        } else {
            inputs.push(secret);
        }
    }

    let mut w0 = Welford::new();
    let mut w1 = Welford::new();

    for i in 0..NUM_TRIALS {
        let is_random = classes[i];
        let input = &inputs[i];

        let t0 = Instant::now();
        let res = black_box(&secret)
            .as_slice()
            .ct_eq(black_box(input).as_slice());
        let dur = t0.elapsed().as_nanos() as f64;
        black_box(res);

        if is_random {
            w1.update(dur);
        } else {
            w0.update(dur);
        }
    }

    let t = welch_t(&w0, &w1);
    // Subtle constant-time equality over 32-byte shared secrets must exhibit |t| < 4.5.
    assert!(
        t.abs() < 4.5,
        "32-byte shared secret ct_eq leaked timing: |t| = {t:.4} (threshold < 4.5)"
    );
}
