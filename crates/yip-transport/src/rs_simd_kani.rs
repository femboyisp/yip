//! Formal symbolic equivalence proofs and exhaustive test harnesses for SIMD Galois Field arithmetic.
//!
//! Under GF(2^8) with reducing polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D):
//! 1. GFNI bit-matrix affine transformation (`GF2P8AFFINEQB`) applies an 8x8 binary matrix
//!    to an input byte, where bit i of the output is the parity of (mat_byte[7 - i] & src).
//! 2. SSSE3, AVX2, AVX-512, and ARM NEON vectorized multiplication split `src` into low and
//!    high nibbles (`src & 0x0f` and `src >> 4`), look up precomputed multiples in `lo` and `hi`
//!    tables, and XOR the partial products (`lo ^ hi`).
//!
//! This module provides:
//! - Kani symbolic proof harnesses (`#[cfg(kani)]`) proving that for all symbolic `coeff` and `src`,
//!   both SIMD implementations match scalar `gf256::mul(coeff, src)` byte-for-byte.
//! - Exhaustive unit tests (`#[cfg(test)]`) verifying all 256 * 256 = 65,536 combinations on
//!   every standard `cargo test` run without requiring the external Kani verifier.

use crate::gf256;
use crate::rs_simd::{gfni_matrix, nibble_tables};

/// Evaluates the GFNI 8x8 affine bit-matrix transform for byte `src` given 64-bit matrix `mat`.
///
/// In Intel GFNI `GF2P8AFFINEQB`, bit `i` of the result byte is computed as the parity
/// (XOR sum of bits) of `(mat_byte[7 - i] & src)`.
#[inline]
pub fn eval_gfni_affine(mat: u64, src: u8) -> u8 {
    let bytes = mat.to_le_bytes();
    let mut res = 0u8;
    for i in 0..8 {
        let mask = bytes[7 - i];
        let bit_parity = ((mask & src).count_ones() & 1) as u8;
        res |= bit_parity << i;
    }
    res
}

/// Evaluates the nibble table lookup for `src` given `lo` and `hi` 16-entry multiplication tables.
///
/// By the distributive property of field multiplication over XOR addition in GF(2^8):
/// `coeff * src = coeff * ((src & 0x0f) ^ (src & 0xf0)) = (coeff * (src & 0x0f)) ^ (coeff * (src & 0xf0))`
/// `            = lo[src & 0x0f] ^ hi[src >> 4]`.
#[inline]
pub fn eval_nibble_lookup(lo: &[u8; 16], hi: &[u8; 16], src: u8) -> u8 {
    let l = (src & 0x0f) as usize;
    let h = (src >> 4) as usize;
    lo[l] ^ hi[h]
}

// ============================================================================
// Kani Symbolic Verification Harnesses
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Formally proves that for any symbolic `coeff` and `src` in GF(2^8),
    /// the GFNI affine bit-matrix transform produces identical results to scalar `gf256::mul`.
    #[kani::proof]
    #[kani::unwind(9)]
    pub fn verify_gfni_matrix_multiplication_equivalence() {
        let coeff: u8 = kani::any();
        let src: u8 = kani::any();

        let mat = gfni_matrix(coeff);
        let gfni_res = eval_gfni_affine(mat, src);
        let expected = gf256::mul(coeff, src);

        assert_eq!(gfni_res, expected);
    }

    /// Formally proves that for any symbolic `coeff` and `src` in GF(2^8),
    /// the nibble lookup table decomposition (`lo ^ hi`) produces identical results to scalar `gf256::mul`.
    #[kani::proof]
    #[kani::unwind(9)]
    pub fn verify_nibble_table_multiplication_equivalence() {
        let coeff: u8 = kani::any();
        let src: u8 = kani::any();

        let (lo, hi) = nibble_tables(coeff);
        let nibble_res = eval_nibble_lookup(&lo, &hi, src);
        let expected = gf256::mul(coeff, src);

        assert_eq!(nibble_res, expected);
    }

    /// Formally proves mutual equivalence: GFNI transform, nibble lookup table,
    /// and scalar multiplication are mutually consistent for all inputs.
    #[kani::proof]
    #[kani::unwind(9)]
    pub fn verify_galois_simd_mutual_equivalence() {
        let coeff: u8 = kani::any();
        let src: u8 = kani::any();

        let mat = gfni_matrix(coeff);
        let gfni_res = eval_gfni_affine(mat, src);

        let (lo, hi) = nibble_tables(coeff);
        let nibble_res = eval_nibble_lookup(&lo, &hi, src);

        let expected = gf256::mul(coeff, src);

        assert_eq!(gfni_res, expected);
        assert_eq!(nibble_res, expected);
        assert_eq!(gfni_res, nibble_res);
    }
}

// ============================================================================
// Unit and Exhaustive Equivalence Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exhaustive_galois_simd_equivalence() {
        // Exhaustively verify all 256 * 256 = 65,536 combinations of coeff and src.
        for coeff in 0..=255u8 {
            let mat = gfni_matrix(coeff);
            let (lo, hi) = nibble_tables(coeff);

            for src in 0..=255u8 {
                let expected = gf256::mul(coeff, src);
                let gfni_res = eval_gfni_affine(mat, src);
                let nibble_res = eval_nibble_lookup(&lo, &hi, src);

                assert_eq!(
                    gfni_res, expected,
                    "GFNI mismatch: coeff={coeff}, src={src}"
                );
                assert_eq!(
                    nibble_res, expected,
                    "Nibble lookup mismatch: coeff={coeff}, src={src}"
                );
                assert_eq!(
                    gfni_res, nibble_res,
                    "Mutual SIMD mismatch: coeff={coeff}, src={src}"
                );
            }
        }
    }

    #[test]
    fn test_zero_coefficient_annihilates() {
        let mat = gfni_matrix(0);
        assert_eq!(mat, 0, "GFNI matrix for coeff=0 must be zero");

        let (lo, hi) = nibble_tables(0);
        assert_eq!(lo, [0u8; 16]);
        assert_eq!(hi, [0u8; 16]);

        for src in 0..=255u8 {
            assert_eq!(eval_gfni_affine(mat, src), 0);
            assert_eq!(eval_nibble_lookup(&lo, &hi, src), 0);
            assert_eq!(gf256::mul(0, src), 0);
        }
    }

    #[test]
    fn test_identity_coefficient_preserves_input() {
        let mat = gfni_matrix(1);
        let (lo, hi) = nibble_tables(1);

        for src in 0..=255u8 {
            let expected = src;
            assert_eq!(eval_gfni_affine(mat, src), expected);
            assert_eq!(eval_nibble_lookup(&lo, &hi, src), expected);
            assert_eq!(gf256::mul(1, src), expected);
        }
    }

    #[test]
    fn test_galois_distributivity_over_xor() {
        // Multiplication in GF(2^8) is linear over addition (XOR):
        // mul(c, a ^ b) == mul(c, a) ^ mul(c, b)
        for coeff in [0u8, 1, 2, 0x1d, 0x57, 0xaa, 0xff] {
            for a in [0u8, 1, 15, 16, 127, 255] {
                for b in [0u8, 2, 14, 32, 128, 240] {
                    let lhs = gf256::mul(coeff, a ^ b);
                    let rhs = gf256::mul(coeff, a) ^ gf256::mul(coeff, b);
                    assert_eq!(lhs, rhs, "Linearity failed for coeff={coeff}, a={a}, b={b}");
                }
            }
        }
    }
}
