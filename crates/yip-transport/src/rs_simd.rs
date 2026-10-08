//! AVX2 SIMD-accelerated Cauchy Reed–Solomon Galois Field engine over GF(2^8).
//!
//! Uses 256-bit AVX2 SIMD nibble shuffle tables (`_mm256_shuffle_epi8`) to vectorize
//! matrix row additions and multiplications over GF(256).
#![allow(unsafe_code)]

use std::sync::OnceLock;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// 32-byte aligned lookup tables for low and high nibble multiplication in GF(2^8).
///
/// For each coefficient `coeff ∈ 0..=255`:
/// - `lo[coeff]` contains `T_lo[b] = mul(coeff, b)` for `b ∈ 0..16`, repeated across both 128-bit AVX2 lanes.
/// - `hi[coeff]` contains `T_hi[b] = mul(coeff, b << 4)` for `b ∈ 0..16`, repeated across both 128-bit AVX2 lanes.
#[repr(C, align(32))]
struct SimdTables {
    lo: [[u8; 32]; 256],
    hi: [[u8; 32]; 256],
}

static TABLES: OnceLock<SimdTables> = OnceLock::new();

fn tables() -> &'static SimdTables {
    TABLES.get_or_init(|| {
        let mut lo = [[0u8; 32]; 256];
        let mut hi = [[0u8; 32]; 256];
        for coeff in 0..=255u8 {
            let c = coeff as usize;
            for b in 0..16u8 {
                let v_lo = crate::gf256::mul(coeff, b);
                let v_hi = crate::gf256::mul(coeff, b << 4);
                lo[c][b as usize] = v_lo;
                lo[c][b as usize + 16] = v_lo;
                hi[c][b as usize] = v_hi;
                hi[c][b as usize + 16] = v_hi;
            }
        }
        SimdTables { lo, hi }
    })
}

/// Returns the 16-entry low and high nibble multiplication tables for `coeff`.
///
/// - `lo[b] = mul(coeff, b)` for `b ∈ 0..16`.
/// - `hi[b] = mul(coeff, b << 4)` for `b ∈ 0..16`.
pub fn nibble_tables(coeff: u8) -> ([u8; 16], [u8; 16]) {
    let t = tables();
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&t.lo[coeff as usize][..16]);
    hi.copy_from_slice(&t.hi[coeff as usize][..16]);
    (lo, hi)
}

/// Check if AVX2 is supported at runtime on this CPU.
pub fn avx2_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Multiplies `src` by `coeff` in GF(2^8) and accumulates (XORs) into `dst` using 256-bit AVX2 SIMD.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the AVX2 target feature (e.g. verified
/// via [`avx2_supported`]).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn mul_add_avx2(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    if coeff == 0 {
        return;
    }

    let len = src.len();
    let chunks = len / 32;
    let t = tables();
    let c = coeff as usize;

    // SAFETY: t.lo and t.hi hold 32 bytes per entry, so reading 32 bytes via unaligned load is in-bounds.
    let v_tbl_lo = unsafe { _mm256_loadu_si256(t.lo[c].as_ptr().cast::<__m256i>()) };
    // SAFETY: t.lo and t.hi hold 32 bytes per entry, so reading 32 bytes via unaligned load is in-bounds.
    let v_tbl_hi = unsafe { _mm256_loadu_si256(t.hi[c].as_ptr().cast::<__m256i>()) };
    // _mm256_set1_epi8 creates a vector register with byte broadcast; no memory dereference.
    let mask_lo = _mm256_set1_epi8(0x0f);

    for i in 0..chunks {
        let offset = i * 32;
        // SAFETY: offset + 32 <= len, and src and dst have verified length `len`. Pointers are valid
        // for 32-byte unaligned load and store operations without overlap (by Rust borrow rules).
        unsafe {
            let src_ptr = src.as_ptr().add(offset).cast::<__m256i>();
            let dst_ptr = dst.as_mut_ptr().add(offset).cast::<__m256i>();

            let data = _mm256_loadu_si256(src_ptr);
            let prev_dst = _mm256_loadu_si256(dst_ptr);

            let v_lo = _mm256_and_si256(data, mask_lo);
            let shifted = _mm256_srli_epi16(data, 4);
            let v_hi = _mm256_and_si256(shifted, mask_lo);

            let p_lo = _mm256_shuffle_epi8(v_tbl_lo, v_lo);
            let p_hi = _mm256_shuffle_epi8(v_tbl_hi, v_hi);

            let prod = _mm256_xor_si256(p_lo, p_hi);
            let acc = _mm256_xor_si256(prev_dst, prod);

            _mm256_storeu_si256(dst_ptr, acc);
        }
    }

    let remainder = chunks * 32;
    for i in remainder..len {
        dst[i] ^= crate::gf256::mul(src[i], coeff);
    }
}

/// Fallback implementation of `mul_add_avx2` for non-x86_64 target architectures.
///
/// # Safety
///
/// Safe to call on non-x86_64 architectures; adheres to the same safety contract as the AVX2 version.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn mul_add_avx2(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    crate::gf256::mul_slice_into(dst, src, coeff);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nibble_tables_match_scalar_gf256() {
        for coeff in 0..=255u8 {
            let (lo, hi) = nibble_tables(coeff);
            for b in 0..16u8 {
                assert_eq!(lo[b as usize], crate::gf256::mul(coeff, b));
                assert_eq!(hi[b as usize], crate::gf256::mul(coeff, b << 4));
            }
        }
    }

    #[test]
    fn test_mul_add_avx2_matches_scalar() {
        if !avx2_supported() {
            return;
        }

        let mut src = [0u8; 128];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }

        for coeff in [0u8, 1, 2, 0x1d, 0x57, 0xff] {
            for len in [0, 1, 15, 16, 31, 32, 33, 64, 100, 128] {
                let mut dst_simd = vec![0xaa; len];
                let mut dst_scalar = vec![0xaa; len];

                // SAFETY: avx2_supported() confirmed AVX2 is available, slice lengths match.
                unsafe {
                    mul_add_avx2(coeff, &src[..len], &mut dst_simd);
                }
                crate::gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

                assert_eq!(
                    dst_simd, dst_scalar,
                    "mismatch for coeff={coeff}, len={len}"
                );
            }
        }
    }
}
