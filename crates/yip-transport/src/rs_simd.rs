//! Poly-vector SIMD-accelerated Cauchy Reed–Solomon Galois Field engine over GF(2^8).
//!
//! Provides tiered SIMD acceleration:
//! - GFNI (Galois Field New Instructions bit-matrix affine transformation)
//! - AVX-512BW (512-bit nibble shuffle, 64 bytes per iteration)
//! - AVX2 (256-bit nibble shuffle, 32 bytes per iteration)
//! - SSSE3 (128-bit nibble shuffle, 16 bytes per iteration)
//! - ARM64 NEON (128-bit table lookup `vqtbl1q_u8`, 16 bytes per iteration)
//! - Pure-Rust scalar fallback
#![allow(unsafe_code)]

use std::sync::OnceLock;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// 64-byte aligned lookup tables for nibble multiplication and GFNI bit matrices in GF(2^8).
#[repr(C, align(64))]
struct SimdTables {
    lo: [[u8; 32]; 256],
    hi: [[u8; 32]; 256],
    gfni: [u64; 256],
}

static TABLES: OnceLock<SimdTables> = OnceLock::new();

/// Computes the 8x8 Galois field bit-matrix $A$ representing multiplication by `coeff`
/// in $GF(2^8)$ under polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (0x11d).
///
/// In GFNI `GF2P8AFFINEQB`, bit `i` of the output byte is computed as the parity of
/// `src AND byte[7-i]` of the 64-bit matrix operand. Therefore, byte `7-i` has bit `k`
/// equal to bit `i` of `coeff * (1 << k)`.
pub fn gfni_matrix(coeff: u8) -> u64 {
    let mut matrix_bytes = [0u8; 8];
    for k in 0..8 {
        let c_k = crate::gf256::mul(coeff, 1 << k);
        for i in 0..8 {
            if (c_k & (1 << i)) != 0 {
                matrix_bytes[7 - i] |= 1 << k;
            }
        }
    }
    u64::from_le_bytes(matrix_bytes)
}

fn tables() -> &'static SimdTables {
    TABLES.get_or_init(|| {
        let mut lo = [[0u8; 32]; 256];
        let mut hi = [[0u8; 32]; 256];
        let mut gfni = [0u64; 256];
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
            gfni[c] = gfni_matrix(coeff);
        }
        SimdTables { lo, hi, gfni }
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

/// Check if SSSE3 is supported at runtime on this CPU.
pub fn ssse3_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("ssse3")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
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

/// Check if AVX-512BW is supported at runtime on this CPU.
pub fn avx512bw_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx512bw")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Check if GFNI is supported at runtime on this CPU.
pub fn gfni_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("gfni")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Check if ARM64 NEON is supported at runtime on this CPU.
pub fn neon_supported() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("neon")
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Multiplies `src` by `coeff` in GF(2^8) and accumulates (XORs) into `dst` using 128-bit SSSE3 SIMD.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the SSSE3 target feature (e.g. verified
/// via [`ssse3_supported`]).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
pub unsafe fn mul_add_ssse3(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    if coeff == 0 {
        return;
    }

    let len = src.len();
    let chunks = len / 16;
    let t = tables();
    let c = coeff as usize;

    // SAFETY: t.lo and t.hi hold at least 16 bytes per entry, so reading 16 bytes via unaligned load is in-bounds.
    let v_tbl_lo = unsafe { _mm_loadu_si128(t.lo[c].as_ptr().cast::<__m128i>()) };
    // SAFETY: t.lo and t.hi hold at least 16 bytes per entry, so reading 16 bytes via unaligned load is in-bounds.
    let v_tbl_hi = unsafe { _mm_loadu_si128(t.hi[c].as_ptr().cast::<__m128i>()) };
    let mask_lo = _mm_set1_epi8(0x0f);

    for i in 0..chunks {
        let offset = i * 16;
        // SAFETY: offset + 16 <= len, and src and dst have verified length `len`. Pointers are valid
        // for 16-byte unaligned load and store operations without overlap (by Rust borrow rules).
        unsafe {
            let src_ptr = src.as_ptr().add(offset).cast::<__m128i>();
            let dst_ptr = dst.as_mut_ptr().add(offset).cast::<__m128i>();

            let data = _mm_loadu_si128(src_ptr);
            let prev_dst = _mm_loadu_si128(dst_ptr);

            let v_lo = _mm_and_si128(data, mask_lo);
            let shifted = _mm_srli_epi16(data, 4);
            let v_hi = _mm_and_si128(shifted, mask_lo);

            let p_lo = _mm_shuffle_epi8(v_tbl_lo, v_lo);
            let p_hi = _mm_shuffle_epi8(v_tbl_hi, v_hi);

            let prod = _mm_xor_si128(p_lo, p_hi);
            let acc = _mm_xor_si128(prev_dst, prod);

            _mm_storeu_si128(dst_ptr, acc);
        }
    }

    let remainder = chunks * 16;
    for i in remainder..len {
        dst[i] ^= crate::gf256::mul(src[i], coeff);
    }
}

/// Fallback implementation of `mul_add_ssse3` for non-x86_64 target architectures.
///
/// # Safety
///
/// Safe to call on non-x86_64 architectures; adheres to the same safety contract.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn mul_add_ssse3(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    crate::gf256::mul_slice_into(dst, src, coeff);
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
/// Safe to call on non-x86_64 architectures; adheres to the same safety contract.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn mul_add_avx2(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    crate::gf256::mul_slice_into(dst, src, coeff);
}

/// Multiplies `src` by `coeff` in GF(2^8) and accumulates (XORs) into `dst` using 512-bit AVX-512BW SIMD.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the AVX-512BW target feature (e.g. verified
/// via [`avx512bw_supported`]).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
pub unsafe fn mul_add_avx512(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    if coeff == 0 {
        return;
    }

    let len = src.len();
    let chunks = len / 64;
    let t = tables();
    let c = coeff as usize;

    // SAFETY: t.lo holds at least 16 bytes per entry in the first 16 bytes, so reading 16 bytes is in-bounds.
    let tbl_lo_128 = unsafe { _mm_loadu_si128(t.lo[c].as_ptr().cast::<__m128i>()) };
    // SAFETY: t.hi holds at least 16 bytes per entry in the first 16 bytes, so reading 16 bytes is in-bounds.
    let tbl_hi_128 = unsafe { _mm_loadu_si128(t.hi[c].as_ptr().cast::<__m128i>()) };

    // Broadcast 128-bit table across all 4 128-bit lanes of 512-bit ZMM registers.
    let v_tbl_lo = _mm512_broadcast_i32x4(tbl_lo_128);
    let v_tbl_hi = _mm512_broadcast_i32x4(tbl_hi_128);
    let mask_lo = _mm512_set1_epi8(0x0f);

    for i in 0..chunks {
        let offset = i * 64;
        // SAFETY: offset + 64 <= len, and src and dst have verified length `len`. Pointers are valid
        // for 64-byte unaligned load and store operations without overlap (by Rust borrow rules).
        unsafe {
            let src_ptr = src.as_ptr().add(offset).cast::<__m512i>();
            let dst_ptr = dst.as_mut_ptr().add(offset).cast::<__m512i>();

            let data = _mm512_loadu_si512(src_ptr);
            let prev_dst = _mm512_loadu_si512(dst_ptr);

            let v_lo = _mm512_and_si512(data, mask_lo);
            let shifted = _mm512_srli_epi16(data, 4);
            let v_hi = _mm512_and_si512(shifted, mask_lo);

            let p_lo = _mm512_shuffle_epi8(v_tbl_lo, v_lo);
            let p_hi = _mm512_shuffle_epi8(v_tbl_hi, v_hi);

            let prod = _mm512_xor_si512(p_lo, p_hi);
            let acc = _mm512_xor_si512(prev_dst, prod);

            _mm512_storeu_si512(dst_ptr, acc);
        }
    }

    let remainder = chunks * 64;
    for i in remainder..len {
        dst[i] ^= crate::gf256::mul(src[i], coeff);
    }
}

/// Fallback implementation of `mul_add_avx512` for non-x86_64 target architectures.
///
/// # Safety
///
/// Safe to call on non-x86_64 architectures; adheres to the same safety contract.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn mul_add_avx512(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    crate::gf256::mul_slice_into(dst, src, coeff);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx512f")]
unsafe fn mul_add_gfni_512(mat: u64, coeff: u8, src: &[u8], dst: &mut [u8]) {
    let len = src.len();
    let chunks = len / 64;
    let v_mat = _mm512_set1_epi64(mat as i64);

    for i in 0..chunks {
        let offset = i * 64;
        // SAFETY: offset + 64 <= len, src and dst have verified length len, unaligned 64-byte pointers valid.
        unsafe {
            let src_ptr = src.as_ptr().add(offset).cast::<__m512i>();
            let dst_ptr = dst.as_mut_ptr().add(offset).cast::<__m512i>();

            let data = _mm512_loadu_si512(src_ptr);
            let prev_dst = _mm512_loadu_si512(dst_ptr);

            let prod = _mm512_gf2p8affine_epi64_epi8::<0>(data, v_mat);
            let acc = _mm512_xor_si512(prev_dst, prod);

            _mm512_storeu_si512(dst_ptr, acc);
        }
    }

    let remainder = chunks * 64;
    for i in remainder..len {
        dst[i] ^= crate::gf256::mul(src[i], coeff);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn mul_add_gfni_256(mat: u64, coeff: u8, src: &[u8], dst: &mut [u8]) {
    let len = src.len();
    let chunks = len / 32;
    let v_mat = _mm256_set1_epi64x(mat as i64);

    for i in 0..chunks {
        let offset = i * 32;
        // SAFETY: offset + 32 <= len, src and dst have verified length len, unaligned 32-byte pointers valid.
        unsafe {
            let src_ptr = src.as_ptr().add(offset).cast::<__m256i>();
            let dst_ptr = dst.as_mut_ptr().add(offset).cast::<__m256i>();

            let data = _mm256_loadu_si256(src_ptr);
            let prev_dst = _mm256_loadu_si256(dst_ptr);

            let prod = _mm256_gf2p8affine_epi64_epi8::<0>(data, v_mat);
            let acc = _mm256_xor_si256(prev_dst, prod);

            _mm256_storeu_si256(dst_ptr, acc);
        }
    }

    let remainder = chunks * 32;
    for i in remainder..len {
        dst[i] ^= crate::gf256::mul(src[i], coeff);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni")]
unsafe fn mul_add_gfni_128(mat: u64, coeff: u8, src: &[u8], dst: &mut [u8]) {
    let len = src.len();
    let chunks = len / 16;
    let v_mat = _mm_set1_epi64x(mat as i64);

    for i in 0..chunks {
        let offset = i * 16;
        // SAFETY: offset + 16 <= len, src and dst have verified length len, unaligned 16-byte pointers valid.
        unsafe {
            let src_ptr = src.as_ptr().add(offset).cast::<__m128i>();
            let dst_ptr = dst.as_mut_ptr().add(offset).cast::<__m128i>();

            let data = _mm_loadu_si128(src_ptr);
            let prev_dst = _mm_loadu_si128(dst_ptr);

            let prod = _mm_gf2p8affine_epi64_epi8::<0>(data, v_mat);
            let acc = _mm_xor_si128(prev_dst, prod);

            _mm_storeu_si128(dst_ptr, acc);
        }
    }

    let remainder = chunks * 16;
    for i in remainder..len {
        dst[i] ^= crate::gf256::mul(src[i], coeff);
    }
}

/// Multiplies `src` by `coeff` in GF(2^8) and accumulates (XORs) into `dst` using GFNI SIMD.
///
/// Dispatches dynamically to the widest vector width supported by the host CPU:
/// 512-bit (AVX-512F), 256-bit (AVX2), or 128-bit (SSE).
///
/// # Safety
///
/// The caller must ensure that the CPU supports GFNI (e.g. verified via [`gfni_supported`]).
#[cfg(target_arch = "x86_64")]
pub unsafe fn mul_add_gfni(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    if coeff == 0 {
        return;
    }
    let mat = tables().gfni[coeff as usize];
    if std::is_x86_feature_detected!("avx512f") {
        // SAFETY: Caller verified gfni_supported(), and avx512f is detected. Lengths verified equal.
        unsafe { mul_add_gfni_512(mat, coeff, src, dst) };
    } else if std::is_x86_feature_detected!("avx2") {
        // SAFETY: Caller verified gfni_supported(), and avx2 is detected. Lengths verified equal.
        unsafe { mul_add_gfni_256(mat, coeff, src, dst) };
    } else {
        // SAFETY: Caller verified gfni_supported(). Lengths verified equal.
        unsafe { mul_add_gfni_128(mat, coeff, src, dst) };
    }
}

/// Fallback implementation of `mul_add_gfni` for non-x86_64 target architectures.
///
/// # Safety
///
/// Safe to call on non-x86_64 architectures; adheres to the same safety contract.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn mul_add_gfni(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    crate::gf256::mul_slice_into(dst, src, coeff);
}

/// Multiplies `src` by `coeff` in GF(2^8) and accumulates (XORs) into `dst` using 128-bit ARM64 NEON.
///
/// # Safety
///
/// The caller must ensure that the CPU supports ARM64 NEON (e.g. verified via [`neon_supported`]).
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn mul_add_neon(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst lengths must match");
    if coeff == 0 {
        return;
    }

    use core::arch::aarch64::*;

    let len = src.len();
    let chunks = len / 16;
    let (tbl_lo, tbl_hi) = nibble_tables(coeff);

    // SAFETY: tbl_lo is a 16-byte fixed array, so reading 16 bytes via unaligned load is in-bounds.
    let t_lo = unsafe { vld1q_u8(tbl_lo.as_ptr()) };
    // SAFETY: tbl_hi is a 16-byte fixed array, so reading 16 bytes via unaligned load is in-bounds.
    let t_hi = unsafe { vld1q_u8(tbl_hi.as_ptr()) };
    let mask_lo = vdupq_n_u8(0x0f);

    for i in 0..chunks {
        let offset = i * 16;
        // SAFETY: offset + 16 <= len, and src and dst have verified length `len`. Pointers are valid
        // for 16-byte unaligned load and store operations without overlap (by Rust borrow rules).
        unsafe {
            let src_ptr = src.as_ptr().add(offset);
            let dst_ptr = dst.as_mut_ptr().add(offset);

            let data = vld1q_u8(src_ptr);
            let prev_dst = vld1q_u8(dst_ptr);

            let v_lo = vandq_u8(data, mask_lo);
            let shifted = vshrq_n_u8(data, 4);
            let v_hi = vandq_u8(shifted, mask_lo);

            let p_lo = vqtbl1q_u8(t_lo, v_lo);
            let p_hi = vqtbl1q_u8(t_hi, v_hi);

            let prod = veorq_u8(p_lo, p_hi);
            let acc = veorq_u8(prev_dst, prod);

            vst1q_u8(dst_ptr, acc);
        }
    }

    let remainder = chunks * 16;
    for i in remainder..len {
        dst[i] ^= crate::gf256::mul(src[i], coeff);
    }
}

/// Fallback implementation of `mul_add_neon` for non-aarch64 target architectures.
///
/// # Safety
///
/// Safe to call on non-aarch64 architectures; adheres to the same safety contract.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn mul_add_neon(coeff: u8, src: &[u8], dst: &mut [u8]) {
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
    fn test_gfni_matrix_matches_scalar_gf256() {
        for coeff in 0..=255u8 {
            let mat = gfni_matrix(coeff);
            let bytes = mat.to_le_bytes();
            for x in 0..=255u8 {
                let mut res = 0u8;
                for i in 0..8 {
                    let mask = bytes[7 - i];
                    let bit_parity = (mask & x).count_ones() as u8 % 2;
                    res |= bit_parity << i;
                }
                assert_eq!(
                    res,
                    crate::gf256::mul(coeff, x),
                    "GFNI bit matrix mismatch for coeff={coeff}, x={x}"
                );
            }
        }
    }

    #[test]
    fn test_mul_add_ssse3_matches_scalar() {
        if !ssse3_supported() {
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

                // SAFETY: ssse3_supported() confirmed SSSE3 is available, slice lengths match.
                unsafe {
                    mul_add_ssse3(coeff, &src[..len], &mut dst_simd);
                }
                crate::gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

                assert_eq!(
                    dst_simd, dst_scalar,
                    "mismatch for coeff={coeff}, len={len}"
                );
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

    #[test]
    fn test_mul_add_avx512_matches_scalar() {
        if !avx512bw_supported() {
            return;
        }

        let mut src = [0u8; 256];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(23);
        }

        for coeff in [0u8, 1, 2, 0x1d, 0x57, 0xff] {
            for len in [0, 1, 15, 16, 31, 32, 63, 64, 65, 128, 200, 256] {
                let mut dst_simd = vec![0x55; len];
                let mut dst_scalar = vec![0x55; len];

                // SAFETY: avx512bw_supported() confirmed AVX-512BW is available, slice lengths match.
                unsafe {
                    mul_add_avx512(coeff, &src[..len], &mut dst_simd);
                }
                crate::gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

                assert_eq!(
                    dst_simd, dst_scalar,
                    "mismatch for coeff={coeff}, len={len}"
                );
            }
        }
    }

    #[test]
    fn test_mul_add_gfni_matches_scalar() {
        if !gfni_supported() {
            return;
        }

        let mut src = [0u8; 256];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(19).wrapping_add(41);
        }

        for coeff in [0u8, 1, 2, 0x1d, 0x57, 0xff] {
            for len in [0, 1, 15, 16, 31, 32, 63, 64, 65, 128, 200, 256] {
                let mut dst_simd = vec![0xcc; len];
                let mut dst_scalar = vec![0xcc; len];

                // SAFETY: gfni_supported() confirmed GFNI is available, slice lengths match.
                unsafe {
                    mul_add_gfni(coeff, &src[..len], &mut dst_simd);
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
