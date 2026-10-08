use yip_transport::gf256;
use yip_transport::rs::{decode_source, encode_repair, mul_add_row, Scheme};
use yip_transport::rs_simd::{
    avx2_supported, avx512bw_supported, gfni_supported, mul_add_avx2, mul_add_avx512, mul_add_gfni,
    mul_add_ssse3, mul_add_wasm128, neon_supported, ssse3_supported, wasm_simd_supported,
};

const TEST_LENGTHS: &[usize] = &[
    0, 1, 7, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1024, 1500,
];

fn make_pseudo_random_buffer(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i as u8)
                .wrapping_mul(17)
                .wrapping_add(seed)
                .wrapping_mul(31)
        })
        .collect()
}

#[test]
fn test_simd_feature_flags_do_not_panic() {
    let _ = ssse3_supported();
    let _ = avx2_supported();
    let _ = avx512bw_supported();
    let _ = gfni_supported();
    let _ = neon_supported();
    let _ = wasm_simd_supported();
}

#[test]
fn test_ssse3_matches_scalar_differential() {
    if !ssse3_supported() {
        return;
    }

    let src = make_pseudo_random_buffer(2000, 13);
    for coeff in 0..=255u8 {
        for &len in TEST_LENGTHS {
            let mut dst_simd = make_pseudo_random_buffer(len, 42);
            let mut dst_scalar = dst_simd.clone();

            // SAFETY: ssse3_supported() verified SSSE3 is available, slice lengths match.
            unsafe {
                mul_add_ssse3(coeff, &src[..len], &mut dst_simd);
            }
            gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

            assert_eq!(
                dst_simd, dst_scalar,
                "SSSE3 mismatch for coeff={coeff}, len={len}"
            );
        }
    }
}

#[test]
fn test_avx2_matches_scalar_differential() {
    if !avx2_supported() {
        return;
    }

    let src = make_pseudo_random_buffer(2000, 19);
    for coeff in 0..=255u8 {
        for &len in TEST_LENGTHS {
            let mut dst_simd = make_pseudo_random_buffer(len, 77);
            let mut dst_scalar = dst_simd.clone();

            // SAFETY: avx2_supported() verified AVX2 is available, slice lengths match.
            unsafe {
                mul_add_avx2(coeff, &src[..len], &mut dst_simd);
            }
            gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

            assert_eq!(
                dst_simd, dst_scalar,
                "AVX2 mismatch for coeff={coeff}, len={len}"
            );
        }
    }
}

#[test]
fn test_avx512bw_matches_scalar_differential() {
    if !avx512bw_supported() {
        return;
    }

    let src = make_pseudo_random_buffer(2000, 23);
    for coeff in 0..=255u8 {
        for &len in TEST_LENGTHS {
            let mut dst_simd = make_pseudo_random_buffer(len, 89);
            let mut dst_scalar = dst_simd.clone();

            // SAFETY: avx512bw_supported() verified AVX-512BW is available, slice lengths match.
            unsafe {
                mul_add_avx512(coeff, &src[..len], &mut dst_simd);
            }
            gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

            assert_eq!(
                dst_simd, dst_scalar,
                "AVX-512BW mismatch for coeff={coeff}, len={len}"
            );
        }
    }
}

#[test]
fn test_gfni_matches_scalar_differential() {
    if !gfni_supported() {
        return;
    }

    let src = make_pseudo_random_buffer(2000, 31);
    for coeff in 0..=255u8 {
        for &len in TEST_LENGTHS {
            let mut dst_simd = make_pseudo_random_buffer(len, 101);
            let mut dst_scalar = dst_simd.clone();

            // SAFETY: gfni_supported() verified GFNI is available, slice lengths match.
            unsafe {
                mul_add_gfni(coeff, &src[..len], &mut dst_simd);
            }
            gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

            assert_eq!(
                dst_simd, dst_scalar,
                "GFNI mismatch for coeff={coeff}, len={len}"
            );
        }
    }
}

#[test]
fn test_mul_add_row_tiered_dispatch_differential() {
    let src = make_pseudo_random_buffer(2000, 37);
    for coeff in 0..=255u8 {
        for &len in TEST_LENGTHS {
            let mut dst_tiered = make_pseudo_random_buffer(len, 113);
            let mut dst_scalar = dst_tiered.clone();

            mul_add_row(coeff, &src[..len], &mut dst_tiered);
            gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

            assert_eq!(
                dst_tiered, dst_scalar,
                "Tiered mul_add_row mismatch for coeff={coeff}, len={len}"
            );
        }
    }
}

#[test]
fn test_cauchy_rs_encode_decode_roundtrip_simd() {
    let len = 1500;
    let k = 8;
    let r = 4;
    let sources: Vec<Vec<u8>> = (0..k)
        .map(|idx| make_pseudo_random_buffer(len, (idx * 13 + 7) as u8))
        .collect();

    let repairs = encode_repair(&sources, r, Scheme::Cauchy);
    assert_eq!(repairs.len(), r);
    for rep in &repairs {
        assert_eq!(rep.len(), len);
    }

    // Drop shards 1, 3, 5, 7 (4 erasures out of 12)
    // Receive shards: source 0, 2, 4, 6 and repair 0, 1, 2, 3 -> exactly 8 shards
    let received: Vec<(u16, &[u8])> = vec![
        (0, &sources[0]),
        (2, &sources[2]),
        (4, &sources[4]),
        (6, &sources[6]),
        (8, &repairs[0]),
        (9, &repairs[1]),
        (10, &repairs[2]),
        (11, &repairs[3]),
    ];

    let decoded = decode_source(k, len, &received, Scheme::Cauchy)
        .expect("Cauchy RS must decode 8 shards out of 12");
    assert_eq!(decoded, sources, "Decoded sources must match original");
}

#[test]
fn test_pq_encode_decode_roundtrip_simd() {
    let len = 1500;
    let k = 6;
    let r = 2;
    let sources: Vec<Vec<u8>> = (0..k)
        .map(|idx| make_pseudo_random_buffer(len, (idx * 23 + 11) as u8))
        .collect();

    let repairs = encode_repair(&sources, r, Scheme::Pq);
    assert_eq!(repairs.len(), 2);

    // Drop source shards 0 and 2 (2 erasures out of 8)
    // Receive source 1, 3, 4, 5 and repair P (idx 6) and Q (idx 7) -> 6 shards
    let received: Vec<(u16, &[u8])> = vec![
        (1, &sources[1]),
        (3, &sources[3]),
        (4, &sources[4]),
        (5, &sources[5]),
        (6, &repairs[0]),
        (7, &repairs[1]),
    ];

    let decoded =
        decode_source(k, len, &received, Scheme::Pq).expect("P+Q RS must recover 2 erasures");
    assert_eq!(decoded, sources, "Decoded sources must match original");
}

#[test]
fn test_wasm128_matches_scalar_differential() {
    let src = make_pseudo_random_buffer(2000, 41);
    for coeff in 0..=255u8 {
        for &len in TEST_LENGTHS {
            let mut dst_simd = make_pseudo_random_buffer(len, 127);
            let mut dst_scalar = dst_simd.clone();

            // SAFETY: Slice lengths match.
            unsafe {
                mul_add_wasm128(coeff, &src[..len], &mut dst_simd);
            }
            gf256::mul_slice_into(&mut dst_scalar, &src[..len], coeff);

            assert_eq!(
                dst_simd, dst_scalar,
                "WASM128 mismatch for coeff={coeff}, len={len}"
            );
        }
    }
}
