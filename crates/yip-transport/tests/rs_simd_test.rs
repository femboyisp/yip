use yip_transport::rs::test_mul_add_row_differential;

#[test]
fn test_rs_simd_matches_scalar_across_all_coefficients_and_lengths() {
    let mut src = vec![0u8; 1500];
    for (i, byte) in src.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    for coeff in 0..=255u8 {
        for len in [0, 1, 15, 16, 31, 32, 63, 64, 128, 512, 1280, 1500] {
            test_mul_add_row_differential(coeff, &src[..len]);
        }
    }
}
