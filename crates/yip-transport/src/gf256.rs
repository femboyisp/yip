//! GF(2^8) arithmetic (reducing polynomial 0x11D, primitive element 2) — the
//! reusable field core for yip's Reed–Solomon FEC (and the future RLC codec).
#![forbid(unsafe_code)]

use std::sync::OnceLock;

/// Reducing polynomial x^8 + x^4 + x^3 + x^2 + 1, low 8 bits (0x11D & 0xFF).
const POLY: u8 = 0x1d;

struct Tables {
    /// EXP[i] = 2^i in GF(256); doubled to 512 so `mul` needs no modular reduction.
    exp: [u8; 512],
    /// LOG[v] = discrete log of v base 2 (LOG[0] unused).
    log: [u8; 256],
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u8 = 1;
        // `i` indexes `exp` sequentially while doubling as the stored value in
        // `log[x]`, and `x` is a running state carried across iterations — not
        // a simple element-wise map, so a range loop is clearer than an iterator.
        #[expect(
            clippy::needless_range_loop,
            reason = "sequential state machine over two arrays, not an element-wise map"
        )]
        for i in 0..255usize {
            exp[i] = x;
            log[usize::from(x)] = u8::try_from(i).expect("i < 255");
            // x *= 2  (i.e. multiply by the primitive element)
            let hi = x & 0x80;
            x <<= 1;
            if hi != 0 {
                x ^= POLY;
            }
        }
        for i in 255..512usize {
            exp[i] = exp[i - 255];
        }
        Tables { exp, log }
    })
}

/// Field addition (and subtraction) — XOR.
#[inline]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Field multiplication.
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let idx = usize::from(t.log[usize::from(a)]) + usize::from(t.log[usize::from(b)]);
    t.exp[idx] // idx <= 254+254 = 508 < 512
}

/// Multiplicative inverse. Precondition: `a != 0`.
#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "gf256::inv(0) is undefined");
    let t = tables();
    // 2^(255 - log a)
    t.exp[255 - usize::from(t.log[usize::from(a)])]
}

/// Accumulate `c * src` into `dst` (`dst[i] ^= mul(src[i], c)`). Lengths must match.
#[inline]
pub fn mul_slice_into(dst: &mut [u8], src: &[u8], c: u8) {
    debug_assert_eq!(dst.len(), src.len());
    if c == 0 {
        return;
    }
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= mul(s, c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Brute-force reference multiply over GF(2^8) with reducing poly 0x11D.
    fn ref_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1d; // 0x11D truncated to 8 bits
            }
            b >>= 1;
        }
        p
    }

    #[test]
    fn mul_matches_reference() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), ref_mul(a, b), "mul({a},{b})");
            }
        }
    }

    #[test]
    fn exp_table_is_primitive() {
        // A primitive generator visits all 255 nonzero elements before repeating.
        let mut seen = [false; 256];
        let mut x = 1u8;
        for _ in 0..255 {
            assert!(
                !seen[usize::from(x)],
                "generator not primitive: repeat at {x}"
            );
            seen[usize::from(x)] = true;
            x = mul(x, 2);
        }
        assert_eq!(x, 1, "order of 2 must be 255");
    }

    #[test]
    fn inverse_is_correct() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a*inv(a) for {a}");
        }
    }

    #[test]
    fn mul_slice_into_accumulates() {
        let src = [1u8, 2, 3, 4];
        let mut dst = [10u8, 20, 30, 40];
        mul_slice_into(&mut dst, &src, 5);
        for i in 0..4 {
            assert_eq!(dst[i], (10 * (i as u8 + 1)) ^ mul(src[i], 5));
        }
    }
}
