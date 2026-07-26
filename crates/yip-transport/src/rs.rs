//! Normative RS-v1 systematic Reed–Solomon over GF(256) (spec §3.2.1): a Cauchy
//! generator `[ I_K ; C ]` with `C[m][i] = inv((K+m) ^ i)`, giving MDS (any K of
//! K+R shards decode). Source rows are identity, so no-loss decode is a copy.
#![forbid(unsafe_code)]

use crate::gf256;

/// Generator scheme for the repair rows (packed into `payload_id[3]` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Cauchy generator (MDS for all R). Used for R >= 3.
    Cauchy,
    /// RAID-6-style P+Q (MDS for R <= 2). P = XOR all-ones, Q = 2^i syndrome.
    Pq,
}

/// Wire id for `Scheme::Cauchy`.
pub const SCHEME_CAUCHY: u8 = 0;
/// Wire id for `Scheme::Pq`.
pub const SCHEME_PQ: u8 = 1;

impl Scheme {
    /// Wire id for `payload_id[3]`.
    pub fn to_u8(self) -> u8 {
        match self {
            Scheme::Cauchy => SCHEME_CAUCHY,
            Scheme::Pq => SCHEME_PQ,
        }
    }

    /// Parse a wire id; `None` for an unknown scheme.
    pub fn from_u8(v: u8) -> Option<Scheme> {
        match v {
            SCHEME_CAUCHY => Some(Scheme::Cauchy),
            SCHEME_PQ => Some(Scheme::Pq),
            _ => None,
        }
    }
}

/// The K generator coefficients for repair row `m` under `scheme`.
/// For `Scheme::Pq`, only `m ∈ {0,1}` is valid (P, Q); callers guard higher `m`
/// (an out-of-range PQ row here yields an all-zero row, never reached in practice).
pub fn repair_row(scheme: Scheme, k: usize, m: usize) -> Vec<u8> {
    match scheme {
        Scheme::Cauchy => (0..k).map(|i| cauchy_coef(k, m, i)).collect(),
        Scheme::Pq => match m {
            0 => vec![1u8; k], // P: all ones (XOR)
            1 => {
                // Q: [2^0, 2^1, ..., 2^(k-1)] over GF(256), built incrementally.
                let mut p = 1u8;
                (0..k)
                    .map(|_| {
                        let c = p;
                        p = gf256::mul(p, 2);
                        c
                    })
                    .collect()
            }
            _ => vec![0u8; k],
        },
    }
}

/// Cauchy generator entry for repair row `m`, source column `i`, with `k` sources.
/// `C[m][i] = inv(x_m ^ y_i)` where `x_m = k + m`, `y_i = i`.
pub fn cauchy_coef(k: usize, m: usize, i: usize) -> u8 {
    let x = u8::try_from(k + m).expect("k+m < 256 (K+R <= 255)");
    let y = u8::try_from(i).expect("i < 256");
    gf256::inv(gf256::add(x, y)) // x ^ y != 0 since {y_i} and {x_m} are disjoint
}

/// Generate `r` repair shards from the `source` shards (all equal length) under `scheme`.
pub fn encode_repair(source: &[Vec<u8>], r: usize, scheme: Scheme) -> Vec<Vec<u8>> {
    let k = source.len();
    let len = source.first().map_or(0, Vec::len);
    let mut repair = vec![vec![0u8; len]; r];
    for (m, rep) in repair.iter_mut().enumerate() {
        let coefs = repair_row(scheme, k, m);
        for (src, &c) in source.iter().zip(coefs.iter()) {
            if c == 1 {
                // Pure-XOR fast path (the entire P row; Q's i=0 term).
                for (d, &s) in rep.iter_mut().zip(src.iter()) {
                    *d ^= s;
                }
            } else if c != 0 {
                gf256::mul_slice_into(rep, src, c);
            }
        }
    }
    repair
}

/// Recover the K source shards from ≥K distinct received `(symbol_index, bytes)`.
/// Returns `None` if fewer than K distinct usable shards, or (defensively) if the
/// K×K matrix is singular (never happens for valid distinct indices — MDS).
pub fn decode_source(
    k: usize,
    shard_len: usize,
    received: &[(u16, &[u8])],
    scheme: Scheme,
) -> Option<Vec<Vec<u8>>> {
    // Deduplicate by index, keep the first K distinct.
    let mut seen = [false; 256];
    let mut rows: Vec<(usize, &[u8])> = Vec::with_capacity(k);
    for &(idx, bytes) in received {
        let idx = usize::from(idx);
        if idx >= 255 || bytes.len() != shard_len || seen[idx] {
            continue;
        }
        seen[idx] = true;
        rows.push((idx, bytes));
        if rows.len() == k {
            break;
        }
    }
    if rows.len() < k {
        return None;
    }

    // Fast path: all K source shards present (indices 0..k) → systematic copy.
    if rows.iter().all(|&(idx, _)| idx < k) {
        let mut out = vec![vec![0u8; shard_len]; k];
        for &(idx, bytes) in &rows {
            out[idx].copy_from_slice(bytes);
        }
        return Some(out);
    }

    // General path: build the K×K generator submatrix M for the received rows,
    // invert it (Gauss–Jordan over GF(256)), and apply to the received shards.
    // Row for source index i (< k): unit vector e_i. Row for repair index j (>= k):
    // Cauchy row (j - k), i.e. M[row][i] = cauchy_coef(k, j-k, i).
    let mut m = vec![vec![0u8; k]; k];
    for (row, &(idx, _)) in rows.iter().enumerate() {
        if idx < k {
            m[row][idx] = 1;
        } else {
            let rm = idx - k; // repair row index (0-based)
            if scheme == Scheme::Pq && rm >= 2 {
                return None; // invalid P+Q repair row
            }
            m[row].copy_from_slice(&repair_row(scheme, k, rm));
        }
    }
    let minv = invert(&mut m)?;

    // source_i = Σ_row minv[i][row] * received_shard[row]
    let mut out = vec![vec![0u8; shard_len]; k];
    for i in 0..k {
        for (row, &(_, bytes)) in rows.iter().enumerate() {
            gf256::mul_slice_into(&mut out[i], bytes, minv[i][row]);
        }
    }
    Some(out)
}

/// Gauss–Jordan inverse of a K×K GF(256) matrix; `None` if singular.
fn invert(a: &mut [Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = a.len();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| (0..n).map(|j| u8::from(i == j)).collect())
        .collect();
    for col in 0..n {
        // find a pivot row at/below `col` with a nonzero entry in `col`
        let piv = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, piv);
        inv.swap(col, piv);
        // normalize pivot row so a[col][col] == 1
        let d = gf256::inv(a[col][col]);
        for j in 0..n {
            a[col][j] = gf256::mul(a[col][j], d);
            inv[col][j] = gf256::mul(inv[col][j], d);
        }
        // eliminate `col` from every other row
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = a[r][col];
            if f == 0 {
                continue;
            }
            for j in 0..n {
                a[r][j] ^= gf256::mul(f, a[col][j]);
                inv[r][j] ^= gf256::mul(f, inv[col][j]);
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap()))
            .collect()
    }

    #[test]
    fn repair_row_p_is_all_ones_q_is_powers_of_two() {
        assert_eq!(repair_row(Scheme::Pq, 4, 0), vec![1, 1, 1, 1]);
        // Q: 2^0,2^1,2^2,2^3 over GF(256) = 1,2,4,8
        assert_eq!(repair_row(Scheme::Pq, 4, 1), vec![1, 2, 4, 8]);
        // Cauchy row matches cauchy_coef
        let cr = repair_row(Scheme::Cauchy, 3, 0);
        assert_eq!(
            cr,
            vec![
                cauchy_coef(3, 0, 0),
                cauchy_coef(3, 0, 1),
                cauchy_coef(3, 0, 2)
            ]
        );
    }

    #[test]
    fn scheme_u8_roundtrip_and_selection() {
        assert_eq!(Scheme::from_u8(SCHEME_CAUCHY), Some(Scheme::Cauchy));
        assert_eq!(Scheme::from_u8(SCHEME_PQ), Some(Scheme::Pq));
        assert_eq!(Scheme::from_u8(9), None);
        assert_eq!(Scheme::Pq.to_u8(), SCHEME_PQ);
    }

    /// Every k-subset of the k+r shards must reconstruct, for the scheme yip uses at that R.
    #[test]
    fn exhaustive_k_of_k_plus_r_decodes_both_schemes() {
        let len = 64usize;
        let cases = [
            (Scheme::Pq, 1usize),
            (Scheme::Pq, 2usize),
            (Scheme::Cauchy, 3usize),
            (Scheme::Cauchy, 4usize),
        ];
        for (scheme, r) in cases {
            for k in 1..=8usize {
                let source: Vec<Vec<u8>> = (0..k)
                    .map(|s| shard(u8::try_from(s).unwrap() * 7 + 1, len))
                    .collect();
                let repair = encode_repair(&source, r, scheme);
                let mut all: Vec<(u16, Vec<u8>)> = Vec::new();
                for (i, s) in source.iter().enumerate() {
                    all.push((u16::try_from(i).unwrap(), s.clone()));
                }
                for (m, s) in repair.iter().enumerate() {
                    all.push((u16::try_from(k + m).unwrap(), s.clone()));
                }
                let n = all.len();
                for mask in 0u32..(1 << n) {
                    if usize::try_from(mask.count_ones()).unwrap() != k {
                        continue;
                    }
                    let recv: Vec<(u16, &[u8])> = (0..n)
                        .filter(|b| mask & (1 << b) != 0)
                        .map(|b| (all[b].0, all[b].1.as_slice()))
                        .collect();
                    let got = decode_source(k, len, &recv, scheme).unwrap_or_else(|| {
                        panic!("decode failed scheme={scheme:?} k={k} r={r} mask={mask:b}")
                    });
                    assert_eq!(got, source, "scheme={scheme:?} k={k} r={r} mask={mask:b}");
                }
            }
        }
    }

    /// P+Q must recover ANY two erasures at k=4,r=2 (the RAID-6 property).
    #[test]
    fn pq_recovers_every_two_erasures() {
        let len = 48usize;
        let k = 4usize;
        let source: Vec<Vec<u8>> = (0..k)
            .map(|s| shard(u8::try_from(s).unwrap() + 9, len))
            .collect();
        let repair = encode_repair(&source, 2, Scheme::Pq);
        let mut all: Vec<(u16, Vec<u8>)> = Vec::new();
        for (i, s) in source.iter().enumerate() {
            all.push((u16::try_from(i).unwrap(), s.clone()));
        }
        for (m, s) in repair.iter().enumerate() {
            all.push((u16::try_from(k + m).unwrap(), s.clone()));
        }
        let n = all.len(); // k+2 = 6
        for a in 0..n {
            for b in (a + 1)..n {
                let recv: Vec<(u16, &[u8])> = (0..n)
                    .filter(|&x| x != a && x != b)
                    .map(|x| (all[x].0, all[x].1.as_slice()))
                    .collect();
                let got = decode_source(k, len, &recv, Scheme::Pq).expect("k of k+2 decodes");
                assert_eq!(got, source, "erased {a},{b}");
            }
        }
    }

    /// An out-of-range index (>= 256) in `received` must be silently ignored,
    /// never cause an out-of-bounds `seen[idx]` panic. Kills the `replace ||
    /// with && in decode_source` mutant at the first `||` (idx>=255 with
    /// bytes.len()!=shard_len): under `&&`, an out-of-range idx with a
    /// correctly-sized shard no longer short-circuits, and falls through to
    /// `seen[idx]` with idx >= 256, indexing past the 256-entry array.
    #[test]
    fn decode_source_ignores_out_of_range_index_without_panic() {
        let len = 8;
        let bogus = vec![0u8; len]; // correct length, but idx way out of range
        let received: Vec<(u16, &[u8])> = vec![(1000u16, bogus.as_slice())];
        assert_eq!(
            decode_source(2, len, &received, Scheme::Cauchy),
            None,
            "out-of-range index must be ignored (not enough valid shards), not panic"
        );
    }

    /// A true duplicate index (same idx submitted twice) must be deduplicated
    /// — first occurrence wins, and a later genuinely-distinct index must
    /// still be collected. Kills the `replace || with && in decode_source`
    /// mutant at the second `||` (... || seen[idx]): under `&&`, an
    /// already-seen index is no longer skipped, so a duplicate silently
    /// overwrites data and crowds out a real, distinct shard.
    #[test]
    fn decode_source_skips_true_duplicate_indices_not_just_high_ones() {
        let len = 4;
        let data_a = vec![0xAAu8; len]; // first occurrence of idx 0 -> must win
        let data_b = vec![0xBBu8; len]; // duplicate idx 0 -> must be ignored
        let data_c = vec![0xCCu8; len]; // genuine idx 1 -> must be collected
        let received: Vec<(u16, &[u8])> = vec![
            (0u16, data_a.as_slice()),
            (0u16, data_b.as_slice()),
            (1u16, data_c.as_slice()),
        ];
        let got = decode_source(2, len, &received, Scheme::Cauchy)
            .expect("first-occurrence dedup + one genuine shard decodes k=2");
        assert_eq!(
            got[0], data_a,
            "first occurrence of idx 0 must win over a later duplicate"
        );
        assert_eq!(
            got[1], data_c,
            "genuine idx 1 must be collected, not crowded out by a duplicate"
        );
    }

    /// Fewer than K distinct shards must be rejected even when every provided
    /// index happens to be < K (which would otherwise silently qualify for
    /// the systematic fast-path copy and fabricate the missing shard(s) as
    /// zero bytes). Kills the `replace < with > in decode_source` mutant
    /// (line 117): `rows.len()` can never exceed `k` by construction (the
    /// collection loop breaks at exactly `k`), so `rows.len() > k` is always
    /// false — under that mutant the "not enough shards" guard never fires.
    #[test]
    fn decode_source_rejects_fewer_than_k_shards_even_via_fast_path() {
        let len = 4;
        let data = vec![0x11u8; len];
        let received: Vec<(u16, &[u8])> = vec![(0u16, data.as_slice())]; // only 1 of 2 needed
        assert_eq!(
            decode_source(2, len, &received, Scheme::Cauchy),
            None,
            "fewer than K shards must be rejected, not silently zero-filled \
             via the idx<K fast path"
        );
    }

    /// A SCHEME_PQ repair index with m>=2 is invalid → decode returns None (no panic).
    #[test]
    fn pq_rejects_repair_row_ge_2() {
        let len = 16usize;
        let k = 2usize;
        let source: Vec<Vec<u8>> = (0..k)
            .map(|s| shard(u8::try_from(s).unwrap() + 1, len))
            .collect();
        // Fabricate: 1 real source (idx 0) + a bogus repair at index k+2 (m=2), scheme Pq.
        let bogus = vec![0u8; len];
        let recv: Vec<(u16, &[u8])> = vec![
            (0u16, source[0].as_slice()),
            (u16::try_from(k + 2).unwrap(), bogus.as_slice()),
        ];
        assert_eq!(decode_source(k, len, &recv, Scheme::Pq), None);
    }
}
