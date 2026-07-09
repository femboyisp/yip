//! Normative RS-v1 systematic Reed–Solomon over GF(256) (spec §3.2.1): a Cauchy
//! generator `[ I_K ; C ]` with `C[m][i] = inv((K+m) ^ i)`, giving MDS (any K of
//! K+R shards decode). Source rows are identity, so no-loss decode is a copy.
#![forbid(unsafe_code)]

use crate::gf256;

/// Cauchy generator entry for repair row `m`, source column `i`, with `k` sources.
/// `C[m][i] = inv(x_m ^ y_i)` where `x_m = k + m`, `y_i = i`.
pub fn cauchy_coef(k: usize, m: usize, i: usize) -> u8 {
    let x = u8::try_from(k + m).expect("k+m < 256 (K+R <= 255)");
    let y = u8::try_from(i).expect("i < 256");
    gf256::inv(gf256::add(x, y)) // x ^ y != 0 since {y_i} and {x_m} are disjoint
}

/// Generate `r` repair shards from the `source` shards (all equal length).
pub fn encode_repair(source: &[Vec<u8>], r: usize) -> Vec<Vec<u8>> {
    let k = source.len();
    let len = source.first().map_or(0, Vec::len);
    let mut repair = vec![vec![0u8; len]; r];
    for (m, rep) in repair.iter_mut().enumerate() {
        for (i, src) in source.iter().enumerate() {
            gf256::mul_slice_into(rep, src, cauchy_coef(k, m, i));
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
            for (i, cell) in m[row].iter_mut().enumerate() {
                *cell = cauchy_coef(k, idx - k, i);
            }
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

    /// Every k-subset of the k+r shards must reconstruct the source (MDS).
    #[test]
    fn exhaustive_k_of_k_plus_r_decodes() {
        let len = 64usize;
        for k in 1..=8usize {
            for r in 1..=4usize {
                let source: Vec<Vec<u8>> = (0..k)
                    .map(|s| shard(u8::try_from(s).unwrap() * 7 + 1, len))
                    .collect();
                let repair = encode_repair(&source, r);
                // all shards indexed 0..k (source) then k..k+r (repair)
                let mut all: Vec<(u16, Vec<u8>)> = Vec::new();
                for (i, s) in source.iter().enumerate() {
                    all.push((u16::try_from(i).unwrap(), s.clone()));
                }
                for (m, s) in repair.iter().enumerate() {
                    all.push((u16::try_from(k + m).unwrap(), s.clone()));
                }
                // every combination of exactly k of the k+r shards
                let n = all.len();
                for mask in 0u32..(1 << n) {
                    if usize::try_from(mask.count_ones()).unwrap() != k {
                        continue;
                    }
                    let recv: Vec<(u16, &[u8])> = (0..n)
                        .filter(|b| mask & (1 << b) != 0)
                        .map(|b| (all[b].0, all[b].1.as_slice()))
                        .collect();
                    let got = decode_source(k, len, &recv)
                        .unwrap_or_else(|| panic!("decode failed k={k} r={r} mask={mask:b}"));
                    assert_eq!(got, source, "k={k} r={r} mask={mask:b}");
                }
            }
        }
    }

    /// Independent-implementation agreement: reed-solomon-erasure recovers the
    /// same erasure scenarios (recovery success, not byte-identity — matrices differ).
    #[test]
    fn reed_solomon_erasure_oracle_agrees() {
        use reed_solomon_erasure::galois_8::ReedSolomon;
        let len = 32usize;
        for (k, r) in [(2usize, 2usize), (3, 2), (4, 1)] {
            let source: Vec<Vec<u8>> = (0..k)
                .map(|s| shard(u8::try_from(s).unwrap() + 3, len))
                .collect();
            let rse = ReedSolomon::new(k, r).unwrap();
            let mut shards: Vec<Vec<u8>> = source.clone();
            shards.extend(std::iter::repeat_n(vec![0u8; len], r));
            rse.encode(&mut shards).unwrap();
            // erase the first source shard; reed-solomon-erasure must recover it
            let mut opt: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            opt[0] = None;
            rse.reconstruct(&mut opt).unwrap();
            assert_eq!(
                opt[0].as_ref().unwrap(),
                &source[0],
                "oracle recovers k={k} r={r}"
            );
        }
    }
}
