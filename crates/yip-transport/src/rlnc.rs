//! Rateless Random Linear Network Coding (RLNC) over GF(2^8).
//!
//! Implements rateless encoding with deterministic coefficient generation
//! and incremental Gaussian elimination decoding over GF(2^8).

use crate::gf256;
use crate::rs::mul_add_row;

/// SplitMix32 pseudorandom generator for deterministic coefficient generation.
#[inline]
fn splitmix32(state: &mut u32) -> u32 {
    *state = state.wrapping_add(0x9e3779b9);
    let mut z = *state;
    z = (z ^ (z >> 16)).wrapping_mul(0x85ebca6b);
    z = (z ^ (z >> 13)).wrapping_mul(0xc2b2ae35);
    z ^ (z >> 16)
}

/// Scale all bytes in `row` in-place by GF(2^8) scalar `c`.
pub fn scale_row(c: u8, row: &mut [u8]) {
    if c == 1 {
        return;
    }
    if c == 0 {
        row.fill(0);
        return;
    }
    for byte in row.iter_mut() {
        *byte = gf256::mul(c, *byte);
    }
}

/// RLNC encoder over GF(2^8).
#[derive(Debug, Clone)]
pub struct RlncEncoder {
    window_size: usize,
    symbols: Vec<Vec<u8>>,
    symbol_len: usize,
}

impl RlncEncoder {
    /// Create a new RLNC encoder for a coding window of `window_size` source symbols.
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            symbols: Vec::with_capacity(window_size),
            symbol_len: 0,
        }
    }

    /// Returns the window size configured for this encoder.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Returns the number of source symbols currently pushed into the encoder.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns true if no source symbols have been pushed.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Push a source symbol into the coding window.
    ///
    /// # Panics
    ///
    /// Panics if more than `window_size` symbols are pushed, or if subsequent symbols
    /// differ in length from the first pushed symbol.
    pub fn push_source(&mut self, symbol: &[u8]) {
        assert!(
            self.symbols.len() < self.window_size,
            "cannot push more than window_size symbols"
        );
        if self.symbols.is_empty() {
            self.symbol_len = symbol.len();
        } else {
            assert_eq!(
                symbol.len(),
                self.symbol_len,
                "all source symbols must have identical length"
            );
        }
        self.symbols.push(symbol.to_vec());
    }

    /// Produce a coded symbol from a deterministic `seed`.
    ///
    /// Returns `(coeffs, coded_symbol)`, where `coeffs` has length `window_size`
    /// and contains the GF(2^8) linear combination coefficients, and `coded_symbol`
    /// contains the combined payload.
    ///
    /// Guarantees that the generated coefficients over active source symbols are not all zero.
    pub fn produce_coded_symbol(&self, seed: u32) -> (Vec<u8>, Vec<u8>) {
        let n = self.symbols.len();
        if n == 0 {
            return (vec![0u8; self.window_size], vec![0u8; self.symbol_len]);
        }

        let mut s = seed;
        let mut coeffs = vec![0u8; self.window_size];

        // Draw coefficients until at least one non-zero coefficient is drawn.
        loop {
            let mut all_zero = true;
            for i in (0..n).step_by(4) {
                let rand_val = splitmix32(&mut s);
                let bytes = rand_val.to_le_bytes();
                for j in 0..4 {
                    if i + j < n {
                        coeffs[i + j] = bytes[j];
                        if bytes[j] != 0 {
                            all_zero = false;
                        }
                    }
                }
            }
            if !all_zero {
                break;
            }
        }

        let mut coded = vec![0u8; self.symbol_len];
        for (i, sym) in self.symbols.iter().enumerate() {
            let coeff = coeffs[i];
            if coeff != 0 {
                mul_add_row(coeff, sym, &mut coded);
            }
        }

        (coeffs, coded)
    }
}

/// RLNC decoder performing incremental Gaussian elimination over GF(2^8).
#[derive(Debug, Clone)]
pub struct RlncDecoder {
    window_size: usize,
    symbol_len: usize,
    echelon: Vec<Vec<u8>>,
    coeff_matrix: Vec<Vec<u8>>,
    has_row: Vec<bool>,
    rank: usize,
}

impl RlncDecoder {
    /// Create a new RLNC decoder expecting `window_size` symbols of length `symbol_len`.
    pub fn new(window_size: usize, symbol_len: usize) -> Self {
        Self {
            window_size,
            symbol_len,
            echelon: vec![vec![0u8; symbol_len]; window_size],
            coeff_matrix: vec![vec![0u8; window_size]; window_size],
            has_row: vec![false; window_size],
            rank: 0,
        }
    }

    /// Returns the window size configured for this decoder.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Returns the expected symbol length in bytes.
    pub fn symbol_len(&self) -> usize {
        self.symbol_len
    }

    /// Current matrix rank (number of linearly independent symbols received).
    pub fn rank(&self) -> usize {
        self.rank
    }

    /// Returns true if full rank is achieved (`rank == window_size`).
    pub fn is_complete(&self) -> bool {
        self.rank == self.window_size
    }

    /// Consume a received coded symbol and its coefficient vector.
    ///
    /// Performs incremental Gaussian elimination over GF(2^8).
    /// Returns `true` if the symbol was linearly independent and increased the rank,
    /// or `false` if the symbol was linearly dependent (redundant), malformed, or
    /// if the decoder is already complete.
    pub fn consume_coded_symbol(&mut self, coeffs: &[u8], coded: &[u8]) -> bool {
        if self.is_complete() {
            return false;
        }
        if coeffs.len() != self.window_size || coded.len() != self.symbol_len {
            return false;
        }

        let mut cur_coeffs = coeffs.to_vec();
        let mut cur_coded = coded.to_vec();

        for col in 0..self.window_size {
            let c = cur_coeffs[col];
            if c == 0 {
                continue;
            }

            if self.has_row[col] {
                // Eliminate coefficient cur_coeffs[col] using normalized pivot row `col`.
                cur_coeffs[col] = 0;
                for (target, &p_coeff) in cur_coeffs[(col + 1)..self.window_size]
                    .iter_mut()
                    .zip(&self.coeff_matrix[col][(col + 1)..self.window_size])
                {
                    if p_coeff != 0 {
                        *target ^= gf256::mul(c, p_coeff);
                    }
                }
                mul_add_row(c, &self.echelon[col], &mut cur_coded);
            } else {
                // Found a new pivot in column `col`. Normalize row so cur_coeffs[col] == 1.
                let inv = gf256::inv(c);
                cur_coeffs[col] = 1;
                for coeff in &mut cur_coeffs[(col + 1)..self.window_size] {
                    *coeff = gf256::mul(*coeff, inv);
                }
                scale_row(inv, &mut cur_coded);

                self.coeff_matrix[col] = cur_coeffs;
                self.echelon[col] = cur_coded;
                self.has_row[col] = true;
                self.rank += 1;
                return true;
            }
        }

        // Vector eliminated to zero: linearly dependent.
        false
    }

    /// Extract the original source symbols by back-substitution into the identity matrix $I$.
    ///
    /// Returns `Some(symbols)` if the decoder is complete (`rank == window_size`),
    /// or `None` if full rank has not yet been reached.
    pub fn extract_source_symbols(&self) -> Option<Vec<Vec<u8>>> {
        if !self.is_complete() {
            return None;
        }

        let mut symbols = vec![vec![0u8; self.symbol_len]; self.window_size];

        for i in (0..self.window_size).rev() {
            let mut s = self.echelon[i].clone();
            for (sym, &f) in symbols[(i + 1)..self.window_size]
                .iter()
                .zip(&self.coeff_matrix[i][(i + 1)..self.window_size])
            {
                if f != 0 {
                    mul_add_row(f, sym, &mut s);
                }
            }
            symbols[i] = s;
        }

        Some(symbols)
    }
}
