// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Mathematically exact systematic Reed-Solomon erasure coding over `GF(2^8)`.
//!
//! Uses a systematic Cauchy generator matrix (`I_k` stacked above `C_{m x k}`
//! with `C[i][j] = 1 / (i ^ (m + j))` in `GF(2^8)` modulo `0x11d`). Every
//! `k x k` submatrix is guaranteed invertible, allowing exact reconstruction
//! of the original payload from **any `k` surviving shards** out of `k + m`
//! drives (up to `k + m <= 256`).

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Primitive polynomial for `GF(2^8)`: `x^8 + x^4 + x^3 + x^2 + 1` (`0x11d`).
const GF_POLY: u16 = 0x11d;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ErasureError {
    #[error("invalid erasure parameters: data={data}, parity={parity}")]
    InvalidParams { data: usize, parity: usize },
    #[error("insufficient healthy shards: need at least {needed}, got {available}")]
    InsufficientShards { needed: usize, available: usize },
    #[error("shard length mismatch")]
    ShardLengthMismatch,
    #[error("singular decoding matrix")]
    SingularMatrix,
}

/// Encoded erasure shard accompanied by its SHA-256 bitrot checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedShard {
    pub index: usize,
    pub bytes: Vec<u8>,
    pub sha256_hex: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc: u8 = 0;
    while b != 0 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= (GF_POLY & 0xff) as u8;
        }
        b >>= 1;
    }
    acc
}

fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut acc: u8 = 1;
    while exp > 0 {
        if (exp & 1) != 0 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    acc
}

fn gf_inv(a: u8) -> u8 {
    assert_ne!(a, 0, "division by zero in GF(2^8)");
    // Fermat's little theorem in GF(2^8): a^(255 - 1) = a^254 = a^-1.
    gf_pow(a, 254)
}

/// Systematic generator row `row_idx` (`0..k+m`) of width `k`.
fn generator_row(row_idx: usize, k: usize, m: usize) -> Vec<u8> {
    let mut row = vec![0u8; k];
    if row_idx < k {
        row[row_idx] = 1;
    } else {
        let p = (row_idx - k) as u8;
        for (col, cell) in row.iter_mut().enumerate() {
            let y = (m + col) as u8;
            *cell = gf_inv(p ^ y);
        }
    }
    row
}

/// Invert a `k x k` matrix over `GF(2^8)` via Gauss-Jordan elimination.
fn invert_matrix(mut mat: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, ErasureError> {
    let k = mat.len();
    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }

    for col in 0..k {
        let pivot = (col..k)
            .find(|&r| mat[r][col] != 0)
            .ok_or(ErasureError::SingularMatrix)?;
        if pivot != col {
            mat.swap(col, pivot);
            inv.swap(col, pivot);
        }
        let scale = gf_inv(mat[col][col]);
        for c in 0..k {
            mat[col][c] = gf_mul(mat[col][c], scale);
            inv[col][c] = gf_mul(inv[col][c], scale);
        }
        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = mat[r][col];
            if factor == 0 {
                continue;
            }
            for c in 0..k {
                mat[r][c] ^= gf_mul(factor, mat[col][c]);
                inv[r][c] ^= gf_mul(factor, inv[col][c]);
            }
        }
    }
    Ok(inv)
}

/// Encode `payload` into `data_shards + parity_shards` erasure-coded shards.
pub fn encode(
    payload: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<EncodedShard>, ErasureError> {
    if data_shards == 0 || data_shards + parity_shards > 255 {
        return Err(ErasureError::InvalidParams {
            data: data_shards,
            parity: parity_shards,
        });
    }
    let shard_len = payload.len().div_ceil(data_shards).max(1);
    let mut data_blocks = vec![vec![0u8; shard_len]; data_shards];
    for (i, chunk) in payload.chunks(shard_len).enumerate() {
        data_blocks[i][..chunk.len()].copy_from_slice(chunk);
    }

    let total = data_shards + parity_shards;
    let mut shards = Vec::with_capacity(total);
    for idx in 0..total {
        let bytes = if idx < data_shards {
            data_blocks[idx].clone()
        } else {
            let row = generator_row(idx, data_shards, parity_shards);
            let mut parity = vec![0u8; shard_len];
            for (c, &coeff) in row.iter().enumerate() {
                if coeff == 0 {
                    continue;
                }
                for (dst, &src) in parity.iter_mut().zip(&data_blocks[c]) {
                    *dst ^= gf_mul(coeff, src);
                }
            }
            parity
        };
        let digest = sha256_hex(&bytes);
        shards.push(EncodedShard {
            index: idx,
            bytes,
            sha256_hex: digest,
        });
    }
    Ok(shards)
}

/// Reconstruct the exact original `orig_len` bytes from any `data_shards`
/// surviving `(shard_index, shard_bytes)` pairs.
pub fn reconstruct(
    available: &[(usize, Vec<u8>)],
    data_shards: usize,
    parity_shards: usize,
    orig_len: usize,
) -> Result<Vec<u8>, ErasureError> {
    if data_shards == 0 || data_shards + parity_shards > 255 {
        return Err(ErasureError::InvalidParams {
            data: data_shards,
            parity: parity_shards,
        });
    }
    if available.len() < data_shards {
        return Err(ErasureError::InsufficientShards {
            needed: data_shards,
            available: available.len(),
        });
    }
    let chosen = &available[..data_shards];
    let shard_len = chosen[0].1.len();
    if chosen.iter().any(|(_, b)| b.len() != shard_len) {
        return Err(ErasureError::ShardLengthMismatch);
    }

    let submatrix: Vec<Vec<u8>> = chosen
        .iter()
        .map(|(idx, _)| generator_row(*idx, data_shards, parity_shards))
        .collect();
    let inv = invert_matrix(submatrix)?;

    let mut out = Vec::with_capacity(data_shards * shard_len);
    for row in &inv {
        let mut block = vec![0u8; shard_len];
        for (col, &coeff) in row.iter().enumerate() {
            if coeff == 0 {
                continue;
            }
            for (dst, &src) in block.iter_mut().zip(&chosen[col].1) {
                *dst ^= gf_mul(coeff, src);
            }
        }
        out.extend_from_slice(&block);
    }
    out.truncate(orig_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs_recovers_exact_bytes_across_4x4_and_3x2_erasure_combinations() {
        let payload: Vec<u8> = (0..1337).map(|i| ((i * 37 + 13) % 251) as u8).collect();

        // 4x4: k=12, m=4 -> drop 4 data shards, recover using all 4 parity shards.
        let shards = encode(&payload, 12, 4).unwrap();
        let surviving: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .filter(|s| ![0, 3, 7, 11].contains(&s.index))
            .map(|s| (s.index, s.bytes.clone()))
            .collect();
        let recovered = reconstruct(&surviving, 12, 4, payload.len()).unwrap();
        assert_eq!(recovered, payload);

        // 3x2: k=3, m=3 -> drop ALL 3 data shards, recover solely from 3 parity shards!
        let shards3x2 = encode(&payload, 3, 3).unwrap();
        let parity_only: Vec<(usize, Vec<u8>)> = shards3x2[3..]
            .iter()
            .map(|s| (s.index, s.bytes.clone()))
            .collect();
        let recovered3x2 = reconstruct(&parity_only, 3, 3, payload.len()).unwrap();
        assert_eq!(recovered3x2, payload);
    }
}
