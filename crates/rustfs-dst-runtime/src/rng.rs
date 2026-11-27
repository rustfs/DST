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

//! Deterministic and production randomness abstractions for RustFS.
//!
//! All UUID generation (version IDs, upload IDs, lock tokens, temp paths),
//! jittered backoff delays, and shard selection randomness in RustFS should
//! flow through [`RngSource`] so that replaying a seed produces bit-identical
//! IDs and schedules.

use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Unified randomness source replacing `rand::rng()` and `Uuid::new_v4()`.
pub trait RngSource: Send + Sync + std::fmt::Debug {
    /// Produce the next pseudo-random `u64`.
    fn next_u64(&self) -> u64;

    /// Fill `dest` with random bytes.
    fn fill_bytes(&self, dest: &mut [u8]);

    /// Generate a uniform random `usize` in `0..upper`.
    ///
    /// # Panics
    /// Panics if `upper == 0`.
    fn gen_range_usize(&self, upper: usize) -> usize {
        assert!(upper > 0, "upper bound must be > 0");
        let bound = upper as u64;
        // Rejection sampling to avoid modulo bias while remaining deterministic.
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let v = self.next_u64();
            if v < zone {
                return (v % bound) as usize;
            }
        }
    }

    /// Return `true` with probability `prob` in `[0.0, 1.0]`.
    fn gen_bool(&self, prob: f64) -> bool {
        if prob <= 0.0 {
            return false;
        }
        if prob >= 1.0 {
            return true;
        }
        // Use 53 bits of precision matching IEEE-754 f64 significand.
        let bits = self.next_u64() >> 11;
        let sample = (bits as f64) / ((1u64 << 53) as f64);
        sample < prob
    }

    /// Generate an RFC 4122 version-4 UUID deterministically when backed by [`SimRng`].
    fn gen_uuid_v4(&self) -> Uuid {
        let mut bytes = [0u8; 16];
        self.fill_bytes(&mut bytes);
        // Set version 4 and RFC 4122 variant bits.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }
}

/// Production [`RngSource`] backed by OS/thread randomness.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealRng;

impl RngSource for RealRng {
    fn next_u64(&self) -> u64 {
        rand::rng().random::<u64>()
    }

    fn fill_bytes(&self, dest: &mut [u8]) {
        rand::rng().fill_bytes(dest);
    }
}

/// Deterministic seeded [`RngSource`] backed by ChaCha8 with domain-separated
/// sub-stream forking.
#[derive(Clone, Debug)]
pub struct SimRng {
    seed: u64,
    inner: Arc<Mutex<ChaCha8Rng>>,
}

impl SimRng {
    /// Create a new deterministic RNG from a 64-bit simulation seed.
    pub fn from_seed(seed: u64) -> Self {
        Self {
            seed,
            inner: Arc::new(Mutex::new(ChaCha8Rng::seed_from_u64(seed))),
        }
    }

    /// Return the root seed used to initialize this RNG.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Derive an independent deterministic sub-stream for a named subsystem or
    /// node (e.g., `"node:n1"`, `"nemesis:network"`, `"workload:client-0"`).
    ///
    /// Forking uses SHA-256 domain separation over `(self.seed, label)` so that
    /// adding or reordering operations in one subsystem does not perturb
    /// unrelated sub-streams.
    pub fn fork(&self, label: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(self.seed.to_le_bytes());
        hasher.update(b"::");
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        let mut child_seed_bytes = [0u8; 32];
        child_seed_bytes.copy_from_slice(&digest);
        let child_seed_u64 = u64::from_le_bytes(child_seed_bytes[..8].try_into().unwrap());
        Self {
            seed: child_seed_u64,
            inner: Arc::new(Mutex::new(ChaCha8Rng::from_seed(child_seed_bytes))),
        }
    }
}

impl RngSource for SimRng {
    fn next_u64(&self) -> u64 {
        let mut guard = self.inner.lock().expect("SimRng lock poisoned");
        guard.next_u64()
    }

    fn fill_bytes(&self, dest: &mut [u8]) {
        let mut guard = self.inner.lock().expect("SimRng lock poisoned");
        guard.fill_bytes(dest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_rng_replays_identically_and_isolates_forks() {
        let r1 = SimRng::from_seed(42);
        let r2 = SimRng::from_seed(42);

        let f1a = r1.fork("ecstore:n1");
        let f1b = r1.fork("nemesis");
        let f2b = r2.fork("nemesis");
        let f2a = r2.fork("ecstore:n1");

        // Advance f1b before reading f1a; f1a must still match f2a identically.
        let _ = f1b.next_u64();
        assert_eq!(f1a.gen_uuid_v4(), f2a.gen_uuid_v4());
        assert_eq!(f1a.next_u64(), f2a.next_u64());
        let _ = f2b.next_u64();
        assert_eq!(f1b.next_u64(), f2b.next_u64());
    }
}
