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

//! FoundationDB-style two-stage deterministic `Buggify` fault injector.
//!
//! Stage 1 (per-seed activation): each named fault site is deterministically
//! activated or silenced once per seed (`activation_prob`, default 0.25), so
//! every seed explores a different subset of rare edge cases without collapsing
//! into permanent failure.
//!
//! Stage 2 (per-call firing): whenever execution reaches an active site, it
//! fires with probability `fire_prob` drawn from the seed's deterministic RNG.

use rustfs_dst_runtime::rng::{RngSource, SimRng};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct SiteState {
    active: bool,
    rng: SimRng,
    fired: u64,
}

#[derive(Debug)]
struct BuggifyInner {
    seed: u64,
    activation_prob: f64,
    sites: BTreeMap<String, SiteState>,
}

/// Deterministic two-stage fault injector modeled on FoundationDB's `BUGGIFY`.
#[derive(Clone, Debug)]
pub struct Buggify {
    enabled: Arc<AtomicBool>,
    inner: Arc<Mutex<BuggifyInner>>,
}

impl Buggify {
    /// Create a disabled no-op `Buggify` instance (fast atomic path).
    pub fn disabled() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            inner: Arc::new(Mutex::new(BuggifyInner {
                seed: 0,
                activation_prob: 0.0,
                sites: BTreeMap::new(),
            })),
        }
    }

    /// Create an enabled `Buggify` injector seeded with `seed`.
    pub fn seeded(seed: u64, activation_prob: f64) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(true)),
            inner: Arc::new(Mutex::new(BuggifyInner {
                seed,
                activation_prob: activation_prob.clamp(0.0, 1.0),
                sites: BTreeMap::new(),
            })),
        }
    }

    /// Dynamically enable or disable buggification.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Evaluate a named buggify point with default firing probability `0.05`.
    pub fn should_fire(&self, site: &str) -> bool {
        self.should_fire_with_prob(site, 0.05)
    }

    /// Evaluate a named buggify point with explicit stage-2 firing probability.
    pub fn should_fire_with_prob(&self, site: &str, fire_prob: f64) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }
        let mut inner = self.inner.lock().expect("Buggify lock poisoned");
        if !inner.sites.contains_key(site) {
            let active = deterministic_activation(inner.seed, site, inner.activation_prob);
            // Per-site sub-stream: firing one site must not shift another site's
            // sequence when a new buggify point is added.
            let rng = SimRng::from_seed(inner.seed).fork(&format!("buggify:{site}"));
            inner.sites.insert(
                site.to_string(),
                SiteState {
                    active,
                    rng,
                    fired: 0,
                },
            );
        }
        let state = inner.sites.get_mut(site).expect("buggify site");
        if !state.active {
            return false;
        }
        let fired = state.rng.gen_bool(fire_prob);
        if fired {
            state.fired += 1;
        }
        fired
    }

    /// Return a map of how many times each buggify site fired during this run.
    pub fn fired_counts(&self) -> BTreeMap<String, u64> {
        self.inner
            .lock()
            .expect("Buggify lock poisoned")
            .sites
            .iter()
            .filter(|(_, state)| state.fired > 0)
            .map(|(site, state)| (site.clone(), state.fired))
            .collect()
    }
}

fn deterministic_activation(seed: u64, site: &str, activation_prob: f64) -> bool {
    if activation_prob <= 0.0 {
        return false;
    }
    if activation_prob >= 1.0 {
        return true;
    }
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(b"::buggify::");
    hasher.update(site.as_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_le_bytes(digest[..8].try_into().unwrap());
    let sample = ((raw >> 11) as f64) / ((1u64 << 53) as f64);
    sample < activation_prob
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buggify_is_deterministic_for_identical_seeds() {
        let b1 = Buggify::seeded(12345, 0.5);
        let b2 = Buggify::seeded(12345, 0.5);

        let seq1: Vec<bool> = (0..50)
            .map(|i| b1.should_fire_with_prob(&format!("site_{}", i % 5), 0.3))
            .collect();
        let seq2: Vec<bool> = (0..50)
            .map(|i| b2.should_fire_with_prob(&format!("site_{}", i % 5), 0.3))
            .collect();
        assert_eq!(seq1, seq2);
    }

    #[test]
    fn buggify_sites_do_not_perturb_each_other() {
        let exercised = Buggify::seeded(99, 1.0);
        let control = Buggify::seeded(99, 1.0);
        for _ in 0..20 {
            let _ = exercised.should_fire_with_prob("ecstore.skip_tmp_cleanup", 0.5);
        }
        let from_exercised: Vec<bool> = (0..30)
            .map(|_| exercised.should_fire_with_prob("ecstore.other_site", 0.4))
            .collect();
        let from_control: Vec<bool> = (0..30)
            .map(|_| control.should_fire_with_prob("ecstore.other_site", 0.4))
            .collect();
        assert_eq!(from_exercised, from_control);
    }

    #[test]
    fn disabled_buggify_never_fires() {
        let b = Buggify::disabled();
        for _ in 0..100 {
            assert!(!b.should_fire_with_prob("always_never", 1.0));
        }
    }
}
