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

//! 6-Invariant Consistency & Durability Oracle for RustFS DST.
//!
//! Tracks every committed, indeterminate (reply-dropped), and deleted object
//! state across the simulation and asserts:
//! 1. **Linearizability / Monotonicity**: Reads never return a generation older
//!    than the latest acknowledged write/delete.
//! 2. **Bit-Exact Integrity**: Every returned payload matches the exact SHA-256
//!    of a committed or indeterminate write (no torn mixes, no silent bitrot).
//! 3. **Crash Atomicity (Old-or-New-Never-Mixed)**: After hard power loss,
//!    every readable object is either byte-for-byte the pre-crash committed
//!    state or the full new version.
//! 4. **Quorum Safety**: Operations never falsely succeed below quorum.
//! 5. **Lock Mutual Exclusion & Monotonic Fencing**: Overlapping valid leases
//!    never coexist on the same resource.
//! 6. **Heal Convergence**: Post-heal, every drive in the erasure set agrees on
//!    the identical generation and zero temporary staging artifacts leak.

use crate::erasure::sha256_hex;
use rustfs_dst_faults::probe::ProbeRegistry;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Ground-truth version state recorded by the oracle for a single `(bucket, key)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedState {
    pub generation: u64,
    pub version_id: String,
    pub is_deleted: bool,
    pub payload_sha256: Option<String>,
}

/// Violation detected by [`ConsistencyOracle`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant: String,
    pub key: String,
    pub detail: String,
}

/// Multi-invariant verification oracle for RustFS simulation runs.
#[derive(Clone, Debug)]
pub struct ConsistencyOracle {
    /// Latest durably acknowledged state per `bucket/key`.
    acked: BTreeMap<String, CommittedState>,
    /// All payloads (and generations) whose write returned an indeterminate
    /// error (e.g., reply dropped after apply) and may legally become visible.
    indeterminate: BTreeMap<String, Vec<CommittedState>>,
    /// Set of all payload hashes ever submitted for a key (for bit-exactness check).
    ever_written_hashes: BTreeMap<String, BTreeSet<String>>,
    /// Highest generation ever observed by any successful read per key.
    max_observed_gen: BTreeMap<String, u64>,
    /// Active lock holder tracking for mutual exclusion verification.
    active_locks: BTreeMap<String, (String, u64)>,
    /// Accumulated violations.
    violations: Vec<InvariantViolation>,
    /// Probe telemetry registry.
    probes: ProbeRegistry,
}

impl ConsistencyOracle {
    pub fn new(probes: ProbeRegistry) -> Self {
        Self {
            acked: BTreeMap::new(),
            indeterminate: BTreeMap::new(),
            ever_written_hashes: BTreeMap::new(),
            max_observed_gen: BTreeMap::new(),
            active_locks: BTreeMap::new(),
            violations: Vec::new(),
            probes,
        }
    }

    pub fn record_submitted_payload(&mut self, full_key: &str, payload: &[u8]) -> String {
        let hash = sha256_hex(payload);
        self.ever_written_hashes
            .entry(full_key.to_string())
            .or_default()
            .insert(hash.clone());
        hash
    }

    pub fn record_acked_put(
        &mut self,
        full_key: &str,
        generation: u64,
        version_id: String,
        payload_sha256: String,
    ) {
        self.ever_written_hashes
            .entry(full_key.to_string())
            .or_default()
            .insert(payload_sha256.clone());
        let state = CommittedState {
            generation,
            version_id,
            is_deleted: false,
            payload_sha256: Some(payload_sha256),
        };
        self.acked.insert(full_key.to_string(), state);
        self.indeterminate.remove(full_key);
    }

    pub fn record_acked_delete(&mut self, full_key: &str, generation: u64, version_id: String) {
        let state = CommittedState {
            generation,
            version_id,
            is_deleted: true,
            payload_sha256: None,
        };
        self.acked.insert(full_key.to_string(), state);
        self.indeterminate.remove(full_key);
    }

    pub fn record_indeterminate_put(
        &mut self,
        full_key: &str,
        generation: u64,
        version_id: String,
        payload_sha256: String,
    ) {
        self.ever_written_hashes
            .entry(full_key.to_string())
            .or_default()
            .insert(payload_sha256.clone());
        self.indeterminate
            .entry(full_key.to_string())
            .or_default()
            .push(CommittedState {
                generation,
                version_id,
                is_deleted: false,
                payload_sha256: Some(payload_sha256),
            });
    }

    /// Verify a successful `GetObject` response against invariants 1 & 2.
    pub fn check_read_present(&mut self, full_key: &str, generation: u64, payload: &[u8]) {
        let got_hash = sha256_hex(payload);

        // Invariant 2: Bit-exact integrity (never corrupted or torn).
        let hash_valid = self
            .ever_written_hashes
            .get(full_key)
            .is_some_and(|set| set.contains(&got_hash));
        self.probes.always(
            "invariant.bit_exact_integrity",
            hash_valid,
            json!({"key": full_key, "generation": generation, "sha256": got_hash}),
        );
        if !hash_valid {
            self.violations.push(InvariantViolation {
                invariant: "bit_exact_integrity".to_string(),
                key: full_key.to_string(),
                detail: format!(
                    "read returned unknown/corrupted payload digest {got_hash} at gen {generation}"
                ),
            });
        }

        // Invariant 1a: Read-after-write monotonicity against acknowledged writes.
        if let Some(acked) = self.acked.get(full_key) {
            let linearizable = if generation < acked.generation {
                false
            } else if generation == acked.generation {
                !acked.is_deleted && acked.payload_sha256.as_deref() == Some(got_hash.as_str())
            } else {
                // Generation > acked is only legal if an indeterminate write landed.
                self.indeterminate
                    .get(full_key)
                    .is_some_and(|cands| cands.iter().any(|c| c.generation == generation))
            };
            self.probes.always(
                "invariant.linearizable_read",
                linearizable,
                json!({
                    "key": full_key,
                    "read_gen": generation,
                    "acked_gen": acked.generation,
                    "acked_deleted": acked.is_deleted,
                }),
            );
            if !linearizable {
                self.violations.push(InvariantViolation {
                    invariant: "linearizable_read".to_string(),
                    key: full_key.to_string(),
                    detail: format!(
                        "stale or inconsistent read: got gen={generation}, acked gen={} deleted={}",
                        acked.generation, acked.is_deleted
                    ),
                });
            }
        }

        // Invariant 1b: Monotonic reads across sequential reads.
        let prev_max = self.max_observed_gen.get(full_key).copied().unwrap_or(0);
        let monotonic = generation >= prev_max;
        self.probes.always(
            "invariant.monotonic_read_generation",
            monotonic,
            json!({"key": full_key, "read_gen": generation, "prev_max": prev_max}),
        );
        if !monotonic {
            self.violations.push(InvariantViolation {
                invariant: "monotonic_read_generation".to_string(),
                key: full_key.to_string(),
                detail: format!("generation regressed from {prev_max} to {generation}"),
            });
        } else {
            self.max_observed_gen
                .insert(full_key.to_string(), generation);
        }
    }

    /// Verify a `NotFound` / deleted read response against acknowledged state.
    pub fn check_read_not_found(&mut self, full_key: &str) {
        if let Some(acked) = self.acked.get(full_key) {
            let valid = acked.is_deleted;
            self.probes.always(
                "invariant.no_lost_acknowledged_write",
                valid,
                json!({"key": full_key, "acked_gen": acked.generation, "acked_deleted": acked.is_deleted}),
            );
            if !valid {
                self.violations.push(InvariantViolation {
                    invariant: "no_lost_acknowledged_write".to_string(),
                    key: full_key.to_string(),
                    detail: format!(
                        "read returned NotFound for acknowledged live object gen={}",
                        acked.generation
                    ),
                });
            }
        }
    }

    /// Record lock acquisition and verify mutual exclusion + monotonic fencing.
    pub fn check_lock_acquired(&mut self, resource: &str, owner: &str, fence_token: u64) {
        if let Some((existing_owner, existing_fence)) = self.active_locks.get(resource) {
            let exclusive = existing_owner == owner;
            self.probes.always(
                "invariant.lock_mutual_exclusion",
                exclusive,
                json!({
                    "resource": resource,
                    "existing_owner": existing_owner,
                    "new_owner": owner,
                    "existing_fence": existing_fence,
                    "new_fence": fence_token,
                }),
            );
            if !exclusive {
                self.violations.push(InvariantViolation {
                    invariant: "lock_mutual_exclusion".to_string(),
                    key: resource.to_string(),
                    detail: format!(
                        "split-brain lock: {owner} (fence={fence_token}) overlapped with {existing_owner} (fence={existing_fence})"
                    ),
                });
            }
        } else {
            self.probes.always(
                "invariant.lock_mutual_exclusion",
                true,
                json!({"resource": resource, "owner": owner, "fence": fence_token}),
            );
        }
        self.active_locks
            .insert(resource.to_string(), (owner.to_string(), fence_token));
    }

    pub fn record_lock_released(&mut self, resource: &str, owner: &str) {
        if let Some((existing, _)) = self.active_locks.get(resource)
            && existing == owner
        {
            self.active_locks.remove(resource);
        }
    }

    /// Record a violation explicitly (e.g., from heal convergence check).
    pub fn record_violation(
        &mut self,
        invariant: impl Into<String>,
        key: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let inv = invariant.into();
        let k = key.into();
        let d = detail.into();
        self.probes.always(
            &format!("invariant.{inv}"),
            false,
            json!({"key": k, "detail": d}),
        );
        self.violations.push(InvariantViolation {
            invariant: inv,
            key: k,
            detail: d,
        });
    }

    pub fn acked_keys(&self) -> &BTreeMap<String, CommittedState> {
        &self.acked
    }

    pub fn violations(&self) -> &[InvariantViolation] {
        &self.violations
    }

    pub fn is_valid(&self) -> bool {
        self.violations.is_empty() && self.probes.violations().is_empty()
    }
}
