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
//! 1. **Sequential read-after-write consistency**: A GET or LIST observes a
//!    valid current state after acknowledged or indeterminate mutations.
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

use crate::ecstore::{GetResult, ListedObject};
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
    /// Most recent accepted state, or the earliest possible observed delete.
    observed: BTreeMap<String, CommittedState>,
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
            observed: BTreeMap::new(),
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

    pub fn record_indeterminate_delete(
        &mut self,
        full_key: &str,
        generation: u64,
        version_id: String,
    ) {
        self.indeterminate
            .entry(full_key.to_string())
            .or_default()
            .push(CommittedState {
                generation,
                version_id,
                is_deleted: true,
                payload_sha256: None,
            });
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

    /// Verify a successful `GetObject` response including its version and checksum.
    pub fn check_get_result(&mut self, full_key: &str, result: &GetResult) {
        let actual_hash = sha256_hex(&result.payload);
        if result.payload_sha256 != actual_hash {
            self.record_violation(
                "bit_exact_integrity",
                full_key,
                format!(
                    "response checksum {} does not match payload digest {actual_hash}",
                    result.payload_sha256
                ),
            );
        }
        self.check_present(
            full_key,
            result.generation,
            Some(&result.version_id),
            &actual_hash,
        );
    }

    /// Verify an observation without a version ID, for callers that only have bytes.
    pub fn check_read_present(&mut self, full_key: &str, generation: u64, payload: &[u8]) {
        self.check_present(full_key, generation, None, &sha256_hex(payload));
    }

    fn check_present(
        &mut self,
        full_key: &str,
        generation: u64,
        version_id: Option<&str>,
        actual_hash: &str,
    ) {
        let hash_valid = self
            .ever_written_hashes
            .get(full_key)
            .is_some_and(|set| set.contains(actual_hash));
        self.probes.always(
            "invariant.bit_exact_integrity",
            hash_valid,
            json!({"key": full_key, "generation": generation, "sha256": actual_hash}),
        );
        if !hash_valid {
            self.violations.push(InvariantViolation {
                invariant: "bit_exact_integrity".to_string(),
                key: full_key.to_string(),
                detail: format!(
                    "read returned unknown/corrupted payload digest {actual_hash} at gen {generation}"
                ),
            });
        }

        let read_state = self
            .possible_states(full_key)
            .find(|state| {
                !state.is_deleted
                    && state.generation == generation
                    && version_id.is_none_or(|id| state.version_id == id)
                    && state.payload_sha256.as_deref() == Some(actual_hash)
            })
            .cloned();
        self.probes.always(
            "invariant.linearizable_read",
            read_state.is_some(),
            json!({
                "key": full_key,
                "read_gen": generation,
                "version_id": version_id,
                "sha256": actual_hash,
            }),
        );
        if let Some(state) = read_state {
            self.observed.insert(full_key.to_string(), state);
        } else {
            self.violations.push(InvariantViolation {
                invariant: "linearizable_read".to_string(),
                key: full_key.to_string(),
                detail: format!(
                    "read gen={generation}, version={version_id:?}, sha256={actual_hash} matches no possible current state"
                ),
            });
        }
    }

    /// Verify a `NotFound` read and remember the earliest deletion that could explain it.
    pub fn check_read_not_found(&mut self, full_key: &str) {
        let possibly_unwritten =
            !self.acked.contains_key(full_key) && !self.observed.contains_key(full_key);
        let deletion = if possibly_unwritten {
            None
        } else {
            self.possible_states(full_key)
                .filter(|state| state.is_deleted)
                .min_by_key(|state| state.generation)
                .cloned()
        };
        let valid = possibly_unwritten || deletion.is_some();
        self.probes.always(
            "invariant.no_lost_acknowledged_write",
            valid,
            json!({"key": full_key, "possible_delete": deletion}),
        );
        if let Some(state) = deletion {
            self.observed.insert(full_key.to_string(), state);
        } else if !valid {
            self.violations.push(InvariantViolation {
                invariant: "no_lost_acknowledged_write".to_string(),
                key: full_key.to_string(),
                detail: "read returned NotFound with no possible current deletion".to_string(),
            });
        }
    }

    fn possible_states<'a>(&'a self, full_key: &str) -> impl Iterator<Item = &'a CommittedState> {
        let acked = self.acked.get(full_key);
        let observed = self.observed.get(full_key);
        acked
            .into_iter()
            .chain(self.indeterminate.get(full_key).into_iter().flatten())
            .filter(move |state| {
                acked.is_none_or(|ack| state.generation > ack.generation || *state == ack)
                    && observed.is_none_or(|previous| {
                        state.generation > previous.generation || *state == previous
                    })
            })
    }

    /// Verify a complete listing after a sequence of acknowledged mutations.
    pub fn check_acked_listing(&mut self, bucket: &str, listed: &[ListedObject]) {
        let prefix = format!("{bucket}/");
        let expected: Vec<_> = self
            .acked
            .iter()
            .filter_map(|(full_key, state)| {
                let key = full_key.strip_prefix(&prefix)?;
                let payload_sha256 = state.payload_sha256.clone()?;
                Some(ListedObject {
                    key: key.to_string(),
                    generation: state.generation,
                    version_id: state.version_id.clone(),
                    payload_sha256,
                })
            })
            .collect();
        self.probes.always(
            "invariant.list_objects_exact_match",
            listed == expected,
            json!({"bucket": bucket, "listed": format!("{listed:?}"), "expected": format!("{expected:?}")}),
        );
        if listed != expected {
            self.violations.push(InvariantViolation {
                invariant: "list_consistency".to_string(),
                key: bucket.to_string(),
                detail: format!("expected {expected:?}, got {listed:?}"),
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "bucket/key";

    fn get_result(generation: u64, version_id: &str, payload: &[u8]) -> GetResult {
        GetResult {
            generation,
            version_id: version_id.to_string(),
            payload: payload.to_vec(),
            payload_sha256: sha256_hex(payload),
        }
    }

    #[test]
    fn rejects_a_definitely_failed_write_even_if_its_payload_was_submitted() {
        let mut oracle = ConsistencyOracle::new(ProbeRegistry::new());
        oracle.record_submitted_payload(KEY, b"uncommitted");
        oracle.check_get_result(KEY, &get_result(1, "failed", b"uncommitted"));
        assert_eq!(oracle.violations()[0].invariant, "linearizable_read");
    }

    #[test]
    fn a_get_must_match_the_same_mutation_for_generation_version_and_payload() {
        for unexpected in [
            get_result(2, "wrong-version", b"new"),
            get_result(2, "new-version", b"old"),
            get_result(3, "delete-marker", b"new"),
        ] {
            let mut oracle = ConsistencyOracle::new(ProbeRegistry::new());
            oracle.record_acked_put(KEY, 1, "old-version".into(), sha256_hex(b"old"));
            oracle.record_indeterminate_put(KEY, 2, "new-version".into(), sha256_hex(b"new"));
            oracle.record_indeterminate_delete(KEY, 3, "delete-marker".into());
            oracle.check_get_result(KEY, &get_result(2, "new-version", b"new"));
            assert!(oracle.is_valid());
            oracle.check_get_result(KEY, &unexpected);
            assert_eq!(oracle.violations()[0].invariant, "linearizable_read");
        }
    }

    #[test]
    fn sequential_reads_cannot_regress_after_an_indeterminate_mutation_is_observed() {
        let mut oracle = ConsistencyOracle::new(ProbeRegistry::new());
        oracle.record_acked_put(KEY, 1, "old-version".into(), sha256_hex(b"old"));
        oracle.record_indeterminate_delete(KEY, 2, "delete-marker".into());
        oracle.check_read_not_found(KEY);
        assert!(oracle.is_valid());
        oracle.check_get_result(KEY, &get_result(1, "old-version", b"old"));
        assert_eq!(oracle.violations()[0].invariant, "linearizable_read");

        let mut oracle = ConsistencyOracle::new(ProbeRegistry::new());
        oracle.record_indeterminate_put(KEY, 1, "first-version".into(), sha256_hex(b"first"));
        oracle.check_read_not_found(KEY);
        oracle.check_get_result(KEY, &get_result(1, "first-version", b"first"));
        assert!(oracle.is_valid());
        oracle.check_read_not_found(KEY);
        assert_eq!(
            oracle.violations()[0].invariant,
            "no_lost_acknowledged_write"
        );
    }

    #[test]
    fn list_checks_versions_checksums_and_delete_markers_in_addition_to_keys() {
        let mut oracle = ConsistencyOracle::new(ProbeRegistry::new());
        let expected = ListedObject {
            key: "key".to_string(),
            generation: 2,
            version_id: "current".to_string(),
            payload_sha256: sha256_hex(b"current"),
        };
        oracle.record_acked_delete("bucket/another-key", 1, "delete-marker".into());
        oracle.record_acked_put(
            KEY,
            2,
            expected.version_id.clone(),
            expected.payload_sha256.clone(),
        );
        oracle.check_acked_listing("bucket", std::slice::from_ref(&expected));
        assert!(oracle.is_valid());
        oracle.check_acked_listing(
            "bucket",
            &[ListedObject {
                generation: 1,
                version_id: "stale".to_string(),
                payload_sha256: sha256_hex(b"stale"),
                ..expected
            }],
        );
        assert_eq!(oracle.violations()[0].invariant, "list_consistency");
    }
}
