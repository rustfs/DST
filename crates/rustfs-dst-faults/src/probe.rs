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

//! Simulation assertion probes (`CodeProbe`) with Antithesis-compatible
//! structured JSONL telemetry.
//!
//! Mirrors Antithesis assertion semantics:
//! - `always(id, cond, details)` — must be true every single time it is evaluated.
//! - `sometimes(id, cond, details)` — should be observed true at least once across a campaign.
//! - `reachable(id, details)` — marks that an important recovery/fault state was reached.
//! - `unreachable(id, details)` — must never be reached.
//!
//! When the environment variable `ANTITHESIS_OUTPUT_DIR` is set, structured
//! JSON lines are appended to `$ANTITHESIS_OUTPUT_DIR/sdk.jsonl` so the same
//! RustFS DST binary integrates cleanly with the commercial Antithesis platform.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Kind of property assertion recorded in [`ProbeRegistry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionKind {
    Always,
    Sometimes,
    Reachable,
    Unreachable,
}

/// Aggregated statistics for a single assertion property ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeStats {
    pub id: String,
    pub kind: AssertionKind,
    pub pass_count: u64,
    pub fail_count: u64,
}

impl ProbeStats {
    pub fn is_violated(&self) -> bool {
        match self.kind {
            AssertionKind::Always => self.fail_count > 0,
            AssertionKind::Unreachable => self.fail_count > 0,
            AssertionKind::Sometimes | AssertionKind::Reachable => false,
        }
    }
}

/// Structured event payload emitted in Antithesis-compatible JSONL format.
#[derive(Clone, Debug, Serialize)]
struct AntithesisEvent<'a> {
    antithesis_assert: AntithesisAssertBody<'a>,
}

#[derive(Clone, Debug, Serialize)]
struct AntithesisAssertBody<'a> {
    id: &'a str,
    message: &'a str,
    assert_type: &'static str,
    must_hit: bool,
    condition: bool,
    hit: bool,
    details: &'a Value,
}

/// Thread-safe assertion & coverage registry shared across a simulation run.
#[derive(Clone, Debug)]
pub struct ProbeRegistry {
    stats: Arc<Mutex<BTreeMap<String, ProbeStats>>>,
    antithesis_file: Option<PathBuf>,
}

impl Default for ProbeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeRegistry {
    pub fn new() -> Self {
        let antithesis_file = std::env::var_os("ANTITHESIS_OUTPUT_DIR")
            .map(PathBuf::from)
            .map(|dir| dir.join("sdk.jsonl"));
        Self {
            stats: Arc::new(Mutex::new(BTreeMap::new())),
            antithesis_file,
        }
    }

    /// Emit the Antithesis lifecycle `setup_complete` event when running under Antithesis.
    pub fn emit_setup_complete(&self, details: Value) {
        let Some(path) = &self.antithesis_file else {
            return;
        };
        let payload = serde_json::json!({
            "antithesis_sdk": {
                "status": "setup_complete",
                "details": details,
            }
        });
        self.append_jsonl(path, &payload);
    }

    /// Assert that `condition` is ALWAYS true at this point.
    pub fn always(&self, id: &str, condition: bool, details: Value) {
        self.record(id, AssertionKind::Always, condition, details);
    }

    /// Record a SOMETIMES property that should become true at least once across seeds.
    pub fn sometimes(&self, id: &str, condition: bool, details: Value) {
        self.record(id, AssertionKind::Sometimes, condition, details);
    }

    /// Mark that an important code path (e.g., bitrot heal, rollback recovery) was reached.
    pub fn reachable(&self, id: &str, details: Value) {
        self.record(id, AssertionKind::Reachable, true, details);
    }

    /// Assert that this branch is UNREACHABLE (fails immediately in summary if hit).
    pub fn unreachable(&self, id: &str, details: Value) {
        self.record(id, AssertionKind::Unreachable, false, details);
    }

    fn record(&self, id: &str, kind: AssertionKind, condition: bool, details: Value) {
        {
            let mut map = self.stats.lock().expect("ProbeRegistry lock poisoned");
            let entry = map.entry(id.to_string()).or_insert_with(|| ProbeStats {
                id: id.to_string(),
                kind,
                pass_count: 0,
                fail_count: 0,
            });
            if condition {
                entry.pass_count += 1;
            } else {
                entry.fail_count += 1;
            }
        }

        if let Some(path) = &self.antithesis_file {
            let (assert_type, must_hit) = match kind {
                AssertionKind::Always => ("always", true),
                AssertionKind::Sometimes => ("sometimes", true),
                AssertionKind::Reachable => ("reachability", true),
                AssertionKind::Unreachable => ("always", false),
            };
            let event = AntithesisEvent {
                antithesis_assert: AntithesisAssertBody {
                    id,
                    message: id,
                    assert_type,
                    must_hit,
                    condition,
                    hit: true,
                    details: &details,
                },
            };
            self.append_jsonl(path, &event);
        }
    }

    fn append_jsonl<T: Serialize>(&self, path: &PathBuf, payload: &T) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path)
            && let Ok(line) = serde_json::to_string(payload)
        {
            let _ = writeln!(file, "{line}");
        }
    }

    /// Snapshot all recorded probes.
    pub fn snapshot(&self) -> BTreeMap<String, ProbeStats> {
        self.stats
            .lock()
            .expect("ProbeRegistry lock poisoned")
            .clone()
    }

    /// Merge another run's probes into this aggregate registry (used across multi-seed runs).
    pub fn merge_from(&self, other: &BTreeMap<String, ProbeStats>) {
        let mut map = self.stats.lock().expect("ProbeRegistry lock poisoned");
        for (id, st) in other {
            let entry = map.entry(id.clone()).or_insert_with(|| ProbeStats {
                id: id.clone(),
                kind: st.kind,
                pass_count: 0,
                fail_count: 0,
            });
            entry.pass_count += st.pass_count;
            entry.fail_count += st.fail_count;
        }
    }

    /// Return all violated `Always` / `Unreachable` assertions.
    pub fn violations(&self) -> Vec<ProbeStats> {
        self.stats
            .lock()
            .expect("ProbeRegistry lock poisoned")
            .values()
            .filter(|s| s.is_violated())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_registry_tracks_always_sometimes_and_violations() {
        let reg = ProbeRegistry::new();
        reg.always("linearizable_read", true, serde_json::json!({"key": "k1"}));
        reg.sometimes("bitrot_reconstructed", true, serde_json::json!({}));
        reg.reachable("quorum_degraded_put", serde_json::json!({}));
        assert!(reg.violations().is_empty());

        reg.always("linearizable_read", false, serde_json::json!({"key": "k2"}));
        assert_eq!(reg.violations().len(), 1);
        assert_eq!(reg.violations()[0].id, "linearizable_read");
    }
}
