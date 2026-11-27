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

//! Deterministic commit crash-point registry mirroring RustFS's
//! `crates/ecstore/src/crash_inject.rs`.
//!
//! Arming a [`CrashPoint`] for a given `(point, key)` causes the simulated
//! storage commit sequence to abort immediately **without rollback** and drop
//! un-fsynced page-cache state on the affected drive(s), testing the
//! "old-or-new-never-mixed" durability invariant.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Named crash windows inside RustFS's erasure-coded commit sequences.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CrashPoint {
    /// After data shard rename into destination, before `xl.meta.bkp` is written (pre-commit).
    RenameAfterDataRename,
    /// After `xl.meta.bkp` is durable, immediately before atomic `xl.meta` commit rename (pre-commit).
    RenameAfterBackupBeforeMetaCommit,
    /// After `xl.meta` commit rename lands, before final `fsync_dir` durability barrier (post-commit).
    RenameAfterMetaCommit,
    /// After replacement `xl.meta` is staged in `.rustfs.sys/tmp`, before commit rename (pre-commit).
    MetaWriteAfterTmpBeforeRename,
    /// Multipart commit: after parts are staged and locked, before `rename_data` commit (pre-commit).
    MultipartBeforeCommitRename,
    /// Multipart commit: after `rename_data` succeeds, before stale part cleanup (post-commit).
    MultipartAfterCommitBeforeCleanup,
}

impl CrashPoint {
    /// Return every crash point variant in canonical order for exhaustive matrix testing.
    pub const ALL: [CrashPoint; 6] = [
        CrashPoint::RenameAfterDataRename,
        CrashPoint::RenameAfterBackupBeforeMetaCommit,
        CrashPoint::RenameAfterMetaCommit,
        CrashPoint::MetaWriteAfterTmpBeforeRename,
        CrashPoint::MultipartBeforeCommitRename,
        CrashPoint::MultipartAfterCommitBeforeCleanup,
    ];
}

/// Keyed crash-point registry shared by a simulated cluster.
#[derive(Clone, Debug, Default)]
pub struct CrashRegistry {
    armed: Arc<Mutex<BTreeSet<(CrashPoint, String)>>>,
}

impl CrashRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a one-shot crash at `(point, key)`.
    pub fn arm(&self, point: CrashPoint, key: impl Into<String>) {
        let mut guard = self.armed.lock().expect("CrashRegistry lock poisoned");
        guard.insert((point, key.into()));
    }

    /// Check and consume an armed crash point for `(point, key)`.
    pub fn take_if_armed(&self, point: CrashPoint, key: &str) -> bool {
        let mut guard = self.armed.lock().expect("CrashRegistry lock poisoned");
        guard.remove(&(point, key.to_string()))
    }

    /// Disarm all crash points.
    pub fn clear(&self) {
        let mut guard = self.armed.lock().expect("CrashRegistry lock poisoned");
        guard.clear();
    }
}
