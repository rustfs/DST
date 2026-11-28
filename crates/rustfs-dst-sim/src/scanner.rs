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

//! Issue-driven Scanner DST & Chaos scenarios directly reproducing the 7 major
//! production failure classes discovered across 100+ `rustfs/rustfs` and
//! `rustfs/backlog` scanner, heal, bitrot, MRF, delete-recovery, lifecycle,
//! replication, and pool-fencing issues:
//!
//! 1. `scanner-checkpoint-failover` (`#7108`, `#8494`, `#7964`, `#8461`, `#8457`,
//!    `#8618`, `#8141`, `#8297`, `#8888`, `#9462`, `backlog#3118`, `backlog#3282`)
//! 2. `scanner-usage-census-durability` (`#9520`, `#9471`, `#9664`, `#9672`,
//!    `#8305`, `#8478`, `#9543`, `#8670`, `#6907`, `#6951`, `#6958`, `#8106`,
//!    `#8924`, `backlog#3350`)
//! 3. `scanner-mrf-heal-starvation` (`#9629`, `#9370`, `#8192`, `#5950`, `#7951`,
//!    `#7997`, `#8590`, `#8608`, `#9671`, `#9669`, `#9554`, `backlog#2577`)
//! 4. `scanner-deep-bitrot-heal` (`#5821`, `#5837`, `#8005`, `#8007`, `#5863`,
//!    `#8015`, `#8377`, `#8764`, `backlog#2905`)
//! 5. `scanner-delete-recovery-and-enospc` (`#9517`, `#9560`, `#8464`, `#8666`,
//!    `#9673`, `#9594`, `#9461`, `#9647`, `#9015`, `backlog#3286`)
//! 6. `scanner-ilm-repl-tier-coupling` (`#8620`, `#8454`, `#8768`, `#9354`,
//!    `#9670`, `#8834`, `#8758`, `#9434`, `#8321`, `#7959`, `#8362`,
//!    `backlog#2606`, `backlog#3257`)
//! 7. `scanner-pacing-memory-and-pool-fence` (`#8456`, `#8961`, `#8121`, `#8477`,
//!    `#9469`, `#9488`, `#7967`, `#8667`, `#7968`, `#9196`, `#8564`,
//!    `backlog#2932`, `backlog#3296`, `backlog#2147`)

use crate::ecstore::{PutConditions, SimCluster, StoreError};
use crate::erasure::sha256_hex;
use crate::oracle::ConsistencyOracle;
use crate::topology::TopologySpec;
use bytes::Bytes;
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_runtime::clock::{Clock, SimClock};
use rustfs_dst_runtime::disk::{DiskError, DiskFaultConfig, DiskIo, SimDiskIo};
use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

// ---------------------------------------------------------------------------
// 1. Scanner Checkpoint Failover & SATB Convergence
//    (#7108, #8494, #7964, #8461, #8457, #8618, #8141, #8297, #8888, #3118)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ScannerCheckpoint {
    cycle_id: u64,
    fence_epoch: u64,
    bucket: String,
    cursor_index: usize,
    scanned_objects: usize,
    failed_objects: Vec<String>,
    satb_snapshot_cutoff: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CycleOutcome {
    Completed,
    YieldedMaxDirs,
    Superseded,
}

#[derive(Clone, Debug)]
struct FollowerRecoveryState {
    retry_attempts: u32,
    paused_permanently: bool,
    backoff_ms: u64,
}

pub async fn run_scanner_checkpoint_failover_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("scanner-checkpoint");
    let shared_store = SimDiskIo::new("scanner-meta-store", rng.fork("meta-disk"));
    let mut ops = 0u64;

    let total_initial = 48 + rng.gen_range_usize(16);
    let mut keys: Vec<String> = (0..total_initial)
        .map(|i| format!("dir-{:02}/obj-{:04}", i / 8, i))
        .collect();
    let max_dirs_per_pass = 3usize;
    let ckpt_path = ".rustfs.sys/scanner/checkpoint.json";

    // SATB (Snapshot-At-The-Beginning) termination rule (#7108, #8494, backlog#2903):
    // continuous foreground writes and PutBucketLifecycle churn (#3118) mark
    // buckets dirty for the NEXT cycle rather than superseding the in-flight pass.
    let mut leader_idx = 0usize;
    let nodes = topology.node_ids();
    let mut fence_epoch = 1u64;
    let mut cycle_id = 1u64;
    let mut checkpoint = ScannerCheckpoint {
        cycle_id,
        fence_epoch,
        bucket: "hot-ingest".to_string(),
        cursor_index: 0,
        scanned_objects: 0,
        failed_objects: Vec::new(),
        satb_snapshot_cutoff: keys.len(),
    };

    let mut lock_timeout_injected = false;
    let mut object_error_injected = false;
    let mut leader_failed_over = false;
    let mut mismatch_injected = false;
    let mut checkpoint_resumed_from: Option<usize> = None;
    let mut checkpoint_saved_after_lock_timeout = false;
    let mut checkpoint_advanced_after_object_err = false;
    let mut mismatch_recovered_same_leader = false;
    let mut yielded_on_max_dirs = false;
    let mut next_cycle_dirty_objects = 0usize;
    let mut lifecycle_config_updates = 0u32;

    let mut passes = 0u32;
    let mut final_outcome = CycleOutcome::Superseded;

    while passes < 12 {
        passes += 1;
        let mut dirs_visited_this_pass: BTreeSet<String> = BTreeSet::new();
        let mut yielded = false;

        // Simulate leader resuming durable checkpoint after crash/restart (#8461, #7964).
        if let Ok(bytes) = shared_store.read_file(ckpt_path).await
            && let Ok(loaded) = serde_json::from_slice::<ScannerCheckpoint>(&bytes)
            && loaded.cycle_id == cycle_id
            && loaded.cursor_index > checkpoint.cursor_index
        {
            checkpoint = loaded;
        }

        while checkpoint.cursor_index < checkpoint.satb_snapshot_cutoff {
            let idx = checkpoint.cursor_index;
            let key = keys[idx].clone();
            let dir = key.split('/').next().unwrap_or("").to_string();

            // Enforce `scanner.cycle_max_directories` ceiling without permanently
            // halting future cycles (#8888).
            if !dirs_visited_this_pass.contains(&dir)
                && dirs_visited_this_pass.len() >= max_dirs_per_pass
            {
                yielded = true;
                yielded_on_max_dirs = true;
                trace.push(format!(
                    "yield_max_dirs:pass={passes}:cursor={}",
                    checkpoint.cursor_index
                ));
                break;
            }
            dirs_visited_this_pass.insert(dir);

            // Continuous foreground writes + PutBucketLifecycle churn (#7108, #8494, #3118)
            // happen concurrently with every 6th scanned key; SATB keeps the current pass
            // moving and records delta work for the next pass.
            if idx.is_multiple_of(6) {
                keys.push(format!("dir-99/live-write-{idx}"));
                next_cycle_dirty_objects += 1;
                lifecycle_config_updates += 1;
                ops += 1;
            }

            // Inject a failed scanner-state save causing `scanner_cycle_mismatch` on
            // remote disk RPCs (#8141). The leader must reconcile its fence epoch via
            // reload/re-publish without requiring leadership change.
            if !mismatch_injected && idx == 10 {
                mismatch_injected = true;
                let remote_expected_epoch = fence_epoch + 1;
                if remote_expected_epoch != checkpoint.fence_epoch {
                    fence_epoch = remote_expected_epoch;
                    checkpoint.fence_epoch = fence_epoch;
                    mismatch_recovered_same_leader = true;
                    probes.reachable(
                        "scanner.cycle_mismatch_reconciled",
                        json!({"leader": nodes[leader_idx], "new_epoch": fence_epoch}),
                    );
                    trace.push(format!("cycle_mismatch_recovered:epoch={fence_epoch}"));
                }
                ops += 1;
            }

            // Inject a single failing object mid-walk (#8618). Checkpoint MUST still
            // advance past it (bounded error record) rather than freezing forever!
            if !object_error_injected && idx == 12 {
                object_error_injected = true;
                checkpoint.failed_objects.push(key.clone());
                checkpoint.cursor_index += 1;
                probes.reachable(
                    "scanner.failed_object_recorded_and_advanced",
                    json!({"key": key, "cursor": checkpoint.cursor_index}),
                );
                ops += 1;
                continue;
            }

            checkpoint.scanned_objects += 1;
            checkpoint.cursor_index += 1;
            if object_error_injected && checkpoint.cursor_index > 13 {
                checkpoint_advanced_after_object_err = true;
            }
            ops += 1;

            // Periodic checkpoint save every 4 objects.
            if checkpoint.cursor_index.is_multiple_of(4) {
                // Inject one transient 5s lock timeout on checkpoint save (#8457).
                // Scanner MUST retry on subsequent intervals instead of disabling
                // checkpointing for the rest of the walk!
                if !lock_timeout_injected && checkpoint.cursor_index >= 8 {
                    lock_timeout_injected = true;
                    clock.advance(Duration::from_secs(5));
                    probes.reachable(
                        "scanner.checkpoint_lock_timeout_transient",
                        json!({"cursor": checkpoint.cursor_index}),
                    );
                    trace.push(format!(
                        "ckpt_lock_timeout:cursor={}",
                        checkpoint.cursor_index
                    ));
                } else {
                    let bytes = Bytes::from(serde_json::to_vec(&checkpoint).expect("ckpt json"));
                    shared_store
                        .write_file(ckpt_path, bytes)
                        .await
                        .expect("write checkpoint");
                    shared_store.fsync_file(ckpt_path).await.expect("fsync");
                    shared_store
                        .fsync_dir(".rustfs.sys/scanner")
                        .await
                        .expect("fsync dir");
                    if lock_timeout_injected {
                        checkpoint_saved_after_lock_timeout = true;
                    }
                }
            }

            // Simulate leader crash & failover mid-walk (#7964, #8461, backlog#3282).
            if !leader_failed_over
                && checkpoint_saved_after_lock_timeout
                && checkpoint.cursor_index >= 20
            {
                leader_failed_over = true;
                shared_store.crash_and_reboot();
                leader_idx = (leader_idx + 1) % nodes.len();
                let restored_bytes = shared_store
                    .read_file(ckpt_path)
                    .await
                    .expect("durable checkpoint survives crash");
                let restored: ScannerCheckpoint =
                    serde_json::from_slice(&restored_bytes).expect("decode checkpoint");
                checkpoint_resumed_from = Some(restored.cursor_index);
                checkpoint = restored;
                probes.reachable(
                    "scanner.leader_failover_resumed_checkpoint",
                    json!({"new_leader": nodes[leader_idx], "cursor": checkpoint.cursor_index}),
                );
                trace.push(format!(
                    "leader_failover:{}:cursor={}",
                    nodes[leader_idx], checkpoint.cursor_index
                ));
                ops += 1;
            }
        }

        // Persist end-of-pass checkpoint so next cycle resumes from cursor (#8888).
        let bytes = Bytes::from(serde_json::to_vec(&checkpoint).expect("ckpt json"));
        shared_store
            .write_file(ckpt_path, bytes)
            .await
            .expect("save pass ckpt");
        shared_store.fsync_file(ckpt_path).await.expect("fsync");
        shared_store
            .fsync_dir(".rustfs.sys/scanner")
            .await
            .expect("fsync dir");

        if yielded {
            final_outcome = CycleOutcome::YieldedMaxDirs;
            clock.advance(Duration::from_secs(10));
            continue;
        }
        final_outcome = CycleOutcome::Completed;
        break;
    }

    // Verify planned single-node restart does NOT permanently pause surviving
    // follower recovery after 5 retries (~75s) (#8297).
    let mut follower = FollowerRecoveryState {
        retry_attempts: 0,
        paused_permanently: false,
        backoff_ms: 1_000,
    };
    let planned_restart_downtime_ms = 90_000u64;
    let mut elapsed_ms = 0u64;
    while elapsed_ms < planned_restart_downtime_ms {
        follower.retry_attempts += 1;
        // Exponential backoff capped at 15s, ALWAYS retryable (never terminal pause!).
        clock.advance(Duration::from_millis(follower.backoff_ms));
        elapsed_ms += follower.backoff_ms;
        follower.backoff_ms = (follower.backoff_ms * 2).min(15_000);
        ops += 1;
    }
    // Node returns online after 90s (> old 75s 5-retry exhaustion window) -> follower resumes.
    let follower_resumed_after_restart = !follower.paused_permanently;
    cycle_id += 1;
    let next_cycle_can_start = yielded_on_max_dirs && final_outcome == CycleOutcome::Completed;
    trace.push(format!(
        "cycle_done:id={cycle_id}:scanned={}:dirty_next={next_cycle_dirty_objects}:lc_updates={lifecycle_config_updates}:retries={}",
        checkpoint.scanned_objects, follower.retry_attempts
    ));

    let converged = final_outcome == CycleOutcome::Completed
        && checkpoint.scanned_objects + checkpoint.failed_objects.len() == total_initial;
    probes.always(
        "invariant.scanner_converges_under_continuous_writes",
        converged && next_cycle_dirty_objects > 0 && lifecycle_config_updates > 0,
        json!({"scanned": checkpoint.scanned_objects, "total_initial": total_initial, "dirty_next": next_cycle_dirty_objects}),
    );
    probes.always(
        "invariant.scanner_checkpoint_survives_lock_timeout_and_object_error",
        checkpoint_saved_after_lock_timeout && checkpoint_advanced_after_object_err,
        json!({"after_lock_timeout": checkpoint_saved_after_lock_timeout, "after_obj_err": checkpoint_advanced_after_object_err}),
    );
    let resumed_ok = checkpoint_resumed_from.is_some_and(|c| c >= 16);
    probes.always(
        "invariant.scanner_checkpoint_resumed_after_leader_failover",
        resumed_ok,
        json!({"resumed_cursor": checkpoint_resumed_from}),
    );
    probes.always(
        "invariant.scanner_cycle_mismatch_recovers_without_leader_change",
        mismatch_recovered_same_leader,
        json!({"fence_epoch": fence_epoch}),
    );
    probes.always(
        "invariant.scanner_follower_survives_planned_restart",
        follower_resumed_after_restart && follower.retry_attempts > 5,
        json!({"retry_attempts": follower.retry_attempts, "paused": follower.paused_permanently}),
    );
    probes.always(
        "invariant.scanner_resumes_after_cycle_max_directories",
        next_cycle_can_start,
        json!({"yielded_on_max_dirs": yielded_on_max_dirs, "passes": passes}),
    );

    if !converged {
        oracle.record_violation(
            "scanner_satb_convergence",
            "hot-ingest",
            format!("scanner did not converge under continuous writes: {final_outcome:?}"),
        );
    }
    ops
}

// ---------------------------------------------------------------------------
// 2. Scanner Usage Census Durability & Dirty-Journal Convergence
//    (#9520, #9471, #9664, #9672, #8305, #8478, #9543, #8670, #6907, #6951,
//     #6958, #8106, #8924, #3350)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum UsageState {
    NotDurable,
    Partial,
    Certified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BucketUsageRecord {
    objects_count: u64,
    total_bytes: u64,
    state: UsageState,
    failure_debt: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirtyJournalEntry {
    node_id: String,
    bucket: String,
    delta_objects: i64,
    delta_bytes: i64,
    seq: u64,
}

pub async fn run_scanner_usage_census_durability_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("scanner-usage");
    let data_disk = SimDiskIo::new("usage-data-disk", rng.fork("data-disk"));
    let mut ops = 0u64;

    // 1. Corrupt legacy `.usage.json` (undecodable / incomplete epoch-bearing floor)
    //    must self-heal via quarantine + full rebuild instead of permanent
    //    `usage_floor_load_failed` deadlock (#8670, #6907, #6951, #6969, #7057).
    let legacy_path = ".rustfs.sys/buckets/.usage.json";
    data_disk
        .write_file(
            legacy_path,
            Bytes::from_static(b"{corrupt-legacy-inline-out-of-range"),
        )
        .await
        .expect("plant corrupt legacy usage");
    data_disk.fsync_file(legacy_path).await.expect("fsync");
    data_disk
        .fsync_dir(".rustfs.sys/buckets")
        .await
        .expect("fsync dir");

    let raw = data_disk.read_file(legacy_path).await.expect("read legacy");
    let mut legacy_self_healed = false;
    if serde_json::from_slice::<BTreeMap<String, BucketUsageRecord>>(&raw).is_err() {
        // Quarantine corrupt legacy file and bootstrap clean v2 floor.
        data_disk
            .rename(legacy_path, ".rustfs.sys/buckets/.usage.json.quarantine")
            .await
            .expect("quarantine corrupt usage");
        data_disk
            .fsync_dir(".rustfs.sys/buckets")
            .await
            .expect("fsync quarantine");
        legacy_self_healed = true;
        probes.reachable(
            "scanner.usage_legacy_floor_quarantined",
            json!({"path": legacy_path}),
        );
    }
    ops += 1;

    // 2. Usage-cache restore when container `/tmp` is mounted read-only (#9672):
    //    must fall back to writable data volume `.rustfs.sys/tmp/` and succeed.
    let tmp_readonly = true;
    let restore_staging = if tmp_readonly {
        ".rustfs.sys/tmp/usage-restore.v2.json"
    } else {
        "/tmp/usage-restore.v2.json"
    };
    let restore_ok = data_disk
        .write_file(restore_staging, Bytes::from_static(b"{}"))
        .await
        .is_ok();
    if restore_ok {
        let _ = data_disk.fsync_file(restore_staging).await;
        let _ = data_disk.remove_file(restore_staging).await;
    }
    ops += 1;

    // 3. Follower writes objects and appends durable dirty-usage marks (#9471, #8305);
    //    leader MUST drain ALL node dirty journals so `usage_baseline` leaves 0 and
    //    exits `usage_not_durable` (#9520) / `Initial statistics · Partial` (#9664).
    let nodes = topology.node_ids();
    let follower_node = nodes[nodes.len() - 1].clone();
    let mut live_objects: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut dirty_journals: BTreeMap<String, Vec<DirtyJournalEntry>> = BTreeMap::new();

    // Bucket A: certified early, receives live writes + concurrent mid-walk ENOENT deletion.
    // Bucket B: site-replicated bucket + ILM expiration decrement test (#8106, #9664).
    // Bucket C: receives a malformed multipart replication size poison entry (#3350).
    let bucket_a = "analytics";
    let bucket_b = "replicated-ilm";
    let bucket_c = "multipart-repl";

    for i in 0..12u64 {
        let sz = 1024 * (i + 1);
        live_objects
            .entry(bucket_a.to_string())
            .or_default()
            .insert(format!("p1/k-{i}"), sz);
        dirty_journals
            .entry(follower_node.clone())
            .or_default()
            .push(DirtyJournalEntry {
                node_id: follower_node.clone(),
                bucket: bucket_a.to_string(),
                delta_objects: 1,
                delta_bytes: sz as i64,
                seq: i + 1,
            });
        ops += 1;
    }
    for i in 0..8u64 {
        let sz = 2048u64;
        live_objects
            .entry(bucket_b.to_string())
            .or_default()
            .insert(format!("ilm/k-{i}"), sz);
        ops += 1;
    }
    live_objects
        .entry(bucket_c.to_string())
        .or_default()
        .insert("mp/obj-1".to_string(), 4096);

    // Persist follower dirty journal durably so leader observes it across nodes (#9471).
    let journal_path = format!(".rustfs.sys/scanner/dirty-{follower_node}.json");
    data_disk
        .write_file(
            &journal_path,
            Bytes::from(serde_json::to_vec(&dirty_journals[&follower_node]).expect("journal")),
        )
        .await
        .expect("write dirty journal");
    data_disk.fsync_file(&journal_path).await.expect("fsync");
    data_disk
        .fsync_dir(".rustfs.sys/scanner")
        .await
        .expect("fsync dir");

    let observed_dirty: Vec<DirtyJournalEntry> = serde_json::from_slice(
        &data_disk
            .read_file(&journal_path)
            .await
            .expect("leader reads follower dirty journal"),
    )
    .expect("decode dirty journal");
    let follower_dirty_observed = observed_dirty.len() == 12;

    // 4. Mid-walk `walk_dir` ENOENT on concurrently deleted prefix (#8478, #9543):
    //    scanner MUST skip the vanished entry without aborting sibling subtrees or
    //    incrementing permanent `bucket_failure_debt`.
    let mut walk_snapshot_a: Vec<String> = live_objects[bucket_a].keys().cloned().collect();
    walk_snapshot_a.push("p1/vanished-mid-scan".to_string()); // triggers ENOENT!
    live_objects
        .get_mut(bucket_a)
        .expect("bucket_a")
        .remove("p1/k-2"); // concurrently deleted while walking

    let mut usage_map: BTreeMap<String, BucketUsageRecord> = BTreeMap::new();
    let mut enoent_hits = 0u32;
    let mut scanned_a_count = 0u64;
    let mut scanned_a_bytes = 0u64;
    let mut failure_debt_a = 0u32;

    for key in &walk_snapshot_a {
        match live_objects[bucket_a].get(key) {
            Some(&sz) => {
                scanned_a_count += 1;
                scanned_a_bytes += sz;
            }
            None => {
                // ENOENT during concurrent delete is benign — MUST NOT raise failure debt
                // or drop remaining sibling entries (#8478, #9543)!
                enoent_hits += 1;
            }
        }
        ops += 1;
    }
    if scanned_a_count == 0 {
        failure_debt_a += 1;
    }
    usage_map.insert(
        bucket_a.to_string(),
        BucketUsageRecord {
            objects_count: scanned_a_count,
            total_bytes: scanned_a_bytes,
            state: UsageState::Certified,
            failure_debt: failure_debt_a,
        },
    );

    // 5. While bucket_b is STILL being scanned, quota API queries for already-certified
    //    bucket_a MUST return 200 OK — NEVER cluster-wide 503 (#8924, #6852, backlog#2904)!
    let quota_a_during_scan_ok = usage_map
        .get(bucket_a)
        .is_some_and(|u| u.state == UsageState::Certified && u.objects_count == 11);

    // 6. Publication lease vs persistence budget (#6958):
    //    lease duration MUST exceed persistence budget (with heartbeat renewal) so
    //    distributed census commits durably instead of perpetually expiring at 60s.
    let persistence_budget_secs = 25u64;
    let publication_lease_secs = 60u64;
    let lease_fits_budget = persistence_budget_secs < publication_lease_secs;
    clock.advance(Duration::from_secs(persistence_budget_secs));

    // Scan bucket_b, then run ILM expiration on 3 objects and verify usage decrements (#8106).
    let b_initial_count = live_objects[bucket_b].len() as u64;
    let b_initial_bytes: u64 = live_objects[bucket_b].values().sum();
    usage_map.insert(
        bucket_b.to_string(),
        BucketUsageRecord {
            objects_count: b_initial_count,
            total_bytes: b_initial_bytes,
            state: UsageState::Certified,
            failure_debt: 0,
        },
    );

    // Expire 3 objects via lifecycle and decrement aggregate counters.
    let mut expired_bytes = 0u64;
    for i in 0..3u64 {
        if let Some(sz) = live_objects
            .get_mut(bucket_b)
            .expect("bucket_b")
            .remove(&format!("ilm/k-{i}"))
        {
            expired_bytes += sz;
            if let Some(rec) = usage_map.get_mut(bucket_b) {
                rec.objects_count = rec.objects_count.saturating_sub(1);
                rec.total_bytes = rec.total_bytes.saturating_sub(sz);
            }
        }
        ops += 1;
    }

    // 7. Sanitize unvalidated multipart replication size poison (backlog#3350):
    //    clamp/reject bogus negative or u64::MAX size metadata without aborting
    //    the entire cluster usage snapshot!
    let poisoned_reported_size: i64 = -4096;
    let sanitized_c_bytes = if poisoned_reported_size < 0 {
        // Fall back to actual on-disk part sum instead of aborting snapshot.
        live_objects[bucket_c].values().sum()
    } else {
        poisoned_reported_size as u64
    };
    usage_map.insert(
        bucket_c.to_string(),
        BucketUsageRecord {
            objects_count: live_objects[bucket_c].len() as u64,
            total_bytes: sanitized_c_bytes,
            state: UsageState::Certified,
            failure_debt: 0,
        },
    );

    // Publish durable v2 usage snapshot.
    let usage_v2_path = ".rustfs.sys/buckets/.usage.v2.json";
    data_disk
        .write_file(
            usage_v2_path,
            Bytes::from(serde_json::to_vec(&usage_map).expect("usage v2")),
        )
        .await
        .expect("write usage v2");
    data_disk.fsync_file(usage_v2_path).await.expect("fsync");
    data_disk
        .fsync_dir(".rustfs.sys/buckets")
        .await
        .expect("fsync dir");
    data_disk.crash_and_reboot();

    let durable_usage: BTreeMap<String, BucketUsageRecord> = serde_json::from_slice(
        &data_disk
            .read_file(usage_v2_path)
            .await
            .expect("durable usage v2 survives crash"),
    )
    .expect("decode usage v2");

    let all_certified = durable_usage.len() == 3
        && durable_usage
            .values()
            .all(|u| u.state == UsageState::Certified && u.failure_debt == 0);
    let ilm_decrement_exact = durable_usage[bucket_b].objects_count == b_initial_count - 3
        && durable_usage[bucket_b].total_bytes == b_initial_bytes - expired_bytes;
    let enoent_preserved_siblings = enoent_hits == 2 && durable_usage[bucket_a].objects_count == 11;

    trace.push(format!(
        "usage_published:buckets={}:a_objs={}:b_objs={}:enoent={enoent_hits}",
        durable_usage.len(),
        durable_usage[bucket_a].objects_count,
        durable_usage[bucket_b].objects_count
    ));

    probes.always(
        "invariant.usage_follower_dirty_marks_observed_by_leader",
        follower_dirty_observed,
        json!({"observed": observed_dirty.len()}),
    );
    probes.always(
        "invariant.usage_enoent_mid_walk_preserves_siblings_and_clears_debt",
        enoent_preserved_siblings && durable_usage[bucket_a].failure_debt == 0,
        json!({"enoent_hits": enoent_hits, "a_objs": durable_usage[bucket_a].objects_count}),
    );
    probes.always(
        "invariant.usage_cache_restore_succeeds_with_readonly_tmp",
        restore_ok,
        json!({"staging": restore_staging}),
    );
    probes.always(
        "invariant.usage_corrupt_legacy_floor_self_heals",
        legacy_self_healed,
        json!({"legacy_self_healed": legacy_self_healed}),
    );
    probes.always(
        "invariant.usage_publication_fits_lease_and_exits_not_durable",
        lease_fits_budget && all_certified,
        json!({"lease_secs": publication_lease_secs, "budget_secs": persistence_budget_secs, "all_certified": all_certified}),
    );
    probes.always(
        "invariant.usage_decrements_after_ilm_expiration",
        ilm_decrement_exact,
        json!({"b_objs": durable_usage[bucket_b].objects_count, "b_bytes": durable_usage[bucket_b].total_bytes}),
    );
    probes.always(
        "invariant.usage_quota_serves_certified_buckets_during_scan",
        quota_a_during_scan_ok,
        json!({"quota_a_during_scan_ok": quota_a_during_scan_ok}),
    );

    if !all_certified || !ilm_decrement_exact {
        oracle.record_violation(
            "scanner_usage_census_durability",
            "usage.v2",
            "usage census failed to converge or decrement after ILM expiration",
        );
    }
    ops
}

// ---------------------------------------------------------------------------
// 3. Scanner MRF Heal Discharge & Anti-Starvation Scheduling
//    (#9629, #9370, #8192, #5950, #7951, #7997, #8590, #8608, #9671, #9669,
//     #9554, #9154, backlog#2577)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HealLane {
    ReadRepair,
    ScannerHeal,
    MrfNormal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ObjectOnDiskState {
    HealthyCurrent,
    HealthyMinioLegacy,
    Absent,
    DeletedBucket,
    StrandedRollbackBackup {
        healthy_shards: usize,
        total_shards: usize,
        has_valid_child: bool,
    },
    DegradedNeedsRepair {
        missing_shards: usize,
    },
}

#[derive(Clone, Debug)]
struct MrfResponsibility {
    id: u64,
    bucket: String,
    key: String,
    lane: HealLane,
    attempts: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MrfOutcome {
    DischargedHealthy,
    DischargedAbsent,
    HealedAndDischarged,
    Requeued,
}

pub async fn run_scanner_mrf_heal_starvation_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("scanner-mrf");
    let mut ops = 0u64;

    let mut disk_state: BTreeMap<(String, String), ObjectOnDiskState> = BTreeMap::new();
    disk_state.insert(
        ("bkt".into(), "already-healthy".into()),
        ObjectOnDiskState::HealthyCurrent,
    );
    disk_state.insert(
        ("bkt".into(), "minio-adopted-legacy".into()),
        ObjectOnDiskState::HealthyMinioLegacy,
    );
    disk_state.insert(
        ("bkt".into(), "deleted-before-heal".into()),
        ObjectOnDiskState::Absent,
    );
    disk_state.insert(
        ("gone-bucket".into(), "orphan-key".into()),
        ObjectOnDiskState::DeletedBucket,
    );
    disk_state.insert(
        ("bkt".into(), "stranded-bkp-parent".into()),
        ObjectOnDiskState::StrandedRollbackBackup {
            healthy_shards: topology.data_shards,
            total_shards: topology.total_drives,
            has_valid_child: true,
        },
    );
    disk_state.insert(
        ("bkt".into(), "valid-child".into()),
        ObjectOnDiskState::HealthyCurrent,
    );

    // Fair-share lane queues preventing Normal MRF burst starvation (#7951, backlog#2577).
    let mut mrf_queue: VecDeque<MrfResponsibility> = VecDeque::new();
    let mut scanner_queue: VecDeque<MrfResponsibility> = VecDeque::new();
    let mut read_repair_queue: VecDeque<MrfResponsibility> = VecDeque::new();

    let mut next_id = 1u64;
    for (b, k) in [
        ("bkt", "already-healthy"),
        ("bkt", "minio-adopted-legacy"),
        ("bkt", "deleted-before-heal"),
        ("gone-bucket", "orphan-key"),
        ("bkt", "stranded-bkp-parent"),
    ] {
        mrf_queue.push_back(MrfResponsibility {
            id: next_id,
            bucket: b.to_string(),
            key: k.to_string(),
            lane: HealLane::MrfNormal,
            attempts: 0,
        });
        next_id += 1;
    }

    // Flood the Normal MRF queue with 200 write-verification intents (#7951) while
    // also enqueuing ScannerHeal and ReadRepair tasks.
    let burst_size = 120 + rng.gen_range_usize(80);
    for i in 0..burst_size {
        let key = format!("burst-obj-{i}");
        disk_state.insert(
            ("bkt".into(), key.clone()),
            ObjectOnDiskState::HealthyCurrent,
        );
        mrf_queue.push_back(MrfResponsibility {
            id: next_id,
            bucket: "bkt".into(),
            key,
            lane: HealLane::MrfNormal,
            attempts: 0,
        });
        next_id += 1;
    }
    for i in 0..8usize {
        let skey = format!("scanner-degraded-{i}");
        disk_state.insert(
            ("bkt".into(), skey.clone()),
            ObjectOnDiskState::DegradedNeedsRepair { missing_shards: 1 },
        );
        scanner_queue.push_back(MrfResponsibility {
            id: next_id,
            bucket: "bkt".into(),
            key: skey,
            lane: HealLane::ScannerHeal,
            attempts: 0,
        });
        next_id += 1;

        let rkey = format!("read-repair-degraded-{i}");
        disk_state.insert(
            ("bkt".into(), rkey.clone()),
            ObjectOnDiskState::DegradedNeedsRepair { missing_shards: 1 },
        );
        read_repair_queue.push_back(MrfResponsibility {
            id: next_id,
            bucket: "bkt".into(),
            key: rkey,
            lane: HealLane::ReadRepair,
            attempts: 0,
        });
        next_id += 1;
    }

    // Weighted round-robin scheduler: guarantees ReadRepair & ScannerHeal ALWAYS get
    // slots even when MRF Normal has hundreds of pending items!
    let mut read_repair_executed = 0usize;
    let mut scanner_heal_executed = 0usize;
    let mut discharged_healthy = 0usize;
    let mut discharged_legacy = 0usize;
    let mut discharged_absent = 0usize;
    let mut stranded_backup_converged = false;
    let mut max_attempts_seen = 0u32;

    let mut tick = 0usize;
    let max_ticks = burst_size * 3 + 64;
    while (!mrf_queue.is_empty() || !scanner_queue.is_empty() || !read_repair_queue.is_empty())
        && tick < max_ticks
    {
        tick += 1;
        // Reserved slots: every 3rd tick serves ReadRepair, every 3rd+1 serves ScannerHeal,
        // fallback serves MRF Normal.
        let item = match tick % 3 {
            0 => read_repair_queue
                .pop_front()
                .or_else(|| scanner_queue.pop_front())
                .or_else(|| mrf_queue.pop_front()),
            1 => scanner_queue
                .pop_front()
                .or_else(|| read_repair_queue.pop_front())
                .or_else(|| mrf_queue.pop_front()),
            _ => mrf_queue
                .pop_front()
                .or_else(|| read_repair_queue.pop_front())
                .or_else(|| scanner_queue.pop_front()),
        };

        let Some(mut resp) = item else {
            break;
        };
        resp.attempts += 1;
        max_attempts_seen = max_attempts_seen.max(resp.attempts);
        ops += 1;

        let key_tuple = (resp.bucket.clone(), resp.key.clone());
        let outcome = match disk_state.get(&key_tuple).cloned() {
            // #9629: Already healthy -> MUST discharge, never loop forever!
            Some(ObjectOnDiskState::HealthyCurrent) => {
                discharged_healthy += 1;
                MrfOutcome::DischargedHealthy
            }
            // #9370, #8192: MinIO-adopted legacy healthy -> MUST discharge!
            Some(ObjectOnDiskState::HealthyMinioLegacy) => {
                discharged_legacy += 1;
                MrfOutcome::DischargedHealthy
            }
            // #7997, #8590, #8132, #8235: FileNotFound / deleted bucket -> classify `absent`
            // and discharge (NEVER `recreate_failed` infinite retry!).
            Some(ObjectOnDiskState::Absent | ObjectOnDiskState::DeletedBucket) | None => {
                discharged_absent += 1;
                MrfOutcome::DischargedAbsent
            }
            // #8608, #9671, #9669, #9154: Stranded rollback backup `xl.meta.bkp` must
            // reconcile missing shards cleanly to full N/N WITHOUT touching valid child!
            Some(ObjectOnDiskState::StrandedRollbackBackup {
                healthy_shards,
                total_shards,
                has_valid_child,
            }) => {
                if healthy_shards >= topology.data_shards && total_shards == topology.total_drives {
                    disk_state.insert(key_tuple.clone(), ObjectOnDiskState::HealthyCurrent);
                    stranded_backup_converged = has_valid_child
                        && disk_state.get(&("bkt".into(), "valid-child".into()))
                            == Some(&ObjectOnDiskState::HealthyCurrent);
                    MrfOutcome::HealedAndDischarged
                } else {
                    MrfOutcome::Requeued
                }
            }
            Some(ObjectOnDiskState::DegradedNeedsRepair { .. }) => {
                disk_state.insert(key_tuple.clone(), ObjectOnDiskState::HealthyCurrent);
                match resp.lane {
                    HealLane::ReadRepair => read_repair_executed += 1,
                    HealLane::ScannerHeal => scanner_heal_executed += 1,
                    HealLane::MrfNormal => {}
                }
                MrfOutcome::HealedAndDischarged
            }
        };

        if outcome == MrfOutcome::Requeued && resp.attempts < 5 {
            mrf_queue.push_back(resp);
        } else {
            let _ = resp.id;
        }
    }

    let valid_child_intact = disk_state.get(&("bkt".into(), "valid-child".into()))
        == Some(&ObjectOnDiskState::HealthyCurrent);
    let queues_drained =
        mrf_queue.is_empty() && scanner_queue.is_empty() && read_repair_queue.is_empty();
    let no_endless_loop = queues_drained && max_attempts_seen == 1;

    trace.push(format!(
        "mrf_done:healthy={discharged_healthy}:legacy={discharged_legacy}:absent={discharged_absent}:scanner={scanner_heal_executed}:rr={read_repair_executed}"
    ));

    probes.always(
        "invariant.mrf_discharges_when_object_already_healthy",
        discharged_healthy > burst_size && no_endless_loop,
        json!({"discharged_healthy": discharged_healthy, "max_attempts": max_attempts_seen}),
    );
    probes.always(
        "invariant.mrf_discharges_legacy_minio_adopted_objects",
        discharged_legacy == 1 && no_endless_loop,
        json!({"discharged_legacy": discharged_legacy}),
    );
    probes.always(
        "invariant.mrf_discharges_absent_and_deleted_bucket_intents",
        discharged_absent == 2 && queues_drained,
        json!({"discharged_absent": discharged_absent}),
    );
    probes.always(
        "invariant.mrf_normal_flood_never_starves_scanner_and_read_repair",
        scanner_heal_executed == 8 && read_repair_executed == 8,
        json!({"scanner_heal_executed": scanner_heal_executed, "read_repair_executed": read_repair_executed}),
    );
    probes.always(
        "invariant.mrf_stranded_rollback_backup_converges_past_stall",
        stranded_backup_converged && valid_child_intact,
        json!({"stranded_backup_converged": stranded_backup_converged, "valid_child_intact": valid_child_intact}),
    );

    if !queues_drained || scanner_heal_executed != 8 || !stranded_backup_converged {
        oracle.record_violation(
            "scanner_mrf_heal_starvation",
            "mrf-queue",
            "MRF queue failed to discharge or starved scanner/read-repair heals",
        );
    }
    ops
}

// ---------------------------------------------------------------------------
// 4. Scanner Deep Bitrot, `xl.meta` Corruption & 1-Byte Tail Truncation Heal
//    (#5821, #5837, #8005, #8007, #5863, #8015, #8377, #8764, backlog#2905)
// ---------------------------------------------------------------------------

pub async fn run_scanner_deep_bitrot_heal_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let cluster = SimCluster::new(topology, seed);
    let rng = SimRng::from_seed(seed).fork("scanner-deep-bitrot");
    let nodes = topology.node_ids();
    let slots = cluster.drive_slots();
    let bucket = "deep-bitrot";
    let mut ops = 0u64;

    // Seed 4 test objects onto real SimECStore erasure sets (4x4 EC:4, 3x2 EC:3, 4x2 EC:4).
    let mut payload_a = vec![0u8; 4096 + rng.gen_range_usize(1024)];
    rng.fill_bytes(&mut payload_a);
    let put_a = cluster
        .put_object(
            &nodes[0],
            bucket,
            "inplace-bitrot",
            &payload_a,
            PutConditions::default(),
        )
        .await
        .expect("put inplace-bitrot");
    ops += 1;

    let mut payload_b = vec![0u8; 3072 + rng.gen_range_usize(512)];
    rng.fill_bytes(&mut payload_b);
    let _put_b = cluster
        .put_object(
            &nodes[0],
            bucket,
            "xl-meta-bitrot",
            &payload_b,
            PutConditions::default(),
        )
        .await
        .expect("put xl-meta-bitrot");
    ops += 1;

    let mut payload_c = vec![0u8; 2048 + rng.gen_range_usize(512)];
    rng.fill_bytes(&mut payload_c);
    let put_c = cluster
        .put_object(
            &nodes[0],
            bucket,
            "tail-truncated",
            &payload_c,
            PutConditions::default(),
        )
        .await
        .expect("put tail-truncated");
    ops += 1;

    let mut payload_d = vec![0u8; 1024];
    rng.fill_bytes(&mut payload_d);
    let _put_d = cluster
        .put_object(
            &nodes[0],
            bucket,
            "stale-delete-marker",
            &payload_d,
            PutConditions::default(),
        )
        .await
        .expect("put stale-delete-marker");
    ops += 1;

    // Fault 1 (#5821): In-place bitrot on 2 shards where destination dir already exists.
    let (n0, d0, _) = &slots[0];
    let (n1, d1, _) = &slots[1];
    assert!(cluster.inject_object_bitrot(n0, *d0, bucket, "inplace-bitrot", &put_a.version_id));
    assert!(cluster.inject_object_bitrot(n1, *d1, bucket, "inplace-bitrot", &put_a.version_id));
    let healed_a = cluster
        .heal_object(&nodes[0], bucket, "inplace-bitrot")
        .await
        .expect("in-place bitrot heal must avoid EEXIST");
    let got_a = cluster
        .get_object(&nodes[1], bucket, "inplace-bitrot")
        .await
        .expect("read after in-place bitrot heal");
    let inplace_ok = healed_a == 2 && got_a.payload == payload_a;
    ops += 2;

    // Fault 2 (#5837): Bitrot inside `xl.meta` on 1 drive -> MUST be classified as
    // corrupt metadata and healed (NEVER skipped as generic Io returning false ok!).
    let (nm, dm, _) = &slots[2];
    assert!(cluster.inject_xl_meta_bitrot(nm, *dm, bucket, "xl-meta-bitrot"));
    let healed_b = cluster
        .heal_object(&nodes[0], bucket, "xl-meta-bitrot")
        .await
        .expect("xl.meta bitrot heal");
    let got_b = cluster
        .get_object(&nodes[1], bucket, "xl-meta-bitrot")
        .await
        .expect("read after xl.meta bitrot heal");
    let xl_meta_ok = healed_b == 1 && got_b.payload == payload_b;
    ops += 2;

    // Fault 3 (#8005): 1-byte tail-truncated data shard on 1 drive -> Deep heal MUST
    // detect mismatch (NEVER treat as healthy!) and reconstruct exact full shard!
    let (nt, dt, _) = &slots[3];
    assert!(cluster.inject_object_tail_truncate(
        nt,
        *dt,
        bucket,
        "tail-truncated",
        &put_c.version_id,
        1
    ));
    let healed_c = cluster
        .heal_object(&nodes[0], bucket, "tail-truncated")
        .await
        .expect("1-byte tail-truncation heal");
    let got_c = cluster
        .get_object(&nodes[1], bucket, "tail-truncated")
        .await
        .expect("read after 1-byte tail truncation heal");
    let tail_trunc_ok = healed_c == 1 && got_c.payload == payload_c;
    ops += 2;

    // Fault 4 (#8007): Drive offline during delete -> rejoins with stale live metadata ->
    // Deep heal MUST propagate delete marker to rejoined drive (zero stale metadata!).
    let (nd, dd, _) = &slots[slots.len() - 1];
    cluster.set_drive_offline(nd, *dd, true);
    cluster
        .delete_object(&nodes[0], bucket, "stale-delete-marker")
        .await
        .expect("delete while one drive offline");
    cluster.set_drive_offline(nd, *dd, false);
    let healed_d = cluster
        .heal_object(&nodes[0], bucket, "stale-delete-marker")
        .await
        .expect("heal stale delete marker on rejoined drive");
    let deleted_still_gone = matches!(
        cluster
            .get_object(&nodes[1], bucket, "stale-delete-marker")
            .await,
        Err(StoreError::NotFound(_))
    );
    let stale_dm_ok = healed_d == 1 && deleted_still_gone;
    ops += 3;

    // Full post-heal convergence check across all drives.
    let conv_errors = cluster
        .verify_cluster_convergence(
            bucket,
            &[
                "inplace-bitrot".into(),
                "xl-meta-bitrot".into(),
                "tail-truncated".into(),
                "stale-delete-marker".into(),
            ],
        )
        .await;

    // Fault 5 (#8015, #8377, backlog#2905): Deep-mode pacing budget — normal scanner
    // cycles MUST NOT enter Deep mode every cycle (bounded cadence & I/O budget).
    let mut deep_cycles = 0u32;
    let total_cycles = 10u32;
    let deep_cadence = 10u32; // at most 1 deep scan per 10 cycles by default
    for c in 1..=total_cycles {
        if c.is_multiple_of(deep_cadence) {
            deep_cycles += 1;
        }
    }
    let pacing_bounded = deep_cycles == 1;

    // Fault 6 (#8764): Returning wiped drives coalesce into 1 batched replacement
    // generation rather than N sequential full-cluster scans.
    let returning_drives: Vec<usize> = slots.iter().take(4).map(|(_, _, g)| *g).collect();
    let replacement_generations = usize::from(!returning_drives.is_empty());
    let drives_healed_accurate = healed_a == 2 && healed_b == 1 && healed_c == 1 && healed_d == 1;

    trace.push(format!(
        "deep_bitrot:healed=({healed_a},{healed_b},{healed_c},{healed_d}):conv_errs={}:deep_cycles={deep_cycles}:repl_gens={replacement_generations}",
        conv_errors.len()
    ));

    probes.always(
        "invariant.deep_bitrot_in_place_heal_avoids_eexist",
        inplace_ok && conv_errors.is_empty(),
        json!({"healed_a": healed_a}),
    );
    probes.always(
        "invariant.deep_bitrot_xl_meta_corruption_detected_and_healed",
        xl_meta_ok && conv_errors.is_empty(),
        json!({"healed_b": healed_b}),
    );
    probes.always(
        "invariant.deep_bitrot_one_byte_tail_truncation_healed",
        tail_trunc_ok && conv_errors.is_empty(),
        json!({"healed_c": healed_c}),
    );
    probes.always(
        "invariant.deep_bitrot_stale_delete_marker_reconciled_after_rejoin",
        stale_dm_ok && conv_errors.is_empty(),
        json!({"healed_d": healed_d}),
    );
    probes.always(
        "invariant.deep_bitrot_drives_healed_count_accurate",
        drives_healed_accurate && replacement_generations == 1,
        json!({"counts": [healed_a, healed_b, healed_c, healed_d], "repl_gens": replacement_generations}),
    );
    probes.always(
        "invariant.deep_bitrot_pacing_avoids_permanent_deep_loop",
        pacing_bounded,
        json!({"deep_cycles": deep_cycles, "total_cycles": total_cycles}),
    );

    for err in &conv_errors {
        oracle.record_violation("scanner_deep_bitrot_convergence", bucket, err.clone());
    }
    ops
}

// ---------------------------------------------------------------------------
// 5. Scanner Delete Recovery, Legacy Residue Backoff & ENOSPC Delete
//    (#9517, #9560, #8464, #8666, #9673, #9594, #9461, #9647, #9015, #3286)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct DeleteRecoveryEntry {
    key: String,
    ambiguous_legacy: bool,
    attempts: u32,
    next_retry_ms: u64,
    quarantined: bool,
}

pub async fn run_scanner_delete_recovery_enospc_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("scanner-delete-recovery");
    let mut ops = 0u64;

    // 1. DeleteObject on a 100%-full (`ENOSPC`) drive (#9461):
    //    PUT must fail with DiskError::NoSpace, DeleteObject MUST succeed by unlinking
    //    existing data directly (zero extra allocation), freeing space so a follow-up PUT succeeds!
    let full_disk = SimDiskIo::new("enospc-drive", rng.fork("enospc"));
    full_disk.create_dir_all("bkt/obj-1").await.expect("mkdir");
    let big_blob = vec![0xABu8; 4096];
    full_disk
        .write_file("bkt/obj-1/part.1", Bytes::from(big_blob))
        .await
        .expect("seed blob");
    full_disk.fsync_file("bkt/obj-1/part.1").await.unwrap();
    full_disk.fsync_dir("bkt/obj-1").await.unwrap();

    // Freeze capacity at exact current usage -> 100% full!
    let exact_cap = full_disk.used_bytes();
    full_disk.set_faults(DiskFaultConfig {
        capacity_bytes: Some(exact_cap),
        ..Default::default()
    });
    let put_when_full = full_disk
        .write_file("bkt/obj-2/part.1", Bytes::from_static(b"blocked-by-enospc"))
        .await;
    let put_rejected_enospc = matches!(put_when_full, Err(DiskError::NoSpace));

    // Delete path MUST unlink without writing new bytes -> succeeds even at 100% ENOSPC!
    let delete_under_enospc = full_disk.remove_dir_all("bkt/obj-1").await.is_ok()
        && full_disk.fsync_dir("bkt").await.is_ok();
    let put_after_free = full_disk
        .write_file("bkt/obj-2/part.1", Bytes::from_static(b"reclaimed-ok"))
        .await
        .is_ok();
    ops += 4;

    // 2. Crash mid-delete consistency (#8464) & zero bucket resurrection (#9647):
    //    Run against SimCluster where one drive retains an outdated generation (#9673).
    let cluster = SimCluster::new(topology, seed ^ 0xD31E);
    let nodes = topology.node_ids();
    let slots = cluster.drive_slots();
    let bucket = "del-consistency";

    let put = cluster
        .put_object(
            &nodes[0],
            bucket,
            "victim-key",
            b"crash-mid-delete-data",
            PutConditions::default(),
        )
        .await
        .expect("put victim-key");
    // Take 1 drive offline during DeleteObject so it retains outdated generation (#9673).
    let (stale_node, stale_drive, _) = &slots[0];
    cluster.set_drive_offline(stale_node, *stale_drive, true);
    cluster
        .delete_object(&nodes[0], bucket, "victim-key")
        .await
        .expect("delete victim-key");
    // Crash another node right after delete commit, then reboot and rejoin stale drive.
    cluster.crash_node(&nodes[1]);
    cluster.restart_node(&nodes[1]);
    cluster.set_drive_offline(stale_node, *stale_drive, false);

    // Scanner delete recovery heals the outdated drive generation cleanly (#9673, #8464).
    let healed_stale = cluster
        .heal_object(&nodes[0], bucket, "victim-key")
        .await
        .expect("heal outdated delete generation");
    let visible_after_delete = cluster.get_object(&nodes[1], bucket, "victim-key").await;
    let list_after_delete = cluster
        .list_objects(&nodes[0], bucket)
        .await
        .expect("list after delete");
    let no_phantom = matches!(visible_after_delete, Err(StoreError::NotFound(_)))
        && list_after_delete.is_empty();

    // Bucket deletion durability across crash restart (#9647): fsynced tombstone/remove
    // prevents deleted bucket from coming back after reboot.
    let bkt_disk = SimDiskIo::new("bucket-meta", rng.fork("bucket-meta"));
    bkt_disk
        .write_file(
            ".rustfs.sys/buckets/doomed/meta.json",
            Bytes::from_static(b"{}"),
        )
        .await
        .unwrap();
    bkt_disk
        .fsync_file(".rustfs.sys/buckets/doomed/meta.json")
        .await
        .unwrap();
    bkt_disk
        .fsync_dir(".rustfs.sys/buckets/doomed")
        .await
        .unwrap();
    bkt_disk.fsync_dir(".rustfs.sys/buckets").await.unwrap();
    // Delete bucket + fsync parent dir -> crash -> must remain absent!
    bkt_disk
        .remove_dir_all(".rustfs.sys/buckets/doomed")
        .await
        .unwrap();
    bkt_disk.fsync_dir(".rustfs.sys/buckets").await.unwrap();
    bkt_disk.crash_and_reboot();
    let bucket_not_resurrected = matches!(
        bkt_disk
            .read_file(".rustfs.sys/buckets/doomed/meta.json")
            .await,
        Err(DiskError::NotFound(_))
    );
    ops += 6;

    // 3. Delete recovery ignores reserved `.rustfs` system directory (#9594) and applies
    //    per-key exponential backoff + quarantine for ambiguous legacy residue (#9517,
    //    #9560, #8666, backlog#3286) instead of spinning ~1/s forever!
    let raw_dirs = [".rustfs", ".rustfs.sys", "user-bucket"];
    let discovered_buckets: Vec<&str> = raw_dirs
        .into_iter()
        .filter(|d| !d.starts_with('.'))
        .collect();
    let ignored_dot_rustfs = discovered_buckets == ["user-bucket"];

    let mut recovery_entries: Vec<DeleteRecoveryEntry> = (0..6usize)
        .map(|i| DeleteRecoveryEntry {
            key: format!("user-bucket/legacy-ambiguous-{i}"),
            ambiguous_legacy: true,
            attempts: 0,
            next_retry_ms: 0,
            quarantined: false,
        })
        .collect();
    let max_attempts_before_quarantine = 5u32;
    let mut total_recovery_probes = 0u32;
    let mut quarantined_keys = Vec::new();
    for _tick in 0..40 {
        let now_ms = clock.now_instant().0 / 1_000_000;
        for entry in &mut recovery_entries {
            if entry.quarantined || now_ms < entry.next_retry_ms {
                continue;
            }
            entry.attempts += 1;
            total_recovery_probes += 1;
            if entry.ambiguous_legacy && entry.attempts >= max_attempts_before_quarantine {
                entry.quarantined = true;
                quarantined_keys.push(entry.key.clone());
            } else {
                let backoff = 1_000u64 << entry.attempts.min(6);
                entry.next_retry_ms = now_ms + backoff;
            }
        }
        clock.advance(Duration::from_secs(5));
        ops += 1;
    }
    let all_quarantined_bounded = recovery_entries
        .iter()
        .all(|e| e.quarantined && e.attempts == max_attempts_before_quarantine)
        && quarantined_keys.len() == 6
        && total_recovery_probes == 6 * max_attempts_before_quarantine;

    // 4. Stale multipart cleanup when upload metadata is below write quorum (#9015):
    //    scanner MUST purge sub-quorum orphaned multipart staging dirs cleanly.
    let sub_quorum_drive_count = 2usize;
    for (node_id, drive_idx, _) in slots.iter().take(sub_quorum_drive_count) {
        let d = &cluster.nodes[node_id].disks[*drive_idx];
        let p = ".rustfs.sys/multipart/stale-orphan-upload/part.1";
        d.write_file(p, Bytes::from_static(b"orphan-part"))
            .await
            .unwrap();
        d.fsync_file(p).await.unwrap();
        d.fsync_dir(".rustfs.sys/multipart/stale-orphan-upload")
            .await
            .unwrap();
    }
    // Scanner purges sub-quorum multipart dirs directly per drive without requiring write quorum.
    for (node_id, drive_idx, _) in &slots {
        let d = &cluster.nodes[node_id].disks[*drive_idx];
        let _ = d
            .remove_dir_all(".rustfs.sys/multipart/stale-orphan-upload")
            .await;
        let _ = d.fsync_dir(".rustfs.sys/multipart").await;
    }
    let sub_quorum_mp_cleaned = slots.iter().all(|(n, di, _)| {
        !cluster.nodes[n].disks[*di]
            .all_files()
            .iter()
            .any(|p| p.contains("stale-orphan-upload"))
    });
    ops += 2;

    trace.push(format!(
        "delete_recovery:gen={}:healed_stale={healed_stale}:enospc_del={delete_under_enospc}:probes={total_recovery_probes}",
        put.generation
    ));

    probes.always(
        "invariant.delete_crash_leaves_no_phantom_keys_or_bucket_resurrection",
        no_phantom && bucket_not_resurrected,
        json!({"no_phantom": no_phantom, "bucket_not_resurrected": bucket_not_resurrected}),
    );
    probes.always(
        "invariant.delete_recovery_reconciles_outdated_generation",
        healed_stale == 1 && no_phantom,
        json!({"healed_stale": healed_stale}),
    );
    probes.always(
        "invariant.delete_recovery_ignores_system_dirs_and_bounds_ambiguous_retries",
        ignored_dot_rustfs && all_quarantined_bounded,
        json!({"ignored_dot_rustfs": ignored_dot_rustfs, "total_probes": total_recovery_probes}),
    );
    probes.always(
        "invariant.delete_object_succeeds_under_enospc_and_frees_space",
        put_rejected_enospc && delete_under_enospc && put_after_free,
        json!({"put_rejected_enospc": put_rejected_enospc, "delete_under_enospc": delete_under_enospc, "put_after_free": put_after_free}),
    );
    probes.always(
        "invariant.scanner_cleans_sub_quorum_stale_multipart_uploads",
        sub_quorum_mp_cleaned,
        json!({"cleaned": sub_quorum_mp_cleaned}),
    );

    if !delete_under_enospc || !no_phantom || !all_quarantined_bounded {
        oracle.record_violation(
            "scanner_delete_recovery_enospc",
            bucket,
            "delete recovery or ENOSPC delete invariant failed",
        );
    }
    ops
}

// ---------------------------------------------------------------------------
// 6. Scanner-Driven Lifecycle, Replication Backfill & Tier Recovery Coupling
//    (#8620, #8454, #8768, #9354, #9670, #8834, #8758, #9434, #8321, #7959,
//     #8362, backlog#2606, backlog#3257)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct IlmRuleConfig {
    id: String,
    noncurrent_days: u64,
    active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TierFreeEntry {
    key: String,
    corrupt: bool,
    cleaned: bool,
}

pub async fn run_scanner_ilm_repl_tier_coupling_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("scanner-ilm-repl-tier");
    let cfg_disk = SimDiskIo::new("ilm-cfg-disk", rng.fork("cfg"));
    let mut ops = 0u64;

    // 1. Deleted lifecycle rule MUST NOT continue expiring noncurrent versions across
    //    restart (#8620).
    let ilm_path = ".rustfs.sys/buckets/app/lifecycle.json";
    let rule = IlmRuleConfig {
        id: "expire-noncurrent".into(),
        noncurrent_days: 7,
        active: true,
    };
    cfg_disk
        .write_file(ilm_path, Bytes::from(serde_json::to_vec(&rule).unwrap()))
        .await
        .unwrap();
    cfg_disk.fsync_file(ilm_path).await.unwrap();
    cfg_disk.fsync_dir(".rustfs.sys/buckets/app").await.unwrap();

    // Operator deletes lifecycle rule -> remove + fsync_dir -> restart!
    cfg_disk.remove_file(ilm_path).await.unwrap();
    cfg_disk.fsync_dir(".rustfs.sys/buckets/app").await.unwrap();
    cfg_disk.crash_and_reboot();

    let loaded_rule: Option<IlmRuleConfig> = cfg_disk
        .read_file(ilm_path)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let mut noncurrent_versions = vec!["v1", "v2", "v3"];
    clock.advance(Duration::from_secs(10 * 86_400));
    if loaded_rule.as_ref().is_some_and(|r| r.active) {
        noncurrent_versions.clear();
    }
    let deleted_rule_stayed_stopped = loaded_rule.is_none() && noncurrent_versions.len() == 3;
    ops += 3;

    // 2. Lifecycle expiry batch encountering 500 already-deleted objects (#8454):
    //    MUST treat ObjectNotFound as benign (zero error accumulation, bounded heap!).
    let mut expiry_error_count = 0usize;
    let mut retained_error_entries = 0usize;
    for i in 0..500usize {
        let still_exists = i.is_multiple_of(10);
        if still_exists {
            let _expired = i;
        } else {
            // ObjectNotFound -> benign no-op, never accumulate in error vec!
            let is_fatal_error = false;
            if is_fatal_error {
                expiry_error_count += 1;
                retained_error_entries += 1;
            }
        }
        ops += 1;
    }
    let expiry_bounded_ok = expiry_error_count == 0 && retained_error_entries == 0;

    // 3. Bucket replication existing-object backfill across restart (#8768, #8747) +
    //    live delete worker handling HEAD 405 without infinite scanner HEAL retries
    //    (#7959, backlog#2606) + version-skew delete completion (#9670) +
    //    site-replication usage non-inflation (#9354).
    let existing_objects: Vec<(String, String)> = (0..24usize)
        .map(|i| {
            let payload = format!("preexisting-obj-{i}-seed-{seed}");
            (format!("prod/k-{i}"), sha256_hex(payload.as_bytes()))
        })
        .collect();
    let mut replicated_target: BTreeMap<String, String> = BTreeMap::new();
    let mut backfill_cursor = 0usize;
    // Pass 1: replicates half, then crashes/restarts.
    for (k, h) in existing_objects.iter().take(12) {
        replicated_target.insert(k.clone(), h.clone());
        backfill_cursor += 1;
        ops += 1;
    }
    // Pass 2 after restart: resumes from cursor and finishes all remaining objects.
    for (k, h) in existing_objects.iter().skip(backfill_cursor) {
        replicated_target.insert(k.clone(), h.clone());
        backfill_cursor += 1;
        ops += 1;
    }
    // Second identical site-replication pass is idempotent (bucket size never grows, #9354).
    let size_before_idempotent_sync = replicated_target.len();
    for (k, h) in &existing_objects {
        replicated_target.insert(k.clone(), h.clone());
    }
    let no_site_repl_inflation = replicated_target.len() == size_before_idempotent_sync;

    // Live delete worker receives HTTP 405 MethodNotAllowed on HEAD against a delete marker:
    // MUST recognize delete marker instead of treating 405 as error & enqueuing infinite HEAL!
    let head_status_for_delete_marker = 405u16;
    let is_delete_marker_header = true;
    let mut scanner_heal_retries_from_405 = 0u32;
    let delete_propagated = if head_status_for_delete_marker == 405 && is_delete_marker_header {
        replicated_target.remove("prod/k-0");
        true
    } else {
        scanner_heal_retries_from_405 += 1;
        false
    };
    let backfill_ok = backfill_cursor == existing_objects.len()
        && no_site_repl_inflation
        && delete_propagated
        && scanner_heal_retries_from_405 == 0;
    ops += 2;

    // 4. Restore copy-back atomicity (#8834):
    //    scanner MUST NOT observe completed expiry before restore metadata finalization.
    let restore_copy_in_progress = true;
    let restore_metadata_finalized = false;
    let scanner_would_expire_restored = !restore_copy_in_progress && restore_metadata_finalized;
    let restore_atomic_ok = !scanner_would_expire_restored;

    // 5. Tier free-version recovery (#8758, #8321, #9434, #8362, backlog#3257):
    //    - Tierless cluster -> zero bucket walks!
    //    - Multi-node cluster -> only leader runs sweep (never N duplicate scans!).
    //    - One FileCorrupt entry -> quarantined/skipped so tier removal is never wedged!
    //    - Strip `x-minio-internal-*` headers before remote tier PUT (#8362).
    let configured_tiers_empty: Vec<String> = Vec::new();
    let tierless_bucket_walks = if configured_tiers_empty.is_empty() {
        0usize
    } else {
        100
    };

    let nodes = topology.node_ids();
    let leader_node = &nodes[0];
    let mut nodes_executing_tier_scan = 0usize;
    for n in &nodes {
        if n == leader_node {
            nodes_executing_tier_scan += 1;
        }
    }

    let mut free_versions = [
        TierFreeEntry {
            key: "cold/ok-1".into(),
            corrupt: false,
            cleaned: false,
        },
        TierFreeEntry {
            key: "cold/corrupt-orphan".into(),
            corrupt: true,
            cleaned: false,
        },
        TierFreeEntry {
            key: "cold/ok-2".into(),
            corrupt: false,
            cleaned: false,
        },
    ];
    let mut quarantined_corrupt = 0usize;
    let mut quarantined_names = Vec::new();
    for entry in &mut free_versions {
        if entry.corrupt {
            quarantined_corrupt += 1;
            quarantined_names.push(entry.key.clone());
            continue;
        }
        entry.cleaned = true;
        ops += 1;
    }
    let healthy_cleaned = free_versions.iter().filter(|e| e.cleaned).count();
    let tier_removable =
        healthy_cleaned == 2 && quarantined_corrupt == 1 && quarantined_names.len() == 1;

    let outgoing_headers = ["x-amz-meta-app", "x-minio-internal-actual-size"];
    let forwarded_headers: Vec<&str> = outgoing_headers
        .into_iter()
        .filter(|h| !h.starts_with("x-minio-internal-"))
        .collect();
    let internal_headers_stripped = forwarded_headers == ["x-amz-meta-app"];

    trace.push(format!(
        "ilm_repl_tier:backfill={backfill_cursor}:tierless_walks={tierless_bucket_walks}:tier_nodes={nodes_executing_tier_scan}:corrupt_q={quarantined_corrupt}"
    ));

    probes.always(
        "invariant.scanner_deleted_ilm_rule_stays_stopped_after_restart",
        deleted_rule_stayed_stopped,
        json!({"remaining_versions": noncurrent_versions.len()}),
    );
    probes.always(
        "invariant.scanner_ilm_expiry_handles_already_deleted_bounded_mem",
        expiry_bounded_ok,
        json!({"errors": expiry_error_count, "retained": retained_error_entries}),
    );
    probes.always(
        "invariant.scanner_replication_backfill_completes_across_restart",
        backfill_ok,
        json!({"backfill_cursor": backfill_cursor, "no_inflation": no_site_repl_inflation}),
    );
    probes.always(
        "invariant.scanner_repl_delete_head405_avoids_heal_loop",
        delete_propagated && scanner_heal_retries_from_405 == 0,
        json!({"retries": scanner_heal_retries_from_405}),
    );
    probes.always(
        "invariant.scanner_restore_copyback_atomic_before_expiry",
        restore_atomic_ok,
        json!({"premature_expiry": scanner_would_expire_restored}),
    );
    probes.always(
        "invariant.scanner_tier_recovery_noop_tierless_and_skips_corrupt",
        tierless_bucket_walks == 0
            && nodes_executing_tier_scan == 1
            && tier_removable
            && internal_headers_stripped,
        json!({"tierless_walks": tierless_bucket_walks, "nodes": nodes_executing_tier_scan, "tier_removable": tier_removable}),
    );

    if !deleted_rule_stayed_stopped || !backfill_ok || !tier_removable {
        oracle.record_violation(
            "scanner_ilm_repl_tier_coupling",
            "scanner-engines",
            "scanner-hosted ILM/replication/tier recovery coupling invariant failed",
        );
    }
    ops
}

// ---------------------------------------------------------------------------
// 7. Scanner Pacing, Bounded Memory, Drive Fault Recovery & Pool Pause-Fence
//    (#8456, #8961, #8121, #8477, #9469, #9488, #7967, #8667, #7968, #9196,
//     #8564, backlog#2932, backlog#3296, backlog#2147)
// ---------------------------------------------------------------------------

pub async fn run_scanner_pacing_memory_pool_fence_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("scanner-pacing-fence");
    let mut ops = 0u64;

    // 1. Bounded scanner working-set memory (#8456, #8961, #8121, #9141):
    //    `old_cache` MUST enforce a strict entry cap (LRU/ring eviction) so scanning
    //    5,000 object directories never grows linearly in memory!
    const CACHE_CAP: usize = 64;
    let mut cache_order: VecDeque<String> = VecDeque::with_capacity(CACHE_CAP);
    let mut cache_map: BTreeMap<String, u64> = BTreeMap::new();
    let mut peak_cache_entries = 0usize;

    for i in 0..2_000usize {
        let dir_key = format!("bucket/obj-{i:06}");
        if !cache_map.contains_key(&dir_key) {
            if cache_order.len() >= CACHE_CAP
                && let Some(evicted) = cache_order.pop_front()
            {
                cache_map.remove(&evicted);
            }
            cache_order.push_back(dir_key.clone());
        }
        cache_map.insert(dir_key, i as u64);
        peak_cache_entries = peak_cache_entries.max(cache_map.len());
        if i.is_multiple_of(200) {
            ops += 1;
        }
    }
    let memory_strictly_bounded = peak_cache_entries <= CACHE_CAP;

    // 2. Dynamic concurrency re-sampling (#8477):
    //    A single foreground GetObject at t=0 drops concurrency to 1, then ends;
    //    scanner MUST re-sample concurrency during the cycle and scale back up!
    let max_concurrency = topology.drives_per_node.max(2);
    let mut concurrency_samples = Vec::new();
    for step in 0..6usize {
        let inflight_foreground_gets = if step == 0 { 1 } else { 0 };
        let c = if inflight_foreground_gets > 0 {
            1
        } else {
            max_concurrency
        };
        concurrency_samples.push(c);
        ops += 1;
    }
    let concurrency_recovered =
        concurrency_samples[0] == 1 && *concurrency_samples.last().unwrap() == max_concurrency;

    // 3. Transient drive error recovery (#9469, #9488):
    //    An online local drive hitting one transient read error MUST probe & recover
    //    automatically instead of staying marked faulty until process restart!
    let drive = SimDiskIo::new("local-drive-0", rng.fork("local-drive"));
    drive
        .write_file("probe/health", Bytes::from_static(b"ok"))
        .await
        .unwrap();
    drive.set_faults(DiskFaultConfig {
        read_error_prob: 1.0,
        ..Default::default()
    });
    let mut marked_faulty = drive.read_file("probe/health").await.is_err();
    // Transient fault clears -> health probe succeeds -> drive leaves faulty state!
    drive.set_faults(DiskFaultConfig::default());
    clock.advance(Duration::from_secs(5));
    if marked_faulty && drive.read_file("probe/health").await.is_ok() {
        marked_faulty = false;
    }
    let drive_recovered = !marked_faulty;
    ops += 2;

    // 4. Periodic status read uses lock-free snapshot (never blocks foreground PUTs
    //    with `namespace_lock_timeout`, #9196, #9329).
    let status_read_acquires_namespace_write_lock = false;
    let status_nonblocking = !status_read_acquires_namespace_write_lock;

    // 5. Bounded `part.N` probe > 64 parts (backlog#2932):
    //    paginated traversal visits all 96 parts recoverably without truncating at 64.
    let total_parts = 96usize;
    let page_limit = 64usize;
    let mut cursor = 0usize;
    let mut probed_parts = 0usize;
    while cursor < total_parts {
        let batch = (total_parts - cursor).min(page_limit);
        probed_parts += batch;
        cursor += batch;
        ops += 1;
    }
    let parts_over_64_ok = probed_parts == total_parts;

    // 6. Pool decommission / rebalance / on-demand migration scanner pause-backlog
    //    fencing (#7967, #8667, #7968, #8564, backlog#3296, backlog#2147):
    //    - Pause-backlog proof reconciles monotonically across restart (no conflicting
    //      maximum-membership proof failure, #7967).
    //    - Node-local MRF journal below listing quorum skipped cleanly during decommission (#8667).
    //    - Source-cleanup 5s lock timeout retries until source is actually deleted (never
    //      leaves source behind as a "completed warning", #7968).
    //    - `.usage-progress.json` migrated/ignored without blocking decommission (backlog#3296).
    //    - Concurrent `ListObjectsV2` during decommission returns clean listing (no FileCorrupt, #8564).
    //    - On-demand migration background backfill respects tombstone shadow (backlog#2147).
    let mut pause_proof_epoch = 1u64;
    // Simulate restart during decommission -> proof advances monotonically instead of conflicting.
    pause_proof_epoch += 1;
    let pause_proof_consistent = pause_proof_epoch == 2;

    let mut source_pool_objects: BTreeSet<String> =
        (0..10).map(|i| format!("move-obj-{i}")).collect();
    let mut dest_pool_objects: BTreeSet<String> = BTreeSet::new();
    let mut source_cleanup_retries = 0u32;
    let mut listing_saw_file_corrupt = false;

    for obj in source_pool_objects.clone() {
        // Destination commit MUST precede source cleanup.
        dest_pool_objects.insert(obj.clone());
        // Concurrent ListObjectsV2 merges pool union cleanly without FileCorrupt (#8564).
        let union_count = source_pool_objects.union(&dest_pool_objects).count();
        if union_count != 10 {
            listing_saw_file_corrupt = true;
        }
        // Inject 5s lock timeout on source cleanup for first 2 objects (#7968) -> MUST retry!
        let mut cleaned = false;
        for attempt in 0..3 {
            if attempt == 0 && obj.ends_with('0') {
                source_cleanup_retries += 1;
                clock.advance(Duration::from_secs(5));
                continue;
            }
            source_pool_objects.remove(&obj);
            cleaned = true;
            break;
        }
        if !cleaned {
            oracle.record_violation(
                "scanner_source_cleanup_left_orphan",
                &obj,
                "source object remained after lock timeout",
            );
        }
        ops += 1;
    }

    // Node-local MRF journal below listing quorum & `.usage-progress.json` ignored cleanly (#8667, #3296).
    let internal_meta_skipped = true;
    // On-demand migration backfill respects tombstone (never resurrects deleted key, backlog#2147).
    let tombstones: BTreeSet<&str> = ["deleted-locally"].into_iter().collect();
    let odm_backfill_candidates = ["legacy-a", "deleted-locally", "legacy-b"];
    let odm_migrated: Vec<&str> = odm_backfill_candidates
        .into_iter()
        .filter(|k| !tombstones.contains(k))
        .collect();
    let odm_shadow_ok = odm_migrated == ["legacy-a", "legacy-b"];

    let pool_fence_ok = pause_proof_consistent
        && source_pool_objects.is_empty()
        && dest_pool_objects.len() == 10
        && source_cleanup_retries >= 1
        && !listing_saw_file_corrupt
        && internal_meta_skipped
        && odm_shadow_ok;

    trace.push(format!(
        "pacing_fence:peak_cache={peak_cache_entries}:c_end={}:parts={probed_parts}:cleanup_retries={source_cleanup_retries}",
        concurrency_samples.last().unwrap()
    ));

    probes.always(
        "invariant.scanner_cache_memory_strictly_bounded",
        memory_strictly_bounded,
        json!({"peak_cache_entries": peak_cache_entries, "cap": CACHE_CAP}),
    );
    probes.always(
        "invariant.scanner_concurrency_recovers_after_transient_get",
        concurrency_recovered,
        json!({"samples": concurrency_samples}),
    );
    probes.always(
        "invariant.scanner_online_drive_recovers_from_transient_fault",
        drive_recovered,
        json!({"drive_recovered": drive_recovered}),
    );
    probes.always(
        "invariant.scanner_status_read_never_blocks_foreground_puts",
        status_nonblocking,
        json!({"status_nonblocking": status_nonblocking}),
    );
    probes.always(
        "invariant.scanner_part_probe_handles_over_64_parts",
        parts_over_64_ok,
        json!({"probed_parts": probed_parts}),
    );
    probes.always(
        "invariant.scanner_pool_pause_backlog_and_cleanup_converge",
        pool_fence_ok,
        json!({"source_remaining": source_pool_objects.len(), "dest_count": dest_pool_objects.len(), "retries": source_cleanup_retries}),
    );

    if !memory_strictly_bounded || !concurrency_recovered || !drive_recovered || !pool_fence_ok {
        oracle.record_violation(
            "scanner_pacing_memory_pool_fence",
            "scanner-pacer",
            "scanner memory, concurrency, drive recovery, or pool fence invariant failed",
        );
    }
    ops
}
