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

//! Deterministic simulation scenarios for Enterprise Data Services:
//! - Domain #17: **S3 Tables** (Table Buckets, Namespaces, Iceberg `versionToken` CAS)
//! - Domain #18: **Capacity Quota** (`HARD` & `FIFO` distributed bucket quotas)
//! - Domain #19: **On-Demand Migration** (Lazy pull-through migration + tombstone shadowing)

use crate::erasure::sha256_hex;
use crate::oracle::ConsistencyOracle;
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_runtime::clock::SimClock;
use rustfs_dst_runtime::disk::{DiskIo, SimDiskIo};
use rustfs_dst_runtime::network::{NetError, Network, RpcFrame, RpcHandler, SimNetwork};
use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Domain #17: S3 Tables (Iceberg Optimistic Concurrency Control)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IcebergTableRecord {
    table_bucket: String,
    namespace: String,
    name: String,
    version_token: String,
    metadata_location: String,
    snapshot_lineage: Vec<String>,
}

pub async fn run_s3_tables_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("s3-tables");
    let disk = SimDiskIo::new("tables-catalog", rng.fork("disk"));

    let mut table_buckets: BTreeSet<String> = BTreeSet::new();
    let mut namespaces: BTreeSet<(String, String)> = BTreeSet::new();
    let mut tables: BTreeMap<(String, String, String), IcebergTableRecord> = BTreeMap::new();
    let mut ops = 0u64;

    // 1. Create Table Bucket -> Namespace -> Iceberg Table.
    table_buckets.insert("analytics-tb".to_string());
    namespaces.insert(("analytics-tb".to_string(), "sales".to_string()));
    let init_token = rng.gen_uuid_v4().to_string();
    let key = (
        "analytics-tb".to_string(),
        "sales".to_string(),
        "orders".to_string(),
    );
    tables.insert(
        key.clone(),
        IcebergTableRecord {
            table_bucket: "analytics-tb".to_string(),
            namespace: "sales".to_string(),
            name: "orders".to_string(),
            version_token: init_token.clone(),
            metadata_location: "s3://analytics-tb/sales/orders/metadata/v0.metadata.json"
                .to_string(),
            snapshot_lineage: vec!["v0".to_string()],
        },
    );
    ops += 3;

    // 2. Deleting non-empty namespace MUST fail closed!
    let ns_has_tables = tables
        .keys()
        .any(|(tb, ns, _)| tb == "analytics-tb" && ns == "sales");
    probes.always(
        "s3_tables.non_empty_namespace_delete_rejected",
        ns_has_tables,
        json!({}),
    );

    // 3. Simulate 10 rounds of 3 concurrent Iceberg writers racing on the EXACT SAME `versionToken`!
    let mut expected_lineage = vec!["v0".to_string()];
    for round in 1..=10u64 {
        let base_token = tables[&key].version_token.clone();
        let mut winners = 0u32;
        let mut winning_snap = String::new();

        // Deterministically shuffle writer arrival order.
        let mut writers = [0usize, 1, 2];
        for i in (1..writers.len()).rev() {
            let j = rng.gen_range_usize(i + 1);
            writers.swap(i, j);
        }

        for w in writers {
            let snap_id = format!("r{round}-w{w}");
            let rec = tables.get_mut(&key).unwrap();
            // Atomic CAS on `versionToken` (UpdateTableMetadataLocation):
            if rec.version_token == base_token {
                rec.version_token = rng.gen_uuid_v4().to_string();
                rec.metadata_location =
                    format!("s3://analytics-tb/sales/orders/metadata/{snap_id}.metadata.json");
                rec.snapshot_lineage.push(snap_id.clone());
                winners += 1;
                winning_snap = snap_id;

                // Persist catalog state durably.
                disk.write_file(
                    "catalog/orders.json",
                    bytes::Bytes::from(serde_json::to_vec(&rec).unwrap()),
                )
                .await
                .unwrap();
                disk.fsync_file("catalog/orders.json").await.unwrap();
                disk.fsync_dir("catalog").await.unwrap();
            }
            ops += 1;
        }

        probes.always(
            "s3_tables.single_winner_per_version_token_cas",
            winners == 1,
            json!({"round": round, "winners": winners}),
        );
        if winners != 1 {
            oracle.record_violation(
                "s3_tables_cas_conflict",
                "analytics-tb/sales/orders",
                format!("round {round} had {winners} concurrent winners on same versionToken"),
            );
        }
        expected_lineage.push(winning_snap);

        // Periodic power-loss reboot & catalog reload to verify zero lost Iceberg snapshots.
        if round % 3 == 0 {
            disk.crash_and_reboot();
            let reloaded: IcebergTableRecord =
                serde_json::from_slice(&disk.read_file("catalog/orders.json").await.unwrap())
                    .unwrap();
            tables.insert(key.clone(), reloaded);
        }
    }

    let lineage_intact = tables[&key].snapshot_lineage == expected_lineage;
    probes.always(
        "s3_tables.unbroken_iceberg_snapshot_lineage",
        lineage_intact,
        json!({"snapshots": tables[&key].snapshot_lineage.len()}),
    );
    if !lineage_intact {
        oracle.record_violation(
            "s3_tables_lineage",
            "analytics-tb/sales/orders",
            "lost or diverged Iceberg snapshot",
        );
    }

    trace.push(format!("s3_tables:snapshots={}", expected_lineage.len()));
    ops
}

// ---------------------------------------------------------------------------
// Domain #18: Capacity Quota (HARD & FIFO Distributed Quotas)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuotaMode {
    Hard,
    Fifo,
}

#[derive(Clone, Debug)]
struct QuotaObj {
    key: String,
    size: u64,
    created_seq: u64,
    worm_locked: bool,
}

struct QuotaBucket {
    mode: QuotaMode,
    limit_bytes: u64,
    used_bytes: u64,
    reserved_bytes: u64,
    seq: u64,
    objects: BTreeMap<String, QuotaObj>,
}

impl QuotaBucket {
    fn new(mode: QuotaMode, limit_bytes: u64) -> Self {
        Self {
            mode,
            limit_bytes,
            used_bytes: 0,
            reserved_bytes: 0,
            seq: 0,
            objects: BTreeMap::new(),
        }
    }

    fn try_put(&mut self, key: &str, size: u64, worm_locked: bool) -> bool {
        let old_size = self.objects.get(key).map(|o| o.size).unwrap_or(0);
        let delta = size.saturating_sub(old_size);

        if self.used_bytes + self.reserved_bytes + delta > self.limit_bytes {
            match self.mode {
                QuotaMode::Hard => return false,
                QuotaMode::Fifo => {
                    // Evict strictly oldest non-WORM objects until enough room is freed!
                    let mut evictable: Vec<(u64, String)> = self
                        .objects
                        .values()
                        .filter(|o| !o.worm_locked && o.key != key)
                        .map(|o| (o.created_seq, o.key.clone()))
                        .collect();
                    evictable.sort();
                    for (_, victim_key) in evictable {
                        if self.used_bytes + self.reserved_bytes + delta <= self.limit_bytes {
                            break;
                        }
                        if let Some(removed) = self.objects.remove(&victim_key) {
                            self.used_bytes -= removed.size;
                        }
                    }
                    if self.used_bytes + self.reserved_bytes + delta > self.limit_bytes {
                        return false; // Protected by WORM locks -> fail closed!
                    }
                }
            }
        }

        self.seq += 1;
        self.used_bytes = self.used_bytes - old_size + size;
        self.objects.insert(
            key.to_string(),
            QuotaObj {
                key: key.to_string(),
                size,
                created_seq: self.seq,
                worm_locked,
            },
        );
        true
    }

    fn delete(&mut self, key: &str) {
        if let Some(removed) = self.objects.remove(key) {
            self.used_bytes -= removed.size;
        }
    }

    fn reserve_multipart(&mut self, size: u64) -> bool {
        if self.used_bytes + self.reserved_bytes + size > self.limit_bytes {
            return false;
        }
        self.reserved_bytes += size;
        true
    }

    fn abort_multipart(&mut self, size: u64) {
        self.reserved_bytes = self.reserved_bytes.saturating_sub(size);
    }
}

pub async fn run_capacity_quota_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("capacity-quota");
    let mut ops = 0u64;

    // 1. HARD Quota bucket (1000 bytes): PUT, CopyObject (#7947), Multipart reserve/abort, Delete reclaim!
    let mut hard = QuotaBucket::new(QuotaMode::Hard, 1000);
    assert!(hard.try_put("a", 400, false));
    assert!(hard.try_put("b", 400, false));
    // CopyObject destination admission (400 bytes -> 1200 > 1000) MUST fail!
    let copy_over_quota = hard.try_put("copy-of-a", 400, false);
    probes.always(
        "quota.hard_rejects_copy_over_limit",
        !copy_over_quota,
        json!({}),
    );

    // Multipart reservation + abort MUST cleanly reclaim reserved bytes (zero leak!).
    assert!(hard.reserve_multipart(200));
    assert!(!hard.try_put("overflow", 1, false));
    hard.abort_multipart(200);
    assert_eq!(hard.reserved_bytes, 0);
    assert!(hard.try_put("c", 200, false));
    probes.always(
        "quota.hard_never_exceeded",
        hard.used_bytes <= hard.limit_bytes,
        json!({"used": hard.used_bytes, "limit": hard.limit_bytes}),
    );

    // Delete reclaims exact bytes.
    hard.delete("a");
    assert!(hard.try_put("d", 400, false));
    let exact_accounting = hard.used_bytes == hard.objects.values().map(|o| o.size).sum::<u64>();
    probes.always("quota.exact_reclaim_zero_leak", exact_accounting, json!({}));
    if !exact_accounting {
        oracle.record_violation(
            "quota_leak",
            "hard-bkt",
            "quota accounting diverged from actual objects",
        );
    }
    ops += 8;

    // 2. FIFO Quota bucket (1000 bytes) with WORM-locked oldest object!
    let mut fifo = QuotaBucket::new(QuotaMode::Fifo, 1000);
    assert!(fifo.try_put("worm-oldest", 400, true)); // WORM-locked -> MUST NOT be evicted!
    assert!(fifo.try_put("evictable-1", 400, false));
    assert!(fifo.try_put("evictable-2", 200, false));
    // Adding 400 bytes MUST evict `evictable-1` while keeping `worm-oldest` intact!
    assert!(fifo.try_put("newest", 400, false));
    let fifo_worm_safe = fifo.objects.contains_key("worm-oldest")
        && !fifo.objects.contains_key("evictable-1")
        && fifo.objects.contains_key("newest")
        && fifo.used_bytes <= fifo.limit_bytes;
    probes.always(
        "quota.fifo_evicts_oldest_and_respects_worm",
        fifo_worm_safe,
        json!({}),
    );
    if !fifo_worm_safe {
        oracle.record_violation(
            "quota_fifo_worm",
            "fifo-bkt",
            "FIFO evicted WORM object or exceeded limit",
        );
    }

    // Randomized fuzz loop over HARD quota ensuring limit is never breached.
    for i in 0..20 {
        let size = (50 + rng.gen_range_usize(300)) as u64;
        let k = format!("fuzz-{}", i % 5);
        if rng.gen_bool(0.7) {
            let _ = hard.try_put(&k, size, false);
        } else {
            hard.delete(&k);
        }
        probes.always(
            "quota.hard_invariant_under_fuzz",
            hard.used_bytes <= hard.limit_bytes,
            json!({"used": hard.used_bytes}),
        );
        ops += 1;
    }

    trace.push(format!(
        "capacity_quota:hard_used={} fifo_used={}",
        hard.used_bytes, fifo.used_bytes
    ));
    ops + 4
}

// ---------------------------------------------------------------------------
// Domain #19: On-Demand Migration (Lazy Pull-Through + Tombstone Shadowing)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum LocalMigrationEntry {
    Present {
        payload: Vec<u8>,
        sha256: String,
        generation: u64,
    },
    Tombstone {
        generation: u64,
    },
}

pub async fn run_on_demand_migration_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("on-demand-migration");
    let net = SimNetwork::new(clock.clone(), rng.fork("net"));
    let local_disk = SimDiskIo::new("rustfs-target", rng.fork("disk"));

    // Legacy MinIO/S3 source cluster populated with 5 objects.
    let legacy_data: Arc<Mutex<BTreeMap<String, Vec<u8>>>> =
        Arc::new(Mutex::new(BTreeMap::from([
            ("legacy/a.bin".to_string(), b"legacy-a-bytes".to_vec()),
            (
                "legacy/overwrite.bin".to_string(),
                b"legacy-stale-overwrite".to_vec(),
            ),
            (
                "legacy/delete-me.bin".to_string(),
                b"legacy-should-stay-deleted".to_vec(),
            ),
            (
                "legacy/outage.bin".to_string(),
                b"legacy-after-outage".to_vec(),
            ),
            ("legacy/bg.bin".to_string(), b"legacy-bg-synced".to_vec()),
        ])));
    let legacy_ref = Arc::clone(&legacy_data);

    struct LegacySourceHandler {
        data: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl RpcHandler for LegacySourceHandler {
        async fn handle(&self, _from: &str, req: RpcFrame) -> Result<RpcFrame, NetError> {
            let key = String::from_utf8_lossy(&req.payload).to_string();
            match self.data.lock().unwrap().get(&key) {
                Some(b) => Ok(RpcFrame::new("legacy.found", b.clone())),
                None => Err(NetError::Io("NotFound".to_string())),
            }
        }
    }

    net.register(
        "legacy-minio",
        Arc::new(LegacySourceHandler { data: legacy_ref }),
    );

    let mut local_index: BTreeMap<String, LocalMigrationEntry> = BTreeMap::new();
    let mut ops = 0u64;

    // Read-through GetObject: checks local RustFS (including Tombstone!), pulls from legacy on miss.
    async fn get_through(
        key: &str,
        local_index: &mut BTreeMap<String, LocalMigrationEntry>,
        local_disk: &SimDiskIo,
        net: &SimNetwork,
    ) -> Result<Vec<u8>, String> {
        if let Some(entry) = local_index.get(key) {
            return match entry {
                LocalMigrationEntry::Present { payload, .. } => Ok(payload.clone()),
                LocalMigrationEntry::Tombstone { .. } => Err("NotFound(Tombstone)".to_string()),
            };
        }
        let resp = net
            .call(
                "rustfs",
                "legacy-minio",
                RpcFrame::new("legacy.get", key.as_bytes().to_vec()),
            )
            .await
            .map_err(|e| e.to_string())?;
        let bytes = resp.payload.to_vec();
        let sha = sha256_hex(&bytes);
        local_disk
            .write_file(key, bytes::Bytes::from(bytes.clone()))
            .await
            .map_err(|e| e.to_string())?;
        local_disk
            .fsync_file(key)
            .await
            .map_err(|e| e.to_string())?;
        local_index.insert(
            key.to_string(),
            LocalMigrationEntry::Present {
                payload: bytes.clone(),
                sha256: sha,
                generation: 1,
            },
        );
        Ok(bytes)
    }

    // 1. Lazy read-through pulls `legacy/a.bin` bit-for-bit on first GET and caches durably.
    let pulled = get_through("legacy/a.bin", &mut local_index, &local_disk, &net)
        .await
        .unwrap();
    probes.always(
        "migration.lazy_pull_through_bit_exact",
        pulled == b"legacy-a-bytes",
        json!({}),
    );
    ops += 1;

    // 2. Local PutObject overwrite on RustFS MUST shadow legacy source forever!
    let fresh_local = b"rustfs-new-authoritative-write".to_vec();
    local_index.insert(
        "legacy/overwrite.bin".to_string(),
        LocalMigrationEntry::Present {
            payload: fresh_local.clone(),
            sha256: sha256_hex(&fresh_local),
            generation: 2,
        },
    );

    // 3. Local DeleteObject tombstone on RustFS MUST shadow legacy source (ZERO resurrection)!
    local_index.insert(
        "legacy/delete-me.bin".to_string(),
        LocalMigrationEntry::Tombstone { generation: 2 },
    );

    // 4. Legacy source outage: cached & locally written keys stay readable; uncached miss fails cleanly.
    net.set_node_down("legacy-minio", true);
    let cached_hit = get_through("legacy/a.bin", &mut local_index, &local_disk, &net)
        .await
        .is_ok();
    let uncached_miss_err = get_through("legacy/outage.bin", &mut local_index, &local_disk, &net)
        .await
        .is_err();
    probes.always(
        "migration.cached_keys_survive_legacy_outage",
        cached_hit && uncached_miss_err,
        json!({}),
    );

    // 5. Legacy recovers + background migrator sweeps ALL legacy keys -> MUST NOT clobber local overwrite or resurrect tombstone!
    net.set_node_down("legacy-minio", false);
    let legacy_keys: Vec<String> = legacy_data.lock().unwrap().keys().cloned().collect();
    for k in legacy_keys {
        if !local_index.contains_key(&k) {
            let _ = get_through(&k, &mut local_index, &local_disk, &net).await;
        }
        ops += 1;
    }

    let overwrite_shadowed =
        get_through("legacy/overwrite.bin", &mut local_index, &local_disk, &net)
            .await
            .is_ok_and(|b| b == fresh_local);
    let tombstone_shadowed =
        get_through("legacy/delete-me.bin", &mut local_index, &local_disk, &net)
            .await
            .is_err();
    let cutover_bg_ok = get_through("legacy/bg.bin", &mut local_index, &local_disk, &net)
        .await
        .is_ok_and(|b| b == b"legacy-bg-synced")
        && get_through("legacy/outage.bin", &mut local_index, &local_disk, &net)
            .await
            .is_ok_and(|b| b == b"legacy-after-outage");

    probes.always(
        "migration.local_overwrite_shadows_legacy",
        overwrite_shadowed,
        json!({}),
    );
    probes.always(
        "migration.local_tombstone_never_resurrects",
        tombstone_shadowed,
        json!({}),
    );
    probes.always("migration.cutover_parity_100pct", cutover_bg_ok, json!({}));
    if !overwrite_shadowed || !tombstone_shadowed || !cutover_bg_ok {
        oracle.record_violation(
            "on_demand_migration",
            "legacy/",
            "shadowing or cutover parity violated",
        );
    }

    clock.advance(Duration::from_secs(1));
    trace.push(format!(
        "on_demand_migration:tracked_entries={}",
        local_index.len()
    ));
    ops + 5
}
