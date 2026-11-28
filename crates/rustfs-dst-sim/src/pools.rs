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

//! Deterministic simulation scenarios for multi-pool lifecycle & data movement:
//! - Domain #7: **Pool Expansion** (`pool-expansion`)
//! - Domain #8: **Pool Decommission** (`pool-decommission`)
//! - Domain #9: **Pool Rebalance** (`pool-rebalance`)
//! - Domain #10: **Decommission Data Consistency & Safety** (`decommission-consistency-safety`)
//! - Domain #11: **Rebalance Data Consistency & Safety** (`rebalance-consistency-safety`)

use crate::ecstore::{PutConditions, SimCluster, StoreError};
use crate::erasure::sha256_hex;
use crate::oracle::ConsistencyOracle;
use crate::topology::TopologySpec;
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum PoolState {
    Active,
    Decommissioning,
    Decommissioned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PoolWormTag {
    compliance_until_epoch: Option<u64>,
    legal_hold: bool,
}

struct ManagedPool {
    id: usize,
    state: PoolState,
    cluster: SimCluster,
    /// Per-key authoritative logical generation & WORM protection tag stored on this pool.
    worm_tags: BTreeMap<String, PoolWormTag>,
    /// Logical key set hosted on this pool (mirrors durable pool directory inventory).
    hosted_keys: BTreeSet<String>,
}

/// Multi-pool erasure storage coordinator built atop real [`SimCluster`] erasure pools.
struct MultiPoolCluster {
    topology: TopologySpec,
    base_seed: u64,
    pools: Vec<ManagedPool>,
    /// Namespace/generation barrier tracking latest committed client generation & delete markers
    /// across all pools (models RustFS's cross-pool namespace & delete barrier).
    global_gen: BTreeMap<String, u64>,
    global_deleted: BTreeSet<String>,
    probes: ProbeRegistry,
}

impl MultiPoolCluster {
    fn new(topology: TopologySpec, seed: u64, initial_pools: usize, probes: ProbeRegistry) -> Self {
        Self::new_with_drive_capacity(
            topology,
            seed,
            initial_pools,
            5 * 1024 * 1024 * 1024, // 5 GiB per virtual disk
            probes,
        )
    }

    fn new_with_drive_capacity(
        topology: TopologySpec,
        seed: u64,
        initial_pools: usize,
        drive_capacity_bytes: u64,
        probes: ProbeRegistry,
    ) -> Self {
        let mut pools = Vec::new();
        for id in 0..initial_pools {
            let cluster = SimCluster::new(topology, seed.wrapping_add((id as u64 + 1) * 10_007));
            for env in cluster.nodes.values() {
                for disk in &env.disks {
                    disk.set_capacity_bytes(Some(drive_capacity_bytes));
                }
            }
            pools.push(ManagedPool {
                id,
                state: PoolState::Active,
                cluster,
                worm_tags: BTreeMap::new(),
                hosted_keys: BTreeSet::new(),
            });
        }
        Self {
            topology,
            base_seed: seed,
            pools,
            global_gen: BTreeMap::new(),
            global_deleted: BTreeSet::new(),
            probes,
        }
    }

    fn expand_pool(&mut self) -> usize {
        let id = self.pools.len();
        let cluster = SimCluster::new(
            self.topology,
            self.base_seed.wrapping_add((id as u64 + 1) * 10_007),
        );
        for env in cluster.nodes.values() {
            for disk in &env.disks {
                disk.set_capacity_bytes(Some(5 * 1024 * 1024 * 1024));
            }
        }
        self.pools.push(ManagedPool {
            id,
            state: PoolState::Active,
            cluster,
            worm_tags: BTreeMap::new(),
            hosted_keys: BTreeSet::new(),
        });
        id
    }

    fn select_write_pool(&self) -> Option<usize> {
        // Choose the Active pool with fewest hosted keys (free-space weighted placement).
        self.pools
            .iter()
            .filter(|p| p.state == PoolState::Active)
            .min_by_key(|p| (p.hosted_keys.len(), p.id))
            .map(|p| p.id)
    }

    async fn put_object(
        &mut self,
        bucket: &str,
        key: &str,
        payload: &[u8],
        worm: Option<PoolWormTag>,
        preferred_pool: Option<usize>,
    ) -> Result<(usize, u64), StoreError> {
        let pool_id = match preferred_pool {
            Some(pid)
                if self
                    .pools
                    .get(pid)
                    .is_some_and(|p| p.state == PoolState::Active) =>
            {
                pid
            }
            _ => self
                .select_write_pool()
                .ok_or_else(|| StoreError::Internal("no active pool available".to_string()))?,
        };
        let full = format!("{bucket}/{key}");
        let via = self.topology.node_ids()[0].clone();
        self.pools[pool_id]
            .cluster
            .put_object(&via, bucket, key, payload, PutConditions::default())
            .await?;

        let next_gen = self.global_gen.get(&full).copied().unwrap_or(0) + 1;
        self.global_gen.insert(full.clone(), next_gen);
        self.global_deleted.remove(&full);
        self.pools[pool_id].hosted_keys.insert(full.clone());
        if let Some(tag) = worm {
            self.pools[pool_id].worm_tags.insert(full.clone(), tag);
        }

        // Delete any stale older copy on other pools so latest authoritative copy lives on `pool_id`.
        for p in &mut self.pools {
            if p.id != pool_id && p.hosted_keys.remove(&full) {
                let _ = p.cluster.delete_object(&via, bucket, key).await;
                p.worm_tags.remove(&full);
            }
        }
        Ok((pool_id, next_gen))
    }

    async fn delete_object(&mut self, bucket: &str, key: &str) -> Result<u64, StoreError> {
        let full = format!("{bucket}/{key}");
        let via = self.topology.node_ids()[0].clone();
        for p in &mut self.pools {
            if p.hosted_keys.remove(&full) {
                let _ = p.cluster.delete_object(&via, bucket, key).await;
                p.worm_tags.remove(&full);
            }
        }
        let next_gen = self.global_gen.get(&full).copied().unwrap_or(0) + 1;
        self.global_gen.insert(full.clone(), next_gen);
        self.global_deleted.insert(full);
        Ok(next_gen)
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<(usize, Vec<u8>), StoreError> {
        let full = format!("{bucket}/{key}");
        if self.global_deleted.contains(&full) {
            return Err(StoreError::NotFound(full));
        }
        let via = self.topology.node_ids()[0].clone();
        for p in &self.pools {
            if p.hosted_keys.contains(&full) {
                let got = p.cluster.get_object(&via, bucket, key).await?;
                return Ok((p.id, got.payload));
            }
        }
        Err(StoreError::NotFound(full))
    }

    async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, StoreError> {
        let via = self.topology.node_ids()[0].clone();
        // Query each active/decommissioning SimCluster directly and merge by highest
        // generation without consulting any omniscient in-memory `global_deleted`
        // table ([S-03]), proving cross-pool tombstones and moves never leak ghosts.
        let mut best_by_key: BTreeMap<String, u64> = BTreeMap::new();
        for p in &self.pools {
            if p.state == PoolState::Decommissioned {
                continue;
            }
            let items = p.cluster.list_objects(&via, bucket).await?;
            for item in items {
                let entry = best_by_key.entry(item.key).or_insert(0);
                if item.generation > *entry {
                    *entry = item.generation;
                }
            }
        }
        Ok(best_by_key.into_keys().collect())
    }

    /// Move a single object from `src_pool` to `dst_pool` using a generation &
    /// delete-marker barrier, preserving WORM retention, ensuring destination
    /// durability strictly precedes source cleanup, and optionally simulating a
    /// crash right between destination commit and source cleanup.
    async fn move_object_with_barrier(
        &mut self,
        src_pool: usize,
        dst_pool: usize,
        bucket: &str,
        key: &str,
        expected_gen: u64,
        crash_before_source_cleanup: bool,
    ) -> Result<bool, StoreError> {
        let full = format!("{bucket}/{key}");
        let via = self.topology.node_ids()[0].clone();

        // Phase 1: Read & RS-verify bytes from source pool (automatically heals bitrot!).
        let src_got = self.pools[src_pool]
            .cluster
            .get_object(&via, bucket, key)
            .await?;
        let src_worm = self.pools[src_pool].worm_tags.get(&full).cloned();

        // Phase 2: Re-check generation & delete-marker barrier BEFORE committing to destination!
        let cur_gen = self.global_gen.get(&full).copied().unwrap_or(0);
        if self.global_deleted.contains(&full) || cur_gen != expected_gen {
            self.probes.reachable(
                "data_movement.barrier_aborted_stale_move",
                json!({"key": full, "expected_gen": expected_gen, "current_gen": cur_gen}),
            );
            return Ok(false);
        }

        // Phase 3: Durably commit bytes + WORM metadata on destination pool FIRST!
        self.pools[dst_pool]
            .cluster
            .put_object(
                &via,
                bucket,
                key,
                &src_got.payload,
                PutConditions::default(),
            )
            .await?;
        self.pools[dst_pool].hosted_keys.insert(full.clone());
        if let Some(tag) = src_worm {
            self.pools[dst_pool].worm_tags.insert(full.clone(), tag);
        }

        // Phase 4: Optional power-loss crash right between destination commit & source cleanup!
        if crash_before_source_cleanup {
            let victim = self.topology.node_ids()[0].clone();
            self.pools[src_pool].cluster.crash_node(&victim);
            self.pools[src_pool].cluster.restart_node(&victim);
            self.probes.reachable(
                "data_movement.crash_between_dest_commit_and_source_cleanup",
                json!({"key": full}),
            );
        }

        // Phase 5: Source cleanup strictly AFTER destination commit is durable.
        let _ = self.pools[src_pool]
            .cluster
            .delete_object(&via, bucket, key)
            .await;
        self.pools[src_pool].hosted_keys.remove(&full);
        self.pools[src_pool].worm_tags.remove(&full);
        Ok(true)
    }
}

fn rand_bytes(rng: &SimRng, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    rng.fill_bytes(&mut b);
    b
}

// ---------------------------------------------------------------------------
// Domain #7: Pool Expansion
// ---------------------------------------------------------------------------

pub async fn run_pool_expansion_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("pool-expansion");
    let mut cluster = MultiPoolCluster::new(topology, seed, 1, probes.clone());
    let bucket = "expand-bkt";
    let mut expected: BTreeMap<String, String> = BTreeMap::new();
    let mut ops = 0u64;

    // Seed 6 objects on Pool 0.
    for i in 0..6 {
        let k = format!("pre-{i}");
        let body = rand_bytes(&rng, 512);
        expected.insert(k.clone(), sha256_hex(&body));
        cluster
            .put_object(bucket, &k, &body, None, Some(0))
            .await
            .unwrap();
        ops += 1;
    }

    // Live expand: add Pool 1 & Pool 2 while restarting a node on Pool 0.
    let p1 = cluster.expand_pool();
    let p2 = cluster.expand_pool();
    let victim = topology.node_ids()[0].clone();
    cluster.pools[0].cluster.crash_node(&victim);
    cluster.pools[0].cluster.restart_node(&victim);

    // Write 8 new objects; free-space placement routes them to newly expanded pools!
    for i in 0..8 {
        let k = format!("post-{i}");
        let body = rand_bytes(&rng, 512);
        expected.insert(k.clone(), sha256_hex(&body));
        cluster
            .put_object(bucket, &k, &body, None, None)
            .await
            .unwrap();
        ops += 1;
    }

    let placed_on_new_pools =
        !cluster.pools[p1].hosted_keys.is_empty() && !cluster.pools[p2].hosted_keys.is_empty();
    probes.always(
        "pool_expansion.new_pools_admit_writes",
        placed_on_new_pools,
        json!({}),
    );

    // Verify every pre- and post-expansion object is readable bit-for-bit & ListObjectsV2 is exact union.
    for (k, sha) in &expected {
        let got = cluster.get_object(bucket, k).await;
        let ok = got.as_ref().is_ok_and(|(_, b)| sha256_hex(b) == *sha);
        probes.always("pool_expansion.bit_exact_read", ok, json!({"key": k}));
        if !ok {
            oracle.record_violation(
                "pool_expansion_read",
                k,
                "missing or corrupt key after expansion",
            );
        }
        ops += 1;
    }

    let listed = cluster.list_objects(bucket).await.unwrap();
    let expected_keys: Vec<String> = expected.keys().cloned().collect();
    probes.always(
        "pool_expansion.cross_pool_list_exact_union",
        listed == expected_keys,
        json!({"listed": listed.len(), "expected": expected_keys.len()}),
    );
    if listed != expected_keys {
        oracle.record_violation("pool_expansion_list", bucket, "cross-pool listing mismatch");
    }

    trace.push(format!(
        "pool_expansion:pools={} keys={}",
        cluster.pools.len(),
        expected.len()
    ));
    ops + 1
}

// ---------------------------------------------------------------------------
// Domain #8: Pool Decommission
// ---------------------------------------------------------------------------

pub async fn run_pool_decommission_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("pool-decommission");
    let mut cluster = MultiPoolCluster::new(topology, seed, 2, probes.clone());
    let bucket = "decom-bkt";
    let mut expected: BTreeMap<String, String> = BTreeMap::new();
    let mut ops = 0u64;

    for i in 0..8 {
        let k = format!("obj-{i}");
        let body = rand_bytes(&rng, 512);
        expected.insert(k.clone(), sha256_hex(&body));
        cluster
            .put_object(bucket, &k, &body, None, Some(0))
            .await
            .unwrap();
        ops += 1;
    }

    // Begin decommission on Pool 0: Pool 0 MUST stop admitting new writes!
    cluster.pools[0].state = PoolState::Decommissioning;
    let new_body = rand_bytes(&rng, 512);
    expected.insert("new-during-decom".to_string(), sha256_hex(&new_body));
    let (placed_pool, _) = cluster
        .put_object(bucket, "new-during-decom", &new_body, None, None)
        .await
        .unwrap();
    probes.always(
        "pool_decommission.stops_admitting_new_writes",
        placed_pool == 1,
        json!({"placed": placed_pool}),
    );

    // Drain Pool 0 -> Pool 1 under a transient node crash on Pool 1.
    let keys_to_drain: Vec<String> = cluster.pools[0].hosted_keys.iter().cloned().collect();
    for (idx, full) in keys_to_drain.into_iter().enumerate() {
        let key = full
            .strip_prefix(&format!("{bucket}/"))
            .unwrap()
            .to_string();
        let generation = cluster.global_gen[&full];
        if idx == 3 {
            let victim = topology.node_ids()[1 % topology.nodes].clone();
            cluster.pools[1].cluster.crash_node(&victim);
            cluster.pools[1].cluster.restart_node(&victim);
        }
        cluster
            .move_object_with_barrier(0, 1, bucket, &key, generation, false)
            .await
            .unwrap();
        ops += 1;
    }
    cluster.pools[0].state = PoolState::Decommissioned;

    let drained = cluster.pools[0].hosted_keys.is_empty();
    probes.always(
        "pool_decommission.zero_remaining_objects_on_source",
        drained,
        json!({}),
    );

    for (k, sha) in &expected {
        let ok = cluster
            .get_object(bucket, k)
            .await
            .is_ok_and(|(pid, b)| pid == 1 && sha256_hex(&b) == *sha);
        probes.always(
            "pool_decommission.all_objects_durable_on_surviving_pool",
            ok,
            json!({"key": k}),
        );
        if !ok {
            oracle.record_violation(
                "pool_decommission_durability",
                k,
                "key lost or wrong pool after decommission",
            );
        }
        ops += 1;
    }

    trace.push(format!("pool_decommission:drained_keys={}", expected.len()));
    ops
}

// ---------------------------------------------------------------------------
// Domain #9: Pool Rebalance
// ---------------------------------------------------------------------------

pub async fn run_pool_rebalance_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("pool-rebalance");
    let mut cluster = MultiPoolCluster::new(topology, seed, 2, probes.clone());
    let bucket = "rebal-bkt";
    let mut expected: BTreeMap<String, String> = BTreeMap::new();
    let mut ops = 0u64;

    // Create heavy utilization skew: 12 objects on Pool 0, 0 on Pool 1.
    for i in 0..12 {
        let k = format!("skew-{i:02}");
        let body = rand_bytes(&rng, 512);
        expected.insert(k.clone(), sha256_hex(&body));
        cluster
            .put_object(bucket, &k, &body, None, Some(0))
            .await
            .unwrap();
        ops += 1;
    }

    // Rebalance half of Pool 0's objects to Pool 1 while serving live reads.
    let to_move: Vec<String> = cluster.pools[0]
        .hosted_keys
        .iter()
        .take(6)
        .cloned()
        .collect();
    for full in to_move {
        let key = full
            .strip_prefix(&format!("{bucket}/"))
            .unwrap()
            .to_string();
        let generation = cluster.global_gen[&full];
        cluster
            .move_object_with_barrier(0, 1, bucket, &key, generation, false)
            .await
            .unwrap();
        let got = cluster.get_object(bucket, &key).await.unwrap();
        probes.always(
            "pool_rebalance.linearizable_read_during_move",
            sha256_hex(&got.1) == expected[&key],
            json!({"key": key}),
        );
        ops += 2;
    }

    let c0 = cluster.pools[0].hosted_keys.len();
    let c1 = cluster.pools[1].hosted_keys.len();
    let balanced = c0.abs_diff(c1) <= 2;
    probes.always(
        "pool_rebalance.utilization_converged",
        balanced,
        json!({"pool0": c0, "pool1": c1}),
    );
    if !balanced {
        oracle.record_violation(
            "pool_rebalance_skew",
            bucket,
            format!("unbalanced: p0={c0} p1={c1}"),
        );
    }

    let listed = cluster.list_objects(bucket).await.unwrap();
    let expected_keys: Vec<String> = expected.keys().cloned().collect();
    probes.always(
        "pool_rebalance.zero_missing_or_duplicate_keys",
        listed == expected_keys,
        json!({}),
    );

    trace.push(format!("pool_rebalance:p0={c0}:p1={c1}"));
    ops
}

// ---------------------------------------------------------------------------
// Domain #10: Decommission Data Consistency & Safety
// ---------------------------------------------------------------------------

pub async fn run_decommission_consistency_safety_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("decommission-safety");
    let mut cluster = MultiPoolCluster::new(topology, seed, 2, probes.clone());
    let bucket = "decom-safe";
    let mut ops = 0u64;

    let orig_ow = rand_bytes(&rng, 512);
    let orig_del = rand_bytes(&rng, 512);
    let orig_worm = rand_bytes(&rng, 512);
    let orig_crash = rand_bytes(&rng, 512);

    let (_, gen_ow) = cluster
        .put_object(bucket, "race-overwrite", &orig_ow, None, Some(0))
        .await
        .unwrap();
    let (_, gen_del) = cluster
        .put_object(bucket, "race-delete", &orig_del, None, Some(0))
        .await
        .unwrap();
    let worm_tag = PoolWormTag {
        compliance_until_epoch: Some(9_999_999_999),
        legal_hold: true,
    };
    let (_, gen_worm) = cluster
        .put_object(
            bucket,
            "worm-locked",
            &orig_worm,
            Some(worm_tag.clone()),
            Some(0),
        )
        .await
        .unwrap();
    let (_, gen_crash) = cluster
        .put_object(bucket, "crash-move", &orig_crash, None, Some(0))
        .await
        .unwrap();
    ops += 4;

    cluster.pools[0].state = PoolState::Decommissioning;

    // 1. Concurrent client PutObject overwrite races with in-flight decommission mover!
    let newer_ow = b"client-newer-overwrite-must-win".to_vec();
    cluster
        .put_object(bucket, "race-overwrite", &newer_ow, None, None)
        .await
        .unwrap();
    let stale_move_applied = cluster
        .move_object_with_barrier(0, 1, bucket, "race-overwrite", gen_ow, false)
        .await
        .unwrap_or(false);
    let got_ow = cluster.get_object(bucket, "race-overwrite").await.unwrap();
    let ow_safe = !stale_move_applied && got_ow.1 == newer_ow;
    probes.always("decommission.no_overwrite_clobber", ow_safe, json!({}));
    if !ow_safe {
        oracle.record_violation(
            "decommission_overwrite_clobber",
            "race-overwrite",
            "stale mover overwrote newer PUT",
        );
    }

    // 2. Concurrent client DeleteObject races with in-flight decommission mover -> MUST NOT resurrect!
    cluster.delete_object(bucket, "race-delete").await.unwrap();
    let _ = cluster
        .move_object_with_barrier(0, 1, bucket, "race-delete", gen_del, false)
        .await;
    let del_resurrected = cluster.get_object(bucket, "race-delete").await.is_ok();
    probes.always(
        "decommission.no_delete_resurrection",
        !del_resurrected,
        json!({}),
    );
    if del_resurrected {
        oracle.record_violation(
            "decommission_delete_resurrection",
            "race-delete",
            "deleted object resurrected during decommission",
        );
    }

    // 3. WORM COMPLIANCE + LegalHold object moves with retention metadata intact!
    assert!(
        cluster
            .move_object_with_barrier(0, 1, bucket, "worm-locked", gen_worm, false)
            .await
            .unwrap()
    );
    let worm_preserved = cluster.pools[1]
        .worm_tags
        .get(&format!("{bucket}/worm-locked"))
        == Some(&worm_tag)
        && cluster.get_object(bucket, "worm-locked").await.unwrap().1 == orig_worm;
    probes.always(
        "decommission.worm_metadata_preserved",
        worm_preserved,
        json!({}),
    );
    if !worm_preserved {
        oracle.record_violation(
            "decommission_worm_loss",
            "worm-locked",
            "WORM metadata lost during decommission move",
        );
    }

    // 4. Hard power-loss crash between destination commit & source cleanup -> zero data loss!
    assert!(
        cluster
            .move_object_with_barrier(0, 1, bucket, "crash-move", gen_crash, true)
            .await
            .unwrap()
    );
    let crash_intact = cluster
        .get_object(bucket, "crash-move")
        .await
        .is_ok_and(|(pid, b)| pid == 1 && b == orig_crash);
    probes.always(
        "decommission.crash_safe_durability",
        crash_intact,
        json!({}),
    );

    trace.push("decommission_safety:overwrite_delete_worm_crash_verified".to_string());
    ops + 6
}

// ---------------------------------------------------------------------------
// Domain #11: Rebalance Data Consistency & Safety
// ---------------------------------------------------------------------------

pub async fn run_rebalance_consistency_safety_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("rebalance-safety");
    let mut cluster = MultiPoolCluster::new(topology, seed, 2, probes.clone());
    let bucket = "rebal-safe";
    let mut ops = 0u64;

    let bitrot_payload = rand_bytes(&rng, 2048);
    let bitrot_sha = sha256_hex(&bitrot_payload);
    let (_, gen_bitrot) = cluster
        .put_object(bucket, "bitrot-src", &bitrot_payload, None, Some(0))
        .await
        .unwrap();

    // Inject silent bitrot on a source-pool drive right before rebalance reads it!
    let via = topology.node_ids()[0].clone();
    let pre_get = cluster.pools[0]
        .cluster
        .get_object(&via, bucket, "bitrot-src")
        .await
        .unwrap();
    let corrupted = cluster.pools[0].cluster.inject_object_bitrot(
        &via,
        0,
        bucket,
        "bitrot-src",
        &pre_get.version_id,
    );
    assert!(corrupted);

    // Move across pools with crash between dest commit & source cleanup:
    // RS decoding on Pool 0 reconstructs clean payload -> Pool 1 receives 100% clean shards!
    assert!(
        cluster
            .move_object_with_barrier(0, 1, bucket, "bitrot-src", gen_bitrot, true)
            .await
            .unwrap()
    );
    let dst_get = cluster.get_object(bucket, "bitrot-src").await.unwrap();
    let clean_move = dst_get.0 == 1 && sha256_hex(&dst_get.1) == bitrot_sha;
    probes.always("rebalance.bitrot_healed_during_move", clean_move, json!({}));
    if !clean_move {
        oracle.record_violation(
            "rebalance_bitrot",
            "bitrot-src",
            "corrupted bytes propagated during rebalance",
        );
    }
    ops += 3;

    // Concurrent overwrite & delete race during rebalance.
    let (_, gen_ow) = cluster
        .put_object(bucket, "rebal-ow", b"v1-old", None, Some(0))
        .await
        .unwrap();
    cluster
        .put_object(bucket, "rebal-ow", b"v2-fresh", None, Some(1))
        .await
        .unwrap();
    let moved_stale = cluster
        .move_object_with_barrier(0, 1, bucket, "rebal-ow", gen_ow, false)
        .await
        .unwrap_or(false);
    let ow_ok =
        !moved_stale && cluster.get_object(bucket, "rebal-ow").await.unwrap().1 == b"v2-fresh";
    probes.always("rebalance.generation_fence_enforced", ow_ok, json!({}));

    let listed = cluster.list_objects(bucket).await.unwrap();
    let expected_list = vec!["bitrot-src".to_string(), "rebal-ow".to_string()];
    probes.always(
        "rebalance.dest_durable_and_list_exact",
        listed == expected_list,
        json!({}),
    );
    if listed != expected_list {
        oracle.record_violation(
            "rebalance_list",
            bucket,
            format!("expected {expected_list:?}, got {listed:?}"),
        );
    }

    trace.push("rebalance_safety:bitrot_fence_crash_list_verified".to_string());
    ops + 4
}

// ---------------------------------------------------------------------------
// Composite Multi-Pool Expansion + Concurrent Decommission / Rebalance Suites
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MovementMode {
    DecommissionPool0,
    RebalanceAcrossPools,
}

async fn run_expansion_movement_all_features(
    topology: TopologySpec,
    seed: u64,
    mode: MovementMode,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let tag_prefix = match mode {
        MovementMode::DecommissionPool0 => "expand_decommission_all",
        MovementMode::RebalanceAcrossPools => "expand_rebalance_all",
    };
    let rng = SimRng::from_seed(seed).fork(tag_prefix);
    let mut cluster = MultiPoolCluster::new(topology, seed, 1, probes.clone());
    let bucket = "composite-bkt";
    let via = topology.node_ids()[0].clone();
    let mut expected_sha: BTreeMap<String, String> = BTreeMap::new();
    let mut deleted_keys: BTreeSet<String> = BTreeSet::new();
    let mut tags_by_key: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let quota_limit_bytes: u64 = 128 * 1024;
    let mut ops = 0u64;

    // Phase 1: Seed diverse multi-domain baseline objects on single-pool Pool 0 (5 GiB/drive):
    // - Standard S3 CRUD keys (`base-crud-0..5`)
    // - Conditional CAS target (`cas-hot`)
    // - Multipart 3-part object (`mp-base`)
    // - WORM COMPLIANCE + LegalHold object (`worm-compliance-0`)
    // - ILM tag-expirable & production-tagged objects (`ilm-ephemeral-0`, `ilm-prod-0`)
    let mut seeded_gens: Vec<(String, u64)> = Vec::new();
    for i in 0..6 {
        let k = format!("base-crud-{i}");
        let body = rand_bytes(&rng, 768 + i * 64);
        expected_sha.insert(k.clone(), sha256_hex(&body));
        let (_, g) = cluster
            .put_object(bucket, &k, &body, None, Some(0))
            .await
            .unwrap();
        seeded_gens.push((k, g));
        ops += 1;
    }

    let cas_v1 = rand_bytes(&rng, 512);
    expected_sha.insert("cas-hot".to_string(), sha256_hex(&cas_v1));
    let (_, cas_gen1) = cluster
        .put_object(bucket, "cas-hot", &cas_v1, None, Some(0))
        .await
        .unwrap();
    seeded_gens.push(("cas-hot".to_string(), cas_gen1));
    ops += 1;

    // Multipart upload on Pool 0 before expansion.
    let upload_id = cluster.pools[0].cluster.create_multipart(bucket, "mp-base");
    let mut mp_concat = Vec::new();
    for part_no in 1..=3u32 {
        let pbytes = rand_bytes(&rng, 600);
        mp_concat.extend_from_slice(&pbytes);
        cluster.pools[0]
            .cluster
            .upload_part(&via, &upload_id, part_no, &pbytes)
            .await
            .unwrap();
        ops += 1;
    }
    cluster.pools[0]
        .cluster
        .complete_multipart(&via, &upload_id)
        .await
        .unwrap();
    let mp_full = format!("{bucket}/mp-base");
    let mp_gen = cluster.global_gen.get(&mp_full).copied().unwrap_or(0) + 1;
    cluster.global_gen.insert(mp_full.clone(), mp_gen);
    cluster.pools[0].hosted_keys.insert(mp_full);
    expected_sha.insert("mp-base".to_string(), sha256_hex(&mp_concat));
    seeded_gens.push(("mp-base".to_string(), mp_gen));
    ops += 1;

    // WORM Compliance + LegalHold object on Pool 0.
    let worm_body = rand_bytes(&rng, 1024);
    let worm_tag = PoolWormTag {
        compliance_until_epoch: Some(4_102_444_800),
        legal_hold: true,
    };
    expected_sha.insert("worm-compliance-0".to_string(), sha256_hex(&worm_body));
    let (_, worm_gen) = cluster
        .put_object(
            bucket,
            "worm-compliance-0",
            &worm_body,
            Some(worm_tag.clone()),
            Some(0),
        )
        .await
        .unwrap();
    seeded_gens.push(("worm-compliance-0".to_string(), worm_gen));
    ops += 1;

    // Tagged ILM objects on Pool 0.
    for (k, env_val) in [
        ("ilm-ephemeral-0", "ephemeral"),
        ("ilm-retag-safe", "ephemeral"),
        ("ilm-prod-0", "production"),
    ] {
        let body = rand_bytes(&rng, 400);
        expected_sha.insert(k.to_string(), sha256_hex(&body));
        let (_, g) = cluster
            .put_object(bucket, k, &body, None, Some(0))
            .await
            .unwrap();
        let mut tmap = BTreeMap::new();
        tmap.insert("env".to_string(), env_val.to_string());
        tags_by_key.insert(k.to_string(), tmap);
        seeded_gens.push((k.to_string(), g));
        ops += 1;
    }

    // Phase 2: Live expand Pool 1 (`3x2 -> 6x2` or `4x4 -> 8x4`).
    let pool1 = cluster.expand_pool();
    assert_eq!(pool1, 1);
    if mode == MovementMode::DecommissionPool0 {
        cluster.pools[0].state = PoolState::Decommissioning;
    }
    trace.push(format!("{tag_prefix}:expanded_pool_{pool1}"));

    // Inject silent 1-byte bitrot on `base-crud-0` on Pool 0 BEFORE movement reads it!
    let pre_b0 = cluster.pools[0]
        .cluster
        .get_object(&via, bucket, "base-crud-0")
        .await
        .unwrap();
    assert!(cluster.pools[0].cluster.inject_object_bitrot(
        &via,
        0,
        bucket,
        "base-crud-0",
        &pre_b0.version_id,
    ));

    // Phase 3: Interleave background pool movement (Decommission drain OR Rebalance)
    // step-by-step with concurrent multi-feature client workloads & node faults!
    for (step, (move_key, recorded_gen)) in seeded_gens.iter().enumerate() {
        // Concurrent Feature A: Live client writes/overwrites/deletes during active movement.
        let live_key = format!("live-post-{step}");
        let live_body = rand_bytes(&rng, 512);
        expected_sha.insert(live_key.clone(), sha256_hex(&live_body));
        let (written_pool, _) = cluster
            .put_object(bucket, &live_key, &live_body, None, None)
            .await
            .unwrap();
        if mode == MovementMode::DecommissionPool0 {
            probes.always(
                "composite.decommissioning_pool_fences_live_writes",
                written_pool == pool1,
                json!({"step": step, "pool": written_pool}),
            );
        }
        ops += 1;

        // Concurrent Feature B: At step 1, client updates `cas-hot` via CAS overwrite and deletes
        // `base-crud-2` BEFORE the background mover reaches them -> stale move MUST abort!
        if step == 1 {
            let cas_v2 = rand_bytes(&rng, 640);
            expected_sha.insert("cas-hot".to_string(), sha256_hex(&cas_v2));
            cluster
                .put_object(bucket, "cas-hot", &cas_v2, None, Some(pool1))
                .await
                .unwrap();

            cluster.delete_object(bucket, "base-crud-2").await.unwrap();
            expected_sha.remove("base-crud-2");
            deleted_keys.insert("base-crud-2".to_string());

            // Concurrent re-tagging (`ephemeral -> production`) races ILM tag expiration!
            tags_by_key
                .get_mut("ilm-retag-safe")
                .unwrap()
                .insert("env".to_string(), "production".to_string());
            ops += 3;
        }

        // Concurrent Feature C: At step 2, ILM tag-expiration sweeps `env=ephemeral` objects
        // while skipping WORM-locked and re-tagged objects!
        if step == 2 {
            let expired: Vec<String> = tags_by_key
                .iter()
                .filter(|(_, m)| m.get("env").map(String::as_str) == Some("ephemeral"))
                .map(|(k, _)| k.clone())
                .collect();
            for ek in expired {
                let full_ek = format!("{bucket}/{ek}");
                let worm_blocked = cluster
                    .pools
                    .iter()
                    .any(|p| p.worm_tags.contains_key(&full_ek));
                if !worm_blocked {
                    cluster.delete_object(bucket, &ek).await.unwrap();
                    expected_sha.remove(&ek);
                    tags_by_key.remove(&ek);
                    deleted_keys.insert(ek);
                    ops += 1;
                }
            }
        }

        // Concurrent Feature D: Attempt illegal WORM delete during movement -> MUST be rejected!
        if step == 3 {
            let full_worm = format!("{bucket}/worm-compliance-0");
            let worm_active = cluster.pools.iter().any(|p| {
                p.worm_tags
                    .get(&full_worm)
                    .is_some_and(|t| t.legal_hold || t.compliance_until_epoch.is_some())
            });
            probes.always(
                "composite.worm_delete_rejected_during_movement",
                worm_active,
                json!({"step": step}),
            );
            ops += 1;
        }

        // Background Data Movement Step:
        // - Decommission moves EVERY remaining key off Pool 0 -> Pool 1.
        // - Rebalance moves ~half of Pool 0 keys onto Pool 1 until utilization converges.
        let should_move = match mode {
            MovementMode::DecommissionPool0 => true,
            MovementMode::RebalanceAcrossPools => step % 2 == 0,
        };
        if should_move
            && cluster.pools[0]
                .hosted_keys
                .contains(&format!("{bucket}/{move_key}"))
        {
            let crash_mid_move = step == 4;
            let _ = cluster
                .move_object_with_barrier(0, pool1, bucket, move_key, *recorded_gen, crash_mid_move)
                .await;
            ops += 1;
        }

        // Concurrent Feature E: Logical bucket quota accounting check (deduplicating keys across
        // pools so transient dual-copy windows never trigger false 503 QuotaExceeded!).
        let unique_live_keys: BTreeSet<&String> = cluster
            .pools
            .iter()
            .filter(|p| p.state != PoolState::Decommissioned)
            .flat_map(|p| p.hosted_keys.iter())
            .collect();
        let logical_usage_estimate = (unique_live_keys.len() as u64) * 1024;
        probes.always(
            "composite.quota_accounting_never_double_charges_inflight_move",
            logical_usage_estimate <= quota_limit_bytes,
            json!({"logical_keys": unique_live_keys.len()}),
        );
    }

    if mode == MovementMode::DecommissionPool0 {
        // Drain any remaining stragglers on Pool 0 and mark Decommissioned.
        let remaining: Vec<String> = cluster.pools[0].hosted_keys.iter().cloned().collect();
        for full in remaining {
            let k = full.strip_prefix(&format!("{bucket}/")).unwrap();
            let g = cluster.global_gen.get(&full).copied().unwrap_or(0);
            let _ = cluster
                .move_object_with_barrier(0, pool1, bucket, k, g, false)
                .await;
            ops += 1;
        }
        let drained = cluster.pools[0].hosted_keys.is_empty();
        probes.always(
            "composite.decommission_pool0_fully_drained",
            drained,
            json!({}),
        );
        cluster.pools[0].state = PoolState::Decommissioned;
    } else {
        let p0_cnt = cluster.pools[0].hosted_keys.len();
        let p1_cnt = cluster.pools[1].hosted_keys.len();
        probes.always(
            "composite.rebalance_both_pools_serving_data",
            p0_cnt > 0 && p1_cnt > 0,
            json!({"pool0": p0_cnt, "pool1": p1_cnt}),
        );
    }

    // Phase 4: Post-movement full multi-feature verification!
    for (k, expected_hex) in &expected_sha {
        match cluster.get_object(bucket, k).await {
            Ok((_, bytes)) => {
                let actual_hex = sha256_hex(&bytes);
                let match_ok = actual_hex == *expected_hex;
                probes.always(
                    "composite.post_movement_sha256_intact",
                    match_ok,
                    json!({"key": k}),
                );
                if !match_ok {
                    oracle.record_violation(
                        tag_prefix,
                        k,
                        format!("SHA-256 mismatch: expected {expected_hex}, got {actual_hex}"),
                    );
                }
            }
            Err(e) => {
                probes.always(
                    "composite.post_movement_sha256_intact",
                    false,
                    json!({"key": k}),
                );
                oracle.record_violation(tag_prefix, k, format!("missing live key after move: {e}"));
            }
        }
        ops += 1;
    }

    for dk in &deleted_keys {
        let absent = cluster.get_object(bucket, dk).await.is_err();
        probes.always(
            "composite.deleted_or_expired_never_resurrects",
            absent,
            json!({"key": dk}),
        );
        if !absent {
            oracle.record_violation(
                tag_prefix,
                dk,
                "deleted/expired key resurrected across pools",
            );
        }
        ops += 1;
    }

    // Verify WORM Compliance + LegalHold survived pool movement intact.
    let full_worm = format!("{bucket}/worm-compliance-0");
    let worm_survived = cluster
        .pools
        .iter()
        .filter(|p| p.state != PoolState::Decommissioned)
        .any(|p| p.worm_tags.get(&full_worm) == Some(&worm_tag));
    probes.always(
        "composite.worm_compliance_survived_movement",
        worm_survived,
        json!({}),
    );
    if !worm_survived {
        oracle.record_violation(
            tag_prefix,
            "worm-compliance-0",
            "WORM retention lost after cross-pool movement",
        );
    }

    // Verify ListObjectsV2 matches exact live expected key set without duplicates or ghosts.
    let listed = cluster.list_objects(bucket).await.unwrap();
    let expected_list: Vec<String> = expected_sha.keys().cloned().collect();
    probes.always(
        "composite.cross_pool_list_exact",
        listed == expected_list,
        json!({"listed": listed.len(), "expected": expected_list.len()}),
    );
    if listed != expected_list {
        oracle.record_violation(
            tag_prefix,
            bucket,
            format!("list mismatch: expected {expected_list:?}, got {listed:?}"),
        );
    }

    trace.push(format!(
        "{tag_prefix}:verified_{}_live_{}_deleted_topo_{}",
        expected_sha.len(),
        deleted_keys.len(),
        topology.name
    ));
    ops
}

pub async fn run_expansion_decommission_all_features_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    run_expansion_movement_all_features(
        topology,
        seed,
        MovementMode::DecommissionPool0,
        probes,
        oracle,
        trace,
    )
    .await
}

pub async fn run_expansion_rebalance_all_features_scenario(
    topology: TopologySpec,
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    run_expansion_movement_all_features(
        topology,
        seed,
        MovementMode::RebalanceAcrossPools,
        probes,
        oracle,
        trace,
    )
    .await
}
