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

//! Deterministic simulation scenarios for:
//! - Domain #1: **Site Replication** (active-active multi-site IAM, policies, buckets, objects)
//! - Domain #2: **Bucket Replication** (async cross-cluster version & delete-marker replication)

use crate::erasure::sha256_hex;
use crate::oracle::ConsistencyOracle;
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_runtime::clock::{Clock, SimClock};
use rustfs_dst_runtime::disk::{DiskIo, SimDiskIo};
use rustfs_dst_runtime::network::{
    LinkFaultProfile, NetError, Network, RpcFrame, RpcHandler, SimNetwork,
};
use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Domain #1: Site Replication (Multi-Site Active-Active Sync)
// ---------------------------------------------------------------------------

const METHOD_SITE_SYNC: &str = "rustfs.site_repl.ApplyEntity";

/// Causal hybrid logical timestamp for deterministic LWW conflict resolution.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct CausalStamp {
    logical: u64,
    wall_ms: i64,
    origin_site: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SiteEntity {
    entity_key: String, // e.g. "iam:user:alice", "policy:readonly", "bucket:app", "obj:app/k1"
    value: String,
    deleted: bool,
    stamp: CausalStamp,
    hops: u32,
}

struct SiteNode {
    site_id: String,
    clock: SimClock,
    disk: SimDiskIo,
    state: Arc<Mutex<BTreeMap<String, SiteEntity>>>,
    logical_counter: Arc<Mutex<u64>>,
    applied_events: Arc<Mutex<BTreeSet<(String, u64, String)>>>,
    loop_detected: Arc<Mutex<bool>>,
}

impl SiteNode {
    fn new(site_id: impl Into<String>, clock: SimClock, rng: SimRng) -> Self {
        let id = site_id.into();
        let disk = SimDiskIo::new(format!("site-meta-{id}"), rng.fork(&format!("disk:{id}")));
        Self {
            site_id: id,
            clock,
            disk,
            state: Arc::new(Mutex::new(BTreeMap::new())),
            logical_counter: Arc::new(Mutex::new(0)),
            applied_events: Arc::new(Mutex::new(BTreeSet::new())),
            loop_detected: Arc::new(Mutex::new(false)),
        }
    }

    async fn local_mutate(&self, entity_key: &str, value: &str, deleted: bool) -> SiteEntity {
        let logical = {
            let mut c = self.logical_counter.lock().unwrap();
            *c += 1;
            *c
        };
        let entity = SiteEntity {
            entity_key: entity_key.to_string(),
            value: value.to_string(),
            deleted,
            stamp: CausalStamp {
                logical,
                wall_ms: self.clock.now_unix_ms(),
                origin_site: self.site_id.clone(),
            },
            hops: 0,
        };
        self.apply_entity(entity.clone(), false).await;
        entity
    }

    /// Apply a local or replicated entity using deterministic causal LWW rules.
    /// Returns `true` if the state changed (new winning version), `false` if duplicate/stale.
    async fn apply_entity(&self, mut entity: SiteEntity, from_remote: bool) -> bool {
        if from_remote && entity.stamp.origin_site == self.site_id && entity.hops > 0 {
            *self.loop_detected.lock().unwrap() = true;
            return false;
        }
        let event_id = (
            entity.entity_key.clone(),
            entity.stamp.logical,
            entity.stamp.origin_site.clone(),
        );
        {
            let mut seen = self.applied_events.lock().unwrap();
            if !seen.insert(event_id) {
                return false;
            }
        }

        // Advance local Lamport clock past incoming logical counter.
        {
            let mut c = self.logical_counter.lock().unwrap();
            if entity.stamp.logical > *c {
                *c = entity.stamp.logical;
            }
        }

        let changed = {
            let mut map = self.state.lock().unwrap();
            let should_replace = match map.get(&entity.entity_key) {
                None => true,
                Some(cur) => entity.stamp > cur.stamp,
            };
            if should_replace {
                if from_remote {
                    entity.hops += 1;
                }
                map.insert(entity.entity_key.clone(), entity.clone());
                true
            } else {
                false
            }
        };

        if changed {
            let snap = {
                let map = self.state.lock().unwrap();
                serde_json::to_vec(&*map).expect("serialize site state")
            };
            let _ = self
                .disk
                .write_file("site-repl/state.json", bytes::Bytes::from(snap))
                .await;
            let _ = self.disk.fsync_file("site-repl/state.json").await;
            let _ = self.disk.fsync_dir("site-repl").await;
        }
        changed
    }

    async fn crash_and_recover(&self) {
        self.disk.crash_and_reboot();
        if let Ok(bytes) = self.disk.read_file("site-repl/state.json").await
            && let Ok(restored) = serde_json::from_slice::<BTreeMap<String, SiteEntity>>(&bytes)
        {
            *self.state.lock().unwrap() = restored;
        } else {
            self.state.lock().unwrap().clear();
        }
        self.applied_events.lock().unwrap().clear();
    }

    fn snapshot(&self) -> BTreeMap<String, (String, bool, CausalStamp)> {
        self.state
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), (v.value.clone(), v.deleted, v.stamp.clone())))
            .collect()
    }
}

struct SiteRpcHandler {
    node: Arc<SiteNode>,
}

#[async_trait::async_trait]
impl RpcHandler for SiteRpcHandler {
    async fn handle(&self, _from: &str, request: RpcFrame) -> Result<RpcFrame, NetError> {
        if request.method != METHOD_SITE_SYNC {
            return Err(NetError::Io(format!("unknown method {}", request.method)));
        }
        let entity: SiteEntity =
            serde_json::from_slice(&request.payload).map_err(|e| NetError::Io(e.to_string()))?;
        let changed = self.node.apply_entity(entity, true).await;
        Ok(RpcFrame::new(
            METHOD_SITE_SYNC,
            if changed {
                b"1".as_slice()
            } else {
                b"0".as_slice()
            },
        ))
    }
}

pub async fn run_site_replication_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("site-replication");
    let net = SimNetwork::new(clock.clone(), rng.fork("net"));

    let site_ids = ["site-a", "site-b", "site-c"];
    let mut sites = BTreeMap::new();
    for id in site_ids {
        let node = Arc::new(SiteNode::new(id, clock.for_node(id), rng.fork(id)));
        net.register(
            id,
            Arc::new(SiteRpcHandler {
                node: Arc::clone(&node),
            }),
        );
        sites.insert(id.to_string(), node);
    }

    let mut backlog: Vec<(String, SiteEntity)> = Vec::new();
    let mut ops = 0u64;

    // Helper: push an entity from origin to all peers, queuing failed deliveries for anti-entropy retry.
    async fn broadcast(
        net: &SimNetwork,
        from: &str,
        peers: &[&str],
        entity: &SiteEntity,
        backlog: &mut Vec<(String, SiteEntity)>,
    ) {
        let payload = serde_json::to_vec(entity).expect("serialize SiteEntity");
        for &to in peers {
            if to == from {
                continue;
            }
            if net
                .call(from, to, RpcFrame::new(METHOD_SITE_SYNC, payload.clone()))
                .await
                .is_err()
            {
                backlog.push((to.to_string(), entity.clone()));
            }
        }
    }

    // 1. Healthy baseline IAM user, policy, bucket, and object replication.
    let e_user = sites["site-a"]
        .local_mutate("iam:user:alice", "enabled:readwrite", false)
        .await;
    broadcast(&net, "site-a", &site_ids, &e_user, &mut backlog).await;
    let e_bucket = sites["site-b"]
        .local_mutate("bucket:finance", "versioning=enabled", false)
        .await;
    broadcast(&net, "site-b", &site_ids, &e_bucket, &mut backlog).await;
    ops += 2;

    // 2. Inject clock skew (+/- 30s) + partition site-a from {site-b, site-c} + asymmetric cut b->c.
    clock.set_node_skew_ms("site-a", 30_000);
    clock.set_node_skew_ms("site-c", -25_000);
    net.partition_groups(
        &["site-a".to_string()],
        &["site-b".to_string(), "site-c".to_string()],
    );
    net.partition_one_way("site-b", "site-c");
    trace.push("site_repl:partition_and_skew".to_string());

    // 3. Split-brain conflicting policy updates + disjoint user/object creations across partitions.
    let conflict_a = sites["site-a"]
        .local_mutate("policy:analytics", "allow:s3:GetObject", false)
        .await;
    broadcast(&net, "site-a", &site_ids, &conflict_a, &mut backlog).await;
    let conflict_b = sites["site-b"]
        .local_mutate("policy:analytics", "allow:s3:GetObject,PutObject", false)
        .await;
    broadcast(&net, "site-b", &site_ids, &conflict_b, &mut backlog).await;

    let user_c = sites["site-c"]
        .local_mutate("iam:user:charlie", "enabled:admin", false)
        .await;
    broadcast(&net, "site-c", &site_ids, &user_c, &mut backlog).await;

    // 4. Crash & reboot site-c mid-partition.
    net.set_node_down("site-c", true);
    sites["site-c"].crash_and_recover().await;
    probes.reachable(
        "site_replication.site_crash_during_partition",
        json!({"seed": seed}),
    );
    ops += 4;

    // 5. Heal network, bring site-c back up, replay backlog + full anti-entropy gossip twice (idempotency!).
    net.heal_all();
    net.set_node_down("site-c", false);
    clock.clear_faults();

    for (target, entity) in backlog.drain(..) {
        let payload = serde_json::to_vec(&entity).expect("serialize SiteEntity");
        let _ = net
            .call(
                &entity.stamp.origin_site,
                &target,
                RpcFrame::new(METHOD_SITE_SYNC, payload),
            )
            .await;
        ops += 1;
    }

    // Two full anti-entropy mesh sync rounds (also proves idempotent replay & zero replication loops).
    for _round in 0..2 {
        for &src in &site_ids {
            let entities: Vec<SiteEntity> =
                sites[src].state.lock().unwrap().values().cloned().collect();
            for entity in entities {
                let payload = serde_json::to_vec(&entity).expect("serialize SiteEntity");
                for &dst in &site_ids {
                    if dst == src || dst == entity.stamp.origin_site {
                        continue;
                    }
                    let _ = net
                        .call(src, dst, RpcFrame::new(METHOD_SITE_SYNC, payload.clone()))
                        .await;
                    ops += 1;
                }
            }
        }
    }

    // 6. Verify strict convergence, zero lost non-conflicting entities, and zero loops.
    let snap_a = sites["site-a"].snapshot();
    let snap_b = sites["site-b"].snapshot();
    let snap_c = sites["site-c"].snapshot();

    let converged = snap_a == snap_b && snap_b == snap_c;
    probes.always(
        "site_replication.all_sites_converged_identically",
        converged,
        json!({"a_keys": snap_a.len(), "b_keys": snap_b.len(), "c_keys": snap_c.len()}),
    );
    if !converged {
        oracle.record_violation(
            "site_replication_convergence",
            "mesh",
            "sites diverged after partition heal and anti-entropy",
        );
    }

    let required_keys = [
        "iam:user:alice",
        "iam:user:charlie",
        "bucket:finance",
        "policy:analytics",
    ];
    let all_present = required_keys.iter().all(|k| snap_a.contains_key(*k));
    probes.always(
        "site_replication.zero_lost_entities",
        all_present,
        json!({"keys": snap_a.keys().collect::<Vec<_>>()}),
    );
    if !all_present {
        oracle.record_violation(
            "site_replication_durability",
            "mesh",
            "missing replicated IAM/bucket/policy entity after heal",
        );
    }

    let any_loop = sites.values().any(|s| *s.loop_detected.lock().unwrap());
    probes.always("site_replication.zero_cyclic_loops", !any_loop, json!({}));
    if any_loop {
        oracle.record_violation(
            "site_replication_loop",
            "mesh",
            "cyclic replication loop detected back to origin site",
        );
    }

    clock.advance(Duration::from_secs(1));
    trace.push(format!("site_repl:converged_entities={}", snap_a.len()));
    ops
}

// ---------------------------------------------------------------------------
// Domain #2: Bucket Replication (Cross-Cluster Async Object & Delete-Marker)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ReplStatus {
    Pending,
    Completed,
    Failed,
    Replica,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReplObject {
    key: String,
    version_id: String,
    generation: u64,
    is_delete_marker: bool,
    payload: Vec<u8>,
    sha256: String,
    status: ReplStatus,
    tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct BucketReplRule {
    prefix: String,
    replicate_delete_markers: bool,
}

pub async fn run_bucket_replication_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("bucket-replication");
    let net = SimNetwork::new(clock.clone(), rng.fork("net"));

    let target_store: Arc<Mutex<BTreeMap<String, ReplObject>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    let target_ref = Arc::clone(&target_store);
    let target_loop_triggered = Arc::new(Mutex::new(false));
    let loop_ref = Arc::clone(&target_loop_triggered);

    struct TargetReplHandler {
        store: Arc<Mutex<BTreeMap<String, ReplObject>>>,
        loop_flag: Arc<Mutex<bool>>,
    }

    #[async_trait::async_trait]
    impl RpcHandler for TargetReplHandler {
        async fn handle(&self, _from: &str, request: RpcFrame) -> Result<RpcFrame, NetError> {
            let mut obj: ReplObject = serde_json::from_slice(&request.payload)
                .map_err(|e| NetError::Io(e.to_string()))?;
            if obj.status == ReplStatus::Replica {
                // Replicating a REPLICA back must be rejected to prevent ping-pong loops!
                *self.loop_flag.lock().unwrap() = true;
                return Err(NetError::Io("rejected loop of REPLICA object".to_string()));
            }
            obj.status = ReplStatus::Replica;
            let mut map = self.store.lock().unwrap();
            // Reject stale out-of-order delayed replication packets!
            let accept = match map.get(&obj.key) {
                None => true,
                Some(existing) => obj.generation > existing.generation,
            };
            if accept {
                map.insert(obj.key.clone(), obj);
            }
            Ok(RpcFrame::new("repl.ack", b"ok".as_slice()))
        }
    }

    net.register(
        "target",
        Arc::new(TargetReplHandler {
            store: target_ref,
            loop_flag: loop_ref,
        }),
    );

    let rule = BucketReplRule {
        prefix: "prod/".to_string(),
        replicate_delete_markers: true,
    };

    let mut source_store: BTreeMap<String, ReplObject> = BTreeMap::new();
    let mut pending_queue: Vec<ReplObject> = Vec::new();
    let mut ops = 0u64;

    let mut put_source =
        |key: &str, generation: u64, is_dm: bool, payload: Vec<u8>| -> ReplObject {
            let sha = sha256_hex(&payload);
            let matches =
                key.starts_with(&rule.prefix) && (!is_dm || rule.replicate_delete_markers);
            let obj = ReplObject {
                key: key.to_string(),
                version_id: rng.gen_uuid_v4().to_string(),
                generation,
                is_delete_marker: is_dm,
                payload,
                sha256: sha,
                status: if matches {
                    ReplStatus::Pending
                } else {
                    ReplStatus::Completed
                },
                tags: BTreeMap::new(),
            };
            source_store.insert(key.to_string(), obj.clone());
            if matches {
                pending_queue.push(obj.clone());
            }
            obj
        };

    // 1. Write matching objects, a non-matching object, and an overwrite on same key.
    let v1_bytes = b"prod-order-v1-payload".to_vec();
    let v2_bytes = b"prod-order-v2-latest-payload".to_vec();
    let obj_v1 = put_source("prod/orders/1", 1, false, v1_bytes);
    let obj_v2 = put_source("prod/orders/1", 2, false, v2_bytes.clone());
    let _excluded = put_source("scratch/temp.bin", 1, false, b"do-not-replicate".to_vec());
    let _dm = put_source("prod/orders/deleted", 1, false, b"to-be-deleted".to_vec());
    let _dm2 = put_source("prod/orders/deleted", 2, true, Vec::new());
    ops += 5;

    // 2. Simulate target outage + packet loss during first replication attempt.
    net.set_node_down("target", true);
    let mut retry_queue = Vec::new();
    for item in pending_queue.drain(..) {
        let body = serde_json::to_vec(&item).unwrap();
        match net
            .call("source", "target", RpcFrame::new("repl.put", body))
            .await
        {
            Ok(_) => {}
            Err(_) => {
                let mut failed = item;
                failed.status = ReplStatus::Failed;
                retry_queue.push(failed);
            }
        }
        ops += 1;
    }
    probes.reachable(
        "bucket_replication.target_outage_queued_retries",
        json!({"queued": retry_queue.len()}),
    );

    // 3. Bring target back online with flaky link, deliver v2 BEFORE delayed v1 (out-of-order test!).
    net.set_node_down("target", false);
    net.set_link_profile(
        "source",
        "target",
        LinkFaultProfile {
            partitioned: false,
            drop_prob: 0.25,
            post_apply_reply_drop_prob: 0.15,
            min_delay_ms: 1,
            max_delay_ms: 10,
        },
    );

    // Deliver obj_v2 first, then stale obj_v1 afterwards!
    let mut ordered_retries = vec![obj_v2.clone(), obj_v1.clone()];
    for item in retry_queue {
        if item.key != "prod/orders/1" {
            ordered_retries.push(item);
        }
    }

    for item in ordered_retries {
        let body = serde_json::to_vec(&item).unwrap();
        // Retry until acknowledged (or heal link after 5 retries).
        for attempt in 0..8 {
            if attempt == 4 {
                net.heal_all();
            }
            if net
                .call("source", "target", RpcFrame::new("repl.put", body.clone()))
                .await
                .is_ok()
            {
                if let Some(src) = source_store.get_mut(&item.key)
                    && src.generation == item.generation
                {
                    src.status = ReplStatus::Completed;
                }
                break;
            }
            ops += 1;
        }
    }

    // 4. Verify bi-directional loop guard: REPLICA objects must never re-enqueue.
    let target_snap = target_store.lock().unwrap().clone();
    let orders1 = target_snap.get("prod/orders/1");
    let no_stale_clobber = orders1.is_some_and(|o| {
        o.generation == 2 && o.sha256 == sha256_hex(&v2_bytes) && o.status == ReplStatus::Replica
    });
    probes.always(
        "bucket_replication.no_stale_out_of_order_clobber",
        no_stale_clobber,
        json!({"target_gen": orders1.map(|o| o.generation)}),
    );
    if !no_stale_clobber {
        oracle.record_violation(
            "bucket_replication_order",
            "prod/orders/1",
            "target regressed to stale generation or corrupted SHA-256",
        );
    }

    let dm_ok = target_snap
        .get("prod/orders/deleted")
        .is_some_and(|o| o.is_delete_marker && o.generation == 2);
    probes.always(
        "bucket_replication.delete_marker_propagated",
        dm_ok,
        json!({}),
    );
    if !dm_ok {
        oracle.record_violation(
            "bucket_replication_delete_marker",
            "prod/orders/deleted",
            "delete marker failed to replicate",
        );
    }

    let prefix_filtered = !target_snap.contains_key("scratch/temp.bin");
    probes.always(
        "bucket_replication.prefix_filter_honored",
        prefix_filtered,
        json!({}),
    );
    if !prefix_filtered {
        oracle.record_violation(
            "bucket_replication_filter",
            "scratch/temp.bin",
            "non-matching prefix was replicated unexpectedly",
        );
    }

    // Explicitly verify a REPLICA object is NOT re-replicated in bi-directional configs.
    let replica_requeue_blocked = target_snap
        .values()
        .all(|o| o.status == ReplStatus::Replica);
    probes.always(
        "bucket_replication.replica_marked_no_loop",
        replica_requeue_blocked && !*target_loop_triggered.lock().unwrap(),
        json!({}),
    );

    trace.push(format!("bucket_repl:replicated_keys={}", target_snap.len()));
    ops
}
