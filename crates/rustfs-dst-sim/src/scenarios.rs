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

//! Named deterministic simulation scenarios for RustFS DST.
//!
//! Each scenario takes `(topology, seed)` and returns a [`ScenarioReport`]
//! containing all invariant checks, CodeProbe coverage statistics, and a
//! deterministic SHA-256 execution trace digest proving bit-for-bit replay.

use crate::ecstore::{PutConditions, SimCluster, StoreError};
use crate::enterprise_data::{
    run_capacity_quota_scenario, run_on_demand_migration_scenario, run_s3_tables_scenario,
};
use crate::governance::{
    run_lifecycle_expiration_scenario, run_lifecycle_tag_scenario,
    run_lifecycle_transition_scenario, run_tiered_restore_scenario,
    run_tiering_management_scenario, run_worm_scenario,
};
use crate::oracle::{ConsistencyOracle, InvariantViolation};
use crate::pools::{
    run_decommission_consistency_safety_scenario, run_pool_decommission_scenario,
    run_pool_expansion_scenario, run_pool_rebalance_scenario,
    run_rebalance_consistency_safety_scenario,
};
use crate::replication::{run_bucket_replication_scenario, run_site_replication_scenario};
use crate::security_obs::{
    run_audit_logging_scenario, run_bucket_notification_scenario, run_oidc_sts_scenario,
};
use crate::topology::{TopologyKind, TopologySpec};
use crate::turmoil_cluster::run_turmoil_tcp_quorum_sim;
use rustfs_dst_faults::crash::CrashPoint;
use rustfs_dst_faults::probe::ProbeStats;
use rustfs_dst_faults::scheduler::{FaultAction, SwizzleClogScheduler};
use rustfs_dst_runtime::network::LinkFaultProfile;
use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// All supported deterministic simulation scenarios (7 core + 19 enterprise domains = 26).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScenarioKind {
    // --- Core Storage & Consensus Scenarios (7) ---
    /// Quorum PUT/GET/DELETE/If-Match under node loss & partitions.
    ErasureQuorum,
    /// Exhaustive RustFS `xl.meta` commit crash-point & un-fsynced power-loss matrix.
    CrashConsistency,
    /// Silent bitrot corruption on up to `parity` drives + transparent RS read & heal.
    BitrotHeal,
    /// Multipart upload staging, mid-commit crash, retry, and abort cleanup.
    MultipartCommit,
    /// Distributed quorum lock mutual exclusion under partitions & wall-clock skew.
    DistributedLockSkew,
    /// Real Tokio `turmoil` virtual-TCP multi-node partition & quorum simulation.
    TurmoilTcpCluster,
    /// Full Swizzle-Clog chaos combining partitions, asymmetric cuts, clog, crashes, bitrot, and heal.
    SwizzleClogChaos,

    // --- Enterprise Domain Scenarios (19) ---
    /// #1 Multi-site active-active IAM/policy/bucket/object replication under partitions & skew.
    SiteReplication,
    /// #2 Async cross-cluster bucket version & delete-marker replication with out-of-order & loop guards.
    BucketReplication,
    /// #3 WORM Object Lock (COMPLIANCE, GOVERNANCE, Legal Hold) under hostile NTP clock jumps.
    WormObjectLock,
    /// #4 Virtual-clock lifecycle cold-tier transition racing with overwrites, outages, and crashes.
    LifecycleTransition,
    /// #5 Virtual-clock lifecycle expiration (current, noncurrent, delete markers, multipart, WORM).
    LifecycleExpiration,
    /// #6 Tag-based lifecycle management & expiration (`Prefix + Tag` AND-filter + TOCTOU re-tag barrier).
    LifecycleTagExpiration,
    /// #7 Live multi-pool expansion under concurrent S3 traffic and node restarts.
    PoolExpansion,
    /// #8 Pool decommission write-admission fence and full version drain under faults.
    PoolDecommission,
    /// #9 Multi-pool utilization rebalance under live reads/writes and crash resume.
    PoolRebalance,
    /// #10 Adversarial decommission data consistency & safety (overwrite/delete races, WORM, crash).
    DecommissionConsistencySafety,
    /// #11 Adversarial rebalance data consistency & safety (source bitrot healing, generation fence, crash).
    RebalanceConsistencySafety,
    /// #12 OIDC / STS JWT validation, rotating JWKS, IdP outage caching, and revocation.
    OidcStsAuth,
    /// #13 Bucket notification multi-target fan-out, filters, durable spill queue, and data-path isolation.
    BucketNotification,
    /// #14 Tamper-evident hash-chained audit logging, crash durability, and credential redaction.
    AuditLogging,
    /// #15 Remote tiering management, credential rotation, health flapping, and in-use deletion guard.
    TieringManagement,
    /// #16 Tiered remote data restore (`RestoreObject`), anti-rollback (#3074), and hot-cache TTL expiry.
    TieredRemoteRestore,
    /// #17 S3 Tables (Table Buckets, Namespaces, Iceberg `versionToken` CAS serializability).
    S3Tables,
    /// #18 Distributed HARD & FIFO capacity quotas (PUT, CopyObject, multipart reserve/abort, WORM safety).
    CapacityQuota,
    /// #19 On-demand lazy pull-through migration with local overwrite & tombstone shadowing.
    OnDemandMigration,
}

impl ScenarioKind {
    pub const CORE: [ScenarioKind; 7] = [
        ScenarioKind::ErasureQuorum,
        ScenarioKind::CrashConsistency,
        ScenarioKind::BitrotHeal,
        ScenarioKind::MultipartCommit,
        ScenarioKind::DistributedLockSkew,
        ScenarioKind::TurmoilTcpCluster,
        ScenarioKind::SwizzleClogChaos,
    ];

    pub const ENTERPRISE: [ScenarioKind; 19] = [
        ScenarioKind::SiteReplication,
        ScenarioKind::BucketReplication,
        ScenarioKind::WormObjectLock,
        ScenarioKind::LifecycleTransition,
        ScenarioKind::LifecycleExpiration,
        ScenarioKind::LifecycleTagExpiration,
        ScenarioKind::PoolExpansion,
        ScenarioKind::PoolDecommission,
        ScenarioKind::PoolRebalance,
        ScenarioKind::DecommissionConsistencySafety,
        ScenarioKind::RebalanceConsistencySafety,
        ScenarioKind::OidcStsAuth,
        ScenarioKind::BucketNotification,
        ScenarioKind::AuditLogging,
        ScenarioKind::TieringManagement,
        ScenarioKind::TieredRemoteRestore,
        ScenarioKind::S3Tables,
        ScenarioKind::CapacityQuota,
        ScenarioKind::OnDemandMigration,
    ];

    pub const ALL: [ScenarioKind; 26] = [
        ScenarioKind::ErasureQuorum,
        ScenarioKind::CrashConsistency,
        ScenarioKind::BitrotHeal,
        ScenarioKind::MultipartCommit,
        ScenarioKind::DistributedLockSkew,
        ScenarioKind::TurmoilTcpCluster,
        ScenarioKind::SwizzleClogChaos,
        ScenarioKind::SiteReplication,
        ScenarioKind::BucketReplication,
        ScenarioKind::WormObjectLock,
        ScenarioKind::LifecycleTransition,
        ScenarioKind::LifecycleExpiration,
        ScenarioKind::LifecycleTagExpiration,
        ScenarioKind::PoolExpansion,
        ScenarioKind::PoolDecommission,
        ScenarioKind::PoolRebalance,
        ScenarioKind::DecommissionConsistencySafety,
        ScenarioKind::RebalanceConsistencySafety,
        ScenarioKind::OidcStsAuth,
        ScenarioKind::BucketNotification,
        ScenarioKind::AuditLogging,
        ScenarioKind::TieringManagement,
        ScenarioKind::TieredRemoteRestore,
        ScenarioKind::S3Tables,
        ScenarioKind::CapacityQuota,
        ScenarioKind::OnDemandMigration,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::ErasureQuorum => "erasure-quorum",
            Self::CrashConsistency => "crash-consistency",
            Self::BitrotHeal => "bitrot-heal",
            Self::MultipartCommit => "multipart-commit",
            Self::DistributedLockSkew => "distributed-lock-skew",
            Self::TurmoilTcpCluster => "turmoil-tcp-cluster",
            Self::SwizzleClogChaos => "swizzle-clog-chaos",
            Self::SiteReplication => "site-replication",
            Self::BucketReplication => "bucket-replication",
            Self::WormObjectLock => "worm-object-lock",
            Self::LifecycleTransition => "lifecycle-transition",
            Self::LifecycleExpiration => "lifecycle-expiration",
            Self::LifecycleTagExpiration => "lifecycle-tag-expiration",
            Self::PoolExpansion => "pool-expansion",
            Self::PoolDecommission => "pool-decommission",
            Self::PoolRebalance => "pool-rebalance",
            Self::DecommissionConsistencySafety => "decommission-consistency-safety",
            Self::RebalanceConsistencySafety => "rebalance-consistency-safety",
            Self::OidcStsAuth => "oidc-sts-auth",
            Self::BucketNotification => "bucket-notification",
            Self::AuditLogging => "audit-logging",
            Self::TieringManagement => "tiering-management",
            Self::TieredRemoteRestore => "tiered-remote-restore",
            Self::S3Tables => "s3-tables",
            Self::CapacityQuota => "capacity-quota",
            Self::OnDemandMigration => "on-demand-migration",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::ErasureQuorum => {
                "Quorum PUT/GET/DELETE/If-Match linearizability under node loss and network partitions"
            }
            Self::CrashConsistency => {
                "Exhaustive RustFS xl.meta commit CrashPoint and un-fsynced power-loss matrix"
            }
            Self::BitrotHeal => {
                "Silent bitrot injection up to parity limit with transparent RS reconstruction and healing"
            }
            Self::MultipartCommit => {
                "Multipart upload staging, crash-mid-commit atomicity, retry, and abort reclamation"
            }
            Self::DistributedLockSkew => {
                "Distributed quorum lock mutual exclusion and fencing under partitions and clock skew"
            }
            Self::TurmoilTcpCluster => {
                "Real Tokio turmoil virtual-TCP multi-node quorum cluster with partitions and holds"
            }
            Self::SwizzleClogChaos => {
                "Full Swizzle-Clog chaos: asymmetric cuts, reply drops, node crashes, drive faults, and convergence"
            }
            Self::SiteReplication => {
                "[#1] Multi-site active-active IAM/policy/bucket/object replication under partitions, crashes, and clock skew"
            }
            Self::BucketReplication => {
                "[#2] Cross-cluster version & delete-marker replication under target outage, out-of-order packets, and loop guards"
            }
            Self::WormObjectLock => {
                "[#3] WORM COMPLIANCE/GOVERNANCE/LegalHold immunity against hostile +/-1y NTP jumps and bypass attacks"
            }
            Self::LifecycleTransition => {
                "[#4] Virtual-clock cold-tier transition racing with client overwrites, tier outages, and crashes"
            }
            Self::LifecycleExpiration => {
                "[#5] Virtual-clock current/noncurrent/delete-marker/multipart expiration with WORM lock immunity"
            }
            Self::LifecycleTagExpiration => {
                "[#6] Tag-based lifecycle AND-filters with TOCTOU generation re-check under concurrent re-tagging"
            }
            Self::PoolExpansion => {
                "[#7] Live multi-pool expansion with zero-downtime reads and exact cross-pool listing union"
            }
            Self::PoolDecommission => {
                "[#8] Pool decommission write-admission fence and full version drain across faults"
            }
            Self::PoolRebalance => {
                "[#9] Cross-pool utilization rebalance under live S3 traffic with zero missing or duplicate keys"
            }
            Self::DecommissionConsistencySafety => {
                "[#10] Decommission overwrite/delete race barriers, WORM metadata preservation, and crash durability"
            }
            Self::RebalanceConsistencySafety => {
                "[#11] Rebalance source-shard bitrot RS-healing, generation fences, and destination-before-source ordering"
            }
            Self::OidcStsAuth => {
                "[#12] OIDC/STS JWT validation, JWKS rotation, IdP outage caching, clock skew, and subject revocation"
            }
            Self::BucketNotification => {
                "[#13] Multi-target bucket notification fan-out, filters, crash-durable spill queue, and non-blocking S3 writes"
            }
            Self::AuditLogging => {
                "[#14] Hash-chained crash-durable audit trail with zero missing entries and strict credential redaction"
            }
            Self::TieringManagement => {
                "[#15] Remote cold-tier registry, credential rotation, health flapping, and in-use deletion guard"
            }
            Self::TieredRemoteRestore => {
                "[#16] RestoreObject bit-exactness, anti-rollback (#3074), and virtual-clock hot-cache TTL expiry"
            }
            Self::S3Tables => {
                "[#17] S3 Tables catalog and Iceberg versionToken CAS serializability across crashes"
            }
            Self::CapacityQuota => {
                "[#18] Distributed HARD & FIFO bucket quotas covering PUT, CopyObject, multipart aborts, and WORM locks"
            }
            Self::OnDemandMigration => {
                "[#19] Lazy pull-through migration from legacy S3/MinIO with strict overwrite & tombstone shadowing"
            }
        }
    }
}

impl fmt::Display for ScenarioKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for ScenarioKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for kind in Self::ALL {
            if kind.slug().eq_ignore_ascii_case(s.trim()) {
                return Ok(kind);
            }
        }
        Err(format!(
            "unknown scenario '{s}' (available: {})",
            Self::ALL
                .iter()
                .map(|k| k.slug())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Complete report produced by one deterministic `(scenario, topology, seed)` run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub scenario: ScenarioKind,
    pub topology: String,
    pub seed: u64,
    pub passed: bool,
    pub operations: u64,
    pub trace_sha256: String,
    pub violations: Vec<InvariantViolation>,
    pub probes: BTreeMap<String, ProbeStats>,
}

/// Execute a single deterministic simulation scenario on a single-threaded Tokio
/// runtime so scheduling order is 100% deterministic for any given seed.
pub fn run_scenario(scenario: ScenarioKind, topology: TopologyKind, seed: u64) -> ScenarioReport {
    if scenario == ScenarioKind::TurmoilTcpCluster {
        return run_turmoil_scenario(topology.spec(), seed);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build deterministic current-thread tokio runtime");
    rt.block_on(run_scenario_async(scenario, topology.spec(), seed))
}

fn run_turmoil_scenario(topology: TopologySpec, seed: u64) -> ScenarioReport {
    match run_turmoil_tcp_quorum_sim(topology.nodes, seed) {
        Ok(rep) => ScenarioReport {
            scenario: ScenarioKind::TurmoilTcpCluster,
            topology: topology.name.to_string(),
            seed,
            passed: true,
            operations: rep.committed_writes + rep.rejected_partition_writes + rep.verified_reads,
            trace_sha256: rep.trace_sha256,
            violations: Vec::new(),
            probes: BTreeMap::new(),
        },
        Err(err) => ScenarioReport {
            scenario: ScenarioKind::TurmoilTcpCluster,
            topology: topology.name.to_string(),
            seed,
            passed: false,
            operations: 0,
            trace_sha256: String::new(),
            violations: vec![InvariantViolation {
                invariant: "turmoil_tcp_quorum".to_string(),
                key: "cluster".to_string(),
                detail: err,
            }],
            probes: BTreeMap::new(),
        },
    }
}

fn hash_trace(cluster: &SimCluster, extra_events: &[String]) -> String {
    let mut hasher = Sha256::new();
    for ev in extra_events {
        hasher.update(b"E:");
        hasher.update(ev.as_bytes());
        hasher.update(b"\n");
    }
    for net_ev in cluster.network.trace_snapshot() {
        hasher.update(b"N:");
        hasher.update(net_ev.seq.to_le_bytes());
        hasher.update(net_ev.at_ms.to_le_bytes());
        hasher.update(net_ev.from.as_bytes());
        hasher.update(b"->");
        hasher.update(net_ev.to.as_bytes());
        hasher.update(net_ev.method.as_bytes());
        hasher.update(net_ev.outcome.as_bytes());
    }
    for (node_id, env) in &cluster.nodes {
        for (idx, disk) in env.disks.iter().enumerate() {
            hasher.update(b"D:");
            hasher.update(node_id.as_bytes());
            hasher.update((idx as u64).to_le_bytes());
            hasher.update(disk.durable_state_hash());
        }
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn deterministic_payload(rng: &SimRng, min_len: usize, max_len: usize) -> Vec<u8> {
    let len = min_len + rng.gen_range_usize(max_len - min_len + 1);
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

async fn run_scenario_async(
    scenario: ScenarioKind,
    topology: TopologySpec,
    seed: u64,
) -> ScenarioReport {
    let mut cluster = SimCluster::new(topology, seed);
    cluster.probes.emit_setup_complete(json!({
        "scenario": scenario.slug(),
        "topology": topology.name,
        "seed": seed,
    }));

    let mut oracle = ConsistencyOracle::new(cluster.probes.clone());
    let workload_rng = cluster.rng.fork("workload");
    let mut trace = Vec::new();
    let mut ops = 0u64;

    match scenario {
        ScenarioKind::ErasureQuorum => {
            ops = scenario_erasure_quorum(&cluster, &mut oracle, &workload_rng, &mut trace).await;
        }
        ScenarioKind::CrashConsistency => {
            ops =
                scenario_crash_consistency(&cluster, &mut oracle, &workload_rng, &mut trace).await;
        }
        ScenarioKind::BitrotHeal => {
            ops = scenario_bitrot_heal(&cluster, &mut oracle, &workload_rng, &mut trace).await;
        }
        ScenarioKind::MultipartCommit => {
            ops = scenario_multipart_commit(&mut cluster, &mut oracle, &workload_rng, &mut trace)
                .await;
        }
        ScenarioKind::DistributedLockSkew => {
            ops = scenario_distributed_lock_skew(&cluster, &mut oracle, &workload_rng, &mut trace)
                .await;
        }
        ScenarioKind::SwizzleClogChaos => {
            ops =
                scenario_swizzle_clog_chaos(&cluster, &mut oracle, &workload_rng, &mut trace).await;
        }
        ScenarioKind::SiteReplication => {
            ops = run_site_replication_scenario(
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::BucketReplication => {
            ops = run_bucket_replication_scenario(
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::WormObjectLock => {
            ops = run_worm_scenario(seed, cluster.probes.clone(), &mut oracle, &mut trace).await;
        }
        ScenarioKind::LifecycleTransition => {
            ops = run_lifecycle_transition_scenario(
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::LifecycleExpiration => {
            ops = run_lifecycle_expiration_scenario(
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::LifecycleTagExpiration => {
            ops = run_lifecycle_tag_scenario(seed, cluster.probes.clone(), &mut oracle, &mut trace)
                .await;
        }
        ScenarioKind::PoolExpansion => {
            ops = run_pool_expansion_scenario(
                topology,
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::PoolDecommission => {
            ops = run_pool_decommission_scenario(
                topology,
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::PoolRebalance => {
            ops = run_pool_rebalance_scenario(
                topology,
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::DecommissionConsistencySafety => {
            ops = run_decommission_consistency_safety_scenario(
                topology,
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::RebalanceConsistencySafety => {
            ops = run_rebalance_consistency_safety_scenario(
                topology,
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::OidcStsAuth => {
            ops =
                run_oidc_sts_scenario(seed, cluster.probes.clone(), &mut oracle, &mut trace).await;
        }
        ScenarioKind::BucketNotification => {
            ops = run_bucket_notification_scenario(
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::AuditLogging => {
            ops = run_audit_logging_scenario(seed, cluster.probes.clone(), &mut oracle, &mut trace)
                .await;
        }
        ScenarioKind::TieringManagement => {
            ops = run_tiering_management_scenario(
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::TieredRemoteRestore => {
            ops =
                run_tiered_restore_scenario(seed, cluster.probes.clone(), &mut oracle, &mut trace)
                    .await;
        }
        ScenarioKind::S3Tables => {
            ops =
                run_s3_tables_scenario(seed, cluster.probes.clone(), &mut oracle, &mut trace).await;
        }
        ScenarioKind::CapacityQuota => {
            ops =
                run_capacity_quota_scenario(seed, cluster.probes.clone(), &mut oracle, &mut trace)
                    .await;
        }
        ScenarioKind::OnDemandMigration => {
            ops = run_on_demand_migration_scenario(
                seed,
                cluster.probes.clone(),
                &mut oracle,
                &mut trace,
            )
            .await;
        }
        ScenarioKind::TurmoilTcpCluster => {}
    }

    let trace_sha256 = hash_trace(&cluster, &trace);
    let probes = cluster.probes.snapshot();
    let mut violations = oracle.violations().to_vec();
    for probe in probes.values().filter(|probe| probe.is_violated()) {
        let invariant = probe.id.strip_prefix("invariant.").unwrap_or(&probe.id);
        if !violations
            .iter()
            .any(|violation| violation.invariant == invariant)
        {
            violations.push(InvariantViolation {
                invariant: invariant.to_string(),
                key: "scenario".to_string(),
                detail: format!("assertion failed {} times", probe.fail_count),
            });
        }
    }
    ScenarioReport {
        scenario,
        topology: topology.name.to_string(),
        seed,
        passed: violations.is_empty(),
        operations: ops,
        trace_sha256,
        violations,
        probes,
    }
}

async fn scenario_erasure_quorum(
    cluster: &SimCluster,
    oracle: &mut ConsistencyOracle,
    rng: &SimRng,
    trace: &mut Vec<String>,
) -> u64 {
    let nodes = cluster.topology.node_ids();
    let bucket = "dst-quorum";
    let keys: Vec<String> = (0..4).map(|i| format!("obj-{i}")).collect();
    let mut ops = 0u64;

    // 1. Seed initial objects on healthy cluster + test If-None-Match: * precondition.
    for key in &keys {
        let via = &nodes[rng.gen_range_usize(nodes.len())];
        let payload = deterministic_payload(rng, 256, 2048);
        let full = format!("{bucket}/{key}");
        let hash = oracle.record_submitted_payload(&full, &payload);
        let res = cluster
            .put_object(
                via,
                bucket,
                key,
                &payload,
                PutConditions {
                    if_none_match_any: true,
                    if_match_sha256: None,
                },
            )
            .await
            .expect("initial If-None-Match put must succeed");
        oracle.record_acked_put(&full, res.generation, res.version_id, hash.clone());
        trace.push(format!("put:{full}:g{}", res.generation));
        ops += 1;

        // Second If-None-Match: * must fail with PreconditionFailed.
        let dup = cluster
            .put_object(
                via,
                bucket,
                key,
                b"should-reject",
                PutConditions {
                    if_none_match_any: true,
                    if_match_sha256: None,
                },
            )
            .await;
        cluster.probes.always(
            "invariant.if_none_match_rejects_existing",
            matches!(dup, Err(StoreError::PreconditionFailed)),
            json!({"key": full}),
        );
        ops += 1;
    }

    // 2. Crash 1 node (within parity tolerance for 4x4, 3x2, and 4x2) -> degraded writes & reads must succeed!
    let victim = &nodes[rng.gen_range_usize(nodes.len())];
    cluster.crash_node(victim);
    trace.push(format!("crash:{victim}"));

    let live_nodes: Vec<String> = nodes.iter().filter(|n| *n != victim).cloned().collect();
    for key in &keys {
        let via = &live_nodes[rng.gen_range_usize(live_nodes.len())];
        let payload = deterministic_payload(rng, 512, 3072);
        let full = format!("{bucket}/{key}");
        let hash = oracle.record_submitted_payload(&full, &payload);
        let put = cluster
            .put_object(via, bucket, key, &payload, PutConditions::default())
            .await;
        match put {
            Ok(res) => {
                oracle.record_acked_put(&full, res.generation, res.version_id, hash);
                trace.push(format!("degraded_put:{full}:g{}", res.generation));
            }
            Err(e) => {
                oracle.record_violation(
                    "degraded_write_availability",
                    &full,
                    format!("single-node loss should retain write quorum: {e}"),
                );
            }
        }
        ops += 1;

        // Read from another surviving node must return exact new payload.
        let reader = &live_nodes[rng.gen_range_usize(live_nodes.len())];
        match cluster.get_object(reader, bucket, key).await {
            Ok(got) => oracle.check_get_result(&full, &got),
            Err(e) => oracle.record_violation(
                "degraded_read_availability",
                &full,
                format!("single-node loss should retain read quorum: {e}"),
            ),
        }
        ops += 1;
    }

    // 3. Partition into halves (loses write quorum on both sides in 4x4/4x2, or minority side in 3x2) -> minority writes MUST fail closed!
    cluster.heal_infrastructure();
    let mid = nodes.len() / 2;
    let minority = nodes[..mid].to_vec();
    let majority = nodes[mid..].to_vec();
    cluster.network.partition_groups(&minority, &majority);
    trace.push(format!("partition:{minority:?}|{majority:?}"));

    let minority_node = &minority[0];
    let split_put = cluster
        .put_object(
            minority_node,
            bucket,
            &keys[0],
            b"illegal-minority-write",
            PutConditions::default(),
        )
        .await;
    cluster.probes.always(
        "invariant.minority_partition_rejects_write",
        split_put.is_err(),
        json!({"minority": minority, "outcome": format!("{split_put:?}")}),
    );
    if split_put.is_ok() {
        oracle.record_violation(
            "quorum_safety",
            format!("{bucket}/{}", keys[0]),
            "write succeeded on minority partition",
        );
    }
    ops += 1;

    // 4. Heal, delete one object, verify delete marker & ListObjectsV2 consistency.
    cluster.heal_infrastructure();
    let del_key = &keys[keys.len() - 1];
    let del_full = format!("{bucket}/{del_key}");
    let del = cluster
        .delete_object(&nodes[0], bucket, del_key)
        .await
        .expect("delete on healed cluster");
    oracle.record_acked_delete(&del_full, del.generation, del.version_id);
    ops += 1;

    match cluster.get_object(&nodes[1], bucket, del_key).await {
        Err(StoreError::NotFound(_)) => oracle.check_read_not_found(&del_full),
        other => oracle.record_violation(
            "delete_visibility",
            &del_full,
            format!("deleted key returned {other:?}"),
        ),
    }
    ops += 1;

    // S3 If-None-Match: * treats a delete marker as "object does not exist".
    let replacement = b"recreated-after-delete";
    let recreated = cluster
        .put_object(
            &nodes[0],
            bucket,
            del_key,
            replacement,
            PutConditions {
                if_none_match_any: true,
                if_match_sha256: None,
            },
        )
        .await;
    cluster.probes.always(
        "invariant.if_none_match_allows_delete_marker",
        recreated.is_ok(),
        json!({"key": del_full, "outcome": format!("{recreated:?}")}),
    );
    match recreated {
        Ok(put) => {
            let digest = oracle.record_submitted_payload(&del_full, replacement);
            oracle.record_acked_put(&del_full, put.generation, put.version_id, digest);
            match cluster.get_object(&nodes[1], bucket, del_key).await {
                Ok(got) => oracle.check_get_result(&del_full, &got),
                Err(err) => {
                    oracle.record_violation("recreate_visibility", &del_full, err.to_string())
                }
            }
            ops += 1;
        }
        Err(err) => oracle.record_violation(
            "if_none_match_after_delete",
            &del_full,
            format!("If-None-Match rejected a delete marker: {err}"),
        ),
    }
    let deleted_again = cluster
        .delete_object(&nodes[0], bucket, del_key)
        .await
        .expect("delete restored key");
    oracle.record_acked_delete(
        &del_full,
        deleted_again.generation,
        deleted_again.version_id,
    );
    ops += 2;

    // LIST must reflect the acknowledged overwrite and delete before repair runs.
    match cluster.list_objects(&nodes[0], bucket).await {
        Ok(listed) => oracle.check_acked_listing(bucket, &listed),
        Err(err) => oracle.record_violation("list_availability", bucket, err.to_string()),
    }
    ops += 1;

    for key in &keys {
        let _ = cluster.heal_object(&nodes[0], bucket, key).await;
    }
    cluster.sweep_tmp_orphans(&nodes[0]).await;

    for err in cluster.verify_cluster_convergence(bucket, &keys).await {
        oracle.record_violation("heal_convergence", bucket, err);
    }
    ops
}

async fn scenario_crash_consistency(
    cluster: &SimCluster,
    oracle: &mut ConsistencyOracle,
    rng: &SimRng,
    trace: &mut Vec<String>,
) -> u64 {
    let nodes = cluster.topology.node_ids();
    let bucket = "dst-crash";
    let mut ops = 0u64;
    let mut keys = Vec::new();

    for (idx, cp) in [
        CrashPoint::MetaWriteAfterTmpBeforeRename,
        CrashPoint::RenameAfterDataRename,
        CrashPoint::RenameAfterBackupBeforeMetaCommit,
        CrashPoint::RenameAfterMetaCommit,
    ]
    .iter()
    .enumerate()
    {
        let key = format!("crash-obj-{idx}");
        let full = format!("{bucket}/{key}");
        keys.push(key.clone());

        // Commit durable v1 first.
        let v1 = deterministic_payload(rng, 512, 1536);
        let v1_hash = oracle.record_submitted_payload(&full, &v1);
        let r1 = cluster
            .put_object(&nodes[0], bucket, &key, &v1, PutConditions::default())
            .await
            .expect("v1 put must succeed");
        oracle.record_acked_put(&full, r1.generation, r1.version_id, v1_hash.clone());
        ops += 1;

        // Arm the crash point on this key and attempt overwrite v2.
        cluster.crashes.arm(*cp, &full);
        let v2 = deterministic_payload(rng, 512, 1536);
        let v2_hash = oracle.record_submitted_payload(&full, &v2);
        let r2 = cluster
            .put_object(&nodes[0], bucket, &key, &v2, PutConditions::default())
            .await;
        trace.push(format!("crash_window:{cp:?}:{full}:res={}", r2.is_ok()));
        ops += 1;

        // Only 1 drive crashed at the armed point, so either v2 reached write quorum
        // (and all surviving shards are intact v2) or v2 failed and rolled back to v1!
        match r2 {
            Ok(res) => {
                oracle.record_acked_put(&full, res.generation, res.version_id, v2_hash);
            }
            Err(StoreError::Indeterminate {
                generation,
                version_id,
            }) => {
                oracle.record_indeterminate_put(&full, generation, version_id, v2_hash);
            }
            Err(_) => {}
        }

        // Verify "old-or-new-never-mixed" across the entire cluster!
        let got = cluster
            .get_object(&nodes[1 % nodes.len()], bucket, &key)
            .await
            .expect("object must remain readable as intact old or intact new after crash");
        oracle.check_get_result(&full, &got);
        cluster.probes.reachable(
            "ecstore.crash_window_survived_cleanly",
            json!({"crash_point": format!("{cp:?}"), "key": full, "read_gen": got.generation}),
        );
        ops += 1;

        let _ = cluster.heal_object(&nodes[0], bucket, &key).await;
    }

    cluster.sweep_tmp_orphans(&nodes[0]).await;
    for err in cluster.verify_cluster_convergence(bucket, &keys).await {
        oracle.record_violation("crash_heal_convergence", bucket, err);
    }
    ops
}

async fn scenario_bitrot_heal(
    cluster: &SimCluster,
    oracle: &mut ConsistencyOracle,
    rng: &SimRng,
    trace: &mut Vec<String>,
) -> u64 {
    let nodes = cluster.topology.node_ids();
    let bucket = "dst-bitrot";
    let key = "critical-ledger";
    let full = format!("{bucket}/{key}");
    let payload = deterministic_payload(rng, 2048, 8192);
    let hash = oracle.record_submitted_payload(&full, &payload);

    let put = cluster
        .put_object(&nodes[0], bucket, key, &payload, PutConditions::default())
        .await
        .expect("put before bitrot");
    oracle.record_acked_put(&full, put.generation, put.version_id.clone(), hash);

    // Corrupt exactly `parity_shards` distinct drives — the maximum recoverable fault budget!
    let slots = cluster.drive_slots();
    let mut chosen = Vec::new();
    let mut pool: Vec<usize> = (0..slots.len()).collect();
    for _ in 0..cluster.topology.parity_shards {
        let pick = rng.gen_range_usize(pool.len());
        let slot_idx = pool.swap_remove(pick);
        let (ref node_id, drive_idx, _) = slots[slot_idx];
        assert!(cluster.inject_object_bitrot(node_id, drive_idx, bucket, key, &put.version_id));
        chosen.push(format!("{node_id}:data{}", drive_idx + 1));
    }
    trace.push(format!("bitrot_corrupted:{chosen:?}"));

    // Read must detect all corrupted shards via SHA-256 and reconstruct bit-exact payload!
    let got = cluster
        .get_object(&nodes[nodes.len() - 1], bucket, key)
        .await
        .expect("RS must transparently recover from parity_shards bitrotted drives");
    oracle.check_get_result(&full, &got);

    // Run online heal and confirm every bitrotted drive is repaired cleanly.
    let healed = cluster
        .heal_object(&nodes[0], bucket, key)
        .await
        .expect("heal must succeed");
    cluster.probes.always(
        "invariant.bitrot_heal_repairs_all_corrupt_drives",
        healed == cluster.topology.parity_shards,
        json!({"healed": healed, "parity": cluster.topology.parity_shards}),
    );
    if healed != cluster.topology.parity_shards {
        oracle.record_violation(
            "bitrot_heal_count",
            &full,
            format!(
                "expected {} healed drives, got {healed}",
                cluster.topology.parity_shards
            ),
        );
    }

    cluster.sweep_tmp_orphans(&nodes[0]).await;
    for err in cluster
        .verify_cluster_convergence(bucket, &[key.to_string()])
        .await
    {
        oracle.record_violation("bitrot_convergence", &full, err);
    }
    4
}

async fn scenario_multipart_commit(
    cluster: &mut SimCluster,
    oracle: &mut ConsistencyOracle,
    rng: &SimRng,
    trace: &mut Vec<String>,
) -> u64 {
    let nodes = cluster.topology.node_ids();
    let bucket = "dst-multipart";
    let key = "large-dataset.parquet";
    let full = format!("{bucket}/{key}");

    // Commit initial baseline v1 so we can prove failed multipart commits never corrupt v1.
    let v1 = deterministic_payload(rng, 256, 512);
    let v1_hash = oracle.record_submitted_payload(&full, &v1);
    let base = cluster
        .put_object(&nodes[0], bucket, key, &v1, PutConditions::default())
        .await
        .expect("baseline v1");
    oracle.record_acked_put(&full, base.generation, base.version_id, v1_hash);

    // Create multipart upload with 3 parts.
    let upload_id = cluster.create_multipart(bucket, key);
    let mut full_mp_payload = Vec::new();
    for part_no in 1..=3u32 {
        let part_data = deterministic_payload(rng, 512, 1536);
        full_mp_payload.extend_from_slice(&part_data);
        cluster
            .upload_part(
                &nodes[part_no as usize % nodes.len()],
                &upload_id,
                part_no,
                &part_data,
            )
            .await
            .expect("upload_part");
    }
    let mp_hash = oracle.record_submitted_payload(&full, &full_mp_payload);

    // Before CompleteMultipartUpload, GetObject MUST still observe only v1 (no partial data)!
    let pre = cluster
        .get_object(&nodes[0], bucket, key)
        .await
        .expect("pre-complete read");
    oracle.check_get_result(&full, &pre);

    // Arm crash window during multipart commit, then complete!
    cluster
        .crashes
        .arm(CrashPoint::MultipartBeforeCommitRename, &full);
    let completed = cluster
        .complete_multipart(&nodes[0], &upload_id)
        .await
        .expect("complete_multipart must tolerate 1 crashed drive within write quorum");
    oracle.record_acked_put(&full, completed.generation, completed.version_id, mp_hash);
    trace.push(format!(
        "multipart_complete:{full}:g{}",
        completed.generation
    ));

    let post = cluster
        .get_object(&nodes[1 % nodes.len()], bucket, key)
        .await
        .expect("post-complete read");
    oracle.check_get_result(&full, &post);

    // Also test AbortMultipartUpload leaves live object untouched.
    let aborted_id = cluster.create_multipart(bucket, key);
    cluster
        .upload_part(&nodes[0], &aborted_id, 1, b"aborted-part-bytes")
        .await
        .expect("stage aborted part");
    cluster.abort_multipart(&nodes[0], &aborted_id).await;

    let after_abort = cluster
        .get_object(&nodes[0], bucket, key)
        .await
        .expect("read after abort");
    oracle.check_get_result(&full, &after_abort);

    let _ = cluster.heal_object(&nodes[0], bucket, key).await;
    cluster.sweep_tmp_orphans(&nodes[0]).await;
    for err in cluster
        .verify_cluster_convergence(bucket, &[key.to_string()])
        .await
    {
        oracle.record_violation("multipart_convergence", &full, err);
    }
    8
}

async fn scenario_distributed_lock_skew(
    cluster: &SimCluster,
    oracle: &mut ConsistencyOracle,
    rng: &SimRng,
    trace: &mut Vec<String>,
) -> u64 {
    let nodes = cluster.topology.node_ids();
    let resource = "dst-locks/hot-object";
    let mut ops = 0u64;

    // Acquire monotonic-clock quorum lock from n1.
    let c1 = cluster.lock_client(&nodes[0]);
    let c2 = cluster.lock_client(&nodes[1]);

    let lease1 = c1
        .acquire(resource, "owner-1", 5_000, false)
        .await
        .expect("owner-1 lock acquire");
    oracle.check_lock_acquired(resource, "owner-1", lease1.fence_token);
    ops += 1;

    // Inject huge +60s wall-clock jump on ALL nodes! Monotonic leases MUST NOT prematurely expire!
    for node in &nodes {
        let jump = 30_000 + rng.gen_range_usize(60_000) as i64;
        cluster.clock.set_node_skew_ms(node, jump);
    }
    trace.push("clock_skew:+60s_wall_jump".to_string());

    let contender = c2.acquire(resource, "owner-2", 5_000, false).await;
    cluster.probes.always(
        "invariant.monotonic_lock_immune_to_wall_clock_skew",
        contender.is_err(),
        json!({"contender_outcome": format!("{contender:?}")}),
    );
    if let Ok(bad) = contender {
        oracle.check_lock_acquired(resource, "owner-2", bad.fence_token);
    }
    ops += 1;

    // Advance virtual monotonic clock by 2s (still inside 5s lease) -> must remain exclusive.
    cluster.clock.advance(Duration::from_secs(2));
    assert!(c2.acquire(resource, "owner-2", 5_000, false).await.is_err());
    ops += 1;

    // Release lease1, advance monotonic clock past lease, verify owner-2 acquires with higher fence token!
    c1.release(&lease1).await;
    oracle.record_lock_released(resource, "owner-1");
    cluster.clock.advance(Duration::from_secs(4));

    let lease2 = c2
        .acquire(resource, "owner-2", 5_000, false)
        .await
        .expect("owner-2 acquire after release");
    oracle.check_lock_acquired(resource, "owner-2", lease2.fence_token);
    cluster.probes.always(
        "invariant.lock_fence_token_strictly_monotonic",
        lease2.fence_token > lease1.fence_token,
        json!({"fence1": lease1.fence_token, "fence2": lease2.fence_token}),
    );
    if lease2.fence_token <= lease1.fence_token {
        oracle.record_violation(
            "lock_fence_monotonic",
            resource,
            format!(
                "fence did not advance: {} -> {}",
                lease1.fence_token, lease2.fence_token
            ),
        );
    }
    c2.release(&lease2).await;
    oracle.record_lock_released(resource, "owner-2");
    ops += 2;

    // Negative control: a wall-clock lease MUST expire when skew jumps past
    // its TTL. Monotonic leases above must keep failing that test.
    cluster.clock.clear_faults();
    let wall = "dst-locks/wall-clock-lease";
    let wall_lease = c1
        .acquire(wall, "owner-wall", 5_000, true)
        .await
        .expect("wall-clock lease");
    for node in &nodes {
        cluster.clock.set_node_skew_ms(node, 60_000);
    }
    let stolen = c2.acquire(wall, "owner-wall-2", 5_000, true).await;
    cluster.probes.always(
        "invariant.wall_clock_lease_expires_under_skew",
        stolen.is_ok(),
        json!({"stolen": format!("{stolen:?}"), "fence": wall_lease.fence_token}),
    );
    if stolen.is_err() {
        oracle.record_violation(
            "wall_clock_lease_skew",
            wall,
            "wall-clock lease survived a 60s skew jump",
        );
    }
    ops + 1
}

async fn scenario_swizzle_clog_chaos(
    cluster: &SimCluster,
    oracle: &mut ConsistencyOracle,
    rng: &SimRng,
    trace: &mut Vec<String>,
) -> u64 {
    let nodes = cluster.topology.node_ids();
    let bucket = "dst-chaos";
    let keys: Vec<String> = (0..5).map(|i| format!("k{i}")).collect();
    let scheduler = SwizzleClogScheduler::new(
        nodes.clone(),
        cluster.topology.drives_per_node,
        cluster.rng.fork("swizzle-clog"),
    );
    let plan = scheduler.generate_plan(18);
    let mut ops = 0u64;

    // Seed baseline keys on healthy cluster.
    for key in &keys {
        let payload = deterministic_payload(rng, 128, 1024);
        let full = format!("{bucket}/{key}");
        let hash = oracle.record_submitted_payload(&full, &payload);
        let put = cluster
            .put_object(&nodes[0], bucket, key, &payload, PutConditions::default())
            .await
            .expect("baseline chaos put");
        oracle.record_acked_put(&full, put.generation, put.version_id, hash);
        ops += 1;
    }

    for (step, action) in plan.iter().enumerate() {
        apply_fault(cluster, action);
        trace.push(format!("step{step}:{action:?}"));

        // Execute 3 mixed client operations under active chaos.
        for _ in 0..3 {
            let key = &keys[rng.gen_range_usize(keys.len())];
            let full = format!("{bucket}/{key}");
            let via = &nodes[rng.gen_range_usize(nodes.len())];
            let roll = rng.next_u64() % 100;
            if roll < 45 {
                let payload = deterministic_payload(rng, 128, 1024);
                let hash = oracle.record_submitted_payload(&full, &payload);
                match cluster
                    .put_object(via, bucket, key, &payload, PutConditions::default())
                    .await
                {
                    Ok(res) => {
                        oracle.record_acked_put(&full, res.generation, res.version_id, hash);
                    }
                    Err(StoreError::Indeterminate {
                        generation,
                        version_id,
                    }) => {
                        oracle.record_indeterminate_put(&full, generation, version_id, hash);
                    }
                    Err(_) => {}
                }
            } else if roll < 65 {
                match cluster.delete_object(via, bucket, key).await {
                    Ok(res) => {
                        oracle.record_acked_delete(&full, res.generation, res.version_id);
                    }
                    Err(StoreError::Indeterminate {
                        generation,
                        version_id,
                    }) => {
                        oracle.record_indeterminate_delete(&full, generation, version_id);
                    }
                    Err(_) => {}
                }
            } else {
                match cluster.get_object(via, bucket, key).await {
                    Ok(got) => oracle.check_get_result(&full, &got),
                    Err(StoreError::NotFound(_)) => oracle.check_read_not_found(&full),
                    Err(_) => {}
                }
            }
            ops += 1;
        }
        cluster.clock.advance(Duration::from_millis(250));
    }

    // Final recovery: heal infrastructure, run object healer + tmp GC, verify ALL keys readable & converged!
    cluster.heal_infrastructure();
    for key in &keys {
        let _ = cluster.heal_object(&nodes[0], bucket, key).await;
    }
    cluster.sweep_tmp_orphans(&nodes[0]).await;

    for key in &keys {
        let full = format!("{bucket}/{key}");
        match cluster.get_object(&nodes[0], bucket, key).await {
            Ok(got) => oracle.check_get_result(&full, &got),
            Err(StoreError::NotFound(_)) => oracle.check_read_not_found(&full),
            Err(e) => oracle.record_violation(
                "post_chaos_availability",
                &full,
                format!("key unreadable after full heal: {e}"),
            ),
        }
        ops += 1;
    }

    for err in cluster.verify_cluster_convergence(bucket, &keys).await {
        oracle.record_violation("chaos_convergence", bucket, err);
    }
    ops
}

fn apply_fault(cluster: &SimCluster, action: &FaultAction) {
    match action {
        FaultAction::PartitionHalves { group_a, group_b } => {
            cluster.network.partition_groups(group_a, group_b);
        }
        FaultAction::AsymmetricCut { from, to } => {
            cluster.network.partition_one_way(from, to);
        }
        FaultAction::IsolateNode { node } => {
            cluster.network.isolate_node(node);
        }
        FaultAction::ClogLink {
            from,
            to,
            drop_pct,
            reply_drop_pct,
            max_delay_ms,
        } => {
            cluster.network.set_link_profile(
                from,
                to,
                LinkFaultProfile {
                    partitioned: false,
                    drop_prob: f64::from(*drop_pct) / 100.0,
                    post_apply_reply_drop_prob: f64::from(*reply_drop_pct) / 100.0,
                    min_delay_ms: 1,
                    max_delay_ms: *max_delay_ms,
                },
            );
        }
        FaultAction::CrashNode { node } => {
            cluster.crash_node(node);
        }
        FaultAction::RestartNode { node } => {
            cluster.restart_node(node);
        }
        FaultAction::DriveOffline { node, drive_idx } => {
            cluster.set_drive_offline(node, *drive_idx, true);
        }
        FaultAction::DriveOnline { node, drive_idx } => {
            cluster.set_drive_offline(node, *drive_idx, false);
        }
        FaultAction::ClockSkew { node, skew_ms } => {
            cluster.clock.set_node_skew_ms(node, *skew_ms);
        }
        FaultAction::HealAll => {
            cluster.heal_infrastructure();
        }
    }
}
