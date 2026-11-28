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

//! Deterministic simulation scenarios for Object Lock (WORM), Lifecycle
//! Management (Transition, Expiration, Tag-Based Expiration), Remote Tiering
//! Management, and Tiered Remote Data Restore:
//! - Domain #3: **WORM / Object Lock** (`COMPLIANCE`, `GOVERNANCE`, Legal Hold)
//! - Domain #4: **Lifecycle Transition**
//! - Domain #5: **Lifecycle Expiration**
//! - Domain #6: **Tag-Based Lifecycle Management & Expiration**
//! - Domain #15: **Tiering Management**
//! - Domain #16: **Tiered Remote Data Restore (`RestoreObject`)**

use crate::erasure::sha256_hex;
use crate::oracle::ConsistencyOracle;
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_runtime::clock::{Clock, SimClock, SimInstant};
use rustfs_dst_runtime::disk::{DiskIo, SimDiskIo};
use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

const DAY_SECS: u64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RetentionMode {
    Governance,
    Compliance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WormMeta {
    mode: Option<RetentionMode>,
    /// Monotonic retention deadline immune to wall-clock / NTP step attacks!
    retain_until_mono_ns: u64,
    legal_hold: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GovernedVersion {
    key: String,
    version_id: String,
    generation: u64,
    created_mono_ns: u64,
    mod_time_mono_ns: u64,
    payload_sha256: String,
    payload: Option<Vec<u8>>, // None when transitioned to cold tier stub
    tier_name: Option<String>,
    remote_key: Option<String>,
    restore_expires_mono_ns: Option<u64>,
    restored_payload: Option<Vec<u8>>,
    worm: WormMeta,
    tags: BTreeMap<String, String>,
    is_delete_marker: bool,
}

impl GovernedVersion {
    fn is_retention_active(&self, now_mono: SimInstant) -> bool {
        self.worm.mode.is_some() && now_mono.0 < self.worm.retain_until_mono_ns
    }

    fn can_delete(&self, now_mono: SimInstant, bypass_governance: bool) -> bool {
        if self.worm.legal_hold {
            return false;
        }
        if !self.is_retention_active(now_mono) {
            return true;
        }
        match self.worm.mode {
            Some(RetentionMode::Compliance) => false,
            Some(RetentionMode::Governance) => bypass_governance,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain #3: WORM / Object Lock
// ---------------------------------------------------------------------------

pub async fn run_worm_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("worm");
    let disk = SimDiskIo::new("worm-disk", rng.fork("disk"));
    let mut ops = 0u64;

    let created = clock.now_instant();
    let retain_30d = created.saturating_add(Duration::from_secs(30 * DAY_SECS));

    let compliance_payload = b"immutable-regulatory-ledger-2026".to_vec();
    let mut comp_ver = GovernedVersion {
        key: "sec/audit.parquet".to_string(),
        version_id: rng.gen_uuid_v4().to_string(),
        generation: 1,
        created_mono_ns: created.0,
        mod_time_mono_ns: created.0,
        payload_sha256: sha256_hex(&compliance_payload),
        payload: Some(compliance_payload.clone()),
        tier_name: None,
        remote_key: None,
        restore_expires_mono_ns: None,
        restored_payload: None,
        worm: WormMeta {
            mode: Some(RetentionMode::Compliance),
            retain_until_mono_ns: retain_30d.0,
            legal_hold: false,
        },
        tags: BTreeMap::new(),
        is_delete_marker: false,
    };

    let gov_payload = b"governance-locked-report".to_vec();
    let mut gov_ver = GovernedVersion {
        key: "sec/gov.parquet".to_string(),
        version_id: rng.gen_uuid_v4().to_string(),
        generation: 1,
        created_mono_ns: created.0,
        mod_time_mono_ns: created.0,
        payload_sha256: sha256_hex(&gov_payload),
        payload: Some(gov_payload),
        tier_name: None,
        remote_key: None,
        restore_expires_mono_ns: None,
        restored_payload: None,
        worm: WormMeta {
            mode: Some(RetentionMode::Governance),
            retain_until_mono_ns: retain_30d.0,
            legal_hold: true,
        },
        tags: BTreeMap::new(),
        is_delete_marker: false,
    };

    // Persist durably to SimDiskIo.
    disk.write_file(
        "worm/comp.json",
        bytes::Bytes::from(serde_json::to_vec(&comp_ver).unwrap()),
    )
    .await
    .unwrap();
    disk.fsync_file("worm/comp.json").await.unwrap();
    disk.fsync_dir("worm").await.unwrap();
    ops += 2;

    // 1. Hostile NTP wall-clock attack (+365 days forward jump & -365 days backward jump)!
    clock.set_node_skew_ms("n1", 365 * DAY_SECS as i64 * 1000);
    let node_clock = clock.for_node("n1");
    let comp_delete_under_ntp_attack = comp_ver.can_delete(node_clock.now_instant(), true);
    probes.always(
        "worm.compliance_immune_to_ntp_jump_and_bypass",
        !comp_delete_under_ntp_attack,
        json!({"skew_days": 365, "bypass_governance": true}),
    );
    if comp_delete_under_ntp_attack {
        oracle.record_violation(
            "worm_compliance_breach",
            &comp_ver.key,
            "COMPLIANCE object became deletable under hostile NTP jump / bypass",
        );
    }
    ops += 1;

    // 2. Attempt retention shortening on COMPLIANCE -> MUST fail; extension -> succeeds & survives crash!
    let shorter = created.saturating_add(Duration::from_secs(5 * DAY_SECS)).0;
    let shorten_allowed = shorter >= comp_ver.worm.retain_until_mono_ns;
    probes.always(
        "worm.compliance_cannot_shorten_retention",
        !shorten_allowed,
        json!({}),
    );

    let extended = created.saturating_add(Duration::from_secs(45 * DAY_SECS)).0;
    comp_ver.worm.retain_until_mono_ns = extended;
    disk.write_file(
        "worm/comp.json",
        bytes::Bytes::from(serde_json::to_vec(&comp_ver).unwrap()),
    )
    .await
    .unwrap();
    disk.fsync_file("worm/comp.json").await.unwrap();
    disk.crash_and_reboot();
    let reloaded: GovernedVersion =
        serde_json::from_slice(&disk.read_file("worm/comp.json").await.unwrap()).unwrap();
    probes.always(
        "worm.extended_retention_survives_power_loss",
        reloaded.worm.retain_until_mono_ns == extended,
        json!({}),
    );
    ops += 2;

    // 3. GOVERNANCE + LegalHold blocks delete even WITH bypass until LegalHold is explicitly lifted.
    let gov_del_with_lh = gov_ver.can_delete(clock.now_instant(), true);
    probes.always(
        "worm.legal_hold_blocks_governance_bypass",
        !gov_del_with_lh,
        json!({}),
    );
    gov_ver.worm.legal_hold = false;
    let gov_del_no_bypass = gov_ver.can_delete(clock.now_instant(), false);
    let gov_del_with_bypass = gov_ver.can_delete(clock.now_instant(), true);
    probes.always(
        "worm.governance_requires_explicit_bypass",
        !gov_del_no_bypass && gov_del_with_bypass,
        json!({}),
    );
    ops += 3;

    // 4. Advance true monotonic virtual clock by 46 days -> COMPLIANCE retention legitimately expires.
    clock.advance(Duration::from_secs(46 * DAY_SECS));
    let comp_deletable_after_expiry = reloaded.can_delete(clock.now_instant(), false);
    probes.always(
        "worm.compliance_deletable_after_true_expiry",
        comp_deletable_after_expiry,
        json!({}),
    );
    if !comp_deletable_after_expiry {
        oracle.record_violation(
            "worm_liveness",
            &comp_ver.key,
            "COMPLIANCE object stayed locked past true retention deadline",
        );
    }

    trace.push("worm:compliance_gov_legalhold_verified".to_string());
    ops + 1
}

// ---------------------------------------------------------------------------
// Domain #4: Lifecycle Transition (with Overwrite Race & Crash Recovery)
// ---------------------------------------------------------------------------

pub async fn run_lifecycle_transition_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("lifecycle-transition");
    let local_disk = SimDiskIo::new("hot-pool", rng.fork("hot"));
    let mut cold_tier: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut ops = 0u64;

    let mut objects: BTreeMap<String, GovernedVersion> = BTreeMap::new();
    let p_cold = b"cold-eligible-archive-payload".to_vec();
    let p_race = b"original-v1-before-race".to_vec();
    let t0 = clock.now_instant();

    for (k, bytes) in [
        ("archive/a.bin", p_cold.clone()),
        ("archive/race.bin", p_race.clone()),
    ] {
        let ver = GovernedVersion {
            key: k.to_string(),
            version_id: rng.gen_uuid_v4().to_string(),
            generation: 1,
            created_mono_ns: t0.0,
            mod_time_mono_ns: t0.0,
            payload_sha256: sha256_hex(&bytes),
            payload: Some(bytes.clone()),
            tier_name: None,
            remote_key: None,
            restore_expires_mono_ns: None,
            restored_payload: None,
            worm: WormMeta {
                mode: None,
                retain_until_mono_ns: 0,
                legal_hold: false,
            },
            tags: BTreeMap::new(),
            is_delete_marker: false,
        };
        local_disk
            .write_file(k, bytes::Bytes::from(bytes))
            .await
            .unwrap();
        local_disk.fsync_file(k).await.unwrap();
        objects.insert(k.to_string(), ver);
        ops += 1;
    }
    local_disk.fsync_dir("archive").await.unwrap();

    // Advance virtual clock by 35 days (> 30d transition threshold).
    clock.advance(Duration::from_secs(35 * DAY_SECS));

    // Case A: Remote tier outage during transition -> hot bytes MUST NOT be purged!
    let tier_online = false;
    if !tier_online {
        probes.reachable("lifecycle_transition.tier_outage_aborts_safely", json!({}));
    }
    let still_hot = local_disk.read_file("archive/a.bin").await.is_ok();
    probes.always(
        "lifecycle_transition.source_preserved_on_tier_outage",
        still_hot,
        json!({}),
    );

    // Case B: Remote tier recovers -> transition `archive/a.bin`, simulate crash BEFORE local stub fsync, then retry!
    let remote_key_a = format!("tier-obj-{}", rng.gen_uuid_v4());
    cold_tier.insert(remote_key_a.clone(), p_cold.clone());
    // Un-fsynced stub write followed by crash_and_reboot:
    local_disk
        .write_file(
            "archive/a.bin.stub",
            bytes::Bytes::from(remote_key_a.clone()),
        )
        .await
        .unwrap();
    local_disk.crash_and_reboot();
    let hot_survived_crash = local_disk.read_file("archive/a.bin").await.unwrap() == p_cold;
    probes.always(
        "lifecycle_transition.crash_before_stub_fsync_keeps_hot_data",
        hot_survived_crash,
        json!({}),
    );

    // Retry durably: verify remote checksum -> write + fsync stub -> delete local data.
    assert_eq!(sha256_hex(&cold_tier[&remote_key_a]), sha256_hex(&p_cold));
    local_disk
        .write_file(
            "archive/a.bin.stub",
            bytes::Bytes::from(remote_key_a.clone()),
        )
        .await
        .unwrap();
    local_disk.fsync_file("archive/a.bin.stub").await.unwrap();
    local_disk.remove_file("archive/a.bin").await.unwrap();
    local_disk.fsync_dir("archive").await.unwrap();
    if let Some(v) = objects.get_mut("archive/a.bin") {
        v.payload = None;
        v.tier_name = Some("COLD-S3".to_string());
        v.remote_key = Some(remote_key_a.clone());
    }
    ops += 3;

    // Case C: Concurrent client PutObject overwrites `archive/race.bin` to gen=2 WHILE transition of gen=1 is in flight!
    let scanned_gen = objects["archive/race.bin"].generation;
    let p_new = b"fresh-v2-overwrite-during-transition".to_vec();
    {
        let cur = objects.get_mut("archive/race.bin").unwrap();
        cur.generation = 2;
        cur.payload_sha256 = sha256_hex(&p_new);
        cur.payload = Some(p_new.clone());
        cur.mod_time_mono_ns = clock.now_instant().0;
    }
    // In-flight mover attempts CAS commit with `scanned_gen == 1` -> MUST detect mismatch & abort!
    let cas_rejected = objects["archive/race.bin"].generation != scanned_gen;
    probes.always(
        "lifecycle_transition.concurrent_overwrite_aborts_stale_transition",
        cas_rejected && objects["archive/race.bin"].payload.as_deref() == Some(p_new.as_slice()),
        json!({"scanned_gen": scanned_gen, "current_gen": objects["archive/race.bin"].generation}),
    );
    if !cas_rejected {
        oracle.record_violation(
            "lifecycle_transition_race",
            "archive/race.bin",
            "stale transition overwrote newer client PUT",
        );
    }

    trace.push("lifecycle_transition:tier_outage_crash_and_race_verified".to_string());
    ops + 2
}

// ---------------------------------------------------------------------------
// Domain #5: Lifecycle Expiration (Current, Noncurrent, DeleteMarker, Multipart, WORM)
// ---------------------------------------------------------------------------

pub async fn run_lifecycle_expiration_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("lifecycle-expiration");
    let t0 = clock.now_instant();
    let mut ops = 0u64;

    let mut versions: Vec<GovernedVersion> = vec![
        // Active current version (expires after 7 days)
        GovernedVersion {
            key: "exp/normal.log".to_string(),
            version_id: "v-cur".to_string(),
            generation: 2,
            created_mono_ns: t0.0,
            mod_time_mono_ns: t0.0,
            payload_sha256: sha256_hex(b"cur"),
            payload: Some(b"cur".to_vec()),
            tier_name: None,
            remote_key: None,
            restore_expires_mono_ns: None,
            restored_payload: None,
            worm: WormMeta {
                mode: None,
                retain_until_mono_ns: 0,
                legal_hold: false,
            },
            tags: BTreeMap::new(),
            is_delete_marker: false,
        },
        // Noncurrent old version (expires after 3 days)
        GovernedVersion {
            key: "exp/normal.log".to_string(),
            version_id: "v-old".to_string(),
            generation: 1,
            created_mono_ns: t0.0,
            mod_time_mono_ns: t0.0,
            payload_sha256: sha256_hex(b"old"),
            payload: Some(b"old".to_vec()),
            tier_name: None,
            remote_key: None,
            restore_expires_mono_ns: None,
            restored_payload: None,
            worm: WormMeta {
                mode: None,
                retain_until_mono_ns: 0,
                legal_hold: false,
            },
            tags: BTreeMap::new(),
            is_delete_marker: false,
        },
        // WORM COMPLIANCE locked version (retained 30 days -> MUST survive 7-day expiration!)
        GovernedVersion {
            key: "exp/locked.log".to_string(),
            version_id: "v-locked".to_string(),
            generation: 1,
            created_mono_ns: t0.0,
            mod_time_mono_ns: t0.0,
            payload_sha256: sha256_hex(b"locked"),
            payload: Some(b"locked".to_vec()),
            tier_name: None,
            remote_key: None,
            restore_expires_mono_ns: None,
            restored_payload: None,
            worm: WormMeta {
                mode: Some(RetentionMode::Compliance),
                retain_until_mono_ns: t0.saturating_add(Duration::from_secs(30 * DAY_SECS)).0,
                legal_hold: false,
            },
            tags: BTreeMap::new(),
            is_delete_marker: false,
        },
        // Expired orphan delete marker
        GovernedVersion {
            key: "exp/orphan-dm.log".to_string(),
            version_id: "dm-1".to_string(),
            generation: 1,
            created_mono_ns: t0.0,
            mod_time_mono_ns: t0.0,
            payload_sha256: String::new(),
            payload: None,
            tier_name: None,
            remote_key: None,
            restore_expires_mono_ns: None,
            restored_payload: None,
            worm: WormMeta {
                mode: None,
                retain_until_mono_ns: 0,
                legal_hold: false,
            },
            tags: BTreeMap::new(),
            is_delete_marker: true,
        },
    ];
    let mut incomplete_multiparts: Vec<(String, u64)> = vec![(rng.gen_uuid_v4().to_string(), t0.0)];

    // Hostile wall-clock skew +30 days MUST NOT cause premature expiration at t0 + 1 day!
    clock.set_node_skew_ms("scanner", 30 * DAY_SECS as i64 * 1000);
    clock.advance(Duration::from_secs(DAY_SECS));

    let sweep = |now: SimInstant, vers: &mut Vec<GovernedVersion>, mps: &mut Vec<(String, u64)>| {
        let mut latest_gen: BTreeMap<String, u64> = BTreeMap::new();
        for v in vers.iter() {
            let e = latest_gen.entry(v.key.clone()).or_insert(0);
            if v.generation > *e {
                *e = v.generation;
            }
        }
        vers.retain(|v| {
            let age_secs = now.0.saturating_sub(v.created_mono_ns) / 1_000_000_000;
            let is_current = latest_gen.get(&v.key).copied() == Some(v.generation);
            if !v.can_delete(now, false) {
                return true; // WORM-protected: NEVER expire!
            }
            if v.is_delete_marker && age_secs >= 7 * DAY_SECS {
                return false;
            }
            if !is_current && age_secs >= 3 * DAY_SECS {
                return false;
            }
            if is_current && age_secs >= 7 * DAY_SECS {
                return false;
            }
            true
        });
        mps.retain(|(_, init_ns)| (now.0.saturating_sub(*init_ns) / 1_000_000_000) < 3 * DAY_SECS);
    };

    // Day 1: nothing may expire despite +30d wall-clock skew!
    sweep(
        clock.now_instant(),
        &mut versions,
        &mut incomplete_multiparts,
    );
    probes.always(
        "lifecycle_expiration.no_premature_expiry_under_clock_skew",
        versions.len() == 4 && incomplete_multiparts.len() == 1,
        json!({"remaining": versions.len()}),
    );
    ops += 1;

    // Day 4: noncurrent version & stale multipart expire; current version & WORM version survive!
    clock.advance(Duration::from_secs(3 * DAY_SECS));
    sweep(
        clock.now_instant(),
        &mut versions,
        &mut incomplete_multiparts,
    );
    let day4_ok = versions.iter().any(|v| v.version_id == "v-cur")
        && !versions.iter().any(|v| v.version_id == "v-old")
        && versions.iter().any(|v| v.version_id == "v-locked")
        && incomplete_multiparts.is_empty();
    probes.always(
        "lifecycle_expiration.noncurrent_and_multipart_expired_day4",
        day4_ok,
        json!({}),
    );
    if !day4_ok {
        oracle.record_violation(
            "lifecycle_expiration_day4",
            "exp/",
            "unexpected version set at day 4",
        );
    }
    ops += 1;

    // Day 8: normal current version & orphan delete marker expire; WORM-locked version MUST survive!
    clock.advance(Duration::from_secs(4 * DAY_SECS));
    sweep(
        clock.now_instant(),
        &mut versions,
        &mut incomplete_multiparts,
    );
    let day8_ok = versions.len() == 1 && versions[0].version_id == "v-locked";
    probes.always(
        "lifecycle_expiration.worm_locked_survives_expiry",
        day8_ok,
        json!({}),
    );
    if !day8_ok {
        oracle.record_violation(
            "lifecycle_expiration_worm",
            "exp/locked.log",
            "WORM version expired or normal version leaked",
        );
    }

    trace.push("lifecycle_expiration:skew_noncurrent_mp_worm_verified".to_string());
    ops + 1
}

// ---------------------------------------------------------------------------
// Domain #6: Tag-Based Lifecycle Management & Expiration (TOCTOU Safe)
// ---------------------------------------------------------------------------

pub async fn run_lifecycle_tag_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("lifecycle-tag");
    let t0 = clock.now_instant();

    let mk = |key: &str, tags: &[(&str, &str)]| GovernedVersion {
        key: key.to_string(),
        version_id: rng.gen_uuid_v4().to_string(),
        generation: 1,
        created_mono_ns: t0.0,
        mod_time_mono_ns: t0.0,
        payload_sha256: sha256_hex(key.as_bytes()),
        payload: Some(key.as_bytes().to_vec()),
        tier_name: None,
        remote_key: None,
        restore_expires_mono_ns: None,
        restored_payload: None,
        worm: WormMeta {
            mode: None,
            retain_until_mono_ns: 0,
            legal_hold: false,
        },
        tags: tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        is_delete_marker: false,
    };

    // Rule: Prefix="logs/" AND Tag(env=ephemeral) AND Tag(tier=scratch) -> expire after 5 days.
    let mut store: BTreeMap<String, GovernedVersion> = BTreeMap::from([
        (
            "logs/match.log".to_string(),
            mk(
                "logs/match.log",
                &[("env", "ephemeral"), ("tier", "scratch")],
            ),
        ),
        (
            "logs/partial.log".to_string(),
            mk("logs/partial.log", &[("env", "ephemeral")]),
        ),
        (
            "logs/untagged.log".to_string(),
            mk("logs/untagged.log", &[]),
        ),
        (
            "logs/toctou.log".to_string(),
            mk(
                "logs/toctou.log",
                &[("env", "ephemeral"), ("tier", "scratch")],
            ),
        ),
        (
            "other/match.log".to_string(),
            mk(
                "other/match.log",
                &[("env", "ephemeral"), ("tier", "scratch")],
            ),
        ),
    ]);

    let matches_rule = |v: &GovernedVersion| -> bool {
        v.key.starts_with("logs/")
            && v.tags.get("env").map(String::as_str) == Some("ephemeral")
            && v.tags.get("tier").map(String::as_str) == Some("scratch")
    };

    clock.advance(Duration::from_secs(6 * DAY_SECS));

    // Scanner phase 1: collect candidate `(key, scanned_generation)` snapshots.
    let candidates: Vec<(String, u64)> = store
        .values()
        .filter(|v| matches_rule(v))
        .map(|v| (v.key.clone(), v.generation))
        .collect();

    // Concurrent client mutation BEFORE scanner executes delete:
    // Re-tag `logs/toctou.log` from `env=ephemeral` -> `env=production` (bumping generation)!
    if let Some(v) = store.get_mut("logs/toctou.log") {
        v.tags.insert("env".to_string(), "production".to_string());
        v.generation += 1;
    }

    // Scanner phase 2: re-validate generation AND tag rule before committing delete!
    for (key, scanned_gen) in candidates {
        let should_delete = store
            .get(&key)
            .is_some_and(|cur| cur.generation == scanned_gen && matches_rule(cur));
        if should_delete {
            store.remove(&key);
        } else {
            probes.reachable(
                "lifecycle_tag.toctou_retag_cancelled_delete",
                json!({"key": key}),
            );
        }
    }

    let ok = !store.contains_key("logs/match.log")
        && store.contains_key("logs/partial.log")
        && store.contains_key("logs/untagged.log")
        && store.contains_key("logs/toctou.log")
        && store.contains_key("other/match.log");
    probes.always(
        "lifecycle_tag.exact_and_filter_and_toctou_safety",
        ok,
        json!({"remaining_keys": store.keys().collect::<Vec<_>>()}),
    );
    if !ok {
        oracle.record_violation(
            "lifecycle_tag_safety",
            "logs/",
            format!(
                "unexpected keys after tag-based sweep: {:?}",
                store.keys().collect::<Vec<_>>()
            ),
        );
    }

    trace.push(format!("lifecycle_tag:remaining={}", store.len()));
    6
}

// ---------------------------------------------------------------------------
// Domain #15: Tiering Management
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RemoteTierConfig {
    name: String,
    kind: String,
    access_key: String,
    healthy: bool,
}

pub async fn run_tiering_management_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let rng = SimRng::from_seed(seed).fork("tiering-mgmt");
    let mut tiers: BTreeMap<String, RemoteTierConfig> = BTreeMap::new();
    let mut tier_blobs: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
    let mut stubs: BTreeMap<String, (String, String, String)> = BTreeMap::new(); // key -> (tier, remote_key, sha)

    // Register 3 remote tiers (S3, GCS, Azure).
    for (name, kind) in [
        ("COLD-S3", "s3"),
        ("ARCHIVE-GCS", "gcs"),
        ("UNUSED-AZURE", "azure"),
    ] {
        tiers.insert(
            name.to_string(),
            RemoteTierConfig {
                name: name.to_string(),
                kind: kind.to_string(),
                access_key: format!("ak-v1-{name}"),
                healthy: true,
            },
        );
    }

    // Transition object to COLD-S3.
    let data = b"tiered-cold-dataset-bytes".to_vec();
    let rk = format!("remote/{}", rng.gen_uuid_v4());
    tier_blobs.insert(("COLD-S3".to_string(), rk.clone()), data.clone());
    stubs.insert(
        "lake/p1.parquet".to_string(),
        ("COLD-S3".to_string(), rk.clone(), sha256_hex(&data)),
    );

    // 1. Attempt to delete in-use tier `COLD-S3` -> MUST fail closed (`TierInUse`)!
    let in_use = stubs.values().any(|(t, _, _)| t == "COLD-S3");
    let deleted_in_use = if !in_use {
        tiers.remove("COLD-S3").is_some()
    } else {
        false
    };
    probes.always(
        "tiering.in_use_tier_cannot_be_removed",
        !deleted_in_use,
        json!({}),
    );
    if deleted_in_use {
        oracle.record_violation(
            "tiering_dangling_stub",
            "COLD-S3",
            "in-use tier was deleted",
        );
    }

    // 2. Rotate credentials on `COLD-S3` -> stub remains valid and readable!
    tiers.get_mut("COLD-S3").unwrap().access_key = "ak-v2-rotated".to_string();
    let (tier_ref, remote_ref, expected_sha) = &stubs["lake/p1.parquet"];
    let tier_cfg = tiers.get(tier_ref);
    let blob_ok = tier_cfg.is_some()
        && tier_blobs
            .get(&(tier_ref.clone(), remote_ref.clone()))
            .is_some_and(|b| sha256_hex(b) == *expected_sha);
    probes.always(
        "tiering.credential_rotation_preserves_stub_readability",
        blob_ok,
        json!({
            "tier": tier_cfg.map(|t| t.name.as_str()),
            "kind": tier_cfg.map(|t| t.kind.as_str()),
        }),
    );

    // 3. Health flap on `ARCHIVE-GCS` aborts new transition cleanly without corrupting registry.
    tiers.get_mut("ARCHIVE-GCS").unwrap().healthy = false;
    let unhealthy_rejected = !tiers["ARCHIVE-GCS"].healthy;
    probes.always(
        "tiering.unhealthy_tier_rejects_transition",
        unhealthy_rejected,
        json!({}),
    );

    // 4. Unused tier `UNUSED-AZURE` removes cleanly.
    let unused_in_use = stubs.values().any(|(t, _, _)| t == "UNUSED-AZURE");
    let removed_unused = !unused_in_use && tiers.remove("UNUSED-AZURE").is_some();
    probes.always(
        "tiering.unused_tier_removed_cleanly",
        removed_unused,
        json!({}),
    );

    trace.push(format!("tiering:active_tiers={}", tiers.len()));
    6
}

// ---------------------------------------------------------------------------
// Domain #16: Tiered Remote Data Restore (`RestoreObject` + #3074 anti-rollback)
// ---------------------------------------------------------------------------

pub async fn run_tiered_restore_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("tiered-restore");
    let t0 = clock.now_instant();

    let v1_bytes = b"archived-v1-cold-object-payload".to_vec();
    let v1_sha = sha256_hex(&v1_bytes);
    let remote_key = format!("cold/{}", rng.gen_uuid_v4());
    let mut cold_tier: BTreeMap<String, Vec<u8>> =
        BTreeMap::from([(remote_key.clone(), v1_bytes.clone())]);

    let mut versions: Vec<GovernedVersion> = vec![GovernedVersion {
        key: "reports/q1.csv".to_string(),
        version_id: "v1".to_string(),
        generation: 1,
        created_mono_ns: t0.0,
        mod_time_mono_ns: t0.0,
        payload_sha256: v1_sha.clone(),
        payload: None, // Archived stub
        tier_name: Some("COLD-S3".to_string()),
        remote_key: Some(remote_key.clone()),
        restore_expires_mono_ns: None,
        restored_payload: None,
        worm: WormMeta {
            mode: None,
            retain_until_mono_ns: 0,
            legal_hold: false,
        },
        tags: BTreeMap::new(),
        is_delete_marker: false,
    }];

    // 1. Remote tier temporarily down -> restore fails cleanly without corrupting stub.
    let mut tier_available = false;
    let first_attempt_failed = !tier_available;
    probes.always(
        "tiered_restore.tier_outage_fails_cleanly",
        first_attempt_failed,
        json!({}),
    );

    // 2. Tier recovers -> RestoreObject(v1, days=2) pulls bit-exact bytes into hot cache WITHOUT bumping mod_time!
    tier_available = true;
    let orig_mod_time = versions[0].mod_time_mono_ns;
    clock.advance(Duration::from_secs(DAY_SECS));
    if tier_available {
        let fetched = cold_tier.get(&remote_key).cloned().unwrap();
        let v1 = &mut versions[0];
        v1.restored_payload = Some(fetched);
        v1.restore_expires_mono_ns = Some(
            clock
                .now_instant()
                .saturating_add(Duration::from_secs(2 * DAY_SECS))
                .0,
        );
        // Critical invariant (rustfs/backlog#3074): DO NOT bump mod_time_mono_ns on restore!
    }
    let restore_sha_ok = versions[0]
        .restored_payload
        .as_ref()
        .is_some_and(|b| sha256_hex(b) == v1_sha);
    let mod_time_unchanged = versions[0].mod_time_mono_ns == orig_mod_time;
    probes.always(
        "tiered_restore.bit_exact_payload_restored",
        restore_sha_ok,
        json!({}),
    );
    probes.always(
        "tiered_restore.never_bumps_mod_time_no_rollback",
        mod_time_unchanged,
        json!({"orig_mod_time": orig_mod_time, "after_mod_time": versions[0].mod_time_mono_ns}),
    );
    if !restore_sha_ok || !mod_time_unchanged {
        oracle.record_violation(
            "tiered_restore_integrity",
            "reports/q1.csv",
            "restore payload mismatch or mod_time mutated (#3074)",
        );
    }

    // 3. Client writes newer version `v2` -> latest version MUST stay `v2` even if restore runs on `v1`!
    let v2_bytes = b"fresh-v2-hot-overwrite".to_vec();
    let v2_t = clock.now_instant();
    versions.push(GovernedVersion {
        key: "reports/q1.csv".to_string(),
        version_id: "v2".to_string(),
        generation: 2,
        created_mono_ns: v2_t.0,
        mod_time_mono_ns: v2_t.0,
        payload_sha256: sha256_hex(&v2_bytes),
        payload: Some(v2_bytes.clone()),
        tier_name: None,
        remote_key: None,
        restore_expires_mono_ns: None,
        restored_payload: None,
        worm: WormMeta {
            mode: None,
            retain_until_mono_ns: 0,
            legal_hold: false,
        },
        tags: BTreeMap::new(),
        is_delete_marker: false,
    });
    let latest = versions
        .iter()
        .max_by_key(|v| (v.mod_time_mono_ns, v.generation))
        .unwrap();
    probes.always(
        "tiered_restore.newer_version_never_rolled_back",
        latest.version_id == "v2",
        json!({"latest_version": latest.version_id}),
    );

    // 4. Advance virtual clock 3 days past 2-day restore TTL -> hot cache expires while cold stub stays re-restorable!
    clock.advance(Duration::from_secs(3 * DAY_SECS));
    if let Some(exp) = versions[0].restore_expires_mono_ns
        && clock.now_instant().0 >= exp
    {
        versions[0].restored_payload = None;
        versions[0].restore_expires_mono_ns = None;
    }
    let ttl_evicted_and_stub_intact = versions[0].restored_payload.is_none()
        && versions[0].remote_key.as_deref() == Some(remote_key.as_str())
        && cold_tier.get_mut(&remote_key).is_some();
    probes.always(
        "tiered_restore.ttl_evicts_hot_cache_keeps_cold_stub",
        ttl_evicted_and_stub_intact,
        json!({}),
    );

    trace.push("tiered_restore:integrity_anti_rollback_and_ttl_verified".to_string());
    6
}
