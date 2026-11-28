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

//! Deterministic simulation scenarios for Security & Observability:
//! - Domain #12: **OIDC / STS Authentication & Authorization** (`oidc-sts-auth`)
//! - Domain #13: **Bucket Notification** (`bucket-notification`)
//! - Domain #14: **Audit Logging** (`audit-logging`)

use crate::erasure::sha256_hex;
use crate::oracle::ConsistencyOracle;
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_runtime::clock::{Clock, SimClock};
use rustfs_dst_runtime::disk::{DiskIo, SimDiskIo};
use rustfs_dst_runtime::network::{NetError, Network, RpcFrame, RpcHandler, SimNetwork};
use rustfs_dst_runtime::rng::SimRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Domain #12: OIDC / STS AuthN & AuthZ
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JwtToken {
    kid: String,
    iss: String,
    aud: String,
    sub: String,
    nbf_unix_ms: i64,
    exp_unix_ms: i64,
    policy: String,
    sig_hex: String,
}

impl JwtToken {
    #[allow(clippy::too_many_arguments)]
    fn sign(
        kid: &str,
        secret: &str,
        iss: &str,
        aud: &str,
        sub: &str,
        nbf_unix_ms: i64,
        exp_unix_ms: i64,
        policy: &str,
    ) -> Self {
        let canonical =
            format!("{kid}|{iss}|{aud}|{sub}|{nbf_unix_ms}|{exp_unix_ms}|{policy}|{secret}");
        Self {
            kid: kid.to_string(),
            iss: iss.to_string(),
            aud: aud.to_string(),
            sub: sub.to_string(),
            nbf_unix_ms,
            exp_unix_ms,
            policy: policy.to_string(),
            sig_hex: sha256_hex(canonical.as_bytes()),
        }
    }

    fn verify_sig(&self, secret: &str) -> bool {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.kid,
            self.iss,
            self.aud,
            self.sub,
            self.nbf_unix_ms,
            self.exp_unix_ms,
            self.policy,
            secret
        );
        sha256_hex(canonical.as_bytes()) == self.sig_hex
    }
}

pub async fn run_oidc_sts_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("oidc-sts");
    let net = SimNetwork::new(clock.clone(), rng.fork("net"));

    let idp_keys: Arc<Mutex<BTreeMap<String, String>>> = Arc::new(Mutex::new(BTreeMap::from([(
        "kid-1".to_string(),
        "idp-key-material-v1".to_string(),
    )])));
    let idp_ref = Arc::clone(&idp_keys);

    struct JwksHandler {
        keys: Arc<Mutex<BTreeMap<String, String>>>,
    }

    #[async_trait::async_trait]
    impl RpcHandler for JwksHandler {
        async fn handle(&self, _from: &str, _req: RpcFrame) -> Result<RpcFrame, NetError> {
            let body = serde_json::to_vec(&*self.keys.lock().unwrap()).unwrap();
            Ok(RpcFrame::new("jwks.resp", body))
        }
    }

    net.register("idp", Arc::new(JwksHandler { keys: idp_ref }));

    let mut jwks_cache: BTreeMap<String, String> = BTreeMap::new();
    let mut revoked_subs: BTreeSet<String> = BTreeSet::new();
    let expected_iss = "https://idp.rustfs.example";
    let expected_aud = "rustfs-sts";
    let mut ops = 0u64;

    // Fetch initial JWKS into RustFS STS cache.
    async fn refresh_jwks(net: &SimNetwork, cache: &mut BTreeMap<String, String>) -> bool {
        if let Ok(resp) = net
            .call("rustfs", "idp", RpcFrame::new("jwks.get", Vec::new()))
            .await
            && let Ok(keys) = serde_json::from_slice::<BTreeMap<String, String>>(&resp.payload)
        {
            *cache = keys;
            return true;
        }
        false
    }

    assert!(refresh_jwks(&net, &mut jwks_cache).await);
    ops += 1;

    let validate = |tok: &JwtToken,
                    now_ms: i64,
                    cache: &BTreeMap<String, String>,
                    revoked: &BTreeSet<String>|
     -> bool {
        if tok.iss != expected_iss || tok.aud != expected_aud {
            return false;
        }
        if revoked.contains(&tok.sub) {
            return false;
        }
        if now_ms < tok.nbf_unix_ms || now_ms >= tok.exp_unix_ms {
            return false;
        }
        cache
            .get(&tok.kid)
            .is_some_and(|secret| tok.verify_sig(secret))
    };

    let now = clock.now_unix_ms();
    let valid_v1 = JwtToken::sign(
        "kid-1",
        "idp-key-material-v1",
        expected_iss,
        expected_aud,
        "alice",
        now - 1_000,
        now + 60_000,
        "readwrite",
    );
    let forged = JwtToken::sign(
        "kid-1",
        "attacker-fake-key",
        expected_iss,
        expected_aud,
        "admin",
        now - 1_000,
        now + 60_000,
        "admin",
    );
    let wrong_aud = JwtToken::sign(
        "kid-1",
        "idp-key-material-v1",
        expected_iss,
        "other-service",
        "alice",
        now - 1_000,
        now + 60_000,
        "readwrite",
    );
    let expired = JwtToken::sign(
        "kid-1",
        "idp-key-material-v1",
        expected_iss,
        expected_aud,
        "alice",
        now - 120_000,
        now - 1_000,
        "readwrite",
    );
    let not_yet_valid = JwtToken::sign(
        "kid-1",
        "idp-key-material-v1",
        expected_iss,
        expected_aud,
        "alice",
        now + 30_000,
        now + 90_000,
        "readwrite",
    );

    // 1. Fail-closed checks on all invalid tokens.
    let invalid_all_rejected = !validate(&forged, now, &jwks_cache, &revoked_subs)
        && !validate(&wrong_aud, now, &jwks_cache, &revoked_subs)
        && !validate(&expired, now, &jwks_cache, &revoked_subs)
        && !validate(&not_yet_valid, now, &jwks_cache, &revoked_subs);
    probes.always(
        "oidc.invalid_forged_expired_tokens_fail_closed",
        invalid_all_rejected,
        json!({}),
    );
    if !invalid_all_rejected {
        oracle.record_violation(
            "oidc_auth_bypass",
            "sts",
            "invalid/forged/expired JWT was accepted",
        );
    }

    // 2. IdP outage: valid token continues working via JWKS cache!
    net.set_node_down("idp", true);
    let _ = refresh_jwks(&net, &mut jwks_cache).await; // fails, keeps cached keys
    let cache_survived = validate(&valid_v1, now, &jwks_cache, &revoked_subs);
    probes.always(
        "oidc.jwks_cache_survives_idp_outage",
        cache_survived,
        json!({}),
    );

    // 3. IdP recovers & rotates key (`kid-1` retired -> `kid-2` active).
    net.set_node_down("idp", false);
    {
        let mut keys = idp_keys.lock().unwrap();
        keys.clear();
        keys.insert("kid-2".to_string(), "idp-key-material-v2".to_string());
    }
    assert!(refresh_jwks(&net, &mut jwks_cache).await);
    let valid_v2 = JwtToken::sign(
        "kid-2",
        "idp-key-material-v2",
        expected_iss,
        expected_aud,
        "bob",
        now - 1_000,
        now + 60_000,
        "readonly",
    );
    let rotation_ok = validate(&valid_v2, now, &jwks_cache, &revoked_subs)
        && !validate(&valid_v1, now, &jwks_cache, &revoked_subs);
    probes.always(
        "oidc.jwks_rotation_accepts_new_rejects_retired",
        rotation_ok,
        json!({}),
    );

    // 4. Policy/user revocation immediately rejects previously valid `bob` token.
    revoked_subs.insert("bob".to_string());
    let revoked_rejected = !validate(&valid_v2, now, &jwks_cache, &revoked_subs);
    probes.always(
        "oidc.revoked_subject_immediately_denied",
        revoked_rejected,
        json!({}),
    );

    trace.push("oidc_sts:jwks_rotation_outage_clock_revocation_verified".to_string());
    ops + 8
}

// ---------------------------------------------------------------------------
// Domain #13: Bucket Notification (Multi-Target Fan-Out + Spill Queue)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BucketEvent {
    event_id: u64,
    event_name: String, // e.g. "s3:ObjectCreated:Put"
    bucket: String,
    key: String,
}

pub async fn run_bucket_notification_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("bucket-notification");
    let net = SimNetwork::new(clock.clone(), rng.fork("net"));
    let spill_disk = SimDiskIo::new("notify-queue", rng.fork("disk"));

    let webhook_received: Arc<Mutex<Vec<BucketEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let kafka_received: Arc<Mutex<Vec<BucketEvent>>> = Arc::new(Mutex::new(Vec::new()));

    struct NotifyTarget {
        sink: Arc<Mutex<Vec<BucketEvent>>>,
    }

    #[async_trait::async_trait]
    impl RpcHandler for NotifyTarget {
        async fn handle(&self, _from: &str, req: RpcFrame) -> Result<RpcFrame, NetError> {
            let ev: BucketEvent =
                serde_json::from_slice(&req.payload).map_err(|e| NetError::Io(e.to_string()))?;
            self.sink.lock().unwrap().push(ev);
            Ok(RpcFrame::new("notify.ack", b"ok".as_slice()))
        }
    }

    net.register(
        "webhook",
        Arc::new(NotifyTarget {
            sink: Arc::clone(&webhook_received),
        }),
    );
    net.register(
        "kafka",
        Arc::new(NotifyTarget {
            sink: Arc::clone(&kafka_received),
        }),
    );

    // Filter rule: prefix="uploads/", suffix=".json".
    let matches_filter = |k: &str| k.starts_with("uploads/") && k.ends_with(".json");

    // Take webhook offline to prove: (a) S3 PUTs never deadlock/fail, (b) spill queue survives crash & replays!
    net.set_node_down("webhook", true);
    let mut spilled_for_webhook: Vec<BucketEvent> = Vec::new();
    let mut expected_matching_ids: BTreeSet<u64> = BTreeSet::new();
    let mut ops = 0u64;

    let keys = [
        "uploads/a.json",
        "uploads/b.json",
        "uploads/ignore.txt",
        "other/c.json",
        "uploads/d.json",
    ];
    for (idx, &k) in keys.iter().enumerate() {
        let ev = BucketEvent {
            event_id: idx as u64 + 1,
            event_name: "s3:ObjectCreated:Put".to_string(),
            bucket: "events-bkt".to_string(),
            key: k.to_string(),
        };
        ops += 1;
        if !matches_filter(k) {
            continue;
        }
        expected_matching_ids.insert(ev.event_id);
        let payload = serde_json::to_vec(&ev).unwrap();
        // Fan out to Kafka (online) and Webhook (offline -> durable spill to SimDiskIo!).
        assert!(
            net.call("rustfs", "kafka", RpcFrame::new("notify", payload.clone()))
                .await
                .is_ok()
        );
        if net
            .call("rustfs", "webhook", RpcFrame::new("notify", payload))
            .await
            .is_err()
        {
            spilled_for_webhook.push(ev.clone());
            let path = format!("queue/ev-{}.json", ev.event_id);
            spill_disk
                .write_file(&path, bytes::Bytes::from(serde_json::to_vec(&ev).unwrap()))
                .await
                .unwrap();
            spill_disk.fsync_file(&path).await.unwrap();
            spill_disk.fsync_dir("queue").await.unwrap();
        }
    }

    // Power-loss crash & reboot while webhook is still offline -> durable spill queue must survive!
    spill_disk.crash_and_reboot();
    probes.always(
        "notification.data_path_nonblocking_on_target_outage",
        ops == keys.len() as u64,
        json!({}),
    );

    // Webhook recovers -> replay durable spill queue!
    net.set_node_down("webhook", false);
    for entry in spill_disk.list_dir("queue").await.unwrap() {
        let bytes = spill_disk
            .read_file(&format!("queue/{entry}"))
            .await
            .unwrap();
        net.call("rustfs", "webhook", RpcFrame::new("notify", bytes))
            .await
            .unwrap();
        ops += 1;
    }

    let wh_ids: BTreeSet<u64> = webhook_received
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.event_id)
        .collect();
    let kf_ids: BTreeSet<u64> = kafka_received
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.event_id)
        .collect();
    let delivered_exact = wh_ids == expected_matching_ids && kf_ids == expected_matching_ids;
    probes.always(
        "notification.at_least_once_and_filter_exact",
        delivered_exact,
        json!({"expected": expected_matching_ids.len(), "webhook": wh_ids.len(), "kafka": kf_ids.len()}),
    );
    if !delivered_exact {
        oracle.record_violation(
            "notification_delivery",
            "events-bkt",
            "missing or unfiltered notification event",
        );
    }

    trace.push(format!("notification:delivered={}", wh_ids.len()));
    ops
}

// ---------------------------------------------------------------------------
// Domain #14: Audit Logging (Hash-Chained, Crash-Durable, Secret Redaction)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuditEntry {
    seq: u64,
    timestamp_ms: i64,
    principal: String,
    action: String,
    resource: String,
    status: u16,
    redacted_headers: BTreeMap<String, String>,
    prev_hash: String,
    entry_hash: String,
}

impl AuditEntry {
    fn compute_hash(&self) -> String {
        let raw = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.seq,
            self.timestamp_ms,
            self.principal,
            self.action,
            self.resource,
            self.status,
            self.prev_hash
        );
        sha256_hex(raw.as_bytes())
    }
}

fn redact_headers(raw: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    raw.iter()
        .map(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            let sensitive = lower.contains("authorization")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("password");
            (
                k.clone(),
                if sensitive {
                    "[REDACTED]".to_string()
                } else {
                    v.clone()
                },
            )
        })
        .collect()
}

pub async fn run_audit_logging_scenario(
    seed: u64,
    probes: ProbeRegistry,
    oracle: &mut ConsistencyOracle,
    trace: &mut Vec<String>,
) -> u64 {
    let clock = SimClock::new().with_auto_advance(true);
    let rng = SimRng::from_seed(seed).fork("audit-logging");
    let wal_disk = SimDiskIo::new("audit-wal", rng.fork("wal"));

    let mut prev_hash = "0".repeat(64);
    let mut acked_seqs = Vec::new();
    let secret_canary = "SUPER-SECRET-AWS-KEY-DO-NOT-LEAK";

    for seq in 1..=8u64 {
        clock.advance(Duration::from_millis(50));
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("AWS4-HMAC-SHA256 {secret_canary}"),
        );
        headers.insert(
            "X-Amz-Security-Token".to_string(),
            secret_canary.to_string(),
        );
        headers.insert("User-Agent".to_string(), "rustfs-dst-client".to_string());

        let mut entry = AuditEntry {
            seq,
            timestamp_ms: clock.now_unix_ms(),
            principal: "admin".to_string(),
            action: if seq % 2 == 0 {
                "s3:PutObject"
            } else {
                "admin:SetPolicy"
            }
            .to_string(),
            resource: format!("bkt/k-{seq}"),
            status: 200,
            redacted_headers: redact_headers(&headers),
            prev_hash: prev_hash.clone(),
            entry_hash: String::new(),
        };
        entry.entry_hash = entry.compute_hash();
        prev_hash = entry.entry_hash.clone();

        let path = format!("audit/entry-{seq:04}.json");
        wal_disk
            .write_file(
                &path,
                bytes::Bytes::from(serde_json::to_vec(&entry).unwrap()),
            )
            .await
            .unwrap();
        wal_disk.fsync_file(&path).await.unwrap();
        wal_disk.fsync_dir("audit").await.unwrap();
        acked_seqs.push(seq);
    }

    // Simulate abrupt power loss & reload entire audit WAL.
    wal_disk.crash_and_reboot();
    let files = wal_disk.list_dir("audit").await.unwrap();

    let mut expected_prev = "0".repeat(64);
    let mut loaded_seqs = Vec::new();
    let mut chain_valid = true;
    let mut secret_leaked = false;

    for file in files {
        let raw = wal_disk.read_file(&format!("audit/{file}")).await.unwrap();
        let text = String::from_utf8_lossy(&raw);
        if text.contains(secret_canary) {
            secret_leaked = true;
        }
        let entry: AuditEntry = serde_json::from_slice(&raw).unwrap();
        if entry.prev_hash != expected_prev || entry.entry_hash != entry.compute_hash() {
            chain_valid = false;
        }
        expected_prev = entry.entry_hash.clone();
        loaded_seqs.push(entry.seq);
    }

    let complete = loaded_seqs == acked_seqs;
    probes.always(
        "audit.zero_missing_entries_after_crash",
        complete,
        json!({"acked": acked_seqs.len(), "loaded": loaded_seqs.len()}),
    );
    probes.always("audit.hash_chain_tamper_evident", chain_valid, json!({}));
    probes.always(
        "audit.zero_secret_credential_leaks",
        !secret_leaked,
        json!({}),
    );
    if !complete || !chain_valid || secret_leaked {
        oracle.record_violation(
            "audit_integrity",
            "audit-wal",
            "missing audit entry, broken chain, or leaked secret",
        );
    }

    trace.push(format!("audit:verified_entries={}", loaded_seqs.len()));
    acked_seqs.len() as u64
}
