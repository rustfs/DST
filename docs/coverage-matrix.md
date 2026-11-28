# RustFS DST Complete 26-Scenario Coverage Matrix

## Core Storage & Consensus Scenarios (7)

| Scenario Slug | Verified Invariants & Fault Modes |
|---|---|
| `erasure-quorum` | Quorum PUT/GET/DELETE, `If-None-Match`, single-node crash degraded quorum, minority partition rejection, `ListObjectsV2` convergence |
| `crash-consistency` | Exhaustive `xl.meta` commit `CrashPoint` windows + `SimDiskIo::crash_and_reboot` un-fsynced page-cache drop ("old-or-new-never-mixed") |
| `bitrot-heal` | Silent bitrot up to `parity_shards` drives, SHA-256 detection, GF(2^8) RS reconstruction, online healing |
| `multipart-commit` | Staged parts, mid-commit crash, all-or-nothing visibility, abort cleanup |
| `distributed-lock-skew` | Quorum lock mutual exclusion & strictly monotonic fencing epochs under +60s wall-clock jumps |
| `turmoil-tcp-cluster` | Real Tokio `turmoil::Sim` 4-node virtual TCP cluster (`partition`, `hold`, `release`, `repair`) |
| `swizzle-clog-chaos` | Combined partitions, asymmetric link cuts, link clog, post-apply reply drops, crashes, drive faults, and convergence |

## Enterprise Domain Scenarios (19)

| # | Scenario Slug | Domain | Chaos States & Key Invariants |
|---:|---|---|---|
| 1 | `site-replication` | Site Replication | 3-site active-active mesh, partitions, asymmetric cuts, +/-30s clock skew, site crash -> identical convergence, zero lost IAM/policy/bucket entities, zero replication loops |
| 2 | `bucket-replication` | Bucket Replication | Target outage + spill retry, flaky link + reply drops, out-of-order delayed `gen=1` after `gen=2` -> zero stale clobber, exact SHA-256, delete-marker rules, `REPLICA` loop guard |
| 3 | `worm-object-lock` | WORM / Object Lock | Hostile +/-365d NTP step attacks, admin bypass attempts, `COMPLIANCE` / `GOVERNANCE` / `LegalHold`, power-loss during retention extension -> zero early deletion |
| 4 | `lifecycle-transition` | Lifecycle Transition | Virtual-clock age trigger, remote tier outage, crash before stub fsync, concurrent `PutObject` overwrite CAS -> zero silent regression to cold stub |
| 5 | `lifecycle-expiration` | Lifecycle Expiration | Current, noncurrent, orphan delete-marker, incomplete multipart expiry under +30d wall-clock skew & WORM locks -> zero premature/locked expiry |
| 6 | `lifecycle-tag-expiration` | Tag-Based Lifecycle | `Prefix + Tag` AND-rules racing with `PutObjectTagging` -> TOCTOU generation re-validation cancels stale delete |
| 7 | `pool-expansion` | Pool Expansion | Live `Pool 0` -> `Pool 0+1+2` expansion during node restarts -> zero downtime, multi-pool placement, exact cross-pool `ListObjectsV2` union |
| 8 | `pool-decommission` | Pool Decommission | Write-admission fence (`Decommissioning` rejects new writes), full version drain under node crash -> 0 objects left on source |
| 9 | `pool-rebalance` | Pool Rebalance | Skewed multi-pool utilization rebalance under live linearizable reads -> converged spread, zero missing/duplicate keys |
| 10 | `decommission-consistency-safety` | Decommission Data Safety | Concurrent overwrite & delete races, WORM retention preservation, crash between dest commit & source cleanup -> zero clobber, zero resurrection, WORM intact |
| 11 | `rebalance-consistency-safety` | Rebalance Data Safety | Source-shard bitrot RS-reconstructed before cross-pool move, generation fence, dest-durable-before-source-delete -> zero bitrot propagation |
| 12 | `oidc-sts-auth` | OIDC / STS | Rotating JWKS (`kid-1` -> `kid-2`), IdP outage JWKS cache survival, clock-skewed `exp`/`nbf`, forged/wrong-aud/revoked tokens -> 100% fail-closed |
| 13 | `bucket-notification` | Bucket Notification | Webhook + Kafka fan-out, prefix/suffix filters, target outage + crash-durable spill queue -> non-blocking S3 writes, at-least-once delivery |
| 14 | `audit-logging` | Audit Logging | Cryptographic hash-chained WAL, power-loss recovery, credential/token redaction -> zero missing entries, unbroken chain, zero secret leaks |
| 15 | `tiering-management` | Tiering Management | Multi-tier registry (S3/GCS/Azure), credential rotation, health flapping, in-use deletion guard (`TierInUse`) -> zero dangling stubs |
| 16 | `tiered-remote-restore` | Tiered Remote Restore | `RestoreObject` bit-exactness, tier outage retry, anti-rollback protection (`#3074` never bumps `mod_time`), hot-cache TTL eviction keeping cold stub intact |
| 17 | `s3-tables` | S3 Tables | Table Buckets, Namespaces, concurrent Iceberg `UpdateTableMetadataLocation` `versionToken` CAS + crashes -> strictly 1 winner/token, unbroken snapshot lineage |
| 18 | `capacity-quota` | Capacity Quota | `HARD` & `FIFO` quotas across `PUT`, `CopyObject` (`#7947`), multipart reserve/abort, deletes, and WORM-safe FIFO eviction -> zero over-quota breach or byte leak |
| 19 | `on-demand-migration` | On-Demand Migration | Lazy pull-through from legacy S3/MinIO, legacy outage, background sync -> local `PutObject` & delete tombstones strictly shadow legacy source (zero resurrection) |
