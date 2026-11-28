# RustFS DST Complete 33-Scenario Coverage Matrix (7 Core + 19 Enterprise + 7 Scanner)

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

## Scanner-Centric Issue-Driven Chaos Scenarios (7, `--scenario scanner`)

Mapped directly to 75+ real `rustfs/rustfs` and `rustfs/backlog` scanner, heal, bitrot, MRF, delete-recovery, lifecycle, replication, and pool-fencing issues:

| # | Scenario Slug | Upstream Issues Covered | Chaos States & Key Invariants |
|---:|---|---|---|
| S1 | `scanner-checkpoint-failover` | `#7108`, `#8494`, `#7964`, `#8461`, `#8457`, `#8618`, `#8141`, `#8297`, `#8888`, `#9462`, `backlog#3118`, `backlog#3282` | SATB termination under continuous foreground writes + `PutBucketLifecycle` churn, 5s lock timeout & failed object without halting checkpointing, leader crash/failover checkpoint resume, `scanner_cycle_mismatch` epoch self-recovery, planned restart follower backoff (>5 retries), `cycle_max_directories` resumption |
| S2 | `scanner-usage-census-durability` | `#9520`, `#9471`, `#9664`, `#9672`, `#8305`, `#8478`, `#9543`, `#8670`, `#6907`, `#6951`, `#6958`, `#8106`, `#8924`, `backlog#3350` | Leader drains follower dirty-usage journals (exits `usage_not_durable` & `Partial`), mid-walk `ENOENT` preserves siblings with 0 `bucket_failure_debt`, read-only `/tmp` fallback, corrupt legacy `.usage.json` quarantine/self-heal, publication lease > persistence budget, post-ILM-expiry count/byte decrement, non-blocking per-bucket quota serving |
| S3 | `scanner-mrf-heal-starvation` | `#9629`, `#9370`, `#8192`, `#5950`, `#7951`, `#7997`, `#8590`, `#8608`, `#9671`, `#9669`, `#9554`, `#9154`, `backlog#2577` | MRF discharge for already-healthy, MinIO-adopted legacy, and absent/deleted-bucket objects (`absent` != `recreate_failed`), weighted priority lanes preventing MRF Normal bursts from starving scanner & read-repair heals, stranded `xl.meta.bkp` rollback backup convergence without deleting valid children |
| S4 | `scanner-deep-bitrot-heal` | `#5821`, `#5837`, `#8005`, `#8007`, `#5863`, `#8015`, `#8377`, `#8764`, `backlog#2905` | Real `SimECStore` in-place bitrot heal avoiding `EEXIST`, `xl.meta` CRC/JSON bitrot classification & repair, 1-byte tail-truncated shard (`SimDiskIo::inject_tail_truncate`) detection & RS rebuild, stale delete-marker reconciliation on drive rejoin, accurate `drives_healed` count, Deep-mode cadence budget, batched multi-drive replacement generation |
| S5 | `scanner-delete-recovery-and-enospc` | `#9517`, `#9560`, `#8464`, `#8666`, `#9673`, `#9594`, `#9461`, `#9647`, `#9015`, `backlog#3286` | Mid-delete crash consistency (zero phantom invisible keys or bucket resurrection), outdated generation reconciliation on rejoined drive, ignoring `.rustfs` system dirs, per-key exponential backoff + quarantine for ambiguous legacy residue, `DeleteObject` succeeding on 100%-full (`ENOSPC`) drive to reclaim space, sub-quorum stale multipart cleanup |
| S6 | `scanner-ilm-repl-tier-coupling` | `#8620`, `#8454`, `#8768`, `#9354`, `#9670`, `#8834`, `#8758`, `#9434`, `#8321`, `#7959`, `#8362`, `backlog#2606` | Deleted lifecycle rule stops expiring across restart, benign `ObjectNotFound` on 500 already-deleted objects with O(1) heap, replication existing-object backfill resume across restart & zero site-repl size inflation, live delete HEAD 405 avoiding infinite HEAL loop, restore copy-back atomicity, tierless no-op & single-leader tier recovery skipping `FileCorrupt` orphans |
| S7 | `scanner-pacing-memory-and-pool-fence` | `#8456`, `#8961`, `#8121`, `#8477`, `#9469`, `#9488`, `#7967`, `#8667`, `#7968`, `#9196`, `#8564`, `backlog#2932`, `backlog#3296`, `backlog#2147` | Strictly bounded scanner `old_cache` working set, dynamic concurrency recovery after transient `GetObject`, online local drive recovery from transient fault, lock-free periodic status reads, >64 `part.N` paginated probe, decommission/rebalance/migration pause-backlog proof monotonicity, source-cleanup 5s lock-timeout retry, zero `FileCorrupt` during live listing |
