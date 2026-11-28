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

//! Simulated RustFS Erasure-Coded Storage Engine (`SimECStore`) built purely
//! over [`rustfs_dst_runtime`] traits (`Clock`, `RngSource`, `Network`, `DiskIo`).
//!
//! Faithfully models:
//! - RustFS `xl.meta` atomic two-phase commit (`tmp` -> `part` rename ->
//!   `xl.meta.bkp` -> atomic `xl.meta` rename -> `fsync_dir`)
//! - Strict quorum intersection (`W + R > N`, never serving stale generations)
//! - GF(2^8) Reed-Solomon encoding, bitrot detection via SHA-256, and online healing
//! - Distributed quorum locking via [`QuorumLockClient`]
//! - Multipart upload staging, atomic commit, and abort cleanup
//! - Commit crash points ([`CrashPoint`]) and two-stage [`Buggify`] injection

use crate::erasure::{encode, reconstruct, sha256_hex};
use crate::lock::{METHOD_LOCK_ACQUIRE, METHOD_LOCK_RELEASE, NodeLockService, QuorumLockClient};
use crate::topology::TopologySpec;
use async_trait::async_trait;
use bytes::Bytes;
use rustfs_dst_faults::buggify::Buggify;
use rustfs_dst_faults::crash::{CrashPoint, CrashRegistry};
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_runtime::SimNodeEnv;
use rustfs_dst_runtime::clock::SimClock;
use rustfs_dst_runtime::disk::{DiskError, DiskIo, SimDiskIo};
use rustfs_dst_runtime::network::{NetError, Network, RpcFrame, RpcHandler, SimNetwork};
use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;

const METHOD_DISK_STAGE: &str = "rustfs.disk.StageShard";
const METHOD_DISK_COMMIT: &str = "rustfs.disk.CommitShard";
const METHOD_DISK_ROLLBACK: &str = "rustfs.disk.RollbackMeta";
const METHOD_DISK_READ: &str = "rustfs.disk.ReadShard";
const METHOD_DISK_LIST_BUCKET: &str = "rustfs.disk.ListBucket";
const METHOD_DISK_HEAL_WRITE: &str = "rustfs.disk.HealWrite";
const METHOD_DISK_STAGE_PART: &str = "rustfs.disk.StagePart";
const METHOD_DISK_READ_PART: &str = "rustfs.disk.ReadPart";
const METHOD_DISK_CLEANUP_MP: &str = "rustfs.disk.CleanupMultipart";
const METHOD_DISK_CLEANUP_PART: &str = "rustfs.disk.CleanupPart";
const METHOD_DISK_SWEEP_TMP: &str = "rustfs.disk.SweepTmp";

type ShardReadEntry = (usize, XlMeta, Option<Vec<u8>>);

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("write quorum not met: acked {acked}, need {required}")]
    WriteQuorumNotMet { acked: usize, required: usize },
    #[error("read quorum not met: healthy {healthy}, need {required}")]
    ReadQuorumNotMet { healthy: usize, required: usize },
    #[error("write outcome indeterminate (reply dropped after remote apply) at gen {generation}")]
    Indeterminate { generation: u64, version_id: String },
    #[error("precondition failed (If-Match / If-None-Match mismatch)")]
    PreconditionFailed,
    #[error("distributed lock unavailable: {0}")]
    LockUnavailable(String),
    #[error("multipart upload not found: {0}")]
    UploadNotFound(String),
    #[error("internal storage error: {0}")]
    Internal(String),
}

/// On-disk `xl.meta` descriptor modeled after RustFS's `rustfs-filemeta::FileInfo`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XlMeta {
    pub bucket: String,
    pub key: String,
    pub version_id: String,
    pub generation: u64,
    pub is_delete_marker: bool,
    pub orig_len: usize,
    pub payload_sha256: String,
    pub shard_index: usize,
    pub shard_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutResult {
    pub generation: u64,
    pub version_id: String,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetResult {
    pub generation: u64,
    pub version_id: String,
    pub payload: Vec<u8>,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedObject {
    pub key: String,
    pub generation: u64,
    pub version_id: String,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Default)]
pub struct PutConditions {
    pub if_match_sha256: Option<String>,
    pub if_none_match_any: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommitShardReq {
    drive_idx: usize,
    tx_id: String,
    meta: XlMeta,
    shard_bytes: Vec<u8>,
    is_multipart_commit: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RollbackMetaReq {
    drive_idx: usize,
    bucket: String,
    key: String,
    failed_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReadShardReq {
    drive_idx: usize,
    bucket: String,
    key: String,
    include_data: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ReadShardResp {
    NotFound,
    /// `xl.meta` exists on an online drive but failed CRC/JSON decode (`rustfs#5837`).
    CorruptMeta,
    Found {
        meta: XlMeta,
        shard_bytes: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ListBucketReq {
    drive_idx: usize,
    bucket: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ListBucketResp {
    metas: Vec<XlMeta>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HealWriteReq {
    drive_idx: usize,
    meta: XlMeta,
    shard_bytes: Vec<u8>,
    /// True when the cluster verified all drives and proved any higher local
    /// generation is an unrecoverable uncommitted orphan (< data_shards).
    force_overwrite_orphan: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StagePartReq {
    drive_idx: usize,
    upload_id: String,
    part_number: u32,
    attempt_id: String,
    part_etag: String,
    shard_sha256: String,
    shard_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PartOnDiskMeta {
    part_etag: String,
    shard_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReadPartResp {
    part_etag: String,
    shard_sha256: String,
    shard_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReadPartReq {
    drive_idx: usize,
    upload_id: String,
    part_number: u32,
    attempt_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CleanupMultipartReq {
    drive_idx: usize,
    upload_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CleanupPartReq {
    drive_idx: usize,
    upload_id: String,
    part_number: u32,
    attempt_id: String,
}

fn multipart_part_path(upload_id: &str, part_number: u32, attempt_id: &str) -> String {
    format!(".rustfs.sys/multipart/{upload_id}/part.{part_number}.{attempt_id}")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SweepTmpReq {
    drive_idx: usize,
}

/// Combined per-node RPC router hosting local drives and local lock table.
struct NodeRpcServer {
    disks: Vec<Arc<SimDiskIo>>,
    locks: NodeLockService,
    crashes: CrashRegistry,
    buggify: Buggify,
}

impl NodeRpcServer {
    fn disk(&self, idx: usize) -> Result<&Arc<SimDiskIo>, NetError> {
        self.disks
            .get(idx)
            .ok_or_else(|| NetError::Io(format!("invalid drive_idx {idx}")))
    }

    async fn handle_stage(&self, req: CommitShardReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let full_key = format!("{}/{}", req.meta.bucket, req.meta.key);
        let tmp_dir = format!(".rustfs.sys/tmp/{}", req.tx_id);
        let tmp_part = format!("{tmp_dir}/part.1");
        let tmp_meta = format!("{tmp_dir}/xl.meta");
        let dst_meta = format!("{}/{}/xl.meta", req.meta.bucket, req.meta.key);

        // Reject stale generation writes upfront (generation fence on disk).
        if let Ok(existing_bytes) = disk.read_file(&dst_meta).await
            && let Ok(existing_meta) = serde_json::from_slice::<XlMeta>(&existing_bytes)
            && existing_meta.generation >= req.meta.generation
        {
            return Err(NetError::Io(format!(
                "stale generation {} <= existing {}",
                req.meta.generation, existing_meta.generation
            )));
        }

        let meta_bytes =
            Bytes::from(serde_json::to_vec(&req.meta).map_err(|e| NetError::Io(e.to_string()))?);

        // Phase 1: Stage shard + xl.meta in `.rustfs.sys/tmp/<tx_id>` and fsync.
        disk.create_dir_all(&tmp_dir)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        if !req.meta.is_delete_marker {
            disk.write_file(&tmp_part, Bytes::from(req.shard_bytes))
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.fsync_file(&tmp_part)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
        }
        disk.write_file(&tmp_meta, meta_bytes)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.fsync_file(&tmp_meta)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        let _ = disk.fsync_dir(&tmp_dir).await;

        // Crash window: MetaWriteAfterTmpBeforeRename (pre-commit).
        if self
            .crashes
            .take_if_armed(CrashPoint::MetaWriteAfterTmpBeforeRename, &full_key)
        {
            disk.crash_and_reboot();
            return Err(NetError::Io(
                "crash at MetaWriteAfterTmpBeforeRename".to_string(),
            ));
        }

        if req.is_multipart_commit
            && self
                .crashes
                .take_if_armed(CrashPoint::MultipartBeforeCommitRename, &full_key)
        {
            disk.crash_and_reboot();
            return Err(NetError::Io(
                "crash at MultipartBeforeCommitRename".to_string(),
            ));
        }

        Ok(RpcFrame::new(METHOD_DISK_STAGE, Vec::new()))
    }

    async fn handle_commit(&self, req: CommitShardReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let full_key = format!("{}/{}", req.meta.bucket, req.meta.key);
        let tmp_dir = format!(".rustfs.sys/tmp/{}", req.tx_id);
        let tmp_part = format!("{tmp_dir}/part.1");
        let tmp_meta = format!("{tmp_dir}/xl.meta");
        let obj_dir = format!("{}/{}", req.meta.bucket, req.meta.key);
        let ver_dir = format!("{obj_dir}/{}", req.meta.version_id);
        let dst_part = format!("{ver_dir}/part.1");
        let dst_meta = format!("{obj_dir}/xl.meta");
        let bkp_meta = format!("{obj_dir}/xl.meta.bkp");

        // Reject stale generation writes (generation fence on disk).
        if let Ok(existing_bytes) = disk.read_file(&dst_meta).await
            && let Ok(existing_meta) = serde_json::from_slice::<XlMeta>(&existing_bytes)
            && existing_meta.generation >= req.meta.generation
        {
            let _ = disk.remove_dir_all(&tmp_dir).await;
            return Err(NetError::Io(format!(
                "stale generation {} <= existing {}",
                req.meta.generation, existing_meta.generation
            )));
        }

        // Step 2: Publish staged data shard into versioned directory.
        disk.create_dir_all(&obj_dir)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        if !req.meta.is_delete_marker {
            disk.create_dir_all(&ver_dir)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.rename(&tmp_part, &dst_part)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.fsync_file(&dst_part)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.fsync_dir(&ver_dir)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
        }

        // Crash window: RenameAfterDataRename (pre-commit).
        if self
            .crashes
            .take_if_armed(CrashPoint::RenameAfterDataRename, &full_key)
        {
            disk.crash_and_reboot();
            return Err(NetError::Io("crash at RenameAfterDataRename".to_string()));
        }

        // Step 3: Write rollback backup `xl.meta.bkp` if an old version exists.
        if let Ok(old_meta) = disk.read_file(&dst_meta).await {
            disk.write_file(&bkp_meta, old_meta)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.fsync_file(&bkp_meta)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
        }

        // Crash window: RenameAfterBackupBeforeMetaCommit (pre-commit).
        if self
            .crashes
            .take_if_armed(CrashPoint::RenameAfterBackupBeforeMetaCommit, &full_key)
        {
            disk.crash_and_reboot();
            return Err(NetError::Io(
                "crash at RenameAfterBackupBeforeMetaCommit".to_string(),
            ));
        }

        // Step 4: Atomic commit rename `tmp/xl.meta` -> `obj/xl.meta`.
        disk.rename(&tmp_meta, &dst_meta)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;

        // Crash window: RenameAfterMetaCommit (after volatile rename, before fsync_dir).
        if self
            .crashes
            .take_if_armed(CrashPoint::RenameAfterMetaCommit, &full_key)
        {
            disk.crash_and_reboot();
            return Err(NetError::Io("crash at RenameAfterMetaCommit".to_string()));
        }

        // Step 5: Seal commit durability with `fsync_file` + `fsync_dir`.
        disk.fsync_file(&dst_meta)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.fsync_dir(&obj_dir)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        let _ = disk.fsync_dir(&req.meta.bucket).await;

        if req.is_multipart_commit
            && self
                .crashes
                .take_if_armed(CrashPoint::MultipartAfterCommitBeforeCleanup, &full_key)
        {
            disk.crash_and_reboot();
            return Err(NetError::Io(
                "crash at MultipartAfterCommitBeforeCleanup".to_string(),
            ));
        }

        // Step 6: Clean up temp dir (unless buggify leaves an orphan for GC).
        if !self
            .buggify
            .should_fire_with_prob("ecstore.skip_tmp_cleanup", 0.15)
        {
            let _ = disk.remove_dir_all(&tmp_dir).await;
        }
        let _ = disk.fsync_dir(&obj_dir).await;

        Ok(RpcFrame::new(METHOD_DISK_COMMIT, Vec::new()))
    }

    async fn handle_rollback(&self, req: RollbackMetaReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let obj_dir = format!("{}/{}", req.bucket, req.key);
        let dst_meta = format!("{obj_dir}/xl.meta");
        let bkp_meta = format!("{obj_dir}/xl.meta.bkp");

        if let Ok(cur_bytes) = disk.read_file(&dst_meta).await
            && let Ok(cur_meta) = serde_json::from_slice::<XlMeta>(&cur_bytes)
            && cur_meta.generation == req.failed_generation
        {
            if let Ok(bkp_bytes) = disk.read_file(&bkp_meta).await {
                let _ = disk.write_file(&dst_meta, bkp_bytes).await;
                let _ = disk.fsync_file(&dst_meta).await;
                let _ = disk.remove_file(&bkp_meta).await;
            } else {
                // Unconditionally remove `dst_meta` even when `failed_generation > 1`
                // on a drive that missed earlier generations ([D-03]).
                let _ = disk.remove_file(&dst_meta).await;
            }
            let _ = disk
                .remove_dir_all(&format!("{obj_dir}/{}", cur_meta.version_id))
                .await;
            let _ = disk.fsync_dir(&obj_dir).await;
        }
        Ok(RpcFrame::new(METHOD_DISK_ROLLBACK, Vec::new()))
    }

    async fn handle_read(&self, req: ReadShardReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let dst_meta = format!("{}/{}/xl.meta", req.bucket, req.key);
        let resp = match disk.read_file(&dst_meta).await {
            Err(DiskError::NotFound(_)) => ReadShardResp::NotFound,
            Err(e) => return Err(NetError::Io(e.to_string())),
            Ok(bytes) => match serde_json::from_slice::<XlMeta>(&bytes) {
                Err(_) => ReadShardResp::CorruptMeta,
                Ok(meta) => {
                    let shard_bytes = if req.include_data && !meta.is_delete_marker {
                        let part_path =
                            format!("{}/{}/{}/part.1", req.bucket, req.key, meta.version_id);
                        match disk.read_file(&part_path).await {
                            Ok(b) => Some(b.to_vec()),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };
                    ReadShardResp::Found { meta, shard_bytes }
                }
            },
        };
        let payload = serde_json::to_vec(&resp).map_err(|e| NetError::Io(e.to_string()))?;
        Ok(RpcFrame::new(METHOD_DISK_READ, payload))
    }

    async fn handle_list_bucket(&self, req: ListBucketReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let keys = match disk.list_dir(&req.bucket).await {
            Ok(list) => list,
            Err(DiskError::NotFound(_)) => Vec::new(),
            Err(e) => return Err(NetError::Io(e.to_string())),
        };
        let mut metas = Vec::new();
        for key in keys {
            let meta_path = format!("{}/{key}/xl.meta", req.bucket);
            if let Ok(bytes) = disk.read_file(&meta_path).await
                && let Ok(meta) = serde_json::from_slice::<XlMeta>(&bytes)
            {
                metas.push(meta);
            }
        }
        let payload = serde_json::to_vec(&ListBucketResp { metas })
            .map_err(|e| NetError::Io(e.to_string()))?;
        Ok(RpcFrame::new(METHOD_DISK_LIST_BUCKET, payload))
    }

    async fn handle_heal_write(&self, req: HealWriteReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let obj_dir = format!("{}/{}", req.meta.bucket, req.meta.key);
        let ver_dir = format!("{obj_dir}/{}", req.meta.version_id);
        let dst_part = format!("{ver_dir}/part.1");
        let dst_meta = format!("{obj_dir}/xl.meta");

        // Never overwrite a strictly newer committed generation during heal
        // unless the cluster proved the local entry is an unrecoverable orphan.
        if !req.force_overwrite_orphan
            && let Ok(existing_bytes) = disk.read_file(&dst_meta).await
            && let Ok(existing_meta) = serde_json::from_slice::<XlMeta>(&existing_bytes)
            && existing_meta.generation > req.meta.generation
        {
            return Ok(RpcFrame::new(METHOD_DISK_HEAL_WRITE, Vec::new()));
        }

        disk.create_dir_all(&obj_dir)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        if !req.meta.is_delete_marker {
            disk.create_dir_all(&ver_dir)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.write_file(&dst_part, Bytes::from(req.shard_bytes))
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.fsync_file(&dst_part)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            disk.fsync_dir(&ver_dir)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
        }
        let meta_bytes =
            Bytes::from(serde_json::to_vec(&req.meta).map_err(|e| NetError::Io(e.to_string()))?);
        disk.write_file(&dst_meta, meta_bytes)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.fsync_file(&dst_meta)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.fsync_dir(&obj_dir)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        let _ = disk.fsync_dir(&req.meta.bucket).await;
        Ok(RpcFrame::new(METHOD_DISK_HEAL_WRITE, Vec::new()))
    }

    async fn handle_stage_part(&self, req: StagePartReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let dir = format!(".rustfs.sys/multipart/{}", req.upload_id);
        let path = multipart_part_path(&req.upload_id, req.part_number, &req.attempt_id);
        let meta_path = format!("{path}.meta");
        let meta = PartOnDiskMeta {
            part_etag: req.part_etag,
            shard_sha256: req.shard_sha256,
        };
        let meta_bytes =
            Bytes::from(serde_json::to_vec(&meta).map_err(|e| NetError::Io(e.to_string()))?);
        disk.create_dir_all(&dir)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.write_file(&path, Bytes::from(req.shard_bytes))
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.fsync_file(&path)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.write_file(&meta_path, meta_bytes)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.fsync_file(&meta_path)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        disk.fsync_dir(&dir)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        Ok(RpcFrame::new(METHOD_DISK_STAGE_PART, Vec::new()))
    }

    async fn handle_read_part(&self, req: ReadPartReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let path = multipart_part_path(&req.upload_id, req.part_number, &req.attempt_id);
        let meta_path = format!("{path}.meta");
        let meta_bytes = disk
            .read_file(&meta_path)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        let meta: PartOnDiskMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| NetError::Io(format!("corrupt part meta: {e}")))?;
        let data = disk
            .read_file(&path)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        if sha256_hex(&data) != meta.shard_sha256 {
            return Err(NetError::Io("staged part checksum mismatch".to_string()));
        }
        let resp = ReadPartResp {
            part_etag: meta.part_etag,
            shard_sha256: meta.shard_sha256,
            shard_bytes: data.to_vec(),
        };
        let payload = serde_json::to_vec(&resp).map_err(|e| NetError::Io(e.to_string()))?;
        Ok(RpcFrame::new(METHOD_DISK_READ_PART, payload))
    }

    async fn handle_cleanup_part(&self, req: CleanupPartReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let dir = format!(".rustfs.sys/multipart/{}", req.upload_id);
        let path = multipart_part_path(&req.upload_id, req.part_number, &req.attempt_id);
        let meta_path = format!("{path}.meta");
        let _ = disk.remove_file(&path).await;
        let _ = disk.remove_file(&meta_path).await;
        let _ = disk.fsync_dir(&dir).await;
        Ok(RpcFrame::new(METHOD_DISK_CLEANUP_PART, Vec::new()))
    }

    async fn handle_cleanup_mp(&self, req: CleanupMultipartReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        let dir = format!(".rustfs.sys/multipart/{}", req.upload_id);
        let _ = disk.remove_dir_all(&dir).await;
        let _ = disk.fsync_dir(".rustfs.sys/multipart").await;
        Ok(RpcFrame::new(METHOD_DISK_CLEANUP_MP, Vec::new()))
    }

    async fn handle_sweep_tmp(&self, req: SweepTmpReq) -> Result<RpcFrame, NetError> {
        let disk = self.disk(req.drive_idx)?;
        if let Ok(entries) = disk.list_dir(".rustfs.sys/tmp").await {
            for entry in entries {
                let _ = disk
                    .remove_dir_all(&format!(".rustfs.sys/tmp/{entry}"))
                    .await;
            }
            let _ = disk.fsync_dir(".rustfs.sys/tmp").await;
        }
        Ok(RpcFrame::new(METHOD_DISK_SWEEP_TMP, Vec::new()))
    }
}

#[async_trait]
impl RpcHandler for NodeRpcServer {
    async fn handle(&self, from: &str, request: RpcFrame) -> Result<RpcFrame, NetError> {
        match request.method.as_str() {
            METHOD_LOCK_ACQUIRE | METHOD_LOCK_RELEASE => self.locks.handle(from, request).await,
            METHOD_DISK_STAGE => {
                let req: CommitShardReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_stage(req).await
            }
            METHOD_DISK_COMMIT => {
                let req: CommitShardReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_commit(req).await
            }
            METHOD_DISK_ROLLBACK => {
                let req: RollbackMetaReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_rollback(req).await
            }
            METHOD_DISK_READ => {
                let req: ReadShardReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_read(req).await
            }
            METHOD_DISK_LIST_BUCKET => {
                let req: ListBucketReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_list_bucket(req).await
            }
            METHOD_DISK_HEAL_WRITE => {
                let req: HealWriteReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_heal_write(req).await
            }
            METHOD_DISK_STAGE_PART => {
                let req: StagePartReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_stage_part(req).await
            }
            METHOD_DISK_READ_PART => {
                let req: ReadPartReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_read_part(req).await
            }
            METHOD_DISK_CLEANUP_MP => {
                let req: CleanupMultipartReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_cleanup_mp(req).await
            }
            METHOD_DISK_CLEANUP_PART => {
                let req: CleanupPartReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_cleanup_part(req).await
            }
            METHOD_DISK_SWEEP_TMP => {
                let req: SweepTmpReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.handle_sweep_tmp(req).await
            }
            other => Err(NetError::Io(format!("unknown RPC method: {other}"))),
        }
    }
}

/// Active multipart upload metadata tracked on the coordinator.
#[derive(Clone, Debug)]
struct MultipartSession {
    bucket: String,
    key: String,
    parts: BTreeMap<u32, MultipartPart>,
}

#[derive(Clone, Debug)]
struct MultipartPart {
    attempt_id: String,
    etag: String,
    original_len: usize,
}

/// A simulated multi-node RustFS cluster wired over deterministic runtime traits.
pub struct SimCluster {
    pub topology: TopologySpec,
    pub clock: SimClock,
    pub rng: SimRng,
    pub network: SimNetwork,
    pub nodes: BTreeMap<String, SimNodeEnv>,
    pub lock_services: BTreeMap<String, NodeLockService>,
    pub crashes: CrashRegistry,
    pub buggify: Buggify,
    pub probes: ProbeRegistry,
    multipart_sessions: BTreeMap<String, MultipartSession>,
}

impl SimCluster {
    pub fn new(topology: TopologySpec, seed: u64) -> Self {
        let clock = SimClock::new().with_auto_advance(true);
        let rng = SimRng::from_seed(seed);
        let network = SimNetwork::new(clock.clone(), rng.fork("network"));
        let crashes = CrashRegistry::new();
        let buggify = Buggify::seeded(seed, 0.35);
        let probes = ProbeRegistry::new();

        let mut nodes = BTreeMap::new();
        let mut lock_services = BTreeMap::new();
        for node_id in topology.node_ids() {
            let env = SimNodeEnv::new(
                node_id.clone(),
                &clock,
                &rng,
                network.clone(),
                topology.drives_per_node,
            );
            let lock_svc = NodeLockService::new(env.clock.clone());
            let server = Arc::new(NodeRpcServer {
                disks: env.disks.clone(),
                locks: lock_svc.clone(),
                crashes: crashes.clone(),
                buggify: buggify.clone(),
            });
            network.register(node_id.clone(), server);
            lock_services.insert(node_id.clone(), lock_svc);
            nodes.insert(node_id, env);
        }

        Self {
            topology,
            clock,
            rng,
            network,
            nodes,
            lock_services,
            crashes,
            buggify,
            probes,
            multipart_sessions: BTreeMap::new(),
        }
    }

    /// Enumerate every drive slot `(node_id, local_drive_idx, global_shard_idx)`.
    pub fn drive_slots(&self) -> Vec<(String, usize, usize)> {
        let mut slots = Vec::with_capacity(self.topology.total_drives);
        let mut global_idx = 0usize;
        for (node_id, env) in &self.nodes {
            for local_idx in 0..env.disks.len() {
                slots.push((node_id.clone(), local_idx, global_idx));
                global_idx += 1;
            }
        }
        slots
    }

    pub fn lock_client(&self, via_node: &str) -> QuorumLockClient {
        QuorumLockClient::new(via_node, self.topology.node_ids(), self.network.clone())
    }

    /// Simulate hard power loss on a node: drops un-fsynced disk buffers, clears
    /// volatile locks, and marks node unreachable on the network.
    pub fn crash_node(&self, node_id: &str) {
        self.network.set_node_down(node_id, true);
        if let Some(env) = self.nodes.get(node_id) {
            for disk in &env.disks {
                disk.crash_and_reboot();
            }
        }
        if let Some(lock_svc) = self.lock_services.get(node_id) {
            lock_svc.clear_on_crash();
        }
    }

    /// Bring a previously crashed node back online.
    pub fn restart_node(&self, node_id: &str) {
        self.network.set_node_down(node_id, false);
    }

    /// Take a single drive offline or back online.
    pub fn set_drive_offline(&self, node_id: &str, drive_idx: usize, offline: bool) {
        if let Some(env) = self.nodes.get(node_id)
            && let Some(disk) = env.disks.get(drive_idx)
        {
            disk.set_offline(offline);
        }
    }

    /// Inject silent bitrot on a specific object's shard on `(node_id, drive_idx)`.
    pub fn inject_object_bitrot(
        &self,
        node_id: &str,
        drive_idx: usize,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> bool {
        let Some(env) = self.nodes.get(node_id) else {
            return false;
        };
        let Some(disk) = env.disks.get(drive_idx) else {
            return false;
        };
        let path = format!("{bucket}/{key}/{version_id}/part.1");
        disk.inject_bitrot(&path)
    }

    /// Inject silent bitrot directly into `xl.meta` on `(node_id, drive_idx)`
    /// (reproduces `rustfs/rustfs#5837`).
    pub fn inject_xl_meta_bitrot(
        &self,
        node_id: &str,
        drive_idx: usize,
        bucket: &str,
        key: &str,
    ) -> bool {
        let Some(env) = self.nodes.get(node_id) else {
            return false;
        };
        let Some(disk) = env.disks.get(drive_idx) else {
            return false;
        };
        let path = format!("{bucket}/{key}/xl.meta");
        disk.inject_bitrot(&path)
    }

    /// Inject silent tail-truncation corruption on an object's shard
    /// (reproduces `rustfs/rustfs#8005` 1-byte tail truncation).
    pub fn inject_object_tail_truncate(
        &self,
        node_id: &str,
        drive_idx: usize,
        bucket: &str,
        key: &str,
        version_id: &str,
        trim_bytes: usize,
    ) -> bool {
        let Some(env) = self.nodes.get(node_id) else {
            return false;
        };
        let Some(disk) = env.disks.get(drive_idx) else {
            return false;
        };
        let path = format!("{bucket}/{key}/{version_id}/part.1");
        disk.inject_tail_truncate(&path, trim_bytes)
    }

    /// Heal all network partitions, restart all downed nodes, bring all drives
    /// online, and reset clock skews.
    pub fn heal_infrastructure(&self) {
        self.network.heal_all();
        self.clock.clear_faults();
        for (node_id, env) in &self.nodes {
            self.network.set_node_down(node_id, false);
            for disk in &env.disks {
                disk.set_offline(false);
            }
        }
    }

    async fn read_all_metas(
        &self,
        via_node: &str,
        bucket: &str,
        key: &str,
        include_data: bool,
    ) -> (usize, Vec<(usize, XlMeta, Option<Vec<u8>>)>) {
        let slots = self.drive_slots();
        let mut join_set = tokio::task::JoinSet::new();
        for (ord, (node_id, drive_idx, global_idx)) in slots.into_iter().enumerate() {
            let net = self.network.clone();
            let caller = via_node.to_string();
            let req = ReadShardReq {
                drive_idx,
                bucket: bucket.to_string(),
                key: key.to_string(),
                include_data,
            };
            let payload = serde_json::to_vec(&req).expect("serialize ReadShardReq");
            join_set.spawn(async move {
                let res = net
                    .call(&caller, &node_id, RpcFrame::new(METHOD_DISK_READ, payload))
                    .await;
                (ord, node_id, drive_idx, global_idx, res)
            });
        }
        let mut ordered = vec![None; self.topology.total_drives];
        while let Some(Ok((ord, node_id, drive_idx, global_idx, res))) = join_set.join_next().await
        {
            ordered[ord] = Some((node_id, drive_idx, global_idx, res));
        }

        let mut responded = 0usize;
        let mut found = Vec::new();
        for (node_id, drive_idx, global_idx, res) in ordered.into_iter().flatten() {
            if let Ok(frame) = res
                && let Ok(resp) = serde_json::from_slice::<ReadShardResp>(&frame.payload)
            {
                responded += 1;
                match resp {
                    ReadShardResp::Found { meta, shard_bytes } => {
                        found.push((global_idx, meta, shard_bytes));
                    }
                    ReadShardResp::CorruptMeta => {
                        self.probes.reachable(
                            "ecstore.xl_meta_bitrot_detected",
                            json!({"bucket": bucket, "key": key, "node": node_id, "drive": drive_idx}),
                        );
                    }
                    ReadShardResp::NotFound => {}
                }
            }
        }
        (responded, found)
    }

    /// Execute an erasure-coded `PutObject` with optional conditional headers.
    pub async fn put_object(
        &self,
        via_node: &str,
        bucket: &str,
        key: &str,
        payload: &[u8],
        conditions: PutConditions,
    ) -> Result<PutResult, StoreError> {
        self.commit_object_inner(via_node, bucket, key, payload, false, conditions, false)
            .await
    }

    /// Execute a versioned `DeleteObject` committing a delete marker across write quorum.
    pub async fn delete_object(
        &self,
        via_node: &str,
        bucket: &str,
        key: &str,
    ) -> Result<PutResult, StoreError> {
        self.commit_object_inner(
            via_node,
            bucket,
            key,
            &[],
            true,
            PutConditions::default(),
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_object_inner(
        &self,
        via_node: &str,
        bucket: &str,
        key: &str,
        payload: &[u8],
        is_delete_marker: bool,
        conditions: PutConditions,
        is_multipart_commit: bool,
    ) -> Result<PutResult, StoreError> {
        let resource = format!("{bucket}/{key}");
        let lock_client = self.lock_client(via_node);
        let owner = format!("{via_node}-{}", self.rng.gen_uuid_v4());
        let lease = lock_client
            .acquire(&resource, &owner, 10_000, false)
            .await
            .map_err(|e| StoreError::LockUnavailable(e.to_string()))?;

        let (responded, found) = self.read_all_metas(via_node, bucket, key, false).await;
        if responded < self.topology.read_quorum {
            lock_client.release(&lease).await;
            return Err(StoreError::ReadQuorumNotMet {
                healthy: responded,
                required: self.topology.read_quorum,
            });
        }

        let current_latest = found
            .iter()
            .max_by_key(|(_, m, _)| m.generation)
            .map(|(_, m, _)| m.clone());

        // Enforce S3 conditional write headers (`If-None-Match: *` and `If-Match`).
        if conditions.if_none_match_any
            && let Some(cur) = &current_latest
            && !cur.is_delete_marker
        {
            lock_client.release(&lease).await;
            return Err(StoreError::PreconditionFailed);
        }
        if let Some(expected_etag) = &conditions.if_match_sha256 {
            let matches = current_latest
                .as_ref()
                .is_some_and(|m| !m.is_delete_marker && &m.payload_sha256 == expected_etag);
            if !matches {
                lock_client.release(&lease).await;
                return Err(StoreError::PreconditionFailed);
            }
        }

        let next_gen = current_latest
            .as_ref()
            .map(|m| m.generation + 1)
            .unwrap_or(1);
        let version_id = self.rng.gen_uuid_v4().to_string();
        let tx_id = self.rng.gen_uuid_v4().to_string();
        let payload_sha256 = sha256_hex(payload);

        let shards = if is_delete_marker {
            Vec::new()
        } else {
            encode(
                payload,
                self.topology.data_shards,
                self.topology.parity_shards,
            )
            .map_err(|e| StoreError::Internal(e.to_string()))?
        };

        let slots = self.drive_slots();
        let mut req_payloads = Vec::with_capacity(slots.len());
        for (node_id, drive_idx, global_idx) in &slots {
            let (shard_bytes, shard_sha256) = if is_delete_marker {
                (Vec::new(), String::new())
            } else {
                let s = &shards[*global_idx];
                (s.bytes.clone(), s.sha256_hex.clone())
            };
            let meta = XlMeta {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: version_id.clone(),
                generation: next_gen,
                is_delete_marker,
                orig_len: payload.len(),
                payload_sha256: payload_sha256.clone(),
                shard_index: *global_idx,
                shard_sha256,
            };
            let req = CommitShardReq {
                drive_idx: *drive_idx,
                tx_id: tx_id.clone(),
                meta,
                shard_bytes,
                is_multipart_commit,
            };
            req_payloads.push((
                node_id.clone(),
                *drive_idx,
                serde_json::to_vec(&req).expect("serialize CommitShardReq"),
            ));
        }

        // Phase 1: Stage shards in `.rustfs.sys/tmp/<tx_id>` concurrently across all drives.
        // If staging fails to reach write quorum, abort BEFORE renaming `xl.meta` on any drive!
        let mut stage_join = tokio::task::JoinSet::new();
        for (ord, (node_id, drive_idx, req_bytes)) in req_payloads.iter().cloned().enumerate() {
            let net = self.network.clone();
            let caller = via_node.to_string();
            stage_join.spawn(async move {
                let res = net
                    .call(
                        &caller,
                        &node_id,
                        RpcFrame::new(METHOD_DISK_STAGE, req_bytes),
                    )
                    .await;
                (ord, node_id, drive_idx, res)
            });
        }
        let mut stage_results = vec![None; req_payloads.len()];
        while let Some(Ok((ord, node_id, drive_idx, res))) = stage_join.join_next().await {
            stage_results[ord] = Some((node_id, drive_idx, res));
        }

        let mut staged_indices = Vec::new();
        for (ord, (_node_id, _drive_idx, res)) in stage_results.into_iter().flatten().enumerate() {
            if matches!(res, Ok(_) | Err(NetError::ReplyDroppedAfterApply { .. })) {
                staged_indices.push(ord);
            }
        }

        if staged_indices.len() < self.topology.write_quorum {
            self.probes.reachable(
                "ecstore.write_quorum_rollback",
                json!({"key": resource, "acked": staged_indices.len(), "required": self.topology.write_quorum}),
            );
            lock_client.release(&lease).await;
            return Err(StoreError::WriteQuorumNotMet {
                acked: staged_indices.len(),
                required: self.topology.write_quorum,
            });
        }

        // Phase 2: Publish `xl.meta` concurrently across all staged drives.
        let mut commit_join = tokio::task::JoinSet::new();
        for ord in staged_indices {
            let (node_id, drive_idx, req_bytes) = req_payloads[ord].clone();
            let net = self.network.clone();
            let caller = via_node.to_string();
            commit_join.spawn(async move {
                let res = net
                    .call(
                        &caller,
                        &node_id,
                        RpcFrame::new(METHOD_DISK_COMMIT, req_bytes),
                    )
                    .await;
                (ord, node_id, drive_idx, res)
            });
        }
        let mut commit_results = vec![None; req_payloads.len()];
        while let Some(Ok((ord, node_id, drive_idx, res))) = commit_join.join_next().await {
            commit_results[ord] = Some((node_id, drive_idx, res));
        }

        let mut acked = 0usize;
        let mut reply_dropped = 0usize;
        let mut committed_slots = Vec::new();
        for (node_id, drive_idx, res) in commit_results.into_iter().flatten() {
            match res {
                Ok(_) => {
                    acked += 1;
                    committed_slots.push((node_id, drive_idx));
                }
                Err(NetError::ReplyDroppedAfterApply { .. }) => {
                    reply_dropped += 1;
                    committed_slots.push((node_id.clone(), drive_idx));
                    self.probes.reachable(
                        "ecstore.reply_dropped_after_apply",
                        json!({"key": resource, "node": node_id, "drive": drive_idx}),
                    );
                }
                Err(_) => {}
            }
        }

        if acked >= self.topology.write_quorum {
            if acked < self.topology.total_drives {
                self.probes.sometimes(
                    "ecstore.degraded_quorum_put_succeeded",
                    true,
                    json!({"key": resource, "acked": acked, "total": self.topology.total_drives}),
                );
            }
            lock_client.release(&lease).await;
            return Ok(PutResult {
                generation: next_gen,
                version_id,
                payload_sha256,
            });
        }

        if acked + reply_dropped >= self.topology.write_quorum {
            lock_client.release(&lease).await;
            return Err(StoreError::Indeterminate {
                generation: next_gen,
                version_id,
            });
        }

        // Write definitely failed below quorum -> roll back partial commits.
        self.probes.reachable(
            "ecstore.write_quorum_rollback",
            json!({"key": resource, "acked": acked, "required": self.topology.write_quorum}),
        );
        for (node_id, drive_idx) in committed_slots {
            let rb = RollbackMetaReq {
                drive_idx,
                bucket: bucket.to_string(),
                key: key.to_string(),
                failed_generation: next_gen,
            };
            let rb_bytes = serde_json::to_vec(&rb).expect("serialize RollbackMetaReq");
            let _ = self
                .network
                .call(
                    via_node,
                    &node_id,
                    RpcFrame::new(METHOD_DISK_ROLLBACK, rb_bytes),
                )
                .await;
        }
        lock_client.release(&lease).await;
        Err(StoreError::WriteQuorumNotMet {
            acked,
            required: self.topology.write_quorum,
        })
    }

    /// Execute a linearizable erasure-coded `GetObject` with bitrot detection
    /// and Reed-Solomon reconstruction.
    pub async fn get_object(
        &self,
        via_node: &str,
        bucket: &str,
        key: &str,
    ) -> Result<GetResult, StoreError> {
        let (responded, found) = self.read_all_metas(via_node, bucket, key, true).await;
        if responded < self.topology.read_quorum {
            return Err(StoreError::ReadQuorumNotMet {
                healthy: responded,
                required: self.topology.read_quorum,
            });
        }

        if found.is_empty() {
            return Err(StoreError::NotFound(format!("{bucket}/{key}")));
        }

        let unreachable = self.topology.total_drives.saturating_sub(responded);
        let mut by_gen: BTreeMap<u64, Vec<&ShardReadEntry>> = BTreeMap::new();
        for entry in &found {
            by_gen.entry(entry.1.generation).or_default().push(entry);
        }

        // Newest generation first. RustFS accepts a delete marker only at write
        // quorum (`default_write_quorum` / early-stop), which is data+1 when
        // data == parity. An object version is readable from any `data_shards`
        // healthy shards, including a write that reached exactly that many and
        // then failed the higher write quorum. A newer version that cannot have
        // been committed and cannot be reconstructed must not hide the older one.
        let mut skipped_higher_votes = 0usize;
        for (_gen, top_entries) in by_gen.into_iter().rev() {
            let canonical = &top_entries[0].1;
            let votes = top_entries.len();
            // Drives holding higher generations that were already proven to be
            // uncommitted orphans previously held an older generation (or were empty).
            let max_possible = votes + skipped_higher_votes + unreachable;

            // Any version (delete marker OR data object) whose cumulative support
            // `votes + skipped_higher_votes + unreachable < write_quorum` provably
            // never reached write quorum ([D-01]).
            if max_possible < self.topology.write_quorum {
                skipped_higher_votes += votes;
                self.probes.reachable(
                    "ecstore.skipped_provably_uncommitted_orphan",
                    json!({"bucket": bucket, "key": key, "orphan_gen": canonical.generation}),
                );
                continue;
            }

            if canonical.is_delete_marker {
                if votes + skipped_higher_votes >= self.topology.write_quorum {
                    return Err(StoreError::NotFound(format!("{bucket}/{key}")));
                }
                return Err(StoreError::ReadQuorumNotMet {
                    healthy: votes,
                    required: self.topology.write_quorum,
                });
            }

            // Verify per-shard SHA-256 checksums to filter out silent bitrot!
            let mut healthy_shards = Vec::new();
            let mut bitrot_detected = false;
            for (_global_idx, meta, maybe_bytes) in &top_entries {
                if let Some(bytes) = maybe_bytes {
                    if sha256_hex(bytes) == meta.shard_sha256 {
                        healthy_shards.push((meta.shard_index, bytes.clone()));
                    } else {
                        bitrot_detected = true;
                        self.probes.reachable(
                            "ecstore.bitrot_detected_on_read",
                            json!({"bucket": bucket, "key": key, "shard": meta.shard_index}),
                        );
                    }
                }
            }
            healthy_shards.sort_by_key(|(idx, _)| *idx);
            healthy_shards.dedup_by_key(|(idx, _)| *idx);

            if healthy_shards.len() < self.topology.data_shards {
                if max_possible < self.topology.write_quorum {
                    self.probes.reachable(
                        "ecstore.skipped_provably_uncommitted_orphan",
                        json!({"bucket": bucket, "key": key, "orphan_gen": canonical.generation}),
                    );
                    continue;
                }
                return Err(StoreError::ReadQuorumNotMet {
                    healthy: healthy_shards.len(),
                    required: self.topology.data_shards,
                });
            }

            let payload = reconstruct(
                &healthy_shards,
                self.topology.data_shards,
                self.topology.parity_shards,
                canonical.orig_len,
            )
            .map_err(|e| StoreError::Internal(e.to_string()))?;

            let computed_hash = sha256_hex(&payload);
            self.probes.always(
                "ecstore.reconstructed_payload_matches_meta_sha256",
                computed_hash == canonical.payload_sha256,
                json!({"bucket": bucket, "key": key, "gen": canonical.generation}),
            );
            if computed_hash != canonical.payload_sha256 {
                return Err(StoreError::Internal(
                    "reconstructed payload digest mismatch".to_string(),
                ));
            }

            if bitrot_detected {
                self.probes.sometimes(
                    "ecstore.bitrot_transparently_reconstructed",
                    true,
                    json!({"bucket": bucket, "key": key}),
                );
            }

            return Ok(GetResult {
                generation: canonical.generation,
                version_id: canonical.version_id.clone(),
                payload,
                payload_sha256: canonical.payload_sha256.clone(),
            });
        }

        Err(StoreError::NotFound(format!("{bucket}/{key}")))
    }

    /// Quorum-merged `ListObjectsV2` returning all live keys in `bucket`.
    pub async fn list_objects(
        &self,
        via_node: &str,
        bucket: &str,
    ) -> Result<Vec<ListedObject>, StoreError> {
        let mut responded = 0usize;
        let mut by_key: BTreeMap<String, Vec<XlMeta>> = BTreeMap::new();
        for (node_id, drive_idx, _) in self.drive_slots() {
            let req = ListBucketReq {
                drive_idx,
                bucket: bucket.to_string(),
            };
            let req_bytes = serde_json::to_vec(&req).expect("serialize ListBucketReq");
            if let Ok(frame) = self
                .network
                .call(
                    via_node,
                    &node_id,
                    RpcFrame::new(METHOD_DISK_LIST_BUCKET, req_bytes),
                )
                .await
                && let Ok(resp) = serde_json::from_slice::<ListBucketResp>(&frame.payload)
            {
                responded += 1;
                for meta in resp.metas {
                    by_key.entry(meta.key.clone()).or_default().push(meta);
                }
            }
        }
        if responded < self.topology.read_quorum {
            return Err(StoreError::ReadQuorumNotMet {
                healthy: responded,
                required: self.topology.read_quorum,
            });
        }

        let unreachable = self.topology.total_drives.saturating_sub(responded);
        let mut out = Vec::new();
        for (key, metas) in by_key {
            let mut gens: Vec<u64> = metas.iter().map(|meta| meta.generation).collect();
            gens.sort_unstable();
            gens.dedup();
            let mut choice: Option<&XlMeta> = None;
            let mut ambiguous = false;
            let mut skipped_higher_votes = 0usize;
            for generation in gens.into_iter().rev() {
                let top: Vec<&XlMeta> = metas
                    .iter()
                    .filter(|meta| meta.generation == generation)
                    .collect();
                let votes = top.len();
                let max_possible = votes + skipped_higher_votes + unreachable;
                if max_possible < self.topology.write_quorum {
                    skipped_higher_votes += votes;
                    continue;
                }
                if top[0].is_delete_marker {
                    if votes + skipped_higher_votes >= self.topology.write_quorum {
                        choice = None;
                        break;
                    }
                    ambiguous = true;
                    break;
                }
                if votes >= self.topology.read_quorum {
                    choice = Some(top[0]);
                    break;
                }
                if votes + unreachable < self.topology.read_quorum {
                    skipped_higher_votes += votes;
                    continue;
                }
                ambiguous = true;
                break;
            }
            if ambiguous {
                return Err(StoreError::ReadQuorumNotMet {
                    healthy: responded,
                    required: self.topology.read_quorum,
                });
            }
            if let Some(meta) = choice {
                out.push(ListedObject {
                    key,
                    generation: meta.generation,
                    version_id: meta.version_id.clone(),
                    payload_sha256: meta.payload_sha256.clone(),
                });
            }
        }
        Ok(out)
    }

    /// Create a new multipart upload session.
    pub fn create_multipart(&mut self, bucket: &str, key: &str) -> String {
        let upload_id = self.rng.gen_uuid_v4().to_string();
        self.multipart_sessions.insert(
            upload_id.clone(),
            MultipartSession {
                bucket: bucket.to_string(),
                key: key.to_string(),
                parts: BTreeMap::new(),
            },
        );
        upload_id
    }

    /// Upload and erasure-code a single multipart part onto write quorum drives.
    pub async fn upload_part(
        &mut self,
        via_node: &str,
        upload_id: &str,
        part_number: u32,
        data: &[u8],
    ) -> Result<(), StoreError> {
        if !self.multipart_sessions.contains_key(upload_id) {
            return Err(StoreError::UploadNotFound(upload_id.to_string()));
        }
        let shards = encode(data, self.topology.data_shards, self.topology.parity_shards)
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        let part = MultipartPart {
            attempt_id: self.rng.gen_uuid_v4().to_string(),
            etag: sha256_hex(data),
            original_len: data.len(),
        };

        let mut acked = 0usize;
        for (node_id, drive_idx, global_idx) in self.drive_slots() {
            let shard = &shards[global_idx];
            let req = StagePartReq {
                drive_idx,
                upload_id: upload_id.to_string(),
                part_number,
                attempt_id: part.attempt_id.clone(),
                part_etag: part.etag.clone(),
                shard_sha256: shard.sha256_hex.clone(),
                shard_bytes: shard.bytes.clone(),
            };
            let payload = serde_json::to_vec(&req).expect("serialize StagePartReq");
            if self
                .network
                .call(
                    via_node,
                    &node_id,
                    RpcFrame::new(METHOD_DISK_STAGE_PART, payload),
                )
                .await
                .is_ok()
            {
                acked += 1;
            }
        }

        if acked < self.topology.write_quorum {
            self.cleanup_multipart_part(via_node, upload_id, part_number, &part.attempt_id)
                .await;
            return Err(StoreError::WriteQuorumNotMet {
                acked,
                required: self.topology.write_quorum,
            });
        }

        let previous = self
            .multipart_sessions
            .get_mut(upload_id)
            .expect("upload session cannot change during staging")
            .parts
            .insert(part_number, part);
        if let Some(previous) = previous {
            self.cleanup_multipart_part(via_node, upload_id, part_number, &previous.attempt_id)
                .await;
        }
        Ok(())
    }

    async fn cleanup_multipart_part(
        &self,
        via_node: &str,
        upload_id: &str,
        part_number: u32,
        attempt_id: &str,
    ) {
        for (node_id, drive_idx, _) in self.drive_slots() {
            let req = CleanupPartReq {
                drive_idx,
                upload_id: upload_id.to_string(),
                part_number,
                attempt_id: attempt_id.to_string(),
            };
            let payload = serde_json::to_vec(&req).expect("serialize CleanupPartReq");
            let _ = self
                .network
                .call(
                    via_node,
                    &node_id,
                    RpcFrame::new(METHOD_DISK_CLEANUP_PART, payload),
                )
                .await;
        }
    }

    /// Atomically assemble staged multipart parts and commit the final object.
    pub async fn complete_multipart(
        &mut self,
        via_node: &str,
        upload_id: &str,
    ) -> Result<PutResult, StoreError> {
        let sess = self
            .multipart_sessions
            .get(upload_id)
            .cloned()
            .ok_or_else(|| StoreError::UploadNotFound(upload_id.to_string()))?;

        let mut assembled = Vec::new();
        for (&part_number, part) in &sess.parts {
            let mut shards = Vec::new();
            for (node_id, drive_idx, global_idx) in self.drive_slots() {
                let req = ReadPartReq {
                    drive_idx,
                    upload_id: upload_id.to_string(),
                    part_number,
                    attempt_id: part.attempt_id.clone(),
                };
                let payload = serde_json::to_vec(&req).expect("serialize ReadPartReq");
                let Ok(frame) = self
                    .network
                    .call(
                        via_node,
                        &node_id,
                        RpcFrame::new(METHOD_DISK_READ_PART, payload),
                    )
                    .await
                else {
                    continue;
                };
                let Ok(resp) = serde_json::from_slice::<ReadPartResp>(&frame.payload) else {
                    continue;
                };
                if resp.part_etag == part.etag && sha256_hex(&resp.shard_bytes) == resp.shard_sha256
                {
                    shards.push((global_idx, resp.shard_bytes));
                }
            }
            if shards.len() < self.topology.data_shards {
                return Err(StoreError::ReadQuorumNotMet {
                    healthy: shards.len(),
                    required: self.topology.data_shards,
                });
            }
            let part_bytes = reconstruct(
                &shards,
                self.topology.data_shards,
                self.topology.parity_shards,
                part.original_len,
            )
            .map_err(|e| StoreError::Internal(e.to_string()))?;
            if sha256_hex(&part_bytes) != part.etag {
                return Err(StoreError::Internal(format!(
                    "reconstructed payload digest mismatch for part {part_number}"
                )));
            }
            assembled.extend_from_slice(&part_bytes);
        }

        let res = self
            .commit_object_inner(
                via_node,
                &sess.bucket,
                &sess.key,
                &assembled,
                false,
                PutConditions::default(),
                true,
            )
            .await?;

        self.cleanup_multipart_parts(via_node, upload_id).await;
        self.multipart_sessions.remove(upload_id);
        Ok(res)
    }

    /// Abort a multipart upload and reclaim staged parts across all reachable drives.
    pub async fn abort_multipart(&mut self, via_node: &str, upload_id: &str) {
        self.cleanup_multipart_parts(via_node, upload_id).await;
        self.multipart_sessions.remove(upload_id);
    }

    async fn cleanup_multipart_parts(&self, via_node: &str, upload_id: &str) {
        for (node_id, drive_idx, _) in self.drive_slots() {
            let req = CleanupMultipartReq {
                drive_idx,
                upload_id: upload_id.to_string(),
            };
            let payload = serde_json::to_vec(&req).expect("serialize CleanupMultipartReq");
            let _ = self
                .network
                .call(
                    via_node,
                    &node_id,
                    RpcFrame::new(METHOD_DISK_CLEANUP_MP, payload),
                )
                .await;
        }
    }

    /// Heal a single object across all drives in the erasure set:
    /// reconstructs missing, stale, or bitrot-corrupted shards from any `k`
    /// healthy shards at the highest generation and writes them durably.
    pub async fn heal_object(
        &self,
        via_node: &str,
        bucket: &str,
        key: &str,
    ) -> Result<usize, StoreError> {
        let (responded, found) = self.read_all_metas(via_node, bucket, key, true).await;
        if found.is_empty() {
            return Ok(0);
        }

        let unreachable = self.topology.total_drives.saturating_sub(responded);
        let mut by_gen: BTreeMap<u64, Vec<&ShardReadEntry>> = BTreeMap::new();
        for entry in &found {
            by_gen.entry(entry.1.generation).or_default().push(entry);
        }

        // Select the highest generation that is recoverable (>= data_shards
        // healthy shards or >= read_quorum delete markers). Any higher
        // generation with `entries.len() + unreachable < data_shards` is a
        // provably uncommitted orphan and will be reconciled.
        let mut selected: Option<(XlMeta, BTreeMap<usize, Vec<u8>>, bool)> = None;
        let mut skipped_orphan = false;
        let mut skipped_higher_votes = 0usize;
        for (_gen, entries) in by_gen.into_iter().rev() {
            let canonical = &entries[0].1;
            let votes = entries.len();
            // On `k == m` (`3x2`, `4x2`), `data_shards < write_quorum`: any generation
            // with `votes + skipped_higher_votes + unreachable < write_quorum` provably
            // failed write quorum and MUST be rolled back / overwritten ([D-01]).
            if votes + skipped_higher_votes + unreachable < self.topology.write_quorum {
                skipped_orphan = true;
                skipped_higher_votes += votes;
                continue;
            }
            let mut healthy_by_slot: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
            for (global_idx, meta, maybe_bytes) in &entries {
                if canonical.is_delete_marker {
                    healthy_by_slot.insert(*global_idx, Vec::new());
                } else if let Some(bytes) = maybe_bytes
                    && sha256_hex(bytes) == meta.shard_sha256
                {
                    healthy_by_slot.insert(*global_idx, bytes.clone());
                }
            }
            let min_needed = if canonical.is_delete_marker {
                self.topology
                    .write_quorum
                    .saturating_sub(skipped_higher_votes)
            } else {
                self.topology.data_shards
            };
            if healthy_by_slot.len() >= min_needed {
                selected = Some((canonical.clone(), healthy_by_slot, skipped_orphan));
                break;
            }
            if healthy_by_slot.len() + unreachable < min_needed {
                skipped_orphan = true;
                skipped_higher_votes += votes;
                continue;
            }
            return Err(StoreError::ReadQuorumNotMet {
                healthy: healthy_by_slot.len(),
                required: min_needed,
            });
        }

        let Some((canonical, healthy_by_slot, force_overwrite_orphan)) = selected else {
            return Ok(0);
        };

        let repaired_shards = if canonical.is_delete_marker {
            Vec::new()
        } else {
            let avail: Vec<(usize, Vec<u8>)> = healthy_by_slot
                .iter()
                .map(|(&idx, b)| (idx, b.clone()))
                .collect();
            let payload = reconstruct(
                &avail,
                self.topology.data_shards,
                self.topology.parity_shards,
                canonical.orig_len,
            )
            .map_err(|e| StoreError::Internal(e.to_string()))?;
            encode(
                &payload,
                self.topology.data_shards,
                self.topology.parity_shards,
            )
            .map_err(|e| StoreError::Internal(e.to_string()))?
        };

        let mut healed_count = 0usize;
        for (node_id, drive_idx, global_idx) in self.drive_slots() {
            if healthy_by_slot.contains_key(&global_idx) {
                continue;
            }
            let (shard_bytes, shard_sha256) = if canonical.is_delete_marker {
                (Vec::new(), String::new())
            } else {
                let s = &repaired_shards[global_idx];
                (s.bytes.clone(), s.sha256_hex.clone())
            };
            let mut repaired_meta = canonical.clone();
            repaired_meta.shard_index = global_idx;
            repaired_meta.shard_sha256 = shard_sha256;

            let req = HealWriteReq {
                drive_idx,
                meta: repaired_meta,
                shard_bytes,
                force_overwrite_orphan,
            };
            let req_bytes = serde_json::to_vec(&req).expect("serialize HealWriteReq");
            if self
                .network
                .call(
                    via_node,
                    &node_id,
                    RpcFrame::new(METHOD_DISK_HEAL_WRITE, req_bytes),
                )
                .await
                .is_ok()
            {
                healed_count += 1;
            }
        }
        if healed_count > 0 {
            self.probes.reachable(
                "ecstore.heal_repaired_shards",
                json!({"bucket": bucket, "key": key, "healed_count": healed_count}),
            );
        }
        Ok(healed_count)
    }

    /// Sweep orphaned `.rustfs.sys/tmp/` staging directories across all drives.
    pub async fn sweep_tmp_orphans(&self, via_node: &str) {
        for (node_id, drive_idx, _) in self.drive_slots() {
            let req = SweepTmpReq { drive_idx };
            let payload = serde_json::to_vec(&req).expect("serialize SweepTmpReq");
            let _ = self
                .network
                .call(
                    via_node,
                    &node_id,
                    RpcFrame::new(METHOD_DISK_SWEEP_TMP, payload),
                )
                .await;
        }
    }

    /// Verify post-heal convergence: every drive in the erasure set holds the
    /// identical highest-generation `xl.meta` and valid shard checksum for every
    /// known key, and zero `.rustfs.sys/tmp/` orphans remain.
    pub async fn verify_cluster_convergence(&self, bucket: &str, keys: &[String]) -> Vec<String> {
        let mut errors = Vec::new();
        for key in keys {
            let mut generations = BTreeSet::new();
            let mut valid_drives = 0usize;
            for (node_id, drive_idx, _) in self.drive_slots() {
                let disk = &self.nodes[&node_id].disks[drive_idx];
                let meta_path = format!("{bucket}/{key}/xl.meta");
                if let Ok(bytes) = disk.read_file(&meta_path).await
                    && let Ok(meta) = serde_json::from_slice::<XlMeta>(&bytes)
                {
                    generations.insert(meta.generation);
                    if meta.is_delete_marker {
                        valid_drives += 1;
                    } else {
                        let part_path = format!("{bucket}/{key}/{}/part.1", meta.version_id);
                        if let Ok(part_bytes) = disk.read_file(&part_path).await {
                            if sha256_hex(&part_bytes) == meta.shard_sha256 {
                                valid_drives += 1;
                            } else {
                                errors.push(format!(
                                    "{bucket}/{key} on {node_id}:data{} still has bitrot after heal",
                                    drive_idx + 1
                                ));
                            }
                        }
                    }
                }
            }
            if generations.len() > 1 {
                errors.push(format!(
                    "{bucket}/{key} diverged generations across drives after heal: {generations:?}"
                ));
            }
            if !generations.is_empty() && valid_drives != self.topology.total_drives {
                errors.push(format!(
                    "{bucket}/{key} converged only {valid_drives}/{} drives",
                    self.topology.total_drives
                ));
            }
        }

        // Verify zero temp staging leaks after sweep.
        for (node_id, env) in &self.nodes {
            for (idx, disk) in env.disks.iter().enumerate() {
                let orphans: Vec<String> = disk
                    .all_files()
                    .into_iter()
                    .filter(|p| p.starts_with(".rustfs.sys/tmp/"))
                    .collect();
                if !orphans.is_empty() {
                    errors.push(format!(
                        "{node_id}:data{} leaked {} tmp orphan files: {:?}",
                        idx + 1,
                        orphans.len(),
                        orphans
                    ));
                }
            }
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::TopologyKind;
    use rustfs_dst_runtime::disk::DiskIo;

    async fn plant_meta(cluster: &SimCluster, drives: usize, meta: &XlMeta) {
        let bytes = Bytes::from(serde_json::to_vec(meta).expect("meta"));
        let path = format!("{}/{}/xl.meta", meta.bucket, meta.key);
        for (node_id, drive_idx, _) in cluster.drive_slots().into_iter().take(drives) {
            cluster.nodes[&node_id].disks[drive_idx]
                .write_file(&path, bytes.clone())
                .await
                .expect("plant xl.meta");
        }
    }

    fn delete_meta(generation: u64) -> XlMeta {
        XlMeta {
            bucket: "bkt".to_string(),
            key: "obj".to_string(),
            version_id: format!("del-{generation}"),
            generation,
            is_delete_marker: true,
            orig_len: 0,
            payload_sha256: String::new(),
            shard_index: 0,
            shard_sha256: String::new(),
        }
    }

    #[tokio::test]
    async fn sub_write_quorum_delete_marker_does_not_hide_the_object() {
        let cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 11);
        let payload = b"ledger-v1-visible";
        let put = cluster
            .put_object("n1", "bkt", "obj", payload, PutConditions::default())
            .await
            .expect("put");
        // 3x2 write quorum is 4. Three delete markers used to satisfy read
        // quorum (3) and were reported as NotFound.
        plant_meta(&cluster, 3, &delete_meta(put.generation + 1)).await;

        let got = cluster
            .get_object("n2", "bkt", "obj")
            .await
            .expect("older object remains readable");
        assert_eq!(got.payload, payload);
        assert_eq!(got.generation, put.generation);

        let listed = cluster.list_objects("n1", "bkt").await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "obj");

        plant_meta(
            &cluster,
            cluster.topology.total_drives,
            &delete_meta(put.generation + 2),
        )
        .await;
        assert!(matches!(
            cluster.get_object("n1", "bkt", "obj").await,
            Err(StoreError::NotFound(_))
        ));
        let listed = cluster
            .list_objects("n1", "bkt")
            .await
            .expect("list after quorum delete");
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn unreadable_uncommitted_version_falls_back_to_older_object() {
        let cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 12);
        let payload = b"committed-v1";
        let put = cluster
            .put_object("n1", "bkt", "obj", payload, PutConditions::default())
            .await
            .expect("put");
        let mut bogus = delete_meta(put.generation + 1);
        bogus.is_delete_marker = false;
        bogus.orig_len = 4;
        bogus.payload_sha256 = "not-a-real-payload".to_string();
        bogus.shard_sha256 = "00".to_string();
        // Metadata without a matching shard cannot be reconstructed, and three
        // copies are below write quorum, so GET must return v1 instead of failing closed.
        plant_meta(&cluster, 3, &bogus).await;
        let got = cluster
            .get_object("n3", "bkt", "obj")
            .await
            .expect("fallback");
        assert_eq!(got.payload, payload);
        assert_eq!(got.generation, put.generation);
    }

    #[tokio::test]
    async fn heal_does_not_promote_a_sub_write_quorum_delete() {
        let cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 13);
        let payload = b"keep-me";
        let put = cluster
            .put_object("n1", "bkt", "obj", payload, PutConditions::default())
            .await
            .expect("put");
        plant_meta(&cluster, 3, &delete_meta(put.generation + 1)).await;
        cluster.heal_object("n1", "bkt", "obj").await.expect("heal");
        let got = cluster
            .get_object("n2", "bkt", "obj")
            .await
            .expect("still live");
        assert_eq!(got.payload, payload);
        let errors = cluster
            .verify_cluster_convergence("bkt", &["obj".to_string()])
            .await;
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[tokio::test]
    async fn failed_upload_part_removes_only_that_attempt() {
        let mut cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 14);
        for (node_id, drive_idx, _) in cluster.drive_slots().into_iter().skip(3) {
            cluster.set_drive_offline(&node_id, drive_idx, true);
        }
        let upload_id = cluster.create_multipart("bkt", "obj");
        let err = cluster
            .upload_part("n1", &upload_id, 1, b"partial-part-bytes")
            .await;
        assert!(matches!(err, Err(StoreError::WriteQuorumNotMet { .. })));
        for env in cluster.nodes.values() {
            for disk in &env.disks {
                let leaked: Vec<String> = disk
                    .all_files()
                    .into_iter()
                    .filter(|path| path.contains("multipart"))
                    .collect();
                assert!(leaked.is_empty(), "{leaked:?}");
            }
        }
    }
    #[tokio::test]
    async fn failed_replacement_preserves_the_acknowledged_part() {
        let original = b"acknowledged-part";
        for replacement in [original.as_slice(), b"different-payload"] {
            let mut cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 15);
            let upload_id = cluster.create_multipart("bkt", "obj");
            // The acknowledged part initially exists on exactly the write quorum.
            for (node, drive, _) in cluster.drive_slots().into_iter().skip(4) {
                cluster.set_drive_offline(&node, drive, true);
            }
            cluster
                .upload_part("n1", &upload_id, 1, original)
                .await
                .expect("initial part");

            for (node, drive, _) in cluster.drive_slots().into_iter().skip(3) {
                cluster.set_drive_offline(&node, drive, true);
            }
            assert!(matches!(
                cluster.upload_part("n1", &upload_id, 1, replacement).await,
                Err(StoreError::WriteQuorumNotMet { .. })
            ));
            cluster.heal_infrastructure();

            cluster
                .complete_multipart("n1", &upload_id)
                .await
                .expect("previously acknowledged part must still complete");
            let got = cluster.get_object("n2", "bkt", "obj").await.expect("get");
            assert_eq!(got.payload, original);
        }
    }

    #[tokio::test]
    async fn successful_replacement_is_selected_by_completion() {
        let mut cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 16);
        let upload_id = cluster.create_multipart("bkt", "obj");
        cluster
            .upload_part("n1", &upload_id, 1, b"old-part")
            .await
            .expect("initial part");
        cluster
            .upload_part("n1", &upload_id, 1, b"new-part-with-different-length")
            .await
            .expect("replace part");

        cluster
            .complete_multipart("n1", &upload_id)
            .await
            .expect("complete replacement");
        let got = cluster.get_object("n2", "bkt", "obj").await.expect("get");
        assert_eq!(got.payload, b"new-part-with-different-length");
    }

    #[tokio::test]
    async fn sub_write_quorum_data_version_does_not_shadow_older_object_or_get_healed() {
        // 3x2: N=6, k=3, m=3, R=3, W=4. Planting 3 valid shards of v2 (< W=4)
        // must NEVER shadow v1 in GET/LIST or get promoted by heal_object ([D-01]).
        let cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 21);
        let v1 = b"committed-v1-payload";
        let put1 = cluster
            .put_object("n1", "bkt", "obj", v1, PutConditions::default())
            .await
            .expect("put v1");

        let v2 = b"uncommitted-v2-payload";
        let shards_v2 = encode(v2, 3, 3).expect("encode v2");
        for (node_id, drive_idx, global_idx) in cluster.drive_slots().into_iter().take(3) {
            let disk = &cluster.nodes[&node_id].disks[drive_idx];
            let ver_id = "orphan-v2".to_string();
            let part_path = format!("bkt/obj/{ver_id}/part.1");
            disk.write_file(&part_path, Bytes::from(shards_v2[global_idx].bytes.clone()))
                .await
                .unwrap();
            let meta = XlMeta {
                bucket: "bkt".into(),
                key: "obj".into(),
                version_id: ver_id,
                generation: put1.generation + 1,
                is_delete_marker: false,
                orig_len: v2.len(),
                payload_sha256: sha256_hex(v2),
                shard_index: global_idx,
                shard_sha256: shards_v2[global_idx].sha256_hex.clone(),
            };
            disk.write_file(
                "bkt/obj/xl.meta",
                Bytes::from(serde_json::to_vec(&meta).unwrap()),
            )
            .await
            .unwrap();
        }

        let got = cluster
            .get_object("n2", "bkt", "obj")
            .await
            .expect("v1 readable");
        assert_eq!(got.payload, v1);
        assert_eq!(got.generation, put1.generation);

        let listed = cluster.list_objects("n1", "bkt").await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].generation, put1.generation);

        cluster
            .heal_object("n1", "bkt", "obj")
            .await
            .expect("heal rolls back orphan v2");
        let errors = cluster
            .verify_cluster_convergence("bkt", &["obj".to_string()])
            .await;
        assert!(errors.is_empty(), "{errors:?}");
        let after_heal = cluster
            .get_object("n3", "bkt", "obj")
            .await
            .expect("after heal");
        assert_eq!(after_heal.payload, v1);
    }

    #[tokio::test]
    async fn rollback_cleans_uncommitted_meta_when_drive_missed_first_generation() {
        let cluster = SimCluster::new(TopologyKind::ThreeByTwo.spec(), 22);
        // Take n3:data2 offline during gen=1 so it has no xl.meta and no xl.meta.bkp.
        cluster.set_drive_offline("n3", 1, true);
        cluster
            .put_object("n1", "bkt", "obj", b"v1", PutConditions::default())
            .await
            .expect("v1 degraded put");
        cluster.set_drive_offline("n3", 1, false);

        // Plant failed gen=2 directly on n3:data2 (which has no xl.meta.bkp) and invoke rollback.
        let disk = &cluster.nodes["n3"].disks[1];
        let meta = XlMeta {
            bucket: "bkt".into(),
            key: "obj".into(),
            version_id: "failed-g2".into(),
            generation: 2,
            is_delete_marker: false,
            orig_len: 2,
            payload_sha256: sha256_hex(b"v2"),
            shard_index: 5,
            shard_sha256: sha256_hex(b"v2"),
        };
        disk.write_file(
            "bkt/obj/xl.meta",
            Bytes::from(serde_json::to_vec(&meta).unwrap()),
        )
        .await
        .unwrap();
        let rb = RollbackMetaReq {
            drive_idx: 1,
            bucket: "bkt".into(),
            key: "obj".into(),
            failed_generation: 2,
        };
        cluster
            .network
            .call(
                "n1",
                "n3",
                RpcFrame::new(METHOD_DISK_ROLLBACK, serde_json::to_vec(&rb).unwrap()),
            )
            .await
            .unwrap();
        assert!(matches!(
            disk.read_file("bkt/obj/xl.meta").await,
            Err(DiskError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_writers_with_if_match_cas_serialize_linearizably() {
        let cluster = Arc::new(SimCluster::new(TopologyKind::FourByFour.spec(), 23));
        let init = cluster
            .put_object("n1", "bkt", "cas-key", b"base", PutConditions::default())
            .await
            .expect("seed base");

        let c_a = Arc::clone(&cluster);
        let c_b = Arc::clone(&cluster);
        let etag_a = init.payload_sha256.clone();
        let etag_b = init.payload_sha256;

        let (res_a, res_b) = tokio::join!(
            c_a.put_object(
                "n1",
                "bkt",
                "cas-key",
                b"writer-a",
                PutConditions {
                    if_match_sha256: Some(etag_a),
                    if_none_match_any: false,
                }
            ),
            c_b.put_object(
                "n2",
                "bkt",
                "cas-key",
                b"writer-b",
                PutConditions {
                    if_match_sha256: Some(etag_b),
                    if_none_match_any: false,
                }
            )
        );
        let successes = usize::from(res_a.is_ok()) + usize::from(res_b.is_ok());
        assert_eq!(
            successes, 1,
            "expected exactly 1 CAS winner: a={res_a:?}, b={res_b:?}"
        );
    }
}
