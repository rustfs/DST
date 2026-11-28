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

//! Deterministic crash-consistent disk I/O abstraction for RustFS.
//!
//! [`SimDiskIo`] explicitly separates the **volatile page cache** from the
//! **durable media layer** so that RustFS's write-temp -> `fsync_file` ->
//! `rename` -> `fsync_dir` durability protocol can be tested against abrupt
//! power loss ([`SimDiskIo::crash_and_reboot`]), torn writes, silent bitrot,
//! `ENOSPC`, and drive-offline faults.

use crate::rng::{RngSource, SimRng};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Unified disk I/O errors modeled after RustFS's `ecstore::disk::DiskError`.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DiskError {
    #[error("file or directory not found: {0}")]
    NotFound(String),
    #[error("disk is offline")]
    Offline,
    #[error("no space left on device (ENOSPC)")]
    NoSpace,
    #[error("injected I/O error: {0}")]
    Io(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
}

/// Basic file metadata returned by [`DiskIo::stat`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileStat {
    pub size: u64,
    pub is_dir: bool,
}

/// Unified disk I/O trait replacing direct `tokio::fs` / `std::fs` calls in
/// RustFS's `LocalDisk`.
#[async_trait]
pub trait DiskIo: Send + Sync + std::fmt::Debug {
    async fn create_dir_all(&self, path: &str) -> Result<(), DiskError>;
    async fn write_file(&self, path: &str, data: Bytes) -> Result<(), DiskError>;
    async fn read_file(&self, path: &str) -> Result<Bytes, DiskError>;
    async fn rename(&self, from: &str, to: &str) -> Result<(), DiskError>;
    async fn remove_file(&self, path: &str) -> Result<(), DiskError>;
    async fn remove_dir_all(&self, path: &str) -> Result<(), DiskError>;
    async fn fsync_file(&self, path: &str) -> Result<(), DiskError>;
    async fn fsync_dir(&self, path: &str) -> Result<(), DiskError>;
    async fn list_dir(&self, path: &str) -> Result<Vec<String>, DiskError>;
    async fn stat(&self, path: &str) -> Result<FileStat, DiskError>;
}

/// Production [`DiskIo`] backed by `tokio::fs` rooted at a drive mount path.
#[derive(Clone, Debug)]
pub struct RealDiskIo {
    root: PathBuf,
}

impl RealDiskIo {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn resolve(&self, rel: &str) -> Result<PathBuf, DiskError> {
        let cleaned = normalize_path(rel)?;
        if cleaned.is_empty() {
            return Ok(self.root.clone());
        }
        Ok(self.root.join(cleaned))
    }
}

fn map_io_err(path: &str, err: std::io::Error) -> DiskError {
    match err.kind() {
        std::io::ErrorKind::NotFound => DiskError::NotFound(path.to_string()),
        std::io::ErrorKind::AlreadyExists => DiskError::AlreadyExists(path.to_string()),
        std::io::ErrorKind::StorageFull => DiskError::NoSpace,
        _ => DiskError::Io(err.to_string()),
    }
}

#[async_trait]
impl DiskIo for RealDiskIo {
    async fn create_dir_all(&self, path: &str) -> Result<(), DiskError> {
        let full = self.resolve(path)?;
        tokio::fs::create_dir_all(&full)
            .await
            .map_err(|e| map_io_err(path, e))
    }

    async fn write_file(&self, path: &str, data: Bytes) -> Result<(), DiskError> {
        let full = self.resolve(path)?;
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| map_io_err(path, e))?;
        }
        tokio::fs::write(&full, &data)
            .await
            .map_err(|e| map_io_err(path, e))
    }

    async fn read_file(&self, path: &str) -> Result<Bytes, DiskError> {
        let full = self.resolve(path)?;
        let bytes = tokio::fs::read(&full)
            .await
            .map_err(|e| map_io_err(path, e))?;
        Ok(Bytes::from(bytes))
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), DiskError> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| map_io_err(to, e))?;
        }
        tokio::fs::rename(&src, &dst)
            .await
            .map_err(|e| map_io_err(from, e))
    }

    async fn remove_file(&self, path: &str) -> Result<(), DiskError> {
        let full = self.resolve(path)?;
        tokio::fs::remove_file(&full)
            .await
            .map_err(|e| map_io_err(path, e))
    }

    async fn remove_dir_all(&self, path: &str) -> Result<(), DiskError> {
        let full = self.resolve(path)?;
        tokio::fs::remove_dir_all(&full)
            .await
            .map_err(|e| map_io_err(path, e))
    }

    async fn fsync_file(&self, path: &str) -> Result<(), DiskError> {
        let full = self.resolve(path)?;
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&full)
            .await
            .map_err(|e| map_io_err(path, e))?;
        file.sync_all().await.map_err(|e| map_io_err(path, e))
    }

    async fn fsync_dir(&self, path: &str) -> Result<(), DiskError> {
        let full = self.resolve(path)?;
        let dir = tokio::fs::File::open(&full)
            .await
            .map_err(|e| map_io_err(path, e))?;
        dir.sync_all().await.map_err(|e| map_io_err(path, e))
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>, DiskError> {
        let full = self.resolve(path)?;
        let mut entries = tokio::fs::read_dir(&full)
            .await
            .map_err(|e| map_io_err(path, e))?;
        let mut out = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| map_io_err(path, e))?
        {
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    async fn stat(&self, path: &str) -> Result<FileStat, DiskError> {
        let full = self.resolve(path)?;
        let meta = tokio::fs::metadata(&full)
            .await
            .map_err(|e| map_io_err(path, e))?;
        Ok(FileStat {
            size: meta.len(),
            is_dir: meta.is_dir(),
        })
    }
}

/// Fault injection parameters for a simulated drive.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiskFaultConfig {
    /// Drive completely unreachable (`DiskError::Offline`).
    pub offline: bool,
    /// Optional byte quota; writes exceeding this fail with `DiskError::NoSpace`.
    pub capacity_bytes: Option<u64>,
    /// Probability `[0.0, 1.0]` of an injected write I/O error.
    pub write_error_prob: f64,
    /// Probability `[0.0, 1.0]` of an injected read I/O error.
    pub read_error_prob: f64,
    /// Probability `[0.0, 1.0]` that a write tears (persists only a prefix) before returning `Io`.
    pub torn_write_prob: f64,
}

/// Inode tracked separately from directory entries so file bytes and names
/// become durable at different barriers.
///
/// - [`DiskIo::fsync_file`] copies `volatile_data` into `durable_data` and does
///   not publish the directory entry.
/// - [`DiskIo::fsync_dir`] publishes this directory's child names and makes the
///   directory reachable from the filesystem root. It does **not** flush dirty
///   file bytes.
#[derive(Clone, Debug)]
struct Inode {
    is_dir: bool,
    volatile_data: Bytes,
    durable_data: Option<Bytes>,
    volatile_children: BTreeMap<String, u64>,
    durable_children: BTreeMap<String, u64>,
}

impl Inode {
    fn file() -> Self {
        Self {
            is_dir: false,
            volatile_data: Bytes::new(),
            durable_data: None,
            volatile_children: BTreeMap::new(),
            durable_children: BTreeMap::new(),
        }
    }

    fn dir() -> Self {
        Self {
            is_dir: true,
            volatile_data: Bytes::new(),
            durable_data: None,
            volatile_children: BTreeMap::new(),
            durable_children: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct SimDiskInner {
    id: String,
    inodes: BTreeMap<u64, Inode>,
    next_inode: u64,
    root: u64,
    faults: DiskFaultConfig,
    /// Total power-loss crashes simulated on this drive.
    crash_count: u64,
}

impl SimDiskInner {
    fn empty(id: String) -> Self {
        let root = 1;
        let mut inodes = BTreeMap::new();
        inodes.insert(root, Inode::dir());
        Self {
            id,
            inodes,
            next_inode: 2,
            root,
            faults: DiskFaultConfig::default(),
            crash_count: 0,
        }
    }

    fn alloc(&mut self, is_dir: bool) -> u64 {
        let id = self.next_inode;
        self.next_inode += 1;
        self.inodes
            .insert(id, if is_dir { Inode::dir() } else { Inode::file() });
        id
    }

    fn children(&self, id: u64, durable: bool) -> Option<&BTreeMap<String, u64>> {
        let inode = self.inodes.get(&id)?;
        Some(if durable {
            &inode.durable_children
        } else {
            &inode.volatile_children
        })
    }

    fn lookup(&self, path: &str, durable: bool) -> Option<u64> {
        let mut id = self.root;
        if path.is_empty() {
            return Some(id);
        }
        for part in path.split('/') {
            id = *self.children(id, durable)?.get(part)?;
        }
        Some(id)
    }

    fn ensure_online(&self) -> Result<(), DiskError> {
        if self.faults.offline {
            Err(DiskError::Offline)
        } else {
            Ok(())
        }
    }

    /// Create missing volatile directories along `path` and return the directory inode.
    fn ensure_volatile_dir(&mut self, path: &str) -> Result<u64, DiskError> {
        let mut id = self.root;
        if path.is_empty() {
            return Ok(id);
        }
        for part in path.split('/') {
            if let Some(child) = self
                .inodes
                .get(&id)
                .and_then(|inode| inode.volatile_children.get(part))
                .copied()
            {
                if !self.inodes.get(&child).is_some_and(|inode| inode.is_dir) {
                    return Err(DiskError::AlreadyExists(path.to_string()));
                }
                id = child;
            } else {
                let child = self.alloc(true);
                self.inodes
                    .get_mut(&id)
                    .expect("parent inode")
                    .volatile_children
                    .insert(part.to_string(), child);
                id = child;
            }
        }
        Ok(id)
    }

    /// Link each path component into its parent's durable directory so a nested
    /// `fsync_dir` stays reachable after power loss. Sibling entries of those
    /// parents are left untouched — only this chain is published.
    fn publish_volatile_path(&mut self, path: &str) {
        let mut parent = self.root;
        for part in path.split('/').filter(|part| !part.is_empty()) {
            let Some(child) = self
                .inodes
                .get(&parent)
                .and_then(|inode| inode.volatile_children.get(part))
                .copied()
            else {
                return;
            };
            self.inodes
                .get_mut(&parent)
                .expect("parent inode")
                .durable_children
                .insert(part.to_string(), child);
            parent = child;
        }
    }

    fn total_volatile_bytes(&self) -> u64 {
        self.inodes
            .values()
            .filter(|inode| !inode.is_dir)
            .map(|inode| inode.volatile_data.len() as u64)
            .sum()
    }

    fn crash_and_reboot(&mut self) {
        for inode in self.inodes.values_mut() {
            inode.volatile_children = inode.durable_children.clone();
            if !inode.is_dir {
                inode.volatile_data = inode.durable_data.clone().unwrap_or_else(Bytes::new);
            }
        }
        self.gc_unreachable();
        self.crash_count += 1;
    }

    fn gc_unreachable(&mut self) {
        let mut reachable = BTreeSet::new();
        let mut stack = vec![self.root];
        while let Some(id) = stack.pop() {
            if !reachable.insert(id) {
                continue;
            }
            if let Some(inode) = self.inodes.get(&id) {
                stack.extend(inode.volatile_children.values().copied());
            }
        }
        self.inodes.retain(|id, _| reachable.contains(id));
    }

    fn walk(
        &self,
        id: u64,
        prefix: &str,
        durable: bool,
        files: &mut Vec<(String, Bytes)>,
        dirs: &mut Vec<String>,
    ) {
        if let Some(inode) = self.inodes.get(&id)
            && inode.is_dir
        {
            dirs.push(prefix.to_string());
        }
        let Some(children) = self.children(id, durable) else {
            return;
        };
        for (name, child) in children {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Some(inode) = self.inodes.get(child) else {
                continue;
            };
            if inode.is_dir {
                self.walk(*child, &path, durable, files, dirs);
            } else {
                let data = if durable {
                    inode.durable_data.clone().unwrap_or_else(Bytes::new)
                } else {
                    inode.volatile_data.clone()
                };
                files.push((path, data));
            }
        }
    }
}

fn split_parent(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None => ("", path),
    }
}

/// Deterministic crash-consistent virtual disk simulator.
///
/// Models:
/// - **Inode bytes vs directory entries**: `fsync_file` persists file bytes
///   only. `fsync_dir` persists that directory's names and makes the directory
///   reachable from the root. It does not flush dirty file data.
/// - **Power loss ([`SimDiskIo::crash_and_reboot`])**: restores every inode
///   from its durable bytes and durable directory links.
/// - **Bitrot ([`SimDiskIo::inject_bitrot`])**: flips a deterministic byte in a
///   persisted file on both layers to test checksum detection & erasure healing.
/// - **Capacity, EIO, torn writes, and offline drives**.
#[derive(Clone, Debug)]
pub struct SimDiskIo {
    inner: Arc<Mutex<SimDiskInner>>,
    rng: SimRng,
}

impl SimDiskIo {
    pub fn new(id: impl Into<String>, rng: SimRng) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimDiskInner::empty(id.into()))),
            rng,
        }
    }

    pub fn id(&self) -> String {
        self.inner
            .lock()
            .expect("SimDiskIo lock poisoned")
            .id
            .clone()
    }

    pub fn set_faults(&self, faults: DiskFaultConfig) {
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.faults = faults;
    }

    pub fn set_offline(&self, offline: bool) {
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.faults.offline = offline;
    }

    pub fn is_offline(&self) -> bool {
        self.inner
            .lock()
            .expect("SimDiskIo lock poisoned")
            .faults
            .offline
    }

    /// Simulate an abrupt power failure and reboot: every un-fsynced write or
    /// directory mutation is lost, and the OS boots from the durable image.
    pub fn crash_and_reboot(&self) {
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.crash_and_reboot();
    }

    /// Deterministically corrupt one byte of `path` on both volatile and durable
    /// layers when they still have the same length (silent bitrot). Returns
    /// `true` if the file existed and was flipped.
    pub fn inject_bitrot(&self, path: &str) -> bool {
        let Ok(norm) = normalize_path(path) else {
            return false;
        };
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        let Some(id) = inner.lookup(&norm, false) else {
            return false;
        };
        let Some(existing) = inner.inodes.get(&id).and_then(|inode| {
            if inode.is_dir || inode.volatile_data.is_empty() {
                None
            } else {
                Some(inode.volatile_data.clone())
            }
        }) else {
            return false;
        };
        let idx = self.rng.gen_range_usize(existing.len());
        let mut corrupted = existing.to_vec();
        corrupted[idx] ^= 0xFF;
        let bytes = Bytes::from(corrupted);
        let inode = inner.inodes.get_mut(&id).expect("inode");
        if inode
            .durable_data
            .as_ref()
            .is_some_and(|durable| durable.len() == existing.len())
        {
            let mut durable = inode.durable_data.as_ref().expect("durable bytes").to_vec();
            durable[idx] ^= 0xFF;
            inode.durable_data = Some(Bytes::from(durable));
        }
        inode.volatile_data = bytes;
        true
    }

    /// Wipe the entire drive (simulating drive replacement with a fresh empty disk).
    pub fn wipe_drive(&self) {
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        let id = inner.id.clone();
        let faults = inner.faults.clone();
        let crash_count = inner.crash_count;
        *inner = SimDiskInner::empty(id);
        inner.faults = faults;
        inner.crash_count = crash_count;
    }

    /// Return all file paths currently present in the volatile image.
    pub fn all_files(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        inner.walk(inner.root, "", false, &mut files, &mut dirs);
        files.into_iter().map(|(path, _)| path).collect()
    }

    /// Compute a deterministic SHA-256 digest of the durable namespace.
    pub fn durable_state_hash(&self) -> [u8; 32] {
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        inner.walk(inner.root, "", true, &mut files, &mut dirs);
        let mut hasher = Sha256::new();
        for dir in dirs {
            hasher.update(b"D:");
            hasher.update(dir.as_bytes());
            hasher.update(b"\n");
        }
        for (path, data) in files {
            hasher.update(b"F:");
            hasher.update(path.as_bytes());
            hasher.update(b"=");
            hasher.update(&data);
            hasher.update(b"\n");
        }
        hasher.finalize().into()
    }

    pub fn crash_count(&self) -> u64 {
        self.inner
            .lock()
            .expect("SimDiskIo lock poisoned")
            .crash_count
    }
}

fn normalize_path(raw: &str) -> Result<String, DiskError> {
    let mut parts = Vec::new();
    for segment in raw.split('/') {
        match segment {
            "" | "." => continue,
            ".." => return Err(DiskError::InvalidPath(raw.to_string())),
            s => parts.push(s),
        }
    }
    Ok(parts.join("/"))
}

#[async_trait]
impl DiskIo for SimDiskIo {
    async fn create_dir_all(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        inner.ensure_volatile_dir(&norm)?;
        Ok(())
    }

    async fn write_file(&self, path: &str, data: Bytes) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        if norm.is_empty() {
            return Err(DiskError::InvalidPath(path.to_string()));
        }
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        if self.rng.gen_bool(inner.faults.write_error_prob) {
            return Err(DiskError::Io("injected write failure".to_string()));
        }
        let (parent_path, name) = split_parent(&norm);
        let parent_id = inner.ensure_volatile_dir(parent_path)?;
        let existing = inner
            .inodes
            .get(&parent_id)
            .and_then(|inode| inode.volatile_children.get(name))
            .copied();
        if let Some(id) = existing
            && inner.inodes.get(&id).is_some_and(|inode| inode.is_dir)
        {
            return Err(DiskError::AlreadyExists(path.to_string()));
        }
        if let Some(cap) = inner.faults.capacity_bytes {
            let old_len = existing
                .and_then(|id| inner.inodes.get(&id))
                .map(|inode| inode.volatile_data.len() as u64)
                .unwrap_or(0);
            let projected = inner.total_volatile_bytes() - old_len + data.len() as u64;
            if projected > cap {
                return Err(DiskError::NoSpace);
            }
        }
        let torn = self.rng.gen_bool(inner.faults.torn_write_prob) && data.len() > 1;
        let stored = if torn {
            let cut = 1 + self.rng.gen_range_usize(data.len() - 1);
            data.slice(..cut)
        } else {
            data
        };
        if let Some(id) = existing {
            inner.inodes.get_mut(&id).expect("file inode").volatile_data = stored;
        } else {
            let id = inner.alloc(false);
            inner.inodes.get_mut(&id).expect("new file").volatile_data = stored;
            inner
                .inodes
                .get_mut(&parent_id)
                .expect("parent dir")
                .volatile_children
                .insert(name.to_string(), id);
        }
        if torn {
            return Err(DiskError::Io("injected torn write".to_string()));
        }
        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Bytes, DiskError> {
        let norm = normalize_path(path)?;
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        if self.rng.gen_bool(inner.faults.read_error_prob) {
            return Err(DiskError::Io("injected read failure".to_string()));
        }
        let id = inner
            .lookup(&norm, false)
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        let inode = inner.inodes.get(&id).expect("inode");
        if inode.is_dir {
            return Err(DiskError::InvalidPath(path.to_string()));
        }
        Ok(inode.volatile_data.clone())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), DiskError> {
        let src = normalize_path(from)?;
        let dst = normalize_path(to)?;
        if src.is_empty() || dst.is_empty() {
            return Err(DiskError::InvalidPath(from.to_string()));
        }
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        if self.rng.gen_bool(inner.faults.write_error_prob) {
            return Err(DiskError::Io("injected rename failure".to_string()));
        }
        let (src_parent, src_name) = split_parent(&src);
        let src_parent_id = inner
            .lookup(src_parent, false)
            .ok_or_else(|| DiskError::NotFound(from.to_string()))?;
        let src_id = inner
            .inodes
            .get(&src_parent_id)
            .and_then(|inode| inode.volatile_children.get(src_name))
            .copied()
            .ok_or_else(|| DiskError::NotFound(from.to_string()))?;
        let (dst_parent, dst_name) = split_parent(&dst);
        let dst_parent_id = inner.ensure_volatile_dir(dst_parent)?;
        inner
            .inodes
            .get_mut(&src_parent_id)
            .expect("src parent")
            .volatile_children
            .remove(src_name);
        inner
            .inodes
            .get_mut(&dst_parent_id)
            .expect("dst parent")
            .volatile_children
            .insert(dst_name.to_string(), src_id);
        Ok(())
    }

    async fn remove_file(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        let (parent, name) = split_parent(&norm);
        let parent_id = inner
            .lookup(parent, false)
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        let child = inner
            .inodes
            .get(&parent_id)
            .and_then(|inode| inode.volatile_children.get(name))
            .copied()
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        if inner.inodes.get(&child).is_some_and(|inode| inode.is_dir) {
            return Err(DiskError::InvalidPath(path.to_string()));
        }
        inner
            .inodes
            .get_mut(&parent_id)
            .expect("parent")
            .volatile_children
            .remove(name);
        Ok(())
    }

    async fn remove_dir_all(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        if norm.is_empty() {
            let root = inner.root;
            if let Some(inode) = inner.inodes.get_mut(&root) {
                inode.volatile_children.clear();
            }
            return Ok(());
        }
        let (parent, name) = split_parent(&norm);
        let Some(parent_id) = inner.lookup(parent, false) else {
            return Ok(());
        };
        inner
            .inodes
            .get_mut(&parent_id)
            .expect("parent")
            .volatile_children
            .remove(name);
        Ok(())
    }

    async fn fsync_file(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        let id = inner
            .lookup(&norm, false)
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        let inode = inner.inodes.get_mut(&id).expect("inode");
        if inode.is_dir {
            return Err(DiskError::InvalidPath(path.to_string()));
        }
        inode.durable_data = Some(inode.volatile_data.clone());
        Ok(())
    }

    async fn fsync_dir(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        let id = inner
            .lookup(&norm, false)
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        if !inner.inodes.get(&id).is_some_and(|inode| inode.is_dir) {
            return Err(DiskError::InvalidPath(path.to_string()));
        }
        if !norm.is_empty() {
            inner.publish_volatile_path(&norm);
        }
        let children = inner
            .inodes
            .get(&id)
            .expect("dir")
            .volatile_children
            .clone();
        inner.inodes.get_mut(&id).expect("dir").durable_children = children;
        Ok(())
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>, DiskError> {
        let norm = normalize_path(path)?;
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        let id = inner
            .lookup(&norm, false)
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        let inode = inner.inodes.get(&id).expect("inode");
        if !inode.is_dir {
            return Err(DiskError::InvalidPath(path.to_string()));
        }
        Ok(inode.volatile_children.keys().cloned().collect())
    }

    async fn stat(&self, path: &str) -> Result<FileStat, DiskError> {
        let norm = normalize_path(path)?;
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.ensure_online()?;
        let id = inner
            .lookup(&norm, false)
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        let inode = inner.inodes.get(&id).expect("inode");
        if inode.is_dir {
            Ok(FileStat {
                size: 0,
                is_dir: true,
            })
        } else {
            Ok(FileStat {
                size: inode.volatile_data.len() as u64,
                is_dir: false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn power_loss_drops_unfsynced_writes_and_preserves_fsynced_commits() {
        let disk = SimDiskIo::new("d1", SimRng::from_seed(7));
        disk.create_dir_all("bucket/obj").await.unwrap();
        disk.write_file("bucket/obj/xl.meta", Bytes::from_static(b"v1"))
            .await
            .unwrap();
        disk.fsync_file("bucket/obj/xl.meta").await.unwrap();
        disk.fsync_dir("bucket/obj").await.unwrap();

        // Stage v2 without fsyncing directory -> power loss must revert to v1!
        disk.write_file("bucket/obj/xl.meta.tmp", Bytes::from_static(b"v2"))
            .await
            .unwrap();
        disk.rename("bucket/obj/xl.meta.tmp", "bucket/obj/xl.meta")
            .await
            .unwrap();
        disk.crash_and_reboot();

        let after_crash = disk.read_file("bucket/obj/xl.meta").await.unwrap();
        assert_eq!(after_crash, Bytes::from_static(b"v1"));
    }

    #[tokio::test]
    async fn bitrot_flips_persisted_bytes_deterministically() {
        let d1 = SimDiskIo::new("d1", SimRng::from_seed(99));
        let d2 = SimDiskIo::new("d1", SimRng::from_seed(99));
        let payload = Bytes::from_static(b"rustfs-erasure-shard-payload");
        d1.write_file("s/part.1", payload.clone()).await.unwrap();
        d2.write_file("s/part.1", payload.clone()).await.unwrap();
        d1.fsync_file("s/part.1").await.unwrap();
        d2.fsync_file("s/part.1").await.unwrap();

        assert!(d1.inject_bitrot("s/part.1"));
        assert!(d2.inject_bitrot("s/part.1"));
        let b1 = d1.read_file("s/part.1").await.unwrap();
        let b2 = d2.read_file("s/part.1").await.unwrap();
        assert_ne!(b1, payload);
        assert_eq!(b1, b2);
    }

    #[tokio::test]
    async fn fsync_file_without_directory_sync_does_not_survive_crash() {
        let disk = SimDiskIo::new("d1", SimRng::from_seed(3));
        disk.create_dir_all("bucket/obj").await.unwrap();
        disk.write_file("bucket/obj/xl.meta", Bytes::from_static(b"v1"))
            .await
            .unwrap();
        disk.fsync_file("bucket/obj/xl.meta").await.unwrap();
        disk.crash_and_reboot();
        assert!(matches!(
            disk.read_file("bucket/obj/xl.meta").await,
            Err(DiskError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn fsync_dir_does_not_persist_dirty_file_bytes() {
        let disk = SimDiskIo::new("d1", SimRng::from_seed(4));
        disk.create_dir_all("bucket/obj").await.unwrap();
        disk.write_file("bucket/obj/xl.meta", Bytes::from_static(b"v1"))
            .await
            .unwrap();
        disk.fsync_file("bucket/obj/xl.meta").await.unwrap();
        disk.fsync_dir("bucket/obj").await.unwrap();

        disk.write_file("bucket/obj/xl.meta", Bytes::from_static(b"v2-dirty"))
            .await
            .unwrap();
        disk.fsync_dir("bucket/obj").await.unwrap();
        disk.crash_and_reboot();

        let after = disk.read_file("bucket/obj/xl.meta").await.unwrap();
        assert_eq!(after, Bytes::from_static(b"v1"));
    }

    #[tokio::test]
    async fn rename_without_dir_fsync_keeps_the_old_directory_entry() {
        let disk = SimDiskIo::new("d1", SimRng::from_seed(5));
        disk.create_dir_all("bucket/obj").await.unwrap();
        disk.write_file("bucket/obj/xl.meta", Bytes::from_static(b"v1"))
            .await
            .unwrap();
        disk.fsync_file("bucket/obj/xl.meta").await.unwrap();
        disk.fsync_dir("bucket/obj").await.unwrap();

        disk.rename("bucket/obj/xl.meta", "bucket/obj/xl.meta.next")
            .await
            .unwrap();
        disk.fsync_file("bucket/obj/xl.meta.next").await.unwrap();
        disk.crash_and_reboot();

        assert_eq!(
            disk.read_file("bucket/obj/xl.meta").await.unwrap(),
            Bytes::from_static(b"v1")
        );
        assert!(matches!(
            disk.read_file("bucket/obj/xl.meta.next").await,
            Err(DiskError::NotFound(_))
        ));
    }
}
