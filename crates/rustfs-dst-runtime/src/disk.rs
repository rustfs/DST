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
use std::path::{Path, PathBuf};
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

#[derive(Clone, Debug, Default)]
struct FsImage {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, Bytes>,
}

impl FsImage {
    fn new() -> Self {
        let mut dirs = BTreeSet::new();
        dirs.insert(String::new());
        Self {
            dirs,
            files: BTreeMap::new(),
        }
    }

    fn total_bytes(&self) -> u64 {
        self.files.values().map(|b| b.len() as u64).sum()
    }

    fn ensure_parents(&mut self, path: &str) {
        let mut current = String::new();
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.len() <= 1 {
            return;
        }
        for part in &parts[..parts.len() - 1] {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(part);
            self.dirs.insert(current.clone());
        }
    }
}

#[derive(Debug)]
struct SimDiskInner {
    id: String,
    /// Volatile OS page cache visible to live reads/writes.
    volatile: FsImage,
    /// Durable platter/NVMe image populated only via `fsync_file` / `fsync_dir`.
    durable: FsImage,
    faults: DiskFaultConfig,
    /// Total power-loss crashes simulated on this drive.
    crash_count: u64,
}

/// Deterministic crash-consistent virtual disk simulator.
///
/// Models:
/// - **Volatile vs durable split**: writes land in `volatile` and only reach
///   `durable` when `fsync_file` is called; directory entries (renames,
///   unlinks, mkdirs) only reach `durable` when `fsync_dir` is called on the
///   parent directory.
/// - **Power loss ([`SimDiskIo::crash_and_reboot`])**: discards all un-fsynced
///   volatile buffers and restores `volatile = durable`.
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
            inner: Arc::new(Mutex::new(SimDiskInner {
                id: id.into(),
                volatile: FsImage::new(),
                durable: FsImage::new(),
                faults: DiskFaultConfig::default(),
                crash_count: 0,
            })),
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
        inner.volatile = inner.durable.clone();
        inner.crash_count += 1;
    }

    /// Deterministically corrupt one byte of `path` on both volatile and durable
    /// layers (silent bitrot). Returns `true` if the file existed and was flipped.
    pub fn inject_bitrot(&self, path: &str) -> bool {
        let Ok(norm) = normalize_path(path) else {
            return false;
        };
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        let Some(existing) = inner.volatile.files.get(&norm).cloned() else {
            return false;
        };
        if existing.is_empty() {
            return false;
        }
        let idx = self.rng.gen_range_usize(existing.len());
        let mut corrupted = existing.to_vec();
        corrupted[idx] ^= 0xFF;
        let bytes = Bytes::from(corrupted);
        inner.volatile.files.insert(norm.clone(), bytes.clone());
        if inner.durable.files.contains_key(&norm) {
            inner.durable.files.insert(norm, bytes);
        }
        true
    }

    /// Wipe the entire drive (simulating drive replacement with a fresh empty disk).
    pub fn wipe_drive(&self) {
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.volatile = FsImage::new();
        inner.durable = FsImage::new();
    }

    /// Return all file paths currently present in the volatile image.
    pub fn all_files(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        inner.volatile.files.keys().cloned().collect()
    }

    /// Compute a deterministic SHA-256 digest of the entire durable image.
    pub fn durable_state_hash(&self) -> [u8; 32] {
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        let mut hasher = Sha256::new();
        for dir in &inner.durable.dirs {
            hasher.update(b"D:");
            hasher.update(dir.as_bytes());
            hasher.update(b"\n");
        }
        for (path, data) in &inner.durable.files {
            hasher.update(b"F:");
            hasher.update(path.as_bytes());
            hasher.update(b"=");
            hasher.update(data);
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

fn parent_dir(norm: &str) -> String {
    match norm.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => String::new(),
    }
}

#[async_trait]
impl DiskIo for SimDiskIo {
    async fn create_dir_all(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if norm.is_empty() {
            return Ok(());
        }
        let mut acc = String::new();
        for part in norm.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            inner.volatile.dirs.insert(acc.clone());
        }
        Ok(())
    }

    async fn write_file(&self, path: &str, data: Bytes) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        if norm.is_empty() {
            return Err(DiskError::InvalidPath(path.to_string()));
        }
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if self.rng.gen_bool(inner.faults.write_error_prob) {
            return Err(DiskError::Io("injected write failure".to_string()));
        }
        if let Some(cap) = inner.faults.capacity_bytes {
            let old_len = inner
                .volatile
                .files
                .get(&norm)
                .map(|b| b.len() as u64)
                .unwrap_or(0);
            let projected = inner.volatile.total_bytes() - old_len + data.len() as u64;
            if projected > cap {
                return Err(DiskError::NoSpace);
            }
        }
        inner.volatile.ensure_parents(&norm);
        if self.rng.gen_bool(inner.faults.torn_write_prob) && data.len() > 1 {
            let cut = 1 + self.rng.gen_range_usize(data.len() - 1);
            inner.volatile.files.insert(norm, data.slice(..cut));
            return Err(DiskError::Io("injected torn write".to_string()));
        }
        inner.volatile.files.insert(norm, data);
        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Bytes, DiskError> {
        let norm = normalize_path(path)?;
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if self.rng.gen_bool(inner.faults.read_error_prob) {
            return Err(DiskError::Io("injected read failure".to_string()));
        }
        inner
            .volatile
            .files
            .get(&norm)
            .cloned()
            .ok_or_else(|| DiskError::NotFound(path.to_string()))
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), DiskError> {
        let src = normalize_path(from)?;
        let dst = normalize_path(to)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if self.rng.gen_bool(inner.faults.write_error_prob) {
            return Err(DiskError::Io("injected rename failure".to_string()));
        }
        if let Some(bytes) = inner.volatile.files.remove(&src) {
            inner.volatile.ensure_parents(&dst);
            inner.volatile.files.insert(dst, bytes);
            return Ok(());
        }
        if inner.volatile.dirs.contains(&src) {
            let prefix = format!("{src}/");
            let moving_dirs: Vec<String> = inner
                .volatile
                .dirs
                .iter()
                .filter(|d| *d == &src || d.starts_with(&prefix))
                .cloned()
                .collect();
            let moving_files: Vec<(String, Bytes)> = inner
                .volatile
                .files
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            for d in &moving_dirs {
                inner.volatile.dirs.remove(d);
            }
            for (k, _) in &moving_files {
                inner.volatile.files.remove(k);
            }

            inner.volatile.ensure_parents(&dst);
            for d in moving_dirs {
                let suffix = d.strip_prefix(&src).unwrap_or("");
                inner.volatile.dirs.insert(format!("{dst}{suffix}"));
            }
            for (k, v) in moving_files {
                let suffix = k.strip_prefix(&src).unwrap_or("");
                inner.volatile.files.insert(format!("{dst}{suffix}"), v);
            }
            return Ok(());
        }
        Err(DiskError::NotFound(from.to_string()))
    }

    async fn remove_file(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        inner
            .volatile
            .files
            .remove(&norm)
            .map(|_| ())
            .ok_or_else(|| DiskError::NotFound(path.to_string()))
    }

    async fn remove_dir_all(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if norm.is_empty() {
            inner.volatile = FsImage::new();
            return Ok(());
        }
        let prefix = format!("{norm}/");
        inner
            .volatile
            .dirs
            .retain(|d| d != &norm && !d.starts_with(&prefix));
        inner.volatile.files.retain(|k, _| !k.starts_with(&prefix));
        Ok(())
    }

    async fn fsync_file(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        let data = inner
            .volatile
            .files
            .get(&norm)
            .cloned()
            .ok_or_else(|| DiskError::NotFound(path.to_string()))?;
        inner.durable.ensure_parents(&norm);
        inner.durable.files.insert(norm, data);
        Ok(())
    }

    async fn fsync_dir(&self, path: &str) -> Result<(), DiskError> {
        let norm = normalize_path(path)?;
        let mut inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if !inner.volatile.dirs.contains(&norm) {
            return Err(DiskError::NotFound(path.to_string()));
        }
        // Persist the directory and synchronize direct children (entries created,
        // renamed, or unlinked inside `norm`).
        let mut acc = String::new();
        for part in norm.split('/').filter(|p| !p.is_empty()) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            inner.durable.dirs.insert(acc.clone());
        }

        let direct_volatile_files: BTreeMap<String, Bytes> = inner
            .volatile
            .files
            .iter()
            .filter(|(k, _)| parent_dir(k) == norm)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        inner.durable.files.retain(|k, _| parent_dir(k) != norm);
        for (k, v) in direct_volatile_files {
            inner.durable.files.insert(k, v);
        }

        let direct_volatile_dirs: BTreeSet<String> = inner
            .volatile
            .dirs
            .iter()
            .filter(|d| !d.is_empty() && parent_dir(d) == norm)
            .cloned()
            .collect();
        inner
            .durable
            .dirs
            .retain(|d| d.is_empty() || parent_dir(d) != norm || direct_volatile_dirs.contains(d));
        for d in direct_volatile_dirs {
            inner.durable.dirs.insert(d);
        }
        Ok(())
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>, DiskError> {
        let norm = normalize_path(path)?;
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if !inner.volatile.dirs.contains(&norm) {
            return Err(DiskError::NotFound(path.to_string()));
        }
        let mut entries = BTreeSet::new();
        for f in inner.volatile.files.keys() {
            if parent_dir(f) == norm {
                let name = Path::new(f)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(f);
                entries.insert(name.to_string());
            }
        }
        for d in &inner.volatile.dirs {
            if !d.is_empty() && parent_dir(d) == norm {
                let name = Path::new(d)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(d);
                entries.insert(name.to_string());
            }
        }
        Ok(entries.into_iter().collect())
    }

    async fn stat(&self, path: &str) -> Result<FileStat, DiskError> {
        let norm = normalize_path(path)?;
        let inner = self.inner.lock().expect("SimDiskIo lock poisoned");
        if inner.faults.offline {
            return Err(DiskError::Offline);
        }
        if let Some(bytes) = inner.volatile.files.get(&norm) {
            return Ok(FileStat {
                size: bytes.len() as u64,
                is_dir: false,
            });
        }
        if inner.volatile.dirs.contains(&norm) {
            return Ok(FileStat {
                size: 0,
                is_dir: true,
            });
        }
        Err(DiskError::NotFound(path.to_string()))
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
}
