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

//! Simulated RustFS distributed quorum lock manager over [`SimNetwork`] and
//! [`SimClock`].
//!
//! Models RustFS's `crates/lock` quorum acquisition, lease TTL expiration, and
//! monotonically increasing fencing tokens (`fence_epoch`), allowing DST to
//! verify mutual exclusion under partitions, message drops, and wall-clock skew.

use rustfs_dst_runtime::clock::{Clock, SimClock, SimInstant};
use rustfs_dst_runtime::network::{NetError, Network, RpcFrame, RpcHandler, SimNetwork};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

pub const METHOD_LOCK_ACQUIRE: &str = "rustfs.lock.Acquire";
pub const METHOD_LOCK_RELEASE: &str = "rustfs.lock.Release";

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LockError {
    #[error("quorum not reached for lock on {resource}: got {granted}, need {quorum}")]
    QuorumNotReached {
        resource: String,
        granted: usize,
        quorum: usize,
    },
    #[error("lock contention on {resource}")]
    Contended { resource: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockAcquireReq {
    pub resource: String,
    pub owner: String,
    pub lease_ms: u64,
    /// When `true`, uses wall-clock time (vulnerable to clock skew — used in negative tests).
    /// Production RustFS lock leases should always use monotonic instants (`false`).
    pub use_wall_clock: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockAcquireResp {
    pub granted: bool,
    pub fence_token: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockReleaseReq {
    pub resource: String,
    pub owner: String,
    pub fence_token: u64,
}

#[derive(Clone, Debug)]
struct LeaseEntry {
    owner: String,
    fence_token: u64,
    expires_monotonic: SimInstant,
    expires_wall_ms: i64,
}

/// Per-node lock table participating in distributed quorum locking.
#[derive(Clone, Debug)]
pub struct NodeLockService {
    clock: SimClock,
    leases: Arc<Mutex<BTreeMap<String, LeaseEntry>>>,
    next_fence: Arc<Mutex<u64>>,
}

impl NodeLockService {
    pub fn new(clock: SimClock) -> Self {
        Self {
            clock,
            leases: Arc::new(Mutex::new(BTreeMap::new())),
            next_fence: Arc::new(Mutex::new(1)),
        }
    }

    pub fn try_acquire(&self, req: &LockAcquireReq) -> LockAcquireResp {
        let now_mono = self.clock.now_instant();
        let now_wall = self.clock.now_unix_ms();
        let mut table = self.leases.lock().expect("NodeLockService lock poisoned");
        let expired = match table.get(&req.resource) {
            None => true,
            Some(existing) if existing.owner == req.owner => true,
            Some(existing) => {
                if req.use_wall_clock {
                    now_wall >= existing.expires_wall_ms
                } else {
                    now_mono >= existing.expires_monotonic
                }
            }
        };
        if !expired {
            return LockAcquireResp {
                granted: false,
                fence_token: 0,
            };
        }

        let mut fence = self.next_fence.lock().expect("fence counter poisoned");
        let token = *fence;
        *fence += 1;

        table.insert(
            req.resource.clone(),
            LeaseEntry {
                owner: req.owner.clone(),
                fence_token: token,
                expires_monotonic: now_mono.saturating_add(Duration::from_millis(req.lease_ms)),
                expires_wall_ms: now_wall.saturating_add(i64::try_from(req.lease_ms).unwrap_or(0)),
            },
        );
        LockAcquireResp {
            granted: true,
            fence_token: token,
        }
    }

    pub fn release(&self, req: &LockReleaseReq) {
        let mut table = self.leases.lock().expect("NodeLockService lock poisoned");
        if let Some(existing) = table.get(&req.resource)
            && existing.owner == req.owner
            && existing.fence_token <= req.fence_token
        {
            table.remove(&req.resource);
        }
    }

    /// Clear volatile in-memory leases on simulated node crash/restart.
    pub fn clear_on_crash(&self) {
        self.leases
            .lock()
            .expect("NodeLockService lock poisoned")
            .clear();
    }
}

#[async_trait::async_trait]
impl RpcHandler for NodeLockService {
    async fn handle(&self, _from: &str, request: RpcFrame) -> Result<RpcFrame, NetError> {
        match request.method.as_str() {
            METHOD_LOCK_ACQUIRE => {
                let req: LockAcquireReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                let resp = self.try_acquire(&req);
                let payload = serde_json::to_vec(&resp).map_err(|e| NetError::Io(e.to_string()))?;
                Ok(RpcFrame::new(METHOD_LOCK_ACQUIRE, payload))
            }
            METHOD_LOCK_RELEASE => {
                let req: LockReleaseReq = serde_json::from_slice(&request.payload)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                self.release(&req);
                Ok(RpcFrame::new(METHOD_LOCK_RELEASE, Vec::new()))
            }
            other => Err(NetError::Io(format!("unknown lock RPC method: {other}"))),
        }
    }
}

/// Active distributed lock grant carrying its monotonic fencing epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedLease {
    pub resource: String,
    pub owner: String,
    pub fence_token: u64,
    pub granted_on: Vec<String>,
}

/// Quorum lock coordinator talking to all cluster lock peers over [`SimNetwork`].
#[derive(Clone, Debug)]
pub struct QuorumLockClient {
    caller_node: String,
    lock_peers: Vec<String>,
    quorum: usize,
    network: SimNetwork,
}

impl QuorumLockClient {
    pub fn new(
        caller_node: impl Into<String>,
        lock_peers: Vec<String>,
        network: SimNetwork,
    ) -> Self {
        let quorum = lock_peers.len() / 2 + 1;
        Self {
            caller_node: caller_node.into(),
            lock_peers,
            quorum,
            network,
        }
    }

    pub async fn acquire(
        &self,
        resource: &str,
        owner: &str,
        lease_ms: u64,
        use_wall_clock: bool,
    ) -> Result<DistributedLease, LockError> {
        let req = LockAcquireReq {
            resource: resource.to_string(),
            owner: owner.to_string(),
            lease_ms,
            use_wall_clock,
        };
        let payload = serde_json::to_vec(&req).expect("serialize LockAcquireReq");
        let mut granted_on = Vec::new();
        let mut max_fence = 0u64;

        for peer in &self.lock_peers {
            let frame = RpcFrame::new(METHOD_LOCK_ACQUIRE, payload.clone());
            if let Ok(resp_frame) = self.network.call(&self.caller_node, peer, frame).await
                && let Ok(resp) = serde_json::from_slice::<LockAcquireResp>(&resp_frame.payload)
                && resp.granted
            {
                granted_on.push(peer.clone());
                max_fence = max_fence.max(resp.fence_token);
            }
        }

        if granted_on.len() >= self.quorum {
            Ok(DistributedLease {
                resource: resource.to_string(),
                owner: owner.to_string(),
                fence_token: max_fence,
                granted_on,
            })
        } else {
            // Roll back partial grants so we don't leak stale leases on minority partitions.
            for peer in &granted_on {
                let rel = LockReleaseReq {
                    resource: resource.to_string(),
                    owner: owner.to_string(),
                    fence_token: max_fence,
                };
                let rel_payload = serde_json::to_vec(&rel).expect("serialize LockReleaseReq");
                let _ = self
                    .network
                    .call(
                        &self.caller_node,
                        peer,
                        RpcFrame::new(METHOD_LOCK_RELEASE, rel_payload),
                    )
                    .await;
            }
            Err(LockError::QuorumNotReached {
                resource: resource.to_string(),
                granted: granted_on.len(),
                quorum: self.quorum,
            })
        }
    }

    pub async fn release(&self, lease: &DistributedLease) {
        let rel = LockReleaseReq {
            resource: lease.resource.clone(),
            owner: lease.owner.clone(),
            fence_token: lease.fence_token,
        };
        let rel_payload = serde_json::to_vec(&rel).expect("serialize LockReleaseReq");
        for peer in &lease.granted_on {
            let _ = self
                .network
                .call(
                    &self.caller_node,
                    peer,
                    RpcFrame::new(METHOD_LOCK_RELEASE, rel_payload.clone()),
                )
                .await;
        }
    }
}
