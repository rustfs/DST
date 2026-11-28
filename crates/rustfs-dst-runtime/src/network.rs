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

//! Deterministic and production network transport abstractions for RustFS.
//!
//! Models RustFS inter-node RPC communication (erasure disk RPCs, distributed
//! lock RPCs, heal RPCs) with injectable partitions, asymmetric link cuts,
//! Swizzle-Clog jitter/drops, message delays, and post-apply reply drops.

use crate::clock::{Clock, SimClock};
use crate::rng::{RngSource, SimRng};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

/// Logical node identifier within a RustFS cluster (e.g., `"n1"`, `"n2"`).
pub type NodeId = String;

/// Errors returned by [`Network`] RPC calls.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NetError {
    #[error("network partition between {from} and {to}")]
    Partitioned { from: NodeId, to: NodeId },
    #[error("packet dropped between {from} and {to}")]
    PacketDropped { from: NodeId, to: NodeId },
    #[error("reply dropped after remote execution on {to} (indeterminate outcome)")]
    ReplyDroppedAfterApply { from: NodeId, to: NodeId },
    #[error("RPC timed out from {from} to {to} after {timeout_ms}ms")]
    Timeout {
        from: NodeId,
        to: NodeId,
        timeout_ms: u64,
    },
    #[error("node {0} is crashed or unreachable")]
    NodeDown(NodeId),
    #[error("endpoint handler not registered for node {0}")]
    UnregisteredNode(NodeId),
    #[error("transport I/O error: {0}")]
    Io(String),
}

/// RPC envelope exchanged between RustFS nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcFrame {
    pub method: String,
    pub payload: Bytes,
}

impl RpcFrame {
    pub fn new(method: impl Into<String>, payload: impl Into<Bytes>) -> Self {
        Self {
            method: method.into(),
            payload: payload.into(),
        }
    }
}

/// Asynchronous RPC handler registered on a simulated node.
#[async_trait]
pub trait RpcHandler: Send + Sync {
    async fn handle(&self, from: &str, request: RpcFrame) -> Result<RpcFrame, NetError>;
}

/// Unified inter-node RPC network trait.
#[async_trait]
pub trait Network: Send + Sync {
    /// Send a request frame from `from` to `to` and await the response frame.
    async fn call(&self, from: &str, to: &str, request: RpcFrame) -> Result<RpcFrame, NetError>;
}

/// Per-directed-link fault profile for [`SimNetwork`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LinkFaultProfile {
    /// Drop all packets on this directed link (`from -> to`).
    pub partitioned: bool,
    /// Probability `[0.0, 1.0]` that a request is dropped before reaching `to`.
    pub drop_prob: f64,
    /// Probability `[0.0, 1.0]` that the response is dropped AFTER `to` executed
    /// the RPC (produces an indeterminate outcome, exercising idempotency & quorum retry).
    pub post_apply_reply_drop_prob: f64,
    /// Minimum one-way simulated latency in milliseconds.
    pub min_delay_ms: u64,
    /// Maximum one-way simulated latency in milliseconds.
    pub max_delay_ms: u64,
}

/// Recorded network event for deterministic trace hashing and post-mortem debugging.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTraceEvent {
    pub seq: u64,
    pub at_ms: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub method: String,
    pub outcome: String,
}

struct SimNetworkInner {
    handlers: BTreeMap<NodeId, Arc<dyn RpcHandler>>,
    down_nodes: BTreeSet<NodeId>,
    links: HashMap<(NodeId, NodeId), LinkFaultProfile>,
    default_profile: LinkFaultProfile,
    trace: Vec<NetworkTraceEvent>,
    seq: u64,
}

/// Deterministic in-memory virtual network fabric for RustFS inter-node RPCs.
///
/// Supports symmetric & asymmetric partitions, Swizzle-Clog per-link jitter,
/// packet drops, node crash isolation, and post-apply reply drops.
#[derive(Clone)]
pub struct SimNetwork {
    inner: Arc<Mutex<SimNetworkInner>>,
    clock: SimClock,
    rng: SimRng,
}

impl std::fmt::Debug for SimNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimNetwork").finish_non_exhaustive()
    }
}

impl SimNetwork {
    pub fn new(clock: SimClock, rng: SimRng) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimNetworkInner {
                handlers: BTreeMap::new(),
                down_nodes: BTreeSet::new(),
                links: HashMap::new(),
                default_profile: LinkFaultProfile::default(),
                trace: Vec::new(),
                seq: 0,
            })),
            clock,
            rng,
        }
    }

    /// Register an RPC handler for `node_id`.
    pub fn register(&self, node_id: impl Into<NodeId>, handler: Arc<dyn RpcHandler>) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner.handlers.insert(node_id.into(), handler);
    }

    /// Set the default fault profile applied to links without an explicit override.
    pub fn set_default_profile(&self, profile: LinkFaultProfile) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner.default_profile = profile;
    }

    /// Configure a fault profile on the directed link `from -> to`.
    pub fn set_link_profile(
        &self,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        profile: LinkFaultProfile,
    ) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner.links.insert((from.into(), to.into()), profile);
    }

    /// Symmetrically partition two groups of nodes (`group_a` cannot talk to `group_b`).
    pub fn partition_groups(&self, group_a: &[String], group_b: &[String]) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        for a in group_a {
            for b in group_b {
                inner
                    .links
                    .entry((a.clone(), b.clone()))
                    .or_default()
                    .partitioned = true;
                inner
                    .links
                    .entry((b.clone(), a.clone()))
                    .or_default()
                    .partitioned = true;
            }
        }
    }

    /// Create a one-way asymmetric partition (`from -> to` dropped, `to -> from` allowed).
    pub fn partition_one_way(&self, from: impl Into<NodeId>, to: impl Into<NodeId>) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner
            .links
            .entry((from.into(), to.into()))
            .or_default()
            .partitioned = true;
    }

    /// Isolate a single node from all other registered nodes.
    pub fn isolate_node(&self, target: &str) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        let peers: Vec<NodeId> = inner
            .handlers
            .keys()
            .filter(|k| k.as_str() != target)
            .cloned()
            .collect();
        for peer in peers {
            inner
                .links
                .entry((target.to_string(), peer.clone()))
                .or_default()
                .partitioned = true;
            inner
                .links
                .entry((peer, target.to_string()))
                .or_default()
                .partitioned = true;
        }
    }

    /// Heal all network partitions and link overrides.
    pub fn heal_all(&self) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner.links.clear();
    }

    /// Mark a node as crashed/stopped (`NetError::NodeDown`).
    pub fn set_node_down(&self, node_id: impl Into<NodeId>, down: bool) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        let id = node_id.into();
        if down {
            inner.down_nodes.insert(id);
        } else {
            inner.down_nodes.remove(&id);
        }
    }

    /// Check whether a node is currently marked down.
    pub fn is_node_down(&self, node_id: &str) -> bool {
        let inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner.down_nodes.contains(node_id)
    }

    /// Snapshot the recorded network trace for determinism hashing or diagnostics.
    pub fn trace_snapshot(&self) -> Vec<NetworkTraceEvent> {
        let inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner.trace.clone()
    }

    fn record(&self, from: &str, to: &str, method: &str, outcome: &str) {
        let mut inner = self.inner.lock().expect("SimNetwork lock poisoned");
        inner.seq += 1;
        let seq = inner.seq;
        inner.trace.push(NetworkTraceEvent {
            seq,
            at_ms: self.clock.global_instant().as_millis(),
            from: from.to_string(),
            to: to.to_string(),
            method: method.to_string(),
            outcome: outcome.to_string(),
        });
    }

    fn sample_delay(&self, profile: &LinkFaultProfile) -> Duration {
        if profile.max_delay_ms <= profile.min_delay_ms {
            return Duration::from_millis(profile.min_delay_ms);
        }
        let span = (profile.max_delay_ms - profile.min_delay_ms + 1) as usize;
        let offset = self.rng.gen_range_usize(span) as u64;
        Duration::from_millis(profile.min_delay_ms + offset)
    }
}

#[async_trait]
impl Network for SimNetwork {
    async fn call(&self, from: &str, to: &str, request: RpcFrame) -> Result<RpcFrame, NetError> {
        let method = request.method.clone();
        let (handler, profile, from_down, to_down) = {
            let inner = self.inner.lock().expect("SimNetwork lock poisoned");
            let from_down = inner.down_nodes.contains(from);
            let to_down = inner.down_nodes.contains(to);
            let profile = if from == to {
                LinkFaultProfile::default()
            } else {
                inner
                    .links
                    .get(&(from.to_string(), to.to_string()))
                    .cloned()
                    .unwrap_or_else(|| inner.default_profile.clone())
            };
            let handler = inner.handlers.get(to).cloned();
            (handler, profile, from_down, to_down)
        };

        if from_down {
            self.record(from, to, &method, "from_down");
            return Err(NetError::NodeDown(from.to_string()));
        }
        if to_down {
            self.record(from, to, &method, "to_down");
            return Err(NetError::NodeDown(to.to_string()));
        }
        if profile.partitioned {
            self.record(from, to, &method, "partitioned");
            return Err(NetError::Partitioned {
                from: from.to_string(),
                to: to.to_string(),
            });
        }
        if self.rng.gen_bool(profile.drop_prob) {
            self.record(from, to, &method, "request_dropped");
            return Err(NetError::PacketDropped {
                from: from.to_string(),
                to: to.to_string(),
            });
        }

        let req_delay = self.sample_delay(&profile);
        if !req_delay.is_zero() {
            self.clock.sleep(req_delay).await;
        }

        let handler = handler.ok_or_else(|| NetError::UnregisteredNode(to.to_string()))?;
        let response = handler.handle(from, request).await;

        // Check return path faults after remote execution.
        let (return_profile, to_crashed_mid_flight) = {
            let inner = self.inner.lock().expect("SimNetwork lock poisoned");
            let rp = if from == to {
                LinkFaultProfile::default()
            } else {
                inner
                    .links
                    .get(&(to.to_string(), from.to_string()))
                    .cloned()
                    .unwrap_or_else(|| inner.default_profile.clone())
            };
            (rp, inner.down_nodes.contains(to))
        };

        if to_crashed_mid_flight
            || return_profile.partitioned
            || self.rng.gen_bool(profile.post_apply_reply_drop_prob)
        {
            // Only classify as ReplyDroppedAfterApply when the remote handler
            // actually succeeded (`Ok`). If the handler failed (`Err`), nothing
            // was applied remotely so reporting ReplyDroppedAfterApply would
            // falsely mark an unapplied write as indeterminate!
            if response.is_ok() {
                self.record(from, to, &method, "reply_dropped_after_apply");
                return Err(NetError::ReplyDroppedAfterApply {
                    from: from.to_string(),
                    to: to.to_string(),
                });
            }
            self.record(from, to, &method, "handler_err_reply_lost");
            if to_crashed_mid_flight {
                return Err(NetError::NodeDown(to.to_string()));
            }
            if return_profile.partitioned {
                return Err(NetError::Partitioned {
                    from: to.to_string(),
                    to: from.to_string(),
                });
            }
            return Err(NetError::PacketDropped {
                from: to.to_string(),
                to: from.to_string(),
            });
        }

        let resp_delay = self.sample_delay(&return_profile);
        if !resp_delay.is_zero() {
            self.clock.sleep(resp_delay).await;
        }

        match &response {
            Ok(_) => self.record(from, to, &method, "ok"),
            Err(_) => self.record(from, to, &method, "handler_err"),
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingHandler;

    #[async_trait]
    impl RpcHandler for FailingHandler {
        async fn handle(&self, _from: &str, _req: RpcFrame) -> Result<RpcFrame, NetError> {
            Err(NetError::Io("disk offline".to_string()))
        }
    }

    #[tokio::test]
    async fn handler_error_with_dropped_return_link_is_never_marked_applied() {
        let clock = SimClock::new();
        let net = SimNetwork::new(clock, SimRng::from_seed(7));
        net.register("n2", Arc::new(FailingHandler));
        net.partition_one_way("n2", "n1");

        let res = net
            .call("n1", "n2", RpcFrame::new("commit", Vec::new()))
            .await;
        assert!(
            !matches!(res, Err(NetError::ReplyDroppedAfterApply { .. })),
            "unapplied handler error falsely reported as ReplyDroppedAfterApply: {res:?}"
        );
    }
}
