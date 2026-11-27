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

//! Deterministic Swizzle-Clog fault schedule generator.
//!
//! Produces reproducible sequences of network partitions, asymmetric link cuts,
//! link clogging (latency + packet drops + post-apply reply drops), node crashes,
//! drive offline/bitrot faults, and clock skew jumps from a single [`SimRng`].

use rustfs_dst_runtime::rng::{RngSource, SimRng};
use serde::{Deserialize, Serialize};

/// A single discrete fault action applied to a simulated RustFS cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultAction {
    /// Split cluster nodes into two mutually isolated partitions.
    PartitionHalves {
        group_a: Vec<String>,
        group_b: Vec<String>,
    },
    /// Drop traffic in one direction (`from -> to`) while keeping `to -> from` open.
    AsymmetricCut { from: String, to: String },
    /// Completely isolate one node from the cluster.
    IsolateNode { node: String },
    /// Clog a directed link with latency, packet loss, and post-apply reply drops.
    ClogLink {
        from: String,
        to: String,
        drop_pct: u8,
        reply_drop_pct: u8,
        max_delay_ms: u64,
    },
    /// Abruptly crash a node (simulating power loss on all its attached drives).
    CrashNode { node: String },
    /// Restart a previously crashed node.
    RestartNode { node: String },
    /// Take a single drive offline (`node`, `drive_idx`).
    DriveOffline { node: String, drive_idx: usize },
    /// Bring a single drive back online.
    DriveOnline { node: String, drive_idx: usize },
    /// Inject a wall-clock skew jump on a node.
    ClockSkew { node: String, skew_ms: i64 },
    /// Heal all network partitions, restart downed nodes, bring drives online, clear clock skew.
    HealAll,
}

/// Deterministic fault schedule generator parameterized by cluster geometry.
#[derive(Clone, Debug)]
pub struct SwizzleClogScheduler {
    nodes: Vec<String>,
    drives_per_node: usize,
    rng: SimRng,
}

impl SwizzleClogScheduler {
    pub fn new(nodes: Vec<String>, drives_per_node: usize, rng: SimRng) -> Self {
        Self {
            nodes,
            drives_per_node,
            rng,
        }
    }

    /// Generate a deterministic sequence of `steps` fault actions ending with [`FaultAction::HealAll`].
    pub fn generate_plan(&self, steps: usize) -> Vec<FaultAction> {
        let mut plan = Vec::with_capacity(steps + 1);
        for step in 0..steps {
            // Periodically heal so recovery & convergence paths are exercised every run.
            if step > 0 && step % 5 == 4 {
                plan.push(FaultAction::HealAll);
                continue;
            }
            plan.push(self.next_action());
        }
        plan.push(FaultAction::HealAll);
        plan
    }

    fn next_action(&self) -> FaultAction {
        let n = self.nodes.len();
        if n < 2 {
            return FaultAction::HealAll;
        }
        match self.rng.gen_range_usize(8) {
            0 => {
                let split = (n / 2).max(1);
                let mut indices: Vec<usize> = (0..n).collect();
                // Deterministic Fisher-Yates shuffle.
                for i in (1..indices.len()).rev() {
                    let j = self.rng.gen_range_usize(i + 1);
                    indices.swap(i, j);
                }
                let group_a = indices[..split]
                    .iter()
                    .map(|&i| self.nodes[i].clone())
                    .collect();
                let group_b = indices[split..]
                    .iter()
                    .map(|&i| self.nodes[i].clone())
                    .collect();
                FaultAction::PartitionHalves { group_a, group_b }
            }
            1 => {
                let a = self.rng.gen_range_usize(n);
                let mut b = self.rng.gen_range_usize(n - 1);
                if b >= a {
                    b += 1;
                }
                FaultAction::AsymmetricCut {
                    from: self.nodes[a].clone(),
                    to: self.nodes[b].clone(),
                }
            }
            2 => {
                let idx = self.rng.gen_range_usize(n);
                FaultAction::IsolateNode {
                    node: self.nodes[idx].clone(),
                }
            }
            3 => {
                let a = self.rng.gen_range_usize(n);
                let mut b = self.rng.gen_range_usize(n - 1);
                if b >= a {
                    b += 1;
                }
                FaultAction::ClogLink {
                    from: self.nodes[a].clone(),
                    to: self.nodes[b].clone(),
                    drop_pct: (10 + self.rng.gen_range_usize(30)) as u8,
                    reply_drop_pct: (5 + self.rng.gen_range_usize(20)) as u8,
                    max_delay_ms: 5 + self.rng.gen_range_usize(50) as u64,
                }
            }
            4 => {
                let idx = self.rng.gen_range_usize(n);
                FaultAction::CrashNode {
                    node: self.nodes[idx].clone(),
                }
            }
            5 => {
                let idx = self.rng.gen_range_usize(n);
                FaultAction::RestartNode {
                    node: self.nodes[idx].clone(),
                }
            }
            6 => {
                let node_idx = self.rng.gen_range_usize(n);
                let drive_idx = self.rng.gen_range_usize(self.drives_per_node.max(1));
                FaultAction::DriveOffline {
                    node: self.nodes[node_idx].clone(),
                    drive_idx,
                }
            }
            _ => {
                let node_idx = self.rng.gen_range_usize(n);
                let sign = if self.rng.gen_bool(0.5) { 1i64 } else { -1i64 };
                let magnitude = (100 + self.rng.gen_range_usize(5_000)) as i64;
                FaultAction::ClockSkew {
                    node: self.nodes[node_idx].clone(),
                    skew_ms: sign * magnitude,
                }
            }
        }
    }
}
