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

//! Official RustFS distributed erasure-coding topologies and quorum formulas.
//!
//! Matches `rustfs/rustfs` `crates/ecstore` `default_parity_count` and
//! `default_write_quorum`:
//! - `4x4`: 4 nodes × 4 drives = 16 drives, parity = 4, data = 12, R = 12, W = 12
//! - `3x2`: 3 nodes × 2 drives = 6 drives, parity = 3, data = 3, R = 3, W = 4
//! - `4x2`: 4 nodes × 2 drives = 8 drives, parity = 4, data = 4, R = 4, W = 5

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Standard RustFS cluster topology presets for DST.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TopologyKind {
    /// 4 nodes × 4 drives = 16 drives (EC:4, data=12, read quorum=12, write quorum=12).
    FourByFour,
    /// 3 nodes × 2 drives = 6 drives (EC:3, data=3, read quorum=3, write quorum=4).
    ThreeByTwo,
    /// 4 nodes × 2 drives = 8 drives (EC:4, data=4, read quorum=4, write quorum=5).
    FourByTwo,
}

impl TopologyKind {
    pub fn spec(self) -> TopologySpec {
        match self {
            Self::FourByFour => TopologySpec::new("4x4", 4, 4),
            Self::ThreeByTwo => TopologySpec::new("3x2", 3, 2),
            Self::FourByTwo => TopologySpec::new("4x2", 4, 2),
        }
    }
}

impl fmt::Display for TopologyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.spec().name)
    }
}

impl FromStr for TopologyKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "4x4" => Ok(Self::FourByFour),
            "3x2" => Ok(Self::ThreeByTwo),
            "4x2" => Ok(Self::FourByTwo),
            other => Err(format!(
                "unknown topology '{other}' (expected one of: 4x4, 3x2, 4x2)"
            )),
        }
    }
}

/// Concrete RustFS erasure-set geometry and quorum parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologySpec {
    pub name: &'static str,
    pub nodes: usize,
    pub drives_per_node: usize,
    pub total_drives: usize,
    pub parity_shards: usize,
    pub data_shards: usize,
    pub read_quorum: usize,
    pub write_quorum: usize,
}

impl TopologySpec {
    pub fn new(name: &'static str, nodes: usize, drives_per_node: usize) -> Self {
        let total_drives = nodes * drives_per_node;
        let parity_shards = default_parity_count(total_drives);
        let data_shards = total_drives - parity_shards;
        let read_quorum = data_shards;
        // RustFS rule (`default_write_quorum`): when data_shards == parity_shards,
        // write_quorum = data_shards + 1 to prevent split-brain writes on 50/50 partitions.
        let write_quorum = if data_shards == parity_shards {
            data_shards + 1
        } else {
            data_shards
        };
        Self {
            name,
            nodes,
            drives_per_node,
            total_drives,
            parity_shards,
            data_shards,
            read_quorum,
            write_quorum,
        }
    }

    /// Generate canonical node identifiers (`["n1", "n2", ...]`).
    pub fn node_ids(&self) -> Vec<String> {
        (1..=self.nodes).map(|i| format!("n{i}")).collect()
    }

    /// Strict majority of cluster nodes required for distributed lock quorum.
    pub fn lock_quorum(&self) -> usize {
        self.nodes / 2 + 1
    }
}

/// Exact RustFS default parity calculation (`default_parity_count`).
pub const fn default_parity_count(set_drive_count: usize) -> usize {
    match set_drive_count {
        0 | 1 => 0,
        2 | 3 => 1,
        4 | 5 => 2,
        6 | 7 => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_quorums_match_rustfs_1_0_7() {
        let t4x4 = TopologyKind::FourByFour.spec();
        assert_eq!(t4x4.total_drives, 16);
        assert_eq!(t4x4.parity_shards, 4);
        assert_eq!(t4x4.data_shards, 12);
        assert_eq!(t4x4.read_quorum, 12);
        assert_eq!(t4x4.write_quorum, 12);

        let t3x2 = TopologyKind::ThreeByTwo.spec();
        assert_eq!(t3x2.total_drives, 6);
        assert_eq!(t3x2.parity_shards, 3);
        assert_eq!(t3x2.data_shards, 3);
        assert_eq!(t3x2.read_quorum, 3);
        assert_eq!(t3x2.write_quorum, 4);

        let t4x2 = TopologyKind::FourByTwo.spec();
        assert_eq!(t4x2.total_drives, 8);
        assert_eq!(t4x2.parity_shards, 4);
        assert_eq!(t4x2.data_shards, 4);
        assert_eq!(t4x2.read_quorum, 4);
        assert_eq!(t4x2.write_quorum, 5);
    }
}
