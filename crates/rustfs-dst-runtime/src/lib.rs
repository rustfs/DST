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

//! Unified non-determinism abstraction traits for RustFS Deterministic
//! Simulation Testing (DST).
//!
//! Every source of non-determinism in the RustFS storage engine — system time,
//! randomness, network I/O, and disk I/O — is represented by a trait in this
//! crate:
//!
//! - [`clock::Clock`] (`RealClock` / [`clock::SimClock`])
//! - [`rng::RngSource`] (`RealRng` / [`rng::SimRng`])
//! - [`network::Network`] ([`network::SimNetwork`] / [`turmoil_net`])
//! - [`disk::DiskIo`] ([`disk::RealDiskIo`] / [`disk::SimDiskIo`])

pub mod clock;
pub mod disk;
pub mod madsim_compat;
pub mod network;
pub mod rng;
#[cfg(feature = "turmoil-sim")]
pub mod turmoil_net;

use crate::clock::{Clock, SimClock};
use crate::disk::{DiskIo, SimDiskIo};
use crate::network::{Network, SimNetwork};
use crate::rng::{RngSource, SimRng};
use std::sync::Arc;

/// Aggregate runtime environment bundle injected into RustFS storage, locking,
/// healing, and scanning subsystems.
pub trait RuntimeEnv: Send + Sync + 'static {
    type ClockImpl: Clock;
    type RngImpl: RngSource;
    type NetworkImpl: Network;
    type DiskImpl: DiskIo;

    fn clock(&self) -> &Self::ClockImpl;
    fn rng(&self) -> &Self::RngImpl;
    fn network(&self) -> &Self::NetworkImpl;
    fn disk(&self, index: usize) -> Option<&Self::DiskImpl>;
}

/// Fully deterministic simulation environment for a single RustFS node.
#[derive(Clone, Debug)]
pub struct SimNodeEnv {
    pub node_id: String,
    pub clock: SimClock,
    pub rng: SimRng,
    pub network: SimNetwork,
    pub disks: Vec<Arc<SimDiskIo>>,
}

impl SimNodeEnv {
    pub fn new(
        node_id: impl Into<String>,
        root_clock: &SimClock,
        root_rng: &SimRng,
        network: SimNetwork,
        drives_per_node: usize,
    ) -> Self {
        let node_id = node_id.into();
        let clock = root_clock.for_node(&node_id);
        let rng = root_rng.fork(&format!("node:{node_id}"));
        let disks = (1..=drives_per_node)
            .map(|idx| {
                let disk_id = format!("{node_id}:data{idx}");
                Arc::new(SimDiskIo::new(
                    disk_id.clone(),
                    rng.fork(&format!("disk:{disk_id}")),
                ))
            })
            .collect();
        Self {
            node_id,
            clock,
            rng,
            network,
            disks,
        }
    }
}

impl RuntimeEnv for SimNodeEnv {
    type ClockImpl = SimClock;
    type RngImpl = SimRng;
    type NetworkImpl = SimNetwork;
    type DiskImpl = SimDiskIo;

    fn clock(&self) -> &Self::ClockImpl {
        &self.clock
    }

    fn rng(&self) -> &Self::RngImpl {
        &self.rng
    }

    fn network(&self) -> &Self::NetworkImpl {
        &self.network
    }

    fn disk(&self, index: usize) -> Option<&Self::DiskImpl> {
        self.disks.get(index).map(Arc::as_ref)
    }
}
