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

//! Integration test suite proving determinism and invariant preservation across
//! all RustFS DST scenarios and official topologies (`4x4`, `3x2`, `4x2`).

use rustfs_dst_sim::scenarios::{ScenarioKind, run_scenario};
use rustfs_dst_sim::topology::TopologyKind;

#[test]
fn all_scenarios_pass_across_4x4_3x2_and_4x2() {
    for topo in [
        TopologyKind::FourByFour,
        TopologyKind::ThreeByTwo,
        TopologyKind::FourByTwo,
    ] {
        for scenario in ScenarioKind::ALL {
            let report = run_scenario(scenario, topo, 2026);
            assert!(
                report.passed,
                "scenario {scenario} on {topo} failed: {:?}",
                report.violations
            );
            assert!(!report.trace_sha256.is_empty());
        }
    }
}

#[test]
fn identical_seeds_produce_bit_identical_trace_hashes() {
    for scenario in ScenarioKind::ALL {
        let a = run_scenario(scenario, TopologyKind::FourByFour, 42_4242);
        let b = run_scenario(scenario, TopologyKind::FourByFour, 42_4242);
        assert!(a.passed, "{scenario} failed: {:?}", a.violations);
        assert_eq!(
            a.trace_sha256, b.trace_sha256,
            "non-determinism detected in scenario {scenario}!"
        );
        assert_eq!(a.operations, b.operations);
    }
}

#[test]
fn multi_seed_swizzle_clog_chaos_holds_all_invariants() {
    for seed in 1..=25u64 {
        for topo in [TopologyKind::FourByFour, TopologyKind::ThreeByTwo] {
            let report = run_scenario(ScenarioKind::SwizzleClogChaos, topo, seed);
            assert!(
                report.passed,
                "SwizzleClogChaos failed on {topo} seed={seed}: {:?}",
                report.violations
            );
        }
    }
}
