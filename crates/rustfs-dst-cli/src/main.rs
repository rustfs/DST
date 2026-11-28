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

//! `rustfs-dst`: Joshua-style multi-seed deterministic simulation runner,
//! reproducer, and determinism verifier for RustFS.

use clap::{Parser, Subcommand};
use rayon::prelude::*;
use rustfs_dst_faults::probe::ProbeRegistry;
use rustfs_dst_sim::oracle::InvariantViolation;
use rustfs_dst_sim::scenarios::{ScenarioKind, ScenarioReport, run_scenario};
use rustfs_dst_sim::topology::TopologyKind;
use std::ops::RangeInclusive;
use std::panic::{UnwindSafe, catch_unwind};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "rustfs-dst",
    version,
    about = "Deterministic Simulation Testing (DST) runner for RustFS"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a multi-seed deterministic simulation campaign in parallel.
    Run {
        /// Scenario slug or "all" to run every scenario.
        #[arg(long, default_value = "all")]
        scenario: String,
        /// RustFS cluster topology: 4x4, 3x2, or 4x2.
        #[arg(long, default_value = "4x4")]
        topology: TopologyKind,
        /// Starting seed (inclusive).
        #[arg(long, default_value_t = 1)]
        start_seed: u64,
        /// Number of sequential seeds to execute per scenario.
        #[arg(long, default_value_t = 20)]
        seeds: u64,
        /// Emit machine-readable JSON summary.
        #[arg(long)]
        json: bool,
    },
    /// Replay one specific `(scenario, topology, seed)` deterministically.
    Repro {
        #[arg(long)]
        scenario: ScenarioKind,
        #[arg(long, default_value = "4x4")]
        topology: TopologyKind,
        #[arg(long)]
        seed: u64,
    },
    /// Execute each scenario twice with the same seed and compare both passing reports.
    VerifyDeterminism {
        #[arg(long, default_value = "4x4")]
        topology: TopologyKind,
        #[arg(long, default_value_t = 2026)]
        seed: u64,
    },
    /// List all available DST scenarios.
    ListScenarios,
}

fn parse_scenarios(raw: &str) -> Result<Vec<ScenarioKind>, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(ScenarioKind::ALL.to_vec()),
        "core" => Ok(ScenarioKind::CORE.to_vec()),
        "enterprise" => Ok(ScenarioKind::ENTERPRISE.to_vec()),
        "scanner" => Ok(ScenarioKind::SCANNER.to_vec()),
        "composite" => Ok(ScenarioKind::COMPOSITE.to_vec()),
        "replication" => Ok(vec![
            ScenarioKind::SiteReplication,
            ScenarioKind::BucketReplication,
        ]),
        "governance" => Ok(vec![
            ScenarioKind::WormObjectLock,
            ScenarioKind::LifecycleTransition,
            ScenarioKind::LifecycleExpiration,
            ScenarioKind::LifecycleTagExpiration,
            ScenarioKind::TieringManagement,
            ScenarioKind::TieredRemoteRestore,
        ]),
        "pools" => Ok(vec![
            ScenarioKind::PoolExpansion,
            ScenarioKind::PoolDecommission,
            ScenarioKind::PoolRebalance,
            ScenarioKind::DecommissionConsistencySafety,
            ScenarioKind::RebalanceConsistencySafety,
            ScenarioKind::ExpansionDecommissionAllFeatures,
            ScenarioKind::ExpansionRebalanceAllFeatures,
        ]),
        "security" => Ok(vec![
            ScenarioKind::OidcStsAuth,
            ScenarioKind::BucketNotification,
            ScenarioKind::AuditLogging,
        ]),
        "data" => Ok(vec![
            ScenarioKind::S3Tables,
            ScenarioKind::CapacityQuota,
            ScenarioKind::OnDemandMigration,
        ]),
        _ => raw
            .split(',')
            .map(str::parse::<ScenarioKind>)
            .collect::<Result<Vec<_>, _>>(),
    }
}

fn seed_range(start_seed: u64, count: u64) -> Result<RangeInclusive<u64>, &'static str> {
    let last_offset = count.checked_sub(1).ok_or("--seeds must be at least 1")?;
    let last_seed = start_seed
        .checked_add(last_offset)
        .ok_or("seed range exceeds u64::MAX")?;
    Ok(start_seed..=last_seed)
}

fn run_case(
    scenario: ScenarioKind,
    topology: TopologyKind,
    seed: u64,
    simulate: impl FnOnce(ScenarioKind, TopologyKind, u64) -> ScenarioReport + UnwindSafe,
) -> ScenarioReport {
    match catch_unwind(|| simulate(scenario, topology, seed)) {
        Ok(report) => report,
        Err(panic) => {
            let detail = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("simulation panicked");
            ScenarioReport {
                scenario,
                topology: topology.to_string(),
                seed,
                passed: false,
                operations: 0,
                trace_sha256: String::new(),
                violations: vec![InvariantViolation {
                    invariant: "simulation_panic".to_string(),
                    key: "scenario".to_string(),
                    detail: detail.to_string(),
                }],
                probes: Default::default(),
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::ListScenarios => {
            println!("Available RustFS DST scenarios:");
            for sc in ScenarioKind::ALL {
                println!("  {:<24} {}", sc.slug(), sc.description());
            }
            ExitCode::SUCCESS
        }
        Command::Repro {
            scenario,
            topology,
            seed,
        } => {
            let report = run_case(scenario, topology, seed, run_scenario);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize ScenarioReport")
            );
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::VerifyDeterminism { topology, seed } => {
            let mut ok = true;
            for scenario in ScenarioKind::ALL {
                let r1 = run_case(scenario, topology, seed, run_scenario);
                let r2 = run_case(scenario, topology, seed, run_scenario);
                if !r1.passed || r1 != r2 {
                    eprintln!(
                        "FAIL replay: scenario={scenario} topo={topology} seed={seed} passed_1={} passed_2={} trace_1={} trace_2={}",
                        r1.passed, r2.passed, r1.trace_sha256, r2.trace_sha256
                    );
                    for (replay, report) in [(1, r1), (2, r2)] {
                        eprintln!(
                            "  replay {replay} operations={} probes={:?} violations={:?}",
                            report.operations, report.probes, report.violations
                        );
                    }
                    ok = false;
                } else {
                    println!(
                        "OK   {:<24} topo={topology} seed={seed} ops={:<4} trace={}",
                        scenario.slug(),
                        r1.operations,
                        &r1.trace_sha256[..16]
                    );
                }
            }
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::Run {
            scenario,
            topology,
            start_seed,
            seeds,
            json,
        } => {
            let scenarios = match parse_scenarios(&scenario) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let range = match seed_range(start_seed, seeds) {
                Ok(range) => range,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let Some((seeds_per_scenario, total_runs)) =
                usize::try_from(seeds).ok().and_then(|count| {
                    count
                        .checked_mul(scenarios.len())
                        .map(|total| (count, total))
                })
            else {
                eprintln!("error: campaign run count exceeds platform capacity");
                return ExitCode::FAILURE;
            };

            let reports: Vec<_> = (0..total_runs)
                .into_par_iter()
                .map(|index| {
                    let scenario = scenarios[index / seeds_per_scenario];
                    let seed = range.start() + (index % seeds_per_scenario) as u64;
                    run_case(scenario, topology, seed, run_scenario)
                })
                .collect();

            let aggregate_probes = ProbeRegistry::new();
            let mut failures = Vec::new();
            let mut total_ops = 0u64;
            for report in reports {
                total_ops += report.operations;
                aggregate_probes.merge_from(&report.probes);
                if !report.passed {
                    failures.push(report);
                }
            }

            let unhit = if seeds >= 5 {
                aggregate_probes.unhit_must_hit()
            } else {
                Vec::new()
            };

            if json {
                let summary = serde_json::json!({
                    "topology": topology.to_string(),
                    "scenarios": scenarios.iter().map(|scenario| scenario.slug()).collect::<Vec<_>>(),
                    "start_seed": range.start(),
                    "end_seed": range.end(),
                    "seeds_per_scenario": seeds,
                    "total_runs": total_runs,
                    "passed_runs": total_runs - failures.len(),
                    "failed_runs": failures.len(),
                    "total_operations": total_ops,
                    "probes": aggregate_probes.snapshot(),
                    "unhit_must_hit_probes": unhit,
                    "failures": failures,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).expect("serialize summary")
                );
            } else {
                println!(
                    "RustFS DST Summary: topology={topology} seeds={range:?} runs={} passed={} failed={} ops={total_ops}",
                    total_runs,
                    total_runs - failures.len(),
                    failures.len(),
                );
                let probes = aggregate_probes.snapshot();
                if !probes.is_empty() {
                    println!(
                        "CodeProbe / Antithesis Coverage ({} properties):",
                        probes.len()
                    );
                    for (id, st) in probes {
                        println!(
                            "  [{:?}] {:<52} pass={} fail={}",
                            st.kind, id, st.pass_count, st.fail_count
                        );
                    }
                }
                for st in &unhit {
                    eprintln!(
                        "UNHIT MUST-HIT PROBE: [{:?}] {} had pass_count=0 across {seeds} seeds",
                        st.kind, st.id
                    );
                }
                for fail in &failures {
                    eprintln!(
                        "FAILURE: scenario={} topology={} seed={} -> repro: rustfs-dst repro --scenario {} --topology {} --seed {}",
                        fail.scenario,
                        fail.topology,
                        fail.seed,
                        fail.scenario.slug(),
                        fail.topology,
                        fail.seed
                    );
                    for v in &fail.violations {
                        eprintln!("  - [{}] {}: {}", v.invariant, v.key, v.detail);
                    }
                }
            }

            if failures.is_empty() && unhit.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_or_overflowing_campaigns_and_accepts_the_final_seed() {
        assert!(seed_range(1, 0).is_err());
        assert!(seed_range(u64::MAX, 2).is_err());
        assert_eq!(
            seed_range(u64::MAX, 1).unwrap().collect::<Vec<_>>(),
            vec![u64::MAX]
        );
    }

    #[test]
    fn turns_a_scenario_panic_into_a_reproducible_failure_report() {
        let scenario = ScenarioKind::ErasureQuorum;
        let topology = TopologyKind::FourByFour;
        let report = run_case(scenario, topology, 55, |_, _, _| {
            panic!("initial write failed");
        });
        assert!(!report.passed);
        assert_eq!(report.scenario, scenario);
        assert_eq!(report.topology, topology.to_string());
        assert_eq!(report.seed, 55);
        assert_eq!(report.violations[0].invariant, "simulation_panic");
        assert_eq!(report.violations[0].detail, "initial write failed");
    }
}
