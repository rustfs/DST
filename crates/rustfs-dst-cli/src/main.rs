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
use rustfs_dst_sim::scenarios::{ScenarioKind, ScenarioReport, run_scenario};
use rustfs_dst_sim::topology::TopologyKind;
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
    /// Execute each scenario twice with the same seed and verify identical SHA-256 trace hashes.
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
            let report = run_scenario(scenario, topology, seed);
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
                let r1 = run_scenario(scenario, topology, seed);
                let r2 = run_scenario(scenario, topology, seed);
                if !r1.passed || r1.trace_sha256 != r2.trace_sha256 {
                    eprintln!(
                        "FAIL determinism check: scenario={scenario} topo={topology} seed={seed} passed={} h1={} h2={}",
                        r1.passed, r1.trace_sha256, r2.trace_sha256
                    );
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
            let work: Vec<(ScenarioKind, u64)> = scenarios
                .iter()
                .flat_map(|&sc| (start_seed..start_seed + seeds).map(move |seed| (sc, seed)))
                .collect();

            let reports: Vec<ScenarioReport> = work
                .par_iter()
                .map(|&(sc, seed)| run_scenario(sc, topology, seed))
                .collect();

            let aggregate_probes = ProbeRegistry::new();
            let mut failures = Vec::new();
            let mut total_ops = 0u64;
            for rep in &reports {
                total_ops += rep.operations;
                aggregate_probes.merge_from(&rep.probes);
                if !rep.passed {
                    failures.push(rep);
                }
            }

            if json {
                let summary = serde_json::json!({
                    "topology": topology.to_string(),
                    "total_runs": reports.len(),
                    "passed_runs": reports.len() - failures.len(),
                    "failed_runs": failures.len(),
                    "total_operations": total_ops,
                    "probes": aggregate_probes.snapshot(),
                    "failures": failures,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).expect("serialize summary")
                );
            } else {
                println!(
                    "RustFS DST Summary: topology={topology} runs={} passed={} failed={} ops={total_ops}",
                    reports.len(),
                    reports.len() - failures.len(),
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

            if failures.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
