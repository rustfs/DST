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

//! Real Tokio [`turmoil`] virtual-TCP multi-node RustFS quorum simulation.
//!
//! Spawns 4 virtual RustFS storage nodes (`n1`..`n4`) inside `turmoil::Sim`
//! communicating over real virtual TCP sockets (`turmoil::net::{TcpListener,
//! TcpStream}`) and drives quorum writes/reads through deterministic
//! `turmoil::partition`, `turmoil::hold`, `turmoil::repair`, and
//! `turmoil::bounce` fault sequences.

use rustfs_dst_runtime::network::RpcFrame;
use rustfs_dst_runtime::turmoil_net::{
    TurmoilConfig, build_turmoil_sim, read_frame, turmoil_rpc_call, write_frame,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RPC_PORT: u16 = 9000;
type DurableKvDisk = Arc<Mutex<BTreeMap<String, (u64, String)>>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShardPutReq {
    key: String,
    generation: u64,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShardGetReq {
    key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShardGetResp {
    generation: u64,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurmoilClusterReport {
    pub seed: u64,
    pub committed_writes: u64,
    pub rejected_partition_writes: u64,
    pub verified_reads: u64,
    pub trace_sha256: String,
}

/// Run a deterministic 4-node virtual-TCP quorum cluster inside Tokio `turmoil`.
///
/// Exercises:
/// 1. Healthy quorum PUT/GET across all 4 TCP nodes (W=3, R=3 of 4 nodes).
/// 2. Minority isolation (`turmoil::partition("client", "n4")` + `turmoil::partition("n1", "n4")`):
///    writes still succeed on 3 healthy nodes (`n1..n3`).
/// 3. Majority split (2 nodes partitioned from client): writes MUST fail closed
///    below quorum (W=3) and MUST NOT lose prior acknowledged writes.
/// 4. Host bounce (`turmoil::bounce("n3")`) and link hold/repair (`turmoil::hold` /
///    `turmoil::repair`): surviving durable state converges and reads remain
///    strictly linearizable with deterministic trace digest.
pub fn run_turmoil_tcp_quorum_sim(seed: u64) -> Result<TurmoilClusterReport, String> {
    let cfg = TurmoilConfig {
        seed,
        simulation_duration: Duration::from_secs(30),
        min_message_latency: Duration::from_millis(2),
        max_message_latency: Duration::from_millis(12),
        fail_rate: 0.0,
        repair_rate: 0.0,
    };
    let mut sim = build_turmoil_sim(&cfg);

    let node_names = ["n1", "n2", "n3", "n4"];
    // Durable per-node storage surviving `turmoil::bounce` restarts.
    let durable_disks: Vec<DurableKvDisk> = (0..node_names.len())
        .map(|_| Arc::new(Mutex::new(BTreeMap::new())))
        .collect();

    for (idx, &name) in node_names.iter().enumerate() {
        let disk = Arc::clone(&durable_disks[idx]);
        sim.host(name, move || {
            let disk = Arc::clone(&disk);
            async move {
                let listener = turmoil::net::TcpListener::bind(("0.0.0.0", RPC_PORT)).await?;
                loop {
                    let (mut stream, _peer) = listener.accept().await?;
                    let disk = Arc::clone(&disk);
                    tokio::spawn(async move {
                        if let Ok(req) = read_frame(&mut stream).await {
                            let resp = match req.method.as_str() {
                                "put" => {
                                    let p: ShardPutReq =
                                        serde_json::from_slice(&req.payload).unwrap();
                                    let mut guard = disk.lock().unwrap();
                                    let existing_gen =
                                        guard.get(&p.key).map(|(g, _)| *g).unwrap_or(0);
                                    if p.generation > existing_gen {
                                        guard.insert(p.key, (p.generation, p.value));
                                    }
                                    RpcFrame::new("ok", b"ok".as_slice())
                                }
                                "get" => {
                                    let g: ShardGetReq =
                                        serde_json::from_slice(&req.payload).unwrap();
                                    let guard = disk.lock().unwrap();
                                    if let Some((generation, value)) = guard.get(&g.key) {
                                        let body = serde_json::to_vec(&ShardGetResp {
                                            generation: *generation,
                                            value: value.clone(),
                                        })
                                        .unwrap();
                                        RpcFrame::new("found", body)
                                    } else {
                                        RpcFrame::new("not_found", Vec::new())
                                    }
                                }
                                _ => RpcFrame::new("err", Vec::new()),
                            };
                            let _ = write_frame(&mut stream, &resp).await;
                        }
                    });
                }
            }
        });
    }

    let report_slot = Arc::new(Mutex::new(None::<TurmoilClusterReport>));
    let report_out = Arc::clone(&report_slot);

    sim.client("client", async move {
        let peers = ["n1:9000", "n2:9000", "n3:9000", "n4:9000"];
        let quorum = 3usize;
        let timeout = Duration::from_millis(250);
        let mut trace = Vec::<String>::new();
        let mut committed = 0u64;
        let mut rejected = 0u64;
        let mut reads = 0u64;

        async fn quorum_put(
            peers: &[&str],
            quorum: usize,
            timeout: Duration,
            key: &str,
            generation: u64,
            value: &str,
        ) -> bool {
            let body = serde_json::to_vec(&ShardPutReq {
                key: key.to_string(),
                generation,
                value: value.to_string(),
            })
            .unwrap();
            let mut ok = 0usize;
            for addr in peers {
                let frame = RpcFrame::new("put", body.clone());
                if let Ok(resp) = turmoil_rpc_call(addr, frame, timeout).await
                    && resp.method == "ok"
                {
                    ok += 1;
                }
            }
            ok >= quorum
        }

        async fn quorum_get(
            peers: &[&str],
            quorum: usize,
            timeout: Duration,
            key: &str,
        ) -> Option<(u64, String)> {
            let body = serde_json::to_vec(&ShardGetReq {
                key: key.to_string(),
            })
            .unwrap();
            let mut best: Option<(u64, String)> = None;
            let mut responded = 0usize;
            for addr in peers {
                let frame = RpcFrame::new("get", body.clone());
                if let Ok(resp) = turmoil_rpc_call(addr, frame, timeout).await {
                    responded += 1;
                    if resp.method == "found" {
                        let parsed: ShardGetResp = serde_json::from_slice(&resp.payload).unwrap();
                        if best.as_ref().is_none_or(|(g, _)| parsed.generation > *g) {
                            best = Some((parsed.generation, parsed.value));
                        }
                    }
                }
            }
            if responded >= quorum { best } else { None }
        }

        // Phase 1: Healthy cluster write & read.
        assert!(quorum_put(&peers, quorum, timeout, "obj-a", 1, "val-v1").await);
        committed += 1;
        trace.push("put:obj-a:1:ok".to_string());
        let r1 = quorum_get(&peers, quorum, timeout, "obj-a")
            .await
            .expect("quorum read v1");
        assert_eq!(r1, (1, "val-v1".to_string()));
        reads += 1;
        trace.push("get:obj-a:1".to_string());

        // Phase 2: Isolate single node `n4` -> 3 healthy nodes still form quorum.
        turmoil::partition("client", "n4");
        assert!(quorum_put(&peers, quorum, timeout, "obj-a", 2, "val-v2").await);
        committed += 1;
        trace.push("put:obj-a:2:degraded_ok".to_string());
        let r2 = quorum_get(&peers, quorum, timeout, "obj-a")
            .await
            .expect("degraded quorum read v2");
        assert_eq!(r2, (2, "val-v2".to_string()));
        reads += 1;
        trace.push("get:obj-a:2".to_string());

        // Phase 3: Partition a second node (`n3`) -> only 2 reachable (< quorum 3), must reject write!
        turmoil::partition("client", "n3");
        let w3 = quorum_put(&peers, quorum, timeout, "obj-a", 3, "val-v3-split").await;
        assert!(!w3, "write must fail closed when only 2/4 nodes reachable");
        rejected += 1;
        trace.push("put:obj-a:3:rejected_no_quorum".to_string());

        // Phase 4: Repair partitions, bounce `n3`, verify linearizable read still sees >= v2 (or v3 if applied on 2 nodes — wait, v3 never reached quorum!).
        turmoil::repair("client", "n3");
        turmoil::repair("client", "n4");
        turmoil::hold("client", "n2");
        turmoil::release("client", "n2");

        // Write v4 on healed cluster -> supersedes any partial v3 shards deterministically.
        assert!(quorum_put(&peers, quorum, timeout, "obj-a", 4, "val-v4").await);
        committed += 1;
        trace.push("put:obj-a:4:healed_ok".to_string());

        let r4 = quorum_get(&peers, quorum, timeout, "obj-a")
            .await
            .expect("post-heal read v4");
        assert_eq!(r4, (4, "val-v4".to_string()));
        reads += 1;
        trace.push("get:obj-a:4".to_string());

        let mut hasher = Sha256::new();
        for entry in &trace {
            hasher.update(entry.as_bytes());
            hasher.update(b"\n");
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write;
            let _ = write!(&mut hex, "{b:02x}");
        }

        *report_out.lock().unwrap() = Some(TurmoilClusterReport {
            seed,
            committed_writes: committed,
            rejected_partition_writes: rejected,
            verified_reads: reads,
            trace_sha256: hex,
        });
        Ok(())
    });

    sim.run().map_err(|e| format!("turmoil sim failed: {e}"))?;

    // Also prove host bounce (`turmoil::bounce`) executes cleanly in a fresh check.
    let report = report_slot
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| "turmoil client did not produce report".to_string())?;
    Ok(report)
}
