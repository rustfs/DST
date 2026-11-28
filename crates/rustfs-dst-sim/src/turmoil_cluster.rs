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

//! Real Tokio [`turmoil`] virtual-TCP multi-node quorum simulation.
//!
//! This tier checks the virtual TCP transport (framing, `partition`, `hold`,
//! `repair`, `bounce`) with a node-majority quorum. It is not the erasure-set
//! `SimECStore`: drive-level Reed-Solomon quorum stays in the in-process
//! simulator. Node count follows the topology (`3` for `3x2`, `4` for `4x4`
//! and `4x2`) and the write quorum is `nodes / 2 + 1`.

use rustfs_dst_runtime::network::RpcFrame;
use rustfs_dst_runtime::turmoil_net::{
    TurmoilConfig, build_turmoil_sim, read_frame, turmoil_rpc_call, write_frame,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RPC_PORT: u16 = 9000;

#[derive(Clone, Debug)]
struct Record {
    generation: u64,
    value: String,
    prev: Option<(u64, String)>,
}

type DurableKvDisk = Arc<Mutex<BTreeMap<String, Record>>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShardPutReq {
    key: String,
    generation: u64,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShardRollbackReq {
    key: String,
    generation: u64,
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

/// Run a deterministic virtual-TCP quorum cluster inside Tokio `turmoil`.
///
/// `nodes` is the storage-node count (not the drive count). Quorum is a strict
/// majority of those nodes.
pub fn run_turmoil_tcp_quorum_sim(nodes: usize, seed: u64) -> Result<TurmoilClusterReport, String> {
    if !(2..=8).contains(&nodes) {
        return Err(format!("turmoil node count {nodes} is outside 2..=8"));
    }
    let cfg = TurmoilConfig {
        seed,
        simulation_duration: Duration::from_secs(30),
        min_message_latency: Duration::from_millis(2),
        max_message_latency: Duration::from_millis(12),
        fail_rate: 0.0,
        repair_rate: 0.0,
    };
    let mut sim = build_turmoil_sim(&cfg);

    let node_names: Vec<String> = (1..=nodes).map(|idx| format!("n{idx}")).collect();
    // Durable per-node storage surviving `turmoil::bounce` restarts.
    let durable_disks: Vec<DurableKvDisk> = (0..node_names.len())
        .map(|_| Arc::new(Mutex::new(BTreeMap::new())))
        .collect();

    for (idx, name) in node_names.iter().enumerate() {
        let disk = Arc::clone(&durable_disks[idx]);
        let host_name = name.clone();
        sim.host(host_name, move || {
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
                                        guard.get(&p.key).map(|rec| rec.generation).unwrap_or(0);
                                    if p.generation > existing_gen {
                                        let prev = guard
                                            .get(&p.key)
                                            .map(|rec| (rec.generation, rec.value.clone()));
                                        guard.insert(
                                            p.key,
                                            Record {
                                                generation: p.generation,
                                                value: p.value,
                                                prev,
                                            },
                                        );
                                    }
                                    RpcFrame::new("ok", b"ok".as_slice())
                                }
                                "rollback" => {
                                    let p: ShardRollbackReq =
                                        serde_json::from_slice(&req.payload).unwrap();
                                    let mut guard = disk.lock().unwrap();
                                    if guard
                                        .get(&p.key)
                                        .is_some_and(|rec| rec.generation == p.generation)
                                    {
                                        let prev =
                                            guard.get(&p.key).and_then(|rec| rec.prev.clone());
                                        match prev {
                                            Some((generation, value)) => {
                                                guard.insert(
                                                    p.key,
                                                    Record {
                                                        generation,
                                                        value,
                                                        prev: None,
                                                    },
                                                );
                                            }
                                            None => {
                                                guard.remove(&p.key);
                                            }
                                        }
                                    }
                                    RpcFrame::new("ok", b"ok".as_slice())
                                }
                                "get" => {
                                    let g: ShardGetReq =
                                        serde_json::from_slice(&req.payload).unwrap();
                                    let guard = disk.lock().unwrap();
                                    if let Some(rec) = guard.get(&g.key) {
                                        let body = serde_json::to_vec(&ShardGetResp {
                                            generation: rec.generation,
                                            value: rec.value.clone(),
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
    let names_for_client = node_names.clone();
    let bounce_phase = Arc::new(AtomicU8::new(0));
    let bounce_phase_client = Arc::clone(&bounce_phase);
    let bounce_name = node_names[0].clone();

    sim.client("client", async move {
        let peers: Vec<String> = names_for_client
            .iter()
            .map(|name| format!("{name}:{RPC_PORT}"))
            .collect();
        let peer_refs: Vec<&str> = peers.iter().map(String::as_str).collect();
        let quorum = names_for_client.len() / 2 + 1;
        let timeout = Duration::from_millis(250);
        let mut trace = Vec::<String>::new();
        trace.push(format!("nodes:{}:quorum:{quorum}", names_for_client.len()));
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
            let rollback_body = serde_json::to_vec(&ShardRollbackReq {
                key: key.to_string(),
                generation,
            })
            .unwrap();
            let mut applied = Vec::new();
            for addr in peers {
                let frame = RpcFrame::new("put", body.clone());
                if let Ok(resp) = turmoil_rpc_call(addr, frame, timeout).await
                    && resp.method == "ok"
                {
                    applied.push(*addr);
                }
            }
            if applied.len() >= quorum {
                return true;
            }
            for addr in applied {
                let frame = RpcFrame::new("rollback", rollback_body.clone());
                let _ = turmoil_rpc_call(addr, frame, timeout).await;
            }
            false
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
        assert!(
            quorum_put(&peer_refs, quorum, timeout, "obj-a", 1, "val-v1").await,
            "healthy quorum put"
        );
        committed += 1;
        trace.push("put:obj-a:1:ok".to_string());
        let r1 = quorum_get(&peer_refs, quorum, timeout, "obj-a")
            .await
            .expect("quorum read v1");
        assert_eq!(r1, (1, "val-v1".to_string()));
        reads += 1;
        trace.push("get:obj-a:1".to_string());

        // Phase 2: Isolate the last node. The remainder is still a majority.
        let isolated = names_for_client.last().expect("node").clone();
        turmoil::partition("client", isolated.clone());
        assert!(
            quorum_put(&peer_refs, quorum, timeout, "obj-a", 2, "val-v2").await,
            "majority remains after isolating one node"
        );
        committed += 1;
        trace.push(format!("put:obj-a:2:degraded_ok:isolated:{isolated}"));
        let r2 = quorum_get(&peer_refs, quorum, timeout, "obj-a")
            .await
            .expect("degraded quorum read v2");
        assert_eq!(r2, (2, "val-v2".to_string()));
        reads += 1;
        trace.push("get:obj-a:2".to_string());

        // Phase 3: Isolate one more node so the client is below majority.
        // The partial put must roll back; a later read must still observe v2.
        let second = names_for_client[names_for_client.len() - 2].clone();
        turmoil::partition("client", second.clone());
        let w3 = quorum_put(&peer_refs, quorum, timeout, "obj-a", 3, "val-v3-split").await;
        assert!(
            !w3,
            "write must fail closed when fewer than {quorum} nodes are reachable"
        );
        rejected += 1;
        trace.push(format!("put:obj-a:3:rejected_no_quorum:isolated:{second}"));
        turmoil::repair("client", isolated);
        turmoil::repair("client", second);
        let after_reject = quorum_get(&peer_refs, quorum, timeout, "obj-a")
            .await
            .expect("read after rejected write");
        assert_eq!(
            after_reject,
            (2, "val-v2".to_string()),
            "rejected write became visible"
        );
        reads += 1;
        trace.push("get:obj-a:2:after_rejected_put".to_string());

        // Phase 4: Hold every link across an RPC so the timeout is real, then release.
        for name in &names_for_client {
            turmoil::hold("client", name.clone());
        }
        let held = quorum_get(&peer_refs, quorum, timeout, "obj-a").await;
        assert!(
            held.is_none(),
            "quorum read succeeded while every client link was held"
        );
        trace.push("get:obj-a:held_timeout".to_string());
        for name in &names_for_client {
            turmoil::release("client", name.clone());
        }
        let after_release = quorum_get(&peer_refs, quorum, timeout, "obj-a")
            .await
            .expect("read after releasing holds");
        assert_eq!(after_release, (2, "val-v2".to_string()));
        reads += 1;
        trace.push("get:obj-a:2:after_hold".to_string());

        // Phase 5: Ask the driver to bounce a node, then wait for that restart.
        // `Sim::bounce` is not callable from inside a host. Durable state lives
        // outside the restarted task.
        bounce_phase_client.store(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after_bounce = quorum_get(&peer_refs, quorum, timeout, "obj-a")
            .await
            .expect("read after host bounce");
        assert_eq!(after_bounce, (2, "val-v2".to_string()));
        reads += 1;
        trace.push(format!("get:obj-a:2:after_bounce:{}", names_for_client[0]));

        assert!(
            quorum_put(&peer_refs, quorum, timeout, "obj-a", 4, "val-v4").await,
            "healed quorum put"
        );
        committed += 1;
        trace.push("put:obj-a:4:healed_ok".to_string());
        let r4 = quorum_get(&peer_refs, quorum, timeout, "obj-a")
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
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(&mut hex, "{byte:02x}");
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

    loop {
        if bounce_phase.load(Ordering::SeqCst) == 1 {
            sim.bounce(bounce_name.clone());
            bounce_phase.store(2, Ordering::SeqCst);
        }
        let finished = sim
            .step()
            .map_err(|err| format!("turmoil sim failed: {err}"))?;
        if finished {
            break;
        }
    }

    report_slot
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| "turmoil client did not produce report".to_string())
}
