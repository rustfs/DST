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

//! Real Tokio [`turmoil`] virtual TCP transport adapter for RustFS DST.
//!
//! Enables RustFS multi-node RPC protocols to execute over deterministic
//! virtual TCP sockets (`turmoil::net::{TcpListener, TcpStream}`) with
//! seeded link latency, packet loss, symmetric/asymmetric partitions
//! (`turmoil::partition`), link holds (`turmoil::hold`), and host restarts
//! (`turmoil::bounce`).

use crate::network::{NetError, RpcFrame};
use bytes::Bytes;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Configuration for building a deterministic [`turmoil::Sim`] world.
#[derive(Clone, Debug)]
pub struct TurmoilConfig {
    /// Deterministic PRNG seed passed into `turmoil::Builder::rng_seed`.
    pub seed: u64,
    /// Simulated duration limit before the simulation stops.
    pub simulation_duration: Duration,
    /// Minimum virtual network message latency.
    pub min_message_latency: Duration,
    /// Maximum virtual network message latency.
    pub max_message_latency: Duration,
    /// Probability `[0.0, 1.0]` of random packet failure inside Turmoil.
    pub fail_rate: f64,
    /// Probability `[0.0, 1.0]` of automatic link repair inside Turmoil.
    pub repair_rate: f64,
}

impl Default for TurmoilConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            simulation_duration: Duration::from_secs(60),
            min_message_latency: Duration::from_millis(1),
            max_message_latency: Duration::from_millis(25),
            fail_rate: 0.0,
            repair_rate: 0.0,
        }
    }
}

/// Build a fully deterministic [`turmoil::Sim`] seeded via [`turmoil::Builder::rng_seed`].
pub fn build_turmoil_sim<'a>(cfg: &TurmoilConfig) -> turmoil::Sim<'a> {
    let mut builder = turmoil::Builder::new();
    builder
        .simulation_duration(cfg.simulation_duration)
        .min_message_latency(cfg.min_message_latency)
        .max_message_latency(cfg.max_message_latency)
        .fail_rate(cfg.fail_rate)
        .repair_rate(cfg.repair_rate)
        .rng_seed(cfg.seed)
        .enable_random_order();
    builder.build()
}

/// Write a length-prefixed JSON [`RpcFrame`] over a [`turmoil::net::TcpStream`].
pub async fn write_frame(
    stream: &mut turmoil::net::TcpStream,
    frame: &RpcFrame,
) -> Result<(), NetError> {
    let encoded = serde_json::to_vec(frame).map_err(|e| NetError::Io(e.to_string()))?;
    let len = u32::try_from(encoded.len()).map_err(|e| NetError::Io(e.to_string()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| NetError::Io(e.to_string()))?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|e| NetError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| NetError::Io(e.to_string()))?;
    Ok(())
}

/// Read a length-prefixed JSON [`RpcFrame`] from a [`turmoil::net::TcpStream`].
pub async fn read_frame(stream: &mut turmoil::net::TcpStream) -> Result<RpcFrame, NetError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| NetError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(NetError::Io(format!("frame length {len} exceeds 16 MiB")));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| NetError::Io(e.to_string()))?;
    let frame: RpcFrame = serde_json::from_slice(&buf).map_err(|e| NetError::Io(e.to_string()))?;
    Ok(frame)
}

/// Perform a single request/response RPC over a Turmoil virtual TCP connection
/// with an explicit simulated timeout.
pub async fn turmoil_rpc_call(
    addr: &str,
    request: RpcFrame,
    timeout: Duration,
) -> Result<RpcFrame, NetError> {
    let fut = async {
        let mut stream = turmoil::net::TcpStream::connect(addr)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        write_frame(&mut stream, &request).await?;
        read_frame(&mut stream).await
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| NetError::Timeout {
            from: "client".to_string(),
            to: addr.to_string(),
            timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        })?
}

/// Helper to construct a simple health-check ping frame.
pub fn ping_frame(payload: impl Into<Bytes>) -> RpcFrame {
    RpcFrame::new("rustfs.internal.Ping", payload)
}
