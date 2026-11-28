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

//! Compatibility notes and conditional hooks for `madsim`.
//!
//! RustFS DST supports three complementary simulation engines:
//!
//! 1. **In-process trait simulator (`SimEnv`)** — zero external runtime fork,
//!    runs on stable Rust, models [`crate::clock::SimClock`],
//!    [`crate::rng::SimRng`], [`crate::network::SimNetwork`], and
//!    crash-consistent [`crate::disk::SimDiskIo`] directly.
//! 2. **Tokio `turmoil` (`turmoil-sim` feature)** — simulates real TCP/UDP
//!    sockets and deterministic Tokio task scheduling without replacing the
//!    `tokio` crate.
//! 3. **`madsim` (`RUSTFLAGS="--cfg madsim"`)** — drop-in deterministic runtime
//!    replacement for `tokio`, `tonic`, and `rand` when testing unmodified
//!    gRPC/Tonic servers in `rustfs/rustfs`.

/// Returns `true` when this crate is compiled with `RUSTFLAGS="--cfg madsim"`.
///
/// The `madsim-compat` feature only marks the hook. It does not activate
/// madsim; Cargo patches and `--cfg madsim` do.
pub const fn is_madsim_active() -> bool {
    cfg!(madsim)
}

/// Yield execution cleanly across standard Tokio, Turmoil, and Madsim runtimes.
pub async fn yield_now() {
    tokio::task::yield_now().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_build_does_not_report_madsim_active() {
        assert!(!is_madsim_active());
    }
}
