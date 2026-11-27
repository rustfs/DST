# RustFS DST Architecture & Upstream Trait Adoption Blueprint

This document describes how RustFS abstracts non-determinism across its core crates (`crates/ecstore`, `crates/lock`, `crates/heal`, `crates/scanner`) to enable Deterministic Simulation Testing (DST).

## 1. Why Deterministic Simulation Testing?

Traditional integration tests and chaos engineering suffer from two limitations:
- **Non-reproducibility**: A race condition triggered once in 10,000 runs cannot be replayed step-by-step under a debugger.
- **Wall-clock bottleneck**: Testing lease expirations, scanner intervals, and multi-stage heal recoveries in real time takes hours per scenario.

DST eliminates all four sources of non-determinism by injecting trait-based abstractions at the system boundary:

| Non-Deterministic Source | RustFS Production Call Sites | Unified Trait (`rustfs-dst-runtime`) | Simulator Behavior |
|---|---|---|---|
| System time | `SystemTime::now()`, `Instant::now()`, `tokio::time::sleep` in `ecstore`, `lock`, `heal`, `scanner` | `Clock` | Virtual discrete-event clock with per-node wall-clock skew and monotonic drift |
| Randomness | `rand::rng()`, `Uuid::new_v4()` for version IDs, upload IDs, temp names, backoff jitter | `RngSource` | ChaCha8 PRNG with SHA-256 domain-separated `fork(label)` sub-streams |
| Network I/O | Inter-node gRPC/Tonic RPCs (`PeerDisk`, `RemoteClient` locks) | `Network` / `turmoil::net` | Symmetric/asymmetric partitions, Swizzle-Clog jitter, packet drop, post-apply reply drop |
| Disk I/O | `tokio::fs` / `std::fs` in `ecstore::disk::local::LocalDisk` | `DiskIo` | Explicit volatile page-cache vs durable `fsync` split, power-loss `crash_and_reboot`, bitrot, torn writes, `ENOSPC` |

## 2. Two-Phase Crash-Consistent Commit Model

RustFS commits object overwrites using a staged atomic protocol modeled directly in `rustfs-dst-sim::ecstore`:

1. Write data shard + `xl.meta` into `.rustfs.sys/tmp/<tx_id>/` and call `fsync_file`.
2. Rename staged data shard into `<bucket>/<key>/<version_id>/part.1` and `fsync_dir`.
3. Copy existing `xl.meta` into `xl.meta.bkp` and `fsync_file`.
4. Atomically rename `tmp/xl.meta` -> `<bucket>/<key>/xl.meta`.
5. Call `fsync_file` + `fsync_dir` to seal durability, then remove `.rustfs.sys/tmp/<tx_id>` and `xl.meta.bkp`.

`SimDiskIo::crash_and_reboot` discards every un-fsynced file write and directory rename, enabling exhaustive verification of every `CrashPoint` window mirroring `rustfs/rustfs/crates/ecstore/src/crash_inject.rs`.

## 3. Incremental Adoption Plan for `rustfs/rustfs`

1. **Phase 1 — Leaf trait adoption (`crates/lock`)**: Parameterize `FastObjectLockManager` and `DistributedLockGuard` lease expiry over `Clock` so lock safety under skew and partitions is verified deterministically.
2. **Phase 2 — Disk I/O boundary (`crates/ecstore/src/disk`)**: Implement `DiskAPI` over `DiskIo` alongside `LocalDisk`, allowing `ECStore` set operations to execute verbatim over `SimDiskIo` with power-loss crashes.
3. **Phase 3 — Inter-node RPC boundary (`crates/ecstore/src/disk`, `crates/protos`)**: Route peer disk & lock RPCs through `Network` (or `turmoil::net` / `madsim-tonic`) so multi-node `ECStore` clusters run inside single-process deterministic simulations.
4. **Phase 4 — Continuous Joshua/Antithesis Fuzzing**: Execute thousands of seeds per PR and nightly sweeps with `CodeProbe` coverage gates.
