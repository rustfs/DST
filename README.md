# RustFS DST — Deterministic Simulation Testing

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**RustFS DST** is the official Deterministic Simulation Testing (DST) framework, runtime trait abstraction layer, virtual fault simulator, and multi-seed correctness verifier for [RustFS](https://github.com/rustfs/rustfs).

Inspired by FoundationDB's Flow simulator, Tokio [`turmoil`](https://github.com/tokio-rs/turmoil), [`madsim`](https://github.com/madsim-rs/madsim), and [Antithesis](https://antithesis.com/), RustFS DST abstracts every source of non-determinism in a distributed storage engine behind clean Rust traits so complex multi-node failure modes execute deterministically inside a single process and reproduce bit-for-bit from a single `u64` seed.

## Core Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │       RustFS Storage Engine Subsystems       │
                     │  (ECStore · Distributed Lock · Heal · GC)    │
                     └──────────────────────┬───────────────────────┘
                                            │
                            Unified Determinism Traits
                              (`rustfs-dst-runtime`)
       ┌────────────────────┬───────────────┴──────────────┬────────────────────┐
       ▼                    ▼                              ▼                    ▼
  trait Clock         trait RngSource                trait Network         trait DiskIo
  ├─ RealClock        ├─ RealRng                     ├─ SimNetwork         ├─ RealDiskIo
  └─ SimClock         └─ SimRng (ChaCha8 + fork)     │   (Swizzle-Clog,    └─ SimDiskIo
     (skew, drift,                                   │    asymmetric cuts,    (volatile vs
      virtual time)                                  │    reply drops)         durable fsync,
                                                     └─ turmoil::net           power loss,
                                                        (virtual TCP)          bitrot, ENOSPC)
```

## Workspace Crates

| Crate | Purpose |
|---|---|
| [`rustfs-dst-runtime`](crates/rustfs-dst-runtime) | Unified traits (`Clock`, `RngSource`, `Network`, `DiskIo`, `RuntimeEnv`) with production, in-memory deterministic simulator, Tokio `turmoil` virtual TCP adapter, and `madsim` compatibility layer. |
| [`rustfs-dst-faults`](crates/rustfs-dst-faults) | Two-stage deterministic `Buggify` injector, `CodeProbe` coverage tracker with Antithesis-compatible JSONL assertion emission, RustFS commit `CrashPoint` registry, and `SwizzleClogScheduler`. |
| [`rustfs-dst-sim`](crates/rustfs-dst-sim) | Simulated RustFS distributed erasure-coded storage engine (`SimECStore`) with GF(2^8) Cauchy Reed-Solomon, `xl.meta` atomic two-phase commit, quorum locking, online healing, real `turmoil` TCP cluster tests, and a 6-invariant `ConsistencyOracle`. |
| [`rustfs-dst-cli`](crates/rustfs-dst-cli) | Joshua-style parallel multi-seed runner (`rustfs-dst run`), single-seed bit-exact reproducer (`rustfs-dst repro`), and determinism prover (`rustfs-dst verify-determinism`). |

## Verified Invariants

1. **Linearizability & Monotonic Read-After-Write**: Readers never observe a generation older than an acknowledged write or delete, even across degraded quorums (`W + R > N`).
2. **Bit-Exact Data Integrity**: Every readable object matches the exact SHA-256 of a submitted payload; silent bitrot up to the parity limit is detected and reconstructed transparently.
3. **Crash Atomicity (Old-or-New-Never-Mixed)**: Abrupt power loss (`SimDiskIo::crash_and_reboot`) at any RustFS `xl.meta` commit window drops un-fsynced page-cache state without corrupting previously committed versions.
4. **Quorum Safety**: Writes fail closed on minority partitions and roll back partial drive writes cleanly; reply drops after remote apply are modeled as indeterminate outcomes.
5. **Distributed Lock Mutual Exclusion & Monotonic Fencing**: Monotonic-clock quorum leases remain immune to wall-clock skew jumps and issue strictly increasing fencing epochs.
6. **Heal Convergence & Zero Orphan Leaks**: Post-heal, every drive in `4x4` (16 drives, EC:4), `3x2` (6 drives, EC:3), and `4x2` (8 drives, EC:4) converges to the identical generation with zero leaked `.rustfs.sys/tmp/` artifacts.

## Quickstart

```bash
# Run the full unit and integration test suite
cargo test --workspace

# Prove bit-for-bit determinism across every scenario
cargo run --release -p rustfs-dst-cli -- verify-determinism --topology 4x4 --seed 2026

# Run a 100-seed parallel DST campaign on 4x4 and 3x2 topologies
cargo run --release -p rustfs-dst-cli -- run --scenario all --topology 4x4 --seeds 100
cargo run --release -p rustfs-dst-cli -- run --scenario all --topology 3x2 --seeds 100

# Replay a single failing seed deterministically
cargo run --release -p rustfs-dst-cli -- repro --scenario swizzle-clog-chaos --topology 4x4 --seed 42
```

## Supported Topologies

| Topology | Nodes × Drives | Total Drives | Parity (`m`) | Data (`k`) | Read Quorum (`R`) | Write Quorum (`W`) |
|---|---:|---:|---:|---:|---:|---:|
| `4x4` | 4 × 4 | 16 | 4 | 12 | 12 | 12 |
| `3x2` | 3 × 2 | 6 | 3 | 3 | 3 | 4 |
| `4x2` | 4 × 2 | 8 | 4 | 4 | 4 | 5 |

## Documentation

- [Complete 26-Scenario Coverage Matrix (7 Core + 19 Enterprise Domains)](docs/coverage-matrix.md)
- [Architecture & Upstream Trait Adoption Blueprint (`rustfs/rustfs`)](docs/architecture.md)
- [Simulation Backends: In-Process, Turmoil, Madsim & Antithesis](docs/antithesis.md)
- [Jepsen Distributed Verification Companion (`rustfs/Jepsen`)](https://github.com/rustfs/Jepsen)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
