# Simulation Engines: In-Process, Turmoil, Madsim, and Antithesis

RustFS DST is intentionally layered so the same invariants and workloads work across four execution tiers:

## 1. In-Process Trait Simulator (`SimEnv`)

- **Best for**: Fast PR CI gates (hundreds of seeds in seconds), exhaustive `CrashPoint` matrices, `SimDiskIo` power-loss testing, and bit-exact SHA-256 trace verification.
- **How to run**: `cargo run --release -p rustfs-dst-cli -- run --seeds 100`.

## 2. Tokio `turmoil` Virtual TCP (`turmoil-sim`)

- **Best for**: Exercising real TCP framing, connection resets, socket timeouts, `turmoil::partition`, `turmoil::hold`, `turmoil::repair`, and `turmoil::bounce` without modifying the `tokio` runtime.
- **How to run**: `cargo run --release -p rustfs-dst-cli -- repro --scenario turmoil-tcp-cluster --seed 2026`.

## 3. `madsim` Drop-In Runtime (`madsim-compat`)

- **Best for**: Running unmodified `tonic` / `tokio` gRPC code from `rustfs/rustfs` under a deterministic scheduler by swapping `[patch.crates-io]` to `madsim-tokio` and `madsim-tonic` with `RUSTFLAGS="--cfg madsim"`.
- Because `madsim` replaces Tokio globally via Cargo patches, it is isolated behind the optional `madsim-compat` feature so default stable-Rust builds stay fast and dependency-minimal.

## 4. Antithesis Autonomous Testing

When the `ANTITHESIS_OUTPUT_DIR` environment variable is set, `rustfs-dst-faults::probe::ProbeRegistry` automatically emits structured Antithesis-compatible JSONL assertion events to `$ANTITHESIS_OUTPUT_DIR/sdk.jsonl`:

- `always` -> safety invariants (linearizability, bit-exact integrity, mutual exclusion)
- `sometimes` -> liveness and fault-recovery coverage (degraded quorum PUTs, transparent bitrot reconstruction)
- `reachability` -> fault paths reached (`reply_dropped_after_apply`, `write_quorum_rollback`, `heal_repaired_shards`)
- `setup_complete` -> emitted once simulation initialization finishes

### Running the Antithesis Composer Stack

See [`antithesis/Dockerfile`](../antithesis/Dockerfile) and [`antithesis/docker-compose.yaml`](../antithesis/docker-compose.yaml) for a ready-to-build workload container image that streams Antithesis assertions while executing continuous DST campaigns.
