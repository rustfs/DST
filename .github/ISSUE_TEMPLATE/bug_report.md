---
name: Simulation Failure / Bug Report
about: Report a deterministic simulation failure or invariant violation
title: "[DST] "
labels: ["bug", "dst"]
---

## Reproducer Command

```bash
cargo run --release -p rustfs-dst-cli -- repro --scenario <SCENARIO> --topology <4x4|3x2|4x2> --seed <SEED>
```

## Violated Invariant

Describe which invariant failed (linearizability, bit-exact integrity, crash atomicity, lock fencing, heal convergence).

## Expected Behavior

## Actual Output / Trace Digest
