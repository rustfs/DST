## Summary

Describe the changes and the RustFS invariants or simulation capabilities added.

## Related Issues

Closes #

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo run --release -p rustfs-dst-cli -- verify-determinism --topology 4x4 --seed 2026`
- [ ] `cargo run --release -p rustfs-dst-cli -- run --scenario all --topology 4x4 --seeds 50`
