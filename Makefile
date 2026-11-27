.PHONY: test lint fmt determinism run-4x4 run-3x2 run-4x2

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

determinism:
	cargo run --release -p rustfs-dst-cli -- verify-determinism --topology 4x4 --seed 2026
	cargo run --release -p rustfs-dst-cli -- verify-determinism --topology 3x2 --seed 2026

run-4x4:
	cargo run --release -p rustfs-dst-cli -- run --scenario all --topology 4x4 --seeds 100

run-3x2:
	cargo run --release -p rustfs-dst-cli -- run --scenario all --topology 3x2 --seeds 100

run-4x2:
	cargo run --release -p rustfs-dst-cli -- run --scenario all --topology 4x2 --seeds 100
