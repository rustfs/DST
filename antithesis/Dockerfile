# Copyright 2026 RustFS Team
# Licensed under the Apache License, Version 2.0

FROM rust:1.88-slim-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p rustfs-dst-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/rustfs-dst /usr/local/bin/rustfs-dst
ENV ANTITHESIS_OUTPUT_DIR=/tmp/antithesis
RUN mkdir -p /tmp/antithesis
ENTRYPOINT ["/usr/local/bin/rustfs-dst"]
CMD ["run", "--scenario", "all", "--topology", "4x4", "--seeds", "100"]
