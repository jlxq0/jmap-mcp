# syntax=docker/dockerfile:1.7

# Multi-stage build → distroless runtime. Final image ~20-25 MiB.
# Unlike matrix-mcp, jmap-mcp has NO C build deps (no libopus/CMake) and no
# bundled SQLite — it's a stateless JMAP MCP server. Pure-Rust + rustls.

ARG RUST_VERSION=1.93
# Digest pinned to rust:1.93-bookworm (OCI index). Update via Renovate.
FROM rust:${RUST_VERSION}-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

WORKDIR /build

# Cache dependencies separately from source: copy manifest first, build a
# stub, then copy real source. `cargo build` only re-runs the slow dependency
# compile if Cargo.toml / Cargo.lock change.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("dep stub"); }' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/deps/jmap_mcp* target/release/jmap-mcp*

COPY src ./src
RUN cargo build --release --locked

# Distroless runtime: no shell, no apt. `cc` variant ships glibc + ca-certs,
# which we need for HTTPS to Logto (JWKS) and Stalwart (JMAP).
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77

ARG APP_VERSION=0.2.10
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="jmap-mcp" \
      org.opencontainers.image.description="Remote MCP server exposing a Stalwart JMAP mailbox" \
      org.opencontainers.image.source="https://github.com/jlxq0/jmap-mcp" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

WORKDIR /app
COPY --from=builder /build/target/release/jmap-mcp /app/jmap-mcp

# Non-root by default (distroless `nonroot`, UID 65532).
USER nonroot:nonroot

EXPOSE 3000
ENTRYPOINT ["/app/jmap-mcp"]
