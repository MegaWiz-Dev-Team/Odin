# ── Build stage ──────────────────────────────────────────────────
FROM rust:latest AS builder

WORKDIR /app

# Cache dependencies (workspace root + the `thor` policy crate member)
COPY Cargo.toml Cargo.lock ./
COPY thor ./thor
RUN mkdir src && echo "fn main(){}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -f target/release/deps/Odin* target/release/Odin

# Build real binary
COPY src ./src
RUN cargo build --release

# ── Runtime stage ─────────────────────────────────────────────────
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/Odin /usr/local/bin/odin
COPY static ./static

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/chat.html || exit 1

CMD ["odin"]
