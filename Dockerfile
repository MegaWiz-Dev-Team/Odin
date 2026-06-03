# ── Build stage ──────────────────────────────────────────────────
FROM rust:latest AS builder

WORKDIR /app

# `thor` is a PRIVATE git dependency (MegaWiz-Dev-Team/Thor). Fetch it with the
# git CLI, authenticated via a BuildKit secret. The token is injected into git's
# config via GIT_CONFIG_* env vars (process-only) — never written to a file or an
# image layer, so it cannot leak. Build with:
#   GH_TOKEN=$(gh auth token) docker build --secret id=gh_token,env=GH_TOKEN -t odin:latest .
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Cache dependencies (thor git dep + regorus etc.)
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs
RUN --mount=type=secret,id=gh_token \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/gh_token)@github.com/.insteadOf" \
    GIT_CONFIG_VALUE_0="https://github.com/" \
    cargo build --release 2>/dev/null || true
RUN rm -f target/release/deps/Odin* target/release/Odin

# Build real binary
COPY src ./src
RUN --mount=type=secret,id=gh_token \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/gh_token)@github.com/.insteadOf" \
    GIT_CONFIG_VALUE_0="https://github.com/" \
    cargo build --release

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
