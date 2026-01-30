# syntax=docker/dockerfile:1

# --- builder ---
FROM rust:1.85-slim-bookworm AS builder
WORKDIR /src

# System deps for building crates that may link C libs (ring, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache deps
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY docs ./docs
COPY packaging ./packaging
COPY scripts ./scripts

RUN cargo build --release

# --- runtime ---
# Minimal-ish runtime while still providing Poppler + Tesseract.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    poppler-utils \
    tesseract-ocr \
    tesseract-ocr-eng \
    libseccomp2 \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged user
RUN useradd --system --home /nonexistent --shell /usr/sbin/nologin acip

WORKDIR /opt/acip
COPY --from=builder /src/target/release/moltbot-acip-sidecar /opt/acip/moltbot-acip-sidecar
COPY --from=builder /src/target/release/acip-extract /opt/acip/acip-extract

ENV RUST_LOG=info \
    ACIP_EXTRACTOR_BIN=/opt/acip/acip-extract

USER acip
EXPOSE 18795

# Expect config mounted at /etc/acip/config.toml by default.
ENTRYPOINT ["/opt/acip/moltbot-acip-sidecar"]
CMD ["--config", "/etc/acip/config.toml"]
