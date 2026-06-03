FROM python:3.11-slim AS base

# System dependencies for liboqs build (liboqs-python has no wheel for linux/amd64 in some versions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    libssl-dev \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cached layer)
COPY requirements.txt requirements-api.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-api.txt

# Copy source
COPY aggregator/ aggregator/
COPY core/       core/
COPY stark/      stark/

# Mount the pre-built STARK binary at /app/stark_stwo/target/release/qlsa-stark-stwo
# Build it on the host with:
#   cd stark_stwo && cargo +nightly-2025-07-01 build --release
# Then mount via docker-compose volumes.

ENV PYTHONUNBUFFERED=1
ENV AGGREGATOR_HOST=0.0.0.0
ENV AGGREGATOR_PORT=8080

# ── Security / node configuration ──────────────────────────────────────────
# N_FRI_QUERIES: FRI queries per proof group.
#   1  → 16-bit on-chain soundness  (default, gas-safe for testnet)
#   3  → 28-bit on-chain soundness  (~45 M gas, safe within 2 txs at 15 M each)
#   5  → 40-bit on-chain soundness  (~75 M gas)
#   20 → 130-bit on-chain soundness (~300 M gas, exceeds mainnet block limit)
ENV N_FRI_QUERIES=1

# TRUSTED_PROXIES: comma-separated IPs of trusted reverse proxies.
# The rightmost X-Forwarded-For entry from these IPs is used for rate limiting.
# Default: 127.0.0.1,::1 (loopback only — safe for direct deployments).
# Example for a single nginx proxy at 10.0.0.1: TRUSTED_PROXIES=10.0.0.1
ENV TRUSTED_PROXIES=127.0.0.1,::1

EXPOSE 8080

CMD ["uvicorn", "aggregator.api:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--log-level", "info"]
