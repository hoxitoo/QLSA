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

EXPOSE 8080

CMD ["uvicorn", "aggregator.api:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--log-level", "info"]
