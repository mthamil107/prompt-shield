# =============================================================================
# prompt-shield Docker image — multi-stage build for minimal runtime footprint
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build — install dependencies and build the wheel
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps needed for building wheels (regex, pydantic-core, etc.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Copy only dependency metadata first for better layer caching
COPY pyproject.toml ./
COPY src/ ./src/

# Build a wheel and install into a prefix that we can copy later
RUN pip install --no-cache-dir --prefix=/install "." && \
    pip install --no-cache-dir --prefix=/install "fastapi>=0.100" "uvicorn[standard]>=0.20" "httpx>=0.24"

# ---------------------------------------------------------------------------
# Stage 2: Runtime — lean image with only what we need
# ---------------------------------------------------------------------------
FROM python:3.12-slim

# --- OCI / opencontainers labels -------------------------------------------
LABEL maintainer="prompt-shield contributors" \
      version="0.3.0" \
      description="Self-learning prompt injection detection engine for LLM applications" \
      org.opencontainers.image.title="prompt-shield" \
      org.opencontainers.image.description="Self-learning prompt injection detection engine" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.url="https://github.com/prompt-shield/prompt-shield" \
      org.opencontainers.image.source="https://github.com/prompt-shield/prompt-shield" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install curl for the HEALTHCHECK and runtime needs
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# --- Non-root user (security best practice) ---------------------------------
RUN groupadd --gid 1000 shield && \
    useradd --uid 1000 --gid shield --create-home shield

# Create writable data directory for SQLite databases, vault, etc.
RUN mkdir -p /home/shield/data && chown -R shield:shield /home/shield/data

USER shield
WORKDIR /home/shield

# --- Environment variables ---------------------------------------------------
ENV PROMPT_SHIELD_MODE=block \
    PROMPT_SHIELD_THRESHOLD=0.7 \
    PROMPT_SHIELD_DATA_DIR=/home/shield/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# --- Health check ------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# --- Expose API port ---------------------------------------------------------
EXPOSE 8000

# --- Entrypoint --------------------------------------------------------------
# Default: run the REST API server.
# Override with CLI:  docker run prompt-shield prompt-shield scan "text"
ENTRYPOINT ["python", "-m", "prompt_shield.api"]
