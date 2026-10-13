# ────────────────────────────────────────────────────────────────
# Vaulting — production Dockerfile
# Multi-stage build: compile C core, then copy into slim runtime.
# ────────────────────────────────────────────────────────────────

# ── Stage 1: C build ─────────────────────────────────────────────
FROM python:3.12-slim AS c-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY c_src/ ./c_src/
COPY vaulting/  ./vaulting/

# Build shared library (Linux .so)
RUN cd c_src && make all

# ── Stage 2: Python deps ──────────────────────────────────────────
FROM python:3.12-slim AS python-builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt hypothesis


# ── Stage 3: Runtime ─────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: run as non-root
RUN useradd --uid 1000 --gid 0 --no-create-home vaulting

WORKDIR /app

# Copy installed packages
COPY --from=python-builder /install /usr/local

# Copy source
COPY --chown=vaulting:root vaulting/ ./vaulting/
COPY --chown=vaulting:root demo/     ./demo/

# Copy compiled C library
COPY --from=c-builder /build/vaulting/libvaulting_core.so \
     ./vaulting/libvaulting_core.so

# Data volume for SQLite DB
RUN mkdir -p /data && chown vaulting:root /data
VOLUME ["/data"]

# TLS certificate directory (optional mTLS)
RUN mkdir -p /tls && chown vaulting:root /tls
VOLUME ["/tls"]

USER vaulting

# Expose API and metrics ports
EXPOSE 8080 9101

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

ENV VAULTING_DB=/data/vault.db \
    VAULTING_METRICS_PORT=9101 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Entrypoint: run the HTTP server
CMD ["python", "-m", "vaulting.server"]

# ── Labels ────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="Vaulting"
LABEL org.opencontainers.image.description="Hybrid Python/C secrets vault with Shamir unseal"
LABEL org.opencontainers.image.source="https://github.com/yourorg/vaulting"
LABEL org.opencontainers.image.licenses="MIT"
