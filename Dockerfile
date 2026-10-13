# ────────────────────────────────────────────────────────────────
# Vaulting — production multi-stage Dockerfile
# Stage 1 compiles the native C core into libvaulting_core.so
# Stage 2 builds the lightweight Python runtime
# ────────────────────────────────────────────────────────────────

# ── Stage 1: Compile C Core ───────────────────────────────────────
FROM python:3.12-slim AS c-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY c_src/ ./c_src/
RUN gcc -O2 -Wall -Wextra -std=c11 -fPIC -shared -lpthread \
    -I./c_src -o libvaulting_core.so ./c_src/vaulting_core.c

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN useradd --uid 1000 --gid 0 --no-create-home vaulting

WORKDIR /app

# Install dependencies directly into Python runtime
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY --chown=vaulting:root vaulting/ ./vaulting/
COPY --chown=vaulting:root demo/     ./demo/

# Copy compiled C core from builder
COPY --from=c-builder --chown=vaulting:root /build/libvaulting_core.so \
     ./vaulting/libvaulting_core.so

# Data volume for SQLite DB and TLS certificates
RUN mkdir -p /data /tls && chown -R vaulting:root /data /tls
VOLUME ["/data", "/tls"]

USER vaulting

EXPOSE 8080 9101

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

ENV VAULTING_DB=/data/vault.db \
    VAULTING_METRICS_PORT=9101 \
    VAULTING_KEYS="k1:u53XvG0X21N0O7wJ7yvI4X+G69p7R1k4r7x3Z9Y1a2c=" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Entrypoint: run the HTTP server
CMD ["python", "-m", "vaulting", "serve", "--host", "0.0.0.0", "--port", "8080"]

# ── Labels ────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="Vaulting"
LABEL org.opencontainers.image.description="High-assurance secrets management engine with C core"
LABEL org.opencontainers.image.source="https://github.com/gitSouvik/Vaulting"
LABEL org.opencontainers.image.licenses="MIT"
