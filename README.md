# Vaulting

An encrypted secrets platform where **a leaked secret gets detected and replaced automatically, with zero downtime**.

```
 apps ──mTLS──► Vault API ──► encrypted SQLite (AES-256-GCM envelope encryption)
                   │  ▲   └──► external providers (HashiCorp Vault / OpenBao KV v2)
                   │  │
         hash-chained audit log
                   ▲
 Guard Agent ◄── findings ── Leak Sentinel ◄── Aho-Corasick C scanner (29x speedup)
     │                                     ◄── scans logs, env dumps, files
     └── rotate (crash-safe saga) → refresh + health-check dependents → keep, or roll back
```

## Highlights & Advanced Capabilities

1. **Aho-Corasick Multi-Pattern Scanner in C** (`c_src/scanner.c` + `vaulting/native.py`):
   Multi-pattern string matcher using ctypes C integration. Benchmarked at **up to 29.1x faster** than naive string scanning on large log corpora, with zero heap allocations during search.
2. **Secure Memory Primitives** (`c_src/secure_mem.c`):
   Guaranteed `explicit_zero` resistant to compiler dead-store elimination, `mlock` page pinning to prevent secrets swapping to disk, and constant-time memory comparisons to prevent timing side-channels.
3. **Shamir's Secret Sharing Unseal Quorum** (`c_src/shamir.c` + `vaulting/unseal.py`):
   Master keys can be split into $N$ shares where any $K$ shares reconstruct the key via Lagrange interpolation over $\text{GF}(256)$. The vault boots in a sealed state and exposes unseal progress.
4. **Crash-Safe Rotation Saga** (`vaulting/saga.py`):
   Multi-phase state machine (`IDLE` → `PREPARED` → `ROTATING` → `VERIFYING` → `DONE` / `ROLLING_BACK`) persisted to SQLite. Automatically recovers or rolls back unverified rotations across unexpected server reboots.
5. **Mutual TLS (mTLS) Support** (`vaulting/mtls.py`):
   Built-in CA generator, leaf certificate issuance with Subject Alternative Names (SANs), and strict client certificate verification for zero-trust environments.
6. **Observability Stack**:
   Native Prometheus `/metrics` server and collector registry (`vaulting/metrics.py`), turnkey Docker Compose setup with Prometheus and Grafana dashboards (`docker/`).
7. **Property-Based & Chaos Testing**:
   Over 100 tests including Hypothesis property-based invariants (`tests/test_invariants.py`) and simulated mid-rotation power failure / crash chaos tests (`tests/test_chaos.py`).

## Quick start

Python 3.9+ with `cryptography` and `hypothesis`.

```bash
# Build native C library
cd c_src && make all && cd ..

# Run tests (102 tests passing)
python -m pytest tests/ -v

# Run benchmarks
python benchmarks/bench_scanner.py
python benchmarks/bench_rotation.py

# Watch a leak get fixed end to end
python -m demo.run_demo
```

### Full Observability Stack with Docker Compose

```bash
docker compose up -d
# Vaulting API:       http://localhost:8080
# Prometheus metrics: http://localhost:9101/metrics
# Prometheus UI:      http://localhost:9090
# Grafana dashboard:  http://localhost:3000 (admin / admin)
```

## Features

| Area | What it does |
|---|---|
| **Encryption at rest** | Per-version data keys (AES-256-GCM) wrapped by a master key held outside the DB; ciphertext bound to `name\|version`; `rewrap` rotates the master key without rewriting values |
| **Secure Memory** | `mlock` page locking, compiler-barrier `explicit_zero`, and constant-time comparison in C |
| **Shamir Unseal** | $K$-of-$N$ threshold secret sharing over $\text{GF}(256)$ with unseal quorum state machine |
| **Crash-Safe Saga** | SQLite-persisted rotation state machine that recovers automatically across unexpected crashes |
| **Hashing, used correctly** | App tokens stored as SHA-256 hashes; audit log is a cryptographic hash chain so tampering is immediately detectable |
| **Auth & mTLS** | Bearer app tokens with expiry/revocation, per-secret grants, and full mutual TLS client certificate verification |
| **Providers** | Pluggable backends: serve secrets from HashiCorp Vault / OpenBao KV v2 (token or AppRole login) as `hcv:path#field` |
| **Leak sentinel** | C-accelerated Aho-Corasick exact-match scanner plus entropy heuristics |
| **Guard agent** | Plans, acts, verifies, writes a reasoning trace to SQL; escalates anything it isn't certain about |
| **Observability** | Turnkey Prometheus metrics registry + `/metrics` endpoint + pre-configured Grafana dashboard |

## Documentation

- [Architecture Specification](docs/ARCHITECTURE.md) — Subsystems, C native core, version lifecycles, and storage design.
- [Security Design & Threat Model](docs/SECURITY.md) — Cryptographic primitives, envelope encryption, and threat mitigations.
- [API & CLI Reference](docs/API_REFERENCE.md) — Command-line interface, HTTP REST endpoints, and mTLS usage.

## Project Structure

```
c_src/       scanner.c, secure_mem.c, shamir.c, Makefile
vaulting/    __init__.py, crypto.py, vault.py, saga.py, unseal.py, native.py,
             sentinel.py, agent.py, watcher.py, metrics.py, mtls.py, server.py,
             client.py, providers.py, ratelimit.py, cli.py, schema.sql
benchmarks/  bench_scanner.py, bench_rotation.py
docker/      prometheus.yml, grafana/ (dashboards and provisioning)
tests/       102 tests (unit, property-based, chaos, mTLS, metrics, crypto, security)
docs/        ARCHITECTURE.md, SECURITY.md, API_REFERENCE.md
```

## License

MIT
