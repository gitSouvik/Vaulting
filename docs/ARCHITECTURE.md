# Vaulting Architecture Specification

## 1. System Overview

Vaulting is a high-assurance, defense-in-depth secrets service engineered to automatically detect compromised credentials in telemetry and logs, rotate them safely with zero downtime, and record tamper-evident audit trails.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                CLIENT WORKLOADS                                 │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │ mTLS (TLS 1.2+ / client certs)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                VAULTING ENGINE                                  │
│                                                                                 │
│   ┌─────────────────────┐    ┌─────────────────────┐   ┌────────────────────┐   │
│   │   Rate Limiter      │───►│ Auth & Grants Guard │──►│ Prometheus Engine  │   │
│   │  (Token Bucket)     │    │  (Hashed Tokens)    │   │ (Port 9101 /metrics│   │
│   └─────────────────────┘    └──────────┬──────────┘   └────────────────────┘   │
│                                         │                                       │
│                ┌────────────────────────┴───────────────────────┐               │
│                ▼                                                ▼               │
│   ┌───────────────────────────┐                    ┌────────────────────────┐   │
│   │ Local Encrypted Store     │                    │ External Providers     │   │
│   │ AES-256-GCM Envelope      │                    │ (HashiCorp / OpenBao)  │   │
│   └────────────┬──────────────┘                    └────────────────────────┘   │
│                ▼                                                                │
│   ┌───────────────────────────┐    ┌────────────────────────────────────────┐   │
│   │ Cryptographic Hash Chain  │    │ Shamir Unseal Quorum Machine           │   │
│   │ (Tamper-evident logs)     │    │ (K-of-N Lagrange interpolation)        │   │
│   └───────────────────────────┘    └────────────────────────────────────────┘   │
└────────────────┬───────────────────────────────────────────────▲────────────────┘
                 │                                               │
                 ▼                                               │
┌─────────────────────────────────┐               ┌──────────────┴────────────────┐
│   CRASH-SAFE ROTATION SAGA      │               │     C NATIVE SECURITY CORE    │
│                                 │               │                               │
│  IDLE ──► PREPARED ──► ROTATING │               │ • Aho-Corasick Scanner        │
│               │             │   │               │ • mlock memory pinning        │
│               ▼             ▼   │               │ • explicit_zero barriers      │
│          ROLLING_BACK ◄── VERIFY│               │ • consttime_memcmp            │
│               │             │   │               │ • Shamir GF(256) arithmetic   │
│               ▼             ▼   │               └───────────────────────────────┘
│            ABORTED        DONE  │
└─────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 C Native Security Core (`c_src/` & `vaulting/native.py`)
To prevent performance degradation as the volume of secrets grows, Vaulting offloads critical compute and memory operations to a native C library loaded via `ctypes`:

- **Aho-Corasick Multi-Pattern Search** (`c_src/scanner.c`):
  Constructs a deterministic finite automaton (trie with failure links). All active secrets are evaluated simultaneously against streaming input in $\mathcal{O}(N + M)$ time. Zero heap allocations occur during search, delivering up to **29.1x faster** scanning than standard iteration.
- **Hardware-Protected Memory & Anti-Elision** (`c_src/secure_mem.c`):
  - `mlock()`: Locks memory pages containing key material into RAM, preventing them from being swapped out to disk or captured in swap dumps.
  - `vlt_explicit_zero()`: Uses volatile pointers and inline compiler memory barriers (`__asm__ volatile("" ::: "memory")`) or `memset_s` to guarantee key zeroing is never elided by compiler dead-store elimination.
  - `vlt_consttime_memcmp()`: Constant-time byte array comparator ensuring timing attacks cannot deduce secret bytes.

### 2.2 Cryptographic Key Management & Shamir Unseal
- **Envelope Encryption**: Each secret version is encrypted with an independent random 256-bit Data Encryption Key (DEK) using AES-256-GCM. The DEK is encrypted under the Key Encryption Key (KEK / master key).
- **AAD Binding**: Authenticated Additional Data binds each ciphertext to `name|version`. Swapping ciphertext between different secret entries fails GCM authentication.
- **Shamir's Secret Sharing ($K$-of-$N$)**:
  The master key is split into $N$ cryptographic shares over the Galois field $\text{GF}(256)$ using random polynomials of degree $K-1$. The vault boots in a `SEALED` state; feeding $K$ unique shares into `UnsealMachine` reconstructs the key in secure memory.

### 2.3 Crash-Safe Rotation Saga (`vaulting/saga.py`)
Key rotation follows a multi-phase saga persisted to SQLite WAL:
1. `PREPARED`: New key generated, staged, and written.
2. `ROTATING`: Local database pointers and dependent configurations transition to the staged key.
3. `VERIFYING`: Dependent application health checks are probed.
4. `DONE`: Verification succeeds; old key material enters grace or immediate revocation.
5. `ROLLING_BACK`: On health-check failure or crash, the saga transitions backwards to safely restore the known-good version.

On process boot, `RotationSaga.recover()` automatically inspects active sagas, recovering in-flight state without manual intervention.

### 2.4 Leak Sentinel & Guard Agent (`vaulting/sentinel.py`, `agent.py`)
- **Leak Sentinel**: Ingests files, environment dumps, and log streams. Uses exact-match verification via Aho-Corasick for managed secrets, accompanied by Shannon entropy analysis and regex pattern detectors for third-party tokens (e.g. AWS keys, Slack tokens).
- **Guard Agent**: Analyzes findings using deterministic rules. Only confirmed leaks of managed secrets trigger automated zero-downtime rotation. Ambiguous findings are logged and escalated for human review.

---

## 3. Secret Version Lifecycle

State progression is strictly enforced by SQLite partial unique indexes:

```
  create ──► ACTIVE ──rotate──► GRACE ──revoke──► REVOKED
                ▲                 │
                └───rollback──────┘   (active reverts to revoked)
```

- **Invariant 1**: For any secret, at most **one** version is in the `ACTIVE` state.
- **Invariant 2**: For any secret, at most **one** version is in the `GRACE` state.
- **Invariant 3**: Deprecated or replaced versions transition to `REVOKED` and cannot be decrypted by standard client read tokens.

---

## 4. Observability & Telemetry

- **Prometheus Collector Engine** (`vaulting/metrics.py`):
  Exposes standard Prometheus metrics on port `9101` (`/metrics`):
  - Counters: `vaulting_rotations_total`, `vaulting_sentinel_scans`, `vaulting_sentinel_hits`, `vaulting_http_requests_total`
  - Gauges: `vaulting_secrets_total`, `vaulting_vault_sealed`, `vaulting_native_available`
  - Histograms: `vaulting_rotation_duration_seconds`, `vaulting_http_request_duration_seconds`
- **Grafana Provisioning**: Pre-packaged dashboards in `docker/grafana` visualising operational health, unseal status, scan throughput, and rotation latency.
