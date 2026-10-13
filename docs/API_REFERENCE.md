# Vaulting API & CLI Reference

## 1. CLI Commands

The Vaulting CLI is invoked via `python -m vaulting` or the installed binary `vaulting`.

### Key & State Management
| Command | Description | Example |
|---|---|---|
| `keygen` | Generate a new random master key | `vaulting keygen --out master.key` |
| `rewrap` | Re-wrap all DEKs to the latest active master key | `vaulting rewrap` |
| `status` | Print database status, key count, unseal state | `vaulting status` |
| `audit` | Verify the cryptographic integrity of the audit chain | `vaulting audit --verify` |

### Secrets Operations
| Command | Description | Example |
|---|---|---|
| `put <name>` | Securely store or prompt for a secret | `vaulting put db_password` |
| `get <name>` | Retrieve active secret value (requires token/key) | `vaulting get db_password` |
| `rotate <name>` | Trigger safe saga rotation of a secret | `vaulting rotate db_password` |
| `set-rotation <name> <hours>` | Set automatic scheduled rotation policy | `vaulting set-rotation db_password 24` |

### Access Control & Applications
| Command | Description | Example |
|---|---|---|
| `register-app <app>` | Issue a bearer token with grants and TTL | `vaulting register-app web --grant db_pass --ttl-days 30` |
| `revoke-app <app>` | Immediately revoke an application token | `vaulting revoke-app web` |

### Daemon & Service Operations
| Command | Description | Example |
|---|---|---|
| `serve` | Run the Vaulting HTTPS/mTLS service | `vaulting serve --port 8080 --tls-cert cert.pem --tls-key key.pem` |
| `watch` | Run leak sentinel and scheduled rotation loop | `vaulting watch --paths /var/log --dependent db_pass=http://app:8080` |

---

## 2. HTTP REST API

All authenticated endpoints require an `Authorization: Bearer <token>` header. Responses are sent with `Cache-Control: no-store`.

### `GET /v1/secrets/<name>`
Fetches the active version of a secret.
- **Headers**: `Authorization: Bearer <token>`
- **Response `200 OK`**:
  ```json
  {
    "name": "db_password",
    "value": "s3cr3t_v2",
    "version": 2,
    "ttl_seconds": 3600
  }
  ```
- **Error Codes**: `401 Unauthorized` (invalid/expired token), `403 Forbidden` (no grant), `404 Not Found`.

### `POST /v1/validate`
Validates whether a candidate secret value matches the current active or grace version without revealing the plaintext.
- **Payload**: `{"name": "db_password", "value": "candidate_val"}`
- **Response `200 OK`**: `{"valid": true, "version": 2, "state": "active"}`

### `GET /v1/metrics`
Administrative Prometheus metrics endpoint (requires admin token or direct metrics port `9101`).
- **Response `200 OK`**: Prometheus text format (`text/plain`).

### `GET /healthz`
Service readiness and liveness probe.
- **Response `200 OK`**: `{"status": "ok", "sealed": false}`

---

## 3. Mutual TLS (mTLS)

Vaulting provides built-in utilities in `vaulting.mtls`:

```python
from vaulting.mtls import (
    generate_ca,
    generate_cert,
    make_server_ssl_context,
    make_client_ssl_context,
    MTLSServer,
)

# 1. Generate Root CA
ca_cert, ca_key = generate_ca(common_name="Vaulting CA")

# 2. Generate Server Certificate
srv_cert, srv_key = generate_cert(
    ca_cert, ca_key, common_name="vault.internal", san_dns=["vault.internal"]
)

# 3. Generate Client Certificate
cli_cert, cli_key = generate_cert(
    ca_cert, ca_key, common_name="order-service", is_server=False
)

# 4. Create TLS Contexts
server_ctx = make_server_ssl_context(srv_cert, srv_key, ca_cert)
client_ctx = make_client_ssl_context(cli_cert, cli_key, ca_cert)
```
