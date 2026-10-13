# Security Architecture & Threat Model

## 1. Cryptographic Primitives

| Data Class | Retention | Objective | Cryptographic Primitive | Implementation |
|---|---|---|---|---|
| Secret Values | Reversible | Confidentiality & Integrity | Authenticated Envelope Encryption | AES-256-GCM + Random DEK per version |
| Application Tokens | Irreversible | Authenticity & Verification | Cryptographic Hash Function | SHA-256 over 192-bit CSPRNG token |
| Audit Ledger | Append-only | Tamper-evidence | Cryptographic Hash Chain | SHA-256 chain: $H_i = \text{SHA256}(H_{i-1} \parallel \text{Entry}_i)$ |
| Unseal Master Key | Ephemeral | Threshold Fault Tolerance | Shamir's Secret Sharing | $K$-of-$N$ threshold scheme over $\text{GF}(256)$ |
| Key Material in RAM | Ephemeral | Memory Anti-Dumping / Zeroing | C Native Memory Lock & Zero | `mlock()`, `vlt_explicit_zero()`, `vlt_consttime_memcmp()` |

---

## 2. Envelope Encryption & Key Hierarchy

```
 Plaintext Value ──► AES-256-GCM(DEK, AAD="name|version") ──► Stored Ciphertext
 Data Encryption Key (DEK) ──► AES-256-GCM(KEK) ───────────► Stored Wrapped DEK
 Key Encryption Key (KEK / Master Key) ────────────────────► Held outside DB or in Shamir quorum
```

- **Per-Version Random DEK**: Compromise of a single DEK does not expose any other version or secret.
- **Authenticated Additional Data (AAD)**: Ciphertext is cryptographically bound to the tuple `(name, version)`. Splicing or copying ciphertext from one row or secret to another causes GCM authentication failure.
- **Random 96-bit Nonce**: Every encryption generates a fresh CSPRNG nonce via `os.urandom(12)`. Identical plaintexts produce distinct, uncorrelatable ciphertexts.
- **Zero-Downtime Master Key Rotation (`rewrap`)**:
  Rotating the KEK only requires unwrapping and re-wrapping the 32-byte DEKs in place. Ciphertexts are not rewritten, eliminating read-lock duration and database write thrashing.

---

## 3. Native Memory Security

Standard Python runtimes cannot guarantee that heap-allocated strings or bytes are wiped immediately or protected from disk swap. Vaulting mitigates this via its C native security layer (`c_src/secure_mem.c`):

1. **Page Pinning (`mlock`)**: Pages containing unsealed master keys and cryptographic buffers are pinned into physical RAM, blocking kernel swapping to disk.
2. **Dead-Store Elimination Defense (`vlt_explicit_zero`)**:
   Compiler optimizations routinely elide standard `memset` calls before memory deallocation. Vaulting uses inline compiler barriers (`__asm__ volatile("" ::: "memory")`) and `memset_s` to guarantee memory is wiped in-place immediately upon release.
3. **Constant-Time Comparison (`vlt_consttime_memcmp`)**:
   Key and token comparisons run in constant time regardless of common prefix length, neutralizing timing side-channels.

---

## 4. Threat Model & Mitigations

| Threat | Attack Vector | Vaulting Mitigation | Operational Requirement |
|---|---|---|---|
| **Stolen Database Artifact** | Exfiltrated SQLite database file | Plaintexts are encrypted under AES-256-GCM; master key is stored strictly outside the database | Keep master key or Shamir shares separate from database backups |
| **Ciphertext Splicing / Row Swapping** | Attacker swaps ciphertext between DB rows | AES-256-GCM authentication tag verification fails due to strict AAD binding (`name\|version`) | Handled automatically by cryptographic engine |
| **Unauthorized Audit Modification** | Attacker edits or deletes audit log rows | Cryptographic hash chaining detects any edited, inserted, or omitted audit records (`vaulting audit --verify`) | Export/anchor audit head hash periodically to immutable storage |
| **Credential Leakage in Telemetry** | Developer inadvertently logs credentials | C-accelerated Aho-Corasick Sentinel detects exact matches in milliseconds; Guard Agent rotates credential and revokes old version | Ensure log paths and dump volumes are monitored by `vaulting watch` |
| **Stolen App Token** | Network eavesdropping or token leak | Tokens hashed via SHA-256 at rest; granular per-secret grants; configurable TTL; instant revocation via CLI/API | Enforce mTLS so tokens cannot be intercepted in transit |
| **Network Eavesdropping / Man-in-the-Middle** | Interception on network interfaces | Strict TLS 1.2+ encryption; full Mutual TLS (mTLS) with client certificate verification (`vaulting/mtls.py`) | Deploy client certificates signed by the Vaulting CA |
| **Denial of Service / Flooding** | Volumetric HTTP requests | Per-IP token bucket rate limiting, socket timeouts, and maximum payload size caps | Use an external reverse proxy (e.g. Envoy/Nginx) for multi-node deployments |
| **Flawed Rotation Outage** | New secret fails with dependents | Crash-safe saga pattern: old secret held in grace period, dependents health-checked, automatic rollback on verification failure | Dependents must implement meaningful health-check endpoints |

---

## 5. Key Management & Operations Runbook

### 5.1 Initial Master Key Generation
```bash
python -m vaulting keygen --out /etc/vaulting/master.key
chmod 0600 /etc/vaulting/master.key
export VAULTING_KEY_FILE=/etc/vaulting/master.key
```

### 5.2 Shamir Secret Sharing Quorum Unseal
```bash
# Split master key into 5 shares requiring any 3 to unseal:
python -m vaulting.cli init-unseal --threshold 3 --shares 5

# On boot, unseal the vault by submitting shares:
python -m vaulting.cli unseal --share <share_1>
python -m vaulting.cli unseal --share <share_2>
python -m vaulting.cli unseal --share <share_3>
```

### 5.3 Master Key Rotation (`rewrap`)
```bash
# 1. Generate new secondary key ID
python -m vaulting keygen --id k2

# 2. Append the new key line to master.key:
#    k1:<base64_key_1>
#    k2:<base64_key_2>

# 3. Rewrap all stored Data Encryption Keys under k2:
python -m vaulting rewrap

# 4. Once rewrap finishes, safely delete k1 from the master.key file
```
