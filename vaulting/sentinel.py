"""Leak sentinel: scans files for secrets.

Two kinds of detection, with very different confidence:
  1. EXACT MATCH against live vault values. Zero false positives: if the string
     is one of our active/grace secrets, it leaked. This is the only kind the
     agent will act on automatically.
  2. PATTERNS / ENTROPY for credentials we don't manage. Noisy, so these are
     reported for humans and never auto-remediated.
"""
import hashlib
import math
import os
import re
import time
from collections import Counter
from typing import Iterable, List

from .vault import Vault

MAX_FILE_BYTES = 1_000_000

PATTERNS = [
    ("aws_access_key_id", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("credential_assignment", "high",
     re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[=:]\s*['\"]?"
                r"([A-Za-z0-9_\-/+=.!@#$%^&*]{8,})")),
]
PLACEHOLDERS = {"changeme", "password", "example", "placeholder", "yourpassword", "xxxxxxxx"}
ENTROPY_RE = re.compile(r"[A-Za-z0-9+/_\-]{24,}")
ENTROPY_THRESHOLD = 4.2


def shannon_entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    return f"{value[:4]}...({len(value)} chars)"


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def iter_files(paths: Iterable[str]):
    for p in paths:
        if os.path.isfile(p):
            yield p
        else:
            for root, _dirs, files in os.walk(p):
                for f in files:
                    yield os.path.join(root, f)


class Sentinel:
    def __init__(self, vault: Vault):
        self.vault = vault

    def scan(self, paths: Iterable[str]) -> List[dict]:
        """Scan and persist NEW findings. Returns only the ones that were new."""
        live = self.vault.live_values()
        new = []
        for path in iter_files(paths):
            for finding in self._scan_file(path, live):
                if self._store(finding):
                    new.append(finding)
        return new

    def _scan_file(self, path: str, live: list):
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                return
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError:
            return
        if b"\x00" in raw[:1024]:  # binary
            return
        for lineno, line in enumerate(raw.decode("utf-8", errors="ignore").splitlines(), 1):
            source = f"{path}:{lineno}"

            exact = [s for s in live if s["value"] in line]
            for s in exact:
                yield {
                    "source": source, "kind": "vault_value_exposed", "secret_name": s["name"],
                    "severity": "critical",
                    "detail": f"live value of '{s['name']}' v{s['version']} found: {redact(s['value'])}",
                    "fingerprint": _fp("exact", path, str(lineno), s["name"], s["value"]),
                }
            if exact:
                continue  # already covered by the strongest signal

            matched = False
            for kind, severity, rx in PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                token = m.group(1) if m.groups() else m.group(0)
                if kind == "credential_assignment" and token.lower() in PLACEHOLDERS:
                    continue
                matched = True
                yield {
                    "source": source, "kind": kind, "secret_name": None, "severity": severity,
                    "detail": f"{kind}: {redact(token)}",
                    "fingerprint": _fp(kind, path, str(lineno), token),
                }
            if matched:
                continue
            for m in ENTROPY_RE.finditer(line):
                token = m.group(0)
                if shannon_entropy(token) >= ENTROPY_THRESHOLD:
                    yield {
                        "source": source, "kind": "high_entropy_string", "secret_name": None,
                        "severity": "medium", "detail": f"high-entropy string: {redact(token)}",
                        "fingerprint": _fp("entropy", path, str(lineno), token),
                    }

    def _store(self, f: dict) -> bool:
        with self.vault.tx() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO findings(ts, source, kind, secret_name, severity, detail, fingerprint) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), f["source"], f["kind"], f["secret_name"], f["severity"],
                 f["detail"], f["fingerprint"]),
            )
            return cur.rowcount == 1
