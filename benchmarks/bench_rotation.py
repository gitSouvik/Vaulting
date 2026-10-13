#!/usr/bin/env python3
"""
benchmarks/bench_rotation.py — Key rotation throughput benchmark

Measures end-to-end rotation latency (put_secret → rotate) at various
secret-store sizes to expose O(n) cost creep or DB locking issues.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulting.crypto import Keyring
from vaulting.vault import Vault


# ── helpers ────────────────────────────────────────────────────────────────

def _fresh_vault(n_pre_existing: int = 0) -> tuple[Vault, str]:
    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tf.close()
    kr = Keyring({"k1": os.urandom(32)}, "k1")
    v  = Vault(tf.name, kr)
    for i in range(n_pre_existing):
        v.put_secret(f"preload_{i}", f"value_{i}")
    return v, tf.name


def _timeit(fn, *, iterations: int = 20) -> float:
    """Return best-of-N elapsed seconds."""
    best = float("inf")
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        best = min(best, t1 - t0)
    return best


# ── scenarios ──────────────────────────────────────────────────────────────

def bench_single_rotation(vault: Vault, name: str) -> float:
    """Measure one complete put_secret → rotate round-trip (best of N)."""
    # Prime: ensure the secret exists
    vault.put_secret(name, "initial-value")

    def _run():
        vault.rotate(name, new_value=f"rotated-{time.time()}")

    return _timeit(_run, iterations=30)


def bench_bulk_rotation(vault: Vault, names: list[str]) -> float:
    """Measure time to rotate all listed secrets once (best of N runs)."""
    for name in names:
        vault.put_secret(name, f"init-{name}")

    def _run():
        for name in names:
            vault.rotate(name, new_value=f"bulk-rotated-{time.time()}")

    return _timeit(_run, iterations=5)


def bench_put(vault: Vault, n: int = 50) -> float:
    """Measure time to insert n new unique secrets (best of 3 runs)."""
    counter = [0]

    def _run():
        for _ in range(n):
            counter[0] += 1
            vault.put_secret(f"bench_new_{counter[0]}", "value")

    return _timeit(_run, iterations=3)


# ── main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Vaulting Rotation Benchmark")
    print("=" * 60)
    print()

    for pre in [0, 100, 500]:
        vault, db = _fresh_vault(pre)
        try:
            t_single = bench_single_rotation(vault, f"target_{pre}")
            bulk_names = [f"bulk_{pre}_{i}" for i in range(20)]
            t_bulk = bench_bulk_rotation(vault, bulk_names)
            t_put  = bench_put(vault, n=20)

            print(f"Pre-existing secrets: {pre:>5}")
            print(f"  put_secret  (20 new) : {t_put*1000:>8.2f} ms  "
                  f"({t_put/20*1000:.2f} ms each)")
            print(f"  single rotation      : {t_single*1000:>8.2f} ms")
            print(f"  bulk-20 rotation     : {t_bulk*1000:>8.2f} ms  "
                  f"({t_bulk/20*1000:.2f} ms each)")
            print()
        finally:
            os.unlink(db)

    print("Benchmark complete.")
