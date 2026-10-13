#!/usr/bin/env python3
"""
benchmarks/bench_scanner.py — Scanner throughput benchmark

Compares:
  A) Naive Python sentinel scan (linear scan of each secret in the log)
  B) Aho-Corasick C scanner (single O(n) pass regardless of secret count)

Outputs a table with throughput (MB/s) and latency (µs/line) for each approach.
"""

from __future__ import annotations

import os
import random
import string
import sys
import time
from pathlib import Path
from typing import Callable

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulting.native import AhoCorasickScanner, native_info


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def _random_secret(length: int = 32) -> bytes:
    chars = string.ascii_letters + string.digits
    return ("sk-" + "".join(random.choices(chars, k=length))).encode()


def _random_log_line(secrets: list[bytes], embed_prob: float = 0.01) -> bytes:
    """Produce a realistic log line, occasionally embedding a secret."""
    template = (
        f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] '
        f'INFO  user=user{random.randint(1, 9999)} '
        f'path=/api/v1/resource/{random.randint(1, 999)} '
        f'latency={random.randint(1, 500)}ms '
        f'status={random.choice([200, 200, 200, 401, 403, 500])}'
    ).encode()
    if random.random() < embed_prob and secrets:
        leak = random.choice(secrets)
        template += b" data=" + leak
    return template + b"\n"


def build_corpus(
    num_secrets: int, num_lines: int, embed_prob: float = 0.02
) -> tuple[list[bytes], bytes]:
    secrets = [_random_secret() for _ in range(num_secrets)]
    lines = [_random_log_line(secrets, embed_prob) for _ in range(num_lines)]
    corpus = b"".join(lines)
    return secrets, corpus


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------

def naive_scan(corpus: bytes, secrets: list[bytes]) -> int:
    """Python: check each secret independently with bytes.find."""
    count = 0
    for secret in secrets:
        start = 0
        while True:
            idx = corpus.find(secret, start)
            if idx == -1:
                break
            count += 1
            start = idx + 1
    return count


def aho_corasick_scan(corpus: bytes, secrets: list[bytes]) -> int:
    """C: build DFA once, scan in a single pass."""
    scanner = AhoCorasickScanner()
    for pid, s in enumerate(secrets):
        scanner.add_pattern(s, pid)
    scanner.build()
    return len(scanner.search(corpus))


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def bench(
    name: str,
    fn: Callable[[bytes, list[bytes]], int],
    corpus: bytes,
    secrets: list[bytes],
    iterations: int = 5,
) -> dict:
    # Warm up
    fn(corpus, secrets)

    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        hits = fn(corpus, secrets)
        t1 = time.perf_counter()
        times.append(t1 - t0)

    elapsed = min(times)  # best-of-N
    mb       = len(corpus) / 1_000_000
    mbs      = mb / elapsed
    return {
        "name":      name,
        "corpus_mb": round(mb, 2),
        "elapsed_ms": round(elapsed * 1000, 1),
        "throughput_MBs": round(mbs, 1),
        "hits": hits,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Vaulting Scanner Benchmark")
    print("=" * 60)
    info = native_info()
    print(f"Native library: {'✓ loaded' if info['available'] else '✗ NOT LOADED (Python fallback)'}")
    if info["path"]:
        print(f"  Path: {info['path']}")
    print()

    configs = [
        ("small",  50,   10_000),
        ("medium", 200,  50_000),
        ("large",  1000, 100_000),
    ]

    for label, num_secrets, num_lines in configs:
        random.seed(42)
        secrets, corpus = build_corpus(num_secrets, num_lines)

        print(f"── {label}: {num_secrets} secrets × {num_lines:,} log lines ──")
        print(f"   Corpus size: {len(corpus)/1_000_000:.2f} MB")

        r_naive = bench("Naive Python",     naive_scan,         corpus, secrets)
        r_ac    = bench("Aho-Corasick (C)", aho_corasick_scan,  corpus, secrets)

        speedup = r_naive["elapsed_ms"] / r_ac["elapsed_ms"]

        print(f"   {'Method':<22} {'Time (ms)':>10} {'Throughput MB/s':>16} {'Hits':>6}")
        print(f"   {'-'*58}")
        for r in [r_naive, r_ac]:
            print(
                f"   {r['name']:<22} {r['elapsed_ms']:>10.1f} "
                f"{r['throughput_MBs']:>16.1f} {r['hits']:>6}"
            )
        print(f"   Speedup: {speedup:.1f}x faster with Aho-Corasick")
        print()

    print("Benchmark complete.")
