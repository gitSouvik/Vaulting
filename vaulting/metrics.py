"""
vaulting/metrics.py — Prometheus-compatible observability layer

Exposes key operational metrics as a Prometheus text endpoint:

  vaulting_secrets_total          gauge   total distinct secrets in vault
  vaulting_rotations_total        counter rotations performed (by outcome)
  vaulting_rotation_duration_sec  histogram rotation wall-clock time
  vaulting_sentinel_scans_total   counter sentinel scan invocations
  vaulting_sentinel_hits_total    counter secrets found leaking in logs
  vaulting_vault_sealed           gauge   1 if vault is sealed, 0 if unsealed
  vaulting_native_available       gauge   1 if C library loaded, 0 if Python fallback

Usage (standalone HTTP server)::

    from vaulting.metrics import MetricsServer
    srv = MetricsServer(port=9101)
    srv.start()          # non-blocking daemon thread

Usage (WSGI / HTTP handler integration)::

    from vaulting.metrics import generate_metrics_page
    # GET /metrics → generate_metrics_page() returns bytes (Prometheus text format)

Usage (instrumenting vault operations)::

    from vaulting.metrics import REGISTRY
    REGISTRY.rotations_total.inc(labels={"outcome": "success"})
    REGISTRY.rotation_duration.observe(elapsed)
"""

from __future__ import annotations

import io
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional


# ---------------------------------------------------------------------------
# Metric primitives
# ---------------------------------------------------------------------------

class _Gauge:
    """A single floating-point value that can go up or down."""

    def __init__(self, name: str, help_text: str, labels: tuple[str, ...] = ()):
        self.name      = name
        self.help_text = help_text
        self._label_names = labels
        self._values: dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def set(self, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = value

    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] += amount

    def dec(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        self.inc(-amount, labels)

    def _key(self, labels: dict[str, str] | None) -> tuple:
        if not labels:
            return ()
        return tuple(labels.get(n, "") for n in self._label_names)

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} gauge",
        ]
        with self._lock:
            for key, val in self._values.items():
                suffix = _format_labels(self._label_names, key)
                lines.append(f"{self.name}{suffix} {val}")
        return "\n".join(lines) + "\n"


class _Counter(_Gauge):
    """Monotonically increasing counter (never decreases)."""

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        with self._lock:
            for key, val in self._values.items():
                suffix = _format_labels(self._label_names, key)
                lines.append(f"{self.name}_total{suffix} {val}")
        return "\n".join(lines) + "\n"

    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        if amount < 0:
            raise ValueError("Counter cannot decrease")
        super().inc(amount, labels)


class _Histogram:
    """Distribution of observed values, exported as buckets + sum + count."""

    DEFAULT_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0)

    def __init__(
        self,
        name: str,
        help_text: str,
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ):
        self.name      = name
        self.help_text = help_text
        self._buckets  = sorted(buckets)
        self._counts   = [0] * len(self._buckets)
        self._inf      = 0
        self._sum      = 0.0
        self._total    = 0
        self._lock     = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum   += value
            self._total += 1
            for i, bound in enumerate(self._buckets):
                if value <= bound:
                    self._counts[i] += 1
            self._inf += 1

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        with self._lock:
            cumulative = 0
            for i, bound in enumerate(self._buckets):
                cumulative += self._counts[i]
                lines.append(f'{self.name}_bucket{{le="{bound}"}} {cumulative}')
            lines.append(f'{self.name}_bucket{{le="+Inf"}} {self._inf}')
            lines.append(f"{self.name}_sum {self._sum}")
            lines.append(f"{self.name}_count {self._total}")
        return "\n".join(lines) + "\n"


def _format_labels(names: tuple[str, ...], values: tuple) -> str:
    if not names or not values:
        return ""
    pairs = ",".join(f'{n}="{v}"' for n, v in zip(names, values))
    return "{" + pairs + "}"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class _Registry:
    """Central collection of all metrics."""

    def __init__(self) -> None:
        self._metrics: list = []

        self.secrets_total = self._g(
            "vaulting_secrets_total",
            "Total distinct secrets currently stored in the vault",
        )
        self.rotations_total = self._c(
            "vaulting_rotations",
            "Total key rotations performed",
            labels=("outcome",),  # outcome: success | failure | rollback
        )
        self.rotation_duration = self._h(
            "vaulting_rotation_duration_seconds",
            "Wall-clock time for a complete key rotation cycle",
        )
        self.sentinel_scans_total = self._c(
            "vaulting_sentinel_scans",
            "Number of log/output chunks scanned by the sentinel",
        )
        self.sentinel_hits_total = self._c(
            "vaulting_sentinel_hits",
            "Number of secret-value matches found by the sentinel",
        )
        self.vault_sealed = self._g(
            "vaulting_vault_sealed",
            "1 if the vault is in sealed state, 0 if unsealed",
        )
        self.native_available = self._g(
            "vaulting_native_available",
            "1 if the C native library is loaded, 0 if using Python fallback",
        )
        self.http_requests_total = self._c(
            "vaulting_http_requests",
            "Total HTTP API requests",
            labels=("method", "path", "status"),
        )
        self.http_request_duration = self._h(
            "vaulting_http_request_duration_seconds",
            "HTTP request handling latency",
        )

        # Auto-populate static gauges
        from vaulting.native import native_available
        self.native_available.set(1.0 if native_available() else 0.0)
        self.vault_sealed.set(1.0)  # assume sealed on startup

    def _g(self, name, help_text, labels=()):
        m = _Gauge(name, help_text, labels)
        self._metrics.append(m)
        return m

    def _c(self, name, help_text, labels=()):
        m = _Counter(name, help_text, labels)
        self._metrics.append(m)
        return m

    def _h(self, name, help_text):
        m = _Histogram(name, help_text)
        self._metrics.append(m)
        return m

    def render(self) -> bytes:
        """Render all metrics in Prometheus text exposition format (v0.0.4)."""
        buf = io.StringIO()
        for m in self._metrics:
            buf.write(m.render())
            buf.write("\n")
        return buf.getvalue().encode("utf-8")


# Global singleton
REGISTRY = _Registry()


# ---------------------------------------------------------------------------
# Context manager for timing
# ---------------------------------------------------------------------------

class _Timer:
    """Usage: with timer(REGISTRY.rotation_duration): ..."""

    def __init__(self, histogram: _Histogram):
        self._h = histogram
        self._t0: float = 0.0

    def __enter__(self) -> "_Timer":
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *_) -> None:
        self._h.observe(time.perf_counter() - self._t0)


def timer(histogram: _Histogram) -> _Timer:
    return _Timer(histogram)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class _MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = REGISTRY.render()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_) -> None:
        pass  # Silence request logging


class MetricsServer:
    """
    Minimal Prometheus-scrape HTTP server.

    Parameters
    ----------
    port : int
        TCP port to listen on (default 9101).
    host : str
        Bind address (default "0.0.0.0").
    """

    def __init__(self, port: int = 9101, host: str = "0.0.0.0") -> None:
        self.port = port
        self.host = host
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the metrics HTTP server in a background daemon thread."""
        self._server = HTTPServer((self.host, self.port), _MetricsHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="vaulting-metrics",
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/metrics"


def generate_metrics_page() -> bytes:
    """Return the current metrics page as bytes (for WSGI integration)."""
    return REGISTRY.render()


# ---------------------------------------------------------------------------
# Integration hooks — call these from vault/sentinel/saga
# ---------------------------------------------------------------------------

def record_rotation(outcome: str, duration_sec: float) -> None:
    """outcome: 'success' | 'failure' | 'rollback'"""
    REGISTRY.rotations_total.inc(labels={"outcome": outcome})
    REGISTRY.rotation_duration.observe(duration_sec)


def record_sentinel_scan(hits: int = 0) -> None:
    REGISTRY.sentinel_scans_total.inc()
    if hits:
        REGISTRY.sentinel_hits_total.inc(hits)


def record_http_request(method: str, path: str, status: int, duration: float) -> None:
    REGISTRY.http_requests_total.inc(labels={
        "method": method, "path": path, "status": str(status)
    })
    REGISTRY.http_request_duration.observe(duration)


def set_vault_sealed(sealed: bool) -> None:
    REGISTRY.vault_sealed.set(1.0 if sealed else 0.0)


def update_secrets_count(count: int) -> None:
    REGISTRY.secrets_total.set(float(count))


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import time

    srv = MetricsServer(port=9101)
    srv.start()
    print(f"Metrics server: {srv.url}")

    # Simulate some activity
    record_rotation("success", 0.042)
    record_rotation("failure", 0.001)
    record_sentinel_scan(hits=3)
    record_http_request("GET", "/v1/secrets/foo", 200, 0.012)
    update_secrets_count(42)

    page = generate_metrics_page().decode()
    print("\n--- Metrics page (excerpt) ---")
    for line in page.splitlines():
        if not line.startswith("#"):
            print(f"  {line}")

    print("\n✓ Metrics module OK")
