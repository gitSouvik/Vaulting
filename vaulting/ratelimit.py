"""Token-bucket rate limiter (in-memory, per key). Slows brute force and runaway clients."""
import threading
import time


class RateLimiter:
    def __init__(self, rate: float, burst: int, max_keys: int = 10_000):
        self.rate, self.burst, self.max_keys = rate, burst, max_keys
        self._buckets = {}   # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= self.max_keys:
                self._buckets.clear()  # crude memory bound against key-flooding
            tokens, last = self._buckets.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                return True
            self._buckets[key] = (tokens, now)
            return False
