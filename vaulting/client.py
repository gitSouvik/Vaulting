"""Client SDK with a TTL cache and optional TLS verification against a private CA."""
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import quote


class VaultingError(Exception):
    pass


class VaultingClient:
    def __init__(self, base_url: str, token: str, timeout: float = 3.0, ca_file: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._ctx = ssl.create_default_context(cafile=ca_file) if self.base_url.startswith("https") else None
        self._cache = {}  # name -> (value, version, expires_at)

    def _request(self, method: str, path: str, body: dict = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise VaultingError(f"HTTP {e.code}") from e
        except (urllib.error.URLError, ssl.SSLError, OSError) as e:
            raise VaultingError(f"cannot reach vault: {getattr(e, 'reason', e)}") from e

    def get_with_version(self, name: str, fresh: bool = False):
        hit = self._cache.get(name)
        if hit and not fresh and hit[2] > time.time():
            return hit[0], hit[1]
        data = self._request("GET", "/v1/secrets/" + quote(name, safe=""))
        self._cache[name] = (data["value"], data["version"], time.time() + data["ttl"])
        return data["value"], data["version"]

    def get(self, name: str, fresh: bool = False) -> str:
        return self.get_with_version(name, fresh)[0]

    def validate(self, name: str, value: str) -> bool:
        return self._request("POST", "/v1/validate", {"name": name, "value": value})["valid"]

    def invalidate(self, name: str = None) -> None:
        if name is None:
            self._cache.clear()
        else:
            self._cache.pop(name, None)
