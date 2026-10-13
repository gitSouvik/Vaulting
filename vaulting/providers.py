"""External secret providers: one unified interface for multiple backends.

A secret name like  hcv:database/mysql#password  means:
    provider "hcv", path "database/mysql", field "password".
Plain names (no colon) are served from Vaulting's own encrypted store.
"""
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional, Tuple
from urllib.parse import quote


class ProviderError(Exception):
    pass


class HashiCorpKVProvider:
    """Read-only client for HashiCorp Vault / OpenBao KV v2.

    Auth: a static token, or AppRole (role_id + secret_id) with automatic re-login.
    """

    def __init__(self, addr: str, token: Optional[str] = None, role_id: Optional[str] = None,
                 secret_id: Optional[str] = None, mount: str = "secret",
                 timeout: float = 3.0, ca_file: Optional[str] = None):
        if not token and not (role_id and secret_id):
            raise ProviderError("provide a token, or role_id and secret_id for AppRole")
        self.addr = addr.rstrip("/")
        self.mount = mount.strip("/")
        self.timeout = timeout
        self._static_token = token
        self._role_id, self._secret_id = role_id, secret_id
        self._token: Optional[str] = None
        self._token_expiry = 0.0
        self._ctx = ssl.create_default_context(cafile=ca_file) if self.addr.startswith("https") else None

    def _call(self, method: str, path: str, body: Optional[dict] = None, token: Optional[str] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.addr + path, data=data, method=method)
        if token:
            req.add_header("X-Vault-Token", token)
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise ProviderError(f"provider returned HTTP {e.code}") from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ProviderError("provider unreachable or returned bad data") from e

    def _get_token(self) -> str:
        if self._static_token:
            return self._static_token
        if self._token and time.time() < self._token_expiry:
            return self._token
        auth = self._call("POST", "/v1/auth/approle/login",
                          {"role_id": self._role_id, "secret_id": self._secret_id}).get("auth", {})
        if "client_token" not in auth:
            raise ProviderError("AppRole login failed")
        self._token = auth["client_token"]
        # renew a little early so we never present an expired token
        self._token_expiry = time.time() + max(float(auth.get("lease_duration", 60)) - 5, 1)
        return self._token

    def get(self, path: str, field: Optional[str] = None) -> Tuple[str, Optional[int]]:
        body = self._call("GET", f"/v1/{self.mount}/data/{quote(path, safe='/')}", token=self._get_token())
        try:
            data = body["data"]["data"]
            version = body["data"]["metadata"]["version"]
        except (KeyError, TypeError) as e:
            raise ProviderError("unexpected provider response") from e
        if field:
            if field not in data:
                raise ProviderError("field not found in secret")
            return str(data[field]), version
        if len(data) == 1:
            return str(next(iter(data.values()))), version
        raise ProviderError("secret has several fields; ask for one with #field")
