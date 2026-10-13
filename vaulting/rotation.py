"""Safe rotation: rotate -> tell dependents -> health check -> keep or roll back."""
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .vault import Vault


@dataclass
class Dependent:
    """Something that uses a secret and can prove it still works after rotation."""
    name: str
    refresh: Callable[[], None]   # drop cached secret, pick up the new one
    healthy: Callable[[], bool]


@dataclass
class RotationResult:
    secret: str
    ok: bool
    old_version: Optional[int] = None
    new_version: Optional[int] = None
    rolled_back: bool = False
    revoked_old: bool = False
    detail: str = ""


def http_dependent(name: str, base_url: str, timeout: float = 3.0) -> Dependent:
    """A dependent exposing POST /refresh and GET /health (see demo/toy_app.py)."""
    base_url = base_url.rstrip("/")

    def refresh() -> None:
        req = urllib.request.Request(base_url + "/refresh", method="POST")
        urllib.request.urlopen(req, timeout=timeout).read()

    def healthy() -> bool:
        try:
            with urllib.request.urlopen(base_url + "/health", timeout=timeout) as r:
                return r.status == 200
        except Exception:
            return False

    return Dependent(name, refresh, healthy)


class RotationManager:
    def __init__(self, vault: Vault):
        self.vault = vault
        self._dependents: Dict[str, List[Dependent]] = {}

    def register(self, secret_name: str, dependent: Dependent) -> None:
        self._dependents.setdefault(secret_name, []).append(dependent)

    def rotate_safely(self, name: str, reason: str, revoke_old_now: bool = False) -> RotationResult:
        deps = self._dependents.get(name, [])
        rotated = self.vault.rotate(name, reason=reason)
        res = RotationResult(name, ok=False, old_version=rotated["old_version"],
                             new_version=rotated["version"])

        failed = []
        for d in deps:
            try:
                d.refresh()
                if not d.healthy():
                    failed.append(d.name)
            except Exception as e:  # a crashing dependent counts as unhealthy
                failed.append(f"{d.name} ({type(e).__name__})")

        if failed:
            self.vault.rollback(name, reason=f"rollback: unhealthy after rotation: {failed}")
            for d in deps:  # best effort: point everyone back at the restored version
                try:
                    d.refresh()
                except Exception:
                    pass
            res.rolled_back = True
            res.detail = f"rolled back to v{res.old_version}; unhealthy: {', '.join(failed)}"
            return res

        res.ok = True
        if revoke_old_now:
            res.revoked_old = self.vault.revoke_grace(name, reason=f"revoked after {reason}") > 0
        res.detail = f"{len(deps)} dependent(s) healthy"
        return res
