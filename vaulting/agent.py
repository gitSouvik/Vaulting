"""Guard agent: observe findings -> plan -> act -> verify -> record a trace.

The planner is deliberately a small, auditable policy (RulePlanner). The
interface is one method, so an LLM-backed planner can be dropped in later.
The hard safety rule stays in code either way: the agent only auto-rotates
secrets it manages, on exact-match evidence.
"""
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple

from .rotation import RotationManager
from .vault import Vault

SEVERITY_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


@dataclass
class Action:
    kind: str                      # rotate_now | flag_human
    secret: Optional[str] = None
    reason: str = ""
    revoke_old_now: bool = False


class RulePlanner:
    def plan(self, finding: dict) -> Tuple[str, Action]:
        kind, secret = finding["kind"], finding["secret_name"]

        if kind == "vault_value_exposed" and secret:
            return (
                f"A live value of managed secret '{secret}' appears verbatim at {finding['source']}. "
                "An exact match has no false-positive risk. Rotate, verify dependents are healthy, "
                "then kill the old version immediately because it is compromised.",
                Action("rotate_now", secret, f"leak at {finding['source']}", revoke_old_now=True),
            )
        if kind == "repeated_denied":
            return (
                "Repeated denied requests could be an attack or a misconfigured app. "
                "That is not enough evidence to rotate anything, so a human should look.",
                Action("flag_human", None, finding["detail"]),
            )
        return (
            f"'{kind}' at {finding['source']} does not map to a secret I manage, and the "
            "detection is heuristic. I can't rotate what I don't own, and guessing risks an outage.",
            Action("flag_human", None, finding["detail"]),
        )


class GuardAgent:
    def __init__(self, vault: Vault, manager: RotationManager, planner=None,
                 denied_window: int = 60, denied_threshold: int = 3):
        self.vault = vault
        self.manager = manager
        self.planner = planner or RulePlanner()
        self.denied_window = denied_window
        self.denied_threshold = denied_threshold

    def detect_access_anomalies(self) -> int:
        now = time.time()
        with self.vault.tx() as c:
            rows = c.execute(
                "SELECT app_id, COUNT(*) AS n FROM access_log "
                "WHERE ts >= ? AND outcome = 'denied' AND app_id IS NOT NULL "
                "GROUP BY app_id HAVING n >= ?",
                (now - self.denied_window, self.denied_threshold),
            ).fetchall()
            added = 0
            bucket = int(now // self.denied_window)
            for r in rows:
                cur = c.execute(
                    "INSERT OR IGNORE INTO findings(ts, source, kind, severity, detail, fingerprint) "
                    "VALUES (?, ?, 'repeated_denied', 'medium', ?, ?)",
                    (now, f"access_log:{r['app_id']}",
                     f"{r['n']} denied requests from '{r['app_id']}' in {self.denied_window}s",
                     f"denied|{r['app_id']}|{bucket}"),
                )
                added += cur.rowcount
        return added

    def _pending(self) -> list:
        with self.vault.tx() as c:
            rows = c.execute(
                f"SELECT * FROM findings WHERE handled = 0 ORDER BY {SEVERITY_ORDER}, id"
            ).fetchall()
        return [dict(r) for r in rows]

    def _finish(self, run_id, finding_id, step, thought, action, result, outcome) -> None:
        with self.vault.tx() as c:
            c.execute(
                "INSERT INTO agent_trace(ts, run_id, finding_id, step, thought, action, result) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), run_id, finding_id, step, thought, action, result),
            )
            c.execute("UPDATE findings SET handled=1, outcome=? WHERE id=?", (outcome, finding_id))

    def run_once(self) -> list:
        run_id = uuid.uuid4().hex[:8]
        self.detect_access_anomalies()
        outcomes = []
        for step, f in enumerate(self._pending(), 1):
            thought, action = self.planner.plan(f)
            if action.kind == "rotate_now":
                res = self.manager.rotate_safely(
                    action.secret, reason=action.reason, revoke_old_now=action.revoke_old_now)
                if res.ok:
                    outcome = "rotated"
                    old = "revoked" if res.revoked_old else "kept in grace"
                    result = f"v{res.old_version} -> v{res.new_version}; {res.detail}; old version {old}"
                else:
                    outcome = "rolled_back"
                    result = f"{res.detail}. SECRET STILL EXPOSED, human needed"
            else:
                outcome = "escalated"
                result = "left for human review"
            label = f"{action.kind}:{action.secret or '-'}"
            self._finish(run_id, f["id"], step, thought, label, result, outcome)
            outcomes.append({"finding_id": f["id"], "kind": f["kind"], "severity": f["severity"],
                             "action": label, "outcome": outcome, "result": result,
                             "thought": thought})
        return outcomes
