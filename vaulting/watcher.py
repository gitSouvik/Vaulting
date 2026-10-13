"""Watcher: the always-on loop (idea from the repo's automatic rotation + monitoring).

Each tick: scheduled rotations -> expire old grace versions -> scan for leaks -> let the agent act.
"""
import threading
from typing import Iterable, Optional


class Watcher:
    def __init__(self, vault, manager, sentinel, agent, scan_paths: Iterable[str] = (),
                 grace_seconds: float = 300.0):
        self.vault, self.manager, self.sentinel, self.agent = vault, manager, sentinel, agent
        self.scan_paths = list(scan_paths)
        self.grace_seconds = grace_seconds

    def tick(self, now: Optional[float] = None) -> dict:
        rotated = []
        for name in self.vault.due_for_rotation(now):
            r = self.manager.rotate_safely(name, reason="scheduled rotation")
            rotated.append({"secret": name, "ok": r.ok, "detail": r.detail})
        expired = self.vault.expire_grace(self.grace_seconds, now)
        new_findings = len(self.sentinel.scan(self.scan_paths)) if self.scan_paths else 0
        actions = self.agent.run_once()
        return {"rotated": rotated, "grace_expired": expired,
                "new_findings": new_findings, "agent_actions": len(actions)}

    def run(self, interval: float, stop: threading.Event, on_tick=None) -> None:
        while not stop.is_set():
            try:
                result = self.tick()
            except Exception as e:  # a bad tick must never kill the loop
                result = {"error": type(e).__name__}
            if on_tick:
                on_tick(result)
            stop.wait(interval)
