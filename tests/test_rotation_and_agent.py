import os
import tempfile
import unittest

from tests.helpers import fresh_vault
from vaulting.agent import GuardAgent
from vaulting.rotation import Dependent, RotationManager
from vaulting.sentinel import Sentinel


def ok_dep(name="svc"):
    return Dependent(name, refresh=lambda: None, healthy=lambda: True)


def sick_dep(name="svc"):
    return Dependent(name, refresh=lambda: None, healthy=lambda: False)


def crashing_dep(name="svc"):
    def boom():
        raise RuntimeError("down")
    return Dependent(name, refresh=boom, healthy=lambda: True)


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        self.v.put_secret("db", "orig-value-123456")
        self.m = RotationManager(self.v)

    def test_healthy_rotation_keeps_new_version(self):
        self.m.register("db", ok_dep())
        r = self.m.rotate_safely("db", "test")
        self.assertTrue(r.ok)
        self.assertEqual(self.v.get_active("db")["version"], 2)

    def test_unhealthy_dependent_triggers_rollback(self):
        self.m.register("db", ok_dep("a"))
        self.m.register("db", sick_dep("b"))
        r = self.m.rotate_safely("db", "test")
        self.assertFalse(r.ok)
        self.assertTrue(r.rolled_back)
        self.assertEqual(self.v.get_active("db")["value"], "orig-value-123456")

    def test_crashing_dependent_counts_as_unhealthy(self):
        self.m.register("db", crashing_dep())
        self.assertTrue(self.m.rotate_safely("db", "test").rolled_back)

    def test_revoke_old_now(self):
        self.m.register("db", ok_dep())
        r = self.m.rotate_safely("db", "leak", revoke_old_now=True)
        self.assertTrue(r.revoked_old)
        self.assertFalse(self.v.validate("db", "orig-value-123456"))


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        self.v.put_secret("db", "Leaky-Value-9a8b7c6d5e")
        self.m = RotationManager(self.v)
        self.dir = tempfile.mkdtemp(prefix="vl-agent-")

    def _log(self, text):
        with open(os.path.join(self.dir, "x.log"), "w") as fh:
            fh.write(text)

    def test_agent_rotates_on_exact_leak(self):
        self.m.register("db", ok_dep())
        self._log("pw Leaky-Value-9a8b7c6d5e\n")
        Sentinel(self.v).scan([self.dir])
        out = GuardAgent(self.v, self.m).run_once()
        self.assertEqual(out[0]["outcome"], "rotated")
        self.assertFalse(self.v.validate("db", "Leaky-Value-9a8b7c6d5e"))

    def test_agent_escalates_instead_of_guessing(self):
        self._log("AWS=AKIAIOSFODNN7EXAMPLE\n")
        Sentinel(self.v).scan([self.dir])
        out = GuardAgent(self.v, self.m).run_once()
        self.assertEqual(out[0]["outcome"], "escalated")
        self.assertEqual(self.v.get_active("db")["version"], 1)  # untouched

    def test_failed_rotation_is_reported_as_still_exposed(self):
        self.m.register("db", sick_dep())
        self._log("pw Leaky-Value-9a8b7c6d5e\n")
        Sentinel(self.v).scan([self.dir])
        out = GuardAgent(self.v, self.m).run_once()
        self.assertEqual(out[0]["outcome"], "rolled_back")
        self.assertIn("STILL EXPOSED", out[0]["result"])

    def test_findings_handled_once_and_trace_written(self):
        self._log("pw Leaky-Value-9a8b7c6d5e\n")
        Sentinel(self.v).scan([self.dir])
        agent = GuardAgent(self.v, self.m)
        self.assertEqual(len(agent.run_once()), 1)
        self.assertEqual(agent.run_once(), [])
        with self.v.tx() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM agent_trace").fetchone()[0], 1)

    def test_critical_handled_before_lower_severity(self):
        self._log("AWS=AKIAIOSFODNN7EXAMPLE\npw Leaky-Value-9a8b7c6d5e\n")
        Sentinel(self.v).scan([self.dir])
        out = GuardAgent(self.v, self.m).run_once()
        self.assertEqual(out[0]["severity"], "critical")

    def test_repeated_denied_requests_flagged_not_rotated(self):
        for _ in range(3):
            self.v.log_access("evil-app", "db", None, "denied")
        out = GuardAgent(self.v, self.m).run_once()
        self.assertEqual([o["kind"] for o in out], ["repeated_denied"])
        self.assertEqual(out[0]["outcome"], "escalated")


if __name__ == "__main__":
    unittest.main()
