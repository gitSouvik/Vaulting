import time
import unittest

from tests.helpers import fresh_vault
from vaulting.agent import GuardAgent
from vaulting.rotation import Dependent, RotationManager
from vaulting.sentinel import Sentinel
from vaulting.watcher import Watcher


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        self.v.put_secret("db", "value-1234567890")
        self.m = RotationManager(self.v)
        self.m.register("db", Dependent("svc", lambda: None, lambda: True))
        self.w = Watcher(self.v, self.m, Sentinel(self.v), GuardAgent(self.v, self.m), grace_seconds=60)

    def test_scheduled_rotation_then_grace_expiry(self):
        self.v.set_rotation_policy("db", 3600)
        out = self.w.tick(now=time.time())
        self.assertEqual(out["rotated"], [])                      # not due yet
        out = self.w.tick(now=time.time() + 3601)
        self.assertEqual([r["ok"] for r in out["rotated"]], [True])
        self.assertEqual(self.v.get_active("db")["version"], 2)
        out = self.w.tick(now=time.time() + 3601 + 61)
        self.assertEqual(out["grace_expired"], 1)

    def test_bad_dependent_rolls_back_scheduled_rotation(self):
        bad = RotationManager(self.v)
        bad.register("db", Dependent("svc", lambda: None, lambda: False))
        w = Watcher(self.v, bad, Sentinel(self.v), GuardAgent(self.v, bad))
        self.v.set_rotation_policy("db", 1)
        out = w.tick(now=time.time() + 5)
        self.assertFalse(out["rotated"][0]["ok"])
        self.assertEqual(self.v.get_active("db")["version"], 1)   # rolled back

    def test_tick_scans_and_acts(self):
        import os, tempfile
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "x.log"), "w") as fh:
            fh.write("pw value-1234567890\n")
        w = Watcher(self.v, self.m, Sentinel(self.v), GuardAgent(self.v, self.m), [d])
        out = w.tick()
        self.assertEqual((out["new_findings"], out["agent_actions"]), (1, 1))
        self.assertFalse(self.v.validate("db", "value-1234567890"))


if __name__ == "__main__":
    unittest.main()
