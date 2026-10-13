import os
import time
import unittest

from tests.helpers import fresh_vault
from vaulting.vault import VaultError


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()

    def test_expired_token_rejected(self):
        t = self.v.register_app("svc", ttl_seconds=0.05)
        self.assertEqual(self.v.authenticate(t), "svc")
        time.sleep(0.1)
        self.assertIsNone(self.v.authenticate(t))

    def test_revoked_app_rejected_immediately(self):
        t = self.v.register_app("svc")
        self.v.revoke_app("svc")
        self.assertIsNone(self.v.authenticate(t))

    def test_revoke_unknown_app_errors(self):
        with self.assertRaises(VaultError):
            self.v.revoke_app("ghost")

    def test_secret_name_validation(self):
        for bad in ["has space", "a:b", "../etc/passwd", "", "x" * 200, "semi;colon"]:
            with self.assertRaises(VaultError, msg=bad):
                self.v.put_secret(bad)

    def test_db_file_is_owner_only(self):
        if os.name == "posix":
            self.assertEqual(os.stat(self.v.db_path).st_mode & 0o077, 0)


class AuditChainTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        for i in range(5):
            self.v.log_access("app", "db", 1, "ok")

    def test_intact_chain_verifies(self):
        r = self.v.verify_audit_chain()
        self.assertTrue(r["ok"])
        self.assertEqual(r["entries"], 5)

    def test_empty_chain_is_ok(self):
        self.assertTrue(fresh_vault().verify_audit_chain()["ok"])

    def test_edited_row_detected(self):
        with self.v.tx() as c:
            c.execute("UPDATE access_log SET outcome='ok', app_id='someone-else' WHERE id=3")
        r = self.v.verify_audit_chain()
        self.assertFalse(r["ok"])
        self.assertEqual(r["bad_id"], 3)

    def test_covering_tracks_by_editing_outcome_detected(self):
        self.v.log_access("evil", "db", None, "denied")
        with self.v.tx() as c:
            c.execute("UPDATE access_log SET outcome='ok' WHERE outcome='denied'")
        self.assertFalse(self.v.verify_audit_chain()["ok"])

    def test_deleted_middle_row_detected(self):
        with self.v.tx() as c:
            c.execute("DELETE FROM access_log WHERE id=2")
        r = self.v.verify_audit_chain()
        self.assertFalse(r["ok"])
        self.assertEqual(r["bad_id"], 3)

    def test_head_changes_with_every_entry(self):
        before = self.v.verify_audit_chain()["head"]
        self.v.log_access("app", "db", 1, "ok")
        self.assertNotEqual(before, self.v.verify_audit_chain()["head"])


class RotationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        self.v.put_secret("db", "value-1234567890")

    def test_due_only_after_interval(self):
        self.v.set_rotation_policy("db", 3600)
        self.assertEqual(self.v.due_for_rotation(), [])
        self.assertEqual(self.v.due_for_rotation(now=time.time() + 3601), ["db"])

    def test_no_policy_means_never_due(self):
        self.assertEqual(self.v.due_for_rotation(now=time.time() + 10**9), [])

    def test_grace_expires_after_window(self):
        self.v.rotate("db")
        self.assertEqual(self.v.expire_grace(300), 0)
        self.assertEqual(self.v.expire_grace(300, now=time.time() + 301), 1)
        self.assertEqual([x["status"] for x in self.v.versions("db")], ["revoked", "active"])


if __name__ == "__main__":
    unittest.main()
