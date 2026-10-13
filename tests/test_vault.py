import sqlite3
import unittest

from tests.helpers import fresh_vault
from vaulting.vault import VaultError


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        self.v.put_secret("db", "pw-one")

    def test_rotate_moves_old_to_grace_and_both_validate(self):
        r = self.v.rotate("db")
        self.assertEqual((r["old_version"], r["version"]), (1, 2))
        self.assertTrue(self.v.validate("db", "pw-one"))      # grace
        self.assertTrue(self.v.validate("db", r["value"]))    # active

    def test_revoke_grace_kills_old_value(self):
        self.v.rotate("db")
        self.v.revoke_grace("db")
        self.assertFalse(self.v.validate("db", "pw-one"))

    def test_rollback_restores_previous_version(self):
        r = self.v.rotate("db")
        self.v.rollback("db")
        self.assertEqual(self.v.get_active("db")["value"], "pw-one")
        self.assertFalse(self.v.validate("db", r["value"]))

    def test_rollback_without_grace_fails(self):
        with self.assertRaises(VaultError):
            self.v.rollback("db")

    def test_second_rotation_revokes_older_grace(self):
        self.v.rotate("db")
        self.v.rotate("db")
        status = {x["version"]: x["status"] for x in self.v.versions("db")}
        self.assertEqual(status, {1: "revoked", 2: "grace", 3: "active"})

    def test_database_enforces_single_active_version(self):
        with self.v.tx() as c, self.assertRaises(sqlite3.IntegrityError):
            c.execute("INSERT INTO secret_versions(name, version, ciphertext, nonce, wrapped_dek, "
                      "dek_nonce, kek_id, status, created_at) "
                      "VALUES ('db', 99, x'00', x'00', x'00', x'00', 'k1', 'active', 0)")

    def test_duplicate_secret_rejected(self):
        with self.assertRaises(VaultError):
            self.v.put_secret("db")

    def test_token_is_stored_hashed_and_auth_works(self):
        token = self.v.register_app("svc")
        self.assertEqual(self.v.authenticate(token), "svc")
        self.assertIsNone(self.v.authenticate("vl_wrong"))
        with self.v.tx() as c:
            stored = c.execute("SELECT token_hash FROM apps").fetchone()[0]
        self.assertNotIn(token, stored)

    def test_grants(self):
        self.v.register_app("svc")
        self.assertFalse(self.v.authorize("svc", "db"))
        self.v.grant("svc", "db")
        self.assertTrue(self.v.authorize("svc", "db"))


if __name__ == "__main__":
    unittest.main()
