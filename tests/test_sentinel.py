import os
import tempfile
import unittest

from tests.helpers import fresh_vault
from vaulting.sentinel import Sentinel, shannon_entropy


class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        self.v.put_secret("db", "S3cretValue-ABC123xyz")
        self.dir = tempfile.mkdtemp(prefix="vl-scan-")
        self.s = Sentinel(self.v)

    def _write(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def test_exact_match_is_critical_and_mapped(self):
        self._write("a.log", "connect pw=S3cretValue-ABC123xyz now\n")
        f = self.s.scan([self.dir])
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["kind"], f[0]["severity"], f[0]["secret_name"]),
                         ("vault_value_exposed", "critical", "db"))

    def test_raw_value_never_stored_in_findings(self):
        self._write("a.log", "x S3cretValue-ABC123xyz\n")
        self.s.scan([self.dir])
        with self.v.tx() as c:
            blob = " ".join(str(tuple(r)) for r in c.execute("SELECT * FROM findings"))
        self.assertNotIn("S3cretValue-ABC123xyz", blob)

    def test_rescan_does_not_duplicate(self):
        self._write("a.log", "x S3cretValue-ABC123xyz\n")
        self.assertEqual(len(self.s.scan([self.dir])), 1)
        self.assertEqual(len(self.s.scan([self.dir])), 0)

    def test_revoked_value_is_not_reported(self):
        self.v.rotate("db")
        self.v.revoke_grace("db")
        self._write("a.log", "old S3cretValue-ABC123xyz\n")
        self.assertEqual(self.s.scan([self.dir]), [])

    def test_aws_key_pattern_is_unmapped(self):
        self._write("env.txt", "AWS=AKIAIOSFODNN7EXAMPLE\n")
        f = self.s.scan([self.dir])
        self.assertEqual(f[0]["kind"], "aws_access_key_id")
        self.assertIsNone(f[0]["secret_name"])

    def test_placeholder_passwords_ignored(self):
        self._write("c.env", "password=changeme\n")
        self.assertEqual(self.s.scan([self.dir]), [])

    def test_binary_files_skipped(self):
        p = os.path.join(self.dir, "b.bin")
        with open(p, "wb") as fh:
            fh.write(b"\x00\x01S3cretValue-ABC123xyz")
        self.assertEqual(self.s.scan([self.dir]), [])

    def test_entropy_ordering(self):
        self.assertLess(shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa"), 1)
        self.assertGreater(shannon_entropy("Zq8vK2mXp9LdR4tYw7NcB1hJ"), 4.2)


if __name__ == "__main__":
    unittest.main()
