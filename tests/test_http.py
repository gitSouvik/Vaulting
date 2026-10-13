import unittest

from tests.helpers import fresh_vault
from vaulting.client import VaultingClient, VaultingError
from vaulting.server import make_server, serve_in_thread


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.v = fresh_vault()
        self.v.put_secret("db", "http-secret-value")
        self.v.put_secret("other", "other-value")
        self.token = self.v.register_app("svc")
        self.v.grant("svc", "db")
        self.srv = make_server(self.v, ttl=60)
        serve_in_thread(self.srv)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_fetch_ok_and_logged(self):
        c = VaultingClient(self.base, self.token)
        self.assertEqual(c.get("db"), "http-secret-value")
        self.assertEqual(self.v.recent_access(1)[0]["outcome"], "ok")

    def test_ungranted_secret_denied_and_logged(self):
        with self.assertRaises(VaultingError):
            VaultingClient(self.base, self.token).get("other")
        self.assertEqual(self.v.recent_access(1)[0]["outcome"], "denied")

    def test_bad_token_unauthenticated(self):
        with self.assertRaises(VaultingError):
            VaultingClient(self.base, "vl_nope").get("db")
        self.assertEqual(self.v.recent_access(1)[0]["outcome"], "unauthenticated")

    def test_client_cache_and_fresh(self):
        c = VaultingClient(self.base, self.token)
        c.get("db")
        c.get("db")
        ok = [r for r in self.v.recent_access(10) if r["outcome"] == "ok"]
        self.assertEqual(len(ok), 1)            # second call served from cache
        c.get("db", fresh=True)
        ok = [r for r in self.v.recent_access(10) if r["outcome"] == "ok"]
        self.assertEqual(len(ok), 2)

    def test_validate_endpoint(self):
        c = VaultingClient(self.base, self.token)
        self.assertTrue(c.validate("db", "http-secret-value"))
        self.assertFalse(c.validate("db", "wrong"))


if __name__ == "__main__":
    unittest.main()
