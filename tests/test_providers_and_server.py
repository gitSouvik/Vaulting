import datetime
import ipaddress
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests.helpers import fresh_vault
from vaulting.client import VaultingClient, VaultingError
from vaulting.providers import HashiCorpKVProvider, ProviderError
from vaulting.ratelimit import RateLimiter
from vaulting.server import make_server, serve_in_thread


class FakeHashiCorpVault:
    """Minimal KV v2 + AppRole mock so provider code is tested without a network."""
    GOOD_TOKEN = "s.static"
    ROLE = ("role-1", "secret-1")

    def __init__(self):
        self.logins = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, body):
                d = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(d)))
                self.end_headers()
                self.wfile.write(d)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/v1/auth/approle/login" and (body["role_id"], body["secret_id"]) == outer.ROLE:
                    outer.logins += 1
                    return self._json(200, {"auth": {"client_token": "s.approle", "lease_duration": 3600}})
                self._json(403, {"errors": ["denied"]})

            def do_GET(self):
                if self.headers.get("X-Vault-Token") not in (outer.GOOD_TOKEN, "s.approle"):
                    return self._json(403, {"errors": ["permission denied"]})
                if self.path == "/v1/secret/data/db/mysql":
                    return self._json(200, {"data": {"data": {"password": "p4ss-from-hcv", "user": "root"},
                                                     "metadata": {"version": 7}}})
                if self.path == "/v1/secret/data/single":
                    return self._json(200, {"data": {"data": {"only": "lonely"}, "metadata": {"version": 1}}})
                self._json(404, {"errors": []})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addr = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.hcv = FakeHashiCorpVault()

    def tearDown(self):
        self.hcv.stop()

    def test_token_auth_and_field(self):
        p = HashiCorpKVProvider(self.hcv.addr, token="s.static")
        self.assertEqual(p.get("db/mysql", "password"), ("p4ss-from-hcv", 7))

    def test_approle_login_is_cached(self):
        p = HashiCorpKVProvider(self.hcv.addr, role_id="role-1", secret_id="secret-1")
        p.get("db/mysql", "password")
        p.get("db/mysql", "user")
        self.assertEqual(self.hcv.logins, 1)

    def test_bad_approle_fails(self):
        p = HashiCorpKVProvider(self.hcv.addr, role_id="role-1", secret_id="WRONG")
        with self.assertRaises(ProviderError):
            p.get("db/mysql", "password")

    def test_bad_token_and_missing_field_and_ambiguity(self):
        with self.assertRaises(ProviderError):
            HashiCorpKVProvider(self.hcv.addr, token="nope").get("db/mysql", "password")
        p = HashiCorpKVProvider(self.hcv.addr, token="s.static")
        with self.assertRaises(ProviderError):
            p.get("db/mysql", "missing")
        with self.assertRaises(ProviderError):
            p.get("db/mysql")                       # two fields, none chosen
        self.assertEqual(p.get("single")[0], "lonely")  # one field: unambiguous

    def test_unreachable_provider_is_clean_error(self):
        with self.assertRaises(ProviderError):
            HashiCorpKVProvider("http://127.0.0.1:1", token="x", timeout=0.5).get("a")

    def test_requires_credentials(self):
        with self.assertRaises(ProviderError):
            HashiCorpKVProvider(self.hcv.addr)


class ServerRoutingTests(unittest.TestCase):
    def setUp(self):
        self.hcv = FakeHashiCorpVault()
        self.v = fresh_vault()
        self.token = self.v.register_app("svc")
        self.v.grant("svc", "hcv:db/mysql#password")
        self.srv = make_server(self.v, providers={"hcv": HashiCorpKVProvider(self.hcv.addr, token="s.static")})
        serve_in_thread(self.srv)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.hcv.stop()

    def test_external_secret_served_through_grant(self):
        c = VaultingClient(self.base, self.token)
        self.assertEqual(c.get_with_version("hcv:db/mysql#password"), ("p4ss-from-hcv", 7))
        self.assertEqual(self.v.recent_access(1)[0]["outcome"], "ok")

    def test_ungranted_external_path_denied(self):
        with self.assertRaises(VaultingError):
            VaultingClient(self.base, self.token).get("hcv:db/mysql#user")
        self.assertEqual(self.v.recent_access(1)[0]["outcome"], "denied")

    def test_provider_failure_is_502_and_leaks_no_detail(self):
        self.v.grant("svc", "hcv:nothing/here")
        try:
            VaultingClient(self.base, self.token).get("hcv:nothing/here")
            self.fail("expected error")
        except VaultingError as e:
            self.assertEqual(str(e), "HTTP 502")
        self.assertEqual(self.v.recent_access(1)[0]["outcome"], "provider_error")


class HardeningTests(unittest.TestCase):
    def _server(self, **kw):
        v = fresh_vault()
        v.put_secret("db", "value-1234567890")
        token = v.register_app("svc")
        v.grant("svc", "db")
        srv = make_server(v, **kw)
        serve_in_thread(srv)
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        scheme = "https" if kw.get("tls_cert") else "http"
        return v, token, f"{scheme}://127.0.0.1:{srv.server_address[1]}"

    def _status(self, url, headers=None, data=None, method=None):
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.status, dict(r.headers), json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), None

    def test_secret_responses_are_not_cacheable(self):
        _, token, base = self._server()
        code, headers, _ = self._status(base + "/v1/secrets/db", {"Authorization": f"Bearer {token}"})
        self.assertEqual((code, headers["Cache-Control"]), (200, "no-store"))

    def test_rate_limit_returns_429(self):
        _, _, base = self._server(limiter=RateLimiter(rate=0.01, burst=3))
        codes = [self._status(base + "/v1/health")[0] for _ in range(6)]
        self.assertEqual(codes[:3], [200, 200, 200])
        self.assertIn(429, codes[3:])

    def test_oversized_body_rejected(self):
        _, token, base = self._server()
        code, _, _ = self._status(base + "/v1/validate", {"Authorization": f"Bearer {token}"},
                                  data=b"x" * 5000, method="POST")
        self.assertEqual(code, 413)

    def test_metrics_disabled_without_admin_token(self):
        _, _, base = self._server()
        self.assertEqual(self._status(base + "/v1/metrics")[0], 404)

    def test_metrics_requires_admin_token(self):
        _, token, base = self._server(admin_token="admin-xyz")
        self.assertEqual(self._status(base + "/v1/metrics")[0], 401)
        self.assertEqual(self._status(base + "/v1/metrics", {"Authorization": f"Bearer {token}"})[0], 401)
        code, _, body = self._status(base + "/v1/metrics", {"Authorization": "Bearer admin-xyz"})
        self.assertEqual(code, 200)
        self.assertTrue(body["audit_chain_ok"])
        self.assertNotIn("value-1234567890", json.dumps(body))

    def test_tls_roundtrip_and_untrusted_cert_rejected(self):
        d = tempfile.mkdtemp()
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        _, token, base = self._server(tls_cert=cert_path, tls_key=key_path)
        good = VaultingClient(base, token, ca_file=cert_path)
        self.assertEqual(good.get("db"), "value-1234567890")
        with self.assertRaises(VaultingError):          # default trust store doesn't know our cert
            VaultingClient(base, token).get("db")


class RateLimiterUnitTests(unittest.TestCase):
    def test_burst_then_refill(self):
        r = RateLimiter(rate=1.0, burst=2)
        self.assertTrue(r.allow("ip", now=0))
        self.assertTrue(r.allow("ip", now=0))
        self.assertFalse(r.allow("ip", now=0))
        self.assertTrue(r.allow("ip", now=1.1))

    def test_keys_are_independent(self):
        r = RateLimiter(rate=0.001, burst=1)
        self.assertTrue(r.allow("a", now=0))
        self.assertTrue(r.allow("b", now=0))
        self.assertFalse(r.allow("a", now=0))


if __name__ == "__main__":
    unittest.main()
