"""HTTP API (stdlib only), hardened.

GET  /v1/health                    liveness (no auth)
GET  /v1/secrets/<name>            fetch a secret      (Bearer app token + grant)
POST /v1/validate                  {"name","value"}    (Bearer app token + grant)
GET  /v1/metrics                   monitoring JSON     (Bearer ADMIN token; off unless configured)

Hardening: optional TLS (>= 1.2), per-IP rate limiting, request size cap, socket timeouts,
no-store caching headers, constant-time admin token compare, no internal error details to clients.
"""
import hmac
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import unquote

from .providers import ProviderError
from .ratelimit import RateLimiter

MAX_BODY = 4096


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Failed TLS handshakes and dropped connections are routine on a public port;
        # don't spray stack traces for them. Everything else keeps the default behaviour.
        import sys
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def make_server(vault, host: str = "127.0.0.1", port: int = 0, ttl: int = 30, providers: Optional[dict] = None,
                admin_token: Optional[str] = None, limiter: Optional[RateLimiter] = None,
                tls_cert: Optional[str] = None, tls_key: Optional[str] = None) -> ThreadingHTTPServer:
    providers = providers or {}

    class Handler(BaseHTTPRequestHandler):
        timeout = 10  # drop slow/stalled connections (slowloris)

        def log_message(self, *args):
            pass

        def _send(self, code: int, body: dict, extra: Optional[dict] = None):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _bearer(self) -> Optional[str]:
            h = self.headers.get("Authorization", "")
            return h[7:] if h.startswith("Bearer ") else None

        def _app(self):
            t = self._bearer()
            return vault.authenticate(t) if t else None

        def _limited(self) -> bool:
            if limiter and not limiter.allow(self.client_address[0]):
                self._send(429, {"error": "rate limited"}, {"Retry-After": "1"})
                return True
            return False

        def do_GET(self):
            if self._limited():
                return
            if self.path == "/v1/health":
                return self._send(200, {"status": "ok"})
            if self.path == "/v1/metrics":
                tok = self._bearer()
                if not admin_token:
                    return self._send(404, {"error": "not found"})
                if not tok or not hmac.compare_digest(tok, admin_token):
                    return self._send(401, {"error": "unauthenticated"})
                return self._send(200, vault.metrics())
            if not self.path.startswith("/v1/secrets/"):
                return self._send(404, {"error": "not found"})

            name = unquote(self.path[len("/v1/secrets/"):])
            app = self._app()
            if app is None:
                vault.log_access(None, name[:128], None, "unauthenticated")
                return self._send(401, {"error": "unauthenticated"})
            if not vault.authorize(app, name):
                vault.log_access(app, name[:128], None, "denied")
                return self._send(403, {"error": "denied"})

            prefix, sep, rest = name.partition(":")
            if sep and prefix in providers:
                path, _, field = rest.partition("#")
                try:
                    value, version = providers[prefix].get(path, field or None)
                except ProviderError:
                    vault.log_access(app, name, None, "provider_error")
                    return self._send(502, {"error": "provider error"})
            else:
                row = vault.get_active(name)
                if row is None:
                    vault.log_access(app, name, None, "not_found")
                    return self._send(404, {"error": "no such secret"})
                value, version = row["value"], row["version"]
            vault.log_access(app, name, version, "ok")
            return self._send(200, {"name": name, "version": version, "value": value, "ttl": ttl})

        def do_POST(self):
            if self._limited():
                return
            if self.path != "/v1/validate":
                return self._send(404, {"error": "not found"})
            app = self._app()
            if app is None:
                return self._send(401, {"error": "unauthenticated"})
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                return self._send(400, {"error": "bad request"})
            if length > MAX_BODY:
                return self._send(413, {"error": "request too large"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                name, value = body["name"], body["value"]
                if not isinstance(name, str) or not isinstance(value, str):
                    raise ValueError
            except (ValueError, KeyError):
                return self._send(400, {"error": "bad request"})
            if not vault.authorize(app, name):
                vault.log_access(app, name[:128], None, "denied")
                return self._send(403, {"error": "denied"})
            return self._send(200, {"valid": vault.validate(name, value)})

    server = _Server((host, port), Handler)
    if tls_cert and tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_cert, tls_key)
        # handshake lazily in the handler thread so a stalled client can't block accept()
        server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t
