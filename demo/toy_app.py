"""A pretend microservice that depends on a vault secret.

/health  200 only if the secret it is using is still valid in the vault
/refresh drop the cached secret (rotation manager calls this)
/whoami  which secret version this app is using right now
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ToyApp:
    def __init__(self, client, secret_name: str, app_name: str = "orders-api", port: int = 0):
        self.client, self.secret_name, self.app_name = client, secret_name, app_name
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                try:
                    value, version = app.client.get_with_version(app.secret_name)
                    if self.path == "/whoami":
                        return self._send(200, {"app": app.app_name, "secret_version": version})
                    if self.path == "/health":
                        if app.client.validate(app.secret_name, value):
                            return self._send(200, {"status": "ok", "secret_version": version})
                        return self._send(503, {"status": "secret rejected", "secret_version": version})
                except Exception as e:
                    return self._send(503, {"status": f"error: {e}"})
                self._send(404, {"error": "not found"})

            def do_POST(self):
                if self.path == "/refresh":
                    app.client.invalidate(app.secret_name)
                    return self._send(200, {"refreshed": True})
                self._send(404, {"error": "not found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
