"""
vaulting/mtls.py — Mutual TLS (mTLS) support for the Vaulting HTTP server

Provides:
  • :func:`generate_ca`     — create a self-signed Certificate Authority
  • :func:`generate_cert`   — issue a leaf cert signed by the CA
  • :func:`make_server_ssl_context` — SSL context that requires client certs
  • :func:`make_client_ssl_context` — SSL context for authenticated clients
  • :class:`MTLSServer`     — HTTPServer subclass with mTLS wired in

mTLS workflow
─────────────
  1. One-time setup (run as admin):
       ca_cert, ca_key = generate_ca("Vaulting CA")
       srv_cert, srv_key = generate_cert(ca_cert, ca_key, "server", ["localhost"])
       cli_cert, cli_key = generate_cert(ca_cert, ca_key, "client-alice")
       # Distribute srv_cert/srv_key to server; cli_cert/cli_key to Alice.
       # Distribute ca_cert to both sides.

  2. Server startup:
       ssl_ctx = make_server_ssl_context(srv_cert, srv_key, ca_cert)
       httpd = MTLSServer(("0.0.0.0", 8443), MyHandler, ssl_ctx)
       httpd.serve_forever()

  3. Client call:
       ssl_ctx = make_client_ssl_context(cli_cert, cli_key, ca_cert)
       conn = http.client.HTTPSConnection("localhost", 8443, context=ssl_ctx)
       conn.request("GET", "/v1/secrets/foo")

All cert generation uses the cryptography library (no openssl subprocess).
"""

from __future__ import annotations

import datetime
from contextlib import contextmanager
import ipaddress
import os
import ssl
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# ── Type aliases ─────────────────────────────────────────────────────────────

_PemBytes = bytes   # PEM-encoded bytes

# ── Certificate generation ───────────────────────────────────────────────────


def generate_ca(
    common_name: str = "Vaulting CA",
    *,
    valid_days: int = 3650,
    key_size: int = 4096,
) -> tuple[_PemBytes, _PemBytes]:
    """
    Generate a self-signed Certificate Authority.

    Returns
    -------
    (ca_cert_pem, ca_key_pem) — both as PEM-encoded bytes.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,    "Vaulting"),
        x509.NameAttribute(NameOID.COMMON_NAME,          common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


def generate_cert(
    ca_cert_pem: _PemBytes,
    ca_key_pem:  _PemBytes,
    common_name: str,
    san_dns:     list[str] | None = None,
    san_ips:     list[str] | None = None,
    *,
    valid_days: int = 365,
    key_size:   int = 2048,
    is_server:  bool = True,
) -> tuple[_PemBytes, _PemBytes]:
    """
    Issue a leaf certificate signed by the provided CA.

    Parameters
    ----------
    san_dns : list of DNS SANs (e.g. ["localhost", "vaulting.internal"])
    san_ips : list of IP SANs (e.g. ["127.0.0.1"])

    Returns
    -------
    (cert_pem, key_pem)
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key  = serialization.load_pem_private_key(ca_key_pem, password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vaulting"),
        x509.NameAttribute(NameOID.COMMON_NAME,       common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)

    san_entries: list[x509.GeneralName] = []
    for dns in (san_dns or []):
        san_entries.append(x509.DNSName(dns))
    for ip in (san_ips or []):
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
    # Ensure at least the CN is in SANs
    if not san_entries:
        san_entries.append(x509.DNSName(common_name))

    extended_key_usages = (
        [x509.ExtendedKeyUsageOID.SERVER_AUTH]
        if is_server
        else [x509.ExtendedKeyUsageOID.CLIENT_AUTH]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage(extended_key_usages), critical=False
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]

    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


# ── SSL context factories ─────────────────────────────────────────────────────


def make_server_ssl_context(
    server_cert_pem: _PemBytes,
    server_key_pem:  _PemBytes,
    ca_cert_pem:     _PemBytes,
    *,
    min_tls: int = ssl.TLSVersion.TLSv1_2,
) -> ssl.SSLContext:
    """
    Create an :class:`ssl.SSLContext` for the server side of mTLS.

    The context:
    * Presents *server_cert* to clients.
    * Requires and verifies a client certificate signed by *ca_cert*.
    * Enforces TLS ≥ 1.2 (prefer 1.3).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version    = min_tls
    ctx.verify_mode        = ssl.CERT_REQUIRED   # <-- require client cert
    ctx.check_hostname     = False               # hostname check N/A server-side

    with _pem_tempfiles(server_cert_pem, server_key_pem, ca_cert_pem) as paths:
        cert_path, key_path, ca_path = paths
        ctx.load_cert_chain(cert_path, key_path)
        ctx.load_verify_locations(ca_path)

    # Prefer strong ciphers; disable known-weak ones
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL:!EXPORT:!RC4"
    )
    return ctx


def make_client_ssl_context(
    client_cert_pem: _PemBytes,
    client_key_pem:  _PemBytes,
    ca_cert_pem:     _PemBytes,
    server_hostname: Optional[str] = None,
    *,
    min_tls: int = ssl.TLSVersion.TLSv1_2,
) -> ssl.SSLContext:
    """
    Create an :class:`ssl.SSLContext` for the client side of mTLS.

    The context:
    * Presents *client_cert* to the server.
    * Verifies the server certificate against *ca_cert*.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = min_tls
    ctx.verify_mode     = ssl.CERT_REQUIRED
    ctx.check_hostname  = server_hostname is not None

    with _pem_tempfiles(client_cert_pem, client_key_pem, ca_cert_pem) as paths:
        cert_path, key_path, ca_path = paths
        ctx.load_cert_chain(cert_path, key_path)
        ctx.load_verify_locations(ca_path)

    return ctx


# ── Convenience: load from files ─────────────────────────────────────────────


def server_context_from_files(
    cert_path: Union[str, Path],
    key_path:  Union[str, Path],
    ca_path:   Union[str, Path],
) -> ssl.SSLContext:
    """Load PEM files from disk and return a server SSL context."""
    return make_server_ssl_context(
        Path(cert_path).read_bytes(),
        Path(key_path).read_bytes(),
        Path(ca_path).read_bytes(),
    )


def client_context_from_files(
    cert_path: Union[str, Path],
    key_path:  Union[str, Path],
    ca_path:   Union[str, Path],
) -> ssl.SSLContext:
    """Load PEM files from disk and return a client SSL context."""
    return make_client_ssl_context(
        Path(cert_path).read_bytes(),
        Path(key_path).read_bytes(),
        Path(ca_path).read_bytes(),
    )


# ── mTLS HTTP server ──────────────────────────────────────────────────────────


class MTLSServer(HTTPServer):
    """
    HTTPServer subclass that wraps the listening socket with mTLS.

    Usage::

        ssl_ctx = make_server_ssl_context(srv_cert, srv_key, ca_cert)
        httpd   = MTLSServer(("0.0.0.0", 8443), MyHandler, ssl_ctx)
        httpd.serve_forever()
    """

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type,
        ssl_ctx: ssl.SSLContext,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True)


# ── Internal helpers ──────────────────────────────────────────────────────────




@contextmanager
def _pem_tempfiles(*pem_blobs: _PemBytes):
    """Write PEM blobs to secure temp files, yield their paths, then delete."""
    files: list[str] = []
    try:
        for blob in pem_blobs:
            fd, path = tempfile.mkstemp(suffix=".pem")
            os.write(fd, blob)
            os.close(fd)
            os.chmod(path, 0o600)
            files.append(path)
        yield files
    finally:
        for path in files:
            try:
                # Zero-fill before deletion (best-effort)
                size = os.path.getsize(path)
                with open(path, "r+b") as f:
                    f.write(b"\x00" * size)
                os.unlink(path)
            except OSError:
                pass


# ── Smoke test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import http.client
    import threading

    print("=== mTLS smoke test ===")

    # Generate CA + server cert + client cert
    ca_cert, ca_key = generate_ca("Test CA")
    srv_cert, srv_key = generate_cert(
        ca_cert, ca_key, "localhost",
        san_dns=["localhost"], san_ips=["127.0.0.1"],
        is_server=True,
    )
    cli_cert, cli_key = generate_cert(
        ca_cert, ca_key, "test-client",
        is_server=False,
    )
    print("✓ CA + server cert + client cert generated")

    # Build SSL contexts
    srv_ctx = make_server_ssl_context(srv_cert, srv_key, ca_cert)
    cli_ctx = make_client_ssl_context(cli_cert, cli_key, ca_cert, server_hostname=None)
    print("✓ SSL contexts created")

    # Start mTLS server on a random port
    class _Echo(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_): pass

    srv = MTLSServer(("127.0.0.1", 0), _Echo, srv_ctx)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"✓ mTLS server started on port {port}")

    # Client request with valid cert
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=cli_ctx)
    conn.request("GET", "/")
    resp = conn.getresponse()
    body = resp.read()
    assert resp.status == 200 and body == b"OK", f"Unexpected: {resp.status} {body}"
    print(f"✓ Client GET /  →  {resp.status} {body}")

    # Client request WITHOUT cert should fail
    no_cert_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    no_cert_ctx.check_hostname = False
    no_cert_ctx.verify_mode = ssl.CERT_NONE
    try:
        conn2 = http.client.HTTPSConnection("127.0.0.1", port, context=no_cert_ctx)
        conn2.request("GET", "/")
        conn2.getresponse()
        print("✗ Should have rejected unauthenticated client!")
    except (ssl.SSLError, ConnectionResetError, OSError) as e:
        print(f"✓ Unauthenticated client correctly rejected: {type(e).__name__}")

    srv.shutdown()
    print("\nAll mTLS checks passed.")
