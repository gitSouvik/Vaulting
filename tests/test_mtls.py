"""
tests/test_mtls.py — Tests for mutual TLS certificate generation and server/client SSL contexts
"""

import ssl
import pytest
from vaulting.mtls import (
    generate_ca,
    generate_cert,
    make_server_ssl_context,
    make_client_ssl_context,
    MTLSServer,
)


def test_ca_generation():
    """Verify self-signed CA generation returns valid cert and key PEMs."""
    ca_pem, key_pem = generate_ca(common_name="Vaulting Test CA", valid_days=1)
    assert b"BEGIN CERTIFICATE" in ca_pem
    assert b"END CERTIFICATE" in ca_pem
    assert b"BEGIN PRIVATE KEY" in key_pem or b"BEGIN RSA PRIVATE KEY" in key_pem


def test_leaf_cert_generation():
    """Verify issuance of server/client leaf certs signed by the CA."""
    ca_pem, ca_key_pem = generate_ca(common_name="Vaulting Test CA", valid_days=1)
    srv_pem, srv_key = generate_cert(
        ca_cert_pem=ca_pem,
        ca_key_pem=ca_key_pem,
        common_name="localhost",
        san_dns=["localhost"],
        san_ips=["127.0.0.1"],
        valid_days=1,
    )
    assert b"BEGIN CERTIFICATE" in srv_pem
    assert b"END CERTIFICATE" in srv_pem

    cli_pem, cli_key = generate_cert(
        ca_cert_pem=ca_pem,
        ca_key_pem=ca_key_pem,
        common_name="client1",
        san_dns=["client1"],
        valid_days=1,
    )
    assert b"BEGIN CERTIFICATE" in cli_pem


def test_ssl_contexts_creation():
    """Verify creating server and client SSLContext objects."""
    ca_pem, ca_key_pem = generate_ca(common_name="Vaulting Test CA", valid_days=1)
    srv_pem, srv_key = generate_cert(
        ca_cert_pem=ca_pem,
        ca_key_pem=ca_key_pem,
        common_name="localhost",
        san_dns=["localhost"],
        san_ips=["127.0.0.1"],
    )
    cli_pem, cli_key = generate_cert(
        ca_cert_pem=ca_pem,
        ca_key_pem=ca_key_pem,
        common_name="client1",
    )

    srv_ctx = make_server_ssl_context(srv_pem, srv_key, ca_pem)
    assert isinstance(srv_ctx, ssl.SSLContext)
    assert srv_ctx.verify_mode == ssl.CERT_REQUIRED

    cli_ctx = make_client_ssl_context(cli_pem, cli_key, ca_pem)
    assert isinstance(cli_ctx, ssl.SSLContext)
    assert cli_ctx.verify_mode == ssl.CERT_REQUIRED
