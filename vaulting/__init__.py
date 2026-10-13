"""
Vaulting: A secure secrets engine with Shamir unsealing, C-accelerated
sentinel scanning, crash-safe rotation sagas, Prometheus metrics, and mutual TLS.
"""

from __future__ import annotations

__version__ = "0.2.0"

from vaulting.crypto import Keyring
from vaulting.vault import Vault
from vaulting.sentinel import Sentinel
from vaulting.native import (
    AhoCorasickScanner,
    SecureBuffer,
    shamir_split,
    shamir_combine,
    consttime_eq,
)
from vaulting.unseal import UnsealMachine, UnsealState, UnsealError
from vaulting.saga import RotationSaga, SagaState
from vaulting.metrics import MetricsServer, REGISTRY, generate_metrics_page
from vaulting.mtls import (
    generate_ca,
    generate_cert,
    make_server_ssl_context,
    make_client_ssl_context,
    server_context_from_files,
    client_context_from_files,
    MTLSServer,
)

__all__ = [
    "__version__",
    "Vault",
    "Keyring",
    "Sentinel",
    "AhoCorasickScanner",
    "SecureBuffer",
    "shamir_split",
    "shamir_combine",
    "consttime_eq",
    "UnsealMachine",
    "UnsealState",
    "UnsealError",
    "RotationSaga",
    "SagaState",
    "MetricsServer",
    "REGISTRY",
    "generate_metrics_page",
    "generate_ca",
    "generate_cert",
    "make_server_ssl_context",
    "make_client_ssl_context",
    "server_context_from_files",
    "client_context_from_files",
    "MTLSServer",
]
