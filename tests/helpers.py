import os
import tempfile

from vaulting.crypto import Keyring
from vaulting.vault import Vault


def fresh_vault(keyring=None) -> Vault:
    path = os.path.join(tempfile.mkdtemp(prefix="vl-test-"), "t.db")
    return Vault(path, keyring or Keyring.generate())
