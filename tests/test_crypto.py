import os
import stat
import tempfile
import unittest

from tests.helpers import fresh_vault
from vaulting.crypto import CryptoError, Keyring, open_sealed, rewrap, seal


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.k = Keyring.generate("k1")

    def test_roundtrip(self):
        s = seal(self.k, b"hunter2-but-long", b"aad")
        self.assertEqual(open_sealed(self.k, s, b"aad"), b"hunter2-but-long")

    def test_ciphertext_does_not_contain_plaintext(self):
        s = seal(self.k, b"PLAINTEXT-MARKER-123", b"aad")
        self.assertNotIn(b"PLAINTEXT-MARKER-123", s.ciphertext)

    def test_same_plaintext_encrypts_differently_each_time(self):
        a, b = seal(self.k, b"same", b"aad"), seal(self.k, b"same", b"aad")
        self.assertNotEqual(a.ciphertext, b.ciphertext)
        self.assertNotEqual(a.nonce, b.nonce)

    def test_tampered_ciphertext_rejected(self):
        s = seal(self.k, b"value", b"aad")
        s.ciphertext = bytes([s.ciphertext[0] ^ 1]) + s.ciphertext[1:]
        with self.assertRaises(CryptoError):
            open_sealed(self.k, s, b"aad")

    def test_tampered_wrapped_key_rejected(self):
        s = seal(self.k, b"value", b"aad")
        s.wrapped_dek = bytes([s.wrapped_dek[0] ^ 1]) + s.wrapped_dek[1:]
        with self.assertRaises(CryptoError):
            open_sealed(self.k, s, b"aad")

    def test_aad_binds_ciphertext_to_its_row(self):
        s = seal(self.k, b"value", b"vaulting:v2|db|1")
        with self.assertRaises(CryptoError):
            open_sealed(self.k, s, b"vaulting:v2|db|2")

    def test_wrong_master_key_rejected(self):
        s = seal(self.k, b"value", b"aad")
        other = Keyring.generate("k1")  # same id, different key material
        with self.assertRaises(CryptoError):
            open_sealed(other, s, b"aad")

    def test_missing_master_key_gives_clear_error(self):
        s = seal(self.k, b"value", b"aad")
        with self.assertRaisesRegex(CryptoError, "not available"):
            open_sealed(Keyring.generate("k9"), s, b"aad")

    def test_rewrap_moves_to_new_key_without_touching_ciphertext(self):
        s = seal(self.k, b"value", b"aad")
        ring = Keyring.from_spec(self.k.spec() + ",k2:" + Keyring.new_key_b64())
        r = rewrap(ring, s, b"aad")
        self.assertEqual((r.kek_id, r.ciphertext, r.nonce), ("k2", s.ciphertext, s.nonce))
        only_new = Keyring.from_spec(
            "k2:" + ring.spec().split(",k2:")[1])      # old key fully retired
        self.assertEqual(open_sealed(only_new, r, b"aad"), b"value")

    def test_keyring_validation(self):
        with self.assertRaises(CryptoError):
            Keyring({"k1": b"short"}, "k1")
        with self.assertRaises(CryptoError):
            Keyring.from_spec("k1:not-base64!!")
        with self.assertRaises(CryptoError):
            Keyring.from_env({})

    def test_key_file_must_be_private(self):
        path = os.path.join(tempfile.mkdtemp(), "keys")
        with open(path, "w") as fh:
            fh.write("k1:" + Keyring.new_key_b64() + "\n")
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(CryptoError, "chmod 600"):
            Keyring.from_env({"VAULTING_KEY_FILE": path})
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(Keyring.from_env({"VAULTING_KEY_FILE": path}).active_id, "k1")


class VaultEncryptionTests(unittest.TestCase):
    def test_stolen_db_file_contains_no_plaintext(self):
        v = fresh_vault()
        v.put_secret("db", "SUPER-SECRET-MARKER-xyz")
        v.rotate("db", new_value="SECOND-SECRET-MARKER-abc")
        with open(v.db_path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"SUPER-SECRET-MARKER-xyz", raw)
        self.assertNotIn(b"SECOND-SECRET-MARKER-abc", raw)

    def test_db_without_key_cannot_be_read(self):
        v = fresh_vault()
        v.put_secret("db", "value-1234567890")
        from vaulting.vault import Vault
        thief = Vault(v.db_path, Keyring.generate("k1"))
        with self.assertRaises(CryptoError):
            thief.get_active("db")

    def test_swapping_ciphertext_between_secrets_is_detected(self):
        v = fresh_vault()
        v.put_secret("a", "value-of-a-1234567")
        v.put_secret("b", "value-of-b-1234567")
        with v.tx() as c:
            ra = c.execute("SELECT * FROM secret_versions WHERE name='a'").fetchone()
            c.execute("UPDATE secret_versions SET ciphertext=?, nonce=?, wrapped_dek=?, dek_nonce=? "
                      "WHERE name='b'", (ra["ciphertext"], ra["nonce"], ra["wrapped_dek"], ra["dek_nonce"]))
        with self.assertRaises(CryptoError):
            v.get_active("b")

    def test_master_key_rotation_end_to_end(self):
        old = Keyring.generate("k1")
        v = fresh_vault(old)
        v.put_secret("db", "value-1234567890")
        v.rotate("db")
        from vaulting.vault import Vault
        new_ring = Keyring.from_spec(old.spec() + ",k2:" + Keyring.new_key_b64())
        v2 = Vault(v.db_path, new_ring)
        self.assertEqual(v2.rewrap_all(), 2)                # both versions moved
        self.assertEqual(v2.rewrap_all(), 0)                # idempotent
        self.assertEqual({x["kek_id"] for x in v2.versions("db")}, {"k2"})
        retired = Vault(v.db_path, Keyring.from_spec("k2:" + new_ring.spec().split(",k2:")[1]))
        self.assertIsNotNone(retired.get_active("db"))      # works with the old key gone

    def test_versions_metadata_never_exposes_values(self):
        v = fresh_vault()
        v.put_secret("db", "value-1234567890")
        self.assertNotIn("value", v.versions("db")[0])


if __name__ == "__main__":
    unittest.main()
