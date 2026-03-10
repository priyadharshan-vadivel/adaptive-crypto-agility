"""
test_crypto_comm.py
Tests for the Cryptographic Communication Module.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from crypto_engine.crypto_comm import (
    classical_x25519, hybrid_key_combiner, encrypt, decrypt,
    run_secure_communication, SharedSecret
)

class TestCryptoComm(unittest.TestCase):

    def test_x25519_returns_32_bytes(self):
        ss = classical_x25519()
        self.assertEqual(len(ss.secret), 32)
        self.assertEqual(ss.size_bits, 256)

    def test_hkdf_returns_32_bytes(self):
        ss = classical_x25519()
        key, _ = hybrid_key_combiner([ss])
        self.assertEqual(len(key), 32)

    def test_two_secrets_same_length(self):
        s1 = classical_x25519()
        s2 = SharedSecret("TEST", b"\x00" * 32)
        k1, _ = hybrid_key_combiner([s1])
        k2, _ = hybrid_key_combiner([s1, s2])
        self.assertEqual(len(k1), len(k2))

    def test_aes_gcm_roundtrip(self):
        import os
        key = os.urandom(32)
        pt  = "Test plaintext payload"
        nonce, ct = encrypt(key, pt)
        self.assertEqual(decrypt(key, nonce, ct), pt)

    def test_classical_mode_success(self):
        r = run_secure_communication("CLASSICAL")
        self.assertTrue(r.success)
        self.assertEqual(len(r.session_key.sources), 1)

    def test_hybrid_mode_success(self):
        r = run_secure_communication("HYBRID")
        self.assertTrue(r.success)
        self.assertEqual(len(r.session_key.sources), 2)

    def test_triple_hybrid_mode_success(self):
        r = run_secure_communication("TRIPLE_HYBRID")
        self.assertTrue(r.success)
        self.assertEqual(len(r.session_key.sources), 3)

    def test_wrong_key_fails_decryption(self):
        import os
        key1, key2 = os.urandom(32), os.urandom(32)
        nonce, ct = encrypt(key1, "secret")
        with self.assertRaises(Exception):
            decrypt(key2, nonce, ct)

if __name__ == "__main__":
    unittest.main()
