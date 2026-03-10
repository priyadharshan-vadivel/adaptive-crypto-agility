"""
test_risk_engine.py
Tests for the Quantum Risk Assessment Engine.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from risk_engine.risk_engine import compute_risk, AssetProfile, batch_evaluate

class TestRiskEngine(unittest.TestCase):

    def test_rsa_1024_high_sens_is_high(self):
        p = AssetProfile("RSA", 1024, "high")
        r = compute_risk(p)
        self.assertEqual(r.risk_class, "HIGH")
        self.assertTrue(r.migration_required)

    def test_aes256_low_sens_is_low(self):
        p = AssetProfile("AES-256", 256, "low")
        r = compute_risk(p)
        self.assertEqual(r.risk_class, "LOW")
        self.assertFalse(r.migration_required)

    def test_mlkem_is_low_risk(self):
        p = AssetProfile("ML-KEM", 1024, "high")
        r = compute_risk(p)
        self.assertLessEqual(r.qrs, 3.0)
        self.assertFalse(r.migration_required)

    def test_qrs_range(self):
        p = AssetProfile("ECC", 256, "medium")
        r = compute_risk(p)
        self.assertGreaterEqual(r.qrs, 0.0)
        self.assertLessEqual(r.qrs, 10.0)

    def test_batch_sorted_desc(self):
        assets = [
            {"algorithm": "AES-256", "key_size": 256,  "sensitivity": "low"},
            {"algorithm": "RSA",     "key_size": 1024, "sensitivity": "high"},
        ]
        results = batch_evaluate(assets)
        self.assertGreater(results[0].qrs, results[1].qrs)

    def test_high_key_score_small_rsa(self):
        p = AssetProfile("RSA", 512, "medium")
        r = compute_risk(p)
        self.assertEqual(r.k_score, 10)

if __name__ == "__main__":
    unittest.main()
