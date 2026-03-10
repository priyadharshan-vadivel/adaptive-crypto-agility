"""
test_decision_engine.py
Tests for the Crypto-Agility Decision Engine.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from risk_engine.decision_engine import decide_from_dict, batch_decide

class TestDecisionEngine(unittest.TestCase):

    def test_low_risk_is_classical(self):
        d = decide_from_dict({"algorithm": "AES-256", "key_size": 256, "sensitivity": "low"})
        self.assertEqual(d.mode, "CLASSICAL")

    def test_high_risk_is_triple_hybrid(self):
        d = decide_from_dict({"algorithm": "RSA", "key_size": 1024, "sensitivity": "high"})
        self.assertEqual(d.mode, "TRIPLE_HYBRID")

    def test_medium_risk_is_hybrid(self):
        d = decide_from_dict({"algorithm": "ECC", "key_size": 256, "sensitivity": "medium"})
        self.assertIn(d.mode, ("HYBRID", "TRIPLE_HYBRID"))

    def test_triple_hybrid_is_quantum_resistant(self):
        d = decide_from_dict({"algorithm": "RSA", "key_size": 2048, "sensitivity": "high"})
        self.assertTrue(d.mode_info["quantum_resistant"])

    def test_classical_not_quantum_resistant(self):
        d = decide_from_dict({"algorithm": "AES-256", "key_size": 256, "sensitivity": "low"})
        self.assertFalse(d.mode_info["quantum_resistant"])

    def test_batch_sorted_desc(self):
        assets = [
            {"algorithm": "AES-256", "key_size": 256,  "sensitivity": "low"},
            {"algorithm": "RSA",     "key_size": 1024, "sensitivity": "high"},
        ]
        results = batch_decide(assets)
        self.assertGreater(results[0].qrs, results[1].qrs)

if __name__ == "__main__":
    unittest.main()
