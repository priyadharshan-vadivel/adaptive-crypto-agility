"""
decision_engine.py
==================
Crypto-Agility Decision Engine.

Reads a quantum risk score and selects the appropriate cryptographic
security mode for network communication:

  QRS 0.0 – 3.0  →  CLASSICAL      (X25519 ECDH + AES-256-GCM)
  QRS 3.1 – 6.0  →  HYBRID         (X25519 + ML-KEM-1024 + AES-256-GCM)
  QRS 6.1 – 10.0 →  TRIPLE_HYBRID  (X25519 + ML-KEM-1024 + QKD + AES-256-GCM)

Based on:
  - IEEE JSAC 2025: Rubio García et al. — Triple-hybrid TLS/IPsec
  - IETF RFC 9370  — Multiple Key Exchanges in IKEv2
  - IETF RFC 8446  — TLS 1.3 Hybrid Key Schedule
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import logging
import json

from risk_engine.risk_engine import (
    AssetProfile,
    RiskResult,
    compute_risk,
    compute_risk_from_dict,
    batch_evaluate,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mode definitions
# ---------------------------------------------------------------------------

MODES = {
    "CLASSICAL": {
        "algorithms": ["X25519 ECDH", "AES-256-GCM"],
        "description": "Single classical ECDH key exchange with AES-256-GCM symmetric encryption.",
        "quantum_resistant": False,
        "secrets_combined": 1,
    },
    "HYBRID": {
        "algorithms": ["X25519 ECDH", "ML-KEM-1024 (Kyber)", "AES-256-GCM"],
        "description": "Classical + Post-Quantum KEM hybrid. Two independent shared secrets "
                       "combined via HKDF. Resistant to Shor's algorithm.",
        "quantum_resistant": True,
        "secrets_combined": 2,
    },
    "TRIPLE_HYBRID": {
        "algorithms": ["X25519 ECDH", "ML-KEM-1024 (Kyber)", "QKD (simulated)", "AES-256-GCM"],
        "description": "Triple-hybrid: Classical + PQ + QKD. Three independent cryptographic "
                       "assumptions combined. Provides information-theoretic security when "
                       "QKD is deployed on real hardware. Addresses HNDL attacks.",
        "quantum_resistant": True,
        "secrets_combined": 3,
    },
}


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class DecisionResult:
    """Full decision output: risk evaluation + selected mode + rationale."""
    risk_result: RiskResult
    mode: str
    mode_info: dict
    rationale: str

    @property
    def qrs(self) -> float:
        return self.risk_result.qrs

    @property
    def risk_class(self) -> str:
        return self.risk_result.risk_class

    def to_dict(self) -> dict:
        return {
            "risk": self.risk_result.to_dict(),
            "decision": {
                "mode": self.mode,
                "algorithms": self.mode_info["algorithms"],
                "quantum_resistant": self.mode_info["quantum_resistant"],
                "secrets_combined": self.mode_info["secrets_combined"],
                "description": self.mode_info["description"],
                "rationale": self.rationale,
            },
        }

    def __str__(self) -> str:
        return (
            f"Asset: {self.risk_result.asset.algorithm}/{self.risk_result.asset.key_size}-bit  "
            f"| QRS: {self.qrs:.2f}  "
            f"| Risk: {self.risk_class}  "
            f"| Mode: {self.mode}  "
            f"| QR-Safe: {'YES' if self.mode_info['quantum_resistant'] else 'NO'}"
        )


# ---------------------------------------------------------------------------
# Core decision logic
# ---------------------------------------------------------------------------

def _select_mode(qrs: float) -> tuple[str, str]:
    """Return (mode_name, rationale) based on QRS threshold."""
    if qrs <= 3.0:
        return (
            "CLASSICAL",
            f"QRS={qrs:.2f} (LOW risk). Classical X25519 ECDH + AES-256-GCM provides "
            "sufficient security. No immediate post-quantum migration needed.",
        )
    elif qrs <= 6.0:
        return (
            "HYBRID",
            f"QRS={qrs:.2f} (MEDIUM risk). Classical cryptography alone is insufficient "
            "against emerging quantum threats. Hybrid mode combines X25519 ECDH and "
            "ML-KEM-1024 (NIST FIPS 203) to ensure quantum-resistant key agreement.",
        )
    else:
        return (
            "TRIPLE_HYBRID",
            f"QRS={qrs:.2f} (HIGH risk). Asset is critically vulnerable to quantum attacks "
            "including HNDL (Harvest Now Decrypt Later). Triple-Hybrid mode deploys "
            "Classical + ML-KEM-1024 + QKD with three independent cryptographic assumptions "
            "— requiring all three to be broken before the system is compromised.",
        )


def decide(profile: AssetProfile) -> DecisionResult:
    """
    Full pipeline: evaluate risk → select mode → return decision.

    Args:
        profile: AssetProfile describing the cryptographic asset.

    Returns:
        DecisionResult with risk evaluation and selected mode.
    """
    risk_result = compute_risk(profile)
    mode, rationale = _select_mode(risk_result.qrs)
    mode_info = MODES[mode]

    decision = DecisionResult(
        risk_result=risk_result,
        mode=mode,
        mode_info=mode_info,
        rationale=rationale,
    )

    logger.info("Decision: %s", decision)
    return decision


def decide_from_dict(d: dict) -> DecisionResult:
    """Convenience wrapper accepting a plain dict."""
    return decide(AssetProfile.from_dict(d))


def batch_decide(profiles: list[dict]) -> list[DecisionResult]:
    """Decide for a list of profiles, sorted by QRS descending."""
    results = [decide_from_dict(p) for p in profiles]
    return sorted(results, key=lambda d: d.qrs, reverse=True)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  CRYPTO-AGILITY DECISION ENGINE — Demonstration")
    print("=" * 70)

    test_assets = [
        {"algorithm": "RSA",     "key_size": 1024, "sensitivity": "high",   "description": "Legacy VPN cert"},
        {"algorithm": "RSA",     "key_size": 2048, "sensitivity": "high",   "description": "TLS server cert"},
        {"algorithm": "ECC",     "key_size": 256,  "sensitivity": "medium", "description": "Client auth key"},
        {"algorithm": "AES-256", "key_size": 256,  "sensitivity": "low",    "description": "File encryption"},
        {"algorithm": "ML-KEM",  "key_size": 1024, "sensitivity": "high",   "description": "PQ KEM key"},
        {"algorithm": "DH",      "key_size": 2048, "sensitivity": "medium", "description": "Key exchange"},
    ]

    decisions = batch_decide(test_assets)

    print(f"\n{'Description':<22} {'Algorithm':<10} {'QRS':>5}  {'Risk':<8} {'Mode':<16} {'QR-Safe'}")
    print("-" * 80)
    for d in decisions:
        desc = d.risk_result.asset.description or ""
        print(
            f"{desc:<22} {d.risk_result.asset.algorithm:<10} {d.qrs:>5.2f}  "
            f"{d.risk_class:<8} {d.mode:<16} {'✓' if d.mode_info['quantum_resistant'] else '✗'}"
        )

    print("\n" + "=" * 70)
    print("  DETAILED RATIONALE FOR TOP-PRIORITY ASSETS")
    print("=" * 70)
    for d in decisions[:3]:
        print(f"\n[{d.mode}] {d.risk_result.asset.description}")
        print(f"  Algorithms : {', '.join(d.mode_info['algorithms'])}")
        print(f"  Rationale  : {d.rationale}")
