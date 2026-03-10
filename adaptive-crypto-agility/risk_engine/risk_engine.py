"""
risk_engine.py
==============
Quantum Risk Assessment Model for the Adaptive Crypto-Agility Decision System.

Computes a Quantum Risk Score (QRS) for a given cryptographic asset based on:
  - Algorithm vulnerability to Shor's algorithm        (weight: 0.40)
  - Key strength against Grover's algorithm            (weight: 0.35)
  - Data sensitivity / long-term confidentiality need  (weight: 0.25)

Formula:
    QRS = (0.40 × A_score) + (0.35 × K_score) + (0.25 × S_score)

References:
    - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
    - Rubio García et al., IEEE JSAC 2025
    - CARAF: Crypto Agility Risk Assessment Framework
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import json
import logging

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

# A_score: Algorithm vulnerability to Shor's algorithm (0 = safe, 10 = fully broken)
ALGO_SCORES: dict[str, int] = {
    "RSA":       10,   # Fully broken by Shor
    "DH":        9,    # Fully broken by Shor (discrete log)
    "ECC":       9,    # Fully broken by Shor
    "ECDH":      9,
    "ECDSA":     9,
    "DSA":       9,
    "ELGAMAL":   9,
    "AES-128":   4,    # Grover reduces to ~64-bit security
    "AES-192":   3,
    "AES-256":   2,    # Grover reduces to ~128-bit security (still safe w/ large keys)
    "3DES":      8,    # Weak classically + quantum
    "RC4":       10,   # Broken classically
    "CHACHA20":  2,    # Symmetric, Grover-resistant at 256-bit
    "ML-KEM":    0,    # NIST FIPS 203 — quantum-resistant KEM
    "KYBER":     0,    # Legacy name for ML-KEM
    "ML-DSA":    0,    # NIST FIPS 204 — quantum-resistant signature
    "DILITHIUM": 0,    # Legacy name for ML-DSA
    "FALCON":    0,    # Alternate PQ signature
    "SPHINCS+":  0,    # Hash-based PQ signature
    "HYBRID":    3,    # Classical+PQ hybrid (depends on weakest link)
    "UNKNOWN":   8,    # Conservative default
}

# S_score: Data sensitivity / confidentiality horizon
SENSITIVITY_SCORES: dict[str, int] = {
    "low":    2,   # Public / ephemeral / test data
    "medium": 5,   # Internal business / customer PII
    "high":   9,   # Classified / healthcare / national security / 10+ year horizon
}

# Weights for the QRS formula
WEIGHTS = {"algorithm": 0.40, "key": 0.35, "sensitivity": 0.25}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AssetProfile:
    """Represents a single cryptographic asset to be evaluated."""
    algorithm: str
    key_size: int
    sensitivity: str = "medium"
    protocol: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "sensitivity": self.sensitivity,
            "protocol": self.protocol,
            "description": self.description,
        }

    @staticmethod
    def from_dict(d: dict) -> "AssetProfile":
        return AssetProfile(
            algorithm=d.get("algorithm", "UNKNOWN"),
            key_size=int(d.get("key_size", 0)),
            sensitivity=d.get("sensitivity", "medium"),
            protocol=d.get("protocol"),
            description=d.get("description"),
        )


@dataclass
class RiskResult:
    """Result of quantum risk evaluation for one asset."""
    asset: AssetProfile
    a_score: float
    k_score: float
    s_score: float
    qrs: float
    risk_class: str          # LOW / MEDIUM / HIGH
    migration_required: bool
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "asset": self.asset.to_dict(),
            "scores": {
                "algorithm":   self.a_score,
                "key_strength": self.k_score,
                "sensitivity": self.s_score,
                "qrs":         self.qrs,
            },
            "risk_class":          self.risk_class,
            "migration_required":  self.migration_required,
            "recommendation":      self.recommendation,
        }

    def __str__(self) -> str:
        return (
            f"Algorithm: {self.asset.algorithm}/{self.asset.key_size}-bit  "
            f"| Sensitivity: {self.asset.sensitivity.upper()}  "
            f"| QRS: {self.qrs:.2f}  "
            f"| Risk: {self.risk_class}  "
            f"| Migrate: {'YES' if self.migration_required else 'NO'}"
        )


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def _algorithm_score(algorithm: str) -> int:
    """Return Shor-vulnerability score for the given algorithm name."""
    key = algorithm.upper().strip()
    # Handle variants like "RSA-2048", "AES128"
    for k in ALGO_SCORES:
        if key.startswith(k):
            return ALGO_SCORES[k]
    return ALGO_SCORES["UNKNOWN"]


def _key_score(key_size: int, algorithm: str) -> int:
    """
    Return Grover-vulnerability score based on key size and algorithm family.

    For symmetric algorithms (AES, ChaCha20), Grover halves effective security.
    For asymmetric algorithms (RSA, DH, ECC), Shor breaks them regardless of size.
    For PQ algorithms, score is 0.
    """
    algo_upper = algorithm.upper()

    # PQ algorithms — quantum-safe
    if any(pq in algo_upper for pq in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "FALCON", "SPHINCS")):
        return 0

    # Symmetric algorithms — Grover halves security
    if any(sym in algo_upper for sym in ("AES", "CHACHA", "3DES", "RC4")):
        if key_size <= 64:  return 10
        if key_size <= 128: return 6
        if key_size <= 192: return 3
        return 2  # AES-256

    # Asymmetric algorithms (RSA, DH, ECC) — Shor breaks all, score by size
    if key_size == 0:    return 8
    if key_size < 1024:  return 10  # Classically broken
    if key_size < 2048:  return 9
    if key_size < 3072:  return 7
    if key_size < 4096:  return 6
    return 4  # 4096+ bit RSA/DH


def _sensitivity_score(sensitivity: str) -> int:
    """Return sensitivity score for data confidentiality horizon."""
    return SENSITIVITY_SCORES.get(sensitivity.lower(), 5)


def _classify(qrs: float) -> tuple[str, bool, str]:
    """Return (risk_class, migration_required, recommendation) for a given QRS."""
    if qrs <= 3.0:
        return (
            "LOW",
            False,
            "No immediate action required. Classical cryptography is acceptable. "
            "Schedule review in 24 months.",
        )
    elif qrs <= 6.0:
        return (
            "MEDIUM",
            True,
            "Plan migration within 12–24 months. Implement Hybrid mode: "
            "Classical X25519 + ML-KEM-1024 + AES-256-GCM.",
        )
    else:
        return (
            "HIGH",
            True,
            "IMMEDIATE migration required. Deploy Triple-Hybrid mode: "
            "Classical + ML-KEM-1024 + QKD. This asset is vulnerable to HNDL attacks.",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_risk(profile: AssetProfile) -> RiskResult:
    """
    Evaluate quantum risk for a single cryptographic asset.

    Args:
        profile: AssetProfile with algorithm, key_size, sensitivity.

    Returns:
        RiskResult with QRS score, classification, and recommendation.
    """
    a = _algorithm_score(profile.algorithm)
    k = _key_score(profile.key_size, profile.algorithm)
    s = _sensitivity_score(profile.sensitivity)

    qrs = round(
        WEIGHTS["algorithm"] * a
        + WEIGHTS["key"] * k
        + WEIGHTS["sensitivity"] * s,
        2,
    )

    risk_class, migration_required, recommendation = _classify(qrs)

    result = RiskResult(
        asset=profile,
        a_score=a,
        k_score=k,
        s_score=s,
        qrs=qrs,
        risk_class=risk_class,
        migration_required=migration_required,
        recommendation=recommendation,
    )

    logger.info("Risk evaluated: %s", result)
    return result


def compute_risk_from_dict(d: dict) -> RiskResult:
    """Convenience wrapper accepting a plain dict."""
    return compute_risk(AssetProfile.from_dict(d))


def batch_evaluate(profiles: list[dict]) -> list[RiskResult]:
    """Evaluate a list of asset profile dicts and return sorted results (highest QRS first)."""
    results = [compute_risk_from_dict(p) for p in profiles]
    return sorted(results, key=lambda r: r.qrs, reverse=True)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  QUANTUM RISK ASSESSMENT ENGINE — Demonstration")
    print("=" * 65)

    test_assets = [
        {"algorithm": "RSA",     "key_size": 1024, "sensitivity": "high",   "description": "Legacy VPN certificate"},
        {"algorithm": "RSA",     "key_size": 2048, "sensitivity": "high",   "description": "TLS server certificate"},
        {"algorithm": "ECC",     "key_size": 256,  "sensitivity": "medium", "description": "Client authentication key"},
        {"algorithm": "AES-256", "key_size": 256,  "sensitivity": "medium", "description": "Symmetric data encryption"},
        {"algorithm": "AES-128", "key_size": 128,  "sensitivity": "high",   "description": "Legacy encrypted archive"},
        {"algorithm": "ML-KEM",  "key_size": 1024, "sensitivity": "high",   "description": "Post-quantum KEM"},
        {"algorithm": "DH",      "key_size": 2048, "sensitivity": "low",    "description": "Ephemeral key exchange"},
    ]

    results = batch_evaluate(test_assets)

    print(f"\n{'Algorithm':<12} {'Key':>6} {'Sens.':<8} {'A':>4} {'K':>4} {'S':>4} {'QRS':>6}  {'Risk':<8} {'Migrate'}")
    print("-" * 75)
    for r in results:
        print(
            f"{r.asset.algorithm:<12} {r.asset.key_size:>6} {r.asset.sensitivity:<8} "
            f"{r.a_score:>4} {r.k_score:>4} {r.s_score:>4} {r.qrs:>6.2f}  "
            f"{r.risk_class:<8} {'✓' if r.migration_required else '—'}"
        )

    print("\n[Top Priority Asset]")
    top = results[0]
    print(f"  {top.asset.description}: {top.recommendation}")
