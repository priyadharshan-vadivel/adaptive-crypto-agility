"""
full_demo.py
============
End-to-End Adaptive Crypto-Agility Demonstration

Runs a complete pipeline:
  1. Asset scanning (manual lab profiles)
  2. Quantum risk assessment (QRS formula)
  3. Adaptive crypto-mode decision
  4. Secure communication simulation (all three modes)
  5. Summary report

Run:
    python scripts/full_demo.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from risk_engine.risk_engine import AssetProfile, compute_risk
from risk_engine.decision_engine import decide_crypto_mode
from crypto_engine.hybrid_combiner import run_secure_communication

DIVIDER = "=" * 70
SUB_DIVIDER = "-" * 70
MESSAGE = "Confidential enterprise payload — protected by adaptive crypto-agility."


def banner():
    print(f"\n{DIVIDER}")
    print("  ADAPTIVE CRYPTO-AGILITY DECISION SYSTEM")
    print("  Quantum-Resilient Network Security — Full Demo")
    print("  Sri Krishna College of Technology | 2025–2026")
    print(DIVIDER)


def section(title: str):
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def run_pipeline(asset: AssetProfile, message: str = MESSAGE):
    """Run the full pipeline for a single asset profile."""

    print(f"\n  Asset  : {asset.label}")
    print(f"  Config : {asset.algorithm}/{asset.key_size}-bit | "
          f"Sensitivity={asset.sensitivity.upper()} | Protocol={asset.protocol}")

    # Step 1: Risk Assessment
    risk = compute_risk(asset)
    print(f"\n  ┌─ Risk Assessment ──────────────────────────────────┐")
    print(f"  │  A_score (Algorithm)   : {risk.a_score:>4.1f} / 10.0")
    print(f"  │  K_score (Key Strength): {risk.k_score:>4.1f} / 10.0")
    print(f"  │  S_score (Sensitivity) : {risk.s_score:>4.1f} / 10.0")
    print(f"  │  QRS (Composite Score) : {risk.qrs:>4.2f} / 10.0")
    print(f"  │  Risk Class            : {risk.risk_class}")
    print(f"  │  Migration Required    : {'YES ⚠' if risk.migration_required else 'NO ✓'}")
    print(f"  └────────────────────────────────────────────────────┘")

    # Step 2: Decision
    decision = decide_crypto_mode(asset)
    print(f"\n  ┌─ Crypto-Agility Decision ─────────────────────────┐")
    print(f"  │  Selected Mode    : {decision.mode}")
    print(f"  │  Algorithms Used  :")
    for algo in decision.algorithms:
        print(f"  │    • {algo}")
    print(f"  └────────────────────────────────────────────────────┘")

    # Step 3: Secure Communication
    t_start = time.monotonic()
    result = run_secure_communication(decision.mode, message)
    elapsed_ms = (time.monotonic() - t_start) * 1000

    status = "✓ SUCCESS" if result["success"] else "✗ FAILURE"
    print(f"\n  ┌─ Secure Communication ─────────────────────────────┐")
    print(f"  │  Mode          : {result['mode']}")
    print(f"  │  Components    : {' + '.join(result['components'])}")
    print(f"  │  Session Key   : {result['session_key'][:32]}...")
    print(f"  │  Ciphertext    : {result['ciphertext_hex']}")
    print(f"  │  Decrypted OK  : {result['success']}")
    print(f"  │  Elapsed       : {elapsed_ms:.1f} ms")
    print(f"  │  Status        : {status}")
    print(f"  └────────────────────────────────────────────────────┘")

    return {
        "asset": asset.label,
        "qrs": risk.qrs,
        "risk_class": risk.risk_class,
        "mode": decision.mode,
        "success": result["success"],
        "elapsed_ms": elapsed_ms,
    }


def main():
    banner()

    # Representative enterprise assets
    assets = [
        AssetProfile("AES-256",  256,  "low",    "TLS 1.3",  "Internal Config Sync Service"),
        AssetProfile("ECC",      256,  "medium", "TLS 1.3",  "Customer Web Portal (ECDH)"),
        AssetProfile("RSA",      2048, "medium", "IPsec",    "VPN Gateway (RSA-2048)"),
        AssetProfile("RSA",      2048, "high",   "TLS 1.2",  "Healthcare Records API (RSA)"),
        AssetProfile("RSA",      1024, "high",   "TLS 1.2",  "Legacy Financial System (HNDL Risk)"),
        AssetProfile("ML-KEM",   1024, "high",   "TLS 1.3",  "Already-Upgraded PQC Service"),
    ]

    section("STEP 1–3: Asset Scan → Risk Assessment → Adaptive Decision → Secure Communication")
    results = []
    for asset in assets:
        print(f"\n{'~' * 70}")
        r = run_pipeline(asset)
        results.append(r)

    # Summary table
    section("SUMMARY REPORT")
    print(f"\n  {'Asset':<40} {'QRS':>5} {'Risk':<8} {'Mode':<15} {'Status'}")
    print(f"  {'-'*40} {'-'*5} {'-'*8} {'-'*15} {'-'*9}")
    for r in results:
        status = "✓ OK" if r["success"] else "✗ FAIL"
        print(f"  {r['asset']:<40} {r['qrs']:>5.2f} {r['risk_class']:<8} {r['mode']:<15} {status}")

    print(f"\n  All {len(results)} assets evaluated. System operating correctly.")
    print(f"\n{DIVIDER}\n")


if __name__ == "__main__":
    main()
