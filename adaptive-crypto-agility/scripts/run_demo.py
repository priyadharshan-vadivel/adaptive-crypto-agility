"""
run_demo.py
===========
Full end-to-end demonstration of the Adaptive Crypto-Agility Decision System.
Runs all modules in sequence — no server/client networking required.

Usage:
    python scripts/run_demo.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client.asset_scanner import SAMPLE_ENTERPRISE_ASSETS
from risk_engine.risk_engine import batch_evaluate
from risk_engine.decision_engine import batch_decide
from crypto_engine.crypto_comm import run_secure_communication, ml_dsa_sign_verify

CYAN  = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
RED   = "\033[91m"; BOLD  = "\033[1m";  RESET  = "\033[0m"

def title(text):
    print(f"\n{BOLD}{CYAN}{'━'*65}")
    print(f"  {text}")
    print(f"{'━'*65}{RESET}")

def step(n, text):
    print(f"\n{YELLOW}{BOLD}  STEP {n}: {text}{RESET}")
    print(f"  {'─'*55}")

def ok(text):
    print(f"  {GREEN}✓{RESET}  {text}")

if __name__ == "__main__":
    title("ADAPTIVE CRYPTO-AGILITY DECISION SYSTEM — Full Demo")
    print(f"  Quantum-Resilient Network Security | Sri Krishna College of Technology")

    # ── Step 1: Asset Inventory ──────────────────────────────────────────
    step(1, "Cryptographic Asset Inventory")
    print(f"\n  {'#':<3} {'Algorithm':<10} {'Key':>5} {'Sens.':<8} {'Description'}")
    print(f"  {'─'*62}")
    for i, a in enumerate(SAMPLE_ENTERPRISE_ASSETS, 1):
        print(f"  {i:<3} {a['algorithm']:<10} {a['key_size']:>5} {a['sensitivity']:<8} {a['description']}")
    ok(f"{len(SAMPLE_ENTERPRISE_ASSETS)} assets inventoried")

    # ── Step 2: Risk Evaluation ──────────────────────────────────────────
    step(2, "Quantum Risk Assessment (QRS scoring)")
    results = batch_evaluate(SAMPLE_ENTERPRISE_ASSETS)
    print(f"\n  {'Algorithm':<10} {'Key':>5} {'Sens.':<8} {'A':>4} {'K':>4} {'S':>4} {'QRS':>6}  {'Risk':<8} {'Migrate'}")
    print(f"  {'─'*65}")
    for r in results:
        mc = RED if r.risk_class=="HIGH" else YELLOW if r.risk_class=="MEDIUM" else GREEN
        print(
            f"  {r.asset.algorithm:<10} {r.asset.key_size:>5} {r.asset.sensitivity:<8} "
            f"{r.a_score:>4} {r.k_score:>4} {r.s_score:>4} {r.qrs:>6.2f}  "
            f"{mc}{r.risk_class:<8}{RESET} {'✓ REQUIRED' if r.migration_required else '—'}"
        )
    high = sum(1 for r in results if r.risk_class=="HIGH")
    med  = sum(1 for r in results if r.risk_class=="MEDIUM")
    ok(f"Risk distribution: {high} HIGH, {med} MEDIUM, {len(results)-high-med} LOW")

    # ── Step 3: Mode Decision ────────────────────────────────────────────
    step(3, "Crypto-Agility Mode Decision")
    decisions = batch_decide(SAMPLE_ENTERPRISE_ASSETS)
    MODE_COLOR = {"CLASSICAL": GREEN, "HYBRID": YELLOW, "TRIPLE_HYBRID": RED}
    print(f"\n  {'Description':<36} {'QRS':>5}  {'Mode':<16} {'Quantum-Safe'}")
    print(f"  {'─'*70}")
    for d in decisions:
        mc = MODE_COLOR.get(d.mode, RESET)
        qs = f"{GREEN}YES ✓{RESET}" if d.mode_info["quantum_resistant"] else f"{RED}NO  ✗{RESET}"
        desc = (d.risk_result.asset.description or "")[:35]
        print(f"  {desc:<36} {d.qrs:>5.2f}  {mc}{d.mode:<16}{RESET} {qs}")
    ok("All assets assigned a cryptographic security mode")

    # ── Step 4: Crypto Communication ─────────────────────────────────────
    step(4, "Hybrid Key Exchange & Secure Communication")
    payload = "Confidential enterprise payload — quantum-resilient session."
    for mode in ["CLASSICAL", "HYBRID", "TRIPLE_HYBRID"]:
        r = run_secure_communication(mode, payload)
        mc = MODE_COLOR.get(mode, RESET)
        print(f"\n  {mc}[{mode}]{RESET}")
        print(f"    Sources   : {', '.join(r.session_key.sources)}")
        print(f"    Deriv. ms : {r.session_key.derivation_time_ms:.3f}")
        print(f"    CT (hex)  : {r.ciphertext.hex()[:48]}...")
        print(f"    Decrypt   : {GREEN}✓ OK{RESET}" if r.success else f"    Decrypt   : {RED}✗ FAILED{RESET}")
    ok("All three modes demonstrated successfully")

    # ── Step 5: PQ Digital Signature ─────────────────────────────────────
    step(5, "Post-Quantum Digital Signature (ML-DSA-65 / Dilithium3)")
    msg = b"Authenticated enterprise transaction — digitally signed"
    sig = ml_dsa_sign_verify(msg)
    print(f"\n  Algorithm   : {sig['algorithm']}")
    print(f"  Sig length  : {sig['signature_len']} bytes")
    print(f"  Valid       : {GREEN}✓ YES{RESET}" if sig["valid"] else f"  Valid       : {RED}✗ NO{RESET}")
    print(f"  Simulated   : {sig['simulated']}")
    ok("Digital signature verified")

    # ── Summary ───────────────────────────────────────────────────────────
    title("DEMO COMPLETE — Summary")
    print(f"  {GREEN}✓{RESET} {len(SAMPLE_ENTERPRISE_ASSETS)} assets scanned and risk-scored")
    print(f"  {GREEN}✓{RESET} Adaptive mode selection: CLASSICAL / HYBRID / TRIPLE_HYBRID")
    print(f"  {GREEN}✓{RESET} Hybrid HKDF key combiner: up to 3 independent shared secrets")
    print(f"  {GREEN}✓{RESET} AES-256-GCM authenticated encryption on all modes")
    print(f"  {GREEN}✓{RESET} ML-KEM-1024 (Kyber) + ML-DSA-65 (Dilithium) PQC integration")
    print(f"  {GREEN}✓{RESET} Simulated QKD for Triple-Hybrid information-theoretic security")
    print(f"\n  Run {CYAN}scripts/attack_simulation.py{RESET} for attack defense scenarios.")
    print(f"  Run {CYAN}server/server.py{RESET} + {CYAN}client/client.py{RESET} for networked demo.\n")
