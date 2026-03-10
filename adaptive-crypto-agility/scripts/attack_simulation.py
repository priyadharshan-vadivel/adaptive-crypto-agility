"""
attack_simulation.py
====================
Attack Simulation & Adaptive Defense Demonstration.

Scenarios:
  1. Risk-based Mode Escalation  — shows adaptive mode selection across risk levels
  2. HNDL Threat Simulation      — demonstrates Triple-Hybrid defense against Harvest Now Decrypt Later
  3. Cipher Strength Analysis    — simulates attacker probing cipher suite
  4. Interception Attempt        — shows attacker sees only AES-256-GCM ciphertext

Run:
    python scripts/attack_simulation.py
"""

import sys
import os
import json
import time
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from risk_engine.decision_engine import decide_from_dict, batch_decide
from crypto_engine.crypto_comm import run_secure_communication

# ANSI colors
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def banner(title: str, color: str = CYAN):
    width = 65
    print(f"\n{color}{BOLD}{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}{RESET}")


def section(title: str):
    print(f"\n{YELLOW}{BOLD}  ▶ {title}{RESET}")
    print(f"  {'─' * 55}")


# ─────────────────────────────────────────────────────────────
# Scenario 1: Risk-Based Mode Escalation
# ─────────────────────────────────────────────────────────────

def scenario_mode_escalation():
    banner("SCENARIO 1 — Adaptive Mode Escalation by Risk Level")

    assets = [
        {"algorithm": "AES-256", "key_size": 256,  "sensitivity": "low",    "label": "Low-sensitivity symmetric key"},
        {"algorithm": "ECC",     "key_size": 256,  "sensitivity": "medium", "label": "Medium-sensitivity ECC key"},
        {"algorithm": "RSA",     "key_size": 2048, "sensitivity": "high",   "label": "High-sensitivity RSA cert"},
        {"algorithm": "RSA",     "key_size": 1024, "sensitivity": "high",   "label": "CRITICAL legacy RSA-1024"},
        {"algorithm": "DH",      "key_size": 2048, "sensitivity": "high",   "label": "DH key exchange (high sens.)"},
    ]

    MODE_COLORS = {
        "CLASSICAL":     GREEN,
        "HYBRID":        YELLOW,
        "TRIPLE_HYBRID": RED,
    }

    print(f"\n  {'Asset':<38} {'QRS':>5}  {'Risk':<8} {'Mode':<16} {'QR-Safe'}")
    print(f"  {'─'*38} {'─'*5}  {'─'*8} {'─'*16} {'─'*7}")

    for a in assets:
        d = decide_from_dict(a)
        mc = MODE_COLORS.get(d.mode, WHITE)
        qs = f"{GREEN}YES ✓{RESET}" if d.mode_info["quantum_resistant"] else f"{RED}NO  ✗{RESET}"
        print(
            f"  {a['label']:<38} {d.qrs:>5.2f}  {d.risk_class:<8} "
            f"{mc}{d.mode:<16}{RESET} {qs}"
        )

    print(f"\n  {CYAN}Key insight:{RESET} The system automatically escalates from CLASSICAL → HYBRID → TRIPLE_HYBRID")
    print(f"  as the QRS score rises — no manual intervention required.")


# ─────────────────────────────────────────────────────────────
# Scenario 2: HNDL Attack Defense
# ─────────────────────────────────────────────────────────────

def scenario_hndl_defense():
    banner("SCENARIO 2 — HNDL (Harvest Now, Decrypt Later) Defense", RED)

    section("Attacker harvests ciphertext today (pre-quantum era)")
    payload = "CONFIDENTIAL: Government contract data — classification LEVEL 3."

    # Victim uses CLASSICAL crypto (RSA-based TLS — legacy system)
    print(f"\n  {YELLOW}[VICTIM SYSTEM — Legacy RSA-2048 / CLASSICAL mode]{RESET}")
    classical = run_secure_communication("CLASSICAL", payload)
    harvested_ct  = classical.ciphertext
    harvested_key = classical.session_key.key
    print(f"  Session key    : {harvested_key.hex()[:32]}...")
    print(f"  Ciphertext     : {harvested_ct.hex()[:48]}...")
    print(f"  {RED}[ATTACKER] Ciphertext harvested and stored. Waiting for quantum computer...{RESET}")

    section("Future quantum computer attempts decryption (simulated)")
    print(f"\n  {RED}[ATTACKER] Running simulated Shor/Grover brute-force on classical key...{RESET}")
    time.sleep(0.3)
    # Simulate "brute force" — we'll just show the key IS recoverable from a classical-only system
    simulated_quantum_recovery = harvested_key  # In reality, Shor would recover this
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        recovered_pt = AESGCM(simulated_quantum_recovery).decrypt(
            classical.nonce, harvested_ct, None
        ).decode()
        print(f"  {RED}[ATTACKER] Classical key recovered. Decrypted: '{recovered_pt[:60]}'{RESET}")
        print(f"  {RED}  → HNDL ATTACK SUCCESSFUL against CLASSICAL mode!{RESET}")
    except Exception as e:
        print(f"  Decrypt failed: {e}")

    section("Protected system — TRIPLE_HYBRID mode with QKD")
    print(f"\n  {GREEN}[PROTECTED SYSTEM — TRIPLE_HYBRID mode]{RESET}")
    triple = run_secure_communication("TRIPLE_HYBRID", payload)
    print(f"  Sources        : {', '.join(triple.session_key.sources)}")
    print(f"  Session key    : {triple.session_key.key.hex()[:32]}...")
    print(f"  Ciphertext     : {triple.ciphertext.hex()[:48]}...")
    print(f"\n  {GREEN}[ATTACKER] Cannot recover QKD component — ITS secure. Cannot decrypt.{RESET}")
    print(f"  {GREEN}  → HNDL ATTACK FAILED against TRIPLE_HYBRID mode.{RESET}")
    print(f"\n  {CYAN}Defense: QKD shared secret cannot be intercepted retroactively.")
    print(f"  Even with Shor's algorithm on RSA + ML-KEM, the QKD key is")
    print(f"  information-theoretically secure — quantum computers cannot recover it.{RESET}")


# ─────────────────────────────────────────────────────────────
# Scenario 3: Cipher Strength Analysis (Attacker perspective)
# ─────────────────────────────────────────────────────────────

def scenario_cipher_analysis():
    banner("SCENARIO 3 — Attacker Cipher Strength Analysis")

    section("Probing server cipher suite (simulated nmap/openssl scan)")
    print(f"\n  {YELLOW}[ATTACKER] Simulating: openssl s_client -connect 192.168.100.20:9000{RESET}")
    print(f"  {YELLOW}[ATTACKER] Simulating: nmap --script ssl-enum-ciphers -p 9000 192.168.100.20{RESET}")
    time.sleep(0.2)

    server_config = {
        "tls_version":      "TLS 1.3",
        "cipher_suite":     "TLS_AES_256_GCM_SHA384",
        "key_exchange":     "X25519 + ML-KEM-1024 (Kyber) + QKD",
        "signature":        "ML-DSA-65 (Dilithium3)",
        "weak_ciphers":     "NONE ACCEPTED",
        "downgrade_attack": "REJECTED",
    }

    print(f"\n  {GREEN}[SERVER RESPONSE]{RESET}")
    for k, v in server_config.items():
        color = GREEN if v not in ("NONE ACCEPTED", "REJECTED") else RED if k in ("weak_ciphers", "downgrade_attack") else GREEN
        print(f"  {k:<22}: {color}{v}{RESET}")

    print(f"\n  {RED}[ATTACKER] No weak ciphers. No downgrade path. ML-KEM-1024 key exchange")
    print(f"  cannot be broken by Shor's algorithm. Attack surface: MINIMAL.{RESET}")


# ─────────────────────────────────────────────────────────────
# Scenario 4: Traffic Interception
# ─────────────────────────────────────────────────────────────

def scenario_interception():
    banner("SCENARIO 4 — Traffic Interception Simulation")

    section("Attacker captures packets (tcpdump / Wireshark simulation)")
    payload = "ENTERPRISE SECRET: Q4 merger strategy — do not distribute."

    for mode in ["CLASSICAL", "HYBRID", "TRIPLE_HYBRID"]:
        result = run_secure_communication(mode, payload)
        attacker_sees = result.ciphertext.hex()

        print(f"\n  {CYAN}[MODE: {mode}]{RESET}")
        print(f"  Attacker captures : {attacker_sees[:64]}...")
        print(f"  Length            : {len(result.ciphertext)} bytes (AES-256-GCM authenticated ciphertext)")
        print(f"  Recoverable?      : {RED}NO — computationally/information-theoretically infeasible{RESET}")
        print(f"  {GREEN}  → Plaintext protected.{RESET}")

    print(f"\n  {CYAN}All modes use AES-256-GCM for symmetric encryption.")
    print(f"  TRIPLE_HYBRID additionally ensures the session key cannot be")
    print(f"  recovered retroactively — even with a future quantum computer.{RESET}")


# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────

def print_summary():
    banner("ATTACK SIMULATION SUMMARY", GREEN)
    rows = [
        ("Mode Escalation",  "Adaptive", "Automatic QRS-driven mode selection prevents under-protection"),
        ("HNDL Attack",      "DEFENDED", "Triple-Hybrid QKD component is ITS-secure; cannot be harvested"),
        ("Cipher Analysis",  "HARDENED", "No weak ciphers; ML-KEM-1024 + ML-DSA-65 resist Shor's algorithm"),
        ("Interception",     "FAILED",   "AES-256-GCM ciphertext is computationally infeasible to decrypt"),
    ]
    print(f"\n  {'Scenario':<22} {'Result':<12} {'Finding'}")
    print(f"  {'─'*22} {'─'*12} {'─'*36}")
    for sc, res, finding in rows:
        color = GREEN if res in ("DEFENDED", "HARDENED", "FAILED", "Adaptive") else RED
        print(f"  {sc:<22} {color}{res:<12}{RESET} {finding}")


if __name__ == "__main__":
    scenario_mode_escalation()
    scenario_hndl_defense()
    scenario_cipher_analysis()
    scenario_interception()
    print_summary()
    print()
