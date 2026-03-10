"""
hybrid_combiner.py
==================
Hybrid Key Combiner — Triple-Hybrid Session Key Derivation

Combines shared secrets from multiple cryptographic sources into a single
unified session key using HKDF-SHA256, following the concatenation-based
approach standardised in TLS 1.3 (RFC 8446) and IETF hybrid key exchange
draft (draft-ietf-tls-hybrid-design).

Approach: Concatenation (TLS 1.3 standard)
    IKM = SS_classical ‖ SS_pq ‖ SS_qkd      (96 bytes total)
    PRK = HKDF-Extract(salt=None, IKM)
    OKM = HKDF-Expand(PRK, info=b"...", L=32)

Security Guarantee (from Rubio García et al., IEEE JSAC 2025):
    The session key is secure as long as at least ONE of the three
    cryptographic assumptions holds. All three must be broken simultaneously
    for the key to be compromised.

Modes supported:
    CLASSICAL      — 1 secret:  classical ECDH only
    HYBRID         — 2 secrets: ECDH + ML-KEM-1024
    TRIPLE_HYBRID  — 3 secrets: ECDH + ML-KEM-1024 + QKD

Symmetric encryption: AES-256-GCM (quantum-safe per NIST with 256-bit keys)
"""

import os
import logging
from typing import List, Tuple
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .classical import classical_ecdh
from .post_quantum import pq_kem_exchange
from .qkd_simulation import simulated_qkd_key

logger = logging.getLogger(__name__)

HKDF_INFO = b"adaptive-crypto-agility-v1.0"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class SessionKey:
    """Derived session key and metadata."""
    key: bytes                  # 32-byte AES-256 session key
    mode: str                   # CLASSICAL / HYBRID / TRIPLE_HYBRID
    secrets_count: int          # Number of independent shared secrets combined
    key_size_bits: int = 256


@dataclass
class EncryptedPayload:
    """AES-256-GCM encrypted payload."""
    ciphertext: bytes
    nonce: bytes
    mode: str


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------

def hybrid_key_combiner(secrets: List[bytes], mode: str = "TRIPLE_HYBRID") -> SessionKey:
    """
    Combine multiple shared secrets into a single session key via HKDF-SHA256.

    Implements the concatenation approach:
        IKM = secret_0 ‖ secret_1 ‖ ... ‖ secret_n
        session_key = HKDF(IKM, info=HKDF_INFO, length=32)

    Args:
        secrets: List of shared secret byte strings (one per crypto source)
        mode:    String label for the selected mode

    Returns:
        SessionKey with 32-byte derived key
    """
    if not secrets:
        raise ValueError("At least one shared secret must be provided")

    ikm = b"".join(secrets)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )
    session_key = hkdf.derive(ikm)

    logger.debug(
        "Hybrid key combiner | mode=%s | secrets=%d | IKM_len=%d | key=%s...",
        mode, len(secrets), len(ikm), session_key.hex()[:16]
    )

    return SessionKey(
        key=session_key,
        mode=mode,
        secrets_count=len(secrets),
    )


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption / Decryption
# ---------------------------------------------------------------------------

def encrypt_aes_gcm(key: bytes, plaintext: str) -> EncryptedPayload:
    """
    Encrypt plaintext using AES-256-GCM with the derived session key.

    AES-256-GCM provides authenticated encryption (AEAD), protecting
    both confidentiality and integrity of the ciphertext.

    Args:
        key:       32-byte session key
        plaintext: String message to encrypt

    Returns:
        EncryptedPayload with ciphertext and nonce
    """
    nonce = os.urandom(12)   # 96-bit nonce (GCM standard)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return EncryptedPayload(ciphertext=ciphertext, nonce=nonce, mode="AES-256-GCM")


def decrypt_aes_gcm(key: bytes, payload: EncryptedPayload) -> str:
    """
    Decrypt an AES-256-GCM payload.

    Args:
        key:     32-byte session key (must match encryption key)
        payload: EncryptedPayload from encrypt_aes_gcm

    Returns:
        Decrypted plaintext string
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(payload.nonce, payload.ciphertext, None)
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Mode-aware Secure Communication Simulation
# ---------------------------------------------------------------------------

def run_secure_communication(mode: str, message: str) -> dict:
    """
    Execute a full secure communication simulation for the given mode.

    Collects shared secrets based on the mode, derives the session key
    via HKDF, encrypts a message, and decrypts it to verify correctness.

    Args:
        mode:    One of CLASSICAL, HYBRID, TRIPLE_HYBRID
        message: Plaintext to encrypt

    Returns:
        Dict with mode, session key hex, ciphertext hex, decrypted text, and status
    """
    secrets = []
    components = []

    # 1. Classical ECDH (always included)
    ecdh = classical_ecdh()
    secrets.append(ecdh.shared_secret)
    components.append("X25519 ECDH")

    # 2. ML-KEM-1024 (Hybrid + Triple-Hybrid)
    if mode in ("HYBRID", "TRIPLE_HYBRID"):
        pq = pq_kem_exchange()
        secrets.append(pq.shared_secret)
        components.append(f"ML-KEM-1024{'(mock)' if pq.is_mock else ''}")

    # 3. Simulated QKD (Triple-Hybrid only)
    if mode == "TRIPLE_HYBRID":
        qkd = simulated_qkd_key()
        secrets.append(qkd.key)
        components.append("QKD(simulated)")

    # 4. Derive unified session key
    session = hybrid_key_combiner(secrets, mode=mode)

    # 5. Encrypt and decrypt
    payload = encrypt_aes_gcm(session.key, message)
    decrypted = decrypt_aes_gcm(session.key, payload)

    success = decrypted == message

    return {
        "mode": mode,
        "components": components,
        "secrets_combined": len(secrets),
        "session_key": session.key.hex(),
        "ciphertext_hex": payload.ciphertext.hex()[:32] + "...",
        "decrypted": decrypted,
        "success": success,
    }


# ---------------------------------------------------------------------------
# CLI / Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    MESSAGE = "Confidential enterprise data — quantum-resilient transmission."

    print("\n" + "=" * 65)
    print("  HYBRID KEY COMBINER — SECURE COMMUNICATION DEMO")
    print("=" * 65)

    for mode in ["CLASSICAL", "HYBRID", "TRIPLE_HYBRID"]:
        result = run_secure_communication(mode, MESSAGE)
        status = "✓ OK" if result["success"] else "✗ FAIL"
        print(f"\n[{mode}]  {status}")
        print(f"  Components   : {' + '.join(result['components'])}")
        print(f"  Secrets Used : {result['secrets_combined']}")
        print(f"  Session Key  : {result['session_key'][:32]}...")
        print(f"  Ciphertext   : {result['ciphertext_hex']}")
        print(f"  Decrypted    : {result['decrypted']}")

    print("\n" + "=" * 65)
