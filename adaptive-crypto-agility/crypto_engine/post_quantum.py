"""
post_quantum.py
===============
Post-Quantum Cryptography Primitives

Implements NIST-standardised post-quantum algorithms via LibOQS:
  - ML-KEM-1024 (formerly Kyber1024) — Key Encapsulation Mechanism (FIPS 203)
  - ML-DSA-65   (formerly Dilithium3) — Digital Signature (FIPS 204)

Security Properties:
  - ML-KEM-1024: 256-bit quantum security level (breaks require 2^128 operations
    even with Grover's algorithm applied to AES-256-GCM)
  - ML-DSA-65: Module-Lattice based, secure against known quantum algorithms

Fallback Mode:
  If liboqs-python is not installed, a mock implementation is provided so the
  rest of the system can run for demonstration purposes. Install liboqs for
  real post-quantum operations.

Installation:
    # Build LibOQS C library first (see docs/lab_setup.md), then:
    pip install liboqs-python
"""

import os
import hashlib
import logging
from dataclasses import dataclass
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LibOQS import with graceful fallback
# ---------------------------------------------------------------------------
try:
    import oqs
    OQS_AVAILABLE = True
    logger.info("liboqs-python loaded — real PQC operations active.")
except ImportError:
    OQS_AVAILABLE = False
    logger.warning(
        "liboqs-python NOT installed. Using mock PQC for demonstration.\n"
        "Install: pip install liboqs-python (requires LibOQS C library).\n"
        "See docs/lab_setup.md for full build instructions."
    )

KEM_ALGORITHM = "Kyber1024"       # NIST FIPS 203 ML-KEM-1024
SIG_ALGORITHM = "Dilithium3"      # NIST FIPS 204 ML-DSA-65


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class KEMResult:
    """Result of a PQ KEM key exchange."""
    shared_secret: bytes      # 32-byte shared secret
    public_key: bytes
    ciphertext: bytes
    algorithm: str
    is_mock: bool = False


@dataclass
class SignatureResult:
    """Result of a PQ digital signature operation."""
    signature: bytes
    public_key: bytes
    algorithm: str
    is_mock: bool = False


# ---------------------------------------------------------------------------
# ML-KEM-1024 (Kyber) — Key Encapsulation
# ---------------------------------------------------------------------------

def pq_kem_keygen() -> Tuple[bytes, bytes]:
    """
    Generate an ML-KEM-1024 keypair on the server side.

    Returns:
        Tuple of (public_key_bytes, secret_key_bytes)
    """
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return public_key, secret_key
    else:
        # Mock: deterministic-looking random keys for demo
        pk = os.urandom(1568)   # Kyber1024 public key size
        sk = os.urandom(3168)   # Kyber1024 secret key size
        logger.debug("Mock ML-KEM keygen (liboqs not available)")
        return pk, sk


def pq_kem_encap(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Client encapsulates a shared secret using the server's public key.

    Args:
        public_key: Server's ML-KEM-1024 public key bytes

    Returns:
        Tuple of (ciphertext, shared_secret)
    """
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret
    else:
        ct = os.urandom(1568)   # Kyber1024 ciphertext size
        ss = os.urandom(32)     # 256-bit shared secret
        return ct, ss


def pq_kem_decap(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Server decapsulates to recover the shared secret.

    Args:
        ciphertext:  Ciphertext received from client
        secret_key:  Server's ML-KEM-1024 secret key bytes

    Returns:
        shared_secret (32 bytes)
    """
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
    else:
        # Mock: deterministic hash of ciphertext as stand-in
        return hashlib.sha256(ciphertext[:32]).digest()


def pq_kem_exchange() -> KEMResult:
    """
    Convenience wrapper: simulate a full ML-KEM-1024 exchange in one call.
    Generates keypair, encapsulates, and decapsulates to verify consistency.

    Returns:
        KEMResult with the shared secret and exchange artifacts.
    """
    public_key, secret_key = pq_kem_keygen()
    ciphertext, client_ss = pq_kem_encap(public_key)
    server_ss = pq_kem_decap(ciphertext, secret_key)

    if OQS_AVAILABLE:
        assert client_ss == server_ss, "ML-KEM shared secret mismatch!"

    logger.debug(
        "ML-KEM-1024 exchange complete | ss=%s... | mock=%s",
        client_ss.hex()[:16], not OQS_AVAILABLE
    )

    return KEMResult(
        shared_secret=client_ss,
        public_key=public_key,
        ciphertext=ciphertext,
        algorithm=KEM_ALGORITHM,
        is_mock=not OQS_AVAILABLE,
    )


# ---------------------------------------------------------------------------
# ML-DSA-65 (Dilithium) — Digital Signatures
# ---------------------------------------------------------------------------

def pq_sign(message: bytes) -> SignatureResult:
    """
    Sign a message using ML-DSA-65 (Dilithium3).

    Args:
        message: Raw bytes to sign

    Returns:
        SignatureResult with signature and public key.
    """
    if OQS_AVAILABLE:
        with oqs.Signature(SIG_ALGORITHM) as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(message)
        return SignatureResult(
            signature=signature,
            public_key=public_key,
            algorithm=SIG_ALGORITHM,
            is_mock=False,
        )
    else:
        # Mock signature
        sig = hashlib.sha512(message).digest() + os.urandom(2388)
        pk  = os.urandom(1952)
        return SignatureResult(
            signature=sig,
            public_key=pk,
            algorithm=SIG_ALGORITHM,
            is_mock=True,
        )


def pq_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an ML-DSA-65 signature.

    Args:
        message:    Original message bytes
        signature:  Signature to verify
        public_key: Signer's public key

    Returns:
        True if valid, False otherwise.
    """
    if OQS_AVAILABLE:
        with oqs.Signature(SIG_ALGORITHM) as verifier:
            return verifier.verify(message, signature, public_key)
    else:
        # Mock: always valid in demo mode
        return True


# ---------------------------------------------------------------------------
# CLI / Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[ML-KEM-1024 Key Exchange]")
    result = pq_kem_exchange()
    print(f"  Algorithm     : {result.algorithm}")
    print(f"  Shared Secret : {result.shared_secret.hex()}")
    print(f"  Secret Bits   : {len(result.shared_secret) * 8}")
    print(f"  Public Key    : {len(result.public_key)} bytes")
    print(f"  Ciphertext    : {len(result.ciphertext)} bytes")
    print(f"  Mode          : {'REAL PQC' if not result.is_mock else 'MOCK (install liboqs)'}")

    print("\n[ML-DSA-65 Digital Signature]")
    msg = b"Enterprise authentication payload - signed by server"
    sig_result = pq_sign(msg)
    valid = pq_verify(msg, sig_result.signature, sig_result.public_key)
    print(f"  Algorithm     : {sig_result.algorithm}")
    print(f"  Signature     : {len(sig_result.signature)} bytes")
    print(f"  Verification  : {'VALID ✓' if valid else 'INVALID ✗'}")
    print(f"  Mode          : {'REAL PQC' if not sig_result.is_mock else 'MOCK (install liboqs)'}")
