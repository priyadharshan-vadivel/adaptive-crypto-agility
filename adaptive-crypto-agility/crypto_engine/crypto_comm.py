"""
crypto_comm.py
==============
Cryptographic Communication Module.

Implements three security modes using a hybrid key combiner:

  CLASSICAL      — X25519 ECDH only
  HYBRID         — X25519 ECDH + ML-KEM-1024 (Kyber)
  TRIPLE_HYBRID  — X25519 ECDH + ML-KEM-1024 + Simulated QKD

All modes derive a final 256-bit session key via HKDF-SHA256
(concatenation approach, per TLS 1.3 RFC 8446 key schedule),
then encrypt payloads with AES-256-GCM.

References:
    - NIST FIPS 203  (ML-KEM / Kyber)
    - IETF RFC 8446  (TLS 1.3 HKDF key schedule)
    - Rubio García et al., IEEE JSAC 2025 (Triple-hybrid protocol)
    - ETSI GS QKD 014 (QKD REST API — simulated here)
"""

from __future__ import annotations
import os
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Try to import liboqs; degrade gracefully if not installed
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    logging.warning(
        "liboqs-python not found. ML-KEM/Dilithium operations will be SIMULATED. "
        "Install: pip install liboqs-python"
    )

logger = logging.getLogger(__name__)

HKDF_INFO = b"adaptive-crypto-agility-v1"
KEY_SIZE   = 32   # 256-bit session key
NONCE_SIZE = 12   # 96-bit GCM nonce


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SharedSecret:
    """A named shared secret from one cryptographic source."""
    source: str        # e.g. "CLASSICAL", "ML-KEM-1024", "QKD"
    secret: bytes
    size_bits: int = field(init=False)

    def __post_init__(self):
        self.size_bits = len(self.secret) * 8

    def __repr__(self):
        return f"SharedSecret(source={self.source}, size={self.size_bits}-bit)"


@dataclass
class SessionKey:
    """Derived session key and metadata from hybrid combiner."""
    key: bytes
    sources: list[str]
    mode: str
    derivation_time_ms: float

    def __repr__(self):
        return (
            f"SessionKey(mode={self.mode}, "
            f"sources={self.sources}, "
            f"time={self.derivation_time_ms:.2f}ms)"
        )


@dataclass
class CommResult:
    """Result of one full encrypt/decrypt round-trip."""
    mode: str
    plaintext: str
    ciphertext: bytes
    nonce: bytes
    decrypted: str
    session_key: SessionKey
    success: bool

    def summary(self) -> str:
        return (
            f"[{self.mode}] "
            f"Secrets={len(self.session_key.sources)}  "
            f"Key={self.session_key.key.hex()[:16]}...  "
            f"CT_len={len(self.ciphertext)} bytes  "
            f"OK={'✓' if self.success else '✗'}"
        )


# ---------------------------------------------------------------------------
# Individual key exchange functions
# ---------------------------------------------------------------------------

def classical_x25519() -> SharedSecret:
    """
    Simulate X25519 ECDH key exchange between client and server.
    Both sides generate ephemeral key-pairs; shared secret is derived.
    """
    client_priv = X25519PrivateKey.generate()
    server_priv = X25519PrivateKey.generate()
    client_pub  = client_priv.public_key()
    server_pub  = server_priv.public_key()

    client_ss = client_priv.exchange(server_pub)
    server_ss = server_priv.exchange(client_pub)

    assert client_ss == server_ss, "X25519: shared secrets do not match!"
    logger.debug("X25519 shared secret: %s...", client_ss.hex()[:16])
    return SharedSecret(source="CLASSICAL-X25519", secret=client_ss)


def pq_mlkem1024() -> SharedSecret:
    """
    ML-KEM-1024 (Kyber) key encapsulation — NIST FIPS 203.

    Server generates keypair → Client encapsulates → Server decapsulates.
    Returns 32-byte (256-bit) shared secret.

    Falls back to os.urandom(32) if liboqs is not installed
    (for development/testing without PQC hardware).
    """
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation("Kyber1024") as server_kem:
            pub_key = server_kem.generate_keypair()
            with oqs.KeyEncapsulation("Kyber1024") as client_kem:
                ciphertext, client_ss = client_kem.encap_secret(pub_key)
            server_ss = server_kem.decap_secret(ciphertext)
        assert client_ss == server_ss, "ML-KEM: shared secrets do not match!"
        logger.debug("ML-KEM-1024 shared secret: %s...", client_ss.hex()[:16])
        return SharedSecret(source="ML-KEM-1024", secret=client_ss)
    else:
        logger.warning("ML-KEM-1024: liboqs not available — using SIMULATED secret.")
        sim = hashlib.sha256(b"SIMULATED_ML_KEM_1024_" + os.urandom(16)).digest()
        return SharedSecret(source="ML-KEM-1024-SIMULATED", secret=sim)


def simulated_qkd() -> SharedSecret:
    """
    Simulate a pre-distributed QKD shared secret.

    In a real deployment, this would call the ETSI GS QKD 014 REST API:
        GET https://<kms>/api/v1/keys/<sae_id>/enc_keys

    Here, we use a cryptographically random 256-bit value to represent
    the key already securely delivered by the QKD hardware (e.g., IDQ Clavis3).
    Both client and server would retrieve the same key via the key ID.
    """
    qkd_secret = os.urandom(KEY_SIZE)
    logger.debug("QKD simulated secret: %s...", qkd_secret.hex()[:16])
    return SharedSecret(source="QKD-SIMULATED", secret=qkd_secret)


def ml_dsa_sign_verify(message: bytes) -> dict:
    """
    ML-DSA-65 (Dilithium3) digital signature — NIST FIPS 204.

    Returns dict with signature, public_key, and verification result.
    Falls back to HMAC-SHA256 simulation if liboqs not available.
    """
    if OQS_AVAILABLE:
        with oqs.Signature("Dilithium3") as signer:
            public_key = signer.generate_keypair()
            signature  = signer.sign(message)
        with oqs.Signature("Dilithium3") as verifier:
            valid = verifier.verify(message, signature, public_key)
        return {
            "algorithm":    "ML-DSA-65 (Dilithium3)",
            "signature_len": len(signature),
            "public_key_len": len(public_key),
            "valid":         valid,
            "simulated":     False,
        }
    else:
        import hmac
        key = os.urandom(32)
        sig = hmac.new(key, message, hashlib.sha256).digest()
        return {
            "algorithm":    "HMAC-SHA256 (simulated ML-DSA-65)",
            "signature_len": len(sig),
            "public_key_len": len(key),
            "valid":         True,
            "simulated":     True,
        }


# ---------------------------------------------------------------------------
# Hybrid Key Combiner (TLS 1.3 concatenation approach)
# ---------------------------------------------------------------------------

def hybrid_key_combiner(secrets: list[SharedSecret]) -> tuple[bytes, float]:
    """
    Concatenate shared secrets and derive a unified 256-bit session key via HKDF-SHA256.

    Follows the TLS 1.3 concatenation approach (IETF draft-ietf-tls-hybrid-design):
        IKM = secret_1 || secret_2 || ... || secret_n
        K   = HKDF-SHA256(IKM, info="adaptive-crypto-agility-v1")

    Security: the output key is secure if ANY ONE of the input secrets is secure.
    This is the core defense-in-depth property of hybrid cryptography.
    """
    t0  = time.perf_counter()
    ikm = b"".join(s.secret for s in secrets)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=HKDF_INFO,
    )
    derived_key = hkdf.derive(ikm)
    elapsed_ms  = (time.perf_counter() - t0) * 1000

    logger.debug(
        "HKDF derived key from %d secret(s) in %.3f ms: %s...",
        len(secrets), elapsed_ms, derived_key.hex()[:16],
    )
    return derived_key, elapsed_ms


# ---------------------------------------------------------------------------
# AES-256-GCM Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)."""
    nonce = os.urandom(NONCE_SIZE)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ct


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """Decrypt AES-256-GCM ciphertext. Returns plaintext string."""
    pt = AESGCM(key).decrypt(nonce, ciphertext, None)
    return pt.decode("utf-8")


# ---------------------------------------------------------------------------
# High-level secure communication runner
# ---------------------------------------------------------------------------

def run_secure_communication(mode: str, payload: str = "Confidential enterprise data payload.") -> CommResult:
    """
    Execute a full key exchange + encrypt/decrypt cycle for the given mode.

    Args:
        mode:    One of "CLASSICAL", "HYBRID", "TRIPLE_HYBRID".
        payload: Plaintext string to encrypt.

    Returns:
        CommResult with full details of the operation.
    """
    mode = mode.upper()
    secrets: list[SharedSecret] = []

    # 1. Collect independent shared secrets based on mode
    secrets.append(classical_x25519())

    if mode in ("HYBRID", "TRIPLE_HYBRID"):
        secrets.append(pq_mlkem1024())

    if mode == "TRIPLE_HYBRID":
        secrets.append(simulated_qkd())

    # 2. Combine secrets into a single session key
    session_key_bytes, deriv_ms = hybrid_key_combiner(secrets)

    session_key = SessionKey(
        key=session_key_bytes,
        sources=[s.source for s in secrets],
        mode=mode,
        derivation_time_ms=deriv_ms,
    )

    # 3. Encrypt payload
    nonce, ciphertext = encrypt(session_key_bytes, payload)

    # 4. Decrypt and verify
    try:
        decrypted = decrypt(session_key_bytes, nonce, ciphertext)
        success   = decrypted == payload
    except Exception as e:
        decrypted = f"DECRYPT_ERROR: {e}"
        success   = False

    return CommResult(
        mode=mode,
        plaintext=payload,
        ciphertext=ciphertext,
        nonce=nonce,
        decrypted=decrypted,
        session_key=session_key,
        success=success,
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  CRYPTOGRAPHIC COMMUNICATION MODULE — Demonstration")
    print("=" * 65)

    payload = "TOP SECRET: Quantum-resilient enterprise data payload."

    for mode in ["CLASSICAL", "HYBRID", "TRIPLE_HYBRID"]:
        print(f"\n  Running mode: {mode}")
        print("  " + "-" * 50)
        result = run_secure_communication(mode, payload)
        print(f"  {result.summary()}")
        print(f"  Sources    : {', '.join(result.session_key.sources)}")
        print(f"  Deriv. time: {result.session_key.derivation_time_ms:.3f} ms")
        print(f"  CT (hex)   : {result.ciphertext.hex()[:48]}...")
        print(f"  Decrypted  : {result.decrypted[:60]}{'...' if len(result.decrypted) > 60 else ''}")

    print("\n  [Signature Demo]")
    msg = b"Authenticate this enterprise message"
    sig_result = ml_dsa_sign_verify(msg)
    print(f"  Algorithm  : {sig_result['algorithm']}")
    print(f"  Sig length : {sig_result['signature_len']} bytes")
    print(f"  Valid      : {'✓' if sig_result['valid'] else '✗'}")
    print(f"  Simulated  : {sig_result['simulated']}")
