"""
classical.py
============
Classical Cryptographic Key Exchange

Implements X25519 Elliptic Curve Diffie-Hellman (ECDH) ephemeral key exchange,
equivalent to the ECDHE used in TLS 1.3.

Why X25519?
  - 128-bit classical security level
  - Fast, constant-time implementation
  - Default ephemeral KEM in TLS 1.3 (RFC 8446)
  - Used as the classical component in triple-hybrid protocols

Note: X25519 is vulnerable to Shor's algorithm on a sufficiently powerful
quantum computer, which is why it is combined with ML-KEM-1024 in Hybrid
and Triple-Hybrid modes.
"""

from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
import logging

logger = logging.getLogger(__name__)


@dataclass
class ECDHResult:
    """Result of a simulated X25519 ECDH key exchange."""
    shared_secret: bytes          # 32-byte shared secret
    client_public_key_bytes: bytes
    server_public_key_bytes: bytes
    key_size_bits: int = 256


def classical_ecdh() -> ECDHResult:
    """
    Simulate a complete X25519 ECDH key exchange between client and server.

    In a real TLS 1.3 handshake:
      1. Client generates an ephemeral keypair and sends public key in ClientHello
      2. Server generates an ephemeral keypair and sends public key in ServerHello
      3. Both sides compute the same shared secret independently

    Returns:
        ECDHResult containing the 32-byte shared secret and public key bytes.
    """
    # Client side
    client_private = X25519PrivateKey.generate()
    client_public = client_private.public_key()

    # Server side
    server_private = X25519PrivateKey.generate()
    server_public = server_private.public_key()

    # Key exchange — both sides derive the same shared secret
    client_shared = client_private.exchange(server_public)
    server_shared = server_private.exchange(client_public)

    assert client_shared == server_shared, "ECDH shared secret mismatch — implementation error"

    client_pub_bytes = client_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    server_pub_bytes = server_public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    logger.debug(
        "Classical ECDH: X25519 | shared_secret=%s...",
        client_shared.hex()[:16]
    )

    return ECDHResult(
        shared_secret=client_shared,
        client_public_key_bytes=client_pub_bytes,
        server_public_key_bytes=server_pub_bytes,
    )


if __name__ == "__main__":
    result = classical_ecdh()
    print(f"[Classical ECDH - X25519]")
    print(f"  Shared Secret  : {result.shared_secret.hex()}")
    print(f"  Secret Length  : {len(result.shared_secret) * 8} bits")
    print(f"  Client Pub Key : {result.client_public_key_bytes.hex()[:32]}...")
    print(f"  Server Pub Key : {result.server_public_key_bytes.hex()[:32]}...")
