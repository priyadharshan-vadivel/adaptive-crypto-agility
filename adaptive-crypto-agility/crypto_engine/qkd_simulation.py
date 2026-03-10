"""
qkd_simulation.py
=================
Simulated Quantum Key Distribution (QKD) Key Material

In a real deployment, QKD keys are retrieved from a Key Management Server (KMS)
via the ETSI GS QKD 014 REST API. This module simulates that process using
cryptographically secure random bytes, enabling the triple-hybrid architecture
to be demonstrated without specialised QKD hardware (e.g., IDQuantique Clavis3).

Real QKD Infrastructure (for reference):
    - QKD nodes connected via dark fibre (quantum channel)
    - Key Management Server (KMS) per QKD node
    - Secure Application Entity (SAE) retrieves keys via ETSI REST API
    - Key identifier (key ID) transmitted over classical channel
    - SKR (Secret Key Rate): ~2.5 kbit/s for IDQuantique Clavis3 over short distances

ETSI GS QKD 014 API Reference:
    GET /api/v1/keys/{slaveKMSID}/enc_keys
    → {"keys": [{"key_ID": "<uuid>", "key": "<base64-encoded-key>"}]}

This simulation:
    - Generates a 256-bit (32-byte) pre-agreed random key
    - Returns a UUID-like key_ID for identification
    - Mimics the round-trip latency (~15–24 ms per API call per Rubio García 2025)

References:
    - ETSI GS QKD 014 v1.1.1 (2019)
    - Rubio García et al., IEEE JSAC 2025 (Section IV, QKD Integration in TLS 1.3)
    - IDQuantique Clavis3 equipment datasheet
"""

import os
import uuid
import time
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Simulate KMS API latency observed in real QKD testbed (ms → seconds)
SIMULATED_KMS_LATENCY_MS = 15.0   # ~15 ms per Rubio García 2025 (in-house KMS)
QKD_KEY_SIZE_BYTES = 32            # 256-bit key


@dataclass
class QKDKeyMaterial:
    """
    Represents a QKD-derived shared secret and its key identifier.

    Attributes:
        key:        32-byte shared secret (equivalent to ETSI 'key' field)
        key_id:     UUID string (equivalent to ETSI 'key_ID' field)
        latency_ms: Simulated KMS API call duration in milliseconds
        is_simulated: Always True in this module
    """
    key: bytes
    key_id: str
    latency_ms: float
    is_simulated: bool = True


def simulated_qkd_key(
    simulate_latency: bool = False,
    key_id: Optional[str] = None,
) -> QKDKeyMaterial:
    """
    Retrieve a simulated QKD shared secret.

    Simulates the ETSI GS QKD 014 key delivery process:
      1. SAE calls GET /api/v1/keys/{kmsID}/enc_keys
      2. KMS returns {"keys": [{"key_ID": "<uuid>", "key": "<base64>"}]}
      3. Key ID is transmitted to the peer over classical channel
      4. Peer calls GET /api/v1/keys/{kmsID}/dec_keys with key_ID
      5. Both sides now hold the same 256-bit quantum key

    Args:
        simulate_latency: If True, sleep to mimic real KMS API call time
        key_id:           Optionally provide a specific key ID (for peer retrieval)

    Returns:
        QKDKeyMaterial with key bytes and key_ID
    """
    start = time.monotonic()

    # In a real system: HTTP GET to KMS API
    # key = base64.b64decode(kms_response["keys"][0]["key"])
    key = os.urandom(QKD_KEY_SIZE_BYTES)
    kid = key_id if key_id else str(uuid.uuid4())

    if simulate_latency:
        time.sleep(SIMULATED_KMS_LATENCY_MS / 1000.0)

    elapsed_ms = (time.monotonic() - start) * 1000

    logger.debug(
        "QKD key retrieved | key_ID=%s | latency=%.1f ms | simulated=True",
        kid, elapsed_ms
    )

    return QKDKeyMaterial(
        key=key,
        key_id=kid,
        latency_ms=elapsed_ms,
        is_simulated=True,
    )


def qkd_key_pair(simulate_latency: bool = False):
    """
    Simulate both ends of a QKD key exchange:
      - 'Alice' (client) retrieves a fresh key and key_ID from KMS
      - 'Bob' (server) retrieves the same key using the key_ID

    In this simulation, both parties receive the same random key.
    In a real deployment, the QKD network guarantees this via the quantum channel.

    Returns:
        Tuple of (alice_material, bob_material) — both have identical keys
    """
    alice = simulated_qkd_key(simulate_latency=simulate_latency)
    # Bob retrieves the same key using Alice's key_ID
    # In simulation, we just copy the key (real QKD: KMS delivers same key)
    bob = QKDKeyMaterial(
        key=alice.key,
        key_id=alice.key_id,
        latency_ms=alice.latency_ms,
        is_simulated=True,
    )
    return alice, bob


if __name__ == "__main__":
    print("[Simulated QKD Key Exchange]")
    alice, bob = qkd_key_pair(simulate_latency=True)
    print(f"  Key ID       : {alice.key_id}")
    print(f"  Alice Key    : {alice.key.hex()}")
    print(f"  Bob Key      : {bob.key.hex()}")
    print(f"  Keys Match   : {alice.key == bob.key}")
    print(f"  Key Bits     : {len(alice.key) * 8}")
    print(f"  KMS Latency  : {alice.latency_ms:.1f} ms (simulated)")
    print(f"  Note: Real QKD adds ~15–24 ms overhead per Rubio García (2025)")
