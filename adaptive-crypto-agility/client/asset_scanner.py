"""
asset_scanner.py
================
Cryptographic Asset Scanner.

Scans and profiles cryptographic assets from:
  1. TLS/SSL certificates of live hosts (via ssl module)
  2. Local PEM/DER certificate files
  3. Manually specified asset configurations

Produces AssetProfile objects consumed by the Risk Engine.
"""

from __future__ import annotations
import ssl
import socket
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Public key type → canonical algorithm name
PUB_KEY_ALGO_MAP = {
    "RSAPublicKey":      "RSA",
    "_RSAPublicKey":     "RSA",
    "EllipticCurvePublicKey":  "ECC",
    "_EllipticCurvePublicKey": "ECC",
    "DHPublicKey":       "DH",
    "_DHPublicKey":      "DH",
    "DSAPublicKey":      "DSA",
    "_DSAPublicKey":     "DSA",
}


def _get_pub_key_info(pub_key) -> tuple[str, int]:
    """Extract (algorithm_name, key_size_bits) from a public key object."""
    algo = PUB_KEY_ALGO_MAP.get(type(pub_key).__name__, "UNKNOWN")
    size = getattr(pub_key, "key_size", 0)
    # ECC key_size might be via curve
    if size == 0 and hasattr(pub_key, "curve"):
        size = getattr(pub_key.curve, "key_size", 0)
    return algo, size


def scan_tls_host(host: str, port: int = 443, sensitivity: str = "medium") -> dict:
    """
    Connect to a TLS host, retrieve its certificate, and build an asset profile.

    Args:
        host:        Hostname or IP address (e.g., "example.com" or "192.168.100.20")
        port:        TLS port (default 443; use 4443 for lab server)
        sensitivity: Data sensitivity classification for the service

    Returns:
        Asset profile dict ready for risk evaluation.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, port))
            cert_bin    = s.getpeercert(binary_form=True)
            cipher_name = s.cipher()[0] if s.cipher() else "Unknown"
            tls_version = s.version() or "Unknown"

        cert    = x509.load_der_x509_certificate(cert_bin, default_backend())
        pub_key = cert.public_key()
        algo, key_size = _get_pub_key_info(pub_key)

        profile = {
            "algorithm":   algo,
            "key_size":    key_size,
            "sensitivity": sensitivity,
            "protocol":    tls_version,
            "description": f"TLS cert for {host}:{port}",
            "cipher":      cipher_name,
            "subject":     cert.subject.rfc4514_string(),
            "not_after":   cert.not_valid_after_utc.isoformat(),
        }
        logger.info("Scanned TLS cert: %s/%d-bit from %s:%d", algo, key_size, host, port)
        return profile

    except Exception as e:
        logger.warning("Could not scan %s:%d — %s. Using manual profile.", host, port, e)
        return build_manual_profile("UNKNOWN", 0, sensitivity, f"scan_failed:{host}:{port}")


def scan_pem_file(pem_path: str, sensitivity: str = "medium") -> dict:
    """
    Read a PEM certificate file and extract algorithm/key info.

    Args:
        pem_path:    Path to a .pem or .crt file.
        sensitivity: Data sensitivity classification.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        data = Path(pem_path).read_bytes()
        # Try PEM first, then DER
        try:
            cert = x509.load_pem_x509_certificate(data, default_backend())
        except Exception:
            cert = x509.load_der_x509_certificate(data, default_backend())

        pub_key = cert.public_key()
        algo, key_size = _get_pub_key_info(pub_key)

        return {
            "algorithm":   algo,
            "key_size":    key_size,
            "sensitivity": sensitivity,
            "description": f"PEM cert: {pem_path}",
            "subject":     cert.subject.rfc4514_string(),
        }
    except Exception as e:
        logger.error("Failed to parse PEM file %s: %s", pem_path, e)
        return build_manual_profile("UNKNOWN", 0, sensitivity, f"pem:{pem_path}")


def build_manual_profile(
    algorithm:   str,
    key_size:    int,
    sensitivity: str = "medium",
    description: str = "",
    protocol:    Optional[str] = None,
) -> dict:
    """
    Build an asset profile dict manually (no live scanning required).
    Use this for the lab VM environment.
    """
    return {
        "algorithm":   algorithm.upper(),
        "key_size":    key_size,
        "sensitivity": sensitivity.lower(),
        "description": description or f"{algorithm}/{key_size}-bit",
        "protocol":    protocol,
    }


def load_profiles_from_json(path: str) -> list[dict]:
    """Load a list of asset profiles from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "assets" in data:
        return data["assets"]
    raise ValueError(f"Unexpected JSON format in {path}")


# ---------------------------------------------------------------------------
# Sample enterprise asset inventory (used in demo/tests)
# ---------------------------------------------------------------------------

SAMPLE_ENTERPRISE_ASSETS = [
    {"algorithm": "RSA",     "key_size": 1024, "sensitivity": "high",   "description": "Legacy VPN gateway cert",         "protocol": "IPsec IKEv1"},
    {"algorithm": "RSA",     "key_size": 2048, "sensitivity": "high",   "description": "Public web server TLS cert",      "protocol": "TLS 1.2"},
    {"algorithm": "RSA",     "key_size": 2048, "sensitivity": "high",   "description": "Email server (SMTPS) certificate","protocol": "TLS 1.2"},
    {"algorithm": "ECC",     "key_size": 256,  "sensitivity": "medium", "description": "Client authentication certificate","protocol": "TLS 1.3"},
    {"algorithm": "ECDH",    "key_size": 256,  "sensitivity": "medium", "description": "API gateway key exchange",        "protocol": "TLS 1.3"},
    {"algorithm": "AES-128", "key_size": 128,  "sensitivity": "high",   "description": "Archived financial records (2015–2020)", "protocol": "AES-CBC"},
    {"algorithm": "AES-256", "key_size": 256,  "sensitivity": "medium", "description": "Current database encryption",    "protocol": "AES-GCM"},
    {"algorithm": "DH",      "key_size": 2048, "sensitivity": "low",    "description": "Ephemeral session key exchange",  "protocol": "TLS 1.2"},
    {"algorithm": "ML-KEM",  "key_size": 1024, "sensitivity": "high",   "description": "New PQ-enabled service (pilot)",  "protocol": "TLS 1.3"},
    {"algorithm": "3DES",    "key_size": 168,  "sensitivity": "high",   "description": "Legacy mainframe link encryption","protocol": "SSH-1"},
]


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  CRYPTOGRAPHIC ASSET SCANNER — Enterprise Inventory Demo")
    print("=" * 65)

    print(f"\n{'#':<3} {'Description':<36} {'Algorithm':<10} {'Key':>5} {'Sensitivity'}")
    print("-" * 72)
    for i, asset in enumerate(SAMPLE_ENTERPRISE_ASSETS, 1):
        print(
            f"{i:<3} {asset['description']:<36} "
            f"{asset['algorithm']:<10} {asset['key_size']:>5} "
            f"{asset['sensitivity']}"
        )

    print(f"\nTotal assets inventoried: {len(SAMPLE_ENTERPRISE_ASSETS)}")
    print("Run risk_engine/risk_engine.py or scripts/run_demo.py for full evaluation.")
